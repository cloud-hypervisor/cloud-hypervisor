// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use super::Error as DeviceError;
use super::{
    ActivateError, ActivateResult, DescriptorChain, EpollHelper, EpollHelperError,
    EpollHelperHandler, Queue, UserspaceMapping, VirtioDevice, VirtioDeviceType,
    EPOLL_HELPER_EVENT_LAST, VIRTIO_F_IOMMU_PLATFORM, VIRTIO_F_VERSION_1,
};
use crate::seccomp_filters::{get_seccomp_filter, Thread};
use crate::{VirtioInterrupt, VirtioInterruptType};
use anyhow::anyhow;
use libc::EFD_NONBLOCK;
use seccomp::{SeccompAction, SeccompFilter};
use serde::ser::{Serialize, SerializeStruct, Serializer};
use std::fmt::{self, Display};
use std::fs::File;
use std::io;
use std::mem::size_of;
use std::os::unix::io::AsRawFd;
use std::result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use vm_memory::{
    Address, ByteValued, Bytes, GuestAddress, GuestAddressSpace, GuestMemoryAtomic,
    GuestMemoryError, GuestMemoryMmap, MmapRegion,
};
use vm_migration::{
    Migratable, MigratableError, Pausable, Snapshot, SnapshotDataSection, Snapshottable,
    Transportable,
};
use vmm_sys_util::eventfd::EventFd;

const QUEUE_SIZE: u16 = 256;
const NUM_QUEUES: usize = 1;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE];

const VIRTIO_PMEM_REQ_TYPE_FLUSH: u32 = 0;
const VIRTIO_PMEM_RESP_TYPE_OK: u32 = 0;
const VIRTIO_PMEM_RESP_TYPE_EIO: u32 = 1;

// New descriptors are pending on the virtio queue.
const QUEUE_AVAIL_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;

#[derive(Copy, Clone, Debug, Default, Deserialize)]
#[repr(C, packed)]
struct VirtioPmemConfig {
    start: u64,
    size: u64,
}

// We must explicitly implement Serialize since the structure is packed and
// it's unsafe to borrow from a packed structure. And by default, if we derive
// Serialize from serde, it will borrow the values from the structure.
// That's why this implementation copies each field separately before it
// serializes the entire structure field by field.
impl Serialize for VirtioPmemConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let start = self.start;
        let size = self.size;

        let mut virtio_pmem_config = serializer.serialize_struct("VirtioPmemConfig", 16)?;
        virtio_pmem_config.serialize_field("start", &start)?;
        virtio_pmem_config.serialize_field("size", &size)?;
        virtio_pmem_config.end()
    }
}

// Safe because it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioPmemConfig {}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
struct VirtioPmemReq {
    type_: u32,
}

// Safe because it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioPmemReq {}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
struct VirtioPmemResp {
    ret: u32,
}

// Safe because it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioPmemResp {}

#[derive(Debug)]
enum Error {
    /// Guest gave us bad memory addresses.
    GuestMemory(GuestMemoryError),
    /// Guest gave us a write only descriptor that protocol says to read from.
    UnexpectedWriteOnlyDescriptor,
    /// Guest gave us a read only descriptor that protocol says to write to.
    UnexpectedReadOnlyDescriptor,
    /// Guest gave us too few descriptors in a descriptor chain.
    DescriptorChainTooShort,
    /// Guest gave us a buffer that was too short to use.
    BufferLengthTooSmall,
    /// Guest sent us invalid request.
    InvalidRequest,
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            BufferLengthTooSmall => write!(f, "buffer length too small"),
            DescriptorChainTooShort => write!(f, "descriptor chain too short"),
            GuestMemory(e) => write!(f, "bad guest memory address: {}", e),
            InvalidRequest => write!(f, "invalid request"),
            UnexpectedReadOnlyDescriptor => write!(f, "unexpected read-only descriptor"),
            UnexpectedWriteOnlyDescriptor => write!(f, "unexpected write-only descriptor"),
        }
    }
}

#[derive(Debug, PartialEq)]
enum RequestType {
    Flush,
}

struct Request {
    type_: RequestType,
    status_addr: GuestAddress,
}

impl Request {
    fn parse(
        avail_desc: &DescriptorChain,
        mem: &GuestMemoryMmap,
    ) -> result::Result<Request, Error> {
        // The head contains the request type which MUST be readable.
        if avail_desc.is_write_only() {
            return Err(Error::UnexpectedWriteOnlyDescriptor);
        }

        if avail_desc.len as usize != size_of::<VirtioPmemReq>() {
            return Err(Error::InvalidRequest);
        }

        let request: VirtioPmemReq = mem.read_obj(avail_desc.addr).map_err(Error::GuestMemory)?;

        let request_type = match request.type_ {
            VIRTIO_PMEM_REQ_TYPE_FLUSH => RequestType::Flush,
            _ => return Err(Error::InvalidRequest),
        };

        let status_desc = avail_desc
            .next_descriptor()
            .ok_or(Error::DescriptorChainTooShort)?;

        // The status MUST always be writable
        if !status_desc.is_write_only() {
            return Err(Error::UnexpectedReadOnlyDescriptor);
        }

        if (status_desc.len as usize) < size_of::<VirtioPmemResp>() {
            return Err(Error::BufferLengthTooSmall);
        }

        Ok(Request {
            type_: request_type,
            status_addr: status_desc.addr,
        })
    }
}

struct PmemEpollHandler {
    queue: Queue,
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
    disk: File,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    queue_evt: EventFd,
    kill_evt: EventFd,
    pause_evt: EventFd,
}

impl PmemEpollHandler {
    fn process_queue(&mut self) -> bool {
        let mut used_desc_heads = [(0, 0); QUEUE_SIZE as usize];
        let mut used_count = 0;
        let mem = self.mem.memory();
        for avail_desc in self.queue.iter(&mem) {
            let len = match Request::parse(&avail_desc, &mem) {
                Ok(ref req) if (req.type_ == RequestType::Flush) => {
                    let status_code = match self.disk.sync_all() {
                        Ok(()) => VIRTIO_PMEM_RESP_TYPE_OK,
                        Err(e) => {
                            error!("failed flushing disk image: {}", e);
                            VIRTIO_PMEM_RESP_TYPE_EIO
                        }
                    };

                    let resp = VirtioPmemResp { ret: status_code };
                    match mem.write_obj(resp, req.status_addr) {
                        Ok(_) => size_of::<VirtioPmemResp>() as u32,
                        Err(e) => {
                            error!("bad guest memory address: {}", e);
                            0
                        }
                    }
                }
                Ok(ref req) => {
                    // Currently, there is only one virtio-pmem request, FLUSH.
                    error!("Invalid virtio request type {:?}", req.type_);
                    0
                }
                Err(e) => {
                    error!("Failed to parse available descriptor chain: {:?}", e);
                    0
                }
            };

            used_desc_heads[used_count] = (avail_desc.index, len);
            used_count += 1;
        }

        for &(desc_index, len) in &used_desc_heads[..used_count] {
            self.queue.add_used(&mem, desc_index, len);
        }
        used_count > 0
    }

    fn signal_used_queue(&self) -> result::Result<(), DeviceError> {
        self.interrupt_cb
            .trigger(&VirtioInterruptType::Queue, Some(&self.queue))
            .map_err(|e| {
                error!("Failed to signal used queue: {:?}", e);
                DeviceError::FailedSignalingUsedQueue(e)
            })
    }

    fn run(&mut self, paused: Arc<AtomicBool>) -> result::Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;
        helper.add_event(self.queue_evt.as_raw_fd(), QUEUE_AVAIL_EVENT)?;
        helper.run(paused, self)?;

        Ok(())
    }
}

impl EpollHelperHandler for PmemEpollHandler {
    fn handle_event(&mut self, _helper: &mut EpollHelper, event: u16) -> bool {
        match event {
            QUEUE_AVAIL_EVENT => {
                if let Err(e) = self.queue_evt.read() {
                    error!("Failed to get queue event: {:?}", e);
                    return true;
                } else if self.process_queue() {
                    if let Err(e) = self.signal_used_queue() {
                        error!("Failed to signal used queue: {:?}", e);
                        return true;
                    }
                }
            }
            _ => {
                error!("Unexpected event: {}", event);
                return true;
            }
        }
        false
    }
}

pub struct Pmem {
    id: String,
    kill_evt: Option<EventFd>,
    pause_evt: Option<EventFd>,
    disk: Option<File>,
    avail_features: u64,
    acked_features: u64,
    config: VirtioPmemConfig,
    queue_evts: Option<Vec<EventFd>>,
    interrupt_cb: Option<Arc<dyn VirtioInterrupt>>,
    epoll_threads: Option<Vec<thread::JoinHandle<()>>>,
    paused: Arc<AtomicBool>,
    mapping: UserspaceMapping,
    seccomp_action: SeccompAction,

    // Hold ownership of the memory that is allocated for the device
    // which will be automatically dropped when the device is dropped
    _region: MmapRegion,
}

#[derive(Serialize, Deserialize)]
pub struct PmemState {
    avail_features: u64,
    acked_features: u64,
    config: VirtioPmemConfig,
}

impl Pmem {
    pub fn new(
        id: String,
        disk: File,
        addr: GuestAddress,
        mapping: UserspaceMapping,
        _region: MmapRegion,
        iommu: bool,
        seccomp_action: SeccompAction,
    ) -> io::Result<Pmem> {
        let config = VirtioPmemConfig {
            start: addr.raw_value().to_le(),
            size: (_region.size() as u64).to_le(),
        };

        let mut avail_features = 1u64 << VIRTIO_F_VERSION_1;

        if iommu {
            avail_features |= 1u64 << VIRTIO_F_IOMMU_PLATFORM;
        }

        Ok(Pmem {
            id,
            kill_evt: None,
            pause_evt: None,
            disk: Some(disk),
            avail_features,
            acked_features: 0u64,
            config,
            queue_evts: None,
            interrupt_cb: None,
            epoll_threads: None,
            paused: Arc::new(AtomicBool::new(false)),
            mapping,
            seccomp_action,
            _region,
        })
    }

    fn state(&self) -> PmemState {
        PmemState {
            avail_features: self.avail_features,
            acked_features: self.acked_features,
            config: self.config,
        }
    }

    fn set_state(&mut self, state: &PmemState) -> io::Result<()> {
        self.avail_features = state.avail_features;
        self.acked_features = state.acked_features;
        self.config = state.config;

        Ok(())
    }
}

impl Drop for Pmem {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
    }
}

impl VirtioDevice for Pmem {
    fn device_type(&self) -> u32 {
        VirtioDeviceType::TYPE_PMEM as u32
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn features(&self) -> u64 {
        self.avail_features
    }

    fn ack_features(&mut self, value: u64) {
        let mut v = value;
        // Check if the guest is ACK'ing a feature that we didn't claim to have.
        let unrequested_features = v & !self.avail_features;
        if unrequested_features != 0 {
            warn!("Received acknowledge request for unknown feature.");

            // Don't count these features as acked.
            v &= !unrequested_features;
        }
        self.acked_features |= v;
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        self.read_config_from_slice(self.config.as_slice(), offset, data);
    }

    fn activate(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        interrupt_cb: Arc<dyn VirtioInterrupt>,
        mut queues: Vec<Queue>,
        mut queue_evts: Vec<EventFd>,
    ) -> ActivateResult {
        if queues.len() != NUM_QUEUES || queue_evts.len() != NUM_QUEUES {
            error!(
                "Cannot perform activate. Expected {} queue(s), got {}",
                NUM_QUEUES,
                queues.len()
            );
            return Err(ActivateError::BadActivate);
        }

        let (self_kill_evt, kill_evt) = EventFd::new(EFD_NONBLOCK)
            .and_then(|e| Ok((e.try_clone()?, e)))
            .map_err(|e| {
                error!("failed creating kill EventFd pair: {}", e);
                ActivateError::BadActivate
            })?;
        self.kill_evt = Some(self_kill_evt);

        let (self_pause_evt, pause_evt) = EventFd::new(EFD_NONBLOCK)
            .and_then(|e| Ok((e.try_clone()?, e)))
            .map_err(|e| {
                error!("failed creating pause EventFd pair: {}", e);
                ActivateError::BadActivate
            })?;
        self.pause_evt = Some(self_pause_evt);

        // Save the interrupt EventFD as we need to return it on reset
        // but clone it to pass into the thread.
        self.interrupt_cb = Some(interrupt_cb.clone());

        let mut tmp_queue_evts: Vec<EventFd> = Vec::new();
        for queue_evt in queue_evts.iter() {
            // Save the queue EventFD as we need to return it on reset
            // but clone it to pass into the thread.
            tmp_queue_evts.push(queue_evt.try_clone().map_err(|e| {
                error!("failed to clone queue EventFd: {}", e);
                ActivateError::BadActivate
            })?);
        }
        self.queue_evts = Some(tmp_queue_evts);

        if let Some(disk) = self.disk.as_ref() {
            let disk = disk.try_clone().map_err(|e| {
                error!("failed cloning pmem disk: {}", e);
                ActivateError::BadActivate
            })?;
            let mut handler = PmemEpollHandler {
                queue: queues.remove(0),
                mem,
                disk,
                interrupt_cb,
                queue_evt: queue_evts.remove(0),
                kill_evt,
                pause_evt,
            };

            let paused = self.paused.clone();
            let mut epoll_threads = Vec::new();
            // Retrieve seccomp filter for virtio_pmem thread
            let virtio_pmem_seccomp_filter =
                get_seccomp_filter(&self.seccomp_action, Thread::VirtioPmem)
                    .map_err(ActivateError::CreateSeccompFilter)?;
            thread::Builder::new()
                .name("virtio_pmem".to_string())
                .spawn(move || {
                    if let Err(e) = SeccompFilter::apply(virtio_pmem_seccomp_filter) {
                        error!("Error applying seccomp filter: {:?}", e);
                    } else if let Err(e) = handler.run(paused) {
                        error!("Error running worker: {:?}", e);
                    }
                })
                .map(|thread| epoll_threads.push(thread))
                .map_err(|e| {
                    error!("failed to clone virtio-pmem epoll thread: {}", e);
                    ActivateError::BadActivate
                })?;

            self.epoll_threads = Some(epoll_threads);

            return Ok(());
        }
        Err(ActivateError::BadActivate)
    }

    fn reset(&mut self) -> Option<(Arc<dyn VirtioInterrupt>, Vec<EventFd>)> {
        // We first must resume the virtio thread if it was paused.
        if self.pause_evt.take().is_some() {
            self.resume().ok()?;
        }

        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }

        // Return the interrupt and queue EventFDs
        Some((
            self.interrupt_cb.take().unwrap(),
            self.queue_evts.take().unwrap(),
        ))
    }

    fn userspace_mappings(&self) -> Vec<UserspaceMapping> {
        vec![self.mapping.clone()]
    }
}

virtio_pausable!(Pmem);
impl Snapshottable for Pmem {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&self) -> std::result::Result<Snapshot, MigratableError> {
        let snapshot =
            serde_json::to_vec(&self.state()).map_err(|e| MigratableError::Snapshot(e.into()))?;

        let mut pmem_snapshot = Snapshot::new(self.id.as_str());
        pmem_snapshot.add_data_section(SnapshotDataSection {
            id: format!("{}-section", self.id),
            snapshot,
        });

        Ok(pmem_snapshot)
    }

    fn restore(&mut self, snapshot: Snapshot) -> std::result::Result<(), MigratableError> {
        if let Some(pmem_section) = snapshot.snapshot_data.get(&format!("{}-section", self.id)) {
            let pmem_state = match serde_json::from_slice(&pmem_section.snapshot) {
                Ok(state) => state,
                Err(error) => {
                    return Err(MigratableError::Restore(anyhow!(
                        "Could not deserialize PMEM {}",
                        error
                    )))
                }
            };

            return self.set_state(&pmem_state).map_err(|e| {
                MigratableError::Restore(anyhow!("Could not restore PMEM state {:?}", e))
            });
        }

        Err(MigratableError::Restore(anyhow!(
            "Could not find PMEM snapshot section"
        )))
    }
}

impl Transportable for Pmem {}
impl Migratable for Pmem {}
