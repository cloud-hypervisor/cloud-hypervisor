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
    EpollHelperHandler, Queue, UserspaceMapping, VirtioCommon, VirtioDevice, VirtioDeviceType,
    EPOLL_HELPER_EVENT_LAST, VIRTIO_F_IOMMU_PLATFORM, VIRTIO_F_VERSION_1,
};
use crate::seccomp_filters::{get_seccomp_filter, Thread};
use crate::{VirtioInterrupt, VirtioInterruptType};
use anyhow::anyhow;
use seccomp::{SeccompAction, SeccompFilter};
use std::fmt::{self, Display};
use std::fs::File;
use std::io;
use std::mem::size_of;
use std::os::unix::io::AsRawFd;
use std::result;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Barrier};
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
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE];

const VIRTIO_PMEM_REQ_TYPE_FLUSH: u32 = 0;
const VIRTIO_PMEM_RESP_TYPE_OK: u32 = 0;
const VIRTIO_PMEM_RESP_TYPE_EIO: u32 = 1;

// New descriptors are pending on the virtio queue.
const QUEUE_AVAIL_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;

#[derive(Copy, Clone, Debug, Default, Serialize, Deserialize)]
#[repr(C)]
struct VirtioPmemConfig {
    start: u64,
    size: u64,
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

    fn run(
        &mut self,
        paused: Arc<AtomicBool>,
        paused_sync: Arc<Barrier>,
    ) -> result::Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;
        helper.add_event(self.queue_evt.as_raw_fd(), QUEUE_AVAIL_EVENT)?;
        helper.run(paused, paused_sync, self)?;

        Ok(())
    }
}

impl EpollHelperHandler for PmemEpollHandler {
    fn handle_event(&mut self, _helper: &mut EpollHelper, event: &epoll::Event) -> bool {
        let ev_type = event.data as u16;
        match ev_type {
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
                error!("Unexpected event: {}", ev_type);
                return true;
            }
        }
        false
    }
}

pub struct Pmem {
    common: VirtioCommon,
    id: String,
    disk: Option<File>,
    config: VirtioPmemConfig,
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
            common: VirtioCommon {
                device_type: VirtioDeviceType::TYPE_PMEM as u32,
                queue_sizes: QUEUE_SIZES.to_vec(),
                paused_sync: Some(Arc::new(Barrier::new(2))),
                avail_features,
                ..Default::default()
            },
            id,
            disk: Some(disk),
            config,
            mapping,
            seccomp_action,
            _region,
        })
    }

    fn state(&self) -> PmemState {
        PmemState {
            avail_features: self.common.avail_features,
            acked_features: self.common.acked_features,
            config: self.config,
        }
    }

    fn set_state(&mut self, state: &PmemState) -> io::Result<()> {
        self.common.avail_features = state.avail_features;
        self.common.acked_features = state.acked_features;
        self.config = state.config;

        Ok(())
    }
}

impl Drop for Pmem {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.common.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
    }
}

impl VirtioDevice for Pmem {
    fn device_type(&self) -> u32 {
        self.common.device_type
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.common.queue_sizes
    }

    fn features(&self) -> u64 {
        self.common.avail_features
    }

    fn ack_features(&mut self, value: u64) {
        self.common.ack_features(value)
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
        self.common.activate(&queues, &queue_evts, &interrupt_cb)?;
        let kill_evt = self
            .common
            .kill_evt
            .as_ref()
            .unwrap()
            .try_clone()
            .map_err(|e| {
                error!("failed to clone kill_evt eventfd: {}", e);
                ActivateError::BadActivate
            })?;
        let pause_evt = self
            .common
            .pause_evt
            .as_ref()
            .unwrap()
            .try_clone()
            .map_err(|e| {
                error!("failed to clone pause_evt eventfd: {}", e);
                ActivateError::BadActivate
            })?;
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

            let paused = self.common.paused.clone();
            let paused_sync = self.common.paused_sync.clone();
            let mut epoll_threads = Vec::new();
            // Retrieve seccomp filter for virtio_pmem thread
            let virtio_pmem_seccomp_filter =
                get_seccomp_filter(&self.seccomp_action, Thread::VirtioPmem)
                    .map_err(ActivateError::CreateSeccompFilter)?;
            thread::Builder::new()
                .name(self.id.clone())
                .spawn(move || {
                    if let Err(e) = SeccompFilter::apply(virtio_pmem_seccomp_filter) {
                        error!("Error applying seccomp filter: {:?}", e);
                    } else if let Err(e) = handler.run(paused, paused_sync.unwrap()) {
                        error!("Error running worker: {:?}", e);
                    }
                })
                .map(|thread| epoll_threads.push(thread))
                .map_err(|e| {
                    error!("failed to clone virtio-pmem epoll thread: {}", e);
                    ActivateError::BadActivate
                })?;

            self.common.epoll_threads = Some(epoll_threads);

            return Ok(());
        }
        Err(ActivateError::BadActivate)
    }

    fn reset(&mut self) -> Option<(Arc<dyn VirtioInterrupt>, Vec<EventFd>)> {
        self.common.reset()
    }

    fn userspace_mappings(&self) -> Vec<UserspaceMapping> {
        vec![self.mapping.clone()]
    }
}

impl Pausable for Pmem {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        self.common.pause()
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        self.common.resume()
    }
}

impl Snapshottable for Pmem {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
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
