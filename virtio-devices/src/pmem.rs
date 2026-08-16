// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::fs::File;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::{io, result};

use anyhow::anyhow;
use event_monitor::event;
use log::{error, info, warn};
use seccompiler::SeccompAction;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use virtio_queue::{DescriptorChain, Queue, QueueT};
use vm_device::UserspaceMapping;
use vm_device::uffd::{Response as UffdResponse, UffdBlock, VmaRegion};
use vm_memory::{
    Address, ByteValued, Bytes, GuestAddress, GuestAddressSpace, GuestMemoryAtomic,
    GuestMemoryError, GuestMemoryLoadGuard,
};
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
use vm_virtio::AccessPlatform;
use vm_virtio::checked_descriptor::DescriptorChainExt;
use vmm_sys_util::eventfd::EventFd;

use super::{
    ActivateError, ActivateResult, EPOLL_HELPER_EVENT_LAST, EpollHelper, EpollHelperError,
    EpollHelperHandler, Error as DeviceError, VIRTIO_F_ACCESS_PLATFORM, VIRTIO_F_VERSION_1,
    VirtioCommon, VirtioDevice, VirtioDeviceType,
};
use crate::device::ActivationContext;
use crate::seccomp_filters::Thread;
use crate::{GuestMemoryMmap, VirtioInterrupt, VirtioInterruptType};

const QUEUE_SIZE: u16 = 256;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE];

const VIRTIO_PMEM_REQ_TYPE_FLUSH: u32 = 0;
const VIRTIO_PMEM_RESP_TYPE_OK: u32 = 0;
const VIRTIO_PMEM_RESP_TYPE_EIO: u32 = 1;

// New descriptors are pending on the virtio queue.
const QUEUE_AVAIL_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;
const UFFD_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 2;

const UFFDIO_WAKE: u64 = 0x8010_aa02;

#[repr(C)]
struct UffdioRange {
    start: u64,
    len: u64,
}

pub struct MmapUffdHandler {
    block: UffdBlock,
    uffd: OwnedFd,
    regions: Vec<VmaRegion>,
}

impl MmapUffdHandler {
    pub fn new(block: UffdBlock, uffd: OwnedFd, regions: Vec<VmaRegion>) -> Self {
        Self {
            block,
            uffd,
            regions,
        }
    }

    fn handle_event(&self) -> io::Result<bool> {
        match self.block.recv_response()? {
            None => Ok(false),
            Some(UffdResponse::Ack) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unexpected UFFD acknowledgement",
            )),
            Some(UffdResponse::FdRanges {
                more: _,
                ranges,
                fds,
            }) => {
                for (range, fd) in ranges.iter().zip(fds) {
                    let range_end = range
                        .device_offset
                        .checked_add(range.len)
                        .ok_or_else(|| io::Error::other("UFFD range overflow"))?;
                    let region = self
                        .regions
                        .iter()
                        .find(|region| {
                            range.device_offset >= region.offset
                                && region
                                    .offset
                                    .checked_add(region.size)
                                    .is_some_and(|region_end| range_end <= region_end)
                        })
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "UFFD range is outside registered regions",
                            )
                        })?;
                    let target_addr = region
                        .virt_addr
                        .checked_add(range.device_offset - region.offset)
                        .ok_or_else(|| io::Error::other("UFFD address overflow"))?;
                    let len = usize::try_from(range.len)
                        .map_err(|_| io::Error::other("UFFD range is too large"))?;

                    // SAFETY: the range is checked against the VMA metadata sent in
                    // the handshake and the received file descriptor remains valid.
                    let mapped = unsafe {
                        libc::mmap(
                            target_addr as *mut libc::c_void,
                            len,
                            region.prot,
                            region.flags | libc::MAP_FIXED,
                            fd.as_raw_fd(),
                            range.blob_offset as libc::off_t,
                        )
                    };
                    if mapped == libc::MAP_FAILED {
                        // If a large number of mappings exhausts the process VMA
                        // limit, this can later fall back to UFFDIO_COPY.
                        return Err(io::Error::last_os_error());
                    }
                    self.wake(target_addr, range.len)?;
                }
                Ok(true)
            }
        }
    }

    fn wake(&self, addr: u64, len: u64) -> io::Result<()> {
        let mut range = UffdioRange { start: addr, len };
        // SAFETY: range is valid for the UFFDIO_WAKE ioctl.
        if unsafe {
            libc::ioctl(
                self.uffd.as_raw_fd(),
                UFFDIO_WAKE as libc::Ioctl,
                &mut range,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn socket_fd(&self) -> RawFd {
        self.block.socket_fd()
    }

    fn shutdown(&self) {
        // SAFETY: block owns a valid socket for the duration of this call.
        unsafe { libc::shutdown(self.block.socket_fd(), libc::SHUT_RDWR) };
    }
}

#[derive(Copy, Clone, Debug, Default, Serialize, Deserialize)]
#[repr(C)]
struct VirtioPmemConfig {
    start: u64,
    size: u64,
}

// SAFETY: it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioPmemConfig {}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
struct VirtioPmemReq {
    type_: u32,
}

// SAFETY: it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioPmemReq {}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
struct VirtioPmemResp {
    ret: u32,
}

// SAFETY: it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioPmemResp {}

#[derive(Error, Debug)]
enum Error {
    #[error("Bad guest memory addresses")]
    GuestMemory(#[source] GuestMemoryError),
    #[error("Unexpected write-only descriptor")]
    UnexpectedWriteOnlyDescriptor,
    #[error("Unexpected read-only descriptor")]
    UnexpectedReadOnlyDescriptor,
    #[error("Descriptor chain too short")]
    DescriptorChainTooShort,
    #[error("Buffer length too small")]
    BufferLengthTooSmall,
    #[error("Invalid request")]
    InvalidRequest,
    #[error("Failed adding used index")]
    QueueAddUsed(#[source] virtio_queue::Error),
}

#[derive(Debug, PartialEq, Eq)]
enum RequestType {
    Flush,
    Unknown(u32),
}

struct Request {
    type_: RequestType,
    status_addr: GuestAddress,
}

impl Request {
    fn parse(
        desc_chain: &mut DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap>>,
        access_platform: Option<&dyn AccessPlatform>,
    ) -> result::Result<Request, Error> {
        let desc = desc_chain
            .next_checked(access_platform)
            .map_err(|addr| Error::GuestMemory(GuestMemoryError::InvalidGuestAddress(addr)))?
            .ok_or(Error::DescriptorChainTooShort)?;
        // The descriptor contains the request type which MUST be readable.
        if desc.is_write_only() {
            return Err(Error::UnexpectedWriteOnlyDescriptor);
        }

        if (desc.len() as usize) < size_of::<VirtioPmemReq>() {
            return Err(Error::InvalidRequest);
        }

        let request: VirtioPmemReq = desc_chain
            .memory()
            .read_obj(desc.addr())
            .map_err(Error::GuestMemory)?;

        let request_type = match request.type_ {
            VIRTIO_PMEM_REQ_TYPE_FLUSH => RequestType::Flush,
            t => RequestType::Unknown(t),
        };

        let status_desc = desc_chain
            .next_checked(access_platform)
            .map_err(|addr| Error::GuestMemory(GuestMemoryError::InvalidGuestAddress(addr)))?
            .ok_or(Error::DescriptorChainTooShort)?;

        // The status MUST always be writable
        if !status_desc.is_write_only() {
            return Err(Error::UnexpectedReadOnlyDescriptor);
        }

        if (status_desc.len() as usize) < size_of::<VirtioPmemResp>() {
            return Err(Error::BufferLengthTooSmall);
        }

        Ok(Request {
            type_: request_type,
            status_addr: status_desc.addr(),
        })
    }
}

struct PmemEpollHandler {
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
    queue: Queue,
    disk: File,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    queue_evt: EventFd,
    kill_evt: EventFd,
    pause_evt: EventFd,
    access_platform: Option<Arc<dyn AccessPlatform>>,
    uffd: Option<Arc<MmapUffdHandler>>,
    shutting_down: Arc<AtomicBool>,
}

impl PmemEpollHandler {
    fn process_queue(&mut self) -> result::Result<bool, Error> {
        let mut used_descs = false;
        while let Some(mut desc_chain) = self.queue.pop_descriptor_chain(self.mem.memory()) {
            let len = match Request::parse(&mut desc_chain, self.access_platform.as_deref()) {
                Ok(ref req) => {
                    let status_code = match req.type_ {
                        RequestType::Flush => match self.disk.sync_all() {
                            Ok(()) => VIRTIO_PMEM_RESP_TYPE_OK,
                            Err(e) => {
                                error!("Failed flushing disk image: {e}");
                                VIRTIO_PMEM_RESP_TYPE_EIO
                            }
                        },
                        RequestType::Unknown(t) => {
                            warn!("Unknown request type: {t}");
                            VIRTIO_PMEM_RESP_TYPE_EIO
                        }
                    };

                    let resp = VirtioPmemResp { ret: status_code };
                    match desc_chain.memory().write_obj(resp, req.status_addr) {
                        Ok(_) => size_of::<VirtioPmemResp>() as u32,
                        Err(e) => {
                            error!("bad guest memory address: {e}");
                            0
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to parse available descriptor chain: {e:?}");
                    0
                }
            };

            self.queue
                .add_used(desc_chain.memory(), desc_chain.head_index(), len)
                .map_err(Error::QueueAddUsed)?;
            used_descs = true;
        }

        Ok(used_descs)
    }

    fn signal_used_queue(&self) -> result::Result<(), DeviceError> {
        self.interrupt_cb
            .trigger(VirtioInterruptType::Queue(0))
            .map_err(|e| {
                error!("Failed to signal used queue: {e:?}");
                DeviceError::FailedSignalingUsedQueue(e)
            })
    }

    fn run(
        &mut self,
        paused: &AtomicBool,
        paused_sync: &Barrier,
    ) -> result::Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;
        helper.add_event(self.queue_evt.as_raw_fd(), QUEUE_AVAIL_EVENT)?;
        if let Some(uffd) = self.uffd.as_ref() {
            helper.add_event_custom(
                uffd.socket_fd(),
                UFFD_EVENT,
                epoll::Events::EPOLLIN | epoll::Events::EPOLLHUP,
            )?;
        }
        helper.run(paused, paused_sync, self)?;

        Ok(())
    }
}

impl EpollHelperHandler for PmemEpollHandler {
    fn handle_event(
        &mut self,
        _helper: &mut EpollHelper,
        event: &epoll::Event,
    ) -> result::Result<(), EpollHelperError> {
        let ev_type = event.data as u16;
        match ev_type {
            QUEUE_AVAIL_EVENT => {
                self.queue_evt.read().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!("Failed to get queue event: {e:?}"))
                })?;

                let needs_notification = self.process_queue().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!("Failed to process queue : {e:?}"))
                })?;

                if needs_notification {
                    self.signal_used_queue().map_err(|e| {
                        EpollHelperError::HandleEvent(anyhow!("Failed to signal used queue: {e:?}"))
                    })?;
                }
            }
            UFFD_EVENT => {
                if event.events & epoll::Events::EPOLLIN.bits() == 0 {
                    if self.shutting_down.load(Ordering::Acquire) {
                        return Ok(());
                    }
                    return Err(EpollHelperError::HandleEvent(anyhow!(
                        "UFFD server closed the socket"
                    )));
                }
                let uffd = self.uffd.as_ref().ok_or_else(|| {
                    EpollHelperError::HandleEvent(anyhow!(
                        "UFFD event without a configured handler"
                    ))
                })?;
                loop {
                    let handled = match uffd.handle_event() {
                        Ok(handled) => handled,
                        Err(_) if self.shutting_down.load(Ordering::Acquire) => return Ok(()),
                        Err(error) => {
                            return Err(EpollHelperError::HandleEvent(anyhow!(error)));
                        }
                    };
                    if !handled {
                        break;
                    }
                }
            }
            _ => {
                return Err(EpollHelperError::HandleEvent(anyhow!(
                    "Unexpected event: {ev_type}"
                )));
            }
        }
        Ok(())
    }
}

pub struct Pmem {
    common: VirtioCommon,
    id: String,
    disk: Option<File>,
    config: VirtioPmemConfig,
    uffd: Option<Arc<MmapUffdHandler>>,
    shutting_down: Arc<AtomicBool>,
    mapping: UserspaceMapping,
    seccomp_action: SeccompAction,
    exit_evt: EventFd,
}

#[derive(Serialize, Deserialize)]
pub struct PmemState {
    avail_features: u64,
    acked_features: u64,
    config: VirtioPmemConfig,
}

impl Pmem {
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        disk: File,
        addr: GuestAddress,
        mapping: UserspaceMapping,
        access_platform_enabled: bool,
        uffd: Option<Arc<MmapUffdHandler>>,
        seccomp_action: SeccompAction,
        exit_evt: EventFd,
        state: Option<PmemState>,
    ) -> io::Result<Pmem> {
        let (avail_features, acked_features, config, paused) = if let Some(state) = state {
            info!("Restoring virtio-pmem {id}");
            (
                state.avail_features,
                state.acked_features,
                state.config,
                true,
            )
        } else {
            let config = VirtioPmemConfig {
                start: addr.raw_value().to_le(),
                size: (mapping.mapping.size() as u64).to_le(),
            };

            let mut avail_features = 1u64 << VIRTIO_F_VERSION_1;

            if access_platform_enabled {
                avail_features |= 1u64 << VIRTIO_F_ACCESS_PLATFORM;
            }
            (avail_features, 0, config, false)
        };

        Ok(Pmem {
            common: VirtioCommon {
                device_type: VirtioDeviceType::Pmem as u32,
                queue_sizes: QUEUE_SIZES.to_vec(),
                paused_sync: Some(Arc::new(Barrier::new(2))),
                avail_features,
                acked_features,
                min_queues: 1,
                paused: Arc::new(AtomicBool::new(paused)),
                ..Default::default()
            },
            id,
            disk: Some(disk),
            config,
            uffd,
            shutting_down: Arc::new(AtomicBool::new(false)),
            mapping,
            seccomp_action,
            exit_evt,
        })
    }

    fn state(&self) -> PmemState {
        PmemState {
            avail_features: self.common.avail_features,
            acked_features: self.common.acked_features,
            config: self.config,
        }
    }

    #[cfg(fuzzing)]
    pub fn wait_for_epoll_threads(&mut self) {
        self.common.wait_for_epoll_threads();
    }
}

impl Drop for Pmem {
    fn drop(&mut self) {
        if let Some(uffd) = self.uffd.as_ref() {
            self.shutting_down.store(true, Ordering::Release);
            if let Some(workers) = self.common.workers.as_ref() {
                workers.signal_exit().ok();
            }
            uffd.shutdown();
        }
        self.common.wait_for_epoll_threads();
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
        self.common.ack_features(value);
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        self.read_config_from_slice(self.config.as_slice(), offset, data);
    }

    fn activate(&mut self, context: ActivationContext) -> ActivateResult {
        let ActivationContext {
            mem,
            interrupt_cb,
            mut queues,
            device_status,
        } = context;
        self.common.activate(&queues, interrupt_cb.clone())?;
        let (kill_evt, pause_evt) = self.common.dup_eventfds()?;
        if let Some(disk) = self.disk.as_ref() {
            let disk = disk.try_clone().map_err(|e| {
                error!("failed cloning pmem disk: {e}");
                ActivateError::BadActivate
            })?;

            let (_, queue, queue_evt) = queues.remove(0);

            let mut handler = PmemEpollHandler {
                mem,
                queue,
                disk,
                interrupt_cb: interrupt_cb.clone(),
                queue_evt,
                kill_evt,
                pause_evt,
                access_platform: self.common.access_platform(),
                uffd: self.uffd.clone(),
                shutting_down: Arc::clone(&self.shutting_down),
            };

            let paused = self.common.paused.clone();
            let paused_sync = self.common.paused_sync.clone();

            let thread_type = if self.uffd.is_some() {
                Thread::VirtioPmemUffd
            } else {
                Thread::VirtioPmem
            };
            self.common.spawn_worker(
                &self.id,
                &self.seccomp_action,
                thread_type,
                &self.exit_evt,
                device_status.clone(),
                interrupt_cb.clone(),
                move || handler.run(&paused, paused_sync.as_ref().unwrap()),
            )?;

            event!("virtio-device", "activated", "id", &self.id);
            return Ok(());
        }
        Err(ActivateError::BadActivate)
    }

    fn reset(&mut self) {
        self.common.reset();
        event!("virtio-device", "reset", "id", &self.id);
    }

    fn userspace_mappings(&self) -> Vec<UserspaceMapping> {
        vec![self.mapping.clone()]
    }

    fn set_access_platform(&mut self, access_platform: Arc<dyn AccessPlatform>) {
        self.common.set_access_platform(access_platform);
    }

    fn access_platform(&self) -> Option<Arc<dyn AccessPlatform>> {
        self.common.access_platform()
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

    fn snapshot(&mut self) -> result::Result<Snapshot, MigratableError> {
        Snapshot::new_from_state(&self.state())
    }
}

impl Transportable for Pmem {}
impl Migratable for Pmem {}
