// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use super::Error as DeviceError;
use super::{
    ActivateError, ActivateResult, DescriptorChain, DeviceEventT, Queue, VirtioDevice,
    VirtioDeviceType, VIRTIO_F_IOMMU_PLATFORM, VIRTIO_F_VERSION_1,
};
use crate::{VirtioInterrupt, VirtioInterruptType};
use epoll;
use libc::EFD_NONBLOCK;
use std::cmp;
use std::fmt::{self, Display};
use std::fs::File;
use std::io::{self, Write};
use std::mem::size_of;
use std::os::unix::io::AsRawFd;
use std::result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use vm_memory::{
    Address, ByteValued, Bytes, GuestAddress, GuestAddressSpace, GuestMemoryAtomic,
    GuestMemoryError, GuestMemoryMmap, GuestUsize,
};
use vm_migration::{Migratable, MigratableError, Pausable, Snapshottable, Transportable};
use vmm_sys_util::eventfd::EventFd;

const QUEUE_SIZE: u16 = 256;
const NUM_QUEUES: usize = 1;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE];

const VIRTIO_PMEM_REQ_TYPE_FLUSH: u32 = 0;
const VIRTIO_PMEM_RESP_TYPE_OK: u32 = 0;
const VIRTIO_PMEM_RESP_TYPE_EIO: u32 = 1;

// New descriptors are pending on the virtio queue.
const QUEUE_AVAIL_EVENT: DeviceEventT = 0;
// The device has been dropped.
const KILL_EVENT: DeviceEventT = 1;
// The device should be paused.
const PAUSE_EVENT: DeviceEventT = 2;

#[derive(Copy, Clone, Debug, Default)]
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

    fn run(&mut self, paused: Arc<AtomicBool>) -> result::Result<(), DeviceError> {
        // Create the epoll file descriptor
        let epoll_fd = epoll::create(true).map_err(DeviceError::EpollCreateFd)?;

        // Add events
        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            self.queue_evt.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, u64::from(QUEUE_AVAIL_EVENT)),
        )
        .map_err(DeviceError::EpollCtl)?;
        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            self.kill_evt.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, u64::from(KILL_EVENT)),
        )
        .map_err(DeviceError::EpollCtl)?;

        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            self.pause_evt.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, u64::from(PAUSE_EVENT)),
        )
        .map_err(DeviceError::EpollCtl)?;

        const EPOLL_EVENTS_LEN: usize = 100;
        let mut events = vec![epoll::Event::new(epoll::Events::empty(), 0); EPOLL_EVENTS_LEN];

        'epoll: loop {
            let num_events = match epoll::wait(epoll_fd, -1, &mut events[..]) {
                Ok(res) => res,
                Err(e) => {
                    if e.kind() == io::ErrorKind::Interrupted {
                        // It's well defined from the epoll_wait() syscall
                        // documentation that the epoll loop can be interrupted
                        // before any of the requested events occurred or the
                        // timeout expired. In both those cases, epoll_wait()
                        // returns an error of type EINTR, but this should not
                        // be considered as a regular error. Instead it is more
                        // appropriate to retry, by calling into epoll_wait().
                        continue;
                    }
                    return Err(DeviceError::EpollWait(e));
                }
            };

            for event in events.iter().take(num_events) {
                let ev_type = event.data as u16;

                match ev_type {
                    QUEUE_AVAIL_EVENT => {
                        if let Err(e) = self.queue_evt.read() {
                            error!("Failed to get queue event: {:?}", e);
                            break 'epoll;
                        } else if self.process_queue() {
                            if let Err(e) = self.signal_used_queue() {
                                error!("Failed to signal used queue: {:?}", e);
                                break 'epoll;
                            }
                        }
                    }
                    KILL_EVENT => {
                        debug!("kill_evt received, stopping epoll loop");
                        break 'epoll;
                    }
                    PAUSE_EVENT => {
                        // Drain pause event
                        let _ = self.pause_evt.read();
                        debug!("PAUSE_EVENT received, pausing virtio-pmem epoll loop");
                        // We loop here to handle spurious park() returns.
                        // Until we have not resumed, the paused boolean will
                        // be true.
                        while paused.load(Ordering::SeqCst) {
                            thread::park();
                        }
                    }
                    _ => {
                        error!("Unknown event for virtio-block");
                    }
                }
            }
        }

        Ok(())
    }
}

pub struct Pmem {
    kill_evt: Option<EventFd>,
    pause_evt: Option<EventFd>,
    disk: Option<File>,
    avail_features: u64,
    acked_features: u64,
    config: VirtioPmemConfig,
    queue_evts: Option<Vec<EventFd>>,
    interrupt_cb: Option<Arc<dyn VirtioInterrupt>>,
    epoll_threads: Option<Vec<thread::JoinHandle<result::Result<(), DeviceError>>>>,
    paused: Arc<AtomicBool>,
}

impl Pmem {
    pub fn new(disk: File, addr: GuestAddress, size: GuestUsize, iommu: bool) -> io::Result<Pmem> {
        let config = VirtioPmemConfig {
            start: addr.raw_value().to_le(),
            size: size.to_le(),
        };

        let mut avail_features = 1u64 << VIRTIO_F_VERSION_1;

        if iommu {
            avail_features |= 1u64 << VIRTIO_F_IOMMU_PLATFORM;
        }

        Ok(Pmem {
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
        })
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

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_slice = self.config.as_slice();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }

        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&config_slice[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        warn!("virtio-pmem device configuration is read-only");
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
            thread::Builder::new()
                .name("virtio_pmem".to_string())
                .spawn(move || handler.run(paused))
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
}

virtio_pausable!(Pmem);
impl Snapshottable for Pmem {}
impl Transportable for Pmem {}
impl Migratable for Pmem {}
