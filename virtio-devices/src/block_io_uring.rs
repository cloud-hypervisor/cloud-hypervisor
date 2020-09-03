// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use super::Error as DeviceError;
use super::{
    ActivateError, ActivateResult, EpollHelper, EpollHelperError, EpollHelperHandler, Queue,
    VirtioCommon, VirtioDevice, VirtioDeviceType, VirtioInterruptType, EPOLL_HELPER_EVENT_LAST,
};
use crate::VirtioInterrupt;
use anyhow::anyhow;
use block_util::{build_disk_image_id, Request, RequestType, VirtioBlockConfig};
use io_uring::IoUring;
use libc::EFD_NONBLOCK;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Seek, SeekFrom};
use std::num::Wrapping;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::PathBuf;
use std::result;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use virtio_bindings::bindings::virtio_blk::*;
use vm_memory::{
    ByteValued, Bytes, GuestAddress, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryError,
    GuestMemoryMmap,
};
use vm_migration::{
    Migratable, MigratableError, Pausable, Snapshot, SnapshotDataSection, Snapshottable,
    Transportable,
};
use vmm_sys_util::eventfd::EventFd;

const SECTOR_SHIFT: u8 = 9;
pub const SECTOR_SIZE: u64 = (0x01 as u64) << SECTOR_SHIFT;

// New descriptors are pending on the virtio queue.
const QUEUE_AVAIL_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;
// New completed tasks are pending on the completion ring.
const IO_URING_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 2;

#[derive(Debug)]
pub enum Error {
    /// Guest gave us bad memory addresses.
    GuestMemory(GuestMemoryError),
    /// Guest gave us offsets that would have overflowed a usize.
    CheckedOffset(GuestAddress, usize),
    /// Guest gave us a write only descriptor that protocol says to read from.
    UnexpectedWriteOnlyDescriptor,
    /// Guest gave us a read only descriptor that protocol says to write to.
    UnexpectedReadOnlyDescriptor,
    /// Guest gave us too few descriptors in a descriptor chain.
    DescriptorChainTooShort,
    /// Guest gave us a descriptor that was too short to use.
    DescriptorLengthTooSmall,
    /// Getting a block's metadata fails for any reason.
    GetFileMetadata,
    /// The requested operation would cause a seek beyond disk end.
    InvalidOffset,
    /// Unsupported operation on the disk.
    Unsupported(u32),
    /// Failed to parse the request.
    RequestParsing(block_util::Error),
    /// Failed to execute the request.
    RequestExecuting(block_util::ExecuteError),
    /// Missing the expected entry in the list of requests.
    MissingEntryRequestList,
    /// The asynchronous request returned with failure.
    AsyncRequestFailure,
}

pub type Result<T> = result::Result<T, Error>;

#[derive(Default, Clone)]
pub struct BlockCounters {
    read_bytes: Arc<AtomicU64>,
    read_ops: Arc<AtomicU64>,
    write_bytes: Arc<AtomicU64>,
    write_ops: Arc<AtomicU64>,
}

struct BlockIoUringEpollHandler {
    queue: Queue,
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
    disk_image_fd: RawFd,
    disk_nsectors: u64,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    disk_image_id: Vec<u8>,
    kill_evt: EventFd,
    pause_evt: EventFd,
    writeback: Arc<AtomicBool>,
    counters: BlockCounters,
    queue_evt: EventFd,
    io_uring: IoUring,
    io_uring_evt: EventFd,
    request_list: HashMap<u16, Request>,
}

impl BlockIoUringEpollHandler {
    fn process_queue_submit(&mut self) -> Result<bool> {
        let queue = &mut self.queue;
        let mem = self.mem.memory();

        let mut used_desc_heads = Vec::new();
        let mut used_count = 0;

        for avail_desc in queue.iter(&mem) {
            let mut request = Request::parse(&avail_desc, &mem).map_err(Error::RequestParsing)?;
            request.set_writeback(self.writeback.load(Ordering::SeqCst));
            if request
                .execute_io_uring(
                    &mem,
                    &mut self.io_uring,
                    self.disk_nsectors,
                    self.disk_image_fd,
                    &self.disk_image_id,
                    avail_desc.index as u64,
                )
                .map_err(Error::RequestExecuting)?
            {
                self.request_list.insert(avail_desc.index, request);
            } else {
                // We use unwrap because the request parsing process already
                // checked that the status_addr was valid.
                mem.write_obj(VIRTIO_BLK_S_OK, request.status_addr).unwrap();

                // If no asynchronous operation has been submitted, we can
                // simply return the used descriptor.
                used_desc_heads.push((avail_desc.index, 0));
                used_count += 1;
            }
        }

        for &(desc_index, len) in used_desc_heads.iter() {
            queue.add_used(&mem, desc_index, len);
        }

        Ok(used_count > 0)
    }

    fn process_queue_complete(&mut self) -> Result<bool> {
        let queue = &mut self.queue;

        let mut used_desc_heads = Vec::new();
        let mut used_count = 0;
        let mem = self.mem.memory();
        let mut read_bytes = Wrapping(0);
        let mut write_bytes = Wrapping(0);
        let mut read_ops = Wrapping(0);
        let mut write_ops = Wrapping(0);

        let cq = self.io_uring.completion();
        for cq_entry in cq.available() {
            let result = cq_entry.result();
            let desc_index = cq_entry.user_data() as u16;
            let request = self
                .request_list
                .remove(&desc_index)
                .ok_or(Error::MissingEntryRequestList)?;

            let (status, len) = if result >= 0 {
                match request.request_type {
                    RequestType::In => {
                        read_bytes += Wrapping(request.data_len as u64);
                        read_ops += Wrapping(1);
                    }
                    RequestType::Out => {
                        if !request.writeback {
                            unsafe { libc::fsync(self.disk_image_fd) };
                        }
                        write_bytes += Wrapping(request.data_len as u64);
                        write_ops += Wrapping(1);
                    }
                    _ => {}
                }

                (VIRTIO_BLK_S_OK, result as u32)
            } else {
                error!(
                    "Request failed: {:?}",
                    io::Error::from_raw_os_error(-result)
                );
                return Err(Error::AsyncRequestFailure);
            };

            // We use unwrap because the request parsing process already
            // checked that the status_addr was valid.
            mem.write_obj(status, request.status_addr).unwrap();

            used_desc_heads.push((desc_index, len));
            used_count += 1;
        }

        for &(desc_index, len) in used_desc_heads.iter() {
            queue.add_used(&mem, desc_index, len);
        }

        self.counters
            .write_bytes
            .fetch_add(write_bytes.0, Ordering::AcqRel);
        self.counters
            .write_ops
            .fetch_add(write_ops.0, Ordering::AcqRel);

        self.counters
            .read_bytes
            .fetch_add(read_bytes.0, Ordering::AcqRel);
        self.counters
            .read_ops
            .fetch_add(read_ops.0, Ordering::AcqRel);

        Ok(used_count > 0)
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
        helper.add_event(self.io_uring_evt.as_raw_fd(), IO_URING_EVENT)?;
        helper.run(paused, paused_sync, self)?;

        Ok(())
    }
}

impl EpollHelperHandler for BlockIoUringEpollHandler {
    fn handle_event(&mut self, _helper: &mut EpollHelper, event: &epoll::Event) -> bool {
        let ev_type = event.data as u16;
        match ev_type {
            QUEUE_AVAIL_EVENT => {
                if let Err(e) = self.queue_evt.read() {
                    error!("Failed to get queue event: {:?}", e);
                    return true;
                }

                match self.process_queue_submit() {
                    Ok(needs_notification) => {
                        if needs_notification {
                            if let Err(e) = self.signal_used_queue() {
                                error!("Failed to signal used queue: {:?}", e);
                                return true;
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to process queue (submit): {:?}", e);
                        return true;
                    }
                }
            }
            IO_URING_EVENT => {
                if let Err(e) = self.io_uring_evt.read() {
                    error!("Failed to get queue event: {:?}", e);
                    return true;
                }

                match self.process_queue_complete() {
                    Ok(needs_notification) => {
                        if needs_notification {
                            if let Err(e) = self.signal_used_queue() {
                                error!("Failed to signal used queue: {:?}", e);
                                return true;
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to process queue (complete): {:?}", e);
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

/// Virtio device for exposing block level read/write operations on a host file.
pub struct BlockIoUring {
    common: VirtioCommon,
    id: String,
    kill_evt: Option<EventFd>,
    disk_image: File,
    disk_path: PathBuf,
    disk_nsectors: u64,
    config: VirtioBlockConfig,
    queue_evts: Option<Vec<EventFd>>,
    interrupt_cb: Option<Arc<dyn VirtioInterrupt>>,
    epoll_threads: Option<Vec<thread::JoinHandle<()>>>,
    pause_evt: Option<EventFd>,
    paused: Arc<AtomicBool>,
    paused_sync: Arc<Barrier>,
    queue_size: Vec<u16>,
    writeback: Arc<AtomicBool>,
    counters: BlockCounters,
}

#[derive(Serialize, Deserialize)]
pub struct BlockState {
    pub disk_path: PathBuf,
    pub disk_nsectors: u64,
    pub avail_features: u64,
    pub acked_features: u64,
    pub config: VirtioBlockConfig,
}

impl BlockIoUring {
    /// Create a new virtio block device that operates on the given file.
    pub fn new(
        id: String,
        mut disk_image: File,
        disk_path: PathBuf,
        is_disk_read_only: bool,
        iommu: bool,
        num_queues: usize,
        queue_size: u16,
    ) -> io::Result<Self> {
        let disk_size = disk_image.seek(SeekFrom::End(0))? as u64;
        if disk_size % SECTOR_SIZE != 0 {
            warn!(
                "Disk size {} is not a multiple of sector size {}; \
                 the remainder will not be visible to the guest.",
                disk_size, SECTOR_SIZE
            );
        }

        let mut avail_features = (1u64 << VIRTIO_F_VERSION_1)
            | (1u64 << VIRTIO_BLK_F_FLUSH)
            | (1u64 << VIRTIO_BLK_F_CONFIG_WCE);

        if iommu {
            avail_features |= 1u64 << VIRTIO_F_IOMMU_PLATFORM;
        }

        if is_disk_read_only {
            avail_features |= 1u64 << VIRTIO_BLK_F_RO;
        }

        let disk_nsectors = disk_size / SECTOR_SIZE;
        let mut config = VirtioBlockConfig {
            capacity: disk_nsectors,
            writeback: 1,
            ..Default::default()
        };

        if num_queues > 1 {
            avail_features |= 1u64 << VIRTIO_BLK_F_MQ;
            config.num_queues = num_queues as u16;
        }

        Ok(BlockIoUring {
            common: VirtioCommon {
                avail_features,
                ..Default::default()
            },
            id,
            kill_evt: None,
            disk_image,
            disk_path,
            disk_nsectors,
            config,
            queue_evts: None,
            interrupt_cb: None,
            epoll_threads: None,
            pause_evt: None,
            paused: Arc::new(AtomicBool::new(false)),
            paused_sync: Arc::new(Barrier::new(num_queues + 1)),
            queue_size: vec![queue_size; num_queues],
            writeback: Arc::new(AtomicBool::new(true)),
            counters: BlockCounters::default(),
        })
    }

    fn state(&self) -> BlockState {
        BlockState {
            disk_path: self.disk_path.clone(),
            disk_nsectors: self.disk_nsectors,
            avail_features: self.common.avail_features,
            acked_features: self.common.acked_features,
            config: self.config,
        }
    }

    fn set_state(&mut self, state: &BlockState) -> io::Result<()> {
        self.disk_path = state.disk_path.clone();
        self.disk_nsectors = state.disk_nsectors;
        self.common.avail_features = state.avail_features;
        self.common.acked_features = state.acked_features;
        self.config = state.config;

        Ok(())
    }

    fn update_writeback(&mut self) {
        // Use writeback from config if VIRTIO_BLK_F_CONFIG_WCE
        let writeback = if self.common.feature_acked(VIRTIO_BLK_F_CONFIG_WCE.into()) {
            self.config.writeback == 1
        } else {
            // Else check if VIRTIO_BLK_F_FLUSH negotiated
            self.common.feature_acked(VIRTIO_BLK_F_FLUSH.into())
        };

        info!(
            "Changing cache mode to {}",
            if writeback {
                "writeback"
            } else {
                "writethrough"
            }
        );
        self.writeback.store(writeback, Ordering::SeqCst);
    }
}

impl Drop for BlockIoUring {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
    }
}

impl VirtioDevice for BlockIoUring {
    fn device_type(&self) -> u32 {
        VirtioDeviceType::TYPE_BLOCK as u32
    }

    fn queue_max_sizes(&self) -> &[u16] {
        self.queue_size.as_slice()
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

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        // The "writeback" field is the only mutable field
        let writeback_offset =
            (&self.config.writeback as *const _ as u64) - (&self.config as *const _ as u64);
        if offset != writeback_offset || data.len() != std::mem::size_of_val(&self.config.writeback)
        {
            error!(
                "Attempt to write to read-only field: offset {:x} length {}",
                offset,
                data.len()
            );
            return;
        }

        self.config.writeback = data[0];
        self.update_writeback();
    }

    fn activate(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        interrupt_cb: Arc<dyn VirtioInterrupt>,
        mut queues: Vec<Queue>,
        mut queue_evts: Vec<EventFd>,
    ) -> ActivateResult {
        if queues.len() != self.queue_size.len() || queue_evts.len() != self.queue_size.len() {
            error!(
                "Cannot perform activate. Expected {} queue(s), got {}",
                self.queue_size.len(),
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

        let disk_image_id = build_disk_image_id(&self.disk_path);

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

        self.update_writeback();

        let mut epoll_threads = Vec::new();
        for i in 0..self.queue_size.len() {
            let queue_size = self.queue_size[i] as usize;
            let queue_evt = queue_evts.remove(0);
            let io_uring = IoUring::new(queue_size as u32).map_err(|e| {
                error!("failed to create io_uring instance: {}", e);
                ActivateError::BadActivate
            })?;
            let mut handler = BlockIoUringEpollHandler {
                queue: queues.remove(0),
                mem: mem.clone(),
                disk_image_fd: self.disk_image.as_raw_fd(),
                disk_nsectors: self.disk_nsectors,
                interrupt_cb: interrupt_cb.clone(),
                disk_image_id: disk_image_id.clone(),
                kill_evt: kill_evt.try_clone().map_err(|e| {
                    error!("failed to clone kill_evt eventfd: {}", e);
                    ActivateError::BadActivate
                })?,
                pause_evt: pause_evt.try_clone().map_err(|e| {
                    error!("failed to clone pause_evt eventfd: {}", e);
                    ActivateError::BadActivate
                })?,
                writeback: self.writeback.clone(),
                counters: self.counters.clone(),
                queue_evt,
                io_uring,
                io_uring_evt: EventFd::new(EFD_NONBLOCK).map_err(|e| {
                    error!("failed to create io_uring eventfd: {}", e);
                    ActivateError::BadActivate
                })?,
                request_list: HashMap::with_capacity(queue_size),
            };

            let paused = self.paused.clone();
            let paused_sync = self.paused_sync.clone();

            // Register the io_uring eventfd that will notify the epoll loop
            // when something in the completion queue is ready.
            handler
                .io_uring
                .submitter()
                .register_eventfd(handler.io_uring_evt.as_raw_fd())
                .map_err(|e| {
                    error!("failed to register eventfd for io_uring: {}", e);
                    ActivateError::BadActivate
                })?;

            thread::Builder::new()
                .name("virtio_blk".to_string())
                .spawn(move || {
                    if let Err(e) = handler.run(paused, paused_sync) {
                        error!("Error running worker: {:?}", e);
                    }
                })
                .map(|thread| epoll_threads.push(thread))
                .map_err(|e| {
                    error!("failed to clone the virtio-blk epoll thread: {}", e);
                    ActivateError::BadActivate
                })?;
        }

        // Save the interrupt EventFD as we need to return it on reset
        // but clone it to pass into the thread.
        self.interrupt_cb = Some(interrupt_cb);

        self.epoll_threads = Some(epoll_threads);

        Ok(())
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

    fn counters(&self) -> Option<HashMap<&'static str, Wrapping<u64>>> {
        let mut counters = HashMap::new();

        counters.insert(
            "read_bytes",
            Wrapping(self.counters.read_bytes.load(Ordering::Acquire)),
        );
        counters.insert(
            "write_bytes",
            Wrapping(self.counters.write_bytes.load(Ordering::Acquire)),
        );
        counters.insert(
            "read_ops",
            Wrapping(self.counters.read_ops.load(Ordering::Acquire)),
        );
        counters.insert(
            "write_ops",
            Wrapping(self.counters.write_ops.load(Ordering::Acquire)),
        );

        Some(counters)
    }
}

virtio_pausable!(BlockIoUring);
impl Snapshottable for BlockIoUring {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        let snapshot =
            serde_json::to_vec(&self.state()).map_err(|e| MigratableError::Snapshot(e.into()))?;

        let mut block_snapshot = Snapshot::new(self.id.as_str());
        block_snapshot.add_data_section(SnapshotDataSection {
            id: format!("{}-section", self.id),
            snapshot,
        });

        Ok(block_snapshot)
    }

    fn restore(&mut self, snapshot: Snapshot) -> std::result::Result<(), MigratableError> {
        if let Some(block_section) = snapshot.snapshot_data.get(&format!("{}-section", self.id)) {
            let block_state = match serde_json::from_slice(&block_section.snapshot) {
                Ok(state) => state,
                Err(error) => {
                    return Err(MigratableError::Restore(anyhow!(
                        "Could not deserialize BLOCK {}",
                        error
                    )))
                }
            };

            return self.set_state(&block_state).map_err(|e| {
                MigratableError::Restore(anyhow!("Could not restore BLOCK state {:?}", e))
            });
        }

        Err(MigratableError::Restore(anyhow!(
            "Could not find BLOCK snapshot section"
        )))
    }
}
impl Transportable for BlockIoUring {}
impl Migratable for BlockIoUring {}
