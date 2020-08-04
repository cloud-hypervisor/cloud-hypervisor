// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use super::Error as DeviceError;
use super::{
    ActivateError, ActivateResult, EpollHelper, EpollHelperError, EpollHelperHandler, Queue,
    VirtioDevice, VirtioDeviceType, VirtioInterruptType, EPOLL_HELPER_EVENT_LAST,
};
use crate::seccomp_filters::{get_seccomp_filter, Thread};
use crate::VirtioInterrupt;
use anyhow::anyhow;
use block_util::{build_disk_image_id, Request, RequestType, VirtioBlockConfig};
use libc::EFD_NONBLOCK;
use seccomp::{SeccompAction, SeccompFilter};
use std::collections::HashMap;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::num::Wrapping;
use std::ops::DerefMut;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::result;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use virtio_bindings::bindings::virtio_blk::*;
use virtio_bindings::bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
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
}

pub trait DiskFile: Read + Seek + Write + Clone {}
impl<D: Read + Seek + Write + Clone> DiskFile for D {}

#[derive(Default, Clone)]
pub struct BlockCounters {
    read_bytes: Arc<AtomicU64>,
    read_ops: Arc<AtomicU64>,
    write_bytes: Arc<AtomicU64>,
    write_ops: Arc<AtomicU64>,
}

struct BlockEpollHandler<T: DiskFile> {
    queue: Queue,
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
    disk_image: Arc<Mutex<T>>,
    disk_nsectors: u64,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    disk_image_id: Vec<u8>,
    kill_evt: EventFd,
    pause_evt: EventFd,
    event_idx: bool,
    writeback: Arc<AtomicBool>,
    counters: BlockCounters,
    queue_evt: EventFd,
}

impl<T: DiskFile> BlockEpollHandler<T> {
    fn process_queue(&mut self) -> bool {
        let queue = &mut self.queue;

        let mut used_desc_heads = Vec::new();
        let mut used_count = 0;
        let mem = self.mem.memory();
        let mut read_bytes = Wrapping(0);
        let mut write_bytes = Wrapping(0);
        let mut read_ops = Wrapping(0);
        let mut write_ops = Wrapping(0);

        for avail_desc in queue.iter(&mem) {
            let len;
            match Request::parse(&avail_desc, &mem) {
                Ok(mut request) => {
                    request.set_writeback(self.writeback.load(Ordering::SeqCst));

                    let mut disk_image_locked = self.disk_image.lock().unwrap();
                    let mut disk_image = disk_image_locked.deref_mut();
                    let status = match request.execute(
                        &mut disk_image,
                        self.disk_nsectors,
                        &mem,
                        &self.disk_image_id,
                    ) {
                        Ok(l) => {
                            len = l;
                            match request.request_type {
                                RequestType::In => {
                                    read_bytes += Wrapping(request.data_len as u64);
                                    read_ops += Wrapping(1);
                                }
                                RequestType::Out => {
                                    write_bytes += Wrapping(request.data_len as u64);
                                    write_ops += Wrapping(1);
                                }
                                _ => {}
                            };
                            VIRTIO_BLK_S_OK
                        }
                        Err(e) => {
                            error!("Failed to execute request: {:?}", e);
                            len = 1; // We need at least 1 byte for the status.
                            e.status()
                        }
                    };
                    // We use unwrap because the request parsing process already checked that the
                    // status_addr was valid.
                    mem.write_obj(status, request.status_addr).unwrap();
                }
                Err(e) => {
                    error!("Failed to parse available descriptor chain: {:?}", e);
                    len = 0;
                }
            }
            used_desc_heads.push((avail_desc.index, len));
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

    #[allow(dead_code)]
    fn update_disk_image(
        &mut self,
        mut disk_image: T,
        disk_path: &PathBuf,
    ) -> result::Result<(), DeviceError> {
        self.disk_nsectors = disk_image
            .seek(SeekFrom::End(0))
            .map_err(DeviceError::IoError)?
            / SECTOR_SIZE;
        self.disk_image_id = build_disk_image_id(disk_path);
        self.disk_image = Arc::new(Mutex::new(disk_image));
        Ok(())
    }

    fn run(&mut self, paused: Arc<AtomicBool>) -> result::Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;
        helper.add_event(self.queue_evt.as_raw_fd(), QUEUE_AVAIL_EVENT)?;
        helper.run(paused, self)?;

        Ok(())
    }
}

impl<T: DiskFile> EpollHelperHandler for BlockEpollHandler<T> {
    fn handle_event(&mut self, _helper: &mut EpollHelper, event: u16) -> bool {
        match event {
            QUEUE_AVAIL_EVENT => {
                if let Err(e) = self.queue_evt.read() {
                    error!("Failed to get queue event: {:?}", e);
                    return true;
                } else if self.event_idx {
                    // vm-virtio's Queue implementation only checks avail_index
                    // once, so to properly support EVENT_IDX we need to keep
                    // calling process_queue() until it stops finding new
                    // requests on the queue.
                    loop {
                        if self.process_queue() {
                            self.queue.update_avail_event(&self.mem.memory());

                            if self
                                .queue
                                .needs_notification(&self.mem.memory(), self.queue.next_used)
                            {
                                if let Err(e) = self.signal_used_queue() {
                                    error!("Failed to signal used queue: {:?}", e);
                                    return true;
                                }
                            }
                        } else {
                            break;
                        }
                    }
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

/// Virtio device for exposing block level read/write operations on a host file.
pub struct Block<T: DiskFile> {
    id: String,
    kill_evt: Option<EventFd>,
    disk_image: Arc<Mutex<T>>,
    disk_path: PathBuf,
    disk_nsectors: u64,
    avail_features: u64,
    acked_features: u64,
    config: VirtioBlockConfig,
    queue_evts: Option<Vec<EventFd>>,
    interrupt_cb: Option<Arc<dyn VirtioInterrupt>>,
    epoll_threads: Option<Vec<thread::JoinHandle<result::Result<(), EpollHelperError>>>>,
    pause_evt: Option<EventFd>,
    paused: Arc<AtomicBool>,
    queue_size: Vec<u16>,
    writeback: Arc<AtomicBool>,
    counters: BlockCounters,
    seccomp_action: SeccompAction,
}

#[derive(Serialize, Deserialize)]
pub struct BlockState {
    pub disk_path: PathBuf,
    pub disk_nsectors: u64,
    pub avail_features: u64,
    pub acked_features: u64,
    pub config: VirtioBlockConfig,
}

impl<T: DiskFile> Block<T> {
    /// Create a new virtio block device that operates on the given file.
    ///
    /// The given file must be seekable and sizable.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        mut disk_image: T,
        disk_path: PathBuf,
        is_disk_read_only: bool,
        iommu: bool,
        num_queues: usize,
        queue_size: u16,
        seccomp_action: SeccompAction,
    ) -> io::Result<Block<T>> {
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
            | (1u64 << VIRTIO_RING_F_EVENT_IDX)
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

        Ok(Block {
            id,
            kill_evt: None,
            disk_image: Arc::new(Mutex::new(disk_image)),
            disk_path,
            disk_nsectors,
            avail_features,
            acked_features: 0u64,
            config,
            queue_evts: None,
            interrupt_cb: None,
            epoll_threads: None,
            pause_evt: None,
            paused: Arc::new(AtomicBool::new(false)),
            queue_size: vec![queue_size; num_queues],
            writeback: Arc::new(AtomicBool::new(true)),
            counters: BlockCounters::default(),
            seccomp_action,
        })
    }

    fn state(&self) -> BlockState {
        BlockState {
            disk_path: self.disk_path.clone(),
            disk_nsectors: self.disk_nsectors,
            avail_features: self.avail_features,
            acked_features: self.acked_features,
            config: self.config,
        }
    }

    fn set_state(&mut self, state: &BlockState) -> io::Result<()> {
        self.disk_path = state.disk_path.clone();
        self.disk_nsectors = state.disk_nsectors;
        self.avail_features = state.avail_features;
        self.acked_features = state.acked_features;
        self.config = state.config;

        Ok(())
    }

    fn update_writeback(&mut self) {
        // Use writeback from config if VIRTIO_BLK_F_CONFIG_WCE
        let writeback =
            if self.acked_features & 1 << VIRTIO_BLK_F_CONFIG_WCE == 1 << VIRTIO_BLK_F_CONFIG_WCE {
                self.config.writeback == 1
            } else {
                // Else check if VIRTIO_BLK_F_FLUSH negotiated
                self.acked_features & 1 << VIRTIO_BLK_F_FLUSH == 1 << VIRTIO_BLK_F_FLUSH
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

impl<T: DiskFile> Drop for Block<T> {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
    }
}

impl<T: 'static + DiskFile + Send> VirtioDevice for Block<T> {
    fn device_type(&self) -> u32 {
        VirtioDeviceType::TYPE_BLOCK as u32
    }

    fn queue_max_sizes(&self) -> &[u16] {
        self.queue_size.as_slice()
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

        let event_idx = self.acked_features & 1u64 << VIRTIO_RING_F_EVENT_IDX
            == 1u64 << VIRTIO_RING_F_EVENT_IDX;
        self.update_writeback();

        let mut epoll_threads = Vec::new();
        for _ in 0..self.queue_size.len() {
            let queue_evt = queue_evts.remove(0);
            let mut handler = BlockEpollHandler {
                queue: queues.remove(0),
                mem: mem.clone(),
                disk_image: self.disk_image.clone(),
                disk_nsectors: self.disk_nsectors,
                interrupt_cb: interrupt_cb.clone(),
                disk_image_id: disk_image_id.clone(),
                kill_evt: kill_evt.try_clone().unwrap(),
                pause_evt: pause_evt.try_clone().unwrap(),
                event_idx,
                writeback: self.writeback.clone(),
                counters: self.counters.clone(),
                queue_evt,
            };

            handler.queue.set_event_idx(event_idx);

            let paused = self.paused.clone();

            // Retrieve seccomp filter for virtio_blk thread
            let api_seccomp_filter = get_seccomp_filter(&self.seccomp_action, Thread::VirtioBlk)
                .map_err(ActivateError::CreateSeccompFilter)?;

            thread::Builder::new()
                .name("virtio_blk".to_string())
                .spawn(move || {
                    SeccompFilter::apply(api_seccomp_filter)
                        .map_err(EpollHelperError::ApplySeccompFilter)?;

                    handler.run(paused)
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

virtio_pausable!(Block, T: 'static + DiskFile + Send);
impl<T: 'static + DiskFile + Send> Snapshottable for Block<T> {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&self) -> std::result::Result<Snapshot, MigratableError> {
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
impl<T: 'static + DiskFile + Send> Transportable for Block<T> {}
impl<T: 'static + DiskFile + Send> Migratable for Block<T> {}
