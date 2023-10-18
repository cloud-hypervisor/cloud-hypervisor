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
    ActivateError, ActivateResult, EpollHelper, EpollHelperError, EpollHelperHandler,
    RateLimiterConfig, VirtioCommon, VirtioDevice, VirtioDeviceType, VirtioInterruptType,
    EPOLL_HELPER_EVENT_LAST,
};
use crate::seccomp_filters::Thread;
use crate::thread_helper::spawn_virtio_thread;
use crate::GuestMemoryMmap;
use crate::VirtioInterrupt;
use anyhow::anyhow;
use block::{
    async_io::AsyncIo, async_io::AsyncIoError, async_io::DiskFile, build_serial, Request,
    RequestType, VirtioBlockConfig,
};
use rate_limiter::{RateLimiter, TokenType};
use seccompiler::SeccompAction;
use std::collections::VecDeque;
use std::io;
use std::num::Wrapping;
use std::ops::Deref;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::result;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::{collections::HashMap, convert::TryInto};
use thiserror::Error;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;
use virtio_bindings::virtio_blk::*;
use virtio_bindings::virtio_config::*;
use virtio_queue::{Queue, QueueOwnedT, QueueT};
use vm_memory::{ByteValued, Bytes, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryError};
use vm_migration::VersionMapped;
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
use vm_virtio::AccessPlatform;
use vmm_sys_util::eventfd::EventFd;

const SECTOR_SHIFT: u8 = 9;
pub const SECTOR_SIZE: u64 = 0x01 << SECTOR_SHIFT;

// New descriptors are pending on the virtio queue.
const QUEUE_AVAIL_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;
// New completed tasks are pending on the completion ring.
const COMPLETION_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 2;
// New 'wake up' event from the rate limiter
const RATE_LIMITER_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 3;

// latency scale, for reduce precision loss in calculate.
const LATENCY_SCALE: u64 = 10000;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to parse the request: {0}")]
    RequestParsing(block::Error),
    #[error("Failed to execute the request: {0}")]
    RequestExecuting(block::ExecuteError),
    #[error("Failed to complete the request: {0}")]
    RequestCompleting(block::Error),
    #[error("Missing the expected entry in the list of requests")]
    MissingEntryRequestList,
    #[error("The asynchronous request returned with failure")]
    AsyncRequestFailure,
    #[error("Failed synchronizing the file: {0}")]
    Fsync(AsyncIoError),
    #[error("Failed adding used index: {0}")]
    QueueAddUsed(virtio_queue::Error),
    #[error("Failed creating an iterator over the queue: {0}")]
    QueueIterator(virtio_queue::Error),
    #[error("Failed to update request status: {0}")]
    RequestStatus(GuestMemoryError),
}

pub type Result<T> = result::Result<T, Error>;

// latency will be records as microseconds, average latency
// will be save as scaled value.
#[derive(Clone)]
pub struct BlockCounters {
    read_bytes: Arc<AtomicU64>,
    read_ops: Arc<AtomicU64>,
    read_latency_min: Arc<AtomicU64>,
    read_latency_max: Arc<AtomicU64>,
    read_latency_avg: Arc<AtomicU64>,
    write_bytes: Arc<AtomicU64>,
    write_ops: Arc<AtomicU64>,
    write_latency_min: Arc<AtomicU64>,
    write_latency_max: Arc<AtomicU64>,
    write_latency_avg: Arc<AtomicU64>,
}

impl Default for BlockCounters {
    fn default() -> Self {
        BlockCounters {
            read_bytes: Arc::new(AtomicU64::new(0)),
            read_ops: Arc::new(AtomicU64::new(0)),
            read_latency_min: Arc::new(AtomicU64::new(u64::MAX)),
            read_latency_max: Arc::new(AtomicU64::new(u64::MAX)),
            read_latency_avg: Arc::new(AtomicU64::new(u64::MAX)),
            write_bytes: Arc::new(AtomicU64::new(0)),
            write_ops: Arc::new(AtomicU64::new(0)),
            write_latency_min: Arc::new(AtomicU64::new(u64::MAX)),
            write_latency_max: Arc::new(AtomicU64::new(u64::MAX)),
            write_latency_avg: Arc::new(AtomicU64::new(u64::MAX)),
        }
    }
}

struct BlockEpollHandler {
    queue_index: u16,
    queue: Queue,
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
    disk_image: Box<dyn AsyncIo>,
    disk_nsectors: u64,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    serial: Vec<u8>,
    kill_evt: EventFd,
    pause_evt: EventFd,
    writeback: Arc<AtomicBool>,
    counters: BlockCounters,
    queue_evt: EventFd,
    inflight_requests: VecDeque<(u16, Request)>,
    rate_limiter: Option<RateLimiter>,
    access_platform: Option<Arc<dyn AccessPlatform>>,
    read_only: bool,
}

impl BlockEpollHandler {
    fn process_queue_submit(&mut self) -> Result<bool> {
        let queue = &mut self.queue;

        let mut used_descs = false;

        while let Some(mut desc_chain) = queue.pop_descriptor_chain(self.mem.memory()) {
            let mut request = Request::parse(&mut desc_chain, self.access_platform.as_ref())
                .map_err(Error::RequestParsing)?;

            // For virtio spec compliance
            // "A device MUST set the status byte to VIRTIO_BLK_S_IOERR for a write request
            // if the VIRTIO_BLK_F_RO feature if offered, and MUST NOT write any data."
            if self.read_only
                && (request.request_type == RequestType::Out
                    || request.request_type == RequestType::Flush)
            {
                desc_chain
                    .memory()
                    .write_obj(VIRTIO_BLK_S_IOERR, request.status_addr)
                    .map_err(Error::RequestStatus)?;

                // If no asynchronous operation has been submitted, we can
                // simply return the used descriptor.
                queue
                    .add_used(desc_chain.memory(), desc_chain.head_index(), 0)
                    .map_err(Error::QueueAddUsed)?;
                used_descs = true;
                continue;
            }

            if let Some(rate_limiter) = &mut self.rate_limiter {
                // If limiter.consume() fails it means there is no more TokenType::Ops
                // budget and rate limiting is in effect.
                if !rate_limiter.consume(1, TokenType::Ops) {
                    // Stop processing the queue and return this descriptor chain to the
                    // avail ring, for later processing.
                    queue.go_to_previous_position();
                    break;
                }
                // Exercise the rate limiter only if this request is of data transfer type.
                if request.request_type == RequestType::In
                    || request.request_type == RequestType::Out
                {
                    let mut bytes = Wrapping(0);
                    for (_, data_len) in &request.data_descriptors {
                        bytes += Wrapping(*data_len as u64);
                    }

                    // If limiter.consume() fails it means there is no more TokenType::Bytes
                    // budget and rate limiting is in effect.
                    if !rate_limiter.consume(bytes.0, TokenType::Bytes) {
                        // Revert the OPS consume().
                        rate_limiter.manual_replenish(1, TokenType::Ops);
                        // Stop processing the queue and return this descriptor chain to the
                        // avail ring, for later processing.
                        queue.go_to_previous_position();
                        break;
                    }
                };
            }

            request.set_writeback(self.writeback.load(Ordering::Acquire));

            if request
                .execute_async(
                    desc_chain.memory(),
                    self.disk_nsectors,
                    self.disk_image.as_mut(),
                    &self.serial,
                    desc_chain.head_index() as u64,
                )
                .map_err(Error::RequestExecuting)?
            {
                self.inflight_requests
                    .push_back((desc_chain.head_index(), request));
            } else {
                desc_chain
                    .memory()
                    .write_obj(VIRTIO_BLK_S_OK, request.status_addr)
                    .map_err(Error::RequestStatus)?;

                // If no asynchronous operation has been submitted, we can
                // simply return the used descriptor.
                queue
                    .add_used(desc_chain.memory(), desc_chain.head_index(), 0)
                    .map_err(Error::QueueAddUsed)?;
                used_descs = true;
            }
        }

        Ok(used_descs)
    }

    fn process_queue_submit_and_signal(&mut self) -> result::Result<(), EpollHelperError> {
        let needs_notification = self.process_queue_submit().map_err(|e| {
            EpollHelperError::HandleEvent(anyhow!("Failed to process queue (submit): {:?}", e))
        })?;

        if needs_notification {
            self.signal_used_queue().map_err(|e| {
                EpollHelperError::HandleEvent(anyhow!("Failed to signal used queue: {:?}", e))
            })?
        };

        Ok(())
    }

    #[inline]
    fn find_inflight_request(&mut self, completed_head: u16) -> Result<Request> {
        // This loop neatly handles the fast path where the completions are
        // in order (it turng into just a pop_front()) and the 1% of the time
        // (analysis during boot) where slight out of ordering has been
        // observed e.g.
        // Submissions: 1 2 3 4 5 6 7
        // Completions: 2 1 3 5 4 7 6
        // In this case find the corresponding item and swap it with the front
        // This is a O(1) operation and is prepared for the future as it it likely
        // the next completion would be for the one that was skipped which will
        // now be the new front.
        for (i, (head, _)) in self.inflight_requests.iter().enumerate() {
            if head == &completed_head {
                return Ok(self.inflight_requests.swap_remove_front(i).unwrap().1);
            }
        }

        Err(Error::MissingEntryRequestList)
    }

    fn process_queue_complete(&mut self) -> Result<bool> {
        let mut used_descs = false;
        let mem = self.mem.memory();
        let mut read_bytes = Wrapping(0);
        let mut write_bytes = Wrapping(0);
        let mut read_ops = Wrapping(0);
        let mut write_ops = Wrapping(0);

        while let Some((user_data, result)) = self.disk_image.next_completed_request() {
            let desc_index = user_data as u16;

            let mut request = self.find_inflight_request(desc_index)?;

            request.complete_async().map_err(Error::RequestCompleting)?;

            let latency = request.start.elapsed().as_micros() as u64;
            let read_ops_last = self.counters.read_ops.load(Ordering::Relaxed);
            let write_ops_last = self.counters.write_ops.load(Ordering::Relaxed);
            let read_max = self.counters.read_latency_max.load(Ordering::Relaxed);
            let write_max = self.counters.write_latency_max.load(Ordering::Relaxed);
            let mut read_avg = self.counters.read_latency_avg.load(Ordering::Relaxed);
            let mut write_avg = self.counters.write_latency_avg.load(Ordering::Relaxed);
            let (status, len) = if result >= 0 {
                match request.request_type {
                    RequestType::In => {
                        for (_, data_len) in &request.data_descriptors {
                            read_bytes += Wrapping(*data_len as u64);
                        }
                        read_ops += Wrapping(1);
                        if latency < self.counters.read_latency_min.load(Ordering::Relaxed) {
                            self.counters
                                .read_latency_min
                                .store(latency, Ordering::Relaxed);
                        }
                        if latency > read_max || read_max == u64::MAX {
                            self.counters
                                .read_latency_max
                                .store(latency, Ordering::Relaxed);
                        }

                        // Special case the first real latency report
                        read_avg = if read_avg == u64::MAX {
                            latency * LATENCY_SCALE
                        } else {
                            // Cumulative average is guaranteed to be
                            // positive if being calculated properly
                            (read_avg as i64
                                + ((latency * LATENCY_SCALE) as i64 - read_avg as i64)
                                    / (read_ops_last + read_ops.0) as i64)
                                .try_into()
                                .unwrap()
                        };
                    }
                    RequestType::Out => {
                        if !request.writeback {
                            self.disk_image.fsync(None).map_err(Error::Fsync)?;
                        }
                        for (_, data_len) in &request.data_descriptors {
                            write_bytes += Wrapping(*data_len as u64);
                        }
                        write_ops += Wrapping(1);
                        if latency < self.counters.write_latency_min.load(Ordering::Relaxed) {
                            self.counters
                                .write_latency_min
                                .store(latency, Ordering::Relaxed);
                        }
                        if latency > write_max || write_max == u64::MAX {
                            self.counters
                                .write_latency_max
                                .store(latency, Ordering::Relaxed);
                        }

                        // Special case the first real latency report
                        write_avg = if write_avg == u64::MAX {
                            latency * LATENCY_SCALE
                        } else {
                            // Cumulative average is guaranteed to be
                            // positive if being calculated properly
                            (write_avg as i64
                                + ((latency * LATENCY_SCALE) as i64 - write_avg as i64)
                                    / (write_ops_last + write_ops.0) as i64)
                                .try_into()
                                .unwrap()
                        }
                    }
                    _ => {}
                }

                self.counters
                    .read_latency_avg
                    .store(read_avg, Ordering::Relaxed);

                self.counters
                    .write_latency_avg
                    .store(write_avg, Ordering::Relaxed);

                (VIRTIO_BLK_S_OK, result as u32)
            } else {
                error!(
                    "Request failed: {:x?} {:?}",
                    request,
                    io::Error::from_raw_os_error(-result)
                );
                return Err(Error::AsyncRequestFailure);
            };

            mem.write_obj(status, request.status_addr)
                .map_err(Error::RequestStatus)?;

            let queue = &mut self.queue;

            queue
                .add_used(mem.deref(), desc_index, len)
                .map_err(Error::QueueAddUsed)?;
            used_descs = true;
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

        Ok(used_descs)
    }

    fn signal_used_queue(&self) -> result::Result<(), DeviceError> {
        self.interrupt_cb
            .trigger(VirtioInterruptType::Queue(self.queue_index))
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
        helper.add_event(self.disk_image.notifier().as_raw_fd(), COMPLETION_EVENT)?;
        if let Some(rate_limiter) = &self.rate_limiter {
            helper.add_event(rate_limiter.as_raw_fd(), RATE_LIMITER_EVENT)?;
        }
        helper.run(paused, paused_sync, self)?;

        Ok(())
    }
}

impl EpollHelperHandler for BlockEpollHandler {
    fn handle_event(
        &mut self,
        _helper: &mut EpollHelper,
        event: &epoll::Event,
    ) -> result::Result<(), EpollHelperError> {
        let ev_type = event.data as u16;
        match ev_type {
            QUEUE_AVAIL_EVENT => {
                self.queue_evt.read().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!("Failed to get queue event: {:?}", e))
                })?;

                let rate_limit_reached =
                    self.rate_limiter.as_ref().map_or(false, |r| r.is_blocked());

                // Process the queue only when the rate limit is not reached
                if !rate_limit_reached {
                    self.process_queue_submit_and_signal()?
                }
            }
            COMPLETION_EVENT => {
                self.disk_image.notifier().read().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!("Failed to get queue event: {:?}", e))
                })?;

                let needs_notification = self.process_queue_complete().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!(
                        "Failed to process queue (complete): {:?}",
                        e
                    ))
                })?;

                if needs_notification {
                    self.signal_used_queue().map_err(|e| {
                        EpollHelperError::HandleEvent(anyhow!(
                            "Failed to signal used queue: {:?}",
                            e
                        ))
                    })?;
                }
            }
            RATE_LIMITER_EVENT => {
                if let Some(rate_limiter) = &mut self.rate_limiter {
                    // Upon rate limiter event, call the rate limiter handler
                    // and restart processing the queue.
                    rate_limiter.event_handler().map_err(|e| {
                        EpollHelperError::HandleEvent(anyhow!(
                            "Failed to process rate limiter event: {:?}",
                            e
                        ))
                    })?;

                    self.process_queue_submit_and_signal()?
                } else {
                    return Err(EpollHelperError::HandleEvent(anyhow!(
                        "Unexpected 'RATE_LIMITER_EVENT' when rate_limiter is not enabled."
                    )));
                }
            }
            _ => {
                return Err(EpollHelperError::HandleEvent(anyhow!(
                    "Unexpected event: {}",
                    ev_type
                )));
            }
        }
        Ok(())
    }
}

/// Virtio device for exposing block level read/write operations on a host file.
pub struct Block {
    common: VirtioCommon,
    id: String,
    disk_image: Box<dyn DiskFile>,
    disk_path: PathBuf,
    disk_nsectors: u64,
    config: VirtioBlockConfig,
    writeback: Arc<AtomicBool>,
    counters: BlockCounters,
    seccomp_action: SeccompAction,
    rate_limiter_config: Option<RateLimiterConfig>,
    exit_evt: EventFd,
    read_only: bool,
    serial: Vec<u8>,
}

#[derive(Versionize)]
pub struct BlockState {
    pub disk_path: String,
    pub disk_nsectors: u64,
    pub avail_features: u64,
    pub acked_features: u64,
    pub config: VirtioBlockConfig,
}

impl VersionMapped for BlockState {}

impl Block {
    /// Create a new virtio block device that operates on the given file.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        mut disk_image: Box<dyn DiskFile>,
        disk_path: PathBuf,
        read_only: bool,
        iommu: bool,
        num_queues: usize,
        queue_size: u16,
        serial: Option<String>,
        seccomp_action: SeccompAction,
        rate_limiter_config: Option<RateLimiterConfig>,
        exit_evt: EventFd,
        state: Option<BlockState>,
    ) -> io::Result<Self> {
        let (disk_nsectors, avail_features, acked_features, config, paused) =
            if let Some(state) = state {
                info!("Restoring virtio-block {}", id);
                (
                    state.disk_nsectors,
                    state.avail_features,
                    state.acked_features,
                    state.config,
                    true,
                )
            } else {
                let disk_size = disk_image.size().map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("Failed getting disk size: {e}"),
                    )
                })?;
                if disk_size % SECTOR_SIZE != 0 {
                    warn!(
                        "Disk size {} is not a multiple of sector size {}; \
                 the remainder will not be visible to the guest.",
                        disk_size, SECTOR_SIZE
                    );
                }

                let mut avail_features = (1u64 << VIRTIO_F_VERSION_1)
                    | (1u64 << VIRTIO_BLK_F_FLUSH)
                    | (1u64 << VIRTIO_BLK_F_CONFIG_WCE)
                    | (1u64 << VIRTIO_BLK_F_BLK_SIZE)
                    | (1u64 << VIRTIO_BLK_F_TOPOLOGY);

                if iommu {
                    avail_features |= 1u64 << VIRTIO_F_IOMMU_PLATFORM;
                }

                if read_only {
                    avail_features |= 1u64 << VIRTIO_BLK_F_RO;
                }

                let topology = disk_image.topology();
                info!("Disk topology: {:?}", topology);

                let logical_block_size = if topology.logical_block_size > 512 {
                    topology.logical_block_size
                } else {
                    512
                };

                // Calculate the exponent that maps physical block to logical block
                let mut physical_block_exp = 0;
                let mut size = logical_block_size;
                while size < topology.physical_block_size {
                    physical_block_exp += 1;
                    size <<= 1;
                }

                let disk_nsectors = disk_size / SECTOR_SIZE;
                let mut config = VirtioBlockConfig {
                    capacity: disk_nsectors,
                    writeback: 1,
                    blk_size: topology.logical_block_size as u32,
                    physical_block_exp,
                    min_io_size: (topology.minimum_io_size / logical_block_size) as u16,
                    opt_io_size: (topology.optimal_io_size / logical_block_size) as u32,
                    ..Default::default()
                };

                if num_queues > 1 {
                    avail_features |= 1u64 << VIRTIO_BLK_F_MQ;
                    config.num_queues = num_queues as u16;
                }

                (disk_nsectors, avail_features, 0, config, false)
            };

        let serial = serial
            .map(Vec::from)
            .unwrap_or_else(|| build_serial(&disk_path));

        Ok(Block {
            common: VirtioCommon {
                device_type: VirtioDeviceType::Block as u32,
                avail_features,
                acked_features,
                paused_sync: Some(Arc::new(Barrier::new(num_queues + 1))),
                queue_sizes: vec![queue_size; num_queues],
                min_queues: 1,
                paused: Arc::new(AtomicBool::new(paused)),
                ..Default::default()
            },
            id,
            disk_image,
            disk_path,
            disk_nsectors,
            config,
            writeback: Arc::new(AtomicBool::new(true)),
            counters: BlockCounters::default(),
            seccomp_action,
            rate_limiter_config,
            exit_evt,
            read_only,
            serial,
        })
    }

    fn state(&self) -> BlockState {
        BlockState {
            disk_path: self.disk_path.to_str().unwrap().to_owned(),
            disk_nsectors: self.disk_nsectors,
            avail_features: self.common.avail_features,
            acked_features: self.common.acked_features,
            config: self.config,
        }
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
        self.writeback.store(writeback, Ordering::Release);
    }

    #[cfg(fuzzing)]
    pub fn wait_for_epoll_threads(&mut self) {
        self.common.wait_for_epoll_threads();
    }
}

impl Drop for Block {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.common.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
        self.common.wait_for_epoll_threads();
    }
}

impl VirtioDevice for Block {
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
        mut queues: Vec<(usize, Queue, EventFd)>,
    ) -> ActivateResult {
        self.common.activate(&queues, &interrupt_cb)?;

        self.update_writeback();

        let mut epoll_threads = Vec::new();
        for i in 0..queues.len() {
            let (_, queue, queue_evt) = queues.remove(0);
            let queue_size = queue.size();
            let (kill_evt, pause_evt) = self.common.dup_eventfds();

            let rate_limiter: Option<RateLimiter> = self
                .rate_limiter_config
                .map(RateLimiterConfig::try_into)
                .transpose()
                .map_err(ActivateError::CreateRateLimiter)?;

            let mut handler = BlockEpollHandler {
                queue_index: i as u16,
                queue,
                mem: mem.clone(),
                disk_image: self
                    .disk_image
                    .new_async_io(queue_size as u32)
                    .map_err(|e| {
                        error!("failed to create new AsyncIo: {}", e);
                        ActivateError::BadActivate
                    })?,
                disk_nsectors: self.disk_nsectors,
                interrupt_cb: interrupt_cb.clone(),
                serial: self.serial.clone(),
                kill_evt,
                pause_evt,
                writeback: self.writeback.clone(),
                counters: self.counters.clone(),
                queue_evt,
                // Analysis during boot shows around ~40 maximum requests
                // This gives head room for systems with slower I/O without
                // compromising the cost of the reallocation or memory overhead
                inflight_requests: VecDeque::with_capacity(64),
                rate_limiter,
                access_platform: self.common.access_platform.clone(),
                read_only: self.read_only,
            };

            let paused = self.common.paused.clone();
            let paused_sync = self.common.paused_sync.clone();

            spawn_virtio_thread(
                &format!("{}_q{}", self.id.clone(), i),
                &self.seccomp_action,
                Thread::VirtioBlock,
                &mut epoll_threads,
                &self.exit_evt,
                move || handler.run(paused, paused_sync.unwrap()),
            )?;
        }

        self.common.epoll_threads = Some(epoll_threads);
        event!("virtio-device", "activated", "id", &self.id);

        Ok(())
    }

    fn reset(&mut self) -> Option<Arc<dyn VirtioInterrupt>> {
        let result = self.common.reset();
        event!("virtio-device", "reset", "id", &self.id);
        result
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
        counters.insert(
            "write_latency_min",
            Wrapping(self.counters.write_latency_min.load(Ordering::Acquire)),
        );
        counters.insert(
            "write_latency_max",
            Wrapping(self.counters.write_latency_max.load(Ordering::Acquire)),
        );
        counters.insert(
            "write_latency_avg",
            Wrapping(self.counters.write_latency_avg.load(Ordering::Acquire) / LATENCY_SCALE),
        );
        counters.insert(
            "read_latency_min",
            Wrapping(self.counters.read_latency_min.load(Ordering::Acquire)),
        );
        counters.insert(
            "read_latency_max",
            Wrapping(self.counters.read_latency_max.load(Ordering::Acquire)),
        );
        counters.insert(
            "read_latency_avg",
            Wrapping(self.counters.read_latency_avg.load(Ordering::Acquire) / LATENCY_SCALE),
        );

        Some(counters)
    }

    fn set_access_platform(&mut self, access_platform: Arc<dyn AccessPlatform>) {
        self.common.set_access_platform(access_platform)
    }
}

impl Pausable for Block {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        self.common.pause()
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        self.common.resume()
    }
}

impl Snapshottable for Block {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        Snapshot::new_from_versioned_state(&self.state())
    }
}
impl Transportable for Block {}
impl Migratable for Block {}
