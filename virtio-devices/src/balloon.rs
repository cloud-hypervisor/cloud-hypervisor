// Copyright (c) 2020 Ant Financial
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::io::{self, Write};
use std::ops::Deref;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::{Arc, Barrier};
use std::{cmp, result};

use anyhow::anyhow;
use event_monitor::event;
use log::{error, info, warn};
use seccompiler::SeccompAction;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use thiserror::Error;
use virtio_queue::{Queue, QueueT};
use vm_allocator::page_size::{align_page_size_down, get_page_size};
use vm_memory::{
    Address, ByteValued, Bytes, GuestAddress, GuestAddressSpace, GuestMemoryAtomic,
    GuestMemoryBackend, GuestMemoryError, GuestMemoryRegion,
};
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
use vm_virtio::AccessPlatform;
use vm_virtio::checked_descriptor::DescriptorChainExt;
use vmm_sys_util::eventfd::{EFD_NONBLOCK, EventFd};
use zerocopy::little_endian::{U16 as Le16, U64 as Le64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::device::ActivationContext;
use crate::seccomp_filters::Thread;
use crate::{
    ActivateResult, EPOLL_HELPER_EVENT_LAST, EpollHelper, EpollHelperError, EpollHelperHandler,
    GuestMemoryMmap, VIRTIO_F_ACCESS_PLATFORM, VIRTIO_F_VERSION_1, VirtioCommon, VirtioDevice,
    VirtioDeviceType, VirtioInterrupt, VirtioInterruptType,
};

const QUEUE_SIZE: u16 = 128;
const REPORTING_QUEUE_SIZE: u16 = 32;
const STATS_QUEUE_SIZE: u16 = 16;
const MIN_NUM_QUEUES: usize = 2;

// Inflate virtio queue event.
const INFLATE_QUEUE_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;
// Deflate virtio queue event.
const DEFLATE_QUEUE_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 2;
// Reporting virtio queue event.
const REPORTING_QUEUE_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 3;
// Statistics virtio queue event.
const STATS_QUEUE_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 4;
// Statistics request event.
const STATS_REQUEST_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 5;

// Size of a PFN in the balloon interface.
const VIRTIO_BALLOON_PFN_SHIFT: u64 = 12;

// Upper bound on a single inflate or deflate descriptor length, in
// bytes. Matches the Linux driver, which submits at most
// VIRTIO_BALLOON_ARRAY_PFNS_MAX of 256 PFN entries of 4 bytes each per
// descriptor.
const VIRTIO_BALLOON_MAX_PFN_BYTES: u32 = 256 * 4;

// Enable statistics virtqueue.
const VIRTIO_BALLOON_F_STATS_VQ: u64 = 1;
// Deflate balloon on OOM
const VIRTIO_BALLOON_F_DEFLATE_ON_OOM: u64 = 2;
// Enable an additional virtqueue to let the guest notify the host about free
// pages.
const VIRTIO_BALLOON_F_REPORTING: u64 = 5;

const VIRTIO_BALLOON_S_SWAP_IN: u16 = 0;
const VIRTIO_BALLOON_S_SWAP_OUT: u16 = 1;
const VIRTIO_BALLOON_S_MAJFLT: u16 = 2;
const VIRTIO_BALLOON_S_MINFLT: u16 = 3;
const VIRTIO_BALLOON_S_MEMFREE: u16 = 4;
const VIRTIO_BALLOON_S_MEMTOT: u16 = 5;
const VIRTIO_BALLOON_S_AVAIL: u16 = 6;
const VIRTIO_BALLOON_S_CACHES: u16 = 7;
const VIRTIO_BALLOON_S_HTLB_PGALLOC: u16 = 8;
const VIRTIO_BALLOON_S_HTLB_PGFAIL: u16 = 9;
// Linux extensions that are not part of virtio 1.4.
const VIRTIO_BALLOON_S_OOM_KILL: u16 = 10;
const VIRTIO_BALLOON_S_ALLOC_STALL: u16 = 11;
const VIRTIO_BALLOON_S_ASYNC_SCAN: u16 = 12;
const VIRTIO_BALLOON_S_DIRECT_SCAN: u16 = 13;
const VIRTIO_BALLOON_S_ASYNC_RECLAIM: u16 = 14;
const VIRTIO_BALLOON_S_DIRECT_RECLAIM: u16 = 15;

// Bound allocations from untrusted descriptor chains. This accommodates far
// more than the 16 statistics currently defined by Linux.
const VIRTIO_BALLOON_MAX_STATS_BYTES: usize = 4096;

#[derive(Copy, Clone, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(C, packed)]
struct BalloonStat {
    tag: Le16,
    val: Le64,
}

#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct BalloonStats {
    pub swap_in: Option<u64>,
    pub swap_out: Option<u64>,
    pub major_faults: Option<u64>,
    pub minor_faults: Option<u64>,
    pub free_memory: Option<u64>,
    pub total_memory: Option<u64>,
    pub available_memory: Option<u64>,
    pub disk_caches: Option<u64>,
    pub hugetlb_allocations: Option<u64>,
    pub hugetlb_failures: Option<u64>,
    pub oom_kills: Option<u64>,
    pub alloc_stalls: Option<u64>,
    pub async_scans: Option<u64>,
    pub direct_scans: Option<u64>,
    pub async_reclaims: Option<u64>,
    pub direct_reclaims: Option<u64>,
}

#[derive(Error, Debug)]
pub enum BalloonStatsError {
    #[error("Invalid balloon statistics descriptor at {0:#x}")]
    InvalidDescriptor(u64),
    #[error("Balloon statistics buffer is too large: {0} bytes")]
    BufferTooLarge(usize),
    #[error("Invalid balloon statistics buffer length: {0} bytes")]
    InvalidBufferLength(usize),
    #[error("Failed to read balloon statistics")]
    GuestMemory(#[source] GuestMemoryError),
}

type BalloonStatsResult = result::Result<BalloonStats, BalloonStatsError>;

struct StatsRequest {
    response_sender: SyncSender<BalloonStatsResult>,
}

fn parse_balloon_stats(data: &[u8]) -> BalloonStatsResult {
    let entries = <[BalloonStat]>::ref_from_bytes(data)
        .map_err(|_| BalloonStatsError::InvalidBufferLength(data.len()))?;

    let mut stats = BalloonStats::default();
    for entry in entries {
        let field = match entry.tag.get() {
            VIRTIO_BALLOON_S_SWAP_IN => &mut stats.swap_in,
            VIRTIO_BALLOON_S_SWAP_OUT => &mut stats.swap_out,
            VIRTIO_BALLOON_S_MAJFLT => &mut stats.major_faults,
            VIRTIO_BALLOON_S_MINFLT => &mut stats.minor_faults,
            VIRTIO_BALLOON_S_MEMFREE => &mut stats.free_memory,
            VIRTIO_BALLOON_S_MEMTOT => &mut stats.total_memory,
            VIRTIO_BALLOON_S_AVAIL => &mut stats.available_memory,
            VIRTIO_BALLOON_S_CACHES => &mut stats.disk_caches,
            VIRTIO_BALLOON_S_HTLB_PGALLOC => &mut stats.hugetlb_allocations,
            VIRTIO_BALLOON_S_HTLB_PGFAIL => &mut stats.hugetlb_failures,
            VIRTIO_BALLOON_S_OOM_KILL => &mut stats.oom_kills,
            VIRTIO_BALLOON_S_ALLOC_STALL => &mut stats.alloc_stalls,
            VIRTIO_BALLOON_S_ASYNC_SCAN => &mut stats.async_scans,
            VIRTIO_BALLOON_S_DIRECT_SCAN => &mut stats.direct_scans,
            VIRTIO_BALLOON_S_ASYNC_RECLAIM => &mut stats.async_reclaims,
            VIRTIO_BALLOON_S_DIRECT_RECLAIM => &mut stats.direct_reclaims,
            _ => continue,
        };
        *field = Some(entry.val.get());
    }

    Ok(stats)
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Guest gave us bad memory addresses.")]
    GuestMemory(#[source] GuestMemoryError),
    #[error("Fallocate fail.")]
    FallocateFail(#[source] io::Error),
    #[error("Madvise fail.")]
    MadviseFail(#[source] io::Error),
    #[error("Invalid queue index: {0}")]
    InvalidQueueIndex(u16),
    #[error("Failed to signal")]
    FailedSignal(#[source] io::Error),
    #[error("Failed adding used index")]
    QueueAddUsed(#[source] virtio_queue::Error),
    #[error("Balloon statistics feature was not negotiated")]
    StatsNotNegotiated,
    #[error("Balloon statistics worker is unavailable")]
    StatsWorkerUnavailable,
    #[error("Failed to signal balloon statistics request")]
    StatsRequestSignal(#[source] io::Error),
}

// Got from include/uapi/linux/virtio_balloon.h
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Serialize, Deserialize)]
pub struct VirtioBalloonConfig {
    // Number of pages host wants Guest to give up.
    num_pages: u32,
    // Number of pages we've actually got in balloon.
    actual: u32,
}

#[derive(Clone, Debug)]
struct PartiallyBalloonedPage {
    addr: u64,
    bitmap: Vec<u64>,
    page_size: u64,
}

impl PartiallyBalloonedPage {
    fn new() -> Self {
        let page_size = get_page_size();
        let len = (page_size >> VIRTIO_BALLOON_PFN_SHIFT).div_ceil(64);
        // Initial each padding bit as 1 in bitmap.
        let mut bitmap = vec![0_u64; len as usize];
        let pad_num = len * 64 - (page_size >> VIRTIO_BALLOON_PFN_SHIFT);
        bitmap[(len - 1) as usize] = !((1 << (64 - pad_num)) - 1);
        Self {
            addr: 0,
            bitmap,
            page_size,
        }
    }

    fn pfn_match(&self, addr: u64) -> bool {
        self.addr == addr & !(self.page_size - 1)
    }

    fn bitmap_full(&self) -> bool {
        self.bitmap.iter().all(|b| *b == u64::MAX)
    }

    fn set_bit(&mut self, addr: u64) {
        let addr_offset = (addr % self.page_size) >> VIRTIO_BALLOON_PFN_SHIFT;
        self.bitmap[(addr_offset / 64) as usize] |= 1 << (addr_offset % 64);
    }

    fn reset(&mut self) {
        let len = (self.page_size >> VIRTIO_BALLOON_PFN_SHIFT).div_ceil(64);
        self.addr = 0;
        self.bitmap = vec![0; len as usize];
        let pad_num = len * 64 - (self.page_size >> VIRTIO_BALLOON_PFN_SHIFT);
        self.bitmap[(len - 1) as usize] = !((1 << (64 - pad_num)) - 1);
    }
}

const CONFIG_ACTUAL_OFFSET: u64 = 4;
const CONFIG_ACTUAL_SIZE: usize = 4;

// SAFETY: it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioBalloonConfig {}

struct BalloonEpollHandler {
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
    queues: Vec<Queue>,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    inflate_queue_evt: EventFd,
    deflate_queue_evt: EventFd,
    stats_queue_evt: Option<EventFd>,
    stats_request_evt: Option<EventFd>,
    stats_request_receiver: Option<Receiver<StatsRequest>>,
    stats_response_sender: Option<SyncSender<BalloonStatsResult>>,
    stats_refresh_in_flight: bool,
    stats_desc_index: Option<u16>,
    stats_queue_index: Option<usize>,
    reporting_queue_evt: Option<EventFd>,
    reporting_queue_index: Option<usize>,
    kill_evt: EventFd,
    pause_evt: EventFd,
    pbp: Option<PartiallyBalloonedPage>,
    access_platform: Option<Arc<dyn AccessPlatform>>,
}

impl BalloonEpollHandler {
    fn signal(&self, int_type: VirtioInterruptType) -> result::Result<(), Error> {
        self.interrupt_cb.trigger(int_type).map_err(|e| {
            error!("Failed to signal used queue: {e:?}");
            Error::FailedSignal(e)
        })
    }

    fn advise_memory_range(
        memory: &GuestMemoryMmap,
        range_base: GuestAddress,
        range_len: usize,
        advice: libc::c_int,
    ) -> result::Result<(), Error> {
        let slice = memory
            .get_slice(range_base, range_len)
            .map_err(Error::GuestMemory)?;
        assert!(slice.len() >= range_len);
        let res =
            // SAFETY: FFI call with valid arguments, guaranteed by VolatileSlice
            unsafe {
                libc::madvise(slice.ptr_guard_mut().as_ptr().cast(),
                range_len as libc::size_t, advice) };
        if res != 0 {
            return Err(Error::MadviseFail(io::Error::last_os_error()));
        }
        Ok(())
    }

    fn release_memory_range(
        memory: &GuestMemoryMmap,
        range_base: GuestAddress,
        range_len: usize,
    ) -> result::Result<(), Error> {
        let region = memory.find_region(range_base).ok_or(Error::GuestMemory(
            GuestMemoryError::InvalidGuestAddress(range_base),
        ))?;

        // No underflow possible because range_base was found in the region by `find_region`.
        let offset = range_base.0 - region.start_addr().0;
        let region_limit = region.len() - offset;
        let len = cmp::min(range_len as u64, region_limit);
        if len < range_len as u64 {
            warn!(
                "Clamping reported range at GPA 0x{:x} from {} to {} bytes \
                 to fit inside its memory region",
                range_base.0, range_len, len
            );
        }
        if len == 0 {
            return Ok(());
        }

        if let Some(f_off) = region.file_offset() {
            // SAFETY: FFI call with valid arguments
            let res = unsafe {
                libc::fallocate64(
                    f_off.file().as_raw_fd(),
                    libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                    (offset + f_off.start()) as libc::off64_t,
                    len as libc::off64_t,
                )
            };

            if res != 0 {
                return Err(Error::FallocateFail(io::Error::last_os_error()));
            }
        }

        Self::advise_memory_range(memory, range_base, len as usize, libc::MADV_DONTNEED)
    }

    fn release_memory_range_4k(
        pbp: &mut Option<PartiallyBalloonedPage>,
        memory: &GuestMemoryMmap,
        pfn: u32,
    ) -> result::Result<(), Error> {
        let range_base = GuestAddress((pfn as u64) << VIRTIO_BALLOON_PFN_SHIFT);
        let range_len = 1 << VIRTIO_BALLOON_PFN_SHIFT;

        let page_size: u64 = get_page_size();
        if page_size == 1 << VIRTIO_BALLOON_PFN_SHIFT {
            return Self::release_memory_range(memory, range_base, range_len);
        }

        if pbp.is_none() {
            *pbp = Some(PartiallyBalloonedPage::new());
        }

        if !pbp.as_ref().unwrap().pfn_match(range_base.0) {
            // We are trying to free memory region in a different pfn with current pbp. Flush pbp.
            pbp.as_mut().unwrap().reset();
            pbp.as_mut().unwrap().addr = align_page_size_down(range_base.0);
        }

        pbp.as_mut().unwrap().set_bit(range_base.0);
        if pbp.as_ref().unwrap().bitmap_full() {
            Self::release_memory_range(
                memory,
                vm_memory::GuestAddress(pbp.as_ref().unwrap().addr),
                page_size as usize,
            )?;

            pbp.as_mut().unwrap().reset();
        }

        Ok(())
    }

    fn process_queue(&mut self, queue_index: u16) -> result::Result<(), Error> {
        let mut used_descs = false;
        while let Some(mut desc_chain) =
            self.queues[queue_index as usize].pop_descriptor_chain(self.mem.memory())
        {
            let data_chunk_size = size_of::<u32>();

            let results: SmallVec<[_; 4]> = desc_chain
                .checked_iter(self.access_platform.as_deref())
                .collect();
            for result in results {
                let desc = match result {
                    Ok(d) => d,
                    Err(_) => break,
                };
                if desc.is_write_only() {
                    warn!("Skipping device-writable descriptor on inflate/deflate queue");
                    continue;
                }
                if !(desc.len() as usize).is_multiple_of(data_chunk_size) {
                    warn!(
                        "Skipping descriptor with length {} not a multiple of {data_chunk_size}",
                        desc.len()
                    );
                    continue;
                }
                if desc.len() > VIRTIO_BALLOON_MAX_PFN_BYTES {
                    warn!(
                        "Skipping descriptor with length {} exceeding cap {VIRTIO_BALLOON_MAX_PFN_BYTES}",
                        desc.len()
                    );
                    continue;
                }

                let mut offset = 0u64;
                while offset < desc.len() as u64 {
                    let Some(addr) = desc.addr().checked_add(offset) else {
                        warn!("Address overflow in balloon descriptor");
                        break;
                    };
                    let pfn: u32 = match desc_chain.memory().read_obj(addr) {
                        Ok(v) => v,
                        Err(e) => {
                            warn!("Failed to read PFN from descriptor: {e}");
                            break;
                        }
                    };
                    offset += data_chunk_size as u64;

                    match queue_index {
                        0 => {
                            if let Err(e) = Self::release_memory_range_4k(
                                &mut self.pbp,
                                desc_chain.memory(),
                                pfn,
                            ) {
                                warn!("Failed to release memory for PFN {pfn:#x}: {e}");
                            }
                        }
                        1 => {
                            let page_size = get_page_size() as usize;
                            let rbase =
                                align_page_size_down((pfn as u64) << VIRTIO_BALLOON_PFN_SHIFT);

                            if let Err(e) = Self::advise_memory_range(
                                desc_chain.memory(),
                                vm_memory::GuestAddress(rbase),
                                page_size,
                                libc::MADV_WILLNEED,
                            ) {
                                warn!("Failed to advise memory for PFN {pfn:#x}: {e}");
                            }
                        }
                        _ => return Err(Error::InvalidQueueIndex(queue_index)),
                    }
                }
            }

            self.queues[queue_index as usize]
                .add_used(desc_chain.memory(), desc_chain.head_index(), 0)
                .map_err(Error::QueueAddUsed)?;
            used_descs = true;
        }

        if used_descs {
            self.signal(VirtioInterruptType::Queue(queue_index))
        } else {
            Ok(())
        }
    }

    fn parse_stats_descriptor<M>(
        &self,
        desc_chain: &mut virtio_queue::DescriptorChain<M>,
    ) -> BalloonStatsResult
    where
        M: Deref<Target = GuestMemoryMmap>,
    {
        let results: SmallVec<[_; 4]> = desc_chain
            .checked_iter(self.access_platform.as_deref())
            .collect();
        let mut data = Vec::new();

        for result in results {
            let desc =
                result.map_err(|addr| BalloonStatsError::InvalidDescriptor(addr.raw_value()))?;
            if desc.is_write_only() {
                return Err(BalloonStatsError::InvalidDescriptor(
                    desc.addr().raw_value(),
                ));
            }

            let new_len = data
                .len()
                .checked_add(desc.len() as usize)
                .ok_or(BalloonStatsError::BufferTooLarge(usize::MAX))?;
            if new_len > VIRTIO_BALLOON_MAX_STATS_BYTES {
                return Err(BalloonStatsError::BufferTooLarge(new_len));
            }
            let old_len = data.len();
            data.resize(new_len, 0);
            desc_chain
                .memory()
                .read_slice(&mut data[old_len..], desc.addr())
                .map_err(BalloonStatsError::GuestMemory)?;
        }

        parse_balloon_stats(&data)
    }

    fn start_stats_refresh(&mut self) -> result::Result<(), Error> {
        if self.stats_response_sender.is_none() || self.stats_refresh_in_flight {
            return Ok(());
        }

        let Some(stats_qi) = self.stats_queue_index else {
            return Ok(());
        };
        let Some(desc_index) = self.stats_desc_index.take() else {
            return Ok(());
        };

        self.queues[stats_qi]
            .add_used(self.mem.memory().deref(), desc_index, 0)
            .map_err(Error::QueueAddUsed)?;
        self.stats_refresh_in_flight = true;
        self.signal(VirtioInterruptType::Queue(stats_qi as u16))
    }

    fn process_stats_requests(&mut self) -> result::Result<(), Error> {
        let Some(receiver) = self.stats_request_receiver.as_ref() else {
            return Ok(());
        };

        while let Ok(request) = receiver.try_recv() {
            self.stats_response_sender = Some(request.response_sender);
        }
        self.start_stats_refresh()
    }

    fn process_stats_queue(&mut self, queue_index: usize) -> result::Result<(), Error> {
        if self.stats_desc_index.is_some() {
            return Ok(());
        }

        let Some(mut desc_chain) = self.queues[queue_index].pop_descriptor_chain(self.mem.memory())
        else {
            return Ok(());
        };

        let desc_index = desc_chain.head_index();
        if self.stats_refresh_in_flight {
            let response = self.parse_stats_descriptor(&mut desc_chain);
            self.stats_refresh_in_flight = false;
            if let Some(response_sender) = self.stats_response_sender.take() {
                let _ = response_sender.send(response);
            }
        }
        self.stats_desc_index = Some(desc_index);
        self.start_stats_refresh()
    }

    fn process_reporting_queue(&mut self, queue_index: usize) -> result::Result<(), Error> {
        let mut used_descs = false;
        while let Some(mut desc_chain) =
            self.queues[queue_index].pop_descriptor_chain(self.mem.memory())
        {
            let mut descs_len = 0;
            let results: SmallVec<[_; 4]> = desc_chain
                .checked_iter(self.access_platform.as_deref())
                .collect();
            for result in results {
                let desc = match result {
                    Ok(d) => d,
                    Err(_) => break,
                };
                descs_len += desc.len();
                if let Err(e) = Self::release_memory_range(
                    desc_chain.memory(),
                    desc.addr(),
                    desc.len() as usize,
                ) {
                    warn!("Failed to release reported memory range: {e}");
                }
            }

            self.queues[queue_index]
                .add_used(desc_chain.memory(), desc_chain.head_index(), descs_len)
                .map_err(Error::QueueAddUsed)?;
            used_descs = true;
        }

        if used_descs {
            self.signal(VirtioInterruptType::Queue(queue_index as u16))
        } else {
            Ok(())
        }
    }

    fn run(
        &mut self,
        paused: &AtomicBool,
        paused_sync: &Barrier,
    ) -> result::Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;
        helper.add_event(self.inflate_queue_evt.as_raw_fd(), INFLATE_QUEUE_EVENT)?;
        helper.add_event(self.deflate_queue_evt.as_raw_fd(), DEFLATE_QUEUE_EVENT)?;
        if let Some(stats_queue_evt) = self.stats_queue_evt.as_ref() {
            helper.add_event(stats_queue_evt.as_raw_fd(), STATS_QUEUE_EVENT)?;
        }
        if let Some(stats_request_evt) = self.stats_request_evt.as_ref() {
            helper.add_event(stats_request_evt.as_raw_fd(), STATS_REQUEST_EVENT)?;
        }
        if let Some(reporting_queue_evt) = self.reporting_queue_evt.as_ref() {
            helper.add_event(reporting_queue_evt.as_raw_fd(), REPORTING_QUEUE_EVENT)?;
        }

        // A descriptor retained by the source is available again after restore,
        // but its original queue kick is not. Recover it before waiting on epoll.
        if let Some(queue_index) = self.stats_queue_index {
            self.process_stats_queue(queue_index)
                .map_err(|e| EpollHelperError::HandleEvent(anyhow!(e)))?;
        }
        helper.run(paused, paused_sync, self)?;

        Ok(())
    }
}

impl EpollHelperHandler for BalloonEpollHandler {
    fn handle_event(
        &mut self,
        _helper: &mut EpollHelper,
        event: &epoll::Event,
    ) -> result::Result<(), EpollHelperError> {
        let ev_type = event.data as u16;
        match ev_type {
            INFLATE_QUEUE_EVENT => {
                self.inflate_queue_evt.read().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!(
                        "Failed to get inflate queue event: {e:?}"
                    ))
                })?;
                self.process_queue(0).map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!(
                        "Failed to signal used inflate queue: {e:?}"
                    ))
                })?;
            }
            DEFLATE_QUEUE_EVENT => {
                self.deflate_queue_evt.read().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!(
                        "Failed to get deflate queue event: {e:?}"
                    ))
                })?;
                self.process_queue(1).map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!(
                        "Failed to signal used deflate queue: {e:?}"
                    ))
                })?;
            }
            STATS_QUEUE_EVENT => {
                if let Some(stats_queue_evt) = self.stats_queue_evt.as_ref() {
                    stats_queue_evt.read().map_err(|e| {
                        EpollHelperError::HandleEvent(anyhow!(
                            "Failed to get stats queue event: {e:?}"
                        ))
                    })?;
                    if let Some(qi) = self.stats_queue_index {
                        self.process_stats_queue(qi).map_err(|e| {
                            EpollHelperError::HandleEvent(anyhow!(
                                "Failed to process stats queue: {e:?}"
                            ))
                        })?;
                    }
                } else {
                    return Err(EpollHelperError::HandleEvent(anyhow!(
                        "Invalid stats queue event as no eventfd registered"
                    )));
                }
            }
            STATS_REQUEST_EVENT => {
                if let Some(stats_request_evt) = self.stats_request_evt.as_ref() {
                    stats_request_evt.read().map_err(|e| {
                        EpollHelperError::HandleEvent(anyhow!(
                            "Failed to get stats request event: {e:?}"
                        ))
                    })?;
                    self.process_stats_requests().map_err(|e| {
                        EpollHelperError::HandleEvent(anyhow!(
                            "Failed to request balloon statistics: {e:?}"
                        ))
                    })?;
                } else {
                    return Err(EpollHelperError::HandleEvent(anyhow!(
                        "Invalid stats request event as no eventfd registered"
                    )));
                }
            }
            REPORTING_QUEUE_EVENT => {
                if let Some(reporting_queue_evt) = self.reporting_queue_evt.as_ref() {
                    reporting_queue_evt.read().map_err(|e| {
                        EpollHelperError::HandleEvent(anyhow!(
                            "Failed to get reporting queue event: {e:?}"
                        ))
                    })?;
                    let qi = self.reporting_queue_index.unwrap();
                    self.process_reporting_queue(qi).map_err(|e| {
                        EpollHelperError::HandleEvent(anyhow!(
                            "Failed to signal used reporting queue: {e:?}"
                        ))
                    })?;
                } else {
                    return Err(EpollHelperError::HandleEvent(anyhow!(
                        "Invalid reporting queue event as no eventfd registered"
                    )));
                }
            }
            _ => {
                return Err(EpollHelperError::HandleEvent(anyhow!(
                    "Unknown event for virtio-balloon"
                )));
            }
        }

        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct BalloonState {
    pub avail_features: u64,
    pub acked_features: u64,
    pub config: VirtioBalloonConfig,
}

// Virtio device for managing guest memory through a balloon.
pub struct Balloon {
    common: VirtioCommon,
    id: String,
    config: VirtioBalloonConfig,
    seccomp_action: SeccompAction,
    exit_evt: EventFd,
    stats_request_evt: EventFd,
    stats_request_sender: Option<Sender<StatsRequest>>,
}

impl Balloon {
    // Create a new virtio-balloon.
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        size: u64,
        deflate_on_oom: bool,
        free_page_reporting: bool,
        access_platform_enabled: bool,
        seccomp_action: SeccompAction,
        exit_evt: EventFd,
        state: Option<BalloonState>,
    ) -> io::Result<Self> {
        let mut queue_sizes = vec![QUEUE_SIZE; MIN_NUM_QUEUES];

        let (avail_features, acked_features, config, paused) = if let Some(state) = state {
            info!("Restoring virtio-balloon {id}");
            (
                state.avail_features,
                state.acked_features,
                state.config,
                true,
            )
        } else {
            let mut avail_features = 1u64 << VIRTIO_F_VERSION_1 | 1u64 << VIRTIO_BALLOON_F_STATS_VQ;
            if deflate_on_oom {
                avail_features |= 1u64 << VIRTIO_BALLOON_F_DEFLATE_ON_OOM;
            }
            if free_page_reporting {
                avail_features |= 1u64 << VIRTIO_BALLOON_F_REPORTING;
            }
            if access_platform_enabled {
                avail_features |= 1u64 << VIRTIO_F_ACCESS_PLATFORM;
            }

            let config = VirtioBalloonConfig {
                num_pages: (size >> VIRTIO_BALLOON_PFN_SHIFT) as u32,
                ..Default::default()
            };

            (avail_features, 0, config, false)
        };

        // Stats queue must come before reporting queue to match virtio spec
        // queue index ordering (the guest transport compresses out disabled
        // queues).
        if avail_features & (1u64 << VIRTIO_BALLOON_F_STATS_VQ) != 0 {
            queue_sizes.push(STATS_QUEUE_SIZE);
        }
        if avail_features & (1u64 << VIRTIO_BALLOON_F_REPORTING) != 0 {
            queue_sizes.push(REPORTING_QUEUE_SIZE);
        }

        let stats_request_evt = EventFd::new(EFD_NONBLOCK)?;

        Ok(Balloon {
            common: VirtioCommon {
                device_type: VirtioDeviceType::Balloon as u32,
                avail_features,
                acked_features,
                paused_sync: Some(Arc::new(Barrier::new(2))),
                queue_sizes,
                min_queues: MIN_NUM_QUEUES as u16,
                paused: Arc::new(AtomicBool::new(paused)),
                ..Default::default()
            },
            id,
            config,
            seccomp_action,
            exit_evt,
            stats_request_evt,
            stats_request_sender: None,
        })
    }

    pub fn resize(&mut self, size: u64) -> Result<(), Error> {
        self.config.num_pages = (size >> VIRTIO_BALLOON_PFN_SHIFT) as u32;

        self.common
            .trigger_interrupt(VirtioInterruptType::Config)
            .map_err(Error::FailedSignal)
    }

    // Get the actual size of the virtio-balloon.
    pub fn get_actual(&self) -> u64 {
        (self.config.actual as u64) << VIRTIO_BALLOON_PFN_SHIFT
    }

    // Request fresh statistics from the virtio-balloon.
    pub fn begin_stats_request(
        &self,
    ) -> Result<Receiver<result::Result<BalloonStats, BalloonStatsError>>, Error> {
        if !self.common.feature_acked(VIRTIO_BALLOON_F_STATS_VQ) {
            return Err(Error::StatsNotNegotiated);
        }
        let request_sender = self
            .stats_request_sender
            .as_ref()
            .ok_or(Error::StatsWorkerUnavailable)?;
        let (response_sender, response_receiver) = mpsc::sync_channel(1);
        request_sender
            .send(StatsRequest { response_sender })
            .map_err(|_| Error::StatsWorkerUnavailable)?;
        self.stats_request_evt
            .write(1)
            .map_err(Error::StatsRequestSignal)?;
        Ok(response_receiver)
    }

    fn state(&self) -> BalloonState {
        BalloonState {
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

impl VirtioDevice for Balloon {
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

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        // The "actual" field is the only mutable field
        if offset != CONFIG_ACTUAL_OFFSET || data.len() != CONFIG_ACTUAL_SIZE {
            error!(
                "Attempt to write to read-only field: offset {:x} length {}",
                offset,
                data.len()
            );
            return;
        }

        let config = self.config.as_mut_slice();
        let config_len = config.len() as u64;
        let data_len = data.len() as u64;
        if offset + data_len > config_len {
            error!(
                "Out-of-bound access to configuration: config_len = {} offset = {:x} length = {} for {}",
                config_len,
                offset,
                data_len,
                self.device_type()
            );
            return;
        }

        if let Some(end) = offset.checked_add(config.len() as u64) {
            let mut offset_config =
                &mut config[offset as usize..cmp::min(end, config_len) as usize];
            offset_config.write_all(data).unwrap();
        }
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

        let mut virtqueues = Vec::new();
        let (_, queue, queue_evt) = queues.remove(0);
        virtqueues.push(queue);
        let inflate_queue_evt = queue_evt;
        let (_, queue, queue_evt) = queues.remove(0);
        virtqueues.push(queue);
        let deflate_queue_evt = queue_evt;

        let (stats_queue_evt, stats_queue_index, stats_request_evt, stats_request_receiver) =
            if self.common.feature_acked(VIRTIO_BALLOON_F_STATS_VQ) && !queues.is_empty() {
                let qi = virtqueues.len();
                let (_, queue, queue_evt) = queues.remove(0);
                virtqueues.push(queue);

                while self.stats_request_evt.read().is_ok() {}
                let (request_sender, request_receiver) = mpsc::channel();
                self.stats_request_sender = Some(request_sender);
                let request_evt = self
                    .stats_request_evt
                    .try_clone()
                    .map_err(crate::ActivateError::CloneEventFd)?;

                (
                    Some(queue_evt),
                    Some(qi),
                    Some(request_evt),
                    Some(request_receiver),
                )
            } else {
                self.stats_request_sender = None;
                (None, None, None, None)
            };

        let (reporting_queue_evt, reporting_queue_index) =
            if self.common.feature_acked(VIRTIO_BALLOON_F_REPORTING) && !queues.is_empty() {
                let qi = virtqueues.len();
                let (_, queue, queue_evt) = queues.remove(0);
                virtqueues.push(queue);
                (Some(queue_evt), Some(qi))
            } else {
                (None, None)
            };

        let mut handler = BalloonEpollHandler {
            mem,
            queues: virtqueues,
            interrupt_cb: interrupt_cb.clone(),
            inflate_queue_evt,
            deflate_queue_evt,
            stats_queue_evt,
            stats_request_evt,
            stats_request_receiver,
            stats_response_sender: None,
            stats_refresh_in_flight: false,
            stats_desc_index: None,
            stats_queue_index,
            reporting_queue_evt,
            reporting_queue_index,
            kill_evt,
            pause_evt,
            pbp: None,
            access_platform: self.common.access_platform(),
        };

        let paused = self.common.paused.clone();
        let paused_sync = self.common.paused_sync.clone();

        if let Err(e) = self.common.spawn_worker(
            &self.id,
            &self.seccomp_action,
            Thread::VirtioBalloon,
            &self.exit_evt,
            device_status.clone(),
            interrupt_cb.clone(),
            move || handler.run(&paused, paused_sync.as_ref().unwrap()),
        ) {
            self.stats_request_sender = None;
            return Err(e);
        }

        event!("virtio-device", "activated", "id", &self.id);
        Ok(())
    }

    fn set_access_platform(&mut self, access_platform: Arc<dyn AccessPlatform>) {
        self.common.set_access_platform(access_platform);
    }

    fn access_platform(&self) -> Option<Arc<dyn AccessPlatform>> {
        self.common.access_platform()
    }

    fn reset(&mut self) {
        self.stats_request_sender = None;
        self.common.reset();
        event!("virtio-device", "reset", "id", &self.id);
    }
}

impl Pausable for Balloon {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        self.common.pause()
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        self.common.resume()
    }
}

impl Snapshottable for Balloon {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> result::Result<Snapshot, MigratableError> {
        Snapshot::new_from_state(&self.state())
    }
}
impl Transportable for Balloon {}
impl Migratable for Balloon {}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::sync_channel;

    use vm_memory::bitmap::AtomicBitmap;
    use vm_virtio::queue::testing::VirtQueue;

    use super::*;

    type TestMemory = vm_memory::GuestMemoryMmap<AtomicBitmap>;

    struct NoopInterrupt;

    impl VirtioInterrupt for NoopInterrupt {
        fn trigger(&self, _int_type: VirtioInterruptType) -> io::Result<()> {
            Ok(())
        }

        fn set_notifier(
            &self,
            _int_type: u32,
            _notifier: Option<EventFd>,
            _vm: &dyn hypervisor::Vm,
        ) -> io::Result<()> {
            Ok(())
        }
    }

    fn stat(tag: u16, value: u64) -> Vec<u8> {
        BalloonStat {
            tag: Le16::new(tag),
            val: Le64::new(value),
        }
        .as_bytes()
        .to_vec()
    }

    #[test]
    fn parse_standard_and_linux_stats() {
        let mut data = Vec::new();
        for (tag, value) in (0u16..=15).zip(100u64..) {
            data.extend(stat(tag, value));
        }

        let stats = parse_balloon_stats(&data).unwrap();
        assert_eq!(stats.swap_in, Some(100));
        assert_eq!(stats.swap_out, Some(101));
        assert_eq!(stats.major_faults, Some(102));
        assert_eq!(stats.minor_faults, Some(103));
        assert_eq!(stats.free_memory, Some(104));
        assert_eq!(stats.total_memory, Some(105));
        assert_eq!(stats.available_memory, Some(106));
        assert_eq!(stats.disk_caches, Some(107));
        assert_eq!(stats.hugetlb_allocations, Some(108));
        assert_eq!(stats.hugetlb_failures, Some(109));
        assert_eq!(stats.oom_kills, Some(110));
        assert_eq!(stats.alloc_stalls, Some(111));
        assert_eq!(stats.async_scans, Some(112));
        assert_eq!(stats.direct_scans, Some(113));
        assert_eq!(stats.async_reclaims, Some(114));
        assert_eq!(stats.direct_reclaims, Some(115));
    }

    #[test]
    fn parse_stats_accepts_arbitrary_order_and_unknown_tags() {
        let data = [
            stat(VIRTIO_BALLOON_S_MEMTOT, 4096),
            stat(u16::MAX, 123),
            stat(VIRTIO_BALLOON_S_SWAP_IN, 10),
        ]
        .concat();

        let stats = parse_balloon_stats(&data).unwrap();
        assert_eq!(stats.total_memory, Some(4096));
        assert_eq!(stats.swap_in, Some(10));
        assert_eq!(stats.swap_out, None);
    }

    #[test]
    fn parse_stats_rejects_partial_entry() {
        let mut data = stat(VIRTIO_BALLOON_S_MEMFREE, 1024);
        data.push(0);

        assert!(matches!(
            parse_balloon_stats(&data),
            Err(BalloonStatsError::InvalidBufferLength(11))
        ));
    }

    #[test]
    fn stats_request_requires_negotiated_feature() {
        let balloon = Balloon::new(
            "balloon0".to_string(),
            0,
            false,
            false,
            false,
            SeccompAction::Allow,
            EventFd::new(EFD_NONBLOCK).unwrap(),
            None,
        )
        .unwrap();

        assert!(matches!(
            balloon.begin_stats_request(),
            Err(Error::StatsNotNegotiated)
        ));
    }

    #[test]
    fn stats_request_returns_fresh_descriptor() {
        const QUEUE_ADDRESS: GuestAddress = GuestAddress(0x1_0000);
        const STATS_ADDRESS: GuestAddress = GuestAddress(0x1_000);

        let memory = TestMemory::from_ranges(&[(GuestAddress(0), 0x2_0000)]).unwrap();
        let guest_queue = VirtQueue::new(QUEUE_ADDRESS, &memory, 16);
        let initial = stat(VIRTIO_BALLOON_S_MEMFREE, 100);
        memory.write_slice(&initial, STATS_ADDRESS).unwrap();
        guest_queue.dtable[0].set(STATS_ADDRESS.raw_value(), initial.len() as u32, 0, 0);
        guest_queue.avail.ring[0].set(0);
        guest_queue.avail.idx.set(1);

        let (request_sender, request_receiver) = mpsc::channel();
        let mut handler = BalloonEpollHandler {
            mem: GuestMemoryAtomic::new(memory.clone()),
            queues: vec![guest_queue.create_queue()],
            interrupt_cb: Arc::new(NoopInterrupt),
            inflate_queue_evt: EventFd::new(EFD_NONBLOCK).unwrap(),
            deflate_queue_evt: EventFd::new(EFD_NONBLOCK).unwrap(),
            stats_queue_evt: Some(EventFd::new(EFD_NONBLOCK).unwrap()),
            stats_request_evt: Some(EventFd::new(EFD_NONBLOCK).unwrap()),
            stats_request_receiver: Some(request_receiver),
            stats_response_sender: None,
            stats_refresh_in_flight: false,
            stats_desc_index: None,
            stats_queue_index: Some(0),
            reporting_queue_evt: None,
            reporting_queue_index: None,
            kill_evt: EventFd::new(EFD_NONBLOCK).unwrap(),
            pause_evt: EventFd::new(EFD_NONBLOCK).unwrap(),
            pbp: None,
            access_platform: None,
        };

        handler.process_stats_queue(0).unwrap();
        assert_eq!(handler.stats_desc_index, Some(0));

        let (response_sender, response_receiver) = sync_channel(1);
        request_sender
            .send(StatsRequest { response_sender })
            .unwrap();
        handler.process_stats_requests().unwrap();
        assert!(handler.stats_refresh_in_flight);
        assert_eq!(handler.stats_desc_index, None);

        let refreshed = stat(VIRTIO_BALLOON_S_MEMFREE, 200);
        memory.write_slice(&refreshed, STATS_ADDRESS).unwrap();
        guest_queue.avail.ring[1].set(0);
        guest_queue.avail.idx.set(2);
        handler.process_stats_queue(0).unwrap();

        assert_eq!(
            response_receiver.recv().unwrap().unwrap().free_memory,
            Some(200)
        );
        assert!(!handler.stats_refresh_in_flight);
        assert_eq!(handler.stats_desc_index, Some(0));
    }
}
