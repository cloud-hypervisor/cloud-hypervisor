// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::num::Wrapping;
use std::os::fd::BorrowedFd;
use std::sync::atomic::AtomicU8;
use std::sync::{Arc, Mutex};
use std::{cmp, io, process, result, thread};

use anyhow::anyhow;
use hypervisor::MemoryVisibility;
use libc::EFD_NONBLOCK;
use log::{error, info, warn};
use seccompiler::SeccompAction;
use virtio_bindings::virtio_config::VIRTIO_F_ACCESS_PLATFORM;
use virtio_queue::Queue;
use vm_allocator::page_size::is_page_size_aligned;
use vm_allocator::{MemorySlotAllocator, RangeMap};
use vm_memory::mmap::MmapRegionError;
use vm_memory::{Address, FileOffset, GuestAddress};
use vm_migration::{MigratableError, Pausable};
use vm_virtio::{AccessPlatform, AccessType, VirtioDeviceType};
use vmm_sys_util::eventfd::EventFd;

use crate::epoll_helper::EpollHelperError;
use crate::seccomp_filters::Thread;
use crate::thread_helper::spawn_virtio_thread;
use crate::{
    ActivateError, ActivateResult, Error, GuestMemory, GuestRegion, MmapRegion, PauseCommon,
    VIRTIO_F_RING_INDIRECT_DESC,
};

pub enum VirtioInterruptType {
    Config,
    Queue(u16),
}

pub trait VirtioInterrupt: Send + Sync {
    fn trigger(&self, int_type: VirtioInterruptType) -> io::Result<()>;
    fn notifier(&self, _int_type: VirtioInterruptType) -> io::Result<Option<EventFd>> {
        Ok(None)
    }
    fn set_notifier(
        &self,
        int_type: u32,
        notifier: Option<EventFd>,
        vm: &dyn hypervisor::Vm,
    ) -> io::Result<()>;
}

#[derive(Clone)]
pub struct VirtioSharedMemory {
    pub offset: u64,
    pub len: u64,
}

struct SharedMemoryBarState {
    addr: GuestAddress,
    mappings: RangeMap<GuestRegion>,
}

struct SharedMemoryBar {
    len: u64,
    region_list: Vec<VirtioSharedMemory>,
    vm: Arc<dyn hypervisor::Vm>,
    slot_allocator: Arc<MemorySlotAllocator>,
    state: Mutex<SharedMemoryBarState>,
}

/// Shared handle to a virtio shared memory PCI BAR and its active
/// per-submapping [`GuestRegion`]s.
///
/// Each dynamically mapped sub-region owns an independent `mmap` allocation and
/// hypervisor memory slot (`MAP_FIXED` is never used). A single mutex protects
/// the current BAR guest address and all active sub-mappings, serializing
/// `map_region`, `unmap_region`, `clear_mappings`, and `move_bar`.
#[derive(Clone)]
pub struct VirtioSharedMemoryList {
    bar: Arc<SharedMemoryBar>,
}

impl VirtioSharedMemoryList {
    pub fn new(
        addr: GuestAddress,
        len: u64,
        region_list: Vec<VirtioSharedMemory>,
        vm: Arc<dyn hypervisor::Vm>,
        slot_allocator: Arc<MemorySlotAllocator>,
    ) -> io::Result<Self> {
        if len == 0 || addr.raw_value().checked_add(len).is_none() {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        if region_list.len() > usize::from(u8::MAX) + 1 {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }

        // Verify all non-zero shared memory region windows fit within the BAR
        // and are pairwise disjoint so their BAR-relative offsets can share
        // one RangeMap without colliding across shmids.
        let mut windows = RangeMap::new();
        for shm in &region_list {
            if shm.len == 0 {
                continue;
            }
            if shm.offset.checked_add(shm.len).is_none_or(|end| end > len) {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }
            windows
                .insert(shm.offset, shm.len, ())
                .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
        }

        Ok(Self {
            bar: Arc::new(SharedMemoryBar {
                len,
                region_list,
                vm,
                slot_allocator,
                state: Mutex::new(SharedMemoryBarState {
                    addr,
                    mappings: RangeMap::new(),
                }),
            }),
        })
    }

    pub fn addr(&self) -> GuestAddress {
        self.bar.state.lock().unwrap().addr
    }

    pub fn len(&self) -> u64 {
        self.bar.len
    }

    pub fn is_empty(&self) -> bool {
        self.bar.len == 0
    }

    pub fn region_list(&self) -> &[VirtioSharedMemory] {
        &self.bar.region_list
    }

    #[cfg(test)]
    pub(crate) fn mapped_count(&self) -> usize {
        self.bar.state.lock().unwrap().mappings.len()
    }

    fn resolve_bar_offset(&self, shmid: u8, shm_offset: u64, len: u64) -> io::Result<u64> {
        if len == 0 {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        let region = self
            .bar
            .region_list
            .get(usize::from(shmid))
            .filter(|r| r.len > 0)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
        if shm_offset
            .checked_add(len)
            .is_none_or(|end| end > region.len)
        {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        let bar_offset = region
            .offset
            .checked_add(shm_offset)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
        if bar_offset
            .checked_add(len)
            .is_none_or(|end| end > self.bar.len)
        {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        Ok(bar_offset)
    }

    /// Map a file-backed sub-region into the shared memory BAR as its own
    /// independent `MmapRegion` and hypervisor memory slot.
    pub fn map_region(
        &self,
        shmid: u8,
        shm_offset: u64,
        len: u64,
        fd: BorrowedFd<'_>,
        fd_offset: u64,
        writable: bool,
    ) -> io::Result<()> {
        let bar_offset = self.resolve_bar_offset(shmid, shm_offset, len)?;
        let len_usize: usize = len
            .try_into()
            .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
        libc::off_t::try_from(fd_offset).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
        if fd_offset.checked_add(len).is_none() {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        if !is_page_size_aligned(len) || !is_page_size_aligned(fd_offset) {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }

        let mut state = self.bar.state.lock().unwrap();
        let guest_addr = state
            .addr
            .raw_value()
            .checked_add(bar_offset)
            .filter(|&addr| addr.checked_add(len).is_some())
            .map(GuestAddress)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
        if !is_page_size_aligned(guest_addr.raw_value()) {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }

        state
            .mappings
            .check_insert(bar_offset, len)
            .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;

        let file = File::from(fd.try_clone_to_owned()?);
        let prot = if writable {
            libc::PROT_READ | libc::PROT_WRITE
        } else {
            libc::PROT_READ
        };
        let mmap_region = MmapRegion::build(
            Some(FileOffset::new(file, fd_offset)),
            len_usize,
            prot,
            libc::MAP_SHARED,
        )
        .map_err(|err| match err {
            MmapRegionError::Mmap(os_err) => os_err,
            other => io::Error::other(other),
        })?;

        let region = GuestRegion::from_mmap(
            mmap_region,
            guest_addr,
            Arc::clone(&self.bar.vm),
            Arc::clone(&self.bar.slot_allocator),
            false,
            !writable,
            false,
            MemoryVisibility::Shared,
        )
        .map_err(io::Error::other)?;
        region.register().map_err(io::Error::other)?;

        state
            .mappings
            .insert(bar_offset, len, region)
            .map_err(io::Error::other)?;
        Ok(())
    }

    /// Unmap the exact sub-region previously mapped at `(shmid, shm_offset, len)`.
    pub fn unmap_region(&self, shmid: u8, shm_offset: u64, len: u64) -> io::Result<()> {
        let bar_offset = self.resolve_bar_offset(shmid, shm_offset, len)?;
        let mut state = self.bar.state.lock().unwrap();
        let region = state
            .mappings
            .remove_exact(bar_offset, len)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
        // Drop under the mutex so the hypervisor slot is removed before any
        // subsequent map_region or move_bar can touch the same guest range.
        drop(region);
        Ok(())
    }

    /// Unmap and unregister all active sub-mappings in this BAR.
    pub fn clear_mappings(&self) {
        self.bar.state.lock().unwrap().mappings.clear();
    }

    /// Relocate the BAR base address and all active sub-mappings to `new_base`.
    ///
    /// Moves are ordered so no two active hypervisor memory slots transiently
    /// overlap when the old and new BAR windows intersect. On failure, already
    /// moved regions are restored in reverse order back to their previous guest
    /// addresses.
    pub fn move_bar(&self, new_base: GuestAddress) -> io::Result<()> {
        let mut state = self.bar.state.lock().unwrap();
        let old_base = state.addr;
        if new_base == old_base {
            return Ok(());
        }
        if new_base.raw_value().checked_add(self.bar.len).is_none() {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }

        for (offset, len, _) in state.mappings.iter() {
            let Some(new_gpa) = new_base.raw_value().checked_add(offset) else {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            };
            if new_gpa.checked_add(len).is_none() || !is_page_size_aligned(new_gpa) {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }
        }

        let mut entries: Vec<(u64, &mut GuestRegion)> = state
            .mappings
            .iter_mut()
            .map(|(offset, _len, region)| (offset, region))
            .collect();
        if new_base > old_base {
            entries.reverse();
        }

        for i in 0..entries.len() {
            let (offset, region) = &mut entries[i];
            let was_registered = region.is_registered();
            let new_gpa = GuestAddress(new_base.raw_value() + *offset);
            if let Err(err) = region.move_guest_address(new_gpa) {
                // Restore the failing entry if its old slot was removed before
                // the new slot creation failed, then unwind previously moved
                // entries in exact reverse order to prevent transient overlaps.
                if was_registered
                    && !region.is_registered()
                    && let Err(rollback) = region.register()
                {
                    error!("FATAL: Failed to restore shared memory BAR mapping: {rollback}");
                    process::exit(1);
                }
                for (prev_offset, prev_region) in entries[..i].iter_mut().rev() {
                    let old_gpa = GuestAddress(old_base.raw_value() + *prev_offset);
                    if let Err(rollback) = prev_region.move_guest_address(old_gpa) {
                        error!("FATAL: Failed to restore shared memory BAR mapping: {rollback}");
                        process::exit(1);
                    }
                }
                return Err(io::Error::other(err));
            }
        }

        state.addr = new_base;
        Ok(())
    }
}

pub struct ActivationContext {
    pub mem: GuestMemory,
    pub interrupt_cb: Arc<dyn VirtioInterrupt>,
    pub queues: Vec<(u16, Queue, EventFd)>,
    pub device_status: Arc<AtomicU8>,
}

/// Trait for virtio devices to be driven by a virtio transport.
///
/// The lifecycle of a virtio device is to be moved to a virtio transport, which will then query the
/// device. Once the guest driver has configured the device, `VirtioDevice::activate` will be called
/// and all the events, memory, and queues for device operation will be moved into the device.
/// Optionally, a virtio device can implement device reset in which it returns said resources and
/// resets its internal.
pub trait VirtioDevice: Send {
    /// The virtio device type.
    fn device_type(&self) -> u32;

    /// The maximum size of each queue that this device supports.
    fn queue_max_sizes(&self) -> &[u16];

    /// Whether the device needs to register extra irqfds at runtime
    /// from external sources.
    /// The default is false.  If this is true, locking is required for
    /// most operations involving interrupts (but not for sending)
    /// interrupts from external irqfds).
    ///
    /// If the device claims to not need to register irqfds, but
    /// attempts to do so, a panic will ensue.
    fn interrupt_source_mutable(&self) -> bool {
        false
    }

    /// The set of feature bits that this device supports.
    fn features(&self) -> u64 {
        0
    }

    /// Acknowledges that this set of features should be enabled.
    fn ack_features(&mut self, value: u64) {
        let _ = value;
    }

    fn config_size(&self) -> Option<u64> {
        None
    }

    /// Reads this device configuration space at `offset`.
    fn read_config(&self, _offset: u64, _data: &mut [u8]) {
        warn!(
            "No readable configuration fields for {}",
            VirtioDeviceType::from(self.device_type())
        );
    }

    /// Writes to this device configuration space at `offset`.
    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        warn!(
            "No writable configuration fields for {}",
            VirtioDeviceType::from(self.device_type())
        );
    }

    /// Activates this device for real usage.
    fn activate(&mut self, context: ActivationContext) -> ActivateResult;

    /// Optionally deactivates this device.
    fn reset(&mut self) {}

    /// Returns the list of shared memory regions required by the device.
    fn get_shm_regions(&self) -> Option<VirtioSharedMemoryList> {
        None
    }

    /// Updates the list of shared memory regions required by the device.
    fn set_shm_regions(
        &mut self,
        _shm_regions: VirtioSharedMemoryList,
    ) -> result::Result<(), Error> {
        std::unimplemented!()
    }

    /// Some devices may need to do some explicit shutdown work. This method
    /// may be implemented to do this. The VMM should call shutdown() on
    /// every device as part of shutting down the VM. Acting on the device
    /// after a shutdown() can lead to unpredictable results.
    fn shutdown(&mut self) {}

    /// Return the counters that this device exposes
    fn counters(&self) -> Option<HashMap<&'static str, Wrapping<u64>>> {
        None
    }

    /// Helper to allow common implementation of read_config
    fn read_config_from_slice(&self, config: &[u8], offset: u64, mut data: &mut [u8]) {
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
        if let Some(end) = offset.checked_add(data.len() as u64) {
            data.write_all(&config[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    /// Set the access platform trait to let the device perform address
    /// translations if needed.
    fn set_access_platform(&mut self, _access_platform: Arc<dyn AccessPlatform>) {}

    /// Returns the access platform only if VIRTIO_F_ACCESS_PLATFORM was
    /// negotiated with the guest.
    fn access_platform(&self) -> Option<Arc<dyn AccessPlatform>> {
        None
    }

    /// Whether the device supports removal from its transport.
    fn is_removable(&self) -> bool {
        false
    }
}

/// Trait to define address translation for devices managed by virtio-iommu
///
/// Trait providing address translation the same way a physical DMA remapping
/// table would provide translation between an IOVA and a physical address.
/// The goal of this trait is to be used by virtio devices to perform the
/// address translation before they try to read from the guest physical address.
/// On the other side, the implementation itself should be provided by the code
/// emulating the IOMMU for the guest.
pub trait DmaRemapping {
    /// Provide a way to translate GVA address ranges into GPAs. The
    /// implementation must reject translations whose [addr, addr+size)
    /// span isn't entirely covered by a single mapping.
    fn translate_gva(
        &self,
        id: u32,
        addr: u64,
        size: u64,
        access_type: AccessType,
    ) -> io::Result<u64>;
    /// Provide a way to translate GPA address ranges into GVAs. Same
    /// span requirement as `translate_gva`.
    fn translate_gpa(&self, id: u32, addr: u64, size: u64) -> io::Result<u64>;
}

/// Owns a device's worker threads plus the kill event that stops them.
pub struct WorkerThreads {
    /// shared kill event, a single write wakes all of them.
    kill_evt: EventFd,
    pause_common: Arc<PauseCommon>,
    // The running worker thread's handles.
    threads: Vec<thread::JoinHandle<()>>,
}

impl WorkerThreads {
    fn new(kill_evt: EventFd, pause_common: Arc<PauseCommon>) -> Self {
        WorkerThreads {
            kill_evt,
            pause_common,
            threads: Vec::new(),
        }
    }

    /// Borrow access to the kill eventfd
    fn kill_evt(&self) -> &EventFd {
        &self.kill_evt
    }

    /// Signal the workers to exit without joining; they are joined later when
    /// this is dropped.
    pub(crate) fn signal_exit(&self) -> io::Result<()> {
        let result = self.kill_evt.write(1);
        self.pause_common.resume();
        result
    }
}

impl Drop for WorkerThreads {
    fn drop(&mut self) {
        let _ = self.signal_exit();
        for t in self.threads.drain(..) {
            if let Err(e) = t.join() {
                error!("Error joining thread: {e:?}");
            }
        }
    }
}

/// Structure to handle device state common to all devices
pub struct VirtioCommon {
    pub avail_features: u64,
    pub acked_features: u64,
    pub interrupt_cb: Option<Arc<dyn VirtioInterrupt>>,
    pub pause_common: Arc<PauseCommon>,
    pub workers: Option<WorkerThreads>,
    pub queue_sizes: Vec<u16>,
    pub queue_evts: Vec<(u16, EventFd)>,
    pub device_type: u32,
    pub min_queues: u16,
    pub access_platform: Option<Arc<dyn AccessPlatform>>,
}

impl VirtioCommon {
    pub fn new(pause_requested: bool) -> io::Result<Self> {
        Ok(Self {
            avail_features: 0,
            acked_features: 0,
            interrupt_cb: None,
            pause_common: Arc::new(PauseCommon::new(pause_requested)?),
            workers: None,
            queue_sizes: Vec::new(),
            queue_evts: Vec::new(),
            device_type: 0,
            min_queues: 0,
            access_platform: None,
        })
    }

    pub fn feature_acked(&self, feature: u64) -> bool {
        self.acked_features & (1 << feature) == 1 << feature
    }

    pub fn ack_features(&mut self, value: u64) {
        let mut v = value;
        // Check if the guest is ACK'ing a feature that we didn't claim to have.
        let unrequested_features = v & !self.avail_features;
        if unrequested_features != 0 {
            warn!("Received acknowledge request for unknown feature.");

            // Don't count these features as acked.
            v &= !unrequested_features;
        }
        self.acked_features = v;
    }

    pub(crate) fn check_access_platform(&self) -> ActivateResult {
        let access_platform = 1u64 << VIRTIO_F_ACCESS_PLATFORM;
        if self.avail_features & access_platform != 0 && self.acked_features & access_platform == 0
        {
            return Err(ActivateError::AccessPlatformNotAcknowledged);
        }
        Ok(())
    }

    pub fn activate(
        &mut self,
        queues: &[(u16, Queue, EventFd)],
        interrupt_cb: Arc<dyn VirtioInterrupt>,
    ) -> ActivateResult {
        self.check_access_platform()?;

        if queues.len() < self.min_queues.into() {
            error!(
                "Number of enabled queues lower than min: {} vs {}",
                queues.len(),
                self.min_queues
            );
            return Err(ActivateError::BadActivate);
        }

        self.queue_evts = queues
            .iter()
            .map(|(queue_index, _, queue_evt)| {
                queue_evt
                    .try_clone()
                    .map(|queue_evt| (*queue_index, queue_evt))
                    .map_err(|e| {
                        error!("Failed cloning queue EventFd: {e}");
                        ActivateError::BadActivate
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let kill_evt = EventFd::new(EFD_NONBLOCK).map_err(|e| {
            error!("failed creating kill EventFd: {e}");
            ActivateError::BadActivate
        })?;
        // Create the worker collection up front so it owns the kill event;
        // handlers clone it via dup_eventfds() before any worker is spawned.
        self.workers = Some(WorkerThreads::new(kill_evt, Arc::clone(&self.pause_common)));

        // Save the interrupt EventFD as we need to return it on reset
        // but clone it to pass into the thread.
        self.interrupt_cb = Some(interrupt_cb);

        Ok(())
    }

    pub fn reset(&mut self) {
        self.queue_evts.clear();
        self.workers = None;
        self.pause_common.reset();

        // Drop the interrupt callback clone
        self.interrupt_cb = None;
    }

    /// Spawn a worker; on failure, reset the device to join prior workers.
    #[expect(clippy::too_many_arguments)]
    pub fn spawn_worker<F>(
        &mut self,
        name: &str,
        seccomp_action: &SeccompAction,
        thread_type: Thread,
        exit_evt: &EventFd,
        device_status: Arc<AtomicU8>,
        interrupt_cb: Arc<dyn VirtioInterrupt>,
        f: F,
    ) -> Result<(), ActivateError>
    where
        F: FnOnce(&PauseCommon) -> Result<(), EpollHelperError> + Send + 'static,
    {
        // Scope the borrow of `workers` so it ends before the reset() below.
        let res = {
            let Some(workers) = self.workers.as_mut() else {
                error!("spawn_worker called before activate()");
                return Err(ActivateError::BadActivate);
            };
            spawn_virtio_thread(
                name,
                seccomp_action,
                thread_type,
                &mut workers.threads,
                exit_evt,
                device_status,
                interrupt_cb,
                Arc::clone(&self.pause_common),
                f,
            )
        };
        if let Err(e) = res {
            self.reset();
            return Err(e);
        }
        Ok(())
    }

    pub fn trigger_interrupt(&self, int_type: VirtioInterruptType) -> io::Result<()> {
        if let Some(interrupt_cb) = &self.interrupt_cb {
            interrupt_cb.trigger(int_type)
        } else {
            Ok(())
        }
    }

    pub fn wait_for_epoll_threads(&mut self) {
        self.workers = None;
    }

    pub fn dup_eventfds(&self) -> Result<(EventFd, EventFd), ActivateError> {
        let kill_evt = self
            .workers
            .as_ref()
            .ok_or(ActivateError::BadActivate)?
            .kill_evt()
            .try_clone()
            .map_err(ActivateError::CloneEventFd)?;
        let pause_evt = self
            .pause_common
            .pause_evt()
            .try_clone()
            .map_err(ActivateError::CloneEventFd)?;
        Ok((kill_evt, pause_evt))
    }

    pub fn set_access_platform(&mut self, access_platform: Arc<dyn AccessPlatform>) {
        self.access_platform = Some(access_platform);
        // Indirect descriptors feature is not supported when the device
        // requires the addresses held by the descriptors to be translated.
        self.avail_features &= !(1 << VIRTIO_F_RING_INDIRECT_DESC);
    }

    /// Returns the access platform only if the feature has been acked.
    pub fn access_platform(&self) -> Option<Arc<dyn AccessPlatform>> {
        if self.feature_acked(VIRTIO_F_ACCESS_PLATFORM as u64) {
            self.access_platform.clone()
        } else {
            None
        }
    }
}

impl Pausable for VirtioCommon {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        info!(
            "Pausing virtio-{}",
            VirtioDeviceType::from(self.device_type)
        );

        self.pause_common
            .pause()
            .map_err(|e| MigratableError::Pause(e.into()))
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        info!(
            "Resuming virtio-{}",
            VirtioDeviceType::from(self.device_type)
        );
        self.pause_common.resume();

        // Signal each activated queue eventfd so workers process restored queues
        // that may already contain pending requests.
        for (_, queue_evt) in &self.queue_evts {
            queue_evt.write(1).map_err(|e| {
                MigratableError::Resume(anyhow!(
                    "Could not notify restored virtio worker on resume: {e}"
                ))
            })?;
        }

        // Also trigger interrupts into the guest to wake up the driver to avoid a "livelock"
        for (queue_index, _) in &self.queue_evts {
            self.trigger_interrupt(crate::VirtioInterruptType::Queue(*queue_index))
                .ok();
        }

        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::any::Any;
    use std::collections::HashMap;
    use std::fs::File;
    use std::mem;
    use std::os::fd::{AsFd, AsRawFd};
    use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use std::sync::{Mutex, mpsc};
    use std::time::Duration;

    #[cfg(target_arch = "x86_64")]
    use hypervisor::ClockData;
    #[cfg(target_arch = "aarch64")]
    use hypervisor::VcpuInit;
    #[cfg(target_arch = "aarch64")]
    use hypervisor::arch::aarch64::gic::{Vgic, VgicConfig};
    #[cfg(target_arch = "riscv64")]
    use hypervisor::arch::riscv64::aia::{Vaia, VaiaConfig};
    #[cfg(target_arch = "x86_64")]
    use hypervisor::arch::x86::VcpuMsrConfigUpdate;
    use hypervisor::{
        DataMatch, HypervisorVmError, InterruptSourceConfig, IoEventAddress, IrqRoutingEntry, Vcpu,
        Vm, VmOps,
    };
    #[cfg(feature = "sev_snp")]
    use igvm_defs::SnpPolicy;
    use vfio_ioctls::VfioDeviceFd;
    use virtio_queue::QueueT;
    use vm_allocator::page_size::get_page_size;
    use vmm_sys_util::eventfd::EFD_NONBLOCK;
    use vmm_sys_util::tempdir::TempDir;

    use super::*;
    use crate::epoll_helper::EPOLL_HELPER_EVENT_PAUSE;
    use crate::{EPOLL_HELPER_EVENT_LAST, EpollHelper, EpollHelperHandler};

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(crate) struct RecordedSlot {
        pub(crate) gpa: u64,
        pub(crate) size: usize,
        pub(crate) userspace_addr: usize,
        pub(crate) readonly: bool,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(crate) enum VmMemoryOp {
        Create {
            slot: u32,
            gpa: u64,
            size: usize,
            readonly: bool,
        },
        Remove {
            slot: u32,
            gpa: u64,
            size: usize,
            readonly: bool,
        },
    }

    #[derive(Default)]
    struct MockVmState {
        slots: HashMap<u32, RecordedSlot>,
        gpa_ranges: RangeMap<u32>,
        ops: Vec<VmMemoryOp>,
        fail_create_at: Option<u64>,
        fail_remove_at: Option<u64>,
    }

    #[derive(Default)]
    pub(crate) struct MockVm {
        state: Mutex<MockVmState>,
    }

    impl MockVm {
        pub(crate) fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }

        pub(crate) fn active_slots(&self) -> Vec<(u32, RecordedSlot)> {
            let state = self.state.lock().unwrap();
            let mut entries: Vec<_> = state
                .slots
                .iter()
                .map(|(&slot, r)| (slot, r.clone()))
                .collect();
            entries.sort_by_key(|(_, r)| r.gpa);
            entries
        }

        pub(crate) fn active_slot_count(&self) -> usize {
            self.state.lock().unwrap().slots.len()
        }

        pub(crate) fn take_ops(&self) -> Vec<VmMemoryOp> {
            mem::take(&mut self.state.lock().unwrap().ops)
        }

        pub(crate) fn fail_next_create_at(&self, gpa: u64) {
            self.state.lock().unwrap().fail_create_at = Some(gpa);
        }

        pub(crate) fn fail_next_remove_at(&self, gpa: u64) {
            self.state.lock().unwrap().fail_remove_at = Some(gpa);
        }
    }

    impl Vm for MockVm {
        #[cfg(target_arch = "x86_64")]
        fn set_identity_map_address(&self, _address: u64) -> result::Result<(), HypervisorVmError> {
            unimplemented!()
        }

        #[cfg(target_arch = "x86_64")]
        fn set_tss_address(&self, _offset: usize) -> result::Result<(), HypervisorVmError> {
            unimplemented!()
        }

        #[cfg(not(target_arch = "riscv64"))]
        fn create_irq_chip(&self) -> result::Result<(), HypervisorVmError> {
            unimplemented!()
        }

        fn register_irqfd(
            &self,
            _fd: &EventFd,
            _gsi: u32,
        ) -> result::Result<(), HypervisorVmError> {
            unimplemented!()
        }

        fn unregister_irqfd(
            &self,
            _fd: &EventFd,
            _gsi: u32,
        ) -> result::Result<(), HypervisorVmError> {
            unimplemented!()
        }

        fn create_vcpu(
            &self,
            _id: u32,
            _vm_ops: Option<Arc<dyn VmOps>>,
            #[cfg(target_arch = "x86_64")] _msr_config_update: Option<VcpuMsrConfigUpdate>,
        ) -> result::Result<Box<dyn Vcpu>, HypervisorVmError> {
            unimplemented!()
        }

        #[cfg(target_arch = "aarch64")]
        fn create_vgic(
            &self,
            _config: &VgicConfig,
        ) -> result::Result<Arc<Mutex<dyn Vgic>>, HypervisorVmError> {
            unimplemented!()
        }

        #[cfg(target_arch = "riscv64")]
        fn create_vaia(
            &self,
            _config: &VaiaConfig,
        ) -> result::Result<Arc<Mutex<dyn Vaia>>, HypervisorVmError> {
            unimplemented!()
        }

        fn register_ioevent(
            &self,
            _fd: &EventFd,
            _addr: &IoEventAddress,
            _datamatch: Option<DataMatch>,
        ) -> result::Result<(), HypervisorVmError> {
            unimplemented!()
        }

        fn unregister_ioevent(
            &self,
            _fd: &EventFd,
            _addr: &IoEventAddress,
        ) -> result::Result<(), HypervisorVmError> {
            unimplemented!()
        }

        fn make_routing_entry(
            &self,
            _gsi: u32,
            _config: &InterruptSourceConfig,
        ) -> IrqRoutingEntry {
            unimplemented!()
        }

        fn set_gsi_routing(
            &self,
            _entries: &[IrqRoutingEntry],
        ) -> result::Result<(), HypervisorVmError> {
            unimplemented!()
        }

        unsafe fn create_user_memory_region(
            &self,
            slot: u32,
            guest_phys_addr: u64,
            memory_size: usize,
            userspace_addr: *mut u8,
            readonly: bool,
            log_dirty_pages: bool,
            visibility: MemoryVisibility,
        ) -> result::Result<(), HypervisorVmError> {
            assert!(!userspace_addr.is_null());
            assert!(!log_dirty_pages);
            assert_eq!(visibility, MemoryVisibility::Shared);
            let mut state = self.state.lock().unwrap();
            if state.fail_create_at == Some(guest_phys_addr) {
                state.fail_create_at = None;
                return Err(HypervisorVmError::CreateUserMemory(anyhow!(
                    "injected create failure at {guest_phys_addr:#x}"
                )));
            }
            if state.slots.contains_key(&slot) {
                return Err(HypervisorVmError::CreateUserMemory(anyhow!(
                    "duplicate slot {slot}"
                )));
            }
            if state
                .gpa_ranges
                .insert(guest_phys_addr, memory_size as u64, slot)
                .is_err()
            {
                return Err(HypervisorVmError::CreateUserMemory(anyhow!(
                    "overlapping guest memory slot at {guest_phys_addr:#x} size {memory_size:#x}"
                )));
            }
            state.slots.insert(
                slot,
                RecordedSlot {
                    gpa: guest_phys_addr,
                    size: memory_size,
                    userspace_addr: userspace_addr as usize,
                    readonly,
                },
            );
            state.ops.push(VmMemoryOp::Create {
                slot,
                gpa: guest_phys_addr,
                size: memory_size,
                readonly,
            });
            Ok(())
        }

        unsafe fn remove_user_memory_region(
            &self,
            slot: u32,
            guest_phys_addr: u64,
            memory_size: usize,
            userspace_addr: *mut u8,
            readonly: bool,
        ) -> result::Result<(), HypervisorVmError> {
            let mut state = self.state.lock().unwrap();
            if state.fail_remove_at == Some(guest_phys_addr) {
                state.fail_remove_at = None;
                return Err(HypervisorVmError::RemoveUserMemory(anyhow!(
                    "injected remove failure at {guest_phys_addr:#x}"
                )));
            }
            let Some(existing) = state.slots.remove(&slot) else {
                return Err(HypervisorVmError::RemoveUserMemory(anyhow!(
                    "missing slot {slot}"
                )));
            };
            assert_eq!(existing.gpa, guest_phys_addr);
            assert_eq!(existing.size, memory_size);
            assert_eq!(existing.userspace_addr, userspace_addr as usize);
            assert_eq!(existing.readonly, readonly);
            assert_eq!(
                state
                    .gpa_ranges
                    .remove_exact(guest_phys_addr, memory_size as u64),
                Some(slot)
            );
            state.ops.push(VmMemoryOp::Remove {
                slot,
                gpa: guest_phys_addr,
                size: memory_size,
                readonly,
            });
            Ok(())
        }

        #[cfg(target_arch = "aarch64")]
        fn get_preferred_target(
            &self,
            _kvi: &mut VcpuInit,
        ) -> result::Result<(), HypervisorVmError> {
            unimplemented!()
        }

        #[cfg(target_arch = "x86_64")]
        fn enable_split_irq(&self) -> result::Result<(), HypervisorVmError> {
            unimplemented!()
        }

        #[cfg(target_arch = "x86_64")]
        fn get_clock(&self) -> result::Result<ClockData, HypervisorVmError> {
            unimplemented!()
        }

        #[cfg(target_arch = "x86_64")]
        fn set_clock(&self, _data: &ClockData) -> result::Result<(), HypervisorVmError> {
            unimplemented!()
        }

        fn create_passthrough_device(&self) -> result::Result<VfioDeviceFd, HypervisorVmError> {
            unimplemented!()
        }

        fn start_dirty_log(&self) -> result::Result<(), HypervisorVmError> {
            unimplemented!()
        }

        fn stop_dirty_log(&self) -> result::Result<(), HypervisorVmError> {
            unimplemented!()
        }

        fn get_dirty_log(
            &self,
            _slot: u32,
            _base_gpa: u64,
            _memory_size: u64,
        ) -> result::Result<Vec<u64>, HypervisorVmError> {
            unimplemented!()
        }

        #[cfg(feature = "sev_snp")]
        fn sev_snp_init(&self, _guest_policy: SnpPolicy) -> result::Result<(), HypervisorVmError> {
            unimplemented!()
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    pub(crate) fn new_test_slot_allocator() -> Arc<MemorySlotAllocator> {
        Arc::new(MemorySlotAllocator::new(
            Arc::new(AtomicU32::new(0)),
            Arc::new(Mutex::new(Vec::new())),
        ))
    }

    #[derive(Default)]
    struct RecordingInterrupt {
        queue_indices: Mutex<Vec<u16>>,
    }

    impl VirtioInterrupt for RecordingInterrupt {
        fn trigger(&self, int_type: VirtioInterruptType) -> io::Result<()> {
            if let VirtioInterruptType::Queue(queue_index) = int_type {
                self.queue_indices.lock().unwrap().push(queue_index);
            }
            Ok(())
        }

        fn set_notifier(
            &self,
            _: u32,
            _: Option<EventFd>,
            _: &dyn hypervisor::Vm,
        ) -> io::Result<()> {
            Ok(())
        }
    }

    struct NoopInterrupt;
    impl VirtioInterrupt for NoopInterrupt {
        fn trigger(&self, _: VirtioInterruptType) -> io::Result<()> {
            Ok(())
        }
        fn set_notifier(
            &self,
            _: u32,
            _: Option<EventFd>,
            _: &dyn hypervisor::Vm,
        ) -> io::Result<()> {
            Ok(())
        }
    }

    struct QueueEventHandler {
        queue_evt: EventFd,
        entered: mpsc::Sender<()>,
        ready: mpsc::Receiver<()>,
        processed: mpsc::Sender<u64>,
    }

    impl QueueEventHandler {
        fn run(
            &mut self,
            kill_evt: &EventFd,
            pause_evt: &EventFd,
            pause_common: &PauseCommon,
        ) -> Result<(), EpollHelperError> {
            self.entered.send(()).unwrap();
            self.ready.recv().unwrap();
            let mut helper = EpollHelper::new(kill_evt, pause_evt)?;
            helper.add_event(self.queue_evt.as_raw_fd(), EPOLL_HELPER_EVENT_LAST + 1)?;
            helper.run(pause_common, self)
        }
    }

    impl EpollHelperHandler for QueueEventHandler {
        fn handle_event(
            &mut self,
            _: &mut EpollHelper,
            _: &epoll::Event,
        ) -> Result<(), EpollHelperError> {
            self.processed.send(self.queue_evt.read().unwrap()).unwrap();
            Ok(())
        }
    }

    struct PauseTestDevice {
        exit_evt: EventFd,
        status: Arc<AtomicU8>,
        entering: mpsc::Receiver<()>,
        requests: mpsc::Receiver<u64>,
        releases: Vec<mpsc::Sender<()>>,
        queue_evts: Vec<EventFd>,
        common: VirtioCommon,
    }

    impl PauseTestDevice {
        const TIMEOUT: Duration = Duration::from_secs(5);

        fn new() -> Self {
            let exit_evt = EventFd::new(EFD_NONBLOCK).unwrap();
            let status = Arc::new(AtomicU8::new(0));
            let mut common = VirtioCommon {
                device_type: VirtioDeviceType::Block as u32,
                ..VirtioCommon::new(true).unwrap()
            };
            common.activate(&[], Arc::new(NoopInterrupt)).unwrap();
            let (entered, entering) = mpsc::channel();
            let (processed, requests) = mpsc::channel();
            let mut releases = Vec::new();
            let mut queue_evts = Vec::new();

            for index in 0..2 {
                let queue_evt = EventFd::new(EFD_NONBLOCK).unwrap();
                queue_evts.push(queue_evt.try_clone().unwrap());
                let (release, ready) = mpsc::channel();
                releases.push(release);
                let mut handler = QueueEventHandler {
                    queue_evt,
                    entered: entered.clone(),
                    ready,
                    processed: processed.clone(),
                };
                let (kill_evt, pause_evt) = common.dup_eventfds().unwrap();
                common
                    .spawn_worker(
                        &format!("pause_test_{index}"),
                        &SeccompAction::Allow,
                        Thread::VirtioBlock,
                        &exit_evt,
                        Arc::clone(&status),
                        Arc::new(NoopInterrupt),
                        move |pause_common| handler.run(&kill_evt, &pause_evt, pause_common),
                    )
                    .unwrap();
            }

            Self {
                exit_evt,
                status,
                entering,
                requests,
                releases,
                queue_evts,
                common,
            }
        }

        fn pause_during_startup(mut self) -> Self {
            self.common.resume().unwrap();
            for _ in &self.queue_evts {
                self.entering
                    .recv_timeout(Self::TIMEOUT)
                    .expect("Thread did not enter handler startup");
            }
            let pause_common = Arc::clone(&self.common.pause_common);
            let pause_evt = self.common.pause_common.pause_evt();
            let pause_monitor = EpollHelper::new(&self.exit_evt, pause_evt).unwrap();
            let (paused, completed) = mpsc::channel();
            let pausing = thread::spawn(move || {
                self.common.pause().unwrap();
                paused.send(self.common).unwrap();
            });
            let mut events = [epoll::Event::new(epoll::Events::empty(), 0)];
            assert_eq!(
                epoll::wait(
                    pause_monitor.as_raw_fd(),
                    Self::TIMEOUT.as_millis() as i32,
                    &mut events,
                )
                .unwrap(),
                1
            );
            let event_id = events[0].data;
            assert_eq!(event_id, u64::from(EPOLL_HELPER_EVENT_PAUSE));
            assert!(pause_common.pause_requested());
            for release in self.releases.drain(..) {
                release.send(()).unwrap();
            }
            self.common = completed
                .recv_timeout(Self::TIMEOUT)
                .expect("Late threads did not acknowledge pause");
            pausing.join().unwrap();
            self
        }

        fn resume_and_pause(mut self) -> Self {
            let (paused, completed) = mpsc::channel();
            let pausing = thread::spawn(move || {
                self.common.resume().unwrap();
                self.common.pause().unwrap();
                paused.send(self.common).unwrap();
            });
            self.common = completed
                .recv_timeout(Self::TIMEOUT)
                .expect("Pause after immediate resume did not complete");
            pausing.join().unwrap();
            self
        }
    }

    /// VirtioCommon with its worker collection created (as activate() does)
    /// and a kill_evt clone for the spawned worker to watch.
    fn make_common_with_workers() -> (VirtioCommon, EventFd) {
        let kill_evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let kill_evt_clone = kill_evt.try_clone().unwrap();
        let common = VirtioCommon::new(false).unwrap();
        let workers = WorkerThreads::new(kill_evt, Arc::clone(&common.pause_common));
        let common = VirtioCommon {
            workers: Some(workers),
            ..common
        };
        (common, kill_evt_clone)
    }

    #[test]
    fn activate_requires_acknowledgment_only_when_access_platform_is_offered() {
        let access_platform = 1u64 << VIRTIO_F_ACCESS_PLATFORM;

        for (offered, acknowledged, should_activate) in [
            (false, false, true),
            (false, true, true),
            (true, false, false),
            (true, true, true),
        ] {
            let mut common = VirtioCommon {
                avail_features: if offered { access_platform } else { 0 },
                ..VirtioCommon::new(false).unwrap()
            };
            if acknowledged {
                common.ack_features(access_platform);
            }
            let result = common.activate(&[], Arc::new(NoopInterrupt));

            if should_activate {
                assert!(
                    result.is_ok(),
                    "offered={offered}, acknowledged={acknowledged}"
                );
            } else {
                assert!(matches!(
                    result,
                    Err(ActivateError::AccessPlatformNotAcknowledged)
                ));
                assert!(common.workers.is_none());
            }
        }
    }

    #[test]
    fn spawn_worker_appends_to_workers() {
        let (mut common, kill_evt_clone) = make_common_with_workers();
        let started = Arc::new(AtomicUsize::new(0));
        let started_clone = Arc::clone(&started);

        let exit_evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let status = Arc::new(AtomicU8::new(0));

        common
            .spawn_worker(
                "test",
                &SeccompAction::Allow,
                Thread::VirtioBlock,
                &exit_evt,
                status,
                Arc::new(NoopInterrupt),
                move |_| {
                    started_clone.fetch_add(1, Ordering::SeqCst);
                    let _ = kill_evt_clone.read();
                    Ok(())
                },
            )
            .unwrap();

        let workers = common.workers.as_ref().expect("workers set");
        assert_eq!(workers.threads.len(), 1);

        // reset() drops the WorkerThreads and joins the worker, exercising
        // the spawn-failure cleanup path on a real running thread.
        common.reset();
        assert!(common.workers.is_none());
        assert_eq!(started.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn dropping_common_joins_workers() {
        let (mut common, kill_evt_clone) = make_common_with_workers();
        let started = Arc::new(AtomicUsize::new(0));
        let started_clone = Arc::clone(&started);

        let exit_evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let status = Arc::new(AtomicU8::new(0));

        common
            .spawn_worker(
                "test",
                &SeccompAction::Allow,
                Thread::VirtioBlock,
                &exit_evt,
                status,
                Arc::new(NoopInterrupt),
                move |_| {
                    started_clone.fetch_add(1, Ordering::SeqCst);
                    let _ = kill_evt_clone.read();
                    Ok(())
                },
            )
            .unwrap();

        // Dropping `common` alone must join the worker via WorkerThreads' Drop.
        drop(common);
        assert_eq!(started.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn resume_preserves_sparse_queue_indices() {
        let interrupt = Arc::new(RecordingInterrupt::default());
        let queues = vec![
            (
                1,
                Queue::new(256).unwrap(),
                EventFd::new(EFD_NONBLOCK).unwrap(),
            ),
            (
                3,
                Queue::new(256).unwrap(),
                EventFd::new(EFD_NONBLOCK).unwrap(),
            ),
        ];
        let mut common = VirtioCommon::new(false).unwrap();
        let interrupt_cb = Arc::clone(&interrupt) as Arc<dyn VirtioInterrupt>;

        common.activate(&queues, interrupt_cb).unwrap();
        common.resume().unwrap();

        assert_eq!(queues[0].2.read().unwrap(), 1);
        assert_eq!(queues[1].2.read().unwrap(), 1);
        assert_eq!(*interrupt.queue_indices.lock().unwrap(), vec![1, 3]);
    }

    #[test]
    fn reset_clears_paused_without_workers() {
        // reset() before any worker was spawned must still clear paused, or
        // the next activation's workers would park immediately and never run.
        let mut common = VirtioCommon::new(false).unwrap();
        common.pause_common.pause().unwrap();
        assert!(common.workers.is_none());

        common.reset();

        assert!(!common.pause_common.pause_requested());
    }

    #[test]
    fn pause_handles_late_threads_and_immediate_resume() {
        let mut device = PauseTestDevice::new();

        // Late threads must acknowledge pause before processing queued work.
        device = device.pause_during_startup();
        for (index, queue_evt) in device.queue_evts.iter().enumerate() {
            queue_evt.write(index as u64 + 1).unwrap();
        }
        assert!(matches!(
            device.requests.recv_timeout(Duration::from_millis(20)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));

        // A brief resume must not prevent the following pause from completing.
        device = device.resume_and_pause();
        device.common.resume().unwrap();
        let timeout = PauseTestDevice::TIMEOUT;
        let mut values = vec![
            device.requests.recv_timeout(timeout).unwrap(),
            device.requests.recv_timeout(timeout).unwrap(),
        ];
        values.sort_unstable();
        assert_eq!(values, vec![1, 2]);
        device.common.reset();
        assert_eq!(device.status.load(Ordering::SeqCst), 0);
    }

    fn create_test_backing_file(size: u64) -> (TempDir, File) {
        let temp_dir = TempDir::new_with_prefix("/tmp/virtio-shm-bar-").unwrap();
        let file = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(temp_dir.as_path().join("blob"))
            .unwrap();
        file.set_len(size).unwrap();
        (temp_dir, file)
    }

    #[test]
    fn shm_list_rejects_invalid_descriptors() {
        let page = get_page_size();
        let vm = MockVm::new();
        let alloc = new_test_slot_allocator();

        // Zero-length BAR
        assert!(
            VirtioSharedMemoryList::new(
                GuestAddress(page),
                0,
                vec![],
                Arc::clone(&vm) as Arc<dyn Vm>,
                Arc::clone(&alloc),
            )
            .is_err()
        );
        // BAR address overflow
        assert!(
            VirtioSharedMemoryList::new(
                GuestAddress(u64::MAX - page + 2),
                page,
                vec![],
                Arc::clone(&vm) as Arc<dyn Vm>,
                Arc::clone(&alloc),
            )
            .is_err()
        );
        // Region exceeds BAR
        assert!(
            VirtioSharedMemoryList::new(
                GuestAddress(page),
                2 * page,
                vec![VirtioSharedMemory {
                    offset: page,
                    len: 2 * page,
                }],
                Arc::clone(&vm) as Arc<dyn Vm>,
                Arc::clone(&alloc),
            )
            .is_err()
        );
        // Overlapping non-zero regions
        assert!(
            VirtioSharedMemoryList::new(
                GuestAddress(page),
                4 * page,
                vec![
                    VirtioSharedMemory {
                        offset: 0,
                        len: 2 * page,
                    },
                    VirtioSharedMemory {
                        offset: page,
                        len: 2 * page,
                    },
                ],
                Arc::clone(&vm) as Arc<dyn Vm>,
                Arc::clone(&alloc),
            )
            .is_err()
        );
        // More than 256 shmids (u8::MAX + 1)
        assert!(
            VirtioSharedMemoryList::new(
                GuestAddress(page),
                page,
                vec![VirtioSharedMemory { offset: 0, len: 0 }; 257],
                Arc::clone(&vm) as Arc<dyn Vm>,
                alloc,
            )
            .is_err()
        );
    }

    #[test]
    fn shm_list_move_bar_ordering_and_rollback() {
        let page = get_page_size();
        let (_dir, file) = create_test_backing_file(4 * page);
        let vm = MockVm::new();
        let alloc = new_test_slot_allocator();
        let initial_base = 0x10 * page;
        let shm_list = VirtioSharedMemoryList::new(
            GuestAddress(initial_base),
            8 * page,
            vec![
                VirtioSharedMemory {
                    offset: 0,
                    len: 4 * page,
                },
                VirtioSharedMemory {
                    offset: 4 * page,
                    len: 4 * page,
                },
            ],
            Arc::clone(&vm) as Arc<dyn Vm>,
            alloc,
        )
        .unwrap();

        // Map three contiguous pages, including a read-only entry.
        shm_list
            .map_region(0, 0, page, file.as_fd(), 0, true)
            .unwrap();
        shm_list
            .map_region(0, page, page, file.as_fd(), page, false)
            .unwrap();
        shm_list
            .map_region(0, 2 * page, page, file.as_fd(), 2 * page, true)
            .unwrap();
        assert_eq!(shm_list.mapped_count(), 3);
        assert_eq!(vm.active_slot_count(), 3);

        // No-op move when new_base == old_base
        let _ = vm.take_ops();
        shm_list.move_bar(GuestAddress(initial_base)).unwrap();
        assert!(vm.take_ops().is_empty());

        // Move UP by 1 page (overlapping old range!): descending order avoids
        // any transient overlap inside `MockVm`.
        let up_base = initial_base + page;
        shm_list.move_bar(GuestAddress(up_base)).unwrap();
        assert_eq!(shm_list.addr(), GuestAddress(up_base));
        let ops = vm.take_ops();
        let created_gpas: Vec<u64> = ops
            .iter()
            .filter_map(|op| match op {
                VmMemoryOp::Create { gpa, .. } => Some(*gpa),
                VmMemoryOp::Remove { .. } => None,
            })
            .collect();
        assert_eq!(
            created_gpas,
            vec![up_base + 2 * page, up_base + page, up_base]
        );

        // Move DOWN by 1 page (overlapping old range!): ascending order avoids
        // any transient overlap inside `MockVm`.
        shm_list.move_bar(GuestAddress(initial_base)).unwrap();
        assert_eq!(shm_list.addr(), GuestAddress(initial_base));
        let ops = vm.take_ops();
        let created_gpas: Vec<u64> = ops
            .iter()
            .filter_map(|op| match op {
                VmMemoryOp::Create { gpa, .. } => Some(*gpa),
                VmMemoryOp::Remove { .. } => None,
            })
            .collect();
        assert_eq!(
            created_gpas,
            vec![initial_base, initial_base + page, initial_base + 2 * page]
        );

        // Inject a CreateRegion failure on the 2nd entry moving UP; verify both
        // the unregistered failing entry and already-moved entry roll back cleanly.
        let before_slots = vm.active_slots();
        vm.fail_next_create_at(up_base + page);
        let _ = shm_list.move_bar(GuestAddress(up_base)).unwrap_err();
        assert_eq!(shm_list.addr(), GuestAddress(initial_base));
        assert_eq!(vm.active_slots(), before_slots);

        // Inject a RemoveRegion failure on the 2nd entry moving DOWN.
        let down_base = initial_base - page;
        vm.fail_next_remove_at(initial_base + page);
        let _ = shm_list.move_bar(GuestAddress(down_base)).unwrap_err();
        assert_eq!(shm_list.addr(), GuestAddress(initial_base));
        assert_eq!(vm.active_slots(), before_slots);

        // Reject overflowing or unaligned destination without moving anything.
        let _ = vm.take_ops();
        assert_eq!(
            shm_list
                .move_bar(GuestAddress(u64::MAX - page))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EINVAL)
        );
        assert_eq!(
            shm_list
                .move_bar(GuestAddress(initial_base + 1))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EINVAL)
        );
        assert!(vm.take_ops().is_empty());
        assert_eq!(shm_list.addr(), GuestAddress(initial_base));

        // clear_mappings removes all active slots from the hypervisor.
        shm_list.clear_mappings();
        assert_eq!(shm_list.mapped_count(), 0);
        assert_eq!(vm.active_slot_count(), 0);
    }

    #[test]
    fn shm_list_register_failure_cleans_up_and_recycles_slot() {
        let page = get_page_size();
        let (_dir, file) = create_test_backing_file(2 * page);
        let vm = MockVm::new();
        let alloc = new_test_slot_allocator();
        let base = 0x10 * page;
        let shm_list = VirtioSharedMemoryList::new(
            GuestAddress(base),
            2 * page,
            vec![VirtioSharedMemory {
                offset: 0,
                len: 2 * page,
            }],
            Arc::clone(&vm) as Arc<dyn Vm>,
            alloc,
        )
        .unwrap();

        // Map slot 0 at offset 0.
        shm_list
            .map_region(0, 0, page, file.as_fd(), 0, true)
            .unwrap();
        assert_eq!(shm_list.mapped_count(), 1);

        // Force hypervisor failure at offset `page` (would get slot 1).
        vm.fail_next_create_at(base + page);
        let _ = shm_list
            .map_region(0, page, page, file.as_fd(), page, false)
            .unwrap_err();
        // Existing mapping is intact, failed mapping was not inserted, slot 1 recycled.
        assert_eq!(shm_list.mapped_count(), 1);
        assert_eq!(vm.active_slot_count(), 1);

        // Retry at offset `page` must succeed and reuse slot 1.
        shm_list
            .map_region(0, page, page, file.as_fd(), page, false)
            .unwrap();
        let slots = vm.active_slots();
        assert_eq!(slots.len(), 2);
        assert_eq!(slots[0].0, 0);
        assert!(!slots[0].1.readonly);
        assert_eq!(slots[1].0, 1);
        assert!(slots[1].1.readonly);

        // Read-only fd cannot be mapped writable -> returns EACCES and leaves state intact.
        let ro_file = File::open(_dir.as_path().join("blob")).unwrap();
        shm_list.unmap_region(0, page, page).unwrap();
        assert_eq!(
            shm_list
                .map_region(0, page, page, ro_file.as_fd(), page, true)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EACCES)
        );
        assert_eq!(shm_list.mapped_count(), 1);
        assert_eq!(vm.active_slot_count(), 1);

        // Read-only fd mapped non-writable succeeds with readonly=true slot.
        shm_list
            .map_region(0, page, page, ro_file.as_fd(), page, false)
            .unwrap();
        let slots = vm.active_slots();
        assert_eq!(slots.len(), 2);
        assert_eq!(slots[1].0, 1);
        assert!(slots[1].1.readonly);
    }
}
