// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::collections::HashMap;
use std::io::Write;
use std::num::Wrapping;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Barrier};
use std::{cmp, io, result, thread};

use anyhow::anyhow;
use libc::EFD_NONBLOCK;
use log::{error, info, warn};
use seccompiler::SeccompAction;
use virtio_bindings::virtio_config::VIRTIO_F_ACCESS_PLATFORM;
use virtio_queue::Queue;
use vm_device::UserspaceMapping;
use vm_memory::{GuestAddress, GuestMemoryAtomic};
use vm_migration::{MigratableError, Pausable};
use vm_virtio::{AccessPlatform, VirtioDeviceType};
use vmm_sys_util::eventfd::EventFd;

use crate::epoll_helper::EpollHelperError;
use crate::seccomp_filters::Thread;
use crate::thread_helper::spawn_virtio_thread;
use crate::{
    ActivateError, ActivateResult, Error, GuestMemoryMmap, GuestRegionMmap, MmapRegion,
    VIRTIO_F_RING_INDIRECT_DESC,
};

pub enum VirtioInterruptType {
    Config,
    Queue(u16),
}

pub trait VirtioInterrupt: Send + Sync {
    fn trigger(&self, int_type: VirtioInterruptType) -> io::Result<()>;
    fn notifier(&self, _int_type: VirtioInterruptType) -> Option<EventFd> {
        None
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

#[derive(Clone)]
pub struct VirtioSharedMemoryList {
    pub mem_slot: u32,
    pub addr: GuestAddress,
    pub mapping: Arc<MmapRegion>,
    pub region_list: Vec<VirtioSharedMemory>,
}

pub struct ActivationContext {
    pub mem: GuestMemoryAtomic<GuestMemoryMmap>,
    pub interrupt_cb: Arc<dyn VirtioInterrupt>,
    pub queues: Vec<(usize, Queue, EventFd)>,
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

    fn add_memory_region(&mut self, _region: &Arc<GuestRegionMmap>) -> result::Result<(), Error> {
        Ok(())
    }

    /// Returns the list of userspace mappings associated with this device.
    fn userspace_mappings(&self) -> Vec<UserspaceMapping> {
        Vec::new()
    }

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
    fn translate_gva(&self, id: u32, addr: u64, size: u64) -> io::Result<u64>;
    /// Provide a way to translate GPA address ranges into GVAs. Same
    /// span requirement as `translate_gva`.
    fn translate_gpa(&self, id: u32, addr: u64, size: u64) -> io::Result<u64>;
}

/// Owns a device's worker threads plus the kill event that stops them.
///
/// Dropping signals every worker to exit, unparks any that are parked, and joins them.
pub struct WorkerThreads {
    /// shared kill event, a single write wakes all of them.
    kill_evt: EventFd,
    // true if the device is paused.
    paused: Arc<AtomicBool>,
    // The running worker thread's handles.
    threads: Vec<thread::JoinHandle<()>>,
}

impl WorkerThreads {
    fn new(kill_evt: EventFd, paused: Arc<AtomicBool>) -> Self {
        WorkerThreads {
            kill_evt,
            paused,
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
        self.kill_evt.write(1)
    }

    /// Unpark every worker so threads parked while paused resume their loop.
    fn unpark(&self) {
        for t in &self.threads {
            t.thread().unpark();
        }
    }
}

impl Drop for WorkerThreads {
    fn drop(&mut self) {
        // Signal the workers to exit, wake any parked so they observe it, then join.
        let _ = self.kill_evt.write(1);
        self.paused.store(false, Ordering::SeqCst);
        self.unpark();
        for t in self.threads.drain(..) {
            if let Err(e) = t.join() {
                error!("Error joining thread: {e:?}");
            }
        }
    }
}

/// Structure to handle device state common to all devices
#[derive(Default)]
pub struct VirtioCommon {
    pub avail_features: u64,
    pub acked_features: u64,
    pub interrupt_cb: Option<Arc<dyn VirtioInterrupt>>,
    pub pause_evt: Option<EventFd>,
    pub paused: Arc<AtomicBool>,
    pub paused_sync: Option<Arc<Barrier>>,
    pub workers: Option<WorkerThreads>,
    pub queue_sizes: Vec<u16>,
    pub queue_evts: Vec<EventFd>,
    pub device_type: u32,
    pub min_queues: u16,
    pub access_platform: Option<Arc<dyn AccessPlatform>>,
}

impl VirtioCommon {
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
        self.acked_features |= v;
    }

    pub fn activate(
        &mut self,
        queues: &[(usize, Queue, EventFd)],
        interrupt_cb: Arc<dyn VirtioInterrupt>,
    ) -> ActivateResult {
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
            .map(|(_, _, queue_evt)| {
                queue_evt.try_clone().map_err(|e| {
                    error!("failed cloning queue EventFd: {e}");
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
        self.workers = Some(WorkerThreads::new(kill_evt, self.paused.clone()));

        let pause_evt = EventFd::new(EFD_NONBLOCK).map_err(|e| {
            error!("failed creating pause EventFd: {e}");
            ActivateError::BadActivate
        })?;
        self.pause_evt = Some(pause_evt);

        // Save the interrupt EventFD as we need to return it on reset
        // but clone it to pass into the thread.
        self.interrupt_cb = Some(interrupt_cb);

        Ok(())
    }

    pub fn reset(&mut self) {
        self.queue_evts.clear();
        self.pause_evt = None;

        // Clear paused explicitly; the workers' Drop does so too, but only
        // when they exist, and reset may run before activate().
        self.paused.store(false, Ordering::SeqCst);

        // Dropping the workers signals kill_evt, unparks any thread parked
        // for migration, and joins them.
        self.workers = None;

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
        F: FnOnce() -> Result<(), EpollHelperError> + Send + 'static,
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

    // Dropping the workers signals, unparks, and joins them. Idempotent.
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
            .pause_evt
            .as_ref()
            .ok_or(ActivateError::BadActivate)?
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

        // If already paused, return early to avoid deadlock waiting on barrier
        // for worker threads that are already parked.
        if self.paused.swap(true, Ordering::SeqCst) {
            return Ok(());
        }

        if let Some(pause_evt) = &self.pause_evt {
            pause_evt
                .write(1)
                .map_err(|e| MigratableError::Pause(e.into()))?;

            // Wait for all threads to acknowledge the pause before going
            // any further. This is exclusively performed when pause_evt
            // eventfd is Some(), as this means the virtio device has been
            // activated. One specific case where the device can be paused
            // while it hasn't been yet activated is snapshot/restore.
            self.paused_sync.as_ref().unwrap().wait();
        }

        Ok(())
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        info!(
            "Resuming virtio-{}",
            VirtioDeviceType::from(self.device_type)
        );
        self.paused.store(false, Ordering::SeqCst);
        if let Some(workers) = &self.workers {
            workers.unpark();
        }

        // Signal each activated queue eventfd so workers process restored queues
        // that may already contain pending requests.
        for queue_evt in &self.queue_evts {
            queue_evt.write(1).map_err(|e| {
                MigratableError::Resume(anyhow!(
                    "Could not notify restored virtio worker on resume: {e}"
                ))
            })?;
        }

        // Also trigger interrupts into the guest to wake up the driver to avoid a "livelock"
        for i in 0..self.queue_evts.len() {
            self.trigger_interrupt(crate::VirtioInterruptType::Queue(i as u16))
                .ok();
        }

        Ok(())
    }
}

#[cfg(test)]
mod unit_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use vmm_sys_util::eventfd::EFD_NONBLOCK;

    use super::*;

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

    /// VirtioCommon with its worker collection created (as activate() does)
    /// and a kill_evt clone for the spawned worker to watch.
    fn make_common_with_workers() -> (VirtioCommon, EventFd) {
        let kill_evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let kill_evt_clone = kill_evt.try_clone().unwrap();
        let common = VirtioCommon::default();
        let workers = WorkerThreads::new(kill_evt, common.paused.clone());
        let common = VirtioCommon {
            workers: Some(workers),
            ..common
        };
        (common, kill_evt_clone)
    }

    #[test]
    fn spawn_worker_appends_to_workers() {
        let (mut common, kill_evt_clone) = make_common_with_workers();
        let started = Arc::new(AtomicUsize::new(0));
        let started_clone = started.clone();

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
                move || {
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
        let started_clone = started.clone();

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
                move || {
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
    fn reset_clears_paused_without_workers() {
        // reset() before any worker was spawned must still clear paused, or
        // the next activation's workers would park immediately and never run.
        let mut common = VirtioCommon {
            pause_evt: Some(EventFd::new(EFD_NONBLOCK).unwrap()),
            ..Default::default()
        };
        common.paused.store(true, Ordering::SeqCst);
        assert!(common.workers.is_none());

        common.reset();

        assert!(!common.paused.load(Ordering::SeqCst));
        assert!(common.pause_evt.is_none());
    }
}
