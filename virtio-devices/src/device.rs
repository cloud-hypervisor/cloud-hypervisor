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
use std::thread;

use anyhow::anyhow;
use libc::EFD_NONBLOCK;
use log::{error, info, warn};
use virtio_bindings::virtio_config::VIRTIO_F_ACCESS_PLATFORM;
use virtio_queue::Queue;
use vm_device::UserspaceMapping;
use vm_memory::{GuestAddress, GuestMemoryAtomic};
use vm_migration::{MigratableError, Pausable};
use vm_virtio::{AccessPlatform, VirtioDeviceType};
use vmm_sys_util::eventfd::EventFd;

use crate::{
    ActivateError, ActivateResult, Error, GuestMemoryMmap, GuestRegionMmap, MmapRegion,
    VIRTIO_F_RING_INDIRECT_DESC,
};

pub enum VirtioInterruptType {
    Config,
    Queue(u16),
}

pub trait VirtioInterrupt: Send + Sync {
    fn trigger(&self, int_type: VirtioInterruptType) -> std::result::Result<(), std::io::Error>;
    fn notifier(&self, _int_type: VirtioInterruptType) -> Option<EventFd> {
        None
    }
    fn set_notifier(
        &self,
        int_type: u32,
        notifier: Option<EventFd>,
        vm: &dyn hypervisor::Vm,
    ) -> std::io::Result<()>;
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
    ) -> std::result::Result<(), Error> {
        std::unimplemented!()
    }

    /// Some devices may need to do some explicit shutdown work. This method
    /// may be implemented to do this. The VMM should call shutdown() on
    /// every device as part of shutting down the VM. Acting on the device
    /// after a shutdown() can lead to unpredictable results.
    fn shutdown(&mut self) {}

    fn add_memory_region(
        &mut self,
        _region: &Arc<GuestRegionMmap>,
    ) -> std::result::Result<(), Error> {
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
            data.write_all(&config[offset as usize..std::cmp::min(end, config_len) as usize])
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
    fn translate_gva(
        &self,
        id: u32,
        addr: u64,
        size: u64,
    ) -> std::result::Result<u64, std::io::Error>;
    /// Provide a way to translate GPA address ranges into GVAs. Same
    /// span requirement as `translate_gva`.
    fn translate_gpa(
        &self,
        id: u32,
        addr: u64,
        size: u64,
    ) -> std::result::Result<u64, std::io::Error>;
}

/// Structure to handle device state common to all devices
#[derive(Default)]
pub struct VirtioCommon {
    pub avail_features: u64,
    pub acked_features: u64,
    pub kill_evt: Option<EventFd>,
    pub interrupt_cb: Option<Arc<dyn VirtioInterrupt>>,
    pub pause_evt: Option<EventFd>,
    pub paused: Arc<AtomicBool>,
    pub paused_sync: Option<Arc<Barrier>>,
    pub epoll_threads: Option<Vec<thread::JoinHandle<()>>>,
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
        self.kill_evt = Some(kill_evt);

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

        // Resume the virtio thread if it was paused. Reset must always
        // converge to fresh state, so a resume failure is logged but doesn't
        // skip the rest of the teardown.
        if self.pause_evt.take().is_some()
            && let Err(e) = self.resume()
        {
            error!("Failed to resume paused device during reset: {e:?}");
        }

        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }

        if let Some(mut threads) = self.epoll_threads.take() {
            for t in threads.drain(..) {
                if let Err(e) = t.join() {
                    error!("Error joining thread: {e:?}");
                }
            }
        }

        // Drop the interrupt callback clone
        self.interrupt_cb = None;
    }

    pub fn trigger_interrupt(&self, int_type: VirtioInterruptType) -> std::io::Result<()> {
        if let Some(interrupt_cb) = &self.interrupt_cb {
            interrupt_cb.trigger(int_type)
        } else {
            Ok(())
        }
    }

    // Wait for the worker thread to finish and return
    pub fn wait_for_epoll_threads(&mut self) {
        if let Some(mut threads) = self.epoll_threads.take() {
            for t in threads.drain(..) {
                if let Err(e) = t.join() {
                    error!("Error joining thread: {e:?}");
                }
            }
        }
    }

    pub fn dup_eventfds(&self) -> (EventFd, EventFd) {
        (
            self.kill_evt.as_ref().unwrap().try_clone().unwrap(),
            self.pause_evt.as_ref().unwrap().try_clone().unwrap(),
        )
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
    fn pause(&mut self) -> std::result::Result<(), MigratableError> {
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

    fn resume(&mut self) -> std::result::Result<(), MigratableError> {
        info!(
            "Resuming virtio-{}",
            VirtioDeviceType::from(self.device_type)
        );
        self.paused.store(false, Ordering::SeqCst);
        if let Some(epoll_threads) = &self.epoll_threads {
            for t in epoll_threads.iter() {
                t.thread().unpark();
            }
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
