// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use crate::{ActivateResult, Error, Queue};
use std::sync::Arc;
use vm_memory::{GuestAddress, GuestMemoryAtomic, GuestMemoryMmap, GuestUsize};
use vmm_sys_util::eventfd::EventFd;

pub enum VirtioInterruptType {
    Config,
    Queue,
}

pub trait VirtioInterrupt: Send + Sync {
    fn trigger(
        &self,
        int_type: &VirtioInterruptType,
        queue: Option<&Queue>,
    ) -> std::result::Result<(), std::io::Error>;
    fn notifier(
        &self,
        _int_type: &VirtioInterruptType,
        _queue: Option<&Queue>,
    ) -> Option<&EventFd> {
        None
    }
}

pub type VirtioIommuRemapping =
    Box<dyn Fn(u64) -> std::result::Result<u64, std::io::Error> + Send + Sync>;

#[derive(Clone)]
pub struct UserspaceMapping {
    pub host_addr: u64,
    pub mem_slot: u32,
    pub addr: GuestAddress,
    pub len: GuestUsize,
    pub mergeable: bool,
}

#[derive(Clone)]
pub struct VirtioSharedMemory {
    pub offset: u64,
    pub len: u64,
}

#[derive(Clone)]
pub struct VirtioSharedMemoryList {
    pub host_addr: u64,
    pub mem_slot: u32,
    pub addr: GuestAddress,
    pub len: GuestUsize,
    pub region_list: Vec<VirtioSharedMemory>,
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

    /// The set of feature bits that this device supports.
    fn features(&self) -> u64 {
        0
    }

    /// Acknowledges that this set of features should be enabled.
    fn ack_features(&mut self, value: u64) {
        let _ = value;
    }

    /// Reads this device configuration space at `offset`.
    fn read_config(&self, offset: u64, data: &mut [u8]);

    /// Writes to this device configuration space at `offset`.
    fn write_config(&mut self, offset: u64, data: &[u8]);

    /// Activates this device for real usage.
    fn activate(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        interrupt_evt: Arc<dyn VirtioInterrupt>,
        queues: Vec<Queue>,
        queue_evts: Vec<EventFd>,
    ) -> ActivateResult;

    /// Optionally deactivates this device and returns ownership of the guest memory map, interrupt
    /// event, and queue events.
    fn reset(&mut self) -> Option<(Arc<dyn VirtioInterrupt>, Vec<EventFd>)> {
        None
    }

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

    fn iommu_translate(&self, addr: u64) -> u64 {
        addr
    }

    /// Some devices may need to do some explicit shutdown work. This method
    /// may be implemented to do this. The VMM should call shutdown() on
    /// every device as part of shutting down the VM. Acting on the device
    /// after a shutdown() can lead to unpredictable results.
    fn shutdown(&mut self) {}

    fn update_memory(&mut self, _mem: &GuestMemoryMmap) -> std::result::Result<(), Error> {
        Ok(())
    }

    /// Returns the list of userspace mappings associated with this device.
    fn userspace_mappings(&self) -> Vec<UserspaceMapping> {
        Vec::new()
    }
}

/// Trait providing address translation the same way a physical DMA remapping
/// table would provide translation between an IOVA and a physical address.
/// The goal of this trait is to be used by virtio devices to perform the
/// address translation before they try to read from the guest physical address.
/// On the other side, the implementation itself should be provided by the code
/// emulating the IOMMU for the guest.
pub trait DmaRemapping: Send + Sync {
    fn translate(&self, id: u32, addr: u64) -> std::result::Result<u64, std::io::Error>;
}

#[macro_export]
macro_rules! virtio_pausable_trait_definition {
    () => {
        trait VirtioPausable {
            fn virtio_pause(&mut self) -> std::result::Result<(), MigratableError>;
            fn virtio_resume(&mut self) -> std::result::Result<(), MigratableError>;
        }
    };
}
#[macro_export]
macro_rules! virtio_pausable_trait_inner {
    () => {
        // This is the common Pausable trait implementation for virtio.
        fn virtio_pause(&mut self) -> result::Result<(), MigratableError> {
            debug!(
                "Pausing virtio-{}",
                VirtioDeviceType::from(self.device_type())
            );
            self.paused.store(true, Ordering::SeqCst);
            if let Some(pause_evt) = &self.pause_evt {
                pause_evt
                    .write(1)
                    .map_err(|e| MigratableError::Pause(e.into()))?;
            }

            Ok(())
        }

        fn virtio_resume(&mut self) -> result::Result<(), MigratableError> {
            debug!(
                "Resuming virtio-{}",
                VirtioDeviceType::from(self.device_type())
            );
            self.paused.store(false, Ordering::SeqCst);
            if let Some(epoll_threads) = &self.epoll_threads {
                for i in 0..epoll_threads.len() {
                    epoll_threads[i].thread().unpark();
                }
            }

            Ok(())
        }
    };
}

#[macro_export]
macro_rules! virtio_pausable_trait {
    ($type:ident) => {
        virtio_pausable_trait_definition!();

        impl VirtioPausable for $type {
            virtio_pausable_trait_inner!();
        }
    };

    ($type:ident, T: $($bounds:tt)+) => {
        virtio_pausable_trait_definition!();

        impl<T: $($bounds)+ > VirtioPausable for $type<T> {
            virtio_pausable_trait_inner!();
        }
    };
}

#[macro_export]
macro_rules! virtio_pausable_inner {
    ($type:ident) => {
        fn pause(&mut self) -> result::Result<(), MigratableError> {
            self.virtio_pause()
        }

        fn resume(&mut self) -> result::Result<(), MigratableError> {
            self.virtio_resume()
        }
    };
}

#[macro_export]
macro_rules! virtio_pausable {
    ($type:ident) => {
        virtio_pausable_trait!($type);

        impl Pausable for $type {
            virtio_pausable_inner!($type);
        }
    };

    // For type bound virtio types
    ($type:ident, T: $($bounds:tt)+) => {
        virtio_pausable_trait!($type, T: $($bounds)+);

        impl<T: $($bounds)+ > Pausable for $type<T> {
            virtio_pausable_inner!($type);
        }
    };
}

#[macro_export]
macro_rules! virtio_ctrl_q_pausable {
    ($type:ident) => {
        virtio_pausable_trait!($type);

        impl Pausable for $type {
            fn pause(&mut self) -> result::Result<(), MigratableError> {
                self.virtio_pause()
            }

            fn resume(&mut self) -> result::Result<(), MigratableError> {
                self.virtio_resume()?;

                if let Some(ctrl_queue_epoll_thread) = &self.ctrl_queue_epoll_thread {
                    ctrl_queue_epoll_thread.thread().unpark();
                }

                Ok(())
            }
        }
    };
}
