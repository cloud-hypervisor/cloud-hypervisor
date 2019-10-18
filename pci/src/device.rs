// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

use crate::configuration::{self, PciBarRegionType};
use crate::msix::MsixTableEntry;
use crate::PciInterruptPin;
use devices::BusDevice;
use std;
use std::fmt::{self, Display};
use std::sync::Arc;
use vm_allocator::SystemAllocator;
use vm_memory::{GuestAddress, GuestUsize};
use vmm_sys_util::eventfd::EventFd;

pub struct InterruptParameters<'a> {
    pub msix: Option<&'a MsixTableEntry>,
}

pub type InterruptDelivery =
    Box<dyn Fn(InterruptParameters) -> std::result::Result<(), std::io::Error> + Send + Sync>;

#[derive(Debug)]
pub enum Error {
    /// Setup of the device capabilities failed.
    CapabilitiesSetup(configuration::Error),
    /// Allocating space for an IO BAR failed.
    IoAllocationFailed(u64),
    /// Registering an IO BAR failed.
    IoRegistrationFailed(u64, configuration::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            CapabilitiesSetup(e) => write!(f, "failed to add capability {}", e),
            IoAllocationFailed(size) => {
                write!(f, "failed to allocate space for an IO BAR, size={}", size)
            }
            IoRegistrationFailed(addr, e) => {
                write!(f, "failed to register an IO BAR, addr={} err={}", addr, e)
            }
        }
    }
}

pub trait PciDevice: BusDevice {
    /// Assign a legacy PCI IRQ to this device.
    /// The device may write to `irq_evt` to trigger an interrupt.
    fn assign_pin_irq(
        &mut self,
        _irq_cb: Arc<InterruptDelivery>,
        _irq_num: u32,
        _irq_pin: PciInterruptPin,
    ) {
    }

    /// Assign MSI-X to this device.
    fn assign_msix(&mut self, _msi_cb: Arc<InterruptDelivery>) {}

    /// Allocates the needed PCI BARs space using the `allocate` function which takes a size and
    /// returns an address. Returns a Vec of (GuestAddress, GuestUsize) tuples.
    fn allocate_bars(
        &mut self,
        _allocator: &mut SystemAllocator,
    ) -> Result<Vec<(GuestAddress, GuestUsize, PciBarRegionType)>> {
        Ok(Vec::new())
    }

    /// Gets a list of ioeventfds that should be registered with the running VM. The list is
    /// returned as a Vec of (eventfd, addr, datamatch) tuples.
    fn ioeventfds(&self) -> Vec<(&EventFd, u64, u64)> {
        Vec::new()
    }
    /// Sets a register in the configuration space.
    /// * `reg_idx` - The index of the config register to modify.
    /// * `offset` - Offset in to the register.
    fn write_config_register(&mut self, reg_idx: usize, offset: u64, data: &[u8]);
    /// Gets a register from the configuration space.
    /// * `reg_idx` - The index of the config register to read.
    fn read_config_register(&self, reg_idx: usize) -> u32;
    /// Reads from a BAR region mapped in to the device.
    /// * `addr` - The guest address inside the BAR.
    /// * `data` - Filled with the data from `addr`.
    fn read_bar(&mut self, _base: u64, _offset: u64, _data: &mut [u8]) {}
    /// Writes to a BAR region mapped in to the device.
    /// * `addr` - The guest address inside the BAR.
    /// * `data` - The data to write.
    fn write_bar(&mut self, _base: u64, _offset: u64, _data: &[u8]) {}
}

/// This trait defines a set of functions which can be triggered whenever a
/// PCI device is modified in any way.
pub trait DeviceRelocation: Send + Sync {
    /// The BAR needs to be moved to a different location in the guest address
    /// space. This follows a decision from the software running in the guest.
    fn move_bar(
        &self,
        old_base: u64,
        new_base: u64,
        len: u64,
        pci_dev: &mut dyn PciDevice,
        region_type: PciBarRegionType,
    );
}
