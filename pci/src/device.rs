// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

use crate::configuration::{self, PciConfiguration};
use crate::msix::MsixTableEntry;
use crate::PciInterruptPin;
use devices::BusDevice;
use std;
use std::fmt::{self, Display};
use std::sync::Arc;
use vm_allocator::SystemAllocator;
use vm_memory::{GuestAddress, GuestUsize};
use vmm_sys_util::EventFd;

pub type IrqClosure = Box<Fn() -> std::result::Result<(), std::io::Error> + Send + Sync>;
pub type MsixClosure =
    Box<Fn(MsixTableEntry) -> std::result::Result<(), std::io::Error> + Send + Sync>;

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
        _irq_cb: Arc<IrqClosure>,
        _irq_num: u32,
        _irq_pin: PciInterruptPin,
    ) {
    }

    /// Assign MSI-X to this device.
    fn assign_msix(&mut self, _msi_cb: Arc<MsixClosure>) {}

    /// Allocates the needed PCI BARs space using the `allocate` function which takes a size and
    /// returns an address. Returns a Vec of (GuestAddress, GuestUsize) tuples.
    fn allocate_bars(
        &mut self,
        _allocator: &mut SystemAllocator,
    ) -> Result<Vec<(GuestAddress, GuestUsize)>> {
        Ok(Vec::new())
    }

    /// Register any capabilties specified by the device.
    fn register_device_capabilities(&mut self) -> Result<()> {
        Ok(())
    }

    /// Gets a list of ioeventfds that should be registered with the running VM. The list is
    /// returned as a Vec of (eventfd, addr, datamatch) tuples.
    fn ioeventfds(&self) -> Vec<(&EventFd, u64, u64)> {
        Vec::new()
    }
    /// Gets the configuration registers of the Pci Device.
    fn config_registers(&self) -> &PciConfiguration; // TODO - remove these
    /// Gets the configuration registers of the Pci Device for modification.
    fn config_registers_mut(&mut self) -> &mut PciConfiguration;
    /// Reads from a BAR region mapped in to the device.
    /// * `addr` - The guest address inside the BAR.
    /// * `data` - Filled with the data from `addr`.
    fn read_bar(&mut self, addr: u64, data: &mut [u8]);
    /// Writes to a BAR region mapped in to the device.
    /// * `addr` - The guest address inside the BAR.
    /// * `data` - The data to write.
    fn write_bar(&mut self, addr: u64, data: &[u8]);
    /// Invoked when the device is sandboxed.
    fn on_device_sandboxed(&mut self) {}
}
