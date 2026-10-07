// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::any::Any;
use std::sync::{Arc, Barrier};
use std::{io, result};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use vm_allocator::{AddressAllocator, SystemAllocator};
use vm_device::Resource;
use vm_memory::GuestAddress;

use crate::PciBarConfiguration;
use crate::configuration::{self, PciBarRegionType};

#[derive(Error, Debug)]
pub enum Error {
    /// Setup of the device capabilities failed.
    #[error("Setup of the device capabilities failed")]
    CapabilitiesSetup(#[source] configuration::Error),
    /// Allocating space for an IO BAR failed.
    #[error("Allocating space for an IO BAR of size {0} failed")]
    IoAllocationFailed(u64),
    /// Registering an IO BAR failed.
    #[error("Registering an IO BAR at address {0:#x} failed")]
    IoRegistrationFailed(u64, #[source] configuration::Error),
    /// Expected resource not found.
    #[error("Expected resource not found")]
    MissingResource,
    /// Invalid resource.
    #[error("Invalid resource: {0:?}")]
    InvalidResource(Resource),
}
pub(crate) type Result<T> = result::Result<T, Error>;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct BarReprogrammingParams {
    pub old_base: u64,
    pub new_base: u64,
    pub len: u64,
    pub region_type: PciBarRegionType,
}

/// One of the two MMIO windows of a PCI segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MmioWindow {
    /// The window below 4 GiB.
    Mmio32,
    /// The window above guest RAM.
    Mmio64,
}

impl MmioWindow {
    /// Returns the windows a memory BAR of `region_type` may occupy.
    ///
    /// A 64-bit BAR may hold any address, so the guest may move it into the
    /// 32-bit window. See PCI Local Bus Specification 3.0, section 6.2.5.1,
    /// summarized in [Base Address Registers]. A 32-bit BAR stays in the
    /// 32-bit window. Its register cannot reach the 64-bit window on x86_64
    /// or aarch64, but on riscv64 that window follows guest RAM and can start
    /// below 4 GiB.
    ///
    /// [Base Address Registers]: https://wiki.osdev.org/PCI#Base_Address_Registers
    pub fn permitted(region_type: PciBarRegionType) -> &'static [MmioWindow] {
        match region_type {
            PciBarRegionType::Memory32BitRegion => &[MmioWindow::Mmio32],
            PciBarRegionType::Memory64BitRegion => &[MmioWindow::Mmio32, MmioWindow::Mmio64],
            PciBarRegionType::IoRegion => &[],
        }
    }

    /// Returns the window holding `addr`, or `None` if a BAR of `region_type`
    /// may not sit there.
    pub fn from_addr(
        region_type: PciBarRegionType,
        addr: GuestAddress,
        mmio32: &AddressAllocator,
        mmio64: &AddressAllocator,
    ) -> Option<MmioWindow> {
        Self::permitted(region_type)
            .iter()
            .copied()
            .find(|window| window.select(mmio32, mmio64).contains(addr))
    }

    /// Returns the window to allocate a BAR in.
    ///
    /// A restored BAR keeps the address the guest last gave it, which for a
    /// 64-bit BAR may be in the 32-bit window, so it goes in the window
    /// holding that address. A new BAR goes in the window matching its width.
    pub fn for_bar(
        region_type: PciBarRegionType,
        restored: Option<GuestAddress>,
        mmio32: &AddressAllocator,
        mmio64: &AddressAllocator,
    ) -> Option<MmioWindow> {
        match (restored, region_type) {
            (Some(addr), _) => Self::from_addr(region_type, addr, mmio32, mmio64),
            (None, PciBarRegionType::Memory32BitRegion) => Some(MmioWindow::Mmio32),
            (None, PciBarRegionType::Memory64BitRegion) => Some(MmioWindow::Mmio64),
            (None, PciBarRegionType::IoRegion) => None,
        }
    }

    /// Picks this window's member of a (32-bit, 64-bit) pair.
    pub fn select<T>(self, mmio32: T, mmio64: T) -> T {
        match self {
            MmioWindow::Mmio32 => mmio32,
            MmioWindow::Mmio64 => mmio64,
        }
    }
}

pub trait PciDevice: Send {
    /// Allocates the needed PCI BARs space using the `allocate` function which takes a size and
    /// returns an address. Returns a Vec of (GuestAddress, GuestUsize) tuples.
    fn allocate_bars(
        &mut self,
        _allocator: &mut SystemAllocator,
        _mmio32_allocator: &mut AddressAllocator,
        _mmio64_allocator: &mut AddressAllocator,
        _resources: Option<Vec<Resource>>,
    ) -> Result<Vec<PciBarConfiguration>> {
        Ok(Vec::new())
    }

    /// Frees the PCI BARs previously allocated with a call to allocate_bars().
    fn free_bars(
        &mut self,
        _allocator: &mut SystemAllocator,
        _mmio32_allocator: &mut AddressAllocator,
        _mmio64_allocator: &mut AddressAllocator,
    ) -> Result<()> {
        Ok(())
    }

    /// Sets a register in the configuration space.
    /// * `reg_idx` - The index of the config register to modify.
    /// * `offset` - Offset into the register.
    fn write_config_register(
        &mut self,
        reg_idx: usize,
        offset: u64,
        data: &[u8],
    ) -> (Vec<BarReprogrammingParams>, Option<Arc<Barrier>>);
    /// Gets a register from the configuration space.
    /// * `reg_idx` - The index of the config register to read.
    fn read_config_register(&mut self, reg_idx: usize) -> u32;
    /// Reads from a BAR region mapped into the device.
    /// * `addr` - The guest address inside the BAR.
    /// * `data` - Filled with the data from `addr`.
    fn read_bar(&mut self, _base: u64, _offset: u64, _data: &mut [u8]) {}
    /// Writes to a BAR region mapped into the device.
    /// * `addr` - The guest address inside the BAR.
    /// * `data` - The data to write.
    fn write_bar(&mut self, _base: u64, _offset: u64, _data: &[u8]) -> Option<Arc<Barrier>> {
        None
    }
    /// Relocates the BAR to a different address in guest address space.
    fn move_bar(&mut self, _old_base: u64, _new_base: u64) -> result::Result<(), io::Error> {
        Ok(())
    }
    /// Restore BAR address in config space after a failed move_bar.
    /// This rolls back the address update made by detect_bar_reprogramming()
    /// so that the config register stays consistent with the MMIO bus mapping.
    fn restore_bar_addr(&mut self, _params: &BarReprogrammingParams) {}
    /// Provides a mutable reference to the Any trait. This is useful to let
    /// the caller have access to the underlying type behind the trait.
    fn as_any_mut(&mut self) -> &mut dyn Any;

    /// Optionally returns a unique identifier.
    fn id(&self) -> Option<String>;
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
    ) -> result::Result<(), io::Error>;
}

#[cfg(test)]
mod tests {
    use MmioWindow::*;
    use PciBarRegionType::*;

    use super::*;

    const MMIO32_BASE: GuestAddress = GuestAddress(0xc000_0000);
    const MMIO32_SIZE: u64 = 0x1000_0000;
    const MMIO64_BASE: GuestAddress = GuestAddress(0x1_0000_0000);
    const MMIO64_SIZE: u64 = 0x1_0000_0000;

    const IN_MMIO32: GuestAddress = GuestAddress(0xc800_0000);
    const IN_MMIO64: GuestAddress = GuestAddress(0x1_8000_0000);
    const IN_NEITHER: GuestAddress = GuestAddress(0x8000_0000);

    // Every BAR type against each window and an address outside both.
    #[test]
    fn from_addr_permits_only_the_windows_of_the_bar_type() {
        let mmio32 = AddressAllocator::new(MMIO32_BASE, MMIO32_SIZE).unwrap();
        let mmio64 = AddressAllocator::new(MMIO64_BASE, MMIO64_SIZE).unwrap();
        let addrs = [IN_MMIO32, IN_MMIO64, IN_NEITHER];

        let cases = [
            (Memory32BitRegion, [Some(Mmio32), None, None]),
            (Memory64BitRegion, [Some(Mmio32), Some(Mmio64), None]),
            (IoRegion, [None, None, None]),
        ];
        for (region_type, windows) in cases {
            for (addr, window) in addrs.into_iter().zip(windows) {
                let found = MmioWindow::from_addr(region_type, addr, &mmio32, &mmio64);
                assert_eq!(found, window, "{region_type:?} at {addr:?}");
            }
        }
    }
}
