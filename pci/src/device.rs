// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::any::Any;
use std::sync::{Arc, Barrier};
use std::{io, result};

use thiserror::Error;
use vm_allocator::{AddressAllocator, SystemAllocator};
use vm_device::{BusDeviceSync, Resource};

use crate::{PciBarConfiguration, PciBdf, configuration};

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

/// A BAR whose current location is to be released.
#[derive(Clone, Copy, Debug)]
pub struct ReleaseParams {
    pub bar_idx: usize,
}

/// A BAR to install at new_base.
#[derive(Clone, Copy, Debug)]
pub struct InstallParams {
    pub bar_idx: usize,
    pub new_base: u64,
}

#[derive(Clone, Debug, Default)]
pub struct BarRelocation {
    pub release: Vec<ReleaseParams>,
    pub install: Vec<InstallParams>,
}

impl BarRelocation {
    pub fn is_empty(&self) -> bool {
        self.release.is_empty() && self.install.is_empty()
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
    ) -> (BarRelocation, Option<Arc<Barrier>>);
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
    /// Tear down the device's host-side resource for the BAR at its old base.
    fn move_bar_prepare(&mut self, _bar_idx: usize) -> result::Result<(), io::Error> {
        Ok(())
    }
    /// Set up the device's host-side resource at `new_base` and record it.
    fn move_bar_commit(
        &mut self,
        _bar_idx: usize,
        _new_base: u64,
    ) -> result::Result<(), io::Error> {
        Ok(())
    }
    /// Whether BAR `bar_idx` is released, i.e. not mapped.
    fn is_bar_released(&self, _bar_idx: usize) -> bool {
        false
    }
    /// BAR `bar_idx` is now mapped at its config-space address.
    fn on_bar_installed(&mut self, _bar_idx: usize) {}
    /// The installs owed to the guest, retried when another device releases
    /// a BAR.
    fn pending_bar_installs(&self) -> Vec<InstallParams> {
        Vec::new()
    }
    /// Provides a mutable reference to the Any trait. This is useful to let
    /// the caller have access to the underlying type behind the trait.
    fn as_any_mut(&mut self) -> &mut dyn Any;

    /// Optionally returns a unique identifier.
    fn id(&self) -> Option<String>;

    /// BDF of this device
    fn bdf(&self) -> PciBdf;
}

/// This trait defines a set of functions which can be triggered whenever a
/// PCI device is modified in any way.
pub trait DeviceRelocation: Send + Sync {
    /// Release a BAR's current location: its allocator and bus ranges and
    /// the device's mappings.
    fn move_bar_prepare(
        &self,
        pci_dev: &mut dyn PciDevice,
        params: &ReleaseParams,
    ) -> result::Result<(), io::Error>;

    /// Install a released BAR at params.new_base, inserting bus_device on
    /// the bus.
    fn move_bar_commit(
        &self,
        pci_dev: &mut dyn PciDevice,
        bus_device: &Arc<dyn BusDeviceSync>,
        params: &InstallParams,
    ) -> result::Result<(), io::Error>;

    /// Release every BAR of `pci_dev` whose address space is not decoded.
    /// Called after a restore.
    fn release_undecoded_bars(
        &self,
        _pci_dev: &mut dyn PciDevice,
    ) -> result::Result<(), io::Error> {
        Ok(())
    }
}
