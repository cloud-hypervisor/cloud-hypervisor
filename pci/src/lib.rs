// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

//! Implements pci devices and busses.
#[macro_use]
extern crate log;
extern crate devices;
extern crate vm_memory;
extern crate vmm_sys_util;

mod bus;
mod configuration;
mod device;
mod msi;
mod msix;

pub use self::bus::{PciBus, PciConfigIo, PciConfigMmio, PciRoot, PciRootError};
pub use self::configuration::{
    PciBarConfiguration, PciBarPrefetchable, PciBarRegionType, PciCapability, PciCapabilityID,
    PciClassCode, PciConfiguration, PciHeaderType, PciMassStorageSubclass,
    PciNetworkControllerSubclass, PciProgrammingInterface, PciSerialBusSubClass, PciSubclass,
};
pub use self::device::{
    BarReprogrammingParams, DeviceRelocation, Error as PciDeviceError, InterruptDelivery,
    InterruptParameters, PciDevice,
};
pub use self::msi::MsiCap;
pub use self::msix::{MsixCap, MsixConfig, MsixTableEntry, MSIX_TABLE_ENTRY_SIZE};
use kvm_bindings::{kvm_irq_routing, kvm_irq_routing_entry};
use kvm_ioctls::*;
use std::collections::HashMap;
use std::io;
use std::mem::size_of;
use std::sync::{Arc, Mutex};
use vm_allocator::SystemAllocator;
use vmm_sys_util::eventfd::EventFd;

/// PCI has four interrupt pins A->D.
#[derive(Copy, Clone)]
pub enum PciInterruptPin {
    IntA,
    IntB,
    IntC,
    IntD,
}

impl PciInterruptPin {
    pub fn to_mask(self) -> u32 {
        self as u32
    }
}

#[derive(Debug)]
pub enum Error {
    AllocateGsi,
    EventFd(io::Error),
    IrqFd(kvm_ioctls::Error),
    SetGsiRouting(kvm_ioctls::Error),
}

// Returns a `Vec<T>` with a size in bytes at least as large as `size_in_bytes`.
fn vec_with_size_in_bytes<T: Default>(size_in_bytes: usize) -> Vec<T> {
    let rounded_size = (size_in_bytes + size_of::<T>() - 1) / size_of::<T>();
    let mut v = Vec::with_capacity(rounded_size);
    v.resize_with(rounded_size, T::default);
    v
}

// The kvm API has many structs that resemble the following `Foo` structure:
//
// ```
// #[repr(C)]
// struct Foo {
//    some_data: u32
//    entries: __IncompleteArrayField<__u32>,
// }
// ```
//
// In order to allocate such a structure, `size_of::<Foo>()` would be too small because it would not
// include any space for `entries`. To make the allocation large enough while still being aligned
// for `Foo`, a `Vec<Foo>` is created. Only the first element of `Vec<Foo>` would actually be used
// as a `Foo`. The remaining memory in the `Vec<Foo>` is for `entries`, which must be contiguous
// with `Foo`. This function is used to make the `Vec<Foo>` with enough space for `count` entries.
pub fn vec_with_array_field<T: Default, F>(count: usize) -> Vec<T> {
    let element_space = count * size_of::<F>();
    let vec_size_bytes = size_of::<T>() + element_space;
    vec_with_size_in_bytes(vec_size_bytes)
}

pub fn set_kvm_routes<S: ::std::hash::BuildHasher>(
    vm_fd: VmFd,
    gsi_msi_routes: Arc<Mutex<HashMap<u32, kvm_irq_routing_entry, S>>>,
) -> Result<(), Error> {
    let mut entry_vec: Vec<kvm_irq_routing_entry> = Vec::new();
    for (_, entry) in gsi_msi_routes.lock().unwrap().iter() {
        entry_vec.push(*entry);
    }

    let mut irq_routing =
        vec_with_array_field::<kvm_irq_routing, kvm_irq_routing_entry>(entry_vec.len());
    irq_routing[0].nr = entry_vec.len() as u32;
    irq_routing[0].flags = 0;

    unsafe {
        let entries: &mut [kvm_irq_routing_entry] =
            irq_routing[0].entries.as_mut_slice(entry_vec.len());
        entries.copy_from_slice(&entry_vec);
    }

    vm_fd
        .set_gsi_routing(&irq_routing[0])
        .map_err(Error::SetGsiRouting)
}

pub struct InterruptRoute {
    gsi: u32,
    irq_fd: EventFd,
}

impl InterruptRoute {
    pub fn new(allocator: &mut SystemAllocator) -> Result<Self, Error> {
        let irq_fd = EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?;
        let gsi = allocator.allocate_gsi().ok_or(Error::AllocateGsi)?;

        Ok(InterruptRoute { gsi, irq_fd })
    }

    pub fn enable(&self, vm: &Arc<VmFd>) -> Result<(), Error> {
        vm.register_irqfd(&self.irq_fd, self.gsi)
            .map_err(Error::IrqFd)
    }

    pub fn disable(&self, vm: &Arc<VmFd>) -> Result<(), Error> {
        vm.unregister_irqfd(&self.irq_fd, self.gsi)
            .map_err(Error::IrqFd)
    }
}
