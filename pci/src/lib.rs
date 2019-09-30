// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

//! Implements pci devices and busses.
#[macro_use]
extern crate log;
extern crate devices;
extern crate kvm_ioctls;
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
    Error as PciDeviceError, InterruptDelivery, InterruptParameters, PciDevice,
};
pub use self::msi::MsiCap;
pub use self::msix::{MsixCap, MsixConfig, MsixTableEntry, MSIX_TABLE_ENTRY_SIZE};

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
