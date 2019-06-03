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

mod configuration;
mod device;
mod root;

pub use self::configuration::{
    PciBarConfiguration, PciBarPrefetchable, PciBarRegionType, PciCapability, PciCapabilityID,
    PciClassCode, PciConfiguration, PciHeaderType, PciProgrammingInterface, PciSerialBusSubClass,
    PciSubclass,
};
pub use self::device::Error as PciDeviceError;
pub use self::device::{IrqClosure, PciDevice};
pub use self::root::{PciConfigIo, PciConfigMmio, PciRoot, PciRootError};

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
