// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

//! Implements pci devices and busses.
#[macro_use]
extern crate log;

mod bus;
mod configuration;
mod device;
mod msi;
mod msix;
mod vfio;
mod vfio_user;

pub use self::bus::{PciBus, PciConfigIo, PciConfigMmio, PciRoot, PciRootError};
pub use self::configuration::{
    PciBarConfiguration, PciBarPrefetchable, PciBarRegionType, PciCapability, PciCapabilityId,
    PciClassCode, PciConfiguration, PciHeaderType, PciMassStorageSubclass,
    PciNetworkControllerSubclass, PciProgrammingInterface, PciSerialBusSubClass, PciSubclass,
};
pub use self::device::{
    BarReprogrammingParams, DeviceRelocation, Error as PciDeviceError, PciDevice,
};
pub use self::msi::{msi_num_enabled_vectors, MsiCap, MsiConfig};
pub use self::msix::{MsixCap, MsixConfig, MsixTableEntry, MSIX_TABLE_ENTRY_SIZE};
pub use self::vfio::{VfioPciDevice, VfioPciError};
pub use self::vfio_user::{VfioUserPciDevice, VfioUserPciDeviceError};

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

#[cfg(target_arch = "x86_64")]
pub const PCI_CONFIG_IO_PORT: u64 = 0xcf8;
#[cfg(target_arch = "x86_64")]
pub const PCI_CONFIG_IO_PORT_SIZE: u64 = 0x8;
