// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use serde::{Deserialize, Serialize};

mod bus;
pub mod dma_mapping;
pub mod interrupt;

pub use self::bus::{Bus, BusDevice, BusDeviceSync, Error as BusError};

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub enum PciBarType {
    Io,
    Mmio32,
    Mmio64,
}

/// Enumeration for device resources.
#[expect(missing_docs)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Resource {
    /// Memory Mapped IO address range.
    MmioAddressRange { base: u64, size: u64 },
    /// PCI BAR
    PciBar {
        index: usize,
        base: u64,
        size: u64,
        type_: PciBarType,
        prefetchable: bool,
    },
}
