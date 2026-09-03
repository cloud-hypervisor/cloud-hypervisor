// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::{GuestAddress, MmapRegion};

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

#[derive(Clone)]
pub struct UserspaceMapping {
    pub mem_slot: u32,
    pub addr: GuestAddress,
    pub mapping: Arc<MmapRegion<AtomicBitmap>>,
    pub mergeable: bool,
}
