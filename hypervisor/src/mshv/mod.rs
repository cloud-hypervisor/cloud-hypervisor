// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2020, Microsoft Corporation
//

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_macros)]
#![allow(non_upper_case_globals)]

// x86_64 dependencies
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[derive(Copy, Clone, Debug)]
pub struct MshvIrqRoutingMsi {
    pub address_lo: u32,
    pub address_hi: u32,
    pub data: u32,
}

#[derive(Copy, Clone, Debug)]
pub enum MshvIrqRouting {
    Msi(MshvIrqRoutingMsi),
}

#[derive(Copy, Clone, Debug)]
pub struct MshvIrqRoutingEntry {
    pub gsi: u32,
    pub route: MshvIrqRouting,
}
pub type IrqRoutingEntry = MshvIrqRoutingEntry;
