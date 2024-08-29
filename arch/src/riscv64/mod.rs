// Copyright © 2024, Institute of Software, CAS. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

/// Module for the flattened device tree.
pub mod fdt;
// /// Layout for this riscv64 system.
// pub mod layout;
// /// Module for system registers definition
// pub mod regs;
// /// Module for loading UEFI binary.
// pub mod uefi;

pub use self::fdt::DeviceInfoForFdt;
