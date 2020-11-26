//
// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

// EFER (technically not a register) bits
pub const EFER_LMA: u64 = 0x400;
pub const EFER_LME: u64 = 0x100;

// CR0 bits
pub const CR0_PE: u64 = 0x1;
pub const CR0_PG: u64 = 0x80000000;

// CR4 bits
pub const CR4_PAE: u64 = 0x20;
pub const CR4_LA57: u64 = 0x1000;
