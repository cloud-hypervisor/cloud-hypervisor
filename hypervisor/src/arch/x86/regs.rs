//
// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

// EFER (technically not a register) bits
pub const EFER_LMA: u64 = 0x400;

// CR0 bits
pub const CR0_PE: u64 = 0x1;

// RFlags bits
pub const CF_SHIFT: usize = 0;
pub const PF_SHIFT: usize = 2;
pub const AF_SHIFT: usize = 4;
pub const ZF_SHIFT: usize = 6;
pub const SF_SHIFT: usize = 7;
pub const DF_SHIFT: usize = 10;
pub const OF_SHIFT: usize = 11;

pub const CF: u64 = 1 << CF_SHIFT;
pub const PF: u64 = 1 << PF_SHIFT;
pub const AF: u64 = 1 << AF_SHIFT;
pub const ZF: u64 = 1 << ZF_SHIFT;
pub const SF: u64 = 1 << SF_SHIFT;
pub const DF: u64 = 1 << DF_SHIFT;
pub const OF: u64 = 1 << OF_SHIFT;
