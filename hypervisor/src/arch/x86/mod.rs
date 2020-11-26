// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2020, Microsoft Corporation
//

pub mod gdt;

#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
#[allow(unused)]
#[allow(
    clippy::unreadable_literal,
    clippy::redundant_static_lifetimes,
    clippy::trivially_copy_pass_by_ref,
    clippy::useless_transmute,
    clippy::should_implement_trait,
    clippy::transmute_ptr_to_ptr,
    clippy::unreadable_literal,
    clippy::redundant_static_lifetimes
)]
pub mod msr_index;

pub mod emulator;

// MTRR constants
pub const MTRR_ENABLE: u64 = 0x800; // IA32_MTRR_DEF_TYPE MSR: E (MTRRs enabled) flag, bit 11
pub const MTRR_MEM_TYPE_WB: u64 = 0x6;

// IOAPIC pins
pub const NUM_IOAPIC_PINS: usize = 24;

// X86 Exceptions
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub enum Exception {
    DE = 1,  // Divide Error
    DB = 2,  // Debug Exception
    BP = 3,  // Breakpoint
    OF = 4,  // Overflow
    BR = 5,  // BOUND Range Exceeded
    UD = 6,  // Invalid/Undefined Opcode
    NM = 7,  // No Math Coprocessor
    DF = 8,  // Double Fault
    TS = 10, // Invalid TSS
    NP = 11, // Segment Not Present
    SS = 12, // Stack Segment Fault
    GP = 13, // General Protection
    PF = 14, // Page Fault
    MF = 16, // Math Fault
    AC = 17, // Alignment Check
    MC = 18, // Machine Check
    XM = 19, // SIMD Floating-Point Exception
    VE = 20, // Virtualization Exception
    CP = 21, // Control Protection Exception
}

pub mod regs;

// Abstracted segment register ops.
// Each x86 hypervisor should implement those.
pub trait SegmentRegisterOps {
    // Segment type
    fn segment_type(&self) -> u8;
    fn set_segment_type(&mut self, val: u8);

    // Descriptor Privilege Level (DPL)
    fn dpl(&self) -> u8;
    fn set_dpl(&mut self, val: u8);

    // Granularity
    fn granularity(&self) -> u8;
    fn set_granularity(&mut self, val: u8);

    // Memory Presence
    fn present(&self) -> u8;
    fn set_present(&mut self, val: u8);

    // Long mode
    fn long(&self) -> u8;
    fn set_long(&mut self, val: u8);

    // Available for system use (AVL)
    fn avl(&self) -> u8;
    fn set_avl(&mut self, val: u8);

    // Descriptor type (System or code/data)
    fn desc_type(&self) -> u8;
    fn set_desc_type(&mut self, val: u8);

    // D/B
    fn db(&self) -> u8;
    fn set_db(&mut self, val: u8);
}

// Code segment
pub const CODE_SEGMENT_TYPE: u8 = 0x8;

// Read/Write or Read/Exec segment
pub const RWRX_SEGMENT_TYPE: u8 = 0x2;

// Expand down segment
pub const EXPAND_DOWN_SEGMENT_TYPE: u8 = 0x4;

pub fn segment_type_code(t: u8) -> bool {
    t & CODE_SEGMENT_TYPE != 0
}

pub fn segment_type_ro(t: u8) -> bool {
    t & !RWRX_SEGMENT_TYPE == 0
}

pub fn segment_type_expand_down(t: u8) -> bool {
    !segment_type_code(t) && (t & EXPAND_DOWN_SEGMENT_TYPE != 0)
}
