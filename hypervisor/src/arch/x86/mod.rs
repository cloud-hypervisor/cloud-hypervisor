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
