// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

use vm_memory::{GuestAddress, GuestUsize};

/*

Memory layout documentation and constants
~~~~~~ ~~~~~~ ~~~~~~~~~~~~~ ~~~ ~~~~~~~~~

Constants are in order and grouped by range. Take care to update all references
when making changes and keep them in order.

*/

// ** Low RAM (start: 0, length: 640KiB) **
pub const LOW_RAM_START: GuestAddress = GuestAddress(0x0);

// == Fixed addresses within the "Low RAM" range: ==

/// The 'zero page', a.k.a linux kernel bootparams.
pub const ZERO_PAGE_START: GuestAddress = GuestAddress(0x7000);

/// Initial stack for the boot CPU.
pub const BOOT_STACK_START: GuestAddress = GuestAddress(0x8000);
pub const BOOT_STACK_POINTER: GuestAddress = GuestAddress(0x8ff0);

/// Kernel command line start address.
pub const CMDLINE_START: GuestAddress = GuestAddress(0x20000);
/// Kernel command line start address maximum size.
pub const CMDLINE_MAX_SIZE: usize = 0x10000;

// == End of "Low RAM" range. ==

// ** EBDA reserved area (start: 640KiB, length: 384KiB) **
pub const EBDA_START: GuestAddress = GuestAddress(0xa0000);

// == Fixed constants within the "EBDA" range ==

// ACPI RSDP table
pub const RSDP_POINTER: GuestAddress = EBDA_START;

// == End of "EBDA" range ==

// ** High RAM (start: 1MiB, length: 3071MiB) **
pub const HIGH_RAM_START: GuestAddress = GuestAddress(0x100000);

// == No fixed addresses in the "High RAM" range ==

// ** 32-bit reserved area (start: 3GiB, length: 1GiB) **
pub const MEM_32BIT_RESERVED_START: GuestAddress = GuestAddress(0xc000_0000);
pub const MEM_32BIT_RESERVED_SIZE: GuestUsize = (1024 << 20);

// == Fixed constants within the "32-bit reserved" range ==

// Sub range: 32-bit PCI devices (start: 3GiB, length: 768Mib)
pub const MEM_32BIT_DEVICES_START: GuestAddress = MEM_32BIT_RESERVED_START;
pub const MEM_32BIT_DEVICES_SIZE: GuestUsize = (768 << 20);

// IOAPIC
pub const IOAPIC_START: GuestAddress = GuestAddress(0xfec0_0000);

// APIC
pub const APIC_START: GuestAddress = GuestAddress(0xfee0_0000);

/// Address for the TSS setup.
pub const KVM_TSS_ADDRESS: GuestAddress = GuestAddress(0xfffb_d000);

// == End of "32-bit reserved" range. ==

// ** 64-bit RAM start (start: 4GiB, length: varies) **
pub const RAM_64BIT_START: GuestAddress = GuestAddress(0x1_0000_0000);
