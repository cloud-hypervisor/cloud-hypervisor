// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unreadable_literal,
    clippy::redundant_static_lifetimes,
    clippy::cast_lossless,
    clippy::transmute_ptr_to_ptr,
    clippy::cast_ptr_alignment
)]

extern crate byteorder;
extern crate kvm_bindings;
extern crate libc;

#[cfg(feature = "acpi")]
extern crate acpi_tables;
extern crate arch_gen;
extern crate kvm_ioctls;
extern crate linux_loader;
extern crate vm_memory;

use std::result;

#[derive(Debug, PartialEq)]
pub enum Error {
    #[cfg(target_arch = "x86_64")]
    /// X86_64 specific error triggered during system configuration.
    X86_64Setup(x86_64::Error),
    /// The zero page extends past the end of guest_mem.
    ZeroPagePastRamEnd,
    /// Error writing the zero page of guest memory.
    ZeroPageSetup,
}
pub type Result<T> = result::Result<T, Error>;

#[derive(PartialEq)]
pub enum RegionType {
    /// RAM type
    Ram,

    /// SubRegion memory region.
    /// A SubRegion is a memory region sub-region, allowing for a region
    /// to be split into sub regions managed separately.
    /// For example, the x86 32-bit memory hole is a SubRegion.
    SubRegion,

    /// Reserved type.
    /// A Reserved memory region is one that should not be used for memory
    /// allocation. This type can be used to prevent the VMM from allocating
    /// memory ranges in a specific address range.
    Reserved,
}

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(target_arch = "aarch64")]
pub use aarch64::{
    arch_memory_regions, configure_system, get_reserved_mem_addr, layout::CMDLINE_MAX_SIZE,
    layout::CMDLINE_START,
};

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "x86_64")]
pub use x86_64::{
    arch_memory_regions, configure_system, layout, layout::CMDLINE_MAX_SIZE, layout::CMDLINE_START,
};
