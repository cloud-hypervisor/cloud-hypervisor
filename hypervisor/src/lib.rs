// Copyright © 2024 Institute of Software, CAS. All rights reserved.
//
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2020, Microsoft Corporation
//
// Copyright 2018-2019 CrowdStrike, Inc.
//
//

//! A generic abstraction around hypervisor functionality
//!
//! This crate offers a trait abstraction for underlying hypervisors
//!
//! # Platform support
//!
//! - x86_64
//! - arm64
//! - riscv64 (experimental)
//!

#[macro_use]
extern crate anyhow;
#[allow(unused_imports)]
#[macro_use]
extern crate log;

/// Architecture specific definitions
#[macro_use]
pub mod arch;

#[cfg(feature = "kvm")]
/// KVM implementation module
pub mod kvm;

/// Microsoft Hypervisor implementation module
#[cfg(feature = "mshv")]
pub mod mshv;

/// Hypervisor related module
mod hypervisor;

/// Vm related module
mod vm;

/// CPU related module
mod cpu;

/// Device related module
mod device;

use std::sync::Arc;

use concat_idents::concat_idents;
#[cfg(target_arch = "x86_64")]
pub use cpu::CpuVendor;
pub use cpu::{HypervisorCpuError, Vcpu, VmExit};
pub use device::HypervisorDeviceError;
#[cfg(all(feature = "kvm", target_arch = "aarch64"))]
pub use kvm::aarch64;
#[cfg(all(feature = "kvm", target_arch = "riscv64"))]
pub use kvm::{AiaState, riscv64};
pub use vm::{
    DataMatch, HypervisorVmError, InterruptSourceConfig, LegacyIrqSourceConfig, MsiIrqSourceConfig,
    Vm, VmOps,
};

pub use crate::hypervisor::{Hypervisor, HypervisorError};

#[derive(Debug, Copy, Clone)]
pub enum HypervisorType {
    #[cfg(feature = "kvm")]
    Kvm,
    #[cfg(feature = "mshv")]
    Mshv,
}

pub fn new() -> std::result::Result<Arc<dyn Hypervisor>, HypervisorError> {
    #[cfg(feature = "kvm")]
    if kvm::KvmHypervisor::is_available()? {
        return kvm::KvmHypervisor::new();
    }

    #[cfg(feature = "mshv")]
    if mshv::MshvHypervisor::is_available()? {
        return mshv::MshvHypervisor::new();
    }

    Err(HypervisorError::HypervisorCreate(anyhow!(
        "no supported hypervisor"
    )))
}

// Returns a `Vec<T>` with a size in bytes at least as large as `size_in_bytes`.
fn vec_with_size_in_bytes<T: Default>(size_in_bytes: usize) -> Vec<T> {
    let rounded_size = size_in_bytes.div_ceil(size_of::<T>());
    let mut v = Vec::with_capacity(rounded_size);
    v.resize_with(rounded_size, T::default);
    v
}

// The kvm API has many structs that resemble the following `Foo` structure:
//
// ```
// #[repr(C)]
// struct Foo {
//    some_data: u32
//    entries: __IncompleteArrayField<__u32>,
// }
// ```
//
// In order to allocate such a structure, `size_of::<Foo>()` would be too small because it would not
// include any space for `entries`. To make the allocation large enough while still being aligned
// for `Foo`, a `Vec<Foo>` is created. Only the first element of `Vec<Foo>` would actually be used
// as a `Foo`. The remaining memory in the `Vec<Foo>` is for `entries`, which must be contiguous
// with `Foo`. This function is used to make the `Vec<Foo>` with enough space for `count` entries.
use std::mem::size_of;
pub fn vec_with_array_field<T: Default, F>(count: usize) -> Vec<T> {
    let element_space = count * size_of::<F>();
    let vec_size_bytes = size_of::<T>() + element_space;
    vec_with_size_in_bytes(vec_size_bytes)
}

///
/// User memory region structure
///
#[derive(Debug, Default, Eq, PartialEq)]
pub struct UserMemoryRegion {
    pub slot: u32,
    pub guest_phys_addr: u64,
    pub memory_size: u64,
    pub userspace_addr: u64,
    pub flags: u32,
}

///
/// Flags for user memory region
///
pub const USER_MEMORY_REGION_READ: u32 = 1;
pub const USER_MEMORY_REGION_WRITE: u32 = 1 << 1;
pub const USER_MEMORY_REGION_EXECUTE: u32 = 1 << 2;
pub const USER_MEMORY_REGION_LOG_DIRTY: u32 = 1 << 3;
pub const USER_MEMORY_REGION_ADJUSTABLE: u32 = 1 << 4;

#[derive(Debug)]
pub enum MpState {
    #[cfg(feature = "kvm")]
    Kvm(kvm_bindings::kvm_mp_state),
    #[cfg(feature = "mshv")]
    Mshv, /* MSHV does not support MpState yet */
}

#[derive(Debug, Clone, Copy)]
pub enum IoEventAddress {
    Pio(u64),
    Mmio(u64),
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum CpuState {
    #[cfg(feature = "kvm")]
    Kvm(kvm::VcpuKvmState),
    #[cfg(feature = "mshv")]
    Mshv(mshv::VcpuMshvState),
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[cfg(target_arch = "x86_64")]
pub enum ClockData {
    #[cfg(feature = "kvm")]
    Kvm(kvm_bindings::kvm_clock_data),
    #[cfg(feature = "mshv")]
    Mshv(mshv::MshvClockData),
}

#[cfg(target_arch = "x86_64")]
impl ClockData {
    pub fn reset_flags(&mut self) {
        match self {
            #[cfg(feature = "kvm")]
            ClockData::Kvm(s) => s.flags = 0,
            #[allow(unreachable_patterns)]
            _ => {}
        }
    }
}

#[derive(Copy, Clone)]
pub enum IrqRoutingEntry {
    #[cfg(feature = "kvm")]
    Kvm(kvm_bindings::kvm_irq_routing_entry),
    #[cfg(feature = "mshv")]
    Mshv(mshv_bindings::mshv_user_irq_entry),
}

#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum VcpuInit {
    #[cfg(all(feature = "kvm", target_arch = "aarch64"))]
    Kvm(kvm_bindings::kvm_vcpu_init),
    #[cfg(all(feature = "mshv", target_arch = "aarch64"))]
    Mshv(mshv_bindings::MshvVcpuInit),
}

#[derive(Debug, Clone, PartialEq)]
pub enum RegList {
    #[cfg(all(feature = "kvm", any(target_arch = "aarch64", target_arch = "riscv64")))]
    Kvm(kvm_bindings::RegList),
    #[cfg(all(feature = "mshv", target_arch = "aarch64"))]
    Mshv(mshv_bindings::MshvRegList),
}

pub enum Register {
    #[cfg(feature = "kvm")]
    Kvm(kvm_bindings::kvm_one_reg),
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum StandardRegisters {
    #[cfg(all(feature = "kvm", not(target_arch = "riscv64")))]
    Kvm(kvm_bindings::kvm_regs),
    #[cfg(all(feature = "kvm", target_arch = "riscv64"))]
    Kvm(kvm_bindings::kvm_riscv_core),
    #[cfg(any(feature = "mshv", feature = "mshv_emulator"))]
    Mshv(mshv_bindings::StandardRegisters),
}

macro_rules! set_x86_64_reg {
    ($reg_name:ident) => {
        concat_idents!(method_name = "set_", $reg_name {
            #[cfg(target_arch = "x86_64")]
            impl StandardRegisters {
                pub fn method_name(&mut self, val: u64) {
                    match self {
                        #[cfg(feature = "kvm")]
                        StandardRegisters::Kvm(s) => s.$reg_name = val,
                        #[cfg(any(feature = "mshv", feature = "mshv_emulator"))]
                        StandardRegisters::Mshv(s) => s.$reg_name = val,
                    }
                }
            }
        });
    }
}

macro_rules! get_x86_64_reg {
    ($reg_name:ident) => {
        concat_idents!(method_name = "get_", $reg_name {
            #[cfg(target_arch = "x86_64")]
            impl StandardRegisters {
                pub fn method_name(&self) -> u64 {
                    match self {
                        #[cfg(feature = "kvm")]
                        StandardRegisters::Kvm(s) => s.$reg_name,
                        #[cfg(any(feature = "mshv", feature = "mshv_emulator"))]
                        StandardRegisters::Mshv(s) => s.$reg_name,
                    }
                }
            }
        });
    }
}

set_x86_64_reg!(rax);
set_x86_64_reg!(rbx);
set_x86_64_reg!(rcx);
set_x86_64_reg!(rdx);
set_x86_64_reg!(rsi);
set_x86_64_reg!(rdi);
set_x86_64_reg!(rsp);
set_x86_64_reg!(rbp);
set_x86_64_reg!(r8);
set_x86_64_reg!(r9);
set_x86_64_reg!(r10);
set_x86_64_reg!(r11);
set_x86_64_reg!(r12);
set_x86_64_reg!(r13);
set_x86_64_reg!(r14);
set_x86_64_reg!(r15);
set_x86_64_reg!(rip);
set_x86_64_reg!(rflags);

get_x86_64_reg!(rax);
get_x86_64_reg!(rbx);
get_x86_64_reg!(rcx);
get_x86_64_reg!(rdx);
get_x86_64_reg!(rsi);
get_x86_64_reg!(rdi);
get_x86_64_reg!(rsp);
get_x86_64_reg!(rbp);
get_x86_64_reg!(r8);
get_x86_64_reg!(r9);
get_x86_64_reg!(r10);
get_x86_64_reg!(r11);
get_x86_64_reg!(r12);
get_x86_64_reg!(r13);
get_x86_64_reg!(r14);
get_x86_64_reg!(r15);
get_x86_64_reg!(rip);
get_x86_64_reg!(rflags);

macro_rules! set_aarch64_reg {
    ($reg_name:ident, $type:ty) => {
        concat_idents!(method_name = "set_", $reg_name {
            #[cfg(target_arch = "aarch64")]
            impl StandardRegisters {
                pub fn method_name(&mut self, val: $type) {
                    match self {
                        #[cfg(feature = "kvm")]
                        StandardRegisters::Kvm(s) => s.regs.$reg_name = val,
                        #[cfg(feature = "mshv")]
                        StandardRegisters::Mshv(s) => s.$reg_name = val,
                    }
                }
            }
        });
    }
}

macro_rules! get_aarch64_reg {
    ($reg_name:ident, $type:ty) => {
        concat_idents!(method_name = "get_", $reg_name {
            #[cfg(target_arch = "aarch64")]
            impl StandardRegisters {
                pub fn method_name(&self) -> $type {
                    match self {
                        #[cfg(feature = "kvm")]
                        StandardRegisters::Kvm(s) => s.regs.$reg_name,
                        #[cfg(feature = "mshv")]
                        StandardRegisters::Mshv(s) => s.$reg_name,
                    }
                }
            }
        });
    }
}

set_aarch64_reg!(regs, [u64; 31usize]);
set_aarch64_reg!(sp, u64);
set_aarch64_reg!(pc, u64);
set_aarch64_reg!(pstate, u64);

get_aarch64_reg!(regs, [u64; 31usize]);
get_aarch64_reg!(sp, u64);
get_aarch64_reg!(pc, u64);
get_aarch64_reg!(pstate, u64);

macro_rules! set_riscv64_reg {
    (mode) => {
        #[cfg(target_arch = "riscv64")]
        impl StandardRegisters {
            pub fn set_mode(&mut self, val: u64) {
                match self {
                    #[cfg(feature = "kvm")]
                    StandardRegisters::Kvm(s) => s.mode = val,
                }
            }
        }
    };
    ($reg_name:ident) => {
        concat_idents!(method_name = "set_", $reg_name {
            #[cfg(target_arch = "riscv64")]
            impl StandardRegisters {
                pub fn method_name(&mut self, val: u64) {
                    match self {
                        #[cfg(feature = "kvm")]
                        StandardRegisters::Kvm(s) => s.regs.$reg_name = val,
                    }
                }
            }
        });
    }
}

macro_rules! get_riscv64_reg {
    (mode) => {
        #[cfg(target_arch = "riscv64")]
        impl StandardRegisters {
            pub fn get_mode(&self) -> u64 {
                match self {
                    #[cfg(feature = "kvm")]
                    StandardRegisters::Kvm(s) => s.mode,
                }
            }
        }
    };
    ($reg_name:ident) => {
        concat_idents!(method_name = "get_", $reg_name {
            #[cfg(target_arch = "riscv64")]
            impl StandardRegisters {
                pub fn method_name(&self) -> u64 {
                    match self {
                        #[cfg(feature = "kvm")]
                        StandardRegisters::Kvm(s) => s.regs.$reg_name,
                    }
                }
            }
        });
    }
}

set_riscv64_reg!(pc);
set_riscv64_reg!(ra);
set_riscv64_reg!(sp);
set_riscv64_reg!(gp);
set_riscv64_reg!(tp);
set_riscv64_reg!(t0);
set_riscv64_reg!(t1);
set_riscv64_reg!(t2);
set_riscv64_reg!(s0);
set_riscv64_reg!(s1);
set_riscv64_reg!(a0);
set_riscv64_reg!(a1);
set_riscv64_reg!(a2);
set_riscv64_reg!(a3);
set_riscv64_reg!(a4);
set_riscv64_reg!(a5);
set_riscv64_reg!(a6);
set_riscv64_reg!(a7);
set_riscv64_reg!(s2);
set_riscv64_reg!(s3);
set_riscv64_reg!(s4);
set_riscv64_reg!(s5);
set_riscv64_reg!(s6);
set_riscv64_reg!(s7);
set_riscv64_reg!(s8);
set_riscv64_reg!(s9);
set_riscv64_reg!(s10);
set_riscv64_reg!(s11);
set_riscv64_reg!(t3);
set_riscv64_reg!(t4);
set_riscv64_reg!(t5);
set_riscv64_reg!(t6);
set_riscv64_reg!(mode);

get_riscv64_reg!(pc);
get_riscv64_reg!(ra);
get_riscv64_reg!(sp);
get_riscv64_reg!(gp);
get_riscv64_reg!(tp);
get_riscv64_reg!(t0);
get_riscv64_reg!(t1);
get_riscv64_reg!(t2);
get_riscv64_reg!(s0);
get_riscv64_reg!(s1);
get_riscv64_reg!(a0);
get_riscv64_reg!(a1);
get_riscv64_reg!(a2);
get_riscv64_reg!(a3);
get_riscv64_reg!(a4);
get_riscv64_reg!(a5);
get_riscv64_reg!(a6);
get_riscv64_reg!(a7);
get_riscv64_reg!(s2);
get_riscv64_reg!(s3);
get_riscv64_reg!(s4);
get_riscv64_reg!(s5);
get_riscv64_reg!(s6);
get_riscv64_reg!(s7);
get_riscv64_reg!(s8);
get_riscv64_reg!(s9);
get_riscv64_reg!(s10);
get_riscv64_reg!(s11);
get_riscv64_reg!(t3);
get_riscv64_reg!(t4);
get_riscv64_reg!(t5);
get_riscv64_reg!(t6);
get_riscv64_reg!(mode);
