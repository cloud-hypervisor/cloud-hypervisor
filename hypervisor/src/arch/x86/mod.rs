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

use core::fmt;

use thiserror::Error;

use crate::CpuVendor;

#[cfg(all(feature = "mshv_emulator", target_arch = "x86_64"))]
pub mod emulator;
pub mod gdt;
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod msr_index;

// MTRR constants
pub const MTRR_ENABLE: u64 = 0x800; // IA32_MTRR_DEF_TYPE MSR: E (MTRRs enabled) flag, bit 11
pub const MTRR_MEM_TYPE_WB: u64 = 0x6;

// IOAPIC pins
pub const NUM_IOAPIC_PINS: usize = 24;

// X86 Exceptions
#[derive(Clone, Debug)]
pub enum Exception {
    DE = 0,  // Divide Error
    DB = 1,  // Debug Exception
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

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct SegmentRegister {
    pub base: u64,
    pub limit: u32,
    pub selector: u16,
    pub type_: u8,
    pub present: u8,
    pub dpl: u8,
    pub db: u8,
    pub s: u8,
    pub l: u8,
    pub g: u8,
    pub avl: u8,
    pub unusable: u8,
}

impl SegmentRegister {
    pub fn segment_type(&self) -> u8 {
        self.type_
    }
    pub fn set_segment_type(&mut self, val: u8) {
        self.type_ = val;
    }

    pub fn dpl(&self) -> u8 {
        self.dpl
    }

    pub fn set_dpl(&mut self, val: u8) {
        self.dpl = val;
    }

    pub fn present(&self) -> u8 {
        self.present
    }

    pub fn set_present(&mut self, val: u8) {
        self.present = val;
    }

    pub fn long(&self) -> u8 {
        self.l
    }

    pub fn set_long(&mut self, val: u8) {
        self.l = val;
    }

    pub fn avl(&self) -> u8 {
        self.avl
    }

    pub fn set_avl(&mut self, val: u8) {
        self.avl = val;
    }

    pub fn desc_type(&self) -> u8 {
        self.s
    }

    pub fn set_desc_type(&mut self, val: u8) {
        self.s = val;
    }

    pub fn granularity(&self) -> u8 {
        self.g
    }

    pub fn set_granularity(&mut self, val: u8) {
        self.g = val;
    }

    pub fn db(&self) -> u8 {
        self.db
    }

    pub fn set_db(&mut self, val: u8) {
        self.db = val;
    }
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
#[macro_export]
macro_rules! msr {
    ($msr:expr) => {
        MsrEntry {
            index: $msr,
            data: 0x0,
        }
    };
}
#[macro_export]
macro_rules! msr_data {
    ($msr:expr, $data:expr) => {
        MsrEntry {
            index: $msr,
            data: $data,
        }
    };
}

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct DescriptorTable {
    pub base: u64,
    pub limit: u16,
}

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct SpecialRegisters {
    pub cs: SegmentRegister,
    pub ds: SegmentRegister,
    pub es: SegmentRegister,
    pub fs: SegmentRegister,
    pub gs: SegmentRegister,
    pub ss: SegmentRegister,
    pub tr: SegmentRegister,
    pub ldt: SegmentRegister,
    pub gdt: DescriptorTable,
    pub idt: DescriptorTable,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub efer: u64,
    pub apic_base: u64,
    pub interrupt_bitmap: [u64; 4usize],
}

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct CpuIdEntry {
    pub function: u32,
    pub index: u32,
    pub flags: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

impl fmt::Display for CpuIdEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "function = 0x{:08x} \
             index = 0x{:08x} \
             eax = 0x{:08x} \
             ebx = 0x{:08x} \
             ecx = 0x{:08x} \
             edx = 0x{:08x} \
             flags = 0x{:08x}",
            self.function, self.index, self.eax, self.ebx, self.ecx, self.edx, self.flags
        )
    }
}

pub const CPUID_FLAG_VALID_INDEX: u32 = 1;

#[derive(Default, Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct FpuState {
    pub fpr: [[u8; 16usize]; 8usize],
    pub fcw: u16,
    pub fsw: u16,
    pub ftwx: u8,
    pub last_opcode: u16,
    pub last_ip: u64,
    pub last_dp: u64,
    pub xmm: [[u8; 16usize]; 16usize],
    pub mxcsr: u32,
}

#[serde_with::serde_as]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LapicState {
    #[serde_as(as = "[_; 1024usize]")]
    pub(crate) regs: [::std::os::raw::c_char; 1024usize],
}

impl Default for LapicState {
    fn default() -> Self {
        // SAFETY: this is plain old data structure
        unsafe { ::std::mem::zeroed() }
    }
}

impl LapicState {
    pub fn get_klapic_reg(&self, reg_offset: usize) -> u32 {
        use std::io::Cursor;
        use std::mem;

        use byteorder::{LittleEndian, ReadBytesExt};

        // SAFETY: plain old data type
        let sliceu8 = unsafe {
            // This array is only accessed as parts of a u32 word, so interpret it as a u8 array.
            // Cursors are only readable on arrays of u8, not i8(c_char).
            mem::transmute::<&[i8], &[u8]>(&self.regs[reg_offset..])
        };

        let mut reader = Cursor::new(sliceu8);
        // Following call can't fail if the offsets defined above are correct.
        reader
            .read_u32::<LittleEndian>()
            .expect("Failed to read klapic register")
    }

    pub fn set_klapic_reg(&mut self, reg_offset: usize, value: u32) {
        use std::io::Cursor;
        use std::mem;

        use byteorder::{LittleEndian, WriteBytesExt};

        // SAFETY: plain old data type
        let sliceu8 = unsafe {
            // This array is only accessed as parts of a u32 word, so interpret it as a u8 array.
            // Cursors are only readable on arrays of u8, not i8(c_char).
            mem::transmute::<&mut [i8], &mut [u8]>(&mut self.regs[reg_offset..])
        };

        let mut writer = Cursor::new(sliceu8);
        // Following call can't fail if the offsets defined above are correct.
        writer
            .write_u32::<LittleEndian>(value)
            .expect("Failed to write klapic register");
    }
}

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct MsrEntry {
    pub index: u32,
    pub data: u64,
}

#[serde_with::serde_as]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct XsaveState {
    #[serde_as(as = "[_; 1024usize]")]
    pub region: [u32; 1024usize],

    // extra data to support xsave2
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra: Vec<u32>,
}

impl Default for XsaveState {
    fn default() -> Self {
        Self {
            // SAFETY: this is plain old data structure
            region: unsafe { std::mem::zeroed() },
            extra: Vec::new(),
        }
    }
}

const ARCH_GET_XCOMP_SUPP: usize = 0x1021;
const ARCH_REQ_XCOMP_GUEST_PERM: usize = 0x1025;
const ARCH_XCOMP_TILECFG: usize = 17;
const ARCH_XCOMP_TILEDATA: usize = 18;

/// Checks whether the host supports AMX.
///
/// Returns `Ok` if AMX is supported on the host and `Err` otherwise.
pub(crate) fn amx_supported(cpu_vendor: CpuVendor) -> Result<(), AmxGuestSupportError> {
    if !matches!(cpu_vendor, CpuVendor::Intel) {
        return Err(AmxGuestSupportError::VendorDoesNotSupportAmx);
    }
    // We make a syscall to get information about which dynamically enabled
    // XSAVE state components are supported. The corresponding state
    // component bits will get set in `features`
    let mut features: usize = 0;
    // SAFETY: Syscall with valid parameters
    let result =
        unsafe { libc::syscall(libc::SYS_arch_prctl, ARCH_GET_XCOMP_SUPP, &raw mut features) };
    // Ensure that both the TILECFG and TILEDATA state components are supported
    let mask = (1 << ARCH_XCOMP_TILECFG) | (1 << ARCH_XCOMP_TILEDATA);
    if result != 0 {
        return Err(AmxGuestSupportError::AmxNotSupported { errno: result });
    }

    if (features & mask) == mask {
        Ok(())
    } else {
        Err(AmxGuestSupportError::InvalidAmxTileFeatureCheck { features })
    }
}

/// Asks the kernel to provide AMX support for guests.
pub(crate) fn request_guest_amx_support() -> Result<(), AmxGuestSupportError> {
    // Make a syscall to request permission for guests to use the TILECFG
    // and TILEDATA state components. Note that as per the kernel
    // [documentation](https://docs.kernel.org/arch/x86/xstate.html#dynamic-features-for-virtual-machines)
    // we need to pass in the number of the highest XSTATE component which is required for
    // the facility to work which in this case is TILEDATA.
    //
    // This syscall will alter the size of `kvm_xsave` when KVM is used as the hypervisor.
    //
    // SAFETY: Syscall with valid parameters
    let result = unsafe {
        libc::syscall(
            libc::SYS_arch_prctl,
            ARCH_REQ_XCOMP_GUEST_PERM,
            ARCH_XCOMP_TILEDATA,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        // Unwrap is OK because we verified that `result` is not zero
        Err(AmxGuestSupportError::AmxGuestTileRequest { errno: result })
    }
}

/// Error that may be returned when attempting to enable AMX state components for guests
#[derive(Debug, Error)]
pub enum AmxGuestSupportError {
    /// Attempted to enable AMX on a CPU from a vendor that is not known to support AMX features.
    #[error("The host CPU's vendor does not support AMX features. Only Intel provides such CPUs.")]
    VendorDoesNotSupportAmx,
    /// Unable to verify that the host supports AMX.
    #[error("The host does not support AMX tile state components: errno={errno}")]
    AmxNotSupported { errno: i64 },
    /// The syscall to check for AMX tile state support succeeded, but the returned
    /// features did not match our expectations.
    #[error(
        "Could not verify AMX support. These are the supported features that were reported: features={features}"
    )]
    InvalidAmxTileFeatureCheck { features: usize },
    /// The request to enable AMX related state components for guests failed.
    #[error("Failed to enable AMX tile state components for guests: errno={errno}")]
    AmxGuestTileRequest { errno: i64 },
}
