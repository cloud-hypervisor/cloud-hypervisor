// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2025, Microsoft Corporation
//

use bitfield_struct::bitfield;
use open_enum::open_enum;
use zerocopy::{FromBytes, IntoBytes};

/// ESR_EL2, exception syndrome register.
#[bitfield(u64)]
#[derive(IntoBytes, FromBytes)]
pub struct EsrEl2 {
    #[bits(25)]
    pub iss: u32,
    pub il: bool,
    #[bits(6)]
    pub ec: u8,
    #[bits(5)]
    pub iss2: u8,
    #[bits(27)]
    _rsvd: u32,
}

#[open_enum]
#[derive(Debug)]
#[repr(u8)]
pub enum FaultStatusCode {
    ADDRESS_SIZE_FAULT_LEVEL0 = 0b000000,
    ADDRESS_SIZE_FAULT_LEVEL1 = 0b000001,
    ADDRESS_SIZE_FAULT_LEVEL2 = 0b000010,
    ADDRESS_SIZE_FAULT_LEVEL3 = 0b000011,
    TRANSLATION_FAULT_LEVEL0 = 0b000100,
    TRANSLATION_FAULT_LEVEL1 = 0b000101,
    TRANSLATION_FAULT_LEVEL2 = 0b000110,
    TRANSLATION_FAULT_LEVEL3 = 0b000111,
    ACCESS_FLAG_FAULT_LEVEL0 = 0b001000,
    ACCESS_FLAG_FAULT_LEVEL1 = 0b001001,
    ACCESS_FLAG_FAULT_LEVEL2 = 0b001010,
    ACCESS_FLAG_FAULT_LEVEL3 = 0b001011,
    PERMISSION_FAULT_LEVEL0 = 0b001100,
    PERMISSION_FAULT_LEVEL1 = 0b001101,
    PERMISSION_FAULT_LEVEL2 = 0b001110,
    PERMISSION_FAULT_LEVEL3 = 0b001111,
    SYNCHRONOUS_EXTERNAL_ABORT = 0b010000,
    SYNC_TAG_CHECK_FAULT = 0b010001,
    SEA_TTW_LEVEL_NEG1 = 0b010011,
    SEA_TTW_LEVEL0 = 0b010100,
    SEA_TTW_LEVEL1 = 0b010101,
    SEA_TTW_LEVEL2 = 0b010110,
    SEA_TTW_LEVEL3 = 0b010111,
    ECC_PARITY = 0b011000,
    ECC_PARITY_TTW_LEVEL_NEG1 = 0b011011,
    ECC_PARITY_TTW_LEVEL0 = 0b011100,
    ECC_PARITY_TTW_LEVEL1 = 0b011101,
    ECC_PARITY_TTW_LEVEL2 = 0b011110,
    ECC_PARITY_TTW_LEVEL3 = 0b011111,
    /// Valid only for data fault.
    ALIGNMENT_FAULT = 0b100001,
    /// Valid only for instruction fault.
    GRANULE_PROTECTION_FAULT_LEVEL_NEG = 0b100011,
    /// Valid only for instruction fault.
    GRANULE_PROTECTION_FAULT_LEVEL0 = 0b100100,
    /// Valid only for instruction fault.
    GRANULE_PROTECTION_FAULT_LEVEL1 = 0b100101,
    /// Valid only for instruction fault.
    GRANULE_PROTECTION_FAULT_LEVEL2 = 0b100110,
    /// Valid only for instruction fault.
    GRANULE_PROTECTION_FAULT_LEVEL3 = 0b100111,
    ADDRESS_SIZE_FAULT_LEVEL_NEG1 = 0b101001,
    TRANSLATION_FAULT_LEVEL_NEG1 = 0b101011,
    TLB_CONFLICT_ABORT = 0b110000,
    UNSUPPORTED_HW_UPDATE_FAULT = 0b110001,
}

/// Support for embedding within IssDataAbort/IssInstructionAbort
impl FaultStatusCode {
    const fn from_bits(bits: u32) -> Self {
        FaultStatusCode((bits & 0x3f) as u8)
    }

    const fn into_bits(self) -> u32 {
        self.0 as u32
    }
}

#[bitfield(u32)]
pub struct IssDataAbort {
    #[bits(6)]
    pub dfsc: FaultStatusCode,
    // Write operation (write not read)
    pub wnr: bool,
    pub s1ptw: bool,
    pub cm: bool,
    pub ea: bool,
    /// FAR not valid
    pub fnv: bool,
    #[bits(2)]
    pub set: u8,
    pub vncr: bool,
    /// Acquire/release
    pub ar: bool,
    /// (ISV==1) 64-bit, (ISV==0) FAR is approximate
    pub sf: bool,
    #[bits(5)]
    /// Register index.
    pub srt: u8,
    /// Sign extended.
    pub sse: bool,
    #[bits(2)]
    /// access width log2
    pub sas: u8,
    /// Valid ESREL2 iss field.
    pub isv: bool,
    #[bits(7)]
    _unused: u8,
}

#[open_enum]
#[repr(u8)]
pub enum ExceptionClass {
    UNKNOWN = 0b000000,
    WFI = 0b000001,
    MCR_MRC_COPROC_15 = 0b000011,
    MCRR_MRRC_COPROC_15 = 0b000100,
    MCR_MRC_COPROC_14 = 0b000101,
    LDC_STC = 0b000110,
    FP_OR_SIMD = 0b000111,
    VMRS = 0b001000,
    POINTER_AUTH_HCR_OR_SCR = 0b001001,
    LS64 = 0b001010,
    MRRC_COPROC_14 = 0b001100,
    BRANCH_TARGET = 0b001101,
    ILLEGAL_STATE = 0b001110,
    SVC32 = 0b010001,
    HVC32 = 0b010010,
    SMC32 = 0b010011,
    SVC = 0b010101,
    HVC = 0b010110,
    SMC = 0b010111,
    SYSTEM = 0b011000,
    SVE = 0b011001,
    ERET = 0b011010,
    TSTART = 0b011011,
    POINTER_AUTH = 0b011100,
    SME = 0b011101,
    INSTRUCTION_ABORT_LOWER = 0b100000,
    INSTRUCTION_ABORT = 0b100001,
    PC_ALIGNMENT = 0b100010,
    DATA_ABORT_LOWER = 0b100100,
    DATA_ABORT = 0b100101,
    SP_ALIGNMENT_FAULT = 0b100110,
    MEMORY_OP = 0b100111,
    FP_EXCEPTION_32 = 0b101000,
    FP_EXCEPTION_64 = 0b101100,
    SERROR = 0b101111,
    BREAKPOINT_LOWER = 0b110000,
    BREAKPOINT = 0b110001,
    STEP_LOWER = 0b110010,
    STEP = 0b110011,
    WATCHPOINT_LOWER = 0b110100,
    WATCHPOINT = 0b110101,
    BRK32 = 0b111000,
    VECTOR_CATCH_32 = 0b111010,
    BRK = 0b111100,
}

#[allow(non_upper_case_globals)]
// PSR (Processor State Register) bits.
// Taken from arch/arm64/include/uapi/asm/ptrace.h.
const PSR_MODE_EL1h: u64 = 0x0000_0005;
const PSR_F_BIT: u64 = 0x0000_0040;
const PSR_I_BIT: u64 = 0x0000_0080;
const PSR_A_BIT: u64 = 0x0000_0100;
const PSR_D_BIT: u64 = 0x0000_0200;
// Taken from arch/arm64/kvm/inject_fault.c.
pub const PSTATE_FAULT_BITS_64: u64 = PSR_MODE_EL1h | PSR_A_BIT | PSR_F_BIT | PSR_I_BIT | PSR_D_BIT;

// AArch64 system register encoding:
// See https://developer.arm.com/documentation/ddi0487 (chapter D12)
//
//   31      22  21 20 19 18 16 15 12 11  8 7   5 4  0
//  +----------+---+-----+-----+-----+-----+-----+----+
//  |1101010100| L | op0 | op1 | CRn | CRm | op2 | Rt |
//  +----------+---+-----+-----+-----+-----+-----+----+
//
// Notes:
// - L and Rt are reserved as implementation defined fields, ignored.

const SYSREG_HEAD: u32 = 0b1101010100u32 << 22;
const SYSREG_OP0_SHIFT: u32 = 19;
const SYSREG_OP0_MASK: u32 = 0b11u32 << 19;
const SYSREG_OP1_SHIFT: u32 = 16;
const SYSREG_OP1_MASK: u32 = 0b111u32 << 16;
const SYSREG_CRN_SHIFT: u32 = 12;
const SYSREG_CRN_MASK: u32 = 0b1111u32 << 12;
const SYSREG_CRM_SHIFT: u32 = 8;
const SYSREG_CRM_MASK: u32 = 0b1111u32 << 8;
const SYSREG_OP2_SHIFT: u32 = 5;
const SYSREG_OP2_MASK: u32 = 0b111u32 << 5;

/// Define the ID of system registers
#[macro_export]
macro_rules! arm64_sys_reg {
    ($name: tt, $op0: tt, $op1: tt, $crn: tt, $crm: tt, $op2: tt) => {
        pub const $name: u32 = SYSREG_HEAD
            | ((($op0 as u32) << SYSREG_OP0_SHIFT) & SYSREG_OP0_MASK as u32)
            | ((($op1 as u32) << SYSREG_OP1_SHIFT) & SYSREG_OP1_MASK as u32)
            | ((($crn as u32) << SYSREG_CRN_SHIFT) & SYSREG_CRN_MASK as u32)
            | ((($crm as u32) << SYSREG_CRM_SHIFT) & SYSREG_CRM_MASK as u32)
            | ((($op2 as u32) << SYSREG_OP2_SHIFT) & SYSREG_OP2_MASK as u32);
    };
}

arm64_sys_reg!(MPIDR_EL1, 3, 0, 0, 0, 5);
arm64_sys_reg!(ID_AA64MMFR0_EL1, 3, 0, 0, 7, 0);
arm64_sys_reg!(TTBR1_EL1, 3, 0, 2, 0, 1);
arm64_sys_reg!(TCR_EL1, 3, 0, 2, 0, 2);

pub const AARCH64_ARCH_TIMER_PHYS_SECURE_IRQ: u32 = 13;
pub const AARCH64_ARCH_TIMER_PHYS_NONSECURE_IRQ: u32 = 14;
pub const AARCH64_ARCH_TIMER_VIRT_IRQ: u32 = 11;
pub const AARCH64_ARCH_TIMER_HYP_IRQ: u32 = 10;

// PMU PPI interrupt number
pub const AARCH64_PMU_IRQ: u32 = 7;

pub const AARCH64_MIN_PPI_IRQ: u32 = 16;
