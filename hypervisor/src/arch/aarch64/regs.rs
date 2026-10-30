// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2025, Microsoft Corporation
//

use bitfield_struct::bitfield;
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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FaultStatusCode(pub u8);

impl FaultStatusCode {
    pub const ADDRESS_SIZE_FAULT_LEVEL0: Self = Self(0b000000);
    pub const ADDRESS_SIZE_FAULT_LEVEL1: Self = Self(0b000001);
    pub const ADDRESS_SIZE_FAULT_LEVEL2: Self = Self(0b000010);
    pub const ADDRESS_SIZE_FAULT_LEVEL3: Self = Self(0b000011);
    pub const TRANSLATION_FAULT_LEVEL0: Self = Self(0b000100);
    pub const TRANSLATION_FAULT_LEVEL1: Self = Self(0b000101);
    pub const TRANSLATION_FAULT_LEVEL2: Self = Self(0b000110);
    pub const TRANSLATION_FAULT_LEVEL3: Self = Self(0b000111);
    pub const ACCESS_FLAG_FAULT_LEVEL0: Self = Self(0b001000);
    pub const ACCESS_FLAG_FAULT_LEVEL1: Self = Self(0b001001);
    pub const ACCESS_FLAG_FAULT_LEVEL2: Self = Self(0b001010);
    pub const ACCESS_FLAG_FAULT_LEVEL3: Self = Self(0b001011);
    pub const PERMISSION_FAULT_LEVEL0: Self = Self(0b001100);
    pub const PERMISSION_FAULT_LEVEL1: Self = Self(0b001101);
    pub const PERMISSION_FAULT_LEVEL2: Self = Self(0b001110);
    pub const PERMISSION_FAULT_LEVEL3: Self = Self(0b001111);
    pub const SYNCHRONOUS_EXTERNAL_ABORT: Self = Self(0b010000);
    pub const SYNC_TAG_CHECK_FAULT: Self = Self(0b010001);
    pub const SEA_TTW_LEVEL_NEG1: Self = Self(0b010011);
    pub const SEA_TTW_LEVEL0: Self = Self(0b010100);
    pub const SEA_TTW_LEVEL1: Self = Self(0b010101);
    pub const SEA_TTW_LEVEL2: Self = Self(0b010110);
    pub const SEA_TTW_LEVEL3: Self = Self(0b010111);
    pub const ECC_PARITY: Self = Self(0b011000);
    pub const ECC_PARITY_TTW_LEVEL_NEG1: Self = Self(0b011011);
    pub const ECC_PARITY_TTW_LEVEL0: Self = Self(0b011100);
    pub const ECC_PARITY_TTW_LEVEL1: Self = Self(0b011101);
    pub const ECC_PARITY_TTW_LEVEL2: Self = Self(0b011110);
    pub const ECC_PARITY_TTW_LEVEL3: Self = Self(0b011111);
    /// Valid only for data fault.
    pub const ALIGNMENT_FAULT: Self = Self(0b100001);
    /// Valid only for instruction fault.
    pub const GRANULE_PROTECTION_FAULT_LEVEL_NEG: Self = Self(0b100011);
    /// Valid only for instruction fault.
    pub const GRANULE_PROTECTION_FAULT_LEVEL0: Self = Self(0b100100);
    /// Valid only for instruction fault.
    pub const GRANULE_PROTECTION_FAULT_LEVEL1: Self = Self(0b100101);
    /// Valid only for instruction fault.
    pub const GRANULE_PROTECTION_FAULT_LEVEL2: Self = Self(0b100110);
    /// Valid only for instruction fault.
    pub const GRANULE_PROTECTION_FAULT_LEVEL3: Self = Self(0b100111);
    pub const ADDRESS_SIZE_FAULT_LEVEL_NEG1: Self = Self(0b101001);
    pub const TRANSLATION_FAULT_LEVEL_NEG1: Self = Self(0b101011);
    pub const TLB_CONFLICT_ABORT: Self = Self(0b110000);
    pub const UNSUPPORTED_HW_UPDATE_FAULT: Self = Self(0b110001);
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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExceptionClass(pub u8);

impl ExceptionClass {
    pub const UNKNOWN: Self = Self(0b000000);
    pub const WFI: Self = Self(0b000001);
    pub const MCR_MRC_COPROC_15: Self = Self(0b000011);
    pub const MCRR_MRRC_COPROC_15: Self = Self(0b000100);
    pub const MCR_MRC_COPROC_14: Self = Self(0b000101);
    pub const LDC_STC: Self = Self(0b000110);
    pub const FP_OR_SIMD: Self = Self(0b000111);
    pub const VMRS: Self = Self(0b001000);
    pub const POINTER_AUTH_HCR_OR_SCR: Self = Self(0b001001);
    pub const LS64: Self = Self(0b001010);
    pub const MRRC_COPROC_14: Self = Self(0b001100);
    pub const BRANCH_TARGET: Self = Self(0b001101);
    pub const ILLEGAL_STATE: Self = Self(0b001110);
    pub const SVC32: Self = Self(0b010001);
    pub const HVC32: Self = Self(0b010010);
    pub const SMC32: Self = Self(0b010011);
    pub const SVC: Self = Self(0b010101);
    pub const HVC: Self = Self(0b010110);
    pub const SMC: Self = Self(0b010111);
    pub const SYSTEM: Self = Self(0b011000);
    pub const SVE: Self = Self(0b011001);
    pub const ERET: Self = Self(0b011010);
    pub const TSTART: Self = Self(0b011011);
    pub const POINTER_AUTH: Self = Self(0b011100);
    pub const SME: Self = Self(0b011101);
    pub const INSTRUCTION_ABORT_LOWER: Self = Self(0b100000);
    pub const INSTRUCTION_ABORT: Self = Self(0b100001);
    pub const PC_ALIGNMENT: Self = Self(0b100010);
    pub const DATA_ABORT_LOWER: Self = Self(0b100100);
    pub const DATA_ABORT: Self = Self(0b100101);
    pub const SP_ALIGNMENT_FAULT: Self = Self(0b100110);
    pub const MEMORY_OP: Self = Self(0b100111);
    pub const FP_EXCEPTION_32: Self = Self(0b101000);
    pub const FP_EXCEPTION_64: Self = Self(0b101100);
    pub const SERROR: Self = Self(0b101111);
    pub const BREAKPOINT_LOWER: Self = Self(0b110000);
    pub const BREAKPOINT: Self = Self(0b110001);
    pub const STEP_LOWER: Self = Self(0b110010);
    pub const STEP: Self = Self(0b110011);
    pub const WATCHPOINT_LOWER: Self = Self(0b110100);
    pub const WATCHPOINT: Self = Self(0b110101);
    pub const BRK32: Self = Self(0b111000);
    pub const VECTOR_CATCH_32: Self = Self(0b111010);
    pub const BRK: Self = Self(0b111100);
}

// PSR (Processor State Register) bits.
// Taken from arch/arm64/include/uapi/asm/ptrace.h.
#[expect(non_upper_case_globals)]
const PSR_MODE_EL1h: u64 = 0x0000_0005;
#[expect(non_upper_case_globals)]
const PSR_MODE_EL2h: u64 = 0x0000_0009;
const PSR_F_BIT: u64 = 0x0000_0040;
const PSR_I_BIT: u64 = 0x0000_0080;
const PSR_A_BIT: u64 = 0x0000_0100;
const PSR_D_BIT: u64 = 0x0000_0200;
// Taken from arch/arm64/kvm/inject_fault.c.
pub const PSTATE_FAULT_BITS_64_EL1H: u64 =
    PSR_MODE_EL1h | PSR_A_BIT | PSR_F_BIT | PSR_I_BIT | PSR_D_BIT;
pub const PSTATE_FAULT_BITS_64_EL2H: u64 =
    PSR_MODE_EL2h | PSR_A_BIT | PSR_F_BIT | PSR_I_BIT | PSR_D_BIT;

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

pub const AARCH64_PMU_PPI_INDEX: u32 = 7;
pub const AARCH64_MIN_PPI_IRQ: u32 = 16;
pub const AARCH64_PMU_IRQ: u32 = AARCH64_MIN_PPI_IRQ + AARCH64_PMU_PPI_INDEX;
pub const AARCH64_GIC_MAINT_PPI_INDEX: u32 = 9;
pub const AARCH64_GIC_MAINT_IRQ: u32 = AARCH64_MIN_PPI_IRQ + AARCH64_GIC_MAINT_PPI_INDEX;
