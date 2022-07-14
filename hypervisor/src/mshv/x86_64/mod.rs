// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2020, Microsoft Corporation
//
// Copyright 2018-2019 CrowdStrike, Inc.
//
//
use crate::arch::x86::{SegmentRegisterOps, StandardRegisters};
use serde::{Deserialize, Serialize};
use std::fmt;

///
/// Export generically-named wrappers of mshv_bindings for Unix-based platforms
///
pub use {
    mshv_bindings::hv_cpuid_entry as CpuIdEntry,
    mshv_bindings::mshv_user_mem_region as MemoryRegion, mshv_bindings::msr_entry as MsrEntry,
    mshv_bindings::CpuId, mshv_bindings::DebugRegisters,
    mshv_bindings::FloatingPointUnit as FpuState, mshv_bindings::LapicState,
    mshv_bindings::MiscRegs as MiscRegisters, mshv_bindings::MsrList,
    mshv_bindings::Msrs as MsrEntries, mshv_bindings::Msrs, mshv_bindings::SegmentRegister,
    mshv_bindings::SpecialRegisters, mshv_bindings::StandardRegisters as MshvStandardRegisters,
    mshv_bindings::SuspendRegisters, mshv_bindings::VcpuEvents, mshv_bindings::XSave as Xsave,
    mshv_bindings::Xcrs as ExtendedControlRegisters,
};

pub const CPUID_FLAG_VALID_INDEX: u32 = 0;

#[derive(Clone, Serialize, Deserialize)]
pub struct VcpuMshvState {
    pub msrs: MsrEntries,
    pub vcpu_events: VcpuEvents,
    pub regs: MshvStandardRegisters,
    pub sregs: SpecialRegisters,
    pub fpu: FpuState,
    pub xcrs: ExtendedControlRegisters,
    pub lapic: LapicState,
    pub dbg: DebugRegisters,
    pub xsave: Xsave,
    pub misc: MiscRegisters,
}

impl fmt::Display for VcpuMshvState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let expected_num_msrs = self.msrs.as_fam_struct_ref().nmsrs as usize;
        let mut msr_entries = vec![vec![0; 2]; expected_num_msrs];

        for (i, entry) in self.msrs.as_slice().iter().enumerate() {
            msr_entries[i][1] = entry.data;
            msr_entries[i][0] = entry.index as u64;
        }
        write!(f, "Number of MSRs: {}: MSRs: {:#010X?}, -- VCPU Events: {:?} -- Standard registers: {:?} Special Registers: {:?} ---- Floating Point Unit: {:?} --- Extended Control Register: {:?} --- Local APIC: {:?} --- DBG: {:?} --- Xsave: {:?}",
                msr_entries.len(),
                msr_entries,
                self.vcpu_events,
                self.regs,
                self.sregs,
                self.fpu,
                self.xcrs,
                self.lapic,
                self.dbg,
                self.xsave,
        )
    }
}

impl SegmentRegisterOps for SegmentRegister {
    fn segment_type(&self) -> u8 {
        self.type_
    }
    fn set_segment_type(&mut self, val: u8) {
        self.type_ = val;
    }

    fn dpl(&self) -> u8 {
        self.dpl
    }

    fn set_dpl(&mut self, val: u8) {
        self.dpl = val;
    }

    fn present(&self) -> u8 {
        self.present
    }

    fn set_present(&mut self, val: u8) {
        self.present = val;
    }

    fn long(&self) -> u8 {
        self.l
    }

    fn set_long(&mut self, val: u8) {
        self.l = val;
    }

    fn avl(&self) -> u8 {
        self.avl
    }

    fn set_avl(&mut self, val: u8) {
        self.avl = val;
    }

    fn desc_type(&self) -> u8 {
        self.s
    }

    fn set_desc_type(&mut self, val: u8) {
        self.s = val;
    }

    fn granularity(&self) -> u8 {
        self.g
    }

    fn set_granularity(&mut self, val: u8) {
        self.g = val;
    }

    fn db(&self) -> u8 {
        self.db
    }

    fn set_db(&mut self, val: u8) {
        self.db = val;
    }
}

impl From<StandardRegisters> for MshvStandardRegisters {
    fn from(regs: StandardRegisters) -> Self {
        Self {
            rax: regs.rax,
            rbx: regs.rbx,
            rcx: regs.rcx,
            rdx: regs.rdx,
            rsi: regs.rsi,
            rdi: regs.rdi,
            rsp: regs.rsp,
            rbp: regs.rbp,
            r8: regs.r8,
            r9: regs.r9,
            r10: regs.r10,
            r11: regs.r11,
            r12: regs.r12,
            r13: regs.r13,
            r14: regs.r14,
            r15: regs.r15,
            rip: regs.rip,
            rflags: regs.rflags,
        }
    }
}

impl From<MshvStandardRegisters> for StandardRegisters {
    fn from(regs: MshvStandardRegisters) -> Self {
        Self {
            rax: regs.rax,
            rbx: regs.rbx,
            rcx: regs.rcx,
            rdx: regs.rdx,
            rsi: regs.rsi,
            rdi: regs.rdi,
            rsp: regs.rsp,
            rbp: regs.rbp,
            r8: regs.r8,
            r9: regs.r9,
            r10: regs.r10,
            r11: regs.r11,
            r12: regs.r12,
            r13: regs.r13,
            r14: regs.r14,
            r15: regs.r15,
            rip: regs.rip,
            rflags: regs.rflags,
        }
    }
}
