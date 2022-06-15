// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2020, Microsoft Corporation
//
// Copyright 2018-2019 CrowdStrike, Inc.
//
//
use crate::arch::x86::{msr_index, SegmentRegisterOps, MTRR_ENABLE, MTRR_MEM_TYPE_WB};
use serde::{Deserialize, Serialize};
use std::fmt;
use crate::generic_x86_64;

///
/// Export generically-named wrappers of mshv_bindings for Unix-based platforms
///
pub use {
    mshv_bindings::hv_cpuid_entry, mshv_bindings::mshv_user_mem_region as MemoryRegion,
    mshv_bindings::msr_entry as MsrEntry, mshv_bindings::CpuId, mshv_bindings::DebugRegisters,
    mshv_bindings::FloatingPointUnit as FpuState, mshv_bindings::LapicState,
    mshv_bindings::MiscRegs as MiscRegisters, mshv_bindings::MsrList,
    mshv_bindings::Msrs as MsrEntries, mshv_bindings::Msrs, mshv_bindings::SegmentRegister,
    mshv_bindings::SpecialRegisters, mshv_bindings::StandardRegisters,
    mshv_bindings::SuspendRegisters, mshv_bindings::VcpuEvents, mshv_bindings::XSave as Xsave,
    mshv_bindings::Xcrs as ExtendedControlRegisters,
};

pub const CPUID_FLAG_VALID_INDEX: u32 = 0;

#[derive(Clone, Serialize, Deserialize)]
pub struct VcpuMshvState {
    pub msrs: MsrEntries,
    pub vcpu_events: VcpuEvents,
    pub regs: generic_x86_64::StandardRegisters,
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

pub struct IrqRouting {}
pub enum VcpuExit {}
pub struct MpState {}


pub fn boot_msr_entries() -> MsrEntries {
    MsrEntries::from_entries(&[
        msr!(msr_index::MSR_IA32_SYSENTER_CS),
        msr!(msr_index::MSR_IA32_SYSENTER_ESP),
        msr!(msr_index::MSR_IA32_SYSENTER_EIP),
        msr!(msr_index::MSR_STAR),
        msr!(msr_index::MSR_CSTAR),
        msr!(msr_index::MSR_LSTAR),
        msr!(msr_index::MSR_KERNEL_GS_BASE),
        msr!(msr_index::MSR_SYSCALL_MASK),
        msr!(msr_index::MSR_IA32_TSC),
        msr_data!(msr_index::MSR_MTRRdefType, MTRR_ENABLE | MTRR_MEM_TYPE_WB),
    ])
    .unwrap()
}

impl From<hv_cpuid_entry> for generic_x86_64::CpuIdEntry {
    fn from(entry: hv_cpuid_entry) -> Self {
        generic_x86_64::CpuIdEntry {
            function: entry.function,
            index: entry.index,
            flags: entry.flags,
            eax: entry.eax,
            ebx: entry.ebx,
            ecx: entry.ecx,
            edx: entry.edx,
            padding: entry.padding,
        }
    }
}

impl From<generic_x86_64::CpuIdEntry> for hv_cpuid_entry {
    fn from(entry: generic_x86_64::CpuIdEntry) -> Self {
        hv_cpuid_entry {
            function: entry.function,
            index: entry.index,
            flags: entry.flags,
            eax: entry.eax,
            ebx: entry.ebx,
            ecx: entry.ecx,
            edx: entry.edx,
            padding: entry.padding,
        }
    }
}

pub fn convert_to_generic_cpu_id(cpuid: &CpuId) -> generic_x86_64::CpuId {
    let cpuid_vector: Vec<generic_x86_64::CpuIdEntry> = cpuid.as_slice()
        .iter()
        .map(|&entry| entry.into())
        .collect();
    generic_x86_64::CpuId::from_entries(&cpuid_vector).unwrap()
}

pub fn convert_from_generic_cpu_id(cpuid: &generic_x86_64::CpuId) -> CpuId {
    let cpuid_vector: Vec<hv_cpuid_entry> = cpuid.as_slice()
        .iter()
        .map(|&entry| entry.into())
        .collect();
    CpuId::from_entries(&cpuid_vector).unwrap()
}

impl From<&StandardRegisters> for generic_x86_64::StandardRegisters {
    fn from(regs: &StandardRegisters) -> Self {
        generic_x86_64::StandardRegisters {
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

impl From<&generic_x86_64::StandardRegisters> for StandardRegisters {
    fn from(regs: &generic_x86_64::StandardRegisters) -> Self {
        StandardRegisters {
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

impl From<&SegmentRegister> for generic_x86_64::SegmentRegister {
    fn from(seg: &SegmentRegister) -> Self {
        generic_x86_64::SegmentRegister {
            base: seg.base,
            limit: seg.limit,
            selector: seg.selector,
            type_: seg.type_,
            present: seg.present,
            dpl: seg.dpl,
            db: seg.db,
            s: seg.s,
            l: seg.l,
            g: seg.g,
            avl: seg.avl,
            unusable: seg.unusable,
            padding: seg.padding,
        }
    }
}

impl From<&generic_x86_64::SegmentRegister> for SegmentRegister {
    fn from(seg: &generic_x86_64::SegmentRegister) -> Self {
        SegmentRegister {
            base: seg.base,
            limit: seg.limit,
            selector: seg.selector,
            type_: seg.type_,
            present: seg.present,
            dpl: seg.dpl,
            db: seg.db,
            s: seg.s,
            l: seg.l,
            g: seg.g,
            avl: seg.avl,
            unusable: seg.unusable,
            padding: seg.padding,
        }
    }
}