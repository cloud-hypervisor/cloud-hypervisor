// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2020, Microsoft Corporation
//
// Copyright 2018-2019 CrowdStrike, Inc.
//
//
use crate::generic_x86_64;
use serde::{Deserialize, Serialize};
use std::fmt;

///
/// Export generically-named wrappers of mshv_bindings for Unix-based platforms
///
pub use {
    mshv_bindings::hv_cpuid_entry, mshv_bindings::mshv_user_mem_region as MemoryRegion,
    mshv_bindings::msr_entry, mshv_bindings::CpuId, mshv_bindings::DebugRegisters,
    mshv_bindings::FloatingPointUnit, mshv_bindings::LapicState,
    mshv_bindings::MiscRegs as MiscRegisters, mshv_bindings::MsrList,
    mshv_bindings::Msrs, mshv_bindings::SegmentRegister,
    mshv_bindings::SpecialRegisters, mshv_bindings::StandardRegisters,
    mshv_bindings::SuspendRegisters, mshv_bindings::TableRegister, mshv_bindings::VcpuEvents,
    mshv_bindings::XSave,
};

pub const CPUID_FLAG_VALID_INDEX: u32 = 0;

#[derive(Clone, Serialize, Deserialize)]
pub struct VcpuMshvState {
    pub msrs: generic_x86_64::MsrEntries,
    pub vcpu_events: generic_x86_64::VcpuEvents,
    pub regs: generic_x86_64::StandardRegisters,
    pub sregs: generic_x86_64::SpecialRegisters,
    pub fpu: generic_x86_64::FpuState,
    pub lapic: generic_x86_64::LapicState,
    pub dbg: DebugRegisters,
    pub xsave: generic_x86_64::Xsave,
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
        write!(f, "Number of MSRs: {}: MSRs: {:#010X?}, -- VCPU Events: {:?} -- Standard registers: {:?} Special Registers: {:?} ---- Floating Point Unit: {:?} --- Local APIC: {:?} --- DBG: {:?} --- Xsave: {:?}",
                msr_entries.len(),
                msr_entries,
                self.vcpu_events,
                self.regs,
                self.sregs,
                self.fpu,
                self.lapic,
                self.dbg,
                self.xsave,
        )
    }
}

pub struct IrqRouting {}
pub enum VcpuExit {}
pub struct MpState {}

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
    let cpuid_vector: Vec<generic_x86_64::CpuIdEntry> =
        cpuid.as_slice().iter().map(|&entry| entry.into()).collect();
    generic_x86_64::CpuId::from_entries(&cpuid_vector).unwrap()
}

pub fn convert_from_generic_cpu_id(cpuid: &generic_x86_64::CpuId) -> CpuId {
    let cpuid_vector: Vec<hv_cpuid_entry> =
        cpuid.as_slice().iter().map(|&entry| entry.into()).collect();
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

impl From<&TableRegister> for generic_x86_64::TableRegister {
    fn from(table: &TableRegister) -> Self {
        generic_x86_64::TableRegister {
            base: table.base,
            limit: table.limit,
        }
    }
}

impl From<&generic_x86_64::TableRegister> for TableRegister {
    fn from(table: &generic_x86_64::TableRegister) -> Self {
        TableRegister {
            base: table.base,
            limit: table.limit,
        }
    }
}

impl From<&SpecialRegisters> for generic_x86_64::SpecialRegisters {
    fn from(sregs: &SpecialRegisters) -> Self {
        generic_x86_64::SpecialRegisters {
            cs: (&sregs.cs).into(),
            ds: (&sregs.ds).into(),
            es: (&sregs.es).into(),
            fs: (&sregs.fs).into(),
            gs: (&sregs.gs).into(),
            ss: (&sregs.ss).into(),
            tr: (&sregs.tr).into(),
            ldt: (&sregs.ldt).into(),
            gdt: (&sregs.gdt).into(),
            idt: (&sregs.idt).into(),
            cr0: sregs.cr0,
            cr2: sregs.cr2,
            cr3: sregs.cr3,
            cr4: sregs.cr4,
            cr8: sregs.cr8,
            efer: sregs.efer,
            apic_base: sregs.apic_base,
            interrupt_bitmap: sregs.interrupt_bitmap,
        }
    }
}

impl From<&generic_x86_64::SpecialRegisters> for SpecialRegisters {
    fn from(sregs: &generic_x86_64::SpecialRegisters) -> Self {
        SpecialRegisters {
            cs: (&sregs.cs).into(),
            ds: (&sregs.ds).into(),
            es: (&sregs.es).into(),
            fs: (&sregs.fs).into(),
            gs: (&sregs.gs).into(),
            ss: (&sregs.ss).into(),
            tr: (&sregs.tr).into(),
            ldt: (&sregs.ldt).into(),
            gdt: (&sregs.gdt).into(),
            idt: (&sregs.idt).into(),
            cr0: sregs.cr0,
            cr2: sregs.cr2,
            cr3: sregs.cr3,
            cr4: sregs.cr4,
            cr8: sregs.cr8,
            efer: sregs.efer,
            apic_base: sregs.apic_base,
            interrupt_bitmap: sregs.interrupt_bitmap,
        }
    }
}

impl From<&FloatingPointUnit> for generic_x86_64::FpuState {
    fn from(fpu: &FloatingPointUnit) -> Self {
        generic_x86_64::FpuState {
            fpr: fpu.fpr,
            fcw: fpu.fcw,
            fsw: fpu.fsw,
            ftwx: fpu.ftwx,
            pad1: fpu.pad1,
            last_opcode: fpu.last_opcode,
            last_ip: fpu.last_ip,
            last_dp: fpu.last_dp,
            xmm: fpu.xmm,
            mxcsr: fpu.mxcsr,
            pad2: fpu.pad2,
        }
    }
}

impl From<&generic_x86_64::FpuState> for FloatingPointUnit {
    fn from(fpu: &generic_x86_64::FpuState) -> Self {
        FloatingPointUnit {
            fpr: fpu.fpr,
            fcw: fpu.fcw,
            fsw: fpu.fsw,
            ftwx: fpu.ftwx,
            pad1: fpu.pad1,
            last_opcode: fpu.last_opcode,
            last_ip: fpu.last_ip,
            last_dp: fpu.last_dp,
            xmm: fpu.xmm,
            mxcsr: fpu.mxcsr,
            pad2: fpu.pad2,
        }
    }
}


impl From<&LapicState> for generic_x86_64::LapicState {
    fn from(lapic: &LapicState) -> Self {
        generic_x86_64::LapicState {
            regs: lapic.regs,
        }
    }
}

impl From<&generic_x86_64::LapicState> for LapicState {
    fn from(lapic: &generic_x86_64::LapicState) -> Self {
        LapicState {
            regs: lapic.regs,
        }
    }
}

impl From<&msr_entry> for generic_x86_64::MsrEntry {
    fn from(msr_entry: &msr_entry) -> Self {
        generic_x86_64::MsrEntry {
            index: msr_entry.index,
            reserved: msr_entry.reserved,
            data: msr_entry.data,
        }
    }
}

impl From<&generic_x86_64::MsrEntry> for msr_entry {
    fn from(msr_entry: &generic_x86_64::MsrEntry) -> Self {
        msr_entry {
            index: msr_entry.index,
            reserved: msr_entry.reserved,
            data: msr_entry.data,
        }
    }
}

pub fn convert_from_generic_msrs(msr_entries: &generic_x86_64::MsrEntries) -> Msrs {
    let msrs_vector: Vec<msr_entry> = msr_entries.as_slice().iter().map(|msr| msr.into()).collect();
    Msrs::from_entries(&msrs_vector).unwrap()
}

pub fn convert_to_generic_msrs(msr_entries: &Msrs) -> generic_x86_64::MsrEntries {
    let msrs_vector: Vec<generic_x86_64::MsrEntry> =
        msr_entries.as_slice().iter().map(|msr| msr.into()).collect();
    generic_x86_64::MsrEntries::from_entries(&msrs_vector).unwrap()
}

pub fn convert_from_generic_msr_list(msr_list: &generic_x86_64::MsrList) -> MsrList {
    let msr_list_vector: &[u32] = msr_list.as_slice();
    MsrList::from_entries(msr_list_vector).unwrap()
}

pub fn convert_to_generic_msr_list(msr_list: &MsrList) -> generic_x86_64::MsrList {
    let msr_list_vector: &[u32] = msr_list.as_slice();
    generic_x86_64::MsrList::from_entries(msr_list_vector).unwrap()
}