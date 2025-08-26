// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2020, Microsoft Corporation
//
// Copyright 2018-2019 CrowdStrike, Inc.
//
//
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::arch::x86::{
    CpuIdEntry, DescriptorTable, FpuState, LapicState, MsrEntry, SegmentRegister, SpecialRegisters,
};

pub mod emulator;

///
/// Export generically-named wrappers of mshv_bindings for Unix-based platforms
///
pub use {
    mshv_bindings::AllVpStateComponents, mshv_bindings::CpuId, mshv_bindings::DebugRegisters,
    mshv_bindings::FloatingPointUnit, mshv_bindings::LapicState as MshvLapicState,
    mshv_bindings::MiscRegs as MiscRegisters, mshv_bindings::MsrList,
    mshv_bindings::Msrs as MsrEntries, mshv_bindings::Msrs,
    mshv_bindings::SegmentRegister as MshvSegmentRegister,
    mshv_bindings::SpecialRegisters as MshvSpecialRegisters,
    mshv_bindings::StandardRegisters as MshvStandardRegisters, mshv_bindings::SuspendRegisters,
    mshv_bindings::TableRegister, mshv_bindings::VcpuEvents, mshv_bindings::XSave as Xsave,
    mshv_bindings::Xcrs as ExtendedControlRegisters, mshv_bindings::hv_cpuid_entry,
    mshv_bindings::mshv_user_mem_region as MemoryRegion, mshv_bindings::msr_entry,
};

#[derive(Clone, Serialize, Deserialize)]
pub struct VcpuMshvState {
    pub msrs: Vec<MsrEntry>,
    pub vcpu_events: VcpuEvents,
    pub regs: MshvStandardRegisters,
    pub sregs: MshvSpecialRegisters,
    pub fpu: FpuState,
    pub xcrs: ExtendedControlRegisters,
    pub dbg: DebugRegisters,
    pub misc: MiscRegisters,
    pub vp_states: AllVpStateComponents,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct MshvClockData {
    pub ref_time: u64,
}

impl fmt::Display for VcpuMshvState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let expected_num_msrs = self.msrs.len();
        let mut msr_entries = vec![vec![0; 2]; expected_num_msrs];

        for (i, entry) in self.msrs.iter().enumerate() {
            msr_entries[i][1] = entry.data;
            msr_entries[i][0] = entry.index as u64;
        }
        write!(
            f,
            "Number of MSRs: {}: MSRs: {:#010X?}, -- VCPU Events: {:?} -- Standard registers: {:?} Special Registers: {:?} ---- Floating Point Unit: {:?} --- Extended Control Register: {:?} --- DBG: {:?} --- VP States: {:?}",
            msr_entries.len(),
            msr_entries,
            self.vcpu_events,
            self.regs,
            self.sregs,
            self.fpu,
            self.xcrs,
            self.dbg,
            self.vp_states,
        )
    }
}

impl From<SegmentRegister> for MshvSegmentRegister {
    fn from(s: SegmentRegister) -> Self {
        Self {
            base: s.base,
            limit: s.limit,
            selector: s.selector,
            type_: s.type_,
            present: s.present,
            dpl: s.dpl,
            db: s.db,
            s: s.s,
            l: s.l,
            g: s.g,
            avl: s.avl,
            unusable: s.unusable,
            ..Default::default()
        }
    }
}

impl From<MshvSegmentRegister> for SegmentRegister {
    fn from(s: MshvSegmentRegister) -> Self {
        Self {
            base: s.base,
            limit: s.limit,
            selector: s.selector,
            type_: s.type_,
            present: s.present,
            dpl: s.dpl,
            db: s.db,
            s: s.s,
            l: s.l,
            g: s.g,
            avl: s.avl,
            unusable: s.unusable,
        }
    }
}

impl From<DescriptorTable> for TableRegister {
    fn from(dt: DescriptorTable) -> Self {
        Self {
            base: dt.base,
            limit: dt.limit,
        }
    }
}

impl From<TableRegister> for DescriptorTable {
    fn from(dt: TableRegister) -> Self {
        Self {
            base: dt.base,
            limit: dt.limit,
        }
    }
}

impl From<SpecialRegisters> for MshvSpecialRegisters {
    fn from(s: SpecialRegisters) -> Self {
        Self {
            cs: s.cs.into(),
            ds: s.ds.into(),
            es: s.es.into(),
            fs: s.fs.into(),
            gs: s.gs.into(),
            ss: s.ss.into(),
            tr: s.tr.into(),
            ldt: s.ldt.into(),
            gdt: s.gdt.into(),
            idt: s.idt.into(),
            cr0: s.cr0,
            cr2: s.cr2,
            cr3: s.cr3,
            cr4: s.cr4,
            cr8: s.cr8,
            efer: s.efer,
            apic_base: s.apic_base,
            interrupt_bitmap: s.interrupt_bitmap,
        }
    }
}

impl From<MshvSpecialRegisters> for SpecialRegisters {
    fn from(s: MshvSpecialRegisters) -> Self {
        Self {
            cs: s.cs.into(),
            ds: s.ds.into(),
            es: s.es.into(),
            fs: s.fs.into(),
            gs: s.gs.into(),
            ss: s.ss.into(),
            tr: s.tr.into(),
            ldt: s.ldt.into(),
            gdt: s.gdt.into(),
            idt: s.idt.into(),
            cr0: s.cr0,
            cr2: s.cr2,
            cr3: s.cr3,
            cr4: s.cr4,
            cr8: s.cr8,
            efer: s.efer,
            apic_base: s.apic_base,
            interrupt_bitmap: s.interrupt_bitmap,
        }
    }
}

impl From<CpuIdEntry> for hv_cpuid_entry {
    fn from(e: CpuIdEntry) -> Self {
        Self {
            function: e.function,
            index: e.index,
            flags: e.flags,
            eax: e.eax,
            ebx: e.ebx,
            ecx: e.ecx,
            edx: e.edx,
            ..Default::default()
        }
    }
}

impl From<hv_cpuid_entry> for CpuIdEntry {
    fn from(e: hv_cpuid_entry) -> Self {
        Self {
            function: e.function,
            index: e.index,
            flags: e.flags,
            eax: e.eax,
            ebx: e.ebx,
            ecx: e.ecx,
            edx: e.edx,
        }
    }
}

impl From<FloatingPointUnit> for FpuState {
    fn from(s: FloatingPointUnit) -> Self {
        Self {
            fpr: s.fpr,
            fcw: s.fcw,
            fsw: s.fsw,
            ftwx: s.ftwx,
            last_opcode: s.last_opcode,
            last_ip: s.last_ip,
            last_dp: s.last_dp,
            xmm: s.xmm,
            mxcsr: s.mxcsr,
        }
    }
}

impl From<FpuState> for FloatingPointUnit {
    fn from(s: FpuState) -> Self {
        Self {
            fpr: s.fpr,
            fcw: s.fcw,
            fsw: s.fsw,
            ftwx: s.ftwx,
            last_opcode: s.last_opcode,
            last_ip: s.last_ip,
            last_dp: s.last_dp,
            xmm: s.xmm,
            mxcsr: s.mxcsr,
            ..Default::default()
        }
    }
}

impl From<LapicState> for MshvLapicState {
    fn from(s: LapicState) -> Self {
        Self { regs: s.regs }
    }
}

impl From<MshvLapicState> for LapicState {
    fn from(s: MshvLapicState) -> Self {
        Self { regs: s.regs }
    }
}

impl From<msr_entry> for MsrEntry {
    fn from(e: msr_entry) -> Self {
        Self {
            index: e.index,
            data: e.data,
        }
    }
}

impl From<MsrEntry> for msr_entry {
    fn from(e: MsrEntry) -> Self {
        Self {
            index: e.index,
            data: e.data,
            ..Default::default()
        }
    }
}
