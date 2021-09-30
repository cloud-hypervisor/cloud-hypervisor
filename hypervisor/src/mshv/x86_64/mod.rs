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
use serde_derive::{Deserialize, Serialize};
use std::fmt;

///
/// Export generically-named wrappers of mshv_bindings for Unix-based platforms
///
pub use {
    mshv_bindings::mshv_user_mem_region as MemoryRegion, mshv_bindings::msr_entry as MsrEntry,
    mshv_bindings::CpuId, mshv_bindings::DebugRegisters,
    mshv_bindings::FloatingPointUnit as FpuState, mshv_bindings::LapicState,
    mshv_bindings::MiscRegs as MiscRegisters, mshv_bindings::MsrList,
    mshv_bindings::Msrs as MsrEntries, mshv_bindings::Msrs, mshv_bindings::SegmentRegister,
    mshv_bindings::SpecialRegisters, mshv_bindings::StandardRegisters,
    mshv_bindings::SuspendRegisters, mshv_bindings::VcpuEvents, mshv_bindings::XSave as Xsave,
    mshv_bindings::Xcrs as ExtendedControlRegisters,
};

#[derive(Clone, Serialize, Deserialize)]
pub struct VcpuMshvState {
    pub msrs: MsrEntries,
    pub vcpu_events: VcpuEvents,
    pub regs: StandardRegisters,
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
