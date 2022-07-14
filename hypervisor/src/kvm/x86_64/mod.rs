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
use crate::kvm::{Cap, Kvm, KvmError, KvmResult};
use serde::{Deserialize, Serialize};

///
/// Export generically-named wrappers of kvm-bindings for Unix-based platforms
///
pub use {
    kvm_bindings::kvm_cpuid_entry2 as CpuIdEntry, kvm_bindings::kvm_dtable as DescriptorTable,
    kvm_bindings::kvm_fpu as FpuState, kvm_bindings::kvm_lapic_state as LapicState,
    kvm_bindings::kvm_mp_state as MpState, kvm_bindings::kvm_msr_entry as MsrEntry,
    kvm_bindings::kvm_regs, kvm_bindings::kvm_segment as SegmentRegister,
    kvm_bindings::kvm_sregs as SpecialRegisters, kvm_bindings::kvm_vcpu_events as VcpuEvents,
    kvm_bindings::kvm_xcrs as ExtendedControlRegisters, kvm_bindings::kvm_xsave as Xsave,
    kvm_bindings::CpuId, kvm_bindings::MsrList, kvm_bindings::Msrs as MsrEntries,
    kvm_bindings::KVM_CPUID_FLAG_SIGNIFCANT_INDEX as CPUID_FLAG_VALID_INDEX,
};

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

///
/// Check KVM extension for Linux
///
pub fn check_required_kvm_extensions(kvm: &Kvm) -> KvmResult<()> {
    if !kvm.check_extension(Cap::SignalMsi) {
        return Err(KvmError::CapabilityMissing(Cap::SignalMsi));
    }
    if !kvm.check_extension(Cap::TscDeadlineTimer) {
        return Err(KvmError::CapabilityMissing(Cap::TscDeadlineTimer));
    }
    if !kvm.check_extension(Cap::SplitIrqchip) {
        return Err(KvmError::CapabilityMissing(Cap::SplitIrqchip));
    }
    if !kvm.check_extension(Cap::SetIdentityMapAddr) {
        return Err(KvmError::CapabilityMissing(Cap::SetIdentityMapAddr));
    }
    if !kvm.check_extension(Cap::SetTssAddr) {
        return Err(KvmError::CapabilityMissing(Cap::SetTssAddr));
    }
    if !kvm.check_extension(Cap::ImmediateExit) {
        return Err(KvmError::CapabilityMissing(Cap::ImmediateExit));
    }
    Ok(())
}
#[derive(Clone, Serialize, Deserialize)]
pub struct VcpuKvmState {
    pub cpuid: CpuId,
    pub msrs: MsrEntries,
    pub vcpu_events: VcpuEvents,
    pub regs: kvm_regs,
    pub sregs: SpecialRegisters,
    pub fpu: FpuState,
    pub lapic_state: LapicState,
    pub xsave: Xsave,
    pub xcrs: ExtendedControlRegisters,
    pub mp_state: MpState,
}

impl From<StandardRegisters> for kvm_regs {
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

impl From<kvm_regs> for StandardRegisters {
    fn from(regs: kvm_regs) -> Self {
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
