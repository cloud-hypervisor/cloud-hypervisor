// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2020, Microsoft Corporation
//
// Copyright 2018-2019 CrowdStrike, Inc.
//
//

use crate::arch::x86::{msr_index, MTRR_ENABLE, MTRR_MEM_TYPE_WB};
use crate::generic_x86_64;
use crate::kvm::{Cap, Kvm, KvmError, KvmResult};
use serde::{Deserialize, Serialize};

///
/// Export generically-named wrappers of kvm-bindings for Unix-based platforms
///
pub use {
    kvm_bindings::kvm_cpuid_entry2, kvm_bindings::kvm_dtable, kvm_bindings::kvm_fpu,
    kvm_bindings::kvm_lapic_state as LapicState, kvm_bindings::kvm_mp_state as MpState,
    kvm_bindings::kvm_msr_entry as MsrEntry, kvm_bindings::kvm_regs, kvm_bindings::kvm_segment,
    kvm_bindings::kvm_sregs, kvm_bindings::kvm_vcpu_events as VcpuEvents,
    kvm_bindings::kvm_xsave as Xsave,
    kvm_bindings::CpuId, kvm_bindings::MsrList, kvm_bindings::Msrs as MsrEntries,
};

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
        msr_data!(
            msr_index::MSR_IA32_MISC_ENABLE,
            msr_index::MSR_IA32_MISC_ENABLE_FAST_STRING as u64
        ),
        msr_data!(msr_index::MSR_MTRRdefType, MTRR_ENABLE | MTRR_MEM_TYPE_WB),
    ])
    .unwrap()
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
    pub cpuid: generic_x86_64::CpuId,
    pub msrs: MsrEntries,
    pub vcpu_events: VcpuEvents,
    pub regs: generic_x86_64::StandardRegisters,
    pub sregs: generic_x86_64::SpecialRegisters,
    pub fpu: generic_x86_64::FpuState,
    pub lapic_state: LapicState,
    pub xsave: Xsave,
    pub mp_state: MpState,
}

impl From<kvm_cpuid_entry2> for generic_x86_64::CpuIdEntry {
    fn from(entry: kvm_cpuid_entry2) -> Self {
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

impl From<generic_x86_64::CpuIdEntry> for kvm_cpuid_entry2 {
    fn from(entry: generic_x86_64::CpuIdEntry) -> Self {
        kvm_cpuid_entry2 {
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
    let cpuid_vector: Vec<kvm_cpuid_entry2> =
        cpuid.as_slice().iter().map(|&entry| entry.into()).collect();
    CpuId::from_entries(&cpuid_vector).unwrap()
}

impl From<&kvm_regs> for generic_x86_64::StandardRegisters {
    fn from(regs: &kvm_regs) -> Self {
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

impl From<&generic_x86_64::StandardRegisters> for kvm_regs {
    fn from(regs: &generic_x86_64::StandardRegisters) -> Self {
        kvm_regs {
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

impl From<&kvm_segment> for generic_x86_64::SegmentRegister {
    fn from(seg: &kvm_segment) -> Self {
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

impl From<&generic_x86_64::SegmentRegister> for kvm_segment {
    fn from(seg: &generic_x86_64::SegmentRegister) -> Self {
        kvm_segment {
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

impl From<&kvm_dtable> for generic_x86_64::TableRegister {
    fn from(table: &kvm_dtable) -> Self {
        generic_x86_64::TableRegister {
            base: table.base,
            limit: table.limit,
        }
    }
}

impl From<&generic_x86_64::TableRegister> for kvm_dtable {
    fn from(table: &generic_x86_64::TableRegister) -> Self {
        kvm_dtable {
            base: table.base,
            limit: table.limit,
            padding: [0; 3],
        }
    }
}

impl From<&kvm_sregs> for generic_x86_64::SpecialRegisters {
    fn from(sregs: &kvm_sregs) -> Self {
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

impl From<&generic_x86_64::SpecialRegisters> for kvm_sregs {
    fn from(sregs: &generic_x86_64::SpecialRegisters) -> Self {
        kvm_sregs {
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

impl From<&kvm_fpu> for generic_x86_64::FpuState {
    fn from(fpu: &kvm_fpu) -> Self {
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

impl From<&generic_x86_64::FpuState> for kvm_fpu {
    fn from(fpu: &generic_x86_64::FpuState) -> Self {
        kvm_fpu {
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