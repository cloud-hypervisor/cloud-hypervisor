// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2020, Microsoft Corporation
//
// Copyright 2018-2019 CrowdStrike, Inc.
//
//

use serde::{Deserialize, Serialize};
///
/// Export generically-named wrappers of kvm-bindings for Unix-based platforms
///
pub use {
    kvm_bindings::CpuId, kvm_bindings::KVM_CPUID_FLAG_SIGNIFCANT_INDEX, kvm_bindings::MsrList,
    kvm_bindings::Msrs as MsrEntries, kvm_bindings::kvm_cpuid_entry2, kvm_bindings::kvm_dtable,
    kvm_bindings::kvm_fpu, kvm_bindings::kvm_lapic_state, kvm_bindings::kvm_mp_state as MpState,
    kvm_bindings::kvm_msr_entry, kvm_bindings::kvm_regs, kvm_bindings::kvm_segment,
    kvm_bindings::kvm_sregs, kvm_bindings::kvm_vcpu_events as VcpuEvents,
    kvm_bindings::kvm_xcrs as ExtendedControlRegisters, kvm_bindings::kvm_xsave,
};

use crate::arch::x86::{
    CPUID_FLAG_VALID_INDEX, CpuIdEntry, DescriptorTable, FpuState, LapicState, MsrEntry,
    SegmentRegister, SpecialRegisters, XsaveState,
};
use crate::kvm::{Cap, Kvm, KvmError, KvmResult};

///
/// Check KVM extension for Linux
///
pub fn check_required_kvm_extensions(kvm: &Kvm) -> KvmResult<()> {
    macro_rules! check_extension {
        ($cap:expr) => {
            if !kvm.check_extension($cap) {
                return Err(KvmError::CapabilityMissing($cap));
            }
        };
    }

    // DeviceCtrl, EnableCap, and SetGuestDebug are also required, but some kernels have
    // the features implemented without the capability flags.
    check_extension!(Cap::AdjustClock);
    check_extension!(Cap::ExtCpuid);
    check_extension!(Cap::GetTscKhz);
    check_extension!(Cap::ImmediateExit);
    check_extension!(Cap::Ioeventfd);
    check_extension!(Cap::Irqchip);
    check_extension!(Cap::Irqfd);
    check_extension!(Cap::IrqRouting);
    check_extension!(Cap::MpState);
    check_extension!(Cap::SetIdentityMapAddr);
    check_extension!(Cap::SetTssAddr);
    check_extension!(Cap::SplitIrqchip);
    check_extension!(Cap::TscDeadlineTimer);
    check_extension!(Cap::UserMemory);
    check_extension!(Cap::UserNmi);
    check_extension!(Cap::VcpuEvents);
    check_extension!(Cap::Xcrs);
    check_extension!(Cap::Xsave);
    Ok(())
}

#[derive(Clone, Serialize, Deserialize)]
pub struct VcpuKvmState {
    pub cpuid: Vec<CpuIdEntry>,
    pub msrs: Vec<MsrEntry>,
    pub vcpu_events: VcpuEvents,
    pub regs: kvm_regs,
    pub sregs: kvm_sregs,
    pub fpu: FpuState,
    pub lapic_state: LapicState,
    pub xsave: XsaveState,
    pub xcrs: ExtendedControlRegisters,
    pub mp_state: MpState,
    pub tsc_khz: Option<u32>,
}

impl From<SegmentRegister> for kvm_segment {
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

impl From<kvm_segment> for SegmentRegister {
    fn from(s: kvm_segment) -> Self {
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

impl From<DescriptorTable> for kvm_dtable {
    fn from(dt: DescriptorTable) -> Self {
        Self {
            base: dt.base,
            limit: dt.limit,
            ..Default::default()
        }
    }
}

impl From<kvm_dtable> for DescriptorTable {
    fn from(dt: kvm_dtable) -> Self {
        Self {
            base: dt.base,
            limit: dt.limit,
        }
    }
}

impl From<SpecialRegisters> for kvm_sregs {
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

impl From<kvm_sregs> for SpecialRegisters {
    fn from(s: kvm_sregs) -> Self {
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

impl From<CpuIdEntry> for kvm_cpuid_entry2 {
    fn from(e: CpuIdEntry) -> Self {
        let flags = if e.flags & CPUID_FLAG_VALID_INDEX != 0 {
            KVM_CPUID_FLAG_SIGNIFCANT_INDEX
        } else {
            0
        };
        Self {
            function: e.function,
            index: e.index,
            flags,
            eax: e.eax,
            ebx: e.ebx,
            ecx: e.ecx,
            edx: e.edx,
            ..Default::default()
        }
    }
}

impl From<kvm_cpuid_entry2> for CpuIdEntry {
    fn from(e: kvm_cpuid_entry2) -> Self {
        let flags = if e.flags & KVM_CPUID_FLAG_SIGNIFCANT_INDEX != 0 {
            CPUID_FLAG_VALID_INDEX
        } else {
            0
        };
        Self {
            function: e.function,
            index: e.index,
            flags,
            eax: e.eax,
            ebx: e.ebx,
            ecx: e.ecx,
            edx: e.edx,
        }
    }
}

impl From<kvm_fpu> for FpuState {
    fn from(s: kvm_fpu) -> Self {
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

impl From<FpuState> for kvm_fpu {
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

impl From<LapicState> for kvm_lapic_state {
    fn from(s: LapicState) -> Self {
        Self { regs: s.regs }
    }
}

impl From<kvm_lapic_state> for LapicState {
    fn from(s: kvm_lapic_state) -> Self {
        Self { regs: s.regs }
    }
}

impl From<kvm_msr_entry> for MsrEntry {
    fn from(e: kvm_msr_entry) -> Self {
        Self {
            index: e.index,
            data: e.data,
        }
    }
}

impl From<MsrEntry> for kvm_msr_entry {
    fn from(e: MsrEntry) -> Self {
        Self {
            index: e.index,
            data: e.data,
            ..Default::default()
        }
    }
}

impl From<kvm_xsave> for XsaveState {
    fn from(s: kvm_xsave) -> Self {
        Self { region: s.region }
    }
}

impl From<XsaveState> for kvm_xsave {
    fn from(s: XsaveState) -> Self {
        Self {
            region: s.region,
            extra: Default::default(),
        }
    }
}
