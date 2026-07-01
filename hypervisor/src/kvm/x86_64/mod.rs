// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2020, Microsoft Corporation
//
// Copyright 2018-2019 CrowdStrike, Inc.
//
//

use std::iter;
use std::num::NonZero;

use kvm_ioctls::{MsrFilterRange, MsrFilterRangeFlags};
use log::error;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use vmm_sys_util::fam;
///
/// Export generically-named wrappers of kvm-bindings for Unix-based platforms
///
pub use {
    kvm_bindings::CpuId, kvm_bindings::KVM_CPUID_FLAG_SIGNIFCANT_INDEX, kvm_bindings::MsrList,
    kvm_bindings::Msrs as MsrEntries, kvm_bindings::Xsave as xsave2,
    kvm_bindings::kvm_cpuid_entry2, kvm_bindings::kvm_dtable, kvm_bindings::kvm_fpu,
    kvm_bindings::kvm_lapic_state, kvm_bindings::kvm_mp_state as MpState,
    kvm_bindings::kvm_msr_entry, kvm_bindings::kvm_regs, kvm_bindings::kvm_segment,
    kvm_bindings::kvm_sregs, kvm_bindings::kvm_vcpu_events as VcpuEvents,
    kvm_bindings::kvm_xcrs as ExtendedControlRegisters, kvm_bindings::kvm_xsave,
    kvm_bindings::nested::KvmNestedStateBuffer,
};

use crate::HypervisorVmError;
use crate::arch::x86::{
    CPUID_FLAG_VALID_INDEX, CpuIdEntry, DescriptorTable, FpuState, LapicState, MsrEntry,
    SegmentRegister, SpecialRegisters, XsaveState, msr_filter_helpers,
};
use crate::kvm::{Cap, Kvm, KvmError, KvmResult};

#[cfg(feature = "sev_snp")]
pub(crate) mod sev;

/// The maximum number of MSR filter ranges KVM permits
const MAX_MSR_FILTER_RANGES: NonZero<usize> = NonZero::new(16).unwrap();

/// The maximum size of an individual bitmap used by an MSR filter range.
/// This number is used inernally by KVM to keep bitmap sizes in check. It
/// is unlikely that it will ever be reduced because that would likely
/// break production workloads.
const MAX_MSR_FILTER_RANGE_BITMAP_SIZE: u32 = 0x600;

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
    // Option to prevent useless 8K (de)serialization when no nested
    // state exists.
    pub nested_state: Option<KvmNestedStateBuffer>,
    #[serde(default)]
    pub hyperv_synic: bool,
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

#[derive(Error, Debug)]
pub enum XsaveStateError {
    #[error("kvm_xsave extra field is not empty")]
    XsaveExtraFieldNotEmpty,
}

impl From<kvm_xsave> for XsaveState {
    fn from(value: kvm_xsave) -> Self {
        // Check if kvm_xsave struct size is larger than region size, indicating extra data exists
        assert_eq!(
            size_of_val(&value),
            size_of_val(&value.region),
            "kvm_xsave extra field is not empty"
        );
        Self {
            region: value.region,
            extra: Vec::new(),
        }
    }
}

impl TryFrom<XsaveState> for kvm_xsave {
    type Error = XsaveStateError;
    fn try_from(value: XsaveState) -> Result<Self, Self::Error> {
        if !value.extra.is_empty() {
            error!("XsaveState extra field is not empty");
            return Err(XsaveStateError::XsaveExtraFieldNotEmpty);
        }
        Ok(Self {
            region: value.region,
            extra: Default::default(),
        })
    }
}

impl From<&xsave2> for XsaveState {
    fn from(xsave: &xsave2) -> Self {
        // SAFETY: `xsave` is a valid reference with properly initialized FAM structure.
        let region = unsafe {
            let ptr = xsave.as_fam_struct_ptr();
            (*ptr).xsave.region
        };
        Self {
            region,
            extra: xsave.as_slice().to_vec(),
        }
    }
}

impl XsaveState {
    pub fn to_xsave2(&self) -> Result<xsave2, fam::Error> {
        let mut xsave = xsave2::new(self.extra.len())?;
        // SAFETY: `xsave` was just created via `Xsave::new()` with valid allocated memory.
        unsafe {
            let ptr = xsave.as_mut_fam_struct_ptr();
            (*ptr).xsave.region = self.region;
        }
        let extra_slice = xsave.as_mut_slice();
        extra_slice.copy_from_slice(&self.extra);
        Ok(xsave)
    }
}

/// Attempt to construct up to [`MAX_MSR_FILTER_RANGES`] [`MsrFilterRanges`](MsrFilterRange)
/// that collectively forbid each of the MSRs specified in `denied_msrs`.
///
/// The `bitmap_arena` is expected to be empty when calling this function and is used to
/// store the bitmaps belonging to the returned MSR filter ranges.
/// # Errors
///
/// An error is returned if it is not possible to construct the MSR filter ranges without
/// one of them having a bitmap whose size exceeds [`MAX_MSR_FILTER_RANGE_BITMAP_SIZE`].
pub(crate) fn denied_msrs_to_filter<'a>(
    mut denied_msrs: Vec<u32>,
    bitmap_arena: &'a mut Vec<u8>,
) -> Result<Box<[MsrFilterRange<'a>]>, HypervisorVmError> {
    assert!(
        bitmap_arena.is_empty(),
        "The caller of denied_msrs_to_filter did not provide an empty bitmap arena"
    );

    denied_msrs.sort_unstable();
    denied_msrs.dedup();

    // Note the following quirk: `partition_denied_msrs` assumes a bitmap with
    // 64-bit entries ([u64]) in its calculation of the bitmap size, as does KVM (at least between kernel version 5.10 and 7.0), but we actually
    // want 8-bit entries ([u8]) in our bitmaps. This discrepancy doesn't matter in practice
    // however.
    let partition = msr_filter_helpers::partition_denied_msrs(
        &denied_msrs,
        MAX_MSR_FILTER_RANGES,
        MAX_MSR_FILTER_RANGE_BITMAP_SIZE,
    )?;

    // For each sorted subset s we want a bitmap representing the smallest range covering s.
    let bitmap_arena_size: usize = partition
        .iter()
        .map(|s| ((s.last().unwrap() - s[0]) + 1).div_ceil(8))
        .map(|v| v as usize)
        .sum();

    // Each 0 means that the corresponding MSR is denied, otherwise it is permitted. We
    // start by setting everything as permitted and then make changes as we process our
    // partition.
    bitmap_arena.extend(iter::repeat_n(u8::MAX, bitmap_arena_size));

    let mut out = Vec::with_capacity(partition.len());

    let mut arena_slice = &mut bitmap_arena[..];

    for s in partition {
        let base = s[0];
        let nmsrs = (s.last().unwrap() - base) + 1;
        let (bm, rest) = arena_slice.split_at_mut(nmsrs.div_ceil(8) as usize);
        arena_slice = rest;
        for msr in s {
            // Compute the index in the bitmap corresponding to the MSR and unset it
            let d_base = *msr - base;
            let byte_idx = (d_base) / 8;
            let bit = 1 << (d_base % 8);
            bm[byte_idx as usize] ^= bit;
        }

        let filter_range = MsrFilterRange {
            flags: MsrFilterRangeFlags::READ | MsrFilterRangeFlags::WRITE,
            base,
            msr_count: nmsrs,
            bitmap: bm,
        };
        out.push(filter_range);
    }

    Ok(out.into_boxed_slice())
}

#[cfg(test)]
mod unit_tests {
    use kvm_ioctls::MsrFilterRange;
    use proptest::prelude::*;

    use super::denied_msrs_to_filter;
    use crate::kvm::x86_64::MAX_MSR_FILTER_RANGES;
    /// Sorts and dedups the MSR vector
    fn prepare(mut denied_msrs: Vec<u32>) -> Vec<u32> {
        denied_msrs.sort_unstable();
        denied_msrs.dedup();
        denied_msrs
    }

    // Helper function to convert a filter into the MSRs it covers
    fn filter_to_msrs(filter: &[MsrFilterRange<'_>]) -> Vec<u32> {
        let mut out = Vec::new();
        for filter_range in filter {
            let base = filter_range.base;
            let mut num_msrs: u32 = 0;
            for byte in filter_range.bitmap {
                // We are interested in the bits that are not set
                // because they correspond to the denied MSRs.
                let mut bits = !*byte;
                while bits != 0 {
                    // Position of the lowest set bit
                    let idx = bits.trailing_zeros();
                    if num_msrs + idx > filter_range.msr_count {
                        break;
                    }
                    out.push(base + num_msrs + idx);
                    // Unset the lowest set bit
                    bits &= bits - 1;
                }
                num_msrs += 8;
            }
        }
        out
    }

    proptest! {
        #[test]
        fn denied_to_filter_works_short(prepared_msrs in (prop::collection::vec(0..u32::MAX, 1..MAX_MSR_FILTER_RANGES.get())).prop_map(prepare)) {
            let mut bitmap_arena = Vec::new();
            let filter = denied_msrs_to_filter(prepared_msrs.clone(), &mut bitmap_arena).unwrap();
            let mut recomputed_msrs = filter_to_msrs(&filter);
            recomputed_msrs.sort_unstable();
            prop_assert_eq!(prepared_msrs, recomputed_msrs);
        }
    }

    proptest! {
        #[test]
        fn denied_to_filter_works(prepared_msrs in (prop::collection::vec(0..u32::MAX, (MAX_MSR_FILTER_RANGES.get() + 1)..70)).prop_map(prepare)) {
            let mut bitmap_arena = Vec::new();
            let Ok(filter) = denied_msrs_to_filter(prepared_msrs.clone(), &mut bitmap_arena) else {
                // This means the bitmap required too much size, which can happen
                return Ok(());
            };
            let mut recomputed_msrs = filter_to_msrs(&filter);
            recomputed_msrs.sort_unstable();
            prop_assert_eq!(prepared_msrs, recomputed_msrs);
        }
    }
}
