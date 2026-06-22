// Copyright © 2026 Cloud Hypervisor macOS port
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! KVM ⇄ HVF arm64 vCPU register translation (milestone M3).
//!
//! The dream this port serves is rehydrating a cloud arm64 snapshot — captured
//! under KVM — onto a local Mac under Apple's Hypervisor.framework. A KVM vCPU
//! snapshot is, at the register level, a list of `KVM_REG_ARM64` ONE_REG
//! id/value pairs: a block of *core* registers (`user_pt_regs` + `sp_el1` /
//! `elr_el1` / `spsr`) and a block of *system* registers. HVF instead exposes
//! named core registers plus `hv_sys_reg_t` system registers. This module maps
//! losslessly between the two representations.
//!
//! ## Why the system-register mapping is a clean bijection
//!
//! Both ABIs pack an AArch64 system register's `(op0, op1, crn, crm, op2)`
//! encoding into the low 16 bits identically:
//!
//! ```text
//! enc16 = (op0 << 14) | (op1 << 11) | (crn << 7) | (crm << 3) | op2
//! ```
//!
//! Apple's `hv_sys_reg_t` *is* `enc16` (e.g. `MPIDR_EL1` = 0xc005:
//! op0=3,op2=5), and KVM's `KVM_REG_ARM64_SYSREG` sub-encoding uses the same
//! shifts (`OP0_SHIFT=14, OP1_SHIFT=11, CRN_SHIFT=7, CRM_SHIFT=3, OP2_SHIFT=0`).
//! So a 64-bit KVM system-register id is just
//! `KVM_REG_ARM64 | U64 | KVM_REG_ARM64_SYSREG | enc16`, and translating in
//! either direction is masking / or-ing — no per-register table required.
//!
//! ## Core registers
//!
//! KVM keeps several registers in the core block that HVF surfaces as system
//! registers (`SP_EL0`, `ELR_EL1`, `SPSR_EL1`) or as the dedicated `sp_el1`
//! field. The core-register id is `KVM_REG_ARM64 | U64 | KVM_REG_ARM_CORE |
//! (byte_offset_in_kvm_regs / 4)`; the relevant offsets are enumerated below.
//!
//! ## Scope (honest boundary)
//!
//! This is the register-translation half of KVM→HVF restore and is validated
//! both by golden unit tests on the encodings and by a hardware round-trip of
//! real captured HVF state (see `hvf_kvm_register_translation_roundtrip`). The
//! GIC distributor/redistributor blob translation (KVM VGIC device state ⇄
//! `hv_gic` blob) and ingesting a serialized `VcpuKvmState` via `kvm-bindings`
//! are the remaining M3 work; the per-vCPU GIC CPU-interface (ICC) registers,
//! however, ARE handled here because they share the system-register encoding.

use super::VcpuHvfState;
use super::ffi::{SYSREG_ELR_EL1, SYSREG_SP_EL0, SYSREG_SP_EL1, SYSREG_SPSR_EL1};

// --- KVM AArch64 ONE_REG ABI constants (architectural, stable) -------------

/// `KVM_REG_ARM64` — the AArch64 register-id namespace.
pub const KVM_REG_ARM64: u64 = 0x6000_0000_0000_0000;
/// `KVM_REG_SIZE_U64` — 64-bit register size field (size code 3 << 52).
pub const KVM_REG_SIZE_U64: u64 = 0x0030_0000_0000_0000;
/// `KVM_REG_ARM_CORE` — coprocessor id for the core (`user_pt_regs`) block.
pub const KVM_REG_ARM_CORE: u64 = 0x0010_0000;
/// `KVM_REG_ARM64_SYSREG` — coprocessor id for the system-register block.
pub const KVM_REG_ARM64_SYSREG: u64 = 0x0013_0000;
/// Mask selecting the coprocessor field that distinguishes the two blocks.
pub const KVM_REG_ARM_COPROC_MASK: u64 = 0x0fff_0000;

/// Low 16 bits hold the `(op0,op1,crn,crm,op2)` system-register encoding.
const SYSREG_ENC_MASK: u64 = 0xffff;

// Byte offsets of the core registers inside `struct kvm_regs` (which begins
// with `struct user_pt_regs { u64 regs[31]; u64 sp; u64 pc; u64 pstate; }`,
// followed by `u64 sp_el1; u64 elr_el1; u64 spsr[5]; ...`). The ONE_REG id
// encodes `offset / 4`.
const OFF_REGS0: usize = 0; // regs[0]; regs[i] = OFF_REGS0 + i*8
const OFF_SP_EL0: usize = 31 * 8; // user_pt_regs.sp  -> SP_EL0
const OFF_PC: usize = 32 * 8;
const OFF_PSTATE: usize = 33 * 8; // -> CPSR/PSTATE
const OFF_SP_EL1: usize = 34 * 8;
const OFF_ELR_EL1: usize = 35 * 8;
const OFF_SPSR0: usize = 36 * 8; // spsr[0] -> SPSR_EL1

/// Build the KVM ONE_REG id for a core register at `byte_offset` in `kvm_regs`.
pub const fn kvm_core_reg_id(byte_offset: usize) -> u64 {
    KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE | (byte_offset as u64 / 4)
}

/// Build the 64-bit KVM ONE_REG id for an AArch64 system register given its
/// 16-bit `(op0,op1,crn,crm,op2)` encoding (an `hv_sys_reg_t` value).
pub const fn kvm_sysreg_id(enc16: u16) -> u64 {
    KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM64_SYSREG | enc16 as u64
}

/// Return the HVF `hv_sys_reg_t` (16-bit encoding) for a KVM system-register
/// id, or `None` if `id` is not a 64-bit `KVM_REG_ARM64_SYSREG` entry.
pub fn kvm_sysreg_to_hvf(id: u64) -> Option<u16> {
    let is_arm64 = (id & 0xff00_0000_0000_0000) == KVM_REG_ARM64;
    let is_u64 = (id & KVM_REG_SIZE_U64) == KVM_REG_SIZE_U64;
    let is_sysreg = (id & KVM_REG_ARM_COPROC_MASK) == KVM_REG_ARM64_SYSREG;
    if is_arm64 && is_u64 && is_sysreg {
        Some((id & SYSREG_ENC_MASK) as u16)
    } else {
        None
    }
}

/// The KVM register-level snapshot of a single AArch64 vCPU, split into the
/// core block, the system-register block, and the per-vCPU GIC CPU-interface
/// (ICC) system registers (which KVM saves via the VGIC device but which share
/// the ordinary system-register encoding).
///
/// Each entry is a `(KVM ONE_REG id, value)` pair — the lossless, ABI-stable
/// form a serialized KVM snapshot carries.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KvmArm64VcpuRegs {
    pub core: Vec<(u64, u64)>,
    pub sys: Vec<(u64, u64)>,
    pub gic_icc: Vec<(u64, u64)>,
}

impl KvmArm64VcpuRegs {
    fn core_value(&self, id: u64) -> Option<u64> {
        self.core.iter().find(|(i, _)| *i == id).map(|(_, v)| *v)
    }
}

/// HVF system registers that KVM stores in the *core* block instead, so they
/// must be lowered to / raised from core-register ids rather than sysreg ids.
const HVF_SYSREGS_THAT_ARE_KVM_CORE: &[u16] = &[
    SYSREG_SP_EL0,  // KVM user_pt_regs.sp
    SYSREG_ELR_EL1, // KVM kvm_regs.elr_el1
    SYSREG_SPSR_EL1, // KVM kvm_regs.spsr[0]
    SYSREG_SP_EL1,  // KVM kvm_regs.sp_el1 (also the VcpuHvfState.sp_el1 field)
];

/// Lower a captured HVF vCPU state to its KVM ONE_REG representation.
///
/// This is the direction a Mac would use to *produce* a KVM-shaped snapshot
/// (and the inverse the round-trip test exercises). GPRs, PC and PSTATE map to
/// the KVM core block; `sp_el1` and the three HVF system registers KVM keeps as
/// core registers (`SP_EL0`, `ELR_EL1`, `SPSR_EL1`) map to their core ids; all
/// remaining HVF system registers and the ICC registers map by the shared
/// 16-bit encoding.
pub fn lower_to_kvm(hvf: &VcpuHvfState) -> KvmArm64VcpuRegs {
    let mut core = Vec::with_capacity(31 + 6);
    for (i, &v) in hvf.gpr.iter().enumerate() {
        core.push((kvm_core_reg_id(OFF_REGS0 + i * 8), v));
    }
    core.push((kvm_core_reg_id(OFF_PC), hvf.pc));
    core.push((kvm_core_reg_id(OFF_PSTATE), hvf.cpsr));
    core.push((kvm_core_reg_id(OFF_SP_EL1), hvf.sp_el1));

    // The three HVF system registers KVM keeps in the core block.
    if let Some(v) = sysreg_value(hvf, SYSREG_SP_EL0) {
        core.push((kvm_core_reg_id(OFF_SP_EL0), v));
    }
    if let Some(v) = sysreg_value(hvf, SYSREG_ELR_EL1) {
        core.push((kvm_core_reg_id(OFF_ELR_EL1), v));
    }
    if let Some(v) = sysreg_value(hvf, SYSREG_SPSR_EL1) {
        core.push((kvm_core_reg_id(OFF_SPSR0), v));
    }

    let sys = hvf
        .sysregs
        .iter()
        .filter(|(id, _)| !HVF_SYSREGS_THAT_ARE_KVM_CORE.contains(id))
        .map(|&(id, v)| (kvm_sysreg_id(id), v))
        .collect();

    let gic_icc = hvf
        .gic_icc
        .iter()
        .map(|&(id, v)| (kvm_sysreg_id(id), v))
        .collect();

    KvmArm64VcpuRegs { core, sys, gic_icc }
}

/// Raise a KVM ONE_REG vCPU snapshot into an HVF `VcpuHvfState`, ready for
/// `Vcpu::set_state`. This is the load-bearing direction for the dream:
/// rehydrating a cloud KVM snapshot on a Mac. System and ICC registers map by
/// the shared encoding; the HVF system registers KVM keeps as core registers
/// are reconstructed from the core block so the resulting `sysregs` list is the
/// exact inverse of `lower_to_kvm`.
pub fn raise_from_kvm(kvm: &KvmArm64VcpuRegs) -> VcpuHvfState {
    let mut gpr = [0u64; 31];
    for (i, slot) in gpr.iter_mut().enumerate() {
        if let Some(v) = kvm.core_value(kvm_core_reg_id(OFF_REGS0 + i * 8)) {
            *slot = v;
        }
    }
    let pc = kvm.core_value(kvm_core_reg_id(OFF_PC)).unwrap_or(0);
    let cpsr = kvm.core_value(kvm_core_reg_id(OFF_PSTATE)).unwrap_or(0);
    let sp_el1 = kvm.core_value(kvm_core_reg_id(OFF_SP_EL1)).unwrap_or(0);

    let mut sysregs: Vec<(u16, u64)> = kvm
        .sys
        .iter()
        .filter_map(|&(id, v)| kvm_sysreg_to_hvf(id).map(|enc| (enc, v)))
        .collect();

    // Reconstruct the HVF system registers KVM kept in the core block.
    if let Some(v) = kvm.core_value(kvm_core_reg_id(OFF_SP_EL0)) {
        sysregs.push((SYSREG_SP_EL0, v));
    }
    if let Some(v) = kvm.core_value(kvm_core_reg_id(OFF_ELR_EL1)) {
        sysregs.push((SYSREG_ELR_EL1, v));
    }
    if let Some(v) = kvm.core_value(kvm_core_reg_id(OFF_SPSR0)) {
        sysregs.push((SYSREG_SPSR_EL1, v));
    }
    // VcpuHvfState carries SP_EL1 both as a field and in `sysregs`; mirror that.
    sysregs.push((SYSREG_SP_EL1, sp_el1));

    let gic_icc = kvm
        .gic_icc
        .iter()
        .filter_map(|&(id, v)| kvm_sysreg_to_hvf(id).map(|enc| (enc, v)))
        .collect();

    VcpuHvfState {
        gpr,
        pc,
        cpsr,
        sp_el1,
        sysregs,
        gic_icc,
        mp_state_running: true,
    }
}

fn sysreg_value(hvf: &VcpuHvfState, enc: u16) -> Option<u64> {
    hvf.sysregs
        .iter()
        .find(|(id, _)| *id == enc)
        .map(|(_, v)| *v)
}

/// Ingest a *real* serialized KVM arm64 vCPU snapshot — cloud-hypervisor's
/// `kvm-bindings` ABI types — into the architectural `KvmArm64VcpuRegs` this
/// module translates. This is the front door of the dream: a cloud snapshot is
/// deserialized into these `kvm-bindings` structs, fed through here, then
/// `raise_from_kvm` produces a `VcpuHvfState` ready for HVF restore.
///
/// Gated behind `kvm-snapshot` so macOS pulls in only the pure-`kvm-bindings`
/// type definitions (no `kvm-ioctls`, no VFIO).
#[cfg(feature = "kvm-snapshot")]
pub mod kvm_ingest {
    use super::*;
    use kvm_bindings::{kvm_one_reg, kvm_regs};

    /// Lower a serialized KVM `kvm_regs` core block plus the system-register
    /// ONE_REG list (each `kvm_one_reg`'s `addr` carries the 64-bit value, as
    /// cloud-hypervisor's `VcpuKvmState` stores it) into `KvmArm64VcpuRegs`.
    ///
    /// `core_regs` is the structured C struct; we re-emit its fields as the
    /// ONE_REG `(id, value)` pairs `raise_from_kvm` consumes so a single code
    /// path handles both synthetic and real input. The per-vCPU GIC CPU
    /// interface (ICC) registers are intentionally NOT sourced here: in a real
    /// KVM snapshot they live in the VGIC device state, not the vCPU ONE_REG
    /// list, so they are supplied by the (still-open) GIC-state translation.
    pub fn from_kvm(core_regs: &kvm_regs, sys_regs: &[kvm_one_reg]) -> KvmArm64VcpuRegs {
        let mut core = Vec::with_capacity(31 + 6);
        for (i, &v) in core_regs.regs.regs.iter().enumerate() {
            core.push((kvm_core_reg_id(OFF_REGS0 + i * 8), v));
        }
        core.push((kvm_core_reg_id(OFF_SP_EL0), core_regs.regs.sp));
        core.push((kvm_core_reg_id(OFF_PC), core_regs.regs.pc));
        core.push((kvm_core_reg_id(OFF_PSTATE), core_regs.regs.pstate));
        core.push((kvm_core_reg_id(OFF_SP_EL1), core_regs.sp_el1));
        core.push((kvm_core_reg_id(OFF_ELR_EL1), core_regs.elr_el1));
        core.push((kvm_core_reg_id(OFF_SPSR0), core_regs.spsr[0]));

        // Keep only genuine 64-bit system registers; the value is in `addr`.
        let sys = sys_regs
            .iter()
            .filter_map(|r| kvm_sysreg_to_hvf(r.id).map(|_| (r.id, r.addr)))
            .collect();

        KvmArm64VcpuRegs {
            core,
            sys,
            gic_icc: Vec::new(),
        }
    }

    /// Convenience: ingest a serialized KVM vCPU snapshot and translate it the
    /// rest of the way to an HVF `VcpuHvfState` ready for `Vcpu::set_state`.
    pub fn kvm_to_hvf(core_regs: &kvm_regs, sys_regs: &[kvm_one_reg]) -> VcpuHvfState {
        raise_from_kvm(&from_kvm(core_regs, sys_regs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    // hv_sys_reg_t values for a representative spread of EL1 system registers.
    const MPIDR_EL1: u16 = 0xc005;
    const SCTLR_EL1: u16 = 0xc080;
    const TTBR0_EL1: u16 = 0xc100;
    const VBAR_EL1: u16 = 0xc600;
    const ICC_PMR_EL1: u16 = 0xc230;

    #[test]
    fn sysreg_encoding_is_a_bijection() {
        // Golden encodings, derived independently from (op0,op1,crn,crm,op2):
        //   MPIDR_EL1  = op0 3, op1 0, crn 0, crm 0, op2 5  -> 0xc005
        //   SCTLR_EL1  = op0 3, op1 0, crn 1, crm 0, op2 0  -> 0xc080
        //   TTBR0_EL1  = op0 3, op1 0, crn 2, crm 0, op2 0  -> 0xc100
        //   VBAR_EL1   = op0 3, op1 0, crn 12, crm 0, op2 0 -> 0xc600
        //   ICC_PMR_EL1= op0 3, op1 0, crn 4, crm 6, op2 0  -> 0xc230
        for enc in [MPIDR_EL1, SCTLR_EL1, TTBR0_EL1, VBAR_EL1, ICC_PMR_EL1] {
            let id = kvm_sysreg_id(enc);
            assert_eq!(
                kvm_sysreg_to_hvf(id),
                Some(enc),
                "round-trip failed for enc {enc:#06x} (id {id:#018x})"
            );
            // The id must carry the ARM64 + U64 + SYSREG markers and the
            // encoding in its low 16 bits.
            assert_eq!(id & 0xff00_0000_0000_0000, KVM_REG_ARM64);
            assert_eq!(id & KVM_REG_SIZE_U64, KVM_REG_SIZE_U64);
            assert_eq!(id & KVM_REG_ARM_COPROC_MASK, KVM_REG_ARM64_SYSREG);
            assert_eq!(id & 0xffff, enc as u64);
        }
    }

    #[test]
    fn core_register_ids_match_kvm_abi() {
        // KVM core ids are KVM_REG_ARM64 | U64 | KVM_REG_ARM_CORE | (off/4).
        // regs[0] @0, regs[1] @8, PC @256, PSTATE @264, SP_EL1 @272.
        let base = KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE;
        assert_eq!(kvm_core_reg_id(0), base);
        assert_eq!(kvm_core_reg_id(8), base | 2);
        assert_eq!(kvm_core_reg_id(OFF_PC), base | 64);
        assert_eq!(kvm_core_reg_id(OFF_PSTATE), base | 66);
        assert_eq!(kvm_core_reg_id(OFF_SP_EL0), base | 62);
        assert_eq!(kvm_core_reg_id(OFF_SP_EL1), base | 68);
        assert_eq!(kvm_core_reg_id(OFF_ELR_EL1), base | 70);
        assert_eq!(kvm_core_reg_id(OFF_SPSR0), base | 72);
    }

    fn sorted(v: &[(u16, u64)]) -> BTreeMap<u16, u64> {
        v.iter().copied().collect()
    }

    #[test]
    fn lower_then_raise_is_identity() {
        // A representative HVF state: distinct GPRs, the load-bearing core
        // fields, the SNAPSHOT system registers (including the three KVM keeps
        // as core regs), and a couple of ICC registers.
        let mut sysregs = vec![
            (MPIDR_EL1, 0x8000_0000u64),
            (SCTLR_EL1, 0x30d0_0980),
            (TTBR0_EL1, 0x4000_1000),
            (VBAR_EL1, 0x4000_1000),
            (SYSREG_SP_EL0, 0xdead_0000),
            (SYSREG_ELR_EL1, 0x4000_2000),
            (SYSREG_SPSR_EL1, 0x3c5),
            (SYSREG_SP_EL1, 0x4000_8000),
        ];
        sysregs.sort_by_key(|(id, _)| *id);
        let mut gpr = [0u64; 31];
        for (i, slot) in gpr.iter_mut().enumerate() {
            *slot = 0x1000 + i as u64;
        }
        let original = VcpuHvfState {
            gpr,
            pc: 0x4000_0000,
            cpsr: 0x3c5,
            sp_el1: 0x4000_8000,
            sysregs,
            gic_icc: vec![(ICC_PMR_EL1, 0xf0), (0xc667, 0x1)], // PMR, IGRPEN1
            mp_state_running: true,
        };

        let kvm = lower_to_kvm(&original);
        let restored = raise_from_kvm(&kvm);

        assert_eq!(restored.gpr, original.gpr, "GPRs must round-trip");
        assert_eq!(restored.pc, original.pc);
        assert_eq!(restored.cpsr, original.cpsr);
        assert_eq!(restored.sp_el1, original.sp_el1);
        assert_eq!(
            sorted(&restored.sysregs),
            sorted(&original.sysregs),
            "system registers must round-trip as a set"
        );
        assert_eq!(
            sorted(&restored.gic_icc),
            sorted(&original.gic_icc),
            "GIC ICC registers must round-trip"
        );
    }

    #[test]
    fn lower_routes_core_vs_sysreg_blocks_correctly() {        let hvf = VcpuHvfState {
            gpr: [7u64; 31],
            pc: 0xabc,
            cpsr: 0x3c5,
            sp_el1: 0x5000,
            sysregs: vec![
                (SCTLR_EL1, 0x1),
                (SYSREG_SP_EL0, 0x2),
                (SYSREG_ELR_EL1, 0x3),
                (SYSREG_SPSR_EL1, 0x4),
                (SYSREG_SP_EL1, 0x5000),
            ],
            gic_icc: vec![],
            mp_state_running: true,
        };
        let kvm = lower_to_kvm(&hvf);

        // SCTLR stays in the system block...
        assert!(kvm.sys.iter().any(|&(id, v)| id == kvm_sysreg_id(SCTLR_EL1) && v == 0x1));
        // ...while SP_EL0/ELR_EL1/SPSR_EL1/SP_EL1 are emitted as core regs only.
        for enc in HVF_SYSREGS_THAT_ARE_KVM_CORE {
            assert!(
                !kvm.sys.iter().any(|&(id, _)| id == kvm_sysreg_id(*enc)),
                "enc {enc:#06x} must not appear in the KVM system block"
            );
        }
        assert!(kvm.core.iter().any(|&(id, v)| id == kvm_core_reg_id(OFF_SP_EL0) && v == 0x2));
        assert!(kvm.core.iter().any(|&(id, v)| id == kvm_core_reg_id(OFF_ELR_EL1) && v == 0x3));
        assert!(kvm.core.iter().any(|&(id, v)| id == kvm_core_reg_id(OFF_SPSR0) && v == 0x4));
        assert!(kvm.core.iter().any(|&(id, v)| id == kvm_core_reg_id(OFF_SP_EL1) && v == 0x5000));
    }

    /// Ingest a real `kvm-bindings` core block + sysreg ONE_REG list and confirm
    /// every load-bearing register lands where HVF restore expects it.
    #[cfg(feature = "kvm-snapshot")]
    #[test]
    fn ingest_real_kvm_bindings_snapshot() {
        use super::kvm_ingest::kvm_to_hvf;
        use kvm_bindings::{kvm_one_reg, kvm_regs, user_pt_regs};

        let mut regs = [0u64; 31];
        for (i, slot) in regs.iter_mut().enumerate() {
            *slot = 0x2000 + i as u64;
        }
        let mut spsr = [0u64; 5];
        spsr[0] = 0x3c5;
        let core_regs = kvm_regs {
            regs: user_pt_regs {
                regs,
                sp: 0xdead_0000,   // -> SP_EL0
                pc: 0x4000_0000,
                pstate: 0x3c5,
            },
            sp_el1: 0x4000_8000,
            elr_el1: 0x4000_2000,
            spsr,
            ..Default::default()
        };
        let sys_regs = vec![
            kvm_one_reg {
                id: kvm_sysreg_id(MPIDR_EL1),
                addr: 0x8000_0000,
            },
            kvm_one_reg {
                id: kvm_sysreg_id(SCTLR_EL1),
                addr: 0x30d0_0980,
            },
            kvm_one_reg {
                id: kvm_sysreg_id(VBAR_EL1),
                addr: 0x4000_1000,
            },
        ];

        let hvf = kvm_to_hvf(&core_regs, &sys_regs);

        // GPRs and the structured core fields.
        for (i, &v) in regs.iter().enumerate() {
            assert_eq!(hvf.gpr[i], v, "GPR x{i} mismatch");
        }
        assert_eq!(hvf.pc, 0x4000_0000);
        assert_eq!(hvf.cpsr, 0x3c5);
        assert_eq!(hvf.sp_el1, 0x4000_8000);

        // EL1 system registers come across by the shared encoding.
        let sys = sorted(&hvf.sysregs);
        assert_eq!(sys.get(&MPIDR_EL1), Some(&0x8000_0000));
        assert_eq!(sys.get(&SCTLR_EL1), Some(&0x30d0_0980));
        assert_eq!(sys.get(&VBAR_EL1), Some(&0x4000_1000));
        // The registers KVM keeps in its core block are reconstructed as HVF
        // system registers from `kvm_regs`, not from the sysreg list.
        assert_eq!(sys.get(&SYSREG_SP_EL0), Some(&0xdead_0000));
        assert_eq!(sys.get(&SYSREG_ELR_EL1), Some(&0x4000_2000));
        assert_eq!(sys.get(&SYSREG_SPSR_EL1), Some(&0x3c5));
        assert_eq!(sys.get(&SYSREG_SP_EL1), Some(&0x4000_8000));
    }
}
