// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2020, Microsoft Corporation
//
// Copyright 2018-2019 CrowdStrike, Inc.
//
//

pub mod gic;

use kvm_bindings::{
    KVM_REG_ARM_COPROC_MASK, KVM_REG_ARM_CORE, KVM_REG_SIZE_MASK, KVM_REG_SIZE_U32,
    KVM_REG_SIZE_U64, KVM_REG_SIZE_U128, KVM_REG_SIZE_U256, KVM_REG_SIZE_U512, KVM_REG_SIZE_U1024,
    KVM_REG_SIZE_U2048, kvm_mp_state, kvm_one_reg, kvm_regs,
};
pub use kvm_ioctls::{Cap, Kvm};
use serde::{Deserialize, Serialize};

use crate::kvm::{KvmError, KvmResult};

// Following are macros that help with getting the ID of a aarch64 core register.
// The core register are represented by the user_pt_regs structure. Look for it in
// arch/arm64/include/uapi/asm/ptrace.h.

// Get the ID of a core register
#[macro_export]
macro_rules! arm64_core_reg_id {
    ($size: tt, $offset: tt) => {
        // The core registers of an arm64 machine are represented
        // in kernel by the `kvm_regs` structure. This structure is a
        // mix of 32, 64 and 128 bit fields:
        // struct kvm_regs {
        //     struct user_pt_regs      regs;
        //
        //     __u64                    sp_el1;
        //     __u64                    elr_el1;
        //
        //     __u64                    spsr[KVM_NR_SPSR];
        //
        //     struct user_fpsimd_state fp_regs;
        // };
        // struct user_pt_regs {
        //     __u64 regs[31];
        //     __u64 sp;
        //     __u64 pc;
        //     __u64 pstate;
        // };
        // The id of a core register can be obtained like this:
        // offset = id & ~(KVM_REG_ARCH_MASK | KVM_REG_SIZE_MASK | KVM_REG_ARM_CORE). Thus,
        // id = KVM_REG_ARM64 | KVM_REG_SIZE_U64/KVM_REG_SIZE_U32/KVM_REG_SIZE_U128 | KVM_REG_ARM_CORE | offset
        KVM_REG_ARM64 as u64
            | u64::from(KVM_REG_ARM_CORE)
            | $size
            | (($offset / mem::size_of::<u32>()) as u64)
    };
}

/// Specifies whether a particular register is a system register or not.
///
/// The kernel splits the registers on aarch64 in core registers and system registers.
/// So, below we get the system registers by checking that they are not core registers.
///
/// # Arguments
///
/// * `regid` - The index of the register we are checking.
/// Classifies a register id from `KVM_GET_REG_LIST` as a "system register"
/// for the purposes of snapshot/restore, i.e. a register that fits in a
/// single `u64` and is saved/restored via `VcpuKvmState::sys_regs`.
///
/// Core registers (aarch64 `KVM_REG_ARM_CORE`) are handled separately, and
/// so are SVE registers wider than 64 bits; see [`is_wide_register`].
///
/// Panics on register sizes we do not recognise at all, so that a future
/// kernel introducing a new register size is loud rather than silently
/// dropped from the snapshot.
pub fn is_system_register(regid: u64) -> bool {
    if (regid & KVM_REG_ARM_COPROC_MASK as u64) == KVM_REG_ARM_CORE as u64 {
        return false;
    }

    let size = regid & KVM_REG_SIZE_MASK;
    match size {
        KVM_REG_SIZE_U32 | KVM_REG_SIZE_U64 => true,
        KVM_REG_SIZE_U128 | KVM_REG_SIZE_U256 | KVM_REG_SIZE_U512 | KVM_REG_SIZE_U1024
        | KVM_REG_SIZE_U2048 => false,
        _ => panic!("Unexpected register size {size:#x} for register id {regid:#x}"),
    }
}

/// Classifies a register id as a "wide register" for snapshot/restore, i.e.
/// a register whose value does not fit in a single `u64` and must be saved
/// via `VcpuKvmState::wide_regs`.
///
/// This covers SVE-introduced register sizes (U128 through U2048). Core
/// registers and U32/U64 system registers return `false` here.
pub fn is_wide_register(regid: u64) -> bool {
    if (regid & KVM_REG_ARM_COPROC_MASK as u64) == KVM_REG_ARM_CORE as u64 {
        return false;
    }

    let size = regid & KVM_REG_SIZE_MASK;
    matches!(
        size,
        KVM_REG_SIZE_U128
            | KVM_REG_SIZE_U256
            | KVM_REG_SIZE_U512
            | KVM_REG_SIZE_U1024
            | KVM_REG_SIZE_U2048
    )
}

/// Returns the size in bytes encoded in a KVM register id.
///
/// The KVM register id encodes its size in bits 52..55:
///   0 -> U8, 1 -> U16, 2 -> U32, 3 -> U64, 4 -> U128, 5 -> U256,
///   6 -> U512, 7 -> U1024, 8 -> U2048.
pub fn reg_size_from_id(regid: u64) -> usize {
    let shift = (regid & KVM_REG_SIZE_MASK) >> 52;
    1usize << shift
}

pub fn check_required_kvm_extensions(kvm: &Kvm) -> KvmResult<()> {
    macro_rules! check_extension {
        ($cap:expr) => {
            if !kvm.check_extension($cap) {
                return Err(KvmError::CapabilityMissing($cap));
            }
        };
    }

    // SetGuestDebug is required but some kernels have it implemented without the capability flag.
    check_extension!(Cap::ImmediateExit);
    check_extension!(Cap::Ioeventfd);
    check_extension!(Cap::Irqchip);
    check_extension!(Cap::Irqfd);
    check_extension!(Cap::IrqRouting);
    check_extension!(Cap::MpState);
    check_extension!(Cap::OneReg);
    check_extension!(Cap::UserMemory);
    Ok(())
}

/// A KVM register whose value is wider than 64 bits.
///
/// `kvm_one_reg` carries its value in a single `u64`, so it cannot represent
/// registers whose `KVM_REG_SIZE_*` is U128 or larger. That set includes the
/// SVE Z registers (U2048), the SVE P registers and FFR (U256), and the SVE
/// VLS pseudo-register (U512). We serialise their raw bytes so they can be
/// round-tripped across snapshot/restore.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct WideReg {
    pub id: u64,
    pub data: Vec<u8>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct VcpuKvmState {
    pub mp_state: kvm_mp_state,
    pub core_regs: kvm_regs,
    pub sys_regs: Vec<kvm_one_reg>,
    /// Registers wider than 64 bits (e.g. SVE Z/P/FFR/VLS).
    ///
    /// `#[serde(default)]` keeps snapshots taken before SVE state was
    /// preserved deserialisable: the field simply defaults to an empty vec
    /// when the key is absent.
    #[serde(default)]
    pub wide_regs: Vec<WideReg>,
}
