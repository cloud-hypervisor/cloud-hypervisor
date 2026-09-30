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
    KVM_REG_ARM_COPROC_MASK, KVM_REG_ARM_CORE, KVM_REG_ARM64, KVM_REG_ARM64_SVE,
    KVM_REG_ARM64_SYSREG, KVM_REG_ARM64_SYSREG_CRM_MASK, KVM_REG_ARM64_SYSREG_CRN_MASK,
    KVM_REG_ARM64_SYSREG_OP0_MASK, KVM_REG_ARM64_SYSREG_OP1_MASK, KVM_REG_ARM64_SYSREG_OP2_MASK,
    KVM_REG_SIZE_MASK, KVM_REG_SIZE_SHIFT, KVM_REG_SIZE_U32, KVM_REG_SIZE_U64, KVM_REG_SIZE_U128,
    KVM_REG_SIZE_U256, KVM_REG_SIZE_U512, KVM_REG_SIZE_U1024, KVM_REG_SIZE_U2048, kvm_mp_state,
    kvm_one_reg, kvm_regs,
};
pub use kvm_ioctls::{Cap, Kvm};
use serde::{Deserialize, Serialize};

use crate::arch::aarch64::regs::VMPIDR_EL2;
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
            | (($offset / size_of::<u32>()) as u64)
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
pub fn is_system_register(regid: u64) -> bool {
    if (regid & KVM_REG_ARM_COPROC_MASK as u64) == KVM_REG_ARM_CORE as u64 {
        return false;
    }

    let size = regid & KVM_REG_SIZE_MASK;
    match size {
        KVM_REG_SIZE_U32 | KVM_REG_SIZE_U64 => true,
        KVM_REG_SIZE_U128 | KVM_REG_SIZE_U256 | KVM_REG_SIZE_U512 | KVM_REG_SIZE_U1024
        | KVM_REG_SIZE_U2048 => false,
        _ => unreachable!("Unexpected register size {size:#x} for register id {regid:#x}"),
    }
}

/// Returns the KVM `ONE_REG` id of a system register, given its Arm encoding
/// as built by `arm64_sys_reg!`.
pub fn sys_reg_id(sys_reg: u32) -> u64 {
    KVM_REG_ARM64
        | KVM_REG_SIZE_U64
        | KVM_REG_ARM64_SYSREG as u64
        | (((sys_reg >> 5)
            & (KVM_REG_ARM64_SYSREG_OP0_MASK
                | KVM_REG_ARM64_SYSREG_OP1_MASK
                | KVM_REG_ARM64_SYSREG_CRN_MASK
                | KVM_REG_ARM64_SYSREG_CRM_MASK
                | KVM_REG_ARM64_SYSREG_OP2_MASK)) as u64)
}

pub fn is_sve_register(regid: u64) -> bool {
    (regid & KVM_REG_ARM_COPROC_MASK as u64) == KVM_REG_ARM64_SVE as u64
}

pub fn reg_size(regid: u64) -> usize {
    let shift = ((regid & KVM_REG_SIZE_MASK) >> KVM_REG_SIZE_SHIFT as u64) as u32;
    1usize << shift
}

pub const KVM_ARM64_SVE_VLS_REGID: u64 =
    KVM_REG_ARM64 | KVM_REG_SIZE_U512 | KVM_REG_ARM64_SVE as u64 | 0xffff;

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

pub use crate::arch::aarch64::ExtendedReg;

pub const PRE_FINALIZE_IDS: &[u64] = &[KVM_ARM64_SVE_VLS_REGID];

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct VcpuKvmState {
    pub mp_state: kvm_mp_state,
    pub core_regs: kvm_regs,
    pub sys_regs: Vec<kvm_one_reg>,
    #[serde(default)]
    pub pre_finalize_regs: Vec<ExtendedReg>,
    #[serde(default)]
    pub extended_regs: Vec<ExtendedReg>,
}

impl VcpuKvmState {
    /// Whether the state was saved from a vCPU created with
    /// `KVM_ARM_VCPU_HAS_EL2`. Only such vCPUs expose the EL2 system registers.
    pub fn has_el2(&self) -> bool {
        let vmpidr_el2 = sys_reg_id(VMPIDR_EL2);
        self.sys_regs.iter().any(|reg| reg.id == vmpidr_el2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::aarch64::regs::MPIDR_EL1;

    #[test]
    fn has_el2_detects_saved_el2_system_registers() {
        let reg = |sys_reg| kvm_one_reg {
            id: sys_reg_id(sys_reg),
            addr: 0,
        };
        let mut state = VcpuKvmState {
            sys_regs: vec![reg(MPIDR_EL1)],
            ..Default::default()
        };
        assert!(!state.has_el2());
        state.sys_regs.push(reg(VMPIDR_EL2));
        assert!(state.has_el2());
    }
}
