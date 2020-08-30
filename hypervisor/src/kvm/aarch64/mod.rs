// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2020, Microsoft Corporation
//
// Copyright 2018-2019 CrowdStrike, Inc.
//
//

///
/// Export generically-named wrappers of kvm-bindings for Unix-based platforms
///
use crate::kvm::{KvmError, KvmResult};
use kvm_bindings::{
    kvm_mp_state, kvm_one_reg, kvm_regs, KVM_REG_ARM64, KVM_REG_ARM64_SYSREG,
    KVM_REG_ARM64_SYSREG_CRM_MASK, KVM_REG_ARM64_SYSREG_CRM_SHIFT, KVM_REG_ARM64_SYSREG_CRN_MASK,
    KVM_REG_ARM64_SYSREG_CRN_SHIFT, KVM_REG_ARM64_SYSREG_OP0_MASK, KVM_REG_ARM64_SYSREG_OP0_SHIFT,
    KVM_REG_ARM64_SYSREG_OP1_MASK, KVM_REG_ARM64_SYSREG_OP1_SHIFT, KVM_REG_ARM64_SYSREG_OP2_MASK,
    KVM_REG_ARM64_SYSREG_OP2_SHIFT, KVM_REG_ARM_COPROC_MASK, KVM_REG_ARM_CORE, KVM_REG_SIZE_MASK,
    KVM_REG_SIZE_U32, KVM_REG_SIZE_U64,
};
pub use kvm_bindings::{
    kvm_one_reg as OneRegister, kvm_regs as StandardRegisters, kvm_vcpu_init as VcpuInit, RegList,
};
use serde_derive::{Deserialize, Serialize};
pub use {kvm_ioctls::Cap, kvm_ioctls::Kvm};

// Following are macros that help with getting the ID of a aarch64 core register.
// The core register are represented by the user_pt_regs structure. Look for it in
// arch/arm64/include/uapi/asm/ptrace.h.

// This macro gets the offset of a structure (i.e `str`) member (i.e `field`) without having
// an instance of that structure.
// It uses a null pointer to retrieve the offset to the field.
// Inspired by C solution: `#define offsetof(str, f) ((size_t)(&((str *)0)->f))`.
// Doing `offset__of!(user_pt_regs, pstate)` in our rust code will trigger the following:
// unsafe { &(*(0 as *const user_pt_regs)).pstate as *const _ as usize }
// The dereference expression produces an lvalue, but that lvalue is not actually read from,
// we're just doing pointer math on it, so in theory, it should safe.
#[macro_export]
macro_rules! offset__of {
    ($str:ty, $field:ident) => {
        unsafe { &(*std::ptr::null::<$str>()).$field as *const _ as usize }
    };
}

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

// This macro computes the ID of a specific ARM64 system register similar to how
// the kernel C macro does.
// https://elixir.bootlin.com/linux/v4.20.17/source/arch/arm64/include/uapi/asm/kvm.h#L203
#[macro_export]
macro_rules! arm64_sys_reg {
    ($name: tt, $op0: tt, $op1: tt, $crn: tt, $crm: tt, $op2: tt) => {
        pub const $name: u64 = KVM_REG_ARM64 as u64
            | KVM_REG_SIZE_U64 as u64
            | KVM_REG_ARM64_SYSREG as u64
            | ((($op0 as u64) << KVM_REG_ARM64_SYSREG_OP0_SHIFT)
                & KVM_REG_ARM64_SYSREG_OP0_MASK as u64)
            | ((($op1 as u64) << KVM_REG_ARM64_SYSREG_OP1_SHIFT)
                & KVM_REG_ARM64_SYSREG_OP1_MASK as u64)
            | ((($crn as u64) << KVM_REG_ARM64_SYSREG_CRN_SHIFT)
                & KVM_REG_ARM64_SYSREG_CRN_MASK as u64)
            | ((($crm as u64) << KVM_REG_ARM64_SYSREG_CRM_SHIFT)
                & KVM_REG_ARM64_SYSREG_CRM_MASK as u64)
            | ((($op2 as u64) << KVM_REG_ARM64_SYSREG_OP2_SHIFT)
                & KVM_REG_ARM64_SYSREG_OP2_MASK as u64);
    };
}

// Constant imported from the Linux kernel:
// https://elixir.bootlin.com/linux/v4.20.17/source/arch/arm64/include/asm/sysreg.h#L135
arm64_sys_reg!(MPIDR_EL1, 3, 0, 0, 0, 5);

/// Specifies whether a particular register is a system register or not.
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
    if size != KVM_REG_SIZE_U32 && size != KVM_REG_SIZE_U64 {
        panic!("Unexpected register size for system register {}", size);
    }
    true
}

pub fn check_required_kvm_extensions(kvm: &Kvm) -> KvmResult<()> {
    if !kvm.check_extension(Cap::SignalMsi) {
        return Err(KvmError::CapabilityMissing(Cap::SignalMsi));
    }
    Ok(())
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct VcpuKvmState {
    pub mp_state: kvm_mp_state,
    pub core_regs: kvm_regs,
    pub sys_regs: Vec<kvm_one_reg>,
    // We will be using the mpidr for passing it to the VmState.
    // The VmState will give this away for saving restoring the icc and redistributor
    // registers.
    pub mpidr: u64,
}
