// Copyright © 2024 Institute of Software, CAS. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

pub mod aia;

use kvm_bindings::{
    kvm_mp_state, kvm_one_reg, kvm_riscv_core, KVM_REG_RISCV_CORE, KVM_REG_RISCV_TYPE_MASK,
    KVM_REG_SIZE_MASK, KVM_REG_SIZE_U64,
};
pub use kvm_ioctls::{Cap, Kvm};
use serde::{Deserialize, Serialize};

use crate::kvm::{KvmError, KvmResult};

// This macro gets the offset of a structure (i.e `str`) member (i.e `field`) without having
// an instance of that structure.
#[macro_export]
macro_rules! _offset_of {
    ($str:ty, $field:ident) => {{
        let tmp: std::mem::MaybeUninit<$str> = std::mem::MaybeUninit::uninit();
        let base = tmp.as_ptr();

        // Avoid warnings when nesting `unsafe` blocks.
        #[allow(unused_unsafe)]
        // SAFETY: The pointer is valid and aligned, just not initialised. Using `addr_of` ensures
        // that we don't actually read from `base` (which would be UB) nor create an intermediate
        // reference.
        let member = unsafe { core::ptr::addr_of!((*base).$field) } as *const u8;

        // Avoid warnings when nesting `unsafe` blocks.
        #[allow(unused_unsafe)]
        // SAFETY: The two pointers are within the same allocated object `tmp`. All requirements
        // from offset_from are upheld.
        unsafe {
            member.offset_from(base as *const u8) as usize
        }
    }};
}

#[macro_export]
macro_rules! offset_of {
    ($reg_struct:ty, $field:ident) => {
        $crate::_offset_of!($reg_struct, $field)
    };
    ($outer_reg_struct:ty, $outer_field:ident, $($inner_reg_struct:ty, $inner_field:ident), +) => {
        $crate::_offset_of!($outer_reg_struct, $outer_field) + offset_of!($($inner_reg_struct, $inner_field), +)
    };
}

// Following are macros that help with getting the ID of a riscv64 register, including config registers, core registers and timer registers.
// The register of core registers are wrapped in the `user_regs_struct` structure. See:
// https://elixir.bootlin.com/linux/v6.10/source/arch/riscv/include/uapi/asm/kvm.h#L62

// Get the ID of a register
#[macro_export]
macro_rules! riscv64_reg_id {
    ($reg_type: tt, $offset: tt) => {
        // The core registers of an riscv64 machine are represented
        // in kernel by the `kvm_riscv_core` structure:
        //
        // struct kvm_riscv_core {
        //     struct user_regs_struct regs;
        //     unsigned long mode;
        // };
        //
        // struct user_regs_struct {
        //     unsigned long pc;
        //     unsigned long ra;
        //     unsigned long sp;
        //     unsigned long gp;
        //     unsigned long tp;
        //     unsigned long t0;
        //     unsigned long t1;
        //     unsigned long t2;
        //     unsigned long s0;
        //     unsigned long s1;
        //     unsigned long a0;
        //     unsigned long a1;
        //     unsigned long a2;
        //     unsigned long a3;
        //     unsigned long a4;
        //     unsigned long a5;
        //     unsigned long a6;
        //     unsigned long a7;
        //     unsigned long s2;
        //     unsigned long s3;
        //     unsigned long s4;
        //     unsigned long s5;
        //     unsigned long s6;
        //     unsigned long s7;
        //     unsigned long s8;
        //     unsigned long s9;
        //     unsigned long s10;
        //     unsigned long s11;
        //     unsigned long t3;
        //     unsigned long t4;
        //     unsigned long t5;
        //     unsigned long t6;
        // };
        // The id of a core register can be obtained like this: offset = id &
        // ~(KVM_REG_ARCH_MASK | KVM_REG_SIZE_MASK | KVM_REG_RISCV_CORE). Thus,
        // id = KVM_REG_RISCV | KVM_REG_SIZE_U64 | KVM_REG_RISCV_CORE | offset
        //
        // To generalize, the id of a register can be obtained by:
        // id = KVM_REG_RISCV | KVM_REG_SIZE_U64 |
        //      KVM_REG_RISCV_CORE/KVM_REG_RISCV_CONFIG/KVM_REG_RISCV_TIMER |
        //      offset
        kvm_bindings::KVM_REG_RISCV as u64
            | u64::from($reg_type)
            | u64::from(kvm_bindings::KVM_REG_SIZE_U64)
            | (($offset / std::mem::size_of::<u64>()) as u64)
    };
}

/// Specifies whether a particular register is a core register or not.
///
/// # Arguments
///
/// * `regid` - The index of the register we are checking.
pub fn is_non_core_register(regid: u64) -> bool {
    if (regid & KVM_REG_RISCV_TYPE_MASK as u64) == KVM_REG_RISCV_CORE as u64 {
        return false;
    }

    let size = regid & KVM_REG_SIZE_MASK;

    assert!(
        size == KVM_REG_SIZE_U64,
        "Unexpected register size for system register {size}"
    );

    true
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

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct VcpuKvmState {
    pub mp_state: kvm_mp_state,
    pub core_regs: kvm_riscv_core,
    pub non_core_regs: Vec<kvm_one_reg>,
}
