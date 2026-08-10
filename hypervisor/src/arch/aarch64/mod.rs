// Copyright 2022 Arm Limited (or its affiliates). All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

pub mod gic;
pub mod regs;

use serde::{Deserialize, Serialize};

/// Reads the architected counter frequency (`CNTFRQ_EL0`, Hz) from the host: KVM
/// does not expose it through ONE_REG and the guest counter runs at host frequency.
pub fn get_cntfrq() -> u64 {
    use std::arch::asm;
    let cntfrq: u64;
    // SAFETY: `mrs cntfrq_el0` only reads a read-only system register and
    // touches no memory (nomem, nostack, preserves_flags).
    unsafe {
        asm!(
            "mrs {}, cntfrq_el0",
            out(reg) cntfrq,
            options(nomem, nostack, preserves_flags),
        );
    }
    cntfrq
}

/// Return the MPIDR based on the vCPU ID
/// Based on reset_mpidr() in linux/arch/arm64/kvm/sys_regs.c
pub const fn mpidr_from_vcpu_id(vcpu_id: u64) -> u64 {
    (vcpu_id & 0x0f)                    // Aff0, bits [7:0]
    | (((vcpu_id >> 4) & 0xff) << 8)    // Aff1, bits [15:8]
    | (((vcpu_id >> 12) & 0xff) << 16)  // Aff2, bits [23:16]
    | (1 << 31) // RES1
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ExtendedReg {
    pub id: u64,
    pub data: Vec<u8>,
}
