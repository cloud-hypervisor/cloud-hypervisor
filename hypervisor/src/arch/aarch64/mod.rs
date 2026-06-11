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

#[derive(Clone, Serialize, Deserialize)]
pub struct ExtendedReg {
    pub id: u64,
    pub data: Vec<u8>,
}
