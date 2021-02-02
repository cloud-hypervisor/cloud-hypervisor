// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use super::get_fdt_addr;
use hypervisor::kvm::kvm_bindings::{
    kvm_regs, user_pt_regs, KVM_REG_ARM64, KVM_REG_ARM_CORE, KVM_REG_SIZE_U64,
};
use hypervisor::{arm64_core_reg_id, offset__of};
use std::sync::Arc;
use std::{mem, result};
use vm_memory::GuestMemoryMmap;

/// Errors thrown while setting aarch64 registers.
#[derive(Debug)]
pub enum Error {
    /// Failed to set core register (PC, PSTATE or general purpose ones).
    SetCoreRegister(hypervisor::HypervisorCpuError),
    /// Failed to get a system register.
    GetSysRegister(hypervisor::HypervisorCpuError),
}
type Result<T> = result::Result<T, Error>;

#[allow(non_upper_case_globals)]
// PSR (Processor State Register) bits.
// Taken from arch/arm64/include/uapi/asm/ptrace.h.
const PSR_MODE_EL1h: u64 = 0x0000_0005;
const PSR_F_BIT: u64 = 0x0000_0040;
const PSR_I_BIT: u64 = 0x0000_0080;
const PSR_A_BIT: u64 = 0x0000_0100;
const PSR_D_BIT: u64 = 0x0000_0200;
// Taken from arch/arm64/kvm/inject_fault.c.
const PSTATE_FAULT_BITS_64: u64 = PSR_MODE_EL1h | PSR_A_BIT | PSR_F_BIT | PSR_I_BIT | PSR_D_BIT;

/// Configure core registers for a given CPU.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
/// * `cpu_id` - Index of current vcpu.
/// * `boot_ip` - Starting instruction pointer.
/// * `mem` - Reserved DRAM for current VM.
pub fn setup_regs(
    vcpu: &Arc<dyn hypervisor::Vcpu>,
    cpu_id: u8,
    boot_ip: u64,
    _mem: &GuestMemoryMmap,
) -> Result<()> {
    let kreg_off = offset__of!(kvm_regs, regs);

    // Get the register index of the PSTATE (Processor State) register.
    let pstate = offset__of!(user_pt_regs, pstate) + kreg_off;
    vcpu.set_reg(
        arm64_core_reg_id!(KVM_REG_SIZE_U64, pstate),
        PSTATE_FAULT_BITS_64,
    )
    .map_err(Error::SetCoreRegister)?;

    // Other vCPUs are powered off initially awaiting PSCI wakeup.
    if cpu_id == 0 {
        // Setting the PC (Processor Counter) to the current program address (kernel address).
        let pc = offset__of!(user_pt_regs, pc) + kreg_off;
        vcpu.set_reg(arm64_core_reg_id!(KVM_REG_SIZE_U64, pc), boot_ip as u64)
            .map_err(Error::SetCoreRegister)?;

        // Last mandatory thing to set -> the address pointing to the FDT (also called DTB).
        // "The device tree blob (dtb) must be placed on an 8-byte boundary and must
        // not exceed 2 megabytes in size." -> https://www.kernel.org/doc/Documentation/arm64/booting.txt.
        // We are choosing to place it the end of DRAM. See `get_fdt_addr`.
        let regs0 = offset__of!(user_pt_regs, regs) + kreg_off;
        vcpu.set_reg(
            arm64_core_reg_id!(KVM_REG_SIZE_U64, regs0),
            get_fdt_addr() as u64,
        )
        .map_err(Error::SetCoreRegister)?;
    }
    Ok(())
}
