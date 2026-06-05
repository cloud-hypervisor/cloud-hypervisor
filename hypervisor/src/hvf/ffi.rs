// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
//! Raw FFI bindings to Apple's `Hypervisor.framework` (arm64) plus the small
//! set of architectural constants the backend decodes. These mirror the public
//! `<Hypervisor/hv*.h>` headers shipped with the macOS SDK.

use std::ffi::c_void;

/// `hv_return_t` success value (`HV_SUCCESS`).
pub const HV_SUCCESS: i32 = 0;

// hv_reg_t — general-purpose and special core registers.
pub const HV_REG_PC: u32 = 31;
pub const HV_REG_CPSR: u32 = 34;

// hv_exit_reason_t
pub const HV_EXIT_REASON_CANCELED: u32 = 0;
pub const HV_EXIT_REASON_EXCEPTION: u32 = 1;
pub const HV_EXIT_REASON_VTIMER_ACTIVATED: u32 = 2;

// hv_memory_flags_t
pub const HV_MEMORY_READ: u64 = 1 << 0;
pub const HV_MEMORY_WRITE: u64 = 1 << 1;
pub const HV_MEMORY_EXEC: u64 = 1 << 2;

// ESR_EL2 exception classes (syndrome >> 26).
pub const EC_WFX: u64 = 0x01; // WFI/WFE trapped
pub const EC_HVC64: u64 = 0x16;
pub const EC_DATA_ABORT_LOWER: u64 = 0x24; // from a lower EL (the guest)
pub const EC_DATA_ABORT_SAME: u64 = 0x25; // from the current EL

// PSTATE for a cold EL1h boot with DAIF (D,A,I,F) masked.
pub const PSTATE_EL1H_DAIF: u64 = 0x3c5;

// PSCI 0.2 function ids issued via HVC.
pub const PSCI_SYSTEM_OFF: u64 = 0x8400_0008;
pub const PSCI_SYSTEM_RESET: u64 = 0x8400_0009;

// hv_sys_reg_t — curated EL1 system-register ids used for snapshot/restore.
pub const SYSREG_MDSCR_EL1: u16 = 0x8012;
pub const SYSREG_SCTLR_EL1: u16 = 0xc080;
pub const SYSREG_CPACR_EL1: u16 = 0xc082;
pub const SYSREG_TTBR0_EL1: u16 = 0xc100;
pub const SYSREG_TTBR1_EL1: u16 = 0xc101;
pub const SYSREG_TCR_EL1: u16 = 0xc102;
pub const SYSREG_SPSR_EL1: u16 = 0xc200;
pub const SYSREG_ELR_EL1: u16 = 0xc201;
pub const SYSREG_SP_EL0: u16 = 0xc208;
pub const SYSREG_ESR_EL1: u16 = 0xc290;
pub const SYSREG_FAR_EL1: u16 = 0xc300;
pub const SYSREG_MAIR_EL1: u16 = 0xc510;
pub const SYSREG_VBAR_EL1: u16 = 0xc600;
pub const SYSREG_TPIDR_EL1: u16 = 0xc684;
pub const SYSREG_TPIDR_EL0: u16 = 0xde82;
pub const SYSREG_TPIDRRO_EL0: u16 = 0xde83;
pub const SYSREG_SP_EL1: u16 = 0xe208;
pub const SYSREG_MPIDR_EL1: u16 = 0xc005;
/// MPIDR_EL1 bit[31] is RES1 on AArch64; affinity fields occupy Aff0..Aff3.
pub const MPIDR_RES1: u64 = 1 << 31;

// hv_interrupt_type_t
pub const HV_INTERRUPT_TYPE_IRQ: u32 = 0;
#[allow(dead_code)]
pub const HV_INTERRUPT_TYPE_FIQ: u32 = 1;

// hv_gic_distributor_reg_t — register offsets within the distributor.
#[allow(dead_code)]
pub const HV_GIC_DIST_REG_GICD_CTLR: u32 = 0x0000;
#[allow(dead_code)]
pub const HV_GIC_DIST_REG_GICD_TYPER: u32 = 0x0004;

/// `hv_vcpu_exit_exception_t`.
#[repr(C)]
pub struct HvVcpuExitException {
    pub syndrome: u64,         // ESR_ELx
    pub virtual_address: u64,  // FAR_ELx
    pub physical_address: u64, // faulting IPA (stage-2)
}

/// `hv_vcpu_exit_t`.
#[repr(C)]
pub struct HvVcpuExit {
    pub reason: u32,
    pub exception: HvVcpuExitException,
}

#[link(name = "Hypervisor", kind = "framework")]
unsafe extern "C" {
    pub fn hv_vm_create(config: *mut c_void) -> i32;
    pub fn hv_vm_destroy() -> i32;
    pub fn hv_vm_map(addr: *mut c_void, ipa: u64, size: usize, flags: u64) -> i32;
    pub fn hv_vm_unmap(ipa: u64, size: usize) -> i32;
    pub fn hv_vcpu_create(vcpu: *mut u64, exit: *mut *mut HvVcpuExit, config: *mut c_void) -> i32;
    pub fn hv_vcpu_destroy(vcpu: u64) -> i32;
    pub fn hv_vcpu_set_reg(vcpu: u64, reg: u32, value: u64) -> i32;
    pub fn hv_vcpu_get_reg(vcpu: u64, reg: u32, value: *mut u64) -> i32;
    pub fn hv_vcpu_set_sys_reg(vcpu: u64, reg: u16, value: u64) -> i32;
    pub fn hv_vcpu_get_sys_reg(vcpu: u64, reg: u16, value: *mut u64) -> i32;
    pub fn hv_vcpu_run(vcpu: u64) -> i32;
    pub fn hv_vcpu_set_pending_interrupt(vcpu: u64, ty: u32, pending: bool) -> i32;
    pub fn hv_vcpu_set_vtimer_mask(vcpu: u64, masked: bool) -> i32;

    // GIC configuration object (os_object, released with os_release).
    pub fn hv_gic_config_create() -> *mut c_void;
    pub fn hv_gic_config_set_distributor_base(config: *mut c_void, base: u64) -> i32;
    pub fn hv_gic_config_set_redistributor_base(config: *mut c_void, base: u64) -> i32;
    // MSI/ITS region setup — reserved for when irqfd/GSI routing lands.
    #[allow(dead_code)]
    pub fn hv_gic_config_set_msi_region_base(config: *mut c_void, base: u64) -> i32;
    #[allow(dead_code)]
    pub fn hv_gic_config_set_msi_interrupt_range(config: *mut c_void, base: u32, count: u32)
        -> i32;

    // GIC lifecycle, register access and interrupt injection.
    pub fn hv_gic_create(config: *mut c_void) -> i32;
    #[allow(dead_code)]
    pub fn hv_gic_reset() -> i32;
    pub fn hv_gic_set_spi(intid: u32, level: bool) -> i32;
    pub fn hv_gic_get_distributor_reg(reg: u32, value: *mut u64) -> i32;
    #[allow(dead_code)]
    pub fn hv_gic_set_distributor_reg(reg: u32, value: u64) -> i32;
    #[allow(dead_code)]
    pub fn hv_gic_get_redistributor_size(size: *mut usize) -> i32;
    #[allow(dead_code)]
    pub fn hv_gic_get_distributor_size(size: *mut usize) -> i32;
    #[allow(dead_code)]
    pub fn hv_gic_get_spi_interrupt_range(base: *mut u32, count: *mut u32) -> i32;

    // GIC state save/restore (os_object state handle).
    pub fn hv_gic_state_create() -> *mut c_void;
    pub fn hv_gic_state_get_size(state: *mut c_void, size: *mut usize) -> i32;
    pub fn hv_gic_state_get_data(state: *mut c_void, data: *mut c_void) -> i32;
    pub fn hv_gic_set_state(data: *const c_void, size: usize) -> i32;
}

unsafe extern "C" {
    /// Release an `os_object` (e.g. an `hv_gic_config_t`/`hv_gic_state_t`).
    pub fn os_release(object: *mut c_void);
}
