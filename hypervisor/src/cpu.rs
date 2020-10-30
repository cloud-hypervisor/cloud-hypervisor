// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2020, Microsoft Corporation
//
// Copyright 2018-2019 CrowdStrike, Inc.
//
//

#[cfg(target_arch = "aarch64")]
use crate::aarch64::VcpuInit;
#[cfg(target_arch = "aarch64")]
use crate::aarch64::{RegList, Register, StandardRegisters};
use crate::{CpuState, MpState};

#[cfg(target_arch = "x86_64")]
use crate::x86_64::{
    CpuId, ExtendedControlRegisters, FpuState, LapicState, MsrEntries, SpecialRegisters,
    StandardRegisters, VcpuEvents, Xsave,
};
use thiserror::Error;

#[derive(Error, Debug)]
///
/// Enum for CPU error
pub enum HypervisorCpuError {
    ///
    /// Setting standard registers error
    ///
    #[error("Failed to set standard register: {0}")]
    SetStandardRegs(#[source] anyhow::Error),
    ///
    /// Setting standard registers error
    ///
    #[error("Failed to get standard registers: {0}")]
    GetStandardRegs(#[source] anyhow::Error),
    ///
    /// Setting special register error
    ///
    #[error("Failed to set special registers: {0}")]
    SetSpecialRegs(#[source] anyhow::Error),
    ///
    /// Getting standard register error
    ///
    #[error("Failed to get special registers: {0}")]
    GetSpecialRegs(#[source] anyhow::Error),
    ///
    /// Setting floating point registers error
    ///
    #[error("Failed to set special register: {0}")]
    SetFloatingPointRegs(#[source] anyhow::Error),
    ///
    /// Getting floating point register error
    ///
    #[error("Failed to get special register: {0}")]
    GetFloatingPointRegs(#[source] anyhow::Error),
    ///
    /// Setting Cpuid error
    ///
    #[error("Failed to set Cpuid: {0}")]
    SetCpuid(#[source] anyhow::Error),
    ///
    /// Getting Cpuid error
    ///
    #[error("Failed to get Cpuid: {0}")]
    GetCpuid(#[source] anyhow::Error),
    ///
    /// Setting lapic state error
    ///
    #[error("Failed to set Lapic state: {0}")]
    SetLapicState(#[source] anyhow::Error),
    ///
    /// Getting Lapic state error
    ///
    #[error("Failed to get Lapic state: {0}")]
    GetlapicState(#[source] anyhow::Error),
    ///
    /// Setting MSR entries error
    ///
    #[error("Failed to set Msr entries: {0}")]
    SetMsrEntries(#[source] anyhow::Error),
    ///
    /// Getting Msr entries error
    ///
    #[error("Failed to get Msr entries: {0}")]
    GetMsrEntries(#[source] anyhow::Error),
    ///
    /// Setting MSR entries error
    ///
    #[error("Failed to set MP state: {0}")]
    SetMpState(#[source] anyhow::Error),
    ///
    /// Getting Msr entries error
    ///
    #[error("Failed to get MP state: {0}")]
    GetMpState(#[source] anyhow::Error),
    ///
    /// Setting Saved Processor Extended States error
    ///
    #[error("Failed to set Saved Processor Extended States: {0}")]
    SetXsaveState(#[source] anyhow::Error),
    ///
    /// Getting Saved Processor Extended States error
    ///
    #[error("Failed to get Saved Processor Extended States: {0}")]
    GetXsaveState(#[source] anyhow::Error),
    ///
    /// Setting Extended Control Registers error
    ///
    #[error("Failed to set Extended Control Registers: {0}")]
    SetXcsr(#[source] anyhow::Error),
    ///
    /// Getting Extended Control Registers error
    ///
    #[error("Failed to get Extended Control Registers: {0}")]
    GetXcsr(#[source] anyhow::Error),
    ///
    /// Running Vcpu error
    ///
    #[error("Failed to run vcpu: {0}")]
    RunVcpu(#[source] anyhow::Error),
    ///
    /// Getting Vcpu events error
    ///
    #[error("Failed to get Vcpu events: {0}")]
    GetVcpuEvents(#[source] anyhow::Error),
    ///
    /// Setting Vcpu events error
    ///
    #[error("Failed to set Vcpu events: {0}")]
    SetVcpuEvents(#[source] anyhow::Error),
    ///
    /// Vcpu Init error
    ///
    #[error("Failed to init vcpu: {0}")]
    VcpuInit(#[source] anyhow::Error),
    ///
    /// Setting one reg error
    ///
    #[error("Failed to init vcpu: {0}")]
    SetRegister(#[source] anyhow::Error),
    ///
    /// Getting one reg error
    ///
    #[error("Failed to init vcpu: {0}")]
    GetRegister(#[source] anyhow::Error),
    ///
    /// Getting guest clock paused error
    ///
    #[error("Failed to notify guest its clock was paused: {0}")]
    NotifyGuestClockPaused(#[source] anyhow::Error),
    ///
    /// Enabling HyperV SynIC error
    ///
    #[error("Failed to enable HyperV SynIC")]
    EnableHyperVSynIC(#[source] anyhow::Error),
    ///
    /// Getting AArch64 core register error
    ///
    #[error("Failed to get core register: {0}")]
    GetCoreRegister(#[source] anyhow::Error),
    ///
    /// Setting AArch64 core register error
    ///
    #[error("Failed to set core register: {0}")]
    SetCoreRegister(#[source] anyhow::Error),
    ///
    /// Getting AArch64 registers list error
    ///
    #[error("Failed to retrieve list of registers: {0}")]
    GetRegList(#[source] anyhow::Error),
    ///
    /// Getting AArch64 system register error
    ///
    #[error("Failed to get system register: {0}")]
    GetSysRegister(#[source] anyhow::Error),
    ///
    /// Setting AArch64 system register error
    ///
    #[error("Failed to set system register: {0}")]
    SetSysRegister(#[source] anyhow::Error),
}

#[derive(Debug)]
pub enum VmExit<'a> {
    #[cfg(target_arch = "x86_64")]
    IoOut(u16 /* port */, &'a [u8] /* data */),
    #[cfg(target_arch = "x86_64")]
    IoIn(u16 /* port */, &'a mut [u8] /* data */),
    #[cfg(target_arch = "x86_64")]
    IoapicEoi(u8 /* vector */),
    MmioRead(u64 /* address */, &'a mut [u8]),
    MmioWrite(u64 /* address */, &'a [u8]),
    Ignore,
    Reset,
    Shutdown,
    Hyperv,
}

///
/// Result type for returning from a function
///
pub type Result<T> = anyhow::Result<T, HypervisorCpuError>;
///
/// Trait to represent a generic Vcpu
///
pub trait Vcpu: Send + Sync {
    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns the vCPU general purpose registers.
    ///
    fn get_regs(&self) -> Result<StandardRegisters>;

    #[cfg(target_arch = "x86_64")]
    ///
    /// Sets the vCPU general purpose registers.
    ///
    fn set_regs(&self, regs: &StandardRegisters) -> Result<()>;
    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns the vCPU special registers.
    ///
    fn get_sregs(&self) -> Result<SpecialRegisters>;
    #[cfg(target_arch = "x86_64")]
    ///
    /// Sets the vCPU special registers
    ///
    fn set_sregs(&self, sregs: &SpecialRegisters) -> Result<()>;
    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns the floating point state (FPU) from the vCPU.
    ///
    fn get_fpu(&self) -> Result<FpuState>;
    #[cfg(target_arch = "x86_64")]
    ///
    /// Set the floating point state (FPU) of a vCPU
    ///
    fn set_fpu(&self, fpu: &FpuState) -> Result<()>;
    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call to setup the CPUID registers.
    ///
    fn set_cpuid2(&self, cpuid: &CpuId) -> Result<()>;
    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call to enable HyperV SynIC
    ///
    fn enable_hyperv_synic(&self) -> Result<()>;
    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call to retrieve the CPUID registers.
    ///
    fn get_cpuid2(&self, num_entries: usize) -> Result<CpuId>;
    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns the state of the LAPIC (Local Advanced Programmable Interrupt Controller).
    ///
    fn get_lapic(&self) -> Result<LapicState>;
    #[cfg(target_arch = "x86_64")]
    ///
    /// Sets the state of the LAPIC (Local Advanced Programmable Interrupt Controller).
    ///
    fn set_lapic(&self, lapic: &LapicState) -> Result<()>;
    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns the model-specific registers (MSR) for this vCPU.
    ///
    fn get_msrs(&self, msrs: &mut MsrEntries) -> Result<usize>;
    #[cfg(target_arch = "x86_64")]
    ///
    /// Setup the model-specific registers (MSR) for this vCPU.
    ///
    fn set_msrs(&self, msrs: &MsrEntries) -> Result<usize>;
    ///
    /// Returns the vcpu's current "multiprocessing state".
    ///
    fn get_mp_state(&self) -> Result<MpState>;
    ///
    /// Sets the vcpu's current "multiprocessing state".
    ///
    fn set_mp_state(&self, mp_state: MpState) -> Result<()>;
    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call that returns the vcpu's current "xsave struct".
    ///
    fn get_xsave(&self) -> Result<Xsave>;
    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call that sets the vcpu's current "xsave struct".
    ///
    fn set_xsave(&self, xsave: &Xsave) -> Result<()>;
    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call that returns the vcpu's current "xcrs".
    ///
    fn get_xcrs(&self) -> Result<ExtendedControlRegisters>;
    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call that sets the vcpu's current "xcrs".
    ///
    fn set_xcrs(&self, xcrs: &ExtendedControlRegisters) -> Result<()>;
    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns currently pending exceptions, interrupts, and NMIs as well as related
    /// states of the vcpu.
    ///
    fn get_vcpu_events(&self) -> Result<VcpuEvents>;
    #[cfg(target_arch = "x86_64")]
    ///
    /// Sets pending exceptions, interrupts, and NMIs as well as related states
    /// of the vcpu.
    ///
    fn set_vcpu_events(&self, events: &VcpuEvents) -> Result<()>;
    #[cfg(target_arch = "x86_64")]
    ///
    /// Let the guest know that it has been paused, which prevents from
    /// potential soft lockups when being resumed.
    ///
    fn notify_guest_clock_paused(&self) -> Result<()>;
    ///
    /// Sets the type of CPU to be exposed to the guest and optional features.
    ///
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    fn vcpu_init(&self, kvi: &VcpuInit) -> Result<()>;
    ///
    /// Sets the value of one register for this vCPU.
    ///
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    fn set_reg(&self, reg_id: u64, data: u64) -> Result<()>;
    ///
    /// Sets the value of one register for this vCPU.
    ///
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    fn get_reg(&self, reg_id: u64) -> Result<u64>;
    ///
    /// Gets a list of the guest registers that are supported for the
    /// KVM_GET_ONE_REG/KVM_SET_ONE_REG calls.
    ///
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    fn get_reg_list(&self, reg_list: &mut RegList) -> Result<()>;
    ///
    /// Save the state of the core registers.
    ///
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    fn core_registers(&self, state: &mut StandardRegisters) -> Result<()>;
    ///
    /// Restore the state of the core registers.
    ///
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    fn set_core_registers(&self, state: &StandardRegisters) -> Result<()>;
    ///
    /// Save the state of the system registers.
    ///
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    fn system_registers(&self, state: &mut Vec<Register>) -> Result<()>;
    ///
    /// Restore the state of the system registers.
    ///
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    fn set_system_registers(&self, state: &[Register]) -> Result<()>;
    ///
    /// Read the MPIDR - Multiprocessor Affinity Register.
    ///
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    fn read_mpidr(&self) -> Result<u64>;
    ///
    /// Retrieve the vCPU state.
    /// This function is necessary to snapshot the VM
    ///
    fn state(&self) -> Result<CpuState>;
    ///
    /// Set the vCPU state.
    /// This function is required when restoring the VM
    ///
    fn set_state(&self, state: &CpuState) -> Result<()>;
    ///
    /// Triggers the running of the current virtual CPU returning an exit reason.
    ///
    fn run(&self) -> std::result::Result<VmExit, HypervisorCpuError>;
}
