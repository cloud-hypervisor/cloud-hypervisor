// Copyright © 2024 Institute of Software, CAS. All rights reserved.
//
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
use std::sync::Arc;

use thiserror::Error;
#[cfg(not(target_arch = "riscv64"))]
use vm_memory::GuestAddress;

#[cfg(target_arch = "x86_64")]
use crate::arch::x86::{CpuIdEntry, FpuState, LapicState, MsrEntry, SpecialRegisters};
#[cfg(feature = "tdx")]
use crate::kvm::{TdxExitDetails, TdxExitStatus};
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
use crate::RegList;
#[cfg(target_arch = "aarch64")]
use crate::VcpuInit;
use crate::{CpuState, MpState, StandardRegisters};

#[cfg(target_arch = "x86_64")]
#[derive(Copy, Clone, Default)]
pub enum CpuVendor {
    #[default]
    Unknown,
    Intel,
    AMD,
}

#[derive(Error, Debug)]
///
/// Enum for CPU error
pub enum HypervisorCpuError {
    ///
    /// Setting standard registers error
    ///
    #[error("Failed to set standard register")]
    SetStandardRegs(#[source] anyhow::Error),
    ///
    /// Setting standard registers error
    ///
    #[error("Failed to get standard registers")]
    GetStandardRegs(#[source] anyhow::Error),
    ///
    /// Setting special register error
    ///
    #[error("Failed to set special registers")]
    SetSpecialRegs(#[source] anyhow::Error),
    ///
    /// Getting standard register error
    ///
    #[error("Failed to get special registers")]
    GetSpecialRegs(#[source] anyhow::Error),
    ///
    /// Setting floating point registers error
    ///
    #[error("Failed to set floating point registers")]
    SetFloatingPointRegs(#[source] anyhow::Error),
    ///
    /// Getting floating point register error
    ///
    #[error("Failed to get floating points registers")]
    GetFloatingPointRegs(#[source] anyhow::Error),
    ///
    /// Setting Cpuid error
    ///
    #[error("Failed to set Cpuid")]
    SetCpuid(#[source] anyhow::Error),
    ///
    /// Getting Cpuid error
    ///
    #[error("Failed to get Cpuid")]
    GetCpuid(#[source] anyhow::Error),
    ///
    /// Setting lapic state error
    ///
    #[error("Failed to set Lapic state")]
    SetLapicState(#[source] anyhow::Error),
    ///
    /// Getting Lapic state error
    ///
    #[error("Failed to get Lapic state")]
    GetlapicState(#[source] anyhow::Error),
    ///
    /// Setting MSR entries error
    ///
    #[error("Failed to set Msr entries")]
    SetMsrEntries(#[source] anyhow::Error),
    ///
    /// Getting Msr entries error
    ///
    #[error("Failed to get Msr entries")]
    GetMsrEntries(#[source] anyhow::Error),
    ///
    /// Setting multi-processing  state error
    ///
    #[error("Failed to set MP state")]
    SetMpState(#[source] anyhow::Error),
    ///
    /// Getting multi-processing  state error
    ///
    #[error("Failed to get MP state")]
    GetMpState(#[source] anyhow::Error),
    ///
    /// Setting Saved Processor Extended States error
    ///
    #[cfg(feature = "kvm")]
    #[error("Failed to set Saved Processor Extended States")]
    SetXsaveState(#[source] anyhow::Error),
    ///
    /// Getting Saved Processor Extended States error
    ///
    #[cfg(feature = "kvm")]
    #[error("Failed to get Saved Processor Extended States")]
    GetXsaveState(#[source] anyhow::Error),
    ///
    /// Getting the VP state components error
    ///
    #[cfg(feature = "mshv")]
    #[error("Failed to get VP State Components")]
    GetAllVpStateComponents(#[source] anyhow::Error),
    ///
    /// Setting the VP state components error
    ///
    #[cfg(feature = "mshv")]
    #[error("Failed to set VP State Components")]
    SetAllVpStateComponents(#[source] anyhow::Error),
    ///
    /// Setting Extended Control Registers error
    ///
    #[error("Failed to set Extended Control Registers")]
    SetXcsr(#[source] anyhow::Error),
    ///
    /// Getting Extended Control Registers error
    ///
    #[error("Failed to get Extended Control Registers")]
    GetXcsr(#[source] anyhow::Error),
    ///
    /// Running Vcpu error
    ///
    #[error("Failed to run vcpu")]
    RunVcpu(#[source] anyhow::Error),
    ///
    /// Getting Vcpu events error
    ///
    #[error("Failed to get Vcpu events")]
    GetVcpuEvents(#[source] anyhow::Error),
    ///
    /// Setting Vcpu events error
    ///
    #[error("Failed to set Vcpu events")]
    SetVcpuEvents(#[source] anyhow::Error),
    ///
    /// Vcpu Init error
    ///
    #[error("Failed to init vcpu")]
    VcpuInit(#[source] anyhow::Error),
    ///
    /// Vcpu Finalize error
    ///
    #[error("Failed to finalize vcpu")]
    VcpuFinalize(#[source] anyhow::Error),
    ///
    /// Setting one reg error
    ///
    #[error("Failed to set one reg")]
    SetRegister(#[source] anyhow::Error),
    ///
    /// Getting one reg error
    ///
    #[error("Failed to get one reg")]
    GetRegister(#[source] anyhow::Error),
    ///
    /// Getting guest clock paused error
    ///
    #[error("Failed to notify guest its clock was paused")]
    NotifyGuestClockPaused(#[source] anyhow::Error),
    ///
    /// Setting debug register error
    ///
    #[error("Failed to set debug registers")]
    SetDebugRegs(#[source] anyhow::Error),
    ///
    /// Getting debug register error
    ///
    #[error("Failed to get debug registers")]
    GetDebugRegs(#[source] anyhow::Error),
    ///
    /// Setting misc register error
    ///
    #[error("Failed to set misc registers")]
    SetMiscRegs(#[source] anyhow::Error),
    ///
    /// Getting misc register error
    ///
    #[error("Failed to get misc registers")]
    GetMiscRegs(#[source] anyhow::Error),
    ///
    /// Write to Guest Mem
    ///
    #[error("Failed to write to Guest Mem at")]
    GuestMemWrite(#[source] anyhow::Error),
    /// Enabling HyperV SynIC error
    ///
    #[error("Failed to enable HyperV SynIC")]
    EnableHyperVSyncIc(#[source] anyhow::Error),
    ///
    /// Getting AArch64 core register error
    ///
    #[error("Failed to get aarch64 core register")]
    GetAarchCoreRegister(#[source] anyhow::Error),
    ///
    /// Setting AArch64 core register error
    ///
    #[error("Failed to set aarch64 core register")]
    SetAarchCoreRegister(#[source] anyhow::Error),
    ///
    /// Getting RISC-V 64-bit core register error
    ///
    #[error("Failed to get riscv64 core register")]
    GetRiscvCoreRegister(#[source] anyhow::Error),
    ///
    /// Setting RISC-V 64-bit core register error
    ///
    #[error("Failed to set riscv64 core register")]
    SetRiscvCoreRegister(#[source] anyhow::Error),
    ///
    /// Getting registers list error
    ///
    #[error("Failed to retrieve list of registers")]
    GetRegList(#[source] anyhow::Error),
    ///
    /// Getting AArch64 system register error
    ///
    #[error("Failed to get system register")]
    GetSysRegister(#[source] anyhow::Error),
    ///
    /// Setting AArch64 system register error
    ///
    #[error("Failed to set system register")]
    SetSysRegister(#[source] anyhow::Error),
    ///
    /// Getting RISC-V 64-bit non-core register error
    ///
    #[error("Failed to get non-core register")]
    GetNonCoreRegister(#[source] anyhow::Error),
    ///
    /// Setting RISC-V 64-bit non-core register error
    ///
    #[error("Failed to set non-core register")]
    SetNonCoreRegister(#[source] anyhow::Error),
    ///
    /// GVA translation error
    ///
    #[error("Failed to translate GVA")]
    TranslateVirtualAddress(#[source] anyhow::Error),
    ///
    /// Set cpu attribute error
    ///
    #[error("Failed to set vcpu attribute")]
    SetVcpuAttribute(#[source] anyhow::Error),
    ///
    /// Check if cpu has a certain attribute error
    ///
    #[error("Failed to check if vcpu has attribute")]
    HasVcpuAttribute(#[source] anyhow::Error),
    ///
    /// Failed to initialize TDX on CPU
    ///
    #[cfg(feature = "tdx")]
    #[error("Failed to initialize TDX")]
    InitializeTdx(#[source] std::io::Error),
    ///
    /// Unknown TDX VM call
    ///
    #[cfg(feature = "tdx")]
    #[error("Unknown TDX VM call")]
    UnknownTdxVmCall,
    #[cfg(target_arch = "aarch64")]
    ///
    /// Failed to initialize PMU
    ///
    #[error("Failed to initialize PMU")]
    InitializePmu,
    #[cfg(target_arch = "x86_64")]
    ///
    /// Error getting TSC frequency
    ///
    #[error("Failed to get TSC frequency")]
    GetTscKhz(#[source] anyhow::Error),
    ///
    /// Error setting TSC frequency
    ///
    #[error("Failed to set TSC frequency")]
    SetTscKhz(#[source] anyhow::Error),
    ///
    /// Error reading value at given GPA
    ///
    #[error("Failed to read from GPA")]
    GpaRead(#[source] anyhow::Error),
    ///
    /// Error writing value at given GPA
    ///
    #[error("Failed to write to GPA")]
    GpaWrite(#[source] anyhow::Error),
    ///
    /// Error getting CPUID leaf
    ///
    #[error("Failed to get CPUID entries")]
    GetCpuidVales(#[source] anyhow::Error),
    ///
    /// Setting SEV control register error
    ///
    #[cfg(feature = "sev_snp")]
    #[error("Failed to set sev control register")]
    SetSevControlRegister(#[source] anyhow::Error),
    ///
    /// Unsupported SysReg registers
    ///
    #[cfg(target_arch = "aarch64")]
    #[error("Unsupported SysReg registers: {0}")]
    UnsupportedSysReg(u32),
    ///
    /// Error injecting NMI
    ///
    #[error("Failed to inject NMI")]
    Nmi(#[source] anyhow::Error),
}

#[derive(Debug)]
pub enum VmExit {
    #[cfg(target_arch = "x86_64")]
    IoapicEoi(u8 /* vector */),
    Ignore,
    Reset,
    Shutdown,
    Hyperv,
    #[cfg(feature = "tdx")]
    Tdx,
    #[cfg(feature = "kvm")]
    Debug,
}

///
/// Result type for returning from a function
///
pub type Result<T> = anyhow::Result<T, HypervisorCpuError>;
///
/// Trait to represent a generic Vcpu
///
pub trait Vcpu: Send + Sync {
    ///
    /// Returns StandardRegisters with default value set
    ///
    fn create_standard_regs(&self) -> StandardRegisters {
        unimplemented!();
    }
    ///
    /// Returns the vCPU general purpose registers.
    ///
    fn get_regs(&self) -> Result<StandardRegisters>;
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
    fn set_cpuid2(&self, cpuid: &[CpuIdEntry]) -> Result<()>;
    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call to enable HyperV SynIC
    ///
    fn enable_hyperv_synic(&self) -> Result<()>;
    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call to retrieve the CPUID registers.
    ///
    fn get_cpuid2(&self, num_entries: usize) -> Result<Vec<CpuIdEntry>>;
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
    fn get_msrs(&self, msrs: &mut Vec<MsrEntry>) -> Result<usize>;
    #[cfg(target_arch = "x86_64")]
    ///
    /// Setup the model-specific registers (MSR) for this vCPU.
    ///
    fn set_msrs(&self, msrs: &[MsrEntry]) -> Result<usize>;
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
    /// Let the guest know that it has been paused, which prevents from
    /// potential soft lockups when being resumed.
    ///
    fn notify_guest_clock_paused(&self) -> Result<()> {
        Ok(())
    }
    ///
    /// Sets debug registers to set hardware breakpoints and/or enable single step.
    ///
    #[cfg(not(target_arch = "riscv64"))]
    fn set_guest_debug(&self, _addrs: &[GuestAddress], _singlestep: bool) -> Result<()> {
        Err(HypervisorCpuError::SetDebugRegs(anyhow!("unimplemented")))
    }
    ///
    /// Sets the type of CPU to be exposed to the guest and optional features.
    ///
    #[cfg(target_arch = "aarch64")]
    fn vcpu_init(&self, kvi: &VcpuInit) -> Result<()>;

    #[cfg(target_arch = "aarch64")]
    fn vcpu_finalize(&self, feature: i32) -> Result<()>;
    ///
    /// Gets the features that have been finalized for a given CPU.
    ///
    #[cfg(target_arch = "aarch64")]
    fn vcpu_get_finalized_features(&self) -> i32;
    ///
    /// Sets processor features for a given CPU.
    ///
    #[cfg(target_arch = "aarch64")]
    fn vcpu_set_processor_features(
        &self,
        vm: &Arc<dyn crate::Vm>,
        kvi: &mut VcpuInit,
        id: u8,
    ) -> Result<()>;
    ///
    /// Returns VcpuInit with default value set
    ///
    #[cfg(target_arch = "aarch64")]
    fn create_vcpu_init(&self) -> VcpuInit;
    ///
    /// Gets a list of the guest registers that are supported for the
    /// KVM_GET_ONE_REG/KVM_SET_ONE_REG calls.
    ///
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    fn get_reg_list(&self, reg_list: &mut RegList) -> Result<()>;
    ///
    /// Gets the value of a system register
    ///
    #[cfg(target_arch = "aarch64")]
    fn get_sys_reg(&self, sys_reg: u32) -> Result<u64>;
    ///
    /// Gets the value of a non-core register on RISC-V 64-bit
    ///
    #[cfg(target_arch = "riscv64")]
    fn get_non_core_reg(&self, non_core_reg: u32) -> Result<u64>;
    ///
    /// Configure core registers for a given CPU.
    ///
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    fn setup_regs(&self, cpu_id: u8, boot_ip: u64, fdt_start: u64) -> Result<()>;
    ///
    /// Check if the CPU supports PMU
    ///
    #[cfg(target_arch = "aarch64")]
    fn has_pmu_support(&self) -> bool;
    ///
    /// Initialize PMU
    ///
    #[cfg(target_arch = "aarch64")]
    fn init_pmu(&self, irq: u32) -> Result<()>;
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
    #[cfg(target_arch = "x86_64")]
    ///
    /// Translate guest virtual address to guest physical address
    ///
    fn translate_gva(&self, gva: u64, flags: u64) -> Result<(u64, u32)>;
    ///
    /// Initialize TDX support on the vCPU
    ///
    #[cfg(feature = "tdx")]
    fn tdx_init(&self, _hob_address: u64) -> Result<()> {
        unimplemented!()
    }
    ///
    /// Set the "immediate_exit" state
    ///
    fn set_immediate_exit(&self, _exit: bool) {}
    #[cfg(feature = "tdx")]
    ///
    /// Returns the details about TDX exit reason
    ///
    fn get_tdx_exit_details(&mut self) -> Result<TdxExitDetails> {
        unimplemented!()
    }
    #[cfg(feature = "tdx")]
    ///
    /// Set the status code for TDX exit
    ///
    fn set_tdx_status(&mut self, _status: TdxExitStatus) {
        unimplemented!()
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Return the list of initial MSR entries for a VCPU
    ///
    fn boot_msr_entries(&self) -> Vec<MsrEntry>;

    #[cfg(target_arch = "x86_64")]
    ///
    /// Get the frequency of the TSC if available
    ///
    fn tsc_khz(&self) -> Result<Option<u32>> {
        Ok(None)
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Set the frequency of the TSC if available
    ///
    fn set_tsc_khz(&self, _freq: u32) -> Result<()> {
        Ok(())
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call to retrieve cpuid leaf
    ///
    fn get_cpuid_values(
        &self,
        _function: u32,
        _index: u32,
        _xfem: u64,
        _xss: u64,
    ) -> Result<[u32; 4]> {
        unimplemented!()
    }
    #[cfg(feature = "mshv")]
    fn set_sev_control_register(&self, _reg: u64) -> Result<()> {
        unimplemented!()
    }
    ///
    /// Sets the value of GIC redistributor address
    ///
    #[cfg(target_arch = "aarch64")]
    fn set_gic_redistributor_addr(&self, _gicr_base_addr: u64) -> Result<()> {
        Ok(())
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Trigger NMI interrupt
    ///
    fn nmi(&self) -> Result<()>;
}
