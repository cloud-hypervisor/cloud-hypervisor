// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
//! Apple Hypervisor.framework (HVF) backend for Cloud Hypervisor.
//!
//! This backend implements the hypervisor-agnostic `Hypervisor`, `Vm` and
//! `Vcpu` traits on top of Apple's `Hypervisor.framework` so that arm64 guests
//! (and, ultimately, rehydrated arm64 cloud snapshots) can run natively on
//! Apple Silicon Macs.
//!
//! Scope (milestone M1): boot an arm64 guest through the real trait objects,
//! service MMIO via [`VmOps`], and snapshot/restore vCPU architectural state
//! through the real `state()`/`set_state()`. Interrupt delivery (the managed
//! `hv_gic`), PMU, multi-vCPU threading and dirty-page live migration are
//! tracked as follow-up milestones.
//!
//! HVF has two hard constraints that shape this code:
//!   * one VM per process (`hv_vm_create`/`hv_vm_destroy` are process-global);
//!   * a vCPU must be created and run on the same host thread.

use std::any::Any;
use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use serde::{Deserialize, Serialize};

use crate::arch::aarch64::gic::{Vgic, VgicConfig};
use crate::cpu::{HypervisorCpuError, Vcpu, VmExit};
use crate::vm::{DataMatch, HypervisorVmError, InterruptSourceConfig, Vm, VmOps};
use crate::{
    CpuState, HypervisorType, HypervisorVmConfig, IoEventAddress, IrqRoutingEntry, MpState,
    RegList, StandardRegisters, VcpuInit,
};

mod ffi;
use ffi::*;
pub mod gic;
use gic::HvfGicV3;

type CpuResult<T> = std::result::Result<T, HypervisorCpuError>;
type VmResult<T> = std::result::Result<T, HypervisorVmError>;

// ---------------------------------------------------------------------------
// Neutral state payloads carried by the `hypervisor` crate enums.
// ---------------------------------------------------------------------------

/// HVF core registers. Field layout mirrors the MSHV `StandardRegisters`
/// variant so the shared `get_/set_aarch64_reg!` macros work unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Default)]
pub struct HvfStandardRegisters {
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

/// HVF analogue of `kvm_vcpu_init` — HVF needs no explicit feature negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Default)]
pub struct HvfVcpuInit {
    pub features: u64,
}

/// HVF register list (system-register ids that participate in snapshot).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct HvfRegList {
    pub regs: Vec<u64>,
}

/// HVF MSI/IRQ routing entry placeholder (interrupt routing lands with hv_gic).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Default)]
pub struct HvfIrqRoutingEntry {
    pub gsi: u32,
    pub address: u64,
    pub data: u32,
}

/// Full architectural vCPU state — the unit of snapshot/restore.
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct VcpuHvfState {
    pub gpr: [u64; 31],
    pub pc: u64,
    pub cpsr: u64,
    pub sp_el1: u64,
    pub sysregs: Vec<(u16, u64)>,
    /// Per-vCPU GIC CPU-interface (ICC) registers. Empty when the VM has no
    /// managed GIC. Captured separately from `sysregs` because the managed GIC
    /// owns these and they are not reachable via `hv_vcpu_get_sys_reg`.
    #[serde(default)]
    pub gic_icc: Vec<(u16, u64)>,
    pub mp_state_running: bool,
}

/// EL1 system registers captured on snapshot. This curated set is the analogue
/// of KVM's ONE_REG list and the future home of KVM->HVF state translation.
const SNAPSHOT_SYS_REGS: &[u16] = &[
    SYSREG_MPIDR_EL1,
    SYSREG_MDSCR_EL1,
    SYSREG_SCTLR_EL1,
    SYSREG_CPACR_EL1,
    SYSREG_TTBR0_EL1,
    SYSREG_TTBR1_EL1,
    SYSREG_TCR_EL1,
    SYSREG_SPSR_EL1,
    SYSREG_ELR_EL1,
    SYSREG_SP_EL0,
    SYSREG_ESR_EL1,
    SYSREG_FAR_EL1,
    SYSREG_MAIR_EL1,
    SYSREG_VBAR_EL1,
    SYSREG_TPIDR_EL1,
    SYSREG_TPIDR_EL0,
    SYSREG_TPIDRRO_EL0,
    SYSREG_SP_EL1,
];

// ---------------------------------------------------------------------------
// Hypervisor
// ---------------------------------------------------------------------------

/// The HVF hypervisor handle. Creating one validates that HVF is usable.
pub struct HvfHypervisor;

impl HvfHypervisor {
    /// Create a new HVF hypervisor wrapped in an `Arc<dyn Hypervisor>`.
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> crate::hypervisor::Result<Arc<dyn crate::Hypervisor>> {
        Ok(Arc::new(HvfHypervisor))
    }

    /// HVF is available on Apple Silicon Macs with the hypervisor entitlement.
    pub fn is_available() -> crate::hypervisor::Result<bool> {
        Ok(cfg!(target_os = "macos"))
    }
}

impl crate::Hypervisor for HvfHypervisor {
    fn hypervisor_type(&self) -> HypervisorType {
        HypervisorType::Hvf
    }

    fn create_vm(&self, _config: HypervisorVmConfig) -> crate::hypervisor::Result<Arc<dyn Vm>> {
        // SAFETY: FFI; NULL config selects HVF defaults. One VM per process.
        let ret = unsafe { hv_vm_create(ptr::null_mut()) };
        if ret != HV_SUCCESS {
            return Err(crate::HypervisorError::VmCreate(anyhow!(
                "hv_vm_create failed: {:#010x}",
                ret as u32
            )));
        }
        Ok(Arc::new(HvfVm {
            mappings: Mutex::new(Vec::new()),
            gic: Mutex::new(None),
            vcpu_created: AtomicBool::new(false),
        }))
    }

    fn get_host_ipa_limit(&self) -> i32 {
        // HVF exposes a wide IPA space; report the common 40-bit limit.
        40
    }

    fn get_max_vcpus(&self) -> u32 {
        // M1 supports a single vCPU; raised once multi-vCPU threading lands.
        1
    }
}

// ---------------------------------------------------------------------------
// Vm
// ---------------------------------------------------------------------------

struct Mapping {
    ipa: u64,
    size: usize,
}

/// One HVF VM. Owns the process-global VM lifetime and the IPA mappings.
pub struct HvfVm {
    mappings: Mutex<Vec<Mapping>>,
    gic: Mutex<Option<Arc<Mutex<HvfGicV3>>>>,
    vcpu_created: AtomicBool,
}

impl Drop for HvfVm {
    fn drop(&mut self) {
        // SAFETY: all vCPUs are destroyed before the VM (enforced by ownership).
        unsafe {
            hv_vm_destroy();
        }
    }
}

impl Vm for HvfVm {
    fn create_irq_chip(&self) -> VmResult<()> {
        // No userspace IRQ chip in M1; the managed hv_gic arrives with M2.
        Ok(())
    }

    fn register_irqfd(&self, _fd: &crate::compat::EventFd, _gsi: u32) -> VmResult<()> {
        Err(HypervisorVmError::RegisterIrqFd(anyhow!(
            "irqfd routing requires hv_gic (not yet implemented)"
        )))
    }

    fn unregister_irqfd(&self, _fd: &crate::compat::EventFd, _gsi: u32) -> VmResult<()> {
        Err(HypervisorVmError::UnregisterIrqFd(anyhow!(
            "irqfd routing requires hv_gic (not yet implemented)"
        )))
    }

    fn create_vcpu(&self, id: u32, vm_ops: Option<Arc<dyn VmOps>>) -> VmResult<Box<dyn Vcpu>> {
        let mut vcpu_id: u64 = 0;
        let mut exit: *mut HvVcpuExit = ptr::null_mut();
        // SAFETY: out-params are valid; must run on the creating thread.
        let ret = unsafe { hv_vcpu_create(&mut vcpu_id, &mut exit, ptr::null_mut()) };
        if ret != HV_SUCCESS {
            return Err(HypervisorVmError::CreateVcpu(anyhow!(
                "hv_vcpu_create failed: {:#010x}",
                ret as u32
            )));
        }
        self.vcpu_created.store(true, Ordering::SeqCst);
        Ok(Box::new(HvfVcpu {
            id: vcpu_id,
            index: id,
            exit,
            vm_ops,
        }))
    }

    fn create_vgic(&self, config: &VgicConfig) -> VmResult<Arc<Mutex<dyn Vgic>>> {
        // hv_gic_create must run after the VM exists but before any vCPU is
        // created; enforce that ordering (and single creation) here rather than
        // relying on HVF to reject a misordered call.
        if self.vcpu_created.load(Ordering::SeqCst) {
            return Err(HypervisorVmError::CreateVgic(anyhow!(
                "hv_gic must be created before any vCPU"
            )));
        }
        let mut slot = self.gic.lock().unwrap();
        if slot.is_some() {
            return Err(HypervisorVmError::CreateVgic(anyhow!(
                "GIC already created for this VM"
            )));
        }
        let gic =
            HvfGicV3::new(config).map_err(|e| HypervisorVmError::CreateVgic(anyhow!("{e}")))?;
        let gic = Arc::new(Mutex::new(gic));
        *slot = Some(gic.clone());
        Ok(gic)
    }

    fn register_ioevent(
        &self,
        _fd: &crate::compat::EventFd,
        _addr: &IoEventAddress,
        _datamatch: Option<DataMatch>,
    ) -> VmResult<()> {
        Err(HypervisorVmError::RegisterIoEvent(anyhow!(
            "ioeventfd requires the device fast-path (not yet implemented)"
        )))
    }

    fn unregister_ioevent(
        &self,
        _fd: &crate::compat::EventFd,
        _addr: &IoEventAddress,
    ) -> VmResult<()> {
        Err(HypervisorVmError::UnregisterIoEvent(anyhow!(
            "ioeventfd requires the device fast-path (not yet implemented)"
        )))
    }

    fn make_routing_entry(&self, gsi: u32, config: &InterruptSourceConfig) -> IrqRoutingEntry {
        let (address, data) = match config {
            InterruptSourceConfig::MsiIrq(cfg) => (
                ((cfg.high_addr as u64) << 32) | cfg.low_addr as u64,
                cfg.data,
            ),
            InterruptSourceConfig::LegacyIrq(_) => (0, 0),
        };
        IrqRoutingEntry::Hvf(HvfIrqRoutingEntry { gsi, address, data })
    }

    fn set_gsi_routing(&self, _entries: &[IrqRoutingEntry]) -> VmResult<()> {
        // No-op until hv_gic MSI routing exists; M1 guests are poll-driven.
        Ok(())
    }

    unsafe fn create_user_memory_region(
        &self,
        _slot: u32,
        guest_phys_addr: u64,
        memory_size: usize,
        userspace_addr: *mut u8,
        readonly: bool,
        _log_dirty_pages: bool,
    ) -> VmResult<()> {
        let mut flags = HV_MEMORY_READ | HV_MEMORY_EXEC;
        if !readonly {
            flags |= HV_MEMORY_WRITE;
        }
        // SAFETY: caller guarantees [userspace_addr, +memory_size) is valid for
        // the lifetime of the mapping (until remove_user_memory_region).
        let ret = unsafe {
            hv_vm_map(
                userspace_addr as *mut c_void,
                guest_phys_addr,
                memory_size,
                flags,
            )
        };
        if ret != HV_SUCCESS {
            return Err(HypervisorVmError::CreateUserMemory(anyhow!(
                "hv_vm_map failed: {:#010x}",
                ret as u32
            )));
        }
        self.mappings.lock().unwrap().push(Mapping {
            ipa: guest_phys_addr,
            size: memory_size,
        });
        Ok(())
    }

    unsafe fn remove_user_memory_region(
        &self,
        _slot: u32,
        guest_phys_addr: u64,
        memory_size: usize,
        _userspace_addr: *mut u8,
        _readonly: bool,
        _log_dirty_pages: bool,
    ) -> VmResult<()> {
        // SAFETY: unmaps a region previously mapped via create_user_memory_region.
        let ret = unsafe { hv_vm_unmap(guest_phys_addr, memory_size) };
        if ret != HV_SUCCESS {
            return Err(HypervisorVmError::RemoveUserMemory(anyhow!(
                "hv_vm_unmap failed: {:#010x}",
                ret as u32
            )));
        }
        self.mappings
            .lock()
            .unwrap()
            .retain(|m| m.ipa != guest_phys_addr || m.size != memory_size);
        Ok(())
    }

    fn get_preferred_target(&self, _kvi: &mut VcpuInit) -> VmResult<()> {
        Ok(())
    }

    fn start_dirty_log(&self) -> VmResult<()> {
        Err(HypervisorVmError::StartDirtyLog(anyhow!(
            "dirty-page logging is not yet implemented for HVF"
        )))
    }

    fn stop_dirty_log(&self) -> VmResult<()> {
        Err(HypervisorVmError::StopDirtyLog(anyhow!(
            "dirty-page logging is not yet implemented for HVF"
        )))
    }

    fn get_dirty_log(&self, _slot: u32, _base_gpa: u64, _memory_size: u64) -> VmResult<Vec<u64>> {
        Err(HypervisorVmError::GetDirtyLog(anyhow!(
            "dirty-page logging is not yet implemented for HVF"
        )))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ---------------------------------------------------------------------------
// Vcpu
// ---------------------------------------------------------------------------

/// One HVF vCPU. Bound to the host thread that created it.
pub struct HvfVcpu {
    id: u64,
    index: u32,
    exit: *mut HvVcpuExit,
    vm_ops: Option<Arc<dyn VmOps>>,
}

// SAFETY: HVF requires a vCPU to be created and run on the same thread; the VMM
// upholds this by owning each HvfVcpu on its dedicated vCPU thread. The raw
// `exit` pointer is owned by HVF and only dereferenced by that thread.
unsafe impl Send for HvfVcpu {}
// SAFETY: see the `Send` impl above — access is confined to the owning thread.
unsafe impl Sync for HvfVcpu {}

impl Drop for HvfVcpu {
    fn drop(&mut self) {
        // SAFETY: destroy on the owning thread, before the VM is destroyed.
        unsafe {
            hv_vcpu_destroy(self.id);
        }
    }
}

impl HvfVcpu {
    fn set_reg(&self, reg: u32, val: u64) -> CpuResult<()> {
        // SAFETY: FFI on the owning thread.
        let ret = unsafe { hv_vcpu_set_reg(self.id, reg, val) };
        if ret != HV_SUCCESS {
            return Err(HypervisorCpuError::SetRegister(anyhow!(
                "hv_vcpu_set_reg({reg}) failed: {:#010x}",
                ret as u32
            )));
        }
        Ok(())
    }

    fn get_reg(&self, reg: u32) -> CpuResult<u64> {
        let mut v = 0u64;
        // SAFETY: FFI on the owning thread; out-param valid.
        let ret = unsafe { hv_vcpu_get_reg(self.id, reg, &mut v) };
        if ret != HV_SUCCESS {
            return Err(HypervisorCpuError::GetRegister(anyhow!(
                "hv_vcpu_get_reg({reg}) failed: {:#010x}",
                ret as u32
            )));
        }
        Ok(v)
    }

    fn set_sysreg(&self, reg: u16, val: u64) -> CpuResult<()> {
        // SAFETY: FFI on the owning thread.
        let ret = unsafe { hv_vcpu_set_sys_reg(self.id, reg, val) };
        if ret != HV_SUCCESS {
            return Err(HypervisorCpuError::SetSysRegister(anyhow!(
                "hv_vcpu_set_sys_reg({reg:#06x}) failed: {:#010x}",
                ret as u32
            )));
        }
        Ok(())
    }

    fn get_sysreg(&self, reg: u16) -> CpuResult<u64> {
        let mut v = 0u64;
        // SAFETY: FFI on the owning thread; out-param valid.
        let ret = unsafe { hv_vcpu_get_sys_reg(self.id, reg, &mut v) };
        if ret != HV_SUCCESS {
            return Err(HypervisorCpuError::GetSysRegister(anyhow!(
                "hv_vcpu_get_sys_reg({reg:#06x}) failed: {:#010x}",
                ret as u32
            )));
        }
        Ok(v)
    }

    /// Establish this vCPU's affinity in MPIDR_EL1.
    ///
    /// HVF leaves MPIDR_EL1 reading 0, which lacks the architectural RES1 bit
    /// and — more importantly — leaves Apple's managed GIC unable to associate
    /// the vCPU with its redistributor (the GIC keys redistributors by MPIDR
    /// affinity). Without this, an asserted SPI becomes pending in the
    /// distributor but never forwards to the CPU interface, so the guest never
    /// takes the interrupt. Pack the linear cpu index into the architectural
    /// Aff0[7:0]/Aff1[15:8]/Aff2[23:16]/Aff3[39:32] fields. This is verified for
    /// vCPU0; the exact hv_gic redistributor affinity ordering for multiple
    /// vCPUs remains to be validated when HVF multi-vCPU support lands.
    fn set_mpidr_affinity(&self, cpu_id: u32) -> CpuResult<()> {
        let aff = (u64::from(cpu_id) & 0xff)
            | ((u64::from(cpu_id) >> 8 & 0xff) << 8)
            | ((u64::from(cpu_id) >> 16 & 0xff) << 16)
            | ((u64::from(cpu_id) >> 24 & 0xff) << 32);
        self.set_sysreg(SYSREG_MPIDR_EL1, MPIDR_RES1 | aff)
    }

    /// Read a managed-GIC CPU-interface (ICC) register for this vCPU.
    fn get_icc_reg(&self, reg: u16) -> CpuResult<u64> {
        let mut v = 0u64;
        // SAFETY: FFI on the owning thread; out-param valid.
        let ret = unsafe { hv_gic_get_icc_reg(self.id, reg, &mut v) };
        if ret != HV_SUCCESS {
            return Err(HypervisorCpuError::GetSysRegister(anyhow!(
                "hv_gic_get_icc_reg({reg:#06x}) failed: {:#010x}",
                ret as u32
            )));
        }
        Ok(v)
    }

    /// Write a managed-GIC CPU-interface (ICC) register for this vCPU.
    fn set_icc_reg(&self, reg: u16, val: u64) -> CpuResult<()> {
        // SAFETY: FFI on the owning thread.
        let ret = unsafe { hv_gic_set_icc_reg(self.id, reg, val) };
        if ret != HV_SUCCESS {
            return Err(HypervisorCpuError::SetSysRegister(anyhow!(
                "hv_gic_set_icc_reg({reg:#06x}) failed: {:#010x}",
                ret as u32
            )));
        }
        Ok(())
    }

    /// Service a stage-2 data abort (MMIO) by decoding ESR and calling VmOps.
    fn handle_data_abort(&self, esr: u64, ipa: u64) -> CpuResult<()> {
        let iss = esr & 0x01ff_ffff;
        let isv = (iss >> 24) & 1;
        if isv == 0 {
            return Err(HypervisorCpuError::RunVcpu(anyhow!(
                "MMIO data abort without valid ISS at IPA {ipa:#x} (esr={esr:#x})"
            )));
        }
        let sas = ((iss >> 22) & 0x3) as u32; // 0=B,1=H,2=W,3=D
        let srt = ((iss >> 16) & 0x1f) as u32; // transfer register index
        let is_write = (iss >> 6) & 1 == 1;
        let access = 1usize << sas;

        let Some(vm_ops) = self.vm_ops.as_ref() else {
            return Err(HypervisorCpuError::RunVcpu(anyhow!(
                "MMIO at {ipa:#x} but no VmOps registered"
            )));
        };

        if is_write {
            let val = if srt == 31 { 0 } else { self.get_reg(srt)? };
            let bytes = val.to_le_bytes();
            vm_ops
                .mmio_write(ipa, &bytes[..access])
                .map_err(|e| HypervisorCpuError::RunVcpu(e.into()))?;
        } else {
            let mut bytes = [0u8; 8];
            vm_ops
                .mmio_read(ipa, &mut bytes[..access])
                .map_err(|e| HypervisorCpuError::RunVcpu(e.into()))?;
            if srt != 31 {
                self.set_reg(srt, u64::from_le_bytes(bytes))?;
            }
        }

        // Advance PC past the faulting load/store.
        let pc = self.get_reg(HV_REG_PC)?;
        self.set_reg(HV_REG_PC, pc.wrapping_add(4))?;
        Ok(())
    }
}

impl Vcpu for HvfVcpu {
    fn create_standard_regs(&self) -> StandardRegisters {
        StandardRegisters::Hvf(HvfStandardRegisters::default())
    }

    fn get_regs(&self) -> CpuResult<StandardRegisters> {
        let mut regs = [0u64; 31];
        for (i, slot) in regs.iter_mut().enumerate() {
            *slot = self.get_reg(i as u32)?;
        }
        Ok(StandardRegisters::Hvf(HvfStandardRegisters {
            regs,
            sp: self.get_sysreg(SYSREG_SP_EL1)?,
            pc: self.get_reg(HV_REG_PC)?,
            pstate: self.get_reg(HV_REG_CPSR)?,
        }))
    }

    fn set_regs(&self, regs: &StandardRegisters) -> CpuResult<()> {
        // Refutable when several backends are compiled in; on an HVF-only build
        // there is a single variant, hence the allow.
        #[allow(irrefutable_let_patterns)]
        let StandardRegisters::Hvf(r) = regs else {
            return Err(HypervisorCpuError::SetStandardRegs(anyhow!(
                "expected HVF StandardRegisters"
            )));
        };
        for (i, v) in r.regs.iter().enumerate() {
            self.set_reg(i as u32, *v)?;
        }
        self.set_reg(HV_REG_PC, r.pc)?;
        self.set_reg(HV_REG_CPSR, r.pstate)?;
        self.set_sysreg(SYSREG_SP_EL1, r.sp)?;
        Ok(())
    }

    fn get_mp_state(&self) -> CpuResult<MpState> {
        Ok(MpState::Hvf)
    }

    fn set_mp_state(&self, _mp_state: MpState) -> CpuResult<()> {
        Ok(())
    }

    fn vcpu_init(&self, _kvi: &VcpuInit) -> CpuResult<()> {
        Ok(())
    }

    fn vcpu_finalize(&self, _feature: i32) -> CpuResult<()> {
        Ok(())
    }

    fn vcpu_get_finalized_features(&self) -> i32 {
        0
    }

    fn vcpu_set_processor_features(
        &self,
        _vm: &dyn Vm,
        _kvi: &mut VcpuInit,
        _id: u32,
    ) -> CpuResult<()> {
        Ok(())
    }

    fn create_vcpu_init(&self) -> VcpuInit {
        VcpuInit::Hvf(HvfVcpuInit::default())
    }

    fn get_reg_list(&self, reg_list: &mut RegList) -> CpuResult<()> {
        #[allow(irrefutable_let_patterns)]
        if let RegList::Hvf(list) = reg_list {
            list.regs = SNAPSHOT_SYS_REGS.iter().map(|&r| r as u64).collect();
            Ok(())
        } else {
            Err(HypervisorCpuError::GetRegList(anyhow!(
                "expected HVF RegList"
            )))
        }
    }

    fn get_sys_reg(&self, sys_reg: u32) -> CpuResult<u64> {
        self.get_sysreg(sys_reg as u16)
    }

    fn setup_regs(&self, cpu_id: u32, boot_ip: u64, fdt_start: u64) -> CpuResult<()> {
        // EL1h, with DAIF interrupts masked, ready for a cold boot.
        self.set_reg(HV_REG_CPSR, PSTATE_EL1H_DAIF)?;
        self.set_reg(HV_REG_PC, boot_ip)?;
        // Linux/PSCI boot protocol: x0 = device-tree blob address.
        self.set_reg(0, fdt_start)?;
        self.set_mpidr_affinity(cpu_id)?;
        Ok(())
    }

    fn has_pmu_support(&self) -> bool {
        false
    }

    fn init_pmu(&self, _irq: u32) -> CpuResult<()> {
        Err(HypervisorCpuError::InitializePmu(anyhow!(
            "PMU is not yet implemented for HVF"
        )))
    }

    fn state(&self) -> CpuResult<CpuState> {
        let mut gpr = [0u64; 31];
        for (i, slot) in gpr.iter_mut().enumerate() {
            *slot = self.get_reg(i as u32)?;
        }
        let mut sysregs = Vec::with_capacity(SNAPSHOT_SYS_REGS.len());
        for &id in SNAPSHOT_SYS_REGS {
            sysregs.push((id, self.get_sysreg(id)?));
        }
        // Capture the managed-GIC CPU-interface registers. These are absent on a
        // GIC-less VM; in that case the first read fails and we record none.
        let mut gic_icc = Vec::new();
        if self.get_icc_reg(GIC_ICC_SNAPSHOT_REGS[0]).is_ok() {
            for &reg in GIC_ICC_SNAPSHOT_REGS {
                gic_icc.push((reg, self.get_icc_reg(reg)?));
            }
        }
        Ok(CpuState::Hvf(VcpuHvfState {
            gpr,
            pc: self.get_reg(HV_REG_PC)?,
            cpsr: self.get_reg(HV_REG_CPSR)?,
            sp_el1: self.get_sysreg(SYSREG_SP_EL1)?,
            sysregs,
            gic_icc,
            mp_state_running: true,
        }))
    }

    fn set_state(&self, state: &CpuState) -> CpuResult<()> {
        #[allow(irrefutable_let_patterns)]
        let CpuState::Hvf(s) = state else {
            return Err(HypervisorCpuError::SetRegister(anyhow!(
                "expected HVF CpuState"
            )));
        };
        for (i, v) in s.gpr.iter().enumerate() {
            self.set_reg(i as u32, *v)?;
        }
        self.set_reg(HV_REG_PC, s.pc)?;
        self.set_reg(HV_REG_CPSR, s.cpsr)?;
        // Some EL1 system registers may be read-only on a given core; restoring
        // them is best-effort and must not abort the whole restore.
        let _ = self.set_sysreg(SYSREG_SP_EL1, s.sp_el1);
        let mut restored_mpidr = false;
        for &(id, v) in &s.sysregs {
            if id == SYSREG_MPIDR_EL1 {
                // MPIDR affinity is load-bearing for GIC interrupt delivery, so
                // it is restored with a hard failure rather than best-effort.
                self.set_sysreg(SYSREG_MPIDR_EL1, v)?;
                restored_mpidr = true;
            } else {
                let _ = self.set_sysreg(id, v);
            }
        }
        if !restored_mpidr {
            // Older snapshots predate capturing MPIDR; synthesize it from this
            // vCPU's index so a restored guest can still take interrupts.
            self.set_mpidr_affinity(self.index)?;
        }
        // Restore the managed-GIC CPU-interface registers (priority mask, group
        // enables, active priorities, ...). These are load-bearing for delivery
        // and live in the GIC, not in the vCPU sysreg file. They are restored
        // after MPIDR so the vCPU is already associated with its redistributor.
        for &(reg, v) in &s.gic_icc {
            self.set_icc_reg(reg, v)?;
        }
        Ok(())
    }

    fn run(&mut self) -> std::result::Result<VmExit, HypervisorCpuError> {
        // SAFETY: FFI on the owning thread.
        let ret = unsafe { hv_vcpu_run(self.id) };
        if ret != HV_SUCCESS {
            return Err(HypervisorCpuError::RunVcpu(anyhow!(
                "hv_vcpu_run failed: {:#010x}",
                ret as u32
            )));
        }
        // SAFETY: `exit` is owned by HVF and valid until the next run() call.
        let exit = unsafe { &*self.exit };
        match exit.reason {
            HV_EXIT_REASON_EXCEPTION => {
                let esr = exit.exception.syndrome;
                let ipa = exit.exception.physical_address;
                let ec = (esr >> 26) & 0x3f;
                match ec {
                    EC_DATA_ABORT_LOWER | EC_DATA_ABORT_SAME => {
                        self.handle_data_abort(esr, ipa)?;
                        Ok(VmExit::Ignore)
                    }
                    EC_WFX => {
                        // Trapped WFI/WFE: the guest is idling for an interrupt.
                        // Advance past the instruction so that on re-entry any
                        // interrupt the GIC has since made pending (an asserted
                        // SPI or the virtual timer) is taken. ESR bit0 (TI)
                        // distinguishes WFE from WFI; both are treated the same.
                        // NOTE: this only handles the trapped-WFx exit. The
                        // blocked-in-kernel WFI wakeup path (which would need an
                        // explicit hv_vcpus_exit kick after a cross-thread
                        // injection) is not yet exercised or verified.
                        let pc = self.get_reg(HV_REG_PC)?;
                        self.set_reg(HV_REG_PC, pc.wrapping_add(4))?;
                        Ok(VmExit::Ignore)
                    }
                    EC_HVC64 => {
                        // PSCI: x0 carries the function id. PC already points past
                        // the HVC, so do not advance it here.
                        let func = self.get_reg(0)?;
                        match func {
                            PSCI_SYSTEM_OFF => Ok(VmExit::Shutdown),
                            PSCI_SYSTEM_RESET => Ok(VmExit::Reset),
                            _ => {
                                // Unknown PSCI/HVC call: report success (0) and
                                // continue so the guest keeps running.
                                self.set_reg(0, 0)?;
                                Ok(VmExit::Ignore)
                            }
                        }
                    }
                    _ => Err(HypervisorCpuError::RunVcpu(anyhow!(
                        "unhandled guest exception: EC={ec:#x} ESR={esr:#x} IPA={ipa:#x} (vcpu {})",
                        self.index
                    ))),
                }
            }
            HV_EXIT_REASON_VTIMER_ACTIVATED => {
                // The virtual timer fired and HVF auto-masked it on exit. With
                // the managed GIC the timer is normally delivered as GIC PPI 27
                // without this exit at all (see hvf_guest_takes_virtual_timer);
                // this branch is the defensive path for when HVF does surface
                // the activation. Re-arm the timer so the GIC re-evaluates and
                // delivers PPI 27 — without asserting the raw IRQ line, which
                // would bypass the GIC and deliver a spurious interrupt.
                if let Err(rc) = gic::rearm_vtimer(self.id) {
                    return Err(HypervisorCpuError::RunVcpu(anyhow!(
                        "failed to re-arm vtimer: {:#010x}",
                        rc as u32
                    )));
                }
                Ok(VmExit::Ignore)
            }
            HV_EXIT_REASON_CANCELED => Ok(VmExit::Ignore),
            other => Err(HypervisorCpuError::RunVcpu(anyhow!(
                "unexpected HVF exit reason: {other}"
            ))),
        }
    }
}
