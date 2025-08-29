// Copyright © 2020, Oracle and/or its affiliates.
//
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
//

use std::collections::BTreeMap;
#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
use std::io::Write;
#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
use std::mem::size_of;
use std::os::unix::thread::JoinHandleExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::{cmp, io, result, thread};

#[cfg(not(target_arch = "riscv64"))]
use acpi_tables::sdt::Sdt;
use acpi_tables::{aml, Aml};
use anyhow::anyhow;
#[cfg(target_arch = "x86_64")]
use arch::x86_64::get_x2apic_id;
use arch::{EntryPoint, NumaNodes};
#[cfg(target_arch = "aarch64")]
use devices::gic::Gic;
use devices::interrupt_controller::InterruptController;
#[cfg(all(target_arch = "aarch64", feature = "guest_debug"))]
use gdbstub_arch::aarch64::reg::AArch64CoreRegs as CoreRegs;
#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
use gdbstub_arch::x86::reg::{X86SegmentRegs, X86_64CoreRegs as CoreRegs};
#[cfg(all(target_arch = "aarch64", feature = "guest_debug"))]
use hypervisor::arch::aarch64::regs::{ID_AA64MMFR0_EL1, TCR_EL1, TTBR1_EL1};
#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
use hypervisor::arch::x86::msr_index;
#[cfg(target_arch = "x86_64")]
use hypervisor::arch::x86::CpuIdEntry;
#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
use hypervisor::arch::x86::MsrEntry;
#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
use hypervisor::arch::x86::SpecialRegisters;
#[cfg(feature = "tdx")]
use hypervisor::kvm::{TdxExitDetails, TdxExitStatus};
#[cfg(target_arch = "x86_64")]
use hypervisor::CpuVendor;
#[cfg(feature = "kvm")]
use hypervisor::HypervisorType;
#[cfg(feature = "guest_debug")]
use hypervisor::StandardRegisters;
use hypervisor::{CpuState, HypervisorCpuError, VmExit, VmOps};
use libc::{c_void, siginfo_t};
#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
use linux_loader::elf::Elf64_Nhdr;
use seccompiler::{apply_filter, SeccompAction};
use thiserror::Error;
use tracer::trace_scoped;
use vm_device::BusDevice;
#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
use vm_memory::ByteValued;
#[cfg(feature = "guest_debug")]
use vm_memory::{Bytes, GuestAddressSpace};
use vm_memory::{GuestAddress, GuestMemoryAtomic};
use vm_migration::{
    snapshot_from_id, Migratable, MigratableError, Pausable, Snapshot, SnapshotData, Snapshottable,
    Transportable,
};
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::signal::{register_signal_handler, SIGRTMIN};
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
use crate::coredump::{
    CpuElf64Writable, CpuSegment, CpuState as DumpCpusState, DumpState, Elf64Writable,
    GuestDebuggableError, NoteDescType, X86_64ElfPrStatus, X86_64UserRegs, COREDUMP_NAME_SIZE,
    NT_PRSTATUS,
};
#[cfg(feature = "guest_debug")]
use crate::gdb::{get_raw_tid, Debuggable, DebuggableError};
use crate::seccomp_filters::{get_seccomp_filter, Thread};
#[cfg(target_arch = "x86_64")]
use crate::vm::physical_bits;
use crate::vm_config::CpusConfig;
use crate::{GuestMemoryMmap, CPU_MANAGER_SNAPSHOT_ID};

#[cfg(all(target_arch = "aarch64", feature = "guest_debug"))]
/// Extract the specified bits of a 64-bit integer.
/// For example, to extrace 2 bits from offset 1 (zero based) of `6u64`,
/// following expression should return 3 (`0b11`):
/// `extract_bits_64!(0b0000_0110u64, 1, 2)`
///
macro_rules! extract_bits_64 {
    ($value: tt, $offset: tt, $length: tt) => {
        ($value >> $offset) & (!0u64 >> (64 - $length))
    };
}

#[cfg(all(target_arch = "aarch64", feature = "guest_debug"))]
macro_rules! extract_bits_64_without_offset {
    ($value: tt, $length: tt) => {
        $value & (!0u64 >> (64 - $length))
    };
}

pub const CPU_MANAGER_ACPI_SIZE: usize = 0xc;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Error creating vCPU")]
    VcpuCreate(#[source] anyhow::Error),

    #[error("Error running vCPU")]
    VcpuRun(#[source] anyhow::Error),

    #[error("Error spawning vCPU thread")]
    VcpuSpawn(#[source] io::Error),

    #[error("Error generating common CPUID")]
    CommonCpuId(#[source] arch::Error),

    #[error("Error configuring vCPU")]
    VcpuConfiguration(#[source] arch::Error),

    #[error("Still pending removed vCPU")]
    VcpuPendingRemovedVcpu,

    #[cfg(target_arch = "aarch64")]
    #[error("Error fetching preferred target")]
    VcpuArmPreferredTarget(#[source] hypervisor::HypervisorVmError),

    #[cfg(target_arch = "aarch64")]
    #[error("Error setting vCPU processor features")]
    VcpuSetProcessorFeatures(#[source] hypervisor::HypervisorCpuError),

    #[cfg(target_arch = "aarch64")]
    #[error("Error initialising vCPU")]
    VcpuArmInit(#[source] hypervisor::HypervisorCpuError),

    #[cfg(target_arch = "aarch64")]
    #[error("Error finalising vCPU")]
    VcpuArmFinalize(#[source] hypervisor::HypervisorCpuError),

    #[cfg(target_arch = "aarch64")]
    #[error("Error initialising GICR base address")]
    VcpuSetGicrBaseAddr(#[source] hypervisor::HypervisorCpuError),

    #[error("Failed to join on vCPU threads: {0:?}")]
    ThreadCleanup(std::boxed::Box<dyn std::any::Any + std::marker::Send>),

    #[error("Error adding CpuManager to MMIO bus")]
    BusError(#[source] vm_device::BusError),

    #[error("Requested zero vCPUs")]
    DesiredVCpuCountIsZero,

    #[error("Requested vCPUs exceed maximum")]
    DesiredVCpuCountExceedsMax,

    #[error("Cannot create seccomp filter")]
    CreateSeccompFilter(#[source] seccompiler::Error),

    #[error("Cannot apply seccomp filter")]
    ApplySeccompFilter(#[source] seccompiler::Error),

    #[error("Error starting vCPU after restore")]
    StartRestoreVcpu(#[source] anyhow::Error),

    #[error("Unexpected VmExit")]
    UnexpectedVmExit,

    #[error("Failed to allocate MMIO address for CpuManager")]
    AllocateMmmioAddress,

    #[cfg(feature = "tdx")]
    #[error("Error initializing TDX")]
    InitializeTdx(#[source] hypervisor::HypervisorCpuError),

    #[cfg(target_arch = "aarch64")]
    #[error("Error initializing PMU")]
    InitPmu(#[source] hypervisor::HypervisorCpuError),

    #[cfg(feature = "guest_debug")]
    #[error("Error during CPU debug")]
    CpuDebug(#[source] hypervisor::HypervisorCpuError),

    #[cfg(feature = "guest_debug")]
    #[error("Error translating virtual address")]
    TranslateVirtualAddress(#[source] anyhow::Error),

    #[cfg(target_arch = "x86_64")]
    #[error("Error setting up AMX")]
    AmxEnable(#[source] anyhow::Error),

    #[error("Maximum number of vCPUs exceeds host limit")]
    MaximumVcpusExceeded,

    #[cfg(feature = "sev_snp")]
    #[error("Failed to set sev control register")]
    SetSevControlRegister(#[source] hypervisor::HypervisorCpuError),

    #[cfg(target_arch = "x86_64")]
    #[error("Failed to inject NMI")]
    NmiError(#[source] hypervisor::HypervisorCpuError),
}
pub type Result<T> = result::Result<T, Error>;

#[cfg(target_arch = "x86_64")]
#[allow(dead_code)]
#[repr(C, packed)]
#[derive(IntoBytes, Immutable, FromBytes)]
struct LocalX2Apic {
    pub r#type: u8,
    pub length: u8,
    pub _reserved: u16,
    pub apic_id: u32,
    pub flags: u32,
    pub processor_id: u32,
}

#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Default, IntoBytes, Immutable, FromBytes)]
struct Ioapic {
    pub r#type: u8,
    pub length: u8,
    pub ioapic_id: u8,
    _reserved: u8,
    pub apic_address: u32,
    pub gsi_base: u32,
}

#[cfg(target_arch = "aarch64")]
#[allow(dead_code)]
#[repr(C, packed)]
#[derive(IntoBytes, Immutable, FromBytes)]
struct GicC {
    pub r#type: u8,
    pub length: u8,
    pub reserved0: u16,
    pub cpu_interface_number: u32,
    pub uid: u32,
    pub flags: u32,
    pub parking_version: u32,
    pub performance_interrupt: u32,
    pub parked_address: u64,
    pub base_address: u64,
    pub gicv_base_address: u64,
    pub gich_base_address: u64,
    pub vgic_interrupt: u32,
    pub gicr_base_address: u64,
    pub mpidr: u64,
    pub proc_power_effi_class: u8,
    pub reserved1: u8,
    pub spe_overflow_interrupt: u16,
}

#[cfg(target_arch = "aarch64")]
#[allow(dead_code)]
#[repr(C, packed)]
#[derive(IntoBytes, Immutable, FromBytes)]
struct GicD {
    pub r#type: u8,
    pub length: u8,
    pub reserved0: u16,
    pub gic_id: u32,
    pub base_address: u64,
    pub global_irq_base: u32,
    pub version: u8,
    pub reserved1: [u8; 3],
}

#[cfg(target_arch = "aarch64")]
#[allow(dead_code)]
#[repr(C, packed)]
#[derive(IntoBytes, Immutable, FromBytes)]
struct GicR {
    pub r#type: u8,
    pub length: u8,
    pub reserved: u16,
    pub base_address: u64,
    pub range_length: u32,
}

#[cfg(target_arch = "aarch64")]
#[allow(dead_code)]
#[repr(C, packed)]
#[derive(IntoBytes, Immutable, FromBytes)]
struct GicIts {
    pub r#type: u8,
    pub length: u8,
    pub reserved0: u16,
    pub translation_id: u32,
    pub base_address: u64,
    pub reserved1: u32,
}

#[cfg(target_arch = "aarch64")]
#[allow(dead_code)]
#[repr(C, packed)]
#[derive(IntoBytes, Immutable, FromBytes)]
struct ProcessorHierarchyNode {
    pub r#type: u8,
    pub length: u8,
    pub reserved: u16,
    pub flags: u32,
    pub parent: u32,
    pub acpi_processor_id: u32,
    pub num_private_resources: u32,
}

#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Default, IntoBytes, Immutable, FromBytes)]
struct InterruptSourceOverride {
    pub r#type: u8,
    pub length: u8,
    pub bus: u8,
    pub source: u8,
    pub gsi: u32,
    pub flags: u16,
}

#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
macro_rules! round_up {
    ($n:expr,$d:expr) => {
        (($n / ($d + 1)) + 1) * $d
    };
}

/// A wrapper around creating and using a kvm-based VCPU.
pub struct Vcpu {
    // The hypervisor abstracted CPU.
    vcpu: Arc<dyn hypervisor::Vcpu>,
    id: u32,
    #[cfg(target_arch = "aarch64")]
    mpidr: u64,
    saved_state: Option<CpuState>,
    #[cfg(target_arch = "x86_64")]
    vendor: CpuVendor,
}

impl Vcpu {
    /// Constructs a new VCPU for `vm`.
    ///
    /// # Arguments
    ///
    /// * `id` - Represents the CPU number between [0, max vcpus).
    /// * `vm` - The virtual machine this vcpu will get attached to.
    /// * `vm_ops` - Optional object for exit handling.
    /// * `cpu_vendor` - CPU vendor as reported by __cpuid(0x0)
    pub fn new(
        id: u32,
        apic_id: u32,
        vm: &Arc<dyn hypervisor::Vm>,
        vm_ops: Option<Arc<dyn VmOps>>,
        #[cfg(target_arch = "x86_64")] cpu_vendor: CpuVendor,
    ) -> Result<Self> {
        let vcpu = vm
            .create_vcpu(apic_id, vm_ops)
            .map_err(|e| Error::VcpuCreate(e.into()))?;
        // Initially the cpuid per vCPU is the one supported by this VM.
        Ok(Vcpu {
            vcpu,
            id,
            #[cfg(target_arch = "aarch64")]
            mpidr: 0,
            saved_state: None,
            #[cfg(target_arch = "x86_64")]
            vendor: cpu_vendor,
        })
    }

    /// Configures a vcpu and should be called once per vcpu when created.
    ///
    /// # Arguments
    ///
    /// * `kernel_entry_point` - Kernel entry point address in guest memory and boot protocol used.
    /// * `guest_memory` - Guest memory.
    /// * `cpuid` - (x86_64) CpuId, wrapper over the `kvm_cpuid2` structure.
    pub fn configure(
        &mut self,
        #[cfg(target_arch = "aarch64")] vm: &Arc<dyn hypervisor::Vm>,
        boot_setup: Option<(EntryPoint, &GuestMemoryAtomic<GuestMemoryMmap>)>,
        #[cfg(target_arch = "x86_64")] cpuid: Vec<CpuIdEntry>,
        #[cfg(target_arch = "x86_64")] kvm_hyperv: bool,
        #[cfg(target_arch = "x86_64")] topology: (u16, u16, u16, u16),
    ) -> Result<()> {
        #[cfg(target_arch = "aarch64")]
        {
            self.init(vm)?;
            self.mpidr = arch::configure_vcpu(&self.vcpu, self.id, boot_setup)
                .map_err(Error::VcpuConfiguration)?;
        }
        #[cfg(target_arch = "riscv64")]
        arch::configure_vcpu(&self.vcpu, self.id, boot_setup).map_err(Error::VcpuConfiguration)?;
        info!("Configuring vCPU: cpu_id = {}", self.id);
        #[cfg(target_arch = "x86_64")]
        arch::configure_vcpu(
            &self.vcpu,
            self.id,
            boot_setup,
            cpuid,
            kvm_hyperv,
            self.vendor,
            topology,
        )
        .map_err(Error::VcpuConfiguration)?;

        Ok(())
    }

    /// Gets the MPIDR register value.
    #[cfg(target_arch = "aarch64")]
    pub fn get_mpidr(&self) -> u64 {
        self.mpidr
    }

    /// Gets the saved vCPU state.
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    pub fn get_saved_state(&self) -> Option<CpuState> {
        self.saved_state.clone()
    }

    /// Initializes an aarch64 specific vcpu for booting Linux.
    #[cfg(target_arch = "aarch64")]
    pub fn init(&self, vm: &Arc<dyn hypervisor::Vm>) -> Result<()> {
        use std::arch::is_aarch64_feature_detected;
        #[allow(clippy::nonminimal_bool)]
        let sve_supported =
            is_aarch64_feature_detected!("sve") || is_aarch64_feature_detected!("sve2");
        let mut kvi = self.vcpu.create_vcpu_init();

        // This reads back the kernel's preferred target type.
        vm.get_preferred_target(&mut kvi)
            .map_err(Error::VcpuArmPreferredTarget)?;

        self.vcpu
            .vcpu_set_processor_features(vm, &mut kvi, self.id)
            .map_err(Error::VcpuSetProcessorFeatures)?;

        self.vcpu.vcpu_init(&kvi).map_err(Error::VcpuArmInit)?;

        if sve_supported {
            let finalized_features = self.vcpu.vcpu_get_finalized_features();
            self.vcpu
                .vcpu_finalize(finalized_features)
                .map_err(Error::VcpuArmFinalize)?;
        }
        Ok(())
    }

    /// Runs the VCPU until it exits, returning the reason.
    ///
    /// Note that the state of the VCPU and associated VM must be setup first for this to do
    /// anything useful.
    pub fn run(&self) -> std::result::Result<VmExit, HypervisorCpuError> {
        self.vcpu.run()
    }

    #[cfg(feature = "sev_snp")]
    pub fn set_sev_control_register(&self, vmsa_pfn: u64) -> Result<()> {
        self.vcpu
            .set_sev_control_register(vmsa_pfn)
            .map_err(Error::SetSevControlRegister)
    }

    ///
    /// Sets the vCPU's GIC redistributor base address.
    ///
    #[cfg(target_arch = "aarch64")]
    pub fn set_gic_redistributor_addr(
        &self,
        base_redist_addr: u64,
        redist_size: u64,
    ) -> Result<()> {
        let gicr_base = base_redist_addr + (arch::layout::GIC_V3_REDIST_SIZE * self.id as u64);
        assert!(gicr_base + arch::layout::GIC_V3_REDIST_SIZE <= base_redist_addr + redist_size);
        self.vcpu
            .set_gic_redistributor_addr(gicr_base)
            .map_err(Error::VcpuSetGicrBaseAddr)?;
        Ok(())
    }
}

impl Pausable for Vcpu {}
impl Snapshottable for Vcpu {
    fn id(&self) -> String {
        self.id.to_string()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        let saved_state = self
            .vcpu
            .state()
            .map_err(|e| MigratableError::Snapshot(anyhow!("Could not get vCPU state {:?}", e)))?;

        self.saved_state = Some(saved_state.clone());

        Ok(Snapshot::from_data(SnapshotData::new_from_state(
            &saved_state,
        )?))
    }
}

pub struct CpuManager {
    config: CpusConfig,
    #[cfg_attr(target_arch = "aarch64", allow(dead_code))]
    interrupt_controller: Option<Arc<Mutex<dyn InterruptController>>>,
    #[cfg(target_arch = "x86_64")]
    cpuid: Vec<CpuIdEntry>,
    #[cfg_attr(target_arch = "aarch64", allow(dead_code))]
    vm: Arc<dyn hypervisor::Vm>,
    vcpus_kill_signalled: Arc<AtomicBool>,
    vcpus_pause_signalled: Arc<AtomicBool>,
    vcpus_kick_signalled: Arc<AtomicBool>,
    exit_evt: EventFd,
    #[cfg_attr(target_arch = "aarch64", allow(dead_code))]
    reset_evt: EventFd,
    #[cfg(feature = "guest_debug")]
    vm_debug_evt: EventFd,
    vcpu_states: Vec<VcpuState>,
    selected_cpu: u8,
    vcpus: Vec<Arc<Mutex<Vcpu>>>,
    seccomp_action: SeccompAction,
    vm_ops: Arc<dyn VmOps>,
    #[cfg_attr(target_arch = "aarch64", allow(dead_code))]
    acpi_address: Option<GuestAddress>,
    proximity_domain_per_cpu: BTreeMap<u32, u32>,
    affinity: BTreeMap<u32, Vec<usize>>,
    dynamic: bool,
    hypervisor: Arc<dyn hypervisor::Hypervisor>,
    #[cfg(feature = "sev_snp")]
    sev_snp_enabled: bool,
}

const CPU_ENABLE_FLAG: usize = 0;
const CPU_INSERTING_FLAG: usize = 1;
const CPU_REMOVING_FLAG: usize = 2;
const CPU_EJECT_FLAG: usize = 3;

const CPU_STATUS_OFFSET: u64 = 4;
const CPU_SELECTION_OFFSET: u64 = 0;

impl BusDevice for CpuManager {
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        // The Linux kernel, quite reasonably, doesn't zero the memory it gives us.
        data.fill(0);

        match offset {
            CPU_SELECTION_OFFSET => {
                data[0] = self.selected_cpu;
            }
            CPU_STATUS_OFFSET => {
                if (self.selected_cpu as u32) < self.max_vcpus() {
                    let state = &self.vcpu_states[usize::from(self.selected_cpu)];
                    if state.active() {
                        data[0] |= 1 << CPU_ENABLE_FLAG;
                    }
                    if state.inserting {
                        data[0] |= 1 << CPU_INSERTING_FLAG;
                    }
                    if state.removing {
                        data[0] |= 1 << CPU_REMOVING_FLAG;
                    }
                } else {
                    warn!("Out of range vCPU id: {}", self.selected_cpu);
                }
            }
            _ => {
                warn!(
                    "Unexpected offset for accessing CPU manager device: {:#}",
                    offset
                );
            }
        }
    }

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        match offset {
            CPU_SELECTION_OFFSET => {
                self.selected_cpu = data[0];
            }
            CPU_STATUS_OFFSET => {
                if (self.selected_cpu as u32) < self.max_vcpus() {
                    let state = &mut self.vcpu_states[usize::from(self.selected_cpu)];
                    // The ACPI code writes back a 1 to acknowledge the insertion
                    if (data[0] & (1 << CPU_INSERTING_FLAG) == 1 << CPU_INSERTING_FLAG)
                        && state.inserting
                    {
                        state.inserting = false;
                    }
                    // Ditto for removal
                    if (data[0] & (1 << CPU_REMOVING_FLAG) == 1 << CPU_REMOVING_FLAG)
                        && state.removing
                    {
                        state.removing = false;
                    }
                    // Trigger removal of vCPU
                    if data[0] & (1 << CPU_EJECT_FLAG) == 1 << CPU_EJECT_FLAG {
                        if let Err(e) = self.remove_vcpu(self.selected_cpu as u32) {
                            error!("Error removing vCPU: {:?}", e);
                        }
                    }
                } else {
                    warn!("Out of range vCPU id: {}", self.selected_cpu);
                }
            }
            _ => {
                warn!(
                    "Unexpected offset for accessing CPU manager device: {:#}",
                    offset
                );
            }
        }
        None
    }
}

#[derive(Default)]
struct VcpuState {
    inserting: bool,
    removing: bool,
    pending_removal: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
    kill: Arc<AtomicBool>,
    vcpu_run_interrupted: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
}

impl VcpuState {
    fn active(&self) -> bool {
        self.handle.is_some()
    }

    /// Sends a signal to the underlying thread.
    ///
    /// Please call [`Self::wait_until_signal_acknowledged`] afterward to block
    /// until the vCPU thread has acknowledged the signal.
    fn signal_thread(&self) {
        if let Some(handle) = self.handle.as_ref() {
            // SAFETY: FFI call with correct arguments
            unsafe {
                libc::pthread_kill(handle.as_pthread_t() as _, SIGRTMIN());
            }
        }
    }

    /// Blocks until the vCPU thread has acknowledged the signal.
    ///
    /// This is the counterpart of [`Self::signal_thread`].
    fn wait_until_signal_acknowledged(&self) {
        if let Some(_handle) = self.handle.as_ref() {
            loop {
                if self.vcpu_run_interrupted.load(Ordering::SeqCst) {
                    break;
                } else {
                    // This is more effective than thread::yield_now() at
                    // avoiding a priority inversion with the vCPU thread
                    thread::sleep(std::time::Duration::from_millis(1));
                }
            }
        }
    }

    fn join_thread(&mut self) -> Result<()> {
        if let Some(handle) = self.handle.take() {
            handle.join().map_err(Error::ThreadCleanup)?
        }

        Ok(())
    }

    fn unpark_thread(&self) {
        if let Some(handle) = self.handle.as_ref() {
            handle.thread().unpark()
        }
    }
}

impl CpuManager {
    #[allow(unused_variables)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: &CpusConfig,
        vm: Arc<dyn hypervisor::Vm>,
        exit_evt: EventFd,
        reset_evt: EventFd,
        #[cfg(feature = "guest_debug")] vm_debug_evt: EventFd,
        hypervisor: &Arc<dyn hypervisor::Hypervisor>,
        seccomp_action: SeccompAction,
        vm_ops: Arc<dyn VmOps>,
        #[cfg(feature = "tdx")] tdx_enabled: bool,
        numa_nodes: &NumaNodes,
        #[cfg(feature = "sev_snp")] sev_snp_enabled: bool,
    ) -> Result<Arc<Mutex<CpuManager>>> {
        if u32::from(config.max_vcpus) > hypervisor.get_max_vcpus() {
            return Err(Error::MaximumVcpusExceeded);
        }

        let mut vcpu_states = Vec::with_capacity(usize::from(config.max_vcpus));
        vcpu_states.resize_with(usize::from(config.max_vcpus), VcpuState::default);
        let hypervisor_type = hypervisor.hypervisor_type();
        #[cfg(target_arch = "x86_64")]
        let cpu_vendor = hypervisor.get_cpu_vendor();

        #[cfg(target_arch = "x86_64")]
        if config.features.amx {
            const ARCH_GET_XCOMP_GUEST_PERM: usize = 0x1024;
            const ARCH_REQ_XCOMP_GUEST_PERM: usize = 0x1025;
            const XFEATURE_XTILEDATA: usize = 18;
            const XFEATURE_XTILEDATA_MASK: usize = 1 << XFEATURE_XTILEDATA;

            // SAFETY: the syscall is only modifying kernel internal
            // data structures that the kernel is itself expected to safeguard.
            let amx_tile = unsafe {
                libc::syscall(
                    libc::SYS_arch_prctl,
                    ARCH_REQ_XCOMP_GUEST_PERM,
                    XFEATURE_XTILEDATA,
                )
            };

            if amx_tile != 0 {
                return Err(Error::AmxEnable(anyhow!("Guest AMX usage not supported")));
            } else {
                let mask: usize = 0;
                // SAFETY: the mask being modified (not marked mutable as it is
                // modified in unsafe only which is permitted) isn't in use elsewhere.
                let result = unsafe {
                    libc::syscall(libc::SYS_arch_prctl, ARCH_GET_XCOMP_GUEST_PERM, &mask)
                };
                if result != 0 || (mask & XFEATURE_XTILEDATA_MASK) != XFEATURE_XTILEDATA_MASK {
                    return Err(Error::AmxEnable(anyhow!("Guest AMX usage not supported")));
                }
            }
        }

        let proximity_domain_per_cpu: BTreeMap<u32, u32> = {
            let mut cpu_list = Vec::new();
            for (proximity_domain, numa_node) in numa_nodes.iter() {
                for cpu in numa_node.cpus.iter() {
                    cpu_list.push((*cpu, *proximity_domain))
                }
            }
            cpu_list
        }
        .into_iter()
        .collect();

        let affinity = if let Some(cpu_affinity) = config.affinity.as_ref() {
            cpu_affinity
                .iter()
                .map(|a| (a.vcpu as u32, a.host_cpus.clone()))
                .collect()
        } else {
            BTreeMap::new()
        };

        #[cfg(feature = "tdx")]
        let dynamic = !tdx_enabled;
        #[cfg(not(feature = "tdx"))]
        let dynamic = true;

        Ok(Arc::new(Mutex::new(CpuManager {
            config: config.clone(),
            interrupt_controller: None,
            #[cfg(target_arch = "x86_64")]
            cpuid: Vec::new(),
            vm,
            vcpus_kill_signalled: Arc::new(AtomicBool::new(false)),
            vcpus_pause_signalled: Arc::new(AtomicBool::new(false)),
            vcpus_kick_signalled: Arc::new(AtomicBool::new(false)),
            vcpu_states,
            exit_evt,
            reset_evt,
            #[cfg(feature = "guest_debug")]
            vm_debug_evt,
            selected_cpu: 0,
            vcpus: Vec::with_capacity(usize::from(config.max_vcpus)),
            seccomp_action,
            vm_ops,
            acpi_address: None,
            proximity_domain_per_cpu,
            affinity,
            dynamic,
            hypervisor: hypervisor.clone(),
            #[cfg(feature = "sev_snp")]
            sev_snp_enabled,
        })))
    }

    #[cfg(target_arch = "x86_64")]
    pub fn populate_cpuid(
        &mut self,
        hypervisor: &Arc<dyn hypervisor::Hypervisor>,
        #[cfg(feature = "tdx")] tdx: bool,
    ) -> Result<()> {
        self.cpuid = {
            let phys_bits = physical_bits(hypervisor, self.config.max_phys_bits);
            arch::generate_common_cpuid(
                hypervisor,
                &arch::CpuidConfig {
                    phys_bits,
                    kvm_hyperv: self.config.kvm_hyperv,
                    #[cfg(feature = "tdx")]
                    tdx,
                    amx: self.config.features.amx,
                },
            )
            .map_err(Error::CommonCpuId)?
        };

        Ok(())
    }

    fn create_vcpu(&mut self, cpu_id: u32, snapshot: Option<Snapshot>) -> Result<Arc<Mutex<Vcpu>>> {
        info!("Creating vCPU: cpu_id = {}", cpu_id);

        #[cfg(target_arch = "x86_64")]
        let topology = self.get_vcpu_topology();
        #[cfg(target_arch = "x86_64")]
        let x2apic_id = arch::x86_64::get_x2apic_id(cpu_id, topology);
        #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
        let x2apic_id = cpu_id;

        let mut vcpu = Vcpu::new(
            cpu_id,
            x2apic_id,
            &self.vm,
            Some(self.vm_ops.clone()),
            #[cfg(target_arch = "x86_64")]
            self.hypervisor.get_cpu_vendor(),
        )?;

        if let Some(snapshot) = snapshot {
            // AArch64 vCPUs should be initialized after created.
            #[cfg(target_arch = "aarch64")]
            vcpu.init(&self.vm)?;

            let state: CpuState = snapshot.to_state().map_err(|e| {
                Error::VcpuCreate(anyhow!("Could not get vCPU state from snapshot {:?}", e))
            })?;
            vcpu.vcpu
                .set_state(&state)
                .map_err(|e| Error::VcpuCreate(anyhow!("Could not set the vCPU state {:?}", e)))?;

            vcpu.saved_state = Some(state);
        }

        let vcpu = Arc::new(Mutex::new(vcpu));

        // Adding vCPU to the CpuManager's vCPU list.
        self.vcpus.push(vcpu.clone());

        Ok(vcpu)
    }

    pub fn configure_vcpu(
        &self,
        vcpu: Arc<Mutex<Vcpu>>,
        boot_setup: Option<(EntryPoint, &GuestMemoryAtomic<GuestMemoryMmap>)>,
    ) -> Result<()> {
        let mut vcpu = vcpu.lock().unwrap();

        #[cfg(feature = "sev_snp")]
        if self.sev_snp_enabled {
            if let Some((kernel_entry_point, _)) = boot_setup {
                vcpu.set_sev_control_register(
                    kernel_entry_point.entry_addr.0 / crate::igvm::HV_PAGE_SIZE,
                )?;
            }

            // Traditional way to configure vcpu doesn't work for SEV-SNP guests.
            // All the vCPU configuration for SEV-SNP guest is provided via VMSA.
            return Ok(());
        }

        #[cfg(target_arch = "x86_64")]
        assert!(!self.cpuid.is_empty());

        #[cfg(target_arch = "x86_64")]
        let topology = self.config.topology.clone().map_or_else(
            || {
                (
                    1_u16,
                    u16::try_from(self.boot_vcpus()).unwrap(),
                    1_u16,
                    1_u16,
                )
            },
            |t| {
                (
                    t.threads_per_core.into(),
                    t.cores_per_die.into(),
                    t.dies_per_package.into(),
                    t.packages.into(),
                )
            },
        );
        #[cfg(target_arch = "x86_64")]
        vcpu.configure(
            boot_setup,
            self.cpuid.clone(),
            self.config.kvm_hyperv,
            topology,
        )?;

        #[cfg(target_arch = "aarch64")]
        vcpu.configure(&self.vm, boot_setup)?;

        #[cfg(target_arch = "riscv64")]
        vcpu.configure(boot_setup)?;

        Ok(())
    }

    /// Only create new vCPUs if there aren't any inactive ones to reuse
    fn create_vcpus(
        &mut self,
        desired_vcpus: u32,
        snapshot: Option<Snapshot>,
    ) -> Result<Vec<Arc<Mutex<Vcpu>>>> {
        let mut vcpus: Vec<Arc<Mutex<Vcpu>>> = vec![];
        info!(
            "Request to create new vCPUs: desired = {}, max = {}, allocated = {}, present = {}",
            desired_vcpus,
            self.config.max_vcpus,
            self.vcpus.len(),
            self.present_vcpus()
        );

        if desired_vcpus > self.config.max_vcpus as u32 {
            return Err(Error::DesiredVCpuCountExceedsMax);
        }

        // Only create vCPUs in excess of all the allocated vCPUs.
        for cpu_id in self.vcpus.len() as u32..desired_vcpus {
            vcpus.push(self.create_vcpu(
                cpu_id,
                // TODO: The special format of the CPU id can be removed once
                // ready to break live upgrade.
                snapshot_from_id(snapshot.as_ref(), cpu_id.to_string().as_str()),
            )?);
        }

        Ok(vcpus)
    }

    #[cfg(target_arch = "aarch64")]
    pub fn init_pmu(&self, irq: u32) -> Result<bool> {
        for cpu in self.vcpus.iter() {
            let cpu = cpu.lock().unwrap();
            // Check if PMU attr is available, if not, log the information.
            if cpu.vcpu.has_pmu_support() {
                cpu.vcpu.init_pmu(irq).map_err(Error::InitPmu)?;
            } else {
                debug!(
                    "PMU attribute is not supported in vCPU{}, skip PMU init!",
                    cpu.id
                );
                return Ok(false);
            }
        }

        Ok(true)
    }

    pub fn vcpus(&self) -> Vec<Arc<Mutex<Vcpu>>> {
        self.vcpus.clone()
    }

    fn start_vcpu(
        &mut self,
        vcpu: Arc<Mutex<Vcpu>>,
        vcpu_id: u32,
        vcpu_thread_barrier: Arc<Barrier>,
        inserting: bool,
    ) -> Result<()> {
        let reset_evt = self.reset_evt.try_clone().unwrap();
        let exit_evt = self.exit_evt.try_clone().unwrap();
        #[cfg(feature = "kvm")]
        let hypervisor_type = self.hypervisor.hypervisor_type();
        #[cfg(feature = "guest_debug")]
        let vm_debug_evt = self.vm_debug_evt.try_clone().unwrap();
        let panic_exit_evt = self.exit_evt.try_clone().unwrap();
        let vcpu_kill_signalled = self.vcpus_kill_signalled.clone();
        let vcpu_pause_signalled = self.vcpus_pause_signalled.clone();
        let vcpu_kick_signalled = self.vcpus_kick_signalled.clone();

        let vcpu_kill = self.vcpu_states[usize::try_from(vcpu_id).unwrap()]
            .kill
            .clone();
        let vcpu_run_interrupted = self.vcpu_states[usize::try_from(vcpu_id).unwrap()]
            .vcpu_run_interrupted
            .clone();
        let panic_vcpu_run_interrupted = vcpu_run_interrupted.clone();
        let vcpu_paused = self.vcpu_states[usize::try_from(vcpu_id).unwrap()]
            .paused
            .clone();

        // Prepare the CPU set the current vCPU is expected to run onto.
        let cpuset = self.affinity.get(&vcpu_id).map(|host_cpus| {
            // SAFETY: all zeros is a valid pattern
            let mut cpuset: libc::cpu_set_t = unsafe { std::mem::zeroed() };
            // SAFETY: FFI call, trivially safe
            unsafe { libc::CPU_ZERO(&mut cpuset) };
            for host_cpu in host_cpus {
                // SAFETY: FFI call, trivially safe
                unsafe { libc::CPU_SET(*host_cpu, &mut cpuset) };
            }
            cpuset
        });

        // Retrieve seccomp filter for vcpu thread
        let vcpu_seccomp_filter = get_seccomp_filter(
            &self.seccomp_action,
            Thread::Vcpu,
            self.hypervisor.hypervisor_type(),
        )
        .map_err(Error::CreateSeccompFilter)?;

        #[cfg(target_arch = "x86_64")]
        let interrupt_controller_clone = self.interrupt_controller.as_ref().cloned();

        info!("Starting vCPU: cpu_id = {}", vcpu_id);

        let handle = Some(
            thread::Builder::new()
                .name(format!("vcpu{vcpu_id}"))
                .spawn(move || {
                    // Schedule the thread to run on the expected CPU set
                    if let Some(cpuset) = cpuset.as_ref() {
                        // SAFETY: FFI call with correct arguments
                        let ret = unsafe {
                            libc::sched_setaffinity(
                                0,
                                std::mem::size_of::<libc::cpu_set_t>(),
                                cpuset as *const libc::cpu_set_t,
                            )
                        };

                        if ret != 0 {
                            error!(
                                "Failed scheduling the vCPU {} on the expected CPU set: {}",
                                vcpu_id,
                                io::Error::last_os_error()
                            );
                            return;
                        }
                    }

                    // Apply seccomp filter for vcpu thread.
                    if !vcpu_seccomp_filter.is_empty() {
                        if let Err(e) =
                            apply_filter(&vcpu_seccomp_filter).map_err(Error::ApplySeccompFilter)
                        {
                            error!("Error applying seccomp filter: {:?}", e);
                            return;
                        }
                    }
                    extern "C" fn handle_signal(_: i32, _: *mut siginfo_t, _: *mut c_void) {}
                    // This uses an async signal safe handler to kill the vcpu handles.
                    register_signal_handler(SIGRTMIN(), handle_signal)
                        .expect("Failed to register vcpu signal handler");
                    // Block until all CPUs are ready.
                    vcpu_thread_barrier.wait();

                    std::panic::catch_unwind(move || {
                        loop {
                            // If we are being told to pause, we park the thread
                            // until the pause boolean is toggled.
                            // The resume operation is responsible for toggling
                            // the boolean and unpark the thread.
                            // We enter a loop because park() could spuriously
                            // return. We will then park() again unless the
                            // pause boolean has been toggled.

                            // Need to use Ordering::SeqCst as we have multiple
                            // loads and stores to different atomics and we need
                            // to see them in a consistent order in all threads

                            if vcpu_pause_signalled.load(Ordering::SeqCst) {
                                // As a pause can be caused by PIO & MMIO exits then we need to ensure they are
                                // completed by returning to KVM_RUN. From the kernel docs:
                                //
                                // For KVM_EXIT_IO, KVM_EXIT_MMIO, KVM_EXIT_OSI, KVM_EXIT_PAPR, KVM_EXIT_XEN,
                                // KVM_EXIT_EPR, KVM_EXIT_X86_RDMSR and KVM_EXIT_X86_WRMSR the corresponding
                                // operations are complete (and guest state is consistent) only after userspace
                                // has re-entered the kernel with KVM_RUN.  The kernel side will first finish
                                // incomplete operations and then check for pending signals.
                                // The pending state of the operation is not preserved in state which is
                                // visible to userspace, thus userspace should ensure that the operation is
                                // completed before performing a live migration.  Userspace can re-enter the
                                // guest with an unmasked signal pending or with the immediate_exit field set
                                // to complete pending operations without allowing any further instructions
                                // to be executed.

                                #[cfg(feature = "kvm")]
                                if matches!(hypervisor_type, HypervisorType::Kvm) {
                                    vcpu.lock().as_ref().unwrap().vcpu.set_immediate_exit(true);
                                    if !matches!(vcpu.lock().unwrap().run(), Ok(VmExit::Ignore)) {
                                        error!("Unexpected VM exit on \"immediate_exit\" run");
                                        break;
                                    }
                                    vcpu.lock().as_ref().unwrap().vcpu.set_immediate_exit(false);
                                }

                                vcpu_run_interrupted.store(true, Ordering::SeqCst);

                                vcpu_paused.store(true, Ordering::SeqCst);
                                while vcpu_pause_signalled.load(Ordering::SeqCst) {
                                    thread::park();
                                }
                                vcpu_run_interrupted.store(false, Ordering::SeqCst);
                            }

                            if vcpu_kick_signalled.load(Ordering::SeqCst) {
                                vcpu_run_interrupted.store(true, Ordering::SeqCst);
                                #[cfg(target_arch = "x86_64")]
                                match vcpu.lock().as_ref().unwrap().vcpu.nmi() {
                                    Ok(()) => {},
                                    Err(e) => {
                                        error!("Error when inject nmi {}", e);
                                        break;
                                    }
                                }
                            }

                            // We've been told to terminate
                            if vcpu_kill_signalled.load(Ordering::SeqCst)
                                || vcpu_kill.load(Ordering::SeqCst)
                            {
                                vcpu_run_interrupted.store(true, Ordering::SeqCst);
                                break;
                            }

                            #[cfg(feature = "tdx")]
                            let mut vcpu = vcpu.lock().unwrap();
                            #[cfg(not(feature = "tdx"))]
                            let vcpu = vcpu.lock().unwrap();
                            // vcpu.run() returns false on a triple-fault so trigger a reset
                            match vcpu.run() {
                                Ok(run) => match run {
                                    #[cfg(feature = "kvm")]
                                    VmExit::Debug => {
                                        info!("VmExit::Debug");
                                        #[cfg(feature = "guest_debug")]
                                        {
                                            vcpu_pause_signalled.store(true, Ordering::SeqCst);
                                            let raw_tid = get_raw_tid(vcpu_id as usize);
                                            vm_debug_evt.write(raw_tid as u64).unwrap();
                                        }
                                    }
                                    #[cfg(target_arch = "x86_64")]
                                    VmExit::IoapicEoi(vector) => {
                                        if let Some(interrupt_controller) =
                                            &interrupt_controller_clone
                                        {
                                            interrupt_controller
                                                .lock()
                                                .unwrap()
                                                .end_of_interrupt(vector);
                                        }
                                    }
                                    VmExit::Ignore => {}
                                    VmExit::Hyperv => {}
                                    VmExit::Reset => {
                                        info!("VmExit::Reset");
                                        vcpu_run_interrupted.store(true, Ordering::SeqCst);
                                        reset_evt.write(1).unwrap();
                                        break;
                                    }
                                    VmExit::Shutdown => {
                                        info!("VmExit::Shutdown");
                                        vcpu_run_interrupted.store(true, Ordering::SeqCst);
                                        exit_evt.write(1).unwrap();
                                        break;
                                    }
                                    #[cfg(feature = "tdx")]
                                    VmExit::Tdx => {
                                        if let Some(vcpu) = Arc::get_mut(&mut vcpu.vcpu) {
                                            match vcpu.get_tdx_exit_details() {
                                                Ok(details) => match details {
                                                    TdxExitDetails::GetQuote => warn!("TDG_VP_VMCALL_GET_QUOTE not supported"),
                                                    TdxExitDetails::SetupEventNotifyInterrupt => {
                                                        warn!("TDG_VP_VMCALL_SETUP_EVENT_NOTIFY_INTERRUPT not supported")
                                                    }
                                                },
                                                Err(e) => error!("Unexpected TDX VMCALL: {}", e),
                                            }
                                            vcpu.set_tdx_status(TdxExitStatus::InvalidOperand);
                                        } else {
                                            // We should never reach this code as
                                            // this means the design from the code
                                            // is wrong.
                                            unreachable!("Couldn't get a mutable reference from Arc<dyn Vcpu> as there are multiple instances");
                                        }
                                    }
                                },

                                Err(e) => {
                                    error!("VCPU generated error: {:?}", Error::VcpuRun(e.into()));
                                    vcpu_run_interrupted.store(true, Ordering::SeqCst);
                                    exit_evt.write(1).unwrap();
                                    break;
                                }
                            }

                            // We've been told to terminate
                            if vcpu_kill_signalled.load(Ordering::SeqCst)
                                || vcpu_kill.load(Ordering::SeqCst)
                            {
                                vcpu_run_interrupted.store(true, Ordering::SeqCst);
                                break;
                            }
                        }
                    })
                    .or_else(|_| {
                        panic_vcpu_run_interrupted.store(true, Ordering::SeqCst);
                        error!("vCPU thread panicked");
                        panic_exit_evt.write(1)
                    })
                    .ok();
                })
                .map_err(Error::VcpuSpawn)?,
        );

        // On hot plug calls into this function entry_point is None. It is for
        // those hotplug CPU additions that we need to set the inserting flag.
        self.vcpu_states[usize::try_from(vcpu_id).unwrap()].handle = handle;
        self.vcpu_states[usize::try_from(vcpu_id).unwrap()].inserting = inserting;

        Ok(())
    }

    /// Start up as many vCPUs threads as needed to reach `desired_vcpus`
    fn activate_vcpus(
        &mut self,
        desired_vcpus: u32,
        inserting: bool,
        paused: Option<bool>,
    ) -> Result<()> {
        if desired_vcpus > self.config.max_vcpus as u32 {
            return Err(Error::DesiredVCpuCountExceedsMax);
        }

        let vcpu_thread_barrier = Arc::new(Barrier::new(
            (desired_vcpus - self.present_vcpus() + 1) as usize,
        ));

        if let Some(paused) = paused {
            self.vcpus_pause_signalled.store(paused, Ordering::SeqCst);
        }

        info!(
            "Starting vCPUs: desired = {}, allocated = {}, present = {}, paused = {}",
            desired_vcpus,
            self.vcpus.len(),
            self.present_vcpus(),
            self.vcpus_pause_signalled.load(Ordering::SeqCst)
        );

        // This reuses any inactive vCPUs as well as any that were newly created
        for vcpu_id in self.present_vcpus()..desired_vcpus {
            let vcpu = Arc::clone(&self.vcpus[vcpu_id as usize]);
            self.start_vcpu(vcpu, vcpu_id, vcpu_thread_barrier.clone(), inserting)?;
        }

        // Unblock all CPU threads.
        vcpu_thread_barrier.wait();
        Ok(())
    }

    fn mark_vcpus_for_removal(&mut self, desired_vcpus: u32) {
        // Mark vCPUs for removal, actual removal happens on ejection
        for cpu_id in desired_vcpus..self.present_vcpus() {
            self.vcpu_states[usize::try_from(cpu_id).unwrap()].removing = true;
            self.vcpu_states[usize::try_from(cpu_id).unwrap()]
                .pending_removal
                .store(true, Ordering::SeqCst);
        }
    }

    pub fn check_pending_removed_vcpu(&mut self) -> bool {
        for state in self.vcpu_states.iter() {
            if state.active() && state.pending_removal.load(Ordering::SeqCst) {
                return true;
            }
        }
        false
    }

    fn remove_vcpu(&mut self, cpu_id: u32) -> Result<()> {
        info!("Removing vCPU: cpu_id = {}", cpu_id);
        let state = &mut self.vcpu_states[usize::try_from(cpu_id).unwrap()];
        state.kill.store(true, Ordering::SeqCst);
        state.signal_thread();
        state.wait_until_signal_acknowledged();
        state.join_thread()?;
        state.handle = None;

        // Once the thread has exited, clear the "kill" so that it can reused
        state.kill.store(false, Ordering::SeqCst);
        state.pending_removal.store(false, Ordering::SeqCst);

        Ok(())
    }

    pub fn create_boot_vcpus(
        &mut self,
        snapshot: Option<Snapshot>,
    ) -> Result<Vec<Arc<Mutex<Vcpu>>>> {
        trace_scoped!("create_boot_vcpus");

        self.create_vcpus(self.boot_vcpus(), snapshot)
    }

    // Starts all the vCPUs that the VM is booting with. Blocks until all vCPUs are running.
    pub fn start_boot_vcpus(&mut self, paused: bool) -> Result<()> {
        self.activate_vcpus(self.boot_vcpus(), false, Some(paused))
    }

    pub fn start_restored_vcpus(&mut self) -> Result<()> {
        self.activate_vcpus(self.vcpus.len() as u32, false, Some(true))
            .map_err(|e| {
                Error::StartRestoreVcpu(anyhow!("Failed to start restored vCPUs: {:#?}", e))
            })?;

        Ok(())
    }

    pub fn resize(&mut self, desired_vcpus: u32) -> Result<bool> {
        if desired_vcpus.cmp(&self.present_vcpus()) == cmp::Ordering::Equal {
            return Ok(false);
        }

        if !self.dynamic {
            return Ok(false);
        }

        if desired_vcpus < 1 {
            return Err(Error::DesiredVCpuCountIsZero);
        }

        if self.check_pending_removed_vcpu() {
            return Err(Error::VcpuPendingRemovedVcpu);
        }

        match desired_vcpus.cmp(&self.present_vcpus()) {
            cmp::Ordering::Greater => {
                let vcpus = self.create_vcpus(desired_vcpus, None)?;
                for vcpu in vcpus {
                    self.configure_vcpu(vcpu, None)?
                }
                self.activate_vcpus(desired_vcpus, true, None)?;
                Ok(true)
            }
            cmp::Ordering::Less => {
                self.mark_vcpus_for_removal(desired_vcpus);
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Signal to the spawned threads (vCPUs and console signal handler).
    ///
    /// For the vCPU threads this will interrupt the KVM_RUN ioctl() allowing
    /// the loop to check the shared state booleans.
    fn signal_vcpus(&self) {
        // Splitting this into two loops reduced the time to pause many vCPUs
        // massively. Example: 254 vCPUs. >254ms -> ~4ms.
        for state in self.vcpu_states.iter() {
            state.signal_thread();
        }
        for state in self.vcpu_states.iter() {
            state.wait_until_signal_acknowledged();
        }
    }

    pub fn shutdown(&mut self) -> Result<()> {
        // Tell the vCPUs to stop themselves next time they go through the loop
        self.vcpus_kill_signalled.store(true, Ordering::SeqCst);

        // Toggle the vCPUs pause boolean
        self.vcpus_pause_signalled.store(false, Ordering::SeqCst);

        // Unpark all the VCPU threads.
        for state in self.vcpu_states.iter() {
            state.unpark_thread();
        }

        self.signal_vcpus();

        // Wait for all the threads to finish. This removes the state from the vector.
        for mut state in self.vcpu_states.drain(..) {
            state.join_thread()?;
        }

        Ok(())
    }

    #[cfg(feature = "tdx")]
    pub fn initialize_tdx(&self, hob_address: u64) -> Result<()> {
        for vcpu in &self.vcpus {
            vcpu.lock()
                .unwrap()
                .vcpu
                .tdx_init(hob_address)
                .map_err(Error::InitializeTdx)?;
        }
        Ok(())
    }

    pub fn boot_vcpus(&self) -> u32 {
        self.config.boot_vcpus as u32
    }

    pub fn max_vcpus(&self) -> u32 {
        self.config.max_vcpus as u32
    }

    #[cfg(target_arch = "x86_64")]
    pub fn common_cpuid(&self) -> Vec<CpuIdEntry> {
        assert!(!self.cpuid.is_empty());
        self.cpuid.clone()
    }

    fn present_vcpus(&self) -> u32 {
        self.vcpu_states
            .iter()
            .fold(0, |acc, state| acc + state.active() as u32)
    }

    #[cfg(target_arch = "aarch64")]
    pub fn get_mpidrs(&self) -> Vec<u64> {
        self.vcpus
            .iter()
            .map(|cpu| cpu.lock().unwrap().get_mpidr())
            .collect()
    }

    #[cfg(target_arch = "aarch64")]
    pub fn get_saved_states(&self) -> Vec<CpuState> {
        self.vcpus
            .iter()
            .map(|cpu| cpu.lock().unwrap().get_saved_state().unwrap())
            .collect()
    }

    pub fn get_vcpu_topology(&self) -> Option<(u16, u16, u16, u16)> {
        self.config.topology.clone().map(|t| {
            (
                t.threads_per_core.into(),
                t.cores_per_die.into(),
                t.dies_per_package.into(),
                t.packages.into(),
            )
        })
    }

    #[cfg(not(target_arch = "riscv64"))]
    pub fn create_madt(&self) -> Sdt {
        use crate::acpi;
        // This is also checked in the commandline parsing.
        assert!(self.config.boot_vcpus <= self.config.max_vcpus);

        let mut madt = Sdt::new(*b"APIC", 44, 5, *b"CLOUDH", *b"CHMADT  ", 1);
        #[cfg(target_arch = "x86_64")]
        {
            madt.write(36, arch::layout::APIC_START.0);

            for cpu in 0..self.config.max_vcpus as u32 {
                let x2apic_id = get_x2apic_id(cpu, self.get_vcpu_topology());

                let lapic = LocalX2Apic {
                    r#type: acpi::ACPI_X2APIC_PROCESSOR,
                    length: 16,
                    processor_id: cpu,
                    apic_id: x2apic_id,
                    flags: if cpu < self.config.boot_vcpus as u32 {
                        1 << MADT_CPU_ENABLE_FLAG
                    } else {
                        0
                    } | (1 << MADT_CPU_ONLINE_CAPABLE_FLAG),
                    _reserved: 0,
                };
                madt.append(lapic);
            }

            madt.append(Ioapic {
                r#type: acpi::ACPI_APIC_IO,
                length: 12,
                ioapic_id: 0,
                apic_address: arch::layout::IOAPIC_START.0 as u32,
                gsi_base: 0,
                ..Default::default()
            });

            madt.append(InterruptSourceOverride {
                r#type: acpi::ACPI_APIC_XRUPT_OVERRIDE,
                length: 10,
                bus: 0,
                source: 4,
                gsi: 4,
                flags: 0,
            });
        }

        #[cfg(target_arch = "aarch64")]
        {
            /* Notes:
             * Ignore Local Interrupt Controller Address at byte offset 36 of MADT table.
             */

            // See section 5.2.12.14 GIC CPU Interface (GICC) Structure in ACPI spec.
            for cpu in 0..self.config.boot_vcpus {
                let vcpu = &self.vcpus[cpu as usize];
                let mpidr = vcpu.lock().unwrap().get_mpidr();
                /* ARMv8 MPIDR format:
                     Bits [63:40] Must be zero
                     Bits [39:32] Aff3 : Match Aff3 of target processor MPIDR
                     Bits [31:24] Must be zero
                     Bits [23:16] Aff2 : Match Aff2 of target processor MPIDR
                     Bits [15:8] Aff1 : Match Aff1 of target processor MPIDR
                     Bits [7:0] Aff0 : Match Aff0 of target processor MPIDR
                */
                let mpidr_mask = 0xff_00ff_ffff;
                let gicc = GicC {
                    r#type: acpi::ACPI_APIC_GENERIC_CPU_INTERFACE,
                    length: 80,
                    reserved0: 0,
                    cpu_interface_number: cpu as u32,
                    uid: cpu as u32,
                    flags: 1,
                    parking_version: 0,
                    performance_interrupt: 0,
                    parked_address: 0,
                    base_address: 0,
                    gicv_base_address: 0,
                    gich_base_address: 0,
                    vgic_interrupt: 0,
                    gicr_base_address: 0,
                    mpidr: mpidr & mpidr_mask,
                    proc_power_effi_class: 0,
                    reserved1: 0,
                    spe_overflow_interrupt: 0,
                };

                madt.append(gicc);
            }
            let vgic_config = Gic::create_default_config(self.config.boot_vcpus.into());

            // GIC Distributor structure. See section 5.2.12.15 in ACPI spec.
            let gicd = GicD {
                r#type: acpi::ACPI_APIC_GENERIC_DISTRIBUTOR,
                length: 24,
                reserved0: 0,
                gic_id: 0,
                base_address: vgic_config.dist_addr,
                global_irq_base: 0,
                version: 3,
                reserved1: [0; 3],
            };
            madt.append(gicd);

            // See 5.2.12.17 GIC Redistributor (GICR) Structure in ACPI spec.
            let gicr = GicR {
                r#type: acpi::ACPI_APIC_GENERIC_REDISTRIBUTOR,
                length: 16,
                reserved: 0,
                base_address: vgic_config.redists_addr,
                range_length: vgic_config.redists_size as u32,
            };
            madt.append(gicr);

            // See 5.2.12.18 GIC Interrupt Translation Service (ITS) Structure in ACPI spec.
            let gicits = GicIts {
                r#type: acpi::ACPI_APIC_GENERIC_TRANSLATOR,
                length: 20,
                reserved0: 0,
                translation_id: 0,
                base_address: vgic_config.msi_addr,
                reserved1: 0,
            };
            madt.append(gicits);

            madt.update_checksum();
        }

        madt
    }

    #[cfg(target_arch = "aarch64")]
    pub fn create_pptt(&self) -> Sdt {
        let pptt_start = 0;
        let mut cpus = 0;
        let mut uid = 0;
        // If topology is not specified, the default setting is:
        // 1 package, multiple cores, 1 thread per core
        // This is also the behavior when PPTT is missing.
        let (threads_per_core, cores_per_die, dies_per_package, packages) = self
            .get_vcpu_topology()
            .unwrap_or((1, u16::try_from(self.max_vcpus()).unwrap(), 1, 1));
        let cores_per_package = cores_per_die * dies_per_package;

        let mut pptt = Sdt::new(*b"PPTT", 36, 2, *b"CLOUDH", *b"CHPPTT  ", 1);

        for cluster_idx in 0..packages {
            if cpus < self.config.boot_vcpus as usize {
                let cluster_offset = pptt.len() - pptt_start;
                let cluster_hierarchy_node = ProcessorHierarchyNode {
                    r#type: 0,
                    length: 20,
                    reserved: 0,
                    flags: 0x2,
                    parent: 0,
                    acpi_processor_id: cluster_idx as u32,
                    num_private_resources: 0,
                };
                pptt.append(cluster_hierarchy_node);

                for core_idx in 0..cores_per_package {
                    let core_offset = pptt.len() - pptt_start;

                    if threads_per_core > 1 {
                        let core_hierarchy_node = ProcessorHierarchyNode {
                            r#type: 0,
                            length: 20,
                            reserved: 0,
                            flags: 0x2,
                            parent: cluster_offset as u32,
                            acpi_processor_id: core_idx as u32,
                            num_private_resources: 0,
                        };
                        pptt.append(core_hierarchy_node);

                        for _thread_idx in 0..threads_per_core {
                            let thread_hierarchy_node = ProcessorHierarchyNode {
                                r#type: 0,
                                length: 20,
                                reserved: 0,
                                flags: 0xE,
                                parent: core_offset as u32,
                                acpi_processor_id: uid as u32,
                                num_private_resources: 0,
                            };
                            pptt.append(thread_hierarchy_node);
                            uid += 1;
                        }
                    } else {
                        let thread_hierarchy_node = ProcessorHierarchyNode {
                            r#type: 0,
                            length: 20,
                            reserved: 0,
                            flags: 0xA,
                            parent: cluster_offset as u32,
                            acpi_processor_id: uid as u32,
                            num_private_resources: 0,
                        };
                        pptt.append(thread_hierarchy_node);
                        uid += 1;
                    }
                }
                cpus += (cores_per_package * threads_per_core) as usize;
            }
        }

        pptt.update_checksum();
        pptt
    }

    #[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
    fn create_standard_regs(&self, cpu_id: u8) -> StandardRegisters {
        self.vcpus[usize::from(cpu_id)]
            .lock()
            .unwrap()
            .vcpu
            .create_standard_regs()
    }

    #[cfg(feature = "guest_debug")]
    fn get_regs(&self, cpu_id: u8) -> Result<StandardRegisters> {
        self.vcpus[usize::from(cpu_id)]
            .lock()
            .unwrap()
            .vcpu
            .get_regs()
            .map_err(Error::CpuDebug)
    }

    #[cfg(feature = "guest_debug")]
    fn set_regs(&self, cpu_id: u8, regs: &StandardRegisters) -> Result<()> {
        self.vcpus[usize::from(cpu_id)]
            .lock()
            .unwrap()
            .vcpu
            .set_regs(regs)
            .map_err(Error::CpuDebug)
    }

    #[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
    fn get_sregs(&self, cpu_id: u8) -> Result<SpecialRegisters> {
        self.vcpus[usize::from(cpu_id)]
            .lock()
            .unwrap()
            .vcpu
            .get_sregs()
            .map_err(Error::CpuDebug)
    }

    #[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
    fn set_sregs(&self, cpu_id: u8, sregs: &SpecialRegisters) -> Result<()> {
        self.vcpus[usize::from(cpu_id)]
            .lock()
            .unwrap()
            .vcpu
            .set_sregs(sregs)
            .map_err(Error::CpuDebug)
    }

    #[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
    fn translate_gva(
        &self,
        _guest_memory: &GuestMemoryAtomic<GuestMemoryMmap>,
        cpu_id: u8,
        gva: u64,
    ) -> Result<u64> {
        let (gpa, _) = self.vcpus[usize::from(cpu_id)]
            .lock()
            .unwrap()
            .vcpu
            .translate_gva(gva, /* flags: unused */ 0)
            .map_err(|e| Error::TranslateVirtualAddress(e.into()))?;
        Ok(gpa)
    }

    ///
    /// On AArch64, `translate_gva` API is not provided by KVM. We implemented
    /// it in VMM by walking through translation tables.
    ///
    /// Address translation is big topic, here we only focus the scenario that
    /// happens in VMM while debugging kernel. This `translate_gva`
    /// implementation is restricted to:
    /// - Exception Level 1
    /// - Translate high address range only (kernel space)
    ///
    /// This implementation supports following Arm-v8a features related to
    /// address translation:
    /// - FEAT_LPA
    /// - FEAT_LVA
    /// - FEAT_LPA2
    ///
    #[cfg(all(target_arch = "aarch64", feature = "guest_debug"))]
    fn translate_gva(
        &self,
        guest_memory: &GuestMemoryAtomic<GuestMemoryMmap>,
        cpu_id: u8,
        gva: u64,
    ) -> Result<u64> {
        let tcr_el1: u64 = self.vcpus[usize::from(cpu_id)]
            .lock()
            .unwrap()
            .vcpu
            .get_sys_reg(TCR_EL1)
            .map_err(|e| Error::TranslateVirtualAddress(e.into()))?;
        let ttbr1_el1: u64 = self.vcpus[usize::from(cpu_id)]
            .lock()
            .unwrap()
            .vcpu
            .get_sys_reg(TTBR1_EL1)
            .map_err(|e| Error::TranslateVirtualAddress(e.into()))?;
        let id_aa64mmfr0_el1: u64 = self.vcpus[usize::from(cpu_id)]
            .lock()
            .unwrap()
            .vcpu
            .get_sys_reg(ID_AA64MMFR0_EL1)
            .map_err(|e| Error::TranslateVirtualAddress(e.into()))?;

        // Bit 55 of the VA determines the range, high (0xFFFxxx...)
        // or low (0x000xxx...).
        let high_range = extract_bits_64!(gva, 55, 1);
        if high_range == 0 {
            info!("VA (0x{:x}) range is not supported!", gva);
            return Ok(gva);
        }

        // High range size offset
        let tsz = extract_bits_64!(tcr_el1, 16, 6);
        // Granule size
        let tg = extract_bits_64!(tcr_el1, 30, 2);
        // Indication of 48-bits (0) or 52-bits (1) for FEAT_LPA2
        let ds = extract_bits_64!(tcr_el1, 59, 1);

        if tsz == 0 {
            info!("VA translation is not ready!");
            return Ok(gva);
        }

        // VA size is determined by TCR_BL1.T1SZ
        let va_size = 64 - tsz;
        // Number of bits in VA consumed in each level of translation
        let stride = match tg {
            3 => 13, // 64KB granule size
            1 => 11, // 16KB granule size
            _ => 9,  // 4KB, default
        };
        // Starting level of walking
        let mut level = 4 - (va_size - 4) / stride;

        // PA or IPA size is determined
        let tcr_ips = extract_bits_64!(tcr_el1, 32, 3);
        let pa_range = extract_bits_64_without_offset!(id_aa64mmfr0_el1, 4);
        // The IPA size in TCR_BL1 and PA Range in ID_AA64MMFR0_EL1 should match.
        // To be safe, we use the minimum value if they are different.
        let pa_range = std::cmp::min(tcr_ips, pa_range);
        // PA size in bits
        let pa_size = match pa_range {
            0 => 32,
            1 => 36,
            2 => 40,
            3 => 42,
            4 => 44,
            5 => 48,
            6 => 52,
            _ => {
                return Err(Error::TranslateVirtualAddress(anyhow!(format!(
                    "PA range not supported {pa_range}"
                ))))
            }
        };

        let indexmask_grainsize = (!0u64) >> (64 - (stride + 3));
        let mut indexmask = (!0u64) >> (64 - (va_size - (stride * (4 - level))));
        // If FEAT_LPA2 is present, the translation table descriptor holds
        // 50 bits of the table address of next level.
        // Otherwise, it is 48 bits.
        let descaddrmask = if ds == 1 {
            !0u64 >> (64 - 50) // mask with 50 least significant bits
        } else {
            !0u64 >> (64 - 48) // mask with 48 least significant bits
        };
        let descaddrmask = descaddrmask & !indexmask_grainsize;

        // Translation table base address
        let mut descaddr: u64 = extract_bits_64_without_offset!(ttbr1_el1, 48);
        // In the case of FEAT_LPA and FEAT_LPA2, the initial translation table
        // address bits [48:51] comes from TTBR1_EL1 bits [2:5].
        if pa_size == 52 {
            descaddr |= extract_bits_64!(ttbr1_el1, 2, 4) << 48;
        }

        // Loop through tables of each level
        loop {
            // Table offset for current level
            let table_offset: u64 = (gva >> (stride * (4 - level))) & indexmask;
            descaddr |= table_offset;
            descaddr &= !7u64;

            let mut buf = [0; 8];
            guest_memory
                .memory()
                .read(&mut buf, GuestAddress(descaddr))
                .map_err(|e| Error::TranslateVirtualAddress(e.into()))?;
            let descriptor = u64::from_le_bytes(buf);

            descaddr = descriptor & descaddrmask;
            // In the case of FEAT_LPA, the next-level translation table address
            // bits [48:51] comes from bits [12:15] of the current descriptor.
            // For FEAT_LPA2, the next-level translation table address
            // bits [50:51] comes from bits [8:9] of the current descriptor,
            // bits [48:49] comes from bits [48:49] of the descriptor which was
            // handled previously.
            if pa_size == 52 {
                if ds == 1 {
                    // FEAT_LPA2
                    descaddr |= extract_bits_64!(descriptor, 8, 2) << 50;
                } else {
                    // FEAT_LPA
                    descaddr |= extract_bits_64!(descriptor, 12, 4) << 48;
                }
            }

            if (descriptor & 2) != 0 && (level < 3) {
                // This is a table entry. Go down to next level.
                level += 1;
                indexmask = indexmask_grainsize;
                continue;
            }

            break;
        }

        // We have reached either:
        // - a page entry at level 3 or
        // - a block entry at level 1 or 2
        let page_size = 1u64 << ((stride * (4 - level)) + 3);
        descaddr &= !(page_size - 1);
        descaddr |= gva & (page_size - 1);

        Ok(descaddr)
    }

    pub(crate) fn set_acpi_address(&mut self, acpi_address: GuestAddress) {
        self.acpi_address = Some(acpi_address);
    }

    pub(crate) fn set_interrupt_controller(
        &mut self,
        interrupt_controller: Arc<Mutex<dyn InterruptController>>,
    ) {
        self.interrupt_controller = Some(interrupt_controller);
    }

    pub(crate) fn vcpus_kill_signalled(&self) -> &Arc<AtomicBool> {
        &self.vcpus_kill_signalled
    }

    #[cfg(feature = "igvm")]
    pub(crate) fn get_cpuid_leaf(
        &self,
        cpu_id: u8,
        eax: u32,
        ecx: u32,
        xfem: u64,
        xss: u64,
    ) -> Result<[u32; 4]> {
        let leaf_info = self.vcpus[usize::from(cpu_id)]
            .lock()
            .unwrap()
            .vcpu
            .get_cpuid_values(eax, ecx, xfem, xss)
            .unwrap();
        Ok(leaf_info)
    }

    #[cfg(feature = "sev_snp")]
    pub(crate) fn sev_snp_enabled(&self) -> bool {
        self.sev_snp_enabled
    }

    pub(crate) fn nmi(&self) -> Result<()> {
        self.vcpus_kick_signalled.store(true, Ordering::SeqCst);
        self.signal_vcpus();
        self.vcpus_kick_signalled.store(false, Ordering::SeqCst);

        Ok(())
    }
}

struct Cpu {
    cpu_id: u32,
    proximity_domain: u32,
    dynamic: bool,
    #[cfg(target_arch = "x86_64")]
    topology: Option<(u16, u16, u16, u16)>,
}

#[cfg(target_arch = "x86_64")]
const MADT_CPU_ENABLE_FLAG: usize = 0;

#[cfg(target_arch = "x86_64")]
const MADT_CPU_ONLINE_CAPABLE_FLAG: usize = 1;

impl Cpu {
    #[cfg(target_arch = "x86_64")]
    fn generate_mat(&self) -> Vec<u8> {
        let x2apic_id = arch::x86_64::get_x2apic_id(self.cpu_id, self.topology);

        let lapic = LocalX2Apic {
            r#type: crate::acpi::ACPI_X2APIC_PROCESSOR,
            length: 16,
            processor_id: self.cpu_id,
            apic_id: x2apic_id,
            flags: 1 << MADT_CPU_ENABLE_FLAG,
            _reserved: 0,
        };

        let mut mat_data: Vec<u8> = vec![0; std::mem::size_of_val(&lapic)];
        // SAFETY: mat_data is large enough to hold lapic
        unsafe { *(mat_data.as_mut_ptr() as *mut LocalX2Apic) = lapic };

        mat_data
    }
}

impl Aml for Cpu {
    fn to_aml_bytes(&self, sink: &mut dyn acpi_tables::AmlSink) {
        #[cfg(target_arch = "x86_64")]
        let mat_data: Vec<u8> = self.generate_mat();
        #[allow(clippy::if_same_then_else)]
        if self.dynamic {
            aml::Device::new(
                format!("C{:03X}", self.cpu_id).as_str().into(),
                vec![
                    &aml::Name::new("_HID".into(), &"ACPI0007"),
                    &aml::Name::new("_UID".into(), &self.cpu_id),
                    // Currently, AArch64 cannot support following fields.
                    /*
                    _STA return value:
                    Bit [0] – Set if the device is present.
                    Bit [1] – Set if the device is enabled and decoding its resources.
                    Bit [2] – Set if the device should be shown in the UI.
                    Bit [3] – Set if the device is functioning properly (cleared if device failed its diagnostics).
                    Bit [4] – Set if the battery is present.
                    Bits [31:5] – Reserved (must be cleared).
                    */
                    #[cfg(target_arch = "x86_64")]
                    &aml::Method::new(
                        "_STA".into(),
                        0,
                        false,
                        // Call into CSTA method which will interrogate device
                        vec![&aml::Return::new(&aml::MethodCall::new(
                            "CSTA".into(),
                            vec![&self.cpu_id],
                        ))],
                    ),
                    &aml::Method::new(
                        "_PXM".into(),
                        0,
                        false,
                        vec![&aml::Return::new(&self.proximity_domain)],
                    ),
                    // The Linux kernel expects every CPU device to have a _MAT entry
                    // containing the LAPIC for this processor with the enabled bit set
                    // even it if is disabled in the MADT (non-boot CPU)
                    #[cfg(target_arch = "x86_64")]
                    &aml::Name::new("_MAT".into(), &aml::BufferData::new(mat_data)),
                    // Trigger CPU ejection
                    #[cfg(target_arch = "x86_64")]
                    &aml::Method::new(
                        "_EJ0".into(),
                        1,
                        false,
                        // Call into CEJ0 method which will actually eject device
                        vec![&aml::MethodCall::new("CEJ0".into(), vec![&self.cpu_id])],
                    ),
                ],
            )
            .to_aml_bytes(sink);
        } else {
            aml::Device::new(
                format!("C{:03X}", self.cpu_id).as_str().into(),
                vec![
                    &aml::Name::new("_HID".into(), &"ACPI0007"),
                    &aml::Name::new("_UID".into(), &self.cpu_id),
                    #[cfg(target_arch = "x86_64")]
                    &aml::Method::new(
                        "_STA".into(),
                        0,
                        false,
                        // Mark CPU present see CSTA implementation
                        vec![&aml::Return::new(&0xfu8)],
                    ),
                    &aml::Method::new(
                        "_PXM".into(),
                        0,
                        false,
                        vec![&aml::Return::new(&self.proximity_domain)],
                    ),
                    // The Linux kernel expects every CPU device to have a _MAT entry
                    // containing the LAPIC for this processor with the enabled bit set
                    // even it if is disabled in the MADT (non-boot CPU)
                    #[cfg(target_arch = "x86_64")]
                    &aml::Name::new("_MAT".into(), &aml::BufferData::new(mat_data)),
                ],
            )
            .to_aml_bytes(sink);
        }
    }
}

struct CpuNotify {
    cpu_id: u32,
}

impl Aml for CpuNotify {
    fn to_aml_bytes(&self, sink: &mut dyn acpi_tables::AmlSink) {
        let object = aml::Path::new(&format!("C{:03X}", self.cpu_id));
        aml::If::new(
            &aml::Equal::new(&aml::Arg(0), &self.cpu_id),
            vec![&aml::Notify::new(&object, &aml::Arg(1))],
        )
        .to_aml_bytes(sink)
    }
}

struct CpuMethods {
    max_vcpus: u32,
    dynamic: bool,
}

impl Aml for CpuMethods {
    fn to_aml_bytes(&self, sink: &mut dyn acpi_tables::AmlSink) {
        if self.dynamic {
            // CPU status method
            aml::Method::new(
                "CSTA".into(),
                1,
                true,
                vec![
                    // Take lock defined above
                    &aml::Acquire::new("\\_SB_.PRES.CPLK".into(), 0xffff),
                    // Write CPU number (in first argument) to I/O port via field
                    &aml::Store::new(&aml::Path::new("\\_SB_.PRES.CSEL"), &aml::Arg(0)),
                    &aml::Store::new(&aml::Local(0), &aml::ZERO),
                    // Check if CPEN bit is set, if so make the local variable 0xf (see _STA for details of meaning)
                    &aml::If::new(
                        &aml::Equal::new(&aml::Path::new("\\_SB_.PRES.CPEN"), &aml::ONE),
                        vec![&aml::Store::new(&aml::Local(0), &0xfu8)],
                    ),
                    // Release lock
                    &aml::Release::new("\\_SB_.PRES.CPLK".into()),
                    // Return 0 or 0xf
                    &aml::Return::new(&aml::Local(0)),
                ],
            )
            .to_aml_bytes(sink);

            let mut cpu_notifies = Vec::new();
            for cpu_id in 0..self.max_vcpus {
                cpu_notifies.push(CpuNotify { cpu_id });
            }

            let mut cpu_notifies_refs: Vec<&dyn Aml> = Vec::new();
            for cpu_id in 0..self.max_vcpus {
                cpu_notifies_refs.push(&cpu_notifies[usize::try_from(cpu_id).unwrap()]);
            }

            aml::Method::new("CTFY".into(), 2, true, cpu_notifies_refs).to_aml_bytes(sink);

            aml::Method::new(
                "CEJ0".into(),
                1,
                true,
                vec![
                    &aml::Acquire::new("\\_SB_.PRES.CPLK".into(), 0xffff),
                    // Write CPU number (in first argument) to I/O port via field
                    &aml::Store::new(&aml::Path::new("\\_SB_.PRES.CSEL"), &aml::Arg(0)),
                    // Set CEJ0 bit
                    &aml::Store::new(&aml::Path::new("\\_SB_.PRES.CEJ0"), &aml::ONE),
                    &aml::Release::new("\\_SB_.PRES.CPLK".into()),
                ],
            )
            .to_aml_bytes(sink);

            aml::Method::new(
                "CSCN".into(),
                0,
                true,
                vec![
                    // Take lock defined above
                    &aml::Acquire::new("\\_SB_.PRES.CPLK".into(), 0xffff),
                    &aml::Store::new(&aml::Local(0), &aml::ZERO),
                    &aml::While::new(
                        &aml::LessThan::new(&aml::Local(0), &self.max_vcpus),
                        vec![
                            // Write CPU number (in first argument) to I/O port via field
                            &aml::Store::new(&aml::Path::new("\\_SB_.PRES.CSEL"), &aml::Local(0)),
                            // Check if CINS bit is set
                            &aml::If::new(
                                &aml::Equal::new(&aml::Path::new("\\_SB_.PRES.CINS"), &aml::ONE),
                                // Notify device if it is
                                vec![
                                    &aml::MethodCall::new(
                                        "CTFY".into(),
                                        vec![&aml::Local(0), &aml::ONE],
                                    ),
                                    // Reset CINS bit
                                    &aml::Store::new(
                                        &aml::Path::new("\\_SB_.PRES.CINS"),
                                        &aml::ONE,
                                    ),
                                ],
                            ),
                            // Check if CRMV bit is set
                            &aml::If::new(
                                &aml::Equal::new(&aml::Path::new("\\_SB_.PRES.CRMV"), &aml::ONE),
                                // Notify device if it is (with the eject constant 0x3)
                                vec![
                                    &aml::MethodCall::new(
                                        "CTFY".into(),
                                        vec![&aml::Local(0), &3u8],
                                    ),
                                    // Reset CRMV bit
                                    &aml::Store::new(
                                        &aml::Path::new("\\_SB_.PRES.CRMV"),
                                        &aml::ONE,
                                    ),
                                ],
                            ),
                            &aml::Add::new(&aml::Local(0), &aml::Local(0), &aml::ONE),
                        ],
                    ),
                    // Release lock
                    &aml::Release::new("\\_SB_.PRES.CPLK".into()),
                ],
            )
            .to_aml_bytes(sink)
        } else {
            aml::Method::new("CSCN".into(), 0, true, vec![]).to_aml_bytes(sink)
        }
    }
}

impl Aml for CpuManager {
    fn to_aml_bytes(&self, sink: &mut dyn acpi_tables::AmlSink) {
        #[cfg(target_arch = "x86_64")]
        if let Some(acpi_address) = self.acpi_address {
            // CPU hotplug controller
            aml::Device::new(
                "_SB_.PRES".into(),
                vec![
                    &aml::Name::new("_HID".into(), &aml::EISAName::new("PNP0A06")),
                    &aml::Name::new("_UID".into(), &"CPU Hotplug Controller"),
                    // Mutex to protect concurrent access as we write to choose CPU and then read back status
                    &aml::Mutex::new("CPLK".into(), 0),
                    &aml::Name::new(
                        "_CRS".into(),
                        &aml::ResourceTemplate::new(vec![&aml::AddressSpace::new_memory(
                            aml::AddressSpaceCacheable::NotCacheable,
                            true,
                            acpi_address.0,
                            acpi_address.0 + CPU_MANAGER_ACPI_SIZE as u64 - 1,
                            None,
                        )]),
                    ),
                    // OpRegion and Fields map MMIO range into individual field values
                    &aml::OpRegion::new(
                        "PRST".into(),
                        aml::OpRegionSpace::SystemMemory,
                        &(acpi_address.0 as usize),
                        &CPU_MANAGER_ACPI_SIZE,
                    ),
                    &aml::Field::new(
                        "PRST".into(),
                        aml::FieldAccessType::Byte,
                        aml::FieldLockRule::NoLock,
                        aml::FieldUpdateRule::WriteAsZeroes,
                        vec![
                            aml::FieldEntry::Reserved(32),
                            aml::FieldEntry::Named(*b"CPEN", 1),
                            aml::FieldEntry::Named(*b"CINS", 1),
                            aml::FieldEntry::Named(*b"CRMV", 1),
                            aml::FieldEntry::Named(*b"CEJ0", 1),
                            aml::FieldEntry::Reserved(4),
                            aml::FieldEntry::Named(*b"CCMD", 8),
                        ],
                    ),
                    &aml::Field::new(
                        "PRST".into(),
                        aml::FieldAccessType::DWord,
                        aml::FieldLockRule::NoLock,
                        aml::FieldUpdateRule::Preserve,
                        vec![
                            aml::FieldEntry::Named(*b"CSEL", 32),
                            aml::FieldEntry::Reserved(32),
                            aml::FieldEntry::Named(*b"CDAT", 32),
                        ],
                    ),
                ],
            )
            .to_aml_bytes(sink);
        }

        // CPU devices
        let hid = aml::Name::new("_HID".into(), &"ACPI0010");
        let uid = aml::Name::new("_CID".into(), &aml::EISAName::new("PNP0A05"));
        // Bundle methods together under a common object
        let methods = CpuMethods {
            max_vcpus: self.config.max_vcpus as u32,
            dynamic: self.dynamic,
        };
        let mut cpu_data_inner: Vec<&dyn Aml> = vec![&hid, &uid, &methods];

        #[cfg(target_arch = "x86_64")]
        let topology = self.get_vcpu_topology();
        let mut cpu_devices = Vec::new();
        for cpu_id in 0..(self.config.max_vcpus as u32) {
            let proximity_domain = *self.proximity_domain_per_cpu.get(&cpu_id).unwrap_or(&0);
            let cpu_device = Cpu {
                cpu_id,
                proximity_domain,
                dynamic: self.dynamic,
                #[cfg(target_arch = "x86_64")]
                topology,
            };

            cpu_devices.push(cpu_device);
        }

        for cpu_device in cpu_devices.iter() {
            cpu_data_inner.push(cpu_device);
        }

        aml::Device::new("_SB_.CPUS".into(), cpu_data_inner).to_aml_bytes(sink)
    }
}

impl Pausable for CpuManager {
    fn pause(&mut self) -> std::result::Result<(), MigratableError> {
        // Tell the vCPUs to pause themselves next time they exit
        self.vcpus_pause_signalled.store(true, Ordering::SeqCst);

        self.signal_vcpus();

        for vcpu in self.vcpus.iter() {
            let mut vcpu = vcpu.lock().unwrap();
            vcpu.pause()?;
            #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
            if !self.config.kvm_hyperv {
                vcpu.vcpu.notify_guest_clock_paused().map_err(|e| {
                    MigratableError::Pause(anyhow!(
                        "Could not notify guest it has been paused {:?}",
                        e
                    ))
                })?;
            }
        }

        // The vCPU thread will change its paused state before parking, wait here for each
        // activated vCPU change their state to ensure they have parked.
        for state in self.vcpu_states.iter() {
            if state.active() {
                while !state.paused.load(Ordering::SeqCst) {
                    // To avoid a priority inversion with the vCPU thread
                    thread::sleep(std::time::Duration::from_millis(1));
                }
            }
        }

        Ok(())
    }

    fn resume(&mut self) -> std::result::Result<(), MigratableError> {
        for vcpu in self.vcpus.iter() {
            vcpu.lock().unwrap().resume()?;
        }

        // Toggle the vCPUs pause boolean
        self.vcpus_pause_signalled.store(false, Ordering::SeqCst);

        // Unpark all the VCPU threads.
        // Once unparked, the next thing they will do is checking for the pause
        // boolean. Since it'll be set to false, they will exit their pause loop
        // and go back to vmx root.
        for state in self.vcpu_states.iter() {
            state.paused.store(false, Ordering::SeqCst);
            state.unpark_thread();
        }
        Ok(())
    }
}

impl Snapshottable for CpuManager {
    fn id(&self) -> String {
        CPU_MANAGER_SNAPSHOT_ID.to_string()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        let mut cpu_manager_snapshot = Snapshot::default();

        // The CpuManager snapshot is a collection of all vCPUs snapshots.
        for vcpu in &self.vcpus {
            let mut vcpu = vcpu.lock().unwrap();
            cpu_manager_snapshot.add_snapshot(vcpu.id(), vcpu.snapshot()?);
        }

        Ok(cpu_manager_snapshot)
    }
}

impl Transportable for CpuManager {}
impl Migratable for CpuManager {}

#[cfg(feature = "guest_debug")]
impl Debuggable for CpuManager {
    #[cfg(feature = "kvm")]
    fn set_guest_debug(
        &self,
        cpu_id: usize,
        addrs: &[GuestAddress],
        singlestep: bool,
    ) -> std::result::Result<(), DebuggableError> {
        self.vcpus[cpu_id]
            .lock()
            .unwrap()
            .vcpu
            .set_guest_debug(addrs, singlestep)
            .map_err(DebuggableError::SetDebug)
    }

    fn debug_pause(&mut self) -> std::result::Result<(), DebuggableError> {
        Ok(())
    }

    fn debug_resume(&mut self) -> std::result::Result<(), DebuggableError> {
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn read_regs(&self, cpu_id: usize) -> std::result::Result<CoreRegs, DebuggableError> {
        // General registers: RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, r8-r15
        let gregs = self
            .get_regs(cpu_id as u8)
            .map_err(DebuggableError::ReadRegs)?;
        let regs = [
            gregs.get_rax(),
            gregs.get_rbx(),
            gregs.get_rcx(),
            gregs.get_rdx(),
            gregs.get_rsi(),
            gregs.get_rdi(),
            gregs.get_rbp(),
            gregs.get_rsp(),
            gregs.get_r8(),
            gregs.get_r9(),
            gregs.get_r10(),
            gregs.get_r11(),
            gregs.get_r12(),
            gregs.get_r13(),
            gregs.get_r14(),
            gregs.get_r15(),
        ];

        // GDB exposes 32-bit eflags instead of 64-bit rflags.
        // https://github.com/bminor/binutils-gdb/blob/master/gdb/features/i386/64bit-core.xml
        let eflags = gregs.get_rflags() as u32;
        let rip = gregs.get_rip();

        // Segment registers: CS, SS, DS, ES, FS, GS
        let sregs = self
            .get_sregs(cpu_id as u8)
            .map_err(DebuggableError::ReadRegs)?;
        let segments = X86SegmentRegs {
            cs: sregs.cs.selector as u32,
            ss: sregs.ss.selector as u32,
            ds: sregs.ds.selector as u32,
            es: sregs.es.selector as u32,
            fs: sregs.fs.selector as u32,
            gs: sregs.gs.selector as u32,
        };

        // TODO: Add other registers

        Ok(CoreRegs {
            regs,
            eflags,
            rip,
            segments,
            ..Default::default()
        })
    }

    #[cfg(target_arch = "aarch64")]
    fn read_regs(&self, cpu_id: usize) -> std::result::Result<CoreRegs, DebuggableError> {
        let gregs = self
            .get_regs(cpu_id as u8)
            .map_err(DebuggableError::ReadRegs)?;
        Ok(CoreRegs {
            x: gregs.get_regs(),
            sp: gregs.get_sp(),
            pc: gregs.get_pc(),
            ..Default::default()
        })
    }

    #[cfg(target_arch = "x86_64")]
    fn write_regs(
        &self,
        cpu_id: usize,
        regs: &CoreRegs,
    ) -> std::result::Result<(), DebuggableError> {
        let orig_gregs = self
            .get_regs(cpu_id as u8)
            .map_err(DebuggableError::ReadRegs)?;
        let mut gregs = self.create_standard_regs(cpu_id as u8);
        gregs.set_rax(regs.regs[0]);
        gregs.set_rbx(regs.regs[1]);
        gregs.set_rcx(regs.regs[2]);
        gregs.set_rdx(regs.regs[3]);
        gregs.set_rsi(regs.regs[4]);
        gregs.set_rdi(regs.regs[5]);
        gregs.set_rbp(regs.regs[6]);
        gregs.set_rsp(regs.regs[7]);
        gregs.set_r8(regs.regs[8]);
        gregs.set_r9(regs.regs[9]);
        gregs.set_r10(regs.regs[10]);
        gregs.set_r11(regs.regs[11]);
        gregs.set_r12(regs.regs[12]);
        gregs.set_r13(regs.regs[13]);
        gregs.set_r14(regs.regs[14]);
        gregs.set_r15(regs.regs[15]);
        gregs.set_rip(regs.rip);
        // Update the lower 32-bit of rflags.
        gregs.set_rflags((orig_gregs.get_rflags() & !(u32::MAX as u64)) | (regs.eflags as u64));

        self.set_regs(cpu_id as u8, &gregs)
            .map_err(DebuggableError::WriteRegs)?;

        // Segment registers: CS, SS, DS, ES, FS, GS
        // Since GDB care only selectors, we call get_sregs() first.
        let mut sregs = self
            .get_sregs(cpu_id as u8)
            .map_err(DebuggableError::ReadRegs)?;
        sregs.cs.selector = regs.segments.cs as u16;
        sregs.ss.selector = regs.segments.ss as u16;
        sregs.ds.selector = regs.segments.ds as u16;
        sregs.es.selector = regs.segments.es as u16;
        sregs.fs.selector = regs.segments.fs as u16;
        sregs.gs.selector = regs.segments.gs as u16;

        self.set_sregs(cpu_id as u8, &sregs)
            .map_err(DebuggableError::WriteRegs)?;

        // TODO: Add other registers

        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn write_regs(
        &self,
        cpu_id: usize,
        regs: &CoreRegs,
    ) -> std::result::Result<(), DebuggableError> {
        let mut gregs = self
            .get_regs(cpu_id as u8)
            .map_err(DebuggableError::ReadRegs)?;

        gregs.set_regs(regs.x);
        gregs.set_sp(regs.sp);
        gregs.set_pc(regs.pc);

        self.set_regs(cpu_id as u8, &gregs)
            .map_err(DebuggableError::WriteRegs)?;

        Ok(())
    }

    fn read_mem(
        &self,
        guest_memory: &GuestMemoryAtomic<GuestMemoryMmap>,
        cpu_id: usize,
        vaddr: GuestAddress,
        len: usize,
    ) -> std::result::Result<Vec<u8>, DebuggableError> {
        let mut buf = vec![0; len];
        let mut total_read = 0_u64;

        while total_read < len as u64 {
            let gaddr = vaddr.0 + total_read;
            let paddr = match self.translate_gva(guest_memory, cpu_id as u8, gaddr) {
                Ok(paddr) => paddr,
                Err(_) if gaddr == u64::MIN => gaddr, // Silently return GVA as GPA if GVA == 0.
                Err(e) => return Err(DebuggableError::TranslateGva(e)),
            };
            let psize = arch::PAGE_SIZE as u64;
            let read_len = std::cmp::min(len as u64 - total_read, psize - (paddr & (psize - 1)));
            guest_memory
                .memory()
                .read(
                    &mut buf[total_read as usize..total_read as usize + read_len as usize],
                    GuestAddress(paddr),
                )
                .map_err(DebuggableError::ReadMem)?;
            total_read += read_len;
        }
        Ok(buf)
    }

    fn write_mem(
        &self,
        guest_memory: &GuestMemoryAtomic<GuestMemoryMmap>,
        cpu_id: usize,
        vaddr: &GuestAddress,
        data: &[u8],
    ) -> std::result::Result<(), DebuggableError> {
        let mut total_written = 0_u64;

        while total_written < data.len() as u64 {
            let gaddr = vaddr.0 + total_written;
            let paddr = match self.translate_gva(guest_memory, cpu_id as u8, gaddr) {
                Ok(paddr) => paddr,
                Err(_) if gaddr == u64::MIN => gaddr, // Silently return GVA as GPA if GVA == 0.
                Err(e) => return Err(DebuggableError::TranslateGva(e)),
            };
            let psize = arch::PAGE_SIZE as u64;
            let write_len = std::cmp::min(
                data.len() as u64 - total_written,
                psize - (paddr & (psize - 1)),
            );
            guest_memory
                .memory()
                .write(
                    &data[total_written as usize..total_written as usize + write_len as usize],
                    GuestAddress(paddr),
                )
                .map_err(DebuggableError::WriteMem)?;
            total_written += write_len;
        }
        Ok(())
    }

    fn active_vcpus(&self) -> usize {
        self.present_vcpus() as usize
    }
}

#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
impl Elf64Writable for CpuManager {}

#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
impl CpuElf64Writable for CpuManager {
    fn cpu_write_elf64_note(
        &mut self,
        dump_state: &DumpState,
    ) -> std::result::Result<(), GuestDebuggableError> {
        let mut coredump_file = dump_state.file.as_ref().unwrap();
        for vcpu in &self.vcpus {
            let note_size = self.get_note_size(NoteDescType::Elf, 1);
            let mut pos: usize = 0;
            let mut buf = vec![0; note_size as usize];
            let descsz = size_of::<X86_64ElfPrStatus>();
            let vcpu_id = vcpu.lock().unwrap().id;

            let note = Elf64_Nhdr {
                n_namesz: COREDUMP_NAME_SIZE,
                n_descsz: descsz as u32,
                n_type: NT_PRSTATUS,
            };

            let bytes: &[u8] = note.as_slice();
            buf.splice(0.., bytes.to_vec());
            pos += round_up!(size_of::<Elf64_Nhdr>(), 4);
            buf.resize(pos + 4, 0);
            buf.splice(pos.., "CORE".to_string().into_bytes());

            pos += round_up!(COREDUMP_NAME_SIZE as usize, 4);
            buf.resize(pos + 32 + 4, 0);
            let pid = vcpu_id as u64;
            let bytes: &[u8] = pid.as_slice();
            buf.splice(pos + 32.., bytes.to_vec()); /* pr_pid */

            pos += descsz - size_of::<X86_64UserRegs>() - size_of::<u64>();

            let orig_rax: u64 = 0;
            let gregs = self.vcpus[usize::try_from(vcpu_id).unwrap()]
                .lock()
                .unwrap()
                .vcpu
                .get_regs()
                .map_err(|_e| GuestDebuggableError::Coredump(anyhow!("get regs failed")))?;

            let regs1 = [
                gregs.get_r15(),
                gregs.get_r14(),
                gregs.get_r13(),
                gregs.get_r12(),
                gregs.get_rbp(),
                gregs.get_rbx(),
                gregs.get_r11(),
                gregs.get_r10(),
            ];
            let regs2 = [
                gregs.get_r9(),
                gregs.get_r8(),
                gregs.get_rax(),
                gregs.get_rcx(),
                gregs.get_rdx(),
                gregs.get_rsi(),
                gregs.get_rdi(),
                orig_rax,
            ];

            let sregs = self.vcpus[usize::try_from(vcpu_id).unwrap()]
                .lock()
                .unwrap()
                .vcpu
                .get_sregs()
                .map_err(|_e| GuestDebuggableError::Coredump(anyhow!("get sregs failed")))?;

            debug!(
                "rip 0x{:x} rsp 0x{:x} gs 0x{:x} cs 0x{:x} ss 0x{:x} ds 0x{:x}",
                gregs.get_rip(),
                gregs.get_rsp(),
                sregs.gs.base,
                sregs.cs.selector,
                sregs.ss.selector,
                sregs.ds.selector,
            );

            let regs = X86_64UserRegs {
                regs1,
                regs2,
                rip: gregs.get_rip(),
                cs: sregs.cs.selector as u64,
                eflags: gregs.get_rflags(),
                rsp: gregs.get_rsp(),
                ss: sregs.ss.selector as u64,
                fs_base: sregs.fs.base,
                gs_base: sregs.gs.base,
                ds: sregs.ds.selector as u64,
                es: sregs.es.selector as u64,
                fs: sregs.fs.selector as u64,
                gs: sregs.gs.selector as u64,
            };

            // let bytes: &[u8] = unsafe { any_as_u8_slice(&regs) };
            let bytes: &[u8] = regs.as_slice();
            buf.resize(note_size as usize, 0);
            buf.splice(pos.., bytes.to_vec());
            buf.resize(note_size as usize, 0);

            coredump_file
                .write(&buf)
                .map_err(GuestDebuggableError::CoredumpFile)?;
        }

        Ok(())
    }

    fn cpu_write_vmm_note(
        &mut self,
        dump_state: &DumpState,
    ) -> std::result::Result<(), GuestDebuggableError> {
        let mut coredump_file = dump_state.file.as_ref().unwrap();
        for vcpu in &self.vcpus {
            let note_size = self.get_note_size(NoteDescType::Vmm, 1);
            let mut pos: usize = 0;
            let mut buf = vec![0; note_size as usize];
            let descsz = size_of::<DumpCpusState>();
            let vcpu_id = vcpu.lock().unwrap().id;

            let note = Elf64_Nhdr {
                n_namesz: COREDUMP_NAME_SIZE,
                n_descsz: descsz as u32,
                n_type: 0,
            };

            let bytes: &[u8] = note.as_slice();
            buf.splice(0.., bytes.to_vec());
            pos += round_up!(size_of::<Elf64_Nhdr>(), 4);

            buf.resize(pos + 4, 0);
            buf.splice(pos.., "QEMU".to_string().into_bytes());

            pos += round_up!(COREDUMP_NAME_SIZE as usize, 4);

            let gregs = self.vcpus[usize::try_from(vcpu_id).unwrap()]
                .lock()
                .unwrap()
                .vcpu
                .get_regs()
                .map_err(|_e| GuestDebuggableError::Coredump(anyhow!("get regs failed")))?;

            let regs1 = [
                gregs.get_rax(),
                gregs.get_rbx(),
                gregs.get_rcx(),
                gregs.get_rdx(),
                gregs.get_rsi(),
                gregs.get_rdi(),
                gregs.get_rsp(),
                gregs.get_rbp(),
            ];

            let regs2 = [
                gregs.get_r8(),
                gregs.get_r9(),
                gregs.get_r10(),
                gregs.get_r11(),
                gregs.get_r12(),
                gregs.get_r13(),
                gregs.get_r14(),
                gregs.get_r15(),
            ];

            let sregs = self.vcpus[usize::try_from(vcpu_id).unwrap()]
                .lock()
                .unwrap()
                .vcpu
                .get_sregs()
                .map_err(|_e| GuestDebuggableError::Coredump(anyhow!("get sregs failed")))?;

            let mut msrs = vec![MsrEntry {
                index: msr_index::MSR_KERNEL_GS_BASE,
                ..Default::default()
            }];

            self.vcpus[vcpu_id as usize]
                .lock()
                .unwrap()
                .vcpu
                .get_msrs(&mut msrs)
                .map_err(|_e| GuestDebuggableError::Coredump(anyhow!("get msr failed")))?;
            let kernel_gs_base = msrs[0].data;

            let cs = CpuSegment::new(sregs.cs);
            let ds = CpuSegment::new(sregs.ds);
            let es = CpuSegment::new(sregs.es);
            let fs = CpuSegment::new(sregs.fs);
            let gs = CpuSegment::new(sregs.gs);
            let ss = CpuSegment::new(sregs.ss);
            let ldt = CpuSegment::new(sregs.ldt);
            let tr = CpuSegment::new(sregs.tr);
            let gdt = CpuSegment::new_from_table(sregs.gdt);
            let idt = CpuSegment::new_from_table(sregs.idt);
            let cr = [sregs.cr0, sregs.cr8, sregs.cr2, sregs.cr3, sregs.cr4];
            let regs = DumpCpusState {
                version: 1,
                size: size_of::<DumpCpusState>() as u32,
                regs1,
                regs2,
                rip: gregs.get_rip(),
                rflags: gregs.get_rflags(),
                cs,
                ds,
                es,
                fs,
                gs,
                ss,
                ldt,
                tr,
                gdt,
                idt,
                cr,
                kernel_gs_base,
            };

            let bytes: &[u8] = regs.as_slice();
            buf.resize(note_size as usize, 0);
            buf.splice(pos.., bytes.to_vec());
            buf.resize(note_size as usize, 0);

            coredump_file
                .write(&buf)
                .map_err(GuestDebuggableError::CoredumpFile)?;
        }

        Ok(())
    }
}

#[cfg(all(feature = "kvm", target_arch = "x86_64"))]
#[cfg(test)]
mod tests {
    use arch::layout::{BOOT_STACK_POINTER, ZERO_PAGE_START};
    use arch::x86_64::interrupts::*;
    use arch::x86_64::regs::*;
    use hypervisor::arch::x86::{FpuState, LapicState};
    use hypervisor::StandardRegisters;
    use linux_loader::loader::bootparam::setup_header;

    #[test]
    fn test_setlint() {
        let hv = hypervisor::new().unwrap();
        let vm = hv.create_vm().expect("new VM fd creation failed");
        hv.check_required_extensions().unwrap();
        // Calling get_lapic will fail if there is no irqchip before hand.
        vm.create_irq_chip().unwrap();
        let vcpu = vm.create_vcpu(0, None).unwrap();
        let klapic_before: LapicState = vcpu.get_lapic().unwrap();

        // Compute the value that is expected to represent LVT0 and LVT1.
        let lint0 = klapic_before.get_klapic_reg(APIC_LVT0);
        let lint1 = klapic_before.get_klapic_reg(APIC_LVT1);
        let lint0_mode_expected = set_apic_delivery_mode(lint0, APIC_MODE_EXTINT);
        let lint1_mode_expected = set_apic_delivery_mode(lint1, APIC_MODE_NMI);

        set_lint(&vcpu).unwrap();

        // Compute the value that represents LVT0 and LVT1 after set_lint.
        let klapic_actual: LapicState = vcpu.get_lapic().unwrap();
        let lint0_mode_actual = klapic_actual.get_klapic_reg(APIC_LVT0);
        let lint1_mode_actual = klapic_actual.get_klapic_reg(APIC_LVT1);
        assert_eq!(lint0_mode_expected, lint0_mode_actual);
        assert_eq!(lint1_mode_expected, lint1_mode_actual);
    }

    #[test]
    fn test_setup_fpu() {
        let hv = hypervisor::new().unwrap();
        let vm = hv.create_vm().expect("new VM fd creation failed");
        let vcpu = vm.create_vcpu(0, None).unwrap();
        setup_fpu(&vcpu).unwrap();

        let expected_fpu: FpuState = FpuState {
            fcw: 0x37f,
            mxcsr: 0x1f80,
            ..Default::default()
        };
        let actual_fpu: FpuState = vcpu.get_fpu().unwrap();
        // TODO: auto-generate kvm related structures with PartialEq on.
        assert_eq!(expected_fpu.fcw, actual_fpu.fcw);
        // Setting the mxcsr register from FpuState inside setup_fpu does not influence anything.
        // See 'kvm_arch_vcpu_ioctl_set_fpu' from arch/x86/kvm/x86.c.
        // The mxcsr will stay 0 and the assert below fails. Decide whether or not we should
        // remove it at all.
        // assert!(expected_fpu.mxcsr == actual_fpu.mxcsr);
    }

    #[test]
    fn test_setup_msrs() {
        use hypervisor::arch::x86::{msr_index, MsrEntry};

        let hv = hypervisor::new().unwrap();
        let vm = hv.create_vm().expect("new VM fd creation failed");
        let vcpu = vm.create_vcpu(0, None).unwrap();
        setup_msrs(&vcpu).unwrap();

        // This test will check against the last MSR entry configured (the tenth one).
        // See create_msr_entries for details.
        let mut msrs = vec![MsrEntry {
            index: msr_index::MSR_IA32_MISC_ENABLE,
            ..Default::default()
        }];

        // get_msrs returns the number of msrs that it succeed in reading. We only want to read 1
        // in this test case scenario.
        let read_msrs = vcpu.get_msrs(&mut msrs).unwrap();
        assert_eq!(read_msrs, 1);

        // Official entries that were setup when we did setup_msrs. We need to assert that the
        // tenth one (i.e the one with index msr_index::MSR_IA32_MISC_ENABLE has the data we
        // expect.
        let entry_vec = vcpu.boot_msr_entries();
        assert_eq!(entry_vec.as_slice()[9], msrs.as_slice()[0]);
    }

    #[test]
    fn test_setup_regs_for_pvh() {
        let hv = hypervisor::new().unwrap();
        let vm = hv.create_vm().expect("new VM fd creation failed");
        let vcpu = vm.create_vcpu(0, None).unwrap();

        let mut expected_regs: StandardRegisters = vcpu.create_standard_regs();
        expected_regs.set_rflags(0x0000000000000002u64);
        expected_regs.set_rbx(arch::layout::PVH_INFO_START.0);
        expected_regs.set_rip(1);

        setup_regs(
            &vcpu,
            arch::EntryPoint {
                entry_addr: vm_memory::GuestAddress(expected_regs.get_rip()),
                setup_header: None,
            },
        )
        .unwrap();

        let actual_regs: StandardRegisters = vcpu.get_regs().unwrap();
        assert_eq!(actual_regs, expected_regs);
    }

    #[test]
    fn test_setup_regs_for_bzimage() {
        let hv = hypervisor::new().unwrap();
        let vm = hv.create_vm().expect("new VM fd creation failed");
        let vcpu = vm.create_vcpu(0, None).unwrap();

        let mut expected_regs: StandardRegisters = vcpu.create_standard_regs();
        expected_regs.set_rflags(0x0000000000000002u64);
        expected_regs.set_rip(1);
        expected_regs.set_rsp(BOOT_STACK_POINTER.0);
        expected_regs.set_rsi(ZERO_PAGE_START.0);

        setup_regs(
            &vcpu,
            arch::EntryPoint {
                entry_addr: vm_memory::GuestAddress(expected_regs.get_rip()),
                setup_header: Some(setup_header {
                    ..Default::default()
                }),
            },
        )
        .unwrap();

        let actual_regs: StandardRegisters = vcpu.get_regs().unwrap();
        assert_eq!(actual_regs, expected_regs);
    }
}

#[cfg(target_arch = "aarch64")]
#[cfg(test)]
mod tests {
    #[cfg(feature = "kvm")]
    use std::{mem, mem::offset_of};

    use arch::layout;
    use hypervisor::arch::aarch64::regs::MPIDR_EL1;
    #[cfg(feature = "kvm")]
    use hypervisor::arm64_core_reg_id;
    #[cfg(feature = "kvm")]
    use hypervisor::kvm::aarch64::is_system_register;
    #[cfg(feature = "kvm")]
    use hypervisor::kvm::kvm_bindings::{
        user_pt_regs, KVM_REG_ARM64, KVM_REG_ARM64_SYSREG, KVM_REG_ARM_CORE, KVM_REG_SIZE_U64,
    };
    use hypervisor::HypervisorCpuError;

    #[test]
    fn test_setup_regs() {
        let hv = hypervisor::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0, None).unwrap();

        // Must fail when vcpu is not initialized yet.
        vcpu.setup_regs(0, 0x0, layout::FDT_START.0).unwrap_err();

        let mut kvi = vcpu.create_vcpu_init();
        vm.get_preferred_target(&mut kvi).unwrap();
        vcpu.vcpu_init(&kvi).unwrap();

        vcpu.setup_regs(0, 0x0, layout::FDT_START.0).unwrap();
    }

    #[test]
    fn test_read_mpidr() {
        let hv = hypervisor::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0, None).unwrap();
        let mut kvi = vcpu.create_vcpu_init();
        vm.get_preferred_target(&mut kvi).unwrap();

        // Must fail when vcpu is not initialized yet.
        vcpu.get_sys_reg(MPIDR_EL1).unwrap_err();

        vcpu.vcpu_init(&kvi).unwrap();
        assert_eq!(vcpu.get_sys_reg(MPIDR_EL1).unwrap(), 0x80000000);
    }

    #[cfg(feature = "kvm")]
    #[test]
    fn test_is_system_register() {
        let offset = offset_of!(user_pt_regs, pc);
        let regid = arm64_core_reg_id!(KVM_REG_SIZE_U64, offset);
        assert!(!is_system_register(regid));
        let regid = KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM64_SYSREG as u64;
        assert!(is_system_register(regid));
    }

    #[test]
    fn test_save_restore_core_regs() {
        let hv = hypervisor::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0, None).unwrap();
        let mut kvi = vcpu.create_vcpu_init();
        vm.get_preferred_target(&mut kvi).unwrap();

        fn hypervisor_cpu_error_to_raw_os_error(error: &anyhow::Error) -> libc::c_int {
            let cause = error.chain().next().expect("should have root cause");
            cause
                .downcast_ref::<vmm_sys_util::errno::Error>()
                .unwrap_or_else(|| panic!("should be io::Error but is: {cause:?}"))
                .errno() as libc::c_int
        }

        // test get_regs
        {
            let error = vcpu
                .get_regs()
                .expect_err("should fail as vCPU is not initialized");
            let io_error_raw = if let HypervisorCpuError::GetAarchCoreRegister(error) = error {
                hypervisor_cpu_error_to_raw_os_error(&error)
            } else {
                panic!("get_regs() must fail with error HypervisorCpuError::GetAarchCoreRegister");
            };
            assert_eq!(io_error_raw, libc::ENOEXEC);
        }

        // test set_regs
        let mut state = vcpu.create_standard_regs();
        {
            let error = vcpu
                .set_regs(&state)
                .expect_err("should fail as vCPU is not initialized");
            let io_error_raw = if let HypervisorCpuError::SetAarchCoreRegister(error) = error {
                hypervisor_cpu_error_to_raw_os_error(&error)
            } else {
                panic!("set_regs() must fail with error HypervisorCpuError::SetAarchCoreRegister");
            };
            assert_eq!(io_error_raw, libc::ENOEXEC);
        }

        vcpu.vcpu_init(&kvi).unwrap();
        state = vcpu.get_regs().unwrap();
        assert_eq!(state.get_pstate(), 0x3C5);

        vcpu.set_regs(&state).unwrap();
    }

    #[test]
    fn test_get_set_mpstate() {
        let hv = hypervisor::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0, None).unwrap();
        let mut kvi = vcpu.create_vcpu_init();
        vm.get_preferred_target(&mut kvi).unwrap();

        let state = vcpu.get_mp_state().unwrap();
        vcpu.set_mp_state(state).unwrap();
    }
}
