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

#[cfg(target_arch = "x86_64")]
use crate::config::CpuTopology;
use crate::config::CpusConfig;
use crate::device_manager::DeviceManager;
use crate::memory_manager::MemoryManager;
use crate::seccomp_filters::{get_seccomp_filter, Thread};
use crate::vm::physical_bits;
use crate::CPU_MANAGER_SNAPSHOT_ID;
#[cfg(feature = "acpi")]
use acpi_tables::{aml, aml::Aml, sdt::SDT};
use anyhow::anyhow;
#[cfg(feature = "acpi")]
use arch::layout;
#[cfg(target_arch = "x86_64")]
use arch::x86_64::SgxEpcSection;
#[cfg(target_arch = "x86_64")]
use arch::CpuidPatch;
use arch::EntryPoint;
use devices::interrupt_controller::InterruptController;
#[cfg(target_arch = "aarch64")]
use hypervisor::kvm::kvm_bindings;
#[cfg(target_arch = "x86_64")]
use hypervisor::CpuId;
use hypervisor::{CpuState, HypervisorCpuError, VmExit};
use seccomp::{SeccompAction, SeccompFilter};

use libc::{c_void, siginfo_t};
use std::os::unix::thread::JoinHandleExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::{cmp, io, result, thread};
use vm_device::BusDevice;
#[cfg(target_arch = "x86_64")]
use vm_memory::GuestAddress;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};
use vm_migration::{
    Migratable, MigratableError, Pausable, Snapshot, SnapshotDataSection, Snapshottable,
    Transportable,
};
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::signal::{register_signal_handler, SIGRTMIN};

// CPUID feature bits
#[cfg(target_arch = "x86_64")]
const TSC_DEADLINE_TIMER_ECX_BIT: u8 = 24; // tsc deadline timer ecx bit.
#[cfg(target_arch = "x86_64")]
const HYPERVISOR_ECX_BIT: u8 = 31; // Hypervisor ecx bit.
#[cfg(target_arch = "x86_64")]
const MTRR_EDX_BIT: u8 = 12; // Hypervisor ecx bit.

#[derive(Debug)]
pub enum Error {
    /// Cannot create the vCPU.
    VcpuCreate(anyhow::Error),

    /// Cannot run the VCPUs.
    VcpuRun(anyhow::Error),

    /// Cannot spawn a new vCPU thread.
    VcpuSpawn(io::Error),

    /// Cannot patch the CPU ID
    PatchCpuId(anyhow::Error),

    /// The call to KVM_SET_CPUID2 failed.
    SetSupportedCpusFailed(anyhow::Error),

    #[cfg(target_arch = "x86_64")]
    /// Cannot set the local interruption due to bad configuration.
    LocalIntConfiguration(anyhow::Error),

    /// Error configuring VCPU
    VcpuConfiguration(arch::Error),

    #[cfg(target_arch = "aarch64")]
    /// Error fetching prefered target
    VcpuArmPreferredTarget(hypervisor::HypervisorVmError),

    #[cfg(target_arch = "aarch64")]
    /// Error doing vCPU init on Arm.
    VcpuArmInit(hypervisor::HypervisorCpuError),

    /// Failed to join on vCPU threads
    ThreadCleanup(std::boxed::Box<dyn std::any::Any + std::marker::Send>),

    /// Cannot add legacy device to Bus.
    BusError(vm_device::BusError),

    /// Failed to allocate IO port
    AllocateIOPort,

    /// Asking for more vCPUs that we can have
    DesiredVCPUCountExceedsMax,

    /// Failed to get KVM vcpu lapic.
    VcpuGetLapic(anyhow::Error),

    /// Failed to set KVM vcpu lapic.
    VcpuSetLapic(anyhow::Error),

    /// Failed to get KVM vcpu MP state.
    VcpuGetMpState(anyhow::Error),

    /// Failed to set KVM vcpu MP state.
    VcpuSetMpState(anyhow::Error),

    /// Failed to get KVM vcpu msrs.
    VcpuGetMsrs(anyhow::Error),

    /// Failed to set KVM vcpu msrs.
    VcpuSetMsrs(anyhow::Error),

    /// Failed to get KVM vcpu regs.
    VcpuGetRegs(anyhow::Error),

    /// Failed to set KVM vcpu regs.
    VcpuSetRegs(anyhow::Error),

    /// Failed to get KVM vcpu sregs.
    VcpuGetSregs(anyhow::Error),

    /// Failed to set KVM vcpu sregs.
    VcpuSetSregs(anyhow::Error),

    /// Failed to get KVM vcpu events.
    VcpuGetVcpuEvents(anyhow::Error),

    /// Failed to set KVM vcpu events.
    VcpuSetVcpuEvents(anyhow::Error),

    /// Failed to get KVM vcpu FPU.
    VcpuGetFpu(anyhow::Error),

    /// Failed to set KVM vcpu FPU.
    VcpuSetFpu(anyhow::Error),

    /// Failed to get KVM vcpu XSAVE.
    VcpuGetXsave(anyhow::Error),

    /// Failed to set KVM vcpu XSAVE.
    VcpuSetXsave(anyhow::Error),

    /// Failed to get KVM vcpu XCRS.
    VcpuGetXcrs(anyhow::Error),

    /// Failed to set KVM vcpu XCRS.
    VcpuSetXcrs(anyhow::Error),

    /// Error resuming vCPU on shutdown
    ResumeOnShutdown(MigratableError),

    /// Cannot create seccomp filter
    CreateSeccompFilter(seccomp::SeccompError),

    /// Cannot apply seccomp filter
    ApplySeccompFilter(seccomp::Error),

    /// Error starting vCPU after restore
    StartRestoreVcpu(anyhow::Error),

    /// Error because an unexpected VmExit type was received.
    UnexpectedVmExit,
}
pub type Result<T> = result::Result<T, Error>;

#[cfg(feature = "acpi")]
#[repr(packed)]
struct LocalAPIC {
    pub r#type: u8,
    pub length: u8,
    pub processor_id: u8,
    pub apic_id: u8,
    pub flags: u32,
}

#[repr(packed)]
#[derive(Default)]
struct IOAPIC {
    pub r#type: u8,
    pub length: u8,
    pub ioapic_id: u8,
    _reserved: u8,
    pub apic_address: u32,
    pub gsi_base: u32,
}

#[repr(packed)]
#[derive(Default)]
struct InterruptSourceOverride {
    pub r#type: u8,
    pub length: u8,
    pub bus: u8,
    pub source: u8,
    pub gsi: u32,
    pub flags: u16,
}

/// A wrapper around creating and using a kvm-based VCPU.
pub struct Vcpu {
    // The hypervisor abstracted CPU.
    vcpu: Arc<dyn hypervisor::Vcpu>,
    id: u8,
    #[cfg(target_arch = "aarch64")]
    mpidr: u64,
    saved_state: Option<CpuState>,
}

impl Vcpu {
    /// Constructs a new VCPU for `vm`.
    ///
    /// # Arguments
    ///
    /// * `id` - Represents the CPU number between [0, max vcpus).
    /// * `vm` - The virtual machine this vcpu will get attached to.
    pub fn new(id: u8, vm: &Arc<dyn hypervisor::Vm>) -> Result<Arc<Mutex<Self>>> {
        let vcpu = vm
            .create_vcpu(id)
            .map_err(|e| Error::VcpuCreate(e.into()))?;
        // Initially the cpuid per vCPU is the one supported by this VM.
        Ok(Arc::new(Mutex::new(Vcpu {
            vcpu,
            id,
            #[cfg(target_arch = "aarch64")]
            mpidr: 0,
            saved_state: None,
        })))
    }

    /// Configures a vcpu and should be called once per vcpu when created.
    ///
    /// # Arguments
    ///
    /// * `kernel_entry_point` - Kernel entry point address in guest memory and boot protocol used.
    /// * `vm_memory` - Guest memory.
    /// * `cpuid` - (x86_64) CpuId, wrapper over the `kvm_cpuid2` structure.
    pub fn configure(
        &mut self,
        #[cfg(target_arch = "aarch64")] vm: &Arc<dyn hypervisor::Vm>,
        kernel_entry_point: Option<EntryPoint>,
        vm_memory: &GuestMemoryAtomic<GuestMemoryMmap>,
        #[cfg(target_arch = "x86_64")] cpuid: CpuId,
        #[cfg(target_arch = "x86_64")] kvm_hyperv: bool,
        phys_bits: u8,
    ) -> Result<()> {
        #[cfg(target_arch = "aarch64")]
        {
            self.init(vm)?;
            self.mpidr = arch::configure_vcpu(
                &self.vcpu,
                self.id,
                kernel_entry_point,
                vm_memory,
                phys_bits,
            )
            .map_err(Error::VcpuConfiguration)?;
        }

        #[cfg(target_arch = "x86_64")]
        arch::configure_vcpu(
            &self.vcpu,
            self.id,
            kernel_entry_point,
            vm_memory,
            cpuid,
            kvm_hyperv,
            phys_bits,
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
    #[cfg(target_arch = "aarch64")]
    pub fn get_saved_state(&self) -> Option<CpuState> {
        self.saved_state.clone()
    }

    /// Initializes an aarch64 specific vcpu for booting Linux.
    #[cfg(target_arch = "aarch64")]
    pub fn init(&self, vm: &Arc<dyn hypervisor::Vm>) -> Result<()> {
        let mut kvi: kvm_bindings::kvm_vcpu_init = kvm_bindings::kvm_vcpu_init::default();

        // This reads back the kernel's preferred target type.
        vm.get_preferred_target(&mut kvi)
            .map_err(Error::VcpuArmPreferredTarget)?;
        // We already checked that the capability is supported.
        kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_PSCI_0_2;
        // Non-boot cpus are powered off initially.
        if self.id > 0 {
            kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_POWER_OFF;
        }
        self.vcpu.vcpu_init(&kvi).map_err(Error::VcpuArmInit)
    }

    /// Runs the VCPU until it exits, returning the reason.
    ///
    /// Note that the state of the VCPU and associated VM must be setup first for this to do
    /// anything useful.
    pub fn run(&self) -> std::result::Result<VmExit, HypervisorCpuError> {
        self.vcpu.run()
    }
}

const VCPU_SNAPSHOT_ID: &str = "vcpu";
impl Pausable for Vcpu {
    fn pause(&mut self) -> std::result::Result<(), MigratableError> {
        self.saved_state =
            Some(self.vcpu.state().map_err(|e| {
                MigratableError::Pause(anyhow!("Could not get vCPU state {:?}", e))
            })?);

        Ok(())
    }

    fn resume(&mut self) -> std::result::Result<(), MigratableError> {
        if let Some(vcpu_state) = &self.saved_state {
            self.vcpu.set_state(vcpu_state).map_err(|e| {
                MigratableError::Pause(anyhow!("Could not set the vCPU state {:?}", e))
            })?;
        }

        Ok(())
    }
}
impl Snapshottable for Vcpu {
    fn id(&self) -> String {
        VCPU_SNAPSHOT_ID.to_string()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        let snapshot = serde_json::to_vec(&self.saved_state)
            .map_err(|e| MigratableError::Snapshot(e.into()))?;

        let mut vcpu_snapshot = Snapshot::new(&format!("{}", self.id));
        vcpu_snapshot.add_data_section(SnapshotDataSection {
            id: format!("{}-section", VCPU_SNAPSHOT_ID),
            snapshot,
        });

        Ok(vcpu_snapshot)
    }

    fn restore(&mut self, snapshot: Snapshot) -> std::result::Result<(), MigratableError> {
        if let Some(vcpu_section) = snapshot
            .snapshot_data
            .get(&format!("{}-section", VCPU_SNAPSHOT_ID))
        {
            let vcpu_state = match serde_json::from_slice(&vcpu_section.snapshot) {
                Ok(state) => state,
                Err(error) => {
                    return Err(MigratableError::Restore(anyhow!(
                        "Could not deserialize the vCPU snapshot {}",
                        error
                    )))
                }
            };

            self.saved_state = Some(vcpu_state);

            Ok(())
        } else {
            Err(MigratableError::Restore(anyhow!(
                "Could not find the vCPU snapshot section"
            )))
        }
    }
}

pub struct CpuManager {
    config: CpusConfig,
    #[cfg_attr(target_arch = "aarch64", allow(dead_code))]
    interrupt_controller: Option<Arc<Mutex<dyn InterruptController>>>,
    #[cfg_attr(target_arch = "aarch64", allow(dead_code))]
    vm_memory: GuestMemoryAtomic<GuestMemoryMmap>,
    #[cfg(target_arch = "x86_64")]
    cpuid: CpuId,
    #[cfg_attr(target_arch = "aarch64", allow(dead_code))]
    vm: Arc<dyn hypervisor::Vm>,
    vcpus_kill_signalled: Arc<AtomicBool>,
    vcpus_pause_signalled: Arc<AtomicBool>,
    exit_evt: EventFd,
    #[cfg_attr(target_arch = "aarch64", allow(dead_code))]
    reset_evt: EventFd,
    vcpu_states: Vec<VcpuState>,
    selected_cpu: u8,
    vcpus: Vec<Arc<Mutex<Vcpu>>>,
    seccomp_action: SeccompAction,
}

const CPU_ENABLE_FLAG: usize = 0;
const CPU_INSERTING_FLAG: usize = 1;
const CPU_REMOVING_FLAG: usize = 2;
const CPU_EJECT_FLAG: usize = 3;

const CPU_STATUS_OFFSET: u64 = 4;
const CPU_SELECTION_OFFSET: u64 = 0;

impl BusDevice for CpuManager {
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        match offset {
            CPU_STATUS_OFFSET => {
                if self.selected_cpu < self.present_vcpus() {
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

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) {
        match offset {
            CPU_SELECTION_OFFSET => {
                self.selected_cpu = data[0];
            }
            CPU_STATUS_OFFSET => {
                let state = &mut self.vcpu_states[usize::from(self.selected_cpu)];
                // The ACPI code writes back a 1 to acknowledge the insertion
                if (data[0] & (1 << CPU_INSERTING_FLAG) == 1 << CPU_INSERTING_FLAG)
                    && state.inserting
                {
                    state.inserting = false;
                }
                // Ditto for removal
                if (data[0] & (1 << CPU_REMOVING_FLAG) == 1 << CPU_REMOVING_FLAG) && state.removing
                {
                    state.removing = false;
                }
                // Trigger removal of vCPU
                if data[0] & (1 << CPU_EJECT_FLAG) == 1 << CPU_EJECT_FLAG {
                    if let Err(e) = self.remove_vcpu(self.selected_cpu) {
                        error!("Error removing vCPU: {:?}", e);
                    }
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
}

#[derive(Default)]
struct VcpuState {
    inserting: bool,
    removing: bool,
    handle: Option<thread::JoinHandle<()>>,
    kill: Arc<AtomicBool>,
    vcpu_run_interrupted: Arc<AtomicBool>,
}

impl VcpuState {
    fn active(&self) -> bool {
        self.handle.is_some()
    }

    fn signal_thread(&self) {
        if let Some(handle) = self.handle.as_ref() {
            loop {
                unsafe {
                    libc::pthread_kill(handle.as_pthread_t() as _, SIGRTMIN());
                }
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
        device_manager: &Arc<Mutex<DeviceManager>>,
        memory_manager: &Arc<Mutex<MemoryManager>>,
        vm: Arc<dyn hypervisor::Vm>,
        exit_evt: EventFd,
        reset_evt: EventFd,
        hypervisor: Arc<dyn hypervisor::Hypervisor>,
        seccomp_action: SeccompAction,
    ) -> Result<Arc<Mutex<CpuManager>>> {
        let guest_memory = memory_manager.lock().unwrap().guest_memory();
        let mut vcpu_states = Vec::with_capacity(usize::from(config.max_vcpus));
        vcpu_states.resize_with(usize::from(config.max_vcpus), VcpuState::default);

        #[cfg(target_arch = "x86_64")]
        let sgx_epc_sections =
            if let Some(sgx_epc_region) = memory_manager.lock().unwrap().sgx_epc_region() {
                Some(sgx_epc_region.epc_sections().clone())
            } else {
                None
            };
        #[cfg(target_arch = "x86_64")]
        let cpuid = CpuManager::patch_cpuid(hypervisor, &config.topology, sgx_epc_sections)?;

        let device_manager = device_manager.lock().unwrap();
        let cpu_manager = Arc::new(Mutex::new(CpuManager {
            config: config.clone(),
            interrupt_controller: device_manager.interrupt_controller().clone(),
            vm_memory: guest_memory,
            #[cfg(target_arch = "x86_64")]
            cpuid,
            vm,
            vcpus_kill_signalled: Arc::new(AtomicBool::new(false)),
            vcpus_pause_signalled: Arc::new(AtomicBool::new(false)),
            vcpu_states,
            exit_evt,
            reset_evt,
            selected_cpu: 0,
            vcpus: Vec::with_capacity(usize::from(config.max_vcpus)),
            seccomp_action,
        }));

        #[cfg(target_arch = "x86_64")]
        device_manager
            .allocator()
            .lock()
            .unwrap()
            .allocate_io_addresses(Some(GuestAddress(0x0cd8)), 0x8, None)
            .ok_or(Error::AllocateIOPort)?;

        #[cfg(target_arch = "x86_64")]
        device_manager
            .io_bus()
            .insert(cpu_manager.clone(), 0x0cd8, 0xc)
            .map_err(Error::BusError)?;

        Ok(cpu_manager)
    }

    #[cfg(target_arch = "x86_64")]
    fn patch_cpuid(
        hypervisor: Arc<dyn hypervisor::Hypervisor>,
        topology: &Option<CpuTopology>,
        sgx_epc_sections: Option<Vec<SgxEpcSection>>,
    ) -> Result<CpuId> {
        let mut cpuid_patches = Vec::new();

        // Patch tsc deadline timer bit
        cpuid_patches.push(CpuidPatch {
            function: 1,
            index: 0,
            flags_bit: None,
            eax_bit: None,
            ebx_bit: None,
            ecx_bit: Some(TSC_DEADLINE_TIMER_ECX_BIT),
            edx_bit: None,
        });

        // Patch hypervisor bit
        cpuid_patches.push(CpuidPatch {
            function: 1,
            index: 0,
            flags_bit: None,
            eax_bit: None,
            ebx_bit: None,
            ecx_bit: Some(HYPERVISOR_ECX_BIT),
            edx_bit: None,
        });

        // Enable MTRR feature
        cpuid_patches.push(CpuidPatch {
            function: 1,
            index: 0,
            flags_bit: None,
            eax_bit: None,
            ebx_bit: None,
            ecx_bit: None,
            edx_bit: Some(MTRR_EDX_BIT),
        });

        // Supported CPUID
        let mut cpuid = hypervisor
            .get_cpuid()
            .map_err(|e| Error::PatchCpuId(e.into()))?;

        CpuidPatch::patch_cpuid(&mut cpuid, cpuid_patches);

        if let Some(t) = topology {
            arch::x86_64::update_cpuid_topology(
                &mut cpuid,
                t.threads_per_core,
                t.cores_per_die,
                t.dies_per_package,
            );
        }

        if let Some(sgx_epc_sections) = sgx_epc_sections {
            arch::x86_64::update_cpuid_sgx(&mut cpuid, sgx_epc_sections).unwrap();
        }

        Ok(cpuid)
    }

    fn create_vcpu(
        &mut self,
        cpu_id: u8,
        entry_point: Option<EntryPoint>,
        snapshot: Option<Snapshot>,
    ) -> Result<Arc<Mutex<Vcpu>>> {
        info!("Creating vCPU: cpu_id = {}", cpu_id);

        let vcpu = Vcpu::new(cpu_id, &self.vm)?;

        if let Some(snapshot) = snapshot {
            // AArch64 vCPUs should be initialized after created.
            #[cfg(target_arch = "aarch64")]
            vcpu.lock().unwrap().init(&self.vm)?;

            vcpu.lock()
                .unwrap()
                .restore(snapshot)
                .expect("Failed to restore vCPU");
        } else {
            let vm_memory = self.vm_memory.clone();

            let phys_bits = physical_bits(self.config.max_phys_bits);

            #[cfg(target_arch = "x86_64")]
            vcpu.lock()
                .unwrap()
                .configure(
                    entry_point,
                    &vm_memory,
                    self.cpuid.clone(),
                    self.config.kvm_hyperv,
                    phys_bits,
                )
                .expect("Failed to configure vCPU");

            #[cfg(target_arch = "aarch64")]
            vcpu.lock()
                .unwrap()
                .configure(&self.vm, entry_point, &vm_memory, phys_bits)
                .expect("Failed to configure vCPU");
        }

        // Adding vCPU to the CpuManager's vCPU list.
        self.vcpus.push(Arc::clone(&vcpu));

        Ok(vcpu)
    }

    /// Only create new vCPUs if there aren't any inactive ones to reuse
    fn create_vcpus(&mut self, desired_vcpus: u8, entry_point: Option<EntryPoint>) -> Result<()> {
        info!(
            "Request to create new vCPUs: desired = {}, max = {}, allocated = {}, present = {}",
            desired_vcpus,
            self.config.max_vcpus,
            self.vcpus.len(),
            self.present_vcpus()
        );

        if desired_vcpus > self.config.max_vcpus {
            return Err(Error::DesiredVCPUCountExceedsMax);
        }

        // Only create vCPUs in excess of all the allocated vCPUs.
        for cpu_id in self.vcpus.len() as u8..desired_vcpus {
            self.create_vcpu(cpu_id, entry_point, None)?;
        }

        Ok(())
    }

    fn start_vcpu(
        &mut self,
        vcpu: Arc<Mutex<Vcpu>>,
        vcpu_thread_barrier: Arc<Barrier>,
        inserting: bool,
    ) -> Result<()> {
        let cpu_id = vcpu.lock().unwrap().id;
        let reset_evt = self.reset_evt.try_clone().unwrap();
        let exit_evt = self.exit_evt.try_clone().unwrap();
        let vcpu_kill_signalled = self.vcpus_kill_signalled.clone();
        let vcpu_pause_signalled = self.vcpus_pause_signalled.clone();

        let vcpu_kill = self.vcpu_states[usize::from(cpu_id)].kill.clone();
        let vcpu_run_interrupted = self.vcpu_states[usize::from(cpu_id)]
            .vcpu_run_interrupted
            .clone();

        info!("Starting vCPU: cpu_id = {}", cpu_id);

        // Retrieve seccomp filter for vcpu thread
        let vcpu_seccomp_filter = get_seccomp_filter(&self.seccomp_action, Thread::Vcpu)
            .map_err(Error::CreateSeccompFilter)?;

        #[cfg(target_arch = "x86_64")]
        let interrupt_controller_clone =
            if let Some(interrupt_controller) = &self.interrupt_controller {
                Some(interrupt_controller.clone())
            } else {
                None
            };

        let handle = Some(
            thread::Builder::new()
                .name(format!("vcpu{}", cpu_id))
                .spawn(move || {
                    // Apply seccomp filter for vcpu thread.
                    if let Err(e) =
                        SeccompFilter::apply(vcpu_seccomp_filter).map_err(Error::ApplySeccompFilter)
                    {
                        error!("Error applying seccomp filter: {:?}", e);
                        return;
                    }

                    extern "C" fn handle_signal(_: i32, _: *mut siginfo_t, _: *mut c_void) {}
                    // This uses an async signal safe handler to kill the vcpu handles.
                    register_signal_handler(SIGRTMIN(), handle_signal)
                        .expect("Failed to register vcpu signal handler");

                    // Block until all CPUs are ready.
                    vcpu_thread_barrier.wait();

                    loop {
                        // If we are being told to pause, we park the thread
                        // until the pause boolean is toggled.
                        // The resume operation is responsible for toggling
                        // the boolean and unpark the thread.
                        // We enter a loop because park() could spuriously
                        // return. We will then park() again unless the
                        // pause boolean has been toggled.
                        if vcpu_pause_signalled.load(Ordering::SeqCst) {
                            vcpu_run_interrupted.store(true, Ordering::SeqCst);
                            while vcpu_pause_signalled.load(Ordering::SeqCst) {
                                thread::park();
                            }
                            vcpu_run_interrupted.store(false, Ordering::SeqCst);
                        }

                        // We've been told to terminate
                        if vcpu_kill_signalled.load(Ordering::SeqCst)
                            || vcpu_kill.load(Ordering::SeqCst)
                        {
                            vcpu_run_interrupted.store(true, Ordering::SeqCst);
                            break;
                        }

                        // vcpu.run() returns false on a triple-fault so trigger a reset
                        match vcpu.lock().unwrap().run() {
                            Ok(run) => match run {
                                #[cfg(target_arch = "x86_64")]
                                VmExit::IoapicEoi(vector) => {
                                    if let Some(interrupt_controller) = &interrupt_controller_clone
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
                                    debug!("VmExit::Reset");
                                    vcpu_run_interrupted.store(true, Ordering::SeqCst);
                                    reset_evt.write(1).unwrap();
                                    break;
                                }
                                VmExit::Shutdown => {
                                    debug!("VmExit::Shutdown");
                                    vcpu_run_interrupted.store(true, Ordering::SeqCst);
                                    exit_evt.write(1).unwrap();
                                    break;
                                }
                                _ => {
                                    error!("VCPU generated error: {:?}", Error::UnexpectedVmExit);
                                    break;
                                }
                            },

                            Err(e) => {
                                error!("VCPU generated error: {:?}", Error::VcpuRun(e.into()));
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
                .map_err(Error::VcpuSpawn)?,
        );

        // On hot plug calls into this function entry_point is None. It is for
        // those hotplug CPU additions that we need to set the inserting flag.
        self.vcpu_states[usize::from(cpu_id)].handle = handle;
        self.vcpu_states[usize::from(cpu_id)].inserting = inserting;

        Ok(())
    }

    /// Start up as many vCPUs threads as needed to reach `desired_vcpus`
    fn activate_vcpus(&mut self, desired_vcpus: u8, inserting: bool) -> Result<()> {
        if desired_vcpus > self.config.max_vcpus {
            return Err(Error::DesiredVCPUCountExceedsMax);
        }

        let vcpu_thread_barrier = Arc::new(Barrier::new(
            (desired_vcpus - self.present_vcpus() + 1) as usize,
        ));

        info!(
            "Starting vCPUs: desired = {}, allocated = {}, present = {}",
            desired_vcpus,
            self.vcpus.len(),
            self.present_vcpus()
        );

        // This reuses any inactive vCPUs as well as any that were newly created
        for cpu_id in self.present_vcpus()..desired_vcpus {
            let vcpu = Arc::clone(&self.vcpus[cpu_id as usize]);
            self.start_vcpu(vcpu, vcpu_thread_barrier.clone(), inserting)?;
        }

        // Unblock all CPU threads.
        vcpu_thread_barrier.wait();
        Ok(())
    }

    fn mark_vcpus_for_removal(&mut self, desired_vcpus: u8) -> Result<()> {
        // Mark vCPUs for removal, actual removal happens on ejection
        for cpu_id in desired_vcpus..self.present_vcpus() {
            self.vcpu_states[usize::from(cpu_id)].removing = true;
        }
        Ok(())
    }

    fn remove_vcpu(&mut self, cpu_id: u8) -> Result<()> {
        info!("Removing vCPU: cpu_id = {}", cpu_id);
        let mut state = &mut self.vcpu_states[usize::from(cpu_id)];
        state.kill.store(true, Ordering::SeqCst);
        state.signal_thread();
        state.join_thread()?;
        state.handle = None;

        // Once the thread has exited, clear the "kill" so that it can reused
        state.kill.store(false, Ordering::SeqCst);

        Ok(())
    }

    pub fn create_boot_vcpus(&mut self, entry_point: EntryPoint) -> Result<()> {
        self.create_vcpus(self.boot_vcpus(), Some(entry_point))
    }

    // Starts all the vCPUs that the VM is booting with. Blocks until all vCPUs are running.
    pub fn start_boot_vcpus(&mut self) -> Result<()> {
        self.activate_vcpus(self.boot_vcpus(), false)
    }

    pub fn start_restored_vcpus(&mut self) -> Result<()> {
        let vcpu_numbers = self.vcpus.len();
        let vcpu_thread_barrier = Arc::new(Barrier::new((vcpu_numbers + 1) as usize));
        // Restore the vCPUs in "paused" state.
        self.vcpus_pause_signalled.store(true, Ordering::SeqCst);

        for vcpu_index in 0..vcpu_numbers {
            let vcpu = Arc::clone(&self.vcpus[vcpu_index as usize]);

            self.start_vcpu(vcpu, vcpu_thread_barrier.clone(), false)
                .map_err(|e| {
                    Error::StartRestoreVcpu(anyhow!("Failed to start restored vCPUs: {:#?}", e))
                })?;
        }
        // Unblock all restored CPU threads.
        vcpu_thread_barrier.wait();
        Ok(())
    }

    pub fn resize(&mut self, desired_vcpus: u8) -> Result<bool> {
        match desired_vcpus.cmp(&self.present_vcpus()) {
            cmp::Ordering::Greater => {
                self.create_vcpus(desired_vcpus, None)?;
                self.activate_vcpus(desired_vcpus, true)?;
                Ok(true)
            }
            cmp::Ordering::Less => self.mark_vcpus_for_removal(desired_vcpus).and(Ok(true)),
            _ => Ok(false),
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

        // Signal to the spawned threads (vCPUs and console signal handler). For the vCPU threads
        // this will interrupt the KVM_RUN ioctl() allowing the loop to check the boolean set
        // above.
        for state in self.vcpu_states.iter() {
            state.signal_thread();
        }

        // Wait for all the threads to finish. This removes the state from the vector.
        for mut state in self.vcpu_states.drain(..) {
            state.join_thread()?;
        }

        Ok(())
    }

    pub fn boot_vcpus(&self) -> u8 {
        self.config.boot_vcpus
    }

    pub fn max_vcpus(&self) -> u8 {
        self.config.max_vcpus
    }

    fn present_vcpus(&self) -> u8 {
        self.vcpu_states
            .iter()
            .fold(0, |acc, state| acc + state.active() as u8)
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

    #[cfg(feature = "acpi")]
    pub fn create_madt(&self) -> SDT {
        // This is also checked in the commandline parsing.
        assert!(self.config.boot_vcpus <= self.config.max_vcpus);

        let mut madt = SDT::new(*b"APIC", 44, 5, *b"CLOUDH", *b"CHMADT  ", 1);
        madt.write(36, layout::APIC_START);

        for cpu in 0..self.config.max_vcpus {
            let lapic = LocalAPIC {
                r#type: 0,
                length: 8,
                processor_id: cpu,
                apic_id: cpu,
                flags: if cpu < self.config.boot_vcpus {
                    1 << MADT_CPU_ENABLE_FLAG
                } else {
                    0
                },
            };
            madt.append(lapic);
        }

        madt.append(IOAPIC {
            r#type: 1,
            length: 12,
            ioapic_id: 0,
            apic_address: layout::IOAPIC_START.0 as u32,
            gsi_base: 0,
            ..Default::default()
        });

        madt.append(InterruptSourceOverride {
            r#type: 2,
            length: 10,
            bus: 0,
            source: 4,
            gsi: 4,
            flags: 0,
        });

        madt
    }
}

#[cfg(feature = "acpi")]
struct CPU {
    cpu_id: u8,
}

#[cfg(feature = "acpi")]
const MADT_CPU_ENABLE_FLAG: usize = 0;

#[cfg(feature = "acpi")]
impl Aml for CPU {
    fn to_aml_bytes(&self) -> Vec<u8> {
        let lapic = LocalAPIC {
            r#type: 0,
            length: 8,
            processor_id: self.cpu_id,
            apic_id: self.cpu_id,
            flags: 1 << MADT_CPU_ENABLE_FLAG,
        };

        let mut mat_data: Vec<u8> = Vec::new();
        mat_data.resize(std::mem::size_of_val(&lapic), 0);
        unsafe { *(mat_data.as_mut_ptr() as *mut LocalAPIC) = lapic };

        aml::Device::new(
            format!("C{:03}", self.cpu_id).as_str().into(),
            vec![
                &aml::Name::new("_HID".into(), &"ACPI0007"),
                &aml::Name::new("_UID".into(), &self.cpu_id),
                /*
                _STA return value:
                Bit [0] – Set if the device is present.
                Bit [1] – Set if the device is enabled and decoding its resources.
                Bit [2] – Set if the device should be shown in the UI.
                Bit [3] – Set if the device is functioning properly (cleared if device failed its diagnostics).
                Bit [4] – Set if the battery is present.
                Bits [31:5] – Reserved (must be cleared).
                */
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
                // The Linux kernel expects every CPU device to have a _MAT entry
                // containing the LAPIC for this processor with the enabled bit set
                // even it if is disabled in the MADT (non-boot CPU)
                &aml::Name::new("_MAT".into(), &aml::Buffer::new(mat_data)),
                // Trigger CPU ejection
                &aml::Method::new(
                    "_EJ0".into(),
                    1,
                    false,
                    // Call into CEJ0 method which will actually eject device
                    vec![&aml::Return::new(&aml::MethodCall::new(
                        "CEJ0".into(),
                        vec![&self.cpu_id],
                    ))],
                ),
            ],
        )
        .to_aml_bytes()
    }
}

#[cfg(feature = "acpi")]
struct CPUNotify {
    cpu_id: u8,
}

#[cfg(feature = "acpi")]
impl Aml for CPUNotify {
    fn to_aml_bytes(&self) -> Vec<u8> {
        let object = aml::Path::new(&format!("C{:03}", self.cpu_id));
        aml::If::new(
            &aml::Equal::new(&aml::Arg(0), &self.cpu_id),
            vec![&aml::Notify::new(&object, &aml::Arg(1))],
        )
        .to_aml_bytes()
    }
}

#[cfg(feature = "acpi")]
struct CPUMethods {
    max_vcpus: u8,
}

#[cfg(feature = "acpi")]
impl Aml for CPUMethods {
    fn to_aml_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            // CPU status method
            &aml::Method::new(
                "CSTA".into(),
                1,
                true,
                vec![
                    // Take lock defined above
                    &aml::Acquire::new("\\_SB_.PRES.CPLK".into(), 0xfff),
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
            .to_aml_bytes(),
        );

        let mut cpu_notifies = Vec::new();
        for cpu_id in 0..self.max_vcpus {
            cpu_notifies.push(CPUNotify { cpu_id });
        }

        let mut cpu_notifies_refs: Vec<&dyn aml::Aml> = Vec::new();
        for cpu_id in 0..self.max_vcpus {
            cpu_notifies_refs.push(&cpu_notifies[usize::from(cpu_id)]);
        }

        bytes.extend_from_slice(
            &aml::Method::new("CTFY".into(), 2, true, cpu_notifies_refs).to_aml_bytes(),
        );

        bytes.extend_from_slice(
            &aml::Method::new(
                "CEJ0".into(),
                1,
                true,
                vec![
                    &aml::Acquire::new("\\_SB_.PRES.CPLK".into(), 0xfff),
                    // Write CPU number (in first argument) to I/O port via field
                    &aml::Store::new(&aml::Path::new("\\_SB_.PRES.CSEL"), &aml::Arg(0)),
                    // Set CEJ0 bit
                    &aml::Store::new(&aml::Path::new("\\_SB_.PRES.CEJ0"), &aml::ONE),
                    &aml::Release::new("\\_SB_.PRES.CPLK".into()),
                ],
            )
            .to_aml_bytes(),
        );

        bytes.extend_from_slice(
            &aml::Method::new(
                "CSCN".into(),
                0,
                true,
                vec![
                    // Take lock defined above
                    &aml::Acquire::new("\\_SB_.PRES.CPLK".into(), 0xfff),
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
            .to_aml_bytes(),
        );
        bytes
    }
}

#[cfg(feature = "acpi")]
impl Aml for CpuManager {
    fn to_aml_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        // CPU hotplug controller
        bytes.extend_from_slice(
            &aml::Device::new(
                "_SB_.PRES".into(),
                vec![
                    &aml::Name::new("_HID".into(), &aml::EISAName::new("PNP0A06")),
                    &aml::Name::new("_UID".into(), &"CPU Hotplug Controller"),
                    // Mutex to protect concurrent access as we write to choose CPU and then read back status
                    &aml::Mutex::new("CPLK".into(), 0),
                    // I/O port for CPU controller
                    &aml::Name::new(
                        "_CRS".into(),
                        &aml::ResourceTemplate::new(vec![&aml::IO::new(
                            0x0cd8, 0x0cd8, 0x01, 0x0c,
                        )]),
                    ),
                    // OpRegion and Fields map I/O port into individual field values
                    &aml::OpRegion::new("PRST".into(), aml::OpRegionSpace::SystemIO, 0x0cd8, 0x0c),
                    &aml::Field::new(
                        "PRST".into(),
                        aml::FieldAccessType::Byte,
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
                        aml::FieldUpdateRule::Preserve,
                        vec![
                            aml::FieldEntry::Named(*b"CSEL", 32),
                            aml::FieldEntry::Reserved(32),
                            aml::FieldEntry::Named(*b"CDAT", 32),
                        ],
                    ),
                ],
            )
            .to_aml_bytes(),
        );

        // CPU devices
        let hid = aml::Name::new("_HID".into(), &"ACPI0010");
        let uid = aml::Name::new("_CID".into(), &aml::EISAName::new("PNP0A05"));
        // Bundle methods together under a common object
        let methods = CPUMethods {
            max_vcpus: self.config.max_vcpus,
        };
        let mut cpu_data_inner: Vec<&dyn aml::Aml> = vec![&hid, &uid, &methods];

        let mut cpu_devices = Vec::new();
        for cpu_id in 0..self.config.max_vcpus {
            let cpu_device = CPU { cpu_id };

            cpu_devices.push(cpu_device);
        }

        for cpu_device in cpu_devices.iter() {
            cpu_data_inner.push(cpu_device);
        }

        bytes.extend_from_slice(
            &aml::Device::new("_SB_.CPUS".into(), cpu_data_inner).to_aml_bytes(),
        );
        bytes
    }
}

impl Pausable for CpuManager {
    fn pause(&mut self) -> std::result::Result<(), MigratableError> {
        // Tell the vCPUs to pause themselves next time they exit
        self.vcpus_pause_signalled.store(true, Ordering::SeqCst);

        // Signal to the spawned threads (vCPUs and console signal handler). For the vCPU threads
        // this will interrupt the KVM_RUN ioctl() allowing the loop to check the boolean set
        // above.
        for state in self.vcpu_states.iter() {
            state.signal_thread();
        }

        for vcpu in self.vcpus.iter() {
            let mut vcpu = vcpu.lock().unwrap();
            vcpu.pause()?;
            #[cfg(target_arch = "x86_64")]
            if !self.config.kvm_hyperv {
                vcpu.vcpu.notify_guest_clock_paused().map_err(|e| {
                    MigratableError::Pause(anyhow!(
                        "Could not notify guest it has been paused {:?}",
                        e
                    ))
                })?;
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
        let mut cpu_manager_snapshot = Snapshot::new(CPU_MANAGER_SNAPSHOT_ID);

        // The CpuManager snapshot is a collection of all vCPUs snapshots.
        for vcpu in &self.vcpus {
            let cpu_snapshot = vcpu.lock().unwrap().snapshot()?;
            cpu_manager_snapshot.add_snapshot(cpu_snapshot);
        }

        Ok(cpu_manager_snapshot)
    }

    fn restore(&mut self, snapshot: Snapshot) -> std::result::Result<(), MigratableError> {
        for (cpu_id, snapshot) in snapshot.snapshots.iter() {
            debug!("Restoring VCPU {}", cpu_id);
            self.create_vcpu(cpu_id.parse::<u8>().unwrap(), None, Some(*snapshot.clone()))
                .map_err(|e| MigratableError::Restore(anyhow!("Could not create vCPU {:?}", e)))?;
        }

        Ok(())
    }
}

impl Transportable for CpuManager {}
impl Migratable for CpuManager {}

#[cfg(target_arch = "x86_64")]
#[cfg(test)]
mod tests {

    use super::*;
    use arch::x86_64::interrupts::*;
    use arch::x86_64::regs::*;
    use arch::x86_64::BootProtocol;
    use hypervisor::x86_64::{FpuState, LapicState, SpecialRegisters, StandardRegisters};

    #[test]
    fn test_setlint() {
        let hv = hypervisor::new().unwrap();
        let vm = hv.create_vm().expect("new VM fd creation failed");
        assert!(hv.check_capability(hypervisor::kvm::Cap::Irqchip));
        // Calling get_lapic will fail if there is no irqchip before hand.
        assert!(vm.create_irq_chip().is_ok());
        let vcpu = vm.create_vcpu(0).unwrap();
        let klapic_before: LapicState = vcpu.get_lapic().unwrap();

        // Compute the value that is expected to represent LVT0 and LVT1.
        let lint0 = get_klapic_reg(&klapic_before, APIC_LVT0);
        let lint1 = get_klapic_reg(&klapic_before, APIC_LVT1);
        let lint0_mode_expected = set_apic_delivery_mode(lint0, APIC_MODE_EXTINT);
        let lint1_mode_expected = set_apic_delivery_mode(lint1, APIC_MODE_NMI);

        set_lint(&vcpu).unwrap();

        // Compute the value that represents LVT0 and LVT1 after set_lint.
        let klapic_actual: LapicState = vcpu.get_lapic().unwrap();
        let lint0_mode_actual = get_klapic_reg(&klapic_actual, APIC_LVT0);
        let lint1_mode_actual = get_klapic_reg(&klapic_actual, APIC_LVT1);
        assert_eq!(lint0_mode_expected, lint0_mode_actual);
        assert_eq!(lint1_mode_expected, lint1_mode_actual);
    }

    #[test]
    fn test_setup_fpu() {
        let hv = hypervisor::new().unwrap();
        let vm = hv.create_vm().expect("new VM fd creation failed");
        let vcpu = vm.create_vcpu(0).unwrap();
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
        use hypervisor::arch::x86::msr_index;
        use hypervisor::x86_64::{MsrEntries, MsrEntry};

        let hv = hypervisor::new().unwrap();
        let vm = hv.create_vm().expect("new VM fd creation failed");
        let vcpu = vm.create_vcpu(0).unwrap();
        setup_msrs(&vcpu).unwrap();

        // This test will check against the last MSR entry configured (the tenth one).
        // See create_msr_entries for details.
        let mut msrs = MsrEntries::from_entries(&[MsrEntry {
            index: msr_index::MSR_IA32_MISC_ENABLE,
            ..Default::default()
        }]);

        // get_msrs returns the number of msrs that it succeed in reading. We only want to read 1
        // in this test case scenario.
        let read_msrs = vcpu.get_msrs(&mut msrs).unwrap();
        assert_eq!(read_msrs, 1);

        // Official entries that were setup when we did setup_msrs. We need to assert that the
        // tenth one (i.e the one with index msr_index::MSR_IA32_MISC_ENABLE has the data we
        // expect.
        let entry_vec = hypervisor::x86_64::boot_msr_entries();
        assert_eq!(entry_vec.as_slice()[9], msrs.as_slice()[0]);
    }

    #[test]
    fn test_setup_regs() {
        let hv = hypervisor::new().unwrap();
        let vm = hv.create_vm().expect("new VM fd creation failed");
        let vcpu = vm.create_vcpu(0).unwrap();

        let expected_regs: StandardRegisters = StandardRegisters {
            rflags: 0x0000000000000002u64,
            rip: 1,
            rsp: 2,
            rbp: 2,
            rsi: 3,
            ..Default::default()
        };

        setup_regs(
            &vcpu,
            expected_regs.rip,
            expected_regs.rsp,
            expected_regs.rsi,
            BootProtocol::LinuxBoot,
        )
        .unwrap();

        let actual_regs: StandardRegisters = vcpu.get_regs().unwrap();
        assert_eq!(actual_regs, expected_regs);
    }

    #[test]
    fn test_setup_sregs() {
        let hv = hypervisor::new().unwrap();
        let vm = hv.create_vm().expect("new VM fd creation failed");
        let vcpu = vm.create_vcpu(0).unwrap();

        let mut expected_sregs: SpecialRegisters = vcpu.get_sregs().unwrap();
        let gm = GuestMemoryMmap::from_ranges(&vec![(GuestAddress(0), 0x10000)]).unwrap();
        configure_segments_and_sregs(&gm, &mut expected_sregs, BootProtocol::LinuxBoot).unwrap();
        setup_page_tables(&gm, &mut expected_sregs).unwrap();

        setup_sregs(&gm, &vcpu, BootProtocol::LinuxBoot).unwrap();
        let actual_sregs: SpecialRegisters = vcpu.get_sregs().unwrap();
        assert_eq!(expected_sregs, actual_sregs);
    }
}

#[cfg(target_arch = "aarch64")]
#[cfg(test)]
mod tests {
    use arch::aarch64::layout;
    use arch::aarch64::regs::*;
    use hypervisor::kvm::aarch64::{is_system_register, MPIDR_EL1};
    use hypervisor::kvm::kvm_bindings::{
        kvm_one_reg, kvm_regs, kvm_vcpu_init, user_pt_regs, KVM_REG_ARM64, KVM_REG_ARM64_SYSREG,
        KVM_REG_ARM_CORE, KVM_REG_SIZE_U64,
    };
    use hypervisor::{arm64_core_reg_id, offset__of};
    use std::mem;
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    #[test]
    fn test_setup_regs() {
        let hv = hypervisor::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let mut regions = Vec::new();
        regions.push((
            GuestAddress(layout::RAM_64BIT_START),
            (layout::FDT_MAX_SIZE + 0x1000) as usize,
        ));
        let mem = GuestMemoryMmap::from_ranges(&regions).expect("Cannot initialize memory");

        let res = setup_regs(&vcpu, 0, 0x0, &mem);
        // Must fail when vcpu is not initialized yet.
        assert!(res.is_err());

        let mut kvi: kvm_vcpu_init = kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi).unwrap();
        vcpu.vcpu_init(&kvi).unwrap();

        assert!(setup_regs(&vcpu, 0, 0x0, &mem).is_ok());
    }

    #[test]
    fn test_read_mpidr() {
        let hv = hypervisor::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let mut kvi: kvm_vcpu_init = kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi).unwrap();

        // Must fail when vcpu is not initialized yet.
        assert!(vcpu.read_mpidr().is_err());

        vcpu.vcpu_init(&kvi).unwrap();
        assert_eq!(vcpu.read_mpidr().unwrap(), 0x80000000);
    }

    #[test]
    fn test_is_system_register() {
        let offset = offset__of!(user_pt_regs, pc);
        let regid = arm64_core_reg_id!(KVM_REG_SIZE_U64, offset);
        assert!(!is_system_register(regid));
        let regid = KVM_REG_ARM64 as u64 | KVM_REG_SIZE_U64 as u64 | KVM_REG_ARM64_SYSREG as u64;
        assert!(is_system_register(regid));
    }

    #[test]
    fn test_save_restore_core_regs() {
        let hv = hypervisor::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let mut kvi: kvm_vcpu_init = kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi).unwrap();

        // Must fail when vcpu is not initialized yet.
        let mut state = kvm_regs::default();
        let res = vcpu.core_registers(&mut state);
        assert!(res.is_err());
        assert_eq!(
            format!("{}", res.unwrap_err()),
            "Failed to get core register: Exec format error (os error 8)"
        );

        let res = vcpu.set_core_registers(&mut state);
        assert!(res.is_err());
        assert_eq!(
            format!("{}", res.unwrap_err()),
            "Failed to set core register: Exec format error (os error 8)"
        );

        vcpu.vcpu_init(&kvi).unwrap();
        assert!(vcpu.core_registers(&mut state).is_ok());
        assert_eq!(state.regs.pstate, 0x3C5);

        assert!(vcpu.set_core_registers(&state).is_ok());
        let off = offset__of!(user_pt_regs, pstate);
        let pstate = vcpu
            .get_reg(arm64_core_reg_id!(KVM_REG_SIZE_U64, off))
            .expect("Failed to call kvm get one reg");
        assert_eq!(state.regs.pstate, pstate);
    }

    #[test]
    fn test_save_restore_system_regs() {
        let hv = hypervisor::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let mut kvi: kvm_vcpu_init = kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi).unwrap();

        // Must fail when vcpu is not initialized yet.
        let mut state: Vec<kvm_one_reg> = Vec::new();
        let res = vcpu.system_registers(&mut state);
        assert!(res.is_err());
        assert_eq!(
            format!("{}", res.unwrap_err()),
            "Failed to retrieve list of registers: Exec format error (os error 8)"
        );

        state.push(kvm_one_reg {
            id: MPIDR_EL1,
            addr: 0x00,
        });
        let res = vcpu.set_system_registers(&mut state);
        assert!(res.is_err());
        assert_eq!(
            format!("{}", res.unwrap_err()),
            "Failed to set system register: Exec format error (os error 8)"
        );

        vcpu.vcpu_init(&kvi).unwrap();
        assert!(vcpu.system_registers(&mut state).is_ok());
        let initial_mpidr: u64 = vcpu.read_mpidr().expect("Fail to read mpidr");
        assert!(state.contains(&kvm_one_reg {
            id: MPIDR_EL1,
            addr: initial_mpidr
        }));

        assert!(vcpu.set_system_registers(&state).is_ok());
        let mpidr: u64 = vcpu.read_mpidr().expect("Fail to read mpidr");
        assert_eq!(initial_mpidr, mpidr);
    }

    #[test]
    fn test_get_set_mpstate() {
        let hv = hypervisor::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let mut kvi: kvm_vcpu_init = kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi).unwrap();

        let res = vcpu.get_mp_state();
        assert!(res.is_ok());
        assert!(vcpu.set_mp_state(res.unwrap()).is_ok());
    }
}
