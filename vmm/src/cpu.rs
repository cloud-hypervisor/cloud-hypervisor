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

use crate::config::CpusConfig;
use crate::device_manager::DeviceManager;
use crate::CPU_MANAGER_SNAPSHOT_ID;
#[cfg(feature = "acpi")]
use acpi_tables::{aml, aml::Aml, sdt::SDT};
use anyhow::anyhow;
#[cfg(feature = "acpi")]
use arch::layout;
use arch::EntryPoint;
#[cfg(target_arch = "x86_64")]
use arch::{CpuidPatch, CpuidReg};
use devices::{interrupt_controller::InterruptController, BusDevice};
#[cfg(target_arch = "aarch64")]
use kvm_bindings::KVM_SYSTEM_EVENT_SHUTDOWN;
#[cfg(target_arch = "x86_64")]
use kvm_bindings::{
    kvm_fpu, kvm_lapic_state, kvm_mp_state, kvm_regs, kvm_sregs, kvm_vcpu_events, kvm_xcrs,
    kvm_xsave, CpuId, Msrs,
};
use kvm_ioctls::*;
use libc::{c_void, siginfo_t};
use serde_derive::{Deserialize, Serialize};
#[cfg(target_arch = "x86_64")]
use std::fmt;
use std::os::unix::thread::JoinHandleExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::{cmp, io, result, thread};
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

// Debug I/O port
#[cfg(target_arch = "x86_64")]
const DEBUG_IOPORT: u16 = 0x80;
#[cfg(target_arch = "x86_64")]
const DEBUG_IOPORT_PREFIX: &str = "Debug I/O port";

#[cfg(target_arch = "x86_64")]
/// Debug I/O port, see:
/// https://www.intel.com/content/www/us/en/support/articles/000005500/boards-and-kits.html
///
/// Since we're not a physical platform, we can freely assign code ranges for
/// debugging specific parts of our virtual platform.
pub enum DebugIoPortRange {
    Firmware,
    Bootloader,
    Kernel,
    Userspace,
    Custom,
}
#[cfg(target_arch = "x86_64")]
impl DebugIoPortRange {
    fn from_u8(value: u8) -> DebugIoPortRange {
        match value {
            0x00..=0x1f => DebugIoPortRange::Firmware,
            0x20..=0x3f => DebugIoPortRange::Bootloader,
            0x40..=0x5f => DebugIoPortRange::Kernel,
            0x60..=0x7f => DebugIoPortRange::Userspace,
            _ => DebugIoPortRange::Custom,
        }
    }
}

#[cfg(target_arch = "x86_64")]
impl fmt::Display for DebugIoPortRange {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DebugIoPortRange::Firmware => write!(f, "{}: Firmware", DEBUG_IOPORT_PREFIX),
            DebugIoPortRange::Bootloader => write!(f, "{}: Bootloader", DEBUG_IOPORT_PREFIX),
            DebugIoPortRange::Kernel => write!(f, "{}: Kernel", DEBUG_IOPORT_PREFIX),
            DebugIoPortRange::Userspace => write!(f, "{}: Userspace", DEBUG_IOPORT_PREFIX),
            DebugIoPortRange::Custom => write!(f, "{}: Custom", DEBUG_IOPORT_PREFIX),
        }
    }
}

#[derive(Debug)]
pub enum Error {
    /// Cannot open the VCPU file descriptor.
    VcpuFd(kvm_ioctls::Error),

    /// Cannot run the VCPUs.
    VcpuRun(kvm_ioctls::Error),

    /// Cannot spawn a new vCPU thread.
    VcpuSpawn(io::Error),

    /// Cannot patch the CPU ID
    PatchCpuId(kvm_ioctls::Error),

    /// The call to KVM_SET_CPUID2 failed.
    SetSupportedCpusFailed(kvm_ioctls::Error),

    #[cfg(target_arch = "x86_64")]
    /// Cannot set the local interruption due to bad configuration.
    LocalIntConfiguration(arch::x86_64::interrupts::Error),

    /// Error configuring VCPU
    VcpuConfiguration(arch::Error),

    /// Unexpected KVM_RUN exit reason
    VcpuUnhandledKvmExit,

    /// Failed to join on vCPU threads
    ThreadCleanup(std::boxed::Box<dyn std::any::Any + std::marker::Send>),

    /// Cannot add legacy device to Bus.
    BusError(devices::BusError),

    /// Failed to allocate IO port
    AllocateIOPort,

    /// Asking for more vCPUs that we can have
    DesiredVCPUCountExceedsMax,

    /// Failed to get KVM vcpu lapic.
    VcpuGetLapic(kvm_ioctls::Error),

    /// Failed to set KVM vcpu lapic.
    VcpuSetLapic(kvm_ioctls::Error),

    /// Failed to get KVM vcpu MP state.
    VcpuGetMpState(kvm_ioctls::Error),

    /// Failed to set KVM vcpu MP state.
    VcpuSetMpState(kvm_ioctls::Error),

    /// Failed to get KVM vcpu msrs.
    VcpuGetMsrs(kvm_ioctls::Error),

    /// Failed to set KVM vcpu msrs.
    VcpuSetMsrs(kvm_ioctls::Error),

    /// Failed to get KVM vcpu regs.
    VcpuGetRegs(kvm_ioctls::Error),

    /// Failed to set KVM vcpu regs.
    VcpuSetRegs(kvm_ioctls::Error),

    /// Failed to get KVM vcpu sregs.
    VcpuGetSregs(kvm_ioctls::Error),

    /// Failed to set KVM vcpu sregs.
    VcpuSetSregs(kvm_ioctls::Error),

    /// Failed to get KVM vcpu events.
    VcpuGetVcpuEvents(kvm_ioctls::Error),

    /// Failed to set KVM vcpu events.
    VcpuSetVcpuEvents(kvm_ioctls::Error),

    /// Failed to get KVM vcpu FPU.
    VcpuGetFpu(kvm_ioctls::Error),

    /// Failed to set KVM vcpu FPU.
    VcpuSetFpu(kvm_ioctls::Error),

    /// Failed to get KVM vcpu XSAVE.
    VcpuGetXsave(kvm_ioctls::Error),

    /// Failed to set KVM vcpu XSAVE.
    VcpuSetXsave(kvm_ioctls::Error),

    /// Failed to get KVM vcpu XCRS.
    VcpuGetXcrs(kvm_ioctls::Error),

    /// Failed to set KVM vcpu XCRS.
    VcpuSetXcrs(kvm_ioctls::Error),

    /// Error resuming vCPU on shutdown
    ResumeOnShutdown(MigratableError),
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
    fd: VcpuFd,
    id: u8,
    #[cfg(target_arch = "x86_64")]
    io_bus: Arc<devices::Bus>,
    mmio_bus: Arc<devices::Bus>,
    #[cfg_attr(target_arch = "aarch64", allow(dead_code))]
    interrupt_controller: Option<Arc<Mutex<dyn InterruptController>>>,
    #[cfg_attr(target_arch = "aarch64", allow(dead_code))]
    vm_ts: std::time::Instant,
    #[cfg(target_arch = "aarch64")]
    mpidr: u64,
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Serialize, Deserialize)]
pub struct VcpuKvmState {
    msrs: Msrs,
    vcpu_events: kvm_vcpu_events,
    regs: kvm_regs,
    sregs: kvm_sregs,
    fpu: kvm_fpu,
    lapic_state: kvm_lapic_state,
    xsave: kvm_xsave,
    xcrs: kvm_xcrs,
    mp_state: kvm_mp_state,
}

#[cfg(target_arch = "aarch64")]
#[derive(Clone, Serialize, Deserialize)]
pub struct VcpuKvmState {}

impl Vcpu {
    /// Constructs a new VCPU for `vm`.
    ///
    /// # Arguments
    ///
    /// * `id` - Represents the CPU number between [0, max vcpus).
    /// * `vm` - The virtual machine this vcpu will get attached to.
    pub fn new(
        id: u8,
        fd: &Arc<VmFd>,
        #[cfg(target_arch = "x86_64")] io_bus: Arc<devices::Bus>,
        mmio_bus: Arc<devices::Bus>,
        interrupt_controller: Option<Arc<Mutex<dyn InterruptController>>>,
        creation_ts: std::time::Instant,
    ) -> Result<Arc<Mutex<Self>>> {
        let kvm_vcpu = fd.create_vcpu(id).map_err(Error::VcpuFd)?;
        // Initially the cpuid per vCPU is the one supported by this VM.
        Ok(Arc::new(Mutex::new(Vcpu {
            fd: kvm_vcpu,
            id,
            #[cfg(target_arch = "x86_64")]
            io_bus,
            mmio_bus,
            interrupt_controller,
            vm_ts: creation_ts,
            #[cfg(target_arch = "aarch64")]
            mpidr: 0,
        })))
    }

    /// Configures a vcpu and should be called once per vcpu when created.
    ///
    /// # Arguments
    ///
    /// * `fd` - VcpuFd.
    /// * `kernel_entry_point` - Kernel entry point address in guest memory and boot protocol used.
    /// * `vm_memory` - Guest memory.
    /// * `cpuid` - (x86_64) CpuId, wrapper over the `kvm_cpuid2` structure.
    pub fn configure(
        &mut self,
        #[cfg(target_arch = "aarch64")] vm_fd: &VmFd,
        kernel_entry_point: Option<EntryPoint>,
        vm_memory: &GuestMemoryAtomic<GuestMemoryMmap>,
        #[cfg(target_arch = "x86_64")] cpuid: CpuId,
    ) -> Result<()> {
        #[cfg(target_arch = "aarch64")]
        {
            self.mpidr =
                arch::configure_vcpu(&self.fd, self.id, vm_fd, kernel_entry_point, vm_memory)
                    .map_err(Error::VcpuConfiguration)?;
        }

        #[cfg(target_arch = "x86_64")]
        arch::configure_vcpu(&self.fd, self.id, kernel_entry_point, vm_memory, cpuid)
            .map_err(Error::VcpuConfiguration)?;

        Ok(())
    }

    /// Gets the MPIDR register value.
    #[cfg(target_arch = "aarch64")]
    pub fn get_mpidr(&self) -> u64 {
        self.mpidr
    }

    /// Runs the VCPU until it exits, returning the reason.
    ///
    /// Note that the state of the VCPU and associated VM must be setup first for this to do
    /// anything useful.
    pub fn run(&self) -> Result<bool> {
        match self.fd.run() {
            Ok(run) => match run {
                #[cfg(target_arch = "x86_64")]
                VcpuExit::IoIn(addr, data) => {
                    self.io_bus.read(u64::from(addr), data);
                    Ok(true)
                }
                #[cfg(target_arch = "x86_64")]
                VcpuExit::IoOut(addr, data) => {
                    if addr == DEBUG_IOPORT && data.len() == 1 {
                        self.log_debug_ioport(data[0]);
                    }
                    self.io_bus.write(u64::from(addr), data);
                    Ok(true)
                }
                VcpuExit::MmioRead(addr, data) => {
                    self.mmio_bus.read(addr as u64, data);
                    Ok(true)
                }
                VcpuExit::MmioWrite(addr, data) => {
                    self.mmio_bus.write(addr as u64, data);
                    Ok(true)
                }
                #[cfg(target_arch = "x86_64")]
                VcpuExit::IoapicEoi(vector) => {
                    if let Some(interrupt_controller) = &self.interrupt_controller {
                        interrupt_controller
                            .lock()
                            .unwrap()
                            .end_of_interrupt(vector);
                    }
                    Ok(true)
                }
                VcpuExit::Shutdown => {
                    // Triple fault to trigger a reboot
                    Ok(false)
                }
                #[cfg(target_arch = "aarch64")]
                VcpuExit::SystemEvent(event_type, flags) => {
                    // On Aarch64, when the VM is shutdown, run() returns
                    // VcpuExit::SystemEvent with reason KVM_SYSTEM_EVENT_SHUTDOWN
                    if event_type == KVM_SYSTEM_EVENT_SHUTDOWN {
                        Ok(false)
                    } else {
                        error!(
                            "Unexpected system event with type 0x{:x}, flags 0x{:x}",
                            event_type, flags
                        );
                        Err(Error::VcpuUnhandledKvmExit)
                    }
                }
                r => {
                    error!("Unexpected exit reason on vcpu run: {:?}", r);
                    Err(Error::VcpuUnhandledKvmExit)
                }
            },

            Err(ref e) => match e.errno() {
                libc::EAGAIN | libc::EINTR => Ok(true),
                _ => {
                    error!("VCPU {:?} error {:?}", self.id, e);
                    Err(Error::VcpuUnhandledKvmExit)
                }
            },
        }
    }

    #[cfg(target_arch = "x86_64")]
    // Log debug io port codes.
    fn log_debug_ioport(&self, code: u8) {
        let ts = self.vm_ts.elapsed();

        debug!(
            "[{} code 0x{:x}] {}.{:>06} seconds",
            DebugIoPortRange::from_u8(code),
            code,
            ts.as_secs(),
            ts.as_micros()
        );
    }

    #[cfg(target_arch = "x86_64")]
    fn kvm_state(&self) -> Result<VcpuKvmState> {
        let mut msrs = arch::x86_64::regs::boot_msr_entries();
        self.fd.get_msrs(&mut msrs).map_err(Error::VcpuGetMsrs)?;

        let vcpu_events = self
            .fd
            .get_vcpu_events()
            .map_err(Error::VcpuGetVcpuEvents)?;
        let regs = self.fd.get_regs().map_err(Error::VcpuGetRegs)?;
        let sregs = self.fd.get_sregs().map_err(Error::VcpuGetSregs)?;
        let lapic_state = self.fd.get_lapic().map_err(Error::VcpuGetLapic)?;
        let fpu = self.fd.get_fpu().map_err(Error::VcpuGetFpu)?;
        let xsave = self.fd.get_xsave().map_err(Error::VcpuGetXsave)?;
        let xcrs = self.fd.get_xcrs().map_err(Error::VcpuGetXsave)?;
        let mp_state = self.fd.get_mp_state().map_err(Error::VcpuGetMpState)?;

        Ok(VcpuKvmState {
            msrs,
            vcpu_events,
            regs,
            sregs,
            fpu,
            lapic_state,
            xsave,
            xcrs,
            mp_state,
        })
    }

    #[cfg(target_arch = "x86_64")]
    fn set_kvm_state(&mut self, state: &VcpuKvmState) -> Result<()> {
        self.fd.set_regs(&state.regs).map_err(Error::VcpuSetRegs)?;

        self.fd.set_fpu(&state.fpu).map_err(Error::VcpuSetFpu)?;

        self.fd
            .set_xsave(&state.xsave)
            .map_err(Error::VcpuSetXsave)?;

        self.fd
            .set_sregs(&state.sregs)
            .map_err(Error::VcpuSetSregs)?;

        self.fd.set_xcrs(&state.xcrs).map_err(Error::VcpuSetXcrs)?;

        self.fd.set_msrs(&state.msrs).map_err(Error::VcpuSetMsrs)?;

        self.fd
            .set_lapic(&state.lapic_state)
            .map_err(Error::VcpuSetLapic)?;

        self.fd
            .set_mp_state(state.mp_state)
            .map_err(Error::VcpuSetMpState)?;

        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn kvm_state(&self) -> Result<VcpuKvmState> {
        unimplemented!();
    }

    #[cfg(target_arch = "aarch64")]
    fn set_kvm_state(&mut self, _state: &VcpuKvmState) -> Result<()> {
        Ok(())
    }
}

const VCPU_SNAPSHOT_ID: &str = "vcpu";
impl Pausable for Vcpu {}
impl Snapshottable for Vcpu {
    fn id(&self) -> String {
        VCPU_SNAPSHOT_ID.to_string()
    }

    fn snapshot(&self) -> std::result::Result<Snapshot, MigratableError> {
        let snapshot = serde_json::to_vec(&self.kvm_state().map_err(|e| {
            MigratableError::Snapshot(anyhow!("Could not get vCPU KVM state {:?}", e))
        })?)
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

            self.set_kvm_state(&vcpu_state).map_err(|e| {
                MigratableError::Restore(anyhow!("Could not set the vCPU KVM state {:?}", e))
            })?;

            Ok(())
        } else {
            Err(MigratableError::Restore(anyhow!(
                "Could not find the vCPU snapshot section"
            )))
        }
    }
}

pub struct CpuManager {
    boot_vcpus: u8,
    max_vcpus: u8,
    #[cfg(target_arch = "x86_64")]
    io_bus: Arc<devices::Bus>,
    #[cfg_attr(target_arch = "aarch64", allow(dead_code))]
    mmio_bus: Arc<devices::Bus>,
    #[cfg_attr(target_arch = "aarch64", allow(dead_code))]
    interrupt_controller: Option<Arc<Mutex<dyn InterruptController>>>,
    #[cfg_attr(target_arch = "aarch64", allow(dead_code))]
    vm_memory: GuestMemoryAtomic<GuestMemoryMmap>,
    #[cfg(target_arch = "x86_64")]
    cpuid: CpuId,
    #[cfg_attr(target_arch = "aarch64", allow(dead_code))]
    fd: Arc<VmFd>,
    vcpus_kill_signalled: Arc<AtomicBool>,
    vcpus_pause_signalled: Arc<AtomicBool>,
    #[cfg_attr(target_arch = "aarch64", allow(dead_code))]
    reset_evt: EventFd,
    vcpu_states: Vec<VcpuState>,
    selected_cpu: u8,
    vcpus: Vec<Arc<Mutex<Vcpu>>>,
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
    pub fn new(
        config: &CpusConfig,
        device_manager: &Arc<Mutex<DeviceManager>>,
        guest_memory: GuestMemoryAtomic<GuestMemoryMmap>,
        #[cfg_attr(target_arch = "aarch64", allow(unused_variables))] kvm: &Kvm,
        fd: Arc<VmFd>,
        reset_evt: EventFd,
    ) -> Result<Arc<Mutex<CpuManager>>> {
        let mut vcpu_states = Vec::with_capacity(usize::from(config.max_vcpus));
        vcpu_states.resize_with(usize::from(config.max_vcpus), VcpuState::default);

        let device_manager = device_manager.lock().unwrap();
        #[cfg(target_arch = "x86_64")]
        let cpuid = CpuManager::patch_cpuid(kvm)?;
        let cpu_manager = Arc::new(Mutex::new(CpuManager {
            boot_vcpus: config.boot_vcpus,
            max_vcpus: config.max_vcpus,
            #[cfg(target_arch = "x86_64")]
            io_bus: device_manager.io_bus().clone(),
            mmio_bus: device_manager.mmio_bus().clone(),
            interrupt_controller: device_manager.interrupt_controller().clone(),
            vm_memory: guest_memory,
            #[cfg(target_arch = "x86_64")]
            cpuid,
            fd,
            vcpus_kill_signalled: Arc::new(AtomicBool::new(false)),
            vcpus_pause_signalled: Arc::new(AtomicBool::new(false)),
            vcpu_states,
            reset_evt,
            selected_cpu: 0,
            vcpus: Vec::with_capacity(usize::from(config.max_vcpus)),
        }));

        #[cfg(target_arch = "x86_64")]
        device_manager
            .allocator()
            .lock()
            .unwrap()
            .allocate_io_addresses(Some(GuestAddress(0x0cd8)), 0x8, None)
            .ok_or(Error::AllocateIOPort)?;

        #[cfg(target_arch = "x86_64")]
        cpu_manager
            .lock()
            .unwrap()
            .io_bus
            .insert(cpu_manager.clone(), 0x0cd8, 0xc)
            .map_err(Error::BusError)?;

        Ok(cpu_manager)
    }

    #[cfg(target_arch = "x86_64")]
    fn patch_cpuid(kvm: &Kvm) -> Result<CpuId> {
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

        // Supported CPUID
        let mut cpuid = kvm
            .get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
            .map_err(Error::PatchCpuId)?;

        CpuidPatch::patch_cpuid(&mut cpuid, cpuid_patches);

        Ok(cpuid)
    }

    fn create_vcpu(
        &mut self,
        cpu_id: u8,
        entry_point: Option<EntryPoint>,
        snapshot: Option<Snapshot>,
    ) -> Result<Arc<Mutex<Vcpu>>> {
        let interrupt_controller = if let Some(interrupt_controller) = &self.interrupt_controller {
            Some(interrupt_controller.clone())
        } else {
            None
        };

        let creation_ts = std::time::Instant::now();

        let vcpu = Vcpu::new(
            cpu_id,
            &self.fd,
            #[cfg(target_arch = "x86_64")]
            self.io_bus.clone(),
            self.mmio_bus.clone(),
            interrupt_controller,
            creation_ts,
        )?;

        if let Some(snapshot) = snapshot {
            #[cfg(target_arch = "x86_64")]
            {
                let mut cpuid = self.cpuid.clone();
                CpuidPatch::set_cpuid_reg(&mut cpuid, 0xb, None, CpuidReg::EDX, u32::from(cpu_id));

                vcpu.lock()
                    .unwrap()
                    .fd
                    .set_cpuid2(&cpuid)
                    .map_err(Error::SetSupportedCpusFailed)?;
            }
            vcpu.lock()
                .unwrap()
                .restore(snapshot)
                .expect("Failed to restore vCPU");
        } else {
            let vm_memory = self.vm_memory.clone();

            #[cfg(target_arch = "x86_64")]
            vcpu.lock()
                .unwrap()
                .configure(entry_point, &vm_memory, self.cpuid.clone())
                .expect("Failed to configure vCPU");

            #[cfg(target_arch = "aarch64")]
            vcpu.lock()
                .unwrap()
                .configure(&self.fd, entry_point, &vm_memory)
                .expect("Failed to configure vCPU");
        }

        let vcpu_clone = Arc::clone(&vcpu);

        Ok(vcpu_clone)
    }

    fn create_vcpus(&mut self, desired_vcpus: u8, entry_point: Option<EntryPoint>) -> Result<()> {
        if desired_vcpus > self.max_vcpus {
            return Err(Error::DesiredVCPUCountExceedsMax);
        }

        for cpu_id in self.present_vcpus()..desired_vcpus {
            let vcpu = self.create_vcpu(cpu_id, entry_point, None)?;
            self.vcpus.push(vcpu);
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
        let vcpu_kill_signalled = self.vcpus_kill_signalled.clone();
        let vcpu_pause_signalled = self.vcpus_pause_signalled.clone();

        let vcpu_kill = self.vcpu_states[usize::from(cpu_id)].kill.clone();
        let vcpu_run_interrupted = self.vcpu_states[usize::from(cpu_id)]
            .vcpu_run_interrupted
            .clone();

        let handle = Some(
            thread::Builder::new()
                .name(format!("vcpu{}", cpu_id))
                .spawn(move || {
                    extern "C" fn handle_signal(_: i32, _: *mut siginfo_t, _: *mut c_void) {}
                    // This uses an async signal safe handler to kill the vcpu handles.
                    register_signal_handler(SIGRTMIN(), handle_signal)
                        .expect("Failed to register vcpu signal handler");

                    // Block until all CPUs are ready.
                    vcpu_thread_barrier.wait();

                    loop {
                        // vcpu.run() returns false on a KVM_EXIT_SHUTDOWN (triple-fault) so trigger a reset
                        match vcpu.lock().unwrap().run() {
                            Err(e) => {
                                error!("VCPU generated error: {:?}", e);
                                break;
                            }
                            Ok(true) => {}
                            Ok(false) => {
                                vcpu_run_interrupted.store(true, Ordering::SeqCst);
                                reset_evt.write(1).unwrap();
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

    fn activate_vcpus(&mut self, desired_vcpus: u8, inserting: bool) -> Result<()> {
        if desired_vcpus > self.max_vcpus {
            return Err(Error::DesiredVCPUCountExceedsMax);
        }

        let vcpu_thread_barrier = Arc::new(Barrier::new(
            (desired_vcpus - self.present_vcpus() + 1) as usize,
        ));

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
        let mut state = &mut self.vcpu_states[usize::from(cpu_id)];
        state.kill.store(true, Ordering::SeqCst);
        state.signal_thread();
        state.join_thread()?;
        state.handle = None;
        Ok(())
    }

    pub fn create_boot_vcpus(&mut self, entry_point: EntryPoint) -> Result<()> {
        self.create_vcpus(self.boot_vcpus(), Some(entry_point))
    }

    // Starts all the vCPUs that the VM is booting with. Blocks until all vCPUs are running.
    pub fn start_boot_vcpus(&mut self) -> Result<()> {
        self.activate_vcpus(self.boot_vcpus(), false)
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

        // Clear pause state and unpark the vCPU threads if they are parked.
        self.resume().map_err(Error::ResumeOnShutdown)?;

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
        self.boot_vcpus
    }

    pub fn max_vcpus(&self) -> u8 {
        self.max_vcpus
    }

    fn present_vcpus(&self) -> u8 {
        self.vcpu_states
            .iter()
            .fold(0, |acc, state| acc + state.active() as u8)
    }

    #[cfg(target_arch = "aarch64")]
    pub fn get_mpidrs(&self) -> Vec<u64> {
        let vcpu_mpidrs = self
            .vcpus
            .iter()
            .map(|cpu| cpu.lock().unwrap().get_mpidr())
            .collect();
        vcpu_mpidrs
    }

    #[cfg(feature = "acpi")]
    pub fn create_madt(&self) -> SDT {
        // This is also checked in the commandline parsing.
        assert!(self.boot_vcpus <= self.max_vcpus);

        let mut madt = SDT::new(*b"APIC", 44, 5, *b"CLOUDH", *b"CHMADT  ", 1);
        madt.write(36, layout::APIC_START);

        for cpu in 0..self.max_vcpus {
            let lapic = LocalAPIC {
                r#type: 0,
                length: 8,
                processor_id: cpu,
                apic_id: cpu,
                flags: if cpu < self.boot_vcpus {
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
            max_vcpus: self.max_vcpus,
        };
        let mut cpu_data_inner: Vec<&dyn aml::Aml> = vec![&hid, &uid, &methods];

        let mut cpu_devices = Vec::new();
        for cpu_id in 0..self.max_vcpus {
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

        Ok(())
    }

    fn resume(&mut self) -> std::result::Result<(), MigratableError> {
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

    fn snapshot(&self) -> std::result::Result<Snapshot, MigratableError> {
        let mut cpu_manager_snapshot = Snapshot::new(CPU_MANAGER_SNAPSHOT_ID);

        // The CpuManager snapshot is a collection of all vCPUs snapshots.
        for vcpu in &self.vcpus {
            let cpu_snapshot = vcpu.lock().unwrap().snapshot()?;
            cpu_manager_snapshot.add_snapshot(cpu_snapshot);
        }

        Ok(cpu_manager_snapshot)
    }

    fn restore(&mut self, snapshot: Snapshot) -> std::result::Result<(), MigratableError> {
        let vcpu_thread_barrier = Arc::new(Barrier::new((snapshot.snapshots.len() + 1) as usize));

        for (cpu_id, snapshot) in snapshot.snapshots.iter() {
            debug!("Restoring VCPU {}", cpu_id);
            let vcpu = self
                .create_vcpu(cpu_id.parse::<u8>().unwrap(), None, Some(*snapshot.clone()))
                .map_err(|e| MigratableError::Restore(anyhow!("Could not create vCPU {:?}", e)))?;
            self.start_vcpu(vcpu, vcpu_thread_barrier.clone(), false)
                .map_err(|e| MigratableError::Restore(anyhow!("Could not restore vCPU {:?}", e)))?;
        }

        // Unblock all restored CPU threads.
        vcpu_thread_barrier.wait();
        Ok(())
    }
}

impl Transportable for CpuManager {}
impl Migratable for CpuManager {}
