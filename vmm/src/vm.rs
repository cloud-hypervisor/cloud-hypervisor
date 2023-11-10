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

use crate::config::{
    add_to_config, DeviceConfig, DiskConfig, FsConfig, HotplugMethod, NetConfig, PmemConfig,
    UserDeviceConfig, ValidationError, VdpaConfig, VmConfig, VsockConfig,
};
use crate::config::{NumaConfig, PayloadConfig};
#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
use crate::coredump::{
    CpuElf64Writable, DumpState, Elf64Writable, GuestDebuggable, GuestDebuggableError, NoteDescType,
};
use crate::cpu;
use crate::device_manager::{DeviceManager, DeviceManagerError, PtyPair};
use crate::device_tree::DeviceTree;
#[cfg(feature = "guest_debug")]
use crate::gdb::{Debuggable, DebuggableError, GdbRequestPayload, GdbResponsePayload};
#[cfg(feature = "igvm")]
use crate::igvm::igvm_loader;
use crate::memory_manager::{
    Error as MemoryManagerError, MemoryManager, MemoryManagerSnapshotData,
};
#[cfg(all(feature = "kvm", target_arch = "x86_64"))]
use crate::migration::get_vm_snapshot;
#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
use crate::migration::url_to_file;
use crate::migration::{url_to_path, SNAPSHOT_CONFIG_FILE, SNAPSHOT_STATE_FILE};
use crate::GuestMemoryMmap;
use crate::{
    PciDeviceInfo, CPU_MANAGER_SNAPSHOT_ID, DEVICE_MANAGER_SNAPSHOT_ID, MEMORY_MANAGER_SNAPSHOT_ID,
};
use anyhow::anyhow;
use arch::get_host_cpu_phys_bits;
#[cfg(target_arch = "x86_64")]
use arch::layout::{KVM_IDENTITY_MAP_START, KVM_TSS_START};
#[cfg(feature = "tdx")]
use arch::x86_64::tdx::TdvfSection;
use arch::EntryPoint;
#[cfg(target_arch = "aarch64")]
use arch::PciSpaceInfo;
use arch::{NumaNode, NumaNodes};
#[cfg(target_arch = "aarch64")]
use devices::interrupt_controller;
use devices::AcpiNotificationFlags;
#[cfg(all(target_arch = "aarch64", feature = "guest_debug"))]
use gdbstub_arch::aarch64::reg::AArch64CoreRegs as CoreRegs;
#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
use gdbstub_arch::x86::reg::X86_64CoreRegs as CoreRegs;
use hypervisor::{HypervisorVmError, VmOps};
use libc::{termios, SIGWINCH};
use linux_loader::cmdline::Cmdline;
#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
use linux_loader::elf;
#[cfg(target_arch = "x86_64")]
use linux_loader::loader::elf::PvhBootCapability::PvhEntryPresent;
#[cfg(target_arch = "aarch64")]
use linux_loader::loader::pe::Error::InvalidImageMagicNumber;
use linux_loader::loader::KernelLoader;
use seccompiler::SeccompAction;
use serde::{Deserialize, Serialize};
use std::cmp;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::convert::TryInto;
use std::fs::{File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
use std::mem::size_of;
use std::num::Wrapping;
use std::ops::Deref;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;
use std::{result, str, thread};
use thiserror::Error;
use tracer::trace_scoped;
use vm_device::Bus;
#[cfg(feature = "tdx")]
use vm_memory::{Address, ByteValued, GuestMemoryRegion, ReadVolatile};
use vm_memory::{
    Bytes, GuestAddress, GuestAddressSpace, GuestMemory, GuestMemoryAtomic, WriteVolatile,
};
use vm_migration::protocol::{Request, Response, Status};
use vm_migration::{
    protocol::MemoryRangeTable, snapshot_from_id, Migratable, MigratableError, Pausable, Snapshot,
    SnapshotData, Snapshottable, Transportable,
};
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

/// Errors associated with VM management
#[derive(Debug, Error)]
pub enum Error {
    #[error("Cannot open kernel file: {0}")]
    KernelFile(#[source] io::Error),

    #[error("Cannot open initramfs file: {0}")]
    InitramfsFile(#[source] io::Error),

    #[error("Cannot load the kernel into memory: {0}")]
    KernelLoad(#[source] linux_loader::loader::Error),

    #[cfg(target_arch = "aarch64")]
    #[error("Cannot load the UEFI binary in memory: {0:?}")]
    UefiLoad(arch::aarch64::uefi::Error),

    #[error("Cannot load the initramfs into memory")]
    InitramfsLoad,

    #[error("Cannot load the kernel command line in memory: {0}")]
    LoadCmdLine(#[source] linux_loader::loader::Error),

    #[error("Cannot modify the kernel command line: {0}")]
    CmdLineInsertStr(#[source] linux_loader::cmdline::Error),

    #[error("Cannot create the kernel command line: {0}")]
    CmdLineCreate(#[source] linux_loader::cmdline::Error),

    #[error("Cannot configure system: {0}")]
    ConfigureSystem(#[source] arch::Error),

    #[cfg(target_arch = "aarch64")]
    #[error("Cannot enable interrupt controller: {0:?}")]
    EnableInterruptController(interrupt_controller::Error),

    #[error("VM state is poisoned")]
    PoisonedState,

    #[error("Error from device manager: {0:?}")]
    DeviceManager(DeviceManagerError),

    #[error("No device with id {0:?} to remove")]
    NoDeviceToRemove(String),

    #[error("Cannot spawn a signal handler thread: {0}")]
    SignalHandlerSpawn(#[source] io::Error),

    #[error("Failed to join on threads: {0:?}")]
    ThreadCleanup(std::boxed::Box<dyn std::any::Any + std::marker::Send>),

    #[error("VM config is missing")]
    VmMissingConfig,

    #[error("VM is not created")]
    VmNotCreated,

    #[error("VM is already created")]
    VmAlreadyCreated,

    #[error("VM is not running")]
    VmNotRunning,

    #[error("Cannot clone EventFd: {0}")]
    EventFdClone(#[source] io::Error),

    #[error("invalid VM state transition: {0:?} to {1:?}")]
    InvalidStateTransition(VmState, VmState),

    #[error("Error from CPU manager: {0}")]
    CpuManager(#[source] cpu::Error),

    #[error("Cannot pause devices: {0}")]
    PauseDevices(#[source] MigratableError),

    #[error("Cannot resume devices: {0}")]
    ResumeDevices(#[source] MigratableError),

    #[error("Cannot pause CPUs: {0}")]
    PauseCpus(#[source] MigratableError),

    #[error("Cannot resume cpus: {0}")]
    ResumeCpus(#[source] MigratableError),

    #[error("Cannot pause VM: {0}")]
    Pause(#[source] MigratableError),

    #[error("Cannot resume VM: {0}")]
    Resume(#[source] MigratableError),

    #[error("Memory manager error: {0:?}")]
    MemoryManager(MemoryManagerError),

    #[error("Eventfd write error: {0}")]
    EventfdError(#[source] std::io::Error),

    #[error("Cannot snapshot VM: {0}")]
    Snapshot(#[source] MigratableError),

    #[error("Cannot restore VM: {0}")]
    Restore(#[source] MigratableError),

    #[error("Cannot send VM snapshot: {0}")]
    SnapshotSend(#[source] MigratableError),

    #[error("Invalid restore source URL")]
    InvalidRestoreSourceUrl,

    #[error("Failed to validate config: {0}")]
    ConfigValidation(#[source] ValidationError),

    #[error("Too many virtio-vsock devices")]
    TooManyVsockDevices,

    #[error("Failed serializing into JSON: {0}")]
    SerializeJson(#[source] serde_json::Error),

    #[error("Invalid NUMA configuration")]
    InvalidNumaConfig,

    #[error("Cannot create seccomp filter: {0}")]
    CreateSeccompFilter(#[source] seccompiler::Error),

    #[error("Cannot apply seccomp filter: {0}")]
    ApplySeccompFilter(#[source] seccompiler::Error),

    #[error("Failed resizing a memory zone")]
    ResizeZone,

    #[error("Cannot activate virtio devices: {0:?}")]
    ActivateVirtioDevices(DeviceManagerError),

    #[error("Error triggering power button: {0:?}")]
    PowerButton(DeviceManagerError),

    #[error("Kernel lacks PVH header")]
    KernelMissingPvhHeader,

    #[error("Failed to allocate firmware RAM: {0:?}")]
    AllocateFirmwareMemory(MemoryManagerError),

    #[error("Error manipulating firmware file: {0}")]
    FirmwareFile(#[source] std::io::Error),

    #[error("Firmware too big")]
    FirmwareTooLarge,

    #[error("Failed to copy firmware to memory: {0}")]
    FirmwareLoad(#[source] vm_memory::GuestMemoryError),

    #[cfg(feature = "sev_snp")]
    #[error("Error enabling SEV-SNP VM: {0}")]
    InitializeSevSnpVm(#[source] hypervisor::HypervisorVmError),

    #[cfg(feature = "tdx")]
    #[error("Error performing I/O on TDX firmware file: {0}")]
    LoadTdvf(#[source] std::io::Error),

    #[cfg(feature = "tdx")]
    #[error("Error performing I/O on the TDX payload file: {0}")]
    LoadPayload(#[source] std::io::Error),

    #[cfg(feature = "tdx")]
    #[error("Error parsing TDVF: {0}")]
    ParseTdvf(#[source] arch::x86_64::tdx::TdvfError),

    #[cfg(feature = "tdx")]
    #[error("Error populating TDX HOB: {0}")]
    PopulateHob(#[source] arch::x86_64::tdx::TdvfError),

    #[cfg(feature = "tdx")]
    #[error("Error allocating TDVF memory: {0:?}")]
    AllocatingTdvfMemory(crate::memory_manager::Error),

    #[cfg(feature = "tdx")]
    #[error("Error enabling TDX VM: {0}")]
    InitializeTdxVm(#[source] hypervisor::HypervisorVmError),

    #[cfg(feature = "tdx")]
    #[error("Error enabling TDX memory region: {0}")]
    InitializeTdxMemoryRegion(#[source] hypervisor::HypervisorVmError),

    #[cfg(feature = "tdx")]
    #[error("Error finalizing TDX VM: {0}")]
    FinalizeTdx(#[source] hypervisor::HypervisorVmError),

    #[cfg(feature = "tdx")]
    #[error("TDX firmware missing")]
    TdxFirmwareMissing,

    #[cfg(feature = "tdx")]
    #[error("Invalid TDX payload type")]
    InvalidPayloadType,

    #[cfg(feature = "guest_debug")]
    #[error("Error debugging VM: {0:?}")]
    Debug(DebuggableError),

    #[error("Error spawning kernel loading thread")]
    KernelLoadThreadSpawn(std::io::Error),

    #[error("Error joining kernel loading thread")]
    KernelLoadThreadJoin(std::boxed::Box<dyn std::any::Any + std::marker::Send>),

    #[error("Payload configuration is not bootable")]
    InvalidPayload,

    #[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
    #[error("Error coredumping VM: {0:?}")]
    Coredump(GuestDebuggableError),

    #[cfg(feature = "igvm")]
    #[error("Cannot open igvm file: {0}")]
    IgvmFile(#[source] io::Error),

    #[cfg(feature = "igvm")]
    #[error("Cannot load the igvm into memory: {0}")]
    IgvmLoad(#[source] igvm_loader::Error),
}
pub type Result<T> = result::Result<T, Error>;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum VmState {
    Created,
    Running,
    Shutdown,
    Paused,
    BreakPoint,
}

impl VmState {
    fn valid_transition(self, new_state: VmState) -> Result<()> {
        match self {
            VmState::Created => match new_state {
                VmState::Created => Err(Error::InvalidStateTransition(self, new_state)),
                VmState::Running | VmState::Paused | VmState::BreakPoint | VmState::Shutdown => {
                    Ok(())
                }
            },

            VmState::Running => match new_state {
                VmState::Created | VmState::Running => {
                    Err(Error::InvalidStateTransition(self, new_state))
                }
                VmState::Paused | VmState::Shutdown | VmState::BreakPoint => Ok(()),
            },

            VmState::Shutdown => match new_state {
                VmState::Paused | VmState::Created | VmState::Shutdown | VmState::BreakPoint => {
                    Err(Error::InvalidStateTransition(self, new_state))
                }
                VmState::Running => Ok(()),
            },

            VmState::Paused => match new_state {
                VmState::Created | VmState::Paused | VmState::BreakPoint => {
                    Err(Error::InvalidStateTransition(self, new_state))
                }
                VmState::Running | VmState::Shutdown => Ok(()),
            },
            VmState::BreakPoint => match new_state {
                VmState::Created | VmState::Running => Ok(()),
                _ => Err(Error::InvalidStateTransition(self, new_state)),
            },
        }
    }
}

struct VmOpsHandler {
    memory: GuestMemoryAtomic<GuestMemoryMmap>,
    #[cfg(target_arch = "x86_64")]
    io_bus: Arc<Bus>,
    mmio_bus: Arc<Bus>,
}

impl VmOps for VmOpsHandler {
    fn guest_mem_write(&self, gpa: u64, buf: &[u8]) -> result::Result<usize, HypervisorVmError> {
        self.memory
            .memory()
            .write(buf, GuestAddress(gpa))
            .map_err(|e| HypervisorVmError::GuestMemWrite(e.into()))
    }

    fn guest_mem_read(&self, gpa: u64, buf: &mut [u8]) -> result::Result<usize, HypervisorVmError> {
        self.memory
            .memory()
            .read(buf, GuestAddress(gpa))
            .map_err(|e| HypervisorVmError::GuestMemRead(e.into()))
    }

    fn mmio_read(&self, gpa: u64, data: &mut [u8]) -> result::Result<(), HypervisorVmError> {
        if let Err(vm_device::BusError::MissingAddressRange) = self.mmio_bus.read(gpa, data) {
            info!("Guest MMIO read to unregistered address 0x{:x}", gpa);
        }
        Ok(())
    }

    fn mmio_write(&self, gpa: u64, data: &[u8]) -> result::Result<(), HypervisorVmError> {
        match self.mmio_bus.write(gpa, data) {
            Err(vm_device::BusError::MissingAddressRange) => {
                info!("Guest MMIO write to unregistered address 0x{:x}", gpa);
            }
            Ok(Some(barrier)) => {
                info!("Waiting for barrier");
                barrier.wait();
                info!("Barrier released");
            }
            _ => {}
        };
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn pio_read(&self, port: u64, data: &mut [u8]) -> result::Result<(), HypervisorVmError> {
        if let Err(vm_device::BusError::MissingAddressRange) = self.io_bus.read(port, data) {
            info!("Guest PIO read to unregistered address 0x{:x}", port);
        }
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn pio_write(&self, port: u64, data: &[u8]) -> result::Result<(), HypervisorVmError> {
        match self.io_bus.write(port, data) {
            Err(vm_device::BusError::MissingAddressRange) => {
                info!("Guest PIO write to unregistered address 0x{:x}", port);
            }
            Ok(Some(barrier)) => {
                info!("Waiting for barrier");
                barrier.wait();
                info!("Barrier released");
            }
            _ => {}
        };
        Ok(())
    }
}

pub fn physical_bits(hypervisor: &Arc<dyn hypervisor::Hypervisor>, max_phys_bits: u8) -> u8 {
    let host_phys_bits = get_host_cpu_phys_bits(hypervisor);

    cmp::min(host_phys_bits, max_phys_bits)
}

pub struct Vm {
    #[cfg(feature = "tdx")]
    kernel: Option<File>,
    initramfs: Option<File>,
    threads: Vec<thread::JoinHandle<()>>,
    device_manager: Arc<Mutex<DeviceManager>>,
    config: Arc<Mutex<VmConfig>>,
    state: RwLock<VmState>,
    cpu_manager: Arc<Mutex<cpu::CpuManager>>,
    memory_manager: Arc<Mutex<MemoryManager>>,
    #[cfg_attr(any(not(feature = "kvm"), target_arch = "aarch64"), allow(dead_code))]
    // The hypervisor abstracted virtual machine.
    vm: Arc<dyn hypervisor::Vm>,
    #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
    saved_clock: Option<hypervisor::ClockData>,
    numa_nodes: NumaNodes,
    #[cfg_attr(any(not(feature = "kvm"), target_arch = "aarch64"), allow(dead_code))]
    hypervisor: Arc<dyn hypervisor::Hypervisor>,
    stop_on_boot: bool,
    load_payload_handle: Option<thread::JoinHandle<Result<EntryPoint>>>,
}

impl Vm {
    pub const HANDLED_SIGNALS: [i32; 1] = [SIGWINCH];

    #[allow(clippy::too_many_arguments)]
    pub fn new_from_memory_manager(
        config: Arc<Mutex<VmConfig>>,
        memory_manager: Arc<Mutex<MemoryManager>>,
        vm: Arc<dyn hypervisor::Vm>,
        exit_evt: EventFd,
        reset_evt: EventFd,
        #[cfg(feature = "guest_debug")] vm_debug_evt: EventFd,
        seccomp_action: &SeccompAction,
        hypervisor: Arc<dyn hypervisor::Hypervisor>,
        activate_evt: EventFd,
        timestamp: Instant,
        serial_pty: Option<PtyPair>,
        console_pty: Option<PtyPair>,
        debug_console_pty: Option<PtyPair>,
        console_resize_pipe: Option<File>,
        original_termios: Arc<Mutex<Option<termios>>>,
        snapshot: Option<Snapshot>,
    ) -> Result<Self> {
        trace_scoped!("Vm::new_from_memory_manager");

        let boot_id_list = config
            .lock()
            .unwrap()
            .validate()
            .map_err(Error::ConfigValidation)?;

        #[cfg(not(feature = "igvm"))]
        let load_payload_handle = if snapshot.is_none() {
            Self::load_payload_async(&memory_manager, &config)?
        } else {
            None
        };

        info!("Booting VM from config: {:?}", &config);

        // Create NUMA nodes based on NumaConfig.
        let numa_nodes =
            Self::create_numa_nodes(config.lock().unwrap().numa.clone(), &memory_manager)?;

        #[cfg(feature = "tdx")]
        let tdx_enabled = config.lock().unwrap().is_tdx_enabled();
        #[cfg(feature = "sev_snp")]
        let sev_snp_enabled = config.lock().unwrap().is_sev_snp_enabled();
        #[cfg(feature = "tdx")]
        let force_iommu = tdx_enabled;
        #[cfg(not(feature = "tdx"))]
        let force_iommu = false;

        #[cfg(feature = "guest_debug")]
        let stop_on_boot = config.lock().unwrap().gdb;
        #[cfg(not(feature = "guest_debug"))]
        let stop_on_boot = false;

        let memory = memory_manager.lock().unwrap().guest_memory();
        #[cfg(target_arch = "x86_64")]
        let io_bus = Arc::new(Bus::new());
        let mmio_bus = Arc::new(Bus::new());

        let vm_ops: Arc<dyn VmOps> = Arc::new(VmOpsHandler {
            memory,
            #[cfg(target_arch = "x86_64")]
            io_bus: io_bus.clone(),
            mmio_bus: mmio_bus.clone(),
        });

        let cpus_config = { &config.lock().unwrap().cpus.clone() };
        let cpu_manager = cpu::CpuManager::new(
            cpus_config,
            vm.clone(),
            exit_evt.try_clone().map_err(Error::EventFdClone)?,
            reset_evt.try_clone().map_err(Error::EventFdClone)?,
            #[cfg(feature = "guest_debug")]
            vm_debug_evt,
            &hypervisor,
            seccomp_action.clone(),
            vm_ops,
            #[cfg(feature = "tdx")]
            tdx_enabled,
            &numa_nodes,
            #[cfg(feature = "sev_snp")]
            sev_snp_enabled,
        )
        .map_err(Error::CpuManager)?;

        #[cfg(target_arch = "x86_64")]
        cpu_manager
            .lock()
            .unwrap()
            .populate_cpuid(
                &memory_manager,
                &hypervisor,
                #[cfg(feature = "tdx")]
                tdx_enabled,
            )
            .map_err(Error::CpuManager)?;

        // Loading the igvm file is pushed down here because
        // igvm parser needs cpu_manager to retrieve cpuid leaf.
        // For the regular case, we can start loading early, but for
        // igvm case we have to wait until cpu_manager is created.
        // Currently, Microsoft Hypervisor does not provide any
        // Hypervisor specific common cpuid, we need to call get_cpuid_values
        // per cpuid through cpu_manager.
        #[cfg(feature = "igvm")]
        let load_payload_handle = if snapshot.is_none() {
            Self::load_payload_async(&memory_manager, &config, &cpu_manager)?
        } else {
            None
        };
        // The initial TDX configuration must be done before the vCPUs are
        // created
        #[cfg(feature = "tdx")]
        if tdx_enabled {
            let cpuid = cpu_manager.lock().unwrap().common_cpuid();
            let max_vcpus = cpu_manager.lock().unwrap().max_vcpus() as u32;
            vm.tdx_init(&cpuid, max_vcpus)
                .map_err(Error::InitializeTdxVm)?;
        }

        cpu_manager
            .lock()
            .unwrap()
            .create_boot_vcpus(snapshot_from_id(snapshot.as_ref(), CPU_MANAGER_SNAPSHOT_ID))
            .map_err(Error::CpuManager)?;

        // This initial SEV-SNP configuration must be done immediately after
        // vCPUs are created. As part of this initialization we are
        // transitioning the guest into secure state.
        #[cfg(feature = "sev_snp")]
        if sev_snp_enabled {
            vm.sev_snp_init().map_err(Error::InitializeSevSnpVm)?;
        }

        #[cfg(feature = "tdx")]
        let dynamic = !tdx_enabled;
        #[cfg(not(feature = "tdx"))]
        let dynamic = true;

        let device_manager = DeviceManager::new(
            #[cfg(target_arch = "x86_64")]
            io_bus,
            mmio_bus,
            hypervisor.hypervisor_type(),
            vm.clone(),
            config.clone(),
            memory_manager.clone(),
            cpu_manager.clone(),
            exit_evt.try_clone().map_err(Error::EventFdClone)?,
            reset_evt,
            seccomp_action.clone(),
            numa_nodes.clone(),
            &activate_evt,
            force_iommu,
            boot_id_list,
            timestamp,
            snapshot_from_id(snapshot.as_ref(), DEVICE_MANAGER_SNAPSHOT_ID),
            dynamic,
        )
        .map_err(Error::DeviceManager)?;

        device_manager
            .lock()
            .unwrap()
            .create_devices(
                serial_pty,
                console_pty,
                debug_console_pty,
                console_resize_pipe,
                original_termios,
            )
            .map_err(Error::DeviceManager)?;

        #[cfg(feature = "tdx")]
        let kernel = config
            .lock()
            .unwrap()
            .payload
            .as_ref()
            .map(|p| p.kernel.as_ref().map(File::open))
            .unwrap_or_default()
            .transpose()
            .map_err(Error::KernelFile)?;

        let initramfs = config
            .lock()
            .unwrap()
            .payload
            .as_ref()
            .map(|p| p.initramfs.as_ref().map(File::open))
            .unwrap_or_default()
            .transpose()
            .map_err(Error::InitramfsFile)?;

        #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
        let saved_clock = if let Some(snapshot) = snapshot.as_ref() {
            let vm_snapshot = get_vm_snapshot(snapshot).map_err(Error::Restore)?;
            vm_snapshot.clock
        } else {
            None
        };

        let vm_state = if snapshot.is_some() {
            VmState::Paused
        } else {
            VmState::Created
        };

        Ok(Vm {
            #[cfg(feature = "tdx")]
            kernel,
            initramfs,
            device_manager,
            config,
            threads: Vec::with_capacity(1),
            state: RwLock::new(vm_state),
            cpu_manager,
            memory_manager,
            vm,
            #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
            saved_clock,
            numa_nodes,
            hypervisor,
            stop_on_boot,
            load_payload_handle,
        })
    }

    fn create_numa_nodes(
        configs: Option<Vec<NumaConfig>>,
        memory_manager: &Arc<Mutex<MemoryManager>>,
    ) -> Result<NumaNodes> {
        let mm = memory_manager.lock().unwrap();
        let mm_zones = mm.memory_zones();
        let mut numa_nodes = BTreeMap::new();

        if let Some(configs) = &configs {
            for config in configs.iter() {
                if numa_nodes.contains_key(&config.guest_numa_id) {
                    error!("Can't define twice the same NUMA node");
                    return Err(Error::InvalidNumaConfig);
                }

                let mut node = NumaNode::default();

                if let Some(memory_zones) = &config.memory_zones {
                    for memory_zone in memory_zones.iter() {
                        if let Some(mm_zone) = mm_zones.get(memory_zone) {
                            node.memory_regions.extend(mm_zone.regions().clone());
                            if let Some(virtiomem_zone) = mm_zone.virtio_mem_zone() {
                                node.hotplug_regions.push(virtiomem_zone.region().clone());
                            }
                            node.memory_zones.push(memory_zone.clone());
                        } else {
                            error!("Unknown memory zone '{}'", memory_zone);
                            return Err(Error::InvalidNumaConfig);
                        }
                    }
                }

                if let Some(cpus) = &config.cpus {
                    node.cpus.extend(cpus);
                }

                if let Some(pci_segments) = &config.pci_segments {
                    node.pci_segments.extend(pci_segments);
                }

                if let Some(distances) = &config.distances {
                    for distance in distances.iter() {
                        let dest = distance.destination;
                        let dist = distance.distance;

                        if !configs.iter().any(|cfg| cfg.guest_numa_id == dest) {
                            error!("Unknown destination NUMA node {}", dest);
                            return Err(Error::InvalidNumaConfig);
                        }

                        if node.distances.contains_key(&dest) {
                            error!("Destination NUMA node {} has been already set", dest);
                            return Err(Error::InvalidNumaConfig);
                        }

                        node.distances.insert(dest, dist);
                    }
                }

                #[cfg(target_arch = "x86_64")]
                if let Some(sgx_epc_sections) = &config.sgx_epc_sections {
                    if let Some(sgx_epc_region) = mm.sgx_epc_region() {
                        let mm_sections = sgx_epc_region.epc_sections();
                        for sgx_epc_section in sgx_epc_sections.iter() {
                            if let Some(mm_section) = mm_sections.get(sgx_epc_section) {
                                node.sgx_epc_sections.push(mm_section.clone());
                            } else {
                                error!("Unknown SGX EPC section '{}'", sgx_epc_section);
                                return Err(Error::InvalidNumaConfig);
                            }
                        }
                    } else {
                        error!("Missing SGX EPC region");
                        return Err(Error::InvalidNumaConfig);
                    }
                }

                numa_nodes.insert(config.guest_numa_id, node);
            }
        }

        Ok(numa_nodes)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vm_config: Arc<Mutex<VmConfig>>,
        exit_evt: EventFd,
        reset_evt: EventFd,
        #[cfg(feature = "guest_debug")] vm_debug_evt: EventFd,
        seccomp_action: &SeccompAction,
        hypervisor: Arc<dyn hypervisor::Hypervisor>,
        activate_evt: EventFd,
        serial_pty: Option<PtyPair>,
        console_pty: Option<PtyPair>,
        debug_console_pty: Option<PtyPair>,
        console_resize_pipe: Option<File>,
        original_termios: Arc<Mutex<Option<termios>>>,
        snapshot: Option<Snapshot>,
        source_url: Option<&str>,
        prefault: Option<bool>,
    ) -> Result<Self> {
        trace_scoped!("Vm::new");

        let timestamp = Instant::now();

        #[cfg(feature = "tdx")]
        let tdx_enabled = if snapshot.is_some() {
            false
        } else {
            vm_config.lock().unwrap().is_tdx_enabled()
        };

        #[cfg(feature = "sev_snp")]
        let sev_snp_enabled = if snapshot.is_some() {
            false
        } else {
            vm_config.lock().unwrap().is_sev_snp_enabled()
        };

        let vm = Self::create_hypervisor_vm(
            &hypervisor,
            #[cfg(feature = "tdx")]
            tdx_enabled,
            #[cfg(feature = "sev_snp")]
            sev_snp_enabled,
        )?;

        let phys_bits = physical_bits(&hypervisor, vm_config.lock().unwrap().cpus.max_phys_bits);

        let memory_manager = if let Some(snapshot) =
            snapshot_from_id(snapshot.as_ref(), MEMORY_MANAGER_SNAPSHOT_ID)
        {
            MemoryManager::new_from_snapshot(
                &snapshot,
                vm.clone(),
                &vm_config.lock().unwrap().memory.clone(),
                source_url,
                prefault.unwrap(),
                phys_bits,
                #[cfg(target_arch = "x86_64")]
                hypervisor.get_cpu_vendor(),
            )
            .map_err(Error::MemoryManager)?
        } else {
            #[cfg(target_arch = "x86_64")]
            let sgx_epc_config = vm_config.lock().unwrap().sgx_epc.clone();

            MemoryManager::new(
                vm.clone(),
                &vm_config.lock().unwrap().memory.clone(),
                None,
                phys_bits,
                #[cfg(feature = "tdx")]
                tdx_enabled,
                None,
                None,
                #[cfg(target_arch = "x86_64")]
                sgx_epc_config,
                #[cfg(target_arch = "x86_64")]
                hypervisor.get_cpu_vendor(),
            )
            .map_err(Error::MemoryManager)?
        };

        Vm::new_from_memory_manager(
            vm_config,
            memory_manager,
            vm,
            exit_evt,
            reset_evt,
            #[cfg(feature = "guest_debug")]
            vm_debug_evt,
            seccomp_action,
            hypervisor,
            activate_evt,
            timestamp,
            serial_pty,
            console_pty,
            debug_console_pty,
            console_resize_pipe,
            original_termios,
            snapshot,
        )
    }

    pub fn create_hypervisor_vm(
        hypervisor: &Arc<dyn hypervisor::Hypervisor>,
        #[cfg(feature = "tdx")] tdx_enabled: bool,
        #[cfg(feature = "sev_snp")] sev_snp_enabled: bool,
    ) -> Result<Arc<dyn hypervisor::Vm>> {
        hypervisor.check_required_extensions().unwrap();

        cfg_if::cfg_if! {
            if #[cfg(feature = "tdx")] {
                // Passing KVM_X86_TDX_VM: 1 if tdx_enabled is true
                // Otherwise KVM_X86_LEGACY_VM: 0
                // value of tdx_enabled is mapped to KVM_X86_TDX_VM or KVM_X86_LEGACY_VM
                let vm = hypervisor
                    .create_vm_with_type(u64::from(tdx_enabled))
                    .unwrap();
            } else if #[cfg(feature = "sev_snp")] {
                // Passing SEV_SNP_ENABLED: 1 if sev_snp_enabled is true
                // Otherwise SEV_SNP_DISABLED: 0
                // value of sev_snp_enabled is mapped to SEV_SNP_ENABLED for true or SEV_SNP_DISABLED for false
                let vm = hypervisor
                    .create_vm_with_type(u64::from(sev_snp_enabled))
                    .unwrap();
            } else {
                let vm = hypervisor.create_vm().unwrap();
            }
        }

        #[cfg(target_arch = "x86_64")]
        {
            vm.set_identity_map_address(KVM_IDENTITY_MAP_START.0)
                .unwrap();
            vm.set_tss_address(KVM_TSS_START.0 as usize).unwrap();
            vm.enable_split_irq().unwrap();
        }

        Ok(vm)
    }

    fn load_initramfs(&mut self, guest_mem: &GuestMemoryMmap) -> Result<arch::InitramfsConfig> {
        let initramfs = self.initramfs.as_mut().unwrap();
        let size: usize = initramfs
            .seek(SeekFrom::End(0))
            .map_err(|_| Error::InitramfsLoad)?
            .try_into()
            .unwrap();
        initramfs.rewind().map_err(|_| Error::InitramfsLoad)?;

        let address =
            arch::initramfs_load_addr(guest_mem, size).map_err(|_| Error::InitramfsLoad)?;
        let address = GuestAddress(address);

        guest_mem
            .read_volatile_from(address, initramfs, size)
            .map_err(|_| Error::InitramfsLoad)?;

        info!("Initramfs loaded: address = 0x{:x}", address.0);
        Ok(arch::InitramfsConfig { address, size })
    }

    pub fn generate_cmdline(
        payload: &PayloadConfig,
        #[cfg(target_arch = "aarch64")] device_manager: &Arc<Mutex<DeviceManager>>,
    ) -> Result<Cmdline> {
        let mut cmdline = Cmdline::new(arch::CMDLINE_MAX_SIZE).map_err(Error::CmdLineCreate)?;
        if let Some(s) = payload.cmdline.as_ref() {
            cmdline.insert_str(s).map_err(Error::CmdLineInsertStr)?;
        }

        #[cfg(target_arch = "aarch64")]
        for entry in device_manager.lock().unwrap().cmdline_additions() {
            cmdline.insert_str(entry).map_err(Error::CmdLineInsertStr)?;
        }
        Ok(cmdline)
    }

    #[cfg(target_arch = "aarch64")]
    fn load_firmware(mut firmware: &File, memory_manager: Arc<Mutex<MemoryManager>>) -> Result<()> {
        let uefi_flash = memory_manager.lock().as_ref().unwrap().uefi_flash();
        let mem = uefi_flash.memory();
        arch::aarch64::uefi::load_uefi(mem.deref(), arch::layout::UEFI_START, &mut firmware)
            .map_err(Error::UefiLoad)?;
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn load_kernel(
        firmware: Option<File>,
        kernel: Option<File>,
        memory_manager: Arc<Mutex<MemoryManager>>,
    ) -> Result<EntryPoint> {
        let guest_memory = memory_manager.lock().as_ref().unwrap().guest_memory();
        let mem = guest_memory.memory();
        let entry_addr = match (firmware, kernel) {
            (None, Some(mut kernel)) => {
                match linux_loader::loader::pe::PE::load(
                    mem.deref(),
                    Some(arch::layout::KERNEL_START),
                    &mut kernel,
                    None,
                ) {
                    Ok(entry_addr) => entry_addr.kernel_load,
                    // Try to load the binary as kernel PE file at first.
                    // If failed, retry to load it as UEFI binary.
                    // As the UEFI binary is formatless, it must be the last option to try.
                    Err(linux_loader::loader::Error::Pe(InvalidImageMagicNumber)) => {
                        Self::load_firmware(&kernel, memory_manager)?;
                        arch::layout::UEFI_START
                    }
                    Err(e) => {
                        return Err(Error::KernelLoad(e));
                    }
                }
            }
            (Some(firmware), None) => {
                Self::load_firmware(&firmware, memory_manager)?;
                arch::layout::UEFI_START
            }
            _ => return Err(Error::InvalidPayload),
        };

        Ok(EntryPoint { entry_addr })
    }

    #[cfg(feature = "igvm")]
    fn load_igvm(
        igvm: File,
        memory_manager: Arc<Mutex<MemoryManager>>,
        cpu_manager: Arc<Mutex<cpu::CpuManager>>,
    ) -> Result<EntryPoint> {
        let res = igvm_loader::load_igvm(&igvm, memory_manager, cpu_manager.clone(), "")
            .map_err(Error::IgvmLoad)?;

        cfg_if::cfg_if! {
            if #[cfg(feature = "sev_snp")] {
                let entry_point = if cpu_manager.lock().unwrap().sev_snp_enabled() {
                    EntryPoint { entry_addr: vm_memory::GuestAddress(res.vmsa_gpa) }
                } else {
                    EntryPoint {entry_addr: vm_memory::GuestAddress(res.vmsa.rip) }
                };
            } else {
               let entry_point = EntryPoint { entry_addr: vm_memory::GuestAddress(res.vmsa.rip) };
            }
        };
        Ok(entry_point)
    }

    #[cfg(target_arch = "x86_64")]
    fn load_kernel(
        mut kernel: File,
        cmdline: Option<Cmdline>,
        memory_manager: Arc<Mutex<MemoryManager>>,
    ) -> Result<EntryPoint> {
        info!("Loading kernel");

        let mem = {
            let guest_memory = memory_manager.lock().as_ref().unwrap().guest_memory();
            guest_memory.memory()
        };
        let entry_addr = linux_loader::loader::elf::Elf::load(
            mem.deref(),
            None,
            &mut kernel,
            Some(arch::layout::HIGH_RAM_START),
        )
        .map_err(Error::KernelLoad)?;

        if let Some(cmdline) = cmdline {
            linux_loader::loader::load_cmdline(mem.deref(), arch::layout::CMDLINE_START, &cmdline)
                .map_err(Error::LoadCmdLine)?;
        }

        if let PvhEntryPresent(entry_addr) = entry_addr.pvh_boot_cap {
            // Use the PVH kernel entry point to boot the guest
            info!("Kernel loaded: entry_addr = 0x{:x}", entry_addr.0);
            Ok(EntryPoint { entry_addr })
        } else {
            Err(Error::KernelMissingPvhHeader)
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn load_payload(
        payload: &PayloadConfig,
        memory_manager: Arc<Mutex<MemoryManager>>,
        #[cfg(feature = "igvm")] cpu_manager: Arc<Mutex<cpu::CpuManager>>,
    ) -> Result<EntryPoint> {
        trace_scoped!("load_payload");
        #[cfg(feature = "igvm")]
        if let Some(_igvm_file) = &payload.igvm {
            let igvm = File::open(_igvm_file).map_err(Error::IgvmFile)?;
            return Self::load_igvm(igvm, memory_manager, cpu_manager);
        }
        match (
            &payload.firmware,
            &payload.kernel,
            &payload.initramfs,
            &payload.cmdline,
        ) {
            (Some(firmware), None, None, None) => {
                let firmware = File::open(firmware).map_err(Error::FirmwareFile)?;
                Self::load_kernel(firmware, None, memory_manager)
            }
            (None, Some(kernel), _, _) => {
                let kernel = File::open(kernel).map_err(Error::KernelFile)?;
                let cmdline = Self::generate_cmdline(payload)?;
                Self::load_kernel(kernel, Some(cmdline), memory_manager)
            }
            _ => Err(Error::InvalidPayload),
        }
    }

    #[cfg(target_arch = "aarch64")]
    fn load_payload(
        payload: &PayloadConfig,
        memory_manager: Arc<Mutex<MemoryManager>>,
    ) -> Result<EntryPoint> {
        match (&payload.firmware, &payload.kernel) {
            (Some(firmware), None) => {
                let firmware = File::open(firmware).map_err(Error::FirmwareFile)?;
                Self::load_kernel(Some(firmware), None, memory_manager)
            }
            (None, Some(kernel)) => {
                let kernel = File::open(kernel).map_err(Error::KernelFile)?;
                Self::load_kernel(None, Some(kernel), memory_manager)
            }
            _ => Err(Error::InvalidPayload),
        }
    }

    fn load_payload_async(
        memory_manager: &Arc<Mutex<MemoryManager>>,
        config: &Arc<Mutex<VmConfig>>,
        #[cfg(feature = "igvm")] cpu_manager: &Arc<Mutex<cpu::CpuManager>>,
    ) -> Result<Option<thread::JoinHandle<Result<EntryPoint>>>> {
        // Kernel with TDX is loaded in a different manner
        #[cfg(feature = "tdx")]
        if config.lock().unwrap().is_tdx_enabled() {
            return Ok(None);
        }

        config
            .lock()
            .unwrap()
            .payload
            .as_ref()
            .map(|payload| {
                let memory_manager = memory_manager.clone();
                let payload = payload.clone();
                #[cfg(feature = "igvm")]
                let cpu_manager = cpu_manager.clone();

                std::thread::Builder::new()
                    .name("payload_loader".into())
                    .spawn(move || {
                        Self::load_payload(
                            &payload,
                            memory_manager,
                            #[cfg(feature = "igvm")]
                            cpu_manager,
                        )
                    })
                    .map_err(Error::KernelLoadThreadSpawn)
            })
            .transpose()
    }

    #[cfg(target_arch = "x86_64")]
    fn configure_system(&mut self, rsdp_addr: GuestAddress) -> Result<()> {
        trace_scoped!("configure_system");
        info!("Configuring system");
        let mem = self.memory_manager.lock().unwrap().boot_guest_memory();

        let initramfs_config = match self.initramfs {
            Some(_) => Some(self.load_initramfs(&mem)?),
            None => None,
        };

        let boot_vcpus = self.cpu_manager.lock().unwrap().boot_vcpus();
        let rsdp_addr = Some(rsdp_addr);
        let sgx_epc_region = self
            .memory_manager
            .lock()
            .unwrap()
            .sgx_epc_region()
            .as_ref()
            .cloned();

        let serial_number = self
            .config
            .lock()
            .unwrap()
            .platform
            .as_ref()
            .and_then(|p| p.serial_number.clone());

        let uuid = self
            .config
            .lock()
            .unwrap()
            .platform
            .as_ref()
            .and_then(|p| p.uuid.clone());

        let oem_strings = self
            .config
            .lock()
            .unwrap()
            .platform
            .as_ref()
            .and_then(|p| p.oem_strings.clone());

        let oem_strings = oem_strings
            .as_deref()
            .map(|strings| strings.iter().map(|s| s.as_ref()).collect::<Vec<&str>>());

        let topology = self.cpu_manager.lock().unwrap().get_vcpu_topology();

        arch::configure_system(
            &mem,
            arch::layout::CMDLINE_START,
            &initramfs_config,
            boot_vcpus,
            rsdp_addr,
            sgx_epc_region,
            serial_number.as_deref(),
            uuid.as_deref(),
            oem_strings.as_deref(),
            topology,
        )
        .map_err(Error::ConfigureSystem)?;
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn configure_system(&mut self, _rsdp_addr: GuestAddress) -> Result<()> {
        let cmdline = Self::generate_cmdline(
            self.config.lock().unwrap().payload.as_ref().unwrap(),
            &self.device_manager,
        )?;
        let vcpu_mpidrs = self.cpu_manager.lock().unwrap().get_mpidrs();
        let vcpu_topology = self.cpu_manager.lock().unwrap().get_vcpu_topology();
        let mem = self.memory_manager.lock().unwrap().boot_guest_memory();
        let mut pci_space_info: Vec<PciSpaceInfo> = Vec::new();
        let initramfs_config = match self.initramfs {
            Some(_) => Some(self.load_initramfs(&mem)?),
            None => None,
        };

        let device_info = &self
            .device_manager
            .lock()
            .unwrap()
            .get_device_info()
            .clone();

        for pci_segment in self.device_manager.lock().unwrap().pci_segments().iter() {
            let pci_space = PciSpaceInfo {
                pci_segment_id: pci_segment.id,
                mmio_config_address: pci_segment.mmio_config_address,
                pci_device_space_start: pci_segment.start_of_mem64_area,
                pci_device_space_size: pci_segment.end_of_mem64_area
                    - pci_segment.start_of_mem64_area
                    + 1,
            };
            pci_space_info.push(pci_space);
        }

        let virtio_iommu_bdf = self
            .device_manager
            .lock()
            .unwrap()
            .iommu_attached_devices()
            .as_ref()
            .map(|(v, _)| *v);

        let vgic = self
            .device_manager
            .lock()
            .unwrap()
            .get_interrupt_controller()
            .unwrap()
            .lock()
            .unwrap()
            .get_vgic()
            .map_err(|_| {
                Error::ConfigureSystem(arch::Error::PlatformSpecific(
                    arch::aarch64::Error::SetupGic,
                ))
            })?;

        // PMU interrupt sticks to PPI, so need to be added by 16 to get real irq number.
        let pmu_supported = self
            .cpu_manager
            .lock()
            .unwrap()
            .init_pmu(arch::aarch64::fdt::AARCH64_PMU_IRQ + 16)
            .map_err(|_| {
                Error::ConfigureSystem(arch::Error::PlatformSpecific(
                    arch::aarch64::Error::VcpuInitPmu,
                ))
            })?;

        arch::configure_system(
            &mem,
            cmdline.as_cstring().unwrap().to_str().unwrap(),
            vcpu_mpidrs,
            vcpu_topology,
            device_info,
            &initramfs_config,
            &pci_space_info,
            virtio_iommu_bdf.map(|bdf| bdf.into()),
            &vgic,
            &self.numa_nodes,
            pmu_supported,
        )
        .map_err(Error::ConfigureSystem)?;

        Ok(())
    }

    pub fn serial_pty(&self) -> Option<PtyPair> {
        self.device_manager.lock().unwrap().serial_pty()
    }

    pub fn console_pty(&self) -> Option<PtyPair> {
        self.device_manager.lock().unwrap().console_pty()
    }

    pub fn debug_console_pty(&self) -> Option<PtyPair> {
        self.device_manager.lock().unwrap().debug_console_pty()
    }

    pub fn console_resize_pipe(&self) -> Option<Arc<File>> {
        self.device_manager.lock().unwrap().console_resize_pipe()
    }

    pub fn shutdown(&mut self) -> Result<()> {
        let mut state = self.state.try_write().map_err(|_| Error::PoisonedState)?;
        let new_state = VmState::Shutdown;

        state.valid_transition(new_state)?;

        // Wake up the DeviceManager threads so they will get terminated cleanly
        self.device_manager
            .lock()
            .unwrap()
            .resume()
            .map_err(Error::Resume)?;

        self.cpu_manager
            .lock()
            .unwrap()
            .shutdown()
            .map_err(Error::CpuManager)?;

        // Wait for all the threads to finish
        for thread in self.threads.drain(..) {
            thread.join().map_err(Error::ThreadCleanup)?
        }
        *state = new_state;

        event!("vm", "shutdown");

        Ok(())
    }

    pub fn resize(
        &mut self,
        desired_vcpus: Option<u8>,
        desired_memory: Option<u64>,
        desired_balloon: Option<u64>,
    ) -> Result<()> {
        event!("vm", "resizing");

        if let Some(desired_vcpus) = desired_vcpus {
            if self
                .cpu_manager
                .lock()
                .unwrap()
                .resize(desired_vcpus)
                .map_err(Error::CpuManager)?
            {
                self.device_manager
                    .lock()
                    .unwrap()
                    .notify_hotplug(AcpiNotificationFlags::CPU_DEVICES_CHANGED)
                    .map_err(Error::DeviceManager)?;
            }
            self.config.lock().unwrap().cpus.boot_vcpus = desired_vcpus;
        }

        if let Some(desired_memory) = desired_memory {
            let new_region = self
                .memory_manager
                .lock()
                .unwrap()
                .resize(desired_memory)
                .map_err(Error::MemoryManager)?;

            let memory_config = &mut self.config.lock().unwrap().memory;

            if let Some(new_region) = &new_region {
                self.device_manager
                    .lock()
                    .unwrap()
                    .update_memory(new_region)
                    .map_err(Error::DeviceManager)?;

                match memory_config.hotplug_method {
                    HotplugMethod::Acpi => {
                        self.device_manager
                            .lock()
                            .unwrap()
                            .notify_hotplug(AcpiNotificationFlags::MEMORY_DEVICES_CHANGED)
                            .map_err(Error::DeviceManager)?;
                    }
                    HotplugMethod::VirtioMem => {}
                }
            }

            // We update the VM config regardless of the actual guest resize
            // operation result (happened or not), so that if the VM reboots
            // it will be running with the last configure memory size.
            match memory_config.hotplug_method {
                HotplugMethod::Acpi => memory_config.size = desired_memory,
                HotplugMethod::VirtioMem => {
                    if desired_memory > memory_config.size {
                        memory_config.hotplugged_size = Some(desired_memory - memory_config.size);
                    } else {
                        memory_config.hotplugged_size = None;
                    }
                }
            }
        }

        if let Some(desired_balloon) = desired_balloon {
            self.device_manager
                .lock()
                .unwrap()
                .resize_balloon(desired_balloon)
                .map_err(Error::DeviceManager)?;

            // Update the configuration value for the balloon size to ensure
            // a reboot would use the right value.
            if let Some(balloon_config) = &mut self.config.lock().unwrap().balloon {
                balloon_config.size = desired_balloon;
            }
        }

        event!("vm", "resized");

        Ok(())
    }

    pub fn resize_zone(&mut self, id: String, desired_memory: u64) -> Result<()> {
        let memory_config = &mut self.config.lock().unwrap().memory;

        if let Some(zones) = &mut memory_config.zones {
            for zone in zones.iter_mut() {
                if zone.id == id {
                    if desired_memory >= zone.size {
                        let hotplugged_size = desired_memory - zone.size;
                        self.memory_manager
                            .lock()
                            .unwrap()
                            .resize_zone(&id, desired_memory - zone.size)
                            .map_err(Error::MemoryManager)?;
                        // We update the memory zone config regardless of the
                        // actual 'resize-zone' operation result (happened or
                        // not), so that if the VM reboots it will be running
                        // with the last configured memory zone size.
                        zone.hotplugged_size = Some(hotplugged_size);

                        return Ok(());
                    } else {
                        error!(
                            "Invalid to ask less ({}) than boot RAM ({}) for \
                            this memory zone",
                            desired_memory, zone.size,
                        );
                        return Err(Error::ResizeZone);
                    }
                }
            }
        }

        error!("Could not find the memory zone {} for the resize", id);
        Err(Error::ResizeZone)
    }

    pub fn add_device(&mut self, mut device_cfg: DeviceConfig) -> Result<PciDeviceInfo> {
        let pci_device_info = self
            .device_manager
            .lock()
            .unwrap()
            .add_device(&mut device_cfg)
            .map_err(Error::DeviceManager)?;

        // Update VmConfig by adding the new device. This is important to
        // ensure the device would be created in case of a reboot.
        {
            let mut config = self.config.lock().unwrap();
            add_to_config(&mut config.devices, device_cfg);
        }

        self.device_manager
            .lock()
            .unwrap()
            .notify_hotplug(AcpiNotificationFlags::PCI_DEVICES_CHANGED)
            .map_err(Error::DeviceManager)?;

        Ok(pci_device_info)
    }

    pub fn add_user_device(&mut self, mut device_cfg: UserDeviceConfig) -> Result<PciDeviceInfo> {
        let pci_device_info = self
            .device_manager
            .lock()
            .unwrap()
            .add_user_device(&mut device_cfg)
            .map_err(Error::DeviceManager)?;

        // Update VmConfig by adding the new device. This is important to
        // ensure the device would be created in case of a reboot.
        {
            let mut config = self.config.lock().unwrap();
            add_to_config(&mut config.user_devices, device_cfg);
        }

        self.device_manager
            .lock()
            .unwrap()
            .notify_hotplug(AcpiNotificationFlags::PCI_DEVICES_CHANGED)
            .map_err(Error::DeviceManager)?;

        Ok(pci_device_info)
    }

    pub fn remove_device(&mut self, id: String) -> Result<()> {
        self.device_manager
            .lock()
            .unwrap()
            .remove_device(id.clone())
            .map_err(Error::DeviceManager)?;

        // Update VmConfig by removing the device. This is important to
        // ensure the device would not be created in case of a reboot.
        self.config.lock().unwrap().remove_device(&id);

        self.device_manager
            .lock()
            .unwrap()
            .notify_hotplug(AcpiNotificationFlags::PCI_DEVICES_CHANGED)
            .map_err(Error::DeviceManager)?;
        Ok(())
    }

    pub fn add_disk(&mut self, mut disk_cfg: DiskConfig) -> Result<PciDeviceInfo> {
        let pci_device_info = self
            .device_manager
            .lock()
            .unwrap()
            .add_disk(&mut disk_cfg)
            .map_err(Error::DeviceManager)?;

        // Update VmConfig by adding the new device. This is important to
        // ensure the device would be created in case of a reboot.
        {
            let mut config = self.config.lock().unwrap();
            add_to_config(&mut config.disks, disk_cfg);
        }

        self.device_manager
            .lock()
            .unwrap()
            .notify_hotplug(AcpiNotificationFlags::PCI_DEVICES_CHANGED)
            .map_err(Error::DeviceManager)?;

        Ok(pci_device_info)
    }

    pub fn add_fs(&mut self, mut fs_cfg: FsConfig) -> Result<PciDeviceInfo> {
        let pci_device_info = self
            .device_manager
            .lock()
            .unwrap()
            .add_fs(&mut fs_cfg)
            .map_err(Error::DeviceManager)?;

        // Update VmConfig by adding the new device. This is important to
        // ensure the device would be created in case of a reboot.
        {
            let mut config = self.config.lock().unwrap();
            add_to_config(&mut config.fs, fs_cfg);
        }

        self.device_manager
            .lock()
            .unwrap()
            .notify_hotplug(AcpiNotificationFlags::PCI_DEVICES_CHANGED)
            .map_err(Error::DeviceManager)?;

        Ok(pci_device_info)
    }

    pub fn add_pmem(&mut self, mut pmem_cfg: PmemConfig) -> Result<PciDeviceInfo> {
        let pci_device_info = self
            .device_manager
            .lock()
            .unwrap()
            .add_pmem(&mut pmem_cfg)
            .map_err(Error::DeviceManager)?;

        // Update VmConfig by adding the new device. This is important to
        // ensure the device would be created in case of a reboot.
        {
            let mut config = self.config.lock().unwrap();
            add_to_config(&mut config.pmem, pmem_cfg);
        }

        self.device_manager
            .lock()
            .unwrap()
            .notify_hotplug(AcpiNotificationFlags::PCI_DEVICES_CHANGED)
            .map_err(Error::DeviceManager)?;

        Ok(pci_device_info)
    }

    pub fn add_net(&mut self, mut net_cfg: NetConfig) -> Result<PciDeviceInfo> {
        let pci_device_info = self
            .device_manager
            .lock()
            .unwrap()
            .add_net(&mut net_cfg)
            .map_err(Error::DeviceManager)?;

        // Update VmConfig by adding the new device. This is important to
        // ensure the device would be created in case of a reboot.
        {
            let mut config = self.config.lock().unwrap();
            add_to_config(&mut config.net, net_cfg);
        }

        self.device_manager
            .lock()
            .unwrap()
            .notify_hotplug(AcpiNotificationFlags::PCI_DEVICES_CHANGED)
            .map_err(Error::DeviceManager)?;

        Ok(pci_device_info)
    }

    pub fn add_vdpa(&mut self, mut vdpa_cfg: VdpaConfig) -> Result<PciDeviceInfo> {
        let pci_device_info = self
            .device_manager
            .lock()
            .unwrap()
            .add_vdpa(&mut vdpa_cfg)
            .map_err(Error::DeviceManager)?;

        // Update VmConfig by adding the new device. This is important to
        // ensure the device would be created in case of a reboot.
        {
            let mut config = self.config.lock().unwrap();
            add_to_config(&mut config.vdpa, vdpa_cfg);
        }

        self.device_manager
            .lock()
            .unwrap()
            .notify_hotplug(AcpiNotificationFlags::PCI_DEVICES_CHANGED)
            .map_err(Error::DeviceManager)?;

        Ok(pci_device_info)
    }

    pub fn add_vsock(&mut self, mut vsock_cfg: VsockConfig) -> Result<PciDeviceInfo> {
        let pci_device_info = self
            .device_manager
            .lock()
            .unwrap()
            .add_vsock(&mut vsock_cfg)
            .map_err(Error::DeviceManager)?;

        // Update VmConfig by adding the new device. This is important to
        // ensure the device would be created in case of a reboot.
        {
            let mut config = self.config.lock().unwrap();
            config.vsock = Some(vsock_cfg);
        }

        self.device_manager
            .lock()
            .unwrap()
            .notify_hotplug(AcpiNotificationFlags::PCI_DEVICES_CHANGED)
            .map_err(Error::DeviceManager)?;

        Ok(pci_device_info)
    }

    pub fn counters(&self) -> Result<HashMap<String, HashMap<&'static str, Wrapping<u64>>>> {
        Ok(self.device_manager.lock().unwrap().counters())
    }

    #[cfg(feature = "tdx")]
    fn extract_tdvf_sections(&mut self) -> Result<(Vec<TdvfSection>, bool)> {
        use arch::x86_64::tdx::*;

        let firmware_path = self
            .config
            .lock()
            .unwrap()
            .payload
            .as_ref()
            .unwrap()
            .firmware
            .clone()
            .ok_or(Error::TdxFirmwareMissing)?;
        // The TDVF file contains a table of section as well as code
        let mut firmware_file = File::open(firmware_path).map_err(Error::LoadTdvf)?;

        // For all the sections allocate some RAM backing them
        parse_tdvf_sections(&mut firmware_file).map_err(Error::ParseTdvf)
    }

    #[cfg(feature = "tdx")]
    fn hob_memory_resources(
        mut sorted_sections: Vec<TdvfSection>,
        guest_memory: &GuestMemoryMmap,
    ) -> Vec<(u64, u64, bool)> {
        let mut list = Vec::new();

        let mut current_section = sorted_sections.pop();

        // RAM regions interleaved with TDVF sections
        let mut next_start_addr = 0;
        for region in guest_memory.iter() {
            let region_start = region.start_addr().0;
            let region_end = region.last_addr().0;
            if region_start > next_start_addr {
                next_start_addr = region_start;
            }

            loop {
                let (start, size, ram) = if let Some(section) = &current_section {
                    if section.address <= next_start_addr {
                        (section.address, section.size, false)
                    } else {
                        let last_addr = std::cmp::min(section.address - 1, region_end);
                        (next_start_addr, last_addr - next_start_addr + 1, true)
                    }
                } else {
                    (next_start_addr, region_end - next_start_addr + 1, true)
                };

                list.push((start, size, ram));

                if !ram {
                    current_section = sorted_sections.pop();
                }

                next_start_addr = start + size;

                if region_start > next_start_addr {
                    next_start_addr = region_start;
                }

                if next_start_addr > region_end {
                    break;
                }
            }
        }

        // Once all the interleaved sections have been processed, let's simply
        // pull the remaining ones.
        if let Some(section) = current_section {
            list.push((section.address, section.size, false));
        }
        while let Some(section) = sorted_sections.pop() {
            list.push((section.address, section.size, false));
        }

        list
    }

    #[cfg(feature = "tdx")]
    fn populate_tdx_sections(
        &mut self,
        sections: &[TdvfSection],
        guid_found: bool,
    ) -> Result<Option<u64>> {
        use arch::x86_64::tdx::*;
        // Get the memory end *before* we start adding TDVF ram regions
        let boot_guest_memory = self
            .memory_manager
            .lock()
            .as_ref()
            .unwrap()
            .boot_guest_memory();
        for section in sections {
            // No need to allocate if the section falls within guest RAM ranges
            if boot_guest_memory.address_in_range(GuestAddress(section.address)) {
                info!(
                    "Not allocating TDVF Section: {:x?} since it is already part of guest RAM",
                    section
                );
                continue;
            }

            info!("Allocating TDVF Section: {:x?}", section);
            self.memory_manager
                .lock()
                .unwrap()
                .add_ram_region(GuestAddress(section.address), section.size as usize)
                .map_err(Error::AllocatingTdvfMemory)?;
        }

        // The TDVF file contains a table of section as well as code
        let firmware_path = self
            .config
            .lock()
            .unwrap()
            .payload
            .as_ref()
            .unwrap()
            .firmware
            .clone()
            .ok_or(Error::TdxFirmwareMissing)?;
        let mut firmware_file = File::open(firmware_path).map_err(Error::LoadTdvf)?;

        // The guest memory at this point now has all the required regions so it
        // is safe to copy from the TDVF file into it.
        let guest_memory = self.memory_manager.lock().as_ref().unwrap().guest_memory();
        let mem = guest_memory.memory();
        let mut payload_info = None;
        let mut hob_offset = None;
        for section in sections {
            info!("Populating TDVF Section: {:x?}", section);
            match section.r#type {
                TdvfSectionType::Bfv | TdvfSectionType::Cfv => {
                    info!("Copying section to guest memory");
                    firmware_file
                        .seek(SeekFrom::Start(section.data_offset as u64))
                        .map_err(Error::LoadTdvf)?;
                    mem.read_volatile_from(
                        GuestAddress(section.address),
                        &mut firmware_file,
                        section.data_size as usize,
                    )
                    .unwrap();
                }
                TdvfSectionType::TdHob => {
                    hob_offset = Some(section.address);
                }
                TdvfSectionType::Payload => {
                    info!("Copying payload to guest memory");
                    if let Some(payload_file) = self.kernel.as_mut() {
                        let payload_size = payload_file
                            .seek(SeekFrom::End(0))
                            .map_err(Error::LoadPayload)?;

                        payload_file
                            .seek(SeekFrom::Start(0x1f1))
                            .map_err(Error::LoadPayload)?;

                        let mut payload_header = linux_loader::bootparam::setup_header::default();
                        payload_file
                            .read_volatile(&mut payload_header.as_bytes())
                            .unwrap();

                        if payload_header.header != 0x5372_6448 {
                            return Err(Error::InvalidPayloadType);
                        }

                        if (payload_header.version < 0x0200)
                            || ((payload_header.loadflags & 0x1) == 0x0)
                        {
                            return Err(Error::InvalidPayloadType);
                        }

                        payload_file.rewind().map_err(Error::LoadPayload)?;
                        mem.read_volatile_from(
                            GuestAddress(section.address),
                            payload_file,
                            payload_size as usize,
                        )
                        .unwrap();

                        // Create the payload info that will be inserted into
                        // the HOB.
                        payload_info = Some(PayloadInfo {
                            image_type: PayloadImageType::BzImage,
                            entry_point: section.address,
                        });
                    }
                }
                TdvfSectionType::PayloadParam => {
                    info!("Copying payload parameters to guest memory");
                    let cmdline = Self::generate_cmdline(
                        self.config.lock().unwrap().payload.as_ref().unwrap(),
                    )?;
                    mem.write_slice(
                        cmdline.as_cstring().unwrap().as_bytes_with_nul(),
                        GuestAddress(section.address),
                    )
                    .unwrap();
                }
                _ => {}
            }
        }

        // Generate HOB
        let mut hob = TdHob::start(hob_offset.unwrap());

        let mut sorted_sections = sections.to_vec();
        sorted_sections.retain(|section| matches!(section.r#type, TdvfSectionType::TempMem));

        sorted_sections.sort_by_key(|section| section.address);
        sorted_sections.reverse();

        for (start, size, ram) in Vm::hob_memory_resources(sorted_sections, &boot_guest_memory) {
            hob.add_memory_resource(&mem, start, size, ram, guid_found)
                .map_err(Error::PopulateHob)?;
        }

        // MMIO regions
        hob.add_mmio_resource(
            &mem,
            arch::layout::MEM_32BIT_DEVICES_START.raw_value(),
            arch::layout::APIC_START.raw_value()
                - arch::layout::MEM_32BIT_DEVICES_START.raw_value(),
        )
        .map_err(Error::PopulateHob)?;
        let start_of_device_area = self
            .memory_manager
            .lock()
            .unwrap()
            .start_of_device_area()
            .raw_value();
        let end_of_device_area = self
            .memory_manager
            .lock()
            .unwrap()
            .end_of_device_area()
            .raw_value();
        hob.add_mmio_resource(
            &mem,
            start_of_device_area,
            end_of_device_area - start_of_device_area,
        )
        .map_err(Error::PopulateHob)?;

        // Loop over the ACPI tables and copy them to the HOB.

        for acpi_table in crate::acpi::create_acpi_tables_tdx(
            &self.device_manager,
            &self.cpu_manager,
            &self.memory_manager,
            &self.numa_nodes,
        ) {
            hob.add_acpi_table(&mem, acpi_table.as_slice())
                .map_err(Error::PopulateHob)?;
        }

        // If a payload info has been created, let's insert it into the HOB.
        if let Some(payload_info) = payload_info {
            hob.add_payload(&mem, payload_info)
                .map_err(Error::PopulateHob)?;
        }

        hob.finish(&mem).map_err(Error::PopulateHob)?;

        Ok(hob_offset)
    }

    #[cfg(feature = "tdx")]
    fn init_tdx_memory(&mut self, sections: &[TdvfSection]) -> Result<()> {
        let guest_memory = self.memory_manager.lock().as_ref().unwrap().guest_memory();
        let mem = guest_memory.memory();

        for section in sections {
            self.vm
                .tdx_init_memory_region(
                    mem.get_host_address(GuestAddress(section.address)).unwrap() as u64,
                    section.address,
                    section.size,
                    /* TDVF_SECTION_ATTRIBUTES_EXTENDMR */
                    section.attributes == 1,
                )
                .map_err(Error::InitializeTdxMemoryRegion)?;
        }

        Ok(())
    }

    // Creates ACPI tables
    // In case of TDX being used, this is a no-op since the tables will be
    // created and passed when populating the HOB.

    fn create_acpi_tables(&self) -> Option<GuestAddress> {
        #[cfg(feature = "tdx")]
        if self.config.lock().unwrap().is_tdx_enabled() {
            return None;
        }
        let mem = self.memory_manager.lock().unwrap().guest_memory().memory();
        let tpm_enabled = self.config.lock().unwrap().tpm.is_some();
        let rsdp_addr = crate::acpi::create_acpi_tables(
            &mem,
            &self.device_manager,
            &self.cpu_manager,
            &self.memory_manager,
            &self.numa_nodes,
            tpm_enabled,
        );
        info!("Created ACPI tables: rsdp_addr = 0x{:x}", rsdp_addr.0);

        Some(rsdp_addr)
    }

    fn entry_point(&mut self) -> Result<Option<EntryPoint>> {
        trace_scoped!("entry_point");

        self.load_payload_handle
            .take()
            .map(|handle| handle.join().map_err(Error::KernelLoadThreadJoin)?)
            .transpose()
    }

    pub fn boot(&mut self) -> Result<()> {
        trace_scoped!("Vm::boot");
        info!("Booting VM");
        event!("vm", "booting");
        let current_state = self.get_state()?;
        if current_state == VmState::Paused {
            return self.resume().map_err(Error::Resume);
        }

        let new_state = if self.stop_on_boot {
            VmState::BreakPoint
        } else {
            VmState::Running
        };
        current_state.valid_transition(new_state)?;

        // Do earlier to parallelise with loading kernel
        #[cfg(target_arch = "x86_64")]
        let rsdp_addr = self.create_acpi_tables();

        // Load kernel synchronously or if asynchronous then wait for load to
        // finish.
        let entry_point = self.entry_point()?;

        #[cfg(feature = "tdx")]
        let tdx_enabled = self.config.lock().unwrap().is_tdx_enabled();

        // Configure the vcpus that have been created
        let vcpus = self.cpu_manager.lock().unwrap().vcpus();
        for vcpu in vcpus {
            let guest_memory = &self.memory_manager.lock().as_ref().unwrap().guest_memory();
            let boot_setup = entry_point.map(|e| (e, guest_memory));
            self.cpu_manager
                .lock()
                .unwrap()
                .configure_vcpu(vcpu, boot_setup)
                .map_err(Error::CpuManager)?;
        }

        #[cfg(feature = "tdx")]
        let (sections, guid_found) = if tdx_enabled {
            self.extract_tdvf_sections()?
        } else {
            (Vec::new(), false)
        };

        // Configuring the TDX regions requires that the vCPUs are created.
        #[cfg(feature = "tdx")]
        let hob_address = if tdx_enabled {
            // TDX sections are written to memory.
            self.populate_tdx_sections(&sections, guid_found)?
        } else {
            None
        };

        // On aarch64 the ACPI tables depend on the vCPU mpidr which is only
        // available after they are configured
        #[cfg(target_arch = "aarch64")]
        let rsdp_addr = self.create_acpi_tables();

        // Configure shared state based on loaded kernel
        entry_point
            .map(|_| {
                // Safe to unwrap rsdp_addr as we know it can't be None when
                // the entry_point is Some.
                self.configure_system(rsdp_addr.unwrap())
            })
            .transpose()?;

        #[cfg(target_arch = "x86_64")]
        // Note: For x86, always call this function before invoking start boot vcpus.
        // Otherwise guest would fail to boot because we haven't created the
        // userspace mappings to update the hypervisor about the memory mappings.
        // These mappings must be created before we start the vCPU threads for
        // the very first time.
        self.memory_manager
            .lock()
            .unwrap()
            .allocate_address_space()
            .map_err(Error::MemoryManager)?;

        #[cfg(feature = "tdx")]
        if let Some(hob_address) = hob_address {
            // With the HOB address extracted the vCPUs can have
            // their TDX state configured.
            self.cpu_manager
                .lock()
                .unwrap()
                .initialize_tdx(hob_address)
                .map_err(Error::CpuManager)?;
            // Let the hypervisor know which memory ranges are shared with the
            // guest. This prevents the guest from ignoring/discarding memory
            // regions provided by the host.
            self.init_tdx_memory(&sections)?;
            // With TDX memory and CPU state configured TDX setup is complete
            self.vm.tdx_finalize().map_err(Error::FinalizeTdx)?;
        }

        self.cpu_manager
            .lock()
            .unwrap()
            .start_boot_vcpus(new_state == VmState::BreakPoint)
            .map_err(Error::CpuManager)?;

        let mut state = self.state.try_write().map_err(|_| Error::PoisonedState)?;
        *state = new_state;
        event!("vm", "booted");
        Ok(())
    }

    pub fn restore(&mut self) -> Result<()> {
        event!("vm", "restoring");

        #[cfg(target_arch = "x86_64")]
        // Note: For x86, always call this function before invoking start boot vcpus.
        // Otherwise guest would fail to boot because we haven't created the
        // userspace mappings to update the hypervisor about the memory mappings.
        // These mappings must be created before we start the vCPU threads for
        // the very first time for the restored VM.
        self.memory_manager
            .lock()
            .unwrap()
            .allocate_address_space()
            .map_err(Error::MemoryManager)?;

        // Now we can start all vCPUs from here.
        self.cpu_manager
            .lock()
            .unwrap()
            .start_restored_vcpus()
            .map_err(Error::CpuManager)?;

        event!("vm", "restored");
        Ok(())
    }

    /// Gets a thread-safe reference counted pointer to the VM configuration.
    pub fn get_config(&self) -> Arc<Mutex<VmConfig>> {
        Arc::clone(&self.config)
    }

    /// Get the VM state. Returns an error if the state is poisoned.
    pub fn get_state(&self) -> Result<VmState> {
        self.state
            .try_read()
            .map_err(|_| Error::PoisonedState)
            .map(|state| *state)
    }

    /// Gets the actual size of the balloon.
    pub fn balloon_size(&self) -> u64 {
        self.device_manager.lock().unwrap().balloon_size()
    }

    pub fn send_memory_fds(
        &mut self,
        socket: &mut UnixStream,
    ) -> std::result::Result<(), MigratableError> {
        for (slot, fd) in self
            .memory_manager
            .lock()
            .unwrap()
            .memory_slot_fds()
            .drain()
        {
            Request::memory_fd(std::mem::size_of_val(&slot) as u64)
                .write_to(socket)
                .map_err(|e| {
                    MigratableError::MigrateSend(anyhow!("Error sending memory fd request: {}", e))
                })?;
            socket
                .send_with_fd(&slot.to_le_bytes()[..], fd)
                .map_err(|e| {
                    MigratableError::MigrateSend(anyhow!("Error sending memory fd: {}", e))
                })?;

            let res = Response::read_from(socket)?;
            if res.status() != Status::Ok {
                warn!("Error during memory fd migration");
                Request::abandon().write_to(socket)?;
                Response::read_from(socket).ok();
                return Err(MigratableError::MigrateSend(anyhow!(
                    "Error during memory fd migration"
                )));
            }
        }

        Ok(())
    }

    pub fn send_memory_regions<F>(
        &mut self,
        ranges: &MemoryRangeTable,
        fd: &mut F,
    ) -> std::result::Result<(), MigratableError>
    where
        F: WriteVolatile,
    {
        let guest_memory = self.memory_manager.lock().as_ref().unwrap().guest_memory();
        let mem = guest_memory.memory();

        for range in ranges.regions() {
            let mut offset: u64 = 0;
            // Here we are manually handling the retry in case we can't the
            // whole region at once because we can't use the implementation
            // from vm-memory::GuestMemory of write_all_to() as it is not
            // following the correct behavior. For more info about this issue
            // see: https://github.com/rust-vmm/vm-memory/issues/174
            loop {
                let bytes_written = mem
                    .write_volatile_to(
                        GuestAddress(range.gpa + offset),
                        fd,
                        (range.length - offset) as usize,
                    )
                    .map_err(|e| {
                        MigratableError::MigrateSend(anyhow!(
                            "Error transferring memory to socket: {}",
                            e
                        ))
                    })?;
                offset += bytes_written as u64;

                if offset == range.length {
                    break;
                }
            }
        }

        Ok(())
    }

    pub fn memory_range_table(&self) -> std::result::Result<MemoryRangeTable, MigratableError> {
        self.memory_manager
            .lock()
            .unwrap()
            .memory_range_table(false)
    }

    pub fn device_tree(&self) -> Arc<Mutex<DeviceTree>> {
        self.device_manager.lock().unwrap().device_tree()
    }

    pub fn activate_virtio_devices(&self) -> Result<()> {
        self.device_manager
            .lock()
            .unwrap()
            .activate_virtio_devices()
            .map_err(Error::ActivateVirtioDevices)
    }

    #[cfg(target_arch = "x86_64")]
    pub fn power_button(&self) -> Result<()> {
        return self
            .device_manager
            .lock()
            .unwrap()
            .notify_power_button()
            .map_err(Error::PowerButton);
    }

    #[cfg(target_arch = "aarch64")]
    pub fn power_button(&self) -> Result<()> {
        self.device_manager
            .lock()
            .unwrap()
            .notify_power_button()
            .map_err(Error::PowerButton)
    }

    pub fn memory_manager_data(&self) -> MemoryManagerSnapshotData {
        self.memory_manager.lock().unwrap().snapshot_data()
    }

    #[cfg(feature = "guest_debug")]
    pub fn debug_request(
        &mut self,
        gdb_request: &GdbRequestPayload,
        cpu_id: usize,
    ) -> Result<GdbResponsePayload> {
        use GdbRequestPayload::*;
        match gdb_request {
            SetSingleStep(single_step) => {
                self.set_guest_debug(cpu_id, &[], *single_step)
                    .map_err(Error::Debug)?;
            }
            SetHwBreakPoint(addrs) => {
                self.set_guest_debug(cpu_id, addrs, false)
                    .map_err(Error::Debug)?;
            }
            Pause => {
                self.debug_pause().map_err(Error::Debug)?;
            }
            Resume => {
                self.debug_resume().map_err(Error::Debug)?;
            }
            ReadRegs => {
                let regs = self.read_regs(cpu_id).map_err(Error::Debug)?;
                return Ok(GdbResponsePayload::RegValues(Box::new(regs)));
            }
            WriteRegs(regs) => {
                self.write_regs(cpu_id, regs).map_err(Error::Debug)?;
            }
            ReadMem(vaddr, len) => {
                let guest_memory = self.memory_manager.lock().as_ref().unwrap().guest_memory();
                let mem = self
                    .read_mem(&guest_memory, cpu_id, *vaddr, *len)
                    .map_err(Error::Debug)?;
                return Ok(GdbResponsePayload::MemoryRegion(mem));
            }
            WriteMem(vaddr, data) => {
                let guest_memory = self.memory_manager.lock().as_ref().unwrap().guest_memory();
                self.write_mem(&guest_memory, cpu_id, vaddr, data)
                    .map_err(Error::Debug)?;
            }
            ActiveVcpus => {
                let active_vcpus = self.active_vcpus();
                return Ok(GdbResponsePayload::ActiveVcpus(active_vcpus));
            }
        }
        Ok(GdbResponsePayload::CommandComplete)
    }

    #[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
    fn get_dump_state(
        &mut self,
        destination_url: &str,
    ) -> std::result::Result<DumpState, GuestDebuggableError> {
        let nr_cpus = self.config.lock().unwrap().cpus.boot_vcpus as u32;
        let elf_note_size = self.get_note_size(NoteDescType::ElfAndVmm, nr_cpus) as isize;
        let mut elf_phdr_num = 1;
        let elf_sh_info = 0;
        let coredump_file_path = url_to_file(destination_url)?;
        let mapping_num = self.memory_manager.lock().unwrap().num_guest_ram_mappings();

        if mapping_num < UINT16_MAX - 2 {
            elf_phdr_num += mapping_num as u16;
        } else {
            panic!("mapping num beyond 65535 not supported");
        }
        let coredump_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(coredump_file_path)
            .map_err(|e| GuestDebuggableError::Coredump(e.into()))?;

        let mem_offset = self.coredump_get_mem_offset(elf_phdr_num, elf_note_size);
        let mem_data = self
            .memory_manager
            .lock()
            .unwrap()
            .coredump_memory_regions(mem_offset);

        Ok(DumpState {
            elf_note_size,
            elf_phdr_num,
            elf_sh_info,
            mem_offset,
            mem_info: Some(mem_data),
            file: Some(coredump_file),
        })
    }

    #[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
    fn coredump_get_mem_offset(&self, phdr_num: u16, note_size: isize) -> u64 {
        size_of::<elf::Elf64_Ehdr>() as u64
            + note_size as u64
            + size_of::<elf::Elf64_Phdr>() as u64 * phdr_num as u64
    }
}

impl Pausable for Vm {
    fn pause(&mut self) -> std::result::Result<(), MigratableError> {
        event!("vm", "pausing");
        let mut state = self
            .state
            .try_write()
            .map_err(|e| MigratableError::Pause(anyhow!("Could not get VM state: {}", e)))?;
        let new_state = VmState::Paused;

        state
            .valid_transition(new_state)
            .map_err(|e| MigratableError::Pause(anyhow!("Invalid transition: {:?}", e)))?;

        #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
        {
            let mut clock = self
                .vm
                .get_clock()
                .map_err(|e| MigratableError::Pause(anyhow!("Could not get VM clock: {}", e)))?;
            clock.reset_flags();
            self.saved_clock = Some(clock);
        }

        // Before pausing the vCPUs activate any pending virtio devices that might
        // need activation between starting the pause (or e.g. a migration it's part of)
        self.activate_virtio_devices().map_err(|e| {
            MigratableError::Pause(anyhow!("Error activating pending virtio devices: {:?}", e))
        })?;

        self.cpu_manager.lock().unwrap().pause()?;
        self.device_manager.lock().unwrap().pause()?;

        *state = new_state;

        event!("vm", "paused");
        Ok(())
    }

    fn resume(&mut self) -> std::result::Result<(), MigratableError> {
        event!("vm", "resuming");
        let mut state = self
            .state
            .try_write()
            .map_err(|e| MigratableError::Resume(anyhow!("Could not get VM state: {}", e)))?;
        let new_state = VmState::Running;

        state
            .valid_transition(new_state)
            .map_err(|e| MigratableError::Resume(anyhow!("Invalid transition: {:?}", e)))?;

        self.cpu_manager.lock().unwrap().resume()?;
        #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
        {
            if let Some(clock) = &self.saved_clock {
                self.vm.set_clock(clock).map_err(|e| {
                    MigratableError::Resume(anyhow!("Could not set VM clock: {}", e))
                })?;
            }
        }
        self.device_manager.lock().unwrap().resume()?;

        // And we're back to the Running state.
        *state = new_state;
        event!("vm", "resumed");
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct VmSnapshot {
    #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
    pub clock: Option<hypervisor::ClockData>,
    #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
    pub common_cpuid: Vec<hypervisor::arch::x86::CpuIdEntry>,
}

pub const VM_SNAPSHOT_ID: &str = "vm";
impl Snapshottable for Vm {
    fn id(&self) -> String {
        VM_SNAPSHOT_ID.to_string()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        event!("vm", "snapshotting");

        #[cfg(feature = "tdx")]
        {
            if self.config.lock().unwrap().is_tdx_enabled() {
                return Err(MigratableError::Snapshot(anyhow!(
                    "Snapshot not possible with TDX VM"
                )));
            }
        }

        let current_state = self.get_state().unwrap();
        if current_state != VmState::Paused {
            return Err(MigratableError::Snapshot(anyhow!(
                "Trying to snapshot while VM is running"
            )));
        }

        #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
        let common_cpuid = {
            let amx = self.config.lock().unwrap().cpus.features.amx;
            let phys_bits = physical_bits(
                &self.hypervisor,
                self.config.lock().unwrap().cpus.max_phys_bits,
            );
            arch::generate_common_cpuid(
                &self.hypervisor,
                &arch::CpuidConfig {
                    sgx_epc_sections: None,
                    phys_bits,
                    kvm_hyperv: self.config.lock().unwrap().cpus.kvm_hyperv,
                    #[cfg(feature = "tdx")]
                    tdx: false,
                    amx,
                },
            )
            .map_err(|e| {
                MigratableError::MigrateReceive(anyhow!("Error generating common cpuid: {:?}", e))
            })?
        };

        let vm_snapshot_data = serde_json::to_vec(&VmSnapshot {
            #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
            clock: self.saved_clock,
            #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
            common_cpuid,
        })
        .map_err(|e| MigratableError::Snapshot(e.into()))?;

        let mut vm_snapshot = Snapshot::from_data(SnapshotData(vm_snapshot_data));

        let (id, snapshot) = {
            let mut cpu_manager = self.cpu_manager.lock().unwrap();
            (cpu_manager.id(), cpu_manager.snapshot()?)
        };
        vm_snapshot.add_snapshot(id, snapshot);
        let (id, snapshot) = {
            let mut memory_manager = self.memory_manager.lock().unwrap();
            (memory_manager.id(), memory_manager.snapshot()?)
        };
        vm_snapshot.add_snapshot(id, snapshot);
        let (id, snapshot) = {
            let mut device_manager = self.device_manager.lock().unwrap();
            (device_manager.id(), device_manager.snapshot()?)
        };
        vm_snapshot.add_snapshot(id, snapshot);

        event!("vm", "snapshotted");
        Ok(vm_snapshot)
    }
}

impl Transportable for Vm {
    fn send(
        &self,
        snapshot: &Snapshot,
        destination_url: &str,
    ) -> std::result::Result<(), MigratableError> {
        let mut snapshot_config_path = url_to_path(destination_url)?;
        snapshot_config_path.push(SNAPSHOT_CONFIG_FILE);

        // Create the snapshot config file
        let mut snapshot_config_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(snapshot_config_path)
            .map_err(|e| MigratableError::MigrateSend(e.into()))?;

        // Serialize and write the snapshot config
        let vm_config = serde_json::to_string(self.config.lock().unwrap().deref())
            .map_err(|e| MigratableError::MigrateSend(e.into()))?;

        snapshot_config_file
            .write(vm_config.as_bytes())
            .map_err(|e| MigratableError::MigrateSend(e.into()))?;

        let mut snapshot_state_path = url_to_path(destination_url)?;
        snapshot_state_path.push(SNAPSHOT_STATE_FILE);

        // Create the snapshot state file
        let mut snapshot_state_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(snapshot_state_path)
            .map_err(|e| MigratableError::MigrateSend(e.into()))?;

        // Serialize and write the snapshot state
        let vm_state =
            serde_json::to_vec(snapshot).map_err(|e| MigratableError::MigrateSend(e.into()))?;

        snapshot_state_file
            .write(&vm_state)
            .map_err(|e| MigratableError::MigrateSend(e.into()))?;

        // Tell the memory manager to also send/write its own snapshot.
        if let Some(memory_manager_snapshot) = snapshot.snapshots.get(MEMORY_MANAGER_SNAPSHOT_ID) {
            self.memory_manager
                .lock()
                .unwrap()
                .send(&memory_manager_snapshot.clone(), destination_url)?;
        } else {
            return Err(MigratableError::Restore(anyhow!(
                "Missing memory manager snapshot"
            )));
        }

        Ok(())
    }
}

impl Migratable for Vm {
    fn start_dirty_log(&mut self) -> std::result::Result<(), MigratableError> {
        self.memory_manager.lock().unwrap().start_dirty_log()?;
        self.device_manager.lock().unwrap().start_dirty_log()
    }

    fn stop_dirty_log(&mut self) -> std::result::Result<(), MigratableError> {
        self.memory_manager.lock().unwrap().stop_dirty_log()?;
        self.device_manager.lock().unwrap().stop_dirty_log()
    }

    fn dirty_log(&mut self) -> std::result::Result<MemoryRangeTable, MigratableError> {
        Ok(MemoryRangeTable::new_from_tables(vec![
            self.memory_manager.lock().unwrap().dirty_log()?,
            self.device_manager.lock().unwrap().dirty_log()?,
        ]))
    }

    fn start_migration(&mut self) -> std::result::Result<(), MigratableError> {
        self.memory_manager.lock().unwrap().start_migration()?;
        self.device_manager.lock().unwrap().start_migration()
    }

    fn complete_migration(&mut self) -> std::result::Result<(), MigratableError> {
        self.memory_manager.lock().unwrap().complete_migration()?;
        self.device_manager.lock().unwrap().complete_migration()
    }
}

#[cfg(feature = "guest_debug")]
impl Debuggable for Vm {
    fn set_guest_debug(
        &self,
        cpu_id: usize,
        addrs: &[GuestAddress],
        singlestep: bool,
    ) -> std::result::Result<(), DebuggableError> {
        self.cpu_manager
            .lock()
            .unwrap()
            .set_guest_debug(cpu_id, addrs, singlestep)
    }

    fn debug_pause(&mut self) -> std::result::Result<(), DebuggableError> {
        if *self.state.read().unwrap() == VmState::Running {
            self.pause().map_err(DebuggableError::Pause)?;
        }

        let mut state = self
            .state
            .try_write()
            .map_err(|_| DebuggableError::PoisonedState)?;
        *state = VmState::BreakPoint;
        Ok(())
    }

    fn debug_resume(&mut self) -> std::result::Result<(), DebuggableError> {
        if *self.state.read().unwrap() == VmState::BreakPoint {
            self.resume().map_err(DebuggableError::Pause)?;
        }

        Ok(())
    }

    fn read_regs(&self, cpu_id: usize) -> std::result::Result<CoreRegs, DebuggableError> {
        self.cpu_manager.lock().unwrap().read_regs(cpu_id)
    }

    fn write_regs(
        &self,
        cpu_id: usize,
        regs: &CoreRegs,
    ) -> std::result::Result<(), DebuggableError> {
        self.cpu_manager.lock().unwrap().write_regs(cpu_id, regs)
    }

    fn read_mem(
        &self,
        guest_memory: &GuestMemoryAtomic<GuestMemoryMmap>,
        cpu_id: usize,
        vaddr: GuestAddress,
        len: usize,
    ) -> std::result::Result<Vec<u8>, DebuggableError> {
        self.cpu_manager
            .lock()
            .unwrap()
            .read_mem(guest_memory, cpu_id, vaddr, len)
    }

    fn write_mem(
        &self,
        guest_memory: &GuestMemoryAtomic<GuestMemoryMmap>,
        cpu_id: usize,
        vaddr: &GuestAddress,
        data: &[u8],
    ) -> std::result::Result<(), DebuggableError> {
        self.cpu_manager
            .lock()
            .unwrap()
            .write_mem(guest_memory, cpu_id, vaddr, data)
    }

    fn active_vcpus(&self) -> usize {
        let active_vcpus = self.cpu_manager.lock().unwrap().active_vcpus();
        if active_vcpus > 0 {
            active_vcpus
        } else {
            // The VM is not booted yet. Report boot_vcpus() instead.
            self.cpu_manager.lock().unwrap().boot_vcpus() as usize
        }
    }
}

#[cfg(feature = "guest_debug")]
pub const UINT16_MAX: u32 = 65535;

#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
impl Elf64Writable for Vm {}

#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
impl GuestDebuggable for Vm {
    fn coredump(&mut self, destination_url: &str) -> std::result::Result<(), GuestDebuggableError> {
        event!("vm", "coredumping");

        let mut resume = false;

        #[cfg(feature = "tdx")]
        {
            if let Some(ref platform) = self.config.lock().unwrap().platform {
                if platform.tdx {
                    return Err(GuestDebuggableError::Coredump(anyhow!(
                        "Coredump not possible with TDX VM"
                    )));
                }
            }
        }

        match self.get_state().unwrap() {
            VmState::Running => {
                self.pause().map_err(GuestDebuggableError::Pause)?;
                resume = true;
            }
            VmState::Paused => {}
            _ => {
                return Err(GuestDebuggableError::Coredump(anyhow!(
                    "Trying to coredump while VM is not running or paused"
                )));
            }
        }

        let coredump_state = self.get_dump_state(destination_url)?;

        self.write_header(&coredump_state)?;
        self.write_note(&coredump_state)?;
        self.write_loads(&coredump_state)?;

        self.cpu_manager
            .lock()
            .unwrap()
            .cpu_write_elf64_note(&coredump_state)?;
        self.cpu_manager
            .lock()
            .unwrap()
            .cpu_write_vmm_note(&coredump_state)?;

        self.memory_manager
            .lock()
            .unwrap()
            .coredump_iterate_save_mem(&coredump_state)?;

        if resume {
            self.resume().map_err(GuestDebuggableError::Resume)?;
        }

        Ok(())
    }
}

#[cfg(all(feature = "kvm", target_arch = "x86_64"))]
#[cfg(test)]
mod tests {
    use super::*;

    fn test_vm_state_transitions(state: VmState) {
        match state {
            VmState::Created => {
                // Check the transitions from Created
                assert!(state.valid_transition(VmState::Created).is_err());
                assert!(state.valid_transition(VmState::Running).is_ok());
                assert!(state.valid_transition(VmState::Shutdown).is_ok());
                assert!(state.valid_transition(VmState::Paused).is_ok());
                assert!(state.valid_transition(VmState::BreakPoint).is_ok());
            }
            VmState::Running => {
                // Check the transitions from Running
                assert!(state.valid_transition(VmState::Created).is_err());
                assert!(state.valid_transition(VmState::Running).is_err());
                assert!(state.valid_transition(VmState::Shutdown).is_ok());
                assert!(state.valid_transition(VmState::Paused).is_ok());
                assert!(state.valid_transition(VmState::BreakPoint).is_ok());
            }
            VmState::Shutdown => {
                // Check the transitions from Shutdown
                assert!(state.valid_transition(VmState::Created).is_err());
                assert!(state.valid_transition(VmState::Running).is_ok());
                assert!(state.valid_transition(VmState::Shutdown).is_err());
                assert!(state.valid_transition(VmState::Paused).is_err());
                assert!(state.valid_transition(VmState::BreakPoint).is_err());
            }
            VmState::Paused => {
                // Check the transitions from Paused
                assert!(state.valid_transition(VmState::Created).is_err());
                assert!(state.valid_transition(VmState::Running).is_ok());
                assert!(state.valid_transition(VmState::Shutdown).is_ok());
                assert!(state.valid_transition(VmState::Paused).is_err());
                assert!(state.valid_transition(VmState::BreakPoint).is_err());
            }
            VmState::BreakPoint => {
                // Check the transitions from Breakpoint
                assert!(state.valid_transition(VmState::Created).is_ok());
                assert!(state.valid_transition(VmState::Running).is_ok());
                assert!(state.valid_transition(VmState::Shutdown).is_err());
                assert!(state.valid_transition(VmState::Paused).is_err());
                assert!(state.valid_transition(VmState::BreakPoint).is_err());
            }
        }
    }

    #[test]
    fn test_vm_created_transitions() {
        test_vm_state_transitions(VmState::Created);
    }

    #[test]
    fn test_vm_running_transitions() {
        test_vm_state_transitions(VmState::Running);
    }

    #[test]
    fn test_vm_shutdown_transitions() {
        test_vm_state_transitions(VmState::Shutdown);
    }

    #[test]
    fn test_vm_paused_transitions() {
        test_vm_state_transitions(VmState::Paused);
    }

    #[cfg(feature = "tdx")]
    #[test]
    fn test_hob_memory_resources() {
        // Case 1: Two TDVF sections in the middle of the RAM
        let sections = vec![
            TdvfSection {
                address: 0xc000,
                size: 0x1000,
                ..Default::default()
            },
            TdvfSection {
                address: 0x1000,
                size: 0x4000,
                ..Default::default()
            },
        ];
        let guest_ranges: Vec<(GuestAddress, usize)> = vec![(GuestAddress(0), 0x1000_0000)];
        let expected = vec![
            (0, 0x1000, true),
            (0x1000, 0x4000, false),
            (0x5000, 0x7000, true),
            (0xc000, 0x1000, false),
            (0xd000, 0x0fff_3000, true),
        ];
        assert_eq!(
            expected,
            Vm::hob_memory_resources(
                sections,
                &GuestMemoryMmap::from_ranges(&guest_ranges).unwrap()
            )
        );

        // Case 2: Two TDVF sections with no conflict with the RAM
        let sections = vec![
            TdvfSection {
                address: 0x1000_1000,
                size: 0x1000,
                ..Default::default()
            },
            TdvfSection {
                address: 0,
                size: 0x1000,
                ..Default::default()
            },
        ];
        let guest_ranges: Vec<(GuestAddress, usize)> = vec![(GuestAddress(0x1000), 0x1000_0000)];
        let expected = vec![
            (0, 0x1000, false),
            (0x1000, 0x1000_0000, true),
            (0x1000_1000, 0x1000, false),
        ];
        assert_eq!(
            expected,
            Vm::hob_memory_resources(
                sections,
                &GuestMemoryMmap::from_ranges(&guest_ranges).unwrap()
            )
        );

        // Case 3: Two TDVF sections with partial conflicts with the RAM
        let sections = vec![
            TdvfSection {
                address: 0x1000_0000,
                size: 0x2000,
                ..Default::default()
            },
            TdvfSection {
                address: 0,
                size: 0x2000,
                ..Default::default()
            },
        ];
        let guest_ranges: Vec<(GuestAddress, usize)> = vec![(GuestAddress(0x1000), 0x1000_0000)];
        let expected = vec![
            (0, 0x2000, false),
            (0x2000, 0x0fff_e000, true),
            (0x1000_0000, 0x2000, false),
        ];
        assert_eq!(
            expected,
            Vm::hob_memory_resources(
                sections,
                &GuestMemoryMmap::from_ranges(&guest_ranges).unwrap()
            )
        );

        // Case 4: Two TDVF sections with no conflict before the RAM and two
        // more additional sections with no conflict after the RAM.
        let sections = vec![
            TdvfSection {
                address: 0x2000_1000,
                size: 0x1000,
                ..Default::default()
            },
            TdvfSection {
                address: 0x2000_0000,
                size: 0x1000,
                ..Default::default()
            },
            TdvfSection {
                address: 0x1000,
                size: 0x1000,
                ..Default::default()
            },
            TdvfSection {
                address: 0,
                size: 0x1000,
                ..Default::default()
            },
        ];
        let guest_ranges: Vec<(GuestAddress, usize)> = vec![(GuestAddress(0x4000), 0x1000_0000)];
        let expected = vec![
            (0, 0x1000, false),
            (0x1000, 0x1000, false),
            (0x4000, 0x1000_0000, true),
            (0x2000_0000, 0x1000, false),
            (0x2000_1000, 0x1000, false),
        ];
        assert_eq!(
            expected,
            Vm::hob_memory_resources(
                sections,
                &GuestMemoryMmap::from_ranges(&guest_ranges).unwrap()
            )
        );

        // Case 5: One TDVF section overriding the entire RAM
        let sections = vec![TdvfSection {
            address: 0,
            size: 0x2000_0000,
            ..Default::default()
        }];
        let guest_ranges: Vec<(GuestAddress, usize)> = vec![(GuestAddress(0x1000), 0x1000_0000)];
        let expected = vec![(0, 0x2000_0000, false)];
        assert_eq!(
            expected,
            Vm::hob_memory_resources(
                sections,
                &GuestMemoryMmap::from_ranges(&guest_ranges).unwrap()
            )
        );

        // Case 6: Two TDVF sections with no conflict with 2 RAM regions
        let sections = vec![
            TdvfSection {
                address: 0x1000_2000,
                size: 0x2000,
                ..Default::default()
            },
            TdvfSection {
                address: 0,
                size: 0x2000,
                ..Default::default()
            },
        ];
        let guest_ranges: Vec<(GuestAddress, usize)> = vec![
            (GuestAddress(0x2000), 0x1000_0000),
            (GuestAddress(0x1000_4000), 0x1000_0000),
        ];
        let expected = vec![
            (0, 0x2000, false),
            (0x2000, 0x1000_0000, true),
            (0x1000_2000, 0x2000, false),
            (0x1000_4000, 0x1000_0000, true),
        ];
        assert_eq!(
            expected,
            Vm::hob_memory_resources(
                sections,
                &GuestMemoryMmap::from_ranges(&guest_ranges).unwrap()
            )
        );

        // Case 7: Two TDVF sections with partial conflicts with 2 RAM regions
        let sections = vec![
            TdvfSection {
                address: 0x1000_0000,
                size: 0x4000,
                ..Default::default()
            },
            TdvfSection {
                address: 0,
                size: 0x4000,
                ..Default::default()
            },
        ];
        let guest_ranges: Vec<(GuestAddress, usize)> = vec![
            (GuestAddress(0x1000), 0x1000_0000),
            (GuestAddress(0x1000_3000), 0x1000_0000),
        ];
        let expected = vec![
            (0, 0x4000, false),
            (0x4000, 0x0fff_c000, true),
            (0x1000_0000, 0x4000, false),
            (0x1000_4000, 0x0fff_f000, true),
        ];
        assert_eq!(
            expected,
            Vm::hob_memory_resources(
                sections,
                &GuestMemoryMmap::from_ranges(&guest_ranges).unwrap()
            )
        );
    }
}

#[cfg(target_arch = "aarch64")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::GuestMemoryMmap;
    use arch::aarch64::fdt::create_fdt;
    use arch::aarch64::layout;
    use arch::{DeviceType, MmioDeviceInfo};
    use devices::gic::Gic;

    const LEN: u64 = 4096;

    #[test]
    fn test_create_fdt_with_devices() {
        let regions = vec![(layout::RAM_START, (layout::FDT_MAX_SIZE + 0x1000) as usize)];
        let mem = GuestMemoryMmap::from_ranges(&regions).expect("Cannot initialize memory");

        let dev_info: HashMap<(DeviceType, std::string::String), MmioDeviceInfo> = [
            (
                (DeviceType::Serial, DeviceType::Serial.to_string()),
                MmioDeviceInfo {
                    addr: 0x00,
                    len: LEN,
                    irq: 33,
                },
            ),
            (
                (DeviceType::Virtio(1), "virtio".to_string()),
                MmioDeviceInfo {
                    addr: LEN,
                    len: LEN,
                    irq: 34,
                },
            ),
            (
                (DeviceType::Rtc, "rtc".to_string()),
                MmioDeviceInfo {
                    addr: 2 * LEN,
                    len: LEN,
                    irq: 35,
                },
            ),
        ]
        .iter()
        .cloned()
        .collect();

        let hv = hypervisor::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let gic = vm
            .create_vgic(Gic::create_default_config(1))
            .expect("Cannot create gic");
        assert!(create_fdt(
            &mem,
            "console=tty0",
            vec![0],
            Some((0, 0, 0)),
            &dev_info,
            &gic,
            &None,
            &Vec::new(),
            &BTreeMap::new(),
            None,
            true,
        )
        .is_ok())
    }
}

#[cfg(all(feature = "kvm", target_arch = "x86_64"))]
#[test]
pub fn test_vm() {
    use hypervisor::VmExit;
    use vm_memory::{Address, GuestMemory, GuestMemoryRegion};
    // This example based on https://lwn.net/Articles/658511/
    let code = [
        0xba, 0xf8, 0x03, /* mov $0x3f8, %dx */
        0x00, 0xd8, /* add %bl, %al */
        0x04, b'0', /* add $'0', %al */
        0xee, /* out %al, (%dx) */
        0xb0, b'\n', /* mov $'\n', %al */
        0xee,  /* out %al, (%dx) */
        0xf4,  /* hlt */
    ];

    let mem_size = 0x1000;
    let load_addr = GuestAddress(0x1000);
    let mem = GuestMemoryMmap::from_ranges(&[(load_addr, mem_size)]).unwrap();

    let hv = hypervisor::new().unwrap();
    let vm = hv.create_vm().expect("new VM creation failed");

    for (index, region) in mem.iter().enumerate() {
        let mem_region = vm.make_user_memory_region(
            index as u32,
            region.start_addr().raw_value(),
            region.len(),
            region.as_ptr() as u64,
            false,
            false,
        );

        vm.create_user_memory_region(mem_region)
            .expect("Cannot configure guest memory");
    }
    mem.write_slice(&code, load_addr)
        .expect("Writing code to memory failed");

    let vcpu = vm.create_vcpu(0, None).expect("new Vcpu failed");

    let mut vcpu_sregs = vcpu.get_sregs().expect("get sregs failed");
    vcpu_sregs.cs.base = 0;
    vcpu_sregs.cs.selector = 0;
    vcpu.set_sregs(&vcpu_sregs).expect("set sregs failed");

    let mut vcpu_regs = vcpu.get_regs().expect("get regs failed");
    vcpu_regs.rip = 0x1000;
    vcpu_regs.rax = 2;
    vcpu_regs.rbx = 3;
    vcpu_regs.rflags = 2;
    vcpu.set_regs(&vcpu_regs).expect("set regs failed");

    loop {
        match vcpu.run().expect("run failed") {
            VmExit::IoOut(addr, data) => {
                println!(
                    "IO out -- addr: {:#x} data [{:?}]",
                    addr,
                    str::from_utf8(data).unwrap()
                );
            }
            VmExit::Reset => {
                println!("HLT");
                break;
            }
            r => panic!("unexpected exit reason: {r:?}"),
        }
    }
}
