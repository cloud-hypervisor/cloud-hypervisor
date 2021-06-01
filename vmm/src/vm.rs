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

#[cfg(feature = "acpi")]
use crate::config::NumaConfig;
use crate::config::{
    DeviceConfig, DiskConfig, FsConfig, HotplugMethod, NetConfig, PmemConfig, ValidationError,
    VmConfig, VsockConfig,
};
use crate::cpu;
use crate::device_manager::{
    self, get_win_size, Console, DeviceManager, DeviceManagerError, PtyPair,
};
use crate::device_tree::DeviceTree;
use crate::memory_manager::{Error as MemoryManagerError, MemoryManager};
use crate::migration::{get_vm_snapshot, url_to_path, VM_SNAPSHOT_FILE};
use crate::seccomp_filters::{get_seccomp_filter, Thread};
use crate::{
    PciDeviceInfo, CPU_MANAGER_SNAPSHOT_ID, DEVICE_MANAGER_SNAPSHOT_ID, MEMORY_MANAGER_SNAPSHOT_ID,
};
use anyhow::anyhow;
use arch::get_host_cpu_phys_bits;
#[cfg(feature = "tdx")]
use arch::x86_64::tdx::TdvfSection;
use arch::EntryPoint;
use devices::AcpiNotificationFlags;
use hypervisor::vm::{HypervisorVmError, VmmOps};
use linux_loader::cmdline::Cmdline;
#[cfg(target_arch = "x86_64")]
use linux_loader::loader::elf::PvhBootCapability::PvhEntryPresent;
use linux_loader::loader::KernelLoader;
use seccomp::{SeccompAction, SeccompFilter};
use signal_hook::{
    consts::{SIGINT, SIGTERM, SIGWINCH},
    iterator::backend::Handle,
    iterator::Signals,
};
use std::cmp;
use std::collections::{BTreeMap, HashMap};
use std::convert::TryInto;
use std::ffi::CString;
#[cfg(target_arch = "x86_64")]
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::io::{Seek, SeekFrom};
use std::num::Wrapping;
use std::ops::Deref;
use std::sync::{Arc, Mutex, RwLock};
use std::{result, str, thread};
use vm_device::Bus;
use vm_memory::{
    Address, Bytes, GuestAddress, GuestAddressSpace, GuestMemory, GuestMemoryAtomic,
    GuestMemoryMmap, GuestMemoryRegion, GuestRegionMmap,
};
use vm_migration::{
    protocol::{MemoryRange, MemoryRangeTable},
    Migratable, MigratableError, Pausable, Snapshot, SnapshotDataSection, Snapshottable,
    Transportable,
};
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::terminal::Terminal;

#[cfg(target_arch = "aarch64")]
use arch::aarch64::gic::gicv3::kvm::{KvmGicV3, GIC_V3_SNAPSHOT_ID};
#[cfg(target_arch = "aarch64")]
use arch::aarch64::gic::kvm::create_gic;
#[cfg(target_arch = "aarch64")]
use devices::interrupt_controller::{self, InterruptController};

/// Errors associated with VM management
#[derive(Debug)]
pub enum Error {
    /// Cannot open the kernel image
    KernelFile(io::Error),

    /// Cannot open the initramfs image
    InitramfsFile(io::Error),

    /// Cannot load the kernel in memory
    KernelLoad(linux_loader::loader::Error),

    /// Cannot load the initramfs in memory
    InitramfsLoad,

    /// Cannot load the command line in memory
    LoadCmdLine(linux_loader::loader::Error),

    /// Cannot modify the command line
    CmdLineInsertStr(linux_loader::cmdline::Error),

    /// Cannot convert command line into CString
    CmdLineCString(std::ffi::NulError),

    /// Cannot configure system
    ConfigureSystem(arch::Error),

    /// Cannot enable interrupt controller
    #[cfg(target_arch = "aarch64")]
    EnableInterruptController(interrupt_controller::Error),

    PoisonedState,

    /// Cannot create a device manager.
    DeviceManager(DeviceManagerError),

    /// Write to the console failed.
    Console(vmm_sys_util::errno::Error),

    /// Write to the pty console failed.
    PtyConsole(io::Error),

    /// Cannot setup terminal in raw mode.
    SetTerminalRaw(vmm_sys_util::errno::Error),

    /// Cannot setup terminal in canonical mode.
    SetTerminalCanon(vmm_sys_util::errno::Error),

    /// Memory is overflow
    MemOverflow,

    /// Cannot spawn a signal handler thread
    SignalHandlerSpawn(io::Error),

    /// Failed to join on vCPU threads
    ThreadCleanup(std::boxed::Box<dyn std::any::Any + std::marker::Send>),

    /// VM is not created
    VmNotCreated,

    /// VM is already created
    VmAlreadyCreated,

    /// VM is not running
    VmNotRunning,

    /// Cannot clone EventFd.
    EventFdClone(io::Error),

    /// Invalid VM state transition
    InvalidStateTransition(VmState, VmState),

    /// Error from CPU handling
    CpuManager(cpu::Error),

    /// Cannot pause devices
    PauseDevices(MigratableError),

    /// Cannot resume devices
    ResumeDevices(MigratableError),

    /// Cannot pause CPUs
    PauseCpus(MigratableError),

    /// Cannot resume cpus
    ResumeCpus(MigratableError),

    /// Cannot pause VM
    Pause(MigratableError),

    /// Cannot resume VM
    Resume(MigratableError),

    /// Memory manager error
    MemoryManager(MemoryManagerError),

    /// Eventfd write error
    EventfdError(std::io::Error),

    /// Cannot snapshot VM
    Snapshot(MigratableError),

    /// Cannot restore VM
    Restore(MigratableError),

    /// Cannot send VM snapshot
    SnapshotSend(MigratableError),

    /// Cannot convert source URL from Path into &str
    RestoreSourceUrlPathToStr,

    /// Failed to validate config
    ConfigValidation(ValidationError),

    /// No more that one virtio-vsock device
    TooManyVsockDevices,

    /// Failed serializing into JSON
    SerializeJson(serde_json::Error),

    /// Invalid configuration for NUMA.
    InvalidNumaConfig,

    /// Cannot create seccomp filter
    CreateSeccompFilter(seccomp::SeccompError),

    /// Cannot apply seccomp filter
    ApplySeccompFilter(seccomp::Error),

    /// Failed resizing a memory zone.
    ResizeZone,

    /// Cannot activate virtio devices
    ActivateVirtioDevices(device_manager::DeviceManagerError),

    /// Power button not supported
    PowerButtonNotSupported,

    /// Error triggering power button
    PowerButton(device_manager::DeviceManagerError),

    /// Kernel lacks PVH header
    KernelMissingPvhHeader,

    /// Error doing I/O on TDX firmware file
    #[cfg(feature = "tdx")]
    LoadTdvf(std::io::Error),

    /// Error parsing TDVF
    #[cfg(feature = "tdx")]
    ParseTdvf(arch::x86_64::tdx::TdvfError),

    /// Error populating HOB
    #[cfg(feature = "tdx")]
    PopulateHob(arch::x86_64::tdx::TdvfError),

    /// Error allocating TDVF memory
    #[cfg(feature = "tdx")]
    AllocatingTdvfMemory(crate::memory_manager::Error),

    /// Error enabling TDX VM
    #[cfg(feature = "tdx")]
    InitializeTdxVm(hypervisor::HypervisorVmError),

    /// Error enabling TDX memory region
    #[cfg(feature = "tdx")]
    InitializeTdxMemoryRegion(hypervisor::HypervisorVmError),

    /// Error finalizing TDX setup
    #[cfg(feature = "tdx")]
    FinalizeTdx(hypervisor::HypervisorVmError),
}
pub type Result<T> = result::Result<T, Error>;

#[derive(Clone, Default)]
pub struct NumaNode {
    memory_regions: Vec<Arc<GuestRegionMmap>>,
    hotplug_regions: Vec<Arc<GuestRegionMmap>>,
    cpus: Vec<u8>,
    distances: BTreeMap<u32, u8>,
    memory_zones: Vec<String>,
}

impl NumaNode {
    pub fn memory_regions(&self) -> &Vec<Arc<GuestRegionMmap>> {
        &self.memory_regions
    }

    pub fn hotplug_regions(&self) -> &Vec<Arc<GuestRegionMmap>> {
        &self.hotplug_regions
    }

    pub fn cpus(&self) -> &Vec<u8> {
        &self.cpus
    }

    pub fn distances(&self) -> &BTreeMap<u32, u8> {
        &self.distances
    }

    pub fn memory_zones(&self) -> &Vec<String> {
        &self.memory_zones
    }
}

pub type NumaNodes = BTreeMap<u32, NumaNode>;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq)]
pub enum VmState {
    Created,
    Running,
    Shutdown,
    Paused,
}

impl VmState {
    fn valid_transition(self, new_state: VmState) -> Result<()> {
        match self {
            VmState::Created => match new_state {
                VmState::Created | VmState::Shutdown => {
                    Err(Error::InvalidStateTransition(self, new_state))
                }
                VmState::Running | VmState::Paused => Ok(()),
            },

            VmState::Running => match new_state {
                VmState::Created | VmState::Running => {
                    Err(Error::InvalidStateTransition(self, new_state))
                }
                VmState::Paused | VmState::Shutdown => Ok(()),
            },

            VmState::Shutdown => match new_state {
                VmState::Paused | VmState::Created | VmState::Shutdown => {
                    Err(Error::InvalidStateTransition(self, new_state))
                }
                VmState::Running => Ok(()),
            },

            VmState::Paused => match new_state {
                VmState::Created | VmState::Paused => {
                    Err(Error::InvalidStateTransition(self, new_state))
                }
                VmState::Running | VmState::Shutdown => Ok(()),
            },
        }
    }
}

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

struct VmOps {
    memory: GuestMemoryAtomic<GuestMemoryMmap>,
    #[cfg(target_arch = "x86_64")]
    io_bus: Arc<Bus>,
    mmio_bus: Arc<Bus>,
    #[cfg(target_arch = "x86_64")]
    timestamp: std::time::Instant,
}

impl VmOps {
    #[cfg(target_arch = "x86_64")]
    // Log debug io port codes.
    fn log_debug_ioport(&self, code: u8) {
        let elapsed = self.timestamp.elapsed();

        debug!(
            "[{} code 0x{:x}] {}.{:>06} seconds",
            DebugIoPortRange::from_u8(code),
            code,
            elapsed.as_secs(),
            elapsed.as_micros()
        );
    }
}

impl VmmOps for VmOps {
    fn guest_mem_write(&self, gpa: u64, buf: &[u8]) -> hypervisor::vm::Result<usize> {
        self.memory
            .memory()
            .write(buf, GuestAddress(gpa))
            .map_err(|e| HypervisorVmError::GuestMemWrite(e.into()))
    }

    fn guest_mem_read(&self, gpa: u64, buf: &mut [u8]) -> hypervisor::vm::Result<usize> {
        self.memory
            .memory()
            .read(buf, GuestAddress(gpa))
            .map_err(|e| HypervisorVmError::GuestMemRead(e.into()))
    }

    fn mmio_read(&self, gpa: u64, data: &mut [u8]) -> hypervisor::vm::Result<()> {
        if let Err(vm_device::BusError::MissingAddressRange) = self.mmio_bus.read(gpa, data) {
            warn!("Guest MMIO read to unregistered address 0x{:x}", gpa);
        }
        Ok(())
    }

    fn mmio_write(&self, gpa: u64, data: &[u8]) -> hypervisor::vm::Result<()> {
        match self.mmio_bus.write(gpa, data) {
            Err(vm_device::BusError::MissingAddressRange) => {
                warn!("Guest MMIO write to unregistered address 0x{:x}", gpa);
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
    fn pio_read(&self, port: u64, data: &mut [u8]) -> hypervisor::vm::Result<()> {
        if let Err(vm_device::BusError::MissingAddressRange) = self.io_bus.read(port, data) {
            warn!("Guest PIO read to unregistered address 0x{:x}", port);
        }
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn pio_write(&self, port: u64, data: &[u8]) -> hypervisor::vm::Result<()> {
        if port == DEBUG_IOPORT as u64 && data.len() == 1 {
            self.log_debug_ioport(data[0]);
            return Ok(());
        }

        match self.io_bus.write(port, data) {
            Err(vm_device::BusError::MissingAddressRange) => {
                warn!("Guest PIO write to unregistered address 0x{:x}", port);
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

pub fn physical_bits(max_phys_bits: Option<u8>) -> u8 {
    let host_phys_bits = get_host_cpu_phys_bits();
    cmp::min(host_phys_bits, max_phys_bits.unwrap_or(host_phys_bits))
}

pub struct Vm {
    kernel: Option<File>,
    initramfs: Option<File>,
    threads: Vec<thread::JoinHandle<()>>,
    device_manager: Arc<Mutex<DeviceManager>>,
    config: Arc<Mutex<VmConfig>>,
    on_tty: bool,
    signals: Option<Handle>,
    state: RwLock<VmState>,
    cpu_manager: Arc<Mutex<cpu::CpuManager>>,
    memory_manager: Arc<Mutex<MemoryManager>>,
    #[cfg_attr(not(feature = "kvm"), allow(dead_code))]
    // The hypervisor abstracted virtual machine.
    vm: Arc<dyn hypervisor::Vm>,
    #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
    saved_clock: Option<hypervisor::ClockData>,
    #[cfg(feature = "acpi")]
    numa_nodes: NumaNodes,
    seccomp_action: SeccompAction,
    exit_evt: EventFd,
}

impl Vm {
    #[allow(clippy::too_many_arguments)]
    fn new_from_memory_manager(
        config: Arc<Mutex<VmConfig>>,
        memory_manager: Arc<Mutex<MemoryManager>>,
        vm: Arc<dyn hypervisor::Vm>,
        exit_evt: EventFd,
        reset_evt: EventFd,
        seccomp_action: &SeccompAction,
        hypervisor: Arc<dyn hypervisor::Hypervisor>,
        #[cfg(all(feature = "kvm", target_arch = "x86_64"))] _saved_clock: Option<
            hypervisor::ClockData,
        >,
        activate_evt: EventFd,
    ) -> Result<Self> {
        config
            .lock()
            .unwrap()
            .validate()
            .map_err(Error::ConfigValidation)?;

        info!("Booting VM from config: {:?}", &config);

        // Create NUMA nodes based on NumaConfig.
        #[cfg(feature = "acpi")]
        let numa_nodes =
            Self::create_numa_nodes(config.lock().unwrap().numa.clone(), &memory_manager)?;

        let device_manager = DeviceManager::new(
            vm.clone(),
            config.clone(),
            memory_manager.clone(),
            &exit_evt,
            &reset_evt,
            seccomp_action.clone(),
            #[cfg(feature = "acpi")]
            numa_nodes.clone(),
            &activate_evt,
        )
        .map_err(Error::DeviceManager)?;

        let memory = memory_manager.lock().unwrap().guest_memory();
        #[cfg(target_arch = "x86_64")]
        let io_bus = Arc::clone(device_manager.lock().unwrap().io_bus());
        let mmio_bus = Arc::clone(device_manager.lock().unwrap().mmio_bus());
        // Create the VmOps structure, which implements the VmmOps trait.
        // And send it to the hypervisor.
        let vm_ops: Arc<Box<dyn VmmOps>> = Arc::new(Box::new(VmOps {
            memory,
            #[cfg(target_arch = "x86_64")]
            io_bus,
            mmio_bus,
            #[cfg(target_arch = "x86_64")]
            timestamp: std::time::Instant::now(),
        }));

        let exit_evt_clone = exit_evt.try_clone().map_err(Error::EventFdClone)?;
        let cpu_manager = cpu::CpuManager::new(
            &config.lock().unwrap().cpus.clone(),
            &device_manager,
            &memory_manager,
            vm.clone(),
            exit_evt_clone,
            reset_evt,
            hypervisor,
            seccomp_action.clone(),
            vm_ops,
        )
        .map_err(Error::CpuManager)?;

        let on_tty = unsafe { libc::isatty(libc::STDIN_FILENO as i32) } != 0;
        let kernel = config
            .lock()
            .unwrap()
            .kernel
            .as_ref()
            .map(|k| File::open(&k.path))
            .transpose()
            .map_err(Error::KernelFile)?;

        let initramfs = config
            .lock()
            .unwrap()
            .initramfs
            .as_ref()
            .map(|i| File::open(&i.path))
            .transpose()
            .map_err(Error::InitramfsFile)?;

        Ok(Vm {
            kernel,
            initramfs,
            device_manager,
            config,
            on_tty,
            threads: Vec::with_capacity(1),
            signals: None,
            state: RwLock::new(VmState::Created),
            cpu_manager,
            memory_manager,
            vm,
            #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
            saved_clock: _saved_clock,
            #[cfg(feature = "acpi")]
            numa_nodes,
            seccomp_action: seccomp_action.clone(),
            exit_evt,
        })
    }

    #[cfg(feature = "acpi")]
    fn create_numa_nodes(
        configs: Option<Vec<NumaConfig>>,
        memory_manager: &Arc<Mutex<MemoryManager>>,
    ) -> Result<NumaNodes> {
        let mm = memory_manager.lock().unwrap();
        let mm_zones = mm.memory_zones();
        let mut numa_nodes = BTreeMap::new();

        if let Some(configs) = &configs {
            let node_id_list: Vec<u32> = configs.iter().map(|cfg| cfg.guest_numa_id).collect();

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

                if let Some(distances) = &config.distances {
                    for distance in distances.iter() {
                        let dest = distance.destination;
                        let dist = distance.distance;

                        if !node_id_list.contains(&dest) {
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

                numa_nodes.insert(config.guest_numa_id, node);
            }
        }

        Ok(numa_nodes)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: Arc<Mutex<VmConfig>>,
        exit_evt: EventFd,
        reset_evt: EventFd,
        seccomp_action: &SeccompAction,
        hypervisor: Arc<dyn hypervisor::Hypervisor>,
        activate_evt: EventFd,
        serial_pty: Option<PtyPair>,
        console_pty: Option<PtyPair>,
    ) -> Result<Self> {
        #[cfg(feature = "tdx")]
        let tdx_enabled = config.lock().unwrap().tdx.is_some();
        hypervisor.check_required_extensions().unwrap();
        #[cfg(feature = "tdx")]
        let vm = hypervisor
            .create_vm_with_type(if tdx_enabled {
                2 // KVM_X86_TDX_VM
            } else {
                0 // KVM_X86_LEGACY_VM
            })
            .unwrap();
        #[cfg(not(feature = "tdx"))]
        let vm = hypervisor.create_vm().unwrap();

        #[cfg(target_arch = "x86_64")]
        vm.enable_split_irq().unwrap();
        let phys_bits = physical_bits(config.lock().unwrap().cpus.max_phys_bits);
        let memory_manager = MemoryManager::new(
            vm.clone(),
            &config.lock().unwrap().memory.clone(),
            false,
            phys_bits,
            #[cfg(feature = "tdx")]
            tdx_enabled,
        )
        .map_err(Error::MemoryManager)?;

        #[cfg(target_arch = "x86_64")]
        {
            if let Some(sgx_epc_config) = config.lock().unwrap().sgx_epc.clone() {
                memory_manager
                    .lock()
                    .unwrap()
                    .setup_sgx(sgx_epc_config)
                    .map_err(Error::MemoryManager)?;
            }
        }

        let new_vm = Vm::new_from_memory_manager(
            config,
            memory_manager,
            vm,
            exit_evt,
            reset_evt,
            seccomp_action,
            hypervisor,
            #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
            None,
            activate_evt,
        )?;

        // The device manager must create the devices from here as it is part
        // of the regular code path creating everything from scratch.
        new_vm
            .device_manager
            .lock()
            .unwrap()
            .create_devices(serial_pty, console_pty)
            .map_err(Error::DeviceManager)?;
        Ok(new_vm)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_from_snapshot(
        snapshot: &Snapshot,
        exit_evt: EventFd,
        reset_evt: EventFd,
        source_url: Option<&str>,
        prefault: bool,
        seccomp_action: &SeccompAction,
        hypervisor: Arc<dyn hypervisor::Hypervisor>,
        activate_evt: EventFd,
    ) -> Result<Self> {
        hypervisor.check_required_extensions().unwrap();
        let vm = hypervisor.create_vm().unwrap();
        #[cfg(target_arch = "x86_64")]
        vm.enable_split_irq().unwrap();
        let vm_snapshot = get_vm_snapshot(snapshot).map_err(Error::Restore)?;
        let config = vm_snapshot.config;
        if let Some(state) = vm_snapshot.state {
            vm.set_state(state)
                .map_err(|e| Error::Restore(MigratableError::Restore(e.into())))?;
        }

        let memory_manager = if let Some(memory_manager_snapshot) =
            snapshot.snapshots.get(MEMORY_MANAGER_SNAPSHOT_ID)
        {
            let phys_bits = physical_bits(config.lock().unwrap().cpus.max_phys_bits);
            MemoryManager::new_from_snapshot(
                memory_manager_snapshot,
                vm.clone(),
                &config.lock().unwrap().memory.clone(),
                source_url,
                prefault,
                phys_bits,
            )
            .map_err(Error::MemoryManager)?
        } else {
            return Err(Error::Restore(MigratableError::Restore(anyhow!(
                "Missing memory manager snapshot"
            ))));
        };

        Vm::new_from_memory_manager(
            config,
            memory_manager,
            vm,
            exit_evt,
            reset_evt,
            seccomp_action,
            hypervisor,
            #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
            vm_snapshot.clock,
            activate_evt,
        )
    }

    pub fn new_from_migration(
        config: Arc<Mutex<VmConfig>>,
        exit_evt: EventFd,
        reset_evt: EventFd,
        seccomp_action: &SeccompAction,
        hypervisor: Arc<dyn hypervisor::Hypervisor>,
        activate_evt: EventFd,
    ) -> Result<Self> {
        hypervisor.check_required_extensions().unwrap();
        let vm = hypervisor.create_vm().unwrap();
        #[cfg(target_arch = "x86_64")]
        vm.enable_split_irq().unwrap();
        let phys_bits = physical_bits(config.lock().unwrap().cpus.max_phys_bits);

        let memory_manager = MemoryManager::new(
            vm.clone(),
            &config.lock().unwrap().memory.clone(),
            false,
            phys_bits,
            #[cfg(feature = "tdx")]
            false,
        )
        .map_err(Error::MemoryManager)?;

        Vm::new_from_memory_manager(
            config,
            memory_manager,
            vm,
            exit_evt,
            reset_evt,
            seccomp_action,
            hypervisor,
            #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
            None,
            activate_evt,
        )
    }

    fn load_initramfs(&mut self, guest_mem: &GuestMemoryMmap) -> Result<arch::InitramfsConfig> {
        let mut initramfs = self.initramfs.as_ref().unwrap();
        let size: usize = initramfs
            .seek(SeekFrom::End(0))
            .map_err(|_| Error::InitramfsLoad)?
            .try_into()
            .unwrap();
        initramfs
            .seek(SeekFrom::Start(0))
            .map_err(|_| Error::InitramfsLoad)?;

        let address =
            arch::initramfs_load_addr(guest_mem, size).map_err(|_| Error::InitramfsLoad)?;
        let address = GuestAddress(address);

        guest_mem
            .read_from(address, &mut initramfs, size)
            .map_err(|_| Error::InitramfsLoad)?;

        info!("Initramfs loaded: address = 0x{:x}", address.0);
        Ok(arch::InitramfsConfig { address, size })
    }

    fn get_cmdline(&mut self) -> Result<CString> {
        let mut cmdline = Cmdline::new(arch::CMDLINE_MAX_SIZE);
        cmdline
            .insert_str(self.config.lock().unwrap().cmdline.args.clone())
            .map_err(Error::CmdLineInsertStr)?;
        for entry in self.device_manager.lock().unwrap().cmdline_additions() {
            cmdline.insert_str(entry).map_err(Error::CmdLineInsertStr)?;
        }
        CString::new(cmdline).map_err(Error::CmdLineCString)
    }

    #[cfg(target_arch = "aarch64")]
    fn load_kernel(&mut self) -> Result<EntryPoint> {
        let guest_memory = self.memory_manager.lock().as_ref().unwrap().guest_memory();
        let mem = guest_memory.memory();
        let mut kernel = self.kernel.as_ref().unwrap();
        let entry_addr = match linux_loader::loader::pe::PE::load(
            mem.deref(),
            Some(GuestAddress(arch::get_kernel_start())),
            &mut kernel,
            None,
        ) {
            Ok(entry_addr) => entry_addr,
            Err(e) => {
                return Err(Error::KernelLoad(e));
            }
        };

        let entry_point_addr: GuestAddress = entry_addr.kernel_load;

        Ok(EntryPoint {
            entry_addr: entry_point_addr,
        })
    }

    #[cfg(target_arch = "x86_64")]
    fn load_kernel(&mut self) -> Result<EntryPoint> {
        info!("Loading kernel");
        let cmdline_cstring = self.get_cmdline()?;
        let guest_memory = self.memory_manager.lock().as_ref().unwrap().guest_memory();
        let mem = guest_memory.memory();
        let mut kernel = self.kernel.as_ref().unwrap();
        let entry_addr = match linux_loader::loader::elf::Elf::load(
            mem.deref(),
            None,
            &mut kernel,
            Some(arch::layout::HIGH_RAM_START),
        ) {
            Ok(entry_addr) => entry_addr,
            Err(e) => {
                return Err(Error::KernelLoad(e));
            }
        };

        linux_loader::loader::load_cmdline(
            mem.deref(),
            arch::layout::CMDLINE_START,
            &cmdline_cstring,
        )
        .map_err(Error::LoadCmdLine)?;

        if let PvhEntryPresent(entry_addr) = entry_addr.pvh_boot_cap {
            // Use the PVH kernel entry point to boot the guest
            info!("Kernel loaded: entry_addr = 0x{:x}", entry_addr.0);
            Ok(EntryPoint { entry_addr })
        } else {
            Err(Error::KernelMissingPvhHeader)
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn configure_system(&mut self) -> Result<()> {
        info!("Configuring system");
        let mem = self.memory_manager.lock().unwrap().boot_guest_memory();

        let initramfs_config = match self.initramfs {
            Some(_) => Some(self.load_initramfs(&mem)?),
            None => None,
        };

        let boot_vcpus = self.cpu_manager.lock().unwrap().boot_vcpus();

        #[allow(unused_mut, unused_assignments)]
        let mut rsdp_addr: Option<GuestAddress> = None;

        #[cfg(feature = "acpi")]
        {
            rsdp_addr = Some(crate::acpi::create_acpi_tables(
                &mem,
                &self.device_manager,
                &self.cpu_manager,
                &self.memory_manager,
                &self.numa_nodes,
            ));
            info!(
                "Created ACPI tables: rsdp_addr = 0x{:x}",
                rsdp_addr.unwrap().0
            );
        }

        let sgx_epc_region = self
            .memory_manager
            .lock()
            .unwrap()
            .sgx_epc_region()
            .as_ref()
            .cloned();

        arch::configure_system(
            &mem,
            arch::layout::CMDLINE_START,
            &initramfs_config,
            boot_vcpus,
            rsdp_addr,
            sgx_epc_region,
        )
        .map_err(Error::ConfigureSystem)?;
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn configure_system(&mut self) -> Result<()> {
        let cmdline_cstring = self.get_cmdline()?;
        let vcpu_mpidrs = self.cpu_manager.lock().unwrap().get_mpidrs();
        let mem = self.memory_manager.lock().unwrap().boot_guest_memory();
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

        let pci_space_start: GuestAddress = self
            .memory_manager
            .lock()
            .as_ref()
            .unwrap()
            .start_of_device_area();

        let pci_space_end: GuestAddress = self
            .memory_manager
            .lock()
            .as_ref()
            .unwrap()
            .end_of_device_area();

        let pci_space_size = pci_space_end
            .checked_offset_from(pci_space_start)
            .ok_or(Error::MemOverflow)?
            + 1;

        let pci_space = (pci_space_start.0, pci_space_size);

        #[cfg(feature = "acpi")]
        {
            let _ = crate::acpi::create_acpi_tables(
                &mem,
                &self.device_manager,
                &self.cpu_manager,
                &self.memory_manager,
                &self.numa_nodes,
            );
        }

        let gic_device = create_gic(
            &self.memory_manager.lock().as_ref().unwrap().vm,
            self.cpu_manager.lock().unwrap().boot_vcpus() as u64,
        )
        .map_err(|e| {
            Error::ConfigureSystem(arch::Error::AArch64Setup(arch::aarch64::Error::SetupGic(e)))
        })?;

        arch::configure_system(
            &mem,
            &cmdline_cstring,
            vcpu_mpidrs,
            device_info,
            &initramfs_config,
            &pci_space,
            &*gic_device,
        )
        .map_err(Error::ConfigureSystem)?;

        // Update the GIC entity in device manager
        self.device_manager
            .lock()
            .unwrap()
            .get_interrupt_controller()
            .unwrap()
            .lock()
            .unwrap()
            .set_gic_device(Arc::new(Mutex::new(gic_device)));

        // Activate gic device
        self.device_manager
            .lock()
            .unwrap()
            .get_interrupt_controller()
            .unwrap()
            .lock()
            .unwrap()
            .enable()
            .map_err(Error::EnableInterruptController)?;

        Ok(())
    }

    pub fn serial_pty(&self) -> Option<PtyPair> {
        self.device_manager.lock().unwrap().serial_pty()
    }

    pub fn console_pty(&self) -> Option<PtyPair> {
        self.device_manager.lock().unwrap().console_pty()
    }

    pub fn shutdown(&mut self) -> Result<()> {
        let mut state = self.state.try_write().map_err(|_| Error::PoisonedState)?;
        let new_state = VmState::Shutdown;

        state.valid_transition(new_state)?;

        if self.on_tty {
            // Don't forget to set the terminal in canonical mode
            // before to exit.
            io::stdin()
                .lock()
                .set_canon_mode()
                .map_err(Error::SetTerminalCanon)?;
        }

        // Trigger the termination of the signal_handler thread
        if let Some(signals) = self.signals.take() {
            signals.close();
        }

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

            let mut memory_config = &mut self.config.lock().unwrap().memory;

            if let Some(new_region) = &new_region {
                self.device_manager
                    .lock()
                    .unwrap()
                    .update_memory(&new_region)
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

    fn add_to_config<T>(devices: &mut Option<Vec<T>>, device: T) {
        if let Some(devices) = devices {
            devices.push(device);
        } else {
            *devices = Some(vec![device]);
        }
    }

    pub fn add_device(&mut self, mut _device_cfg: DeviceConfig) -> Result<PciDeviceInfo> {
        {
            // Validate on a clone of the config
            let mut config = self.config.lock().unwrap().clone();
            Self::add_to_config(&mut config.devices, _device_cfg.clone());
            config.validate().map_err(Error::ConfigValidation)?;
        }

        let pci_device_info = self
            .device_manager
            .lock()
            .unwrap()
            .add_device(&mut _device_cfg)
            .map_err(Error::DeviceManager)?;

        // Update VmConfig by adding the new device. This is important to
        // ensure the device would be created in case of a reboot.
        {
            let mut config = self.config.lock().unwrap();
            Self::add_to_config(&mut config.devices, _device_cfg);
        }

        self.device_manager
            .lock()
            .unwrap()
            .notify_hotplug(AcpiNotificationFlags::PCI_DEVICES_CHANGED)
            .map_err(Error::DeviceManager)?;

        Ok(pci_device_info)
    }

    pub fn remove_device(&mut self, _id: String) -> Result<()> {
        self.device_manager
            .lock()
            .unwrap()
            .remove_device(_id.clone())
            .map_err(Error::DeviceManager)?;

        // Update VmConfig by removing the device. This is important to
        // ensure the device would not be created in case of a reboot.
        let mut config = self.config.lock().unwrap();

        // Remove if VFIO device
        if let Some(devices) = config.devices.as_mut() {
            devices.retain(|dev| dev.id.as_ref() != Some(&_id));
        }

        // Remove if disk device
        if let Some(disks) = config.disks.as_mut() {
            disks.retain(|dev| dev.id.as_ref() != Some(&_id));
        }

        // Remove if net device
        if let Some(net) = config.net.as_mut() {
            net.retain(|dev| dev.id.as_ref() != Some(&_id));
        }

        // Remove if pmem device
        if let Some(pmem) = config.pmem.as_mut() {
            pmem.retain(|dev| dev.id.as_ref() != Some(&_id));
        }

        // Remove if vsock device
        if let Some(vsock) = config.vsock.as_ref() {
            if vsock.id.as_ref() == Some(&_id) {
                config.vsock = None;
            }
        }

        self.device_manager
            .lock()
            .unwrap()
            .notify_hotplug(AcpiNotificationFlags::PCI_DEVICES_CHANGED)
            .map_err(Error::DeviceManager)?;
        Ok(())
    }

    pub fn add_disk(&mut self, mut _disk_cfg: DiskConfig) -> Result<PciDeviceInfo> {
        {
            // Validate on a clone of the config
            let mut config = self.config.lock().unwrap().clone();
            Self::add_to_config(&mut config.disks, _disk_cfg.clone());
            config.validate().map_err(Error::ConfigValidation)?;
        }

        let pci_device_info = self
            .device_manager
            .lock()
            .unwrap()
            .add_disk(&mut _disk_cfg)
            .map_err(Error::DeviceManager)?;

        // Update VmConfig by adding the new device. This is important to
        // ensure the device would be created in case of a reboot.
        {
            let mut config = self.config.lock().unwrap();
            Self::add_to_config(&mut config.disks, _disk_cfg);
        }

        self.device_manager
            .lock()
            .unwrap()
            .notify_hotplug(AcpiNotificationFlags::PCI_DEVICES_CHANGED)
            .map_err(Error::DeviceManager)?;

        Ok(pci_device_info)
    }

    pub fn add_fs(&mut self, mut _fs_cfg: FsConfig) -> Result<PciDeviceInfo> {
        {
            // Validate on a clone of the config
            let mut config = self.config.lock().unwrap().clone();
            Self::add_to_config(&mut config.fs, _fs_cfg.clone());
            config.validate().map_err(Error::ConfigValidation)?;
        }

        let pci_device_info = self
            .device_manager
            .lock()
            .unwrap()
            .add_fs(&mut _fs_cfg)
            .map_err(Error::DeviceManager)?;

        // Update VmConfig by adding the new device. This is important to
        // ensure the device would be created in case of a reboot.
        {
            let mut config = self.config.lock().unwrap();
            Self::add_to_config(&mut config.fs, _fs_cfg);
        }

        self.device_manager
            .lock()
            .unwrap()
            .notify_hotplug(AcpiNotificationFlags::PCI_DEVICES_CHANGED)
            .map_err(Error::DeviceManager)?;

        Ok(pci_device_info)
    }

    pub fn add_pmem(&mut self, mut _pmem_cfg: PmemConfig) -> Result<PciDeviceInfo> {
        {
            // Validate on a clone of the config
            let mut config = self.config.lock().unwrap().clone();
            Self::add_to_config(&mut config.pmem, _pmem_cfg.clone());
            config.validate().map_err(Error::ConfigValidation)?;
        }

        let pci_device_info = self
            .device_manager
            .lock()
            .unwrap()
            .add_pmem(&mut _pmem_cfg)
            .map_err(Error::DeviceManager)?;

        // Update VmConfig by adding the new device. This is important to
        // ensure the device would be created in case of a reboot.
        {
            let mut config = self.config.lock().unwrap();
            Self::add_to_config(&mut config.pmem, _pmem_cfg);
        }

        self.device_manager
            .lock()
            .unwrap()
            .notify_hotplug(AcpiNotificationFlags::PCI_DEVICES_CHANGED)
            .map_err(Error::DeviceManager)?;

        Ok(pci_device_info)
    }

    pub fn add_net(&mut self, mut _net_cfg: NetConfig) -> Result<PciDeviceInfo> {
        {
            // Validate on a clone of the config
            let mut config = self.config.lock().unwrap().clone();
            Self::add_to_config(&mut config.net, _net_cfg.clone());
            config.validate().map_err(Error::ConfigValidation)?;
        }

        let pci_device_info = self
            .device_manager
            .lock()
            .unwrap()
            .add_net(&mut _net_cfg)
            .map_err(Error::DeviceManager)?;

        // Update VmConfig by adding the new device. This is important to
        // ensure the device would be created in case of a reboot.
        {
            let mut config = self.config.lock().unwrap();
            Self::add_to_config(&mut config.net, _net_cfg);
        }

        self.device_manager
            .lock()
            .unwrap()
            .notify_hotplug(AcpiNotificationFlags::PCI_DEVICES_CHANGED)
            .map_err(Error::DeviceManager)?;

        Ok(pci_device_info)
    }

    pub fn add_vsock(&mut self, mut _vsock_cfg: VsockConfig) -> Result<PciDeviceInfo> {
        if self.config.lock().unwrap().vsock.is_some() {
            return Err(Error::TooManyVsockDevices);
        }

        {
            // Validate on a clone of the config
            let mut config = self.config.lock().unwrap().clone();
            config.vsock = Some(_vsock_cfg.clone());
            config.validate().map_err(Error::ConfigValidation)?;
        }

        let pci_device_info = self
            .device_manager
            .lock()
            .unwrap()
            .add_vsock(&mut _vsock_cfg)
            .map_err(Error::DeviceManager)?;

        // Update VmConfig by adding the new device. This is important to
        // ensure the device would be created in case of a reboot.
        {
            let mut config = self.config.lock().unwrap();
            config.vsock = Some(_vsock_cfg);
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

    fn os_signal_handler(
        mut signals: Signals,
        console_input_clone: Arc<Console>,
        on_tty: bool,
        exit_evt: EventFd,
    ) {
        for signal in signals.forever() {
            match signal {
                SIGWINCH => {
                    let (col, row) = get_win_size();
                    console_input_clone.update_console_size(col, row);
                }
                SIGTERM | SIGINT => {
                    if on_tty {
                        io::stdin()
                            .lock()
                            .set_canon_mode()
                            .expect("failed to restore terminal mode");
                    }
                    if exit_evt.write(1).is_err() {
                        std::process::exit(1);
                    }
                }
                _ => (),
            }
        }
    }

    #[cfg(feature = "tdx")]
    fn init_tdx(&mut self) -> Result<()> {
        let cpuid = self.cpu_manager.lock().unwrap().common_cpuid();
        let max_vcpus = self.cpu_manager.lock().unwrap().max_vcpus() as u32;
        self.vm
            .tdx_init(&cpuid, max_vcpus)
            .map_err(Error::InitializeTdxVm)?;
        Ok(())
    }

    #[cfg(feature = "tdx")]
    fn extract_tdvf_sections(&mut self) -> Result<Vec<TdvfSection>> {
        use arch::x86_64::tdx::*;
        // The TDVF file contains a table of section as well as code
        let mut firmware_file =
            File::open(&self.config.lock().unwrap().tdx.as_ref().unwrap().firmware)
                .map_err(Error::LoadTdvf)?;

        // For all the sections allocate some RAM backing them
        parse_tdvf_sections(&mut firmware_file).map_err(Error::ParseTdvf)
    }

    #[cfg(feature = "tdx")]
    fn populate_tdx_sections(&mut self, sections: &[TdvfSection]) -> Result<Option<u64>> {
        use arch::x86_64::tdx::*;
        // Get the memory end *before* we start adding TDVF ram regions
        let mem_end = {
            let guest_memory = self.memory_manager.lock().as_ref().unwrap().guest_memory();
            let mem = guest_memory.memory();
            mem.last_addr()
        };
        for section in sections {
            info!("Allocating TDVF Section: {:?}", section);
            self.memory_manager
                .lock()
                .unwrap()
                .add_ram_region(GuestAddress(section.address), section.size as usize)
                .map_err(Error::AllocatingTdvfMemory)?;
        }

        // The TDVF file contains a table of section as well as code
        let mut firmware_file =
            File::open(&self.config.lock().unwrap().tdx.as_ref().unwrap().firmware)
                .map_err(Error::LoadTdvf)?;

        // The guest memory at this point now has all the required regions so it
        // is safe to copy from the TDVF file into it.
        let guest_memory = self.memory_manager.lock().as_ref().unwrap().guest_memory();
        let mem = guest_memory.memory();
        let mut hob_offset = None;
        for section in sections {
            info!("Populating TDVF Section: {:?}", section);
            match section.r#type {
                TdvfSectionType::Bfv | TdvfSectionType::Cfv => {
                    info!("Copying section to guest memory");
                    firmware_file
                        .seek(SeekFrom::Start(section.data_offset as u64))
                        .map_err(Error::LoadTdvf)?;
                    mem.read_from(
                        GuestAddress(section.address),
                        &mut firmware_file,
                        section.data_size as usize,
                    )
                    .unwrap();
                }
                TdvfSectionType::TdHob => {
                    hob_offset = Some(section.address);
                }
                _ => {}
            }
        }

        // Generate HOB
        let mut hob = TdHob::start(hob_offset.unwrap());

        // RAM regions (all below 3GiB case)
        if mem_end < arch::layout::MEM_32BIT_RESERVED_START {
            hob.add_memory_resource(&mem, 0, mem_end.0 + 1, true)
                .map_err(Error::PopulateHob)?;
        } else {
            // Otherwise split into two
            hob.add_memory_resource(&mem, 0, arch::layout::MEM_32BIT_RESERVED_START.0, true)
                .map_err(Error::PopulateHob)?;
            if mem_end > arch::layout::RAM_64BIT_START {
                hob.add_memory_resource(
                    &mem,
                    arch::layout::RAM_64BIT_START.raw_value(),
                    mem_end.unchecked_offset_from(arch::layout::RAM_64BIT_START) + 1,
                    true,
                )
                .map_err(Error::PopulateHob)?;
            }
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

    pub fn boot(&mut self) -> Result<()> {
        info!("Booting VM");
        event!("vm", "booting");
        let current_state = self.get_state()?;
        if current_state == VmState::Paused {
            return self.resume().map_err(Error::Resume);
        }

        let new_state = VmState::Running;
        current_state.valid_transition(new_state)?;

        // Load kernel if configured
        let entry_point = if self.kernel.as_ref().is_some() {
            Some(self.load_kernel()?)
        } else {
            None
        };

        // The initial TDX configuration must be done before the vCPUs are
        // created
        #[cfg(feature = "tdx")]
        if self.config.lock().unwrap().tdx.is_some() {
            self.init_tdx()?;
        }

        // Create and configure vcpus
        self.cpu_manager
            .lock()
            .unwrap()
            .create_boot_vcpus(entry_point)
            .map_err(Error::CpuManager)?;

        #[cfg(feature = "tdx")]
        let sections = self.extract_tdvf_sections()?;

        // Configuring the TDX regions requires that the vCPUs are created
        #[cfg(feature = "tdx")]
        let hob_address = if self.config.lock().unwrap().tdx.is_some() {
            self.populate_tdx_sections(&sections)?
        } else {
            None
        };

        // Configure shared state based on loaded kernel
        entry_point.map(|_| self.configure_system()).transpose()?;

        #[cfg(feature = "tdx")]
        if let Some(hob_address) = hob_address {
            // With the HOB address extracted the vCPUs can have
            // their TDX state configured.
            self.cpu_manager
                .lock()
                .unwrap()
                .initialize_tdx(hob_address)
                .map_err(Error::CpuManager)?;
            self.init_tdx_memory(&sections)?;
            // With TDX memory and CPU state configured TDX setup is complete
            self.vm.tdx_finalize().map_err(Error::FinalizeTdx)?;
        }

        self.cpu_manager
            .lock()
            .unwrap()
            .start_boot_vcpus()
            .map_err(Error::CpuManager)?;

        if self
            .device_manager
            .lock()
            .unwrap()
            .console()
            .input_enabled()
        {
            let console = self.device_manager.lock().unwrap().console().clone();
            let signals = Signals::new(&[SIGWINCH, SIGINT, SIGTERM]);
            match signals {
                Ok(signals) => {
                    self.signals = Some(signals.handle());
                    let exit_evt = self.exit_evt.try_clone().map_err(Error::EventFdClone)?;
                    let on_tty = self.on_tty;
                    let signal_handler_seccomp_filter =
                        get_seccomp_filter(&self.seccomp_action, Thread::SignalHandler)
                            .map_err(Error::CreateSeccompFilter)?;
                    self.threads.push(
                        thread::Builder::new()
                            .name("signal_handler".to_string())
                            .spawn(move || {
                                if let Err(e) = SeccompFilter::apply(signal_handler_seccomp_filter)
                                    .map_err(Error::ApplySeccompFilter)
                                {
                                    error!("Error applying seccomp filter: {:?}", e);
                                    return;
                                }

                                Vm::os_signal_handler(signals, console, on_tty, exit_evt);
                            })
                            .map_err(Error::SignalHandlerSpawn)?,
                    );
                }
                Err(e) => error!("Signal not found {}", e),
            }

            if self.on_tty {
                io::stdin()
                    .lock()
                    .set_raw_mode()
                    .map_err(Error::SetTerminalRaw)?;
            }
        }

        let mut state = self.state.try_write().map_err(|_| Error::PoisonedState)?;
        *state = new_state;
        event!("vm", "booted");
        Ok(())
    }

    pub fn handle_pty(&self) -> Result<()> {
        // Could be a little dangerous, picks up a lock on device_manager
        // and goes into a blocking read. If the epoll loops starts to be
        // services by multiple threads likely need to revist this.
        let dm = self.device_manager.lock().unwrap();
        let mut out = [0u8; 64];
        if let Some(mut pty) = dm.serial_pty() {
            let count = pty.main.read(&mut out).map_err(Error::PtyConsole)?;
            let console = dm.console();
            if console.input_enabled() {
                console
                    .queue_input_bytes_serial(&out[..count])
                    .map_err(Error::Console)?;
            }
        };
        let count = match dm.console_pty() {
            Some(mut pty) => pty.main.read(&mut out).map_err(Error::PtyConsole)?,
            None => return Ok(()),
        };
        let console = dm.console();
        if console.input_enabled() {
            console.queue_input_bytes_console(&out[..count])
        }

        Ok(())
    }

    pub fn handle_stdin(&self) -> Result<()> {
        let mut out = [0u8; 64];
        let count = io::stdin()
            .lock()
            .read_raw(&mut out)
            .map_err(Error::Console)?;

        // Replace "\n" with "\r" to deal with Windows SAC (#1170)
        if count == 1 && out[0] == 0x0a {
            out[0] = 0x0d;
        }

        if self
            .device_manager
            .lock()
            .unwrap()
            .console()
            .input_enabled()
        {
            self.device_manager
                .lock()
                .unwrap()
                .console()
                .queue_input_bytes(&out[..count])
                .map_err(Error::Console)?;
        }

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

    /// Load saved clock from snapshot
    #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
    pub fn load_clock_from_snapshot(
        &mut self,
        snapshot: &Snapshot,
    ) -> Result<Option<hypervisor::ClockData>> {
        let vm_snapshot = get_vm_snapshot(snapshot).map_err(Error::Restore)?;
        self.saved_clock = vm_snapshot.clock;
        Ok(self.saved_clock)
    }

    #[cfg(target_arch = "aarch64")]
    /// Add the vGIC section to the VM snapshot.
    fn add_vgic_snapshot_section(
        &self,
        vm_snapshot: &mut Snapshot,
    ) -> std::result::Result<(), MigratableError> {
        let saved_vcpu_states = self.cpu_manager.lock().unwrap().get_saved_states();
        let gic_device = Arc::clone(
            self.device_manager
                .lock()
                .unwrap()
                .get_interrupt_controller()
                .unwrap()
                .lock()
                .unwrap()
                .get_gic_device()
                .unwrap(),
        );

        gic_device
            .lock()
            .unwrap()
            .set_gicr_typers(&saved_vcpu_states);

        vm_snapshot.add_snapshot(
            gic_device
                .lock()
                .unwrap()
                .as_any_concrete_mut()
                .downcast_mut::<KvmGicV3>()
                .unwrap()
                .snapshot()?,
        );

        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    /// Restore the vGIC from the VM snapshot and enable the interrupt controller routing.
    fn restore_vgic_and_enable_interrupt(
        &self,
        vm_snapshot: &Snapshot,
    ) -> std::result::Result<(), MigratableError> {
        let saved_vcpu_states = self.cpu_manager.lock().unwrap().get_saved_states();
        // The number of vCPUs is the same as the number of saved vCPU states.
        let vcpu_numbers = saved_vcpu_states.len();

        // Creating a GIC device here, as the GIC will not be created when
        // restoring the device manager. Note that currently only the bare GICv3
        // without ITS is supported.
        let mut gic_device = create_gic(&self.vm, vcpu_numbers.try_into().unwrap())
            .map_err(|e| MigratableError::Restore(anyhow!("Could not create GIC: {:#?}", e)))?;

        // Here we prepare the GICR_TYPER registers from the restored vCPU states.
        gic_device.set_gicr_typers(&saved_vcpu_states);

        let gic_device = Arc::new(Mutex::new(gic_device));
        // Update the GIC entity in device manager
        self.device_manager
            .lock()
            .unwrap()
            .get_interrupt_controller()
            .unwrap()
            .lock()
            .unwrap()
            .set_gic_device(Arc::clone(&gic_device));

        // Restore GIC states.
        if let Some(gic_v3_snapshot) = vm_snapshot.snapshots.get(GIC_V3_SNAPSHOT_ID) {
            gic_device
                .lock()
                .unwrap()
                .as_any_concrete_mut()
                .downcast_mut::<KvmGicV3>()
                .unwrap()
                .restore(*gic_v3_snapshot.clone())?;
        } else {
            return Err(MigratableError::Restore(anyhow!("Missing GICv3 snapshot")));
        }

        // Activate gic device
        self.device_manager
            .lock()
            .unwrap()
            .get_interrupt_controller()
            .unwrap()
            .lock()
            .unwrap()
            .enable()
            .map_err(|e| {
                MigratableError::Restore(anyhow!(
                    "Could not enable interrupt controller routing: {:#?}",
                    e
                ))
            })?;

        Ok(())
    }

    /// Gets the actual size of the balloon.
    pub fn balloon_size(&self) -> u64 {
        self.device_manager.lock().unwrap().balloon_size()
    }

    pub fn receive_memory_regions<F>(
        &mut self,
        ranges: &MemoryRangeTable,
        fd: &mut F,
    ) -> std::result::Result<(), MigratableError>
    where
        F: Read,
    {
        let guest_memory = self.memory_manager.lock().as_ref().unwrap().guest_memory();
        let mem = guest_memory.memory();

        for range in ranges.regions() {
            mem.read_exact_from(GuestAddress(range.gpa), fd, range.length as usize)
                .map_err(|e| {
                    MigratableError::MigrateReceive(anyhow!(
                        "Error transferring memory to socket: {}",
                        e
                    ))
                })?;
        }
        Ok(())
    }

    pub fn send_memory_regions<F>(
        &mut self,
        ranges: &MemoryRangeTable,
        fd: &mut F,
    ) -> std::result::Result<(), MigratableError>
    where
        F: Write,
    {
        let guest_memory = self.memory_manager.lock().as_ref().unwrap().guest_memory();
        let mem = guest_memory.memory();

        for range in ranges.regions() {
            mem.write_all_to(GuestAddress(range.gpa), fd, range.length as usize)
                .map_err(|e| {
                    MigratableError::MigrateSend(anyhow!(
                        "Error transferring memory to socket: {}",
                        e
                    ))
                })?;
        }

        Ok(())
    }

    pub fn memory_range_table(&self) -> std::result::Result<MemoryRangeTable, MigratableError> {
        let mut table = MemoryRangeTable::default();
        let guest_memory = self.memory_manager.lock().as_ref().unwrap().guest_memory();

        guest_memory.memory().with_regions_mut(|_, region| {
            table.push(MemoryRange {
                gpa: region.start_addr().raw_value(),
                length: region.len() as u64,
            });
            Ok(())
        })?;

        Ok(table)
    }

    pub fn start_memory_dirty_log(&self) -> std::result::Result<(), MigratableError> {
        self.memory_manager.lock().unwrap().start_memory_dirty_log()
    }

    pub fn dirty_memory_range_table(
        &self,
    ) -> std::result::Result<MemoryRangeTable, MigratableError> {
        self.memory_manager
            .lock()
            .unwrap()
            .dirty_memory_range_table()
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
        #[cfg(feature = "acpi")]
        return self
            .device_manager
            .lock()
            .unwrap()
            .notify_power_button()
            .map_err(Error::PowerButton);
        #[cfg(not(feature = "acpi"))]
        Err(Error::PowerButtonNotSupported)
    }

    #[cfg(target_arch = "aarch64")]
    pub fn power_button(&self) -> Result<()> {
        self.device_manager
            .lock()
            .unwrap()
            .notify_power_button()
            .map_err(Error::PowerButton)
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
            // Reset clock flags.
            clock.flags = 0;
            self.saved_clock = Some(clock);
        }
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
    pub config: Arc<Mutex<VmConfig>>,
    #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
    pub clock: Option<hypervisor::ClockData>,
    pub state: Option<hypervisor::VmState>,
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
            if self.config.lock().unwrap().tdx.is_some() {
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

        let mut vm_snapshot = Snapshot::new(VM_SNAPSHOT_ID);
        let vm_state = self
            .vm
            .state()
            .map_err(|e| MigratableError::Snapshot(e.into()))?;
        let vm_snapshot_data = serde_json::to_vec(&VmSnapshot {
            config: self.get_config(),
            #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
            clock: self.saved_clock,
            state: Some(vm_state),
        })
        .map_err(|e| MigratableError::Snapshot(e.into()))?;

        vm_snapshot.add_snapshot(self.cpu_manager.lock().unwrap().snapshot()?);
        vm_snapshot.add_snapshot(self.memory_manager.lock().unwrap().snapshot()?);

        #[cfg(target_arch = "aarch64")]
        self.add_vgic_snapshot_section(&mut vm_snapshot)
            .map_err(|e| MigratableError::Snapshot(e.into()))?;

        vm_snapshot.add_snapshot(self.device_manager.lock().unwrap().snapshot()?);
        vm_snapshot.add_data_section(SnapshotDataSection {
            id: format!("{}-section", VM_SNAPSHOT_ID),
            snapshot: vm_snapshot_data,
        });

        event!("vm", "snapshotted");
        Ok(vm_snapshot)
    }

    fn restore(&mut self, snapshot: Snapshot) -> std::result::Result<(), MigratableError> {
        event!("vm", "restoring");

        let current_state = self
            .get_state()
            .map_err(|e| MigratableError::Restore(anyhow!("Could not get VM state: {:#?}", e)))?;
        let new_state = VmState::Paused;
        current_state.valid_transition(new_state).map_err(|e| {
            MigratableError::Restore(anyhow!("Could not restore VM state: {:#?}", e))
        })?;

        if let Some(memory_manager_snapshot) = snapshot.snapshots.get(MEMORY_MANAGER_SNAPSHOT_ID) {
            self.memory_manager
                .lock()
                .unwrap()
                .restore(*memory_manager_snapshot.clone())?;
        } else {
            return Err(MigratableError::Restore(anyhow!(
                "Missing memory manager snapshot"
            )));
        }

        if let Some(cpu_manager_snapshot) = snapshot.snapshots.get(CPU_MANAGER_SNAPSHOT_ID) {
            self.cpu_manager
                .lock()
                .unwrap()
                .restore(*cpu_manager_snapshot.clone())?;
        } else {
            return Err(MigratableError::Restore(anyhow!(
                "Missing CPU manager snapshot"
            )));
        }

        if let Some(device_manager_snapshot) = snapshot.snapshots.get(DEVICE_MANAGER_SNAPSHOT_ID) {
            self.device_manager
                .lock()
                .unwrap()
                .restore(*device_manager_snapshot.clone())?;
        } else {
            return Err(MigratableError::Restore(anyhow!(
                "Missing device manager snapshot"
            )));
        }

        #[cfg(target_arch = "aarch64")]
        self.restore_vgic_and_enable_interrupt(&snapshot)?;

        // Now we can start all vCPUs from here.
        self.cpu_manager
            .lock()
            .unwrap()
            .start_restored_vcpus()
            .map_err(|e| {
                MigratableError::Restore(anyhow!("Cannot start restored vCPUs: {:#?}", e))
            })?;

        if self
            .device_manager
            .lock()
            .unwrap()
            .console()
            .input_enabled()
        {
            let console = self.device_manager.lock().unwrap().console().clone();
            let signals = Signals::new(&[SIGWINCH, SIGINT, SIGTERM]);
            match signals {
                Ok(signals) => {
                    self.signals = Some(signals.handle());

                    let on_tty = self.on_tty;
                    let signal_handler_seccomp_filter =
                        get_seccomp_filter(&self.seccomp_action, Thread::SignalHandler).map_err(
                            |e| {
                                MigratableError::Restore(anyhow!(
                                    "Could not create seccomp filter: {:#?}",
                                    Error::CreateSeccompFilter(e)
                                ))
                            },
                        )?;
                    let exit_evt = self.exit_evt.try_clone().map_err(|e| {
                        MigratableError::Restore(anyhow!("Could not clone exit event fd: {:?}", e))
                    })?;

                    self.threads.push(
                        thread::Builder::new()
                            .name("signal_handler".to_string())
                            .spawn(move || {
                                if let Err(e) = SeccompFilter::apply(signal_handler_seccomp_filter)
                                    .map_err(Error::ApplySeccompFilter)
                                {
                                    error!("Error applying seccomp filter: {:?}", e);
                                    return;
                                }

                                Vm::os_signal_handler(signals, console, on_tty, exit_evt)
                            })
                            .map_err(|e| {
                                MigratableError::Restore(anyhow!(
                                    "Could not start console signal thread: {:#?}",
                                    e
                                ))
                            })?,
                    );
                }
                Err(e) => error!("Signal not found {}", e),
            }

            if self.on_tty {
                io::stdin().lock().set_raw_mode().map_err(|e| {
                    MigratableError::Restore(anyhow!(
                        "Could not set terminal in raw mode: {:#?}",
                        e
                    ))
                })?;
            }
        }

        let mut state = self
            .state
            .try_write()
            .map_err(|e| MigratableError::Restore(anyhow!("Could not set VM state: {:#?}", e)))?;
        *state = new_state;

        event!("vm", "restored");
        Ok(())
    }
}

impl Transportable for Vm {
    fn send(
        &self,
        snapshot: &Snapshot,
        destination_url: &str,
    ) -> std::result::Result<(), MigratableError> {
        let mut vm_snapshot_path = url_to_path(destination_url)?;
        vm_snapshot_path.push(VM_SNAPSHOT_FILE);

        // Create the snapshot file
        let mut vm_snapshot_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(vm_snapshot_path)
            .map_err(|e| MigratableError::MigrateSend(e.into()))?;

        // Serialize and write the snapshot
        let vm_snapshot =
            serde_json::to_vec(snapshot).map_err(|e| MigratableError::MigrateSend(e.into()))?;

        vm_snapshot_file
            .write(&vm_snapshot)
            .map_err(|e| MigratableError::MigrateSend(e.into()))?;

        // Tell the memory manager to also send/write its own snapshot.
        if let Some(memory_manager_snapshot) = snapshot.snapshots.get(MEMORY_MANAGER_SNAPSHOT_ID) {
            self.memory_manager
                .lock()
                .unwrap()
                .send(&*memory_manager_snapshot.clone(), destination_url)?;
        } else {
            return Err(MigratableError::Restore(anyhow!(
                "Missing memory manager snapshot"
            )));
        }

        Ok(())
    }
}
impl Migratable for Vm {}

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
                assert!(state.valid_transition(VmState::Shutdown).is_err());
                assert!(state.valid_transition(VmState::Paused).is_ok());
            }
            VmState::Running => {
                // Check the transitions from Running
                assert!(state.valid_transition(VmState::Created).is_err());
                assert!(state.valid_transition(VmState::Running).is_err());
                assert!(state.valid_transition(VmState::Shutdown).is_ok());
                assert!(state.valid_transition(VmState::Paused).is_ok());
            }
            VmState::Shutdown => {
                // Check the transitions from Shutdown
                assert!(state.valid_transition(VmState::Created).is_err());
                assert!(state.valid_transition(VmState::Running).is_ok());
                assert!(state.valid_transition(VmState::Shutdown).is_err());
                assert!(state.valid_transition(VmState::Paused).is_err());
            }
            VmState::Paused => {
                // Check the transitions from Paused
                assert!(state.valid_transition(VmState::Created).is_err());
                assert!(state.valid_transition(VmState::Running).is_ok());
                assert!(state.valid_transition(VmState::Shutdown).is_ok());
                assert!(state.valid_transition(VmState::Paused).is_err());
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
}

#[cfg(target_arch = "aarch64")]
#[cfg(test)]
mod tests {
    use super::*;
    use arch::aarch64::fdt::create_fdt;
    use arch::aarch64::gic::kvm::create_gic;
    use arch::aarch64::{layout, DeviceInfoForFdt};
    use arch::{DeviceType, MmioDeviceInfo};
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    const LEN: u64 = 4096;

    #[test]
    fn test_create_fdt_with_devices() {
        let mut regions = Vec::new();
        regions.push((
            GuestAddress(layout::RAM_64BIT_START),
            (layout::FDT_MAX_SIZE + 0x1000) as usize,
        ));
        let mem = GuestMemoryMmap::from_ranges(&regions).expect("Cannot initialize memory");

        let dev_info: HashMap<(DeviceType, std::string::String), MmioDeviceInfo> = [
            (
                (DeviceType::Serial, DeviceType::Serial.to_string()),
                MmioDeviceInfo {
                    addr: 0x00,
                    irq: 33,
                },
            ),
            (
                (DeviceType::Virtio(1), "virtio".to_string()),
                MmioDeviceInfo {
                    addr: 0x00 + LEN,
                    irq: 34,
                },
            ),
            (
                (DeviceType::Rtc, "rtc".to_string()),
                MmioDeviceInfo {
                    addr: 0x00 + 2 * LEN,
                    irq: 35,
                },
            ),
        ]
        .iter()
        .cloned()
        .collect();

        let hv = hypervisor::new().unwrap();
        let vm = hv.create_vm().unwrap();
        let gic = create_gic(&vm, 1).unwrap();
        assert!(create_fdt(
            &mem,
            &CString::new("console=tty0").unwrap(),
            vec![0],
            &dev_info,
            &*gic,
            &None,
            &(0x1_0000_0000, 0x1_0000),
        )
        .is_ok())
    }
}

#[cfg(all(feature = "kvm", target_arch = "x86_64"))]
#[test]
pub fn test_vm() {
    use hypervisor::VmExit;
    use vm_memory::{GuestMemory, GuestMemoryRegion};
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

    mem.with_regions(|index, region| {
        let mem_region = vm.make_user_memory_region(
            index as u32,
            region.start_addr().raw_value(),
            region.len() as u64,
            region.as_ptr() as u64,
            false,
            false,
        );

        vm.set_user_memory_region(mem_region)
    })
    .expect("Cannot configure guest memory");
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
                    str::from_utf8(&data).unwrap()
                );
            }
            VmExit::Reset => {
                println!("HLT");
                break;
            }
            r => panic!("unexpected exit reason: {:?}", r),
        }
    }
}
