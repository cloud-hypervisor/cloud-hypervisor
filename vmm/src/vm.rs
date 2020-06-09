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

extern crate arch;
extern crate devices;
extern crate epoll;
extern crate kvm_ioctls;
extern crate libc;
extern crate linux_loader;
extern crate net_util;
extern crate signal_hook;
#[cfg(feature = "pci_support")]
extern crate vm_allocator;
extern crate vm_memory;
extern crate vm_virtio;

use crate::config::{
    DeviceConfig, DiskConfig, FsConfig, HotplugMethod, NetConfig, PmemConfig, ValidationError,
    VmConfig, VsockConfig,
};
use crate::cpu;
use crate::device_manager::{self, get_win_size, Console, DeviceManager, DeviceManagerError};
use crate::memory_manager::{Error as MemoryManagerError, MemoryManager};
use crate::migration::{url_to_path, vm_config_from_snapshot, VM_SNAPSHOT_FILE};
use crate::{CPU_MANAGER_SNAPSHOT_ID, DEVICE_MANAGER_SNAPSHOT_ID, MEMORY_MANAGER_SNAPSHOT_ID};
use anyhow::anyhow;
#[cfg(target_arch = "x86_64")]
use arch::BootProtocol;
use arch::{check_required_kvm_extensions, EntryPoint};
#[cfg(target_arch = "x86_64")]
use devices::ioapic;
use devices::HotPlugNotificationFlags;
#[cfg(target_arch = "x86_64")]
use kvm_bindings::{kvm_enable_cap, kvm_userspace_memory_region, KVM_CAP_SPLIT_IRQCHIP};
use kvm_ioctls::*;
use linux_loader::cmdline::Cmdline;
#[cfg(target_arch = "x86_64")]
use linux_loader::loader::elf::Error::InvalidElfMagicNumber;
use linux_loader::loader::KernelLoader;
use signal_hook::{iterator::Signals, SIGINT, SIGTERM, SIGWINCH};
#[cfg(target_arch = "x86_64")]
use std::convert::TryInto;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
#[cfg(target_arch = "x86_64")]
use std::io::{Seek, SeekFrom};
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::{result, str, thread};
use url::Url;
#[cfg(target_arch = "x86_64")]
use vm_memory::{Address, Bytes, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};
use vm_memory::{GuestAddress, GuestAddressSpace};
use vm_migration::{
    Migratable, MigratableError, Pausable, Snapshot, SnapshotDataSection, Snapshottable,
    Transportable,
};
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::terminal::Terminal;

// 64 bit direct boot entry offset for bzImage
#[cfg(target_arch = "x86_64")]
const KERNEL_64BIT_ENTRY_OFFSET: u64 = 0x200;

/// Errors associated with VM management
#[derive(Debug)]
pub enum Error {
    /// Cannot open the VM file descriptor.
    VmFd(io::Error),

    /// Cannot create the KVM instance
    VmCreate(kvm_ioctls::Error),

    /// Cannot set the VM up
    VmSetup(kvm_ioctls::Error),

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
    EnableInterruptController(device_manager::DeviceManagerError),

    PoisonedState,

    /// Cannot create a device manager.
    DeviceManager(DeviceManagerError),

    /// Write to the console failed.
    Console(vmm_sys_util::errno::Error),

    /// Cannot setup terminal in raw mode.
    SetTerminalRaw(vmm_sys_util::errno::Error),

    /// Cannot setup terminal in canonical mode.
    SetTerminalCanon(vmm_sys_util::errno::Error),

    /// Failed parsing network parameters
    ParseNetworkParameters,

    /// Memory is overflow
    MemOverflow,

    /// Failed to allocate the IOAPIC memory range.
    IoapicRangeAllocation,

    /// Cannot spawn a signal handler thread
    SignalHandlerSpawn(io::Error),

    /// Failed to join on vCPU threads
    ThreadCleanup(std::boxed::Box<dyn std::any::Any + std::marker::Send>),

    /// Failed to create a new KVM instance
    KvmNew(kvm_ioctls::Error),

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

    /// No PCI support
    NoPciSupport,

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
}
pub type Result<T> = result::Result<T, Error>;

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
                VmState::Created | VmState::Shutdown | VmState::Paused => {
                    Err(Error::InvalidStateTransition(self, new_state))
                }
                VmState::Running => Ok(()),
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

pub struct Vm {
    kernel: File,
    #[cfg_attr(target_arch = "aarch64", allow(dead_code))]
    initramfs: Option<File>,
    threads: Vec<thread::JoinHandle<()>>,
    device_manager: Arc<Mutex<DeviceManager>>,
    config: Arc<Mutex<VmConfig>>,
    on_tty: bool,
    signals: Option<Signals>,
    state: RwLock<VmState>,
    cpu_manager: Arc<Mutex<cpu::CpuManager>>,
    memory_manager: Arc<Mutex<MemoryManager>>,
}

impl Vm {
    fn kvm_new() -> Result<(Kvm, Arc<VmFd>)> {
        let kvm = Kvm::new().map_err(Error::KvmNew)?;

        check_required_kvm_extensions(&kvm).expect("Missing KVM capabilities");

        let fd: VmFd;
        loop {
            match kvm.create_vm() {
                Ok(res) => fd = res,
                Err(e) => {
                    if e.errno() == libc::EINTR {
                        // If the error returned is EINTR, which means the
                        // ioctl has been interrupted, we have to retry as
                        // this can't be considered as a regular error.
                        continue;
                    } else {
                        return Err(Error::VmCreate(e));
                    }
                }
            }
            break;
        }
        let fd = Arc::new(fd);

        // Set TSS
        #[cfg(target_arch = "x86_64")]
        fd.set_tss_address(arch::x86_64::layout::KVM_TSS_ADDRESS.raw_value() as usize)
            .map_err(Error::VmSetup)?;

        #[cfg(target_arch = "x86_64")]
        {
            // Create split irqchip
            // Only the local APIC is emulated in kernel, both PICs and IOAPIC
            // are not.
            let mut cap: kvm_enable_cap = Default::default();
            cap.cap = KVM_CAP_SPLIT_IRQCHIP;
            cap.args[0] = ioapic::NUM_IOAPIC_PINS as u64;
            fd.enable_cap(&cap).map_err(Error::VmSetup)?;
        }

        Ok((kvm, fd))
    }

    fn new_from_memory_manager(
        config: Arc<Mutex<VmConfig>>,
        memory_manager: Arc<Mutex<MemoryManager>>,
        fd: Arc<VmFd>,
        kvm: Kvm,
        exit_evt: EventFd,
        reset_evt: EventFd,
        vmm_path: PathBuf,
    ) -> Result<Self> {
        config
            .lock()
            .unwrap()
            .validate()
            .map_err(Error::ConfigValidation)?;

        let device_manager = DeviceManager::new(
            fd.clone(),
            config.clone(),
            memory_manager.clone(),
            &exit_evt,
            &reset_evt,
            vmm_path,
        )
        .map_err(Error::DeviceManager)?;

        let cpu_manager = cpu::CpuManager::new(
            &config.lock().unwrap().cpus.clone(),
            &device_manager,
            memory_manager.lock().unwrap().guest_memory(),
            &kvm,
            fd,
            reset_evt,
        )
        .map_err(Error::CpuManager)?;

        let on_tty = unsafe { libc::isatty(libc::STDIN_FILENO as i32) } != 0;
        let kernel = File::open(&config.lock().unwrap().kernel.as_ref().unwrap().path)
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
        })
    }

    pub fn new(
        config: Arc<Mutex<VmConfig>>,
        exit_evt: EventFd,
        reset_evt: EventFd,
        vmm_path: PathBuf,
    ) -> Result<Self> {
        let (kvm, fd) = Vm::kvm_new()?;
        let memory_manager = MemoryManager::new(
            fd.clone(),
            &config.lock().unwrap().memory.clone(),
            None,
            false,
        )
        .map_err(Error::MemoryManager)?;

        let vm = Vm::new_from_memory_manager(
            config,
            memory_manager,
            fd,
            kvm,
            exit_evt,
            reset_evt,
            vmm_path,
        )?;

        // The device manager must create the devices from here as it is part
        // of the regular code path creating everything from scratch.
        vm.device_manager
            .lock()
            .unwrap()
            .create_devices()
            .map_err(Error::DeviceManager)?;

        Ok(vm)
    }

    pub fn new_from_snapshot(
        snapshot: &Snapshot,
        exit_evt: EventFd,
        reset_evt: EventFd,
        vmm_path: PathBuf,
        source_url: &str,
        prefault: bool,
    ) -> Result<Self> {
        let (kvm, fd) = Vm::kvm_new()?;
        let config = vm_config_from_snapshot(snapshot).map_err(Error::Restore)?;

        let memory_manager = if let Some(memory_manager_snapshot) =
            snapshot.snapshots.get(MEMORY_MANAGER_SNAPSHOT_ID)
        {
            MemoryManager::new_from_snapshot(
                memory_manager_snapshot,
                fd.clone(),
                &config.lock().unwrap().memory.clone(),
                source_url,
                prefault,
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
            fd,
            kvm,
            exit_evt,
            reset_evt,
            vmm_path,
        )
    }

    #[cfg(target_arch = "x86_64")]
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
        Ok(CString::new(cmdline).map_err(Error::CmdLineCString)?)
    }

    #[cfg(target_arch = "aarch64")]
    fn load_kernel(&mut self) -> Result<EntryPoint> {
        let guest_memory = self.memory_manager.lock().as_ref().unwrap().guest_memory();
        let mem = guest_memory.memory();
        let entry_addr = match linux_loader::loader::pe::PE::load(
            mem.deref(),
            Some(GuestAddress(arch::get_kernel_start())),
            &mut self.kernel,
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
        let cmdline_cstring = self.get_cmdline()?;
        let guest_memory = self.memory_manager.lock().as_ref().unwrap().guest_memory();
        let mem = guest_memory.memory();
        let entry_addr = match linux_loader::loader::elf::Elf::load(
            mem.deref(),
            None,
            &mut self.kernel,
            Some(arch::layout::HIGH_RAM_START),
        ) {
            Ok(entry_addr) => entry_addr,
            Err(linux_loader::loader::Error::Elf(InvalidElfMagicNumber)) => {
                linux_loader::loader::bzimage::BzImage::load(
                    mem.deref(),
                    None,
                    &mut self.kernel,
                    Some(arch::layout::HIGH_RAM_START),
                )
                .map_err(Error::KernelLoad)?
            }
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

        if entry_addr.setup_header.is_some() {
            let load_addr = entry_addr
                .kernel_load
                .raw_value()
                .checked_add(KERNEL_64BIT_ENTRY_OFFSET)
                .ok_or(Error::MemOverflow)?;

            Ok(EntryPoint {
                entry_addr: GuestAddress(load_addr),
                protocol: BootProtocol::LinuxBoot,
                setup_header: entry_addr.setup_header,
            })
        } else {
            let entry_point_addr: GuestAddress;
            let boot_prot: BootProtocol;

            if let Some(pvh_entry_addr) = entry_addr.pvh_entry_addr {
                // Use the PVH kernel entry point to boot the guest
                entry_point_addr = pvh_entry_addr;
                boot_prot = BootProtocol::PvhBoot;
            } else {
                // Use the Linux 64-bit boot protocol
                entry_point_addr = entry_addr.kernel_load;
                boot_prot = BootProtocol::LinuxBoot;
            }

            Ok(EntryPoint {
                entry_addr: entry_point_addr,
                protocol: boot_prot,
                setup_header: None,
            })
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn configure_system(&mut self, entry_addr: EntryPoint) -> Result<()> {
        let cmdline_cstring = self.get_cmdline()?;
        let guest_memory = self.memory_manager.lock().as_ref().unwrap().guest_memory();
        let mem = guest_memory.memory();

        let initramfs_config = match self.initramfs {
            Some(_) => Some(self.load_initramfs(mem.deref())?),
            None => None,
        };

        let boot_vcpus = self.cpu_manager.lock().unwrap().boot_vcpus();

        #[allow(unused_mut, unused_assignments)]
        let mut rsdp_addr: Option<GuestAddress> = None;

        #[cfg(feature = "acpi")]
        {
            rsdp_addr = Some(crate::acpi::create_acpi_tables(
                mem.deref(),
                &self.device_manager,
                &self.cpu_manager,
                &self.memory_manager,
            ));
        }

        match entry_addr.setup_header {
            Some(hdr) => {
                arch::configure_system(
                    &mem,
                    arch::layout::CMDLINE_START,
                    cmdline_cstring.to_bytes().len() + 1,
                    &initramfs_config,
                    boot_vcpus,
                    Some(hdr),
                    rsdp_addr,
                    BootProtocol::LinuxBoot,
                )
                .map_err(Error::ConfigureSystem)?;
            }
            None => {
                arch::configure_system(
                    &mem,
                    arch::layout::CMDLINE_START,
                    cmdline_cstring.to_bytes().len() + 1,
                    &initramfs_config,
                    boot_vcpus,
                    None,
                    rsdp_addr,
                    entry_addr.protocol,
                )
                .map_err(Error::ConfigureSystem)?;
            }
        }
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn configure_system(&mut self, _entry_addr: EntryPoint) -> Result<()> {
        let cmdline_cstring = self.get_cmdline()?;
        let vcpu_mpidrs = self.cpu_manager.lock().unwrap().get_mpidrs();
        let guest_memory = self.memory_manager.lock().as_ref().unwrap().guest_memory();
        let mem = guest_memory.memory();

        let device_info = &self
            .device_manager
            .lock()
            .unwrap()
            .get_device_info()
            .clone();

        arch::configure_system(
            &self.memory_manager.lock().as_ref().unwrap().fd,
            &mem,
            &cmdline_cstring,
            self.cpu_manager.lock().unwrap().boot_vcpus() as u64,
            vcpu_mpidrs,
            device_info,
            &None,
        )
        .map_err(Error::ConfigureSystem)?;

        self.device_manager
            .lock()
            .unwrap()
            .enable_interrupt_controller()
            .map_err(Error::EnableInterruptController)?;

        Ok(())
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

        Ok(())
    }

    pub fn resize(&mut self, desired_vcpus: Option<u8>, desired_memory: Option<u64>) -> Result<()> {
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
                    .notify_hotplug(HotPlugNotificationFlags::CPU_DEVICES_CHANGED)
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

            if let Some(new_region) = &new_region {
                self.device_manager
                    .lock()
                    .unwrap()
                    .update_memory(&new_region)
                    .map_err(Error::DeviceManager)?;

                let memory_config = &self.config.lock().unwrap().memory;
                match memory_config.hotplug_method {
                    HotplugMethod::Acpi => {
                        self.device_manager
                            .lock()
                            .unwrap()
                            .notify_hotplug(HotPlugNotificationFlags::MEMORY_DEVICES_CHANGED)
                            .map_err(Error::DeviceManager)?;
                    }
                    HotplugMethod::VirtioMem => {}
                }
            }

            // We update the VM config regardless of the actual guest resize
            // operation result (happened or not), so that if the VM reboots
            // it will be running with the last configure memory size.
            self.config.lock().unwrap().memory.size = desired_memory;
        }
        Ok(())
    }

    pub fn add_device(&mut self, mut _device_cfg: DeviceConfig) -> Result<()> {
        if cfg!(feature = "pci_support") {
            #[cfg(feature = "pci_support")]
            {
                self.device_manager
                    .lock()
                    .unwrap()
                    .add_device(&mut _device_cfg)
                    .map_err(Error::DeviceManager)?;

                // Update VmConfig by adding the new device. This is important to
                // ensure the device would be created in case of a reboot.
                {
                    let mut config = self.config.lock().unwrap();
                    if let Some(devices) = config.devices.as_mut() {
                        devices.push(_device_cfg);
                    } else {
                        config.devices = Some(vec![_device_cfg]);
                    }
                }

                self.device_manager
                    .lock()
                    .unwrap()
                    .notify_hotplug(HotPlugNotificationFlags::PCI_DEVICES_CHANGED)
                    .map_err(Error::DeviceManager)?;
            }
            Ok(())
        } else {
            Err(Error::NoPciSupport)
        }
    }

    pub fn remove_device(&mut self, _id: String) -> Result<()> {
        if cfg!(feature = "pci_support") {
            #[cfg(feature = "pci_support")]
            {
                self.device_manager
                    .lock()
                    .unwrap()
                    .remove_device(_id.clone())
                    .map_err(Error::DeviceManager)?;

                // Update VmConfig by removing the device. This is important to
                // ensure the device would not be created in case of a reboot.
                {
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
                }

                self.device_manager
                    .lock()
                    .unwrap()
                    .notify_hotplug(HotPlugNotificationFlags::PCI_DEVICES_CHANGED)
                    .map_err(Error::DeviceManager)?;
            }
            Ok(())
        } else {
            Err(Error::NoPciSupport)
        }
    }

    pub fn add_disk(&mut self, mut _disk_cfg: DiskConfig) -> Result<()> {
        if cfg!(feature = "pci_support") {
            #[cfg(feature = "pci_support")]
            {
                self.device_manager
                    .lock()
                    .unwrap()
                    .add_disk(&mut _disk_cfg)
                    .map_err(Error::DeviceManager)?;

                // Update VmConfig by adding the new device. This is important to
                // ensure the device would be created in case of a reboot.
                {
                    let mut config = self.config.lock().unwrap();
                    if let Some(disks) = config.disks.as_mut() {
                        disks.push(_disk_cfg);
                    } else {
                        config.disks = Some(vec![_disk_cfg]);
                    }
                }

                self.device_manager
                    .lock()
                    .unwrap()
                    .notify_hotplug(HotPlugNotificationFlags::PCI_DEVICES_CHANGED)
                    .map_err(Error::DeviceManager)?;
            }
            Ok(())
        } else {
            Err(Error::NoPciSupport)
        }
    }

    pub fn add_fs(&mut self, mut _fs_cfg: FsConfig) -> Result<()> {
        if cfg!(feature = "pci_support") {
            #[cfg(feature = "pci_support")]
            {
                self.device_manager
                    .lock()
                    .unwrap()
                    .add_fs(&mut _fs_cfg)
                    .map_err(Error::DeviceManager)?;

                // Update VmConfig by adding the new device. This is important to
                // ensure the device would be created in case of a reboot.
                {
                    let mut config = self.config.lock().unwrap();
                    if let Some(fs_config) = config.fs.as_mut() {
                        fs_config.push(_fs_cfg);
                    } else {
                        config.fs = Some(vec![_fs_cfg]);
                    }
                }

                self.device_manager
                    .lock()
                    .unwrap()
                    .notify_hotplug(HotPlugNotificationFlags::PCI_DEVICES_CHANGED)
                    .map_err(Error::DeviceManager)?;
            }
            Ok(())
        } else {
            Err(Error::NoPciSupport)
        }
    }

    pub fn add_pmem(&mut self, mut _pmem_cfg: PmemConfig) -> Result<()> {
        if cfg!(feature = "pci_support") {
            #[cfg(feature = "pci_support")]
            {
                self.device_manager
                    .lock()
                    .unwrap()
                    .add_pmem(&mut _pmem_cfg)
                    .map_err(Error::DeviceManager)?;

                // Update VmConfig by adding the new device. This is important to
                // ensure the device would be created in case of a reboot.
                {
                    let mut config = self.config.lock().unwrap();
                    if let Some(pmem) = config.pmem.as_mut() {
                        pmem.push(_pmem_cfg);
                    } else {
                        config.pmem = Some(vec![_pmem_cfg]);
                    }
                }

                self.device_manager
                    .lock()
                    .unwrap()
                    .notify_hotplug(HotPlugNotificationFlags::PCI_DEVICES_CHANGED)
                    .map_err(Error::DeviceManager)?;
            }
            Ok(())
        } else {
            Err(Error::NoPciSupport)
        }
    }

    pub fn add_net(&mut self, mut _net_cfg: NetConfig) -> Result<()> {
        if cfg!(feature = "pci_support") {
            #[cfg(feature = "pci_support")]
            {
                self.device_manager
                    .lock()
                    .unwrap()
                    .add_net(&mut _net_cfg)
                    .map_err(Error::DeviceManager)?;

                // Update VmConfig by adding the new device. This is important to
                // ensure the device would be created in case of a reboot.
                {
                    let mut config = self.config.lock().unwrap();
                    if let Some(net) = config.net.as_mut() {
                        net.push(_net_cfg);
                    } else {
                        config.net = Some(vec![_net_cfg]);
                    }
                }

                self.device_manager
                    .lock()
                    .unwrap()
                    .notify_hotplug(HotPlugNotificationFlags::PCI_DEVICES_CHANGED)
                    .map_err(Error::DeviceManager)?;
            }
            Ok(())
        } else {
            Err(Error::NoPciSupport)
        }
    }

    pub fn add_vsock(&mut self, mut _vsock_cfg: VsockConfig) -> Result<()> {
        if cfg!(feature = "pci_support") {
            #[cfg(feature = "pci_support")]
            {
                if self.config.lock().unwrap().vsock.is_some() {
                    return Err(Error::TooManyVsockDevices);
                }

                self.device_manager
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
                    .notify_hotplug(HotPlugNotificationFlags::PCI_DEVICES_CHANGED)
                    .map_err(Error::DeviceManager)?;
            }
            Ok(())
        } else {
            Err(Error::NoPciSupport)
        }
    }

    fn os_signal_handler(signals: Signals, console_input_clone: Arc<Console>, on_tty: bool) {
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
                    std::process::exit((signal != SIGTERM) as i32);
                }
                _ => (),
            }
        }
    }

    pub fn boot(&mut self) -> Result<()> {
        let current_state = self.get_state()?;
        if current_state == VmState::Paused {
            return self.resume().map_err(Error::Resume);
        }

        let new_state = VmState::Running;
        current_state.valid_transition(new_state)?;

        let entry_point = self.load_kernel()?;

        // create and configure vcpus
        self.cpu_manager
            .lock()
            .unwrap()
            .create_boot_vcpus(entry_point)
            .map_err(Error::CpuManager)?;

        self.configure_system(entry_point)?;

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
                    self.signals = Some(signals.clone());

                    let on_tty = self.on_tty;
                    self.threads.push(
                        thread::Builder::new()
                            .name("signal_handler".to_string())
                            .spawn(move || Vm::os_signal_handler(signals, console, on_tty))
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

        Ok(())
    }

    pub fn handle_stdin(&self) -> Result<()> {
        let mut out = [0u8; 64];
        let count = io::stdin()
            .lock()
            .read_raw(&mut out)
            .map_err(Error::Console)?;

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
}

impl Pausable for Vm {
    fn pause(&mut self) -> std::result::Result<(), MigratableError> {
        let mut state = self
            .state
            .try_write()
            .map_err(|e| MigratableError::Pause(anyhow!("Could not get VM state: {}", e)))?;
        let new_state = VmState::Paused;

        state
            .valid_transition(new_state)
            .map_err(|e| MigratableError::Pause(anyhow!("Invalid transition: {:?}", e)))?;

        self.cpu_manager.lock().unwrap().pause()?;
        self.device_manager.lock().unwrap().pause()?;

        *state = new_state;

        Ok(())
    }

    fn resume(&mut self) -> std::result::Result<(), MigratableError> {
        let mut state = self
            .state
            .try_write()
            .map_err(|e| MigratableError::Resume(anyhow!("Could not get VM state: {}", e)))?;
        let new_state = VmState::Running;

        state
            .valid_transition(new_state)
            .map_err(|e| MigratableError::Pause(anyhow!("Invalid transition: {:?}", e)))?;

        self.device_manager.lock().unwrap().resume()?;
        self.cpu_manager.lock().unwrap().resume()?;

        // And we're back to the Running state.
        *state = new_state;

        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct VmSnapshot {
    pub config: Arc<Mutex<VmConfig>>,
}

pub const VM_SNAPSHOT_ID: &str = "vm";
impl Snapshottable for Vm {
    fn id(&self) -> String {
        VM_SNAPSHOT_ID.to_string()
    }

    fn snapshot(&self) -> std::result::Result<Snapshot, MigratableError> {
        let current_state = self.get_state().unwrap();
        if current_state != VmState::Paused {
            return Err(MigratableError::Snapshot(anyhow!(
                "Trying to snapshot while VM is running"
            )));
        }

        let mut vm_snapshot = Snapshot::new(VM_SNAPSHOT_ID);
        let vm_snapshot_data = serde_json::to_vec(&VmSnapshot {
            config: self.get_config(),
        })
        .map_err(|e| MigratableError::Snapshot(e.into()))?;

        vm_snapshot.add_snapshot(self.cpu_manager.lock().unwrap().snapshot()?);
        vm_snapshot.add_snapshot(self.memory_manager.lock().unwrap().snapshot()?);
        vm_snapshot.add_snapshot(self.device_manager.lock().unwrap().snapshot()?);
        vm_snapshot.add_data_section(SnapshotDataSection {
            id: format!("{}-section", VM_SNAPSHOT_ID),
            snapshot: vm_snapshot_data,
        });

        Ok(vm_snapshot)
    }

    fn restore(&mut self, snapshot: Snapshot) -> std::result::Result<(), MigratableError> {
        let current_state = self
            .get_state()
            .map_err(|e| MigratableError::Restore(anyhow!("Could not get VM state: {:#?}", e)))?;
        let new_state = VmState::Running;
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
                    self.signals = Some(signals.clone());

                    let on_tty = self.on_tty;
                    self.threads.push(
                        thread::Builder::new()
                            .name("signal_handler".to_string())
                            .spawn(move || Vm::os_signal_handler(signals, console, on_tty))
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
        Ok(())
    }
}

impl Transportable for Vm {
    fn send(
        &self,
        snapshot: &Snapshot,
        destination_url: &str,
    ) -> std::result::Result<(), MigratableError> {
        let url = Url::parse(destination_url).map_err(|e| {
            MigratableError::MigrateSend(anyhow!("Could not parse destination URL: {}", e))
        })?;

        match url.scheme() {
            "file" => {
                let mut vm_snapshot_path = url_to_path(&url)?;
                vm_snapshot_path.push(VM_SNAPSHOT_FILE);

                // Create the snapshot file
                let mut vm_snapshot_file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(vm_snapshot_path)
                    .map_err(|e| MigratableError::MigrateSend(e.into()))?;

                // Serialize and write the snapshot
                let vm_snapshot = serde_json::to_vec(snapshot)
                    .map_err(|e| MigratableError::MigrateSend(e.into()))?;

                vm_snapshot_file
                    .write(&vm_snapshot)
                    .map_err(|e| MigratableError::MigrateSend(e.into()))?;

                // Tell the memory manager to also send/write its own snapshot.
                if let Some(memory_manager_snapshot) =
                    snapshot.snapshots.get(MEMORY_MANAGER_SNAPSHOT_ID)
                {
                    self.memory_manager
                        .lock()
                        .unwrap()
                        .send(&*memory_manager_snapshot.clone(), destination_url)?;
                } else {
                    return Err(MigratableError::Restore(anyhow!(
                        "Missing memory manager snapshot"
                    )));
                }
            }
            _ => {
                return Err(MigratableError::MigrateSend(anyhow!(
                    "Unsupported VM transport URL scheme: {}",
                    url.scheme()
                )))
            }
        }
        Ok(())
    }
}
impl Migratable for Vm {}

#[cfg(target_arch = "x86_64")]
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
                assert!(state.valid_transition(VmState::Paused).is_err());
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

#[cfg(target_arch = "x86_64")]
#[allow(unused)]
pub fn test_vm() {
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

    let kvm = Kvm::new().expect("new KVM instance creation failed");
    let vm_fd = kvm.create_vm().expect("new VM fd creation failed");

    mem.with_regions(|index, region| {
        let mem_region = kvm_userspace_memory_region {
            slot: index as u32,
            guest_phys_addr: region.start_addr().raw_value(),
            memory_size: region.len() as u64,
            userspace_addr: region.as_ptr() as u64,
            flags: 0,
        };

        // Safe because the guest regions are guaranteed not to overlap.
        unsafe { vm_fd.set_user_memory_region(mem_region) }
    })
    .expect("Cannot configure guest memory");
    mem.write_slice(&code, load_addr)
        .expect("Writing code to memory failed");

    let vcpu_fd = vm_fd.create_vcpu(0).expect("new VcpuFd failed");

    let mut vcpu_sregs = vcpu_fd.get_sregs().expect("get sregs failed");
    vcpu_sregs.cs.base = 0;
    vcpu_sregs.cs.selector = 0;
    vcpu_fd.set_sregs(&vcpu_sregs).expect("set sregs failed");

    let mut vcpu_regs = vcpu_fd.get_regs().expect("get regs failed");
    vcpu_regs.rip = 0x1000;
    vcpu_regs.rax = 2;
    vcpu_regs.rbx = 3;
    vcpu_regs.rflags = 2;
    vcpu_fd.set_regs(&vcpu_regs).expect("set regs failed");

    loop {
        match vcpu_fd.run().expect("run failed") {
            VcpuExit::IoIn(addr, data) => {
                println!(
                    "IO in -- addr: {:#x} data [{:?}]",
                    addr,
                    str::from_utf8(&data).unwrap()
                );
            }
            VcpuExit::IoOut(addr, data) => {
                println!(
                    "IO out -- addr: {:#x} data [{:?}]",
                    addr,
                    str::from_utf8(&data).unwrap()
                );
            }
            VcpuExit::MmioRead(_addr, _data) => {}
            VcpuExit::MmioWrite(_addr, _data) => {}
            VcpuExit::Unknown => {}
            VcpuExit::Exception => {}
            VcpuExit::Hypercall => {}
            VcpuExit::Debug => {}
            VcpuExit::Hlt => {
                println!("HLT");
            }
            VcpuExit::IrqWindowOpen => {}
            VcpuExit::Shutdown => {}
            VcpuExit::FailEntry => {}
            VcpuExit::Intr => {}
            VcpuExit::SetTpr => {}
            VcpuExit::TprAccess => {}
            VcpuExit::S390Sieic => {}
            VcpuExit::S390Reset => {}
            VcpuExit::Dcr => {}
            VcpuExit::Nmi => {}
            VcpuExit::InternalError => {}
            VcpuExit::Osi => {}
            VcpuExit::PaprHcall => {}
            VcpuExit::S390Ucontrol => {}
            VcpuExit::Watchdog => {}
            VcpuExit::S390Tsch => {}
            VcpuExit::Epr => {}
            VcpuExit::SystemEvent(_, _) => {}
            VcpuExit::S390Stsi => {}
            VcpuExit::IoapicEoi(_vector) => {}
            VcpuExit::Hyperv => {}
        }
        //        r => panic!("unexpected exit reason: {:?}", r),
    }
}
