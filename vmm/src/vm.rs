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

extern crate anyhow;
extern crate arch;
extern crate devices;
extern crate epoll;
extern crate kvm_ioctls;
extern crate libc;
extern crate linux_loader;
extern crate net_util;
extern crate signal_hook;
#[cfg(feature = "pci_support")]
extern crate vfio;
extern crate vm_allocator;
extern crate vm_memory;
extern crate vm_virtio;

use crate::config::VmConfig;
use crate::cpu;
use crate::device_manager::{get_win_size, Console, DeviceManager, DeviceManagerError};
use crate::memory_manager::{get_host_cpu_phys_bits, Error as MemoryManagerError, MemoryManager};
use anyhow::anyhow;
use arc_swap::ArcSwap;
use arch::layout;
use devices::{ioapic, HotPlugNotificationType};
use kvm_bindings::{kvm_enable_cap, kvm_userspace_memory_region, KVM_CAP_SPLIT_IRQCHIP};
use kvm_ioctls::*;
use linux_loader::cmdline::Cmdline;
use linux_loader::loader::KernelLoader;
use signal_hook::{iterator::Signals, SIGINT, SIGTERM, SIGWINCH};
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::sync::{Arc, Mutex, RwLock};
use std::{result, str, thread};
use vm_allocator::{GsiApic, SystemAllocator};
use vm_device::{Migratable, MigratableError, Pausable, Snapshotable};
use vm_memory::{
    Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion, GuestUsize,
};
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::terminal::Terminal;

const X86_64_IRQ_BASE: u32 = 5;

// CPUID feature bits
const TSC_DEADLINE_TIMER_ECX_BIT: u8 = 24; // tsc deadline timer ecx bit.
const HYPERVISOR_ECX_BIT: u8 = 31; // Hypervisor ecx bit.

// 64 bit direct boot entry offset for bzImage
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

    /// Cannot load the kernel in memory
    KernelLoad(linux_loader::loader::Error),

    /// Cannot load the command line in memory
    CmdLine,

    PoisonedState,

    /// Cannot create a device manager.
    DeviceManager(DeviceManagerError),

    /// Write to the console failed.
    Console(vmm_sys_util::errno::Error),

    /// Cannot setup terminal in raw mode.
    SetTerminalRaw(vmm_sys_util::errno::Error),

    /// Cannot setup terminal in canonical mode.
    SetTerminalCanon(vmm_sys_util::errno::Error),

    /// Cannot create the system allocator
    CreateSystemAllocator,

    /// Failed parsing network parameters
    ParseNetworkParameters,

    /// Memory is overflow
    MemOverflow,

    /// Failed to allocate the IOAPIC memory range.
    IoapicRangeAllocation,

    /// Cannot spawn a signal handler thread
    SignalHandlerSpawn(io::Error),

    /// Failed to join on vCPU threads
    ThreadCleanup,

    /// Failed to create a new KVM instance
    KvmNew(kvm_ioctls::Error),

    /// VM is not created
    VmNotCreated,

    /// VM is not running
    VmNotRunning,

    /// Cannot clone EventFd.
    EventFdClone(io::Error),

    /// Invalid VM state transition
    InvalidStateTransition(VmState, VmState),

    /// Error from CPU handling
    CpuManager(cpu::Error),

    /// Capability missing
    CapabilityMissing(Cap),

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
}
pub type Result<T> = result::Result<T, Error>;

pub struct VmInfo<'a> {
    pub memory: &'a Arc<ArcSwap<GuestMemoryMmap>>,
    pub vm_fd: &'a Arc<VmFd>,
    pub vm_cfg: Arc<Mutex<VmConfig>>,
}

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
    threads: Vec<thread::JoinHandle<()>>,
    devices: DeviceManager,
    config: Arc<Mutex<VmConfig>>,
    on_tty: bool,
    signals: Option<Signals>,
    state: RwLock<VmState>,
    cpu_manager: Arc<Mutex<cpu::CpuManager>>,
    memory_manager: Arc<Mutex<MemoryManager>>,
}

impl Vm {
    pub fn new(
        config: Arc<Mutex<VmConfig>>,
        exit_evt: EventFd,
        reset_evt: EventFd,
    ) -> Result<Self> {
        let kvm = Kvm::new().map_err(Error::KvmNew)?;

        // Check required capabilities:
        if !kvm.check_extension(Cap::SignalMsi) {
            return Err(Error::CapabilityMissing(Cap::SignalMsi));
        }

        if !kvm.check_extension(Cap::TscDeadlineTimer) {
            return Err(Error::CapabilityMissing(Cap::TscDeadlineTimer));
        }

        if !kvm.check_extension(Cap::SplitIrqchip) {
            return Err(Error::CapabilityMissing(Cap::SplitIrqchip));
        }

        let kernel = File::open(&config.lock().unwrap().kernel.as_ref().unwrap().path)
            .map_err(Error::KernelFile)?;
        let fd = kvm.create_vm().map_err(Error::VmCreate)?;
        let fd = Arc::new(fd);

        // Set TSS
        fd.set_tss_address(arch::x86_64::layout::KVM_TSS_ADDRESS.raw_value() as usize)
            .map_err(Error::VmSetup)?;

        let mut cpuid_patches = Vec::new();
        // Create split irqchip
        // Only the local APIC is emulated in kernel, both PICs and IOAPIC
        // are not.
        let mut cap: kvm_enable_cap = Default::default();
        cap.cap = KVM_CAP_SPLIT_IRQCHIP;
        cap.args[0] = ioapic::NUM_IOAPIC_PINS as u64;
        fd.enable_cap(&cap).map_err(Error::VmSetup)?;

        // Patch tsc deadline timer bit
        cpuid_patches.push(cpu::CpuidPatch {
            function: 1,
            index: 0,
            flags_bit: None,
            eax_bit: None,
            ebx_bit: None,
            ecx_bit: Some(TSC_DEADLINE_TIMER_ECX_BIT),
            edx_bit: None,
        });

        // Patch hypervisor bit
        cpuid_patches.push(cpu::CpuidPatch {
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
            .map_err(Error::VmSetup)?;

        cpu::CpuidPatch::patch_cpuid(&mut cpuid, cpuid_patches);

        let ioapic = GsiApic::new(
            X86_64_IRQ_BASE,
            ioapic::NUM_IOAPIC_PINS as u32 - X86_64_IRQ_BASE,
        );

        // Let's allocate 64 GiB of addressable MMIO space, starting at 0.
        let allocator = Arc::new(Mutex::new(
            SystemAllocator::new(
                GuestAddress(0),
                1 << 16 as GuestUsize,
                GuestAddress(0),
                1 << get_host_cpu_phys_bits(),
                layout::MEM_32BIT_RESERVED_START,
                layout::MEM_32BIT_DEVICES_SIZE,
                vec![ioapic],
            )
            .ok_or(Error::CreateSystemAllocator)?,
        ));

        let memory_config = config.lock().unwrap().memory.clone();

        let memory_manager = MemoryManager::new(
            allocator.clone(),
            fd.clone(),
            memory_config.size,
            memory_config.hotplug_size,
            &memory_config.file,
            memory_config.mergeable,
        )
        .map_err(Error::MemoryManager)?;

        let guest_memory = memory_manager.lock().unwrap().guest_memory();
        let vm_info = VmInfo {
            memory: &guest_memory,
            vm_fd: &fd,
            vm_cfg: config.clone(),
        };

        let device_manager = DeviceManager::new(
            &vm_info,
            allocator,
            memory_manager.clone(),
            &exit_evt,
            &reset_evt,
        )
        .map_err(Error::DeviceManager)?;

        let on_tty = unsafe { libc::isatty(libc::STDIN_FILENO as i32) } != 0;

        let boot_vcpus = config.lock().unwrap().cpus.boot_vcpus;
        let max_vcpus = config.lock().unwrap().cpus.max_vcpus;
        let cpu_manager = cpu::CpuManager::new(
            boot_vcpus,
            max_vcpus,
            &device_manager,
            guest_memory.clone(),
            fd,
            cpuid,
            reset_evt,
        )
        .map_err(Error::CpuManager)?;

        Ok(Vm {
            kernel,
            devices: device_manager,
            config,
            on_tty,
            threads: Vec::with_capacity(1),
            signals: None,
            state: RwLock::new(VmState::Created),
            cpu_manager,
            memory_manager,
        })
    }

    fn load_kernel(&mut self) -> Result<GuestAddress> {
        let mut cmdline = Cmdline::new(arch::CMDLINE_MAX_SIZE);
        cmdline
            .insert_str(self.config.lock().unwrap().cmdline.args.clone())
            .map_err(|_| Error::CmdLine)?;
        for entry in self.devices.cmdline_additions() {
            cmdline.insert_str(entry).map_err(|_| Error::CmdLine)?;
        }

        let cmdline_cstring = CString::new(cmdline).map_err(|_| Error::CmdLine)?;
        let guest_memory = self.memory_manager.lock().as_ref().unwrap().guest_memory();
        let mem = guest_memory.load_full();
        let entry_addr = match linux_loader::loader::Elf::load(
            mem.as_ref(),
            None,
            &mut self.kernel,
            Some(arch::layout::HIGH_RAM_START),
        ) {
            Ok(entry_addr) => entry_addr,
            Err(linux_loader::loader::Error::InvalidElfMagicNumber) => {
                linux_loader::loader::BzImage::load(
                    mem.as_ref(),
                    None,
                    &mut self.kernel,
                    Some(arch::layout::HIGH_RAM_START),
                )
                .map_err(Error::KernelLoad)?
            }
            _ => panic!("Invalid elf file"),
        };

        linux_loader::loader::load_cmdline(
            mem.as_ref(),
            arch::layout::CMDLINE_START,
            &cmdline_cstring,
        )
        .map_err(|_| Error::CmdLine)?;
        let boot_vcpus = self.cpu_manager.lock().unwrap().boot_vcpus();
        let _max_vcpus = self.cpu_manager.lock().unwrap().max_vcpus();

        #[allow(unused_mut, unused_assignments)]
        let mut rsdp_addr: Option<GuestAddress> = None;

        #[cfg(feature = "acpi")]
        {
            rsdp_addr = Some(crate::acpi::create_acpi_tables(
                &mem,
                &self.devices,
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
                    boot_vcpus,
                    Some(hdr),
                    rsdp_addr,
                )
                .map_err(|_| Error::CmdLine)?;

                let load_addr = entry_addr
                    .kernel_load
                    .raw_value()
                    .checked_add(KERNEL_64BIT_ENTRY_OFFSET)
                    .ok_or(Error::MemOverflow)?;

                Ok(GuestAddress(load_addr))
            }
            None => {
                arch::configure_system(
                    &mem,
                    arch::layout::CMDLINE_START,
                    cmdline_cstring.to_bytes().len() + 1,
                    boot_vcpus,
                    None,
                    rsdp_addr,
                )
                .map_err(|_| Error::CmdLine)?;

                Ok(entry_addr.kernel_load)
            }
        }
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

        self.cpu_manager
            .lock()
            .unwrap()
            .shutdown()
            .map_err(Error::CpuManager)?;

        // Wait for all the threads to finish
        for thread in self.threads.drain(..) {
            thread.join().map_err(|_| Error::ThreadCleanup)?
        }
        *state = new_state;

        Ok(())
    }

    pub fn resize(&mut self, desired_vcpus: Option<u8>, desired_memory: Option<u64>) -> Result<()> {
        if let Some(desired_vcpus) = desired_vcpus {
            self.cpu_manager
                .lock()
                .unwrap()
                .resize(desired_vcpus)
                .map_err(Error::CpuManager)?;
            self.devices
                .notify_hotplug(HotPlugNotificationType::CPUDevicesChanged)
                .map_err(Error::DeviceManager)?;
            self.config.lock().unwrap().cpus.boot_vcpus = desired_vcpus;
        }

        if let Some(desired_memory) = desired_memory {
            self.config.lock().unwrap().memory.size = desired_memory;
        }
        Ok(())
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

        let entry_addr = self.load_kernel()?;

        self.cpu_manager
            .lock()
            .unwrap()
            .start_boot_vcpus(entry_addr)
            .map_err(Error::CpuManager)?;

        if self.devices.console().input_enabled() {
            let console = self.devices.console().clone();
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

        if self.devices.console().input_enabled() {
            self.devices
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
        self.devices.pause()?;

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

        self.devices.resume()?;
        self.cpu_manager.lock().unwrap().resume()?;

        // And we're back to the Running state.
        *state = new_state;

        Ok(())
    }
}

impl Snapshotable for Vm {}
impl Migratable for Vm {}

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
            _ => {}
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
    let mem = GuestMemoryMmap::new(&[(load_addr, mem_size)]).unwrap();

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
            VcpuExit::SystemEvent => {}
            VcpuExit::S390Stsi => {}
            VcpuExit::IoapicEoi(_vector) => {}
            VcpuExit::Hyperv => {}
        }
        //        r => panic!("unexpected exit reason: {:?}", r),
    }
}
