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
extern crate vfio;
extern crate vm_allocator;
extern crate vm_memory;
extern crate vm_virtio;

use crate::config::VmConfig;
use crate::device_manager::{get_win_size, Console, DeviceManager, DeviceManagerError};
use arch::RegionType;
use devices::ioapic;
use kvm_bindings::{
    kvm_enable_cap, kvm_pit_config, kvm_userspace_memory_region, KVM_CAP_SPLIT_IRQCHIP,
    KVM_PIT_SPEAKER_DUMMY,
};
use kvm_ioctls::*;
use libc::{c_void, siginfo_t};
use linux_loader::cmdline::Cmdline;
use linux_loader::loader::KernelLoader;
use signal_hook::{iterator::Signals, SIGWINCH};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io;
use std::ops::Deref;
use std::os::unix::io::FromRawFd;
use std::os::unix::thread::JoinHandleExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex, RwLock};
use std::{fmt, result, str, thread};
use vm_allocator::{GsiApic, SystemAllocator};
use vm_memory::guest_memory::FileOffset;
use vm_memory::{
    Address, Bytes, Error as MmapError, GuestAddress, GuestMemory, GuestMemoryMmap,
    GuestMemoryRegion, GuestUsize,
};
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::signal::{register_signal_handler, validate_signal_num};
use vmm_sys_util::terminal::Terminal;

const VCPU_RTSIG_OFFSET: i32 = 0;
const X86_64_IRQ_BASE: u32 = 5;

// CPUID feature bits
const TSC_DEADLINE_TIMER_ECX_BIT: u8 = 24; // tsc deadline timer ecx bit.
const HYPERVISOR_ECX_BIT: u8 = 31; // Hypervisor ecx bit.

// 64 bit direct boot entry offset for bzImage
const KERNEL_64BIT_ENTRY_OFFSET: u64 = 0x200;

// Debug I/O port
#[cfg(target_arch = "x86_64")]
const DEBUG_IOPORT: u16 = 0x80;
const DEBUG_IOPORT_PREFIX: &str = "Debug I/O port";

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

/// Errors associated with VM management
#[derive(Debug)]
pub enum Error {
    /// Cannot open the VM file descriptor.
    VmFd(io::Error),

    /// Cannot create the KVM instance
    VmCreate(io::Error),

    /// Cannot set the VM up
    VmSetup(io::Error),

    /// Cannot open the kernel image
    KernelFile(io::Error),

    /// Mmap backed guest memory error
    GuestMemory(MmapError),

    /// Cannot load the kernel in memory
    KernelLoad(linux_loader::loader::Error),

    /// Cannot load the command line in memory
    CmdLine,

    /// Cannot open the VCPU file descriptor.
    VcpuFd(io::Error),

    /// Cannot run the VCPUs.
    VcpuRun(io::Error),

    /// Cannot spawn a new vCPU thread.
    VcpuSpawn(io::Error),

    #[cfg(target_arch = "x86_64")]
    /// Cannot set the local interruption due to bad configuration.
    LocalIntConfiguration(arch::x86_64::interrupts::Error),

    #[cfg(target_arch = "x86_64")]
    /// Error configuring the MSR registers
    MSRSConfiguration(arch::x86_64::regs::Error),

    PoisonedState,

    #[cfg(target_arch = "x86_64")]
    /// Error configuring the general purpose registers
    REGSConfiguration(arch::x86_64::regs::Error),

    #[cfg(target_arch = "x86_64")]
    /// Error configuring the special registers
    SREGSConfiguration(arch::x86_64::regs::Error),

    #[cfg(target_arch = "x86_64")]
    /// Error configuring the floating point related registers
    FPUConfiguration(arch::x86_64::regs::Error),

    /// The call to KVM_SET_CPUID2 failed.
    SetSupportedCpusFailed(io::Error),

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

    /// Unexpected KVM_RUN exit reason
    VcpuUnhandledKvmExit,

    /// Memory is overflow
    MemOverflow,

    /// Failed to create shared file.
    SharedFileCreate(io::Error),

    /// Failed to set shared file length.
    SharedFileSetLen(io::Error),

    /// Failed to allocate a memory range.
    MemoryRangeAllocation,

    /// Failed to allocate the IOAPIC memory range.
    IoapicRangeAllocation,

    /// Cannot spawn a signal handler thread
    SignalHandlerSpawn(io::Error),

    /// Failed to join on vCPU threads
    ThreadCleanup,

    /// Failed to create a new KVM instance
    KvmNew(io::Error),

    /// VM is not created
    VmNotCreated,

    /// VM is not running
    VmNotRunning,

    /// Cannot clone EventFd.
    EventFdClone(io::Error),

    /// Invalid VM state transition
    InvalidStateTransition(VmState, VmState),
}
pub type Result<T> = result::Result<T, Error>;

#[allow(dead_code)]
#[derive(Copy, Clone)]
enum CpuidReg {
    EAX,
    EBX,
    ECX,
    EDX,
}

struct CpuidPatch {
    function: u32,
    index: u32,
    flags_bit: Option<u8>,
    eax_bit: Option<u8>,
    ebx_bit: Option<u8>,
    ecx_bit: Option<u8>,
    edx_bit: Option<u8>,
}

impl CpuidPatch {
    fn set_cpuid_reg(
        cpuid: &mut CpuId,
        function: u32,
        index: Option<u32>,
        reg: CpuidReg,
        value: u32,
    ) {
        let entries = cpuid.as_mut_slice();

        for entry in entries.iter_mut() {
            if entry.function == function && (index == None || index.unwrap() == entry.index) {
                match reg {
                    CpuidReg::EAX => {
                        entry.eax = value;
                    }
                    CpuidReg::EBX => {
                        entry.ebx = value;
                    }
                    CpuidReg::ECX => {
                        entry.ecx = value;
                    }
                    CpuidReg::EDX => {
                        entry.edx = value;
                    }
                }
            }
        }
    }

    fn patch_cpuid(cpuid: &mut CpuId, patches: Vec<CpuidPatch>) {
        let entries = cpuid.as_mut_slice();

        for entry in entries.iter_mut() {
            for patch in patches.iter() {
                if entry.function == patch.function && entry.index == patch.index {
                    if let Some(flags_bit) = patch.flags_bit {
                        entry.flags |= 1 << flags_bit;
                    }
                    if let Some(eax_bit) = patch.eax_bit {
                        entry.eax |= 1 << eax_bit;
                    }
                    if let Some(ebx_bit) = patch.ebx_bit {
                        entry.ebx |= 1 << ebx_bit;
                    }
                    if let Some(ecx_bit) = patch.ecx_bit {
                        entry.ecx |= 1 << ecx_bit;
                    }
                    if let Some(edx_bit) = patch.edx_bit {
                        entry.edx |= 1 << edx_bit;
                    }
                }
            }
        }
    }
}

/// A wrapper around creating and using a kvm-based VCPU.
pub struct Vcpu {
    fd: VcpuFd,
    id: u8,
    io_bus: Arc<devices::Bus>,
    mmio_bus: Arc<devices::Bus>,
    ioapic: Option<Arc<Mutex<ioapic::Ioapic>>>,
    vm_ts: std::time::Instant,
}

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
        io_bus: Arc<devices::Bus>,
        mmio_bus: Arc<devices::Bus>,
        ioapic: Option<Arc<Mutex<ioapic::Ioapic>>>,
        creation_ts: std::time::Instant,
    ) -> Result<Self> {
        let kvm_vcpu = fd.create_vcpu(id).map_err(Error::VcpuFd)?;
        // Initially the cpuid per vCPU is the one supported by this VM.
        Ok(Vcpu {
            fd: kvm_vcpu,
            id,
            io_bus,
            mmio_bus,
            ioapic,
            vm_ts: creation_ts,
        })
    }

    /// Configures a x86_64 specific vcpu and should be called once per vcpu from the vcpu's thread.
    ///
    /// # Arguments
    ///
    /// * `machine_config` - Specifies necessary info used for the CPUID configuration.
    /// * `kernel_start_addr` - Offset from `guest_mem` at which the kernel starts.
    /// * `vm` - The virtual machine this vcpu will get attached to.
    pub fn configure(
        &mut self,
        kernel_start_addr: GuestAddress,
        vm_memory: &Arc<RwLock<GuestMemoryMmap>>,
        cpuid: CpuId,
    ) -> Result<()> {
        let mut cpuid = cpuid;
        CpuidPatch::set_cpuid_reg(&mut cpuid, 0xb, None, CpuidReg::EDX, u32::from(self.id));
        self.fd
            .set_cpuid2(&cpuid)
            .map_err(Error::SetSupportedCpusFailed)?;

        arch::x86_64::regs::setup_msrs(&self.fd).map_err(Error::MSRSConfiguration)?;
        // Safe to unwrap because this method is called after the VM is configured
        arch::x86_64::regs::setup_regs(
            &self.fd,
            kernel_start_addr.raw_value(),
            arch::x86_64::layout::BOOT_STACK_POINTER.raw_value(),
            arch::x86_64::layout::ZERO_PAGE_START.raw_value(),
        )
        .map_err(Error::REGSConfiguration)?;
        arch::x86_64::regs::setup_fpu(&self.fd).map_err(Error::FPUConfiguration)?;
        arch::x86_64::regs::setup_sregs(&vm_memory.read().unwrap(), &self.fd)
            .map_err(Error::SREGSConfiguration)?;
        arch::x86_64::interrupts::set_lint(&self.fd).map_err(Error::LocalIntConfiguration)?;
        Ok(())
    }

    /// Runs the VCPU until it exits, returning the reason.
    ///
    /// Note that the state of the VCPU and associated VM must be setup first for this to do
    /// anything useful.
    pub fn run(&self) -> Result<bool> {
        match self.fd.run() {
            Ok(run) => match run {
                VcpuExit::IoIn(addr, data) => {
                    self.io_bus.read(u64::from(addr), data);
                    Ok(true)
                }
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
                VcpuExit::IoapicEoi(vector) => {
                    if let Some(ioapic) = &self.ioapic {
                        ioapic.lock().unwrap().end_of_interrupt(vector);
                    }
                    Ok(true)
                }
                VcpuExit::Shutdown => {
                    // Triple fault to trigger a reboot
                    Ok(false)
                }
                r => {
                    error!("Unexpected exit reason on vcpu run: {:?}", r);
                    Err(Error::VcpuUnhandledKvmExit)
                }
            },

            Err(ref e) => match e.raw_os_error().unwrap() {
                libc::EAGAIN | libc::EINTR => Ok(true),
                _ => {
                    error!("VCPU {:?} error {:?}", self.id, e);
                    Err(Error::VcpuUnhandledKvmExit)
                }
            },
        }
    }

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
}

pub struct VmInfo<'a> {
    pub memory: &'a Arc<RwLock<GuestMemoryMmap>>,
    pub vm_fd: &'a Arc<VmFd>,
    pub vm_cfg: &'a VmConfig,
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

pub struct CpuManager {
    boot_vcpus: u8,
    io_bus: Arc<devices::Bus>,
    mmio_bus: Arc<devices::Bus>,
    ioapic: Option<Arc<Mutex<ioapic::Ioapic>>>,
    vm_memory: Arc<RwLock<GuestMemoryMmap>>,
    cpuid: CpuId,
    fd: Arc<VmFd>,
    vcpus_kill_signalled: Arc<AtomicBool>,
    vcpus_pause_signalled: Arc<AtomicBool>,
    reset_evt: EventFd,
    threads: Vec<thread::JoinHandle<()>>,
}

impl CpuManager {
    fn new(
        boot_vcpus: u8,
        device_manager: &DeviceManager,
        guest_memory: Arc<RwLock<GuestMemoryMmap>>,
        fd: Arc<VmFd>,
        cpuid: CpuId,
        reset_evt: EventFd,
    ) -> CpuManager {
        CpuManager {
            boot_vcpus,
            io_bus: device_manager.io_bus().clone(),
            mmio_bus: device_manager.mmio_bus().clone(),
            ioapic: device_manager.ioapic().clone(),
            vm_memory: guest_memory,
            cpuid,
            fd,
            vcpus_kill_signalled: Arc::new(AtomicBool::new(false)),
            vcpus_pause_signalled: Arc::new(AtomicBool::new(false)),
            threads: Vec::with_capacity(boot_vcpus as usize),
            reset_evt,
        }
    }

    // Starts all the vCPUs that the VM is booting with. Blocks until all vCPUs are running.
    fn start_boot_vcpus(&mut self, entry_addr: GuestAddress) -> Result<()> {
        let creation_ts = std::time::Instant::now();

        let vcpu_thread_barrier = Arc::new(Barrier::new((self.boot_vcpus + 1) as usize));

        for cpu_id in 0..self.boot_vcpus {
            let ioapic = if let Some(ioapic) = &self.ioapic {
                Some(ioapic.clone())
            } else {
                None
            };

            let mut vcpu = Vcpu::new(
                cpu_id,
                &self.fd,
                self.io_bus.clone(),
                self.mmio_bus.clone(),
                ioapic,
                creation_ts,
            )?;
            vcpu.configure(entry_addr, &self.vm_memory, self.cpuid.clone())?;

            let vcpu_thread_barrier = vcpu_thread_barrier.clone();

            let reset_evt = self.reset_evt.try_clone().unwrap();
            let vcpu_kill_signalled = self.vcpus_kill_signalled.clone();
            let vcpu_pause_signalled = self.vcpus_pause_signalled.clone();
            self.threads.push(
                thread::Builder::new()
                    .name(format!("vcpu{}", vcpu.id))
                    .spawn(move || {
                        unsafe {
                            extern "C" fn handle_signal(_: i32, _: *mut siginfo_t, _: *mut c_void) {
                            }
                            // This uses an async signal safe handler to kill the vcpu handles.
                            register_signal_handler(
                                VCPU_RTSIG_OFFSET,
                                vmm_sys_util::signal::SignalHandler::Siginfo(handle_signal),
                                true,
                                0,
                            )
                            .expect("Failed to register vcpu signal handler");
                        }

                        // Block until all CPUs are ready.
                        vcpu_thread_barrier.wait();

                        loop {
                            // vcpu.run() returns false on a KVM_EXIT_SHUTDOWN (triple-fault) so trigger a reset
                            match vcpu.run() {
                                Err(e) => {
                                    error!("VCPU generated error: {:?}", e);
                                    break;
                                }
                                Ok(true) => {}
                                Ok(false) => {
                                    reset_evt.write(1).unwrap();
                                    break;
                                }
                            }

                            // We've been told to terminate
                            if vcpu_kill_signalled.load(Ordering::SeqCst) {
                                break;
                            }

                            // If we are being told to pause, we park the thread
                            // until the pause boolean is toggled.
                            // The resume operation is responsible for toggling
                            // the boolean and unpark the thread.
                            // We enter a loop because park() could spuriously
                            // return. We will then park() again unless the
                            // pause boolean has been toggled.
                            while vcpu_pause_signalled.load(Ordering::SeqCst) {
                                thread::park();
                            }
                        }
                    })
                    .map_err(Error::VcpuSpawn)?,
            );
        }

        // Unblock all CPU threads.
        vcpu_thread_barrier.wait();
        Ok(())
    }

    fn shutdown(&mut self) -> Result<()> {
        // Tell the vCPUs to stop themselves next time they go through the loop
        self.vcpus_kill_signalled.store(true, Ordering::SeqCst);

        // Signal to the spawned threads (vCPUs and console signal handler). For the vCPU threads
        // this will interrupt the KVM_RUN ioctl() allowing the loop to check the boolean set
        // above.
        for thread in self.threads.iter() {
            let signum = validate_signal_num(VCPU_RTSIG_OFFSET, true).unwrap();
            unsafe {
                libc::pthread_kill(thread.as_pthread_t(), signum);
            }
        }

        // Wait for all the threads to finish
        for thread in self.threads.drain(..) {
            thread.join().map_err(|_| Error::ThreadCleanup)?
        }

        Ok(())
    }

    fn pause(&self) -> Result<()> {
        // Tell the vCPUs to pause themselves next time they exit
        self.vcpus_pause_signalled.store(true, Ordering::SeqCst);

        // Signal to the spawned threads (vCPUs and console signal handler). For the vCPU threads
        // this will interrupt the KVM_RUN ioctl() allowing the loop to check the boolean set
        // above.
        for thread in self.threads.iter() {
            let signum = validate_signal_num(VCPU_RTSIG_OFFSET, true).unwrap();
            unsafe {
                libc::pthread_kill(thread.as_pthread_t(), signum);
            }
        }

        Ok(())
    }

    fn resume(&self) -> Result<()> {
        // Toggle the vCPUs pause boolean
        self.vcpus_pause_signalled.store(false, Ordering::SeqCst);

        // Unpark all the VCPU threads.
        // Once unparked, the next thing they will do is checking for the pause
        // boolean. Since it'll be set to false, they will exit their pause loop
        // and go back to vmx root.
        for vcpu_thread in self.threads.iter() {
            vcpu_thread.thread().unpark();
        }
        Ok(())
    }
}

pub struct Vm {
    kernel: File,
    memory: Arc<RwLock<GuestMemoryMmap>>,
    threads: Vec<thread::JoinHandle<()>>,
    devices: DeviceManager,
    config: Arc<VmConfig>,
    on_tty: bool,
    signals: Option<Signals>,
    state: RwLock<VmState>,
    cpu_manager: CpuManager,
}

fn get_host_cpu_phys_bits() -> u8 {
    use core::arch::x86_64;
    unsafe {
        let leaf = x86_64::__cpuid(0x8000_0000);

        if leaf.eax >= 0x8000_0008 {
            let leaf = x86_64::__cpuid(0x8000_0008);
            (leaf.eax & 0xff) as u8
        } else {
            36
        }
    }
}

impl Vm {
    pub fn new(config: Arc<VmConfig>, exit_evt: EventFd, reset_evt: EventFd) -> Result<Self> {
        let kvm = Kvm::new().map_err(Error::KvmNew)?;
        let kernel =
            File::open(&config.kernel.as_ref().unwrap().path).map_err(Error::KernelFile)?;
        let fd = kvm.create_vm().map_err(Error::VmCreate)?;
        let fd = Arc::new(fd);

        // Init guest memory
        let arch_mem_regions = arch::arch_memory_regions(config.memory.size);

        let ram_regions: Vec<(GuestAddress, usize)> = arch_mem_regions
            .iter()
            .filter(|r| r.2 == RegionType::Ram)
            .map(|r| (r.0, r.1))
            .collect();
        let sub_regions: Vec<(GuestAddress, usize)> = arch_mem_regions
            .iter()
            .filter(|r| r.2 == RegionType::SubRegion)
            .map(|r| (r.0, r.1))
            .collect();

        // Check the number of reserved regions, and only take the first one
        // that's acrtually a 32-bit hole.
        let mut mem_hole = (GuestAddress(0), 0);
        for region in sub_regions.iter() {
            if region.0.unchecked_add(region.1 as u64).raw_value() <= 0x1_0000_0000 {
                mem_hole = (region.0, region.1);
                break;
            }
        }

        let guest_memory = match config.memory.file {
            Some(ref file) => {
                let mut mem_regions = Vec::<(GuestAddress, usize, Option<FileOffset>)>::new();
                for region in ram_regions.iter() {
                    if file.is_file() {
                        let file = OpenOptions::new()
                            .read(true)
                            .write(true)
                            .open(file)
                            .map_err(Error::SharedFileCreate)?;

                        file.set_len(region.1 as u64)
                            .map_err(Error::SharedFileSetLen)?;

                        mem_regions.push((region.0, region.1, Some(FileOffset::new(file, 0))));
                    } else if file.is_dir() {
                        let fs_str = format!("{}{}", file.display(), "/tmpfile_XXXXXX");
                        let fs = std::ffi::CString::new(fs_str).unwrap();
                        let mut path = fs.as_bytes_with_nul().to_owned();
                        let path_ptr = path.as_mut_ptr() as *mut _;
                        let fd = unsafe { libc::mkstemp(path_ptr) };
                        unsafe { libc::unlink(path_ptr) };

                        let f = unsafe { File::from_raw_fd(fd) };
                        f.set_len(region.1 as u64)
                            .map_err(Error::SharedFileSetLen)?;

                        mem_regions.push((region.0, region.1, Some(FileOffset::new(f, 0))));
                    }
                }

                GuestMemoryMmap::with_files(&mem_regions).map_err(Error::GuestMemory)?
            }
            None => GuestMemoryMmap::new(&ram_regions).map_err(Error::GuestMemory)?,
        };

        guest_memory
            .with_regions(|index, region| {
                let mem_region = kvm_userspace_memory_region {
                    slot: index as u32,
                    guest_phys_addr: region.start_addr().raw_value(),
                    memory_size: region.len() as u64,
                    userspace_addr: region.as_ptr() as u64,
                    flags: 0,
                };

                // Safe because the guest regions are guaranteed not to overlap.
                unsafe { fd.set_user_memory_region(mem_region) }
            })
            .map_err(|_| Error::GuestMemory(MmapError::NoMemoryRegion))?;

        // Set TSS
        fd.set_tss_address(arch::x86_64::layout::KVM_TSS_ADDRESS.raw_value() as usize)
            .map_err(Error::VmSetup)?;

        let msi_capable = kvm.check_extension(Cap::SignalMsi);

        let mut cpuid_patches = Vec::new();
        let mut userspace_ioapic = false;
        if kvm.check_extension(Cap::TscDeadlineTimer) {
            if kvm.check_extension(Cap::SplitIrqchip) && msi_capable {
                // Create split irqchip
                // Only the local APIC is emulated in kernel, both PICs and IOAPIC
                // are not.
                let mut cap: kvm_enable_cap = Default::default();
                cap.cap = KVM_CAP_SPLIT_IRQCHIP;
                cap.args[0] = ioapic::NUM_IOAPIC_PINS as u64;
                fd.enable_cap(&cap).map_err(Error::VmSetup)?;

                // Because of the split irqchip, we need a userspace IOAPIC.
                userspace_ioapic = true;
            } else {
                // Create irqchip
                // A local APIC, 2 PICs and an IOAPIC are emulated in kernel.
                fd.create_irq_chip().map_err(Error::VmSetup)?;
            }

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
        } else {
            // Create irqchip
            // A local APIC, 2 PICs and an IOAPIC are emulated in kernel.
            fd.create_irq_chip().map_err(Error::VmSetup)?;
            // Creates an in-kernel device model for the PIT.
            let mut pit_config = kvm_pit_config::default();
            // We need to enable the emulation of a dummy speaker port stub so that writing to port 0x61
            // (i.e. KVM_SPEAKER_BASE_ADDRESS) does not trigger an exit to user space.
            pit_config.flags = KVM_PIT_SPEAKER_DUMMY;
            fd.create_pit2(pit_config).map_err(Error::VmSetup)?;
        }

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
            .get_supported_cpuid(MAX_KVM_CPUID_ENTRIES)
            .map_err(Error::VmSetup)?;

        CpuidPatch::patch_cpuid(&mut cpuid, cpuid_patches);

        let ioapic = GsiApic::new(
            X86_64_IRQ_BASE,
            ioapic::NUM_IOAPIC_PINS as u32 - X86_64_IRQ_BASE,
        );

        // Let's allocate 64 GiB of addressable MMIO space, starting at 0.
        let mut allocator = SystemAllocator::new(
            GuestAddress(0),
            1 << 16 as GuestUsize,
            GuestAddress(0),
            1 << get_host_cpu_phys_bits(),
            mem_hole.0,
            mem_hole.1 as GuestUsize,
            vec![ioapic],
        )
        .ok_or(Error::CreateSystemAllocator)?;

        // Allocate RAM and Reserved address ranges.
        for region in arch_mem_regions.iter() {
            allocator
                .allocate_mmio_addresses(Some(region.0), region.1 as GuestUsize, None)
                .ok_or(Error::MemoryRangeAllocation)?;
        }

        // Convert the guest memory into an Arc. The point being able to use it
        // anywhere in the code, no matter which thread might use it.
        // Add the RwLock aspect to guest memory as we might want to perform
        // additions to the memory during runtime.
        let guest_memory = Arc::new(RwLock::new(guest_memory));

        let vm_info = VmInfo {
            memory: &guest_memory,
            vm_fd: &fd,
            vm_cfg: &config,
        };

        let device_manager = DeviceManager::new(
            &vm_info,
            allocator,
            msi_capable,
            userspace_ioapic,
            ram_regions.len() as u32,
            &exit_evt,
            &reset_evt,
        )
        .map_err(Error::DeviceManager)?;

        let on_tty = unsafe { libc::isatty(libc::STDIN_FILENO as i32) } != 0;

        let boot_vcpus = config.cpus.cpu_count;
        let cpu_manager = CpuManager::new(
            boot_vcpus,
            &device_manager,
            guest_memory.clone(),
            fd,
            cpuid,
            reset_evt,
        );

        Ok(Vm {
            kernel,
            memory: guest_memory,
            devices: device_manager,
            config,
            on_tty,
            threads: Vec::with_capacity(1),
            signals: None,
            state: RwLock::new(VmState::Created),
            cpu_manager,
        })
    }

    fn load_kernel(&mut self) -> Result<GuestAddress> {
        let mut cmdline = Cmdline::new(arch::CMDLINE_MAX_SIZE);
        cmdline
            .insert_str(self.config.cmdline.args.clone())
            .map_err(|_| Error::CmdLine)?;
        for entry in self.devices.cmdline_additions() {
            cmdline.insert_str(entry).map_err(|_| Error::CmdLine)?;
        }

        let cmdline_cstring = CString::new(cmdline).map_err(|_| Error::CmdLine)?;
        let mem = self.memory.read().unwrap();
        let entry_addr = match linux_loader::loader::Elf::load(
            mem.deref(),
            None,
            &mut self.kernel,
            Some(arch::layout::HIGH_RAM_START),
        ) {
            Ok(entry_addr) => entry_addr,
            Err(linux_loader::loader::Error::InvalidElfMagicNumber) => {
                linux_loader::loader::BzImage::load(
                    mem.deref(),
                    None,
                    &mut self.kernel,
                    Some(arch::layout::HIGH_RAM_START),
                )
                .map_err(Error::KernelLoad)?
            }
            _ => panic!("Invalid elf file"),
        };

        linux_loader::loader::load_cmdline(
            mem.deref(),
            arch::layout::CMDLINE_START,
            &cmdline_cstring,
        )
        .map_err(|_| Error::CmdLine)?;
        let vcpu_count = self.config.cpus.cpu_count;

        #[allow(unused_mut, unused_assignments)]
        let mut rsdp_addr: Option<GuestAddress> = None;

        #[cfg(feature = "acpi")]
        {
            rsdp_addr = Some({
                let end_of_range = GuestAddress((1 << get_host_cpu_phys_bits()) - 1);

                let mem_end = mem.end_addr();
                let start_of_device_area = if mem_end < arch::layout::MEM_32BIT_RESERVED_START {
                    arch::layout::RAM_64BIT_START
                } else {
                    mem_end.unchecked_add(1)
                };

                use crate::config::ConsoleOutputMode;
                crate::acpi::create_acpi_tables(
                    &mem,
                    vcpu_count,
                    self.config.serial.mode != ConsoleOutputMode::Off,
                    start_of_device_area,
                    end_of_range,
                    self.devices.virt_iommu(),
                )
            });
        }

        match entry_addr.setup_header {
            Some(hdr) => {
                arch::configure_system(
                    &mem,
                    arch::layout::CMDLINE_START,
                    cmdline_cstring.to_bytes().len() + 1,
                    vcpu_count,
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
                    vcpu_count,
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

        self.cpu_manager.shutdown()?;

        // Wait for all the threads to finish
        for thread in self.threads.drain(..) {
            thread.join().map_err(|_| Error::ThreadCleanup)?
        }
        *state = new_state;

        Ok(())
    }

    pub fn pause(&mut self) -> Result<()> {
        let mut state = self.state.try_write().map_err(|_| Error::PoisonedState)?;
        let new_state = VmState::Paused;

        state.valid_transition(new_state)?;

        self.cpu_manager.pause()?;

        *state = new_state;

        Ok(())
    }

    pub fn resume(&mut self) -> Result<()> {
        let mut state = self.state.try_write().map_err(|_| Error::PoisonedState)?;
        let new_state = VmState::Running;

        state.valid_transition(new_state)?;

        self.cpu_manager.resume()?;

        // And we're back to the Running state.
        *state = new_state;

        Ok(())
    }

    fn os_signal_handler(signals: Signals, console_input_clone: Arc<Console>) {
        for signal in signals.forever() {
            if signal == SIGWINCH {
                let (col, row) = get_win_size();
                console_input_clone.update_console_size(col, row);
            }
        }
    }

    pub fn boot(&mut self) -> Result<()> {
        let current_state = self.get_state()?;
        if current_state == VmState::Paused {
            return self.resume();
        }

        let new_state = VmState::Running;
        current_state.valid_transition(new_state)?;

        let entry_addr = self.load_kernel()?;

        self.cpu_manager.start_boot_vcpus(entry_addr)?;

        if self.devices.console().input_enabled() {
            let console = self.devices.console().clone();
            let signals = Signals::new(&[SIGWINCH]);
            match signals {
                Ok(signals) => {
                    self.signals = Some(signals.clone());

                    self.threads.push(
                        thread::Builder::new()
                            .name("signal_handler".to_string())
                            .spawn(move || Vm::os_signal_handler(signals, console))
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

    /// Gets an Arc to the guest memory owned by this VM.
    pub fn get_memory(&self) -> Arc<RwLock<GuestMemoryMmap>> {
        self.memory.clone()
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
    pub fn get_config(&self) -> Arc<VmConfig> {
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
