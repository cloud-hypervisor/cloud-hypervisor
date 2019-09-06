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
extern crate vfio;
extern crate vm_allocator;
extern crate vm_memory;
extern crate vm_virtio;
extern crate vmm_sys_util;

use crate::config::{ConsoleOutputMode, VmConfig};
use crate::device_manager::{get_win_size, Console, DeviceManager, DeviceManagerError};
use arch::RegionType;
use devices::ioapic;
use kvm_bindings::{
    kvm_enable_cap, kvm_pit_config, kvm_userspace_memory_region, KVM_CAP_SPLIT_IRQCHIP,
    KVM_PIT_SPEAKER_DUMMY,
};
use kvm_ioctls::*;
use libc::EFD_NONBLOCK;
use libc::{c_void, siginfo_t};
use linux_loader::loader::KernelLoader;
use signal_hook::{iterator::Signals, SIGWINCH};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io;
use std::ops::Deref;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
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

    /// Cannot create EventFd.
    EventFd(io::Error),

    /// Cannot create epoll context.
    EpollError(io::Error),

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
        let entries = cpuid.mut_entries_slice();

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
        let entries = cpuid.mut_entries_slice();

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
    io_bus: devices::Bus,
    mmio_bus: devices::Bus,
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
        vm: &Vm,
        io_bus: devices::Bus,
        mmio_bus: devices::Bus,
        ioapic: Option<Arc<Mutex<ioapic::Ioapic>>>,
    ) -> Result<Self> {
        let kvm_vcpu = vm.fd.create_vcpu(id).map_err(Error::VcpuFd)?;
        // Initially the cpuid per vCPU is the one supported by this VM.
        Ok(Vcpu {
            fd: kvm_vcpu,
            id,
            io_bus,
            mmio_bus,
            ioapic,
            vm_ts: vm.creation_ts,
        })
    }

    /// Configures a x86_64 specific vcpu and should be called once per vcpu from the vcpu's thread.
    ///
    /// # Arguments
    ///
    /// * `machine_config` - Specifies necessary info used for the CPUID configuration.
    /// * `kernel_start_addr` - Offset from `guest_mem` at which the kernel starts.
    /// * `vm` - The virtual machine this vcpu will get attached to.
    pub fn configure(&mut self, kernel_start_addr: GuestAddress, vm: &Vm) -> Result<()> {
        let mut cpuid = vm.cpuid.clone();
        CpuidPatch::set_cpuid_reg(&mut cpuid, 0xb, None, CpuidReg::EDX, u32::from(self.id));
        self.fd
            .set_cpuid2(&cpuid)
            .map_err(Error::SetSupportedCpusFailed)?;

        arch::x86_64::regs::setup_msrs(&self.fd).map_err(Error::MSRSConfiguration)?;
        // Safe to unwrap because this method is called after the VM is configured
        let vm_memory = vm.get_memory();
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
    pub vm_cfg: &'a VmConfig<'a>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum EpollDispatch {
    Exit,
    Reset,
    Stdin,
}

pub struct EpollContext {
    raw_fd: RawFd,
    dispatch_table: Vec<Option<EpollDispatch>>,
}

impl EpollContext {
    pub fn new() -> result::Result<EpollContext, io::Error> {
        let raw_fd = epoll::create(true)?;

        // Initial capacity needs to be large enough to hold:
        // * 1 exit event
        // * 1 stdin event
        let mut dispatch_table = Vec::with_capacity(4);
        dispatch_table.push(None);

        Ok(EpollContext {
            raw_fd,
            dispatch_table,
        })
    }

    pub fn add_stdin(&mut self) -> result::Result<(), io::Error> {
        let dispatch_index = self.dispatch_table.len() as u64;
        epoll::ctl(
            self.raw_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            libc::STDIN_FILENO,
            epoll::Event::new(epoll::Events::EPOLLIN, dispatch_index),
        )?;

        self.dispatch_table.push(Some(EpollDispatch::Stdin));

        Ok(())
    }

    fn add_event<T>(&mut self, fd: &T, token: EpollDispatch) -> result::Result<(), io::Error>
    where
        T: AsRawFd,
    {
        let dispatch_index = self.dispatch_table.len() as u64;
        epoll::ctl(
            self.raw_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            fd.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, dispatch_index),
        )?;
        self.dispatch_table.push(Some(token));

        Ok(())
    }
}

impl AsRawFd for EpollContext {
    fn as_raw_fd(&self) -> RawFd {
        self.raw_fd
    }
}

#[derive(PartialEq)]
pub enum ExitBehaviour {
    Shutdown = 1,
    Reset = 2,
}

pub struct Vm<'a> {
    fd: Arc<VmFd>,
    kernel: File,
    memory: Arc<RwLock<GuestMemoryMmap>>,
    threads: Vec<thread::JoinHandle<()>>,
    devices: DeviceManager,
    cpuid: CpuId,
    config: &'a VmConfig<'a>,
    epoll: EpollContext,
    on_tty: bool,
    creation_ts: std::time::Instant,
    vcpus_kill_signalled: Arc<AtomicBool>,
    // Shutdown (exit) and reboot (reset) control
    exit_evt: EventFd,
    reset_evt: EventFd,
}

impl<'a> Vm<'a> {
    pub fn new(kvm: &Kvm, config: &'a VmConfig<'a>) -> Result<Self> {
        let kernel = File::open(&config.kernel.path).map_err(Error::KernelFile)?;
        let fd = kvm.create_vm().map_err(Error::VmCreate)?;
        let fd = Arc::new(fd);
        let creation_ts = std::time::Instant::now();

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
            Some(file) => {
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

        // Supported CPUID
        let mut cpuid = kvm
            .get_supported_cpuid(MAX_KVM_CPUID_ENTRIES)
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
            1 << 36 as GuestUsize,
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
            vm_cfg: config,
        };

        let exit_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::EventFd)?;
        let reset_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::EventFd)?;

        let device_manager = DeviceManager::new(
            &vm_info,
            &mut allocator,
            msi_capable,
            userspace_ioapic,
            ram_regions.len() as u32,
            &exit_evt,
            &reset_evt,
        )
        .map_err(Error::DeviceManager)?;

        // Let's add our STDIN fd.
        let mut epoll = EpollContext::new().map_err(Error::EpollError)?;

        let on_tty = unsafe { libc::isatty(libc::STDIN_FILENO as i32) } != 0;
        if on_tty {
            epoll.add_stdin().map_err(Error::EpollError)?;
        }

        // Let's add an exit event.
        epoll
            .add_event(&exit_evt, EpollDispatch::Exit)
            .map_err(Error::EpollError)?;
        epoll
            .add_event(&reset_evt, EpollDispatch::Reset)
            .map_err(Error::EpollError)?;

        let threads = Vec::with_capacity(u8::from(&config.cpus) as usize + 1);

        Ok(Vm {
            fd,
            kernel,
            memory: guest_memory,
            threads,
            devices: device_manager,
            cpuid,
            config,
            epoll,
            on_tty,
            creation_ts,
            vcpus_kill_signalled: Arc::new(AtomicBool::new(false)),
            exit_evt,
            reset_evt,
        })
    }

    pub fn load_kernel(&mut self) -> Result<GuestAddress> {
        let cmdline_cstring =
            CString::new(self.config.cmdline.args.clone()).map_err(|_| Error::CmdLine)?;
        let mem = self.memory.read().unwrap();
        let entry_addr = match linux_loader::loader::Elf::load(
            mem.deref(),
            None,
            &mut self.kernel,
            Some(arch::HIMEM_START),
        ) {
            Ok(entry_addr) => entry_addr,
            Err(linux_loader::loader::Error::InvalidElfMagicNumber) => {
                linux_loader::loader::BzImage::load(
                    mem.deref(),
                    None,
                    &mut self.kernel,
                    Some(arch::HIMEM_START),
                )
                .map_err(Error::KernelLoad)?
            }
            _ => panic!("Invalid elf file"),
        };

        linux_loader::loader::load_cmdline(
            mem.deref(),
            self.config.cmdline.offset,
            &cmdline_cstring,
        )
        .map_err(|_| Error::CmdLine)?;

        let vcpu_count = u8::from(&self.config.cpus);

        match entry_addr.setup_header {
            Some(hdr) => {
                arch::configure_system(
                    &mem,
                    self.config.cmdline.offset,
                    cmdline_cstring.to_bytes().len() + 1,
                    vcpu_count,
                    Some(hdr),
                    self.config.serial.mode != ConsoleOutputMode::Off,
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
                    self.config.cmdline.offset,
                    cmdline_cstring.to_bytes().len() + 1,
                    vcpu_count,
                    None,
                    self.config.serial.mode != ConsoleOutputMode::Off,
                )
                .map_err(|_| Error::CmdLine)?;

                Ok(entry_addr.kernel_load)
            }
        }
    }

    pub fn control_loop(&mut self) -> Result<ExitBehaviour> {
        // Let's start the STDIN polling thread.
        const EPOLL_EVENTS_LEN: usize = 100;

        let mut events = vec![epoll::Event::new(epoll::Events::empty(), 0); EPOLL_EVENTS_LEN];
        let epoll_fd = self.epoll.as_raw_fd();

        if self.devices.console().input_enabled() && self.on_tty {
            io::stdin()
                .lock()
                .set_raw_mode()
                .map_err(Error::SetTerminalRaw)?;
        }

        let exit_behaviour;

        'outer: loop {
            let num_events = match epoll::wait(epoll_fd, -1, &mut events[..]) {
                Ok(res) => res,
                Err(e) => {
                    if e.kind() == io::ErrorKind::Interrupted {
                        // It's well defined from the epoll_wait() syscall
                        // documentation that the epoll loop can be interrupted
                        // before any of the requested events occurred or the
                        // timeout expired. In both those cases, epoll_wait()
                        // returns an error of type EINTR, but this should not
                        // be considered as a regular error. Instead it is more
                        // appropriate to retry, by calling into epoll_wait().
                        continue;
                    }
                    return Err(Error::EpollError(e));
                }
            };

            for event in events.iter().take(num_events) {
                let dispatch_idx = event.data as usize;

                if let Some(dispatch_type) = self.epoll.dispatch_table[dispatch_idx] {
                    match dispatch_type {
                        EpollDispatch::Exit => {
                            // Consume the event.
                            self.exit_evt.read().map_err(Error::EventFd)?;
                            exit_behaviour = ExitBehaviour::Shutdown;

                            break 'outer;
                        }
                        EpollDispatch::Reset => {
                            // Consume the event.
                            self.reset_evt.read().map_err(Error::EventFd)?;
                            exit_behaviour = ExitBehaviour::Reset;

                            break 'outer;
                        }
                        EpollDispatch::Stdin => {
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
                        }
                    }
                }
            }
        }

        if self.on_tty {
            // Don't forget to set the terminal in canonical mode
            // before to exit.
            io::stdin()
                .lock()
                .set_canon_mode()
                .map_err(Error::SetTerminalCanon)?;
        }

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

        Ok(exit_behaviour)
    }

    fn os_signal_handler(signals: Signals, console_input_clone: Arc<Console>, quit_signum: i32) {
        for signal in signals.forever() {
            match signal {
                SIGWINCH => {
                    let (col, row) = get_win_size();
                    console_input_clone.update_console_size(col, row);
                }
                s if s == quit_signum => {
                    break;
                }
                _ => {}
            }
        }
    }

    pub fn start(&mut self, entry_addr: GuestAddress) -> Result<ExitBehaviour> {
        self.devices
            .register_devices()
            .map_err(Error::DeviceManager)?;

        let vcpu_count = u8::from(&self.config.cpus);

        //        let vcpus: Vec<thread::JoinHandle<()>> = Vec::with_capacity(vcpu_count as usize);
        let vcpu_thread_barrier = Arc::new(Barrier::new((vcpu_count + 1) as usize));

        for cpu_id in 0..vcpu_count {
            let io_bus = self.devices.io_bus().clone();
            let mmio_bus = self.devices.mmio_bus().clone();
            let ioapic = if let Some(ioapic) = &self.devices.ioapic() {
                Some(ioapic.clone())
            } else {
                None
            };

            let mut vcpu = Vcpu::new(cpu_id, &self, io_bus, mmio_bus, ioapic)?;
            vcpu.configure(entry_addr, &self)?;

            let vcpu_thread_barrier = vcpu_thread_barrier.clone();

            let reset_evt = self.reset_evt.try_clone().unwrap();
            let vcpu_kill_signalled = self.vcpus_kill_signalled.clone();
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
                        }
                    })
                    .map_err(Error::VcpuSpawn)?,
            );
        }

        // Unblock all CPU threads.
        vcpu_thread_barrier.wait();

        if self.devices.console().input_enabled() {
            let console = self.devices.console().clone();
            let quit_signum = validate_signal_num(VCPU_RTSIG_OFFSET, true).unwrap();
            let signals = Signals::new(&[SIGWINCH, quit_signum]);
            match signals {
                Ok(sig) => {
                    self.threads.push(
                        thread::Builder::new()
                            .name("signal_handler".to_string())
                            .spawn(move || Vm::os_signal_handler(sig, console, quit_signum))
                            .map_err(Error::SignalHandlerSpawn)?,
                    );
;
                }
                Err(e) => error!("Signal not found {}", e),
            }
        }
        self.control_loop()
    }

    /// Gets an Arc to the guest memory owned by this VM.
    pub fn get_memory(&self) -> Arc<RwLock<GuestMemoryMmap>> {
        self.memory.clone()
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
