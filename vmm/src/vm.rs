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
use arch::RegionType;
use devices::ioapic;
use kvm_bindings::{
    kvm_enable_cap, kvm_msi, kvm_pit_config, kvm_userspace_memory_region, KVM_CAP_SPLIT_IRQCHIP,
    KVM_PIT_SPEAKER_DUMMY,
};
use kvm_ioctls::*;
use libc::O_TMPFILE;
use libc::{c_void, siginfo_t, EFD_NONBLOCK, TIOCGWINSZ};
use linux_loader::loader::KernelLoader;
use net_util::Tap;
use pci::{
    InterruptDelivery, InterruptParameters, PciConfigIo, PciDevice, PciInterruptPin, PciRoot,
};
use qcow::{self, ImageType, QcowFile};
use signal_hook::{iterator::Signals, SIGWINCH};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{self, sink, stdout};
use std::ops::Deref;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex, RwLock};
use std::{fmt, result, str, thread};
use vfio::{VfioDevice, VfioPciDevice, VfioPciError};
use vm_allocator::{GsiApic, SystemAllocator};
use vm_memory::guest_memory::FileOffset;
use vm_memory::{
    Address, Bytes, Error as MmapError, GuestAddress, GuestMemory, GuestMemoryMmap,
    GuestMemoryRegion, GuestUsize,
};
use vm_virtio::transport::VirtioPciDevice;
use vm_virtio::{VirtioSharedMemory, VirtioSharedMemoryList};
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::signal::{register_signal_handler, validate_signal_num};
use vmm_sys_util::terminal::Terminal;

const VCPU_RTSIG_OFFSET: i32 = 0;
const X86_64_IRQ_BASE: u32 = 5;
const DEFAULT_MSIX_VEC_NUM: u16 = 2;

// CPUID feature bits
const TSC_DEADLINE_TIMER_ECX_BIT: u8 = 24; // tsc deadline timer ecx bit.
const HYPERVISOR_ECX_BIT: u8 = 31; // Hypervisor ecx bit.

// 64 bit direct boot entry offset for bzImage
const KERNEL_64BIT_ENTRY_OFFSET: u64 = 0x200;

// IOAPIC address range
const IOAPIC_RANGE_ADDR: u64 = 0xfec0_0000;
const IOAPIC_RANGE_SIZE: u64 = 0x20;

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

    /// Cannot add legacy device to Bus.
    BusError(devices::BusError),

    /// Cannot create epoll context.
    EpollError(io::Error),

    /// Write to the serial console failed.
    Serial(vmm_sys_util::errno::Error),

    /// Write to the virtio console failed.
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

/// Errors associated with device manager
#[derive(Debug)]
pub enum DeviceManagerError {
    /// Cannot create EventFd.
    EventFd(io::Error),

    /// Cannot open disk path
    Disk(io::Error),

    /// Cannot create vhost-user-net device
    CreateVhostUserNet(vm_virtio::vhost_user::Error),

    /// Cannot create virtio-blk device
    CreateVirtioBlock(io::Error),

    /// Cannot create virtio-net device
    CreateVirtioNet(vm_virtio::net::Error),

    /// Cannot create virtio-console device
    CreateVirtioConsole(io::Error),

    /// Cannot create virtio-rng device
    CreateVirtioRng(io::Error),

    /// Cannot create virtio-fs device
    CreateVirtioFs(vm_virtio::vhost_user::Error),

    /// Cannot create virtio-pmem device
    CreateVirtioPmem(io::Error),

    /// Failed parsing disk image format
    DetectImageType(qcow::Error),

    /// Cannot open qcow disk path
    QcowDeviceCreate(qcow::Error),

    /// Cannot open tap interface
    OpenTap(net_util::TapError),

    /// Cannot allocate IRQ.
    AllocateIrq,

    /// Cannot configure the IRQ.
    Irq(io::Error),

    /// Cannot allocate PCI BARs
    AllocateBars(pci::PciDeviceError),

    /// Cannot register ioevent.
    RegisterIoevent(io::Error),

    /// Cannot create virtio device
    VirtioDevice(vmm_sys_util::errno::Error),

    /// Cannot add PCI device
    AddPciDevice(pci::PciRootError),

    /// Cannot open persistent memory file
    PmemFileOpen(io::Error),

    /// Cannot set persistent memory file size
    PmemFileSetLen(io::Error),

    /// Cannot find a memory range for persistent memory
    PmemRangeAllocation,

    /// Cannot find a memory range for virtio-fs
    FsRangeAllocation,

    /// Error creating serial output file
    SerialOutputFileOpen(io::Error),

    /// Error creating console output file
    ConsoleOutputFileOpen(io::Error),

    /// Cannot create a VFIO device
    VfioCreate(vfio::VfioError),

    /// Cannot create a VFIO PCI device
    VfioPciCreate(vfio::VfioPciError),

    /// Failed to map VFIO MMIO region.
    VfioMapRegion(VfioPciError),

    /// Failed to create the KVM device.
    CreateKvmDevice(io::Error),

    /// Failed to memory map.
    Mmap(io::Error),
}
pub type DeviceManagerResult<T> = result::Result<T, DeviceManagerError>;

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

struct VmInfo<'a> {
    memory: &'a Arc<RwLock<GuestMemoryMmap>>,
    vm_fd: &'a Arc<VmFd>,
    vm_cfg: &'a VmConfig<'a>,
}

struct BusInfo<'a> {
    io: &'a mut devices::Bus,
    mmio: &'a mut devices::Bus,
}

struct InterruptInfo<'a> {
    msi_capable: bool,
    ioapic: &'a Option<Arc<Mutex<ioapic::Ioapic>>>,
}

struct KernelIoapicIrq {
    evt: EventFd,
}

impl KernelIoapicIrq {
    fn new(evt: EventFd) -> Self {
        KernelIoapicIrq { evt }
    }
}

impl devices::Interrupt for KernelIoapicIrq {
    fn deliver(&self) -> result::Result<(), io::Error> {
        self.evt.write(1)
    }
}

struct UserIoapicIrq {
    ioapic: Arc<Mutex<ioapic::Ioapic>>,
    irq: usize,
}

impl UserIoapicIrq {
    fn new(ioapic: Arc<Mutex<ioapic::Ioapic>>, irq: usize) -> Self {
        UserIoapicIrq { ioapic, irq }
    }
}

pub fn get_win_size() -> (u16, u16) {
    #[repr(C)]
    struct WS {
        rows: u16,
        cols: u16,
    };
    let ws: WS = WS {
        rows: 0u16,
        cols: 0u16,
    };
    unsafe {
        libc::ioctl(0, TIOCGWINSZ, &ws);
    }

    (ws.cols, ws.rows)
}

impl devices::Interrupt for UserIoapicIrq {
    fn deliver(&self) -> result::Result<(), io::Error> {
        self.ioapic
            .lock()
            .unwrap()
            .service_irq(self.irq)
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to inject IRQ #{}: {:?}", self.irq, e),
                )
            })
    }
}

struct DeviceManager {
    io_bus: devices::Bus,
    mmio_bus: devices::Bus,

    // Serial port on 0x3f8
    serial: Option<Arc<Mutex<devices::legacy::Serial>>>,
    console_input: Option<Arc<vm_virtio::ConsoleInput>>,

    // i8042 device for i8042 reset
    i8042: Arc<Mutex<devices::legacy::I8042Device>>,

    // ACPI device for reboot/shutdwon
    acpi_device: Arc<Mutex<devices::AcpiShutdownDevice>>,

    // Shutdown (exit) and reboot (reset) control
    exit_evt: EventFd,
    reset_evt: EventFd,

    // IOAPIC
    ioapic: Option<Arc<Mutex<ioapic::Ioapic>>>,

    // PCI root
    pci: Arc<Mutex<PciConfigIo>>,
}

impl DeviceManager {
    fn new(
        vm_info: &VmInfo,
        allocator: &mut SystemAllocator,
        msi_capable: bool,
        userspace_ioapic: bool,
        mut mem_slots: u32,
    ) -> DeviceManagerResult<Self> {
        let mut io_bus = devices::Bus::new();
        let mut mmio_bus = devices::Bus::new();

        let mut buses = BusInfo {
            io: &mut io_bus,
            mmio: &mut mmio_bus,
        };

        let ioapic = if userspace_ioapic {
            // Create IOAPIC
            Some(Arc::new(Mutex::new(ioapic::Ioapic::new(
                vm_info.vm_fd.clone(),
            ))))
        } else {
            None
        };

        let interrupt_info = InterruptInfo {
            msi_capable,
            ioapic: &ioapic,
        };

        let serial_writer: Option<Box<dyn io::Write + Send>> = match vm_info.vm_cfg.serial.mode {
            ConsoleOutputMode::File => Some(Box::new(
                File::create(vm_info.vm_cfg.serial.file.unwrap())
                    .map_err(DeviceManagerError::SerialOutputFileOpen)?,
            )),
            ConsoleOutputMode::Tty => Some(Box::new(stdout())),
            ConsoleOutputMode::Off | ConsoleOutputMode::Null => None,
        };
        let serial = if vm_info.vm_cfg.serial.mode != ConsoleOutputMode::Off {
            // Serial is tied to IRQ #4
            let serial_irq = 4;
            let interrupt: Box<dyn devices::Interrupt> = if let Some(ioapic) = &ioapic {
                Box::new(UserIoapicIrq::new(ioapic.clone(), serial_irq))
            } else {
                let serial_evt = EventFd::new(EFD_NONBLOCK).map_err(DeviceManagerError::EventFd)?;
                vm_info
                    .vm_fd
                    .register_irqfd(serial_evt.as_raw_fd(), serial_irq as u32)
                    .map_err(DeviceManagerError::Irq)?;

                Box::new(KernelIoapicIrq::new(serial_evt))
            };

            Some(Arc::new(Mutex::new(devices::legacy::Serial::new(
                interrupt,
                serial_writer,
            ))))
        } else {
            None
        };

        // Add a shutdown device (i8042)
        let exit_evt = EventFd::new(EFD_NONBLOCK).map_err(DeviceManagerError::EventFd)?;
        let reset_evt = EventFd::new(EFD_NONBLOCK).map_err(DeviceManagerError::EventFd)?;
        let i8042 = Arc::new(Mutex::new(devices::legacy::I8042Device::new(
            reset_evt.try_clone().map_err(DeviceManagerError::EventFd)?,
        )));
        let acpi_device = Arc::new(Mutex::new(devices::AcpiShutdownDevice::new(
            exit_evt.try_clone().map_err(DeviceManagerError::EventFd)?,
            reset_evt.try_clone().map_err(DeviceManagerError::EventFd)?,
        )));

        let pci_root = PciRoot::new(None);
        let mut pci = PciConfigIo::new(pci_root);

        let console_writer: Option<Box<dyn io::Write + Send>> = match vm_info.vm_cfg.console.mode {
            ConsoleOutputMode::File => Some(Box::new(
                File::create(vm_info.vm_cfg.console.file.unwrap())
                    .map_err(DeviceManagerError::ConsoleOutputFileOpen)?,
            )),
            ConsoleOutputMode::Tty => Some(Box::new(stdout())),
            ConsoleOutputMode::Null => Some(Box::new(sink())),
            ConsoleOutputMode::Off => None,
        };
        let (col, row) = get_win_size();
        let console = if console_writer.is_some() {
            let (virtio_console_device, console_input) =
                vm_virtio::Console::new(console_writer, col, row)
                    .map_err(DeviceManagerError::CreateVirtioConsole)?;
            DeviceManager::add_virtio_pci_device(
                Box::new(virtio_console_device),
                vm_info.memory,
                allocator,
                vm_info.vm_fd,
                &mut pci,
                &mut buses,
                &interrupt_info,
            )?;
            Some(console_input)
        } else {
            None
        };

        DeviceManager::add_virtio_devices(
            vm_info,
            allocator,
            &mut pci,
            &mut buses,
            &interrupt_info,
            &mut mem_slots,
        )?;

        DeviceManager::add_vfio_devices(vm_info, allocator, &mut pci, &mut buses, mem_slots)?;

        let pci = Arc::new(Mutex::new(pci));

        Ok(DeviceManager {
            io_bus,
            mmio_bus,
            serial,
            console_input: console,
            i8042,
            acpi_device,
            exit_evt,
            reset_evt,
            ioapic,
            pci,
        })
    }

    fn add_virtio_devices(
        vm_info: &VmInfo,
        allocator: &mut SystemAllocator,
        pci: &mut PciConfigIo,
        buses: &mut BusInfo,
        interrupt_info: &InterruptInfo,
        mut mem_slots: &mut u32,
    ) -> DeviceManagerResult<()> {
        // Add virtio-blk if required
        DeviceManager::add_virtio_block_devices(vm_info, allocator, pci, buses, &interrupt_info)?;

        // Add virtio-net if required
        DeviceManager::add_virtio_net_devices(vm_info, allocator, pci, buses, &interrupt_info)?;

        // Add virtio-rng if required
        DeviceManager::add_virtio_rng_devices(vm_info, allocator, pci, buses, &interrupt_info)?;

        // Add virtio-fs if required
        DeviceManager::add_virtio_fs_devices(
            vm_info,
            allocator,
            pci,
            buses,
            &interrupt_info,
            &mut mem_slots,
        )?;

        // Add virtio-pmem if required
        DeviceManager::add_virtio_pmem_devices(
            vm_info,
            allocator,
            pci,
            buses,
            &interrupt_info,
            &mut mem_slots,
        )?;

        // Add virtio-vhost-user-net if required
        DeviceManager::add_virtio_vhost_user_net_devices(
            vm_info,
            allocator,
            pci,
            buses,
            &interrupt_info,
        )?;

        Ok(())
    }

    fn add_virtio_block_devices(
        vm_info: &VmInfo,
        allocator: &mut SystemAllocator,
        pci: &mut PciConfigIo,
        buses: &mut BusInfo,
        interrupt_info: &InterruptInfo,
    ) -> DeviceManagerResult<()> {
        if let Some(disk_list_cfg) = &vm_info.vm_cfg.disks {
            for disk_cfg in disk_list_cfg.iter() {
                // Open block device path
                let raw_img: File = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(disk_cfg.path)
                    .map_err(DeviceManagerError::Disk)?;

                let image_type = qcow::detect_image_type(&raw_img)
                    .map_err(DeviceManagerError::DetectImageType)?;
                let block = match image_type {
                    ImageType::Raw => {
                        let raw_img = vm_virtio::RawFile::new(raw_img);
                        let dev =
                            vm_virtio::Block::new(raw_img, disk_cfg.path.to_path_buf(), false)
                                .map_err(DeviceManagerError::CreateVirtioBlock)?;
                        Box::new(dev) as Box<dyn vm_virtio::VirtioDevice>
                    }
                    ImageType::Qcow2 => {
                        let qcow_img = QcowFile::from(raw_img)
                            .map_err(DeviceManagerError::QcowDeviceCreate)?;
                        let dev =
                            vm_virtio::Block::new(qcow_img, disk_cfg.path.to_path_buf(), false)
                                .map_err(DeviceManagerError::CreateVirtioBlock)?;
                        Box::new(dev) as Box<dyn vm_virtio::VirtioDevice>
                    }
                };

                DeviceManager::add_virtio_pci_device(
                    block,
                    vm_info.memory,
                    allocator,
                    vm_info.vm_fd,
                    pci,
                    buses,
                    &interrupt_info,
                )?;
            }
        }

        Ok(())
    }

    fn add_virtio_net_devices(
        vm_info: &VmInfo,
        allocator: &mut SystemAllocator,
        pci: &mut PciConfigIo,
        buses: &mut BusInfo,
        interrupt_info: &InterruptInfo,
    ) -> DeviceManagerResult<()> {
        // Add virtio-net if required
        if let Some(net_list_cfg) = &vm_info.vm_cfg.net {
            for net_cfg in net_list_cfg.iter() {
                let virtio_net_device: vm_virtio::Net;

                if let Some(tap_if_name) = net_cfg.tap {
                    let tap = Tap::open_named(tap_if_name).map_err(DeviceManagerError::OpenTap)?;
                    virtio_net_device = vm_virtio::Net::new_with_tap(tap, Some(&net_cfg.mac))
                        .map_err(DeviceManagerError::CreateVirtioNet)?;
                } else {
                    virtio_net_device =
                        vm_virtio::Net::new(net_cfg.ip, net_cfg.mask, Some(&net_cfg.mac))
                            .map_err(DeviceManagerError::CreateVirtioNet)?;
                }

                DeviceManager::add_virtio_pci_device(
                    Box::new(virtio_net_device),
                    vm_info.memory,
                    allocator,
                    vm_info.vm_fd,
                    pci,
                    buses,
                    &interrupt_info,
                )?;
            }
        }

        Ok(())
    }

    fn add_virtio_rng_devices(
        vm_info: &VmInfo,
        allocator: &mut SystemAllocator,
        pci: &mut PciConfigIo,
        buses: &mut BusInfo,
        interrupt_info: &InterruptInfo,
    ) -> DeviceManagerResult<()> {
        // Add virtio-rng if required
        if let Some(rng_path) = vm_info.vm_cfg.rng.src.to_str() {
            let virtio_rng_device =
                vm_virtio::Rng::new(rng_path).map_err(DeviceManagerError::CreateVirtioRng)?;

            DeviceManager::add_virtio_pci_device(
                Box::new(virtio_rng_device),
                vm_info.memory,
                allocator,
                vm_info.vm_fd,
                pci,
                buses,
                &interrupt_info,
            )?;
        }

        Ok(())
    }

    fn add_virtio_fs_devices(
        vm_info: &VmInfo,
        allocator: &mut SystemAllocator,
        pci: &mut PciConfigIo,
        buses: &mut BusInfo,
        interrupt_info: &InterruptInfo,
        mem_slots: &mut u32,
    ) -> DeviceManagerResult<()> {
        // Add virtio-fs if required
        if let Some(fs_list_cfg) = &vm_info.vm_cfg.fs {
            for fs_cfg in fs_list_cfg.iter() {
                if let Some(fs_sock) = fs_cfg.sock.to_str() {
                    let mut cache: Option<(VirtioSharedMemoryList, u64)> = None;
                    if let Some(fs_cache) = fs_cfg.cache_size {
                        // The memory needs to be 2MiB aligned in order to support
                        // hugepages.
                        let fs_guest_addr = allocator
                            .allocate_mmio_addresses(
                                None,
                                fs_cache as GuestUsize,
                                Some(0x0020_0000),
                            )
                            .ok_or(DeviceManagerError::FsRangeAllocation)?;

                        let addr = unsafe {
                            libc::mmap(
                                null_mut(),
                                fs_cache as usize,
                                libc::PROT_READ | libc::PROT_WRITE,
                                libc::MAP_NORESERVE | libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                                -1,
                                0 as libc::off_t,
                            )
                        };
                        if addr == libc::MAP_FAILED {
                            return Err(DeviceManagerError::Mmap(io::Error::last_os_error()));
                        }

                        let mem_region = kvm_userspace_memory_region {
                            slot: *mem_slots as u32,
                            guest_phys_addr: fs_guest_addr.raw_value(),
                            memory_size: fs_cache,
                            userspace_addr: addr as u64,
                            flags: 0,
                        };
                        // Safe because the guest regions are guaranteed not to overlap.
                        let _ = unsafe { vm_info.vm_fd.set_user_memory_region(mem_region) };

                        // Increment the KVM slot number
                        *mem_slots += 1;

                        let mut region_list = Vec::new();
                        region_list.push(VirtioSharedMemory {
                            offset: 0,
                            len: fs_cache,
                        });
                        cache = Some((
                            VirtioSharedMemoryList {
                                addr: fs_guest_addr,
                                len: fs_cache as GuestUsize,
                                region_list,
                            },
                            addr as u64,
                        ));
                    }

                    let virtio_fs_device = vm_virtio::vhost_user::Fs::new(
                        fs_sock,
                        fs_cfg.tag,
                        fs_cfg.num_queues,
                        fs_cfg.queue_size,
                        cache,
                    )
                    .map_err(DeviceManagerError::CreateVirtioFs)?;

                    DeviceManager::add_virtio_pci_device(
                        Box::new(virtio_fs_device),
                        vm_info.memory,
                        allocator,
                        vm_info.vm_fd,
                        pci,
                        buses,
                        &interrupt_info,
                    )?;
                }
            }
        }

        Ok(())
    }

    fn add_virtio_pmem_devices(
        vm_info: &VmInfo,
        allocator: &mut SystemAllocator,
        pci: &mut PciConfigIo,
        buses: &mut BusInfo,
        interrupt_info: &InterruptInfo,
        mem_slots: &mut u32,
    ) -> DeviceManagerResult<()> {
        // Add virtio-pmem if required
        if let Some(pmem_list_cfg) = &vm_info.vm_cfg.pmem {
            for pmem_cfg in pmem_list_cfg.iter() {
                let size = pmem_cfg.size;

                // The memory needs to be 2MiB aligned in order to support
                // hugepages.
                let pmem_guest_addr = allocator
                    .allocate_mmio_addresses(None, size as GuestUsize, Some(0x0020_0000))
                    .ok_or(DeviceManagerError::PmemRangeAllocation)?;

                let (custom_flags, set_len) = if pmem_cfg.file.is_dir() {
                    (O_TMPFILE, true)
                } else {
                    (0, false)
                };

                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .custom_flags(custom_flags)
                    .open(pmem_cfg.file)
                    .map_err(DeviceManagerError::PmemFileOpen)?;

                if set_len {
                    file.set_len(size)
                        .map_err(DeviceManagerError::PmemFileSetLen)?;
                }

                let addr = unsafe {
                    libc::mmap(
                        null_mut(),
                        size as usize,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_NORESERVE | libc::MAP_SHARED,
                        file.as_raw_fd(),
                        0 as libc::off_t,
                    ) as *mut u8
                };

                let mem_region = kvm_userspace_memory_region {
                    slot: *mem_slots as u32,
                    guest_phys_addr: pmem_guest_addr.raw_value(),
                    memory_size: size,
                    userspace_addr: addr as u64,
                    flags: 0,
                };
                // Safe because the guest regions are guaranteed not to overlap.
                let _ = unsafe { vm_info.vm_fd.set_user_memory_region(mem_region) };

                // Increment the KVM slot number
                *mem_slots += 1;

                let virtio_pmem_device =
                    vm_virtio::Pmem::new(file, pmem_guest_addr, size as GuestUsize)
                        .map_err(DeviceManagerError::CreateVirtioPmem)?;

                DeviceManager::add_virtio_pci_device(
                    Box::new(virtio_pmem_device),
                    vm_info.memory,
                    allocator,
                    vm_info.vm_fd,
                    pci,
                    buses,
                    &interrupt_info,
                )?;
            }
        }

        Ok(())
    }

    fn add_virtio_vhost_user_net_devices(
        vm_info: &VmInfo,
        allocator: &mut SystemAllocator,
        pci: &mut PciConfigIo,
        buses: &mut BusInfo,
        interrupt_info: &InterruptInfo,
    ) -> DeviceManagerResult<()> {
        // Add vhost-user-net if required
        if let Some(vhost_user_net_list_cfg) = &vm_info.vm_cfg.vhost_user_net {
            for vhost_user_net_cfg in vhost_user_net_list_cfg.iter() {
                let vhost_user_net_device = vm_virtio::vhost_user::Net::new(
                    vhost_user_net_cfg.mac,
                    vhost_user_net_cfg.vu_cfg,
                )
                .map_err(DeviceManagerError::CreateVhostUserNet)?;

                DeviceManager::add_virtio_pci_device(
                    Box::new(vhost_user_net_device),
                    vm_info.memory,
                    allocator,
                    vm_info.vm_fd,
                    pci,
                    buses,
                    &interrupt_info,
                )?;
            }
        }

        Ok(())
    }

    fn create_kvm_device(vm: &Arc<VmFd>) -> DeviceManagerResult<DeviceFd> {
        let mut vfio_dev = kvm_bindings::kvm_create_device {
            type_: kvm_bindings::kvm_device_type_KVM_DEV_TYPE_VFIO,
            fd: 0,
            flags: 0,
        };

        vm.create_device(&mut vfio_dev)
            .map_err(DeviceManagerError::CreateKvmDevice)
    }

    fn add_vfio_devices(
        vm_info: &VmInfo,
        allocator: &mut SystemAllocator,
        pci: &mut PciConfigIo,
        buses: &mut BusInfo,
        mem_slots: u32,
    ) -> DeviceManagerResult<()> {
        let mut mem_slot = mem_slots;
        if let Some(device_list_cfg) = &vm_info.vm_cfg.devices {
            // Create the KVM VFIO device
            let device_fd = DeviceManager::create_kvm_device(vm_info.vm_fd)?;
            let device_fd = Arc::new(device_fd);

            for device_cfg in device_list_cfg.iter() {
                let vfio_device =
                    VfioDevice::new(device_cfg.path, device_fd.clone(), vm_info.memory.clone())
                        .map_err(DeviceManagerError::VfioCreate)?;

                let mut vfio_pci_device = VfioPciDevice::new(vm_info.vm_fd, allocator, vfio_device)
                    .map_err(DeviceManagerError::VfioPciCreate)?;

                let bars = vfio_pci_device
                    .allocate_bars(allocator)
                    .map_err(DeviceManagerError::AllocateBars)?;

                mem_slot = vfio_pci_device
                    .map_mmio_regions(vm_info.vm_fd, mem_slot)
                    .map_err(DeviceManagerError::VfioMapRegion)?;

                let vfio_pci_device = Arc::new(Mutex::new(vfio_pci_device));

                pci.add_device(vfio_pci_device.clone())
                    .map_err(DeviceManagerError::AddPciDevice)?;

                pci.register_mapping(vfio_pci_device.clone(), buses.io, buses.mmio, bars)
                    .map_err(DeviceManagerError::AddPciDevice)?;
            }
        }
        Ok(())
    }

    fn add_virtio_pci_device(
        virtio_device: Box<dyn vm_virtio::VirtioDevice>,
        memory: &Arc<RwLock<GuestMemoryMmap>>,
        allocator: &mut SystemAllocator,
        vm_fd: &Arc<VmFd>,
        pci: &mut PciConfigIo,
        buses: &mut BusInfo,
        interrupt_info: &InterruptInfo,
    ) -> DeviceManagerResult<()> {
        let msix_num = if interrupt_info.msi_capable {
            DEFAULT_MSIX_VEC_NUM
        } else {
            0
        };

        let mut virtio_pci_device = VirtioPciDevice::new(memory.clone(), virtio_device, msix_num)
            .map_err(DeviceManagerError::VirtioDevice)?;

        let bars = virtio_pci_device
            .allocate_bars(allocator)
            .map_err(DeviceManagerError::AllocateBars)?;

        for (event, addr, _) in virtio_pci_device.ioeventfds() {
            let io_addr = IoEventAddress::Mmio(addr);
            vm_fd
                .register_ioevent(event.as_raw_fd(), &io_addr, NoDatamatch)
                .map_err(DeviceManagerError::RegisterIoevent)?;
        }

        if interrupt_info.msi_capable {
            let vm_fd_clone = vm_fd.clone();

            let msi_cb = Arc::new(Box::new(move |p: InterruptParameters| {
                if let Some(entry) = p.msix {
                    let msi_queue = kvm_msi {
                        address_lo: entry.msg_addr_lo,
                        address_hi: entry.msg_addr_hi,
                        data: entry.msg_data,
                        flags: 0u32,
                        devid: 0u32,
                        pad: [0u8; 12],
                    };

                    return vm_fd_clone.signal_msi(msi_queue).map(|ret| {
                        if ret > 0 {
                            debug!("MSI message successfully delivered");
                        } else if ret == 0 {
                            warn!("failed to deliver MSI message, blocked by guest");
                        }
                    });
                }

                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "missing MSI-X entry",
                ))
            }) as InterruptDelivery);

            virtio_pci_device.assign_msix(msi_cb);
        } else {
            let irq_num = allocator
                .allocate_irq()
                .ok_or(DeviceManagerError::AllocateIrq)?;

            let irq_cb = if let Some(ioapic) = interrupt_info.ioapic {
                let ioapic_clone = ioapic.clone();
                Box::new(move |_p: InterruptParameters| {
                    ioapic_clone
                        .lock()
                        .unwrap()
                        .service_irq(irq_num as usize)
                        .map_err(|e| {
                            std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!("failed to inject IRQ #{}: {:?}", irq_num, e),
                            )
                        })
                }) as InterruptDelivery
            } else {
                let irqfd = EventFd::new(EFD_NONBLOCK).map_err(DeviceManagerError::EventFd)?;
                vm_fd
                    .register_irqfd(irqfd.as_raw_fd(), irq_num)
                    .map_err(DeviceManagerError::Irq)?;

                Box::new(move |_p: InterruptParameters| irqfd.write(1)) as InterruptDelivery
            };

            virtio_pci_device.assign_pin_irq(
                Arc::new(irq_cb),
                irq_num as u32,
                PciInterruptPin::IntA,
            );
        }

        let virtio_pci_device = Arc::new(Mutex::new(virtio_pci_device));

        pci.add_device(virtio_pci_device.clone())
            .map_err(DeviceManagerError::AddPciDevice)?;

        pci.register_mapping(
            virtio_pci_device.clone(),
            &mut buses.io,
            &mut buses.mmio,
            bars,
        )
        .map_err(DeviceManagerError::AddPciDevice)?;

        Ok(())
    }

    pub fn register_devices(&mut self) -> Result<()> {
        if self.serial.is_some() {
            // Insert serial device
            self.io_bus
                .insert(self.serial.as_ref().unwrap().clone(), 0x3f8, 0x8)
                .map_err(Error::BusError)?;
        }

        // Insert i8042 device
        self.io_bus
            .insert(self.i8042.clone(), 0x61, 0x4)
            .map_err(Error::BusError)?;

        self.io_bus
            .insert(self.acpi_device.clone(), 0x3c0, 0x4)
            .map_err(Error::BusError)?;

        // Insert the PCI root configuration space.
        self.io_bus
            .insert(self.pci.clone(), 0xcf8, 0x8)
            .map_err(Error::BusError)?;

        if let Some(ioapic) = &self.ioapic {
            // Insert IOAPIC
            self.mmio_bus
                .insert(ioapic.clone(), IOAPIC_RANGE_ADDR, IOAPIC_RANGE_SIZE)
                .map_err(Error::BusError)?;
        }

        Ok(())
    }
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
    vcpus: Vec<thread::JoinHandle<()>>,
    devices: DeviceManager,
    cpuid: CpuId,
    config: &'a VmConfig<'a>,
    epoll: EpollContext,
    on_tty: bool,
    creation_ts: std::time::Instant,
    vcpus_kill_signalled: Arc<AtomicBool>,
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

        let device_manager = DeviceManager::new(
            &vm_info,
            &mut allocator,
            msi_capable,
            userspace_ioapic,
            ram_regions.len() as u32,
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
            .add_event(&device_manager.exit_evt, EpollDispatch::Exit)
            .map_err(Error::EpollError)?;
        epoll
            .add_event(&device_manager.reset_evt, EpollDispatch::Reset)
            .map_err(Error::EpollError)?;

        let vcpus = Vec::with_capacity(u8::from(&config.cpus) as usize);

        Ok(Vm {
            fd,
            kernel,
            memory: guest_memory,
            vcpus,
            devices: device_manager,
            cpuid,
            config,
            epoll,
            on_tty,
            creation_ts,
            vcpus_kill_signalled: Arc::new(AtomicBool::new(false)),
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

        if (self.devices.serial.is_some() || self.devices.console_input.is_some()) && self.on_tty {
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
                            self.devices.exit_evt.read().map_err(Error::EventFd)?;
                            exit_behaviour = ExitBehaviour::Shutdown;

                            break 'outer;
                        }
                        EpollDispatch::Reset => {
                            // Consume the event.
                            self.devices.reset_evt.read().map_err(Error::EventFd)?;
                            exit_behaviour = ExitBehaviour::Reset;

                            break 'outer;
                        }
                        EpollDispatch::Stdin => {
                            let mut out = [0u8; 64];
                            let count = io::stdin()
                                .lock()
                                .read_raw(&mut out)
                                .map_err(Error::Serial)?;

                            if self.devices.serial.is_some()
                                && self.config.serial.mode.input_enabled()
                            {
                                self.devices
                                    .serial
                                    .as_ref()
                                    .unwrap()
                                    .lock()
                                    .expect("Failed to process stdin event due to poisoned lock")
                                    .queue_input_bytes(&out[..count])
                                    .map_err(Error::Serial)?;
                            }

                            if self.devices.console_input.is_some()
                                && self.config.console.mode.input_enabled()
                            {
                                self.devices
                                    .console_input
                                    .as_ref()
                                    .unwrap()
                                    .queue_input_bytes(&out[..count]);
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

        // Signal to the vCPU threads. This will interrupt the KVM_RUN ioctl() allowing
        // the loop to check the boolean set above.
        for vcpu in self.vcpus.iter() {
            let signum = validate_signal_num(VCPU_RTSIG_OFFSET, true).unwrap();
            unsafe {
                use std::os::unix::thread::JoinHandleExt;
                libc::pthread_kill(vcpu.as_pthread_t(), signum);
            }
        }

        // Wait for all the vCPU threads to finish
        for vcpu in self.vcpus.drain(..) {
            vcpu.join().map_err(|_| Error::ThreadCleanup)?
        }

        Ok(exit_behaviour)
    }

    fn os_signal_handler(signals: Signals, console_input_clone: Arc<vm_virtio::ConsoleInput>) {
        for signal in signals.forever() {
            if signal == SIGWINCH {
                let (col, row) = get_win_size();
                console_input_clone.update_console_size(col, row);
            }
        }
    }

    pub fn start(&mut self, entry_addr: GuestAddress) -> Result<ExitBehaviour> {
        self.devices.register_devices()?;

        let vcpu_count = u8::from(&self.config.cpus);

        //        let vcpus: Vec<thread::JoinHandle<()>> = Vec::with_capacity(vcpu_count as usize);
        let vcpu_thread_barrier = Arc::new(Barrier::new((vcpu_count + 1) as usize));

        for cpu_id in 0..vcpu_count {
            let io_bus = self.devices.io_bus.clone();
            let mmio_bus = self.devices.mmio_bus.clone();
            let ioapic = if let Some(ioapic) = &self.devices.ioapic {
                Some(ioapic.clone())
            } else {
                None
            };

            let mut vcpu = Vcpu::new(cpu_id, &self, io_bus, mmio_bus, ioapic)?;
            vcpu.configure(entry_addr, &self)?;

            let vcpu_thread_barrier = vcpu_thread_barrier.clone();

            let reset_evt = self.devices.reset_evt.try_clone().unwrap();
            let vcpu_kill_signalled = self.vcpus_kill_signalled.clone();
            self.vcpus.push(
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

        if let Some(console_input) = &self.devices.console_input {
            let console_input_clone = console_input.clone();
            let signals = Signals::new(&[SIGWINCH]);
            match signals {
                Ok(sig) => {
                    thread::Builder::new()
                        .name("signal_handler".to_string())
                        .spawn(move || Vm::os_signal_handler(sig, console_input_clone))
                        .map_err(Error::SignalHandlerSpawn)?;
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
