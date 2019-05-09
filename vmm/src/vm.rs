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
extern crate vm_allocator;
extern crate vm_memory;
extern crate vm_virtio;
extern crate vmm_sys_util;

use kvm_bindings::{kvm_pit_config, kvm_userspace_memory_region, KVM_PIT_SPEAKER_DUMMY};
use kvm_ioctls::*;
use libc::{c_void, siginfo_t, EFD_NONBLOCK};
use linux_loader::cmdline;
use linux_loader::loader::KernelLoader;
use net_util::{MacAddr, Tap};
use pci::{PciConfigIo, PciDevice, PciInterruptPin, PciRoot};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{self, stdout};
use std::net::Ipv4Addr;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;
use std::sync::{Arc, Barrier, Mutex};
use std::{result, str, thread};
use vm_allocator::SystemAllocator;
use vm_memory::{
    Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion, GuestUsize,
    MmapError,
};
use vm_virtio::transport::VirtioPciDevice;
use vmm_sys_util::signal::register_signal_handler;
use vmm_sys_util::terminal::Terminal;
use vmm_sys_util::EventFd;

const VCPU_RTSIG_OFFSET: i32 = 0;
pub const DEFAULT_VCPUS: u8 = 1;
pub const DEFAULT_MEMORY: GuestUsize = 512;
const CMDLINE_OFFSET: GuestAddress = GuestAddress(0x20000);
const X86_64_IRQ_BASE: u32 = 5;

// CPUID feature bits
const ECX_HYPERVISOR_SHIFT: u32 = 31; // Hypervisor bit.

/// Errors associated with the wrappers over KVM ioctls.
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

    /// Cannot create EventFd.
    EventFd(io::Error),

    /// Cannot create a device manager.
    DeviceManager,

    /// Cannot add legacy device to Bus.
    BusError(devices::BusError),

    /// Cannot create epoll context.
    EpollError(io::Error),

    /// Write to the serial console failed.
    Serial(vmm_sys_util::Error),

    /// Cannot setup terminal in raw mode.
    SetTerminalRaw(vmm_sys_util::Error),

    /// Cannot setup terminal in canonical mode.
    SetTerminalCanon(vmm_sys_util::Error),

    /// Cannot allocate IRQ.
    AllocateIrq,

    /// Cannot allocate PCI BARs
    AllocateBars(pci::PciDeviceError),

    /// Cannot register ioevent.
    RegisterIoevent(io::Error),

    /// Cannot configure the IRQ.
    Irq(io::Error),

    /// Cannot create virtio device
    VirtioDevice,

    /// Cannot add PCI device
    AddPciDevice(pci::PciRootError),

    /// Cannot open disk path
    Disk(io::Error),

    /// Cannot create virtio-blk device
    CreateVirtioBlock(io::Error),

    /// Cannot create virtio-net device
    CreateVirtioNet(vm_virtio::net::Error),

    /// Cannot create virtio-rng device
    CreateVirtioRng(io::Error),

    /// Cannot create the system allocator
    CreateSystemAllocator,

    /// Failed parsing network parameters
    ParseNetworkParameters,

    /// Cannot open tap interface
    OpenTap(net_util::TapError),
}
pub type Result<T> = result::Result<T, Error>;

/// A wrapper around creating and using a kvm-based VCPU.
pub struct Vcpu {
    fd: VcpuFd,
    id: u8,
}

impl Vcpu {
    /// Constructs a new VCPU for `vm`.
    ///
    /// # Arguments
    ///
    /// * `id` - Represents the CPU number between [0, max vcpus).
    /// * `vm` - The virtual machine this vcpu will get attached to.
    pub fn new(id: u8, vm: &Vm) -> Result<Self> {
        let kvm_vcpu = vm.fd.create_vcpu(id).map_err(Error::VcpuFd)?;
        // Initially the cpuid per vCPU is the one supported by this VM.
        Ok(Vcpu { fd: kvm_vcpu, id })
    }

    /// Configures a x86_64 specific vcpu and should be called once per vcpu from the vcpu's thread.
    ///
    /// # Arguments
    ///
    /// * `machine_config` - Specifies necessary info used for the CPUID configuration.
    /// * `kernel_start_addr` - Offset from `guest_mem` at which the kernel starts.
    /// * `vm` - The virtual machine this vcpu will get attached to.
    pub fn configure(&mut self, kernel_start_addr: GuestAddress, vm: &Vm) -> Result<()> {
        self.fd
            .set_cpuid2(&vm.cpuid)
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
        arch::x86_64::regs::setup_sregs(vm_memory, &self.fd).map_err(Error::SREGSConfiguration)?;
        arch::x86_64::interrupts::set_lint(&self.fd).map_err(Error::LocalIntConfiguration)?;
        Ok(())
    }

    /// Runs the VCPU until it exits, returning the reason.
    ///
    /// Note that the state of the VCPU and associated VM must be setup first for this to do
    /// anything useful.
    pub fn run(&self) -> Result<VcpuExit> {
        self.fd.run().map_err(Error::VcpuRun)
    }
}

pub struct VmConfig<'a> {
    kernel_path: &'a Path,
    disk_path: &'a Path,
    rng_path: Option<String>,
    cmdline: cmdline::Cmdline,
    cmdline_addr: GuestAddress,
    net_params: Option<String>,
    memory_size: GuestUsize,
    vcpu_count: u8,
}

impl<'a> VmConfig<'a> {
    pub fn new(
        kernel_path: &'a Path,
        disk_path: &'a Path,
        rng_path: Option<String>,
        cmdline_str: String,
        net_params: Option<String>,
        vcpus: u8,
        memory_size: GuestUsize,
    ) -> Result<Self> {
        let mut cmdline = cmdline::Cmdline::new(arch::CMDLINE_MAX_SIZE);
        cmdline.insert_str(cmdline_str).unwrap();

        Ok(VmConfig {
            kernel_path,
            disk_path,
            rng_path,
            cmdline,
            cmdline_addr: CMDLINE_OFFSET,
            net_params,
            memory_size,
            vcpu_count: vcpus,
        })
    }
}

#[derive(Debug)]
struct NetParams<'a> {
    tap_if_name: Option<&'a str>,
    ip_addr: Ipv4Addr,
    net_mask: Ipv4Addr,
    mac_addr: MacAddr,
}

fn parse_net_params(net_params: &str) -> Result<NetParams> {
    // Split the parameters based on the comma delimiter
    let params_list: Vec<&str> = net_params.split(',').collect();

    let mut tap: &str = "";
    let mut ip: &str = "";
    let mut mask: &str = "";
    let mut mac: &str = "";

    for param in params_list.iter() {
        if param.starts_with("tap=") {
            tap = &param[4..];
        } else if param.starts_with("ip=") {
            ip = &param[3..];
        } else if param.starts_with("mask=") {
            mask = &param[5..];
        } else if param.starts_with("mac=") {
            mac = &param[4..];
        }
    }

    let mut tap_if_name: Option<&str> = None;
    let mut ip_addr: Ipv4Addr = "192.168.249.1".parse().unwrap();
    let mut net_mask: Ipv4Addr = "255.255.255.0".parse().unwrap();
    let mut mac_addr: MacAddr = MacAddr::parse_str("12:34:56:78:90:ab").unwrap();

    if !tap.is_empty() {
        tap_if_name = Some(tap);
    }
    if !ip.is_empty() {
        ip_addr = ip.parse().unwrap();
    }
    if !mask.is_empty() {
        net_mask = mask.parse().unwrap();
    }
    if !mac.is_empty() {
        mac_addr = MacAddr::parse_str(mac).unwrap();
    }

    Ok(NetParams {
        tap_if_name,
        ip_addr,
        net_mask,
        mac_addr,
    })
}

struct DeviceManager {
    io_bus: devices::Bus,
    mmio_bus: devices::Bus,

    // Serial port on 0x3f8
    serial: Arc<Mutex<devices::legacy::Serial>>,
    serial_evt: EventFd,

    // i8042 device for exit
    i8042: Arc<Mutex<devices::legacy::I8042Device>>,
    exit_evt: EventFd,

    // PCI root
    pci: Arc<Mutex<PciConfigIo>>,
}

impl DeviceManager {
    fn new(
        memory: GuestMemoryMmap,
        allocator: &mut SystemAllocator,
        vm_fd: &VmFd,
        vm_cfg: &VmConfig,
    ) -> Result<Self> {
        let io_bus = devices::Bus::new();
        let mut mmio_bus = devices::Bus::new();
        let serial_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::EventFd)?;
        let serial = Arc::new(Mutex::new(devices::legacy::Serial::new_out(
            serial_evt.try_clone().map_err(Error::EventFd)?,
            Box::new(stdout()),
        )));

        let exit_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::EventFd)?;
        let i8042 = Arc::new(Mutex::new(devices::legacy::I8042Device::new(
            exit_evt.try_clone().map_err(Error::EventFd)?,
        )));

        let mut pci_root = PciRoot::new(None);

        // Open block device path
        let raw_img: File = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&vm_cfg.disk_path)
            .map_err(Error::Disk)?;

        // Add virtio-blk
        let virtio_block_device =
            vm_virtio::Block::new(raw_img, false).map_err(Error::CreateVirtioBlock)?;

        DeviceManager::add_virtio_pci_device(
            Box::new(virtio_block_device),
            memory.clone(),
            allocator,
            vm_fd,
            &mut pci_root,
            &mut mmio_bus,
        )?;

        // Add virtio-net if required
        if let Some(net_params) = &vm_cfg.net_params {
            if let Ok(net_params) = parse_net_params(net_params) {
                let mut virtio_net_device: vm_virtio::Net;

                if let Some(tap_if_name) = net_params.tap_if_name {
                    let tap = Tap::open_named(tap_if_name).map_err(Error::OpenTap)?;
                    virtio_net_device =
                        vm_virtio::Net::new_with_tap(tap, Some(&net_params.mac_addr))
                            .map_err(Error::CreateVirtioNet)?;
                } else {
                    virtio_net_device = vm_virtio::Net::new(
                        net_params.ip_addr,
                        net_params.net_mask,
                        Some(&net_params.mac_addr),
                    )
                    .map_err(Error::CreateVirtioNet)?;
                }

                DeviceManager::add_virtio_pci_device(
                    Box::new(virtio_net_device),
                    memory.clone(),
                    allocator,
                    vm_fd,
                    &mut pci_root,
                    &mut mmio_bus,
                )?;
            }
        }

        // Add virtio-rng if required
        if let Some(rng_path) = &vm_cfg.rng_path {
            let virtio_rng_device =
                vm_virtio::Rng::new(rng_path).map_err(Error::CreateVirtioRng)?;

            DeviceManager::add_virtio_pci_device(
                Box::new(virtio_rng_device),
                memory.clone(),
                allocator,
                vm_fd,
                &mut pci_root,
                &mut mmio_bus,
            )?;
        }

        let pci = Arc::new(Mutex::new(PciConfigIo::new(pci_root)));

        Ok(DeviceManager {
            io_bus,
            mmio_bus,
            serial,
            serial_evt,
            i8042,
            exit_evt,
            pci,
        })
    }

    fn add_virtio_pci_device(
        virtio_device: Box<vm_virtio::VirtioDevice>,
        memory: GuestMemoryMmap,
        allocator: &mut SystemAllocator,
        vm_fd: &VmFd,
        pci_root: &mut PciRoot,
        mmio_bus: &mut devices::Bus,
    ) -> Result<()> {
        let mut virtio_pci_device =
            VirtioPciDevice::new(memory, virtio_device).map_err(|_| Error::VirtioDevice)?;
        let bars = virtio_pci_device
            .allocate_bars(allocator)
            .map_err(Error::AllocateBars)?;

        for (event, addr, _) in virtio_pci_device.ioeventfds() {
            let io_addr = IoEventAddress::Mmio(addr);
            vm_fd
                .register_ioevent(event.as_raw_fd(), &io_addr, NoDatamatch)
                .map_err(Error::RegisterIoevent)?;
        }

        // Assign IRQ to the virtio-pci device
        let irqfd = EventFd::new(EFD_NONBLOCK).map_err(Error::EventFd)?;
        let irq_num = allocator.allocate_irq().ok_or(Error::AllocateIrq)?;
        vm_fd
            .register_irqfd(irqfd.as_raw_fd(), irq_num)
            .map_err(Error::Irq)?;
        // Let's use irq line INTA for now.
        virtio_pci_device.assign_irq(irqfd, irq_num as u32, PciInterruptPin::IntA);

        let virtio_pci_device = Arc::new(Mutex::new(virtio_pci_device));

        pci_root
            .add_device(virtio_pci_device.clone(), mmio_bus, bars)
            .map_err(Error::AddPciDevice)?;

        Ok(())
    }

    pub fn register_devices(&mut self) -> Result<()> {
        // Insert serial device
        self.io_bus
            .insert(self.serial.clone(), 0x3f8, 0x8)
            .map_err(Error::BusError)?;

        // Insert i8042 device
        self.io_bus
            .insert(self.i8042.clone(), 0x61, 0x4)
            .map_err(Error::BusError)?;

        // Insert the PCI root configuration space.
        self.io_bus
            .insert(self.pci.clone(), 0xcf8, 0x8)
            .map_err(Error::BusError)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum EpollDispatch {
    Exit,
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
        let mut dispatch_table = Vec::with_capacity(3);
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

pub struct Vm<'a> {
    fd: VmFd,
    kernel: File,
    memory: GuestMemoryMmap,
    vcpus: Vec<thread::JoinHandle<()>>,
    devices: DeviceManager,
    cpuid: CpuId,
    config: VmConfig<'a>,
    epoll: EpollContext,
}

impl<'a> Vm<'a> {
    pub fn new(kvm: &Kvm, config: VmConfig<'a>) -> Result<Self> {
        let kernel = File::open(&config.kernel_path).map_err(Error::KernelFile)?;
        let fd = kvm.create_vm().map_err(Error::VmCreate)?;

        // Init guest memory
        let arch_mem_regions = arch::arch_memory_regions(config.memory_size << 20);
        let guest_memory = GuestMemoryMmap::new(&arch_mem_regions).map_err(Error::GuestMemory)?;

        guest_memory
            .with_regions(|index, region| {
                let mem_region = kvm_userspace_memory_region {
                    slot: index as u32,
                    guest_phys_addr: region.start_addr().raw_value(),
                    memory_size: region.len() as u64,
                    userspace_addr: region.as_ptr() as u64,
                    flags: 0,
                };

                println!(
                    "Size {:?} guest addr 0x{:x} host addr 0x{:x}",
                    mem_region.memory_size, mem_region.guest_phys_addr, mem_region.userspace_addr
                );

                // Safe because the guest regions are guaranteed not to overlap.
                fd.set_user_memory_region(mem_region)
            })
            .map_err(|_| Error::GuestMemory(MmapError::NoMemoryRegion))?;

        // Set TSS
        fd.set_tss_address(arch::x86_64::layout::KVM_TSS_ADDRESS.raw_value() as usize)
            .map_err(Error::VmSetup)?;

        // Create IRQ chip
        fd.create_irq_chip().map_err(Error::VmSetup)?;

        // Creates an in-kernel device model for the PIT.
        let mut pit_config = kvm_pit_config::default();
        // We need to enable the emulation of a dummy speaker port stub so that writing to port 0x61
        // (i.e. KVM_SPEAKER_BASE_ADDRESS) does not trigger an exit to user space.
        pit_config.flags = KVM_PIT_SPEAKER_DUMMY;
        fd.create_pit2(pit_config).map_err(Error::VmSetup)?;

        // Supported CPUID
        let mut cpuid = kvm
            .get_supported_cpuid(MAX_KVM_CPUID_ENTRIES)
            .map_err(Error::VmSetup)?;
        Vm::patch_cpuid(&mut cpuid);

        // Let's allocate 64 GiB of addressable MMIO space, starting at 0.
        let mut allocator = SystemAllocator::new(
            None,
            None,
            GuestAddress(0),
            1 << 36 as GuestUsize,
            X86_64_IRQ_BASE,
        )
        .ok_or(Error::CreateSystemAllocator)?;

        let device_manager = DeviceManager::new(guest_memory.clone(), &mut allocator, &fd, &config)
            .map_err(|_| Error::DeviceManager)?;
        fd.register_irqfd(device_manager.serial_evt.as_raw_fd(), 4)
            .map_err(Error::Irq)?;

        // Let's add our STDIN fd.
        let mut epoll = EpollContext::new().map_err(Error::EpollError)?;
        epoll.add_stdin().map_err(Error::EpollError)?;

        // Let's add an exit event.
        epoll
            .add_event(&device_manager.exit_evt, EpollDispatch::Exit)
            .map_err(Error::EpollError)?;

        let vcpus = Vec::with_capacity(config.vcpu_count as usize);

        Ok(Vm {
            fd,
            kernel,
            memory: guest_memory,
            vcpus,
            devices: device_manager,
            cpuid,
            config,
            epoll,
        })
    }

    pub fn load_kernel(&mut self) -> Result<GuestAddress> {
        let cmdline_cstring =
            CString::new(self.config.cmdline.clone()).map_err(|_| Error::CmdLine)?;
        let entry_addr = linux_loader::loader::Elf::load(
            &self.memory,
            None,
            &mut self.kernel,
            Some(arch::HIMEM_START),
        )
        .map_err(Error::KernelLoad)?;

        linux_loader::loader::load_cmdline(
            &self.memory,
            self.config.cmdline_addr,
            &cmdline_cstring,
        )
        .map_err(|_| Error::CmdLine)?;

        let vcpu_count = self.config.vcpu_count;

        arch::configure_system(
            &self.memory,
            self.config.cmdline_addr,
            cmdline_cstring.to_bytes().len() + 1,
            vcpu_count,
        )
        .map_err(|_| Error::CmdLine)?;

        Ok(entry_addr.kernel_load)
    }

    pub fn control_loop(&mut self) -> Result<()> {
        // Let's start the STDIN polling thread.
        const EPOLL_EVENTS_LEN: usize = 100;

        let mut events = vec![epoll::Event::new(epoll::Events::empty(), 0); EPOLL_EVENTS_LEN];
        let epoll_fd = self.epoll.as_raw_fd();

        let stdin = io::stdin();
        let stdin_lock = stdin.lock();
        stdin_lock.set_raw_mode().map_err(Error::SetTerminalRaw)?;

        loop {
            let num_events =
                epoll::wait(epoll_fd, -1, &mut events[..]).map_err(Error::EpollError)?;

            for event in events.iter().take(num_events) {
                let dispatch_idx = event.data as usize;

                if let Some(dispatch_type) = self.epoll.dispatch_table[dispatch_idx] {
                    match dispatch_type {
                        EpollDispatch::Exit => {
                            // Consume the event.
                            self.devices.exit_evt.read().map_err(Error::EventFd)?;

                            // Don't forget to set the terminal in canonical mode
                            // before to exit.
                            stdin_lock
                                .set_canon_mode()
                                .map_err(Error::SetTerminalCanon)?;

                            // Safe because we're terminating the process anyway.
                            unsafe {
                                libc::_exit(0);
                            }
                        }
                        EpollDispatch::Stdin => {
                            let mut out = [0u8; 64];
                            let count = stdin_lock.read_raw(&mut out).map_err(Error::Serial)?;

                            self.devices
                                .serial
                                .lock()
                                .expect("Failed to process stdin event due to poisoned lock")
                                .queue_input_bytes(&out[..count])
                                .map_err(Error::Serial)?;
                        }
                    }
                }
            }
        }
    }

    pub fn start(&mut self, entry_addr: GuestAddress) -> Result<()> {
        self.devices.register_devices()?;

        let vcpu_count = self.config.vcpu_count;

        //        let vcpus: Vec<thread::JoinHandle<()>> = Vec::with_capacity(vcpu_count as usize);
        let vcpu_thread_barrier = Arc::new(Barrier::new((vcpu_count + 1) as usize));

        for cpu_id in 0..vcpu_count {
            println!("Starting VCPU {:?}", cpu_id);
            let io_bus = self.devices.io_bus.clone();
            let mmio_bus = self.devices.mmio_bus.clone();
            let mut vcpu = Vcpu::new(cpu_id, &self)?;
            vcpu.configure(entry_addr, &self)?;

            let vcpu_thread_barrier = vcpu_thread_barrier.clone();

            self.vcpus.push(
                thread::Builder::new()
                    .name(format!("cloud-hypervisor_vcpu{}", vcpu.id))
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
                            match vcpu.run() {
                                Ok(run) => match run {
                                    VcpuExit::IoIn(addr, data) => {
                                        io_bus.read(u64::from(addr), data);
                                    }
                                    VcpuExit::IoOut(addr, data) => {
                                        io_bus.write(u64::from(addr), data);
                                    }
                                    VcpuExit::MmioRead(addr, data) => {
                                        mmio_bus.read(addr as u64, data);
                                    }
                                    VcpuExit::MmioWrite(addr, data) => {
                                        mmio_bus.write(addr as u64, data);
                                    }
                                    VcpuExit::Unknown => {
                                        println!("Unknown");
                                    }
                                    VcpuExit::Exception => {
                                        println!("Exception");
                                    }
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
                                    VcpuExit::IoapicEoi => {}
                                    VcpuExit::Hyperv => {}
                                },
                                Err(Error::VcpuRun(ref e)) => {
                                    match e.raw_os_error().unwrap() {
                                        // Why do we check for these if we only return EINVAL?
                                        libc::EAGAIN | libc::EINTR => {}
                                        _ => {
                                            println! {"VCPU {:?} error {:?}", cpu_id, e};
                                            break;
                                        }
                                    }
                                }
                                _ => (),
                            }
                        }
                    })
                    .map_err(Error::VcpuSpawn)?,
            );
        }

        // Unblock all CPU threads.
        vcpu_thread_barrier.wait();

        self.control_loop()?;

        Ok(())
    }

    /// Gets a reference to the guest memory owned by this VM.
    ///
    /// Note that `GuestMemory` does not include any device memory that may have been added after
    /// this VM was constructed.
    pub fn get_memory(&self) -> &GuestMemoryMmap {
        &self.memory
    }

    /// Gets a reference to the kvm file descriptor owned by this VM.
    ///
    pub fn get_fd(&self) -> &VmFd {
        &self.fd
    }

    fn patch_cpuid(cpuid: &mut CpuId) {
        let entries = cpuid.mut_entries_slice();

        for entry in entries.iter_mut() {
            if let 1 = entry.function {
                if entry.index == 0 {
                    entry.ecx |= 1 << ECX_HYPERVISOR_SHIFT;
                }
            }
        }
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
        vm_fd.set_user_memory_region(mem_region)
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
            VcpuExit::IoapicEoi => {}
            VcpuExit::Hyperv => {}
        }
        //        r => panic!("unexpected exit reason: {:?}", r),
    }
}
