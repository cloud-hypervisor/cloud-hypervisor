// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

extern crate arch;
extern crate kvm_ioctls;
extern crate libc;
extern crate linux_loader;
extern crate vm_memory;
extern crate vmm_sys_util;

use kvm_bindings::kvm_userspace_memory_region;
use kvm_ioctls::*;
use libc::{c_void, siginfo_t};
use linux_loader::cmdline;
use linux_loader::loader::KernelLoader;
use std::ffi::CString;
use std::fs::File;
use std::path::Path;
use std::sync::{Arc, Barrier};
use std::{io, result, str, thread};
use vm_memory::{
    Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion, GuestUsize,
    MmapError,
};
use vmm_sys_util::signal::register_signal_handler;

const VCPU_RTSIG_OFFSET: i32 = 0;
const DEFAULT_CMDLINE: &str =
    "console=ttyS0,115200n8 init=/init tsc=reliable no_timer_check cryptomgr.notests";
const CMDLINE_OFFSET: GuestAddress = GuestAddress(0x20000);

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
}
pub type Result<T> = result::Result<T, Error>;

/// A wrapper around creating and using a kvm-based VCPU.
pub struct Vcpu {
    //    #[cfg(target_arch = "x86_64")]
    //    cpuid: CpuId,
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

struct VmConfig<'a> {
    kernel_path: &'a Path,
    cmdline: Option<cmdline::Cmdline>,
    cmdline_addr: GuestAddress,

    memory_size: GuestUsize,
    vcpu_count: u8,
}

impl<'a> Default for VmConfig<'a> {
    fn default() -> Self {
        let line = String::from(DEFAULT_CMDLINE);
        let mut cmdline = cmdline::Cmdline::new(line.capacity());
        cmdline.insert_str(line);

        VmConfig {
            kernel_path: Path::new(""),
            cmdline: Some(cmdline),
            cmdline_addr: CMDLINE_OFFSET,
            memory_size: 512,
            vcpu_count: 1,
        }
    }
}

pub struct Vm<'a> {
    fd: VmFd,
    kernel: File,
    memory: GuestMemoryMmap,
    vcpus: Option<Vec<thread::JoinHandle<()>>>,
    config: VmConfig<'a>,
}

impl<'a> Vm<'a> {
    pub fn new(kvm: &Kvm, kernel_path: &'a Path) -> Result<Self> {
        let vm_config = VmConfig {
            kernel_path,
            ..Default::default()
        };

        let kernel = File::open(kernel_path).map_err(Error::KernelFile)?;
        let fd = kvm.create_vm().map_err(Error::VmCreate)?;

        // Init guest memory
        let arch_mem_regions = arch::arch_memory_regions(vm_config.memory_size << 20);
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

        Ok(Vm {
            fd,
            kernel,
            memory: guest_memory,
            vcpus: None,
            config: vm_config,
        })
    }

    pub fn load_kernel(&mut self) -> Result<GuestAddress> {
        let cmdline = self.config.cmdline.clone().ok_or(Error::CmdLine)?;
        let cmdline_cstring = CString::new(cmdline).map_err(|_| Error::CmdLine)?;
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

    pub fn start(&mut self, entry_addr: GuestAddress) -> Result<()> {
        let vcpu_count = self.config.vcpu_count;

        let mut vcpus = Vec::with_capacity(vcpu_count as usize);
        let vcpu_thread_barrier = Arc::new(Barrier::new((vcpu_count + 1) as usize));

        for cpu_id in 0..vcpu_count {
            println!("Starting VCPU {:?}", cpu_id);
            let mut vcpu = Vcpu::new(cpu_id, &self)?;
            let vcpu_thread_barrier = vcpu_thread_barrier.clone();

            vcpu.configure(entry_addr, &self)?;

            vcpus.push(
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

                        vcpu_thread_barrier.wait();

                        loop {
                            match vcpu.run() {
                                Ok(run) => match run {
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
                                },
                                Err(e) => {
                                    println! {"VCPU {:?} error {:?}", cpu_id, e}
                                    break;
                                }
                            }
                        }
                    })
                    .map_err(Error::VcpuSpawn)?,
            );
        }

        vcpu_thread_barrier.wait();
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
