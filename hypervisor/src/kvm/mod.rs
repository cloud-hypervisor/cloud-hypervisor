// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2020, Microsoft Corporation
//
// Copyright 2018-2019 CrowdStrike, Inc.
//
//

use kvm_ioctls::{NoDatamatch, VcpuFd, VmFd};
use std::result;
use std::sync::Arc;
#[cfg(target_arch = "x86_64")]
use vm_memory::Address;
use vmm_sys_util::eventfd::EventFd;

#[cfg(target_arch = "aarch64")]
pub use crate::aarch64::{check_required_kvm_extensions, VcpuInit, VcpuKvmState as CpuState};
use crate::cpu;
use crate::hypervisor;
use crate::vm;
// x86_64 dependencies
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "x86_64")]
use x86_64::{
    check_required_kvm_extensions, FpuState, SpecialRegisters, StandardRegisters, KVM_TSS_ADDRESS,
};

#[cfg(target_arch = "x86_64")]
pub use x86_64::{
    CpuId, ExtendedControlRegisters, LapicState, MsrEntries, VcpuKvmState as CpuState, Xsave,
};

#[cfg(target_arch = "x86_64")]
use kvm_bindings::{kvm_enable_cap, MsrList, KVM_CAP_SPLIT_IRQCHIP};

#[cfg(target_arch = "x86_64")]
use crate::arch::x86::NUM_IOAPIC_PINS;

// aarch64 dependencies
#[cfg(target_arch = "aarch64")]
pub mod aarch64;

pub use kvm_bindings;
pub use kvm_bindings::{
    kvm_create_device, kvm_device_type_KVM_DEV_TYPE_VFIO, kvm_irq_routing, kvm_irq_routing_entry,
    kvm_userspace_memory_region, KVM_IRQ_ROUTING_MSI, KVM_MEM_READONLY, KVM_MSI_VALID_DEVID,
};
pub use kvm_ioctls;
pub use kvm_ioctls::{Cap, Kvm};

///
/// Export generically-named wrappers of kvm-bindings for Unix-based platforms
///
pub use {
    kvm_bindings::kvm_clock_data as ClockData, kvm_bindings::kvm_create_device as CreateDevice,
    kvm_bindings::kvm_irq_routing as IrqRouting, kvm_bindings::kvm_mp_state as MpState,
    kvm_bindings::kvm_userspace_memory_region as MemoryRegion,
    kvm_bindings::kvm_vcpu_events as VcpuEvents, kvm_ioctls::DeviceFd, kvm_ioctls::IoEventAddress,
    kvm_ioctls::VcpuExit,
};

/// Wrapper over KVM VM ioctls.
pub struct KvmVm {
    fd: Arc<VmFd>,
    #[cfg(target_arch = "x86_64")]
    msrs: MsrEntries,
}
///
/// Implementation of Vm trait for KVM
/// Example:
/// #[cfg(feature = "kvm")]
/// extern crate hypervisor
/// let kvm = hypervisor::kvm::KvmHypervisor::new().unwrap();
/// let hypervisor: Arc<dyn hypervisor::Hypervisor> = Arc::new(kvm);
/// let vm = hypervisor.create_vm().expect("new VM fd creation failed");
/// vm.set/get().unwrap()
///
impl vm::Vm for KvmVm {
    #[cfg(target_arch = "x86_64")]
    ///
    /// Sets the address of the three-page region in the VM's address space.
    ///
    fn set_tss_address(&self, offset: usize) -> vm::Result<()> {
        self.fd
            .set_tss_address(offset)
            .map_err(|e| vm::HypervisorVmError::SetTssAddress(e.into()))
    }
    ///
    /// Creates an in-kernel interrupt controller.
    ///
    fn create_irq_chip(&self) -> vm::Result<()> {
        self.fd
            .create_irq_chip()
            .map_err(|e| vm::HypervisorVmError::CreateIrq(e.into()))
    }
    ///
    /// Registers an event that will, when signaled, trigger the `gsi` IRQ.
    ///
    fn register_irqfd(&self, fd: &EventFd, gsi: u32) -> vm::Result<()> {
        self.fd
            .register_irqfd(fd, gsi)
            .map_err(|e| vm::HypervisorVmError::RegisterIrqFd(e.into()))
    }
    ///
    /// Unregisters an event that will, when signaled, trigger the `gsi` IRQ.
    ///
    fn unregister_irqfd(&self, fd: &EventFd, gsi: u32) -> vm::Result<()> {
        self.fd
            .unregister_irqfd(fd, gsi)
            .map_err(|e| vm::HypervisorVmError::UnregisterIrqFd(e.into()))
    }
    ///
    /// Creates a VcpuFd object from a vcpu RawFd.
    ///
    fn create_vcpu(&self, id: u8) -> vm::Result<Arc<dyn cpu::Vcpu>> {
        let vc = self
            .fd
            .create_vcpu(id)
            .map_err(|e| vm::HypervisorVmError::CreateVcpu(e.into()))?;
        let vcpu = KvmVcpu {
            fd: vc,
            #[cfg(target_arch = "x86_64")]
            msrs: self.msrs.clone(),
        };
        Ok(Arc::new(vcpu))
    }
    ///
    /// Registers an event to be signaled whenever a certain address is written to.
    ///
    fn register_ioevent(
        &self,
        fd: &EventFd,
        addr: &IoEventAddress,
        datamatch: Option<vm::DataMatch>,
    ) -> vm::Result<()> {
        if let Some(dm) = datamatch {
            match dm {
                vm::DataMatch::DataMatch32(kvm_dm32) => self
                    .fd
                    .register_ioevent(fd, addr, kvm_dm32)
                    .map_err(|e| vm::HypervisorVmError::RegisterIoEvent(e.into())),
                vm::DataMatch::DataMatch64(kvm_dm64) => self
                    .fd
                    .register_ioevent(fd, addr, kvm_dm64)
                    .map_err(|e| vm::HypervisorVmError::RegisterIoEvent(e.into())),
            }
        } else {
            self.fd
                .register_ioevent(fd, addr, NoDatamatch)
                .map_err(|e| vm::HypervisorVmError::RegisterIoEvent(e.into()))
        }
    }
    ///
    /// Unregisters an event from a certain address it has been previously registered to.
    ///
    fn unregister_ioevent(&self, fd: &EventFd, addr: &IoEventAddress) -> vm::Result<()> {
        self.fd
            .unregister_ioevent(fd, addr, NoDatamatch)
            .map_err(|e| vm::HypervisorVmError::UnregisterIoEvent(e.into()))
    }
    ///
    /// Sets the GSI routing table entries, overwriting any previously set
    /// entries, as per the `KVM_SET_GSI_ROUTING` ioctl.
    ///
    fn set_gsi_routing(&self, irq_routing: &IrqRouting) -> vm::Result<()> {
        self.fd
            .set_gsi_routing(irq_routing)
            .map_err(|e| vm::HypervisorVmError::SetGsiRouting(e.into()))
    }
    ///
    /// Creates a memory region structure that can be used with set_user_memory_region
    ///
    fn make_user_memory_region(
        &self,
        slot: u32,
        guest_phys_addr: u64,
        memory_size: u64,
        userspace_addr: u64,
        readonly: bool,
    ) -> MemoryRegion {
        MemoryRegion {
            slot,
            guest_phys_addr,
            memory_size,
            userspace_addr,
            flags: if readonly { KVM_MEM_READONLY } else { 0 },
        }
    }
    ///
    /// Creates/modifies a guest physical memory slot.
    ///
    fn set_user_memory_region(&self, user_memory_region: MemoryRegion) -> vm::Result<()> {
        // Safe because guest regions are guaranteed not to overlap.
        unsafe {
            self.fd
                .set_user_memory_region(user_memory_region)
                .map_err(|e| vm::HypervisorVmError::SetUserMemory(e.into()))
        }
    }
    ///
    /// Creates an emulated device in the kernel.
    ///
    /// See the documentation for `KVM_CREATE_DEVICE`.
    fn create_device(&self, device: &mut CreateDevice) -> vm::Result<DeviceFd> {
        self.fd
            .create_device(device)
            .map_err(|e| vm::HypervisorVmError::CreateDevice(e.into()))
    }
    ///
    /// Returns the preferred CPU target type which can be emulated by KVM on underlying host.
    ///
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    fn get_preferred_target(&self, kvi: &mut VcpuInit) -> vm::Result<()> {
        self.fd
            .get_preferred_target(kvi)
            .map_err(|e| vm::HypervisorVmError::GetPreferredTarget(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    fn enable_split_irq(&self) -> vm::Result<()> {
        // Set TSS
        self.fd
            .set_tss_address(KVM_TSS_ADDRESS.raw_value() as usize)
            .map_err(|e| vm::HypervisorVmError::EnableSplitIrq(e.into()))?;
        // Create split irqchip
        // Only the local APIC is emulated in kernel, both PICs and IOAPIC
        // are not.
        let mut cap: kvm_enable_cap = Default::default();
        cap.cap = KVM_CAP_SPLIT_IRQCHIP;
        cap.args[0] = NUM_IOAPIC_PINS as u64;
        self.fd
            .enable_cap(&cap)
            .map_err(|e| vm::HypervisorVmError::EnableSplitIrq(e.into()))?;
        Ok(())
    }
    /// Retrieve guest clock.
    #[cfg(target_arch = "x86_64")]
    fn get_clock(&self) -> vm::Result<ClockData> {
        self.fd
            .get_clock()
            .map_err(|e| vm::HypervisorVmError::GetClock(e.into()))
    }
    /// Set guest clock.
    #[cfg(target_arch = "x86_64")]
    fn set_clock(&self, data: &ClockData) -> vm::Result<()> {
        self.fd
            .set_clock(data)
            .map_err(|e| vm::HypervisorVmError::SetClock(e.into()))
    }
    /// Checks if a particular `Cap` is available.
    fn check_extension(&self, c: Cap) -> bool {
        self.fd.check_extension(c)
    }
}
/// Wrapper over KVM system ioctls.
pub struct KvmHypervisor {
    kvm: Kvm,
}
/// Enum for KVM related error
#[derive(Debug)]
pub enum KvmError {
    CapabilityMissing(Cap),
}
pub type KvmResult<T> = result::Result<T, KvmError>;
impl KvmHypervisor {
    /// Create a hypervisor based on Kvm
    pub fn new() -> hypervisor::Result<KvmHypervisor> {
        let kvm_obj = Kvm::new().map_err(|e| hypervisor::HypervisorError::VmCreate(e.into()))?;
        Ok(KvmHypervisor { kvm: kvm_obj })
    }
}
/// Implementation of Hypervisor trait for KVM
/// Example:
/// #[cfg(feature = "kvm")]
/// extern crate hypervisor
/// let kvm = hypervisor::kvm::KvmHypervisor::new().unwrap();
/// let hypervisor: Arc<dyn hypervisor::Hypervisor> = Arc::new(kvm);
/// let vm = hypervisor.create_vm().expect("new VM fd creation failed");
///
impl hypervisor::Hypervisor for KvmHypervisor {
    /// Create a KVM vm object and return the object as Vm trait object
    /// Example
    /// # extern crate hypervisor;
    /// # use hypervisor::KvmHypervisor;
    /// use hypervisor::KvmVm;
    /// let hypervisor = KvmHypervisor::new().unwrap();
    /// let vm = hypervisor.create_vm().unwrap()
    ///
    fn create_vm(&self) -> hypervisor::Result<Arc<dyn vm::Vm>> {
        let fd: VmFd;
        loop {
            match self.kvm.create_vm() {
                Ok(res) => fd = res,
                Err(e) => {
                    if e.errno() == libc::EINTR {
                        // If the error returned is EINTR, which means the
                        // ioctl has been interrupted, we have to retry as
                        // this can't be considered as a regular error.
                        continue;
                    } else {
                        return Err(hypervisor::HypervisorError::VmCreate(e.into()));
                    }
                }
            }
            break;
        }

        let vm_fd = Arc::new(fd);

        #[cfg(target_arch = "x86_64")]
        {
            let msr_list = self.get_msr_list()?;
            let num_msrs = msr_list.as_fam_struct_ref().nmsrs as usize;
            let mut msrs = MsrEntries::new(num_msrs);
            let indices = msr_list.as_slice();
            let msr_entries = msrs.as_mut_slice();
            for (pos, index) in indices.iter().enumerate() {
                msr_entries[pos].index = *index;
            }

            Ok(Arc::new(KvmVm { fd: vm_fd, msrs }))
        }

        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
        {
            Ok(Arc::new(KvmVm { fd: vm_fd }))
        }
    }

    fn check_required_extensions(&self) -> hypervisor::Result<()> {
        check_required_kvm_extensions(&self.kvm).expect("Missing KVM capabilities");
        Ok(())
    }

    ///
    /// Returns the KVM API version.
    ///
    fn get_api_version(&self) -> i32 {
        self.kvm.get_api_version()
    }
    ///
    ///  Returns the size of the memory mapping required to use the vcpu's `kvm_run` structure.
    ///
    fn get_vcpu_mmap_size(&self) -> hypervisor::Result<usize> {
        self.kvm
            .get_vcpu_mmap_size()
            .map_err(|e| hypervisor::HypervisorError::GetVcpuMmap(e.into()))
    }
    ///
    /// Gets the recommended maximum number of VCPUs per VM.
    ///
    fn get_max_vcpus(&self) -> hypervisor::Result<usize> {
        Ok(self.kvm.get_max_vcpus())
    }
    ///
    /// Gets the recommended number of VCPUs per VM.
    ///
    fn get_nr_vcpus(&self) -> hypervisor::Result<usize> {
        Ok(self.kvm.get_nr_vcpus())
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Checks if a particular `Cap` is available.
    ///
    fn check_capability(&self, c: Cap) -> bool {
        self.kvm.check_extension(c)
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call to get the system supported CPUID values.
    ///
    fn get_cpuid(&self) -> hypervisor::Result<CpuId> {
        self.kvm
            .get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
            .map_err(|e| hypervisor::HypervisorError::GetCpuId(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Retrieve the list of MSRs supported by KVM.
    ///
    fn get_msr_list(&self) -> hypervisor::Result<MsrList> {
        self.kvm
            .get_msr_index_list()
            .map_err(|e| hypervisor::HypervisorError::GetMsrList(e.into()))
    }
}
/// Vcpu struct for KVM
pub struct KvmVcpu {
    fd: VcpuFd,
    #[cfg(target_arch = "x86_64")]
    msrs: MsrEntries,
}
/// Implementation of Vcpu trait for KVM
/// Example:
/// #[cfg(feature = "kvm")]
/// extern crate hypervisor
/// let kvm = hypervisor::kvm::KvmHypervisor::new().unwrap();
/// let hypervisor: Arc<dyn hypervisor::Hypervisor> = Arc::new(kvm);
/// let vm = hypervisor.create_vm().expect("new VM fd creation failed");
/// let vcpu = vm.create_vcpu(0).unwrap();
/// vcpu.get/set().unwrap()
///
impl cpu::Vcpu for KvmVcpu {
    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns the vCPU general purpose registers.
    ///
    fn get_regs(&self) -> cpu::Result<StandardRegisters> {
        self.fd
            .get_regs()
            .map_err(|e| cpu::HypervisorCpuError::GetStandardRegs(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Sets the vCPU general purpose registers using the `KVM_SET_REGS` ioctl.
    ///
    fn set_regs(&self, regs: &StandardRegisters) -> cpu::Result<()> {
        self.fd
            .set_regs(regs)
            .map_err(|e| cpu::HypervisorCpuError::SetStandardRegs(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns the vCPU special registers.
    ///
    fn get_sregs(&self) -> cpu::Result<SpecialRegisters> {
        self.fd
            .get_sregs()
            .map_err(|e| cpu::HypervisorCpuError::GetSpecialRegs(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Sets the vCPU special registers using the `KVM_SET_SREGS` ioctl.
    ///
    fn set_sregs(&self, sregs: &SpecialRegisters) -> cpu::Result<()> {
        self.fd
            .set_sregs(sregs)
            .map_err(|e| cpu::HypervisorCpuError::SetSpecialRegs(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns the floating point state (FPU) from the vCPU.
    ///
    fn get_fpu(&self) -> cpu::Result<FpuState> {
        self.fd
            .get_fpu()
            .map_err(|e| cpu::HypervisorCpuError::GetFloatingPointRegs(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Set the floating point state (FPU) of a vCPU using the `KVM_SET_FPU` ioct.
    ///
    fn set_fpu(&self, fpu: &FpuState) -> cpu::Result<()> {
        self.fd
            .set_fpu(fpu)
            .map_err(|e| cpu::HypervisorCpuError::SetFloatingPointRegs(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call to setup the CPUID registers.
    ///
    fn set_cpuid2(&self, cpuid: &CpuId) -> cpu::Result<()> {
        self.fd
            .set_cpuid2(cpuid)
            .map_err(|e| cpu::HypervisorCpuError::SetCpuid(e.into()))
    }
    ///
    /// X86 specific call to retrieve the CPUID registers.
    ///
    #[cfg(target_arch = "x86_64")]
    fn get_cpuid2(&self, num_entries: usize) -> cpu::Result<CpuId> {
        self.fd
            .get_cpuid2(num_entries)
            .map_err(|e| cpu::HypervisorCpuError::GetCpuid(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns the state of the LAPIC (Local Advanced Programmable Interrupt Controller).
    ///
    fn get_lapic(&self) -> cpu::Result<LapicState> {
        self.fd
            .get_lapic()
            .map_err(|e| cpu::HypervisorCpuError::GetlapicState(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Sets the state of the LAPIC (Local Advanced Programmable Interrupt Controller).
    ///
    fn set_lapic(&self, klapic: &LapicState) -> cpu::Result<()> {
        self.fd
            .set_lapic(klapic)
            .map_err(|e| cpu::HypervisorCpuError::SetLapicState(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns the model-specific registers (MSR) for this vCPU.
    ///
    fn get_msrs(&self, msrs: &mut MsrEntries) -> cpu::Result<usize> {
        self.fd
            .get_msrs(msrs)
            .map_err(|e| cpu::HypervisorCpuError::GetMsrEntries(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Setup the model-specific registers (MSR) for this vCPU.
    /// Returns the number of MSR entries actually written.
    ///
    fn set_msrs(&self, msrs: &MsrEntries) -> cpu::Result<usize> {
        self.fd
            .set_msrs(msrs)
            .map_err(|e| cpu::HypervisorCpuError::SetMsrEntries(e.into()))
    }
    ///
    /// Returns the vcpu's current "multiprocessing state".
    ///
    fn get_mp_state(&self) -> cpu::Result<MpState> {
        self.fd
            .get_mp_state()
            .map_err(|e| cpu::HypervisorCpuError::GetMpState(e.into()))
    }
    ///
    /// Sets the vcpu's current "multiprocessing state".
    ///
    fn set_mp_state(&self, mp_state: MpState) -> cpu::Result<()> {
        self.fd
            .set_mp_state(mp_state)
            .map_err(|e| cpu::HypervisorCpuError::SetMpState(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call that returns the vcpu's current "xsave struct".
    ///
    fn get_xsave(&self) -> cpu::Result<Xsave> {
        self.fd
            .get_xsave()
            .map_err(|e| cpu::HypervisorCpuError::GetXsaveState(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call that sets the vcpu's current "xsave struct".
    ///
    fn set_xsave(&self, xsave: &Xsave) -> cpu::Result<()> {
        self.fd
            .set_xsave(xsave)
            .map_err(|e| cpu::HypervisorCpuError::SetXsaveState(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call that returns the vcpu's current "xcrs".
    ///
    fn get_xcrs(&self) -> cpu::Result<ExtendedControlRegisters> {
        self.fd
            .get_xcrs()
            .map_err(|e| cpu::HypervisorCpuError::GetXcsr(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call that sets the vcpu's current "xcrs".
    ///
    fn set_xcrs(&self, xcrs: &ExtendedControlRegisters) -> cpu::Result<()> {
        self.fd
            .set_xcrs(&xcrs)
            .map_err(|e| cpu::HypervisorCpuError::SetXcsr(e.into()))
    }
    ///
    /// Triggers the running of the current virtual CPU returning an exit reason.
    ///
    fn run(&self) -> std::result::Result<cpu::VmExit, cpu::HypervisorCpuError> {
        match self.fd.run() {
            Ok(run) => match run {
                #[cfg(target_arch = "x86_64")]
                VcpuExit::IoIn(addr, data) => Ok(cpu::VmExit::IoIn(addr, data)),
                #[cfg(target_arch = "x86_64")]
                VcpuExit::IoOut(addr, data) => Ok(cpu::VmExit::IoOut(addr, data)),
                #[cfg(target_arch = "x86_64")]
                VcpuExit::IoapicEoi(vector) => Ok(cpu::VmExit::IoapicEoi(vector)),
                #[cfg(target_arch = "x86_64")]
                VcpuExit::Shutdown | VcpuExit::Hlt => Ok(cpu::VmExit::Reset),

                #[cfg(target_arch = "aarch64")]
                VcpuExit::SystemEvent(event_type, flags) => {
                    use kvm_bindings::KVM_SYSTEM_EVENT_SHUTDOWN;
                    // On Aarch64, when the VM is shutdown, run() returns
                    // VcpuExit::SystemEvent with reason KVM_SYSTEM_EVENT_SHUTDOWN
                    if event_type == KVM_SYSTEM_EVENT_SHUTDOWN {
                        Ok(cpu::VmExit::Reset)
                    } else {
                        Err(cpu::HypervisorCpuError::RunVcpu(anyhow!(
                            "Unexpected system event with type 0x{:x}, flags 0x{:x}",
                            event_type,
                            flags
                        )))
                    }
                }

                VcpuExit::MmioRead(addr, data) => Ok(cpu::VmExit::MmioRead(addr, data)),
                VcpuExit::MmioWrite(addr, data) => Ok(cpu::VmExit::MmioWrite(addr, data)),

                r => Err(cpu::HypervisorCpuError::RunVcpu(anyhow!(
                    "Unexpected exit reason on vcpu run: {:?}",
                    r
                ))),
            },

            Err(ref e) => match e.errno() {
                libc::EAGAIN | libc::EINTR => Ok(cpu::VmExit::Ignore),
                _ => Err(cpu::HypervisorCpuError::RunVcpu(anyhow!(
                    "VCPU error {:?}",
                    e
                ))),
            },
        }
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns currently pending exceptions, interrupts, and NMIs as well as related
    /// states of the vcpu.
    ///
    fn get_vcpu_events(&self) -> cpu::Result<VcpuEvents> {
        self.fd
            .get_vcpu_events()
            .map_err(|e| cpu::HypervisorCpuError::GetVcpuEvents(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Sets pending exceptions, interrupts, and NMIs as well as related states
    /// of the vcpu.
    ///
    fn set_vcpu_events(&self, events: &VcpuEvents) -> cpu::Result<()> {
        self.fd
            .set_vcpu_events(events)
            .map_err(|e| cpu::HypervisorCpuError::SetVcpuEvents(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Let the guest know that it has been paused, which prevents from
    /// potential soft lockups when being resumed.
    ///
    fn notify_guest_clock_paused(&self) -> cpu::Result<()> {
        self.fd
            .kvmclock_ctrl()
            .map_err(|e| cpu::HypervisorCpuError::NotifyGuestClockPaused(e.into()))
    }
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    fn vcpu_init(&self, kvi: &VcpuInit) -> cpu::Result<()> {
        self.fd
            .vcpu_init(kvi)
            .map_err(|e| cpu::HypervisorCpuError::VcpuInit(e.into()))
    }
    ///
    /// Sets the value of one register for this vCPU.
    ///
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    fn set_one_reg(&self, reg_id: u64, data: u64) -> cpu::Result<()> {
        self.fd
            .set_one_reg(reg_id, data)
            .map_err(|e| cpu::HypervisorCpuError::SetOneReg(e.into()))
    }
    ///
    /// Gets the value of one register for this vCPU.
    ///
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    fn get_one_reg(&self, reg_id: u64) -> cpu::Result<u64> {
        self.fd
            .get_one_reg(reg_id)
            .map_err(|e| cpu::HypervisorCpuError::GetOneReg(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Get the current CPU state
    ///
    /// Ordering requirements:
    ///
    /// KVM_GET_MP_STATE calls kvm_apic_accept_events(), which might modify
    /// vCPU/LAPIC state. As such, it must be done before most everything
    /// else, otherwise we cannot restore everything and expect it to work.
    ///
    /// KVM_GET_VCPU_EVENTS/KVM_SET_VCPU_EVENTS is unsafe if other vCPUs are
    /// still running.
    ///
    /// KVM_GET_LAPIC may change state of LAPIC before returning it.
    ///
    /// GET_VCPU_EVENTS should probably be last to save. The code looks as
    /// it might as well be affected by internal state modifications of the
    /// GET ioctls.
    ///
    /// SREGS saves/restores a pending interrupt, similar to what
    /// VCPU_EVENTS also does.
    ///
    /// GET_MSRS requires a pre-populated data structure to do something
    /// meaningful. For SET_MSRS it will then contain good data.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate hypervisor;
    /// # use hypervisor::KvmHypervisor;
    /// # use std::sync::Arc;
    /// let kvm = hypervisor::kvm::KvmHypervisor::new().unwrap();
    /// let hv: Arc<dyn hypervisor::Hypervisor> = Arc::new(kvm);
    /// let vm = hv.create_vm().expect("new VM fd creation failed");
    /// vm.enable_split_irq().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let state = vcpu.state().unwrap();
    /// ```
    fn state(&self) -> cpu::Result<CpuState> {
        let mp_state = self.get_mp_state()?;
        let regs = self.get_regs()?;
        let sregs = self.get_sregs()?;
        let xsave = self.get_xsave()?;
        let xcrs = self.get_xcrs()?;
        let lapic_state = self.get_lapic()?;
        let fpu = self.get_fpu()?;
        let mut msrs = self.msrs.clone();
        self.get_msrs(&mut msrs)?;
        let vcpu_events = self.get_vcpu_events()?;

        Ok(CpuState {
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
    #[cfg(target_arch = "aarch64")]
    fn state(&self) -> cpu::Result<CpuState> {
        unimplemented!();
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Restore the previously saved CPU state
    ///
    /// Ordering requirements:
    ///
    /// KVM_GET_VCPU_EVENTS/KVM_SET_VCPU_EVENTS is unsafe if other vCPUs are
    /// still running.
    ///
    /// Some SET ioctls (like set_mp_state) depend on kvm_vcpu_is_bsp(), so
    /// if we ever change the BSP, we have to do that before restoring anything.
    /// The same seems to be true for CPUID stuff.
    ///
    /// SREGS saves/restores a pending interrupt, similar to what
    /// VCPU_EVENTS also does.
    ///
    /// SET_REGS clears pending exceptions unconditionally, thus, it must be
    /// done before SET_VCPU_EVENTS, which restores it.
    ///
    /// SET_LAPIC must come after SET_SREGS, because the latter restores
    /// the apic base msr.
    ///
    /// SET_LAPIC must come before SET_MSRS, because the TSC deadline MSR
    /// only restores successfully, when the LAPIC is correctly configured.
    ///
    /// Arguments: CpuState
    /// # Example
    ///
    /// ```rust
    /// # extern crate hypervisor;
    /// # use hypervisor::KvmHypervisor;
    /// # use std::sync::Arc;
    /// let kvm = hypervisor::kvm::KvmHypervisor::new().unwrap();
    /// let hv: Arc<dyn hypervisor::Hypervisor> = Arc::new(kvm);
    /// let vm = hv.create_vm().expect("new VM fd creation failed");
    /// vm.enable_split_irq().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let state = vcpu.state().unwrap();
    /// vcpu.set_state(&state).unwrap();
    /// ```
    fn set_state(&self, state: &CpuState) -> cpu::Result<()> {
        self.set_mp_state(state.mp_state)?;
        self.set_regs(&state.regs)?;
        self.set_sregs(&state.sregs)?;
        self.set_xsave(&state.xsave)?;
        self.set_xcrs(&state.xcrs)?;
        self.set_lapic(&state.lapic_state)?;
        self.set_fpu(&state.fpu)?;
        self.set_msrs(&state.msrs)?;
        self.set_vcpu_events(&state.vcpu_events)?;

        Ok(())
    }
    #[allow(unused_variables)]
    #[cfg(target_arch = "aarch64")]
    fn set_state(&self, state: &CpuState) -> cpu::Result<()> {
        Ok(())
    }
}
