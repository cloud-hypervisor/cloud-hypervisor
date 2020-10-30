// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2020, Microsoft Corporation
//
// Copyright 2018-2019 CrowdStrike, Inc.
//
//

#[cfg(target_arch = "aarch64")]
pub use crate::aarch64::{
    check_required_kvm_extensions, is_system_register, VcpuInit, VcpuKvmState as CpuState,
    MPIDR_EL1,
};
use crate::cpu;
use crate::device;
use crate::hypervisor;
use crate::vm::{self, VmmOps};
#[cfg(target_arch = "aarch64")]
use crate::{arm64_core_reg_id, offset__of};
use arc_swap::ArcSwapOption;
use kvm_ioctls::{NoDatamatch, VcpuFd, VmFd};
use serde_derive::{Deserialize, Serialize};
use std::os::unix::io::{AsRawFd, RawFd};
use std::result;
#[cfg(target_arch = "x86_64")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
#[cfg(target_arch = "x86_64")]
use vm_memory::Address;
use vmm_sys_util::eventfd::EventFd;
// x86_64 dependencies
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "x86_64")]
use x86_64::{
    check_required_kvm_extensions, FpuState, SpecialRegisters, StandardRegisters, KVM_TSS_ADDRESS,
};

#[cfg(target_arch = "aarch64")]
use aarch64::{RegList, Register, StandardRegisters};

#[cfg(target_arch = "x86_64")]
pub use x86_64::{
    CpuId, CpuIdEntry, ExtendedControlRegisters, LapicState, MsrEntries, VcpuKvmState as CpuState,
    Xsave, CPUID_FLAG_VALID_INDEX,
};

#[cfg(target_arch = "x86_64")]
use kvm_bindings::{
    kvm_enable_cap, kvm_msr_entry, MsrList, KVM_CAP_HYPERV_SYNIC, KVM_CAP_SPLIT_IRQCHIP,
};

#[cfg(target_arch = "x86_64")]
use crate::arch::x86::NUM_IOAPIC_PINS;

// aarch64 dependencies
#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "aarch64")]
use kvm_bindings::{
    kvm_regs, user_fpsimd_state, user_pt_regs, KVM_NR_SPSR, KVM_REG_ARM64, KVM_REG_ARM_CORE,
    KVM_REG_SIZE_U128, KVM_REG_SIZE_U32, KVM_REG_SIZE_U64,
};
#[cfg(target_arch = "aarch64")]
use std::mem;

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
    kvm_bindings::kvm_device_attr as DeviceAttr,
    kvm_bindings::kvm_irq_routing_entry as IrqRoutingEntry, kvm_bindings::kvm_mp_state as MpState,
    kvm_bindings::kvm_userspace_memory_region as MemoryRegion,
    kvm_bindings::kvm_vcpu_events as VcpuEvents, kvm_ioctls::DeviceFd, kvm_ioctls::IoEventAddress,
    kvm_ioctls::VcpuExit,
};
#[derive(Clone, Copy, Debug, PartialEq, Deserialize, Serialize)]
pub struct KvmVmState {}

pub use KvmVmState as VmState;
/// Wrapper over KVM VM ioctls.
pub struct KvmVm {
    fd: Arc<VmFd>,
    #[cfg(target_arch = "x86_64")]
    msrs: MsrEntries,
    state: KvmVmState,
    vmmops: ArcSwapOption<Box<dyn vm::VmmOps>>,
}

// Returns a `Vec<T>` with a size in bytes at least as large as `size_in_bytes`.
fn vec_with_size_in_bytes<T: Default>(size_in_bytes: usize) -> Vec<T> {
    let rounded_size = (size_in_bytes + size_of::<T>() - 1) / size_of::<T>();
    let mut v = Vec::with_capacity(rounded_size);
    v.resize_with(rounded_size, T::default);
    v
}

// The kvm API has many structs that resemble the following `Foo` structure:
//
// ```
// #[repr(C)]
// struct Foo {
//    some_data: u32
//    entries: __IncompleteArrayField<__u32>,
// }
// ```
//
// In order to allocate such a structure, `size_of::<Foo>()` would be too small because it would not
// include any space for `entries`. To make the allocation large enough while still being aligned
// for `Foo`, a `Vec<Foo>` is created. Only the first element of `Vec<Foo>` would actually be used
// as a `Foo`. The remaining memory in the `Vec<Foo>` is for `entries`, which must be contiguous
// with `Foo`. This function is used to make the `Vec<Foo>` with enough space for `count` entries.
use std::mem::size_of;
fn vec_with_array_field<T: Default, F>(count: usize) -> Vec<T> {
    let element_space = count * size_of::<F>();
    let vec_size_bytes = size_of::<T>() + element_space;
    vec_with_size_in_bytes(vec_size_bytes)
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
            vmmops: self.vmmops.clone(),
            #[cfg(target_arch = "x86_64")]
            hyperv_synic: AtomicBool::new(false),
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
    fn set_gsi_routing(&self, entries: &[IrqRoutingEntry]) -> vm::Result<()> {
        let mut irq_routing =
            vec_with_array_field::<kvm_irq_routing, kvm_irq_routing_entry>(entries.len());
        irq_routing[0].nr = entries.len() as u32;
        irq_routing[0].flags = 0;

        unsafe {
            let entries_slice: &mut [kvm_irq_routing_entry] =
                irq_routing[0].entries.as_mut_slice(entries.len());
            entries_slice.copy_from_slice(&entries);
        }

        self.fd
            .set_gsi_routing(&irq_routing[0])
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
    fn create_device(&self, device: &mut CreateDevice) -> vm::Result<Arc<dyn device::Device>> {
        let fd = self
            .fd
            .create_device(device)
            .map_err(|e| vm::HypervisorVmError::CreateDevice(e.into()))?;
        let device = KvmDevice { fd };
        Ok(Arc::new(device))
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
    /// Create a device that is used for passthrough
    fn create_passthrough_device(&self) -> vm::Result<Arc<dyn device::Device>> {
        let mut vfio_dev = kvm_create_device {
            type_: kvm_device_type_KVM_DEV_TYPE_VFIO,
            fd: 0,
            flags: 0,
        };

        self.create_device(&mut vfio_dev)
            .map_err(|e| vm::HypervisorVmError::CreatePassthroughDevice(e.into()))
    }
    ///
    /// Get the Vm state. Return VM specific data
    ///
    fn state(&self) -> vm::Result<VmState> {
        Ok(self.state)
    }
    ///
    /// Set the VM state
    ///
    fn set_state(&self, _state: VmState) -> vm::Result<()> {
        Ok(())
    }

    ///
    /// Set the VmmOps interface
    ///
    fn set_vmmops(&self, vmmops: Box<dyn VmmOps>) -> vm::Result<()> {
        self.vmmops.store(Some(Arc::new(vmmops)));
        Ok(())
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
        let api_version = kvm_obj.get_api_version();

        if api_version != kvm_bindings::KVM_API_VERSION as i32 {
            return Err(hypervisor::HypervisorError::IncompatibleApiVersion);
        }

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

            Ok(Arc::new(KvmVm {
                fd: vm_fd,
                msrs,
                state: VmState {},
                vmmops: ArcSwapOption::from(None),
            }))
        }

        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
        {
            Ok(Arc::new(KvmVm {
                fd: vm_fd,
                state: VmState {},
                vmmops: ArcSwapOption::from(None),
            }))
        }
    }

    fn check_required_extensions(&self) -> hypervisor::Result<()> {
        check_required_kvm_extensions(&self.kvm).expect("Missing KVM capabilities");
        Ok(())
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
    vmmops: ArcSwapOption<Box<dyn vm::VmmOps>>,
    #[cfg(target_arch = "x86_64")]
    hyperv_synic: AtomicBool,
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
    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call to enable HyperV SynIC
    ///
    fn enable_hyperv_synic(&self) -> cpu::Result<()> {
        // Update the information about Hyper-V SynIC being enabled and
        // emulated as it will influence later which MSRs should be saved.
        self.hyperv_synic.store(true, Ordering::SeqCst);

        let mut cap: kvm_enable_cap = Default::default();
        cap.cap = KVM_CAP_HYPERV_SYNIC;
        self.fd
            .enable_cap(&cap)
            .map_err(|e| cpu::HypervisorCpuError::EnableHyperVSynIC(e.into()))
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
                VcpuExit::IoIn(addr, data) => {
                    if let Some(vmmops) = self.vmmops.load_full() {
                        return vmmops
                            .pio_read(addr.into(), data)
                            .map(|_| cpu::VmExit::Ignore)
                            .map_err(|e| cpu::HypervisorCpuError::RunVcpu(e.into()));
                    }

                    Ok(cpu::VmExit::IoIn(addr, data))
                }
                #[cfg(target_arch = "x86_64")]
                VcpuExit::IoOut(addr, data) => {
                    if let Some(vmmops) = self.vmmops.load_full() {
                        return vmmops
                            .pio_write(addr.into(), data)
                            .map(|_| cpu::VmExit::Ignore)
                            .map_err(|e| cpu::HypervisorCpuError::RunVcpu(e.into()));
                    }

                    Ok(cpu::VmExit::IoOut(addr, data))
                }
                #[cfg(target_arch = "x86_64")]
                VcpuExit::IoapicEoi(vector) => Ok(cpu::VmExit::IoapicEoi(vector)),
                #[cfg(target_arch = "x86_64")]
                VcpuExit::Shutdown | VcpuExit::Hlt => Ok(cpu::VmExit::Reset),

                #[cfg(target_arch = "aarch64")]
                VcpuExit::SystemEvent(event_type, flags) => {
                    use kvm_bindings::{KVM_SYSTEM_EVENT_RESET, KVM_SYSTEM_EVENT_SHUTDOWN};
                    // On Aarch64, when the VM is shutdown, run() returns
                    // VcpuExit::SystemEvent with reason KVM_SYSTEM_EVENT_SHUTDOWN
                    if event_type == KVM_SYSTEM_EVENT_RESET {
                        Ok(cpu::VmExit::Reset)
                    } else if event_type == KVM_SYSTEM_EVENT_SHUTDOWN {
                        Ok(cpu::VmExit::Shutdown)
                    } else {
                        Err(cpu::HypervisorCpuError::RunVcpu(anyhow!(
                            "Unexpected system event with type 0x{:x}, flags 0x{:x}",
                            event_type,
                            flags
                        )))
                    }
                }

                VcpuExit::MmioRead(addr, data) => {
                    if let Some(vmmops) = self.vmmops.load_full() {
                        return vmmops
                            .mmio_read(addr, data)
                            .map(|_| cpu::VmExit::Ignore)
                            .map_err(|e| cpu::HypervisorCpuError::RunVcpu(e.into()));
                    }

                    Ok(cpu::VmExit::MmioRead(addr, data))
                }
                VcpuExit::MmioWrite(addr, data) => {
                    if let Some(vmmops) = self.vmmops.load_full() {
                        return vmmops
                            .mmio_write(addr, data)
                            .map(|_| cpu::VmExit::Ignore)
                            .map_err(|e| cpu::HypervisorCpuError::RunVcpu(e.into()));
                    }

                    Ok(cpu::VmExit::MmioWrite(addr, data))
                }
                VcpuExit::Hyperv => Ok(cpu::VmExit::Hyperv),

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
    fn set_reg(&self, reg_id: u64, data: u64) -> cpu::Result<()> {
        self.fd
            .set_one_reg(reg_id, data)
            .map_err(|e| cpu::HypervisorCpuError::SetRegister(e.into()))
    }
    ///
    /// Gets the value of one register for this vCPU.
    ///
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    fn get_reg(&self, reg_id: u64) -> cpu::Result<u64> {
        self.fd
            .get_one_reg(reg_id)
            .map_err(|e| cpu::HypervisorCpuError::GetRegister(e.into()))
    }
    ///
    /// Gets a list of the guest registers that are supported for the
    /// KVM_GET_ONE_REG/KVM_SET_ONE_REG calls.
    ///
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    fn get_reg_list(&self, reg_list: &mut RegList) -> cpu::Result<()> {
        self.fd
            .get_reg_list(reg_list)
            .map_err(|e| cpu::HypervisorCpuError::GetRegList(e.into()))
    }
    ///
    /// Save the state of the core registers.
    ///
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    fn core_registers(&self, state: &mut StandardRegisters) -> cpu::Result<()> {
        let mut off = offset__of!(user_pt_regs, regs);
        // There are 31 user_pt_regs:
        // https://elixir.free-electrons.com/linux/v4.14.174/source/arch/arm64/include/uapi/asm/ptrace.h#L72
        // These actually are the general-purpose registers of the Armv8-a
        // architecture (i.e x0-x30 if used as a 64bit register or w0-30 when used as a 32bit register).
        for i in 0..31 {
            state.regs.regs[i] = self
                .fd
                .get_one_reg(arm64_core_reg_id!(KVM_REG_SIZE_U64, off))
                .map_err(|e| cpu::HypervisorCpuError::GetCoreRegister(e.into()))?;
            off += std::mem::size_of::<u64>();
        }

        // We are now entering the "Other register" section of the ARMv8-a architecture.
        // First one, stack pointer.
        let off = offset__of!(user_pt_regs, sp);
        state.regs.sp = self
            .fd
            .get_one_reg(arm64_core_reg_id!(KVM_REG_SIZE_U64, off))
            .map_err(|e| cpu::HypervisorCpuError::GetCoreRegister(e.into()))?;

        // Second one, the program counter.
        let off = offset__of!(user_pt_regs, pc);
        state.regs.pc = self
            .fd
            .get_one_reg(arm64_core_reg_id!(KVM_REG_SIZE_U64, off))
            .map_err(|e| cpu::HypervisorCpuError::GetCoreRegister(e.into()))?;

        // Next is the processor state.
        let off = offset__of!(user_pt_regs, pstate);
        state.regs.pstate = self
            .fd
            .get_one_reg(arm64_core_reg_id!(KVM_REG_SIZE_U64, off))
            .map_err(|e| cpu::HypervisorCpuError::GetCoreRegister(e.into()))?;

        // The stack pointer associated with EL1
        let off = offset__of!(kvm_regs, sp_el1);
        state.sp_el1 = self
            .fd
            .get_one_reg(arm64_core_reg_id!(KVM_REG_SIZE_U64, off))
            .map_err(|e| cpu::HypervisorCpuError::GetCoreRegister(e.into()))?;

        // Exception Link Register for EL1, when taking an exception to EL1, this register
        // holds the address to which to return afterwards.
        let off = offset__of!(kvm_regs, elr_el1);
        state.elr_el1 = self
            .fd
            .get_one_reg(arm64_core_reg_id!(KVM_REG_SIZE_U64, off))
            .map_err(|e| cpu::HypervisorCpuError::GetCoreRegister(e.into()))?;

        // Saved Program Status Registers, there are 5 of them used in the kernel.
        let mut off = offset__of!(kvm_regs, spsr);
        for i in 0..KVM_NR_SPSR as usize {
            state.spsr[i] = self
                .fd
                .get_one_reg(arm64_core_reg_id!(KVM_REG_SIZE_U64, off))
                .map_err(|e| cpu::HypervisorCpuError::GetCoreRegister(e.into()))?;
            off += std::mem::size_of::<u64>();
        }

        // Now moving on to floting point registers which are stored in the user_fpsimd_state in the kernel:
        // https://elixir.free-electrons.com/linux/v4.9.62/source/arch/arm64/include/uapi/asm/kvm.h#L53
        let mut off = offset__of!(kvm_regs, fp_regs) + offset__of!(user_fpsimd_state, vregs);
        for i in 0..32 {
            state.fp_regs.vregs[i][0] = self
                .fd
                .get_one_reg(arm64_core_reg_id!(KVM_REG_SIZE_U128, off))
                .map_err(|e| cpu::HypervisorCpuError::GetCoreRegister(e.into()))?;
            off += mem::size_of::<u128>();
        }

        // Floating-point Status Register
        let off = offset__of!(kvm_regs, fp_regs) + offset__of!(user_fpsimd_state, fpsr);
        state.fp_regs.fpsr = self
            .fd
            .get_one_reg(arm64_core_reg_id!(KVM_REG_SIZE_U32, off))
            .map_err(|e| cpu::HypervisorCpuError::GetCoreRegister(e.into()))?
            as u32;

        // Floating-point Control Register
        let off = offset__of!(kvm_regs, fp_regs) + offset__of!(user_fpsimd_state, fpcr);
        state.fp_regs.fpcr = self
            .fd
            .get_one_reg(arm64_core_reg_id!(KVM_REG_SIZE_U32, off))
            .map_err(|e| cpu::HypervisorCpuError::GetCoreRegister(e.into()))?
            as u32;
        Ok(())
    }
    ///
    /// Restore the state of the core registers.
    ///
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    fn set_core_registers(&self, state: &StandardRegisters) -> cpu::Result<()> {
        // The function follows the exact identical order from `state`. Look there
        // for some additional info on registers.
        let mut off = offset__of!(user_pt_regs, regs);
        for i in 0..31 {
            self.fd
                .set_one_reg(
                    arm64_core_reg_id!(KVM_REG_SIZE_U64, off),
                    state.regs.regs[i],
                )
                .map_err(|e| cpu::HypervisorCpuError::SetCoreRegister(e.into()))?;
            off += std::mem::size_of::<u64>();
        }

        let off = offset__of!(user_pt_regs, sp);
        self.fd
            .set_one_reg(arm64_core_reg_id!(KVM_REG_SIZE_U64, off), state.regs.sp)
            .map_err(|e| cpu::HypervisorCpuError::SetCoreRegister(e.into()))?;

        let off = offset__of!(user_pt_regs, pc);
        self.fd
            .set_one_reg(arm64_core_reg_id!(KVM_REG_SIZE_U64, off), state.regs.pc)
            .map_err(|e| cpu::HypervisorCpuError::SetCoreRegister(e.into()))?;

        let off = offset__of!(user_pt_regs, pstate);
        self.fd
            .set_one_reg(arm64_core_reg_id!(KVM_REG_SIZE_U64, off), state.regs.pstate)
            .map_err(|e| cpu::HypervisorCpuError::SetCoreRegister(e.into()))?;

        let off = offset__of!(kvm_regs, sp_el1);
        self.fd
            .set_one_reg(arm64_core_reg_id!(KVM_REG_SIZE_U64, off), state.sp_el1)
            .map_err(|e| cpu::HypervisorCpuError::SetCoreRegister(e.into()))?;

        let off = offset__of!(kvm_regs, elr_el1);
        self.fd
            .set_one_reg(arm64_core_reg_id!(KVM_REG_SIZE_U64, off), state.elr_el1)
            .map_err(|e| cpu::HypervisorCpuError::SetCoreRegister(e.into()))?;

        let mut off = offset__of!(kvm_regs, spsr);
        for i in 0..KVM_NR_SPSR as usize {
            self.fd
                .set_one_reg(arm64_core_reg_id!(KVM_REG_SIZE_U64, off), state.spsr[i])
                .map_err(|e| cpu::HypervisorCpuError::SetCoreRegister(e.into()))?;
            off += std::mem::size_of::<u64>();
        }

        let mut off = offset__of!(kvm_regs, fp_regs) + offset__of!(user_fpsimd_state, vregs);
        for i in 0..32 {
            self.fd
                .set_one_reg(
                    arm64_core_reg_id!(KVM_REG_SIZE_U128, off),
                    state.fp_regs.vregs[i][0],
                )
                .map_err(|e| cpu::HypervisorCpuError::SetCoreRegister(e.into()))?;
            off += mem::size_of::<u128>();
        }

        let off = offset__of!(kvm_regs, fp_regs) + offset__of!(user_fpsimd_state, fpsr);
        self.fd
            .set_one_reg(
                arm64_core_reg_id!(KVM_REG_SIZE_U32, off),
                state.fp_regs.fpsr as u64,
            )
            .map_err(|e| cpu::HypervisorCpuError::SetCoreRegister(e.into()))?;

        let off = offset__of!(kvm_regs, fp_regs) + offset__of!(user_fpsimd_state, fpcr);
        self.fd
            .set_one_reg(
                arm64_core_reg_id!(KVM_REG_SIZE_U32, off),
                state.fp_regs.fpcr as u64,
            )
            .map_err(|e| cpu::HypervisorCpuError::SetCoreRegister(e.into()))?;
        Ok(())
    }
    ///
    /// Save the state of the system registers.
    ///
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    fn system_registers(&self, state: &mut Vec<Register>) -> cpu::Result<()> {
        // Call KVM_GET_REG_LIST to get all registers available to the guest. For ArmV8 there are
        // around 500 registers.
        let mut reg_list = RegList::new(512);
        self.fd
            .get_reg_list(&mut reg_list)
            .map_err(|e| cpu::HypervisorCpuError::GetRegList(e.into()))?;

        // At this point reg_list should contain: core registers and system registers.
        // The register list contains the number of registers and their ids. We will be needing to
        // call KVM_GET_ONE_REG on each id in order to save all of them. We carve out from the list
        // the core registers which are represented in the kernel by kvm_regs structure and for which
        // we can calculate the id based on the offset in the structure.

        reg_list.retain(|regid| *regid != 0);
        reg_list.as_slice().to_vec().sort_unstable();

        reg_list.retain(|regid| is_system_register(*regid));

        // Now, for the rest of the registers left in the previously fetched register list, we are
        // simply calling KVM_GET_ONE_REG.
        let indices = reg_list.as_slice();
        for (_pos, index) in indices.iter().enumerate() {
            if _pos > 230 {
                break;
            }
            state.push(kvm_bindings::kvm_one_reg {
                id: *index,
                addr: self
                    .fd
                    .get_one_reg(*index)
                    .map_err(|e| cpu::HypervisorCpuError::GetSysRegister(e.into()))?,
            });
        }

        Ok(())
    }
    ///
    /// Restore the state of the system registers.
    ///
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    fn set_system_registers(&self, state: &[Register]) -> cpu::Result<()> {
        for reg in state {
            self.fd
                .set_one_reg(reg.id, reg.addr)
                .map_err(|e| cpu::HypervisorCpuError::SetSysRegister(e.into()))?;
        }
        Ok(())
    }
    ///
    /// Read the MPIDR - Multiprocessor Affinity Register.
    ///
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    fn read_mpidr(&self) -> cpu::Result<u64> {
        self.fd
            .get_one_reg(MPIDR_EL1)
            .map_err(|e| cpu::HypervisorCpuError::GetSysRegister(e.into()))
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
        let cpuid = self.get_cpuid2(kvm_bindings::KVM_MAX_CPUID_ENTRIES)?;
        let mp_state = self.get_mp_state()?;
        let regs = self.get_regs()?;
        let sregs = self.get_sregs()?;
        let xsave = self.get_xsave()?;
        let xcrs = self.get_xcrs()?;
        let lapic_state = self.get_lapic()?;
        let fpu = self.get_fpu()?;

        // Try to get all MSRs based on the list previously retrieved from KVM.
        // If the number of MSRs obtained from GET_MSRS is different from the
        // expected amount, we fallback onto a slower method by getting MSRs
        // by chunks. This is the only way to make sure we try to get as many
        // MSRs as possible, even if some MSRs are not supported.
        let mut msr_entries = self.msrs.clone();

        // Save extra MSRs if the Hyper-V synthetic interrupt controller is
        // emulated.
        if self.hyperv_synic.load(Ordering::SeqCst) {
            let hyperv_synic_msrs = vec![
                0x40000020, 0x40000021, 0x40000080, 0x40000081, 0x40000082, 0x40000083, 0x40000084,
                0x40000090, 0x40000091, 0x40000092, 0x40000093, 0x40000094, 0x40000095, 0x40000096,
                0x40000097, 0x40000098, 0x40000099, 0x4000009a, 0x4000009b, 0x4000009c, 0x4000009d,
                0x4000009f, 0x400000b0, 0x400000b1, 0x400000b2, 0x400000b3, 0x400000b4, 0x400000b5,
                0x400000b6, 0x400000b7,
            ];
            for index in hyperv_synic_msrs {
                let msr = kvm_msr_entry {
                    index,
                    ..Default::default()
                };
                msr_entries.push(msr).unwrap();
            }
        }

        let expected_num_msrs = msr_entries.as_fam_struct_ref().nmsrs as usize;
        let num_msrs = self.get_msrs(&mut msr_entries)?;
        let msrs = if num_msrs != expected_num_msrs {
            let mut faulty_msr_index = num_msrs;
            let mut msr_entries_tmp =
                MsrEntries::from_entries(&msr_entries.as_slice()[..faulty_msr_index]);

            loop {
                warn!(
                    "Detected faulty MSR 0x{:x} while getting MSRs",
                    msr_entries.as_slice()[faulty_msr_index].index
                );

                let start_pos = faulty_msr_index + 1;
                let mut sub_msr_entries =
                    MsrEntries::from_entries(&msr_entries.as_slice()[start_pos..]);
                let expected_num_msrs = sub_msr_entries.as_fam_struct_ref().nmsrs as usize;
                let num_msrs = self.get_msrs(&mut sub_msr_entries)?;

                for i in 0..num_msrs {
                    msr_entries_tmp
                        .push(sub_msr_entries.as_slice()[i])
                        .map_err(|e| {
                            cpu::HypervisorCpuError::GetMsrEntries(anyhow!(
                                "Failed adding MSR entries: {:?}",
                                e
                            ))
                        })?;
                }

                if num_msrs == expected_num_msrs {
                    break;
                }

                faulty_msr_index = start_pos + num_msrs;
            }

            msr_entries_tmp
        } else {
            msr_entries
        };

        let vcpu_events = self.get_vcpu_events()?;

        Ok(CpuState {
            cpuid,
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
    ///
    /// Get the current AArch64 CPU state
    ///
    #[cfg(target_arch = "aarch64")]
    fn state(&self) -> cpu::Result<CpuState> {
        let mut state = CpuState::default();
        // Get this vCPUs multiprocessing state.
        state.mp_state = self.get_mp_state()?;
        self.core_registers(&mut state.core_regs)?;
        self.system_registers(&mut state.sys_regs)?;
        state.mpidr = self.read_mpidr()?;

        Ok(state)
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
        self.set_cpuid2(&state.cpuid)?;
        self.set_mp_state(state.mp_state)?;
        self.set_regs(&state.regs)?;
        self.set_sregs(&state.sregs)?;
        self.set_xsave(&state.xsave)?;
        self.set_xcrs(&state.xcrs)?;
        self.set_lapic(&state.lapic_state)?;
        self.set_fpu(&state.fpu)?;

        // Try to set all MSRs previously stored.
        // If the number of MSRs set from SET_MSRS is different from the
        // expected amount, we fallback onto a slower method by setting MSRs
        // by chunks. This is the only way to make sure we try to set as many
        // MSRs as possible, even if some MSRs are not supported.
        let expected_num_msrs = state.msrs.as_fam_struct_ref().nmsrs as usize;
        let num_msrs = self.set_msrs(&state.msrs)?;
        if num_msrs != expected_num_msrs {
            let mut faulty_msr_index = num_msrs;

            loop {
                warn!(
                    "Detected faulty MSR 0x{:x} while setting MSRs",
                    state.msrs.as_slice()[faulty_msr_index].index
                );

                let start_pos = faulty_msr_index + 1;
                let sub_msr_entries = MsrEntries::from_entries(&state.msrs.as_slice()[start_pos..]);
                let expected_num_msrs = sub_msr_entries.as_fam_struct_ref().nmsrs as usize;
                let num_msrs = self.set_msrs(&sub_msr_entries)?;

                if num_msrs == expected_num_msrs {
                    break;
                }

                faulty_msr_index = start_pos + num_msrs;
            }
        }

        self.set_vcpu_events(&state.vcpu_events)?;

        Ok(())
    }
    ///
    /// Restore the previously saved AArch64 CPU state
    ///
    #[cfg(target_arch = "aarch64")]
    fn set_state(&self, state: &CpuState) -> cpu::Result<()> {
        self.set_core_registers(&state.core_regs)?;
        self.set_system_registers(&state.sys_regs)?;
        self.set_mp_state(state.mp_state)?;

        Ok(())
    }
}

/// Device struct for KVM
pub struct KvmDevice {
    fd: DeviceFd,
}

impl device::Device for KvmDevice {
    ///
    /// Set device attribute
    ///
    fn set_device_attr(&self, attr: &DeviceAttr) -> device::Result<()> {
        self.fd
            .set_device_attr(attr)
            .map_err(|e| device::HypervisorDeviceError::SetDeviceAttribute(e.into()))
    }
    ///
    /// Get device attribute
    ///
    fn get_device_attr(&self, attr: &mut DeviceAttr) -> device::Result<()> {
        self.fd
            .get_device_attr(attr)
            .map_err(|e| device::HypervisorDeviceError::GetDeviceAttribute(e.into()))
    }
}

impl AsRawFd for KvmDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}
