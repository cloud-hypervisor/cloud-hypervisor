// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2020, Microsoft Corporation
//

use std::any::Any;
use std::collections::HashMap;
#[cfg(feature = "sev_snp")]
use std::num::NonZeroUsize;
use std::sync::{Arc, RwLock};

#[cfg(feature = "sev_snp")]
use arc_swap::ArcSwap;
use mshv_bindings::*;
#[cfg(target_arch = "x86_64")]
use mshv_ioctls::InterruptRequest;
use mshv_ioctls::{set_registers_64, Mshv, NoDatamatch, VcpuFd, VmFd, VmType};
use vfio_ioctls::VfioDeviceFd;
use vm::DataMatch;
#[cfg(feature = "sev_snp")]
use vm_memory::bitmap::AtomicBitmap;

#[cfg(target_arch = "aarch64")]
use crate::arch::aarch64::regs::{
    AARCH64_ARCH_TIMER_VIRT_IRQ, AARCH64_MIN_PPI_IRQ, AARCH64_PMU_IRQ,
};
#[cfg(target_arch = "x86_64")]
use crate::arch::emulator::PlatformEmulator;
#[cfg(target_arch = "x86_64")]
use crate::arch::x86::emulator::Emulator;
#[cfg(target_arch = "aarch64")]
use crate::mshv::aarch64::emulator;
use crate::mshv::emulator::MshvEmulatorContext;
use crate::vm::{self, InterruptSourceConfig, VmOps};
use crate::{cpu, hypervisor, vec_with_array_field, HypervisorType};
#[cfg(feature = "sev_snp")]
mod snp_constants;
// x86_64 dependencies
#[cfg(target_arch = "x86_64")]
pub mod x86_64;
// aarch64 dependencies
#[cfg(target_arch = "aarch64")]
pub mod aarch64;
use std::os::unix::io::AsRawFd;
#[cfg(target_arch = "aarch64")]
use std::sync::Mutex;

#[cfg(target_arch = "aarch64")]
use aarch64::gic::{MshvGicV2M, BASE_SPI_IRQ};
#[cfg(target_arch = "aarch64")]
pub use aarch64::VcpuMshvState;
#[cfg(feature = "sev_snp")]
use igvm_defs::IGVM_VHS_SNP_ID_BLOCK;
#[cfg(feature = "sev_snp")]
use snp_constants::*;
use vmm_sys_util::eventfd::EventFd;
#[cfg(target_arch = "x86_64")]
pub use x86_64::*;
#[cfg(target_arch = "x86_64")]
pub use x86_64::{emulator, VcpuMshvState};
///
/// Export generically-named wrappers of mshv-bindings for Unix-based platforms
///
pub use {
    mshv_bindings::mshv_create_device as CreateDevice,
    mshv_bindings::mshv_device_attr as DeviceAttr, mshv_ioctls, mshv_ioctls::DeviceFd,
};

#[cfg(target_arch = "aarch64")]
use crate::arch::aarch64::gic::{Vgic, VgicConfig};
#[cfg(target_arch = "aarch64")]
use crate::arch::aarch64::regs;
#[cfg(target_arch = "x86_64")]
use crate::arch::x86::{CpuIdEntry, FpuState, MsrEntry};
#[cfg(target_arch = "x86_64")]
use crate::ClockData;
use crate::{
    CpuState, IoEventAddress, IrqRoutingEntry, MpState, UserMemoryRegion,
    USER_MEMORY_REGION_ADJUSTABLE, USER_MEMORY_REGION_EXECUTE, USER_MEMORY_REGION_READ,
    USER_MEMORY_REGION_WRITE,
};

pub const PAGE_SHIFT: usize = 12;

impl From<mshv_user_mem_region> for UserMemoryRegion {
    fn from(region: mshv_user_mem_region) -> Self {
        let mut flags: u32 = USER_MEMORY_REGION_READ | USER_MEMORY_REGION_ADJUSTABLE;
        if region.flags & (1 << MSHV_SET_MEM_BIT_WRITABLE) != 0 {
            flags |= USER_MEMORY_REGION_WRITE;
        }
        if region.flags & (1 << MSHV_SET_MEM_BIT_EXECUTABLE) != 0 {
            flags |= USER_MEMORY_REGION_EXECUTE;
        }

        UserMemoryRegion {
            guest_phys_addr: (region.guest_pfn << PAGE_SHIFT as u64)
                + (region.userspace_addr & ((1 << PAGE_SHIFT) - 1)),
            memory_size: region.size,
            userspace_addr: region.userspace_addr,
            flags,
            ..Default::default()
        }
    }
}

#[cfg(target_arch = "x86_64")]
impl From<MshvClockData> for ClockData {
    fn from(d: MshvClockData) -> Self {
        ClockData::Mshv(d)
    }
}

#[cfg(target_arch = "x86_64")]
impl From<ClockData> for MshvClockData {
    fn from(ms: ClockData) -> Self {
        match ms {
            ClockData::Mshv(s) => s,
            /* Needed in case other hypervisors are enabled */
            #[allow(unreachable_patterns)]
            _ => unreachable!("MSHV clock data is not valid"),
        }
    }
}

impl From<UserMemoryRegion> for mshv_user_mem_region {
    fn from(region: UserMemoryRegion) -> Self {
        let mut flags: u8 = 0;
        if region.flags & USER_MEMORY_REGION_WRITE != 0 {
            flags |= 1 << MSHV_SET_MEM_BIT_WRITABLE;
        }
        if region.flags & USER_MEMORY_REGION_EXECUTE != 0 {
            flags |= 1 << MSHV_SET_MEM_BIT_EXECUTABLE;
        }

        mshv_user_mem_region {
            guest_pfn: region.guest_phys_addr >> PAGE_SHIFT,
            size: region.memory_size,
            userspace_addr: region.userspace_addr,
            flags,
            ..Default::default()
        }
    }
}

impl From<mshv_ioctls::IoEventAddress> for IoEventAddress {
    fn from(a: mshv_ioctls::IoEventAddress) -> Self {
        match a {
            mshv_ioctls::IoEventAddress::Pio(x) => Self::Pio(x),
            mshv_ioctls::IoEventAddress::Mmio(x) => Self::Mmio(x),
        }
    }
}

impl From<IoEventAddress> for mshv_ioctls::IoEventAddress {
    fn from(a: IoEventAddress) -> Self {
        match a {
            IoEventAddress::Pio(x) => Self::Pio(x),
            IoEventAddress::Mmio(x) => Self::Mmio(x),
        }
    }
}

impl From<VcpuMshvState> for CpuState {
    fn from(s: VcpuMshvState) -> Self {
        CpuState::Mshv(s)
    }
}

impl From<CpuState> for VcpuMshvState {
    fn from(s: CpuState) -> Self {
        match s {
            CpuState::Mshv(s) => s,
            /* Needed in case other hypervisors are enabled */
            #[allow(unreachable_patterns)]
            _ => panic!("CpuState is not valid"),
        }
    }
}

impl From<mshv_bindings::StandardRegisters> for crate::StandardRegisters {
    fn from(s: mshv_bindings::StandardRegisters) -> Self {
        crate::StandardRegisters::Mshv(s)
    }
}

impl From<crate::StandardRegisters> for mshv_bindings::StandardRegisters {
    fn from(e: crate::StandardRegisters) -> Self {
        match e {
            crate::StandardRegisters::Mshv(e) => e,
            /* Needed in case other hypervisors are enabled */
            #[allow(unreachable_patterns)]
            _ => panic!("StandardRegisters are not valid"),
        }
    }
}

impl From<mshv_user_irq_entry> for IrqRoutingEntry {
    fn from(s: mshv_user_irq_entry) -> Self {
        IrqRoutingEntry::Mshv(s)
    }
}

impl From<IrqRoutingEntry> for mshv_user_irq_entry {
    fn from(e: IrqRoutingEntry) -> Self {
        match e {
            IrqRoutingEntry::Mshv(e) => e,
            /* Needed in case other hypervisors are enabled */
            #[allow(unreachable_patterns)]
            _ => panic!("IrqRoutingEntry is not valid"),
        }
    }
}

#[cfg(target_arch = "aarch64")]
impl From<mshv_bindings::MshvRegList> for crate::RegList {
    fn from(s: mshv_bindings::MshvRegList) -> Self {
        crate::RegList::Mshv(s)
    }
}

#[cfg(target_arch = "aarch64")]
impl From<crate::RegList> for mshv_bindings::MshvRegList {
    fn from(e: crate::RegList) -> Self {
        match e {
            crate::RegList::Mshv(e) => e,
            /* Needed in case other hypervisors are enabled */
            #[allow(unreachable_patterns)]
            _ => panic!("RegList is not valid"),
        }
    }
}

#[cfg(target_arch = "aarch64")]
impl From<mshv_bindings::MshvVcpuInit> for crate::VcpuInit {
    fn from(s: mshv_bindings::MshvVcpuInit) -> Self {
        crate::VcpuInit::Mshv(s)
    }
}

#[cfg(target_arch = "aarch64")]
impl From<crate::VcpuInit> for mshv_bindings::MshvVcpuInit {
    fn from(e: crate::VcpuInit) -> Self {
        match e {
            crate::VcpuInit::Mshv(e) => e,
            /* Needed in case other hypervisors are enabled */
            #[allow(unreachable_patterns)]
            _ => panic!("VcpuInit is not valid"),
        }
    }
}

struct MshvDirtyLogSlot {
    guest_pfn: u64,
    memory_size: u64,
}

/// Wrapper over mshv system ioctls.
pub struct MshvHypervisor {
    mshv: Mshv,
}

impl MshvHypervisor {
    #[cfg(target_arch = "x86_64")]
    ///
    /// Retrieve the list of MSRs supported by MSHV.
    ///
    fn get_msr_list(&self) -> hypervisor::Result<Vec<u32>> {
        self.mshv
            .get_msr_index_list()
            .map_err(|e| hypervisor::HypervisorError::GetMsrList(e.into()))
    }

    fn create_vm_with_type_and_memory_int(
        &self,
        vm_type: u64,
        #[cfg(feature = "sev_snp")] _mem_size: Option<u64>,
    ) -> hypervisor::Result<Arc<dyn crate::Vm>> {
        let mshv_vm_type: VmType = match VmType::try_from(vm_type) {
            Ok(vm_type) => vm_type,
            Err(_) => return Err(hypervisor::HypervisorError::UnsupportedVmType()),
        };
        let fd: VmFd;
        loop {
            match self.mshv.create_vm_with_type(mshv_vm_type) {
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
            let mut msrs: Vec<MsrEntry> = vec![
                MsrEntry {
                    ..Default::default()
                };
                msr_list.len()
            ];
            for (pos, index) in msr_list.iter().enumerate() {
                msrs[pos].index = *index;
            }

            Ok(Arc::new(MshvVm {
                fd: vm_fd,
                msrs,
                dirty_log_slots: Arc::new(RwLock::new(HashMap::new())),
                #[cfg(feature = "sev_snp")]
                sev_snp_enabled: mshv_vm_type == VmType::Snp,
                #[cfg(feature = "sev_snp")]
                host_access_pages: ArcSwap::new(
                    AtomicBitmap::new(
                        _mem_size.unwrap_or_default() as usize,
                        NonZeroUsize::new(HV_PAGE_SIZE).unwrap(),
                    )
                    .into(),
                ),
            }))
        }

        #[cfg(target_arch = "aarch64")]
        {
            Ok(Arc::new(MshvVm {
                fd: vm_fd,
                dirty_log_slots: Arc::new(RwLock::new(HashMap::new())),
            }))
        }
    }
}

impl MshvHypervisor {
    /// Create a hypervisor based on Mshv
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> hypervisor::Result<Arc<dyn hypervisor::Hypervisor>> {
        let mshv_obj =
            Mshv::new().map_err(|e| hypervisor::HypervisorError::HypervisorCreate(e.into()))?;
        Ok(Arc::new(MshvHypervisor { mshv: mshv_obj }))
    }
    /// Check if the hypervisor is available
    pub fn is_available() -> hypervisor::Result<bool> {
        match std::fs::metadata("/dev/mshv") {
            Ok(_) => Ok(true),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(hypervisor::HypervisorError::HypervisorAvailableCheck(
                err.into(),
            )),
        }
    }
}

/// Implementation of Hypervisor trait for Mshv
///
/// # Examples
///
/// ```
/// use hypervisor::mshv::MshvHypervisor;
/// use std::sync::Arc;
/// let mshv = MshvHypervisor::new().unwrap();
/// let hypervisor = Arc::new(mshv);
/// let vm = hypervisor.create_vm().expect("new VM fd creation failed");
/// ```
impl hypervisor::Hypervisor for MshvHypervisor {
    ///
    /// Returns the type of the hypervisor
    ///
    fn hypervisor_type(&self) -> HypervisorType {
        HypervisorType::Mshv
    }

    ///
    /// Create a Vm of a specific type using the underlying hypervisor, passing memory size
    /// Return a hypervisor-agnostic Vm trait object
    ///
    /// # Examples
    ///
    /// ```
    /// use hypervisor::kvm::KvmHypervisor;
    /// use hypervisor::kvm::KvmVm;
    /// let hypervisor = KvmHypervisor::new().unwrap();
    /// let vm = hypervisor.create_vm_with_type(0, 512*1024*1024).unwrap();
    /// ```
    fn create_vm_with_type_and_memory(
        &self,
        vm_type: u64,
        #[cfg(feature = "sev_snp")] _mem_size: u64,
    ) -> hypervisor::Result<Arc<dyn vm::Vm>> {
        self.create_vm_with_type_and_memory_int(
            vm_type,
            #[cfg(feature = "sev_snp")]
            Some(_mem_size),
        )
    }

    fn create_vm_with_type(&self, vm_type: u64) -> hypervisor::Result<Arc<dyn crate::Vm>> {
        self.create_vm_with_type_and_memory_int(
            vm_type,
            #[cfg(feature = "sev_snp")]
            None,
        )
    }

    /// Create a mshv vm object and return the object as Vm trait object
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate hypervisor;
    /// use hypervisor::mshv::MshvHypervisor;
    /// use hypervisor::mshv::MshvVm;
    /// let hypervisor = MshvHypervisor::new().unwrap();
    /// let vm = hypervisor.create_vm().unwrap();
    /// ```
    fn create_vm(&self) -> hypervisor::Result<Arc<dyn vm::Vm>> {
        let vm_type = 0;
        self.create_vm_with_type(vm_type)
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Get the supported CpuID
    ///
    fn get_supported_cpuid(&self) -> hypervisor::Result<Vec<CpuIdEntry>> {
        let mut cpuid = Vec::new();
        let functions: [u32; 2] = [0x1, 0xb];

        for function in functions {
            cpuid.push(CpuIdEntry {
                function,
                ..Default::default()
            });
        }
        Ok(cpuid)
    }

    /// Get maximum number of vCPUs
    fn get_max_vcpus(&self) -> u32 {
        // TODO: Using HV_MAXIMUM_PROCESSORS would be better
        // but the ioctl API is limited to u8
        256
    }

    fn get_guest_debug_hw_bps(&self) -> usize {
        0
    }

    #[cfg(target_arch = "aarch64")]
    ///
    /// Retrieve AArch64 host maximum IPA size supported by MSHV.
    ///
    fn get_host_ipa_limit(&self) -> i32 {
        let host_ipa = self.mshv.get_host_partition_property(
            hv_partition_property_code_HV_PARTITION_PROPERTY_PHYSICAL_ADDRESS_WIDTH,
        );

        match host_ipa {
            Ok(ipa) => ipa.try_into().unwrap(),
            Err(e) => {
                panic!("Failed to get host IPA limit: {e:?}");
            }
        }
    }
}

#[cfg(feature = "sev_snp")]
struct Ghcb(*mut svm_ghcb_base);

#[cfg(feature = "sev_snp")]
// SAFETY: struct is based on GHCB page in the hypervisor,
// safe to Send across threads
unsafe impl Send for Ghcb {}

#[cfg(feature = "sev_snp")]
// SAFETY: struct is based on GHCB page in the hypervisor,
// safe to Sync across threads as this is only required for Vcpu trait
// functionally not used anyway
unsafe impl Sync for Ghcb {}

/// Vcpu struct for Microsoft Hypervisor
#[allow(dead_code)]
pub struct MshvVcpu {
    fd: VcpuFd,
    vp_index: u8,
    #[cfg(target_arch = "x86_64")]
    cpuid: Vec<CpuIdEntry>,
    #[cfg(target_arch = "x86_64")]
    msrs: Vec<MsrEntry>,
    vm_ops: Option<Arc<dyn vm::VmOps>>,
    vm_fd: Arc<VmFd>,
    #[cfg(feature = "sev_snp")]
    ghcb: Option<Ghcb>,
    #[cfg(feature = "sev_snp")]
    host_access_pages: ArcSwap<AtomicBitmap>,
}

/// Implementation of Vcpu trait for Microsoft Hypervisor
///
/// # Examples
///
/// ```
/// use hypervisor::mshv::MshvHypervisor;
/// use std::sync::Arc;
/// let mshv = MshvHypervisor::new().unwrap();
/// let hypervisor = Arc::new(mshv);
/// let vm = hypervisor.create_vm().expect("new VM fd creation failed");
/// let vcpu = vm.create_vcpu(0, None).unwrap();
/// ```
impl cpu::Vcpu for MshvVcpu {
    ///
    /// Returns StandardRegisters with default value set
    ///
    fn create_standard_regs(&self) -> crate::StandardRegisters {
        mshv_bindings::StandardRegisters::default().into()
    }
    ///
    /// Returns the vCPU general purpose registers.
    ///
    fn get_regs(&self) -> cpu::Result<crate::StandardRegisters> {
        Ok(self
            .fd
            .get_regs()
            .map_err(|e| cpu::HypervisorCpuError::GetStandardRegs(e.into()))?
            .into())
    }

    ///
    /// Sets the vCPU general purpose registers.
    ///
    fn set_regs(&self, regs: &crate::StandardRegisters) -> cpu::Result<()> {
        let regs = (*regs).into();
        self.fd
            .set_regs(&regs)
            .map_err(|e| cpu::HypervisorCpuError::SetStandardRegs(e.into()))
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns the vCPU special registers.
    ///
    fn get_sregs(&self) -> cpu::Result<crate::arch::x86::SpecialRegisters> {
        Ok(self
            .fd
            .get_sregs()
            .map_err(|e| cpu::HypervisorCpuError::GetSpecialRegs(e.into()))?
            .into())
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// Sets the vCPU special registers.
    ///
    fn set_sregs(&self, sregs: &crate::arch::x86::SpecialRegisters) -> cpu::Result<()> {
        let sregs = (*sregs).into();
        self.fd
            .set_sregs(&sregs)
            .map_err(|e| cpu::HypervisorCpuError::SetSpecialRegs(e.into()))
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns the floating point state (FPU) from the vCPU.
    ///
    fn get_fpu(&self) -> cpu::Result<FpuState> {
        Ok(self
            .fd
            .get_fpu()
            .map_err(|e| cpu::HypervisorCpuError::GetFloatingPointRegs(e.into()))?
            .into())
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// Set the floating point state (FPU) of a vCPU.
    ///
    fn set_fpu(&self, fpu: &FpuState) -> cpu::Result<()> {
        let fpu: mshv_bindings::FloatingPointUnit = (*fpu).clone().into();
        self.fd
            .set_fpu(&fpu)
            .map_err(|e| cpu::HypervisorCpuError::SetFloatingPointRegs(e.into()))
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns the model-specific registers (MSR) for this vCPU.
    ///
    fn get_msrs(&self, msrs: &mut Vec<MsrEntry>) -> cpu::Result<usize> {
        let mshv_msrs: Vec<msr_entry> = msrs.iter().map(|e| (*e).into()).collect();
        let mut mshv_msrs = MsrEntries::from_entries(&mshv_msrs).unwrap();
        let succ = self
            .fd
            .get_msrs(&mut mshv_msrs)
            .map_err(|e| cpu::HypervisorCpuError::GetMsrEntries(e.into()))?;

        msrs[..succ].copy_from_slice(
            &mshv_msrs.as_slice()[..succ]
                .iter()
                .map(|e| (*e).into())
                .collect::<Vec<MsrEntry>>(),
        );

        Ok(succ)
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// Setup the model-specific registers (MSR) for this vCPU.
    /// Returns the number of MSR entries actually written.
    ///
    fn set_msrs(&self, msrs: &[MsrEntry]) -> cpu::Result<usize> {
        let mshv_msrs: Vec<msr_entry> = msrs.iter().map(|e| (*e).into()).collect();
        let mshv_msrs = MsrEntries::from_entries(&mshv_msrs).unwrap();
        self.fd
            .set_msrs(&mshv_msrs)
            .map_err(|e| cpu::HypervisorCpuError::SetMsrEntries(e.into()))
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call to enable HyperV SynIC
    ///
    fn enable_hyperv_synic(&self) -> cpu::Result<()> {
        /* We always have SynIC enabled on MSHV */
        Ok(())
    }

    #[allow(non_upper_case_globals)]
    fn run(&self) -> std::result::Result<cpu::VmExit, cpu::HypervisorCpuError> {
        match self.fd.run() {
            Ok(x) => match x.header.message_type {
                hv_message_type_HVMSG_X64_HALT => {
                    debug!("HALT");
                    Ok(cpu::VmExit::Reset)
                }
                hv_message_type_HVMSG_UNRECOVERABLE_EXCEPTION => {
                    warn!("TRIPLE FAULT");
                    Ok(cpu::VmExit::Shutdown)
                }
                #[cfg(target_arch = "x86_64")]
                hv_message_type_HVMSG_X64_IO_PORT_INTERCEPT => {
                    let info = x.to_ioport_info().unwrap();
                    let access_info = info.access_info;
                    // SAFETY: access_info is valid, otherwise we won't be here
                    let len = unsafe { access_info.__bindgen_anon_1.access_size() } as usize;
                    let is_write = info.header.intercept_access_type == 1;
                    let port = info.port_number;
                    let mut data: [u8; 4] = [0; 4];
                    let mut ret_rax = info.rax;

                    /*
                     * XXX: Ignore QEMU fw_cfg (0x5xx) and debug console (0x402) ports.
                     *
                     * Cloud Hypervisor doesn't support fw_cfg at the moment. It does support 0x402
                     * under the "fwdebug" feature flag. But that feature is not enabled by default
                     * and is considered legacy.
                     *
                     * OVMF unconditionally pokes these IO ports with string IO.
                     *
                     * Instead of trying to implement string IO support now which does not do much
                     * now, skip those ports explicitly to avoid panicking.
                     *
                     * Proper string IO support can be added once we gain the ability to translate
                     * guest virtual addresses to guest physical addresses on MSHV.
                     */
                    match port {
                        0x402 | 0x510 | 0x511 | 0x514 => {
                            self.advance_rip_update_rax(&info, ret_rax)?;
                            return Ok(cpu::VmExit::Ignore);
                        }
                        _ => {}
                    }

                    assert!(
                        // SAFETY: access_info is valid, otherwise we won't be here
                        (unsafe { access_info.__bindgen_anon_1.string_op() } != 1),
                        "String IN/OUT not supported"
                    );
                    assert!(
                        // SAFETY: access_info is valid, otherwise we won't be here
                        (unsafe { access_info.__bindgen_anon_1.rep_prefix() } != 1),
                        "Rep IN/OUT not supported"
                    );

                    if is_write {
                        let data = (info.rax as u32).to_le_bytes();
                        if let Some(vm_ops) = &self.vm_ops {
                            vm_ops
                                .pio_write(port.into(), &data[0..len])
                                .map_err(|e| cpu::HypervisorCpuError::RunVcpu(e.into()))?;
                        }
                    } else {
                        if let Some(vm_ops) = &self.vm_ops {
                            vm_ops
                                .pio_read(port.into(), &mut data[0..len])
                                .map_err(|e| cpu::HypervisorCpuError::RunVcpu(e.into()))?;
                        }

                        let v = u32::from_le_bytes(data);
                        /* Preserve high bits in EAX but clear out high bits in RAX */
                        let mask = 0xffffffff >> (32 - len * 8);
                        let eax = (info.rax as u32 & !mask) | (v & mask);
                        ret_rax = eax as u64;
                    }

                    self.advance_rip_update_rax(&info, ret_rax)?;
                    Ok(cpu::VmExit::Ignore)
                }
                #[cfg(target_arch = "aarch64")]
                hv_message_type_HVMSG_UNMAPPED_GPA => {
                    let info = x.to_memory_info().unwrap();
                    let gva = info.guest_virtual_address;
                    let gpa = info.guest_physical_address;

                    debug!("Unmapped GPA exit: GVA {:x} GPA {:x}", gva, gpa);

                    let context = MshvEmulatorContext {
                        vcpu: self,
                        map: (gva, gpa),
                        syndrome: info.syndrome,
                        instruction_bytes: info.instruction_bytes,
                        instruction_byte_count: info.instruction_byte_count,
                        // SAFETY: Accessing a union element from bindgen generated bindings.
                        interruption_pending: unsafe {
                            info.header
                                .execution_state
                                .__bindgen_anon_1
                                .interruption_pending()
                                != 0
                        },
                        pc: info.header.pc,
                    };

                    let mut emulator = emulator::Emulator::new(context);
                    emulator
                        .emulate()
                        .map_err(|e| cpu::HypervisorCpuError::RunVcpu(e.into()))?;

                    Ok(cpu::VmExit::Ignore)
                }
                #[cfg(target_arch = "x86_64")]
                msg_type @ (hv_message_type_HVMSG_UNMAPPED_GPA
                | hv_message_type_HVMSG_GPA_INTERCEPT) => {
                    let info = x.to_memory_info().unwrap();
                    let insn_len = info.instruction_byte_count as usize;
                    let gva = info.guest_virtual_address;
                    let gpa = info.guest_physical_address;

                    debug!("Exit ({:?}) GVA {:x} GPA {:x}", msg_type, gva, gpa);

                    let mut context = MshvEmulatorContext {
                        vcpu: self,
                        map: (gva, gpa),
                    };

                    // Create a new emulator.
                    let mut emul = Emulator::new(&mut context);

                    // Emulate the trapped instruction, and only the first one.
                    let new_state = emul
                        .emulate_first_insn(
                            self.vp_index as usize,
                            &info.instruction_bytes[..insn_len],
                        )
                        .map_err(|e| cpu::HypervisorCpuError::RunVcpu(e.into()))?;

                    // Set CPU state back.
                    context
                        .set_cpu_state(self.vp_index as usize, new_state)
                        .map_err(|e| cpu::HypervisorCpuError::RunVcpu(e.into()))?;

                    Ok(cpu::VmExit::Ignore)
                }
                #[cfg(feature = "sev_snp")]
                hv_message_type_HVMSG_GPA_ATTRIBUTE_INTERCEPT => {
                    let info = x.to_gpa_attribute_info().unwrap();
                    let host_vis = info.__bindgen_anon_1.host_visibility();
                    if host_vis >= HV_MAP_GPA_READABLE | HV_MAP_GPA_WRITABLE {
                        warn!("Ignored attribute intercept with full host visibility");
                        return Ok(cpu::VmExit::Ignore);
                    }

                    let num_ranges = info.__bindgen_anon_1.range_count();
                    assert!(num_ranges >= 1);
                    if num_ranges > 1 {
                        return Err(cpu::HypervisorCpuError::RunVcpu(anyhow!(
                            "Unhandled VCPU exit(GPA_ATTRIBUTE_INTERCEPT): Expected num_ranges to be 1 but found num_ranges {:?}",
                            num_ranges
                        )));
                    }

                    // TODO: we could also deny the request with HvCallCompleteIntercept
                    let mut gpas = Vec::new();
                    let ranges = info.ranges;
                    let (gfn_start, gfn_count) = snp::parse_gpa_range(ranges[0]).unwrap();
                    debug!(
                        "Releasing pages: gfn_start: {:x?}, gfn_count: {:?}",
                        gfn_start, gfn_count
                    );
                    let gpa_start = gfn_start * HV_PAGE_SIZE as u64;
                    for i in 0..gfn_count {
                        gpas.push(gpa_start + i * HV_PAGE_SIZE as u64);
                    }

                    let mut gpa_list =
                        vec_with_array_field::<mshv_modify_gpa_host_access, u64>(gpas.len());
                    gpa_list[0].page_count = gpas.len() as u64;
                    gpa_list[0].flags = 0;
                    if host_vis & HV_MAP_GPA_READABLE != 0 {
                        gpa_list[0].flags |= 1 << MSHV_GPA_HOST_ACCESS_BIT_READABLE;
                    }
                    if host_vis & HV_MAP_GPA_WRITABLE != 0 {
                        gpa_list[0].flags |= 1 << MSHV_GPA_HOST_ACCESS_BIT_WRITABLE;
                    }

                    // SAFETY: gpa_list initialized with gpas.len() and now it is being turned into
                    // gpas_slice with gpas.len() again. It is guaranteed to be large enough to hold
                    // everything from gpas.
                    unsafe {
                        let gpas_slice: &mut [u64] =
                            gpa_list[0].guest_pfns.as_mut_slice(gpas.len());
                        gpas_slice.copy_from_slice(gpas.as_slice());
                    }

                    self.vm_fd
                        .modify_gpa_host_access(&gpa_list[0])
                        .map_err(|e| cpu::HypervisorCpuError::RunVcpu(anyhow!(
                            "Unhandled VCPU exit: attribute intercept - couldn't modify host access {}", e
                        )))?;
                    // Guest is revoking the shared access, so we need to update the bitmap
                    self.host_access_pages.rcu(|_bitmap| {
                        let bm = self.host_access_pages.load().as_ref().clone();
                        bm.reset_addr_range(gpa_start as usize, gfn_count as usize);
                        bm
                    });
                    Ok(cpu::VmExit::Ignore)
                }
                #[cfg(target_arch = "x86_64")]
                hv_message_type_HVMSG_UNACCEPTED_GPA => {
                    let info = x.to_memory_info().unwrap();
                    let gva = info.guest_virtual_address;
                    let gpa = info.guest_physical_address;

                    Err(cpu::HypervisorCpuError::RunVcpu(anyhow!(
                        "Unhandled VCPU exit: Unaccepted GPA({:x}) found at GVA({:x})",
                        gpa,
                        gva,
                    )))
                }
                #[cfg(target_arch = "x86_64")]
                hv_message_type_HVMSG_X64_CPUID_INTERCEPT => {
                    let info = x.to_cpuid_info().unwrap();
                    debug!("cpuid eax: {:x}", { info.rax });
                    Ok(cpu::VmExit::Ignore)
                }
                #[cfg(target_arch = "x86_64")]
                hv_message_type_HVMSG_X64_MSR_INTERCEPT => {
                    let info = x.to_msr_info().unwrap();
                    if info.header.intercept_access_type == 0 {
                        debug!("msr read: {:x}", { info.msr_number });
                    } else {
                        debug!("msr write: {:x}", { info.msr_number });
                    }
                    Ok(cpu::VmExit::Ignore)
                }
                #[cfg(target_arch = "x86_64")]
                hv_message_type_HVMSG_X64_EXCEPTION_INTERCEPT => {
                    //TODO: Handler for VMCALL here.
                    let info = x.to_exception_info().unwrap();
                    debug!("Exception Info {:?}", { info.exception_vector });
                    Ok(cpu::VmExit::Ignore)
                }
                #[cfg(target_arch = "x86_64")]
                hv_message_type_HVMSG_X64_APIC_EOI => {
                    let info = x.to_apic_eoi_info().unwrap();
                    // The kernel should dispatch the EOI to the correct thread.
                    // Check the VP index is the same as the one we have.
                    assert!(info.vp_index == self.vp_index as u32);
                    // The interrupt vector in info is u32, but x86 only supports 256 vectors.
                    // There is no good way to recover from this if the hypervisor messes around.
                    // Just unwrap.
                    Ok(cpu::VmExit::IoapicEoi(
                        info.interrupt_vector.try_into().unwrap(),
                    ))
                }
                #[cfg(feature = "sev_snp")]
                hv_message_type_HVMSG_X64_SEV_VMGEXIT_INTERCEPT => {
                    let info = x.to_vmg_intercept_info().unwrap();
                    let ghcb_data = info.ghcb_msr >> GHCB_INFO_BIT_WIDTH;
                    let ghcb_msr = svm_ghcb_msr {
                        as_uint64: info.ghcb_msr,
                    };
                    // Safe to use unwrap, for sev_snp guest we already have the
                    // GHCB pointer wrapped in the option, otherwise this place is not reached.
                    let ghcb = self.ghcb.as_ref().unwrap().0;

                    // SAFETY: Accessing a union element from bindgen generated bindings.
                    let ghcb_op = unsafe { ghcb_msr.__bindgen_anon_2.ghcb_info() as u32 };
                    // Sanity check on the header fields before handling other operations.
                    assert!(info.header.intercept_access_type == HV_INTERCEPT_ACCESS_EXECUTE as u8);

                    match ghcb_op {
                        GHCB_INFO_HYP_FEATURE_REQUEST => {
                            // Pre-condition: GHCB data must be zero
                            assert!(ghcb_data == 0);
                            let mut ghcb_response = GHCB_INFO_HYP_FEATURE_RESPONSE as u64;
                            // Indicate support for basic SEV-SNP features
                            ghcb_response |=
                                (GHCB_HYP_FEATURE_SEV_SNP << GHCB_INFO_BIT_WIDTH) as u64;
                            // Indicate support for SEV-SNP AP creation
                            ghcb_response |= (GHCB_HYP_FEATURE_SEV_SNP_AP_CREATION
                                << GHCB_INFO_BIT_WIDTH)
                                as u64;
                            debug!(
                                "GHCB_INFO_HYP_FEATURE_REQUEST: Supported features: {:0x}",
                                ghcb_response
                            );
                            let arr_reg_name_value =
                                [(hv_register_name_HV_X64_REGISTER_GHCB, ghcb_response)];
                            set_registers_64!(self.fd, arr_reg_name_value)
                                .map_err(|e| cpu::HypervisorCpuError::SetRegister(e.into()))?;
                        }
                        GHCB_INFO_REGISTER_REQUEST => {
                            let mut ghcb_gpa = hv_x64_register_sev_ghcb::default();

                            // Disable the previously used GHCB page.
                            self.disable_prev_ghcb_page()?;

                            // SAFETY: Accessing a union element from bindgen generated bindings.
                            unsafe {
                                ghcb_gpa.__bindgen_anon_1.set_enabled(1);
                                ghcb_gpa
                                    .__bindgen_anon_1
                                    .set_page_number(ghcb_msr.__bindgen_anon_2.gpa_page_number());
                            }
                            // SAFETY: Accessing a union element from bindgen generated bindings.
                            let reg_name_value = unsafe {
                                [(
                                    hv_register_name_HV_X64_REGISTER_SEV_GHCB_GPA,
                                    ghcb_gpa.as_uint64,
                                )]
                            };

                            set_registers_64!(self.fd, reg_name_value)
                                .map_err(|e| cpu::HypervisorCpuError::SetRegister(e.into()))?;

                            let mut resp_ghcb_msr = svm_ghcb_msr::default();
                            // SAFETY: Accessing a union element from bindgen generated bindings.
                            unsafe {
                                resp_ghcb_msr
                                    .__bindgen_anon_2
                                    .set_ghcb_info(GHCB_INFO_REGISTER_RESPONSE as u64);
                                resp_ghcb_msr.__bindgen_anon_2.set_gpa_page_number(
                                    ghcb_msr.__bindgen_anon_2.gpa_page_number(),
                                );
                                debug!("GHCB GPA is {:x}", ghcb_gpa.as_uint64);
                            }
                            // SAFETY: Accessing a union element from bindgen generated bindings.
                            let reg_name_value = unsafe {
                                [(
                                    hv_register_name_HV_X64_REGISTER_GHCB,
                                    resp_ghcb_msr.as_uint64,
                                )]
                            };

                            set_registers_64!(self.fd, reg_name_value)
                                .map_err(|e| cpu::HypervisorCpuError::SetRegister(e.into()))?;
                        }
                        GHCB_INFO_SEV_INFO_REQUEST => {
                            let sev_cpuid_function = 0x8000_001F;
                            let cpu_leaf = self
                                .fd
                                .get_cpuid_values(sev_cpuid_function, 0, 0, 0)
                                .unwrap();
                            let ebx = cpu_leaf[1];
                            // First 6-byte of EBX represents page table encryption bit number
                            let pbit_encryption = (ebx & 0x3f) as u8;
                            let mut ghcb_response = GHCB_INFO_SEV_INFO_RESPONSE as u64;

                            // GHCBData[63:48] specifies the maximum GHCB protocol version supported
                            ghcb_response |= (GHCB_PROTOCOL_VERSION_MAX as u64) << 48;
                            // GHCBData[47:32] specifies the minimum GHCB protocol version supported
                            ghcb_response |= (GHCB_PROTOCOL_VERSION_MIN as u64) << 32;
                            // GHCBData[31:24] specifies the SEV page table encryption bit number.
                            ghcb_response |= (pbit_encryption as u64) << 24;

                            let arr_reg_name_value =
                                [(hv_register_name_HV_X64_REGISTER_GHCB, ghcb_response)];
                            set_registers_64!(self.fd, arr_reg_name_value)
                                .map_err(|e| cpu::HypervisorCpuError::SetRegister(e.into()))?;
                        }
                        GHCB_INFO_NORMAL => {
                            let exit_code =
                                info.__bindgen_anon_2.__bindgen_anon_1.sw_exit_code as u32;

                            match exit_code {
                                SVM_EXITCODE_HV_DOORBELL_PAGE => {
                                    let exit_info1 =
                                        info.__bindgen_anon_2.__bindgen_anon_1.sw_exit_info1 as u32;
                                    match exit_info1 {
                                        SVM_NAE_HV_DOORBELL_PAGE_GET_PREFERRED => {
                                            // Hypervisor does not have any preference for doorbell GPA.
                                            let preferred_doorbell_gpa: u64 = 0xFFFFFFFFFFFFFFFF;
                                            set_svm_field_u64_ptr!(
                                                ghcb,
                                                exit_info2,
                                                preferred_doorbell_gpa
                                            );
                                        }
                                        SVM_NAE_HV_DOORBELL_PAGE_SET => {
                                            let exit_info2 = info
                                                .__bindgen_anon_2
                                                .__bindgen_anon_1
                                                .sw_exit_info2;
                                            let mut ghcb_doorbell_gpa =
                                                hv_x64_register_sev_hv_doorbell::default();
                                            // SAFETY: Accessing a union element from bindgen generated bindings.
                                            unsafe {
                                                ghcb_doorbell_gpa.__bindgen_anon_1.set_enabled(1);
                                                ghcb_doorbell_gpa
                                                    .__bindgen_anon_1
                                                    .set_page_number(exit_info2 >> PAGE_SHIFT);
                                            }
                                            // SAFETY: Accessing a union element from bindgen generated bindings.
                                            let reg_names = unsafe {
                                                [(
                                                    hv_register_name_HV_X64_REGISTER_SEV_DOORBELL_GPA,
                                                    ghcb_doorbell_gpa.as_uint64,
                                                )]
                                            };
                                            set_registers_64!(self.fd, reg_names).map_err(|e| {
                                                cpu::HypervisorCpuError::SetRegister(e.into())
                                            })?;

                                            set_svm_field_u64_ptr!(ghcb, exit_info2, exit_info2);

                                            // Clear the SW_EXIT_INFO1 register to indicate no error
                                            self.clear_swexit_info1()?;
                                        }
                                        SVM_NAE_HV_DOORBELL_PAGE_QUERY => {
                                            let mut reg_assocs = [ hv_register_assoc {
                                                name: hv_register_name_HV_X64_REGISTER_SEV_DOORBELL_GPA,
                                                ..Default::default()
                                            } ];
                                            self.fd.get_reg(&mut reg_assocs).unwrap();
                                            // SAFETY: Accessing a union element from bindgen generated bindings.
                                            let doorbell_gpa = unsafe { reg_assocs[0].value.reg64 };

                                            set_svm_field_u64_ptr!(ghcb, exit_info2, doorbell_gpa);

                                            // Clear the SW_EXIT_INFO1 register to indicate no error
                                            self.clear_swexit_info1()?;
                                        }
                                        SVM_NAE_HV_DOORBELL_PAGE_CLEAR => {
                                            set_svm_field_u64_ptr!(ghcb, exit_info2, 0);
                                        }
                                        _ => {
                                            panic!(
                                                "SVM_EXITCODE_HV_DOORBELL_PAGE: Unhandled exit code: {exit_info1:0x}"
                                            );
                                        }
                                    }
                                }
                                SVM_EXITCODE_IOIO_PROT => {
                                    let exit_info1 =
                                        info.__bindgen_anon_2.__bindgen_anon_1.sw_exit_info1 as u32;
                                    let port_info = hv_sev_vmgexit_port_info {
                                        as_uint32: exit_info1,
                                    };

                                    let port =
                                        // SAFETY: Accessing a union element from bindgen generated bindings.
                                        unsafe { port_info.__bindgen_anon_1.intercepted_port() };
                                    let mut len = 4;
                                    // SAFETY: Accessing a union element from bindgen generated bindings.
                                    unsafe {
                                        if port_info.__bindgen_anon_1.operand_size_16bit() == 1 {
                                            len = 2;
                                        } else if port_info.__bindgen_anon_1.operand_size_8bit()
                                            == 1
                                        {
                                            len = 1;
                                        }
                                    }
                                    let is_write =
                                        // SAFETY: Accessing a union element from bindgen generated bindings.
                                        unsafe { port_info.__bindgen_anon_1.access_type() == 0 };
                                    // SAFETY: Accessing the field from a mapped address
                                    let mut data = unsafe { (*ghcb).rax.to_le_bytes() };

                                    if is_write {
                                        if let Some(vm_ops) = &self.vm_ops {
                                            vm_ops.pio_write(port.into(), &data[..len]).map_err(
                                                |e| cpu::HypervisorCpuError::RunVcpu(e.into()),
                                            )?;
                                        }
                                    } else {
                                        if let Some(vm_ops) = &self.vm_ops {
                                            vm_ops
                                                .pio_read(port.into(), &mut data[..len])
                                                .map_err(|e| {
                                                    cpu::HypervisorCpuError::RunVcpu(e.into())
                                                })?;
                                        }
                                        set_svm_field_u64_ptr!(ghcb, rax, u64::from_le_bytes(data));
                                    }

                                    // Clear the SW_EXIT_INFO1 register to indicate no error
                                    self.clear_swexit_info1()?;
                                }
                                SVM_EXITCODE_MMIO_READ => {
                                    let src_gpa =
                                        info.__bindgen_anon_2.__bindgen_anon_1.sw_exit_info1;
                                    let data_len =
                                        info.__bindgen_anon_2.__bindgen_anon_1.sw_exit_info2
                                            as usize;
                                    // Sanity check to make sure data len is within supported range.
                                    assert!(data_len <= 0x8);

                                    let mut data: Vec<u8> = vec![0; data_len];
                                    if let Some(vm_ops) = &self.vm_ops {
                                        vm_ops.mmio_read(src_gpa, &mut data).map_err(|e| {
                                            cpu::HypervisorCpuError::RunVcpu(e.into())
                                        })?;
                                    }
                                    // Copy the data to the shared buffer of the GHCB page
                                    let mut buffer_data = [0; 8];
                                    buffer_data[..data_len].copy_from_slice(&data[..data_len]);
                                    // SAFETY: Updating the value of mapped area
                                    unsafe { (*ghcb).shared[0] = u64::from_le_bytes(buffer_data) };

                                    // Clear the SW_EXIT_INFO1 register to indicate no error
                                    self.clear_swexit_info1()?;
                                }
                                SVM_EXITCODE_MMIO_WRITE => {
                                    let dst_gpa =
                                        info.__bindgen_anon_2.__bindgen_anon_1.sw_exit_info1;
                                    let data_len =
                                        info.__bindgen_anon_2.__bindgen_anon_1.sw_exit_info2
                                            as usize;
                                    // Sanity check to make sure data len is within supported range.
                                    assert!(data_len <= 0x8);

                                    let mut data = vec![0; data_len];
                                    // SAFETY: Accessing data from a mapped address
                                    let bytes_shared_ghcb =
                                        unsafe { (*ghcb).shared[0].to_le_bytes() };
                                    data.copy_from_slice(&bytes_shared_ghcb[..data_len]);

                                    if let Some(vm_ops) = &self.vm_ops {
                                        vm_ops.mmio_write(dst_gpa, &data).map_err(|e| {
                                            cpu::HypervisorCpuError::RunVcpu(e.into())
                                        })?;
                                    }

                                    // Clear the SW_EXIT_INFO1 register to indicate no error
                                    self.clear_swexit_info1()?;
                                }
                                SVM_EXITCODE_SNP_GUEST_REQUEST
                                | SVM_EXITCODE_SNP_EXTENDED_GUEST_REQUEST => {
                                    if exit_code == SVM_EXITCODE_SNP_EXTENDED_GUEST_REQUEST {
                                        info!("Fetching extended guest request is not supported");
                                        // We don't support extended guest request, so we just write empty data.
                                        // This matches the behavior of KVM in Linux 6.11.

                                        // Read RBX from the GHCB.
                                        // SAFETY: Accessing data from a mapped address
                                        let data_gpa = unsafe { (*ghcb).rax };
                                        // SAFETY: Accessing data from a mapped address
                                        let data_npages = unsafe { (*ghcb).rbx };

                                        if data_npages > 0 {
                                            // The certificates are terminated by 24 zero bytes.
                                            // TODO: Need to check if data_gpa is the address of the shared buffer in the GHCB page
                                            // in that case we should clear the shared buffer(24 bytes)
                                            self.gpa_write(data_gpa, &[0; 24])?;
                                        }
                                    }

                                    let req_gpa =
                                        info.__bindgen_anon_2.__bindgen_anon_1.sw_exit_info1;
                                    let rsp_gpa =
                                        info.__bindgen_anon_2.__bindgen_anon_1.sw_exit_info2;

                                    let mshv_psp_req =
                                        mshv_issue_psp_guest_request { req_gpa, rsp_gpa };
                                    self.vm_fd
                                        .psp_issue_guest_request(&mshv_psp_req)
                                        .map_err(|e| cpu::HypervisorCpuError::RunVcpu(e.into()))?;

                                    debug!(
                                        "SNP guest request: req_gpa {:0x} rsp_gpa {:0x}",
                                        req_gpa, rsp_gpa
                                    );

                                    set_svm_field_u64_ptr!(ghcb, exit_info2, 0);
                                }
                                SVM_EXITCODE_SNP_AP_CREATION => {
                                    let vmsa_gpa =
                                        info.__bindgen_anon_2.__bindgen_anon_1.sw_exit_info2;
                                    let apic_id =
                                        info.__bindgen_anon_2.__bindgen_anon_1.sw_exit_info1 >> 32;
                                    debug!(
                                        "SNP AP CREATE REQUEST with VMSA GPA {:0x}, and APIC ID {:?}",
                                        vmsa_gpa, apic_id
                                    );

                                    let mshv_ap_create_req = mshv_sev_snp_ap_create {
                                        vp_id: apic_id,
                                        vmsa_gpa,
                                    };
                                    self.vm_fd
                                        .sev_snp_ap_create(&mshv_ap_create_req)
                                        .map_err(|e| cpu::HypervisorCpuError::RunVcpu(e.into()))?;

                                    // Clear the SW_EXIT_INFO1 register to indicate no error
                                    self.clear_swexit_info1()?;
                                }
                                _ => {
                                    panic!("GHCB_INFO_NORMAL: Unhandled exit code: {exit_code:0x}")
                                }
                            }
                        }
                        _ => panic!("Unsupported VMGEXIT operation: {ghcb_op:0x}"),
                    }

                    Ok(cpu::VmExit::Ignore)
                }
                exit => Err(cpu::HypervisorCpuError::RunVcpu(anyhow!(
                    "Unhandled VCPU exit {:?}",
                    exit
                ))),
            },

            Err(e) => match e.errno() {
                libc::EAGAIN | libc::EINTR => Ok(cpu::VmExit::Ignore),
                _ => Err(cpu::HypervisorCpuError::RunVcpu(anyhow!(
                    "VCPU error {:?}",
                    e
                ))),
            },
        }
    }

    #[cfg(target_arch = "aarch64")]
    fn init_pmu(&self, _irq: u32) -> cpu::Result<()> {
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn has_pmu_support(&self) -> bool {
        true
    }

    #[cfg(target_arch = "aarch64")]
    fn setup_regs(&self, cpu_id: u32, boot_ip: u64, fdt_start: u64) -> cpu::Result<()> {
        let arr_reg_name_value = [(
            hv_register_name_HV_ARM64_REGISTER_PSTATE,
            regs::PSTATE_FAULT_BITS_64,
        )];
        set_registers_64!(self.fd, arr_reg_name_value)
            .map_err(|e| cpu::HypervisorCpuError::SetRegister(e.into()))?;

        if cpu_id == 0 {
            let arr_reg_name_value = [
                (hv_register_name_HV_ARM64_REGISTER_PC, boot_ip),
                (hv_register_name_HV_ARM64_REGISTER_X0, fdt_start),
            ];
            set_registers_64!(self.fd, arr_reg_name_value)
                .map_err(|e| cpu::HypervisorCpuError::SetRegister(e.into()))?;
        }

        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn get_sys_reg(&self, sys_reg: u32) -> cpu::Result<u64> {
        let mshv_reg = self.sys_reg_to_mshv_reg(sys_reg)?;

        let mut reg_assocs = [hv_register_assoc {
            name: mshv_reg,
            ..Default::default()
        }];
        self.fd
            .get_reg(&mut reg_assocs)
            .map_err(|e| cpu::HypervisorCpuError::GetRegister(e.into()))?;

        // SAFETY: Accessing a union element from bindgen generated definition.
        let res = unsafe { reg_assocs[0].value.reg64 };
        Ok(res)
    }

    #[cfg(target_arch = "aarch64")]
    fn get_reg_list(&self, _reg_list: &mut crate::RegList) -> cpu::Result<()> {
        unimplemented!()
    }

    #[cfg(target_arch = "aarch64")]
    fn vcpu_init(&self, _kvi: &crate::VcpuInit) -> cpu::Result<()> {
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn vcpu_finalize(&self, _feature: i32) -> cpu::Result<()> {
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn vcpu_get_finalized_features(&self) -> i32 {
        0
    }

    #[cfg(target_arch = "aarch64")]
    fn vcpu_set_processor_features(
        &self,
        _vm: &Arc<dyn crate::Vm>,
        _kvi: &mut crate::VcpuInit,
        _id: u32,
    ) -> cpu::Result<()> {
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn create_vcpu_init(&self) -> crate::VcpuInit {
        MshvVcpuInit {}.into()
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call to setup the CPUID registers.
    ///
    fn set_cpuid2(&self, cpuid: &[CpuIdEntry]) -> cpu::Result<()> {
        let cpuid: Vec<mshv_bindings::hv_cpuid_entry> = cpuid.iter().map(|e| (*e).into()).collect();
        let mshv_cpuid = <CpuId>::from_entries(&cpuid)
            .map_err(|_| cpu::HypervisorCpuError::SetCpuid(anyhow!("failed to create CpuId")))?;

        self.fd
            .register_intercept_result_cpuid(&mshv_cpuid)
            .map_err(|e| cpu::HypervisorCpuError::SetCpuid(e.into()))
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call to retrieve the CPUID registers.
    ///
    fn get_cpuid2(&self, _num_entries: usize) -> cpu::Result<Vec<CpuIdEntry>> {
        Ok(self.cpuid.clone())
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call to retrieve cpuid leaf
    ///
    fn get_cpuid_values(
        &self,
        function: u32,
        index: u32,
        xfem: u64,
        xss: u64,
    ) -> cpu::Result<[u32; 4]> {
        self.fd
            .get_cpuid_values(function, index, xfem, xss)
            .map_err(|e| cpu::HypervisorCpuError::GetCpuidVales(e.into()))
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns the state of the LAPIC (Local Advanced Programmable Interrupt Controller).
    ///
    fn get_lapic(&self) -> cpu::Result<crate::arch::x86::LapicState> {
        Ok(self
            .fd
            .get_lapic()
            .map_err(|e| cpu::HypervisorCpuError::GetlapicState(e.into()))?
            .into())
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// Sets the state of the LAPIC (Local Advanced Programmable Interrupt Controller).
    ///
    fn set_lapic(&self, lapic: &crate::arch::x86::LapicState) -> cpu::Result<()> {
        let lapic: mshv_bindings::LapicState = (*lapic).clone().into();
        self.fd
            .set_lapic(&lapic)
            .map_err(|e| cpu::HypervisorCpuError::SetLapicState(e.into()))
    }

    ///
    /// Returns the vcpu's current "multiprocessing state".
    ///
    fn get_mp_state(&self) -> cpu::Result<MpState> {
        Ok(MpState::Mshv)
    }

    ///
    /// Sets the vcpu's current "multiprocessing state".
    ///
    fn set_mp_state(&self, _mp_state: MpState) -> cpu::Result<()> {
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// Set CPU state for x86_64 guest.
    ///
    fn set_state(&self, state: &CpuState) -> cpu::Result<()> {
        let mut state: VcpuMshvState = state.clone().into();
        self.set_msrs(&state.msrs)?;
        self.set_vcpu_events(&state.vcpu_events)?;
        self.set_regs(&state.regs.into())?;
        self.set_sregs(&state.sregs.into())?;
        self.set_fpu(&state.fpu)?;
        self.set_xcrs(&state.xcrs)?;
        // These registers are global and needed to be set only for first VCPU
        // as Microsoft Hypervisor allows setting this register for only one VCPU
        if self.vp_index == 0 {
            self.fd
                .set_misc_regs(&state.misc)
                .map_err(|e| cpu::HypervisorCpuError::SetMiscRegs(e.into()))?
        }
        self.fd
            .set_debug_regs(&state.dbg)
            .map_err(|e| cpu::HypervisorCpuError::SetDebugRegs(e.into()))?;
        self.fd
            .set_all_vp_state_components(&mut state.vp_states)
            .map_err(|e| cpu::HypervisorCpuError::SetAllVpStateComponents(e.into()))?;
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    ///
    /// Set CPU state for aarch64 guest.
    ///
    fn set_state(&self, _state: &CpuState) -> cpu::Result<()> {
        unimplemented!()
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// Get CPU State for x86_64 guest
    ///
    fn state(&self) -> cpu::Result<CpuState> {
        let regs = self.get_regs()?;
        let sregs = self.get_sregs()?;
        let xcrs = self.get_xcrs()?;
        let fpu = self.get_fpu()?;
        let vcpu_events = self.get_vcpu_events()?;
        let mut msrs = self.msrs.clone();
        self.get_msrs(&mut msrs)?;
        let misc = self
            .fd
            .get_misc_regs()
            .map_err(|e| cpu::HypervisorCpuError::GetMiscRegs(e.into()))?;
        let dbg = self
            .fd
            .get_debug_regs()
            .map_err(|e| cpu::HypervisorCpuError::GetDebugRegs(e.into()))?;
        let vp_states = self
            .fd
            .get_all_vp_state_components()
            .map_err(|e| cpu::HypervisorCpuError::GetAllVpStateComponents(e.into()))?;

        Ok(VcpuMshvState {
            msrs,
            vcpu_events,
            regs: regs.into(),
            sregs: sregs.into(),
            fpu,
            xcrs,
            dbg,
            misc,
            vp_states,
        }
        .into())
    }

    #[cfg(target_arch = "aarch64")]
    ///
    /// Get CPU state for aarch64 guest.
    ///
    fn state(&self) -> cpu::Result<CpuState> {
        unimplemented!()
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// Translate guest virtual address to guest physical address
    ///
    fn translate_gva(&self, gva: u64, flags: u64) -> cpu::Result<(u64, u32)> {
        let r = self
            .fd
            .translate_gva(gva, flags)
            .map_err(|e| cpu::HypervisorCpuError::TranslateVirtualAddress(e.into()))?;

        let gpa = r.0;
        // SAFETY: r is valid, otherwise this function will have returned
        let result_code = unsafe { r.1.__bindgen_anon_1.result_code };

        Ok((gpa, result_code))
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// Return the list of initial MSR entries for a VCPU
    ///
    fn boot_msr_entries(&self) -> Vec<MsrEntry> {
        use crate::arch::x86::{msr_index, MTRR_ENABLE, MTRR_MEM_TYPE_WB};

        [
            msr!(msr_index::MSR_IA32_SYSENTER_CS),
            msr!(msr_index::MSR_IA32_SYSENTER_ESP),
            msr!(msr_index::MSR_IA32_SYSENTER_EIP),
            msr!(msr_index::MSR_STAR),
            msr!(msr_index::MSR_CSTAR),
            msr!(msr_index::MSR_LSTAR),
            msr!(msr_index::MSR_KERNEL_GS_BASE),
            msr!(msr_index::MSR_SYSCALL_MASK),
            msr_data!(msr_index::MSR_MTRRdefType, MTRR_ENABLE | MTRR_MEM_TYPE_WB),
        ]
        .to_vec()
    }

    ///
    /// Sets the AMD specific vcpu's sev control register.
    ///
    #[cfg(feature = "sev_snp")]
    fn set_sev_control_register(&self, vmsa_pfn: u64) -> cpu::Result<()> {
        let sev_control_reg = snp::get_sev_control_register(vmsa_pfn);

        self.fd
            .set_sev_control_register(sev_control_reg)
            .map_err(|e| cpu::HypervisorCpuError::SetSevControlRegister(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Trigger NMI interrupt
    ///
    fn nmi(&self) -> cpu::Result<()> {
        let cfg = InterruptRequest {
            interrupt_type: hv_interrupt_type_HV_X64_INTERRUPT_TYPE_NMI,
            apic_id: self.vp_index as u64,
            level_triggered: false,
            vector: 0,
            logical_destination_mode: false,
            long_mode: false,
        };
        self.vm_fd
            .request_virtual_interrupt(&cfg)
            .map_err(|e| cpu::HypervisorCpuError::Nmi(e.into()))
    }
    ///
    /// Set the GICR base address for the vcpu.
    ///
    #[cfg(target_arch = "aarch64")]
    fn set_gic_redistributor_addr(&self, gicr_base_addr: u64) -> cpu::Result<()> {
        debug!(
            "Setting GICR base address to: {:#x}, for vp_index: {:?}",
            gicr_base_addr, self.vp_index
        );
        let arr_reg_name_value = [(
            hv_register_name_HV_ARM64_REGISTER_GICR_BASE_GPA,
            gicr_base_addr,
        )];
        set_registers_64!(self.fd, arr_reg_name_value)
            .map_err(|e| cpu::HypervisorCpuError::SetRegister(e.into()))?;

        Ok(())
    }
}

impl MshvVcpu {
    ///
    /// Deactivate previously used GHCB page.
    ///
    #[cfg(feature = "sev_snp")]
    fn disable_prev_ghcb_page(&self) -> cpu::Result<()> {
        let mut reg_assocs = [hv_register_assoc {
            name: hv_register_name_HV_X64_REGISTER_SEV_GHCB_GPA,
            ..Default::default()
        }];
        self.fd.get_reg(&mut reg_assocs).unwrap();
        // SAFETY: Accessing a union element from bindgen generated bindings.
        let prev_ghcb_gpa = unsafe { reg_assocs[0].value.reg64 };

        debug!("Prev GHCB GPA is {:x}", prev_ghcb_gpa);

        let mut ghcb_gpa = hv_x64_register_sev_ghcb::default();

        // SAFETY: Accessing a union element from bindgen generated bindings.
        unsafe {
            ghcb_gpa.__bindgen_anon_1.set_enabled(0);
            ghcb_gpa.__bindgen_anon_1.set_page_number(prev_ghcb_gpa);
        }

        // SAFETY: Accessing a union element from bindgen generated bindings.
        let reg_name_value = unsafe {
            [(
                hv_register_name_HV_X64_REGISTER_SEV_GHCB_GPA,
                ghcb_gpa.as_uint64,
            )]
        };

        set_registers_64!(self.fd, reg_name_value)
            .map_err(|e| cpu::HypervisorCpuError::SetRegister(e.into()))?;

        Ok(())
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
            .set_xcrs(xcrs)
            .map_err(|e| cpu::HypervisorCpuError::SetXcsr(e.into()))
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

    ///
    /// Clear SW_EXIT_INFO1 register for SEV-SNP guests.
    ///
    #[cfg(feature = "sev_snp")]
    fn clear_swexit_info1(&self) -> std::result::Result<cpu::VmExit, cpu::HypervisorCpuError> {
        // Clear the SW_EXIT_INFO1 register to indicate no error
        // Safe to use unwrap, for sev_snp guest we already have the
        // GHCB pointer wrapped in the option, otherwise this place is not reached.
        let ghcb = self.ghcb.as_ref().unwrap().0;
        set_svm_field_u64_ptr!(ghcb, exit_info1, 0);

        Ok(cpu::VmExit::Ignore)
    }

    #[cfg(feature = "sev_snp")]
    fn gpa_write(&self, gpa: u64, data: &[u8]) -> cpu::Result<()> {
        for (gpa, chunk) in (gpa..)
            .step_by(HV_READ_WRITE_GPA_MAX_SIZE as usize)
            .zip(data.chunks(HV_READ_WRITE_GPA_MAX_SIZE as usize))
        {
            let mut data = [0; HV_READ_WRITE_GPA_MAX_SIZE as usize];
            data[..chunk.len()].copy_from_slice(chunk);

            let mut rw_gpa_arg = mshv_bindings::mshv_read_write_gpa {
                base_gpa: gpa,
                byte_count: chunk.len() as u32,
                data,
                ..Default::default()
            };
            self.fd
                .gpa_write(&mut rw_gpa_arg)
                .map_err(|e| cpu::HypervisorCpuError::GpaWrite(e.into()))?;
        }

        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn advance_rip_update_rax(
        &self,
        info: &hv_x64_io_port_intercept_message,
        ret_rax: u64,
    ) -> cpu::Result<()> {
        let insn_len = info.header.instruction_length() as u64;
        /*
         * Advance RIP and update RAX
         * First, try to update the registers using VP register page
         * which is mapped into user space for faster access.
         * If the register page is not available, fall back to regular
         * IOCTL to update the registers.
         */
        if let Some(reg_page) = self.fd.get_vp_reg_page() {
            let vp_reg_page = reg_page.0;
            set_gp_regs_field_ptr!(vp_reg_page, rax, ret_rax);
            // SAFETY: access raw pointer to reg page, access union fields
            unsafe {
                (*vp_reg_page).__bindgen_anon_1.__bindgen_anon_1.rip = info.header.rip + insn_len;
                (*vp_reg_page).dirty |= 1 << HV_X64_REGISTER_CLASS_IP;
                (*vp_reg_page).dirty |= 1 << HV_X64_REGISTER_CLASS_GENERAL;
            }
        } else {
            let arr_reg_name_value = [
                (
                    hv_register_name_HV_X64_REGISTER_RIP,
                    info.header.rip + insn_len,
                ),
                (hv_register_name_HV_X64_REGISTER_RAX, ret_rax),
            ];
            set_registers_64!(self.fd, arr_reg_name_value)
                .map_err(|e| cpu::HypervisorCpuError::SetRegister(e.into()))?;
        }
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn sys_reg_to_mshv_reg(&self, sys_regs: u32) -> cpu::Result<u32> {
        match sys_regs {
            regs::MPIDR_EL1 => Ok(hv_register_name_HV_ARM64_REGISTER_MPIDR_EL1),
            _ => Err(cpu::HypervisorCpuError::UnsupportedSysReg(sys_regs)),
        }
    }
}

/// Wrapper over Mshv VM ioctls.
pub struct MshvVm {
    fd: Arc<VmFd>,
    #[cfg(target_arch = "x86_64")]
    msrs: Vec<MsrEntry>,
    dirty_log_slots: Arc<RwLock<HashMap<u64, MshvDirtyLogSlot>>>,
    #[cfg(feature = "sev_snp")]
    sev_snp_enabled: bool,
    #[cfg(feature = "sev_snp")]
    host_access_pages: ArcSwap<AtomicBitmap>,
}

impl MshvVm {
    ///
    /// Creates an in-kernel device.
    ///
    /// See the documentation for `MSHV_CREATE_DEVICE`.
    fn create_device(&self, device: &mut CreateDevice) -> vm::Result<VfioDeviceFd> {
        let device_fd = self
            .fd
            .create_device(device)
            .map_err(|e| vm::HypervisorVmError::CreateDevice(e.into()))?;
        Ok(VfioDeviceFd::new_from_mshv(device_fd))
    }
}

///
/// Implementation of Vm trait for Mshv
///
/// # Examples
///
/// ```
/// extern crate hypervisor;
/// use hypervisor::mshv::MshvHypervisor;
/// use std::sync::Arc;
/// let mshv = MshvHypervisor::new().unwrap();
/// let hypervisor = Arc::new(mshv);
/// let vm = hypervisor.create_vm().expect("new VM fd creation failed");
/// ```
impl vm::Vm for MshvVm {
    #[cfg(target_arch = "x86_64")]
    ///
    /// Sets the address of the one-page region in the VM's address space.
    ///
    fn set_identity_map_address(&self, _address: u64) -> vm::Result<()> {
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// Sets the address of the three-page region in the VM's address space.
    ///
    fn set_tss_address(&self, _offset: usize) -> vm::Result<()> {
        Ok(())
    }

    ///
    /// Creates an in-kernel interrupt controller.
    ///
    fn create_irq_chip(&self) -> vm::Result<()> {
        Ok(())
    }

    ///
    /// Registers an event that will, when signaled, trigger the `gsi` IRQ.
    ///
    fn register_irqfd(&self, fd: &EventFd, gsi: u32) -> vm::Result<()> {
        debug!("register_irqfd fd {} gsi {}", fd.as_raw_fd(), gsi);

        self.fd
            .register_irqfd(fd, gsi)
            .map_err(|e| vm::HypervisorVmError::RegisterIrqFd(e.into()))?;

        Ok(())
    }

    ///
    /// Unregisters an event that will, when signaled, trigger the `gsi` IRQ.
    ///
    fn unregister_irqfd(&self, fd: &EventFd, gsi: u32) -> vm::Result<()> {
        debug!("unregister_irqfd fd {} gsi {}", fd.as_raw_fd(), gsi);

        self.fd
            .unregister_irqfd(fd, gsi)
            .map_err(|e| vm::HypervisorVmError::UnregisterIrqFd(e.into()))?;

        Ok(())
    }

    ///
    /// Creates a VcpuFd object from a vcpu RawFd.
    ///
    fn create_vcpu(
        &self,
        id: u32,
        vm_ops: Option<Arc<dyn VmOps>>,
    ) -> vm::Result<Arc<dyn cpu::Vcpu>> {
        let id: u8 = id.try_into().unwrap();
        let vcpu_fd = self
            .fd
            .create_vcpu(id)
            .map_err(|e| vm::HypervisorVmError::CreateVcpu(e.into()))?;

        /* Map the GHCB page to the VMM(root) address space
         * The map is available after the vcpu creation. This address is mapped
         * to the overlay ghcb page of the Microsoft Hypervisor, don't have
         * to worry about the scenario when a guest changes the GHCB mapping.
         */
        #[cfg(feature = "sev_snp")]
        let ghcb = if self.sev_snp_enabled {
            // SAFETY: Safe to call as VCPU has this map already available upon creation
            let addr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    HV_PAGE_SIZE,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    vcpu_fd.as_raw_fd(),
                    MSHV_VP_MMAP_OFFSET_GHCB as i64 * libc::sysconf(libc::_SC_PAGE_SIZE),
                )
            };
            if std::ptr::eq(addr, libc::MAP_FAILED) {
                // No point of continuing, without this mmap VMGEXIT will fail anyway
                // Return error
                return Err(vm::HypervisorVmError::MmapToRoot);
            }
            Some(Ghcb(addr as *mut svm_ghcb_base))
        } else {
            None
        };
        let vcpu = MshvVcpu {
            fd: vcpu_fd,
            vp_index: id,
            #[cfg(target_arch = "x86_64")]
            cpuid: Vec::new(),
            #[cfg(target_arch = "x86_64")]
            msrs: self.msrs.clone(),
            vm_ops,
            vm_fd: self.fd.clone(),
            #[cfg(feature = "sev_snp")]
            ghcb,
            #[cfg(feature = "sev_snp")]
            host_access_pages: ArcSwap::new(self.host_access_pages.load().clone()),
        };
        Ok(Arc::new(vcpu))
    }

    #[cfg(target_arch = "x86_64")]
    fn enable_split_irq(&self) -> vm::Result<()> {
        Ok(())
    }

    fn register_ioevent(
        &self,
        fd: &EventFd,
        addr: &IoEventAddress,
        datamatch: Option<DataMatch>,
    ) -> vm::Result<()> {
        #[cfg(feature = "sev_snp")]
        if self.sev_snp_enabled {
            return Ok(());
        }

        let addr = &mshv_ioctls::IoEventAddress::from(*addr);
        debug!(
            "register_ioevent fd {} addr {:x?} datamatch {:?}",
            fd.as_raw_fd(),
            addr,
            datamatch
        );
        if let Some(dm) = datamatch {
            match dm {
                vm::DataMatch::DataMatch32(mshv_dm32) => self
                    .fd
                    .register_ioevent(fd, addr, mshv_dm32)
                    .map_err(|e| vm::HypervisorVmError::RegisterIoEvent(e.into())),
                vm::DataMatch::DataMatch64(mshv_dm64) => self
                    .fd
                    .register_ioevent(fd, addr, mshv_dm64)
                    .map_err(|e| vm::HypervisorVmError::RegisterIoEvent(e.into())),
            }
        } else {
            self.fd
                .register_ioevent(fd, addr, NoDatamatch)
                .map_err(|e| vm::HypervisorVmError::RegisterIoEvent(e.into()))
        }
    }

    /// Unregister an event from a certain address it has been previously registered to.
    fn unregister_ioevent(&self, fd: &EventFd, addr: &IoEventAddress) -> vm::Result<()> {
        #[cfg(feature = "sev_snp")]
        if self.sev_snp_enabled {
            return Ok(());
        }

        let addr = &mshv_ioctls::IoEventAddress::from(*addr);
        debug!("unregister_ioevent fd {} addr {:x?}", fd.as_raw_fd(), addr);

        self.fd
            .unregister_ioevent(fd, addr, NoDatamatch)
            .map_err(|e| vm::HypervisorVmError::UnregisterIoEvent(e.into()))
    }

    /// Creates a guest physical memory region.
    fn create_user_memory_region(&self, user_memory_region: UserMemoryRegion) -> vm::Result<()> {
        let user_memory_region: mshv_user_mem_region = user_memory_region.into();
        // No matter read only or not we keep track the slots.
        // For readonly hypervisor can enable the dirty bits,
        // but a VM exit happens before setting the dirty bits
        self.dirty_log_slots.write().unwrap().insert(
            user_memory_region.guest_pfn,
            MshvDirtyLogSlot {
                guest_pfn: user_memory_region.guest_pfn,
                memory_size: user_memory_region.size,
            },
        );

        self.fd
            .map_user_memory(user_memory_region)
            .map_err(|e| vm::HypervisorVmError::CreateUserMemory(e.into()))?;
        Ok(())
    }

    /// Removes a guest physical memory region.
    fn remove_user_memory_region(&self, user_memory_region: UserMemoryRegion) -> vm::Result<()> {
        let user_memory_region: mshv_user_mem_region = user_memory_region.into();
        // Remove the corresponding entry from "self.dirty_log_slots" if needed
        self.dirty_log_slots
            .write()
            .unwrap()
            .remove(&user_memory_region.guest_pfn);

        self.fd
            .unmap_user_memory(user_memory_region)
            .map_err(|e| vm::HypervisorVmError::RemoveUserMemory(e.into()))?;
        Ok(())
    }

    fn make_user_memory_region(
        &self,
        _slot: u32,
        guest_phys_addr: u64,
        memory_size: u64,
        userspace_addr: u64,
        readonly: bool,
        _log_dirty_pages: bool,
    ) -> UserMemoryRegion {
        let mut flags = 1 << MSHV_SET_MEM_BIT_EXECUTABLE;
        if !readonly {
            flags |= 1 << MSHV_SET_MEM_BIT_WRITABLE;
        }

        mshv_user_mem_region {
            flags,
            guest_pfn: guest_phys_addr >> PAGE_SHIFT,
            size: memory_size,
            userspace_addr,
            ..Default::default()
        }
        .into()
    }

    fn create_passthrough_device(&self) -> vm::Result<VfioDeviceFd> {
        let mut vfio_dev = mshv_create_device {
            type_: MSHV_DEV_TYPE_VFIO,
            fd: 0,
            flags: 0,
        };

        self.create_device(&mut vfio_dev)
            .map_err(|e| vm::HypervisorVmError::CreatePassthroughDevice(e.into()))
    }

    ///
    /// Constructs a routing entry
    ///
    fn make_routing_entry(&self, gsi: u32, config: &InterruptSourceConfig) -> IrqRoutingEntry {
        match config {
            InterruptSourceConfig::MsiIrq(cfg) => mshv_user_irq_entry {
                gsi,
                address_lo: cfg.low_addr,
                address_hi: cfg.high_addr,
                data: cfg.data,
            }
            .into(),
            #[cfg(target_arch = "x86_64")]
            _ => {
                unreachable!()
            }
            #[cfg(target_arch = "aarch64")]
            InterruptSourceConfig::LegacyIrq(cfg) => mshv_user_irq_entry {
                gsi,
                // In order to get IRQ line we need to add `BASE_SPI_IRQ` to the pin number
                // as `BASE_SPI_IRQ` is the base SPI interrupt number exposed via FDT to the
                // guest.
                data: cfg.pin + BASE_SPI_IRQ,
                ..Default::default()
            }
            .into(),
        }
    }

    fn set_gsi_routing(&self, entries: &[IrqRoutingEntry]) -> vm::Result<()> {
        let mut msi_routing =
            vec_with_array_field::<mshv_user_irq_table, mshv_user_irq_entry>(entries.len());
        msi_routing[0].nr = entries.len() as u32;

        let entries: Vec<mshv_user_irq_entry> = entries
            .iter()
            .map(|entry| match entry {
                IrqRoutingEntry::Mshv(e) => *e,
                #[allow(unreachable_patterns)]
                _ => panic!("IrqRoutingEntry type is wrong"),
            })
            .collect();

        // SAFETY: msi_routing initialized with entries.len() and now it is being turned into
        // entries_slice with entries.len() again. It is guaranteed to be large enough to hold
        // everything from entries.
        unsafe {
            let entries_slice: &mut [mshv_user_irq_entry] =
                msi_routing[0].entries.as_mut_slice(entries.len());
            entries_slice.copy_from_slice(&entries);
        }

        self.fd
            .set_msi_routing(&msi_routing[0])
            .map_err(|e| vm::HypervisorVmError::SetGsiRouting(e.into()))
    }

    ///
    /// Start logging dirty pages
    ///
    fn start_dirty_log(&self) -> vm::Result<()> {
        self.fd
            .enable_dirty_page_tracking()
            .map_err(|e| vm::HypervisorVmError::StartDirtyLog(e.into()))
    }

    ///
    /// Stop logging dirty pages
    ///
    fn stop_dirty_log(&self) -> vm::Result<()> {
        let dirty_log_slots = self.dirty_log_slots.read().unwrap();
        // Before disabling the dirty page tracking we need
        // to set the dirty bits in the Hypervisor
        // This is a requirement from Microsoft Hypervisor
        for (_, s) in dirty_log_slots.iter() {
            self.fd
                .get_dirty_log(
                    s.guest_pfn,
                    s.memory_size as usize,
                    MSHV_GPAP_ACCESS_OP_SET as u8,
                )
                .map_err(|e| vm::HypervisorVmError::StartDirtyLog(e.into()))?;
        }
        self.fd
            .disable_dirty_page_tracking()
            .map_err(|e| vm::HypervisorVmError::StartDirtyLog(e.into()))?;
        Ok(())
    }

    ///
    /// Get dirty pages bitmap (one bit per page)
    ///
    fn get_dirty_log(&self, _slot: u32, base_gpa: u64, memory_size: u64) -> vm::Result<Vec<u64>> {
        self.fd
            .get_dirty_log(
                base_gpa >> PAGE_SHIFT,
                memory_size as usize,
                MSHV_GPAP_ACCESS_OP_CLEAR as u8,
            )
            .map_err(|e| vm::HypervisorVmError::GetDirtyLog(e.into()))
    }

    /// Retrieve guest clock.
    #[cfg(target_arch = "x86_64")]
    fn get_clock(&self) -> vm::Result<ClockData> {
        let val = self
            .fd
            .get_partition_property(hv_partition_property_code_HV_PARTITION_PROPERTY_REFERENCE_TIME)
            .map_err(|e| vm::HypervisorVmError::GetClock(e.into()))?;
        Ok(MshvClockData { ref_time: val }.into())
    }

    /// Set guest clock.
    #[cfg(target_arch = "x86_64")]
    fn set_clock(&self, data: &ClockData) -> vm::Result<()> {
        let data: MshvClockData = (*data).into();
        self.fd
            .set_partition_property(
                hv_partition_property_code_HV_PARTITION_PROPERTY_REFERENCE_TIME,
                data.ref_time,
            )
            .map_err(|e| vm::HypervisorVmError::SetClock(e.into()))
    }

    /// Downcast to the underlying MshvVm type
    fn as_any(&self) -> &dyn Any {
        self
    }

    /// Initialize the SEV-SNP VM
    #[cfg(feature = "sev_snp")]
    fn sev_snp_init(&self) -> vm::Result<()> {
        self.fd
            .set_partition_property(
                hv_partition_property_code_HV_PARTITION_PROPERTY_ISOLATION_STATE,
                hv_partition_isolation_state_HV_PARTITION_ISOLATION_SECURE as u64,
            )
            .map_err(|e| vm::HypervisorVmError::InitializeSevSnp(e.into()))
    }

    ///
    /// Importing isolated pages, these pages will be used
    /// for the PSP(Platform Security Processor) measurement.
    #[cfg(feature = "sev_snp")]
    fn import_isolated_pages(
        &self,
        page_type: u32,
        page_size: u32,
        pages: &[u64],
    ) -> vm::Result<()> {
        debug_assert!(page_size == hv_isolated_page_size_HV_ISOLATED_PAGE_SIZE_4KB);
        if pages.is_empty() {
            return Ok(());
        }

        let mut isolated_pages =
            vec_with_array_field::<mshv_import_isolated_pages, u64>(pages.len());
        isolated_pages[0].page_type = page_type as u8;
        isolated_pages[0].page_count = pages.len() as u64;
        // SAFETY: isolated_pages initialized with pages.len() and now it is being turned into
        // pages_slice with pages.len() again. It is guaranteed to be large enough to hold
        // everything from pages.
        unsafe {
            let pages_slice: &mut [u64] = isolated_pages[0].guest_pfns.as_mut_slice(pages.len());
            pages_slice.copy_from_slice(pages);
        }
        self.fd
            .import_isolated_pages(&isolated_pages[0])
            .map_err(|e| vm::HypervisorVmError::ImportIsolatedPages(e.into()))
    }

    ///
    /// Complete isolated import, telling the hypervisor that
    /// importing the pages to guest memory is complete.
    ///
    #[cfg(feature = "sev_snp")]
    fn complete_isolated_import(
        &self,
        snp_id_block: IGVM_VHS_SNP_ID_BLOCK,
        host_data: [u8; 32],
        id_block_enabled: u8,
    ) -> vm::Result<()> {
        let mut auth_info = hv_snp_id_auth_info {
            id_key_algorithm: snp_id_block.id_key_algorithm,
            auth_key_algorithm: snp_id_block.author_key_algorithm,
            ..Default::default()
        };
        // Each of r/s component is 576 bits long
        auth_info.id_block_signature[..SIG_R_COMPONENT_SIZE_IN_BYTES]
            .copy_from_slice(snp_id_block.id_key_signature.r_comp.as_ref());
        auth_info.id_block_signature
            [SIG_R_COMPONENT_SIZE_IN_BYTES..SIG_R_AND_S_COMPONENT_SIZE_IN_BYTES]
            .copy_from_slice(snp_id_block.id_key_signature.s_comp.as_ref());
        auth_info.id_key[..ECDSA_CURVE_ID_SIZE_IN_BYTES]
            .copy_from_slice(snp_id_block.id_public_key.curve.to_le_bytes().as_ref());
        auth_info.id_key[ECDSA_SIG_X_COMPONENT_START..ECDSA_SIG_X_COMPONENT_END]
            .copy_from_slice(snp_id_block.id_public_key.qx.as_ref());
        auth_info.id_key[ECDSA_SIG_Y_COMPONENT_START..ECDSA_SIG_Y_COMPONENT_END]
            .copy_from_slice(snp_id_block.id_public_key.qy.as_ref());

        let data = mshv_complete_isolated_import {
            import_data: hv_partition_complete_isolated_import_data {
                psp_parameters: hv_psp_launch_finish_data {
                    id_block: hv_snp_id_block {
                        launch_digest: snp_id_block.ld,
                        family_id: snp_id_block.family_id,
                        image_id: snp_id_block.image_id,
                        version: snp_id_block.version,
                        guest_svn: snp_id_block.guest_svn,
                        policy: get_default_snp_guest_policy(),
                    },
                    id_auth_info: auth_info,
                    host_data,
                    id_block_enabled,
                    author_key_enabled: 0,
                },
            },
        };
        self.fd
            .complete_isolated_import(&data)
            .map_err(|e| vm::HypervisorVmError::CompleteIsolatedImport(e.into()))
    }

    #[cfg(target_arch = "aarch64")]
    fn create_vgic(&self, config: VgicConfig) -> vm::Result<Arc<Mutex<dyn Vgic>>> {
        let gic_device = MshvGicV2M::new(self, config)
            .map_err(|e| vm::HypervisorVmError::CreateVgic(anyhow!("Vgic error {:?}", e)))?;

        // Register GICD address with the hypervisor
        self.fd
            .set_partition_property(
                hv_partition_property_code_HV_PARTITION_PROPERTY_GICD_BASE_ADDRESS,
                gic_device.dist_addr,
            )
            .map_err(|e| {
                vm::HypervisorVmError::CreateVgic(anyhow!("Failed to set GICD address: {}", e))
            })?;

        // Register GITS address with the hypervisor
        self.fd
            .set_partition_property(
                // spellchecker:disable-line
                hv_partition_property_code_HV_PARTITION_PROPERTY_GITS_TRANSLATER_BASE_ADDRESS,
                gic_device.gits_addr,
            )
            .map_err(|e| {
                vm::HypervisorVmError::CreateVgic(anyhow!("Failed to set GITS address: {}", e))
            })?;

        Ok(Arc::new(Mutex::new(gic_device)))
    }

    #[cfg(target_arch = "aarch64")]
    fn get_preferred_target(&self, _kvi: &mut crate::VcpuInit) -> vm::Result<()> {
        Ok(())
    }

    /// Pause the VM
    fn pause(&self) -> vm::Result<()> {
        // Freeze the partition
        self.fd
            .set_partition_property(
                hv_partition_property_code_HV_PARTITION_PROPERTY_TIME_FREEZE,
                1u64,
            )
            .map_err(|e| {
                vm::HypervisorVmError::SetVmProperty(anyhow!(
                    "Failed to set partition property: {}",
                    e
                ))
            })
    }

    /// Resume the VM
    fn resume(&self) -> vm::Result<()> {
        // Resuming the partition using TIME_FREEZE property
        self.fd
            .set_partition_property(
                hv_partition_property_code_HV_PARTITION_PROPERTY_TIME_FREEZE,
                0u64,
            )
            .map_err(|e| {
                vm::HypervisorVmError::SetVmProperty(anyhow!(
                    "Failed to set partition property: {}",
                    e
                ))
            })
    }

    #[cfg(feature = "sev_snp")]
    fn gain_page_access(&self, gpa: u64, size: u32) -> vm::Result<()> {
        use mshv_ioctls::set_bits;
        const ONE_GB: usize = 1024 * 1024 * 1024;

        if !self.sev_snp_enabled {
            return Ok(());
        }

        let start_gpfn: u64 = gpa >> PAGE_SHIFT;
        let end_gpfn: u64 = (gpa + size as u64 - 1) >> PAGE_SHIFT;

        // Enlarge the bitmap if the PFN is greater than the bitmap length
        if end_gpfn >= self.host_access_pages.load().as_ref().len() as u64 {
            self.host_access_pages.rcu(|bitmap| {
                let mut bm = bitmap.as_ref().clone();
                bm.enlarge(ONE_GB);
                bm
            });
        }

        let gpas: Vec<u64> = (start_gpfn..=end_gpfn)
            .filter(|x| {
                !self
                    .host_access_pages
                    .load()
                    .as_ref()
                    .is_bit_set(*x as usize)
            })
            .map(|x| x << PAGE_SHIFT)
            .collect();

        if !gpas.is_empty() {
            let mut gpa_list = vec_with_array_field::<mshv_modify_gpa_host_access, u64>(gpas.len());
            gpa_list[0].page_count = gpas.len() as u64;
            gpa_list[0].flags = set_bits!(
                u8,
                MSHV_GPA_HOST_ACCESS_BIT_ACQUIRE,
                MSHV_GPA_HOST_ACCESS_BIT_READABLE,
                MSHV_GPA_HOST_ACCESS_BIT_WRITABLE
            );

            // SAFETY: gpa_list initialized with gpas.len() and now it is being turned into
            // gpas_slice with gpas.len() again. It is guaranteed to be large enough to hold
            // everything from gpas.
            unsafe {
                let gpas_slice: &mut [u64] = gpa_list[0].guest_pfns.as_mut_slice(gpas.len());
                gpas_slice.copy_from_slice(gpas.as_slice());
            }

            self.fd
                .modify_gpa_host_access(&gpa_list[0])
                .map_err(|e| vm::HypervisorVmError::ModifyGpaHostAccess(e.into()))?;

            for acquired_gpa in gpas {
                self.host_access_pages.rcu(|bitmap| {
                    let bm = bitmap.clone();
                    bm.set_bit((acquired_gpa >> PAGE_SHIFT) as usize);
                    bm
                });
            }
        }

        Ok(())
    }

    fn init(&self) -> vm::Result<()> {
        #[cfg(target_arch = "aarch64")]
        {
            self.fd
                .set_partition_property(
                    hv_partition_property_code_HV_PARTITION_PROPERTY_GIC_LPI_INT_ID_BITS,
                    0,
                )
                .map_err(|e| {
                    vm::HypervisorVmError::InitializeVm(anyhow!(
                        "Failed to set GIC LPI support: {}",
                        e
                    ))
                })?;

            self.fd
                .set_partition_property(
                    hv_partition_property_code_HV_PARTITION_PROPERTY_GIC_PPI_OVERFLOW_INTERRUPT_FROM_CNTV,
                    (AARCH64_ARCH_TIMER_VIRT_IRQ + AARCH64_MIN_PPI_IRQ) as u64,
                )
                .map_err(|e| {
                    vm::HypervisorVmError::InitializeVm(anyhow!(
                        "Failed to set arch timer interrupt ID: {}",
                        e
                    ))
                })?;

            self.fd
                .set_partition_property(
                    hv_partition_property_code_HV_PARTITION_PROPERTY_GIC_PPI_PERFORMANCE_MONITORS_INTERRUPT,
                    (AARCH64_PMU_IRQ + AARCH64_MIN_PPI_IRQ) as u64,
                )
                .map_err(|e| {
                    vm::HypervisorVmError::InitializeVm(anyhow!(
                        "Failed to set PMU interrupt ID: {}",
                        e
                    ))
                })?;
        }

        self.fd
            .initialize()
            .map_err(|e| vm::HypervisorVmError::InitializeVm(e.into()))?;

        // Set additional partition property for SEV-SNP partition.
        #[cfg(feature = "sev_snp")]
        if self.sev_snp_enabled {
            let snp_policy = snp::get_default_snp_guest_policy();
            let vmgexit_offloads = snp::get_default_vmgexit_offload_features();
            // SAFETY: access union fields
            unsafe {
                debug!(
                    "Setting the partition isolation policy as: 0x{:x}",
                    snp_policy.as_uint64
                );
                self.fd
                    .set_partition_property(
                        hv_partition_property_code_HV_PARTITION_PROPERTY_ISOLATION_POLICY,
                        snp_policy.as_uint64,
                    )
                    .map_err(|e| vm::HypervisorVmError::InitializeVm(e.into()))?;
                debug!(
                    "Setting the partition property to enable VMGEXIT offloads as : 0x{:x}",
                    vmgexit_offloads.as_uint64
                );
                self.fd
                    .set_partition_property(
                        hv_partition_property_code_HV_PARTITION_PROPERTY_SEV_VMGEXIT_OFFLOADS,
                        vmgexit_offloads.as_uint64,
                    )
                    .map_err(|e| vm::HypervisorVmError::InitializeVm(e.into()))?;
            }
        }
        // Default Microsoft Hypervisor behavior for unimplemented MSR is to
        // send a fault to the guest if it tries to access it. It is possible
        // to override this behavior with a more suitable option i.e., ignore
        // writes from the guest and return zero in attempt to read unimplemented
        // MSR.
        #[cfg(target_arch = "x86_64")]
        self.fd
            .set_partition_property(
                hv_partition_property_code_HV_PARTITION_PROPERTY_UNIMPLEMENTED_MSR_ACTION,
                hv_unimplemented_msr_action_HV_UNIMPLEMENTED_MSR_ACTION_IGNORE_WRITE_READ_ZERO
                    as u64,
            )
            .map_err(|e| vm::HypervisorVmError::InitializeVm(e.into()))?;

        // Always create a frozen partition
        self.fd
            .set_partition_property(
                hv_partition_property_code_HV_PARTITION_PROPERTY_TIME_FREEZE,
                1u64,
            )
            .map_err(|e| vm::HypervisorVmError::InitializeVm(e.into()))?;

        Ok(())
    }
}
