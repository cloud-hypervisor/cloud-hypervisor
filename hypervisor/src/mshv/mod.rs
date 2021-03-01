// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2020, Microsoft Corporation
//

use crate::arch::emulator::{PlatformEmulator, PlatformError};

use thiserror::Error;

#[cfg(target_arch = "x86_64")]
use crate::arch::x86::emulator::{Emulator, EmulatorCpuState};
use crate::cpu;
use crate::cpu::Vcpu;
use crate::hypervisor;
use crate::vm::{self, VmmOps};
pub use mshv_bindings::*;
pub use mshv_ioctls::IoEventAddress;
use mshv_ioctls::{set_registers_64, InterruptRequest, Mshv, NoDatamatch, VcpuFd, VmFd};
use serde_derive::{Deserialize, Serialize};
use std::sync::Arc;
use vm::DataMatch;
// x86_64 dependencies
#[cfg(target_arch = "x86_64")]
pub mod x86_64;
use crate::device;
use vmm_sys_util::eventfd::EventFd;
#[cfg(target_arch = "x86_64")]
pub use x86_64::VcpuMshvState as CpuState;
#[cfg(target_arch = "x86_64")]
pub use x86_64::*;

use std::collections::HashMap;
use std::os::unix::io::AsRawFd;
use std::sync::RwLock;

pub const PAGE_SHIFT: usize = 12;

#[derive(Debug, Default, Copy, Clone, Serialize, Deserialize)]
pub struct HvState {
    hypercall_page: u64,
}

pub use HvState as VmState;

/// Wrapper over mshv system ioctls.
pub struct MshvHypervisor {
    mshv: Mshv,
}

impl MshvHypervisor {
    /// Create a hypervisor based on Mshv
    pub fn new() -> hypervisor::Result<MshvHypervisor> {
        let mshv_obj =
            Mshv::new().map_err(|e| hypervisor::HypervisorError::HypervisorCreate(e.into()))?;
        Ok(MshvHypervisor { mshv: mshv_obj })
    }
}
/// Implementation of Hypervisor trait for Mshv
/// Example:
/// #[cfg(feature = "mshv")]
/// extern crate hypervisor
/// let mshv = hypervisor::mshv::MshvHypervisor::new().unwrap();
/// let hypervisor: Arc<dyn hypervisor::Hypervisor> = Arc::new(mshv);
/// let vm = hypervisor.create_vm().expect("new VM fd creation failed");
///
impl hypervisor::Hypervisor for MshvHypervisor {
    /// Create a mshv vm object and return the object as Vm trait object
    /// Example
    /// # extern crate hypervisor;
    /// # use hypervisor::MshvHypervisor;
    /// use hypervisor::MshvVm;
    /// let hypervisor = MshvHypervisor::new().unwrap();
    /// let vm = hypervisor.create_vm().unwrap()
    ///
    fn create_vm(&self) -> hypervisor::Result<Arc<dyn vm::Vm>> {
        let fd: VmFd;
        loop {
            match self.mshv.create_vm() {
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

        let msr_list = self.get_msr_list()?;
        let num_msrs = msr_list.as_fam_struct_ref().nmsrs as usize;
        let mut msrs = MsrEntries::new(num_msrs).unwrap();
        let indices = msr_list.as_slice();
        let msr_entries = msrs.as_mut_slice();
        for (pos, index) in indices.iter().enumerate() {
            msr_entries[pos].index = *index;
        }
        let vm_fd = Arc::new(fd);

        let gsi_routes = Arc::new(RwLock::new(HashMap::new()));

        Ok(Arc::new(MshvVm {
            fd: vm_fd,
            msrs,
            gsi_routes,
            hv_state: hv_state_init(),
            vmmops: None,
        }))
    }
    ///
    /// Get the supported CpuID
    ///
    fn get_cpuid(&self) -> hypervisor::Result<CpuId> {
        Ok(CpuId::new(1).unwrap())
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Retrieve the list of MSRs supported by KVM.
    ///
    fn get_msr_list(&self) -> hypervisor::Result<MsrList> {
        self.mshv
            .get_msr_index_list()
            .map_err(|e| hypervisor::HypervisorError::GetMsrList(e.into()))
    }
}

#[allow(dead_code)]
/// Vcpu struct for Microsoft Hypervisor
pub struct MshvVcpu {
    fd: VcpuFd,
    vp_index: u8,
    cpuid: CpuId,
    msrs: MsrEntries,
    gsi_routes: Arc<RwLock<HashMap<u32, MshvIrqRoutingEntry>>>,
    hv_state: Arc<RwLock<HvState>>, // Mshv State
    vmmops: Option<Arc<Box<dyn vm::VmmOps>>>,
}

/// Implementation of Vcpu trait for Microsoft Hypervisor
/// Example:
/// #[cfg(feature = "mshv")]
/// extern crate hypervisor
/// let mshv = hypervisor::mshv::MshvHypervisor::new().unwrap();
/// let hypervisor: Arc<dyn hypervisor::Hypervisor> = Arc::new(mshv);
/// let vm = hypervisor.create_vm().expect("new VM fd creation failed");
/// let vcpu = vm.create_vcpu(0).unwrap();
/// vcpu.get/set().unwrap()
///
impl cpu::Vcpu for MshvVcpu {
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
    /// Sets the vCPU general purpose registers.
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
    /// Sets the vCPU special registers.
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
    /// Set the floating point state (FPU) of a vCPU.
    ///
    fn set_fpu(&self, fpu: &FpuState) -> cpu::Result<()> {
        self.fd
            .set_fpu(fpu)
            .map_err(|e| cpu::HypervisorCpuError::SetFloatingPointRegs(e.into()))
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
    /// X86 specific call to enable HyperV SynIC
    ///
    fn enable_hyperv_synic(&self) -> cpu::Result<()> {
        /* We always have SynIC enabled on MSHV */
        Ok(())
    }
    #[allow(non_upper_case_globals)]
    fn run(&self) -> std::result::Result<cpu::VmExit, cpu::HypervisorCpuError> {
        // Safe because this is just only done during initialization.
        // TODO don't zero it everytime we enter this function.
        let hv_message: hv_message = unsafe { std::mem::zeroed() };
        match self.fd.run(hv_message) {
            Ok(x) => match x.header.message_type {
                hv_message_type_HVMSG_X64_HALT => {
                    debug!("HALT");
                    Ok(cpu::VmExit::Reset)
                }
                hv_message_type_HVMSG_UNRECOVERABLE_EXCEPTION => {
                    warn!("TRIPLE FAULT");
                    Ok(cpu::VmExit::Shutdown)
                }
                hv_message_type_HVMSG_X64_IO_PORT_INTERCEPT => {
                    let info = x.to_ioport_info().unwrap();
                    let access_info = info.access_info;
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
                            let insn_len = info.header.instruction_length() as u64;

                            /* Advance RIP and update RAX */
                            let arr_reg_name_value = [
                                (
                                    hv_register_name::HV_X64_REGISTER_RIP,
                                    info.header.rip + insn_len,
                                ),
                                (hv_register_name::HV_X64_REGISTER_RAX, ret_rax),
                            ];
                            set_registers_64!(self.fd, arr_reg_name_value)
                                .map_err(|e| cpu::HypervisorCpuError::SetRegister(e.into()))?;
                            return Ok(cpu::VmExit::Ignore);
                        }
                        _ => {}
                    }

                    if unsafe { access_info.__bindgen_anon_1.string_op() } == 1 {
                        panic!("String IN/OUT not supported");
                    }
                    if unsafe { access_info.__bindgen_anon_1.rep_prefix() } == 1 {
                        panic!("Rep IN/OUT not supported");
                    }

                    if is_write {
                        let data = (info.rax as u32).to_le_bytes();
                        if let Some(vmmops) = &self.vmmops {
                            vmmops
                                .pio_write(port.into(), &data[0..len])
                                .map_err(|e| cpu::HypervisorCpuError::RunVcpu(e.into()))?;
                        }
                    } else {
                        if let Some(vmmops) = &self.vmmops {
                            vmmops
                                .pio_read(port.into(), &mut data[0..len])
                                .map_err(|e| cpu::HypervisorCpuError::RunVcpu(e.into()))?;
                        }

                        let v = u32::from_le_bytes(data);
                        /* Preserve high bits in EAX but clear out high bits in RAX */
                        let mask = 0xffffffff >> (32 - len * 8);
                        let eax = (info.rax as u32 & !mask) | (v & mask);
                        ret_rax = eax as u64;
                    }

                    let insn_len = info.header.instruction_length() as u64;

                    /* Advance RIP and update RAX */
                    let arr_reg_name_value = [
                        (
                            hv_register_name::HV_X64_REGISTER_RIP,
                            info.header.rip + insn_len,
                        ),
                        (hv_register_name::HV_X64_REGISTER_RAX, ret_rax),
                    ];
                    set_registers_64!(self.fd, arr_reg_name_value)
                        .map_err(|e| cpu::HypervisorCpuError::SetRegister(e.into()))?;
                    Ok(cpu::VmExit::Ignore)
                }
                hv_message_type_HVMSG_UNMAPPED_GPA => {
                    let info = x.to_memory_info().unwrap();
                    let insn_len = info.instruction_byte_count as usize;
                    assert!(insn_len > 0 && insn_len <= 16);

                    let mut context = MshvEmulatorContext {
                        vcpu: self,
                        map: (info.guest_virtual_address, info.guest_physical_address),
                    };

                    // Create a new emulator.
                    let mut emul = Emulator::new(&mut context);

                    // Emulate the trapped instruction, and only the first one.
                    let new_state = emul
                        .emulate_first_insn(self.vp_index as usize, &info.instruction_bytes)
                        .map_err(|e| cpu::HypervisorCpuError::RunVcpu(e.into()))?;

                    // Set CPU state back.
                    context
                        .set_cpu_state(self.vp_index as usize, new_state)
                        .map_err(|e| cpu::HypervisorCpuError::RunVcpu(e.into()))?;

                    Ok(cpu::VmExit::Ignore)
                }
                hv_message_type_HVMSG_X64_CPUID_INTERCEPT => {
                    let info = x.to_cpuid_info().unwrap();
                    debug!("cpuid eax: {:x}", info.rax);
                    Ok(cpu::VmExit::Ignore)
                }
                hv_message_type_HVMSG_X64_MSR_INTERCEPT => {
                    let info = x.to_msr_info().unwrap();
                    if info.header.intercept_access_type == 0 {
                        debug!("msr read: {:x}", info.msr_number);
                    } else {
                        debug!("msr write: {:x}", info.msr_number);
                    }
                    Ok(cpu::VmExit::Ignore)
                }
                hv_message_type_HVMSG_X64_EXCEPTION_INTERCEPT => {
                    //TODO: Handler for VMCALL here.
                    let info = x.to_exception_info().unwrap();
                    debug!("Exception Info {:?}", info.exception_vector);
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
    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call to setup the CPUID registers.
    ///
    fn set_cpuid2(&self, _cpuid: &CpuId) -> cpu::Result<()> {
        Ok(())
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call to retrieve the CPUID registers.
    ///
    fn get_cpuid2(&self, _num_entries: usize) -> cpu::Result<CpuId> {
        Ok(self.cpuid.clone())
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
    fn set_lapic(&self, lapic: &LapicState) -> cpu::Result<()> {
        self.fd
            .set_lapic(lapic)
            .map_err(|e| cpu::HypervisorCpuError::SetLapicState(e.into()))
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
            .set_xsave(*xsave)
            .map_err(|e| cpu::HypervisorCpuError::SetXsaveState(e.into()))
    }
    ///
    /// Set CPU state
    ///
    fn set_state(&self, state: &CpuState) -> cpu::Result<()> {
        self.set_msrs(&state.msrs)?;
        self.set_vcpu_events(&state.vcpu_events)?;
        self.set_regs(&state.regs)?;
        self.set_sregs(&state.sregs)?;
        self.set_fpu(&state.fpu)?;
        self.set_xcrs(&state.xcrs)?;
        self.set_lapic(&state.lapic)?;
        self.set_xsave(&state.xsave)?;
        self.fd
            .set_debug_regs(&state.dbg)
            .map_err(|e| cpu::HypervisorCpuError::SetDebugRegs(e.into()))?;
        Ok(())
    }
    ///
    /// Get CPU State
    ///
    fn state(&self) -> cpu::Result<CpuState> {
        let regs = self.get_regs()?;
        let sregs = self.get_sregs()?;
        let xcrs = self.get_xcrs()?;
        let fpu = self.get_fpu()?;
        let vcpu_events = self.get_vcpu_events()?;
        let mut msrs = self.msrs.clone();
        self.get_msrs(&mut msrs)?;
        let lapic = self.get_lapic()?;
        let xsave = self.get_xsave()?;
        let dbg = self
            .fd
            .get_debug_regs()
            .map_err(|e| cpu::HypervisorCpuError::GetDebugRegs(e.into()))?;
        Ok(CpuState {
            msrs,
            vcpu_events,
            regs,
            sregs,
            fpu,
            xcrs,
            lapic,
            dbg,
            xsave,
        })
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Translate guest virtual address to guest physical address
    ///
    fn translate_gva(&self, gva: u64, flags: u64) -> cpu::Result<(u64, hv_translate_gva_result)> {
        let r = self
            .fd
            .translate_gva(gva, flags)
            .map_err(|e| cpu::HypervisorCpuError::TranslateGVA(e.into()))?;

        Ok(r)
    }
}

struct MshvEmulatorContext<'a> {
    vcpu: &'a MshvVcpu,
    map: (u64, u64), // Initial GVA to GPA mapping provided by the hypervisor
}

impl<'a> MshvEmulatorContext<'a> {
    // Do the actual gva -> gpa translation
    #[allow(non_upper_case_globals)]
    fn translate(&self, gva: u64) -> Result<u64, PlatformError> {
        if self.map.0 == gva {
            return Ok(self.map.1);
        }

        // TODO: More fine-grained control for the flags
        let flags = HV_TRANSLATE_GVA_VALIDATE_READ | HV_TRANSLATE_GVA_VALIDATE_WRITE;

        let r = self
            .vcpu
            .translate_gva(gva, flags.into())
            .map_err(|e| PlatformError::TranslateGVA(anyhow!(e)))?;

        let result_code = unsafe { r.1.__bindgen_anon_1.result_code };
        match result_code {
            hv_translate_gva_result_code_HvTranslateGvaSuccess => Ok(r.0),
            _ => Err(PlatformError::TranslateGVA(anyhow!(result_code))),
        }
    }
}

/// Platform emulation for Hyper-V
impl<'a> PlatformEmulator for MshvEmulatorContext<'a> {
    type CpuState = EmulatorCpuState;

    fn read_memory(&self, gva: u64, data: &mut [u8]) -> Result<(), PlatformError> {
        let gpa = self.translate(gva)?;
        debug!(
            "mshv emulator: memory read {} bytes from [{:#x} -> {:#x}]",
            data.len(),
            gva,
            gpa
        );

        if let Some(vmmops) = &self.vcpu.vmmops {
            if vmmops.guest_mem_read(gpa, data).is_err() {
                vmmops
                    .mmio_read(gpa, data)
                    .map_err(|e| PlatformError::MemoryReadFailure(e.into()))?;
            }
        }

        Ok(())
    }

    fn write_memory(&mut self, gva: u64, data: &[u8]) -> Result<(), PlatformError> {
        let gpa = self.translate(gva)?;
        debug!(
            "mshv emulator: memory write {} bytes at [{:#x} -> {:#x}]",
            data.len(),
            gva,
            gpa
        );

        if let Some(vmmops) = &self.vcpu.vmmops {
            if vmmops.guest_mem_write(gpa, data).is_err() {
                vmmops
                    .mmio_write(gpa, data)
                    .map_err(|e| PlatformError::MemoryWriteFailure(e.into()))?;
            }
        }

        Ok(())
    }

    fn cpu_state(&self, cpu_id: usize) -> Result<Self::CpuState, PlatformError> {
        if cpu_id != self.vcpu.vp_index as usize {
            return Err(PlatformError::GetCpuStateFailure(anyhow!(
                "CPU id mismatch {:?} {:?}",
                cpu_id,
                self.vcpu.vp_index
            )));
        }

        let regs = self
            .vcpu
            .get_regs()
            .map_err(|e| PlatformError::GetCpuStateFailure(e.into()))?;
        let sregs = self
            .vcpu
            .get_sregs()
            .map_err(|e| PlatformError::GetCpuStateFailure(e.into()))?;

        debug!("mshv emulator: Getting new CPU state");
        debug!("mshv emulator: {:#x?}", regs);

        Ok(EmulatorCpuState { regs, sregs })
    }

    fn set_cpu_state(&self, cpu_id: usize, state: Self::CpuState) -> Result<(), PlatformError> {
        if cpu_id != self.vcpu.vp_index as usize {
            return Err(PlatformError::SetCpuStateFailure(anyhow!(
                "CPU id mismatch {:?} {:?}",
                cpu_id,
                self.vcpu.vp_index
            )));
        }

        debug!("mshv emulator: Setting new CPU state");
        debug!("mshv emulator: {:#x?}", state.regs);

        self.vcpu
            .set_regs(&state.regs)
            .map_err(|e| PlatformError::SetCpuStateFailure(e.into()))?;
        self.vcpu
            .set_sregs(&state.sregs)
            .map_err(|e| PlatformError::SetCpuStateFailure(e.into()))
    }

    fn gva_to_gpa(&self, gva: u64) -> Result<u64, PlatformError> {
        self.translate(gva)
    }

    fn fetch(&self, _ip: u64, _instruction_bytes: &mut [u8]) -> Result<(), PlatformError> {
        Err(PlatformError::MemoryReadFailure(anyhow!("unimplemented")))
    }
}

#[allow(dead_code)]
/// Wrapper over Mshv VM ioctls.
pub struct MshvVm {
    fd: Arc<VmFd>,
    msrs: MsrEntries,
    // GSI routing information
    gsi_routes: Arc<RwLock<HashMap<u32, MshvIrqRoutingEntry>>>,
    // Hypervisor State
    hv_state: Arc<RwLock<HvState>>,
    vmmops: Option<Arc<Box<dyn vm::VmmOps>>>,
}

fn hv_state_init() -> Arc<RwLock<HvState>> {
    Arc::new(RwLock::new(HvState { hypercall_page: 0 }))
}

///
/// Implementation of Vm trait for Mshv
/// Example:
/// #[cfg(feature = "mshv")]
/// # extern crate hypervisor;
/// # use hypervisor::MshvHypervisor;
/// let mshv = MshvHypervisor::new().unwrap();
/// let hypervisor: Arc<dyn hypervisor::Hypervisor> = Arc::new(mshv);
/// let vm = hypervisor.create_vm().expect("new VM fd creation failed");
/// vm.set/get().unwrap()
///
impl vm::Vm for MshvVm {
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

        let gsi_routes = self.gsi_routes.read().unwrap();

        if let Some(e) = gsi_routes.get(&gsi) {
            let msi = e
                .get_msi_routing()
                .map_err(|e| vm::HypervisorVmError::RegisterIrqFd(e.into()))?;
            let request = msi.to_interrupt_request();
            self.fd
                .register_irqfd(&fd, gsi, &request)
                .map_err(|e| vm::HypervisorVmError::RegisterIrqFd(e.into()))?;
        } else {
            error!("No routing info found for GSI {}", gsi)
        }

        Ok(())
    }
    ///
    /// Unregisters an event that will, when signaled, trigger the `gsi` IRQ.
    ///
    fn unregister_irqfd(&self, fd: &EventFd, gsi: u32) -> vm::Result<()> {
        debug!("unregister_irqfd fd {} gsi {}", fd.as_raw_fd(), gsi);

        self.fd
            .unregister_irqfd(&fd, gsi)
            .map_err(|e| vm::HypervisorVmError::UnregisterIrqFd(e.into()))?;

        Ok(())
    }
    ///
    /// Creates a VcpuFd object from a vcpu RawFd.
    ///
    fn create_vcpu(
        &self,
        id: u8,
        vmmops: Option<Arc<Box<dyn VmmOps>>>,
    ) -> vm::Result<Arc<dyn cpu::Vcpu>> {
        let vcpu_fd = self
            .fd
            .create_vcpu(id)
            .map_err(|e| vm::HypervisorVmError::CreateVcpu(e.into()))?;
        let vcpu = MshvVcpu {
            fd: vcpu_fd,
            vp_index: id,
            cpuid: CpuId::new(1).unwrap(),
            msrs: self.msrs.clone(),
            gsi_routes: self.gsi_routes.clone(),
            hv_state: self.hv_state.clone(),
            vmmops,
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
        debug!("unregister_ioevent fd {} addr {:x?}", fd.as_raw_fd(), addr);

        self.fd
            .unregister_ioevent(fd, addr, NoDatamatch)
            .map_err(|e| vm::HypervisorVmError::UnregisterIoEvent(e.into()))
    }

    /// Creates/modifies a guest physical memory slot.
    fn set_user_memory_region(&self, user_memory_region: MemoryRegion) -> vm::Result<()> {
        self.fd
            .map_user_memory(user_memory_region)
            .map_err(|e| vm::HypervisorVmError::SetUserMemory(e.into()))?;
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
    ) -> MemoryRegion {
        let mut flags = HV_MAP_GPA_READABLE | HV_MAP_GPA_EXECUTABLE;
        if !readonly {
            flags |= HV_MAP_GPA_WRITABLE;
        }

        mshv_user_mem_region {
            flags,
            guest_pfn: guest_phys_addr >> PAGE_SHIFT,
            size: memory_size,
            userspace_addr: userspace_addr as u64,
        }
    }

    fn create_passthrough_device(&self) -> vm::Result<Arc<dyn device::Device>> {
        Err(vm::HypervisorVmError::CreatePassthroughDevice(anyhow!(
            "No passthrough support"
        )))
    }

    fn set_gsi_routing(&self, irq_routing: &[IrqRoutingEntry]) -> vm::Result<()> {
        let mut routes = self.gsi_routes.write().unwrap();

        routes.drain();

        for r in irq_routing {
            debug!("gsi routing {:x?}", r);
            routes.insert(r.gsi, *r);
        }

        Ok(())
    }
    ///
    /// Get the Vm state. Return VM specific data
    ///
    fn state(&self) -> vm::Result<VmState> {
        Ok(*self.hv_state.read().unwrap())
    }
    ///
    /// Set the VM state
    ///
    fn set_state(&self, state: VmState) -> vm::Result<()> {
        self.hv_state.write().unwrap().hypercall_page = state.hypercall_page;
        Ok(())
    }
    ///
    /// Get dirty pages bitmap (one bit per page)
    ///
    fn get_dirty_log(&self, _slot: u32, _memory_size: u64) -> vm::Result<Vec<u64>> {
        Err(vm::HypervisorVmError::GetDirtyLog(anyhow!(
            "get_dirty_log not implemented"
        )))
    }
}
pub use hv_cpuid_entry as CpuIdEntry;

#[derive(Copy, Clone, Debug)]
pub struct MshvIrqRoutingMsi {
    pub address_lo: u32,
    pub address_hi: u32,
    pub data: u32,
}

#[derive(Copy, Clone, Debug)]
pub enum MshvIrqRouting {
    Msi(MshvIrqRoutingMsi),
}

#[derive(Error, Debug)]
pub enum MshvIrqRoutingEntryError {
    #[error("Invalid MSI address: {0}")]
    InvalidMsiAddress(#[source] anyhow::Error),
}

#[derive(Copy, Clone, Debug)]
pub struct MshvIrqRoutingEntry {
    pub gsi: u32,
    pub route: MshvIrqRouting,
}
pub type IrqRoutingEntry = MshvIrqRoutingEntry;

impl MshvIrqRoutingEntry {
    fn get_msi_routing(&self) -> Result<MshvIrqRoutingMsi, MshvIrqRoutingEntryError> {
        let MshvIrqRouting::Msi(msi) = self.route;
        if msi.address_hi != 0 {
            return Err(MshvIrqRoutingEntryError::InvalidMsiAddress(anyhow!(
                "MSI high address part is not zero"
            )));
        }
        Ok(msi)
    }
}

impl MshvIrqRoutingMsi {
    ///
    /// See Intel SDM vol3 10.11.1
    /// We assume APIC ID and Hyper-V Vcpu ID are the same value
    ///

    fn get_destination(&self) -> u64 {
        ((self.address_lo >> 12) & 0xff).into()
    }

    fn get_destination_mode(&self) -> bool {
        if (self.address_lo >> 2) & 0x1 == 0x1 {
            return true;
        }
        false
    }

    fn get_vector(&self) -> u8 {
        (self.data & 0xff) as u8
    }

    ///
    ///  True means level triggered
    ///
    fn get_trigger_mode(&self) -> bool {
        if (self.data >> 15) & 0x1 == 0x1 {
            return true;
        }
        false
    }

    fn get_delivery_mode(&self) -> u8 {
        ((self.data & 0x700) >> 8) as u8
    }

    ///
    ///  Translate from architectural defined delivery mode to Hyper-V type
    /// See Intel SDM vol3 10.11.2
    ///
    fn get_interrupt_type(&self) -> Option<hv_interrupt_type> {
        match self.get_delivery_mode() {
            0 => Some(hv_interrupt_type_HV_X64_INTERRUPT_TYPE_FIXED),
            1 => Some(hv_interrupt_type_HV_X64_INTERRUPT_TYPE_LOWESTPRIORITY),
            2 => Some(hv_interrupt_type_HV_X64_INTERRUPT_TYPE_SMI),
            4 => Some(hv_interrupt_type_HV_X64_INTERRUPT_TYPE_NMI),
            5 => Some(hv_interrupt_type_HV_X64_INTERRUPT_TYPE_INIT),
            7 => Some(hv_interrupt_type_HV_X64_INTERRUPT_TYPE_EXTINT),
            _ => None,
        }
    }

    pub fn to_interrupt_request(&self) -> InterruptRequest {
        InterruptRequest {
            interrupt_type: self.get_interrupt_type().unwrap(),
            apic_id: self.get_destination(),
            vector: self.get_vector() as u32,
            level_triggered: self.get_trigger_mode(),
            logical_destination_mode: self.get_destination_mode(),
            long_mode: false,
        }
    }
}

pub const CPUID_FLAG_VALID_INDEX: u32 = 0;
