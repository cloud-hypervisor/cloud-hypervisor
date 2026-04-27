// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2024, Microsoft Corporation
//

use anyhow::anyhow;
use iced_x86::Register;
use log::debug;
use mshv_bindings::*;

use crate::arch::emulator::{PlatformEmulator, PlatformError};
use crate::arch::x86::emulator::{CpuStateManager, EmulatorCpuState};
use crate::cpu::Vcpu;
use crate::mshv::MshvVcpu;

pub struct MshvEmulatorContext<'a> {
    pub vcpu: &'a MshvVcpu,
    /// Initial (GVA, GPA) mapping provided by the hypervisor if the hypervisor provided a
    /// valid mapping. Used as a fast path in [`MshvEmulatorContext::translate`] to avoid a
    /// translate hypercall. `None` when the hypervisor did not provide a valid mapping.
    pub mapping: Option<(u64, u64)>,
}

impl MshvEmulatorContext<'_> {
    // Do the actual gva -> gpa translation
    #[allow(non_upper_case_globals)]
    fn translate(&self, gva: u64, flags: u32) -> Result<u64, PlatformError> {
        if let Some((cached_gva, cached_gpa)) = self.mapping
            && cached_gva == gva
        {
            return Ok(cached_gpa);
        }

        let (gpa, result_code) = self
            .vcpu
            .translate_gva(gva, flags.into())
            .map_err(|e| PlatformError::TranslateVirtualAddress(anyhow!(e)))?;

        match result_code {
            hv_translate_gva_result_code_HV_TRANSLATE_GVA_SUCCESS => Ok(gpa),
            _ => Err(PlatformError::TranslateVirtualAddress(anyhow!(result_code))),
        }
    }

    fn r(&self, gva: u64, data: &mut [u8], flags: u32) -> Result<(), PlatformError> {
        let gpa = self.translate(gva, flags)?;
        debug!(
            "mshv emulator: memory read {} bytes from [{:#x} -> {:#x}]",
            data.len(),
            gva,
            gpa
        );

        if let Some(vm_ops) = &self.vcpu.vm_ops
            && vm_ops.guest_mem_read(gpa, data).is_err()
        {
            vm_ops
                .mmio_read(gpa, data)
                .map_err(|e| PlatformError::MemoryReadFailure(e.into()))?;
        }

        Ok(())
    }

    fn read_memory_flags(
        &self,
        gva: u64,
        data: &mut [u8],
        flags: u32,
    ) -> Result<(), PlatformError> {
        let mut len = data.len() as u64;

        // Compare the page number of the first and last byte. If they are different, this is a
        // cross-page access.
        let pg1 = gva >> HV_HYP_PAGE_SHIFT;
        let pg2 = (gva + len - 1) >> HV_HYP_PAGE_SHIFT;
        let cross_page = pg1 != pg2;

        if cross_page {
            // We only handle one page cross-page access
            assert!(pg1 + 1 == pg2);
            let n = (gva + len) & HV_HYP_PAGE_MASK as u64;
            len -= n;
        }

        self.r(gva, &mut data[..len as usize], flags)?;

        if cross_page {
            self.r(gva + len, &mut data[len as usize..], flags)?;
        }

        Ok(())
    }

    fn w(&mut self, gva: u64, data: &[u8]) -> Result<(), PlatformError> {
        let gpa = self.translate(gva, HV_TRANSLATE_GVA_VALIDATE_WRITE)?;
        debug!(
            "mshv emulator: memory write {} bytes at [{:#x} -> {:#x}]",
            data.len(),
            gva,
            gpa
        );

        if let Some(vm_ops) = &self.vcpu.vm_ops
            && vm_ops.guest_mem_write(gpa, data).is_err()
        {
            vm_ops
                .mmio_write(gpa, data)
                .map_err(|e| PlatformError::MemoryWriteFailure(e.into()))?;
        }

        Ok(())
    }

    pub fn update_cpu_state(
        &self,
        cpu_id: usize,
        old_state: <Self as PlatformEmulator>::CpuState,
        new_state: <Self as PlatformEmulator>::CpuState,
    ) -> Result<(), PlatformError> {
        if cpu_id != self.vcpu.vp_index as usize {
            return Err(PlatformError::SetCpuStateFailure(anyhow!(
                "CPU id mismatch {:?} {:?}",
                cpu_id,
                self.vcpu.vp_index
            )));
        }

        debug!("mshv emulator: Updating CPU state");
        debug!("mshv emulator: {:#x?}", new_state.regs);

        self.vcpu
            .set_regs(&new_state.regs)
            .map_err(|e| PlatformError::SetCpuStateFailure(e.into()))?;

        if old_state.sregs != new_state.sregs {
            debug!("mshv emulator: Updating CPU segment registers");
            // Emulation only modifies segment registers among special
            // registers. Use the VP register page to write only segments,
            // avoiding IOCTLs for other special registers (tr, ldt, gdt,
            // idt, cr*, efer, etc.) that emulation never modifies.
            if let Some(reg_page) = self.vcpu.fd.get_vp_reg_page() {
                let vp_reg_page = reg_page.0;
                let sregs: SpecialRegisters = new_state.sregs.into();
                // SAFETY: vp_reg_page is a valid mapped pointer
                unsafe {
                    (*vp_reg_page).__bindgen_anon_3.__bindgen_anon_1.cs = sregs.cs.into();
                    (*vp_reg_page).__bindgen_anon_3.__bindgen_anon_1.ds = sregs.ds.into();
                    (*vp_reg_page).__bindgen_anon_3.__bindgen_anon_1.es = sregs.es.into();
                    (*vp_reg_page).__bindgen_anon_3.__bindgen_anon_1.fs = sregs.fs.into();
                    (*vp_reg_page).__bindgen_anon_3.__bindgen_anon_1.gs = sregs.gs.into();
                    (*vp_reg_page).__bindgen_anon_3.__bindgen_anon_1.ss = sregs.ss.into();
                    (*vp_reg_page).dirty |= 1 << HV_X64_REGISTER_CLASS_SEGMENT;
                }
            } else {
                debug!("mshv emulator: {:#x?}", new_state.sregs);
                self.vcpu
                    .set_sregs(&new_state.sregs)
                    .map_err(|e| PlatformError::SetCpuStateFailure(e.into()))?;
            }
        }

        Ok(())
    }
}

/// Platform emulation for Hyper-V
impl PlatformEmulator for MshvEmulatorContext<'_> {
    type CpuState = EmulatorCpuState;

    fn read_memory(&self, gva: u64, data: &mut [u8]) -> Result<(), PlatformError> {
        self.read_memory_flags(gva, data, HV_TRANSLATE_GVA_VALIDATE_READ)
    }

    fn write_memory(&mut self, gva: u64, data: &[u8]) -> Result<(), PlatformError> {
        let mut len = data.len() as u64;

        // Compare the page number of the first and last byte. If they are different, this is a
        // cross-page access.
        let pg1 = gva >> HV_HYP_PAGE_SHIFT;
        let pg2 = (gva + len - 1) >> HV_HYP_PAGE_SHIFT;
        let cross_page = pg1 != pg2;

        if cross_page {
            // We only handle one page cross-page access
            assert!(pg1 + 1 == pg2);
            let n = (gva + len) & HV_HYP_PAGE_MASK as u64;
            len -= n;
        }

        self.w(gva, &data[..len as usize])?;

        if cross_page {
            self.w(gva + len, &data[len as usize..])?;
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

        // For emulation, we only need segment registers, cr0, and efer
        // from special registers. Read them directly from the VP register
        // page to avoid IOCTLs for other special registers (tr, ldt, gdt,
        // idt, cr2, apic_base, etc.) that emulation doesn't use.
        let sregs = if let Some(reg_page) = self.vcpu.fd.get_vp_reg_page() {
            let vp_reg_page = reg_page.0;
            let mut mshv_sregs = SpecialRegisters::default();
            // SAFETY: vp_reg_page is a valid mapped pointer
            unsafe {
                mshv_sregs.cs = (*vp_reg_page).__bindgen_anon_3.__bindgen_anon_1.cs.into();
                mshv_sregs.ds = (*vp_reg_page).__bindgen_anon_3.__bindgen_anon_1.ds.into();
                mshv_sregs.es = (*vp_reg_page).__bindgen_anon_3.__bindgen_anon_1.es.into();
                mshv_sregs.fs = (*vp_reg_page).__bindgen_anon_3.__bindgen_anon_1.fs.into();
                mshv_sregs.gs = (*vp_reg_page).__bindgen_anon_3.__bindgen_anon_1.gs.into();
                mshv_sregs.ss = (*vp_reg_page).__bindgen_anon_3.__bindgen_anon_1.ss.into();
                mshv_sregs.cr0 = (*vp_reg_page).cr0;
                mshv_sregs.efer = (*vp_reg_page).efer;
            }
            mshv_sregs.into()
        } else {
            self.vcpu
                .get_sregs()
                .map_err(|e| PlatformError::GetCpuStateFailure(e.into()))?
        };

        debug!("mshv emulator: Getting new CPU state");
        debug!("mshv emulator: {regs:#x?}");

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

    fn fetch(&self, ip: u64, instruction_bytes: &mut [u8]) -> Result<(), PlatformError> {
        let rip =
            self.cpu_state(self.vcpu.vp_index as usize)?
                .linearize(Register::CS, ip, false)?;
        self.read_memory_flags(
            rip,
            instruction_bytes,
            HV_TRANSLATE_GVA_VALIDATE_READ | HV_TRANSLATE_GVA_VALIDATE_EXECUTE,
        )
    }
}
