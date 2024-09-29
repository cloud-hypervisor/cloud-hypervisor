// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2024, Microsoft Corporation
//

use iced_x86::Register;
use mshv_bindings::*;

use crate::arch::emulator::{PlatformEmulator, PlatformError};
use crate::arch::x86::emulator::{CpuStateManager, EmulatorCpuState};
use crate::cpu::Vcpu;
use crate::mshv::MshvVcpu;

pub struct MshvEmulatorContext<'a> {
    pub vcpu: &'a MshvVcpu,
    pub map: (u64, u64), // Initial GVA to GPA mapping provided by the hypervisor
}

impl<'a> MshvEmulatorContext<'a> {
    // Do the actual gva -> gpa translation
    #[allow(non_upper_case_globals)]
    fn translate(&self, gva: u64, flags: u32) -> Result<u64, PlatformError> {
        if self.map.0 == gva {
            return Ok(self.map.1);
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

    fn read_memory_flags(
        &self,
        gva: u64,
        data: &mut [u8],
        flags: u32,
    ) -> Result<(), PlatformError> {
        let gpa = self.translate(gva, flags)?;
        debug!(
            "mshv emulator: memory read {} bytes from [{:#x} -> {:#x}]",
            data.len(),
            gva,
            gpa
        );

        if let Some(vm_ops) = &self.vcpu.vm_ops {
            if vm_ops.guest_mem_read(gpa, data).is_err() {
                vm_ops
                    .mmio_read(gpa, data)
                    .map_err(|e| PlatformError::MemoryReadFailure(e.into()))?;
            }
        }

        Ok(())
    }
}

/// Platform emulation for Hyper-V
impl<'a> PlatformEmulator for MshvEmulatorContext<'a> {
    type CpuState = EmulatorCpuState;

    fn read_memory(&self, gva: u64, data: &mut [u8]) -> Result<(), PlatformError> {
        self.read_memory_flags(gva, data, HV_TRANSLATE_GVA_VALIDATE_READ)
    }

    fn write_memory(&mut self, gva: u64, data: &[u8]) -> Result<(), PlatformError> {
        let gpa = self.translate(gva, HV_TRANSLATE_GVA_VALIDATE_WRITE)?;
        debug!(
            "mshv emulator: memory write {} bytes at [{:#x} -> {:#x}]",
            data.len(),
            gva,
            gpa
        );

        if let Some(vm_ops) = &self.vcpu.vm_ops {
            if vm_ops.guest_mem_write(gpa, data).is_err() {
                vm_ops
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
