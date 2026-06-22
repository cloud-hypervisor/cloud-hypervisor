// Copyright © 2026, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//

use anyhow::anyhow;
use iced_x86::Register;
use mshv_bindings::{
    HV_INTERCEPT_ACCESS_READ, HV_INTERCEPT_ACCESS_WRITE, HV_X64_REGISTER_CLASS_GENERAL,
    HV_X64_REGISTER_CLASS_IP, hv_register_assoc, hv_register_name_HV_X64_REGISTER_RCX,
    hv_register_name_HV_X64_REGISTER_RDI, hv_register_name_HV_X64_REGISTER_RIP,
    hv_register_name_HV_X64_REGISTER_RSI, hv_register_value, hv_x64_io_port_intercept_message,
};
use mshv_ioctls::set_registers_64;

use super::MshvSegmentRegister;
use crate::arch::emulator::PlatformEmulator;
use crate::arch::x86::emulator::{
    CpuStateManager, EmulatorCpuState, advance_string_op_index, string_op_backwards,
    string_op_repeat_count,
};
use crate::cpu;
use crate::mshv::MshvVcpu;
use crate::mshv::emulator::MshvEmulatorContext;

impl MshvVcpu {
    #[cfg(target_arch = "x86_64")]
    fn io_port_access_len(info: &hv_x64_io_port_intercept_message) -> cpu::Result<usize> {
        let access_info = info.access_info;
        // SAFETY: access_info comes from an MSHV IO port intercept message.
        let len = unsafe { access_info.__bindgen_anon_1.access_size() } as usize;

        match len {
            1 | 2 | 4 => Ok(len),
            _ => Err(cpu::HypervisorCpuError::RunVcpu(anyhow!(
                "Unsupported MSHV I/O port access size {len}"
            ))),
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn io_port_is_write(info: &hv_x64_io_port_intercept_message) -> cpu::Result<bool> {
        match info.header.intercept_access_type as u32 {
            HV_INTERCEPT_ACCESS_READ => Ok(false),
            HV_INTERCEPT_ACCESS_WRITE => Ok(true),
            access => Err(cpu::HypervisorCpuError::RunVcpu(anyhow!(
                "Unsupported MSHV I/O port access type {access}"
            ))),
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn io_port_is_string(info: &hv_x64_io_port_intercept_message) -> bool {
        let access_info = info.access_info;
        // SAFETY: access_info comes from an MSHV IO port intercept message.
        unsafe { access_info.__bindgen_anon_1.string_op() != 0 }
    }

    #[cfg(target_arch = "x86_64")]
    fn io_port_has_rep(info: &hv_x64_io_port_intercept_message) -> bool {
        let access_info = info.access_info;
        // SAFETY: access_info comes from an MSHV IO port intercept message.
        unsafe { access_info.__bindgen_anon_1.rep_prefix() != 0 }
    }

    #[cfg(target_arch = "x86_64")]
    pub(in crate::mshv) fn handle_io_port_intercept(
        &self,
        info: &hv_x64_io_port_intercept_message,
    ) -> cpu::Result<()> {
        if Self::io_port_is_string(info) {
            self.handle_string_io_port_intercept(info)
        } else {
            if Self::io_port_has_rep(info) {
                return Err(cpu::HypervisorCpuError::RunVcpu(anyhow!(
                    "REP prefix without string I/O is not supported"
                )));
            }

            self.handle_scalar_io_port_intercept(info)
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn handle_scalar_io_port_intercept(
        &self,
        info: &hv_x64_io_port_intercept_message,
    ) -> cpu::Result<()> {
        let len = Self::io_port_access_len(info)?;
        let is_write = Self::io_port_is_write(info)?;
        let port = info.port_number;
        let mut data: [u8; 4] = [0; 4];
        let mut ret_rax = info.rax;

        if is_write {
            let data = (info.rax as u32).to_le_bytes();
            self.io_port_pio_write(port, &data[0..len])?;
        } else {
            self.io_port_pio_read(port, &mut data[0..len])?;

            let v = u32::from_le_bytes(data);
            /* Preserve high bits in EAX but clear out high bits in RAX */
            let mask = 0xffffffff >> (32 - len * 8);
            let eax = (info.rax as u32 & !mask) | (v & mask);
            ret_rax = eax as u64;
        }

        self.advance_rip_update_rax(info, ret_rax)
    }

    #[cfg(target_arch = "x86_64")]
    fn io_port_pio_write(&self, port: u16, data: &[u8]) -> cpu::Result<()> {
        if let Some(vm_ops) = &self.vm_ops {
            vm_ops
                .pio_write(port.into(), data)
                .map_err(|e| cpu::HypervisorCpuError::RunVcpu(e.into()))?;
        }

        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn io_port_pio_read(&self, port: u16, data: &mut [u8]) -> cpu::Result<()> {
        if let Some(vm_ops) = &self.vm_ops {
            vm_ops
                .pio_read(port.into(), data)
                .map_err(|e| cpu::HypervisorCpuError::RunVcpu(e.into()))?;
        }

        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn handle_string_io_port_intercept(
        &self,
        info: &hv_x64_io_port_intercept_message,
    ) -> cpu::Result<()> {
        let len = Self::io_port_access_len(info)?;
        let is_write = Self::io_port_is_write(info)?;
        let rep_prefix = Self::io_port_has_rep(info);
        let port = info.port_number;
        let backwards = string_op_backwards(info.header.rflags);
        let mut count = string_op_repeat_count(rep_prefix, info.rcx);
        let mut rcx = info.rcx;
        let mut rsi = info.rsi;
        let mut rdi = info.rdi;

        let mut context = MshvEmulatorContext {
            vcpu: self,
            mapping: None,
        };
        let state = self.io_port_string_cpu_state(&context, info)?;

        while count > 0 {
            if is_write {
                let data = self.io_port_read_string_operand(&mut context, &state, rsi, len)?;
                self.io_port_pio_write(port, &data[..len])?;
                rsi = advance_string_op_index(rsi, len, backwards);
            } else {
                let mut data: [u8; 4] = [0; 4];
                self.io_port_pio_read(port, &mut data[..len])?;
                self.io_port_write_string_operand(&mut context, &state, rdi, &data[..len])?;
                rdi = advance_string_op_index(rdi, len, backwards);
            }

            if rep_prefix {
                rcx = rcx.wrapping_sub(1);
            }
            count -= 1;
        }

        self.advance_rip_update_string_io_regs(
            info,
            rep_prefix.then_some(rcx),
            is_write.then_some(rsi),
            (!is_write).then_some(rdi),
        )
    }

    #[cfg(target_arch = "x86_64")]
    fn io_port_string_cpu_state(
        &self,
        context: &MshvEmulatorContext<'_>,
        info: &hv_x64_io_port_intercept_message,
    ) -> cpu::Result<EmulatorCpuState> {
        let mut state = context
            .cpu_state(self.vp_index as usize)
            .map_err(|e| cpu::HypervisorCpuError::RunVcpu(e.into()))?;
        state.regs.set_rflags(info.header.rflags);
        let ds: MshvSegmentRegister = info.ds_segment.into();
        let es: MshvSegmentRegister = info.es_segment.into();
        state.sregs.ds = ds.into();
        state.sregs.es = es.into();

        Ok(state)
    }

    #[cfg(target_arch = "x86_64")]
    fn io_port_read_string_operand(
        &self,
        context: &mut MshvEmulatorContext<'_>,
        state: &EmulatorCpuState,
        rsi: u64,
        len: usize,
    ) -> cpu::Result<[u8; 4]> {
        let gva = state
            .linearize(Register::DS, rsi, false)
            .map_err(|e| cpu::HypervisorCpuError::RunVcpu(e.into()))?;
        let mut data: [u8; 4] = [0; 4];
        context
            .read_memory(gva, &mut data[..len])
            .map_err(|e| cpu::HypervisorCpuError::RunVcpu(e.into()))?;

        Ok(data)
    }

    #[cfg(target_arch = "x86_64")]
    fn io_port_write_string_operand(
        &self,
        context: &mut MshvEmulatorContext<'_>,
        state: &EmulatorCpuState,
        rdi: u64,
        data: &[u8],
    ) -> cpu::Result<()> {
        let gva = state
            .linearize(Register::ES, rdi, true)
            .map_err(|e| cpu::HypervisorCpuError::RunVcpu(e.into()))?;
        context
            .write_memory(gva, data)
            .map_err(|e| cpu::HypervisorCpuError::RunVcpu(e.into()))
    }

    #[cfg(target_arch = "x86_64")]
    fn advance_rip_update_string_io_regs(
        &self,
        info: &hv_x64_io_port_intercept_message,
        rcx: Option<u64>,
        rsi: Option<u64>,
        rdi: Option<u64>,
    ) -> cpu::Result<()> {
        let rip = info.header.rip + info.header.instruction_length() as u64;

        if let Some(reg_page) = self.fd.get_vp_reg_page() {
            let vp_reg_page = reg_page.0;
            // SAFETY: access raw pointer to reg page, access union fields
            unsafe {
                if let Some(rcx) = rcx {
                    (*vp_reg_page)
                        .__bindgen_anon_1
                        .__bindgen_anon_1
                        .__bindgen_anon_1
                        .__bindgen_anon_1
                        .rcx = rcx;
                }
                if let Some(rsi) = rsi {
                    (*vp_reg_page)
                        .__bindgen_anon_1
                        .__bindgen_anon_1
                        .__bindgen_anon_1
                        .__bindgen_anon_1
                        .rsi = rsi;
                }
                if let Some(rdi) = rdi {
                    (*vp_reg_page)
                        .__bindgen_anon_1
                        .__bindgen_anon_1
                        .__bindgen_anon_1
                        .__bindgen_anon_1
                        .rdi = rdi;
                }
                (*vp_reg_page).__bindgen_anon_1.__bindgen_anon_1.rip = rip;
                (*vp_reg_page).dirty |= 1 << HV_X64_REGISTER_CLASS_IP;
                if rcx.is_some() || rsi.is_some() || rdi.is_some() {
                    (*vp_reg_page).dirty |= 1 << HV_X64_REGISTER_CLASS_GENERAL;
                }
            }
        } else {
            let mut regs = vec![(hv_register_name_HV_X64_REGISTER_RIP, rip)];
            if let Some(rcx) = rcx {
                regs.push((hv_register_name_HV_X64_REGISTER_RCX, rcx));
            }
            if let Some(rsi) = rsi {
                regs.push((hv_register_name_HV_X64_REGISTER_RSI, rsi));
            }
            if let Some(rdi) = rdi {
                regs.push((hv_register_name_HV_X64_REGISTER_RDI, rdi));
            }

            set_registers_64!(self.fd, regs)
                .map_err(|e| cpu::HypervisorCpuError::SetRegister(e.into()))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use mshv_bindings::{hv_x64_intercept_message_header, hv_x64_io_port_access_info};

    use super::*;

    fn io_port_info(
        access_size: u8,
        string_op: bool,
        rep_prefix: bool,
        access_type: u8,
        rcx: u64,
    ) -> hv_x64_io_port_intercept_message {
        let mut access_info = hv_x64_io_port_access_info { as_uint8: 0 };

        // SAFETY: access_info is initialized locally and the bitfield setters are generated by
        // bindgen for this union variant.
        unsafe {
            access_info.__bindgen_anon_1.set_access_size(access_size);
            access_info.__bindgen_anon_1.set_string_op(string_op as u8);
            access_info
                .__bindgen_anon_1
                .set_rep_prefix(rep_prefix as u8);
        }

        hv_x64_io_port_intercept_message {
            header: hv_x64_intercept_message_header {
                intercept_access_type: access_type,
                ..Default::default()
            },
            access_info,
            rcx,
            ..Default::default()
        }
    }

    #[test]
    fn test_io_port_access_info_helpers() {
        let info = io_port_info(4, true, true, HV_INTERCEPT_ACCESS_WRITE as u8, 7);

        assert_eq!(MshvVcpu::io_port_access_len(&info).unwrap(), 4);
        assert!(MshvVcpu::io_port_is_write(&info).unwrap());
        assert!(MshvVcpu::io_port_is_string(&info));
        assert!(MshvVcpu::io_port_has_rep(&info));
    }

    #[test]
    fn test_io_port_access_info_rejects_invalid_values() {
        let bad_size = io_port_info(3, false, false, HV_INTERCEPT_ACCESS_READ as u8, 0);
        let bad_access = io_port_info(1, false, false, 0xff, 0);

        MshvVcpu::io_port_access_len(&bad_size).unwrap_err();
        MshvVcpu::io_port_is_write(&bad_access).unwrap_err();
    }
}
