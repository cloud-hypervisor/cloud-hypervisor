// Copyright © 2026, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//

use anyhow::anyhow;
use mshv_bindings::{
    HV_INTERCEPT_ACCESS_READ, HV_INTERCEPT_ACCESS_WRITE, hv_x64_io_port_intercept_message,
};

use crate::cpu;
use crate::mshv::MshvVcpu;

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
        let port = info.port_number;

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
                self.advance_rip_update_rax(info, info.rax)?;
                return Ok(());
            }
            _ => {}
        }

        assert!(
            !Self::io_port_is_string(info),
            "String IN/OUT not supported"
        );
        assert!(!Self::io_port_has_rep(info), "Rep IN/OUT not supported");

        self.handle_scalar_io_port_intercept(info)
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

        self.advance_rip_update_rax(info, ret_rax)
    }
}

#[cfg(test)]
mod tests {
    use mshv_bindings::hv_x64_io_port_access_info;

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

        let mut info = hv_x64_io_port_intercept_message::default();
        info.access_info = access_info;
        info.header.intercept_access_type = access_type;
        info.rcx = rcx;
        info
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

        assert!(MshvVcpu::io_port_access_len(&bad_size).is_err());
        assert!(MshvVcpu::io_port_is_write(&bad_access).is_err());
    }
}
