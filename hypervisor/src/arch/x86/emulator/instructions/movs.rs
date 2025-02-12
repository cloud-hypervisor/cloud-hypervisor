//
// Copyright © 2021 Microsoft
//
// SPDX-License-Identifier: Apache-2.0
//

#![allow(non_camel_case_types)]

//
// MOVS - Move Data from String to String
//

use crate::arch::x86::emulator::instructions::*;
use crate::arch::x86::regs::DF;

macro_rules! movs {
    ($bound:ty) => {
        fn emulate(
            &self,
            insn: &Instruction,
            state: &mut T,
            platform: &mut dyn PlatformEmulator<CpuState = T>,
        ) -> Result<(), EmulationError<Exception>> {
            let mut count: u64 = if insn.has_rep_prefix() {
                state
                    .read_reg(Register::ECX)
                    .map_err(|e| EmulationError::InvalidOperand(anyhow!(e)))?
            } else {
                1
            };

            let mut rsi = state
                .read_reg(Register::RSI)
                .map_err(|e| EmulationError::InvalidOperand(anyhow!(e)))?;
            let mut rdi = state
                .read_reg(Register::RDI)
                .map_err(|e| EmulationError::InvalidOperand(anyhow!(e)))?;

            let df = (state.flags() & DF) != 0;
            let len = std::mem::size_of::<$bound>();

            while count > 0 {
                let mut memory: [u8; 8] = [0; 8];

                let src = state
                    .linearize(Register::DS, rsi, false)
                    .map_err(|e| EmulationError::InvalidOperand(anyhow!(e)))?;
                let dst = state
                    .linearize(Register::ES, rdi, true)
                    .map_err(|e| EmulationError::InvalidOperand(anyhow!(e)))?;

                platform
                    .read_memory(src, &mut memory[0..len])
                    .map_err(EmulationError::PlatformEmulationError)?;
                platform
                    .write_memory(dst, &memory[0..len])
                    .map_err(EmulationError::PlatformEmulationError)?;

                if df {
                    rsi = rsi.wrapping_sub(len as u64);
                    rdi = rdi.wrapping_sub(len as u64);
                } else {
                    rsi = rsi.wrapping_add(len as u64);
                    rdi = rdi.wrapping_add(len as u64);
                }
                count -= 1;
            }

            state
                .write_reg(Register::RSI, rsi)
                .map_err(|e| EmulationError::InvalidOperand(anyhow!(e)))?;
            state
                .write_reg(Register::RDI, rdi)
                .map_err(|e| EmulationError::InvalidOperand(anyhow!(e)))?;
            if insn.has_rep_prefix() {
                state
                    .write_reg(Register::ECX, 0)
                    .map_err(|e| EmulationError::InvalidOperand(anyhow!(e)))?;
            }

            Ok(())
        }
    };
}

pub struct Movsq_m64_m64;
impl<T: CpuStateManager> InstructionHandler<T> for Movsq_m64_m64 {
    movs!(u64);
}

pub struct Movsd_m32_m32;
impl<T: CpuStateManager> InstructionHandler<T> for Movsd_m32_m32 {
    movs!(u32);
}

pub struct Movsw_m16_m16;
impl<T: CpuStateManager> InstructionHandler<T> for Movsw_m16_m16 {
    movs!(u16);
}

pub struct Movsb_m8_m8;
impl<T: CpuStateManager> InstructionHandler<T> for Movsb_m8_m8 {
    movs!(u8);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::x86::emulator::mock_vmm::*;

    #[test]
    fn test_rep_movsq_m64_m64() {
        let ip: u64 = 0x1000;
        let memory: [u8; 32] = [
            0x78, 0x56, 0x34, 0x12, // 0x12345678
            0xdd, 0xcc, 0xbb, 0xaa, // 0xaabbccdd
            0xa5, 0x5a, 0xa5, 0x5a, // 0x5aa55aa5
            0xcd, 0xcd, 0xcd, 0xcd, // 0xcdcdcdcd
            0x00, 0x00, 0x00, 0x00, // 0x00000000
            0x00, 0x00, 0x00, 0x00, // 0x00000000
            0x00, 0x00, 0x00, 0x00, // 0x00000000
            0x00, 0x00, 0x00, 0x00, // 0x00000000
        ];
        let insn = [0xf3, 0x48, 0xa5]; // rep movsq
        let regs = vec![
            (Register::ECX, 2),
            (Register::ESI, 0),
            (Register::EDI, 0x10),
        ];
        let mut data = [0u8; 8];

        let mut vmm = MockVmm::new(ip, regs, Some((0, &memory)));

        vmm.emulate_first_insn(0, &insn).unwrap();

        vmm.read_memory(0x10, &mut data).unwrap();
        assert_eq!(0xaabbccdd12345678, <u64>::from_le_bytes(data));
        vmm.read_memory(0x18, &mut data).unwrap();
        assert_eq!(0xcdcdcdcd5aa55aa5, <u64>::from_le_bytes(data));
        // The rest should be default value 0 from MockVmm
        vmm.read_memory(0x20, &mut data).unwrap();
        assert_eq!(0x0, <u64>::from_le_bytes(data));
    }

    #[test]
    fn test_rep_movsd_m32_m32() {
        let ip: u64 = 0x1000;
        let memory: [u8; 24] = [
            0x78, 0x56, 0x34, 0x12, // 0x12345678
            0xdd, 0xcc, 0xbb, 0xaa, // 0xaabbccdd
            0xa5, 0x5a, 0xa5, 0x5a, // 0x5aa55aa5
            0x00, 0x00, 0x00, 0x00, // 0x00000000
            0x00, 0x00, 0x00, 0x00, // 0x00000000
            0x00, 0x00, 0x00, 0x00, // 0x00000000
        ];
        let insn = [0xf3, 0xa5]; // rep movsd
        let regs = vec![(Register::ECX, 3), (Register::ESI, 0), (Register::EDI, 0xc)];
        let mut data = [0u8; 4];

        let mut vmm = MockVmm::new(ip, regs, Some((0, &memory)));

        vmm.emulate_first_insn(0, &insn).unwrap();

        vmm.read_memory(0xc, &mut data).unwrap();
        assert_eq!(0x12345678, <u32>::from_le_bytes(data));
        vmm.read_memory(0xc + 4, &mut data).unwrap();
        assert_eq!(0xaabbccdd, <u32>::from_le_bytes(data));
        vmm.read_memory(0xc + 8, &mut data).unwrap();
        assert_eq!(0x5aa55aa5, <u32>::from_le_bytes(data));
        // The rest should be default value 0 from MockVmm
        vmm.read_memory(0xc + 12, &mut data).unwrap();
        assert_eq!(0x0, <u32>::from_le_bytes(data));
    }

    #[test]
    fn test_movsd_m32_m32() {
        let ip: u64 = 0x1000;
        let memory: [u8; 4] = [
            0x78, 0x56, 0x34, 0x12, // 0x12345678
        ];
        let insn = [0xa5]; // movsd
        let regs = vec![(Register::ESI, 0), (Register::EDI, 0x8)];
        let mut data = [0u8; 4];

        let mut vmm = MockVmm::new(ip, regs, Some((0, &memory)));

        vmm.emulate_first_insn(0, &insn).unwrap();

        vmm.read_memory(0x8, &mut data).unwrap();
        assert_eq!(0x12345678, <u32>::from_le_bytes(data));
        // The rest should be default value 0 from MockVmm
        vmm.read_memory(0x4, &mut data).unwrap();
        assert_eq!(0x0, <u32>::from_le_bytes(data));
        vmm.read_memory(0x8 + 8, &mut data).unwrap();
        assert_eq!(0x0, <u32>::from_le_bytes(data));
    }

    #[test]
    fn test_rep_movsw_m16_m16() {
        let ip: u64 = 0x1000;
        let memory: [u8; 24] = [
            0x78, 0x56, 0x34, 0x12, // 0x12345678
            0xdd, 0xcc, 0xbb, 0xaa, // 0xaabbccdd
            0xa5, 0x5a, 0xa5, 0x5a, // 0x5aa55aa5
            0x00, 0x00, 0x00, 0x00, // 0x00000000
            0x00, 0x00, 0x00, 0x00, // 0x00000000
            0x00, 0x00, 0x00, 0x00, // 0x00000000
        ];
        let insn = [0x66, 0xf3, 0xa5]; // rep movsw
        let regs = vec![(Register::ECX, 6), (Register::ESI, 0), (Register::EDI, 0xc)];
        let mut data = [0u8; 2];

        let mut vmm = MockVmm::new(ip, regs, Some((0, &memory)));

        vmm.emulate_first_insn(0, &insn).unwrap();

        vmm.read_memory(0xc, &mut data).unwrap();
        assert_eq!(0x5678, <u16>::from_le_bytes(data));
        vmm.read_memory(0xc + 2, &mut data).unwrap();
        assert_eq!(0x1234, <u16>::from_le_bytes(data));
        vmm.read_memory(0xc + 4, &mut data).unwrap();
        assert_eq!(0xccdd, <u16>::from_le_bytes(data));
        vmm.read_memory(0xc + 6, &mut data).unwrap();
        assert_eq!(0xaabb, <u16>::from_le_bytes(data));
        vmm.read_memory(0xc + 8, &mut data).unwrap();
        assert_eq!(0x5aa5, <u16>::from_le_bytes(data));
        vmm.read_memory(0xc + 10, &mut data).unwrap();
        assert_eq!(0x5aa5, <u16>::from_le_bytes(data));
        // The rest should be default value 0 from MockVmm
        vmm.read_memory(0xc + 12, &mut data).unwrap();
        assert_eq!(0x0, <u16>::from_le_bytes(data));
    }

    #[test]
    fn test_movsw_m16_m16() {
        let ip: u64 = 0x1000;
        let memory: [u8; 4] = [
            0x78, 0x56, 0x34, 0x12, // 0x12345678
        ];
        let insn = [0x66, 0xa5]; // movsw
        let regs = vec![(Register::ESI, 0), (Register::EDI, 0x8)];
        let mut data = [0u8; 2];

        let mut vmm = MockVmm::new(ip, regs, Some((0, &memory)));

        vmm.emulate_first_insn(0, &insn).unwrap();

        vmm.read_memory(0x8, &mut data).unwrap();
        assert_eq!(0x5678, <u16>::from_le_bytes(data));
        // Only two bytes were copied, so the value at 0xa should be zero
        vmm.read_memory(0xa, &mut data).unwrap();
        assert_eq!(0x0, <u16>::from_le_bytes(data));
        // The rest should be default value 0 from MockVmm
        vmm.read_memory(0x4, &mut data).unwrap();
        assert_eq!(0x0, <u16>::from_le_bytes(data));
        vmm.read_memory(0x8 + 8, &mut data).unwrap();
        assert_eq!(0x0, <u16>::from_le_bytes(data));
    }

    #[test]
    fn test_movsb_m8_m8() {
        let ip: u64 = 0x1000;
        let memory: [u8; 4] = [
            0x78, 0x56, 0x34, 0x12, // 0x12345678
        ];
        let insn = [0x66, 0xa4]; // movsb
        let regs = vec![(Register::ESI, 0), (Register::EDI, 0x8)];
        let mut data = [0u8; 1];

        let mut vmm = MockVmm::new(ip, regs, Some((0, &memory)));

        vmm.emulate_first_insn(0, &insn).unwrap();

        vmm.read_memory(0x8, &mut data).unwrap();
        assert_eq!(0x78, data[0]);
        // Only one byte was copied, so the value at 0x9 should be zero
        vmm.read_memory(0x9, &mut data).unwrap();
        assert_eq!(0x0, data[0]);
        // The rest should be default value 0 from MockVmm
        vmm.read_memory(0x4, &mut data).unwrap();
        assert_eq!(0x0, data[0]);
        // the src value is left as is after movb
        vmm.read_memory(0x0, &mut data).unwrap();
        assert_eq!(0x78, data[0]);
    }

    #[test]
    fn test_rep_movsb_m8_m8() {
        let ip: u64 = 0x1000;
        let memory: [u8; 16] = [
            0x78, 0x56, 0x34, 0x12, // 0x12345678
            0xbb, 0xaa, 0x00, 0x00, // 0x0000aabb
            0x00, 0x00, 0x00, 0x00, // 0x00000000
            0x00, 0x00, 0x00, 0x00, // 0x00000000
        ];
        let insn = [0x66, 0xf3, 0xa4]; // rep movsw
        let regs = vec![(Register::ECX, 6), (Register::ESI, 0), (Register::EDI, 0x8)];
        let mut data = [0u8; 1];

        let mut vmm = MockVmm::new(ip, regs, Some((0, &memory)));

        vmm.emulate_first_insn(0, &insn).unwrap();

        vmm.read_memory(0x8, &mut data).unwrap();
        assert_eq!(0x78, data[0]);
        vmm.read_memory(0x8 + 1, &mut data).unwrap();
        assert_eq!(0x56, data[0]);
        vmm.read_memory(0x8 + 2, &mut data).unwrap();
        assert_eq!(0x34, data[0]);
        vmm.read_memory(0x8 + 3, &mut data).unwrap();
        assert_eq!(0x12, data[0]);
        vmm.read_memory(0x8 + 4, &mut data).unwrap();
        assert_eq!(0xbb, data[0]);
        vmm.read_memory(0x8 + 5, &mut data).unwrap();
        assert_eq!(0xaa, data[0]);
        // The rest should be default value 0 from MockVmm
        vmm.read_memory(0x8 + 6, &mut data).unwrap();
        assert_eq!(0x0, data[0]);
    }
}
