//
// Copyright © 2024 Microsoft
//
// SPDX-License-Identifier: Apache-2.0
//

#![allow(non_camel_case_types)]

//
// STOS - Store String
//

use crate::arch::x86::emulator::instructions::*;
use crate::arch::x86::regs::DF;

macro_rules! stos {
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

            let rax = state
                .read_reg(Register::RAX)
                .map_err(|e| EmulationError::InvalidOperand(anyhow!(e)))?;

            let mut rdi = state
                .read_reg(Register::RDI)
                .map_err(|e| EmulationError::InvalidOperand(anyhow!(e)))?;

            let df = (state.flags() & DF) != 0;
            let len = std::mem::size_of::<$bound>();
            let rax_bytes = rax.to_le_bytes();

            while count > 0 {
                let dst = state
                    .linearize(Register::ES, rdi, true)
                    .map_err(|e| EmulationError::InvalidOperand(anyhow!(e)))?;

                platform
                    .write_memory(dst, &rax_bytes[0..len])
                    .map_err(EmulationError::PlatformEmulationError)?;

                if df {
                    rdi = rdi.wrapping_sub(len as u64);
                } else {
                    rdi = rdi.wrapping_add(len as u64);
                }
                count -= 1;
            }

            if insn.has_rep_prefix() {
                state
                    .write_reg(Register::ECX, 0)
                    .map_err(|e| EmulationError::InvalidOperand(anyhow!(e)))?;
            }

            Ok(())
        }
    };
}

pub struct Stosq_m64_RAX;
impl<T: CpuStateManager> InstructionHandler<T> for Stosq_m64_RAX {
    stos!(u64);
}

pub struct Stosd_m32_EAX;
impl<T: CpuStateManager> InstructionHandler<T> for Stosd_m32_EAX {
    stos!(u32);
}

pub struct Stosw_m16_AX;
impl<T: CpuStateManager> InstructionHandler<T> for Stosw_m16_AX {
    stos!(u16);
}

pub struct Stosb_m8_AL;
impl<T: CpuStateManager> InstructionHandler<T> for Stosb_m8_AL {
    stos!(u8);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::x86::emulator::mock_vmm::*;

    #[test]
    fn test_rep_stosb() {
        let ip: u64 = 0x1000;
        let memory: [u8; 12] = [
            0x78, 0x56, 0x34, 0x12, // 0x12345678
            0xdd, 0xcc, 0xbb, 0xaa, // 0xaabbccdd
            0xa5, 0x5a, 0xa5, 0x5a, // 0x5aa55aa5
        ];
        let insn = [0xf3, 0xaa]; // rep stosb
        let regs = vec![
            (Register::ECX, 3),
            (Register::EDI, 0x0),
            (Register::RAX, 0x123456ff),
        ];
        let mut data = [0u8; 4];

        let mut vmm = MockVmm::new(ip, regs, Some((0, &memory)));

        vmm.emulate_first_insn(0, &insn).unwrap();

        vmm.read_memory(0, &mut data).unwrap();
        assert_eq!(0x12ffffff, <u32>::from_le_bytes(data));
        vmm.read_memory(4, &mut data).unwrap();
        assert_eq!(0xaabbccdd, <u32>::from_le_bytes(data));
        vmm.read_memory(8, &mut data).unwrap();
        assert_eq!(0x5aa55aa5, <u32>::from_le_bytes(data));
    }

    #[test]
    fn test_stosw() {
        let ip: u64 = 0x1000;
        let memory: [u8; 4] = [
            0x78, 0x56, 0x34, 0x12, // 0x12345678
        ];
        let insn = [0x66, 0xab]; // stosw
        let regs = vec![(Register::EDI, 0x1), (Register::AX, 0xaabb)];
        let mut data = [0u8; 4];

        let mut vmm = MockVmm::new(ip, regs, Some((0, &memory)));

        vmm.emulate_first_insn(0, &insn).unwrap();

        vmm.read_memory(0x0, &mut data).unwrap();
        assert_eq!(0x12aabb78, <u32>::from_le_bytes(data));
        // The rest should be default value 0 from MockVmm
        vmm.read_memory(0x4, &mut data).unwrap();
        assert_eq!(0x0, <u32>::from_le_bytes(data));
        vmm.read_memory(0x8 + 8, &mut data).unwrap();
        assert_eq!(0x0, <u32>::from_le_bytes(data));
    }

    #[test]
    fn test_rep_stosw() {
        let ip: u64 = 0x1000;
        let memory: [u8; 8] = [
            0x78, 0x56, 0x34, 0x12, // 0x12345678
            0x00, 0x00, 0x00, 0x00, // 0x00000000
        ];
        let insn = [0x66, 0xf3, 0xab]; // rep stosw
        let regs = vec![
            (Register::ECX, 2),
            (Register::EDI, 0x2),
            (Register::AX, 0xaabb),
        ];
        let mut data = [0u8; 4];

        let mut vmm = MockVmm::new(ip, regs, Some((0, &memory)));

        vmm.emulate_first_insn(0, &insn).unwrap();

        vmm.read_memory(0x0, &mut data).unwrap();
        assert_eq!(0xaabb5678, <u32>::from_le_bytes(data));
        vmm.read_memory(0x4, &mut data).unwrap();
        assert_eq!(0x0000aabb, <u32>::from_le_bytes(data));
        vmm.read_memory(0x8, &mut data).unwrap();
        assert_eq!(0x0, <u32>::from_le_bytes(data));
    }

    #[test]
    fn test_rep_stosd() {
        let ip: u64 = 0x1000;
        let memory: [u8; 12] = [
            0x78, 0x56, 0x34, 0x12, // 0x12345678
            0x00, 0x00, 0x00, 0x00, // 0x00000000
            0x00, 0x00, 0x00, 0x00, // 0x00000000
        ];
        let insn = [0xf3, 0xab]; // rep stosd
        let regs = vec![
            (Register::ECX, 2),
            (Register::EDI, 0x8),
            (Register::EAX, 0xaabbccdd),
        ];
        let mut data = [0u8; 4];

        let mut vmm = MockVmm::new(ip, regs, Some((0, &memory)));

        // Go backwards this time
        let mut state = vmm.cpu_state(0).unwrap();
        state.set_flags(state.flags() | DF);
        vmm.set_cpu_state(0, state).unwrap();

        vmm.emulate_first_insn(0, &insn).unwrap();

        vmm.read_memory(0x0, &mut data).unwrap();
        assert_eq!(0x12345678, <u32>::from_le_bytes(data));
        vmm.read_memory(0x4, &mut data).unwrap();
        assert_eq!(0xaabbccdd, <u32>::from_le_bytes(data));
        vmm.read_memory(0x8, &mut data).unwrap();
        assert_eq!(0xaabbccdd, <u32>::from_le_bytes(data));
        vmm.read_memory(0xc, &mut data).unwrap();
        assert_eq!(0x0, <u32>::from_le_bytes(data));
    }

    #[test]
    fn test_rep_stosq() {
        let ip: u64 = 0x1000;
        let memory: [u8; 8] = [
            0x78, 0x56, 0x34, 0x12, // 0x12345678
            0x00, 0x00, 0x00, 0x00, // 0x00000000
        ];
        let insn = [0xf3, 0x48, 0xab]; // rep stosq
        let regs = vec![
            (Register::ECX, 2),
            (Register::RDI, 0x0),
            (Register::RAX, 0x11223344aabbccdd),
        ];
        let mut data = [0u8; 8];

        let mut vmm = MockVmm::new(ip, regs, Some((0, &memory)));

        vmm.emulate_first_insn(0, &insn).unwrap();

        vmm.read_memory(0x0, &mut data).unwrap();
        assert_eq!(0x11223344aabbccdd, <u64>::from_le_bytes(data));
        vmm.read_memory(0x8, &mut data).unwrap();
        assert_eq!(0x11223344aabbccdd, <u64>::from_le_bytes(data));
        vmm.read_memory(0x10, &mut data).unwrap();
        assert_eq!(0x0, <u64>::from_le_bytes(data));
    }
}
