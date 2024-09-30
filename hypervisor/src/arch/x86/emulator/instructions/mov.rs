//
// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

#![allow(non_camel_case_types)]

//
// MOV-Move
// SDM Volume 1, Chapter 4.3
//   Copies the second operand (source operand) to the first operand (destination operand).
//

use crate::arch::x86::emulator::instructions::*;

macro_rules! mov_rm_r {
    ($bound:ty) => {
        fn emulate(
            &self,
            insn: &Instruction,
            state: &mut T,
            platform: &mut dyn PlatformEmulator<CpuState = T>,
        ) -> Result<(), EmulationError<Exception>> {
            let src_reg_value = get_op(&insn, 1, std::mem::size_of::<$bound>(), state, platform)
                .map_err(EmulationError::PlatformEmulationError)?;

            set_op(
                &insn,
                0,
                std::mem::size_of::<$bound>(),
                state,
                platform,
                src_reg_value,
            )
            .map_err(EmulationError::PlatformEmulationError)?;

            Ok(())
        }
    };
}

macro_rules! mov_rm_imm {
    ($bound:ty) => {
        fn emulate(
            &self,
            insn: &Instruction,
            state: &mut T,
            platform: &mut dyn PlatformEmulator<CpuState = T>,
        ) -> Result<(), EmulationError<Exception>> {
            let imm = get_op(&insn, 1, std::mem::size_of::<$bound>(), state, platform)
                .map_err(EmulationError::PlatformEmulationError)?;

            set_op(
                &insn,
                0,
                std::mem::size_of::<$bound>(),
                state,
                platform,
                imm,
            )
            .map_err(EmulationError::PlatformEmulationError)?;

            Ok(())
        }
    };
}

macro_rules! movzx {
    ($dest_op_size:ty, $src_op_size:ty) => {
        fn emulate(
            &self,
            insn: &Instruction,
            state: &mut T,
            platform: &mut dyn PlatformEmulator<CpuState = T>,
        ) -> Result<(), EmulationError<Exception>> {
            let src_value = get_op(
                &insn,
                1,
                std::mem::size_of::<$src_op_size>(),
                state,
                platform,
            )
            .map_err(EmulationError::PlatformEmulationError)?;

            set_op(
                &insn,
                0,
                std::mem::size_of::<$dest_op_size>(),
                state,
                platform,
                src_value,
            )
            .map_err(EmulationError::PlatformEmulationError)?;

            Ok(())
        }
    };
}

// MOV r/rm is a special case of MOVZX, where both operands have the same size.
macro_rules! mov_r_rm {
    ($op_size:ty) => {
        movzx!($op_size, $op_size);
    };
}

macro_rules! mov_r_imm {
    ($bound:ty) => {
        fn emulate(
            &self,
            insn: &Instruction,
            state: &mut T,
            platform: &mut dyn PlatformEmulator<CpuState = T>,
        ) -> Result<(), EmulationError<Exception>> {
            let imm = get_op(&insn, 1, std::mem::size_of::<$bound>(), state, platform)
                .map_err(EmulationError::PlatformEmulationError)?;

            set_op(
                &insn,
                0,
                std::mem::size_of::<$bound>(),
                state,
                platform,
                imm,
            )
            .map_err(EmulationError::PlatformEmulationError)?;

            Ok(())
        }
    };
}

pub struct Mov_r8_rm8;
impl<T: CpuStateManager> InstructionHandler<T> for Mov_r8_rm8 {
    mov_r_rm!(u8);
}

pub struct Mov_r8_imm8;
impl<T: CpuStateManager> InstructionHandler<T> for Mov_r8_imm8 {
    mov_r_imm!(u8);
}

pub struct Mov_r16_rm16;
impl<T: CpuStateManager> InstructionHandler<T> for Mov_r16_rm16 {
    mov_r_rm!(u16);
}

pub struct Mov_r16_imm16;
impl<T: CpuStateManager> InstructionHandler<T> for Mov_r16_imm16 {
    mov_r_imm!(u16);
}

pub struct Mov_r32_rm32;
impl<T: CpuStateManager> InstructionHandler<T> for Mov_r32_rm32 {
    mov_r_rm!(u32);
}

pub struct Mov_r32_imm32;
impl<T: CpuStateManager> InstructionHandler<T> for Mov_r32_imm32 {
    mov_r_imm!(u32);
}

pub struct Mov_r64_rm64;
impl<T: CpuStateManager> InstructionHandler<T> for Mov_r64_rm64 {
    mov_r_rm!(u64);
}

pub struct Mov_r64_imm64;
impl<T: CpuStateManager> InstructionHandler<T> for Mov_r64_imm64 {
    mov_r_imm!(u64);
}

pub struct Mov_rm8_imm8;
impl<T: CpuStateManager> InstructionHandler<T> for Mov_rm8_imm8 {
    mov_rm_imm!(u8);
}

pub struct Mov_rm8_r8;
impl<T: CpuStateManager> InstructionHandler<T> for Mov_rm8_r8 {
    mov_rm_r!(u8);
}

pub struct Mov_rm16_imm16;
impl<T: CpuStateManager> InstructionHandler<T> for Mov_rm16_imm16 {
    mov_rm_imm!(u16);
}

pub struct Mov_rm16_r16;
impl<T: CpuStateManager> InstructionHandler<T> for Mov_rm16_r16 {
    mov_rm_r!(u16);
}

pub struct Mov_rm32_imm32;
impl<T: CpuStateManager> InstructionHandler<T> for Mov_rm32_imm32 {
    mov_rm_imm!(u32);
}

pub struct Mov_rm32_r32;
impl<T: CpuStateManager> InstructionHandler<T> for Mov_rm32_r32 {
    mov_rm_r!(u32);
}

pub struct Mov_rm64_imm32;
impl<T: CpuStateManager> InstructionHandler<T> for Mov_rm64_imm32 {
    mov_rm_imm!(u32);
}

pub struct Mov_rm64_r64;
impl<T: CpuStateManager> InstructionHandler<T> for Mov_rm64_r64 {
    mov_rm_r!(u64);
}

// MOVZX
pub struct Movzx_r16_rm8;
impl<T: CpuStateManager> InstructionHandler<T> for Movzx_r16_rm8 {
    movzx!(u16, u8);
}

pub struct Movzx_r32_rm8;
impl<T: CpuStateManager> InstructionHandler<T> for Movzx_r32_rm8 {
    movzx!(u32, u8);
}

pub struct Movzx_r64_rm8;
impl<T: CpuStateManager> InstructionHandler<T> for Movzx_r64_rm8 {
    movzx!(u64, u8);
}

pub struct Movzx_r32_rm16;
impl<T: CpuStateManager> InstructionHandler<T> for Movzx_r32_rm16 {
    movzx!(u32, u16);
}

pub struct Movzx_r64_rm16;
impl<T: CpuStateManager> InstructionHandler<T> for Movzx_r64_rm16 {
    movzx!(u64, u16);
}

pub struct Mov_moffs16_AX;
impl<T: CpuStateManager> InstructionHandler<T> for Mov_moffs16_AX {
    movzx!(u16, u16);
}

pub struct Mov_AX_moffs16;
impl<T: CpuStateManager> InstructionHandler<T> for Mov_AX_moffs16 {
    movzx!(u16, u16);
}

pub struct Mov_moffs32_EAX;
impl<T: CpuStateManager> InstructionHandler<T> for Mov_moffs32_EAX {
    movzx!(u32, u32);
}

pub struct Mov_EAX_moffs32;
impl<T: CpuStateManager> InstructionHandler<T> for Mov_EAX_moffs32 {
    movzx!(u32, u32);
}

pub struct Mov_moffs64_RAX;
impl<T: CpuStateManager> InstructionHandler<T> for Mov_moffs64_RAX {
    movzx!(u64, u64);
}

pub struct Mov_RAX_moffs64;
impl<T: CpuStateManager> InstructionHandler<T> for Mov_RAX_moffs64 {
    movzx!(u64, u64);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::x86::emulator::mock_vmm::*;

    #[test]
    // mov rax,rbx
    fn test_mov_r64_r64() {
        let rbx: u64 = 0x8899aabbccddeeff;
        let ip: u64 = 0x1000;
        let cpu_id = 0;
        let insn = [0x48, 0x89, 0xd8];
        let mut vmm = MockVmm::new(ip, vec![(Register::RBX, rbx)], None);
        vmm.emulate_first_insn(cpu_id, &insn).unwrap();

        let rax: u64 = vmm
            .cpu_state(cpu_id)
            .unwrap()
            .read_reg(Register::RAX)
            .unwrap();
        assert_eq!(rax, rbx);
    }

    #[test]
    // mov rax,0x1122334411223344
    fn test_mov_r64_imm64() {
        let imm64: u64 = 0x1122334411223344;
        let ip: u64 = 0x1000;
        let cpu_id = 0;
        let insn = [0x48, 0xb8, 0x44, 0x33, 0x22, 0x11, 0x44, 0x33, 0x22, 0x11];
        let mut vmm = MockVmm::new(ip, vec![], None);
        vmm.emulate_first_insn(cpu_id, &insn).unwrap();

        let rax: u64 = vmm
            .cpu_state(cpu_id)
            .unwrap()
            .read_reg(Register::RAX)
            .unwrap();
        assert_eq!(rax, imm64);
    }

    #[test]
    // mov rax, [rax+rax]
    fn test_mov_r64_m64() {
        let target_rax: u64 = 0x1234567812345678;
        let mut rax: u64 = 0x100;
        let ip: u64 = 0x1000;
        let cpu_id = 0;
        let memory: [u8; 8] = target_rax.to_le_bytes();
        let insn = [0x48, 0x8b, 0x04, 0x00];
        let mut vmm = MockVmm::new(ip, vec![(Register::RAX, rax)], Some((rax + rax, &memory)));
        vmm.emulate_first_insn(cpu_id, &insn).unwrap();

        rax = vmm
            .cpu_state(cpu_id)
            .unwrap()
            .read_reg(Register::RAX)
            .unwrap();
        assert_eq!(rax, target_rax);
    }

    #[test]
    // mov al,0x11
    fn test_mov_r8_imm8() {
        let imm8: u8 = 0x11;
        let ip: u64 = 0x1000;
        let cpu_id = 0;
        let insn = [0xb0, 0x11];
        let mut vmm = MockVmm::new(ip, vec![], None);
        vmm.emulate_first_insn(cpu_id, &insn).unwrap();

        let al = vmm
            .cpu_state(cpu_id)
            .unwrap()
            .read_reg(Register::AL)
            .unwrap();
        assert_eq!(al as u8, imm8);
    }

    #[test]
    // mov eax,0x11
    fn test_mov_r32_imm8() {
        let imm8: u8 = 0x11;
        let ip: u64 = 0x1000;
        let cpu_id = 0;
        let insn = [0xb8, 0x11, 0x00, 0x00, 0x00];
        let mut vmm = MockVmm::new(ip, vec![], None);
        vmm.emulate_first_insn(cpu_id, &insn).unwrap();

        let eax = vmm
            .cpu_state(cpu_id)
            .unwrap()
            .read_reg(Register::EAX)
            .unwrap();
        assert_eq!(eax as u8, imm8);
    }

    #[test]
    // mov rax,0x11223344
    fn test_mov_r64_imm32() {
        let imm32: u32 = 0x11223344;
        let ip: u64 = 0x1000;
        let cpu_id = 0;
        let insn = [0x48, 0xc7, 0xc0, 0x44, 0x33, 0x22, 0x11];
        let mut vmm = MockVmm::new(ip, vec![], None);
        vmm.emulate_first_insn(cpu_id, &insn).unwrap();

        let rax: u64 = vmm
            .cpu_state(cpu_id)
            .unwrap()
            .read_reg(Register::RAX)
            .unwrap();
        assert_eq!(rax, imm32 as u64);
    }

    #[test]
    // mov byte ptr [rax],dh
    fn test_mov_m8_r8() {
        let rax: u64 = 0x100;
        let dh: u8 = 0x99;
        let ip: u64 = 0x1000;
        let cpu_id = 0;
        let insn = [0x88, 0x30];
        let mut vmm = MockVmm::new(
            ip,
            vec![(Register::RAX, rax), (Register::DH, dh.into())],
            None,
        );
        vmm.emulate_first_insn(cpu_id, &insn).unwrap();

        let mut memory: [u8; 1] = [0; 1];
        vmm.read_memory(rax, &mut memory).unwrap();

        assert_eq!(u8::from_le_bytes(memory), dh);
    }

    #[test]
    // mov dword ptr [rax],esi
    fn test_mov_m32_r32() {
        let rax: u64 = 0x100;
        let esi: u32 = 0x8899;
        let ip: u64 = 0x1000;
        let cpu_id = 0;
        let insn = [0x89, 0x30];
        let mut vmm = MockVmm::new(
            ip,
            vec![(Register::RAX, rax), (Register::ESI, esi.into())],
            None,
        );
        vmm.emulate_first_insn(cpu_id, &insn).unwrap();

        let mut memory: [u8; 4] = [0; 4];
        vmm.read_memory(rax, &mut memory).unwrap();

        assert_eq!(u32::from_le_bytes(memory), esi);
    }

    #[test]
    // mov dword ptr [rax+0x00000001],edi
    fn test_mov_m32imm32_r32() {
        let rax: u64 = 0x100;
        let displacement: u64 = 0x1;
        let edi: u32 = 0x8899;
        let ip: u64 = 0x1000;
        let cpu_id = 0;
        let insn = [0x89, 0x3c, 0x05, 0x01, 0x00, 0x00, 0x00];
        let mut vmm = MockVmm::new(
            ip,
            vec![(Register::RAX, rax), (Register::EDI, edi.into())],
            None,
        );
        vmm.emulate_first_insn(cpu_id, &insn).unwrap();

        let mut memory: [u8; 4] = [0; 4];
        vmm.read_memory(rax + displacement, &mut memory).unwrap();

        assert_eq!(u32::from_le_bytes(memory), edi);
    }

    #[test]
    // mov eax,dword ptr [rax+10h]
    fn test_mov_r32_m32imm32() {
        let rax: u64 = 0x100;
        let displacement: u64 = 0x10;
        let eax: u32 = 0xaabbccdd;
        let memory: [u8; 4] = eax.to_le_bytes();
        let ip: u64 = 0x1000;
        let cpu_id = 0;
        let insn = [0x8b, 0x40, 0x10];
        let mut vmm = MockVmm::new(
            ip,
            vec![(Register::RAX, rax)],
            Some((rax + displacement, &memory)),
        );
        vmm.emulate_first_insn(cpu_id, &insn).unwrap();

        let new_eax = vmm
            .cpu_state(cpu_id)
            .unwrap()
            .read_reg(Register::EAX)
            .unwrap();
        assert_eq!(new_eax, eax as u64);
    }

    #[test]
    // mov al,byte ptr [rax+10h]
    fn test_mov_r8_m32imm32() {
        let rax: u64 = 0x100;
        let displacement: u64 = 0x10;
        let al: u8 = 0xaa;
        let ip: u64 = 0x1000;
        let cpu_id = 0;
        let insn = [0x8a, 0x40, 0x10];
        let memory: [u8; 1] = al.to_le_bytes();
        let mut vmm = MockVmm::new(
            ip,
            vec![(Register::RAX, rax)],
            Some((rax + displacement, &memory)),
        );
        vmm.emulate_first_insn(cpu_id, &insn).unwrap();

        let new_al = vmm
            .cpu_state(cpu_id)
            .unwrap()
            .read_reg(Register::AL)
            .unwrap();
        assert_eq!(new_al, al as u64);
    }

    #[test]
    // mov rax, 0x100
    // mov rbx, qword ptr [rax+10h]
    fn test_mov_r64_imm64_and_r64_m64() {
        let target_rax: u64 = 0x1234567812345678;
        let rax: u64 = 0x100;
        let displacement: u64 = 0x10;
        let ip: u64 = 0x1000;
        let cpu_id = 0;
        let memory: [u8; 8] = target_rax.to_le_bytes();
        let insn = [
            0x48, 0xc7, 0xc0, 0x00, 0x01, 0x00, 0x00, // mov rax, 0x100
            0x48, 0x8b, 0x58, 0x10, // mov rbx, qword ptr [rax+10h]
        ];
        let mut vmm = MockVmm::new(ip, vec![], Some((rax + displacement, &memory)));
        vmm.emulate_insn(cpu_id, &insn, Some(2)).unwrap();

        let rbx: u64 = vmm
            .cpu_state(cpu_id)
            .unwrap()
            .read_reg(Register::RBX)
            .unwrap();
        assert_eq!(rbx, target_rax);
    }

    #[test]
    // mov rax, 0x100
    // mov rbx, qword ptr [rax+10h]
    fn test_mov_r64_imm64_and_r64_m64_first_insn() {
        let target_rax: u64 = 0x1234567812345678;
        let rax: u64 = 0x100;
        let displacement: u64 = 0x10;
        let ip: u64 = 0x1000;
        let cpu_id = 0;
        let memory: [u8; 8] = target_rax.to_le_bytes();
        let insn = [
            0x48, 0xc7, 0xc0, 0x00, 0x01, 0x00, 0x00, // mov rax, 0x100
            0x48, 0x8b, 0x58, 0x10, // mov rbx, qword ptr [rax+10h]
        ];

        let mut vmm = MockVmm::new(ip, vec![], Some((rax + displacement, &memory)));
        // Only run the first instruction.
        vmm.emulate_first_insn(cpu_id, &insn).unwrap();

        assert_eq!(ip + 7, vmm.cpu_state(cpu_id).unwrap().ip());

        let new_rax: u64 = vmm
            .cpu_state(cpu_id)
            .unwrap()
            .read_reg(Register::RAX)
            .unwrap();
        assert_eq!(rax, new_rax);
    }

    #[test]
    // mov rax, 0x100
    // mov rbx, qword ptr [rax+10h]
    // mov rax, 0x200
    fn test_mov_r64_imm64_and_r64_m64_two_insns() {
        let target_rax: u64 = 0x1234567812345678;
        let rax: u64 = 0x100;
        let displacement: u64 = 0x10;
        let ip: u64 = 0x1000;
        let cpu_id = 0;
        let memory: [u8; 8] = target_rax.to_le_bytes();
        let insn = [
            0x48, 0xc7, 0xc0, 0x00, 0x01, 0x00, 0x00, // mov rax, 0x100
            0x48, 0x8b, 0x58, 0x10, // mov rbx, qword ptr [rax+10h]
            0x48, 0xc7, 0xc0, 0x00, 0x02, 0x00, 0x00, // mov rax, 0x200
        ];

        let mut vmm = MockVmm::new(ip, vec![], Some((rax + displacement, &memory)));
        // Run the 2 first instructions.
        vmm.emulate_insn(cpu_id, &insn, Some(2)).unwrap();

        assert_eq!(ip + 7 + 4, vmm.cpu_state(cpu_id).unwrap().ip());

        let rbx: u64 = vmm
            .cpu_state(cpu_id)
            .unwrap()
            .read_reg(Register::RBX)
            .unwrap();
        assert_eq!(rbx, target_rax);

        // Check that rax is still at 0x100
        let new_rax: u64 = vmm
            .cpu_state(cpu_id)
            .unwrap()
            .read_reg(Register::RAX)
            .unwrap();
        assert_eq!(rax, new_rax);
    }

    #[test]
    // movzx eax, bl
    fn test_movzx_r32_r8l() {
        let bx: u16 = 0x8899;
        let ip: u64 = 0x1000;
        let cpu_id = 0;
        let insn = [0x0f, 0xb6, 0xc3];
        let mut vmm = MockVmm::new(ip, vec![(Register::BX, bx as u64)], None);
        vmm.emulate_first_insn(cpu_id, &insn).unwrap();

        let eax: u64 = vmm
            .cpu_state(cpu_id)
            .unwrap()
            .read_reg(Register::EAX)
            .unwrap();
        assert_eq!(eax, (bx & 0xff) as u64);
    }

    #[test]
    // movzx eax, bh
    fn test_movzx_r32_r8h() {
        let bx: u16 = 0x8899;
        let ip: u64 = 0x1000;
        let cpu_id = 0;
        let insn = [0x0f, 0xb6, 0xc7];
        let mut vmm = MockVmm::new(ip, vec![(Register::BX, bx as u64)], None);
        vmm.emulate_first_insn(cpu_id, &insn).unwrap();

        let eax: u64 = vmm
            .cpu_state(cpu_id)
            .unwrap()
            .read_reg(Register::EAX)
            .unwrap();
        assert_eq!(eax, (bx >> 8) as u64);
    }

    #[test]
    // movzx eax, byte ptr [rbx]
    fn test_movzx_r32_m8() {
        let rbx: u64 = 0x100;
        let value: u8 = 0xaa;
        let ip: u64 = 0x1000;
        let cpu_id = 0;
        let insn = [0x0f, 0xb7, 0x03];
        let memory: [u8; 1] = value.to_le_bytes();
        let mut vmm = MockVmm::new(ip, vec![(Register::RBX, rbx)], Some((rbx, &memory)));
        vmm.emulate_first_insn(cpu_id, &insn).unwrap();

        let eax: u64 = vmm
            .cpu_state(cpu_id)
            .unwrap()
            .read_reg(Register::EAX)
            .unwrap();
        assert_eq!(eax, value as u64);
    }

    #[test]
    // movabs ax, ds:0x1337
    // movabs eax, ds:0x1337
    // movabs rax, ds:0x1337
    fn test_mov_memoff_ax() {
        let test_inputs: [(Register, &[u8]); 3] = [
            (Register::AX, &[0x66, 0xa1]),
            (Register::EAX, &[0xa1]),
            (Register::RAX, &[0x48, 0xa1]),
        ];

        // Constructs the instruction with the provided inputs and emulates it.
        fn helper(register: Register, instruction_prefix: &[u8]) {
            let mem_addr: u64 = 0x1337;
            let mem_value: u64 = 0x13371337deadbeef;
            let ip: u64 = 0x1000;
            let cpu_id = 0;

            let mut instruction_bytes = Vec::new();
            // instruction prefix with specified register
            instruction_bytes.extend(instruction_prefix);
            // 64-bit memory operand
            instruction_bytes.extend([
                mem_addr.to_le_bytes()[0],
                mem_addr.to_le_bytes()[1],
                0,
                0,
                0,
                0,
                0,
                0,
            ]);

            let memory: [u8; 8] = mem_value.to_le_bytes();
            let mut vmm = MockVmm::new(ip, vec![], Some((mem_addr, &memory)));
            vmm.emulate_first_insn(cpu_id, &instruction_bytes).unwrap();

            let ax: u64 = vmm.cpu_state(cpu_id).unwrap().read_reg(register).unwrap();

            match register {
                Register::AX => {
                    assert_eq!(ax as u16, mem_value as u16);
                }
                Register::EAX => {
                    assert_eq!(ax as u32, mem_value as u32);
                }
                Register::RAX => {
                    assert_eq!(ax, mem_value);
                }
                _ => panic!(),
            }
        }

        for (register, instruction_prefix) in test_inputs {
            helper(register, instruction_prefix)
        }
    }

    #[test]
    // movabs ds:0x1337, ax
    // movabs ds:0x1337, eax
    // movabs ds:0x1337, rax
    fn test_mov_ax_memoff() {
        let test_inputs: [(Register, &[u8]); 3] = [
            (Register::AX, &[0x66, 0xa3]),
            (Register::EAX, &[0xa3]),
            (Register::RAX, &[0x48, 0xa3]),
        ];

        // Constructs the instruction with the provided inputs and emulates it.
        fn helper(register: Register, instruction_prefix: &[u8]) {
            let mem_addr: u64 = 0x1337;
            let ax: u64 = 0x13371337deadbeef;
            let ip: u64 = 0x1000;
            let cpu_id = 0;

            let mut instruction_bytes = Vec::new();
            // instruction prefix with specified register
            instruction_bytes.extend(instruction_prefix);
            // 64-bit memory operand
            instruction_bytes.extend([
                mem_addr.to_le_bytes()[0],
                mem_addr.to_le_bytes()[1],
                0,
                0,
                0,
                0,
                0,
                0,
            ]);

            let mut vmm = MockVmm::new(ip, vec![(Register::RAX, ax)], None);
            vmm.emulate_first_insn(cpu_id, &instruction_bytes).unwrap();

            match register {
                Register::AX => {
                    let mut memory: [u8; 2] = [0; 2];
                    vmm.read_memory(mem_addr, &mut memory).unwrap();
                    assert_eq!(u16::from_le_bytes(memory), ax as u16);
                }
                Register::EAX => {
                    let mut memory: [u8; 4] = [0; 4];
                    vmm.read_memory(mem_addr, &mut memory).unwrap();
                    assert_eq!(u32::from_le_bytes(memory), ax as u32);
                }
                Register::RAX => {
                    let mut memory: [u8; 8] = [0; 8];
                    vmm.read_memory(mem_addr, &mut memory).unwrap();
                    assert_eq!(u64::from_le_bytes(memory), ax);
                }
                _ => panic!(),
            }
        }

        for (register, instruction_prefix) in test_inputs {
            helper(register, instruction_prefix)
        }
    }
}
