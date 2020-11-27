//
// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

extern crate iced_x86;

use crate::arch::emulator::{EmulationError, EmulationResult, PlatformEmulator, PlatformError};
use crate::arch::x86::emulator::instructions::*;
use crate::arch::x86::Exception;
use crate::x86_64::{SegmentRegister, SpecialRegisters, StandardRegisters};
use iced_x86::*;

#[macro_use]
mod instructions;

/// CpuStateManager manages an x86 CPU state.
///
/// Instruction emulation handlers get a mutable reference to
/// a `CpuStateManager` implementation, representing the current state of the
/// CPU they have to emulate an instruction stream against. Usually those
/// handlers will modify the CPU state by modifying `CpuState` and it is up to
/// the handler caller to commit those changes back by invoking a
/// `PlatformEmulator` implementation `set_state()` method.
///
pub trait CpuStateManager: Clone {
    /// Reads a CPU register.
    ///
    /// # Arguments
    ///
    /// * `reg` - A general purpose, control or debug register.
    fn read_reg(&self, reg: Register) -> Result<u64, PlatformError>;

    /// Write to a CPU register.
    ///
    /// # Arguments
    ///
    /// * `reg` - A general purpose, control or debug register.
    /// * `val` - The value to load.
    fn write_reg(&mut self, reg: Register, val: u64) -> Result<(), PlatformError>;

    /// Reads a segment register.
    ///
    /// # Arguments
    ///
    /// * `reg` - A segment register.
    fn read_segment(&self, reg: Register) -> Result<SegmentRegister, PlatformError>;

    /// Write to a segment register.
    ///
    /// # Arguments
    ///
    /// * `reg` - A segment register.
    /// * `segment_reg` - The segment register value to load.
    fn write_segment(
        &mut self,
        reg: Register,
        segment_reg: SegmentRegister,
    ) -> Result<(), PlatformError>;

    /// Get the CPU instruction pointer.
    fn ip(&self) -> u64;

    /// Set the CPU instruction pointer.
    ///
    /// # Arguments
    ///
    /// * `ip` - The CPU instruction pointer.
    fn set_ip(&mut self, ip: u64);

    /// Get the CPU Extended Feature Enable Register.
    fn efer(&self) -> u64;

    /// Set the CPU Extended Feature Enable Register.
    ///
    /// # Arguments
    ///
    /// * `efer` - The CPU EFER value.
    fn set_efer(&mut self, efer: u64);

    /// Get the CPU flags.
    fn flags(&self) -> u64;

    /// Set the CPU flags.
    ///
    /// # Arguments
    ///
    /// * `flags` - The CPU flags
    fn set_flags(&mut self, flags: u64);
}

const REGISTER_MASK_64: u64 = 0xffff_ffff_ffff_ffffu64;
const REGISTER_MASK_32: u64 = 0xffff_ffffu64;
const REGISTER_MASK_16: u64 = 0xffffu64;
const REGISTER_MASK_8: u64 = 0xffu64;

macro_rules! set_reg {
    ($reg:expr, $mask:expr, $value:expr) => {
        $reg = ($reg & $mask) | $value
    };
}

#[derive(Clone, Default, Debug)]
/// A minimal, emulated CPU state.
///
/// Hypervisors needing x86 emulation can choose to either use their own
/// CPU state structures and implement the CpuStateManager interface for it,
/// or use `EmulatorCpuState`. The latter implies creating a new state
/// `EmulatorCpuState` instance for each platform `cpu_state()` call, which
/// might be less efficient.
pub struct EmulatorCpuState {
    pub regs: StandardRegisters,
    pub sregs: SpecialRegisters,
}

impl CpuStateManager for EmulatorCpuState {
    fn read_reg(&self, reg: Register) -> Result<u64, PlatformError> {
        let mut reg_value: u64 = match reg {
            Register::RAX | Register::EAX | Register::AX | Register::AL | Register::AH => {
                self.regs.rax
            }
            Register::RBX | Register::EBX | Register::BX | Register::BL | Register::BH => {
                self.regs.rbx
            }
            Register::RCX | Register::ECX | Register::CX | Register::CL | Register::CH => {
                self.regs.rcx
            }
            Register::RDX | Register::EDX | Register::DX | Register::DL | Register::DH => {
                self.regs.rdx
            }
            Register::RSP | Register::ESP | Register::SP => self.regs.rsp,
            Register::RBP | Register::EBP | Register::BP => self.regs.rbp,
            Register::RSI | Register::ESI | Register::SI | Register::SIL => self.regs.rsi,
            Register::RDI | Register::EDI | Register::DI | Register::DIL => self.regs.rdi,
            Register::R8 | Register::R8D | Register::R8W | Register::R8L => self.regs.r8,
            Register::R9 | Register::R9D | Register::R9W | Register::R9L => self.regs.r9,
            Register::R10 | Register::R10D | Register::R10W | Register::R10L => self.regs.r10,
            Register::R11 | Register::R11D | Register::R11W | Register::R11L => self.regs.r11,
            Register::R12 | Register::R12D | Register::R12W | Register::R12L => self.regs.r12,
            Register::R13 | Register::R13D | Register::R13W | Register::R13L => self.regs.r13,
            Register::R14 | Register::R14D | Register::R14W | Register::R14L => self.regs.r14,
            Register::R15 | Register::R15D | Register::R15W | Register::R15L => self.regs.r15,
            Register::CR0 => self.sregs.cr0,
            Register::CR2 => self.sregs.cr2,
            Register::CR3 => self.sregs.cr3,
            Register::CR4 => self.sregs.cr4,
            Register::CR8 => self.sregs.cr8,

            r => {
                return Err(PlatformError::InvalidRegister(anyhow!(
                    "read_reg invalid GPR {:?}",
                    r
                )))
            }
        };

        reg_value = if reg.is_gpr64() || reg.is_cr() {
            reg_value
        } else if reg.is_gpr32() {
            reg_value & REGISTER_MASK_32
        } else if reg.is_gpr16() {
            reg_value & REGISTER_MASK_16
        } else if reg.is_gpr8() {
            if reg == Register::AH
                || reg == Register::BH
                || reg == Register::CH
                || reg == Register::DH
            {
                (reg_value >> 8) & REGISTER_MASK_8
            } else {
                reg_value & REGISTER_MASK_8
            }
        } else {
            return Err(PlatformError::InvalidRegister(anyhow!(
                "read_reg invalid GPR {:?}",
                reg
            )));
        };

        debug!("Register read: {:#x} from {:?}", reg_value, reg);

        Ok(reg_value)
    }

    fn write_reg(&mut self, reg: Register, val: u64) -> Result<(), PlatformError> {
        debug!("Register write: {:#x} to {:?}", val, reg);

        // SDM Vol 1 - 3.4.1.1
        //
        // 8-bit and 16-bit operands generate an 8-bit or 16-bit result.
        // The upper 56 bits or 48 bits (respectively) of the destination
        // general-purpose register are not modified by the operation.
        let (reg_value, mask): (u64, u64) = if reg.is_gpr64() || reg.is_cr() {
            (val, !REGISTER_MASK_64)
        } else if reg.is_gpr32() {
            (val & REGISTER_MASK_32, !REGISTER_MASK_64)
        } else if reg.is_gpr16() {
            (val & REGISTER_MASK_16, !REGISTER_MASK_16)
        } else if reg.is_gpr8() {
            if reg == Register::AH
                || reg == Register::BH
                || reg == Register::CH
                || reg == Register::DH
            {
                ((val & REGISTER_MASK_8) << 8, !(REGISTER_MASK_8 << 8))
            } else {
                (val & REGISTER_MASK_8, !REGISTER_MASK_8)
            }
        } else {
            return Err(PlatformError::InvalidRegister(anyhow!(
                "write_reg invalid register {:?}",
                reg
            )));
        };

        match reg {
            Register::RAX | Register::EAX | Register::AX | Register::AL | Register::AH => {
                set_reg!(self.regs.rax, mask, reg_value);
            }
            Register::RBX | Register::EBX | Register::BX | Register::BL | Register::BH => {
                set_reg!(self.regs.rbx, mask, reg_value);
            }
            Register::RCX | Register::ECX | Register::CX | Register::CL | Register::CH => {
                set_reg!(self.regs.rcx, mask, reg_value);
            }
            Register::RDX | Register::EDX | Register::DX | Register::DL | Register::DH => {
                set_reg!(self.regs.rdx, mask, reg_value);
            }
            Register::RSP | Register::ESP | Register::SP => {
                set_reg!(self.regs.rsp, mask, reg_value)
            }
            Register::RBP | Register::EBP | Register::BP => {
                set_reg!(self.regs.rbp, mask, reg_value)
            }
            Register::RSI | Register::ESI | Register::SI | Register::SIL => {
                set_reg!(self.regs.rsi, mask, reg_value)
            }
            Register::RDI | Register::EDI | Register::DI | Register::DIL => {
                set_reg!(self.regs.rdi, mask, reg_value)
            }
            Register::R8 | Register::R8D | Register::R8W | Register::R8L => {
                set_reg!(self.regs.r8, mask, reg_value)
            }
            Register::R9 | Register::R9D | Register::R9W | Register::R9L => {
                set_reg!(self.regs.r9, mask, reg_value)
            }
            Register::R10 | Register::R10D | Register::R10W | Register::R10L => {
                set_reg!(self.regs.r10, mask, reg_value)
            }
            Register::R11 | Register::R11D | Register::R11W | Register::R11L => {
                set_reg!(self.regs.r11, mask, reg_value)
            }
            Register::R12 | Register::R12D | Register::R12W | Register::R12L => {
                set_reg!(self.regs.r12, mask, reg_value)
            }
            Register::R13 | Register::R13D | Register::R13W | Register::R13L => {
                set_reg!(self.regs.r13, mask, reg_value)
            }
            Register::R14 | Register::R14D | Register::R14W | Register::R14L => {
                set_reg!(self.regs.r14, mask, reg_value)
            }
            Register::R15 | Register::R15D | Register::R15W | Register::R15L => {
                set_reg!(self.regs.r15, mask, reg_value)
            }
            Register::CR0 => set_reg!(self.sregs.cr0, mask, reg_value),
            Register::CR2 => set_reg!(self.sregs.cr2, mask, reg_value),
            Register::CR3 => set_reg!(self.sregs.cr3, mask, reg_value),
            Register::CR4 => set_reg!(self.sregs.cr4, mask, reg_value),
            Register::CR8 => set_reg!(self.sregs.cr8, mask, reg_value),
            _ => {
                return Err(PlatformError::InvalidRegister(anyhow!(
                    "write_reg invalid register {:?}",
                    reg
                )))
            }
        }

        Ok(())
    }

    fn read_segment(&self, reg: Register) -> Result<SegmentRegister, PlatformError> {
        if !reg.is_segment_register() {
            return Err(PlatformError::InvalidRegister(anyhow!(
                "read_segment {:?} is not a segment register",
                reg
            )));
        }

        match reg {
            Register::CS => Ok(self.sregs.cs),
            Register::DS => Ok(self.sregs.ds),
            Register::ES => Ok(self.sregs.es),
            Register::FS => Ok(self.sregs.fs),
            Register::GS => Ok(self.sregs.gs),
            Register::SS => Ok(self.sregs.ss),
            r => Err(PlatformError::InvalidRegister(anyhow!(
                "read_segment invalid register {:?}",
                r
            ))),
        }
    }

    fn write_segment(
        &mut self,
        reg: Register,
        segment_register: SegmentRegister,
    ) -> Result<(), PlatformError> {
        if !reg.is_segment_register() {
            return Err(PlatformError::InvalidRegister(anyhow!("{:?}", reg)));
        }

        match reg {
            Register::CS => self.sregs.cs = segment_register,
            Register::DS => self.sregs.ds = segment_register,
            Register::ES => self.sregs.es = segment_register,
            Register::FS => self.sregs.fs = segment_register,
            Register::GS => self.sregs.gs = segment_register,
            Register::SS => self.sregs.ss = segment_register,
            r => return Err(PlatformError::InvalidRegister(anyhow!("{:?}", r))),
        }

        Ok(())
    }

    fn ip(&self) -> u64 {
        self.regs.rip
    }

    fn set_ip(&mut self, ip: u64) {
        self.regs.rip = ip;
    }

    fn efer(&self) -> u64 {
        self.sregs.efer
    }

    fn set_efer(&mut self, efer: u64) {
        self.sregs.efer = efer
    }

    fn flags(&self) -> u64 {
        self.regs.rflags
    }

    fn set_flags(&mut self, flags: u64) {
        self.regs.rflags = flags;
    }
}

pub struct Emulator<'a, T: CpuStateManager> {
    platform: &'a mut dyn PlatformEmulator<CpuState = T>,
    insn_map: InstructionMap<T>,
}

impl<'a, T: CpuStateManager> Emulator<'a, T> {
    pub fn new(platform: &mut dyn PlatformEmulator<CpuState = T>) -> Emulator<T> {
        let mut insn_map = InstructionMap::<T>::new();

        // MOV
        insn_add!(insn_map, mov, Mov_r8_imm8);
        insn_add!(insn_map, mov, Mov_r8_rm8);
        insn_add!(insn_map, mov, Mov_r16_imm16);
        insn_add!(insn_map, mov, Mov_r16_rm16);
        insn_add!(insn_map, mov, Mov_r32_imm32);
        insn_add!(insn_map, mov, Mov_r32_rm32);
        insn_add!(insn_map, mov, Mov_r64_imm64);
        insn_add!(insn_map, mov, Mov_r64_rm64);
        insn_add!(insn_map, mov, Mov_rm8_imm8);
        insn_add!(insn_map, mov, Mov_rm8_r8);
        insn_add!(insn_map, mov, Mov_rm16_imm16);
        insn_add!(insn_map, mov, Mov_rm16_r16);
        insn_add!(insn_map, mov, Mov_rm32_imm32);
        insn_add!(insn_map, mov, Mov_rm32_r32);
        insn_add!(insn_map, mov, Mov_rm64_imm32);
        insn_add!(insn_map, mov, Mov_rm64_r64);

        Emulator { platform, insn_map }
    }

    fn emulate_insn_stream(
        &mut self,
        cpu_id: usize,
        insn_stream: &[u8],
        num_insn: Option<usize>,
    ) -> EmulationResult<T, Exception> {
        let mut state = self
            .platform
            .cpu_state(cpu_id)
            .map_err(EmulationError::PlatformEmulationError)?;
        let mut decoder = Decoder::new(64, insn_stream, DecoderOptions::NONE);
        decoder.set_ip(state.ip());

        for (index, insn) in &mut decoder.iter().enumerate() {
            self.insn_map
                .instructions
                .get(&insn.code())
                .ok_or_else(|| {
                    EmulationError::UnsupportedInstruction(anyhow!("{:?}", insn.mnemonic()))
                })?
                .emulate(&insn, &mut state, self.platform)?;

            if let Some(num_insn) = num_insn {
                if index + 1 >= num_insn {
                    // Exit the decoding loop, do not decode the next instruction.
                    break;
                }
            }
        }

        state.set_ip(decoder.ip());
        Ok(state)
    }

    /// Emulate all instructions from the instructions stream.
    pub fn emulate(&mut self, cpu_id: usize, insn_stream: &[u8]) -> EmulationResult<T, Exception> {
        self.emulate_insn_stream(cpu_id, insn_stream, None)
    }

    /// Only emulate the first instruction from the stream.
    ///
    /// This is useful for cases where we get readahead instruction stream
    /// but implicitly must only emulate the first instruction, and then return
    /// to the guest.
    pub fn emulate_first_insn(
        &mut self,
        cpu_id: usize,
        insn_stream: &[u8],
    ) -> EmulationResult<T, Exception> {
        self.emulate_insn_stream(cpu_id, insn_stream, Some(1))
    }
}

#[cfg(test)]
mod mock_vmm {
    #![allow(unused_mut)]

    extern crate env_logger;

    use super::*;
    use crate::arch::emulator::{EmulationError, PlatformEmulator};
    use crate::arch::x86::emulator::{Emulator, EmulatorCpuState as CpuState};
    use crate::arch::x86::gdt::{gdt_entry, segment_from_gdt};
    use crate::arch::x86::Exception;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Clone)]
    pub struct MockVMM {
        memory: Vec<u8>,
        state: Arc<Mutex<CpuState>>,
    }

    unsafe impl Sync for MockVMM {}

    pub type MockResult = Result<(), EmulationError<Exception>>;

    impl MockVMM {
        pub fn new(ip: u64, regs: HashMap<Register, u64>, memory: Option<(u64, &[u8])>) -> MockVMM {
            let _ = env_logger::try_init();
            let cs_reg = segment_from_gdt(gdt_entry(0xc09b, 0, 0xffffffff), 1);
            let ds_reg = segment_from_gdt(gdt_entry(0xc093, 0, 0xffffffff), 2);
            let mut initial_state = CpuState::default();
            initial_state.set_ip(ip);
            initial_state.write_segment(Register::CS, cs_reg).unwrap();
            initial_state.write_segment(Register::DS, ds_reg).unwrap();
            for (reg, value) in regs {
                initial_state.write_reg(reg, value).unwrap();
            }

            let mut vmm = MockVMM {
                memory: vec![0; 4096],
                state: Arc::new(Mutex::new(initial_state)),
            };

            if let Some(mem) = memory {
                vmm.write_memory(mem.0, &mem.1).unwrap();
            }

            vmm
        }

        pub fn emulate_insn(&mut self, cpu_id: usize, insn: &[u8], num_insn: Option<usize>) {
            let ip = self.cpu_state(cpu_id).unwrap().ip();
            let mut emulator = Emulator::new(self);

            let new_state = emulator
                .emulate_insn_stream(cpu_id, &insn, num_insn)
                .unwrap();
            if num_insn.is_none() {
                assert_eq!(ip + insn.len() as u64, new_state.ip());
            }

            self.set_cpu_state(cpu_id, new_state).unwrap();
        }

        pub fn emulate_first_insn(&mut self, cpu_id: usize, insn: &[u8]) {
            self.emulate_insn(cpu_id, insn, None)
        }
    }

    impl PlatformEmulator for MockVMM {
        type CpuState = CpuState;

        fn read_memory(&self, gva: u64, data: &mut [u8]) -> Result<(), PlatformError> {
            debug!(
                "Memory read {} bytes from [{:#x} -> {:#x}]",
                data.len(),
                gva,
                gva
            );
            data.copy_from_slice(&self.memory[gva as usize..gva as usize + data.len()]);
            Ok(())
        }

        fn write_memory(&mut self, gva: u64, data: &[u8]) -> Result<(), PlatformError> {
            debug!(
                "Memory write {} bytes at [{:#x} -> {:#x}]",
                data.len(),
                gva,
                gva
            );
            self.memory[gva as usize..gva as usize + data.len()].copy_from_slice(data);

            Ok(())
        }

        fn cpu_state(&self, _cpu_id: usize) -> Result<CpuState, PlatformError> {
            Ok(self.state.lock().unwrap().clone())
        }

        fn set_cpu_state(
            &self,
            _cpu_id: usize,
            state: Self::CpuState,
        ) -> Result<(), PlatformError> {
            *self.state.lock().unwrap() = state;
            Ok(())
        }

        fn gva_to_gpa(&self, gva: u64) -> Result<u64, PlatformError> {
            Ok(gva)
        }
    }
}
