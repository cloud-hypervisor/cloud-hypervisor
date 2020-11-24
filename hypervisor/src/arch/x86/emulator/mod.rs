//
// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

extern crate iced_x86;

use crate::arch::emulator::PlatformError;
use crate::x86_64::{SegmentRegister, SpecialRegisters, StandardRegisters};
use iced_x86::*;

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
            Register::RSP | Register::ESP => self.regs.rsp,
            Register::RBP | Register::EBP => self.regs.rbp,
            Register::RSI | Register::ESI => self.regs.rsi,
            Register::RDI | Register::EDI | Register::DI | Register::DIL => self.regs.rdi,
            Register::R8 | Register::R8D => self.regs.r8,
            Register::R9 | Register::R9D => self.regs.r9,
            Register::R10 | Register::R10D => self.regs.r10,
            Register::R11 | Register::R11D => self.regs.r11,
            Register::R12 | Register::R12D => self.regs.r12,
            Register::R13 | Register::R13D => self.regs.r13,
            Register::R14 | Register::R14D => self.regs.r14,
            Register::R15 | Register::R15D => self.regs.r15,
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
            Register::RSP | Register::ESP => {
                set_reg!(self.regs.rsp, mask, reg_value)
            }
            Register::RBP | Register::EBP => {
                set_reg!(self.regs.rbp, mask, reg_value)
            }
            Register::RSI | Register::ESI => {
                set_reg!(self.regs.rsi, mask, reg_value)
            }
            Register::RDI | Register::EDI | Register::DI | Register::DIL => {
                set_reg!(self.regs.rdi, mask, reg_value)
            }
            Register::R8 | Register::R8D => {
                set_reg!(self.regs.r8, mask, reg_value)
            }
            Register::R9 | Register::R9D => {
                set_reg!(self.regs.r9, mask, reg_value)
            }
            Register::R10 | Register::R10D => {
                set_reg!(self.regs.r10, mask, reg_value)
            }
            Register::R11 | Register::R11D => {
                set_reg!(self.regs.r11, mask, reg_value)
            }
            Register::R12 | Register::R12D => {
                set_reg!(self.regs.r12, mask, reg_value)
            }
            Register::R13 | Register::R13D => {
                set_reg!(self.regs.r13, mask, reg_value)
            }
            Register::R14 | Register::R14D => {
                set_reg!(self.regs.r14, mask, reg_value)
            }
            Register::R15 | Register::R15D => {
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
