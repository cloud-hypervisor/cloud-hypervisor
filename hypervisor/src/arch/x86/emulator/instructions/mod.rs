//
// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

extern crate iced_x86;

use crate::arch::emulator::{EmulationError, PlatformEmulator, PlatformError};
use crate::arch::x86::emulator::CpuStateManager;
use crate::arch::x86::Exception;
use iced_x86::*;
use std::collections::HashMap;

pub mod mov;

// Returns the linear a.k.a. virtual address for a memory operand.
fn memory_operand_address<T: CpuStateManager>(
    insn: &Instruction,
    state: &T,
) -> Result<u64, PlatformError> {
    let mut address: u64 = 0;

    // Get the DS or override segment base first
    let segment_base = state.read_segment(insn.memory_segment())?.base;
    address += segment_base;

    if insn.memory_base() != iced_x86::Register::None {
        let base: u64 = state.read_reg(insn.memory_base())?;
        address += base;
    }

    if insn.memory_index() != iced_x86::Register::None {
        let mut index: u64 = state.read_reg(insn.memory_index())?;
        index *= insn.memory_index_scale() as u64;

        address += index;
    }

    address += insn.memory_displacement() as u64;

    Ok(address)
}

pub trait InstructionHandler<T: CpuStateManager> {
    fn emulate(
        &self,
        insn: &Instruction,
        state: &mut T,
        platform: &mut dyn PlatformEmulator<CpuState = T>,
    ) -> Result<(), EmulationError<Exception>>;
}

pub struct InstructionMap<T: CpuStateManager> {
    pub instructions: HashMap<Code, Box<dyn InstructionHandler<T> + Sync + Send>>,
}

impl<T: CpuStateManager> InstructionMap<T> {
    pub fn new() -> InstructionMap<T> {
        InstructionMap {
            instructions: HashMap::new(),
        }
    }

    pub fn add_insn(
        &mut self,
        insn: Code,
        insn_handler: Box<dyn InstructionHandler<T> + Sync + Send>,
    ) {
        self.instructions.insert(insn, insn_handler);
    }
}

impl<T: CpuStateManager> Default for InstructionMap<T> {
    fn default() -> Self {
        Self::new()
    }
}

macro_rules! insn_add {
    ($insn_map:ident, $mnemonic:ident, $code:ident) => {
        $insn_map.add_insn(Code::$code, Box::new($mnemonic::$code {}));
    };
}
