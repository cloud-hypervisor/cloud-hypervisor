//
// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

extern crate iced_x86;

use crate::arch::emulator::{EmulationError, PlatformEmulator};
use crate::arch::x86::emulator::CpuStateManager;
use crate::arch::x86::Exception;
use iced_x86::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub trait InstructionHandler<T: CpuStateManager> {
    fn emulate(
        &self,
        insn: &Instruction,
        state: &mut T,
        platform: Arc<Mutex<dyn PlatformEmulator<CpuState = T>>>,
    ) -> Result<(), EmulationError<Exception>>;
}

pub struct InstructionMap<T: CpuStateManager> {
    pub instructions: HashMap<Code, Box<Box<dyn InstructionHandler<T> + Sync + Send>>>,
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
        self.instructions.insert(insn, Box::new(insn_handler));
    }
}

impl<T: CpuStateManager> Default for InstructionMap<T> {
    fn default() -> Self {
        Self::new()
    }
}
