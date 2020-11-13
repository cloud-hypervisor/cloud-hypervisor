//
// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

extern crate iced_x86;

use crate::arch::emulator::PlatformError;
use crate::x86_64::SegmentRegister;
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
