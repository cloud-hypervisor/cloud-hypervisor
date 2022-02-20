// Copyright 2022 Akira Moroo.
// Portions Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: BSD-3-Clause

#[cfg(target_arch = "x86_64")]
use gdbstub_arch::x86::reg::X86_64CoreRegs as CoreRegs;
use vm_memory::GuestAddress;

#[derive(Debug)]
pub enum DebuggableError {
    SetDebug(hypervisor::HypervisorCpuError),
    Pause(vm_migration::MigratableError),
    Resume(vm_migration::MigratableError),
    ReadRegs(crate::cpu::Error),
    WriteRegs(crate::cpu::Error),
    ReadMem(hypervisor::HypervisorVmError),
    WriteMem(hypervisor::HypervisorVmError),
    TranslateGva(crate::cpu::Error),
    PoisonedState,
}

pub trait Debuggable: vm_migration::Pausable {
    fn set_guest_debug(
        &self,
        cpu_id: usize,
        addrs: &[GuestAddress],
        singlestep: bool,
    ) -> Result<(), DebuggableError>;
    fn debug_pause(&mut self) -> std::result::Result<(), DebuggableError>;
    fn debug_resume(&mut self) -> std::result::Result<(), DebuggableError>;
    fn read_regs(&self, cpu_id: usize) -> std::result::Result<CoreRegs, DebuggableError>;
    fn write_regs(
        &self,
        cpu_id: usize,
        regs: &CoreRegs,
    ) -> std::result::Result<(), DebuggableError>;
    fn read_mem(
        &self,
        cpu_id: usize,
        vaddr: GuestAddress,
        len: usize,
    ) -> std::result::Result<Vec<u8>, DebuggableError>;
    fn write_mem(
        &self,
        cpu_id: usize,
        vaddr: &GuestAddress,
        data: &[u8],
    ) -> std::result::Result<(), DebuggableError>;
    fn active_vcpus(&self) -> usize;
}
