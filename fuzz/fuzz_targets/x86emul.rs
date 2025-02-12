// Copyright © 2025 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use hypervisor::arch::emulator::{PlatformEmulator, PlatformError};
use hypervisor::arch::x86::emulator::{Emulator, EmulatorCpuState};
use hypervisor::arch::x86::{DescriptorTable, SegmentRegister, SpecialRegisters};
use hypervisor::StandardRegisters;
use libfuzzer_sys::{fuzz_target, Corpus};

#[derive(Debug)]
struct EmulatorContext {
    state: EmulatorCpuState,
    memory: [u8; 8],
}

impl PlatformEmulator for EmulatorContext {
    type CpuState = EmulatorCpuState;

    fn read_memory(&self, _gva: u64, data: &mut [u8]) -> Result<(), PlatformError> {
        data.copy_from_slice(&self.memory[..data.len()]);
        Ok(())
    }

    fn write_memory(&mut self, _gva: u64, _data: &[u8]) -> Result<(), PlatformError> {
        // Discard writes
        Ok(())
    }

    fn cpu_state(&self, _cpu_id: usize) -> Result<Self::CpuState, PlatformError> {
        Ok(self.state.clone())
    }

    fn set_cpu_state(&self, _cpu_id: usize, _state: Self::CpuState) -> Result<(), PlatformError> {
        // Ignore
        Ok(())
    }

    fn fetch(&self, _ip: u64, _data: &mut [u8]) -> Result<(), PlatformError> {
        // The fuzzer already provides 16 bytes of data, we don't need to fetch anything
        panic!("fetch should not be called");
    }
}

fuzz_target!(|bytes: &[u8]| -> Corpus {
    let (mut ctx, insn) = match generate_context_and_instruction(bytes) {
        Ok((ctx, insn)) => (ctx, insn),
        Err(_) => return Corpus::Reject,
    };

    let mut e = Emulator::new(&mut ctx);

    if e.emulate_first_insn(0, &insn).is_err() {
        return Corpus::Reject;
    }

    Corpus::Keep
});

// Helper functions to generate structures from fuzzer input below

fn generate_segment_register(
    u: &mut arbitrary::Unstructured<'_>,
) -> arbitrary::Result<SegmentRegister> {
    Ok(SegmentRegister {
        base: u.arbitrary()?,
        limit: u.arbitrary()?,
        selector: u.arbitrary()?,
        avl: u.arbitrary()?,
        dpl: u.arbitrary()?,
        db: u.arbitrary()?,
        g: u.arbitrary()?,
        l: u.arbitrary()?,
        present: u.arbitrary()?,
        s: u.arbitrary()?,
        type_: u.arbitrary()?,
        unusable: u.arbitrary()?,
    })
}

fn generate_descriptor_table(
    u: &mut arbitrary::Unstructured<'_>,
) -> arbitrary::Result<DescriptorTable> {
    Ok(DescriptorTable {
        base: u.arbitrary()?,
        limit: u.arbitrary()?,
    })
}

fn generate_context_and_instruction(
    bytes: &[u8],
) -> arbitrary::Result<(EmulatorContext, [u8; 16])> {
    let mut u = arbitrary::Unstructured::new(bytes);

    let mut regs = mshv_bindings::StandardRegisters {
        rax: u.arbitrary()?,
        rbx: u.arbitrary()?,
        rcx: u.arbitrary()?,
        rdx: u.arbitrary()?,
        rsi: u.arbitrary()?,
        rdi: u.arbitrary()?,
        rsp: u.arbitrary()?,
        rbp: u.arbitrary()?,
        r8: u.arbitrary()?,
        r9: u.arbitrary()?,
        r10: u.arbitrary()?,
        r11: u.arbitrary()?,
        r12: u.arbitrary()?,
        r13: u.arbitrary()?,
        r14: u.arbitrary()?,
        r15: u.arbitrary()?,
        rip: u.arbitrary()?,
        rflags: u.arbitrary()?,
    };

    // Cap RCX to avoid looping for too long for reps instructions.
    regs.rcx &= 0xFFFFu64;

    let regs = StandardRegisters::Mshv(regs);

    let sregs = SpecialRegisters {
        cs: generate_segment_register(&mut u)?,
        ds: generate_segment_register(&mut u)?,
        es: generate_segment_register(&mut u)?,
        fs: generate_segment_register(&mut u)?,
        gs: generate_segment_register(&mut u)?,
        ss: generate_segment_register(&mut u)?,
        tr: generate_segment_register(&mut u)?,
        ldt: generate_segment_register(&mut u)?,
        gdt: generate_descriptor_table(&mut u)?,
        idt: generate_descriptor_table(&mut u)?,
        cr0: u.arbitrary()?,
        cr2: u.arbitrary()?,
        cr3: u.arbitrary()?,
        cr4: u.arbitrary()?,
        cr8: u.arbitrary()?,
        efer: u.arbitrary()?,
        apic_base: u.arbitrary()?,
        interrupt_bitmap: u.arbitrary()?,
    };

    let memory = u.arbitrary::<[u8; 8]>()?;
    let insn = u.arbitrary::<[u8; 16]>()?;

    let ctx = EmulatorContext {
        state: EmulatorCpuState { regs, sregs },
        memory,
    };

    Ok((ctx, insn))
}
