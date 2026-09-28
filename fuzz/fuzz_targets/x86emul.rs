// Copyright © 2025 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(target_arch = "x86_64", no_main)]

#[cfg(target_arch = "x86_64")]
mod x86emul {
    use arbitrary::Unstructured;
    use hypervisor::arch::emulator::{PlatformEmulator, PlatformError};
    use hypervisor::arch::x86::emulator::{CpuStateManager, Emulator, EmulatorCpuState};
    use hypervisor::arch::x86::regs::{CR0_PE, DF, EFER_LMA};
    use hypervisor::arch::x86::{DescriptorTable, SegmentRegister, SpecialRegisters};
    use hypervisor::StandardRegisters;
    use libfuzzer_sys::{fuzz_target, Corpus};

    const MEMORY_SIZE: usize = 256;
    const FETCH_BUFFER_SIZE: usize = 16;
    const MAX_REPEAT_COUNT: u64 = 32;

    const SEGMENT_CODE_RX_ACCESSED: u8 = 0xB;
    const SEGMENT_DATA_RW_ACCESSED: u8 = 0x3;
    const SEGMENT_DATA_RO: u8 = 0x2;
    const SEGMENT_DATA_EXPAND_DOWN_RW_ACCESSED: u8 = 0x7;

    #[derive(Debug)]
    struct EmulatorContext {
        state: EmulatorCpuState,
        memory: [u8; MEMORY_SIZE],
        fetch_bytes: [u8; FETCH_BUFFER_SIZE],
        fault: FaultMode,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum FaultMode {
        None,
        CpuState,
        Fetch,
        ReadMemory,
        WriteMemory,
    }

    #[derive(Clone, Copy)]
    enum CpuProfile {
        Real,
        Protected,
        Long,
        InvalidLong,
        ReadOnlySegments,
        ExpandDownSegments,
        ExpandDownSegmentsOk,
        ExpandDownSegmentsOk16,
        GranularSegments,
        LimitedSegments,
        LongAddressOverflow,
    }

    #[derive(Debug)]
    struct FuzzInput {
        regs: mshv_bindings::StandardRegisters,
        memory: [u8; MEMORY_SIZE],
        primary_insn: [u8; FETCH_BUFFER_SIZE],
        secondary_insn: [u8; FETCH_BUFFER_SIZE],
        selector: u8,
    }

    impl PlatformEmulator for EmulatorContext {
        type CpuState = EmulatorCpuState;

        fn read_memory(&self, gva: u64, data: &mut [u8]) -> Result<(), PlatformError> {
            if self.fault == FaultMode::ReadMemory {
                return Err(PlatformError::MemoryReadFailure(
                    std::io::Error::other("Fuzzed memory read failure").into(),
                ));
            }

            let start = usize::try_from(gva).map_err(|_| {
                PlatformError::MemoryReadFailure(
                    std::io::Error::other("Address out of range").into(),
                )
            })?;
            let end = start.checked_add(data.len()).ok_or_else(|| {
                PlatformError::MemoryReadFailure(
                    std::io::Error::other("Address out of range").into(),
                )
            })?;
            let src = self.memory.get(start..end).ok_or_else(|| {
                PlatformError::MemoryReadFailure(
                    std::io::Error::other("Address out of range").into(),
                )
            })?;
            data.copy_from_slice(src);
            Ok(())
        }

        fn write_memory(&mut self, gva: u64, data: &[u8]) -> Result<(), PlatformError> {
            if self.fault == FaultMode::WriteMemory {
                return Err(PlatformError::MemoryWriteFailure(
                    std::io::Error::other("Fuzzed memory write failure").into(),
                ));
            }

            let start = usize::try_from(gva).map_err(|_| {
                PlatformError::MemoryWriteFailure(
                    std::io::Error::other("Address out of range").into(),
                )
            })?;
            let end = start.checked_add(data.len()).ok_or_else(|| {
                PlatformError::MemoryWriteFailure(
                    std::io::Error::other("Address out of range").into(),
                )
            })?;
            let dst = self.memory.get_mut(start..end).ok_or_else(|| {
                PlatformError::MemoryWriteFailure(
                    std::io::Error::other("Address out of range").into(),
                )
            })?;
            dst.copy_from_slice(data);
            Ok(())
        }

        fn cpu_state(&self, _cpu_id: usize) -> Result<Self::CpuState, PlatformError> {
            if self.fault == FaultMode::CpuState {
                return Err(PlatformError::GetCpuStateFailure(
                    std::io::Error::other("Fuzzed CPU state failure").into(),
                ));
            }

            Ok(self.state.clone())
        }

        fn set_cpu_state(
            &self,
            _cpu_id: usize,
            _state: Self::CpuState,
        ) -> Result<(), PlatformError> {
            Ok(())
        }

        fn fetch(&self, ip: u64, data: &mut [u8]) -> Result<(), PlatformError> {
            if self.fault == FaultMode::Fetch {
                return Err(PlatformError::MemoryReadFailure(
                    std::io::Error::other("Fuzzed instruction fetch failure").into(),
                ));
            }

            let start = ip.checked_sub(0x1000).ok_or_else(|| {
                PlatformError::MemoryReadFailure(
                    std::io::Error::other("Address out of range").into(),
                )
            })? as usize;
            let end = start.checked_add(data.len()).ok_or_else(|| {
                PlatformError::MemoryReadFailure(
                    std::io::Error::other("Address out of range").into(),
                )
            })?;
            let src = self.fetch_bytes.get(start..end).ok_or_else(|| {
                PlatformError::MemoryReadFailure(
                    std::io::Error::other("Address out of range").into(),
                )
            })?;
            data.copy_from_slice(src);
            Ok(())
        }
    }

    impl FuzzInput {
        fn parse(bytes: &[u8]) -> arbitrary::Result<Self> {
            let mut u = Unstructured::new(bytes);

            let regs = mshv_bindings::StandardRegisters {
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

            Ok(FuzzInput {
                regs,
                memory: u.arbitrary()?,
                primary_insn: u.arbitrary()?,
                secondary_insn: u.arbitrary()?,
                selector: u.arbitrary()?,
            })
        }
    }

    fn segment_register(
        selector: u16,
        segment_type: u8,
        limit: u32,
        base: u64,
        db: u8,
        granularity: u8,
    ) -> SegmentRegister {
        SegmentRegister {
            base,
            limit,
            selector,
            avl: 0,
            dpl: 0,
            db,
            g: granularity,
            l: 0,
            present: 1,
            s: 1,
            type_: segment_type,
            unusable: 0,
        }
    }

    fn build_sregs(profile: CpuProfile, selector_seed: u16) -> SpecialRegisters {
        let (cr0, efer) = match profile {
            CpuProfile::Real => (0, 0),
            CpuProfile::Protected
            | CpuProfile::ReadOnlySegments
            | CpuProfile::ExpandDownSegments
            | CpuProfile::ExpandDownSegmentsOk
            | CpuProfile::ExpandDownSegmentsOk16
            | CpuProfile::GranularSegments
            | CpuProfile::LimitedSegments => (CR0_PE, 0),
            CpuProfile::Long | CpuProfile::LongAddressOverflow => (CR0_PE, EFER_LMA),
            CpuProfile::InvalidLong => (0, EFER_LMA),
        };

        let ds_segment_type = match profile {
            CpuProfile::ReadOnlySegments => SEGMENT_DATA_RO,
            CpuProfile::ExpandDownSegments
            | CpuProfile::ExpandDownSegmentsOk
            | CpuProfile::ExpandDownSegmentsOk16 => SEGMENT_DATA_EXPAND_DOWN_RW_ACCESSED,
            _ => SEGMENT_DATA_RW_ACCESSED,
        };
        let es_segment_type = ds_segment_type;

        let ds_limit = match profile {
            CpuProfile::ExpandDownSegments
            | CpuProfile::ExpandDownSegmentsOk
            | CpuProfile::ExpandDownSegmentsOk16 => 0x20,
            CpuProfile::GranularSegments => 0,
            CpuProfile::LimitedSegments => 0x20,
            _ => 0xffff,
        };

        let ds_base = if matches!(profile, CpuProfile::LongAddressOverflow) {
            u64::MAX - 0x10
        } else {
            0
        };
        let ds_db = if matches!(profile, CpuProfile::ExpandDownSegmentsOk16) {
            0
        } else {
            1
        };
        let ds_granularity = if matches!(profile, CpuProfile::GranularSegments) {
            1
        } else {
            0
        };

        let cs = segment_register(selector_seed, SEGMENT_CODE_RX_ACCESSED, 0xffff, 0, 1, 0);
        let ds = segment_register(
            selector_seed.wrapping_add(0x8),
            ds_segment_type,
            ds_limit,
            ds_base,
            ds_db,
            ds_granularity,
        );
        let es = segment_register(
            selector_seed.wrapping_add(0x10),
            es_segment_type,
            ds_limit,
            ds_base,
            ds_db,
            ds_granularity,
        );
        let fs = segment_register(
            selector_seed.wrapping_add(0x18),
            SEGMENT_DATA_RW_ACCESSED,
            0xffff,
            0,
            1,
            0,
        );
        let gs = segment_register(
            selector_seed.wrapping_add(0x20),
            SEGMENT_DATA_RW_ACCESSED,
            0xffff,
            0,
            1,
            0,
        );
        let ss = segment_register(
            selector_seed.wrapping_add(0x28),
            SEGMENT_DATA_RW_ACCESSED,
            0xffff,
            0,
            1,
            0,
        );

        SpecialRegisters {
            cs,
            ds,
            es,
            fs,
            gs,
            ss,
            tr: segment_register(
                selector_seed.wrapping_add(0x30),
                SEGMENT_DATA_RW_ACCESSED,
                0xffff,
                0,
                1,
                0,
            ),
            ldt: segment_register(
                selector_seed.wrapping_add(0x38),
                SEGMENT_DATA_RW_ACCESSED,
                0xffff,
                0,
                1,
                0,
            ),
            gdt: DescriptorTable {
                base: 0,
                limit: 0xffff,
            },
            idt: DescriptorTable {
                base: 0,
                limit: 0xffff,
            },
            cr0,
            cr2: 0,
            cr3: 0,
            cr4: 0,
            cr8: 0,
            efer,
            apic_base: 0,
            interrupt_bitmap: [0; 4],
        }
    }

    fn build_state(input: &FuzzInput, profile: CpuProfile) -> EmulatorCpuState {
        let mut regs = input.regs;
        regs.rcx %= MAX_REPEAT_COUNT + 1;
        regs.rax %= MEMORY_SIZE as u64;
        regs.rbx %= MEMORY_SIZE as u64;
        regs.rsi %= MEMORY_SIZE as u64;
        regs.rdi %= MEMORY_SIZE as u64;
        regs.rsp %= MEMORY_SIZE as u64;
        regs.rbp %= MEMORY_SIZE as u64;
        regs.rip = 0x1000;

        if matches!(profile, CpuProfile::ExpandDownSegments) {
            regs.rsi = 0x80;
            regs.rdi = 0x80;
            regs.rax = 0x80;
        }

        if matches!(
            profile,
            CpuProfile::ExpandDownSegmentsOk | CpuProfile::ExpandDownSegmentsOk16
        ) {
            regs.rsi = 0x10;
            regs.rdi = 0x10;
            regs.rax = 0x10;
        }

        if matches!(profile, CpuProfile::GranularSegments) {
            regs.rax = 0x800;
            regs.rbx = 0x20;
            regs.rsi = 0x800;
            regs.rdi = 0x880;
        }

        if matches!(profile, CpuProfile::LimitedSegments) {
            regs.rax = 0x40;
            regs.rsi = 0x40;
            regs.rdi = 0x40;
        }

        if matches!(profile, CpuProfile::LongAddressOverflow) {
            regs.rax = 0x40;
        }

        if (input.selector & 1) != 0 {
            regs.rflags |= DF;
        } else {
            regs.rflags &= !DF;
        }

        EmulatorCpuState {
            regs: StandardRegisters::Mshv(regs),
            sregs: build_sregs(profile, input.selector as u16),
        }
    }

    fn run_emulation(
        input: &FuzzInput,
        profile: CpuProfile,
        insn_stream: &[u8],
        emulate_first_insn_only: bool,
        fetch_bytes: [u8; FETCH_BUFFER_SIZE],
    ) {
        run_emulation_with_fault(
            input,
            profile,
            insn_stream,
            emulate_first_insn_only,
            fetch_bytes,
            FaultMode::None,
        );
    }

    fn run_emulation_with_fault(
        input: &FuzzInput,
        profile: CpuProfile,
        insn_stream: &[u8],
        emulate_first_insn_only: bool,
        fetch_bytes: [u8; FETCH_BUFFER_SIZE],
        fault: FaultMode,
    ) {
        let mut ctx = EmulatorContext {
            state: build_state(input, profile),
            memory: input.memory,
            fetch_bytes,
            fault,
        };
        let mut emulator = Emulator::new(&mut ctx);

        if emulate_first_insn_only {
            let _ = emulator.emulate_first_insn(0, insn_stream);
        } else {
            let _ = emulator.emulate(0, insn_stream);
        }
    }

    fn encode_reg_reg64(opcode: u8, src: u8, dst: u8) -> [u8; 3] {
        let rex = 0x48 | ((src >> 3) << 2) | (dst >> 3);
        let modrm = 0xc0 | ((src & 0x7) << 3) | (dst & 0x7);
        [rex, opcode, modrm]
    }

    fn exercise_cpu_state_manager(input: &FuzzInput) {
        let mut state = build_state(input, CpuProfile::Protected);

        for value in [187usize, 188, 189, 193] {
            if let Ok(reg) = TryFrom::try_from(value) {
                let _ = state.read_reg(reg);
                let _ = state.write_reg(reg, input.regs.rax);
            }
        }

        let replacement = segment_register(
            input.selector as u16,
            SEGMENT_DATA_RW_ACCESSED,
            (input.regs.rcx & 0xffff) as u32,
            input.regs.rbx & 0xffff,
            (input.selector >> 1) & 1,
            (input.selector >> 2) & 1,
        );
        for value in 71usize..=76 {
            if let Ok(reg) = TryFrom::try_from(value) {
                let _ = state.read_segment(reg);
                let _ = state.write_segment(reg, replacement);
            }
        }

        if let Ok(reg) = TryFrom::try_from(77usize) {
            let _ = state.read_reg(reg);
            let _ = state.write_reg(reg, input.regs.rax);
            let _ = state.read_segment(reg);
            let _ = state.write_segment(reg, replacement);
        }
    }

    fn run_harness(input: &FuzzInput) {
        const SUPPORTED_INSNS: &[&[u8]] = &[
            &[0x48, 0x89, 0xd8],                                           // mov rax,rbx
            &[0x48, 0xb8, 0x44, 0x33, 0x22, 0x11, 0x44, 0x33, 0x22, 0x11], // mov rax,imm64
            &[0xb0, 0x11],                                                 // mov al,imm8
            &[0x66, 0xb8, 0x22, 0x11],                                     // mov ax,imm16
            &[0xb8, 0x11, 0x00, 0x00, 0x00],                               // mov eax,imm32
            &[0x66, 0x8b, 0xc3],                                           // mov ax,bx
            &[0x48, 0xc7, 0xc0, 0x44, 0x33, 0x22, 0x11],                   // mov rax,imm32
            &[0xc6, 0x00, 0x11],                   // mov byte ptr [rax],imm8
            &[0x66, 0xc7, 0x00, 0x22, 0x11],       // mov word ptr [rax],imm16
            &[0xc7, 0x00, 0x44, 0x33, 0x22, 0x11], // mov dword ptr [rax],imm32
            &[0x88, 0x30],                         // mov [rax],dh
            &[0x66, 0x89, 0x30],                   // mov [rax],si
            &[0x89, 0x30],                         // mov [rax],esi
            &[0x8b, 0x40, 0x10],                   // mov eax,[rax+0x10]
            &[0x8a, 0x40, 0x10],                   // mov al,[rax+0x10]
            &[0x66, 0x0f, 0xb6, 0xc3],             // movzx ax,bl
            &[0x0f, 0xb6, 0xc3],                   // movzx eax,bl
            &[0x48, 0x0f, 0xb6, 0xc3],             // movzx rax,bl
            &[0x0f, 0xb6, 0xc7],                   // movzx eax,bh
            &[0x0f, 0xb7, 0x03],                   // movzx eax,word ptr [rbx]
            &[0x48, 0x0f, 0xb7, 0x03],             // movzx rax,word ptr [rbx]
            &[0x66, 0xa1, 0, 0, 0, 0],             // mov ax,moffs16
            &[0xa1, 0, 0, 0, 0],                   // mov eax,moffs32
            &[0x48, 0xa1, 0, 0, 0, 0, 0, 0, 0, 0], // mov rax,moffs64
            &[0x66, 0xa3, 0, 0, 0, 0],             // mov moffs16,ax
            &[0xa3, 0, 0, 0, 0],                   // mov moffs32,eax
            &[0x48, 0xa3, 0, 0, 0, 0, 0, 0, 0, 0], // mov moffs64,rax
            &[0x38, 0xc4],                         // cmp ah,al
            &[0x3a, 0xc3],                         // cmp al,bl
            &[0x66, 0x39, 0xd8],                   // cmp ax,bx
            &[0x83, 0xf8, 0x64],                   // cmp eax,100
            &[0x83, 0xf8, 0xff],                   // cmp eax,-1
            &[0x48, 0x83, 0xf8, 0xff],             // cmp rax,-1
            &[0x66, 0x83, 0xf8, 0xff],             // cmp ax,-1
            &[0x80, 0xf8, 0x11],                   // cmp al,0x11
            &[0x66, 0x81, 0xf8, 0x22, 0x11],       // cmp ax,0x1122
            &[0x81, 0xf8, 0x44, 0x33, 0x22, 0x11], // cmp eax,0x11223344
            &[0x48, 0x81, 0xf8, 0x44, 0x33, 0x22, 0x11], // cmp rax,0x11223344
            &[0x3c, 0x11],                         // cmp al,0x11
            &[0x66, 0x3d, 0x22, 0x11],             // cmp ax,0x1122
            &[0x3d, 0x44, 0x33, 0x22, 0x11],       // cmp eax,0x11223344
            &[0x48, 0x3d, 0x44, 0x33, 0x22, 0x11], // cmp rax,0x11223344
            &[0x48, 0x39, 0xd8],                   // cmp rax,rbx
            &[0x39, 0xd8],                         // cmp eax,ebx
            &[0x48, 0x3b, 0xc3],                   // cmp rax,rbx
            &[0x3b, 0xc3],                         // cmp eax,ebx
            &[0x66, 0x3b, 0xc3],                   // cmp ax,bx
            &[0x40, 0x08, 0x70, 0x1],              // or byte ptr [rax+1],sil
            &[0x48, 0xa5],                         // movsq
            &[0xa5],                               // movsd
            &[0x66, 0xa5],                         // movsw
            &[0xa4],                               // movsb
            &[0xf3, 0xa4],                         // rep movsb
            &[0xf3, 0xa5],                         // rep movsd
            &[0xf3, 0x48, 0xa5],                   // rep movsq
            &[0xaa],                               // stosb
            &[0xf3, 0xaa],                         // rep stosb
            &[0x66, 0xab],                         // stosw
            &[0xab],                               // stosd
            &[0x48, 0xab],                         // stosq
            &[0x66, 0xf3, 0xab],                   // rep stosw
            &[0xf3, 0xab],                         // rep stosd
            &[0xf3, 0x48, 0xab],                   // rep stosq
            &[0x88, 0xc4],                         // mov ah,al
            &[0x88, 0xcf],                         // mov bh,cl
            &[0x88, 0xd5],                         // mov ch,dl
            &[0x88, 0xde],                         // mov dh,bl
            &[0x2e, 0x8a, 0x00],                   // mov al,[cs:rax]
            &[0x36, 0x8a, 0x00],                   // mov al,[ss:rax]
            &[0x64, 0x8a, 0x00],                   // mov al,[fs:rax]
            &[0x65, 0x8a, 0x00],                   // mov al,[gs:rax]
        ];

        let main_profiles = [CpuProfile::Protected, CpuProfile::Real, CpuProfile::Long];
        exercise_cpu_state_manager(input);

        for insn in SUPPORTED_INSNS {
            for profile in &main_profiles {
                run_emulation(
                    input,
                    *profile,
                    insn,
                    true,
                    [0x48, 0x89, 0xd8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                );
            }
        }

        for reg in 0u8..16 {
            let src = reg;
            let dst = reg.wrapping_add(5) & 0xf;
            let mov_rm_r = encode_reg_reg64(0x89, src, dst);
            let mov_r_rm = encode_reg_reg64(0x8b, src, dst);
            let cmp_rm_r = encode_reg_reg64(0x39, src, dst);

            run_emulation(
                input,
                CpuProfile::Protected,
                &mov_rm_r,
                true,
                [0x48, 0x89, 0xd8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            );
            run_emulation(
                input,
                CpuProfile::Long,
                &mov_r_rm,
                true,
                [0x48, 0x89, 0xd8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            );
            run_emulation(
                input,
                CpuProfile::Protected,
                &cmp_rm_r,
                true,
                [0x48, 0x39, 0xd8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            );
        }

        run_emulation(
            input,
            CpuProfile::ReadOnlySegments,
            &[0x88, 0x30],
            true,
            [0x88, 0x30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );
        run_emulation(
            input,
            CpuProfile::ExpandDownSegments,
            &[0xa5],
            true,
            [0xa5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );
        run_emulation(
            input,
            CpuProfile::ExpandDownSegmentsOk,
            &[0xa5],
            true,
            [0xa5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );
        run_emulation(
            input,
            CpuProfile::ExpandDownSegmentsOk16,
            &[0xa5],
            true,
            [0xa5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );
        run_emulation(
            input,
            CpuProfile::GranularSegments,
            &[0x8b, 0x40, 0x10],
            true,
            [0x8b, 0x40, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );
        run_emulation(
            input,
            CpuProfile::LimitedSegments,
            &[0x8b, 0x00],
            true,
            [0x8b, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );
        run_emulation(
            input,
            CpuProfile::InvalidLong,
            &[0x8b, 0x40, 0x10],
            true,
            [0x8b, 0x40, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );
        run_emulation(
            input,
            CpuProfile::LongAddressOverflow,
            &[0x88, 0x30],
            true,
            [0x88, 0x30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );
        run_emulation(
            input,
            CpuProfile::Long,
            &[0x48, 0x8b, 0x05, 0, 0, 0, 0],
            true,
            [0x48, 0x8b, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );
        run_emulation(
            input,
            CpuProfile::Protected,
            &[0x8b, 0x44, 0x98, 0x10],
            true,
            [0x8b, 0x44, 0x98, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );

        run_emulation(
            input,
            CpuProfile::Protected,
            &input.primary_insn,
            true,
            input.secondary_insn,
        );

        run_emulation(
            input,
            CpuProfile::Protected,
            &[0x48, 0x8b],
            true,
            [0x48, 0x89, 0xd8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );
        run_emulation_with_fault(
            input,
            CpuProfile::Protected,
            &[0x48, 0x8b],
            true,
            [0x48, 0x89, 0xd8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            FaultMode::Fetch,
        );
        run_emulation(
            input,
            CpuProfile::Protected,
            &[0x48, 0x8b],
            true,
            [0xff; FETCH_BUFFER_SIZE],
        );
        run_emulation_with_fault(
            input,
            CpuProfile::Protected,
            &[0x8b, 0x40, 0x10],
            true,
            [0x8b, 0x40, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            FaultMode::ReadMemory,
        );
        run_emulation_with_fault(
            input,
            CpuProfile::Protected,
            &[0x88, 0x30],
            true,
            [0x88, 0x30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            FaultMode::WriteMemory,
        );
        run_emulation_with_fault(
            input,
            CpuProfile::Protected,
            &[0x48, 0x89, 0xd8],
            true,
            [0x48, 0x89, 0xd8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            FaultMode::CpuState,
        );
        run_emulation(
            input,
            CpuProfile::Protected,
            &[0x0f, 0x0b],
            true,
            [0x0f, 0x0b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );

        let mut stream = [0u8; FETCH_BUFFER_SIZE * 2];
        stream[..FETCH_BUFFER_SIZE].copy_from_slice(&input.primary_insn);
        stream[FETCH_BUFFER_SIZE..].copy_from_slice(&[
            0x48, 0x89, 0xd8, 0x90, 0x90, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        run_emulation(
            input,
            CpuProfile::Long,
            &stream,
            false,
            [0x48, 0x89, 0xd8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );
    }

    fuzz_target!(|bytes: &[u8]| -> Corpus {
        let input = match FuzzInput::parse(bytes) {
            Ok(input) => input,
            Err(_) => return Corpus::Reject,
        };

        run_harness(&input);

        if input.primary_insn.iter().all(|b| *b == 0) {
            return Corpus::Reject;
        }

        Corpus::Keep
    });
}

#[cfg(not(target_arch = "x86_64"))]
fn main() {}
