// Copyright © 2022 ZTE Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use linux_loader::elf;
use std::fs::File;
use std::io::Write;
use vm_memory::ByteValued;

#[derive(Clone)]
pub struct CoredumpMemoryRegion {
    pub mem_offset_in_elf: u64,
    pub mem_size: u64,
}

#[derive(Clone)]
pub struct CoredumpMemoryRegions {
    pub ram_maps: std::collections::BTreeMap<u64, CoredumpMemoryRegion>,
}

/// Platform information
#[derive(Default)]
pub struct DumpState {
    pub elf_note_size: isize,
    pub elf_phdr_num: u16,
    pub elf_sh_info: u32,
    pub mem_offset: u64,
    pub mem_info: Option<CoredumpMemoryRegions>,
    pub file: Option<File>,
}

#[derive(Debug)]
pub enum GuestDebuggableError {
    Coredump(anyhow::Error),
    CoredumpFile(std::io::Error),
}

pub trait GuestDebuggable: vm_migration::Pausable {
    fn coredump(
        &mut self,
        _destination_url: &str,
    ) -> std::result::Result<(), GuestDebuggableError> {
        Ok(())
    }
}

#[macro_export]
macro_rules! div_round_up {
    ($n:expr,$d:expr) => {
        ($n + $d - 1) / $d
    };
}

#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct X86_64UserRegs {
    /// r15, r14, r13, r12, rbp, rbx, r11, r10;
    pub regs1: [u64; 8],
    /// r9, r8, rax, rcx, rdx, rsi, rdi, orig_rax;
    pub regs2: [u64; 8],
    pub rip: u64,
    pub cs: u64,
    pub eflags: u64,
    pub rsp: u64,
    pub ss: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    pub ds: u64,
    pub es: u64,
    pub fs: u64,
    pub gs: u64,
}

#[repr(C)]
#[allow(dead_code)]
pub struct X86_64ElfPrStatus {
    pub pad1: [u8; 32],
    pub pid: u32,
    pub pads2: [u8; 76],
    pub regs: X86_64UserRegs,
    pub pad3: [u8; 8],
}

pub enum NoteDescType {
    ElfDesc = 0,
}

// "CORE" or "QEMU"
pub const COREDUMP_NAME_SIZE: u32 = 5;

/// Core file.
const ET_CORE: u16 = 4;
/// 64-bit object.
const ELFCLASS64: u8 = 2;
/// Current ELF version.
const EV_CURRENT: u8 = 1;
/// AMD x86-64 architecture
const EM_X86_64: u16 = 62;

pub trait Elf64Writable {
    fn write_header(
        &mut self,
        dump_state: &DumpState,
    ) -> std::result::Result<(), GuestDebuggableError> {
        let e_ident = [
            elf::ELFMAG0 as u8, // magic
            elf::ELFMAG1,
            elf::ELFMAG2,
            elf::ELFMAG3,
            ELFCLASS64,             // class
            elf::ELFDATA2LSB as u8, //data
            EV_CURRENT,             // version
            0,                      // os_abi
            0,                      // abi_version
            0,                      // padding
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let elf64_ehdr_size = std::mem::size_of::<elf::Elf64_Ehdr>();
        let elf64_phdr_size = std::mem::size_of::<elf::Elf64_Phdr>();
        let mut elf64_ehdr = elf::Elf64_Ehdr {
            e_ident,
            e_type: ET_CORE,
            e_machine: EM_X86_64,
            e_version: EV_CURRENT as u32,
            e_entry: 0,
            e_phoff: elf64_ehdr_size as u64,
            e_shoff: 0,
            e_flags: 0,
            e_ehsize: 0,
            e_phentsize: elf64_phdr_size as u16,
            e_phnum: dump_state.elf_phdr_num,
            e_shentsize: 0,
            e_shnum: 0,
            e_shstrndx: 0,
        };
        elf64_ehdr.e_ehsize = std::mem::size_of_val(&elf64_ehdr) as u16;

        let mut coredump_file = dump_state.file.as_ref().unwrap();
        let bytes: &[u8] = elf64_ehdr.as_slice();
        coredump_file
            .write(bytes)
            .map_err(|e| GuestDebuggableError::CoredumpFile(e.into()))?;

        Ok(())
    }

    fn write_note(
        &mut self,
        dump_state: &DumpState,
    ) -> std::result::Result<(), GuestDebuggableError> {
        let begin = dump_state.mem_offset - dump_state.elf_note_size as u64;
        let elf64_phdr = elf::Elf64_Phdr {
            p_type: elf::PT_NOTE,
            p_flags: 0,
            p_offset: begin,
            p_vaddr: 0,
            p_paddr: 0,
            p_filesz: dump_state.elf_note_size as u64,
            p_memsz: dump_state.elf_note_size as u64,
            p_align: 0,
        };

        let mut coredump_file = dump_state.file.as_ref().unwrap();
        let bytes: &[u8] = elf64_phdr.as_slice();
        coredump_file
            .write(bytes)
            .map_err(|e| GuestDebuggableError::CoredumpFile(e.into()))?;

        Ok(())
    }

    fn write_load(
        &mut self,
        offset: u64,
        phys_addr: u64,
        length: u64,
        virt_addr: u64,
        dump_state: &DumpState,
    ) -> std::result::Result<(), GuestDebuggableError> {
        let elf64_load = elf::Elf64_Phdr {
            p_type: elf::PT_LOAD,
            p_flags: 0,
            p_offset: offset,
            p_vaddr: virt_addr,
            p_paddr: phys_addr,
            p_filesz: length,
            p_memsz: length,
            p_align: 0,
        };

        let mut coredump_file = dump_state.file.as_ref().unwrap();
        let bytes: &[u8] = elf64_load.as_slice();
        coredump_file
            .write(bytes)
            .map_err(|e| GuestDebuggableError::CoredumpFile(e.into()))?;

        Ok(())
    }

    fn write_loads(
        &mut self,
        dump_state: &DumpState,
    ) -> std::result::Result<(), GuestDebuggableError> {
        let mem_info = dump_state.mem_info.as_ref().unwrap();

        for (gpa, load) in &mem_info.ram_maps {
            self.write_load(load.mem_offset_in_elf, *gpa, load.mem_size, 0, dump_state)?;
        }

        Ok(())
    }

    fn elf_note_size(&self, hdr_size: u32, name_size: u32, desc_size: u32) -> u32 {
        (div_round_up!(hdr_size, 4) + div_round_up!(name_size, 4) + div_round_up!(desc_size, 4)) * 4
    }

    fn get_note_size(&self, desc_type: NoteDescType, nr_cpus: u32) -> u32 {
        let note_head_size = std::mem::size_of::<elf::Elf64_Nhdr>() as u32;
        let elf_desc_size = std::mem::size_of::<X86_64ElfPrStatus>() as u32;

        let elf_note_size = self.elf_note_size(note_head_size, COREDUMP_NAME_SIZE, elf_desc_size);

        match desc_type {
            NoteDescType::ElfDesc => elf_note_size * nr_cpus,
        }
    }
}
