// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Copyright © 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

#![no_main]

use std::io::Cursor;

use arbitrary::Unstructured;
use libfuzzer_sys::{fuzz_target, Corpus};
use linux_loader::loader::KernelLoader;
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::{Address, GuestAddress};

type GuestMemoryMmap = vm_memory::GuestMemoryMmap<AtomicBitmap>;

const MEM_SIZE: usize = 256 * 1024 * 1024;
// From 'arch::x86_64::layout::HIGH_RAM_START'
const HIGH_RAM_START: GuestAddress = GuestAddress(0x100000);

const ELF_HDR_SIZE: usize = 64;
const ELF_PHDR_SIZE: usize = 56;
const PT_LOAD: u32 = 1;
const PT_NULL: u32 = 0;
const PT_NOTE: u32 = 4;
const XEN_ELFNOTE_PHYS32_ENTRY: u32 = 18;

#[derive(Debug)]
struct StructuredInput {
    entry: u64,
    load_addr: u64,
    kernel_offset: u64,
    tweak: u64,
    payload: Vec<u8>,
    note_desc: [u8; 4],
}

impl StructuredInput {
    fn from_bytes(bytes: &[u8]) -> arbitrary::Result<Self> {
        let mut unstructured = Unstructured::new(bytes);
        let entry = unstructured.arbitrary::<u64>()?;
        let load_addr = unstructured.arbitrary::<u64>()?;
        let kernel_offset = unstructured.arbitrary::<u64>()?;
        let tweak = unstructured.arbitrary::<u64>()?;
        let payload_len = unstructured.int_in_range(0..=1024usize)?;
        let mut payload = unstructured.bytes(payload_len)?.to_vec();
        let note_desc = unstructured.arbitrary::<[u8; 4]>()?;
        let flags = unstructured.arbitrary::<u16>()?;
        if payload.is_empty() {
            payload.push((flags & 0xff) as u8);
        }

        Ok(Self {
            entry,
            load_addr,
            kernel_offset,
            tweak,
            payload,
            note_desc,
        })
    }
}

#[derive(Clone, Copy)]
enum ElfCase {
    ValidNoOffset,
    ValidWithOffset,
    InvalidMagic,
    ReadElfHeader,
    BigEndian,
    InvalidProgramHeaderSize,
    InvalidProgramHeaderOffset,
    InvalidEntryAddress,
    KernelLoadOverflow,
    InvalidProgramHeaderAddress,
    ReadProgramHeader,
    ReadKernelImage,
    KernelEndOverflow,
    NonLoadProgramHeader,
    ZeroSizedLoad,
    PvhNotPresent,
    PvhWrongName,
    PvhNameReadFailure,
    PvhDescReadFailure,
    PvhSecondNote,
    InvalidPvhNote,
    PvhNoteReadFailure,
    PvhNoteOverflow,
}

const ELF_CASES: [ElfCase; 23] = [
    ElfCase::ValidNoOffset,
    ElfCase::ValidWithOffset,
    ElfCase::InvalidMagic,
    ElfCase::ReadElfHeader,
    ElfCase::BigEndian,
    ElfCase::InvalidProgramHeaderSize,
    ElfCase::InvalidProgramHeaderOffset,
    ElfCase::InvalidEntryAddress,
    ElfCase::KernelLoadOverflow,
    ElfCase::InvalidProgramHeaderAddress,
    ElfCase::ReadProgramHeader,
    ElfCase::ReadKernelImage,
    ElfCase::KernelEndOverflow,
    ElfCase::NonLoadProgramHeader,
    ElfCase::ZeroSizedLoad,
    ElfCase::PvhNotPresent,
    ElfCase::PvhWrongName,
    ElfCase::PvhNameReadFailure,
    ElfCase::PvhDescReadFailure,
    ElfCase::PvhSecondNote,
    ElfCase::InvalidPvhNote,
    ElfCase::PvhNoteReadFailure,
    ElfCase::PvhNoteOverflow,
];

fuzz_target!(|bytes: &[u8]| -> Corpus {
    let input = match StructuredInput::from_bytes(bytes) {
        Ok(input) => input,
        Err(_) => return Corpus::Reject,
    };

    let guest_memory = match GuestMemoryMmap::from_ranges(&[(GuestAddress(0), MEM_SIZE)]) {
        Ok(memory) => memory,
        Err(_) => return Corpus::Reject,
    };

    for case in ELF_CASES {
        run_case(case, &input, &input.payload, &guest_memory);
    }

    Corpus::Keep
});

fn run_case(
    case: ElfCase,
    input: &StructuredInput,
    payload: &[u8],
    guest_memory: &GuestMemoryMmap,
) {
    let payload_offset = 0x200u64;
    let mut entry = HIGH_RAM_START
        .raw_value()
        .saturating_add(input.entry & 0x1f_ffff);
    let max_load = MEM_SIZE
        .saturating_sub(payload.len())
        .saturating_sub(0x2000) as u64;
    let mut load_addr = if max_load == 0 {
        0
    } else {
        input.load_addr % max_load
    };
    let mut phoff = ELF_HDR_SIZE as u64;
    let mut phentsize = ELF_PHDR_SIZE as u16;
    let phnum = 2u16;
    let mut kernel_offset = None;
    let mut highmem = Some(HIGH_RAM_START);
    let load_offset = payload_offset;
    let mut load_type = PT_LOAD;
    let mut load_filesz = payload.len() as u64;
    let mut load_memsz = load_filesz + (input.tweak & 0x1ff);
    let note_offset = 0x120u64;
    let mut note_filesz = 20u64;
    let mut note_namesz = 4u32;
    let mut note_descsz = 4u32;
    let mut note_type = XEN_ELFNOTE_PHYS32_ENTRY;
    let mut note_name = *b"Xen\0";
    let mut note_desc = input.note_desc;
    let mut truncate_to = None;
    let mut add_second_pvh_note = false;
    let mut little_endian = true;
    let mut valid_magic = true;

    match case {
        ElfCase::ValidNoOffset => {}
        ElfCase::ValidWithOffset => {
            kernel_offset = Some(GuestAddress((input.kernel_offset & 0x1f_ff00) + 0x1000));
            highmem = None;
        }
        ElfCase::InvalidMagic => {
            valid_magic = false;
            highmem = None;
        }
        ElfCase::ReadElfHeader => {
            truncate_to = Some(ELF_HDR_SIZE - 1);
            highmem = None;
        }
        ElfCase::BigEndian => {
            little_endian = false;
            highmem = None;
        }
        ElfCase::InvalidProgramHeaderSize => {
            phentsize = phentsize.saturating_sub(1);
            highmem = None;
        }
        ElfCase::InvalidProgramHeaderOffset => {
            phoff = 0x10;
            highmem = None;
        }
        ElfCase::InvalidEntryAddress => {
            highmem = Some(GuestAddress(entry.saturating_add(1)));
        }
        ElfCase::KernelLoadOverflow => {
            entry = 1;
            kernel_offset = Some(GuestAddress(u64::MAX));
            highmem = None;
        }
        ElfCase::InvalidProgramHeaderAddress => {
            entry = 0;
            kernel_offset = Some(GuestAddress(u64::MAX - 0xfff));
            load_addr = 0x2000;
            highmem = None;
        }
        ElfCase::ReadProgramHeader => {
            truncate_to = Some(ELF_HDR_SIZE + ELF_PHDR_SIZE);
            highmem = None;
        }
        ElfCase::ReadKernelImage => {
            load_filesz = load_filesz.saturating_add(0x200);
            load_memsz = load_filesz;
            highmem = None;
        }
        ElfCase::KernelEndOverflow => {
            load_addr = 0x1000;
            load_memsz = u64::MAX;
            highmem = None;
        }
        ElfCase::NonLoadProgramHeader => {
            load_type = PT_NULL;
            highmem = None;
        }
        ElfCase::ZeroSizedLoad => {
            load_filesz = 0;
            load_memsz = 0;
            highmem = None;
        }
        ElfCase::PvhNotPresent => {
            note_type = 0;
            highmem = None;
        }
        ElfCase::PvhWrongName => {
            note_name = *b"Nop\0";
            highmem = None;
        }
        ElfCase::PvhNameReadFailure => {
            load_filesz = 0;
            load_memsz = 0;
            truncate_to = Some(note_offset as usize + 12);
            highmem = None;
        }
        ElfCase::PvhDescReadFailure => {
            load_filesz = 0;
            load_memsz = 0;
            truncate_to = Some(note_offset as usize + 16);
            highmem = None;
        }
        ElfCase::PvhSecondNote => {
            note_type = 0;
            note_filesz = 40;
            add_second_pvh_note = true;
            highmem = None;
        }
        ElfCase::InvalidPvhNote => {
            note_descsz = 1;
            highmem = None;
        }
        ElfCase::PvhNoteReadFailure => {
            load_filesz = 0;
            load_memsz = 0;
            // Truncate the image before the note so seeking/reading it fails.
            truncate_to = Some(ELF_HDR_SIZE + ELF_PHDR_SIZE * 2);
            highmem = None;
        }
        ElfCase::PvhNoteOverflow => {
            note_type = 0;
            note_namesz = u32::MAX;
            note_descsz = 0;
            note_filesz = 12;
            note_name = [0; 4];
            note_desc = [0; 4];
            highmem = None;
        }
    }

    let mut image = build_image(
        entry,
        phoff,
        phentsize,
        phnum,
        load_type,
        load_offset,
        load_addr,
        load_filesz,
        load_memsz,
        note_offset,
        note_filesz,
        note_namesz,
        note_descsz,
        note_type,
        note_name,
        note_desc,
        payload,
        little_endian,
        valid_magic,
    );

    if add_second_pvh_note {
        write_note(
            &mut image,
            note_offset + 20,
            4,
            4,
            XEN_ELFNOTE_PHYS32_ENTRY,
            *b"Xen\0",
            note_desc,
        );
    }

    if let Some(truncate_len) = truncate_to {
        if truncate_len < image.len() {
            image.truncate(truncate_len);
        }
    }

    let mut kernel_image = Cursor::new(image);
    match linux_loader::loader::elf::Elf::load(
        guest_memory,
        kernel_offset,
        &mut kernel_image,
        highmem,
    ) {
        Ok(loader_result) => {
            let _ = loader_result.pvh_boot_cap.to_string();
        }
        Err(err) => {
            let _ = err.to_string();
        }
    }
}

#[expect(clippy::too_many_arguments)]
fn build_image(
    entry: u64,
    phoff: u64,
    phentsize: u16,
    phnum: u16,
    load_type: u32,
    load_offset: u64,
    load_addr: u64,
    load_filesz: u64,
    load_memsz: u64,
    note_offset: u64,
    note_filesz: u64,
    note_namesz: u32,
    note_descsz: u32,
    note_type: u32,
    note_name: [u8; 4],
    note_desc: [u8; 4],
    payload: &[u8],
    little_endian: bool,
    valid_magic: bool,
) -> Vec<u8> {
    let payload_end = usize::try_from(load_offset)
        .ok()
        .and_then(|offset| offset.checked_add(payload.len()))
        .unwrap_or(ELF_HDR_SIZE + ELF_PHDR_SIZE * 2);
    let note_end = usize::try_from(note_offset)
        .ok()
        .and_then(|offset| offset.checked_add(note_filesz as usize))
        .unwrap_or(ELF_HDR_SIZE + ELF_PHDR_SIZE * 2);

    let mut image = vec![
        0u8;
        payload_end
            .max(note_end)
            .max(ELF_HDR_SIZE + ELF_PHDR_SIZE * 2)
    ];

    let mut ident = [0u8; 16];
    ident[0] = if valid_magic { 0x7f } else { 0 };
    ident[1] = b'E';
    ident[2] = b'L';
    ident[3] = b'F';
    ident[4] = 2;
    ident[5] = if little_endian { 1 } else { 2 };
    ident[6] = 1;
    write_slice(&mut image, 0, &ident);

    write_u16_le(&mut image, 16, 2);
    write_u16_le(&mut image, 18, 62);
    write_u32_le(&mut image, 20, 1);
    write_u64_le(&mut image, 24, entry);
    write_u64_le(&mut image, 32, phoff);
    write_u16_le(&mut image, 52, ELF_HDR_SIZE as u16);
    write_u16_le(&mut image, 54, phentsize);
    write_u16_le(&mut image, 56, phnum);

    let load_phdr = ELF_HDR_SIZE;
    write_u32_le(&mut image, load_phdr, load_type);
    write_u32_le(&mut image, load_phdr + 4, 0);
    write_u64_le(&mut image, load_phdr + 8, load_offset);
    write_u64_le(&mut image, load_phdr + 16, load_addr);
    write_u64_le(&mut image, load_phdr + 24, load_addr);
    write_u64_le(&mut image, load_phdr + 32, load_filesz);
    write_u64_le(&mut image, load_phdr + 40, load_memsz);
    write_u64_le(&mut image, load_phdr + 48, 0x1000);

    if phnum > 1 {
        let note_phdr = ELF_HDR_SIZE + ELF_PHDR_SIZE;
        write_u32_le(&mut image, note_phdr, PT_NOTE);
        write_u64_le(&mut image, note_phdr + 8, note_offset);
        write_u64_le(&mut image, note_phdr + 24, 0);
        write_u64_le(&mut image, note_phdr + 32, note_filesz);
        write_u64_le(&mut image, note_phdr + 40, note_filesz);
        write_u64_le(&mut image, note_phdr + 48, 4);
    }

    if let Ok(offset) = usize::try_from(note_offset) {
        write_note_at(
            &mut image,
            offset,
            note_namesz,
            note_descsz,
            note_type,
            note_name,
            note_desc,
        );
    }

    if let Ok(offset) = usize::try_from(load_offset) {
        write_slice(&mut image, offset, payload);
    }

    image
}

fn write_note(
    image: &mut [u8],
    offset: u64,
    note_namesz: u32,
    note_descsz: u32,
    note_type: u32,
    note_name: [u8; 4],
    note_desc: [u8; 4],
) {
    if let Ok(offset) = usize::try_from(offset) {
        write_note_at(
            image,
            offset,
            note_namesz,
            note_descsz,
            note_type,
            note_name,
            note_desc,
        );
    }
}

fn write_note_at(
    image: &mut [u8],
    offset: usize,
    note_namesz: u32,
    note_descsz: u32,
    note_type: u32,
    note_name: [u8; 4],
    note_desc: [u8; 4],
) {
    write_u32_le(image, offset, note_namesz);
    write_u32_le(image, offset + 4, note_descsz);
    write_u32_le(image, offset + 8, note_type);
    write_slice(image, offset + 12, &note_name);
    write_slice(image, offset + 16, &note_desc);
}

fn write_slice(buf: &mut [u8], offset: usize, bytes: &[u8]) {
    if let Some(end) = offset.checked_add(bytes.len()) {
        if let Some(dst) = buf.get_mut(offset..end) {
            dst.copy_from_slice(bytes);
        }
    }
}

fn write_u16_le(buf: &mut [u8], offset: usize, value: u16) {
    write_slice(buf, offset, &value.to_le_bytes());
}

fn write_u32_le(buf: &mut [u8], offset: usize, value: u32) {
    write_slice(buf, offset, &value.to_le_bytes());
}

fn write_u64_le(buf: &mut [u8], offset: usize, value: u64) {
    write_slice(buf, offset, &value.to_le_bytes());
}
