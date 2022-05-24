// Copyright © 2022 ZTE Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::fs::File;

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
