// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::mem::size_of;

use byteorder::{ByteOrder, LittleEndian, WriteBytesExt};
use remain::sorted;
use thiserror::Error;

use crate::vhdx::vhdx_header::RegionTableEntry;
use crate::vhdx::vhdx_metadata::DiskSpec;

// Payload BAT Entry States
pub const PAYLOAD_BLOCK_NOT_PRESENT: u64 = 0;
pub const PAYLOAD_BLOCK_UNDEFINED: u64 = 1;
pub const PAYLOAD_BLOCK_ZERO: u64 = 2;
pub const PAYLOAD_BLOCK_UNMAPPED: u64 = 3;
pub const PAYLOAD_BLOCK_FULLY_PRESENT: u64 = 6;
pub const PAYLOAD_BLOCK_PARTIALLY_PRESENT: u64 = 7;

// Mask for the BAT state
pub const BAT_STATE_BIT_MASK: u64 = 0x07;
// Mask for the offset within the file in units of 1 MB
pub const BAT_FILE_OFF_MASK: u64 = 0xFFFFFFFFFFF00000;

#[sorted]
#[derive(Error, Debug)]
pub enum VhdxBatError {
    #[error("Invalid BAT entry")]
    InvalidBatEntry,
    #[error("Invalid BAT entry count")]
    InvalidEntryCount,
    #[error("Failed to read BAT entry")]
    ReadBat(#[source] io::Error),
    #[error("Failed to write BAT entry")]
    WriteBat(#[source] io::Error),
}

pub type Result<T> = std::result::Result<T, VhdxBatError>;

#[derive(Default, Clone, Debug)]
pub struct BatEntry(pub u64);

impl BatEntry {
    // Read all BAT entries presented on the disk and insert them to a vector
    pub fn collect_bat_entries(
        f: &mut File,
        disk_spec: &DiskSpec,
        bat_entry: &RegionTableEntry,
    ) -> Result<Vec<BatEntry>> {
        let entry_count = BatEntry::calculate_entries(
            disk_spec.block_size,
            disk_spec.virtual_disk_size,
            disk_spec.chunk_ratio,
        );
        if entry_count as usize > (bat_entry.length as usize / size_of::<BatEntry>()) {
            return Err(VhdxBatError::InvalidEntryCount);
        }

        let mut bat: Vec<BatEntry> = Vec::with_capacity(entry_count as usize);
        let bytes = (entry_count as usize)
            .checked_mul(size_of::<u64>())
            .ok_or(VhdxBatError::InvalidEntryCount)?;
        f.seek(SeekFrom::Start(bat_entry.file_offset))
            .map_err(VhdxBatError::ReadBat)?;
        let mut buf = vec![0u8; bytes];
        f.read_exact(&mut buf).map_err(VhdxBatError::ReadBat)?;
        for chunk in buf.chunks_exact(size_of::<u64>()) {
            bat.push(BatEntry(LittleEndian::read_u64(chunk)));
        }

        Ok(bat)
    }

    // Calculate the number of entries in the BAT
    fn calculate_entries(block_size: u32, virtual_disk_size: u64, chunk_ratio: u64) -> u64 {
        let data_blocks_count = virtual_disk_size.div_ceil(block_size as u64);
        data_blocks_count + (data_blocks_count - 1) / chunk_ratio
    }

    pub fn write_bat_entry(f: &mut File, bat_offset: u64, index: u64, value: u64) -> Result<()> {
        let off = index
            .checked_mul(size_of::<u64>() as u64)
            .and_then(|o| bat_offset.checked_add(o))
            .ok_or(VhdxBatError::InvalidBatEntry)?;
        f.seek(SeekFrom::Start(off))
            .map_err(VhdxBatError::WriteBat)?;
        f.write_u64::<LittleEndian>(value)
            .map_err(VhdxBatError::WriteBat)?;
        Ok(())
    }
}
