// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::os::unix::fs::FileExt;
use std::{io, result};

use thiserror::Error;

use super::header::RegionTableEntry;
use super::metadata::DiskSpec;
use crate::aligned_file::AlignedFile;

// Payload BAT Entry States
pub(super) const PAYLOAD_BLOCK_NOT_PRESENT: u64 = 0;
pub(super) const PAYLOAD_BLOCK_UNDEFINED: u64 = 1;
pub(super) const PAYLOAD_BLOCK_ZERO: u64 = 2;
pub(super) const PAYLOAD_BLOCK_UNMAPPED: u64 = 3;
pub(super) const PAYLOAD_BLOCK_FULLY_PRESENT: u64 = 6;
pub(super) const PAYLOAD_BLOCK_PARTIALLY_PRESENT: u64 = 7;

// Mask for the BAT state
pub(super) const BAT_STATE_BIT_MASK: u64 = 0x07;
// Mask for the offset within the file in units of 1 MB
pub(super) const BAT_FILE_OFF_MASK: u64 = 0xFFFFFFFFFFF00000;

#[derive(Error, Debug)]
pub enum VhdxBatError {
    #[error("Invalid BAT entry")]
    InvalidBatEntry,
    #[error("Invalid BAT entry count")]
    InvalidEntryCount,
    #[error("BAT entry payload block extends past end of file")]
    PayloadPastEnd,
    #[error("Failed to read BAT entry")]
    ReadBat(#[source] io::Error),
    #[error("Failed to write BAT entry")]
    WriteBat(#[source] io::Error),
}

pub(super) type Result<T> = result::Result<T, VhdxBatError>;

#[derive(Default, Clone, Debug)]
pub(super) struct BatEntry(pub u64);

impl BatEntry {
    // Read all BAT entries presented on the disk and insert them to a vector
    pub(super) fn collect_bat_entries(
        f: &AlignedFile,
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

        // Bound the read buffer while avoiding a bounce buffer per entry.
        let bytes = (entry_count as usize)
            .checked_mul(size_of::<u64>())
            .ok_or(VhdxBatError::InvalidEntryCount)?;
        let mut buf = vec![0u8; bytes.min(1 << 20)];

        let mut bat: Vec<BatEntry> = Vec::with_capacity(entry_count as usize);
        for offset in (0..bytes).step_by(1 << 20) {
            let len = (bytes - offset).min(buf.len());
            f.read_exact_at(&mut buf[..len], bat_entry.file_offset + offset as u64)
                .map_err(VhdxBatError::ReadBat)?;
            for chunk in buf[..len].as_chunks::<{ size_of::<u64>() }>().0 {
                let raw_entry = u64::from_le_bytes(*chunk);
                if raw_entry & BAT_STATE_BIT_MASK == PAYLOAD_BLOCK_FULLY_PRESENT
                    && (raw_entry & BAT_FILE_OFF_MASK).saturating_add(disk_spec.block_size as u64)
                        > disk_spec.image_size
                {
                    return Err(VhdxBatError::PayloadPastEnd);
                }
                bat.push(BatEntry(raw_entry));
            }
        }

        Ok(bat)
    }

    // Calculate the number of entries in the BAT
    fn calculate_entries(block_size: u32, virtual_disk_size: u64, chunk_ratio: u64) -> u64 {
        let data_blocks_count = virtual_disk_size.div_ceil(block_size as u64);
        data_blocks_count + (data_blocks_count - 1) / chunk_ratio
    }

    // Update one BAT entry by index.
    pub(super) fn write_bat_entry(
        f: &AlignedFile,
        bat_offset: u64,
        index: u64,
        value: u64,
    ) -> Result<()> {
        let offset = index
            .checked_mul(size_of::<u64>() as u64)
            .and_then(|o| bat_offset.checked_add(o))
            .ok_or(VhdxBatError::InvalidBatEntry)?;

        let buf = value.to_le_bytes();
        f.write_all_at(&buf, offset)
            .map_err(VhdxBatError::WriteBat)?;
        Ok(())
    }
}
