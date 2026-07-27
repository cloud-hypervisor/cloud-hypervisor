// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::os::unix::fs::FileExt;
use std::{io, result};

use remain::sorted;
use thiserror::Error;

use super::bat::{self, BatEntry, VhdxBatError};
use super::metadata::{self, DiskSpec};
use crate::aligned_file::AlignedFile;

#[sorted]
#[derive(Error, Debug)]
pub enum VhdxIoError {
    #[error("Invalid BAT entry state")]
    InvalidBatEntryState,
    #[error("Invalid BAT entry count")]
    InvalidBatIndex,
    #[error("Buffer length does not match the requested sector count")]
    InvalidBufferLength,
    #[error("Invalid disk size")]
    InvalidDiskSize,
    #[error("Failed reading sector blocks from file {0}")]
    ReadSectorBlock(#[source] io::Error),
    #[error("Failed changing file length {0}")]
    ResizeFile(#[source] io::Error),
    #[error("Differencing mode is not supported yet")]
    UnsupportedMode,
    #[error("Failed writing BAT to file {0}")]
    WriteBat(#[source] VhdxBatError),
}

pub(super) type Result<T> = result::Result<T, VhdxIoError>;

macro_rules! align {
    ($n:expr, $align:expr) => {{ $n.div_ceil($align) * $align }};
}

#[derive(Default)]
struct Sector {
    bat_index: u64,
    free_sectors: u64,
    free_bytes: u64,
    file_offset: u64,
    block_offset: u64,
}

impl Sector {
    /// Translate sector index and count of data in file to actual offsets and
    /// BAT index.
    pub(crate) fn new(
        disk_spec: &DiskSpec,
        bat: &[BatEntry],
        sector_index: u64,
        sector_count: u64,
    ) -> Result<Sector> {
        let mut sector = Sector::default();

        sector.bat_index = sector_index / disk_spec.sectors_per_block as u64;
        sector.block_offset = sector_index % disk_spec.sectors_per_block as u64;
        sector.free_sectors = disk_spec.sectors_per_block as u64 - sector.block_offset;
        if sector.free_sectors > sector_count {
            sector.free_sectors = sector_count;
        }

        sector.free_bytes = sector.free_sectors * disk_spec.logical_sector_size as u64;
        sector.block_offset *= disk_spec.logical_sector_size as u64;

        let bat_entry = match bat.get(sector.bat_index as usize) {
            Some(entry) => entry.0,
            None => {
                return Err(VhdxIoError::InvalidBatIndex);
            }
        };
        sector.file_offset = bat_entry & bat::BAT_FILE_OFF_MASK;
        if sector.file_offset != 0 {
            sector.file_offset += sector.block_offset;
        }

        Ok(sector)
    }
}

/// VHDx IO read routine: requires relative sector index and count for the
/// requested data.
pub(super) fn read(
    f: &AlignedFile,
    buf: &mut [u8],
    disk_spec: &DiskSpec,
    bat: &[BatEntry],
    mut sector_index: u64,
    mut sector_count: u64,
) -> Result<usize> {
    if disk_spec.has_parent {
        return Err(VhdxIoError::UnsupportedMode);
    }
    let expected_len = sector_count
        .checked_mul(disk_spec.logical_sector_size as u64)
        .ok_or(VhdxIoError::InvalidBufferLength)?;
    if buf.len() as u64 != expected_len {
        return Err(VhdxIoError::InvalidBufferLength);
    }

    let mut read_count: usize = 0;
    while sector_count > 0 {
        let sector = Sector::new(disk_spec, bat, sector_index, sector_count)?;

        let bat_entry = match bat.get(sector.bat_index as usize) {
            Some(entry) => entry.0,
            None => {
                return Err(VhdxIoError::InvalidBatIndex);
            }
        };

        match bat_entry & bat::BAT_STATE_BIT_MASK {
            bat::PAYLOAD_BLOCK_NOT_PRESENT
            | bat::PAYLOAD_BLOCK_UNDEFINED
            | bat::PAYLOAD_BLOCK_UNMAPPED
            | bat::PAYLOAD_BLOCK_ZERO => {}
            bat::PAYLOAD_BLOCK_FULLY_PRESENT => {
                f.read_exact_at(
                    &mut buf[read_count..(read_count + sector.free_bytes as usize)],
                    sector.file_offset,
                )
                .map_err(VhdxIoError::ReadSectorBlock)?;
            }
            bat::PAYLOAD_BLOCK_PARTIALLY_PRESENT => {
                return Err(VhdxIoError::UnsupportedMode);
            }
            _ => {
                return Err(VhdxIoError::InvalidBatEntryState);
            }
        }
        sector_count -= sector.free_sectors;
        sector_index += sector.free_sectors;
        read_count += sector.free_bytes as usize;
    }
    Ok(read_count)
}

/// VHDx IO write routine: requires relative sector index and count for the
/// requested data.
pub(super) fn write(
    f: &AlignedFile,
    buf: &[u8],
    disk_spec: &mut DiskSpec,
    bat_offset: u64,
    bat: &mut [BatEntry],
    mut sector_index: u64,
    mut sector_count: u64,
) -> Result<usize> {
    if disk_spec.has_parent {
        return Err(VhdxIoError::UnsupportedMode);
    }
    let expected_len = sector_count
        .checked_mul(disk_spec.logical_sector_size as u64)
        .ok_or(VhdxIoError::InvalidBufferLength)?;
    if buf.len() as u64 != expected_len {
        return Err(VhdxIoError::InvalidBufferLength);
    }

    let mut write_count: usize = 0;
    while sector_count > 0 {
        let sector = Sector::new(disk_spec, bat, sector_index, sector_count)?;

        let bat_entry = match bat.get(sector.bat_index as usize) {
            Some(entry) => entry.0,
            None => {
                return Err(VhdxIoError::InvalidBatIndex);
            }
        };

        match bat_entry & bat::BAT_STATE_BIT_MASK {
            bat::PAYLOAD_BLOCK_NOT_PRESENT
            | bat::PAYLOAD_BLOCK_UNDEFINED
            | bat::PAYLOAD_BLOCK_UNMAPPED
            | bat::PAYLOAD_BLOCK_ZERO => {
                let file_offset = align!(disk_spec.image_size, metadata::BLOCK_SIZE_MIN as u64);
                let new_size = file_offset
                    .checked_add(disk_spec.block_size as u64)
                    .ok_or(VhdxIoError::InvalidDiskSize)?;

                f.file()
                    .set_len(new_size)
                    .map_err(VhdxIoError::ResizeFile)?;
                disk_spec.image_size = new_size;

                let new_bat_entry =
                    file_offset | (bat::PAYLOAD_BLOCK_FULLY_PRESENT & bat::BAT_STATE_BIT_MASK);
                bat[sector.bat_index as usize] = BatEntry(new_bat_entry);
                BatEntry::write_bat_entries(f, bat_offset, bat).map_err(VhdxIoError::WriteBat)?;

                if file_offset < metadata::BLOCK_SIZE_MIN as u64 {
                    break;
                }

                f.write_all_at(
                    &buf[write_count..(write_count + sector.free_bytes as usize)],
                    file_offset,
                )
                .map_err(VhdxIoError::ReadSectorBlock)?;
            }
            bat::PAYLOAD_BLOCK_FULLY_PRESENT => {
                if sector.file_offset < metadata::BLOCK_SIZE_MIN as u64 {
                    break;
                }

                f.write_all_at(
                    &buf[write_count..(write_count + sector.free_bytes as usize)],
                    sector.file_offset,
                )
                .map_err(VhdxIoError::ReadSectorBlock)?;
            }
            bat::PAYLOAD_BLOCK_PARTIALLY_PRESENT => {
                return Err(VhdxIoError::UnsupportedMode);
            }
            _ => {
                return Err(VhdxIoError::InvalidBatEntryState);
            }
        }
        sector_count -= sector.free_sectors;
        sector_index += sector.free_sectors;
        write_count += sector.free_bytes as usize;
    }
    Ok(write_count)
}

#[cfg(test)]
mod tests {
    use vmm_sys_util::tempfile::TempFile;

    use super::*;

    // 512 is the only sector size read/write allowed by metadata::parse_metadata.
    // [MS-VHDX] allows 4096, but it's not currently implemented
    const SECTOR_SIZE: u64 = 512;

    // The first BLOCK_SIZE_MIN bytes of a VHDx file are always headers, so
    // write() treats a file offset below BLOCK_SIZE_MIN as malformed and skips
    // the writing operation.
    // Use a DATA_OFFSET greater than BLOCK_SIZE_MIN to bypass that early exit.
    const DATA_OFFSET: u64 = 2 * metadata::BLOCK_SIZE_MIN as u64;

    fn fixture() -> (AlignedFile, DiskSpec, Vec<BatEntry>) {
        let disk_spec = DiskSpec {
            // One block == one sector, so there's exactly one BAT entry.
            sectors_per_block: 1,
            logical_sector_size: SECTOR_SIZE as u32,
            virtual_disk_size: SECTOR_SIZE,
            image_size: DATA_OFFSET + SECTOR_SIZE,
            block_size: SECTOR_SIZE as u32,
            ..Default::default()
        };

        let file = TempFile::new().unwrap().into_file();
        file.set_len(DATA_OFFSET + SECTOR_SIZE).unwrap();
        file.write_all_at(&vec![0xABu8; SECTOR_SIZE as usize], DATA_OFFSET)
            .unwrap();
        // A BAT entry saying "this block's data is already written to the
        // file at `file_offset`".
        let bat = vec![BatEntry(DATA_OFFSET | bat::PAYLOAD_BLOCK_FULLY_PRESENT)];
        (AlignedFile::new(file, false), disk_spec, bat)
    }

    #[test]
    fn read_sector() {
        let (f, disk_spec, bat) = fixture();

        let mut buf = vec![0u8; SECTOR_SIZE as usize];
        let n = read(&f, &mut buf, &disk_spec, &bat, 0, 1).unwrap();

        assert_eq!(n, SECTOR_SIZE as usize);
        assert!(buf.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn write_sector() {
        let (f, mut disk_spec, mut bat) = fixture();

        let data = vec![0xCDu8; SECTOR_SIZE as usize];
        let n = write(&f, &data, &mut disk_spec, 0, &mut bat, 0, 1).unwrap();
        assert_eq!(n, SECTOR_SIZE as usize);

        let mut readback = vec![0u8; SECTOR_SIZE as usize];
        f.file().read_exact_at(&mut readback, DATA_OFFSET).unwrap();
        assert_eq!(readback, data);
    }

    #[test]
    fn read_short_buffer_is_rejected() {
        let (f, disk_spec, bat) = fixture();

        let mut buf = vec![0u8; SECTOR_SIZE as usize - 1];
        let err = read(&f, &mut buf, &disk_spec, &bat, 0, 1).unwrap_err();

        assert!(matches!(err, VhdxIoError::InvalidBufferLength));
    }

    #[test]
    fn write_short_buffer_is_rejected() {
        let (f, mut disk_spec, mut bat) = fixture();

        let data = vec![0xCDu8; SECTOR_SIZE as usize - 1];
        let err = write(&f, &data, &mut disk_spec, 0, &mut bat, 0, 1).unwrap_err();

        assert!(matches!(err, VhdxIoError::InvalidBufferLength));
    }
}
