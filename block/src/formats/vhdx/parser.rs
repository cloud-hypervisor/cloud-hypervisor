// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::btree_map::BTreeMap;
use std::fs::File;
use std::io::{self, Error as IoError, ErrorKind as IoErrorKind, Result as IoResult};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::FileExt;
use std::result;

use remain::sorted;
use thiserror::Error;

use super::bat::{self, BatEntry, VhdxBatError};
use super::header::{self, RegionInfo, RegionTableEntry, VhdxHeader, VhdxHeaderError};
use super::metadata::{self, DiskSpec, VhdxMetadataError};
use crate::aligned_file::AlignedFile;

#[sorted]
#[derive(Error, Debug)]
pub enum VhdxError {
    #[error("Not a VHDx file")]
    NotVhdx(#[source] VhdxHeaderError),
    #[error("Failed to parse VHDx header")]
    ParseVhdxHeader(#[source] VhdxHeaderError),
    #[error("Failed to parse VHDx metadata")]
    ParseVhdxMetadata(#[source] VhdxMetadataError),
    #[error("Failed to parse VHDx region entries")]
    ParseVhdxRegionEntry(#[source] VhdxHeaderError),
    #[error("Failed reading metadata")]
    ReadBatEntry(#[source] VhdxBatError),
    #[error("Failed reading sector from disk")]
    ReadFailed(#[source] VhdxIoError),
    #[error("Failed writing to sector on disk")]
    WriteFailed(#[source] VhdxIoError),
}

pub(super) type Result<T> = result::Result<T, VhdxError>;

#[sorted]
#[derive(Error, Debug)]
pub enum VhdxIoError {
    #[error("Invalid BAT entry state")]
    InvalidBatEntryState,
    #[error("Invalid BAT entry file offset: payload block inside the header area")]
    InvalidBatFileOffset,
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
    #[error("Failed writing sector blocks from file {0}")]
    WriteSectorBlock(#[source] io::Error),
}

/// Translation of a sector index and count into a BAT index and the file
/// offsets of the sectors within the addressed payload block.
#[derive(Default)]
struct Sector {
    bat_index: u64,
    free_sectors: u64,
    free_bytes: u64,
    file_offset: u64,
    block_offset: u64,
}

impl Sector {
    fn new(
        disk_spec: &DiskSpec,
        bat: &[BatEntry],
        sector_index: u64,
        sector_count: u64,
    ) -> result::Result<Sector, VhdxIoError> {
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

#[derive(Debug)]
pub struct Vhdx {
    aligned: AlignedFile,
    vhdx_header: VhdxHeader,
    region_entries: BTreeMap<u64, u64>,
    bat_entry: RegionTableEntry,
    mdr_entry: RegionTableEntry,
    disk_spec: DiskSpec,
    bat_entries: Vec<BatEntry>,
    first_write: bool,
}

impl Vhdx {
    /// Parse the Vhdx header, BAT, and metadata from a file and store info
    // in Vhdx structure.
    pub fn new(file: File, direct_io: bool) -> Result<Vhdx> {
        let aligned = AlignedFile::new(file, direct_io);

        let vhdx_header = VhdxHeader::new(&aligned).map_err(VhdxError::ParseVhdxHeader)?;

        let collected_entries = RegionInfo::new(
            &aligned,
            header::REGION_TABLE_1_START,
            vhdx_header.region_entry_count(),
        )
        .map_err(VhdxError::ParseVhdxRegionEntry)?;

        let bat_entry = collected_entries.bat_entry;
        let mdr_entry = collected_entries.mdr_entry;

        let disk_spec =
            DiskSpec::new(&aligned, &mdr_entry).map_err(VhdxError::ParseVhdxMetadata)?;
        let bat_entries = BatEntry::collect_bat_entries(&aligned, &disk_spec, &bat_entry)
            .map_err(VhdxError::ReadBatEntry)?;

        Ok(Vhdx {
            aligned,
            vhdx_header,
            region_entries: collected_entries.region_entries,
            bat_entry,
            mdr_entry,
            disk_spec,
            bat_entries,
            first_write: true,
        })
    }

    pub fn virtual_disk_size(&self) -> u64 {
        self.disk_spec.virtual_disk_size
    }
}

impl Vhdx {
    /// Convert `offset` and `buf_len` to a sector index and count, rejecting
    /// unaligned I/O.
    fn sector_range(&self, buf_len: usize, offset: u64, op: &str) -> IoResult<(u64, u64)> {
        let sector_size = self.disk_spec.logical_sector_size as u64;
        if !(buf_len as u64).is_multiple_of(sector_size) {
            return Err(IoError::new(
                IoErrorKind::InvalidInput,
                format!(
                    "{op} buffer length {buf_len} is not a multiple of the {sector_size}-byte logical sector size"
                ),
            ));
        }
        if !offset.is_multiple_of(sector_size) {
            return Err(IoError::new(
                IoErrorKind::InvalidInput,
                format!(
                    "{op} offset {offset} is not a multiple of the {sector_size}-byte logical sector size"
                ),
            ));
        }
        Ok((offset / sector_size, buf_len as u64 / sector_size))
    }

    /// Read into `buf` at byte `offset`. The offset and length must be
    /// sector aligned.
    pub fn read_at(&self, buf: &mut [u8], offset: u64) -> IoResult<usize> {
        let (sector_index, sector_count) = self.sector_range(buf.len(), offset, "Read")?;
        self.read_sectors(buf, sector_index, sector_count)
            .map_err(|e| {
                IoError::other(format!(
                    "Failed reading {sector_count} sectors from VHDx at index {sector_index}: {e}"
                ))
            })
    }

    /// Write all of `buf` at byte `offset`. The offset and length must be
    /// sector aligned.
    pub fn write_all_at(&mut self, buf: &[u8], offset: u64) -> IoResult<()> {
        let (sector_index, sector_count) = self.sector_range(buf.len(), offset, "Write")?;

        if self.first_write {
            self.first_write = false;
            self.vhdx_header
                .update(&self.aligned)
                .map_err(|e| IoError::other(format!("Failed to update VHDx header: {e}")))?;
        }

        self.write_sectors(buf, sector_index, sector_count)
            .map_err(|e| {
                IoError::other(format!(
                    "Failed writing {sector_count} sectors on VHDx at index {sector_index}: {e}"
                ))
            })?;

        Ok(())
    }

    fn read_sectors(
        &self,
        buf: &mut [u8],
        mut sector_index: u64,
        mut sector_count: u64,
    ) -> result::Result<usize, VhdxIoError> {
        if self.disk_spec.has_parent {
            return Err(VhdxIoError::UnsupportedMode);
        }
        let expected_len = sector_count
            .checked_mul(self.disk_spec.logical_sector_size as u64)
            .ok_or(VhdxIoError::InvalidBufferLength)?;
        if buf.len() as u64 != expected_len {
            return Err(VhdxIoError::InvalidBufferLength);
        }

        let mut read_count: usize = 0;
        while sector_count > 0 {
            let sector = Sector::new(
                &self.disk_spec,
                &self.bat_entries,
                sector_index,
                sector_count,
            )?;

            let bat_entry = match self.bat_entries.get(sector.bat_index as usize) {
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
                    self.aligned
                        .read_exact_at(
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

    fn write_sectors(
        &mut self,
        buf: &[u8],
        mut sector_index: u64,
        mut sector_count: u64,
    ) -> result::Result<usize, VhdxIoError> {
        if self.disk_spec.has_parent {
            return Err(VhdxIoError::UnsupportedMode);
        }
        let expected_len = sector_count
            .checked_mul(self.disk_spec.logical_sector_size as u64)
            .ok_or(VhdxIoError::InvalidBufferLength)?;
        if buf.len() as u64 != expected_len {
            return Err(VhdxIoError::InvalidBufferLength);
        }

        let bat_offset = self.bat_entry.file_offset;
        let mut write_count: usize = 0;
        while sector_count > 0 {
            let sector = Sector::new(
                &self.disk_spec,
                &self.bat_entries,
                sector_index,
                sector_count,
            )?;

            let bat_entry = match self.bat_entries.get(sector.bat_index as usize) {
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
                    let block_size_min = metadata::BLOCK_SIZE_MIN as u64;
                    let file_offset =
                        self.disk_spec.image_size.div_ceil(block_size_min) * block_size_min;
                    let new_size = file_offset
                        .checked_add(self.disk_spec.block_size as u64)
                        .ok_or(VhdxIoError::InvalidDiskSize)?;

                    self.aligned
                        .file()
                        .set_len(new_size)
                        .map_err(VhdxIoError::ResizeFile)?;
                    self.disk_spec.image_size = new_size;

                    let new_bat_entry =
                        file_offset | (bat::PAYLOAD_BLOCK_FULLY_PRESENT & bat::BAT_STATE_BIT_MASK);
                    self.bat_entries[sector.bat_index as usize] = BatEntry(new_bat_entry);
                    BatEntry::write_bat_entries(&self.aligned, bat_offset, &self.bat_entries)
                        .map_err(VhdxIoError::WriteBat)?;

                    if file_offset < block_size_min {
                        return Err(VhdxIoError::InvalidBatFileOffset);
                    }

                    // The BAT entry addresses the start of the payload block;
                    // the sector's data lives at its own offset within that
                    // block, not at the block base.
                    self.aligned
                        .write_all_at(
                            &buf[write_count..(write_count + sector.free_bytes as usize)],
                            file_offset + sector.block_offset,
                        )
                        .map_err(VhdxIoError::WriteSectorBlock)?;
                }
                bat::PAYLOAD_BLOCK_FULLY_PRESENT => {
                    if sector.file_offset < metadata::BLOCK_SIZE_MIN as u64 {
                        return Err(VhdxIoError::InvalidBatFileOffset);
                    }

                    self.aligned
                        .write_all_at(
                            &buf[write_count..(write_count + sector.free_bytes as usize)],
                            sector.file_offset,
                        )
                        .map_err(VhdxIoError::WriteSectorBlock)?;
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

    pub fn flush(&self) -> IoResult<()> {
        self.aligned.sync_all()
    }
}

impl Vhdx {
    pub(crate) fn physical_size(&self) -> result::Result<u64, crate::Error> {
        self.aligned
            .file()
            .metadata()
            .map(|m| m.len())
            .map_err(crate::Error::GetFileMetadata)
    }
}

impl Vhdx {
    pub fn try_clone(&self) -> IoResult<Vhdx> {
        Ok(Vhdx {
            aligned: self.aligned.try_clone()?,
            vhdx_header: self.vhdx_header.clone(),
            region_entries: self.region_entries.clone(),
            bat_entry: self.bat_entry,
            mdr_entry: self.mdr_entry,
            disk_spec: self.disk_spec.clone(),
            bat_entries: self.bat_entries.clone(),
            first_write: self.first_write,
        })
    }
}

impl AsRawFd for Vhdx {
    fn as_raw_fd(&self) -> RawFd {
        self.aligned.file().as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::FileExt;
    use std::path::Path;

    use super::*;
    use crate::formats::vhdx::bat::PAYLOAD_BLOCK_FULLY_PRESENT;
    use crate::formats::vhdx::test_util::create_dynamic_vhdx;

    /// Opens an image read-write, which is what every test here needs: they
    /// all write through the handle, or check that a write is refused.
    fn open_vhdx(path: &Path) -> Vhdx {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        Vhdx::new(file, false).unwrap()
    }

    /// An unaligned sector write under a forced O_DIRECT alignment must go
    /// through `AlignedFile`'s read-modify-write bounce (the data block and the
    /// BAT update both land at unaligned host offsets) and read back intact.
    #[test]
    fn unaligned_write_is_rmw() {
        let Some(tf) = create_dynamic_vhdx(16) else {
            eprintln!("skipping unaligned_write_is_rmw: qemu-img unavailable");
            return;
        };

        let mut vhdx = open_vhdx(tf.as_path());

        // Force a non-zero alignment so all of vhdx's positioned I/O exercises
        // the bounce/RMW path even though the tempfile is not really O_DIRECT.
        vhdx.aligned = AlignedFile::with_alignment(vhdx.aligned.file().try_clone().unwrap(), 512);

        let sector = vhdx.disk_spec.logical_sector_size as usize;
        let data: Vec<u8> = (0..sector).map(|i| ((i + 1) % 251) as u8).collect();

        // Write at virtual offset 0 (allocates a new data block + rewrites BAT).
        vhdx.write_all_at(&data, 0).unwrap();
        vhdx.flush().unwrap();

        // Read it back through the forced-alignment handle.
        let mut readback = vec![0u8; sector];
        assert_eq!(vhdx.read_at(&mut readback, 0).unwrap(), readback.len());
        assert_eq!(readback, data);
    }

    #[test]
    fn header_update_survives_reopen() {
        let Some(tf) = create_dynamic_vhdx(16) else {
            eprintln!("skipping header_update_survives_reopen: qemu-img unavailable");
            return;
        };

        let data = [0xa5u8; 512];
        {
            let mut vhdx = open_vhdx(tf.as_path());
            vhdx.write_all_at(&data, 0).unwrap();
            vhdx.flush().unwrap();
        }

        let vhdx = open_vhdx(tf.as_path());
        let mut readback = [0u8; 512];
        assert_eq!(vhdx.read_at(&mut readback, 0).unwrap(), readback.len());
        assert_eq!(readback, data);
    }

    #[test]
    fn read_misaligned_buffer_is_rejected() {
        let Some(tf) = create_dynamic_vhdx(16) else {
            eprintln!("skipping read_misaligned_buffer_is_rejected: qemu-img unavailable");
            return;
        };

        let vhdx = open_vhdx(tf.as_path());

        let mut buf = vec![0u8; vhdx.disk_spec.logical_sector_size as usize - 1];
        let err = vhdx.read_at(&mut buf, 0).unwrap_err();
        assert_eq!(err.kind(), IoErrorKind::InvalidInput);
    }

    #[test]
    fn write_misaligned_buffer_is_rejected() {
        let Some(tf) = create_dynamic_vhdx(16) else {
            eprintln!("skipping write_misaligned_buffer_is_rejected: qemu-img unavailable");
            return;
        };

        let mut vhdx = open_vhdx(tf.as_path());

        let buf = vec![0u8; vhdx.disk_spec.logical_sector_size as usize - 1];
        let err = vhdx.write_all_at(&buf, 0).unwrap_err();
        assert_eq!(err.kind(), IoErrorKind::InvalidInput);
    }

    #[test]
    fn write_with_bat_entry_in_header_area_is_rejected() {
        let Some(tf) = create_dynamic_vhdx(16) else {
            eprintln!(
                "skipping write_with_bat_entry_in_header_area_is_rejected: qemu-img unavailable"
            );
            return;
        };

        let mut vhdx = open_vhdx(tf.as_path());

        // Simulate a corrupt image: BAT entry 0 says "fully present at file
        // offset 0", i.e. on top of the VHDX file header.
        vhdx.bat_entries[0] = BatEntry(PAYLOAD_BLOCK_FULLY_PRESENT);

        let data = [0x33u8; 512];
        let err = vhdx.write_all_at(&data, 0).unwrap_err();
        assert!(
            err.to_string().contains("BAT entry file offset"),
            "unexpected error: {err}"
        );

        // The file identifier must still be intact.
        let mut signature = [0u8; 8];
        vhdx.aligned
            .file()
            .read_exact_at(&mut signature, 0)
            .unwrap();
        assert_eq!(&signature, b"vhdxfile");
    }

    #[test]
    fn read_misaligned_offset_is_rejected() {
        let Some(tf) = create_dynamic_vhdx(16) else {
            eprintln!("skipping read_misaligned_offset_is_rejected: qemu-img unavailable");
            return;
        };

        let vhdx = open_vhdx(tf.as_path());
        let sector = vhdx.disk_spec.logical_sector_size as usize;

        let mut buf = vec![0u8; sector];
        let err = vhdx.read_at(&mut buf, 100).unwrap_err();
        assert_eq!(err.kind(), IoErrorKind::InvalidInput);
    }

    #[test]
    fn write_misaligned_offset_is_rejected() {
        let Some(tf) = create_dynamic_vhdx(16) else {
            eprintln!("skipping write_misaligned_offset_is_rejected: qemu-img unavailable");
            return;
        };

        let mut vhdx = open_vhdx(tf.as_path());
        let sector = vhdx.disk_spec.logical_sector_size as usize;

        // Establish known content in sector 0 and sector 1.
        vhdx.write_all_at(&vec![0xAAu8; sector], 0).unwrap();
        vhdx.write_all_at(&vec![0xBBu8; sector], sector as u64)
            .unwrap();

        let err = vhdx.write_all_at(&vec![0xCCu8; sector], 100).unwrap_err();
        assert_eq!(err.kind(), IoErrorKind::InvalidInput);

        // Neither sector may have been touched by the rejected write.
        let mut buf = vec![0u8; sector];
        assert_eq!(vhdx.read_at(&mut buf, 0).unwrap(), sector);
        assert!(buf.iter().all(|&b| b == 0xAA), "sector 0 was modified");
        assert_eq!(vhdx.read_at(&mut buf, sector as u64).unwrap(), sector);
        assert!(buf.iter().all(|&b| b == 0xBB), "sector 1 was modified");
    }

    #[test]
    fn write_allocating_a_block_honours_the_sector_offset() {
        let Some(tf) = create_dynamic_vhdx(16) else {
            eprintln!(
                "skipping write_allocating_a_block_honours_the_sector_offset: qemu-img unavailable"
            );
            return;
        };

        let mut vhdx = open_vhdx(tf.as_path());
        let sector = vhdx.disk_spec.logical_sector_size as usize;

        // Sector 1 of a fresh image: its block is still unallocated, so the
        // write has to allocate the block and place the data at the sector's
        // offset within it.
        let data: Vec<u8> = (0..sector).map(|i| ((i + 1) % 251) as u8).collect();
        vhdx.write_all_at(&data, sector as u64).unwrap();
        vhdx.flush().unwrap();

        // The data must be readable from the sector it was written to...
        let mut readback = vec![0u8; sector];
        assert_eq!(vhdx.read_at(&mut readback, sector as u64).unwrap(), sector);
        assert_eq!(readback, data, "data not readable at the offset written");

        // ... and sector 0 of the same block must stay zeroed.
        let mut first = vec![0xFFu8; sector];
        assert_eq!(vhdx.read_at(&mut first, 0).unwrap(), sector);
        assert!(
            first.iter().all(|&b| b == 0),
            "sector 0 of the block was overwritten"
        );
    }
}
