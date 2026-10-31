// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::{self, Error as IoError, ErrorKind as IoErrorKind, Result as IoResult};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::FileExt;
use std::result;

use thiserror::Error;

use super::bat::{self, BatEntry, VhdxBatError};
use super::header::{self, RegionInfo, VhdxHeader, VhdxHeaderError};
use super::metadata::{self, DiskSpec, VhdxMetadataError};
use crate::aligned_file::AlignedFile;

#[derive(Error, Debug)]
pub enum VhdxError {
    #[error("Failed to parse VHDx header")]
    ParseVhdxHeader(#[source] VhdxHeaderError),
    #[error("Failed to parse VHDx metadata")]
    ParseVhdxMetadata(#[source] VhdxMetadataError),
    #[error("Failed to parse VHDx region entries")]
    ParseVhdxRegionEntry(#[source] VhdxHeaderError),
    #[error("Failed reading metadata")]
    ReadBatEntry(#[source] VhdxBatError),
    #[error("VHDX image has an active log that must be replayed before use")]
    UnsupportedLogReplay,
}

pub(super) type Result<T> = result::Result<T, VhdxError>;

#[derive(Error, Debug)]
enum VhdxIoError {
    #[error("Invalid BAT entry state")]
    InvalidBatEntryState,
    #[error("Invalid BAT entry file offset")]
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
        let payload_index = sector_index / disk_spec.sectors_per_block as u64;
        // Skip the sector bitmap entry after each chunk.
        let mut sector = Sector {
            bat_index: payload_index + payload_index / disk_spec.chunk_ratio,
            ..Default::default()
        };
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
        if bat_entry & bat::BAT_STATE_BIT_MASK == bat::PAYLOAD_BLOCK_FULLY_PRESENT {
            sector.file_offset = (bat_entry & bat::BAT_FILE_OFF_MASK)
                .checked_add(sector.block_offset)
                .ok_or(VhdxIoError::InvalidBatFileOffset)?;
        }

        Ok(sector)
    }
}

#[derive(Debug)]
pub(super) struct Vhdx {
    aligned: AlignedFile,
    vhdx_header: VhdxHeader,
    regions: RegionInfo,
    log_offset: u64,
    log_length: u32,
    disk_spec: DiskSpec,
    bat_entries: Vec<BatEntry>,
    // Unused BAT offsets beyond the original EOF.
    reserved_offsets: Vec<u64>,
    first_write: bool,
}

impl Vhdx {
    /// Parse the Vhdx header, BAT, and metadata from a file and store info
    // in Vhdx structure.
    pub(super) fn new(file: File, direct_io: bool) -> Result<Vhdx> {
        let aligned = AlignedFile::new(file, direct_io);

        let vhdx_header = VhdxHeader::new(&aligned).map_err(VhdxError::ParseVhdxHeader)?;
        if vhdx_header.has_active_log() {
            return Err(VhdxError::UnsupportedLogReplay);
        }

        let collected_entries = RegionInfo::new(
            &aligned,
            header::REGION_TABLE_1_START,
            vhdx_header.region_entry_count(),
        )
        .map_err(VhdxError::ParseVhdxRegionEntry)?;

        let bat_entry = collected_entries.bat_entry;
        let mdr_entry = collected_entries.mdr_entry;
        let (log_offset, log_length) = vhdx_header.log_region();
        if collected_entries
            .region_entries
            .values()
            .any(|&(start, end)| {
                header::ranges_overlap(start, end, log_offset, log_offset + log_length as u64)
            })
        {
            return Err(VhdxError::ParseVhdxRegionEntry(
                VhdxHeaderError::RegionOverlap,
            ));
        }

        let disk_spec =
            DiskSpec::new(&aligned, &mdr_entry).map_err(VhdxError::ParseVhdxMetadata)?;
        let (bat_entries, reserved_offsets) =
            BatEntry::collect_bat_entries(&aligned, &disk_spec, &bat_entry)
                .map_err(VhdxError::ReadBatEntry)?;

        Ok(Vhdx {
            aligned,
            vhdx_header,
            regions: collected_entries,
            log_offset,
            log_length,
            disk_spec,
            bat_entries,
            reserved_offsets,
            first_write: true,
        })
    }

    pub(super) fn virtual_disk_size(&self) -> u64 {
        self.disk_spec.virtual_disk_size
    }

    /// Check that a payload block does not overlap reserved space.
    fn check_payload_block_offset(&self, block_base: u64) -> result::Result<(), VhdxIoError> {
        let block_end = block_base.saturating_add(self.disk_spec.block_size as u64);
        let log_end = self.log_offset + self.log_length as u64;

        if block_base < metadata::BLOCK_SIZE_MIN as u64
            || self
                .regions
                .region_entries
                .values()
                .any(|&(start, end)| header::ranges_overlap(block_base, block_end, start, end))
            || header::ranges_overlap(block_base, block_end, self.log_offset, log_end)
        {
            return Err(VhdxIoError::InvalidBatFileOffset);
        }

        Ok(())
    }

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
    pub(super) fn read_at(&self, buf: &mut [u8], offset: u64) -> IoResult<usize> {
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
    pub(super) fn write_all_at(&mut self, buf: &[u8], offset: u64) -> IoResult<()> {
        let (sector_index, sector_count) = self.sector_range(buf.len(), offset, "Write")?;

        if self.first_write {
            self.vhdx_header
                .update(&self.aligned)
                .map_err(|e| IoError::other(format!("Failed to update VHDx header: {e}")))?;
            self.first_write = false;
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
                | bat::PAYLOAD_BLOCK_ZERO => {
                    buf[read_count..read_count + sector.free_bytes as usize].fill(0);
                }
                bat::PAYLOAD_BLOCK_FULLY_PRESENT => {
                    self.check_payload_block_offset(bat_entry & bat::BAT_FILE_OFF_MASK)?;

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
        let expected_len = sector_count
            .checked_mul(self.disk_spec.logical_sector_size as u64)
            .ok_or(VhdxIoError::InvalidBufferLength)?;
        if buf.len() as u64 != expected_len {
            return Err(VhdxIoError::InvalidBufferLength);
        }

        let bat_offset = self.regions.bat_entry.file_offset;
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
                    let mut file_offset =
                        self.disk_spec.image_size.div_ceil(block_size_min) * block_size_min;
                    let next = self
                        .reserved_offsets
                        .partition_point(|&offset| offset < file_offset);
                    for &reserved in &self.reserved_offsets[next..] {
                        if reserved != file_offset {
                            break;
                        }
                        file_offset = file_offset
                            .checked_add(block_size_min)
                            .ok_or(VhdxIoError::InvalidDiskSize)?;
                    }
                    let new_size = file_offset
                        .checked_add(self.disk_spec.block_size as u64)
                        .ok_or(VhdxIoError::InvalidDiskSize)?;

                    self.aligned
                        .file()
                        .set_len(new_size)
                        .map_err(VhdxIoError::ResizeFile)?;
                    self.disk_spec.image_size = new_size;

                    self.aligned
                        .write_all_at(
                            &buf[write_count..(write_count + sector.free_bytes as usize)],
                            file_offset + sector.block_offset,
                        )
                        .map_err(VhdxIoError::WriteSectorBlock)?;

                    let new_bat_entry =
                        file_offset | (bat::PAYLOAD_BLOCK_FULLY_PRESENT & bat::BAT_STATE_BIT_MASK);
                    BatEntry::write_bat_entry(
                        &self.aligned,
                        bat_offset,
                        sector.bat_index,
                        new_bat_entry,
                    )
                    .map_err(VhdxIoError::WriteBat)?;
                    self.bat_entries[sector.bat_index as usize] = BatEntry(new_bat_entry);
                }
                bat::PAYLOAD_BLOCK_FULLY_PRESENT => {
                    self.check_payload_block_offset(bat_entry & bat::BAT_FILE_OFF_MASK)?;

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

    pub(super) fn flush(&self) -> IoResult<()> {
        self.aligned.sync_all()
    }

    pub(super) fn physical_size(&self) -> result::Result<u64, crate::Error> {
        self.aligned
            .file()
            .metadata()
            .map(|m| m.len())
            .map_err(crate::Error::GetFileMetadata)
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

    use super::*;
    use crate::formats::vhdx::bat::PAYLOAD_BLOCK_FULLY_PRESENT;
    use crate::formats::vhdx::test_util::{create_dynamic_vhdx, edit_header, open_vhdx};

    const VHDX_HEADER_1_OFFSET: u64 = 0x10000;
    const VHDX_HEADER_2_OFFSET: u64 = 0x20000;
    const VHDX_HEADER_SIZE: usize = 4096;
    const VHDX_LOG_GUID_OFFSET: usize = 48;

    #[test]
    fn sector_translation_skips_bitmap_entries() {
        let spec = DiskSpec {
            logical_sector_size: 512,
            sectors_per_block: 2048,
            chunk_ratio: 4096,
            ..Default::default()
        };
        let bat = vec![BatEntry(0); 8195];
        for (sector_index, bat_index, block_offset) in [
            ((1 << 23) - 1, 4095, (1 << 20) - 512),
            (1 << 23, 4097, 0),
            ((1 << 23) + 1, 4097, 512),
            (1 << 24, 8194, 0),
        ] {
            let sector = Sector::new(&spec, &bat, sector_index, 1).unwrap();
            assert_eq!(sector.bat_index, bat_index);
            assert_eq!(sector.block_offset, block_offset);
            assert_eq!(sector.free_bytes, 512);
        }
    }

    #[test]
    fn sector_translation_ignores_unused_offsets() {
        let spec = DiskSpec {
            logical_sector_size: 512,
            sectors_per_block: 4096,
            chunk_ratio: 2048,
            ..Default::default()
        };
        for state in [
            bat::PAYLOAD_BLOCK_NOT_PRESENT,
            bat::PAYLOAD_BLOCK_UNDEFINED,
            bat::PAYLOAD_BLOCK_ZERO,
            bat::PAYLOAD_BLOCK_UNMAPPED,
        ] {
            let bat = [BatEntry(bat::BAT_FILE_OFF_MASK | state)];
            let sector = Sector::new(&spec, &bat, 2048, 1).unwrap();
            assert_eq!(sector.file_offset, 0);
        }
        let bat = [BatEntry(
            bat::BAT_FILE_OFF_MASK | bat::PAYLOAD_BLOCK_FULLY_PRESENT,
        )];
        assert!(matches!(
            Sector::new(&spec, &bat, 2048, 1),
            Err(VhdxIoError::InvalidBatFileOffset)
        ));
    }

    #[test]
    fn unallocated_reads_fill_buffer() {
        let tf = create_dynamic_vhdx(1, None);
        let mut vhdx = open_vhdx(tf.as_path()).unwrap();
        for state in [
            bat::PAYLOAD_BLOCK_NOT_PRESENT,
            bat::PAYLOAD_BLOCK_UNDEFINED,
            bat::PAYLOAD_BLOCK_ZERO,
            bat::PAYLOAD_BLOCK_UNMAPPED,
        ] {
            vhdx.bat_entries[0] = BatEntry(state);
            let mut buf = [0xff; 512];
            assert_eq!(vhdx.read_at(&mut buf, 0).unwrap(), buf.len());
            assert!(buf.iter().all(|&byte| byte == 0), "state={state}");
        }
    }

    #[test]
    fn failed_header_update_is_retried() {
        let tf = create_dynamic_vhdx(1, None);
        let mut vhdx = Vhdx::new(File::open(tf.as_path()).unwrap(), false).unwrap();
        assert!(vhdx.write_all_at(&[0xa5; 512], 0).is_err());
        assert!(vhdx.first_write);
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(tf.as_path())
            .unwrap();
        vhdx.aligned = AlignedFile::new(file, false);
        vhdx.write_all_at(&[0xa5; 512], 0).unwrap();
        assert!(!vhdx.first_write);
    }

    #[test]
    fn failed_bat_write_does_not_publish_allocation() {
        let tf = create_dynamic_vhdx(16, None);
        let mut vhdx = open_vhdx(tf.as_path()).unwrap();
        let old_entry = vhdx.bat_entries[0].0;
        let bat_offset = vhdx.regions.bat_entry.file_offset;
        vhdx.regions.bat_entry.file_offset = u64::MAX;
        assert!(vhdx.write_all_at(&[0xa5; 512], 0).is_err());
        assert_eq!(vhdx.bat_entries[0].0, old_entry);
        vhdx.regions.bat_entry.file_offset = bat_offset;
        vhdx.write_all_at(&[0x5a; 512], 512).unwrap();
        vhdx.flush().unwrap();

        let reopened = open_vhdx(tf.as_path()).unwrap();
        let mut data = [0; 1024];
        reopened.read_at(&mut data, 0).unwrap();
        assert_eq!(data[..512], [0; 512]);
        assert_eq!(data[512..], [0x5a; 512]);
    }

    #[test]
    fn invalid_bat_encodings_are_rejected() {
        let tf = create_dynamic_vhdx(8192, None);
        let vhdx = open_vhdx(tf.as_path()).unwrap();
        let bitmap = vhdx.disk_spec.chunk_ratio;
        for (index, value) in [
            (0, 4),
            (0, 5),
            (0, 7),
            (0, 8),
            (0, 1 << 19),
            (bitmap, 1),
            (bitmap, 2),
            (bitmap, 3),
            (bitmap, 4),
            (bitmap, 5),
            (bitmap, 6),
            (bitmap, 7),
        ] {
            BatEntry::write_bat_entry(
                &vhdx.aligned,
                vhdx.regions.bat_entry.file_offset,
                index,
                value,
            )
            .unwrap();
            assert!(matches!(
                open_vhdx(tf.as_path()),
                Err(VhdxError::ReadBatEntry(VhdxBatError::InvalidBatEntry))
            ));
            BatEntry::write_bat_entry(
                &vhdx.aligned,
                vhdx.regions.bat_entry.file_offset,
                index,
                vhdx.bat_entries[index as usize].0,
            )
            .unwrap();
        }
    }

    #[test]
    fn payload_blocks_must_not_overlap() {
        let tf = create_dynamic_vhdx(1024, None);
        let vhdx = open_vhdx(tf.as_path()).unwrap();
        let start = vhdx.disk_spec.image_size.div_ceil(1 << 20) * (1 << 20);
        let block_size = vhdx.disk_spec.block_size as u64;
        let bat_offset = vhdx.regions.bat_entry.file_offset;
        vhdx.aligned.file().set_len(start + 2 * block_size).unwrap();
        for first_state in [
            bat::PAYLOAD_BLOCK_UNDEFINED,
            bat::PAYLOAD_BLOCK_UNMAPPED,
            PAYLOAD_BLOCK_FULLY_PRESENT,
        ] {
            for second_state in [
                bat::PAYLOAD_BLOCK_UNDEFINED,
                bat::PAYLOAD_BLOCK_UNMAPPED,
                PAYLOAD_BLOCK_FULLY_PRESENT,
            ] {
                BatEntry::write_bat_entry(&vhdx.aligned, bat_offset, 0, start | first_state)
                    .unwrap();
                for delta in [0, 1 << 20, block_size] {
                    BatEntry::write_bat_entry(
                        &vhdx.aligned,
                        bat_offset,
                        1,
                        (start + delta) | second_state,
                    )
                    .unwrap();
                    let result = open_vhdx(tf.as_path());
                    if delta == 0 {
                        assert!(matches!(
                            result,
                            Err(VhdxError::ReadBatEntry(VhdxBatError::DuplicateFileOffset))
                        ));
                    } else if delta < block_size {
                        assert!(matches!(
                            result,
                            Err(VhdxError::ReadBatEntry(
                                VhdxBatError::OverlappingPayloadBlocks
                            ))
                        ));
                    } else {
                        result.unwrap();
                    }
                }
            }
        }
    }

    #[test]
    fn retained_payload_blocks_must_fit_in_file() {
        let tf = create_dynamic_vhdx(1024, None);
        let vhdx = open_vhdx(tf.as_path()).unwrap();
        let start = vhdx.disk_spec.image_size.div_ceil(1 << 20) * (1 << 20);
        let block_size = vhdx.disk_spec.block_size as u64;
        let bat_offset = vhdx.regions.bat_entry.file_offset;
        vhdx.aligned.file().set_len(start + block_size).unwrap();
        for state in [bat::PAYLOAD_BLOCK_UNDEFINED, bat::PAYLOAD_BLOCK_UNMAPPED] {
            // A retained block must fit even when its start is below EOF.
            for offset in [
                start + (1 << 20),
                start + block_size,
                bat::BAT_FILE_OFF_MASK,
            ] {
                BatEntry::write_bat_entry(&vhdx.aligned, bat_offset, 0, offset | state).unwrap();
                assert!(matches!(
                    open_vhdx(tf.as_path()),
                    Err(VhdxError::ReadBatEntry(VhdxBatError::PayloadPastEnd))
                ));
            }
            // Zero means no retained block. A block ending exactly at EOF fits.
            for offset in [0, start] {
                BatEntry::write_bat_entry(&vhdx.aligned, bat_offset, 0, offset | state).unwrap();
                let reopened = open_vhdx(tf.as_path()).unwrap();
                let mut data = [0xff; 512];
                reopened.read_at(&mut data, 0).unwrap();
                assert_eq!(data, [0; 512]);
            }
        }
    }

    #[test]
    fn allocation_preserves_reserved_offsets() {
        let tf = create_dynamic_vhdx(1024, None);
        let vhdx = open_vhdx(tf.as_path()).unwrap();
        let start = vhdx.disk_spec.image_size.div_ceil(1 << 20) * (1 << 20);
        let bat_offset = vhdx.regions.bat_entry.file_offset;
        for index in [1, 2] {
            BatEntry::write_bat_entry(
                &vhdx.aligned,
                bat_offset,
                index,
                start | bat::PAYLOAD_BLOCK_ZERO,
            )
            .unwrap();
        }
        assert!(matches!(
            open_vhdx(tf.as_path()),
            Err(VhdxError::ReadBatEntry(VhdxBatError::DuplicateFileOffset))
        ));
        BatEntry::write_bat_entry(
            &vhdx.aligned,
            bat_offset,
            2,
            (start + (1 << 20)) | bat::PAYLOAD_BLOCK_ZERO,
        )
        .unwrap();
        BatEntry::write_bat_entry(
            &vhdx.aligned,
            bat_offset,
            3,
            bat::BAT_FILE_OFF_MASK | bat::PAYLOAD_BLOCK_ZERO,
        )
        .unwrap();

        let mut vhdx = open_vhdx(tf.as_path()).unwrap();
        for index in [1, 2, 3] {
            let mut data = [0xff; 512];
            vhdx.read_at(&mut data, index * vhdx.disk_spec.block_size as u64)
                .unwrap();
            assert_eq!(data, [0; 512]);
        }
        vhdx.write_all_at(&[0xa5; 512], 0).unwrap();
        assert_eq!(
            vhdx.bat_entries[0].0 & bat::BAT_FILE_OFF_MASK,
            start + (2 << 20)
        );
        vhdx.flush().unwrap();

        let reopened = open_vhdx(tf.as_path()).unwrap();
        let mut data = [0; 512];
        reopened.read_at(&mut data, 0).unwrap();
        assert_eq!(data, [0xa5; 512]);
    }

    /// A VHDX image with an active log must be rejected until replay is
    /// supported; opening it would silently use a stale BAT.
    #[test]
    fn active_log_is_rejected() {
        let tf = create_dynamic_vhdx(16, None);

        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(tf.as_path())
            .unwrap();
        // VHDX header 1 and 2 live at fixed 64 KiB offsets.
        for base in [VHDX_HEADER_1_OFFSET, VHDX_HEADER_2_OFFSET] {
            edit_header(&file, base, VHDX_HEADER_SIZE, |header| {
                header[VHDX_LOG_GUID_OFFSET..VHDX_LOG_GUID_OFFSET + 16].fill(0x5a);
            });
        }
        file.sync_all().unwrap();

        let err = Vhdx::new(file, false).unwrap_err();
        assert!(matches!(err, VhdxError::UnsupportedLogReplay), "{err}");
    }

    /// An unaligned sector write under a forced O_DIRECT alignment must go
    /// through `AlignedFile`'s read-modify-write bounce (the data block and the
    /// BAT update both land at unaligned host offsets) and read back intact.
    #[test]
    fn unaligned_write_is_rmw() {
        let tf = create_dynamic_vhdx(16, None);

        let mut vhdx = open_vhdx(tf.as_path()).unwrap();

        // Force a non-zero alignment so all of vhdx's positioned I/O exercises
        // the bounce/RMW path even though the tempfile is not really O_DIRECT.
        vhdx.aligned =
            AlignedFile::with_alignment(vhdx.aligned.file().try_clone().unwrap(), Some(512));

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
        let tf = create_dynamic_vhdx(16, None);

        let data = [0xa5u8; 512];
        {
            let mut vhdx = open_vhdx(tf.as_path()).unwrap();
            vhdx.write_all_at(&data, 0).unwrap();
            vhdx.flush().unwrap();
        }

        let vhdx = open_vhdx(tf.as_path()).unwrap();
        let mut readback = [0u8; 512];
        assert_eq!(vhdx.read_at(&mut readback, 0).unwrap(), readback.len());
        assert_eq!(readback, data);
    }

    #[test]
    fn read_misaligned_buffer_is_rejected() {
        let tf = create_dynamic_vhdx(16, None);

        let vhdx = open_vhdx(tf.as_path()).unwrap();

        let mut buf = vec![0u8; vhdx.disk_spec.logical_sector_size as usize - 1];
        let err = vhdx.read_at(&mut buf, 0).unwrap_err();
        assert_eq!(err.kind(), IoErrorKind::InvalidInput);
    }

    #[test]
    fn write_misaligned_buffer_is_rejected() {
        let tf = create_dynamic_vhdx(16, None);

        let mut vhdx = open_vhdx(tf.as_path()).unwrap();

        let buf = vec![0u8; vhdx.disk_spec.logical_sector_size as usize - 1];
        let err = vhdx.write_all_at(&buf, 0).unwrap_err();
        assert_eq!(err.kind(), IoErrorKind::InvalidInput);
    }

    #[test]
    fn payload_block_ending_at_region_boundary_is_accepted() {
        let tf = create_dynamic_vhdx(16, Some(1));

        let mut vhdx = open_vhdx(tf.as_path()).unwrap();
        assert_eq!(vhdx.disk_spec.block_size, 1 << 20);
        let bat_start = vhdx.regions.bat_entry.file_offset;
        vhdx.log_length = 0;
        vhdx.bat_entries[0] = BatEntry(
            PAYLOAD_BLOCK_FULLY_PRESENT | ((bat_start - (1 << 20)) & bat::BAT_FILE_OFF_MASK),
        );

        let mut buf = [0u8; 512];
        let read = vhdx.read_at(&mut buf, (1 << 20) - 512);
        assert!(read.is_ok(), "unexpected read error: {read:?}");
    }

    #[test]
    fn read_write_with_bat_entry_overlapping_log_region_is_rejected() {
        let tf = create_dynamic_vhdx(16, Some(1));

        let mut vhdx = open_vhdx(tf.as_path()).unwrap();
        let (log_offset, _) = vhdx.vhdx_header.log_region();
        vhdx.bat_entries[0] =
            BatEntry(PAYLOAD_BLOCK_FULLY_PRESENT | (log_offset & bat::BAT_FILE_OFF_MASK));

        let mut buf = [0u8; 512];
        let read = vhdx.read_at(&mut buf, 0).unwrap_err();
        assert!(
            read.to_string().contains("BAT entry file offset"),
            "unexpected read error: {read}"
        );
        let write = vhdx.write_all_at(&[0x44u8; 512], 0).unwrap_err();
        assert!(
            write.to_string().contains("BAT entry file offset"),
            "unexpected write error: {write}"
        );
    }

    #[test]
    fn read_write_with_bat_entry_overlapping_bat_region_is_rejected() {
        let tf = create_dynamic_vhdx(16, Some(1));

        let mut vhdx = open_vhdx(tf.as_path()).unwrap();
        let bat_start = vhdx.regions.bat_entry.file_offset;
        assert_eq!(vhdx.disk_spec.block_size, 1 << 20);

        // The 1 MiB payload ends exactly where the metadata region starts, so
        // only the BAT-region check can reject it.
        vhdx.bat_entries[0] =
            BatEntry(PAYLOAD_BLOCK_FULLY_PRESENT | (bat_start & bat::BAT_FILE_OFF_MASK));

        let mut buf = [0u8; 512];
        let read = vhdx.read_at(&mut buf, 0).unwrap_err();
        assert!(
            read.to_string().contains("BAT entry file offset"),
            "unexpected read error: {read}"
        );
        let write = vhdx.write_all_at(&[0x44u8; 512], 0).unwrap_err();
        assert!(
            write.to_string().contains("BAT entry file offset"),
            "unexpected write error: {write}"
        );
    }

    #[test]
    fn open_with_bat_entry_past_eof_is_rejected() {
        // A 32 TiB image makes the BAT span multiple 1 MiB read batches.
        let tf = create_dynamic_vhdx(32 << 20, None);

        let vhdx = open_vhdx(tf.as_path()).unwrap();
        let bat_offset = vhdx.regions.bat_entry.file_offset;
        let entry_offset = bat_offset + (vhdx.bat_entries.len() as u64 - 1) * 8;
        assert!(entry_offset - bat_offset >= 1 << 20);
        let past_eof = ((vhdx.disk_spec.image_size / (1 << 20) + 1) << 20 & bat::BAT_FILE_OFF_MASK)
            | PAYLOAD_BLOCK_FULLY_PRESENT;
        vhdx.aligned
            .file()
            .write_all_at(&past_eof.to_le_bytes(), entry_offset)
            .unwrap();
        drop(vhdx);

        let err = open_vhdx(tf.as_path()).unwrap_err();
        assert!(
            matches!(err, VhdxError::ReadBatEntry(VhdxBatError::PayloadPastEnd)),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn write_with_bat_entry_in_header_area_is_rejected() {
        let tf = create_dynamic_vhdx(16, None);

        let mut vhdx = open_vhdx(tf.as_path()).unwrap();

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
    fn read_with_bat_entry_in_header_area_is_rejected() {
        let tf = create_dynamic_vhdx(16, None);

        let mut vhdx = open_vhdx(tf.as_path()).unwrap();

        // Simulate a corrupt image: BAT entry 0 says "fully present at file
        // offset 0", i.e. on top of the VHDX file header.
        vhdx.bat_entries[0] = BatEntry(PAYLOAD_BLOCK_FULLY_PRESENT);

        let mut buf = vec![0u8; vhdx.disk_spec.logical_sector_size as usize];
        let err = vhdx.read_at(&mut buf, 0).unwrap_err();
        assert!(
            err.to_string().contains("BAT entry file offset"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn write_with_bat_entry_overlapping_metadata_region_is_rejected() {
        let tf = create_dynamic_vhdx(16, None);

        let mut vhdx = open_vhdx(tf.as_path()).unwrap();
        let mdr_offset = vhdx.regions.mdr_entry.file_offset;
        let mut before = [0u8; 8];
        vhdx.aligned
            .file()
            .read_exact_at(&mut before, mdr_offset)
            .unwrap();

        vhdx.bat_entries[0] = BatEntry(PAYLOAD_BLOCK_FULLY_PRESENT | mdr_offset);

        let data = [0x44u8; 512];
        let err = vhdx.write_all_at(&data, 0).unwrap_err();
        assert!(
            err.to_string().contains("BAT entry file offset"),
            "unexpected error: {err}"
        );

        let mut after = [0u8; 8];
        vhdx.aligned
            .file()
            .read_exact_at(&mut after, mdr_offset)
            .unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn read_with_bat_entry_overlapping_metadata_region_is_rejected() {
        let tf = create_dynamic_vhdx(16, None);

        let mut vhdx = open_vhdx(tf.as_path()).unwrap();
        let mdr_offset = vhdx.regions.mdr_entry.file_offset;
        vhdx.bat_entries[0] = BatEntry(PAYLOAD_BLOCK_FULLY_PRESENT | mdr_offset);

        let mut buf = vec![0u8; vhdx.disk_spec.logical_sector_size as usize];
        let err = vhdx.read_at(&mut buf, 0).unwrap_err();
        assert!(
            err.to_string().contains("BAT entry file offset"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn read_misaligned_offset_is_rejected() {
        let tf = create_dynamic_vhdx(16, None);

        let vhdx = open_vhdx(tf.as_path()).unwrap();
        let sector = vhdx.disk_spec.logical_sector_size as usize;

        let mut buf = vec![0u8; sector];
        let err = vhdx.read_at(&mut buf, 100).unwrap_err();
        assert_eq!(err.kind(), IoErrorKind::InvalidInput);
    }

    #[test]
    fn write_misaligned_offset_is_rejected() {
        let tf = create_dynamic_vhdx(16, None);

        let mut vhdx = open_vhdx(tf.as_path()).unwrap();
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
        let tf = create_dynamic_vhdx(16, None);

        let mut vhdx = open_vhdx(tf.as_path()).unwrap();
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
