// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::btree_map::BTreeMap;
use std::fs::File;
use std::io::{
    Error as IoError, ErrorKind as IoErrorKind, Read, Result as IoResult, Seek, SeekFrom, Write,
};
use std::os::fd::{AsRawFd, RawFd};
use std::result;

use remain::sorted;
use thiserror::Error;

use super::bat::{BatEntry, VhdxBatError};
use super::header::{self, RegionInfo, RegionTableEntry, VhdxHeader, VhdxHeaderError};
use super::io::{self, VhdxIoError};
use super::metadata::{DiskSpec, VhdxMetadataError};
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

#[derive(Debug)]
pub struct Vhdx {
    aligned: AlignedFile,
    vhdx_header: VhdxHeader,
    region_entries: BTreeMap<u64, u64>,
    bat_entry: RegionTableEntry,
    mdr_entry: RegionTableEntry,
    disk_spec: DiskSpec,
    bat_entries: Vec<BatEntry>,
    current_offset: u64,
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
            current_offset: 0,
            first_write: true,
        })
    }

    pub fn virtual_disk_size(&self) -> u64 {
        self.disk_spec.virtual_disk_size
    }
}

impl Read for Vhdx {
    /// Wrapper function to satisfy Read trait implementation for VHDx disk.
    /// Convert the offset to sector index and buffer length to sector count.
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        let sector_count = (buf.len() as u64).div_ceil(self.disk_spec.logical_sector_size as u64);
        let sector_index = self.current_offset / self.disk_spec.logical_sector_size as u64;

        let result = io::read(
            &self.aligned,
            buf,
            &self.disk_spec,
            &self.bat_entries,
            sector_index,
            sector_count,
        )
        .map_err(|e| {
            IoError::other(format!(
                "Failed reading {sector_count} sectors from VHDx at index {sector_index}: {e}"
            ))
        })?;

        self.current_offset = self.current_offset.checked_add(result as u64).unwrap();

        Ok(result)
    }
}

impl Write for Vhdx {
    fn flush(&mut self) -> IoResult<()> {
        self.aligned.file_mut().flush()
    }

    /// Wrapper function to satisfy Write trait implementation for VHDx disk.
    /// Convert the offset to sector index and buffer length to sector count.
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        let sector_count = (buf.len() as u64).div_ceil(self.disk_spec.logical_sector_size as u64);
        let sector_index = self.current_offset / self.disk_spec.logical_sector_size as u64;

        if self.first_write {
            self.first_write = false;
            self.vhdx_header
                .update(&self.aligned)
                .map_err(|e| IoError::other(format!("Failed to update VHDx header: {e}")))?;
        }

        let result = io::write(
            &self.aligned,
            buf,
            &mut self.disk_spec,
            self.bat_entry.file_offset,
            &mut self.bat_entries,
            sector_index,
            sector_count,
        )
        .map_err(|e| {
            IoError::other(format!(
                "Failed writing {sector_count} sectors on VHDx at index {sector_index}: {e}"
            ))
        })?;

        self.current_offset = self.current_offset.checked_add(result as u64).unwrap();

        Ok(result)
    }
}

impl Seek for Vhdx {
    /// Wrapper function to satisfy Seek trait implementation for VHDx disk.
    /// Updates the offset field in the Vhdx struct.
    fn seek(&mut self, pos: SeekFrom) -> IoResult<u64> {
        let new_offset: Option<u64> = match pos {
            SeekFrom::Start(off) => Some(off),
            SeekFrom::End(off) => {
                if off < 0 {
                    0i64.checked_sub(off).and_then(|increment| {
                        self.virtual_disk_size().checked_sub(increment as u64)
                    })
                } else {
                    self.virtual_disk_size().checked_add(off as u64)
                }
            }
            SeekFrom::Current(off) => {
                if off < 0 {
                    0i64.checked_sub(off)
                        .and_then(|increment| self.current_offset.checked_sub(increment as u64))
                } else {
                    self.current_offset.checked_add(off as u64)
                }
            }
        };

        if let Some(o) = new_offset
            && o <= self.virtual_disk_size()
        {
            self.current_offset = o;
            return Ok(o);
        }

        Err(IoError::new(
            IoErrorKind::InvalidData,
            "Failed seek operation",
        ))
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

impl Clone for Vhdx {
    fn clone(&self) -> Self {
        Vhdx {
            aligned: self.aligned.try_clone().unwrap(),
            vhdx_header: self.vhdx_header.clone(),
            region_entries: self.region_entries.clone(),
            bat_entry: self.bat_entry,
            mdr_entry: self.mdr_entry,
            disk_spec: self.disk_spec.clone(),
            bat_entries: self.bat_entries.clone(),
            current_offset: self.current_offset,
            first_write: self.first_write,
        }
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

    use super::*;
    use crate::formats::vhdx::test_util::create_dynamic_vhdx;

    /// An unaligned sector write under a forced O_DIRECT alignment must go
    /// through `AlignedFile`'s read-modify-write bounce (the data block and the
    /// BAT update both land at unaligned host offsets) and read back intact.
    #[test]
    fn unaligned_write_is_rmw() {
        let Some(tf) = create_dynamic_vhdx(16) else {
            eprintln!("skipping unaligned_write_is_rmw: qemu-img unavailable");
            return;
        };

        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(tf.as_path())
            .unwrap();
        let mut vhdx = Vhdx::new(file, false).unwrap();

        // Force a non-zero alignment so all of vhdx's positioned I/O exercises
        // the bounce/RMW path even though the tempfile is not really O_DIRECT.
        vhdx.aligned = AlignedFile::with_alignment(vhdx.aligned.file().try_clone().unwrap(), 512);

        let sector = vhdx.disk_spec.logical_sector_size as usize;
        let data: Vec<u8> = (0..sector).map(|i| ((i + 1) % 251) as u8).collect();

        // Write at virtual offset 0 (allocates a new data block + rewrites BAT).
        vhdx.seek(SeekFrom::Start(0)).unwrap();
        assert_eq!(vhdx.write(&data).unwrap(), data.len());
        vhdx.flush().unwrap();

        // Read it back through a fresh, forced-alignment handle.
        let mut readback = vec![0u8; sector];
        vhdx.seek(SeekFrom::Start(0)).unwrap();
        assert_eq!(vhdx.read(&mut readback).unwrap(), readback.len());
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
            let file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(tf.as_path())
                .unwrap();
            let mut vhdx = Vhdx::new(file, false).unwrap();
            vhdx.seek(SeekFrom::Start(0)).unwrap();
            assert_eq!(vhdx.write(&data).unwrap(), data.len());
            vhdx.flush().unwrap();
        }

        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(tf.as_path())
            .unwrap();
        let mut vhdx = Vhdx::new(file, false).unwrap();
        let mut readback = [0u8; 512];
        vhdx.seek(SeekFrom::Start(0)).unwrap();
        assert_eq!(vhdx.read(&mut readback).unwrap(), readback.len());
        assert_eq!(readback, data);
    }
}
