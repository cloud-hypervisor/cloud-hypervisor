// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::btree_map::BTreeMap;
use std::fs::File;
use std::io::{Error as IoError, ErrorKind as IoErrorKind, Result as IoResult, Write};
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
        io::read(
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

        io::write(
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

        Ok(())
    }

    pub fn flush(&mut self) -> IoResult<()> {
        self.aligned.file_mut().flush()
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
}
