// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Helpers for constructing and inspecting QCOW2 test images.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::ops::Range;
use std::os::unix::fs::FileExt;
use std::path::Path;

use flate2::Compression;
use flate2::write::DeflateEncoder;
use vmm_sys_util::tempfile::TempFile;

use super::qcow_raw_file::QcowRawFile;
use super::util::{
    CLUSTER_USED_FLAG, COMPRESSED_FLAG, COMPRESSED_SECTOR_SIZE, L1_TABLE_OFFSET_MASK,
};
use super::{QcowDisk, QcowHeader, QcowTempDisk};
use crate::aligned_file::AlignedFile;
use crate::error::BlockResult;

#[derive(Clone, Copy)]
pub(super) struct DiskOptions {
    pub(super) read_only: bool,
    pub(super) direct_io: bool,
    pub(super) backing_files: bool,
    pub(super) sparse: bool,
    pub(super) use_io_uring: bool,
}

impl Default for DiskOptions {
    fn default() -> Self {
        Self {
            read_only: false,
            direct_io: false,
            backing_files: false,
            sparse: true,
            use_io_uring: false,
        }
    }
}

/// Owns the file independently of any open disk or cached metadata.
pub(super) struct TestImage {
    temp: TempFile,
}

impl TestImage {
    pub(super) fn new(virtual_size: u64) -> Self {
        Self {
            temp: QcowTempDisk::new(virtual_size, None, false, true, false)
                .unwrap()
                .into_tempfile(),
        }
    }

    /// Writes the bytes without parsing or rebuilding the image.
    pub(super) fn from_bytes(header: &[u8], file_len: u64) -> Self {
        let temp = TempFile::new().unwrap();
        temp.as_file().write_all_at(header, 0).unwrap();
        temp.as_file().set_len(file_len).unwrap();
        Self { temp }
    }

    pub(super) fn from_header(header: &QcowHeader) -> Self {
        let image = Self {
            temp: TempFile::new().unwrap(),
        };
        header.write_to(&image.aligned_file()).unwrap();
        image
    }

    pub(super) fn as_file(&self) -> &File {
        self.temp.as_file()
    }

    pub(super) fn as_path(&self) -> &Path {
        self.temp.as_path()
    }

    pub(super) fn aligned_file(&self) -> AlignedFile {
        AlignedFile::new(self.as_file().try_clone().unwrap(), false)
    }

    pub(super) fn qcow_raw(&self, cluster_size: u64, refcount_bits: u64) -> QcowRawFile {
        QcowRawFile::from(self.aligned_file(), cluster_size, refcount_bits).unwrap()
    }

    pub(super) fn open(&self) -> BlockResult<QcowDisk> {
        self.open_with(DiskOptions::default())
    }

    pub(super) fn open_with(&self, options: DiskOptions) -> BlockResult<QcowDisk> {
        let file = if options.read_only {
            OpenOptions::new().read(true).open(self.as_path()).unwrap()
        } else {
            self.as_file().try_clone().unwrap()
        };
        QcowDisk::new(
            file,
            options.direct_io,
            options.backing_files,
            options.sparse,
            options.use_io_uring,
        )
    }

    pub(super) fn write_header_u32(&self, field: usize, value: u32) {
        self.as_file()
            .write_all_at(&value.to_be_bytes(), field as u64)
            .unwrap();
    }

    pub(super) fn write_header_u64(&self, field: usize, value: u64) {
        write_u64_at(self.as_file(), field as u64, value);
    }

    pub(super) fn snapshot(&self) -> FileSnapshot {
        self.snapshot_range(0..self.as_file().metadata().unwrap().len())
    }

    pub(super) fn snapshot_range(&self, range: Range<u64>) -> FileSnapshot {
        let mut bytes = vec![0; usize::try_from(range.end - range.start).unwrap()];
        self.as_file()
            .read_exact_at(&mut bytes, range.start)
            .unwrap();
        FileSnapshot {
            file_len: self.as_file().metadata().unwrap().len(),
            offset: range.start,
            bytes,
        }
    }
}

pub(super) mod header_field {
    pub(crate) const CLUSTER_BITS: usize = 20;
    pub(crate) const SIZE: usize = 24;
    pub(crate) const CRYPT_METHOD: usize = 32;
    pub(crate) const L1_SIZE: usize = 36;
    pub(crate) const L1_TABLE_OFFSET: usize = 40;
    pub(crate) const REFCOUNT_TABLE_OFFSET: usize = 48;
    pub(crate) const REFCOUNT_TABLE_CLUSTERS: usize = 56;
    pub(crate) const NB_SNAPSHOTS: usize = 60;
    pub(crate) const INCOMPATIBLE_FEATURES: usize = 72;
    pub(crate) const AUTOCLEAR_FEATURES: usize = 88;
    pub(crate) const REFCOUNT_ORDER: usize = 96;
    pub(crate) const HEADER_LENGTH: usize = 100;
}

pub(super) fn patch_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

pub(super) fn patch_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}

pub(super) fn read_u64_at(file: &File, offset: u64) -> u64 {
    let mut bytes = [0; 8];
    file.read_exact_at(&mut bytes, offset).unwrap();
    u64::from_be_bytes(bytes)
}

pub(super) fn write_u64_at(file: &File, offset: u64, value: u64) {
    file.write_all_at(&value.to_be_bytes(), offset).unwrap();
}

pub(super) fn compressed_l2_entry(
    host_offset: u64,
    compressed_len: usize,
    cluster_bits: u32,
) -> u64 {
    let compressed_size_shift = 62 - (cluster_bits - 8);
    let intra_sector_offset = host_offset & (COMPRESSED_SECTOR_SIZE - 1);
    let total_bytes = compressed_len as u64 + intra_sector_offset;
    let nsectors = total_bytes.div_ceil(COMPRESSED_SECTOR_SIZE);
    let addr_part = host_offset & ((1 << compressed_size_shift) - 1);
    let size_part = (nsectors - 1) << compressed_size_shift;
    COMPRESSED_FLAG | size_part | addr_part
}

/// Compress every allocated cluster in a QCOW2 image file in place.
pub(super) fn compress_allocated_clusters(file: &mut File) {
    let mut buf4 = [0u8; 4];
    file.read_exact_at(&mut buf4, header_field::CLUSTER_BITS as u64)
        .unwrap();
    let cluster_bits = u32::from_be_bytes(buf4);
    let cluster_size = 1u64 << cluster_bits;

    file.read_exact_at(&mut buf4, header_field::L1_SIZE as u64)
        .unwrap();
    let l1_size = u32::from_be_bytes(buf4);

    let mut buf8 = [0u8; 8];
    file.read_exact_at(&mut buf8, header_field::L1_TABLE_OFFSET as u64)
        .unwrap();
    let l1_table_offset = u64::from_be_bytes(buf8);

    let entries_per_l2 = cluster_size / 8;

    let mut append_offset = file.metadata().unwrap().len();
    append_offset = (append_offset + 511) & !511;

    for l1_idx in 0..l1_size as u64 {
        let l1_entry_offset = l1_table_offset + l1_idx * 8;
        file.read_exact_at(&mut buf8, l1_entry_offset).unwrap();
        let l1_entry = u64::from_be_bytes(buf8);

        let l2_table_addr = l1_entry & L1_TABLE_OFFSET_MASK;
        if l2_table_addr == 0 {
            continue;
        }

        for l2_idx in 0..entries_per_l2 {
            let l2_entry_offset = l2_table_addr + l2_idx * 8;
            file.read_exact_at(&mut buf8, l2_entry_offset).unwrap();
            let l2_entry = u64::from_be_bytes(buf8);

            if l2_entry & CLUSTER_USED_FLAG == 0 || l2_entry & COMPRESSED_FLAG != 0 {
                continue;
            }

            let host_cluster_addr = l2_entry & L1_TABLE_OFFSET_MASK;
            if host_cluster_addr == 0 {
                continue;
            }

            let mut cluster_data = vec![0u8; cluster_size as usize];
            file.read_exact_at(&mut cluster_data, host_cluster_addr)
                .unwrap();

            let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(&cluster_data).unwrap();
            let compressed = encoder.finish().unwrap();

            file.write_all_at(&compressed, append_offset).unwrap();

            let padded_len = (compressed.len() + 511) & !511;
            if padded_len > compressed.len() {
                let padding = vec![0u8; padded_len - compressed.len()];
                file.write_all_at(&padding, append_offset + compressed.len() as u64)
                    .unwrap();
            }

            let new_entry = compressed_l2_entry(append_offset, compressed.len(), cluster_bits);
            file.write_all_at(&new_entry.to_be_bytes(), l2_entry_offset)
                .unwrap();

            append_offset += padded_len as u64;
        }
    }

    file.flush().unwrap();
}

pub(super) struct FileSnapshot {
    file_len: u64,
    offset: u64,
    bytes: Vec<u8>,
}

impl FileSnapshot {
    #[track_caller]
    pub(super) fn assert_unchanged(&self, image: &TestImage) {
        assert_eq!(
            image.as_file().metadata().unwrap().len(),
            self.file_len,
            "Image size changed"
        );
        let mut bytes = vec![0; self.bytes.len()];
        image
            .as_file()
            .read_exact_at(&mut bytes, self.offset)
            .unwrap();
        assert_eq!(
            bytes, self.bytes,
            "Image contents changed at offset {:#x}",
            self.offset
        );
    }
}
