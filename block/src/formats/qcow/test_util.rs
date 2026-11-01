// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Helpers for constructing and inspecting QCOW2 test images.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::Path;

use vmm_sys_util::tempfile::TempFile;

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
