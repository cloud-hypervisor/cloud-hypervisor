// Copyright © 2021 Intel Corporation
//
// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

//! QCOW2 async disk backend.

use std::fmt;
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd};
use std::sync::Arc;

use crate::async_io::BorrowedDiskFd;
use crate::disk_file;
use crate::error::{BlockErrorKind, BlockResult, ErrorOp};
use crate::qcow::backing::shared_backing_from;
use crate::qcow::metadata::{BackingRead, QcowMetadata};
use crate::qcow::qcow_raw_file::QcowRawFile;
use crate::qcow::{MAX_NESTING_DEPTH, RawFile, parse_qcow};

/// Device level handle for a QCOW2 image.
///
/// Owns the parsed metadata and backing file chain. One instance is
/// created per disk and shared across virtio queues.
pub struct QcowDiskAsync {
    metadata: Arc<QcowMetadata>,
    backing_file: Option<Arc<dyn BackingRead>>,
    sparse: bool,
    data_raw_file: QcowRawFile,
}

impl fmt::Debug for QcowDiskAsync {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QcowDiskAsync")
            .field("sparse", &self.sparse)
            .field("has_backing", &self.backing_file.is_some())
            .finish_non_exhaustive()
    }
}

impl QcowDiskAsync {
    pub fn new(
        file: File,
        direct_io: bool,
        backing_files: bool,
        sparse: bool,
    ) -> BlockResult<Self> {
        let max_nesting_depth = if backing_files { MAX_NESTING_DEPTH } else { 0 };
        let (inner, backing_file, sparse) =
            parse_qcow(RawFile::new(file, direct_io), max_nesting_depth, sparse).map_err(|e| {
                let e = if !backing_files && matches!(e.kind(), BlockErrorKind::Overflow) {
                    e.with_kind(BlockErrorKind::UnsupportedFeature)
                } else {
                    e
                };
                e.with_op(ErrorOp::Open)
            })?;
        let data_raw_file = inner.raw_file.clone();
        Ok(QcowDiskAsync {
            metadata: Arc::new(QcowMetadata::new(inner)),
            backing_file: backing_file.map(shared_backing_from).transpose()?,
            sparse,
            data_raw_file,
        })
    }
}

impl Drop for QcowDiskAsync {
    fn drop(&mut self) {
        self.metadata.shutdown();
    }
}

impl disk_file::DiskSize for QcowDiskAsync {
    fn logical_size(&self) -> BlockResult<u64> {
        Ok(self.metadata.virtual_size())
    }
}

impl disk_file::PhysicalSize for QcowDiskAsync {
    fn physical_size(&self) -> BlockResult<u64> {
        Ok(self.data_raw_file.physical_size()?)
    }
}

impl disk_file::DiskFd for QcowDiskAsync {
    fn fd(&self) -> BorrowedDiskFd<'_> {
        BorrowedDiskFd::new(self.data_raw_file.as_fd().as_raw_fd())
    }
}
