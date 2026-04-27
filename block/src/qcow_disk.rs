// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::{fmt, io};

use crate::async_io::{AsyncIo, BorrowedDiskFd, DiskFileError};
use crate::disk_file;
use crate::error::{BlockError, BlockErrorKind, BlockResult, ErrorOp};
use crate::qcow::backing::shared_backing_from;
use crate::qcow::metadata::{BackingRead, QcowMetadata};
use crate::qcow::qcow_raw_file::QcowRawFile;
use crate::qcow::{MAX_NESTING_DEPTH, RawFile, parse_qcow};
#[cfg(feature = "io_uring")]
use crate::qcow_async::QcowAsync;
use crate::qcow_sync::QcowSync;

/// Unified DiskFile wrapper for QCOW2 disk images.
///
/// Holds the in memory QCOW2 metadata, the data file, and an optional
/// backing file. The metadata is wrapped in an `Arc` because
/// [`QcowSync`] and [`QcowAsync`] I/O workers receive a clone when
/// they are created via [`create_async_io`](DiskFile::create_async_io).
/// The backing file is likewise shared with workers through an `Arc`.
///
/// The `sparse` flag controls whether the image advertises discard
/// support to the guest. The `use_io_uring` flag selects between the
/// [`QcowSync`] and [`QcowAsync`] I/O backends. Both are recorded at
/// construction time and propagated through [`try_clone`](DiskFile::try_clone).
pub struct QcowDisk {
    metadata: Arc<QcowMetadata>,
    backing_file: Option<Arc<dyn BackingRead>>,
    sparse: bool,
    data_raw_file: QcowRawFile,
    use_io_uring: bool,
}

impl fmt::Debug for QcowDisk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QcowDisk")
            .field("sparse", &self.sparse)
            .field("has_backing", &self.backing_file.is_some())
            .field("use_io_uring", &self.use_io_uring)
            .finish_non_exhaustive()
    }
}

impl QcowDisk {
    pub fn new(
        file: File,
        direct_io: bool,
        backing_files: bool,
        sparse: bool,
        use_io_uring: bool,
    ) -> BlockResult<Self> {
        #[cfg(not(feature = "io_uring"))]
        if use_io_uring {
            return Err(BlockError::new(
                BlockErrorKind::UnsupportedFeature,
                DiskFileError::NewAsyncIo(io::Error::other(
                    "io_uring requested but feature is not enabled",
                )),
            ));
        }

        let max_nesting_depth = if backing_files { MAX_NESTING_DEPTH } else { 0 };
        let raw_file = RawFile::new(file, direct_io);
        let (inner, backing_file, sparse) = parse_qcow(raw_file, max_nesting_depth, sparse)
            .map_err(|e| {
                let e = if !backing_files && matches!(e.kind(), BlockErrorKind::Overflow) {
                    e.with_kind(BlockErrorKind::UnsupportedFeature)
                } else {
                    e
                };
                e.with_op(ErrorOp::Open)
            })?;
        let data_raw_file = inner.raw_file.clone();
        Ok(QcowDisk {
            metadata: Arc::new(QcowMetadata::new(inner)),
            backing_file: backing_file.map(shared_backing_from).transpose()?,
            sparse,
            data_raw_file,
            use_io_uring,
        })
    }
}

impl Drop for QcowDisk {
    fn drop(&mut self) {
        self.metadata.shutdown();
    }
}

impl disk_file::DiskSize for QcowDisk {
    fn logical_size(&self) -> BlockResult<u64> {
        Ok(self.metadata.virtual_size())
    }
}

impl disk_file::PhysicalSize for QcowDisk {
    fn physical_size(&self) -> BlockResult<u64> {
        Ok(self.data_raw_file.physical_size()?)
    }
}

impl disk_file::DiskFd for QcowDisk {
    fn fd(&self) -> BorrowedDiskFd<'_> {
        BorrowedDiskFd::new(self.data_raw_file.as_raw_fd())
    }
}

impl disk_file::Geometry for QcowDisk {}

impl disk_file::SparseCapable for QcowDisk {
    fn supports_sparse_operations(&self) -> bool {
        true
    }

    fn supports_zero_flag(&self) -> bool {
        true
    }
}

impl disk_file::Resizable for QcowDisk {
    fn resize(&mut self, size: u64) -> BlockResult<()> {
        if self.backing_file.is_some() {
            return Err(BlockError::new(
                BlockErrorKind::UnsupportedFeature,
                DiskFileError::ResizeError(io::Error::other(
                    "resize not supported with backing files",
                )),
            )
            .with_op(ErrorOp::Resize));
        }
        self.metadata.resize(size).map_err(|e| {
            BlockError::new(BlockErrorKind::Io, DiskFileError::ResizeError(e))
                .with_op(ErrorOp::Resize)
        })
    }
}

impl disk_file::DiskFile for QcowDisk {}

impl disk_file::AsyncDiskFile for QcowDisk {
    fn try_clone(&self) -> BlockResult<Box<dyn disk_file::AsyncDiskFile>> {
        Ok(Box::new(QcowDisk {
            metadata: Arc::clone(&self.metadata),
            backing_file: self.backing_file.as_ref().map(Arc::clone),
            sparse: self.sparse,
            data_raw_file: self.data_raw_file.clone(),
            use_io_uring: self.use_io_uring,
        }))
    }

    fn create_async_io(&self, ring_depth: u32) -> BlockResult<Box<dyn AsyncIo>> {
        if self.use_io_uring {
            #[cfg(feature = "io_uring")]
            {
                return Ok(Box::new(
                    QcowAsync::new(
                        Arc::clone(&self.metadata),
                        self.data_raw_file.clone(),
                        self.backing_file.as_ref().map(Arc::clone),
                        self.sparse,
                        ring_depth,
                    )
                    .map_err(|e| {
                        BlockError::new(BlockErrorKind::Io, DiskFileError::NewAsyncIo(e))
                    })?,
                ));
            }

            #[cfg(not(feature = "io_uring"))]
            unreachable!("use_io_uring is set but io_uring feature is not enabled");
        }

        let _ = ring_depth;
        Ok(Box::new(QcowSync::new(
            Arc::clone(&self.metadata),
            self.data_raw_file.clone(),
            self.backing_file.as_ref().map(Arc::clone),
            self.sparse,
        )))
    }
}

#[cfg(test)]
mod unit_tests {
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::async_io::AsyncIo;
    use crate::disk_file::{AsyncDiskFile, DiskSize, PhysicalSize};
    use crate::qcow::{QcowFile, RawFile};

    const TEST_SIZE: u64 = 0x5566_7788;

    fn make_qcow_file() -> File {
        let temp_file = TempFile::new().unwrap();
        {
            let raw = RawFile::new(temp_file.as_file().try_clone().unwrap(), false);
            QcowFile::new(raw, 3, TEST_SIZE, true).unwrap();
        }
        temp_file.into_file()
    }

    #[test]
    fn new_sync_returns_correct_size() {
        let file = make_qcow_file();
        let disk = QcowDisk::new(file, false, false, true, false).unwrap();
        assert_eq!(disk.logical_size().unwrap(), TEST_SIZE);
    }

    fn assert_async_io_from_dyn(disk: &dyn AsyncDiskFile, expect_batch: bool) {
        let io: Box<dyn AsyncIo> = disk.create_async_io(128).unwrap();
        assert_eq!(io.batch_requests_enabled(), expect_batch);
    }

    fn assert_async_io(disk: &QcowDisk, expect_batch: bool) {
        assert_async_io_from_dyn(disk, expect_batch);
    }

    #[test]
    fn sync_backend_disables_batch_requests() {
        let file = make_qcow_file();
        let disk = QcowDisk::new(file, false, false, true, false).unwrap();
        assert_async_io(&disk, false);
    }

    #[cfg(feature = "io_uring")]
    #[test]
    fn io_uring_backend_enables_batch_requests() {
        let file = make_qcow_file();
        let disk = QcowDisk::new(file, false, false, true, true).unwrap();
        assert_async_io(&disk, true);
    }

    #[test]
    fn try_clone_preserves_sync_dispatch() {
        let file = make_qcow_file();
        let disk = QcowDisk::new(file, false, false, true, false).unwrap();
        let cloned = disk.try_clone().unwrap();
        assert_async_io_from_dyn(cloned.as_ref(), false);
    }

    #[cfg(feature = "io_uring")]
    #[test]
    fn try_clone_preserves_io_uring_dispatch() {
        let file = make_qcow_file();
        let disk = QcowDisk::new(file, false, false, true, true).unwrap();
        let cloned = disk.try_clone().unwrap();
        assert_async_io_from_dyn(cloned.as_ref(), true);
    }

    #[test]
    fn physical_size_less_than_logical() {
        // make_qcow_file() writes no guest data, so the file on disk
        // only contains QCOW2 headers and metadata tables.
        let file = make_qcow_file();
        let disk = QcowDisk::new(file, false, false, true, false).unwrap();
        assert!(disk.physical_size().unwrap() < disk.logical_size().unwrap());
    }
}
