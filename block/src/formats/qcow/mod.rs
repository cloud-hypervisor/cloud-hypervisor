// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! QCOW2 disk image format.
//!
//! Provides [`QcowDisk`], the `DiskFile` wrapper for QCOW2 images
//! with backing file and compression support.

mod backing;
mod common;
mod decoder;
mod engine_sync;
#[cfg(feature = "io_uring")]
mod engine_uring;
mod header;
mod metadata;
mod parser;
mod qcow_raw_file;
mod refcount;
mod util;
mod vec_cache;

use std::fs::File;
use std::os::unix::io::AsRawFd;
#[cfg(any(test, feature = "test-utils"))]
use std::path::Path;
use std::sync::Arc;
use std::{fmt, io};

pub use parser::{
    BackingFileConfig, CompressionType, Error, ImageType, IncompatFeatures, MissingFeatureError,
    QcowHeader,
};
#[cfg(any(test, feature = "test-utils"))]
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};
#[cfg(any(test, feature = "test-utils"))]
use vmm_sys_util::tempfile::TempFile;

use self::backing::shared_backing_from;
use self::engine_sync::QcowSync;
#[cfg(feature = "io_uring")]
use self::engine_uring::QcowAsync;
use self::metadata::{BackingRead, QcowMetadata};
use self::parser::{MAX_NESTING_DEPTH, parse_qcow};
use self::qcow_raw_file::QcowRawFile;
use crate::aligned_file::AlignedFile;
#[cfg(any(test, feature = "test-utils"))]
use crate::async_io::GuestMemoryTarget;
use crate::async_io::{AsyncIo, BorrowedDiskFd, DiskFileError};
use crate::disk_file;
#[cfg(any(test, feature = "test-utils"))]
use crate::disk_file::AsyncDiskFile;
use crate::error::{BlockError, BlockErrorKind, BlockResult, ErrorOp};

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
        let raw_file = AlignedFile::new(file, direct_io);
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

    /// Synchronous write convenience for tests and benchmarks.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn write_all_at(&self, offset: u64, data: &[u8]) {
        let mut async_io = self.create_async_io(1).unwrap();
        let mem =
            Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), data.len())]).unwrap());
        mem.write_slice(data, GuestAddress(0)).unwrap();
        let range = [(GuestAddress(0), data.len() as u32)];
        let target = GuestMemoryTarget::new(Arc::clone(&mem), &range).unwrap();
        async_io
            .write_from_memory(offset as libc::off_t, target, 0)
            .unwrap();
        while async_io.next_completed_request().is_some() {}
    }

    /// Synchronous read convenience for tests and benchmarks.
    #[cfg(test)]
    pub fn read_all_at(&self, offset: u64, len: usize) -> Vec<u8> {
        let mut async_io = self.create_async_io(1).unwrap();
        let mem = Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), len)]).unwrap());
        let range = [(GuestAddress(0), len as u32)];
        let target = GuestMemoryTarget::new(Arc::clone(&mem), &range).unwrap();
        async_io
            .read_to_memory(offset as libc::off_t, target, 0)
            .unwrap();
        while async_io.next_completed_request().is_some() {}
        let mut buf = vec![0u8; len];
        mem.read_slice(&mut buf, GuestAddress(0)).unwrap();
        buf
    }

    #[cfg(test)]
    fn metadata(&self) -> &QcowMetadata {
        &self.metadata
    }
}

/// Writes a fresh qcow2 layout into `file`
#[cfg(any(test, feature = "test-utils"))]
pub(crate) fn create_image(
    file: &File,
    virtual_size: u64,
    backing_config: Option<&BackingFileConfig>,
) -> BlockResult<()> {
    let path = backing_config.map(|cfg| cfg.path.as_str());
    let mut header = QcowHeader::create_for_size_and_path(3, virtual_size, path)
        .map_err(|e| BlockError::new(BlockErrorKind::Io, e))?;
    if let Some(cfg) = backing_config
        && let Some(backing_file) = &mut header.backing_file
    {
        backing_file.format = cfg.format;
    }
    let raw = AlignedFile::new(
        file.try_clone()
            .map_err(|e| BlockError::new(BlockErrorKind::Io, DiskFileError::Clone(e)))?,
        false,
    );
    header
        .write_to(&raw)
        .map_err(|e| BlockError::new(BlockErrorKind::Io, e))?;
    let (inner, _backing, _sparse) = parse_qcow(raw, MAX_NESTING_DEPTH, true)?;
    // Flush dirty caches and clear the dirty bit
    QcowMetadata::new(inner).shutdown();
    Ok(())
}

/// Helper struct to create a new qcow2 image in a temporary file.
#[cfg(any(test, feature = "test-utils"))]
pub struct QcowTempDisk {
    tmp: TempFile,
    disk: QcowDisk,
}

#[cfg(any(test, feature = "test-utils"))]
impl QcowTempDisk {
    /// Creates a new qcow2 image in a temporary file with optional
    /// backing file. Flags are passed to QcowDisk::new.
    pub fn new(
        virtual_size: u64,
        backing_config: Option<&BackingFileConfig>,
        direct_io: bool,
        sparse: bool,
        use_io_uring: bool,
    ) -> BlockResult<Self> {
        let tmp = TempFile::new().map_err(io::Error::from)?;
        create_image(tmp.as_file(), virtual_size, backing_config)?;
        let file = tmp
            .as_file()
            .try_clone()
            .map_err(|e| BlockError::new(BlockErrorKind::Io, DiskFileError::Clone(e)))?;
        let disk = QcowDisk::new(
            file,
            direct_io,
            backing_config.is_some(),
            sparse,
            use_io_uring,
        )?;
        Ok(Self { tmp, disk })
    }

    pub fn path(&self) -> &Path {
        self.tmp.as_path()
    }

    pub fn as_file(&self) -> &File {
        self.tmp.as_file()
    }

    pub fn disk(&self) -> &QcowDisk {
        &self.disk
    }

    /// Drops the disk handle and returns the underlying TempFile.
    pub fn into_tempfile(self) -> TempFile {
        self.tmp
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
    use super::*;
    use crate::async_io::AsyncIo;
    use crate::disk_file::{AsyncDiskFile, DiskSize, PhysicalSize};

    const TEST_SIZE: u64 = 0x5566_7788;

    fn make_qcow_file() -> File {
        QcowTempDisk::new(TEST_SIZE, None, false, true, false)
            .unwrap()
            .into_tempfile()
            .into_file()
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
