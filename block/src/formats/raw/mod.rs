// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

//! Raw disk image format.
//!
//! Provides [`RawDisk`], the `DiskFile` wrapper for flat disk images
//! with no metadata or copy on write layer.

use std::fs::File;
use std::io;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::io::AsRawFd;

use log::warn;

use self::worker::async_aio::RawAio;
#[cfg(feature = "io_uring")]
use self::worker::async_uring::RawAsync;
use self::worker::sync::RawSync;
use crate::async_io::{AsyncIo, BorrowedDiskFd, DiskFileError};
use crate::error::{BlockError, BlockErrorKind, BlockResult};
use crate::{DiskTopology, disk_file, probe_sparse_support, query_device_size};

pub(crate) mod worker;

/// Selects which async I/O backend a `RawDisk` uses.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RawBackend {
    /// Blocking I/O where the caller waits for completion.
    Sync,
    /// Modern asynchronous I/O using shared submission and completion
    /// rings for lower overhead operation dispatch and completion handling.
    #[cfg(feature = "io_uring")]
    IoUring,
    /// Legacy asynchronous I/O where requests are handed to the kernel
    /// and completions are collected later.
    Aio,
}

/// Unified DiskFile wrapper for raw disk images.
///
/// Owns the underlying file and delegates async I/O creation to the
/// backend selected at construction time via [`RawBackend`].
#[derive(Debug)]
pub struct RawDisk {
    file: File,
    backend: RawBackend,
}

impl RawDisk {
    pub fn new(file: File, backend: RawBackend) -> Self {
        Self { file, backend }
    }
}

impl disk_file::DiskSize for RawDisk {
    fn logical_size(&self) -> BlockResult<u64> {
        query_device_size(&self.file)
            .map(|(logical_size, _)| logical_size)
            .map_err(|e| BlockError::new(BlockErrorKind::Io, DiskFileError::Size(e)))
    }
}

impl disk_file::PhysicalSize for RawDisk {
    fn physical_size(&self) -> BlockResult<u64> {
        query_device_size(&self.file)
            .map(|(_, physical_size)| physical_size)
            .map_err(|e| BlockError::new(BlockErrorKind::Io, DiskFileError::Size(e)))
    }
}

impl disk_file::DiskFd for RawDisk {
    fn fd(&self) -> BorrowedDiskFd<'_> {
        BorrowedDiskFd::new(self.file.as_raw_fd())
    }
}

impl disk_file::Geometry for RawDisk {
    fn topology(&self) -> DiskTopology {
        DiskTopology::probe(&self.file).unwrap_or_else(|_| {
            warn!("Unable to get device topology. Using default topology");
            DiskTopology::default()
        })
    }
}

impl disk_file::SparseCapable for RawDisk {
    fn supports_sparse_operations(&self) -> bool {
        probe_sparse_support(&self.file)
    }
}

impl disk_file::Resizable for RawDisk {
    fn resize(&mut self, size: u64) -> BlockResult<()> {
        let fd_metadata = self
            .file
            .metadata()
            .map_err(|e| BlockError::new(BlockErrorKind::Io, DiskFileError::ResizeError(e)))?;

        if fd_metadata.file_type().is_block_device() {
            // Block devices cannot be resized via ftruncate; they are resized
            // externally (LVM, losetup, etc.). Verify the size matches.
            let (actual_size, _) = query_device_size(&self.file)
                .map_err(|e| BlockError::new(BlockErrorKind::Io, DiskFileError::ResizeError(e)))?;
            if actual_size != size {
                return Err(BlockError::new(
                    BlockErrorKind::Io,
                    DiskFileError::ResizeError(io::Error::other(format!(
                        "Block device size {actual_size} does not match requested size {size}"
                    ))),
                ));
            }
            Ok(())
        } else {
            self.file
                .set_len(size)
                .map_err(|e| BlockError::new(BlockErrorKind::Io, DiskFileError::ResizeError(e)))
        }
    }
}

impl disk_file::DiskFile for RawDisk {}

impl disk_file::AsyncDiskFile for RawDisk {
    fn try_clone(&self) -> BlockResult<Box<dyn disk_file::AsyncDiskFile>> {
        let file = self
            .file
            .try_clone()
            .map_err(|e| BlockError::new(BlockErrorKind::Io, DiskFileError::Clone(e)))?;
        Ok(Box::new(RawDisk {
            file,
            backend: self.backend,
        }))
    }

    fn create_async_io(&self, ring_depth: u32) -> BlockResult<Box<dyn AsyncIo>> {
        match self.backend {
            RawBackend::Sync => Ok(Box::new(RawSync::new(self.file.as_raw_fd()))),
            #[cfg(feature = "io_uring")]
            RawBackend::IoUring => Ok(Box::new(RawAsync::new(self.file.as_raw_fd(), ring_depth)?)),
            RawBackend::Aio => Ok(Box::new(RawAio::new(self.file.as_raw_fd(), ring_depth)?)),
        }
    }
}

#[cfg(test)]
mod unit_tests {
    use std::fs::File;

    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::async_io::AsyncIo;
    use crate::disk_file::{AsyncDiskFile, DiskSize, PhysicalSize, Resizable};

    const TEST_SIZE: u64 = 0x1122_3344;

    fn make_raw_file() -> File {
        let file: File = TempFile::new().unwrap().into_file();
        file.set_len(TEST_SIZE).unwrap();
        file
    }

    #[test]
    fn new_sync_returns_correct_size() {
        let file = make_raw_file();
        let disk = RawDisk::new(file, RawBackend::Sync);
        assert_eq!(disk.logical_size().unwrap(), TEST_SIZE);
    }

    fn assert_async_io_from_dyn(disk: &dyn AsyncDiskFile, expect_backend: RawBackend) {
        let io: Box<dyn AsyncIo> = disk.create_async_io(128).unwrap();
        assert_eq!(
            io.batch_requests_enabled(),
            expect_backend == RawBackend::IoUring
        );
    }

    fn assert_sync_backend(disk: &RawDisk) {
        assert_eq!(disk.backend, RawBackend::Sync);
        assert_async_io_from_dyn(disk, RawBackend::Sync);
    }

    fn assert_aio_backend(disk: &RawDisk) {
        assert_eq!(disk.backend, RawBackend::Aio);
        assert_async_io_from_dyn(disk, RawBackend::Aio);
    }

    #[cfg(feature = "io_uring")]
    fn assert_io_uring_backend(disk: &RawDisk) {
        assert_eq!(disk.backend, RawBackend::IoUring);
        assert_async_io_from_dyn(disk, RawBackend::IoUring);
    }

    #[test]
    fn sync_backend_disables_batch_requests() {
        let file = make_raw_file();
        let disk = RawDisk::new(file, RawBackend::Sync);
        assert_sync_backend(&disk);
    }

    #[test]
    fn aio_backend_disables_batch_requests() {
        let file = make_raw_file();
        let disk = RawDisk::new(file, RawBackend::Aio);
        assert_aio_backend(&disk);
    }

    #[cfg(feature = "io_uring")]
    #[test]
    fn io_uring_backend_enables_batch_requests() {
        let file = make_raw_file();
        let disk = RawDisk::new(file, RawBackend::IoUring);
        assert_io_uring_backend(&disk);
    }

    fn assert_try_clone(disk: &RawDisk, expect_backend: RawBackend) {
        let cloned = disk.try_clone().unwrap();
        assert_async_io_from_dyn(cloned.as_ref(), expect_backend);
    }

    #[test]
    fn try_clone_preserves_sync_backend() {
        let file = make_raw_file();
        let disk = RawDisk::new(file, RawBackend::Sync);
        assert_try_clone(&disk, RawBackend::Sync);
    }

    #[test]
    fn try_clone_preserves_aio_backend() {
        let file = make_raw_file();
        let disk = RawDisk::new(file, RawBackend::Aio);
        assert_try_clone(&disk, RawBackend::Aio);
    }

    #[cfg(feature = "io_uring")]
    #[test]
    fn try_clone_preserves_io_uring_backend() {
        let file = make_raw_file();
        let disk = RawDisk::new(file, RawBackend::IoUring);
        assert_try_clone(&disk, RawBackend::IoUring);
    }

    #[test]
    fn resize_changes_file_size() {
        let file = make_raw_file();
        let mut disk = RawDisk::new(file, RawBackend::Aio);
        let new_size = TEST_SIZE * 2;
        disk.resize(new_size).unwrap();
        assert_eq!(disk.logical_size().unwrap(), new_size);
    }

    #[test]
    fn physical_size_reports_allocated_blocks() {
        let file = make_raw_file();
        let disk = RawDisk::new(file, RawBackend::Aio);
        // Sparse file: physical size is less than logical size.
        assert!(disk.physical_size().unwrap() < disk.logical_size().unwrap());
    }
}
