// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::fs::File;
use std::os::unix::io::AsRawFd;

use log::warn;

use crate::async_io::{BorrowedDiskFd, DiskFileError};
use crate::error::{BlockError, BlockErrorKind, BlockResult};
use crate::{DiskTopology, disk_file, probe_sparse_support, query_device_size};

/// Selects which async I/O backend a `RawDisk` uses.
#[derive(Clone, Copy, Debug)]
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
