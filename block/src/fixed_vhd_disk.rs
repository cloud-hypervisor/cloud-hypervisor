// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io;
use std::os::unix::io::AsRawFd;

use crate::async_io::{AsyncIo, BorrowedDiskFd, DiskFileError};
use crate::disk_file::DiskSize;
use crate::error::{BlockError, BlockErrorKind, BlockResult, ErrorOp};
use crate::fixed_vhd::FixedVhd;
#[cfg(feature = "io_uring")]
use crate::fixed_vhd_async::FixedVhdAsync;
use crate::fixed_vhd_sync::FixedVhdSync;
use crate::{BlockBackend, Error, disk_file};

#[derive(Debug)]
pub struct FixedVhdDisk {
    inner: FixedVhd,
    use_io_uring: bool,
}

impl FixedVhdDisk {
    pub fn new(file: File, use_io_uring: bool) -> BlockResult<Self> {
        #[cfg(not(feature = "io_uring"))]
        if use_io_uring {
            return Err(BlockError::new(
                BlockErrorKind::UnsupportedFeature,
                DiskFileError::NewAsyncIo(io::Error::other(
                    "io_uring requested but feature is not enabled",
                )),
            ));
        }

        Ok(Self {
            inner: FixedVhd::new(file).map_err(|e| BlockError::from(e).with_op(ErrorOp::Open))?,
            use_io_uring,
        })
    }
}

impl disk_file::DiskSize for FixedVhdDisk {
    fn logical_size(&self) -> BlockResult<u64> {
        self.inner
            .logical_size()
            .map_err(|e| BlockError::new(BlockErrorKind::Io, e))
    }
}

impl disk_file::PhysicalSize for FixedVhdDisk {
    fn physical_size(&self) -> BlockResult<u64> {
        self.inner.physical_size().map_err(|e| match e {
            Error::GetFileMetadata(io) => {
                BlockError::new(BlockErrorKind::Io, Error::GetFileMetadata(io))
            }
            _ => unreachable!("unexpected error from FixedVhd::physical_size(): {e}"),
        })
    }
}

impl disk_file::DiskFd for FixedVhdDisk {
    fn fd(&self) -> BorrowedDiskFd<'_> {
        BorrowedDiskFd::new(self.inner.as_raw_fd())
    }
}

impl disk_file::Geometry for FixedVhdDisk {}

impl disk_file::SparseCapable for FixedVhdDisk {}

impl disk_file::Resizable for FixedVhdDisk {
    fn resize(&mut self, _size: u64) -> BlockResult<()> {
        Err(BlockError::new(
            BlockErrorKind::UnsupportedFeature,
            DiskFileError::ResizeError(io::Error::other("resize not supported for fixed VHD")),
        )
        .with_op(ErrorOp::Resize))
    }
}

impl disk_file::DiskFile for FixedVhdDisk {}

impl disk_file::AsyncDiskFile for FixedVhdDisk {
    fn try_clone(&self) -> BlockResult<Box<dyn disk_file::AsyncDiskFile>> {
        Ok(Box::new(FixedVhdDisk {
            inner: self.inner.clone(),
            use_io_uring: self.use_io_uring,
        }))
    }

    fn create_async_io(&self, ring_depth: u32) -> BlockResult<Box<dyn AsyncIo>> {
        let size = self.logical_size()?;

        if self.use_io_uring {
            #[cfg(feature = "io_uring")]
            {
                return Ok(Box::new(FixedVhdAsync::new(
                    self.inner.as_raw_fd(),
                    ring_depth,
                    size,
                )?));
            }

            #[cfg(not(feature = "io_uring"))]
            unreachable!("use_io_uring is set but io_uring feature is not enabled");
        }

        let _ = ring_depth;
        Ok(Box::new(
            FixedVhdSync::new(self.inner.as_raw_fd(), size).map_err(|e| {
                BlockError::new(BlockErrorKind::Io, DiskFileError::NewAsyncIo(e))
                    .with_op(ErrorOp::Open)
            })?,
        ))
    }
}
