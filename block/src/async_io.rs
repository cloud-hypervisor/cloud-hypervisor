// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::os::fd::AsFd;

use thiserror::Error;
use vmm_sys_util::eventfd::EventFd;

use crate::{BatchRequest, DiskTopology, SECTOR_SIZE};

#[derive(Error, Debug)]
pub enum DiskFileError {
    /// Failed getting disk file size.
    #[error("Failed getting disk file size")]
    Size(#[source] std::io::Error),
    /// Failed creating a new AsyncIo.
    #[error("Failed creating a new AsyncIo")]
    NewAsyncIo(#[source] std::io::Error),
    /// Unsupported operation.
    #[error("Unsupported operation")]
    Unsupported,
    /// Resize failed
    #[error("Resize failed")]
    ResizeError(#[source] std::io::Error),
}

pub type DiskFileResult<T> = std::result::Result<T, DiskFileError>;

/// Abstraction over the effective [`File`] backing up a block device,
/// with support for synchronous and asynchronous I/O.
///
/// This allows abstracting over raw image formats as well as structured
/// image formats.
///
/// The [`BorrowedFd`] returned by `<Self as AsFd>::as_fd(self) is
/// only to be used for `fcntl` operations.
pub trait DiskFile: Send + AsFd {
    /// Returns the logical disk size a guest will see.
    ///
    /// For raw formats, this is equal to [`Self::physical_size`]. For file formats
    /// that wrap disk images in a container (e.g. QCOW2), this refers to the
    /// effective size that the guest will see.
    fn logical_size(&mut self) -> DiskFileResult<u64>;
    /// Returns the physical size of the underlying file.
    fn physical_size(&mut self) -> DiskFileResult<u64>;
    fn new_async_io(&self, ring_depth: u32) -> DiskFileResult<Box<dyn AsyncIo>>;
    fn topology(&mut self) -> DiskTopology {
        DiskTopology::default()
    }
    fn resize(&mut self, _size: u64) -> DiskFileResult<()> {
        Err(DiskFileError::Unsupported)
    }

    /// Indicates support for sparse operations (punch hole, write zeroes, discard).
    /// Override to return true when supported.
    fn supports_sparse_operations(&self) -> bool {
        false
    }

    /// Indicates support for zero flag optimization in WRITE_ZEROES. Override
    /// to return true when supported.
    fn supports_zero_flag(&self) -> bool {
        false
    }
}

#[derive(Error, Debug)]
pub enum AsyncIoError {
    /// Failed vectored reading from file.
    #[error("Failed vectored reading from file")]
    ReadVectored(#[source] std::io::Error),
    /// Failed vectored writing to file.
    #[error("Failed vectored writing to file")]
    WriteVectored(#[source] std::io::Error),
    /// Failed synchronizing file.
    #[error("Failed synchronizing file")]
    Fsync(#[source] std::io::Error),
    /// Failed punching hole.
    #[error("Failed punching hole")]
    PunchHole(#[source] std::io::Error),
    /// Failed writing zeroes.
    #[error("Failed writing zeroes")]
    WriteZeroes(#[source] std::io::Error),
    /// Failed submitting batch requests.
    #[error("Failed submitting batch requests")]
    SubmitBatchRequests(#[source] std::io::Error),
}

pub type AsyncIoResult<T> = std::result::Result<T, AsyncIoError>;

pub trait AsyncIo: Send {
    fn notifier(&self) -> &EventFd;
    fn read_vectored(
        &mut self,
        offset: libc::off_t,
        iovecs: &[libc::iovec],
        user_data: u64,
    ) -> AsyncIoResult<()>;
    fn write_vectored(
        &mut self,
        offset: libc::off_t,
        iovecs: &[libc::iovec],
        user_data: u64,
    ) -> AsyncIoResult<()>;
    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()>;
    fn punch_hole(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()>;
    fn write_zeroes(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()>;
    fn next_completed_request(&mut self) -> Option<(u64, i32)>;
    fn batch_requests_enabled(&self) -> bool {
        false
    }
    fn submit_batch_requests(&mut self, _batch_request: &[BatchRequest]) -> AsyncIoResult<()> {
        Ok(())
    }
    fn alignment(&self) -> u64 {
        SECTOR_SIZE
    }
}
