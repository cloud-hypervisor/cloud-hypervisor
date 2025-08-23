// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::marker::PhantomData;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

use thiserror::Error;
use vmm_sys_util::eventfd::EventFd;

use crate::{BatchRequest, DiskTopology};

#[derive(Error, Debug)]
pub enum DiskFileError {
    /// Failed getting disk file size.
    #[error("Failed getting disk file size")]
    Size(#[source] std::io::Error),
    /// Failed creating a new AsyncIo.
    #[error("Failed creating a new AsyncIo")]
    NewAsyncIo(#[source] std::io::Error),
}

pub type DiskFileResult<T> = std::result::Result<T, DiskFileError>;

/// A wrapper for [`RawFd`] capturing the lifetime of a corresponding [`DiskFile`].
///
/// This fulfills the same role as [`BorrowedFd`] but is tailored to the limitations
/// by some implementations of [`DiskFile`], which wrap the effective [`File`]
/// in an `Arc<Mutex<T>>`, making the use of [`BorrowedFd`] impossible.
///
/// [`BorrowedFd`]: std::os::fd::BorrowedFd
#[derive(Copy, Clone, Debug)]
pub struct BorrowedDiskFd<'fd> {
    raw_fd: RawFd,
    _lifetime: PhantomData<&'fd OwnedFd>,
}

impl BorrowedDiskFd<'_> {
    pub(super) fn new(raw_fd: RawFd) -> Self {
        Self {
            raw_fd,
            _lifetime: PhantomData,
        }
    }
}

impl AsRawFd for BorrowedDiskFd<'_> {
    fn as_raw_fd(&self) -> RawFd {
        self.raw_fd
    }
}

/// Abstraction over the effective [`File`] backing up a block device,
/// with support for synchronous and asynchronous I/O.
///
/// This allows abstracting over raw image formats as well as structured
/// image formats.
pub trait DiskFile: Send {
    fn size(&mut self) -> DiskFileResult<u64>;
    fn new_async_io(&self, ring_depth: u32) -> DiskFileResult<Box<dyn AsyncIo>>;
    fn topology(&mut self) -> DiskTopology {
        DiskTopology::default()
    }
    /// Returns the file descriptor of the underlying disk image file.
    ///
    /// The file descriptor is supposed to be used for `fcntl()` calls but no
    /// other operation.
    fn fd(&mut self) -> BorrowedDiskFd<'_>;
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
    /// Failed submitting batch requests.
    #[error("Failed submitting batch requests")]
    SubmitBatchRequests(#[source] std::io::Error),
    /// Failed to punch hole file.
    #[error("Failed to punch hole file: {0}")]
    PunchHole(#[source] std::io::Error),
    /// Failed to write zeroes to file.
    #[error("Failed to write zeroes to file: {0}")]
    WriteZeroes(#[source] std::io::Error),
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
    fn next_completed_request(&mut self) -> Option<(u64, i32)>;
    fn batch_requests_enabled(&self) -> bool {
        false
    }
    fn submit_batch_requests(&mut self, _batch_request: &[BatchRequest]) -> AsyncIoResult<()> {
        Ok(())
    }
    /// Replace a range of bytes with a hole.
    ///
    /// # Arguments
    ///
    /// * `offset`: offset of the file where to replace with a hole.
    /// * `length`: the number of bytes of the hole to replace with.
    fn punch_hole(&mut self, _offset: u64, _length: u64, _user_data: u64) -> AsyncIoResult<()> {
        Err(AsyncIoError::WriteZeroes(std::io::Error::other(
            "PunchHole doesn't support yet",
        )))
    }
    /// Write up to `length` bytes of zeroes starting at `offset`, returning how many bytes were
    /// written.
    ///
    /// # Arguments
    ///
    /// * `offset`: offset of the file where to write zeroes.
    /// * `length`: the number of bytes of zeroes to write to the stream.
    fn write_zeroes_at(
        &mut self,
        _offset: u64,
        _length: usize,
        _user_data: Option<u64>,
    ) -> std::io::Result<usize> {
        Err(std::io::Error::other("WriteZeroesAt doesn't support yet"))
    }

    /// Write zeroes starting at `offset` until `length` bytes have been written.
    ///
    /// This method will continuously write zeroes until the requested `length` is satisfied or an
    /// unrecoverable error is encountered.
    ///
    /// # Arguments
    ///
    /// * `offset`: offset of the file where to write zeroes.
    /// * `length`: the exact number of bytes of zeroes to write to the stream.
    fn write_all_zeroes_at(
        &mut self,
        _offset: u64,
        _length: usize,
        _user_data: u64,
    ) -> AsyncIoResult<()> {
        Err(AsyncIoError::WriteZeroes(std::io::Error::other(
            "WriteAllZeroesAt doesn't support yet",
        )))
    }
}
