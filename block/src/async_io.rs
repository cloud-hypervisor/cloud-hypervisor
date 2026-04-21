// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::marker::PhantomData;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

use thiserror::Error;
use vmm_sys_util::eventfd::EventFd;

use crate::{BatchRequest, SECTOR_SIZE};

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
    #[error("Failed cloning disk file")]
    Clone(#[source] std::io::Error),
}

pub type DiskFileResult<T> = std::result::Result<T, DiskFileError>;

/// A wrapper for [`RawFd`] capturing the lifetime of a corresponding disk file.
///
/// This fulfills the same role as [`BorrowedFd`] but is tailored to the limitations
/// by some disk implementations, which wrap the effective [`File`]
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
