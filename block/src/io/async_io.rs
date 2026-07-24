// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::marker::PhantomData;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
mod aio_data_io;
mod async_io_core;
mod common;
mod completion;
mod guest_memory_target;
mod operation;
mod owned_io_buffer;
#[cfg(feature = "io_uring")]
mod uring_data_io;

use std::{io, result};

pub use aio_data_io::AioDataIo;
pub use completion::AsyncIoCompletion;
pub(crate) use completion::SyncCompletionQueue;
pub use guest_memory_target::GuestMemoryTarget;
pub use operation::AsyncIoOperation;
pub use owned_io_buffer::OwnedIoBuffer;
use thiserror::Error;
#[cfg(feature = "io_uring")]
pub use uring_data_io::UringDataIo;
use vmm_sys_util::eventfd::EventFd;

use crate::SECTOR_SIZE;

#[derive(Error, Debug)]
pub enum DiskFileError {
    /// Failed getting disk file size.
    #[error("Failed getting disk file size")]
    Size(#[source] io::Error),
    /// Failed creating a new AsyncIo.
    #[error("Failed creating a new AsyncIo")]
    NewAsyncIo(#[source] io::Error),
    /// Unsupported operation.
    #[error("Unsupported operation")]
    Unsupported,
    /// Resize failed
    #[error("Resize failed")]
    ResizeError(#[source] io::Error),
    /// Flushing cached metadata failed
    #[error("Flushing cached metadata failed")]
    SyncMetadata(#[source] io::Error),
    #[error("Failed cloning disk file")]
    Clone(#[source] io::Error),
}

pub type DiskFileResult<T> = result::Result<T, DiskFileError>;

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
    pub(crate) fn new(raw_fd: RawFd) -> Self {
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
    ReadVectored(#[source] io::Error),
    /// Failed vectored writing to file.
    #[error("Failed vectored writing to file")]
    WriteVectored(#[source] io::Error),
    /// Failed synchronizing file.
    #[error("Failed synchronizing file")]
    Fsync(#[source] io::Error),
    /// Failed punching hole.
    #[error("Failed punching hole")]
    PunchHole(#[source] io::Error),
    /// Failed writing zeroes.
    #[error("Failed writing zeroes")]
    WriteZeroes(#[source] io::Error),
    /// Failed submitting batch requests.
    #[error("Failed submitting batch requests")]
    SubmitBatchRequests(#[source] io::Error),
}

pub type AsyncIoResult<T> = result::Result<T, AsyncIoError>;

pub trait AsyncIo: Send {
    fn notifier(&self) -> &EventFd;

    /// Submits one owned data operation.
    ///
    /// Takes ownership of `op`.
    /// Implementations that complete asynchronously must retain it until its
    /// completion is returned.
    fn submit_data_operation(&mut self, op: AsyncIoOperation) -> AsyncIoResult<()>;

    /// Submits a read from `offset` into guest memory.
    fn read_to_memory(
        &mut self,
        offset: libc::off_t,
        target: GuestMemoryTarget,
        user_data: u64,
    ) -> AsyncIoResult<()> {
        self.submit_data_operation(AsyncIoOperation::read_to_memory(offset, target, user_data))
    }

    /// Submits a write to `offset` from guest memory.
    fn write_from_memory(
        &mut self,
        offset: libc::off_t,
        target: GuestMemoryTarget,
        user_data: u64,
    ) -> AsyncIoResult<()> {
        self.submit_data_operation(AsyncIoOperation::write_from_memory(
            offset, target, user_data,
        ))
    }

    /// Submits a read from `offset` into an owned host-memory buffer.
    fn read_to_vec(
        &mut self,
        offset: libc::off_t,
        buffer: OwnedIoBuffer,
        user_data: u64,
    ) -> AsyncIoResult<()> {
        self.submit_data_operation(AsyncIoOperation::read_to_vec(offset, buffer, user_data))
    }

    /// Submits a write to `offset` from an owned host-memory buffer.
    fn write_from_vec(
        &mut self,
        offset: libc::off_t,
        buffer: OwnedIoBuffer,
        user_data: u64,
    ) -> AsyncIoResult<()> {
        self.submit_data_operation(AsyncIoOperation::write_from_vec(offset, buffer, user_data))
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()>;
    fn punch_hole(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()>;
    fn write_zeroes(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()>;

    /// Returns the next owned completion, if one is available.
    ///
    /// Read completions from owned host-memory buffers return that buffer here.
    fn next_completed_request(&mut self) -> Option<AsyncIoCompletion>;

    fn batch_requests_enabled(&self) -> bool {
        false
    }

    /// Submits a batch of owned data operations.
    ///
    /// Backends either accept the whole batch for eventual completion or return
    /// an error before taking ownership of any operation.
    fn submit_batch_requests(&mut self, batch_request: Vec<AsyncIoOperation>) -> AsyncIoResult<()> {
        if batch_request.is_empty() {
            Ok(())
        } else {
            Err(AsyncIoError::SubmitBatchRequests(io::Error::other(
                "batch requests are not supported by this backend",
            )))
        }
    }

    fn alignment(&self) -> u64 {
        SECTOR_SIZE
    }
}
