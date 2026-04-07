// Copyright © 2021 Intel Corporation
// Copyright © 2026 Demi Marie Obenour
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::collections::HashMap;

use libc::iovec;
pub use tracker::Tracker;
use vmm_sys_util::eventfd::EventFd;

use crate::async_io::{AsyncIoError, BorrowedDiskFd};
use crate::request::SECTOR_SIZE;
use crate::{BatchRequest, IoBuf};

mod tracker;

pub type SubmitResult = Result<(), (bool, AsyncIoError)>;

/// An I/O completion
pub struct Completion {
    /// User data of the request
    pub user_data: u64,
    /// Result of the request.  Typically, this will be what the synchronous
    /// version of the same system call would have returned.
    pub result: i32,
    /// The buffer used to make the request, if any.
    /// If the request was a read, it will be filled in with the data read.
    pub iobuf: Option<IoBuf>,
}

/// A raw I/O completion
pub struct InnerCompletion {
    /// User data of the request
    pub user_data: u64,
    /// Result of the request.  Typically, this will be what the synchronous
    /// version of the same system call would have returned.
    pub result: i32,
}

/// An engine that can be created from a given queue depth.
pub trait CreatableEngine: AsyncIoEngine + Sized {
    fn create(queue_depth: u32) -> std::io::Result<Self>;
}

/// An asynchronous I/O engine.
///
/// I/O engines are responsible for “raw” async I/O operations.  The functions
/// they provide are unsafe.  Therefore, I/O engines are not directly used by
/// the block layer.  The block layer must go through the tracker abstraction
/// instead.
///
/// # Safety
///
/// In addition to the per-function safety requirements, the following general
/// requirements apply for all `unsafe` functions:
///
/// 1. The `user_data` must be unique among all pending I/O requests.
///    It must not be reused until after this request has completed.
///    A request with user data X is considered complete when, and only
///    when, [`Self::next_completed_request`] returns `Some((X, _))`.
///
/// 2. All file descriptors must remain valid until the request has been submitted.
///    They do not need to remain valid afterwards.
///
/// 3. If a function takes a pointer to a type followed by a usize, the pointer
///    and usize must meet all requirements of `slice::from_raw_parts` *except*
///    for the aliasing requirements.  The memory the pointer points to must remain
///    valid until the I/O is submitted, but not until it completes.
///
/// 4. If the function takes a pointer to `struct iovec` followed by a usize,
///    the requirements in clause 3 apply.  Additionally, the `iov_base` member of
///    each of the iovecs must point to `iov_len` bytes of memory that is valid to access.
///    This memory must remain valid until the I/O is complete.  Implementations
///    must assume that the memory may be concurrently accessed or modified.
///    If the I/O reads from the function, and the memory is concurrently modified,
///    the bytes written to storage will likely be corrupt.
///
///    Iovecs where `iov_len` is zero are exempt from this requirement.
pub trait AsyncIoEngine: Send {
    /// Get the [`EventFd`] that is notified on completion.
    fn notifier(&self) -> &EventFd;

    /// Read data from the provided registered file into the iovecs.
    /// See `man 2 preadv` for how the iovecs are accessed.
    ///
    /// # Safety
    ///
    /// See the trait-level documentation.
    unsafe fn read_vectored(
        &mut self,
        fd: BorrowedDiskFd,
        iovecs: &[iovec],
        offset: u64,
        user_data: u64,
    ) -> SubmitResult;

    /// Submit a batch of guest-generated requests to the kernel.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::batch_requests_enabled`] returns false
    /// and the batch is not empty.
    ///
    /// # Safety
    ///
    /// See the trait-level documentation.
    fn submit_batch_requests(
        &mut self,
        fd: BorrowedDiskFd<'_>,
        batch_requests: Vec<BatchRequest>,
        requests: &mut HashMap<u64, Option<IoBuf>>,
    ) -> Result<(), AsyncIoError>;

    /// Write data from the provided iovecs into the provided registered file.
    /// See `man 2 pwritev` for how the iovecs are accessed.
    ///
    /// # Safety
    ///
    /// See the trait-level documentation.
    unsafe fn write_vectored(
        &mut self,
        fd: BorrowedDiskFd,
        iovecs: &[iovec],
        offset: u64,
        user_data: u64,
    ) -> SubmitResult;

    /// Call fsync on the registered file descriptor at the given index.
    ///
    /// # Safety
    ///
    /// See the trait-level documentation.
    unsafe fn fsync(&mut self, fd: BorrowedDiskFd, user_data: u64) -> SubmitResult;

    /// Punch a hole in the file referred to by the registered file descriptor at the given index.
    /// The offset and length are taken from the function arguments.
    ///
    /// # Safety
    ///
    /// See the trait-level documentation.
    unsafe fn punch_hole(
        &mut self,
        fd: BorrowedDiskFd,
        offset: u64,
        length: u64,
        user_data: u64,
    ) -> SubmitResult;

    /// Write zeroes referred to by the registered file descriptor at the given index.
    /// The offset and length are taken from the function arguments.
    ///
    /// # Safety
    ///
    /// See the trait-level documentation.
    #[allow(unused_variables)]
    unsafe fn write_zeroes(
        &mut self,
        fd: BorrowedDiskFd,
        offset: u64,
        length: u64,
        user_data: u64,
    ) -> SubmitResult;

    /// Reaps the next completed request.
    ///
    /// The return value is `None` if no request has completed.
    /// Otherwise, it is a [`Completion`] struct.
    ///
    /// Implementations must guarantee that the `user_data` field
    /// in the returned [`Completion`] struct is for an I/O that
    /// will no longer access the provided buffers.
    fn next_completed_request(&mut self) -> Option<InnerCompletion>;

    fn alignment(&self) -> u64 {
        SECTOR_SIZE
    }

    /// Returns whether batch requests are supported.
    ///
    /// If this returns false, the following methods will never be called:
    ///
    /// - All methods ending in `_push`.
    /// - `submit`.
    fn batch_requests_enabled(&self) -> bool;
}
