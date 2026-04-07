// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::collections::HashMap;
use std::io::Error;
use std::os::fd::AsRawFd as _;

use io_uring::{IoUring, opcode, types};
use libc::{FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE, FALLOC_FL_ZERO_RANGE, iovec};
use vmm_sys_util::eventfd::EventFd;

use super::tracker::insert_request;
use super::{CreatableEngine, InnerCompletion, IoBuf, SubmitResult};
use crate::async_io::{AsyncIoError, BorrowedDiskFd};
use crate::request::SECTOR_SIZE;
use crate::{BatchRequest, RequestType};

pub struct IoUringEngine {
    io_uring: IoUring,
    eventfd: EventFd,
    alignment: u64,
}

impl IoUringEngine {
    pub fn new(ring_depth: u32) -> std::io::Result<Self> {
        let io_uring = IoUring::new(ring_depth)?;
        let eventfd = EventFd::new(libc::EFD_NONBLOCK | libc::EFD_CLOEXEC)?;

        // Register the io_uring eventfd that will notify when something in
        // the completion queue is ready.
        io_uring.submitter().register_eventfd(eventfd.as_raw_fd())?;

        Ok(IoUringEngine {
            io_uring,
            eventfd,
            alignment: SECTOR_SIZE,
        })
    }

    fn fallocate(
        &mut self,
        fd: BorrowedDiskFd,
        offset: u64,
        length: u64,
        user_data: u64,
        mode: i32,
        err: fn(Error) -> AsyncIoError,
    ) -> SubmitResult {
        let (submitter, mut sq, _) = self.io_uring.split();

        // SAFETY: The file descriptor is known to be valid.
        unsafe {
            sq.push(
                &opcode::Fallocate::new(types::Fd(fd.as_raw_fd()), length)
                    .offset(offset)
                    .mode(mode)
                    .build()
                    .user_data(user_data),
            )
            .map_err(|e| {
                let e = err(Error::other(format!("Submission queue is full: {e:?}")));
                (false, e)
            })?;
        };

        sq.sync();
        submitter.submit().map_err(|e| (true, err(e)))?;

        Ok(())
    }
}

impl CreatableEngine for IoUringEngine {
    fn create(queue_depth: u32) -> std::io::Result<Self> {
        Self::new(queue_depth)
    }
}
impl super::AsyncIoEngine for IoUringEngine {
    fn notifier(&self) -> &EventFd {
        &self.eventfd
    }

    fn alignment(&self) -> u64 {
        self.alignment
    }

    unsafe fn read_vectored(
        &mut self,
        fd: BorrowedDiskFd,
        iovecs: &[iovec],
        offset: u64,
        user_data: u64,
    ) -> SubmitResult {
        // SAFETY: caller promises that this is safe.
        let len = u32::try_from(iovecs.len()).map_err(|_| {
            (
                false,
                AsyncIoError::ReadVectored(Error::other("Exceeded 2^32 iovecs")),
            )
        })?;
        let (submitter, mut sq, _) = self.io_uring.split();

        // SAFETY: we know the file descriptor is valid.
        unsafe {
            sq.push(
                &opcode::Readv::new(types::Fd(fd.as_raw_fd()), iovecs.as_ptr(), len)
                    .offset(offset)
                    .build()
                    .user_data(user_data),
            )
        }
        .map_err(|e| {
            (
                false,
                AsyncIoError::ReadVectored(Error::other(format!(
                    "Submission queue is full: {e:?}"
                ))),
            )
        })?;
        sq.sync();
        submitter
            .submit()
            .map_err(|e| (true, AsyncIoError::ReadVectored(e)))?;
        Ok(())
    }

    unsafe fn write_vectored(
        &mut self,
        fd: BorrowedDiskFd,
        iovecs: &[iovec],
        offset: u64,
        user_data: u64,
    ) -> SubmitResult {
        // SAFETY: caller promises that this is safe.
        let len = u32::try_from(iovecs.len()).map_err(|_| {
            (
                false,
                AsyncIoError::WriteVectored(Error::other("Exceeded 2^32 iovecs")),
            )
        })?;
        let (submitter, mut sq, _) = self.io_uring.split();

        // SAFETY: we know the file descriptor is valid.
        unsafe {
            sq.push(
                &opcode::Writev::new(types::Fd(fd.as_raw_fd()), iovecs.as_ptr(), len)
                    .offset(offset)
                    .build()
                    .user_data(user_data),
            )
        }
        .map_err(|e| {
            (
                false,
                AsyncIoError::WriteVectored(Error::other(format!(
                    "Submission queue is full: {e:?}"
                ))),
            )
        })?;
        sq.sync();
        submitter
            .submit()
            .map_err(|e| (true, AsyncIoError::ReadVectored(e)))?;
        Ok(())
    }

    unsafe fn fsync(&mut self, fd: BorrowedDiskFd, user_data: u64) -> SubmitResult {
        let err = AsyncIoError::Fsync;
        let (submitter, mut sq, _) = self.io_uring.split();

        // SAFETY: we know the file descriptor is valid.
        unsafe {
            sq.push(
                &opcode::Fsync::new(types::Fd(fd.as_raw_fd()))
                    .build()
                    .user_data(user_data),
            )
            .map_err(|e| {
                let e = err(Error::other(format!("Submission queue is full: {e:?}")));
                (false, e)
            })?;
        };

        sq.sync();
        submitter.submit().map_err(|e| (true, err(e)))?;

        Ok(())
    }

    fn next_completed_request(&mut self) -> Option<InnerCompletion> {
        self.io_uring
            .completion()
            .next()
            .map(|entry| InnerCompletion {
                user_data: entry.user_data(),
                result: entry.result(),
            })
    }

    unsafe fn punch_hole(
        &mut self,
        fd: BorrowedDiskFd,
        offset: u64,
        length: u64,
        user_data: u64,
    ) -> SubmitResult {
        let mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;
        let err = AsyncIoError::PunchHole;
        self.fallocate(fd, offset, length, user_data, mode, err)
    }

    unsafe fn write_zeroes(
        &mut self,
        fd: BorrowedDiskFd,
        offset: u64,
        length: u64,
        user_data: u64,
    ) -> SubmitResult {
        let mode = FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE;
        let err = AsyncIoError::WriteZeroes;
        self.fallocate(fd, offset, length, user_data, mode, err)
    }

    fn batch_requests_enabled(&self) -> bool {
        true
    }

    fn submit_batch_requests(
        &mut self,
        fd: BorrowedDiskFd<'_>,
        mut batch_request: Vec<BatchRequest>,
        requests: &mut HashMap<u64, Option<IoBuf>>,
    ) -> Result<(), AsyncIoError> {
        if batch_request.is_empty() {
            return Ok(());
        }
        let (submitter, mut sq, _) = self.io_uring.split();

        for req in batch_request.drain(..) {
            let offset = req.offset;
            let user_data = req.user_data;
            let iovec = insert_request(requests, Some(req.iobuf), user_data)
                .map_err(|e| match req.request_type {
                    RequestType::In => AsyncIoError::ReadVectored(e),
                    RequestType::Out => AsyncIoError::WriteVectored(e),
                    _ => {
                        unreachable!("Unexpected batch request type: {:?}", req.request_type)
                    }
                })?
                .as_mut()
                .expect("Inserted a Some")
                .iovecs();
            match req.request_type {
                RequestType::In => {
                    // SAFETY: we know the file descriptor is valid,
                    // we are guaranteed that the memory is still valid here,
                    // and we have just registered it to make sure it stays
                    // valid while the kernel is using it.
                    // Furthermore, IoBuf::iovec guarantees that the returned
                    // iovec will not move even when the IoBuf moves (as the
                    // hashmap resizes).
                    unsafe {
                        sq.push(
                            &opcode::Readv::new(
                                types::Fd(fd.as_raw_fd()),
                                iovec.as_ptr(),
                                iovec.len() as u32,
                            )
                            .offset(offset as u64)
                            .build()
                            .user_data(user_data),
                        )
                    }
                    .map_err(|_| {
                        // Nothing was actually submitted, so it is safe
                        // (and necessary) to unregister the request.
                        let _: Option<IoBuf> = requests.remove(&user_data).expect("inserted above");
                        AsyncIoError::ReadVectored(Error::other("Submission queue is full"))
                    })?;
                }
                RequestType::Out => {
                    // SAFETY: we know the file descriptor is valid,
                    // we are guaranteed that the memory is still valid here,
                    // and we have just registered it to make sure it stays
                    // valid while the kernel is using it.
                    // Furthermore, IoBuf::iovec guarantees that the returned
                    // iovec will not move even when the IoBuf moves (as the
                    // hashmap resizes).
                    unsafe {
                        sq.push(
                            &opcode::Writev::new(
                                types::Fd(fd.as_raw_fd()),
                                iovec.as_ptr(),
                                iovec.len() as u32,
                            )
                            .offset(offset as u64)
                            .build()
                            .user_data(user_data),
                        )
                    }
                    .map_err(|_| {
                        // Nothing was actually submitted, so it is safe
                        // (and necessary) to unregister the request.
                        let _: Option<IoBuf> = requests.remove(&user_data).expect("inserted above");
                        AsyncIoError::WriteVectored(Error::other("Submission queue is full"))
                    })?;
                }
                _ => {
                    unreachable!("Unexpected batch request type: {:?}", req.request_type)
                }
            }
        }
        sq.sync();
        submitter
            .submit()
            .map_err(AsyncIoError::SubmitBatchRequests)?;

        Ok(())
    }
}
