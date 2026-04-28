// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::io::{Error, ErrorKind};
use std::os::unix::io::{AsRawFd, RawFd};

use io_uring::{IoUring, opcode, types};
use libc::{FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE, FALLOC_FL_ZERO_RANGE};
use vmm_sys_util::eventfd::EventFd;

use crate::async_io::{AsyncIo, AsyncIoError, AsyncIoResult};
use crate::error::{BlockError, BlockErrorKind, BlockResult};
use crate::sparse::{blkdiscard, blkzeroout};
use crate::{BatchRequest, RequestType, SECTOR_SIZE, is_block_device};

pub struct RawFileAsync {
    fd: RawFd,
    io_uring: IoUring,
    eventfd: EventFd,
    alignment: u64,
    is_block_device: bool,
}

impl RawFileAsync {
    pub fn new(fd: RawFd, ring_depth: u32) -> BlockResult<Self> {
        let io_uring =
            IoUring::new(ring_depth).map_err(|e| BlockError::new(BlockErrorKind::Io, e))?;
        if !io_uring.params().is_feature_submit_stable() {
            return Err(BlockError::new(
                BlockErrorKind::UnsupportedFeature,
                Error::new(
                    ErrorKind::Unsupported,
                    "io_uring requires IORING_FEAT_SUBMIT_STABLE",
                ),
            ));
        }
        let eventfd =
            EventFd::new(libc::EFD_NONBLOCK).map_err(|e| BlockError::new(BlockErrorKind::Io, e))?;

        // Register the io_uring eventfd that will notify when something in
        // the completion queue is ready.
        io_uring
            .submitter()
            .register_eventfd(eventfd.as_raw_fd())
            .map_err(|e| BlockError::new(BlockErrorKind::Io, e))?;

        let is_block_device = is_block_device(fd);

        Ok(RawFileAsync {
            fd,
            io_uring,
            eventfd,
            alignment: SECTOR_SIZE,
            is_block_device,
        })
    }

    /// Queue an `IORING_OP_NOP` carrying `user_data` so a synchronously
    /// completed operation (e.g. a BLK* ioctl) is reaped through the normal
    /// io_uring completion path.
    fn submit_nop(&mut self, user_data: u64) -> Result<(), Error> {
        let (submitter, mut sq, _) = self.io_uring.split();
        // SAFETY: Nop carries no buffer; only `user_data` is consumed by the
        // kernel.
        unsafe {
            sq.push(&opcode::Nop::new().build().user_data(user_data))
                .map_err(|e| Error::other(format!("Submission queue is full: {e:?}")))?;
        };
        sq.sync();
        submitter.submit()?;
        Ok(())
    }
}

impl AsyncIo for RawFileAsync {
    fn notifier(&self) -> &EventFd {
        &self.eventfd
    }

    fn alignment(&self) -> u64 {
        self.alignment
    }

    fn read_vectored(
        &mut self,
        offset: libc::off_t,
        iovecs: &[libc::iovec],
        user_data: u64,
    ) -> AsyncIoResult<()> {
        let (submitter, mut sq, _) = self.io_uring.split();

        // SAFETY: we know the file descriptor is valid and we
        // relied on vm-memory to provide the buffer address.
        unsafe {
            sq.push(
                &opcode::Readv::new(types::Fd(self.fd), iovecs.as_ptr(), iovecs.len() as u32)
                    .offset(offset.try_into().unwrap())
                    .build()
                    .user_data(user_data),
            )
            .map_err(|e| {
                AsyncIoError::ReadVectored(Error::other(format!("Submission queue is full: {e:?}")))
            })?;
        };

        // Update the submission queue and submit new operations to the
        // io_uring instance.
        sq.sync();
        submitter.submit().map_err(AsyncIoError::ReadVectored)?;

        Ok(())
    }

    fn write_vectored(
        &mut self,
        offset: libc::off_t,
        iovecs: &[libc::iovec],
        user_data: u64,
    ) -> AsyncIoResult<()> {
        let (submitter, mut sq, _) = self.io_uring.split();

        // SAFETY: we know the file descriptor is valid and we
        // relied on vm-memory to provide the buffer address.
        unsafe {
            sq.push(
                &opcode::Writev::new(types::Fd(self.fd), iovecs.as_ptr(), iovecs.len() as u32)
                    .offset(offset.try_into().unwrap())
                    .build()
                    .user_data(user_data),
            )
            .map_err(|e| {
                AsyncIoError::WriteVectored(Error::other(format!(
                    "Submission queue is full: {e:?}"
                )))
            })?;
        };

        // Update the submission queue and submit new operations to the
        // io_uring instance.
        sq.sync();
        submitter.submit().map_err(AsyncIoError::WriteVectored)?;

        Ok(())
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        if let Some(user_data) = user_data {
            let (submitter, mut sq, _) = self.io_uring.split();

            // SAFETY: we know the file descriptor is valid.
            unsafe {
                sq.push(
                    &opcode::Fsync::new(types::Fd(self.fd))
                        .build()
                        .user_data(user_data),
                )
                .map_err(|e| {
                    AsyncIoError::Fsync(Error::other(format!("Submission queue is full: {e:?}")))
                })?;
            };

            // Update the submission queue and submit new operations to the
            // io_uring instance.
            sq.sync();
            submitter.submit().map_err(AsyncIoError::Fsync)?;
        } else {
            // SAFETY: FFI call with a valid fd
            unsafe { libc::fsync(self.fd) };
        }

        Ok(())
    }

    fn next_completed_request(&mut self) -> Option<(u64, i32)> {
        self.io_uring
            .completion()
            .next()
            .map(|entry| (entry.user_data(), entry.result()))
    }

    fn batch_requests_enabled(&self) -> bool {
        true
    }

    fn submit_batch_requests(&mut self, batch_request: &[BatchRequest]) -> AsyncIoResult<()> {
        if !self.batch_requests_enabled() {
            return Ok(());
        }

        let (submitter, mut sq, _) = self.io_uring.split();
        let mut submitted = false;

        // Refuse the whole batch if it can't fit in the SQ to avoid having to unroll a partially
        // successful push.
        if batch_request.len() > sq.capacity() - sq.len() {
            return Err(AsyncIoError::SubmitBatchRequests(Error::other(
                "io_uring submission queue is full",
            )));
        }

        for req in batch_request {
            match req.request_type {
                RequestType::In => {
                    // SAFETY: we know the file descriptor is valid and we
                    // relied on vm-memory to provide the buffer address.
                    unsafe {
                        sq.push(
                            &opcode::Readv::new(
                                types::Fd(self.fd),
                                req.iovecs.as_ptr(),
                                req.iovecs.len() as u32,
                            )
                            .offset(req.offset as u64)
                            .build()
                            .user_data(req.user_data),
                        )
                        .map_err(|e| {
                            AsyncIoError::ReadVectored(Error::other(format!(
                                "Submission queue is full: {e:?}"
                            )))
                        })?;
                    };
                    submitted = true;
                }
                RequestType::Out => {
                    // SAFETY: we know the file descriptor is valid and we
                    // relied on vm-memory to provide the buffer address.
                    unsafe {
                        sq.push(
                            &opcode::Writev::new(
                                types::Fd(self.fd),
                                req.iovecs.as_ptr(),
                                req.iovecs.len() as u32,
                            )
                            .offset(req.offset as u64)
                            .build()
                            .user_data(req.user_data),
                        )
                        .map_err(|e| {
                            AsyncIoError::WriteVectored(Error::other(format!(
                                "Submission queue is full: {e:?}"
                            )))
                        })?;
                    };
                    submitted = true;
                }
                _ => {
                    unreachable!("Unexpected batch request type: {:?}", req.request_type)
                }
            }
        }

        // Only submit if we actually queued something
        if submitted {
            // Update the submission queue and submit new operations to the
            // io_uring instance.
            sq.sync();
            submitter
                .submit()
                .map_err(AsyncIoError::SubmitBatchRequests)?;
        }

        Ok(())
    }

    fn punch_hole(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        // Some block devices don't support fallocate(). Use ioctl instead. The assumption is that
        // this happens rarely and we don't need to introduce unnecessary complexity by submitting
        // a fallocate request, reaping ENOTSUPP in the completion routine, and reissuing the
        // request with an ioctl.
        if self.is_block_device {
            blkdiscard(self.fd, offset, length).map_err(AsyncIoError::PunchHole)?;
            // Deliver the completion through the normal io_uring path by
            // queuing a NOP carrying `user_data`. The registered eventfd will
            // fire when it completes, just like any other request.
            return self.submit_nop(user_data).map_err(AsyncIoError::PunchHole);
        }

        let (submitter, mut sq, _) = self.io_uring.split();

        let mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;

        // SAFETY: The file descriptor is known to be valid.
        unsafe {
            sq.push(
                &opcode::Fallocate::new(types::Fd(self.fd), length)
                    .offset(offset)
                    .mode(mode)
                    .build()
                    .user_data(user_data),
            )
            .map_err(|e| {
                AsyncIoError::PunchHole(Error::other(format!("Submission queue is full: {e:?}")))
            })?;
        };

        sq.sync();
        submitter.submit().map_err(AsyncIoError::PunchHole)?;

        Ok(())
    }

    fn write_zeroes(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        // Same rationale as punch_hole().
        if self.is_block_device {
            blkzeroout(self.fd, offset, length).map_err(AsyncIoError::WriteZeroes)?;
            return self
                .submit_nop(user_data)
                .map_err(AsyncIoError::WriteZeroes);
        }

        let (submitter, mut sq, _) = self.io_uring.split();

        let mode = FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE;

        // SAFETY: The file descriptor is known to be valid.
        unsafe {
            sq.push(
                &opcode::Fallocate::new(types::Fd(self.fd), length)
                    .offset(offset)
                    .mode(mode)
                    .build()
                    .user_data(user_data),
            )
            .map_err(|e| {
                AsyncIoError::WriteZeroes(Error::other(format!("Submission queue is full: {e:?}")))
            })?;
        };

        sq.sync();
        submitter.submit().map_err(AsyncIoError::WriteZeroes)?;

        Ok(())
    }
}
