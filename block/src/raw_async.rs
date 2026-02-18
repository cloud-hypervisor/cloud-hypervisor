// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::fs::File;
use std::io::{Error, Seek, SeekFrom};
use std::os::unix::io::{AsRawFd, RawFd};

use io_uring::{IoUring, opcode, types};
use log::warn;
use vmm_sys_util::eventfd::EventFd;

use crate::async_io::{
    AsyncIo, AsyncIoError, AsyncIoResult, BorrowedDiskFd, DiskFile, DiskFileError, DiskFileResult,
};
use crate::{BatchRequest, DiskTopology, RequestType, SECTOR_SIZE, probe_sparse_support};

pub struct RawFileDisk {
    file: File,
}

impl RawFileDisk {
    pub fn new(file: File) -> Self {
        RawFileDisk { file }
    }
}

impl DiskFile for RawFileDisk {
    fn logical_size(&mut self) -> DiskFileResult<u64> {
        self.file
            .seek(SeekFrom::End(0))
            .map_err(DiskFileError::Size)
    }

    fn physical_size(&mut self) -> DiskFileResult<u64> {
        self.file
            .metadata()
            .map(|m| m.len())
            .map_err(DiskFileError::Size)
    }

    fn new_async_io(&self, ring_depth: u32) -> DiskFileResult<Box<dyn AsyncIo>> {
        let mut raw = RawFileAsync::new(self.file.as_raw_fd(), ring_depth)
            .map_err(DiskFileError::NewAsyncIo)?;
        raw.alignment = DiskTopology::probe(&self.file)
            .map(|t| t.logical_block_size)
            .unwrap_or(SECTOR_SIZE);
        Ok(Box::new(raw) as Box<dyn AsyncIo>)
    }

    fn topology(&mut self) -> DiskTopology {
        if let Ok(topology) = DiskTopology::probe(&self.file) {
            topology
        } else {
            warn!("Unable to get device topology. Using default topology");
            DiskTopology::default()
        }
    }

    fn resize(&mut self, size: u64) -> DiskFileResult<()> {
        self.file.set_len(size).map_err(DiskFileError::ResizeError)
    }

    fn supports_sparse_operations(&self) -> bool {
        probe_sparse_support(&self.file)
    }

    fn fd(&mut self) -> BorrowedDiskFd<'_> {
        BorrowedDiskFd::new(self.file.as_raw_fd())
    }
}

pub struct RawFileAsync {
    fd: RawFd,
    io_uring: IoUring,
    eventfd: EventFd,
    alignment: u64,
}

impl RawFileAsync {
    pub fn new(fd: RawFd, ring_depth: u32) -> std::io::Result<Self> {
        let io_uring = IoUring::new(ring_depth)?;
        let eventfd = EventFd::new(libc::EFD_NONBLOCK)?;

        // Register the io_uring eventfd that will notify when something in
        // the completion queue is ready.
        io_uring.submitter().register_eventfd(eventfd.as_raw_fd())?;

        Ok(RawFileAsync {
            fd,
            io_uring,
            eventfd,
            alignment: SECTOR_SIZE,
        })
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
            .map_err(|_| AsyncIoError::ReadVectored(Error::other("Submission queue is full")))?;
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
            .map_err(|_| AsyncIoError::WriteVectored(Error::other("Submission queue is full")))?;
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
                .map_err(|_| AsyncIoError::Fsync(Error::other("Submission queue is full")))?;
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
                        .map_err(|_| {
                            AsyncIoError::ReadVectored(Error::other("Submission queue is full"))
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
                        .map_err(|_| {
                            AsyncIoError::WriteVectored(Error::other("Submission queue is full"))
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
        let (submitter, mut sq, _) = self.io_uring.split();

        const FALLOC_FL_PUNCH_HOLE: i32 = 0x02;
        const FALLOC_FL_KEEP_SIZE: i32 = 0x01;
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
        let (submitter, mut sq, _) = self.io_uring.split();

        const FALLOC_FL_ZERO_RANGE: i32 = 0x10;
        const FALLOC_FL_KEEP_SIZE: i32 = 0x01;
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
