// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::fs::File;
use std::io::{Error, ErrorKind, Seek, SeekFrom};
use std::os::unix::io::{AsRawFd, RawFd};

use io_uring::{IoUring, opcode, types};
use log::warn;
use vmm_sys_util::eventfd::EventFd;

use crate::async_io::{
    AsyncIo, AsyncIoError, AsyncIoResult, BorrowedDiskFd, DiskFile, DiskFileError, DiskFileResult,
};
use crate::{BLOCK_URING_CMD_DISCARD, BatchRequest, DiskTopology, RequestType};

const ZERO_BUFFER_SIZE: usize = 64 * 1024;

pub struct RawFileDisk {
    file: File,
}

impl RawFileDisk {
    pub fn new(file: File) -> Self {
        RawFileDisk { file }
    }
}

impl DiskFile for RawFileDisk {
    fn size(&mut self) -> DiskFileResult<u64> {
        self.file
            .seek(SeekFrom::End(0))
            .map_err(DiskFileError::Size)
    }

    fn new_async_io(&self, ring_depth: u32) -> DiskFileResult<Box<dyn AsyncIo>> {
        Ok(Box::new(
            RawFileAsync::new(self.file.as_raw_fd(), ring_depth)
                .map_err(DiskFileError::NewAsyncIo)?,
        ) as Box<dyn AsyncIo>)
    }

    fn topology(&mut self) -> DiskTopology {
        if let Ok(topology) = DiskTopology::probe(&self.file) {
            topology
        } else {
            warn!("Unable to get device topology. Using default topology");
            DiskTopology::default()
        }
    }

    fn fd(&mut self) -> BorrowedDiskFd<'_> {
        BorrowedDiskFd::new(self.file.as_raw_fd())
    }
}

pub struct RawFileAsync {
    fd: RawFd,
    is_block_dev: bool,
    io_uring: IoUring,
    eventfd: EventFd,
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
            is_block_dev: DiskTopology::is_block_device(fd)?,
            io_uring,
            eventfd,
        })
    }
}

impl AsyncIo for RawFileAsync {
    fn notifier(&self) -> &EventFd {
        &self.eventfd
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

        if self.is_block_dev {
            let mut cmd = [0u8; 16];
            cmd[0..8].copy_from_slice(&offset.to_le_bytes());
            cmd[8..16].copy_from_slice(&length.to_le_bytes());

            // SAFETY: we know the file descriptor is valid and points to a block device.
            unsafe {
                sq.push(
                    &opcode::UringCmd16::new(types::Fd(self.fd), BLOCK_URING_CMD_DISCARD() as _)
                        .cmd(cmd)
                        .build()
                        .user_data(user_data),
                )
                .map_err(|_| AsyncIoError::PunchHole(Error::other("Submission queue is full")))?;
            };
        } else {
            // SAFETY: we know the file descriptor is valid.
            unsafe {
                sq.push(
                    &opcode::Fallocate::new(types::Fd(self.fd), length)
                        .offset(offset)
                        .mode(libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE)
                        .build()
                        .user_data(user_data),
                )
                .map_err(|_| AsyncIoError::PunchHole(Error::other("Submission queue is full")))?;
            };
        }

        // Update the submission queue and submit new operations to the
        // io_uring instance.
        sq.sync();
        submitter.submit().map_err(AsyncIoError::PunchHole)?;

        Ok(())
    }

    fn write_zeroes_at(
        &mut self,
        offset: u64,
        len: usize,
        user_data: Option<u64>,
    ) -> std::io::Result<usize> {
        if let Some(user_data) = user_data {
            self.write_all_zeroes_at(offset, len, user_data)
                .map_err(|e| {
                    std::io::Error::other(format!("failed to write whole buffer to file: {e}"))
                })?;
            return Ok(len);
        }
        Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "failed to write zeroes since user_data is none",
        ))
    }

    fn write_all_zeroes_at(
        &mut self,
        offset: u64,
        len: usize,
        user_data: u64,
    ) -> AsyncIoResult<()> {
        let (submitter, mut sq, _) = self.io_uring.split();

        let zero_buffer = [0u8; ZERO_BUFFER_SIZE];
        let mut total_written = 0;

        let mut iovecs = Vec::with_capacity(1);
        while total_written < len {
            let bytes_to_write = std::cmp::min(len - total_written, ZERO_BUFFER_SIZE);
            iovecs.push(libc::iovec {
                // SAFETY: a pointer to our stack buffer
                iov_base: zero_buffer.as_ptr() as *mut libc::c_void,
                iov_len: bytes_to_write,
            });
            total_written += bytes_to_write;
        }

        // SAFETY: we know the file descriptor is valid.
        unsafe {
            sq.push(
                &opcode::Writev::new(types::Fd(self.fd), iovecs.as_ptr(), iovecs.len() as u32)
                    .offset(offset)
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
}
