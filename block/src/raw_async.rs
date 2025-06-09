// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::fs::File;
use std::io::{Error, Seek, SeekFrom};
use std::os::unix::io::{AsRawFd, RawFd};

use io_uring::{opcode, types, IoUring};
use vmm_sys_util::eventfd::EventFd;

use crate::async_io::{
    AsyncIo, AsyncIoError, AsyncIoResult, BorrowedDiskFd, DiskFile, DiskFileError, DiskFileResult,
};
use crate::DiskTopology;

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
            .map_err(|_| AsyncIoError::ReadVectored(Error::other("Submission queue is full")))?
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
            .map_err(|_| AsyncIoError::WriteVectored(Error::other("Submission queue is full")))?
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
                .map_err(|_| AsyncIoError::Fsync(Error::other("Submission queue is full")))?
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
}
