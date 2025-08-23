// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::collections::VecDeque;
use std::fs::File;
use std::io::{Error, ErrorKind, Seek, SeekFrom};
use std::os::unix::io::{AsRawFd, RawFd};

use log::warn;
use vmm_sys_util::eventfd::EventFd;

use crate::DiskTopology;
use crate::async_io::{
    AsyncIo, AsyncIoError, AsyncIoResult, BorrowedDiskFd, DiskFile, DiskFileError, DiskFileResult,
};

const ZERO_BUFFER_SIZE: usize = 64 * 1024;

pub struct RawFileDiskSync {
    file: File,
}

impl RawFileDiskSync {
    pub fn new(file: File) -> Self {
        RawFileDiskSync { file }
    }
}

impl DiskFile for RawFileDiskSync {
    fn size(&mut self) -> DiskFileResult<u64> {
        self.file
            .seek(SeekFrom::End(0))
            .map_err(DiskFileError::Size)
    }

    fn new_async_io(&self, _ring_depth: u32) -> DiskFileResult<Box<dyn AsyncIo>> {
        Ok(Box::new(RawFileSync::new(self.file.as_raw_fd())) as Box<dyn AsyncIo>)
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

pub struct RawFileSync {
    fd: RawFd,
    eventfd: EventFd,
    completion_list: VecDeque<(u64, i32)>,
}

impl RawFileSync {
    pub fn new(fd: RawFd) -> Self {
        RawFileSync {
            fd,
            eventfd: EventFd::new(libc::EFD_NONBLOCK).expect("Failed creating EventFd for RawFile"),
            completion_list: VecDeque::new(),
        }
    }
}

impl AsyncIo for RawFileSync {
    fn notifier(&self) -> &EventFd {
        &self.eventfd
    }

    fn read_vectored(
        &mut self,
        offset: libc::off_t,
        iovecs: &[libc::iovec],
        user_data: u64,
    ) -> AsyncIoResult<()> {
        // SAFETY: FFI call with valid arguments
        let result = unsafe {
            libc::preadv(
                self.fd as libc::c_int,
                iovecs.as_ptr(),
                iovecs.len() as libc::c_int,
                offset,
            )
        };
        if result < 0 {
            return Err(AsyncIoError::ReadVectored(std::io::Error::last_os_error()));
        }

        self.completion_list.push_back((user_data, result as i32));
        self.eventfd.write(1).unwrap();

        Ok(())
    }

    fn write_vectored(
        &mut self,
        offset: libc::off_t,
        iovecs: &[libc::iovec],
        user_data: u64,
    ) -> AsyncIoResult<()> {
        // SAFETY: FFI call with valid arguments
        let result = unsafe {
            libc::pwritev(
                self.fd as libc::c_int,
                iovecs.as_ptr(),
                iovecs.len() as libc::c_int,
                offset,
            )
        };
        if result < 0 {
            return Err(AsyncIoError::WriteVectored(std::io::Error::last_os_error()));
        }

        self.completion_list.push_back((user_data, result as i32));
        self.eventfd.write(1).unwrap();

        Ok(())
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        // SAFETY: FFI call
        let result = unsafe { libc::fsync(self.fd as libc::c_int) };
        if result < 0 {
            return Err(AsyncIoError::Fsync(std::io::Error::last_os_error()));
        }

        if let Some(user_data) = user_data {
            self.completion_list.push_back((user_data, result));
            self.eventfd.write(1).unwrap();
        }

        Ok(())
    }

    fn next_completed_request(&mut self) -> Option<(u64, i32)> {
        self.completion_list.pop_front()
    }

    fn punch_hole(&mut self, offset: u64, len: u64, user_data: u64) -> AsyncIoResult<()> {
        // SAFETY: FFI call with valid arguments
        let result = unsafe {
            libc::fallocate(
                self.fd,
                libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                offset as libc::off_t,
                len as libc::off_t,
            )
        };
        if result < 0 {
            return Err(AsyncIoError::PunchHole(std::io::Error::last_os_error()));
        }
        self.completion_list.push_back((user_data, result as i32));
        self.eventfd.write(1).unwrap();
        Ok(())
    }

    fn write_zeroes_at(
        &mut self,
        offset: u64,
        len: usize,
        user_data: Option<u64>,
    ) -> std::io::Result<usize> {
        // SAFETY: FFI call with valid arguments
        if unsafe {
            libc::fallocate(
                self.fd,
                libc::FALLOC_FL_ZERO_RANGE | libc::FALLOC_FL_KEEP_SIZE,
                offset as libc::off_t,
                len as libc::off_t,
            )
        } == 0
        {
            return Ok(len);
        }

        // fall back to writing a buffer of zeroes until we have written up to length.
        let zero_buffer = [0u8; ZERO_BUFFER_SIZE];
        let mut total_written = 0;
        let mut current_offset = offset;

        while total_written < len {
            let bytes_to_write = std::cmp::min(len - total_written, ZERO_BUFFER_SIZE);
            let iovs = [libc::iovec {
                // SAFETY: a pointer to our stack buffer
                iov_base: zero_buffer.as_ptr() as *mut libc::c_void,
                iov_len: bytes_to_write,
            }];

            let bytes_written = loop {
                // SAFETY: FFI call with valid arguments. We provide a valid file descriptor,
                // a pointer to our iovs array, the count of iovs (1), and the offset.
                let result = unsafe {
                    libc::pwritev(
                        self.fd,
                        iovs.as_ptr(),
                        iovs.len() as libc::c_int,
                        current_offset as libc::off_t,
                    )
                };
                if result < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(err);
                }
                break result as usize;
            };
            if bytes_written == 0 {
                return Err(std::io::Error::new(
                    ErrorKind::WriteZero,
                    "failed to write whole buffer to file",
                ));
            }
            total_written += bytes_written;
            current_offset += bytes_written as u64;
        }
        if let Some(user_data) = user_data {
            self.completion_list
                .push_back((user_data, total_written as i32));
            self.eventfd.write(1)?;
        }
        Ok(total_written)
    }

    fn write_all_zeroes_at(
        &mut self,
        mut offset: u64,
        mut length: usize,
        user_data: u64,
    ) -> AsyncIoResult<()> {
        let total = length;
        while length > 0 {
            match self.write_zeroes_at(offset, length, None) {
                Ok(0) => return Err(AsyncIoError::WriteZeroes(Error::from(ErrorKind::WriteZero))),
                Ok(bytes_written) => {
                    length = length
                        .checked_sub(bytes_written)
                        .ok_or_else(|| AsyncIoError::WriteZeroes(Error::from(ErrorKind::Other)))?;
                    offset = offset
                        .checked_add(bytes_written as u64)
                        .ok_or_else(|| AsyncIoError::WriteZeroes(Error::from(ErrorKind::Other)))?;
                }
                Err(e) => {
                    // If the operation was interrupted, we should retry it.
                    if e.kind() != ErrorKind::Interrupted {
                        return Err(AsyncIoError::WriteZeroes(e));
                    }
                }
            }
        }
        self.completion_list.push_back((user_data, total as i32));
        self.eventfd.write(1).unwrap();
        Ok(())
    }
}
