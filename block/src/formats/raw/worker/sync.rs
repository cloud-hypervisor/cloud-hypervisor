// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::collections::VecDeque;
use std::os::unix::io::RawFd;

use libc::{FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE, FALLOC_FL_ZERO_RANGE};
use vmm_sys_util::eventfd::EventFd;

use crate::SECTOR_SIZE;
use crate::async_io::{AsyncIo, AsyncIoError, AsyncIoResult};

pub struct RawSync {
    fd: RawFd,
    eventfd: EventFd,
    completion_list: VecDeque<(u64, i32)>,
    alignment: u64,
}

impl RawSync {
    pub fn new(fd: RawFd) -> Self {
        RawSync {
            fd,
            eventfd: EventFd::new(libc::EFD_NONBLOCK).expect("Failed creating EventFd for RawFile"),
            completion_list: VecDeque::new(),
            alignment: SECTOR_SIZE,
        }
    }
}

impl AsyncIo for RawSync {
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

    fn punch_hole(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        let mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;

        // SAFETY: FFI call with valid arguments
        let result = unsafe {
            libc::fallocate(
                self.fd as libc::c_int,
                mode,
                offset as libc::off_t,
                length as libc::off_t,
            )
        };
        if result < 0 {
            return Err(AsyncIoError::PunchHole(std::io::Error::last_os_error()));
        }

        self.completion_list.push_back((user_data, result));
        self.eventfd.write(1).unwrap();

        Ok(())
    }

    fn write_zeroes(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        let mode = FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE;

        // SAFETY: FFI call with valid arguments
        let result = unsafe {
            libc::fallocate(
                self.fd as libc::c_int,
                mode,
                offset as libc::off_t,
                length as libc::off_t,
            )
        };
        if result < 0 {
            return Err(AsyncIoError::WriteZeroes(std::io::Error::last_os_error()));
        }

        self.completion_list.push_back((user_data, result));
        self.eventfd.write(1).unwrap();

        Ok(())
    }
}

#[cfg(test)]
mod unit_tests {
    use std::os::unix::io::AsRawFd;

    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::raw_disk::worker::tests;

    #[test]
    fn test_punch_hole() {
        let temp_file = TempFile::new().unwrap();
        let mut file = temp_file.into_file();
        let mut async_io = RawSync::new(file.as_raw_fd());
        tests::test_punch_hole(&mut async_io, &mut file);
    }

    #[test]
    fn test_write_zeroes() {
        let temp_file = TempFile::new().unwrap();
        let mut file = temp_file.into_file();
        let mut async_io = RawSync::new(file.as_raw_fd());
        tests::test_write_zeroes(&mut async_io, &mut file);
    }

    #[test]
    fn test_punch_hole_multiple_operations() {
        let temp_file = TempFile::new().unwrap();
        let mut file = temp_file.into_file();
        let mut async_io = RawSync::new(file.as_raw_fd());
        tests::test_punch_hole_multiple_operations(&mut async_io, &mut file);
    }
}
