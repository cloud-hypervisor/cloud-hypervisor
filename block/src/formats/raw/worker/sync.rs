// Copyright © 2021 Intel Corporation
//
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::collections::VecDeque;
use std::os::unix::io::RawFd;

use vmm_sys_util::eventfd::EventFd;

use crate::async_io::{AsyncIo, AsyncIoCompletion, AsyncIoError, AsyncIoOperation, AsyncIoResult};
use crate::sparse::{punch_hole, write_zeroes};
use crate::{SECTOR_SIZE, is_block_device};

pub struct RawSync {
    fd: RawFd,
    eventfd: EventFd,
    completion_list: VecDeque<AsyncIoCompletion>,
    alignment: u64,
    is_block_device: bool,
}

impl RawSync {
    pub fn new(fd: RawFd) -> Self {
        let is_block_device = is_block_device(fd);
        RawSync {
            fd,
            eventfd: EventFd::new(libc::EFD_NONBLOCK).expect("Failed creating EventFd for RawFile"),
            completion_list: VecDeque::new(),
            alignment: SECTOR_SIZE,
            is_block_device,
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

    fn submit_data_operation(&mut self, op: AsyncIoOperation) -> AsyncIoResult<()> {
        let offset = op.offset();
        let is_read = op.is_read();
        let iovecs = op.iovecs();

        let result = if is_read {
            // SAFETY: the memory pointed to by `iovecs` is backed by the op,
            // and valid for the kernel to write to by construction of
            // AsyncIoOperation.
            unsafe {
                libc::preadv(
                    self.fd as libc::c_int,
                    iovecs.as_ptr(),
                    iovecs.len() as libc::c_int,
                    offset,
                )
            }
        } else {
            // SAFETY: the memory pointed to by `iovecs` is backed by the op,
            // and valid for the kernel to read from by construction of
            // AsyncIoOperation.
            unsafe {
                libc::pwritev(
                    self.fd as libc::c_int,
                    iovecs.as_ptr(),
                    iovecs.len() as libc::c_int,
                    offset,
                )
            }
        };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            return Err(if is_read {
                AsyncIoError::ReadVectored(error)
            } else {
                AsyncIoError::WriteVectored(error)
            });
        }

        self.completion_list
            .push_back(AsyncIoCompletion::from_operation(op, result as i32));
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
            self.completion_list
                .push_back(AsyncIoCompletion::new(user_data, result, None));
            self.eventfd.write(1).unwrap();
        }

        Ok(())
    }

    fn next_completed_request(&mut self) -> Option<AsyncIoCompletion> {
        self.completion_list.pop_front()
    }

    fn punch_hole(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        punch_hole(self.fd, self.is_block_device, offset, length)
            .map_err(AsyncIoError::PunchHole)?;
        self.completion_list
            .push_back(AsyncIoCompletion::new(user_data, 0, None));
        self.eventfd.write(1).unwrap();
        Ok(())
    }

    fn write_zeroes(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        write_zeroes(self.fd, self.is_block_device, offset, length)
            .map_err(AsyncIoError::WriteZeroes)?;
        self.completion_list
            .push_back(AsyncIoCompletion::new(user_data, 0, None));
        self.eventfd.write(1).unwrap();
        Ok(())
    }
}

#[cfg(test)]
mod unit_tests {
    use std::os::unix::io::AsRawFd;

    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::formats::raw::worker::tests;

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
