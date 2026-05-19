// Copyright © 2023 Intel Corporation
//
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
//
// Copyright © 2023 Crusoe Energy Systems LLC
//

use std::os::unix::io::RawFd;

use vmm_sys_util::eventfd::EventFd;

use crate::async_io::{
    AioDataIo, AsyncIo, AsyncIoCompletion, AsyncIoError, AsyncIoOperation, AsyncIoResult,
};
use crate::error::{BlockError, BlockErrorKind, BlockResult};
use crate::sparse::{punch_hole, write_zeroes};
use crate::{SECTOR_SIZE, is_block_device};

pub struct RawFileAsyncAio {
    fd: RawFd,
    data_io: AioDataIo,
    alignment: u64,
    is_block_device: bool,
}

impl RawFileAsyncAio {
    pub fn new(fd: RawFd, queue_depth: u32) -> BlockResult<Self> {
        let data_io =
            AioDataIo::new(queue_depth).map_err(|e| BlockError::new(BlockErrorKind::Io, e))?;
        let is_block_device = is_block_device(fd);

        Ok(RawFileAsyncAio {
            fd,
            data_io,
            alignment: SECTOR_SIZE,
            is_block_device,
        })
    }
}

impl AsyncIo for RawFileAsyncAio {
    fn notifier(&self) -> &EventFd {
        self.data_io.notifier()
    }

    fn alignment(&self) -> u64 {
        self.alignment
    }

    fn submit_data_operation(&mut self, op: AsyncIoOperation) -> AsyncIoResult<()> {
        let is_read = op.is_read();
        self.data_io.submit_operation(self.fd, op).map_err(|e| {
            if is_read {
                AsyncIoError::ReadVectored(e)
            } else {
                AsyncIoError::WriteVectored(e)
            }
        })
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        if let Some(user_data) = user_data {
            self.data_io
                .submit_fsync(self.fd, user_data)
                .map_err(AsyncIoError::Fsync)?;
        } else {
            // SAFETY: FFI call with a valid fd
            unsafe { libc::fsync(self.fd) };
        }

        Ok(())
    }

    fn next_completed_request(&mut self) -> Option<AsyncIoCompletion> {
        self.data_io.next_completion()
    }

    fn punch_hole(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        // Linux AIO has no IOCB command for fallocate, so perform the
        // operation synchronously and signal completion via the completion
        // list, matching the pattern used by the sync backend (RawFileSync).
        punch_hole(self.fd, self.is_block_device, offset, length)
            .map_err(AsyncIoError::PunchHole)?;
        self.data_io
            .inject_completion(AsyncIoCompletion::new(user_data, 0, None));

        Ok(())
    }

    fn write_zeroes(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        // Same as punch_hole().
        write_zeroes(self.fd, self.is_block_device, offset, length)
            .map_err(AsyncIoError::WriteZeroes)?;
        self.data_io
            .inject_completion(AsyncIoCompletion::new(user_data, 0, None));

        Ok(())
    }
}

#[cfg(test)]
mod unit_tests {
    use std::os::unix::io::AsRawFd;

    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::raw_async_io_tests;

    #[test]
    fn test_punch_hole() {
        let temp_file = TempFile::new().unwrap();
        let mut file = temp_file.into_file();
        let mut async_io = RawFileAsyncAio::new(file.as_raw_fd(), 128).unwrap();
        raw_async_io_tests::test_punch_hole(&mut async_io, &mut file);
    }

    #[test]
    fn test_write_zeroes() {
        let temp_file = TempFile::new().unwrap();
        let mut file = temp_file.into_file();
        let mut async_io = RawFileAsyncAio::new(file.as_raw_fd(), 128).unwrap();
        raw_async_io_tests::test_write_zeroes(&mut async_io, &mut file);
    }

    #[test]
    fn test_punch_hole_multiple_operations() {
        let temp_file = TempFile::new().unwrap();
        let mut file = temp_file.into_file();
        let mut async_io = RawFileAsyncAio::new(file.as_raw_fd(), 128).unwrap();
        raw_async_io_tests::test_punch_hole_multiple_operations(&mut async_io, &mut file);
    }
}
