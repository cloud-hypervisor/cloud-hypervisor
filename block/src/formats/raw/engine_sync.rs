// Copyright © 2021 Intel Corporation
//
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::io;
use std::os::unix::io::AsRawFd;

use vmm_sys_util::eventfd::EventFd;

use crate::async_io::{
    AsyncIo, AsyncIoCompletion, AsyncIoError, AsyncIoOperation, AsyncIoResult, SyncCompletionQueue,
};
use crate::sparse::{punch_hole, write_zeroes};
use crate::{AlignedFile, is_block_device};

pub(crate) struct RawSync {
    raw_file: AlignedFile,
    completions: SyncCompletionQueue,
    alignment: u64,
    is_block_device: bool,
}

impl RawSync {
    pub(crate) fn new(raw_file: AlignedFile) -> Self {
        let is_block_device = is_block_device(raw_file.as_raw_fd());
        let alignment = raw_file.alignment() as u64;
        RawSync {
            raw_file,
            completions: SyncCompletionQueue::new(),
            alignment,
            is_block_device,
        }
    }
}

impl AsyncIo for RawSync {
    fn notifier(&self) -> &EventFd {
        self.completions.notifier()
    }

    fn alignment(&self) -> u64 {
        self.alignment
    }

    fn submit_data_operation(&mut self, op: AsyncIoOperation) -> AsyncIoResult<()> {
        let is_read = op.is_read();
        let iovecs = op.iovecs();
        let offset = op.offset() as u64;

        let result = if is_read {
            // SAFETY: op.iovecs() describes valid memory for iov_len bytes by
            // construction of AsyncIoOperation.
            unsafe { self.raw_file.read_vectored_at(iovecs, offset) }
                .map_err(AsyncIoError::ReadVectored)?
        } else {
            // SAFETY: op.iovecs() describes valid memory for iov_len bytes by
            // construction of AsyncIoOperation.
            unsafe { self.raw_file.write_vectored_at(iovecs, offset) }
                .map_err(AsyncIoError::WriteVectored)?
        } as i32;
        self.completions
            .complete(AsyncIoCompletion::from_operation(op, result));

        Ok(())
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        // SAFETY: FFI call
        let result = unsafe { libc::fsync(self.raw_file.as_raw_fd() as libc::c_int) };
        if result < 0 {
            return Err(AsyncIoError::Fsync(io::Error::last_os_error()));
        }

        if let Some(user_data) = user_data {
            self.completions
                .complete(AsyncIoCompletion::new(user_data, result, None));
        }

        Ok(())
    }

    fn next_completed_request(&mut self) -> Option<AsyncIoCompletion> {
        self.completions.next_completed()
    }

    fn punch_hole(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        punch_hole(&mut self.raw_file, self.is_block_device, offset, length)
            .map_err(AsyncIoError::PunchHole)?;
        self.completions
            .complete(AsyncIoCompletion::new(user_data, 0, None));
        Ok(())
    }

    fn write_zeroes(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        write_zeroes(&mut self.raw_file, self.is_block_device, offset, length)
            .map_err(AsyncIoError::WriteZeroes)?;
        self.completions
            .complete(AsyncIoCompletion::new(user_data, 0, None));
        Ok(())
    }
}

#[cfg(test)]
mod unit_tests {
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::formats::raw::tests;

    #[test]
    fn test_punch_hole() {
        let temp_file = TempFile::new().unwrap();
        let mut file = temp_file.into_file();
        let mut async_io = RawSync::new(AlignedFile::new(file.try_clone().unwrap(), false));
        tests::test_punch_hole(&mut async_io, &mut file);
    }

    #[test]
    fn test_write_zeroes() {
        let temp_file = TempFile::new().unwrap();
        let mut file = temp_file.into_file();
        let mut async_io = RawSync::new(AlignedFile::new(file.try_clone().unwrap(), false));
        tests::test_write_zeroes(&mut async_io, &mut file);
    }

    #[test]
    fn test_punch_hole_multiple_operations() {
        let temp_file = TempFile::new().unwrap();
        let mut file = temp_file.into_file();
        let mut async_io = RawSync::new(AlignedFile::new(file.try_clone().unwrap(), false));
        tests::test_punch_hole_multiple_operations(&mut async_io, &mut file);
    }
}
