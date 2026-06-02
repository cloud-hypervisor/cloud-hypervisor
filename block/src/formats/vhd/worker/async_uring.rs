// Copyright © 2021 Intel Corporation
//
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0

use std::os::unix::io::RawFd;

use vmm_sys_util::eventfd::EventFd;

use crate::async_io::{AsyncIo, AsyncIoCompletion, AsyncIoError, AsyncIoOperation, AsyncIoResult};
use crate::error::BlockResult;
use crate::formats::raw::worker::async_uring::RawAsync;

pub struct FixedVhdAsync {
    raw_file_async: RawAsync,
    size: u64,
}

impl FixedVhdAsync {
    pub fn new(fd: RawFd, ring_depth: u32, size: u64) -> BlockResult<Self> {
        let raw_file_async = RawAsync::new(fd, ring_depth)?;

        Ok(FixedVhdAsync {
            raw_file_async,
            size,
        })
    }

    fn validate_operation_bounds(&self, op: &AsyncIoOperation) -> AsyncIoResult<()> {
        let offset = u64::try_from(op.offset()).map_err(|_| self.bounds_error(op))?;
        let len = u64::try_from(op.total_len()).map_err(|_| self.bounds_error(op))?;
        let end = offset
            .checked_add(len)
            .ok_or_else(|| self.bounds_error(op))?;

        if end > self.size {
            return Err(self.bounds_error(op));
        }

        Ok(())
    }

    fn bounds_error(&self, op: &AsyncIoOperation) -> AsyncIoError {
        let error = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Invalid request offset {} and length {}, can't exceed file size {}",
                op.offset(),
                op.total_len(),
                self.size
            ),
        );
        if op.is_read() {
            AsyncIoError::ReadVectored(error)
        } else {
            AsyncIoError::WriteVectored(error)
        }
    }
}

impl AsyncIo for FixedVhdAsync {
    fn notifier(&self) -> &EventFd {
        self.raw_file_async.notifier()
    }

    fn alignment(&self) -> u64 {
        self.raw_file_async.alignment()
    }

    fn submit_data_operation(&mut self, op: AsyncIoOperation) -> AsyncIoResult<()> {
        self.validate_operation_bounds(&op)?;
        self.raw_file_async.submit_data_operation(op)
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        self.raw_file_async.fsync(user_data)
    }

    fn next_completed_request(&mut self) -> Option<AsyncIoCompletion> {
        self.raw_file_async.next_completed_request()
    }

    fn punch_hole(&mut self, _offset: u64, _length: u64, _user_data: u64) -> AsyncIoResult<()> {
        Err(AsyncIoError::PunchHole(std::io::Error::other(
            "punch_hole not supported for fixed VHD",
        )))
    }

    fn write_zeroes(&mut self, _offset: u64, _length: u64, _user_data: u64) -> AsyncIoResult<()> {
        Err(AsyncIoError::WriteZeroes(std::io::Error::other(
            "write_zeroes not supported for fixed VHD",
        )))
    }

    fn batch_requests_enabled(&self) -> bool {
        true
    }

    fn submit_batch_requests(&mut self, batch_request: Vec<AsyncIoOperation>) -> AsyncIoResult<()> {
        for op in &batch_request {
            self.validate_operation_bounds(op)?;
        }

        self.raw_file_async.submit_batch_requests(batch_request)
    }
}
