// Copyright © 2021 Intel Corporation
//
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0

use std::io;

use vmm_sys_util::eventfd::EventFd;

use crate::AlignedFile;
use crate::async_io::{AsyncIo, AsyncIoCompletion, AsyncIoError, AsyncIoOperation, AsyncIoResult};
use crate::error::BlockResult;
use crate::formats::raw::engine_uring::RawAsync;

pub(super) struct FixedVhdAsync {
    raw_file_async: RawAsync,
    size: u64,
}

impl FixedVhdAsync {
    pub(super) fn new(raw_file: AlignedFile, ring_depth: u32, size: u64) -> BlockResult<Self> {
        let raw_file_async = RawAsync::new(raw_file, ring_depth)?;

        Ok(FixedVhdAsync {
            raw_file_async,
            size,
        })
    }
}

impl AsyncIo for FixedVhdAsync {
    fn notifier(&self) -> &EventFd {
        self.raw_file_async.notifier()
    }

    fn submit_data_operation(&mut self, op: AsyncIoOperation) -> AsyncIoResult<()> {
        op.validate_bounds(self.size)?;
        self.raw_file_async.submit_data_operation(op)
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        self.raw_file_async.fsync(user_data)
    }

    fn next_completed_request(&mut self) -> Option<AsyncIoCompletion> {
        self.raw_file_async.next_completed_request()
    }

    fn punch_hole(&mut self, _offset: u64, _length: u64, _user_data: u64) -> AsyncIoResult<()> {
        Err(AsyncIoError::PunchHole(io::Error::other(
            "punch_hole not supported for fixed VHD",
        )))
    }

    fn write_zeroes(&mut self, _offset: u64, _length: u64, _user_data: u64) -> AsyncIoResult<()> {
        Err(AsyncIoError::WriteZeroes(io::Error::other(
            "write_zeroes not supported for fixed VHD",
        )))
    }

    fn batch_requests_enabled(&self) -> bool {
        true
    }

    fn submit_batch_requests(&mut self, batch_request: Vec<AsyncIoOperation>) -> AsyncIoResult<()> {
        for op in &batch_request {
            op.validate_bounds(self.size)?;
        }

        self.raw_file_async.submit_batch_requests(batch_request)
    }
}
