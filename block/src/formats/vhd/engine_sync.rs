// Copyright © 2021 Intel Corporation
//
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0

use std::io;

use vmm_sys_util::eventfd::EventFd;

use crate::AlignedFile;
use crate::async_io::{AsyncIo, AsyncIoCompletion, AsyncIoError, AsyncIoOperation, AsyncIoResult};
use crate::formats::raw::engine_sync::RawSync;

pub(super) struct FixedVhdSync {
    raw_file_sync: RawSync,
    size: u64,
}

impl FixedVhdSync {
    pub(super) fn new(raw_file: AlignedFile, size: u64) -> Self {
        FixedVhdSync {
            raw_file_sync: RawSync::new(raw_file),
            size,
        }
    }
}

impl AsyncIo for FixedVhdSync {
    fn notifier(&self) -> &EventFd {
        self.raw_file_sync.notifier()
    }

    fn submit_data_operation(&mut self, op: AsyncIoOperation) -> AsyncIoResult<()> {
        op.validate_bounds(self.size)?;
        self.raw_file_sync.submit_data_operation(op)
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        self.raw_file_sync.fsync(user_data)
    }

    fn next_completed_request(&mut self) -> Option<AsyncIoCompletion> {
        self.raw_file_sync.next_completed_request()
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
}
