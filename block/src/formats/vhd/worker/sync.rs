// Copyright © 2021 Intel Corporation
//
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0

use std::os::unix::io::RawFd;

use vmm_sys_util::eventfd::EventFd;

use crate::async_io::{AsyncIo, AsyncIoCompletion, AsyncIoError, AsyncIoOperation, AsyncIoResult};
use crate::formats::raw::worker::sync::RawSync;

pub struct FixedVhdSync {
    raw_file_sync: RawSync,
    size: u64,
}

impl FixedVhdSync {
    pub fn new(fd: RawFd, size: u64) -> std::io::Result<Self> {
        Ok(FixedVhdSync {
            raw_file_sync: RawSync::new(fd),
            size,
        })
    }
}

impl AsyncIo for FixedVhdSync {
    fn notifier(&self) -> &EventFd {
        self.raw_file_sync.notifier()
    }

    fn alignment(&self) -> u64 {
        self.raw_file_sync.alignment()
    }

    fn submit_data_operation(&mut self, op: AsyncIoOperation) -> AsyncIoResult<()> {
        let offset = op.offset();
        if offset as u64 >= self.size {
            let error = std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Invalid offset {}, can't be larger than file size {}",
                    offset, self.size
                ),
            );
            return Err(if op.is_read() {
                AsyncIoError::ReadVectored(error)
            } else {
                AsyncIoError::WriteVectored(error)
            });
        }

        self.raw_file_sync.submit_data_operation(op)
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        self.raw_file_sync.fsync(user_data)
    }

    fn next_completed_request(&mut self) -> Option<AsyncIoCompletion> {
        self.raw_file_sync.next_completed_request()
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
}
