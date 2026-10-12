// Copyright © 2021 Intel Corporation
//
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::os::unix::io::AsRawFd;

use vmm_sys_util::eventfd::EventFd;

use crate::async_io::{
    AsyncIo, AsyncIoCompletion, AsyncIoError, AsyncIoOperation, AsyncIoResult, UringDataIo,
};
use crate::error::{BlockError, BlockErrorKind, BlockResult};
use crate::sparse::{punch_hole, write_zeroes};
use crate::{AlignedFile, is_block_device};

pub(crate) struct RawAsync {
    // Drop before raw_file so pending SQEs can be submitted while its fd is valid.
    data_io: UringDataIo,
    raw_file: AlignedFile,
    alignment: Option<u64>,
    is_block_device: bool,
}

impl RawAsync {
    pub(crate) fn new(raw_file: AlignedFile, ring_depth: u32) -> BlockResult<Self> {
        let data_io =
            UringDataIo::new(ring_depth).map_err(|e| BlockError::new(BlockErrorKind::Io, e))?;
        let is_block_device = is_block_device(raw_file.as_raw_fd());
        let alignment = raw_file.alignment().map(|alignment| alignment as u64);

        Ok(RawAsync {
            data_io,
            raw_file,
            alignment,
            is_block_device,
        })
    }
}

impl AsyncIo for RawAsync {
    fn notifier(&self) -> &EventFd {
        self.data_io.notifier()
    }

    fn alignment(&self) -> Option<u64> {
        self.alignment
    }

    fn submit_data_operation(&mut self, op: AsyncIoOperation) -> AsyncIoResult<()> {
        let is_read = op.is_read();

        let fd = self.raw_file.as_raw_fd();
        self.data_io.submit_operation(fd, op).map_err(|e| {
            if is_read {
                AsyncIoError::ReadVectored(e)
            } else {
                AsyncIoError::WriteVectored(e)
            }
        })
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        let fd = self.raw_file.as_raw_fd();
        if let Some(user_data) = user_data {
            self.data_io
                .submit_fsync(fd, user_data)
                .map_err(AsyncIoError::Fsync)?;
        } else {
            // SAFETY: FFI call with a valid fd
            unsafe { libc::fsync(fd) };
        }

        Ok(())
    }

    fn next_completed_request(&mut self) -> Option<AsyncIoCompletion> {
        self.data_io.next_completion()
    }

    fn batch_requests_enabled(&self) -> bool {
        true
    }

    fn submit_batch_requests(&mut self, batch_request: Vec<AsyncIoOperation>) -> AsyncIoResult<()> {
        self.data_io
            .submit_batch(self.raw_file.as_raw_fd(), batch_request)
            .map_err(AsyncIoError::SubmitBatchRequests)
    }

    fn punch_hole(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        // Run synchronously rather than submitting a fallocate request through
        // the ring. This avoids reaping ENOTSUPP in the completion routine and
        // reissuing the request, and lets the sparse helper handle the ioctl
        // path for block devices and the write fallback for unsupported
        // filesystems.
        punch_hole(
            self.raw_file.file_mut(),
            self.is_block_device,
            offset,
            length,
        )
        .map_err(AsyncIoError::PunchHole)?;
        // Deliver the completion through the normal io_uring path by
        // queuing a NOP carrying `user_data`. The registered eventfd will
        // fire when it completes, just like any other request.
        self.data_io
            .submit_nop(user_data)
            .map_err(AsyncIoError::PunchHole)
    }

    fn write_zeroes(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        // Same rationale as punch_hole().
        write_zeroes(
            self.raw_file.file_mut(),
            self.is_block_device,
            offset,
            length,
        )
        .map_err(AsyncIoError::WriteZeroes)?;
        self.data_io
            .submit_nop(user_data)
            .map_err(AsyncIoError::WriteZeroes)
    }
}
