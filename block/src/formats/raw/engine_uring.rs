// Copyright © 2021 Intel Corporation
//
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::os::unix::io::AsRawFd;

use libc::{FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE, FALLOC_FL_ZERO_RANGE};
use vmm_sys_util::eventfd::EventFd;

use super::{operation_is_aligned, run_unaligned_operation};
use crate::async_io::{
    AsyncIo, AsyncIoCompletion, AsyncIoError, AsyncIoOperation, AsyncIoResult, UringDataIo,
};
use crate::error::{BlockError, BlockErrorKind, BlockResult};
use crate::sparse::{blkdiscard, blkzeroout};
use crate::{AlignedFile, is_block_device};

pub(crate) struct RawAsync {
    raw_file: AlignedFile,
    data_io: UringDataIo,
    alignment: u64,
    is_block_device: bool,
}

impl RawAsync {
    pub(crate) fn new(raw_file: AlignedFile, ring_depth: u32) -> BlockResult<Self> {
        let data_io =
            UringDataIo::new(ring_depth).map_err(|e| BlockError::new(BlockErrorKind::Io, e))?;
        let is_block_device = is_block_device(raw_file.as_raw_fd());
        let alignment = raw_file.alignment() as u64;

        Ok(RawAsync {
            raw_file,
            data_io,
            alignment,
            is_block_device,
        })
    }
}

impl AsyncIo for RawAsync {
    fn notifier(&self) -> &EventFd {
        self.data_io.notifier()
    }

    fn alignment(&self) -> u64 {
        self.alignment
    }

    fn submit_data_operation(&mut self, mut op: AsyncIoOperation) -> AsyncIoResult<()> {
        let is_read = op.is_read();

        if operation_is_aligned(&op, self.alignment) {
            let fd = self.raw_file.as_raw_fd();
            return self.data_io.submit_operation(fd, op).map_err(|e| {
                if is_read {
                    AsyncIoError::ReadVectored(e)
                } else {
                    AsyncIoError::WriteVectored(e)
                }
            });
        }

        let result = run_unaligned_operation(&self.raw_file, &mut op)?;
        self.data_io
            .inject_completion(AsyncIoCompletion::from_operation(op, result));

        Ok(())
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
        if self.alignment != 0 {
            let mut aligned_batch = Vec::with_capacity(batch_request.len());
            for mut op in batch_request {
                if operation_is_aligned(&op, self.alignment) {
                    aligned_batch.push(op);
                } else {
                    let result = run_unaligned_operation(&self.raw_file, &mut op)?;
                    self.data_io
                        .inject_completion(AsyncIoCompletion::from_operation(op, result));
                }
            }
            if aligned_batch.is_empty() {
                return Ok(());
            }
            return self
                .data_io
                .submit_batch(self.raw_file.as_raw_fd(), aligned_batch)
                .map_err(AsyncIoError::SubmitBatchRequests);
        }

        self.data_io
            .submit_batch(self.raw_file.as_raw_fd(), batch_request)
            .map_err(AsyncIoError::SubmitBatchRequests)
    }

    fn punch_hole(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        // Some block devices don't support fallocate(). Use ioctl instead. The assumption is that
        // this happens rarely and we don't need to introduce unnecessary complexity by submitting
        // a fallocate request, reaping ENOTSUPP in the completion routine, and reissuing the
        // request with an ioctl.
        if self.is_block_device {
            blkdiscard(self.raw_file.as_raw_fd(), offset, length)
                .map_err(AsyncIoError::PunchHole)?;
            // Deliver the completion through the normal io_uring path by
            // queuing a NOP carrying `user_data`. The registered eventfd will
            // fire when it completes, just like any other request.
            return self
                .data_io
                .submit_nop(user_data)
                .map_err(AsyncIoError::PunchHole);
        }

        let mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;

        self.data_io
            .submit_fallocate(self.raw_file.as_raw_fd(), offset, length, mode, user_data)
            .map_err(AsyncIoError::PunchHole)
    }

    fn write_zeroes(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        // Same rationale as punch_hole().
        if self.is_block_device {
            blkzeroout(self.raw_file.as_raw_fd(), offset, length)
                .map_err(AsyncIoError::WriteZeroes)?;
            return self
                .data_io
                .submit_nop(user_data)
                .map_err(AsyncIoError::WriteZeroes);
        }

        let mode = FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE;

        self.data_io
            .submit_fallocate(self.raw_file.as_raw_fd(), offset, length, mode, user_data)
            .map_err(AsyncIoError::WriteZeroes)
    }
}
