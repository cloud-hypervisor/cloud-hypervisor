// Copyright © 2021 Intel Corporation
//
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::os::unix::io::RawFd;

use libc::{FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE, FALLOC_FL_ZERO_RANGE};
use vmm_sys_util::eventfd::EventFd;

use crate::async_io::{
    AsyncIo, AsyncIoCompletion, AsyncIoError, AsyncIoOperation, AsyncIoResult, UringDataIo,
};
use crate::error::{BlockError, BlockErrorKind, BlockResult};
use crate::sparse::{blkdiscard, blkzeroout};
use crate::{BatchRequest, RequestType, SECTOR_SIZE, is_block_device};

pub struct RawFileAsync {
    fd: RawFd,
    data_io: UringDataIo,
    alignment: u64,
    is_block_device: bool,
}

impl RawFileAsync {
    pub fn new(fd: RawFd, ring_depth: u32) -> BlockResult<Self> {
        let data_io =
            UringDataIo::new(ring_depth).map_err(|e| BlockError::new(BlockErrorKind::Io, e))?;
        let is_block_device = is_block_device(fd);

        Ok(RawFileAsync {
            fd,
            data_io,
            alignment: SECTOR_SIZE,
            is_block_device,
        })
    }
}

impl AsyncIo for RawFileAsync {
    fn notifier(&self) -> &EventFd {
        self.data_io.notifier()
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
        // SAFETY: this legacy trait method's caller must keep the borrowed
        // iovecs and writable buffers valid until completion.
        unsafe {
            self.data_io
                .submit_borrowed_operation(self.fd, offset, true, iovecs, user_data)
        }
        .map_err(AsyncIoError::ReadVectored)
    }

    fn write_vectored(
        &mut self,
        offset: libc::off_t,
        iovecs: &[libc::iovec],
        user_data: u64,
    ) -> AsyncIoResult<()> {
        // SAFETY: this legacy trait method's caller must keep the borrowed
        // iovecs and readable buffers valid until completion.
        unsafe {
            self.data_io
                .submit_borrowed_operation(self.fd, offset, false, iovecs, user_data)
        }
        .map_err(AsyncIoError::WriteVectored)
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

    fn next_completion(&mut self) -> Option<AsyncIoCompletion> {
        self.data_io.next_completion()
    }

    fn batch_requests_enabled(&self) -> bool {
        true
    }

    fn submit_batch_requests(&mut self, batch_request: &[BatchRequest]) -> AsyncIoResult<()> {
        let mut batch = Vec::with_capacity(batch_request.len());
        for req in batch_request {
            let is_read = match req.request_type {
                RequestType::In => true,
                RequestType::Out => false,
                _ => unreachable!("Unexpected batch request type: {:?}", req.request_type),
            };
            batch.push((req.offset, is_read, req.iovecs.as_slice(), req.user_data));
        }

        // SAFETY: this legacy trait method's caller must keep every borrowed
        // iovec array and buffer valid until its completion.
        unsafe { self.data_io.submit_borrowed_batch(self.fd, &batch) }
            .map_err(AsyncIoError::SubmitBatchRequests)
    }

    fn submit_batch_operations(
        &mut self,
        batch_request: Vec<AsyncIoOperation>,
    ) -> AsyncIoResult<()> {
        self.data_io
            .submit_batch(self.fd, batch_request)
            .map_err(AsyncIoError::SubmitBatchRequests)
    }

    fn punch_hole(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        // Some block devices don't support fallocate(). Use ioctl instead. The assumption is that
        // this happens rarely and we don't need to introduce unnecessary complexity by submitting
        // a fallocate request, reaping ENOTSUPP in the completion routine, and reissuing the
        // request with an ioctl.
        if self.is_block_device {
            blkdiscard(self.fd, offset, length).map_err(AsyncIoError::PunchHole)?;
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
            .submit_fallocate(self.fd, offset, length, mode, user_data)
            .map_err(AsyncIoError::PunchHole)
    }

    fn write_zeroes(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        // Same rationale as punch_hole().
        if self.is_block_device {
            blkzeroout(self.fd, offset, length).map_err(AsyncIoError::WriteZeroes)?;
            return self
                .data_io
                .submit_nop(user_data)
                .map_err(AsyncIoError::WriteZeroes);
        }

        let mode = FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE;

        self.data_io
            .submit_fallocate(self.fd, offset, length, mode, user_data)
            .map_err(AsyncIoError::WriteZeroes)
    }
}
