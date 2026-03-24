// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::os::unix::io::{AsRawFd, RawFd};

use vmm_sys_util::eventfd::EventFd;

use crate::async_io::{
    AsyncIo, AsyncIoError, AsyncIoResult, BorrowedDiskFd, DiskFile, DiskFileError, DiskFileResult,
};
use crate::error::{BlockError, BlockErrorKind, BlockResult, ErrorOp};
use crate::fixed_vhd::FixedVhd;
use crate::raw_async::RawFileAsync;
use crate::{BatchRequest, BlockBackend, disk_file};

#[derive(Debug)]
pub struct FixedVhdDiskAsync(FixedVhd);

impl FixedVhdDiskAsync {
    pub fn new(file: File) -> BlockResult<Self> {
        Ok(Self(
            FixedVhd::new(file).map_err(|e| BlockError::from(e).with_op(ErrorOp::Open))?,
        ))
    }
}

impl DiskFile for FixedVhdDiskAsync {
    fn logical_size(&mut self) -> DiskFileResult<u64> {
        Ok(self.0.logical_size().unwrap())
    }

    fn physical_size(&mut self) -> DiskFileResult<u64> {
        Ok(self.0.physical_size().unwrap())
    }

    fn new_async_io(&self, ring_depth: u32) -> DiskFileResult<Box<dyn AsyncIo>> {
        Ok(Box::new(
            FixedVhdAsync::new(
                self.0.as_raw_fd(),
                ring_depth,
                self.0.logical_size().unwrap(),
            )
            .map_err(DiskFileError::NewAsyncIo)?,
        ) as Box<dyn AsyncIo>)
    }

    fn fd(&mut self) -> BorrowedDiskFd<'_> {
        BorrowedDiskFd::new(self.0.as_raw_fd())
    }
}

impl disk_file::DiskSize for FixedVhdDiskAsync {
    fn logical_size(&self) -> BlockResult<u64> {
        Ok(self.0.logical_size().unwrap())
    }
}

impl disk_file::PhysicalSize for FixedVhdDiskAsync {
    fn physical_size(&self) -> BlockResult<u64> {
        self.0.physical_size().map_err(|e| match e {
            crate::Error::GetFileMetadata(io) => {
                BlockError::new(BlockErrorKind::Io, crate::Error::GetFileMetadata(io))
            }
            _ => BlockError::new(BlockErrorKind::Io, e),
        })
    }
}

impl disk_file::DiskFd for FixedVhdDiskAsync {
    fn fd(&self) -> BorrowedDiskFd<'_> {
        BorrowedDiskFd::new(self.0.as_raw_fd())
    }
}

impl disk_file::Geometry for FixedVhdDiskAsync {}

impl disk_file::SparseCapable for FixedVhdDiskAsync {}

impl disk_file::Resizable for FixedVhdDiskAsync {
    fn resize(&mut self, _size: u64) -> BlockResult<()> {
        Err(BlockError::new(
            BlockErrorKind::UnsupportedFeature,
            DiskFileError::ResizeError(std::io::Error::other("resize not supported for fixed VHD")),
        )
        .with_op(ErrorOp::Resize))
    }
}

impl disk_file::DiskFile for FixedVhdDiskAsync {}

pub struct FixedVhdAsync {
    raw_file_async: RawFileAsync,
    size: u64,
}

impl FixedVhdAsync {
    pub fn new(fd: RawFd, ring_depth: u32, size: u64) -> std::io::Result<Self> {
        let raw_file_async = RawFileAsync::new(fd, ring_depth)?;

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

    fn read_vectored(
        &mut self,
        offset: libc::off_t,
        iovecs: &[libc::iovec],
        user_data: u64,
    ) -> AsyncIoResult<()> {
        if offset as u64 >= self.size {
            return Err(AsyncIoError::ReadVectored(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Invalid offset {}, can't be larger than file size {}",
                    offset, self.size
                ),
            )));
        }

        self.raw_file_async.read_vectored(offset, iovecs, user_data)
    }

    fn write_vectored(
        &mut self,
        offset: libc::off_t,
        iovecs: &[libc::iovec],
        user_data: u64,
    ) -> AsyncIoResult<()> {
        if offset as u64 >= self.size {
            return Err(AsyncIoError::WriteVectored(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Invalid offset {}, can't be larger than file size {}",
                    offset, self.size
                ),
            )));
        }

        self.raw_file_async
            .write_vectored(offset, iovecs, user_data)
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        self.raw_file_async.fsync(user_data)
    }

    fn next_completed_request(&mut self) -> Option<(u64, i32)> {
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

    fn submit_batch_requests(&mut self, batch_request: &[BatchRequest]) -> AsyncIoResult<()> {
        self.raw_file_async.submit_batch_requests(batch_request)
    }
}
