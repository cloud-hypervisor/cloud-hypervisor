// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::os::unix::io::{AsRawFd, RawFd};

use vmm_sys_util::eventfd::EventFd;

use crate::async_io::{
    AsyncIo, AsyncIoError, AsyncIoResult, BorrowedDiskFd, DiskFile, DiskFileError, DiskFileResult,
};
use crate::fixed_vhd::FixedVhd;
use crate::raw_async::RawFileAsync;
use crate::BlockBackend;

pub struct FixedVhdDiskAsync(FixedVhd);

impl FixedVhdDiskAsync {
    pub fn new(file: File) -> std::io::Result<Self> {
        Ok(Self(FixedVhd::new(file)?))
    }
}

impl DiskFile for FixedVhdDiskAsync {
    fn size(&mut self) -> DiskFileResult<u64> {
        Ok(self.0.size().unwrap())
    }

    fn new_async_io(&self, ring_depth: u32) -> DiskFileResult<Box<dyn AsyncIo>> {
        Ok(Box::new(
            FixedVhdAsync::new(self.0.as_raw_fd(), ring_depth, self.0.size().unwrap())
                .map_err(DiskFileError::NewAsyncIo)?,
        ) as Box<dyn AsyncIo>)
    }

    fn fd(&mut self) -> BorrowedDiskFd<'_> {
        BorrowedDiskFd::new(self.0.as_raw_fd())
    }
}

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
}
