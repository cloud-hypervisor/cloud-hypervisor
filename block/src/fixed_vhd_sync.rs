// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use vmm_sys_util::eventfd::EventFd;

use crate::BlockBackend;
use crate::async_io::{
    AsyncIo, AsyncIoError, AsyncIoResult, DiskFile, DiskFileError, DiskFileResult,
};
use crate::fixed_vhd::FixedVhd;
use crate::raw_sync::RawFileSync;

pub struct FixedVhdDiskSync(FixedVhd);

impl FixedVhdDiskSync {
    pub fn new(file: File) -> std::io::Result<Self> {
        Ok(Self(FixedVhd::new(file)?))
    }
}
impl AsFd for FixedVhdDiskSync {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl DiskFile for FixedVhdDiskSync {
    fn logical_size(&mut self) -> DiskFileResult<u64> {
        Ok(self.0.logical_size().unwrap())
    }

    fn physical_size(&mut self) -> DiskFileResult<u64> {
        self.0.physical_size().map_err(|e| {
            let io_inner = match e {
                crate::Error::GetFileMetadata(e) => e,
                _ => unreachable!(),
            };
            DiskFileError::Size(io_inner)
        })
    }

    fn new_async_io(&self, _ring_depth: u32) -> DiskFileResult<Box<dyn AsyncIo>> {
        Ok(Box::new(
            FixedVhdSync::new(
                self.0
                    .as_fd()
                    .try_clone_to_owned()
                    .map_err(DiskFileError::NewAsyncIo)?,
                self.0.logical_size().unwrap(),
            )
            .map_err(DiskFileError::NewAsyncIo)?,
        ) as Box<dyn AsyncIo>)
    }
}

pub struct FixedVhdSync {
    raw_file_sync: RawFileSync,
    size: u64,
}

impl FixedVhdSync {
    pub fn new(fd: OwnedFd, size: u64) -> std::io::Result<Self> {
        Ok(FixedVhdSync {
            raw_file_sync: RawFileSync::new(fd),
            size,
        })
    }
}

impl AsyncIo for FixedVhdSync {
    fn notifier(&self) -> &EventFd {
        self.raw_file_sync.notifier()
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

        self.raw_file_sync.read_vectored(offset, iovecs, user_data)
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

        self.raw_file_sync.write_vectored(offset, iovecs, user_data)
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        self.raw_file_sync.fsync(user_data)
    }

    fn next_completed_request(&mut self) -> Option<(u64, i32)> {
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
