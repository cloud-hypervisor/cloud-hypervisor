// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::collections::VecDeque;
use std::fs::File;
use std::os::unix::io::{AsRawFd, RawFd};

use libc::{FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE, FALLOC_FL_ZERO_RANGE};
use log::warn;
use vmm_sys_util::eventfd::EventFd;

use crate::async_io::{
    AsyncIo, AsyncIoError, AsyncIoResult, BorrowedDiskFd, DiskFile, DiskFileError, DiskFileResult,
};
use crate::error::{BlockError, BlockErrorKind, BlockResult};
use crate::{DiskTopology, SECTOR_SIZE, disk_file, probe_sparse_support, query_device_size};

#[derive(Debug)]
pub struct RawFileDiskSync {
    file: File,
}

impl RawFileDiskSync {
    pub fn new(file: File) -> Self {
        RawFileDiskSync { file }
    }
}

impl DiskFile for RawFileDiskSync {
    fn logical_size(&mut self) -> DiskFileResult<u64> {
        Ok(query_device_size(&self.file)
            .map_err(DiskFileError::Size)?
            .0)
    }

    fn physical_size(&mut self) -> DiskFileResult<u64> {
        Ok(query_device_size(&self.file)
            .map_err(DiskFileError::Size)?
            .1)
    }

    fn new_async_io(&self, _ring_depth: u32) -> DiskFileResult<Box<dyn AsyncIo>> {
        let mut raw = RawFileSync::new(self.file.as_raw_fd());
        raw.alignment =
            DiskTopology::probe(&self.file).map_or(SECTOR_SIZE, |t| t.logical_block_size);
        Ok(Box::new(raw) as Box<dyn AsyncIo>)
    }

    fn topology(&mut self) -> DiskTopology {
        if let Ok(topology) = DiskTopology::probe(&self.file) {
            topology
        } else {
            warn!("Unable to get device topology. Using default topology");
            DiskTopology::default()
        }
    }

    fn supports_sparse_operations(&self) -> bool {
        probe_sparse_support(&self.file)
    }

    fn fd(&mut self) -> BorrowedDiskFd<'_> {
        BorrowedDiskFd::new(self.file.as_raw_fd())
    }
}

impl disk_file::DiskSize for RawFileDiskSync {
    fn logical_size(&self) -> BlockResult<u64> {
        query_device_size(&self.file)
            .map(|(logical_size, _)| logical_size)
            .map_err(|e| BlockError::new(BlockErrorKind::Io, DiskFileError::Size(e)))
    }
}

impl disk_file::PhysicalSize for RawFileDiskSync {
    fn physical_size(&self) -> BlockResult<u64> {
        query_device_size(&self.file)
            .map(|(_, physical_size)| physical_size)
            .map_err(|e| BlockError::new(BlockErrorKind::Io, DiskFileError::Size(e)))
    }
}

pub struct RawFileSync {
    fd: RawFd,
    eventfd: EventFd,
    completion_list: VecDeque<(u64, i32)>,
    alignment: u64,
}

impl RawFileSync {
    pub fn new(fd: RawFd) -> Self {
        RawFileSync {
            fd,
            eventfd: EventFd::new(libc::EFD_NONBLOCK).expect("Failed creating EventFd for RawFile"),
            completion_list: VecDeque::new(),
            alignment: SECTOR_SIZE,
        }
    }
}

impl AsyncIo for RawFileSync {
    fn notifier(&self) -> &EventFd {
        &self.eventfd
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
        // SAFETY: FFI call with valid arguments
        let result = unsafe {
            libc::preadv(
                self.fd as libc::c_int,
                iovecs.as_ptr(),
                iovecs.len() as libc::c_int,
                offset,
            )
        };
        if result < 0 {
            return Err(AsyncIoError::ReadVectored(std::io::Error::last_os_error()));
        }

        self.completion_list.push_back((user_data, result as i32));
        self.eventfd.write(1).unwrap();

        Ok(())
    }

    fn write_vectored(
        &mut self,
        offset: libc::off_t,
        iovecs: &[libc::iovec],
        user_data: u64,
    ) -> AsyncIoResult<()> {
        // SAFETY: FFI call with valid arguments
        let result = unsafe {
            libc::pwritev(
                self.fd as libc::c_int,
                iovecs.as_ptr(),
                iovecs.len() as libc::c_int,
                offset,
            )
        };
        if result < 0 {
            return Err(AsyncIoError::WriteVectored(std::io::Error::last_os_error()));
        }

        self.completion_list.push_back((user_data, result as i32));
        self.eventfd.write(1).unwrap();

        Ok(())
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        // SAFETY: FFI call
        let result = unsafe { libc::fsync(self.fd as libc::c_int) };
        if result < 0 {
            return Err(AsyncIoError::Fsync(std::io::Error::last_os_error()));
        }

        if let Some(user_data) = user_data {
            self.completion_list.push_back((user_data, result));
            self.eventfd.write(1).unwrap();
        }

        Ok(())
    }

    fn next_completed_request(&mut self) -> Option<(u64, i32)> {
        self.completion_list.pop_front()
    }

    fn punch_hole(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        let mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;

        // SAFETY: FFI call with valid arguments
        let result = unsafe {
            libc::fallocate(
                self.fd as libc::c_int,
                mode,
                offset as libc::off_t,
                length as libc::off_t,
            )
        };
        if result < 0 {
            return Err(AsyncIoError::PunchHole(std::io::Error::last_os_error()));
        }

        self.completion_list.push_back((user_data, result));
        self.eventfd.write(1).unwrap();

        Ok(())
    }

    fn write_zeroes(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        let mode = FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE;

        // SAFETY: FFI call with valid arguments
        let result = unsafe {
            libc::fallocate(
                self.fd as libc::c_int,
                mode,
                offset as libc::off_t,
                length as libc::off_t,
            )
        };
        if result < 0 {
            return Err(AsyncIoError::WriteZeroes(std::io::Error::last_os_error()));
        }

        self.completion_list.push_back((user_data, result));
        self.eventfd.write(1).unwrap();

        Ok(())
    }
}

#[cfg(test)]
mod unit_tests {
    use std::os::unix::io::AsRawFd;

    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::raw_async_io_tests;

    #[test]
    fn test_punch_hole() {
        let temp_file = TempFile::new().unwrap();
        let mut file = temp_file.into_file();
        let mut async_io = RawFileSync::new(file.as_raw_fd());
        raw_async_io_tests::test_punch_hole(&mut async_io, &mut file);
    }

    #[test]
    fn test_write_zeroes() {
        let temp_file = TempFile::new().unwrap();
        let mut file = temp_file.into_file();
        let mut async_io = RawFileSync::new(file.as_raw_fd());
        raw_async_io_tests::test_write_zeroes(&mut async_io, &mut file);
    }

    #[test]
    fn test_punch_hole_multiple_operations() {
        let temp_file = TempFile::new().unwrap();
        let mut file = temp_file.into_file();
        let mut async_io = RawFileSync::new(file.as_raw_fd());
        raw_async_io_tests::test_punch_hole_multiple_operations(&mut async_io, &mut file);
    }
}
