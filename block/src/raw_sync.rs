// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::collections::VecDeque;
use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::os::unix::io::{AsRawFd, RawFd};

use log::warn;
use vmm_sys_util::eventfd::EventFd;

use crate::async_io::{
    AsyncIo, AsyncIoError, AsyncIoResult, BorrowedDiskFd, DiskFile, DiskFileError, DiskFileResult,
};
use crate::{DiskTopology, SECTOR_SIZE, probe_sparse_support};

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
        self.file
            .seek(SeekFrom::End(0))
            .map_err(DiskFileError::Size)
    }

    fn physical_size(&mut self) -> DiskFileResult<u64> {
        self.file
            .metadata()
            .map(|m| m.len())
            .map_err(DiskFileError::Size)
    }

    fn new_async_io(&self, _ring_depth: u32) -> DiskFileResult<Box<dyn AsyncIo>> {
        let mut raw = RawFileSync::new(self.file.as_raw_fd());
        raw.alignment = DiskTopology::probe(&self.file)
            .map(|t| t.logical_block_size)
            .unwrap_or(SECTOR_SIZE);
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
        const FALLOC_FL_PUNCH_HOLE: i32 = 0x02;
        const FALLOC_FL_KEEP_SIZE: i32 = 0x01;
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
        const FALLOC_FL_ZERO_RANGE: i32 = 0x10;
        const FALLOC_FL_KEEP_SIZE: i32 = 0x01;
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
    use std::io::{Read, Seek, SeekFrom, Write};

    use vmm_sys_util::tempfile::TempFile;

    use super::*;

    #[test]
    fn test_punch_hole() {
        let temp_file = TempFile::new().unwrap();
        let mut file = temp_file.into_file();

        // Write 4MB of data
        let data = vec![0xAA; 4 * 1024 * 1024];
        file.write_all(&data).unwrap();
        file.sync_all().unwrap();

        // Create async IO instance
        let mut async_io = RawFileSync::new(file.as_raw_fd());

        // Punch hole in the middle (1MB at offset 1MB)
        let offset = 1024 * 1024;
        let length = 1024 * 1024;
        async_io.punch_hole(offset, length, 1).unwrap();

        // Check completion
        let (user_data, result) = async_io.next_completed_request().unwrap();
        assert_eq!(user_data, 1);
        assert_eq!(result, 0);

        // Verify the hole reads as zeros
        file.seek(SeekFrom::Start(offset)).unwrap();
        let mut read_buf = vec![0; length as usize];
        file.read_exact(&mut read_buf).unwrap();
        assert!(
            read_buf.iter().all(|&b| b == 0),
            "Punched hole should read as zeros"
        );

        // Verify data before hole is intact
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut read_buf = vec![0; 1024];
        file.read_exact(&mut read_buf).unwrap();
        assert!(
            read_buf.iter().all(|&b| b == 0xAA),
            "Data before hole should be intact"
        );

        // Verify data after hole is intact
        file.seek(SeekFrom::Start(offset + length)).unwrap();
        let mut read_buf = vec![0; 1024];
        file.read_exact(&mut read_buf).unwrap();
        assert!(
            read_buf.iter().all(|&b| b == 0xAA),
            "Data after hole should be intact"
        );
    }

    #[test]
    fn test_write_zeroes() {
        let temp_file = TempFile::new().unwrap();
        let mut file = temp_file.into_file();

        // Write 4MB of data
        let data = vec![0xBB; 4 * 1024 * 1024];
        file.write_all(&data).unwrap();
        file.sync_all().unwrap();

        // Create async IO instance
        let mut async_io = RawFileSync::new(file.as_raw_fd());

        // Write zeros in the middle (512KB at offset 2MB)
        let offset = 2 * 1024 * 1024;
        let length = 512 * 1024;
        let write_zeroes_result = async_io.write_zeroes(offset, length, 2);

        // FALLOC_FL_ZERO_RANGE might not be supported on all filesystems (e.g., tmpfs)
        // If it fails with ENOTSUP, skip the test
        if let Err(AsyncIoError::WriteZeroes(ref e)) = write_zeroes_result
            && (e.raw_os_error() == Some(libc::EOPNOTSUPP)
                || e.raw_os_error() == Some(libc::ENOTSUP))
        {
            eprintln!(
                "Skipping test_write_zeroes: filesystem doesn't support FALLOC_FL_ZERO_RANGE"
            );
            return;
        }
        write_zeroes_result.unwrap();

        // Check completion
        let (user_data, result) = async_io.next_completed_request().unwrap();
        assert_eq!(user_data, 2);
        assert_eq!(result, 0);

        // Verify the zeroed region reads as zeros
        file.seek(SeekFrom::Start(offset)).unwrap();
        let mut read_buf = vec![0; length as usize];
        file.read_exact(&mut read_buf).unwrap();
        assert!(
            read_buf.iter().all(|&b| b == 0),
            "Zeroed region should read as zeros"
        );

        // Verify data before zeroed region is intact
        file.seek(SeekFrom::Start(offset - 1024)).unwrap();
        let mut read_buf = vec![0; 1024];
        file.read_exact(&mut read_buf).unwrap();
        assert!(
            read_buf.iter().all(|&b| b == 0xBB),
            "Data before zeroed region should be intact"
        );

        // Verify data after zeroed region is intact
        file.seek(SeekFrom::Start(offset + length)).unwrap();
        let mut read_buf = vec![0; 1024];
        file.read_exact(&mut read_buf).unwrap();
        assert!(
            read_buf.iter().all(|&b| b == 0xBB),
            "Data after zeroed region should be intact"
        );
    }

    #[test]
    fn test_punch_hole_multiple_operations() {
        let temp_file = TempFile::new().unwrap();
        let mut file = temp_file.into_file();

        // Write 8MB of data
        let data = vec![0xCC; 8 * 1024 * 1024];
        file.write_all(&data).unwrap();
        file.sync_all().unwrap();

        // Create async IO instance
        let mut async_io = RawFileSync::new(file.as_raw_fd());

        // Punch multiple holes
        async_io.punch_hole(1024 * 1024, 512 * 1024, 10).unwrap();
        async_io
            .punch_hole(3 * 1024 * 1024, 512 * 1024, 11)
            .unwrap();
        async_io
            .punch_hole(5 * 1024 * 1024, 512 * 1024, 12)
            .unwrap();

        // Check all completions
        let (user_data, result) = async_io.next_completed_request().unwrap();
        assert_eq!(user_data, 10);
        assert_eq!(result, 0);

        let (user_data, result) = async_io.next_completed_request().unwrap();
        assert_eq!(user_data, 11);
        assert_eq!(result, 0);

        let (user_data, result) = async_io.next_completed_request().unwrap();
        assert_eq!(user_data, 12);
        assert_eq!(result, 0);

        // Verify all holes read as zeros
        file.seek(SeekFrom::Start(1024 * 1024)).unwrap();
        let mut read_buf = vec![0; 512 * 1024];
        file.read_exact(&mut read_buf).unwrap();
        assert!(read_buf.iter().all(|&b| b == 0));

        file.seek(SeekFrom::Start(3 * 1024 * 1024)).unwrap();
        file.read_exact(&mut read_buf).unwrap();
        assert!(read_buf.iter().all(|&b| b == 0));

        file.seek(SeekFrom::Start(5 * 1024 * 1024)).unwrap();
        file.read_exact(&mut read_buf).unwrap();
        assert!(read_buf.iter().all(|&b| b == 0));
    }
}
