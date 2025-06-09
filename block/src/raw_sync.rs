// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::collections::VecDeque;
use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::os::unix::io::{AsRawFd, RawFd};

use vmm_sys_util::eventfd::EventFd;

use crate::async_io::{
    AsyncIo, AsyncIoError, AsyncIoResult, BorrowedDiskFd, DiskFile, DiskFileError, DiskFileResult,
};
use crate::DiskTopology;

pub struct RawFileDiskSync {
    file: File,
}

impl RawFileDiskSync {
    pub fn new(file: File) -> Self {
        RawFileDiskSync { file }
    }
}

impl DiskFile for RawFileDiskSync {
    fn size(&mut self) -> DiskFileResult<u64> {
        self.file
            .seek(SeekFrom::End(0))
            .map_err(DiskFileError::Size)
    }

    fn new_async_io(&self, _ring_depth: u32) -> DiskFileResult<Box<dyn AsyncIo>> {
        Ok(Box::new(RawFileSync::new(self.file.as_raw_fd())) as Box<dyn AsyncIo>)
    }

    fn topology(&mut self) -> DiskTopology {
        if let Ok(topology) = DiskTopology::probe(&self.file) {
            topology
        } else {
            warn!("Unable to get device topology. Using default topology");
            DiskTopology::default()
        }
    }

    fn fd(&mut self) -> BorrowedDiskFd<'_> {
        BorrowedDiskFd::new(self.file.as_raw_fd())
    }
}

pub struct RawFileSync {
    fd: RawFd,
    eventfd: EventFd,
    completion_list: VecDeque<(u64, i32)>,
}

impl RawFileSync {
    pub fn new(fd: RawFd) -> Self {
        RawFileSync {
            fd,
            eventfd: EventFd::new(libc::EFD_NONBLOCK).expect("Failed creating EventFd for RawFile"),
            completion_list: VecDeque::new(),
        }
    }
}

impl AsyncIo for RawFileSync {
    fn notifier(&self) -> &EventFd {
        &self.eventfd
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
}
