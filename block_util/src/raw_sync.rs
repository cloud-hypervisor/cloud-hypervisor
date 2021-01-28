// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use crate::async_io::{
    AsyncIo, AsyncIoError, AsyncIoResult, DiskFile, DiskFileError, DiskFileResult,
};
use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::os::unix::io::{AsRawFd, RawFd};
use vmm_sys_util::eventfd::EventFd;

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
        Ok(self
            .file
            .seek(SeekFrom::End(0))
            .map_err(DiskFileError::Size)? as u64)
    }

    fn new_async_io(&self, _ring_depth: u32) -> DiskFileResult<Box<dyn AsyncIo>> {
        Ok(Box::new(RawFileSync::new(self.file.as_raw_fd())) as Box<dyn AsyncIo>)
    }
}

pub struct RawFileSync {
    fd: RawFd,
    eventfd: EventFd,
    completion_list: Vec<(u64, i32)>,
}

impl RawFileSync {
    pub fn new(fd: RawFd) -> Self {
        RawFileSync {
            fd,
            eventfd: EventFd::new(libc::EFD_NONBLOCK).expect("Failed creating EventFd for RawFile"),
            completion_list: Vec::new(),
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
        iovecs: Vec<libc::iovec>,
        user_data: u64,
    ) -> AsyncIoResult<()> {
        let result = unsafe {
            libc::preadv(
                self.fd as libc::c_int,
                iovecs.as_ptr() as *const libc::iovec,
                iovecs.len() as libc::c_int,
                offset,
            )
        };
        if result < 0 {
            return Err(AsyncIoError::ReadVectored(std::io::Error::last_os_error()));
        }

        self.completion_list.push((user_data, result as i32));
        self.eventfd.write(1).unwrap();

        Ok(())
    }

    fn write_vectored(
        &mut self,
        offset: libc::off_t,
        iovecs: Vec<libc::iovec>,
        user_data: u64,
    ) -> AsyncIoResult<()> {
        let result = unsafe {
            libc::pwritev(
                self.fd as libc::c_int,
                iovecs.as_ptr() as *const libc::iovec,
                iovecs.len() as libc::c_int,
                offset,
            )
        };
        if result < 0 {
            return Err(AsyncIoError::WriteVectored(std::io::Error::last_os_error()));
        }

        self.completion_list.push((user_data, result as i32));
        self.eventfd.write(1).unwrap();

        Ok(())
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        let result = unsafe { libc::fsync(self.fd as libc::c_int) };
        if result < 0 {
            return Err(AsyncIoError::Fsync(std::io::Error::last_os_error()));
        }

        if let Some(user_data) = user_data {
            self.completion_list.push((user_data, result as i32));
            self.eventfd.write(1).unwrap();
        }

        Ok(())
    }

    fn complete(&mut self) -> Vec<(u64, i32)> {
        self.completion_list.drain(..).collect()
    }
}
