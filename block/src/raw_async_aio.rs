// Copyright © 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
//
// Copyright © 2023 Crusoe Energy Systems LLC
//

use std::collections::VecDeque;
use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::io::{AsRawFd, RawFd};

use libc::{FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE, FALLOC_FL_ZERO_RANGE};
use log::warn;
use vmm_sys_util::aio;
use vmm_sys_util::eventfd::EventFd;

use crate::async_io::{
    AsyncIo, AsyncIoError, AsyncIoResult, DiskFile, DiskFileError, DiskFileResult,
};
use crate::{DiskTopology, SECTOR_SIZE, probe_sparse_support};

pub struct RawFileDiskAio {
    file: File,
}

impl RawFileDiskAio {
    pub fn new(file: File) -> Self {
        RawFileDiskAio { file }
    }
}

impl AsFd for RawFileDiskAio {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}

impl DiskFile for RawFileDiskAio {
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

    fn new_async_io(&self, ring_depth: u32) -> DiskFileResult<Box<dyn AsyncIo>> {
        let mut raw = RawFileAsyncAio::new(self.file.as_raw_fd(), ring_depth)
            .map_err(DiskFileError::NewAsyncIo)?;
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
}

pub struct RawFileAsyncAio {
    fd: RawFd,
    ctx: aio::IoContext,
    eventfd: EventFd,
    alignment: u64,
    completion_list: VecDeque<(u64, i32)>,
}

impl RawFileAsyncAio {
    pub fn new(fd: RawFd, queue_depth: u32) -> std::io::Result<Self> {
        let eventfd = EventFd::new(libc::EFD_NONBLOCK)?;
        let ctx = aio::IoContext::new(queue_depth)?;

        Ok(RawFileAsyncAio {
            fd,
            ctx,
            eventfd,
            alignment: SECTOR_SIZE,
            completion_list: VecDeque::new(),
        })
    }
}

impl AsyncIo for RawFileAsyncAio {
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
        let iocbs = [&mut aio::IoControlBlock {
            aio_fildes: self.fd.as_raw_fd() as u32,
            aio_lio_opcode: aio::IOCB_CMD_PREADV as u16,
            aio_buf: iovecs.as_ptr() as u64,
            aio_nbytes: iovecs.len() as u64,
            aio_offset: offset,
            aio_data: user_data,
            aio_flags: aio::IOCB_FLAG_RESFD,
            aio_resfd: self.eventfd.as_raw_fd() as u32,
            ..Default::default()
        }];
        let _ = self
            .ctx
            .submit(&iocbs[..])
            .map_err(AsyncIoError::ReadVectored)?;

        Ok(())
    }

    fn write_vectored(
        &mut self,
        offset: libc::off_t,
        iovecs: &[libc::iovec],
        user_data: u64,
    ) -> AsyncIoResult<()> {
        let iocbs = [&mut aio::IoControlBlock {
            aio_fildes: self.fd.as_raw_fd() as u32,
            aio_lio_opcode: aio::IOCB_CMD_PWRITEV as u16,
            aio_buf: iovecs.as_ptr() as u64,
            aio_nbytes: iovecs.len() as u64,
            aio_offset: offset,
            aio_data: user_data,
            aio_flags: aio::IOCB_FLAG_RESFD,
            aio_resfd: self.eventfd.as_raw_fd() as u32,
            ..Default::default()
        }];
        let _ = self
            .ctx
            .submit(&iocbs[..])
            .map_err(AsyncIoError::WriteVectored)?;

        Ok(())
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        if let Some(user_data) = user_data {
            let iocbs = [&mut aio::IoControlBlock {
                aio_fildes: self.fd.as_raw_fd() as u32,
                aio_lio_opcode: aio::IOCB_CMD_FSYNC as u16,
                aio_data: user_data,
                aio_flags: aio::IOCB_FLAG_RESFD,
                aio_resfd: self.eventfd.as_raw_fd() as u32,
                ..Default::default()
            }];
            let _ = self.ctx.submit(&iocbs[..]).map_err(AsyncIoError::Fsync)?;
        } else {
            // SAFETY: FFI call with a valid fd
            unsafe { libc::fsync(self.fd) };
        }

        Ok(())
    }

    fn next_completed_request(&mut self) -> Option<(u64, i32)> {
        if self.completion_list.is_empty() {
            // Drain pending AIO completions batched into the same queue.
            let mut events = [aio::IoEvent::default(); 32];
            let rc = self.ctx.get_events(0, &mut events, None).unwrap();
            for event in &events[..rc] {
                self.completion_list
                    .push_back((event.data, event.res as i32));
            }
        }
        self.completion_list.pop_front()
    }

    fn punch_hole(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        // Linux AIO has no IOCB command for fallocate, so perform the operation
        // synchronously and signal completion via the completion list, matching
        // the pattern used by the sync backend (RawFileSync).
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
        // Linux AIO has no IOCB command for fallocate, so perform the operation
        // synchronously and signal completion via the completion list, matching
        // the pattern used by the sync backend (RawFileSync).
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
        let mut async_io = RawFileAsyncAio::new(file.as_raw_fd(), 128).unwrap();
        raw_async_io_tests::test_punch_hole(&mut async_io, &mut file);
    }

    #[test]
    fn test_write_zeroes() {
        let temp_file = TempFile::new().unwrap();
        let mut file = temp_file.into_file();
        let mut async_io = RawFileAsyncAio::new(file.as_raw_fd(), 128).unwrap();
        raw_async_io_tests::test_write_zeroes(&mut async_io, &mut file);
    }

    #[test]
    fn test_punch_hole_multiple_operations() {
        let temp_file = TempFile::new().unwrap();
        let mut file = temp_file.into_file();
        let mut async_io = RawFileAsyncAio::new(file.as_raw_fd(), 128).unwrap();
        raw_async_io_tests::test_punch_hole_multiple_operations(&mut async_io, &mut file);
    }
}
