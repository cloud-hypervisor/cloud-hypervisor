// Copyright © 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
//
// Copyright © 2023 Crusoe Energy Systems LLC
//

use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::os::unix::io::{AsRawFd, RawFd};

use vmm_sys_util::aio;
use vmm_sys_util::eventfd::EventFd;

use crate::async_io::{
    AsyncIo, AsyncIoError, AsyncIoResult, BorrowedDiskFd, DiskFile, DiskFileError, DiskFileResult,
};
use crate::DiskTopology;

pub struct RawFileDiskAio {
    file: File,
}

impl RawFileDiskAio {
    pub fn new(file: File) -> Self {
        RawFileDiskAio { file }
    }
}

impl DiskFile for RawFileDiskAio {
    fn size(&mut self) -> DiskFileResult<u64> {
        self.file
            .seek(SeekFrom::End(0))
            .map_err(DiskFileError::Size)
    }

    fn new_async_io(&self, ring_depth: u32) -> DiskFileResult<Box<dyn AsyncIo>> {
        Ok(Box::new(
            RawFileAsyncAio::new(self.file.as_raw_fd(), ring_depth)
                .map_err(DiskFileError::NewAsyncIo)?,
        ) as Box<dyn AsyncIo>)
    }

    fn topology(&mut self) -> DiskTopology {
        if let Ok(topology) = DiskTopology::probe(&self.file) {
            topology
        } else {
            warn!("Unable to get device topology. Using default topology");
            DiskTopology::default()
        }
    }

    fn fd(&mut self) -> BorrowedDiskFd {
        BorrowedDiskFd::new(self.file.as_raw_fd())
    }
}

pub struct RawFileAsyncAio {
    fd: RawFd,
    ctx: aio::IoContext,
    eventfd: EventFd,
}

impl RawFileAsyncAio {
    pub fn new(fd: RawFd, queue_depth: u32) -> std::io::Result<Self> {
        let eventfd = EventFd::new(libc::EFD_NONBLOCK)?;
        let ctx = aio::IoContext::new(queue_depth)?;

        Ok(RawFileAsyncAio { fd, ctx, eventfd })
    }
}

impl AsyncIo for RawFileAsyncAio {
    fn notifier(&self) -> &EventFd {
        &self.eventfd
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
        let mut events: [aio::IoEvent; 1] = [aio::IoEvent::default()];
        let rc = self.ctx.get_events(0, &mut events, None).unwrap();
        if rc == 0 {
            None
        } else {
            Some((events[0].data, events[0].res as i32))
        }
    }
}
