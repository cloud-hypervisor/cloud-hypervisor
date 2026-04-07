// Copyright © 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
//
// Copyright © 2023 Crusoe Energy Systems LLC
//

use std::collections::VecDeque;
use std::os::unix::io::AsRawFd as _;

use libc::{FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE, FALLOC_FL_ZERO_RANGE, iovec};
use vmm_sys_util::aio;
use vmm_sys_util::eventfd::EventFd;

use super::{AsyncIoEngine, CreatableEngine, InnerCompletion, SubmitResult};
use crate::SECTOR_SIZE;
use crate::async_io::{AsyncIoError, BorrowedDiskFd};

pub struct AioEngine {
    ctx: aio::IoContext,
    eventfd: EventFd,
    alignment: u64,
    completion_list: VecDeque<InnerCompletion>,
}

impl AioEngine {
    pub fn new(queue_depth: u32) -> std::io::Result<Self> {
        let eventfd = EventFd::new(libc::EFD_NONBLOCK | libc::EFD_CLOEXEC)?;
        let ctx = aio::IoContext::new(queue_depth)?;

        Ok(AioEngine {
            ctx,
            eventfd,
            alignment: SECTOR_SIZE,
            completion_list: VecDeque::new(),
        })
    }
}

impl CreatableEngine for AioEngine {
    fn create(queue_depth: u32) -> std::io::Result<Self> {
        Self::new(queue_depth)
    }
}

impl AsyncIoEngine for AioEngine {
    fn notifier(&self) -> &EventFd {
        &self.eventfd
    }

    fn alignment(&self) -> u64 {
        self.alignment
    }

    unsafe fn read_vectored(
        &mut self,
        fd: BorrowedDiskFd,
        iovecs: &[iovec],
        offset: u64,
        user_data: u64,
    ) -> SubmitResult {
        // SAFETY: The file descriptor is guaranteed valid by AsRawFd.
        // The caller promises that the data will stay valid until completion.
        let iocbs = [&mut aio::IoControlBlock {
            aio_fildes: fd.as_raw_fd() as u32,
            aio_lio_opcode: aio::IOCB_CMD_PREADV as u16,
            aio_buf: iovecs.as_ptr() as u64,
            aio_nbytes: iovecs.len() as u64,
            aio_offset: offset as _,
            aio_data: user_data,
            aio_flags: aio::IOCB_FLAG_RESFD,
            aio_resfd: self.eventfd.as_raw_fd() as u32,
            ..Default::default()
        }];
        let _ = self
            .ctx
            .submit(&iocbs[..])
            .map_err(|e| (false, AsyncIoError::ReadVectored(e)))?;

        Ok(())
    }

    unsafe fn write_vectored(
        &mut self,
        fd: BorrowedDiskFd,
        iovecs: &[iovec],
        offset: u64,
        user_data: u64,
    ) -> SubmitResult {
        // SAFETY: The file descriptor is guaranteed valid by AsRawFd.
        // The caller promises that the data will stay valid until completion.
        let iocbs = [&mut aio::IoControlBlock {
            aio_fildes: fd.as_raw_fd() as u32,
            aio_lio_opcode: aio::IOCB_CMD_PWRITEV as u16,
            aio_buf: iovecs.as_ptr() as u64,
            aio_nbytes: iovecs.len() as u64,
            aio_offset: offset as _,
            aio_data: user_data,
            aio_flags: aio::IOCB_FLAG_RESFD,
            aio_resfd: self.eventfd.as_raw_fd() as u32,
            ..Default::default()
        }];
        let _: usize = self
            .ctx
            .submit(&iocbs[..])
            .map_err(|e| (false, AsyncIoError::WriteVectored(e)))?;

        Ok(())
    }

    unsafe fn fsync(&mut self, fd: BorrowedDiskFd, user_data: u64) -> SubmitResult {
        // SAFETY: The file descriptor is guaranteed valid by AsRawFd.
        let iocbs = [&mut aio::IoControlBlock {
            aio_fildes: fd.as_raw_fd() as u32,
            aio_lio_opcode: aio::IOCB_CMD_FSYNC as u16,
            aio_data: user_data,
            aio_flags: aio::IOCB_FLAG_RESFD,
            aio_resfd: self.eventfd.as_raw_fd() as u32,
            ..Default::default()
        }];
        let _ = self
            .ctx
            .submit(&iocbs[..])
            .map_err(|e| (false, AsyncIoError::Fsync(e)))?;

        Ok(())
    }

    fn next_completed_request(&mut self) -> Option<InnerCompletion> {
        if self.completion_list.is_empty() {
            // Drain pending AIO completions batched into the same queue.
            let mut events = [aio::IoEvent::default(); 32];
            let rc = self.ctx.get_events(0, &mut events, None).unwrap();
            for event in &events[..rc] {
                self.completion_list.push_back(InnerCompletion {
                    user_data: event.data,
                    result: event.res.try_into().expect("kernel bug?"),
                });
            }
        }
        self.completion_list.pop_front()
    }

    unsafe fn punch_hole(
        &mut self,
        fd: BorrowedDiskFd,
        offset: u64,
        length: u64,
        user_data: u64,
    ) -> SubmitResult {
        // Linux AIO has no IOCB command for fallocate, so perform the operation
        // synchronously and signal completion via the completion list, matching
        // the pattern used by the sync backend (RawFileSync).
        let mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;
        // SAFETY: FFI call with valid arguments
        let result = unsafe {
            libc::fallocate(
                fd.as_raw_fd(),
                mode,
                offset as libc::off_t,
                length as libc::off_t,
            )
        };
        if result < 0 {
            return Err((
                false,
                AsyncIoError::PunchHole(std::io::Error::last_os_error()),
            ));
        }

        self.completion_list
            .push_back(InnerCompletion { user_data, result });
        self.eventfd.write(1).unwrap();

        Ok(())
    }

    unsafe fn write_zeroes(
        &mut self,
        fd: BorrowedDiskFd,
        offset: u64,
        length: u64,
        user_data: u64,
    ) -> SubmitResult {
        // Linux AIO has no IOCB command for fallocate, so perform the operation
        // synchronously and signal completion via the completion list, matching
        // the pattern used by the sync backend (RawFileSync).
        let mode = FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE;

        // SAFETY: FFI call with valid arguments
        let result = unsafe { libc::fallocate64(fd.as_raw_fd(), mode, offset as _, length as _) };
        if result < 0 {
            return Err((
                false,
                AsyncIoError::WriteZeroes(std::io::Error::last_os_error()),
            ));
        }

        self.completion_list
            .push_back(InnerCompletion { user_data, result });
        self.eventfd.write(1).unwrap();

        Ok(())
    }

    fn submit_batch_requests(
        &mut self,
        _fd: BorrowedDiskFd<'_>,
        batch_requests: Vec<crate::BatchRequest>,
        _requests: &mut std::collections::HashMap<u64, Option<super::IoBuf>>,
    ) -> Result<(), AsyncIoError> {
        assert!(batch_requests.is_empty(), "not supported");
        Ok(())
    }

    fn batch_requests_enabled(&self) -> bool {
        false
    }
}
