// Copyright © 2023 Intel Corporation
//
// Copyright © 2023 Crusoe Energy Systems LLC
//
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::os::fd::{AsRawFd, RawFd};
use std::{io, slice};

use log::warn;
use vmm_sys_util::aio;
use vmm_sys_util::eventfd::EventFd;

use super::async_io_core::AsyncIoCore;
use super::common::{duplicate_user_data_error, errno_result};
use super::{AsyncIoCompletion, AsyncIoOperation};

/// Retained Linux AIO queue for owned async data I/O operations.
pub struct AioDataIo {
    // Keep `ctx` before `core`. Rust drops fields in declaration order, so
    // dropping the AIO context destroys kernel AIO state before `core`
    // releases the retained operations whose iovecs reference the backing
    // buffers.
    ctx: aio::IoContext,
    core: AsyncIoCore,
}

impl AioDataIo {
    /// Creates a Linux AIO context and its completion eventfd.
    pub fn new(queue_depth: u32) -> io::Result<Self> {
        Ok(Self {
            ctx: aio::IoContext::new(queue_depth)?,
            core: AsyncIoCore::new()?,
        })
    }

    /// Returns the eventfd signaled when completions are available.
    pub fn notifier(&self) -> &EventFd {
        self.core.notifier()
    }

    /// Submits one owned read or write operation to the queue.
    ///
    /// Submission failures are converted into injected completions so callers
    /// can observe every accepted request through the normal completion path.
    pub fn submit_operation(&mut self, fd: RawFd, op: AsyncIoOperation) -> io::Result<()> {
        self.core.validate_batch(slice::from_ref(&op))?;

        let user_data = op.user_data();
        let iovecs = op.iovecs();
        let opcode = if op.is_read() {
            aio::IOCB_CMD_PREADV
        } else {
            aio::IOCB_CMD_PWRITEV
        };
        let mut iocb = aio::IoControlBlock {
            aio_fildes: fd.as_raw_fd() as u32,
            aio_lio_opcode: opcode as u16,
            aio_buf: iovecs.as_ptr() as u64,
            aio_nbytes: iovecs.len() as u64,
            aio_offset: op.offset(),
            aio_data: user_data,
            aio_flags: aio::IOCB_FLAG_RESFD,
            aio_resfd: self.core.eventfd_raw() as u32,
            ..Default::default()
        };
        self.core.track(user_data, Some(op));

        let result = match self.ctx.submit(&[&mut iocb]) {
            Ok(1) => return Ok(()),
            Ok(_) => -libc::EAGAIN,
            Err(e) => errno_result(&e),
        };

        let buffer = self
            .core
            .take(user_data)
            .and_then(AsyncIoOperation::into_completion_buffer);
        self.core
            .inject_completion(AsyncIoCompletion::new(user_data, result, buffer));
        Ok(())
    }

    /// Submits an fsync operation carrying `user_data`.
    pub fn submit_fsync(&mut self, fd: RawFd, user_data: u64) -> io::Result<()> {
        if self.core.is_in_flight(user_data) {
            return Err(duplicate_user_data_error(user_data));
        }

        let mut iocb = aio::IoControlBlock {
            aio_fildes: fd.as_raw_fd() as u32,
            aio_lio_opcode: aio::IOCB_CMD_FSYNC as u16,
            aio_data: user_data,
            aio_flags: aio::IOCB_FLAG_RESFD,
            aio_resfd: self.core.eventfd_raw() as u32,
            ..Default::default()
        };
        self.core.track(user_data, None);
        let result = match self.ctx.submit(&[&mut iocb]) {
            Ok(1) => return Ok(()),
            Ok(_) => -libc::EAGAIN,
            Err(e) => errno_result(&e),
        };

        self.core.take(user_data);
        self.core
            .inject_completion(AsyncIoCompletion::new(user_data, result, None));
        Ok(())
    }

    /// Injects a completion that did not come from a kernel AIO event.
    ///
    /// The notifier is signaled so callers can drain it with
    /// [`Self::next_completion`].
    pub fn inject_completion(&mut self, completion: AsyncIoCompletion) {
        self.core.inject_completion(completion);
    }

    /// Returns the next kernel or injected completion if one is available.
    ///
    /// Consuming a kernel completion returns ownership of any buffer retained
    /// by the corresponding operation.
    pub fn next_completion(&mut self) -> Option<AsyncIoCompletion> {
        if !self.core.has_completions() {
            let mut events = [aio::IoEvent::default(); 32];
            let rc = match self.ctx.get_events(0, &mut events, None) {
                Ok(rc) => rc,
                Err(e) => {
                    warn!("Linux AIO get_events failed: {e}");
                    return None;
                }
            };
            for event in &events[..rc] {
                let buffer = self
                    .core
                    .take(event.data)
                    .and_then(AsyncIoOperation::into_completion_buffer);
                self.core.enqueue_completion(AsyncIoCompletion::new(
                    event.data,
                    event.res as i32,
                    buffer,
                ));
            }
        }

        self.core.next_completion()
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};
    use std::os::fd::AsRawFd;
    use std::thread::sleep;
    use std::time::Duration;

    use vmm_sys_util::tempfile::TempFile;

    use super::AioDataIo;
    use crate::async_io::{AsyncIoCompletion, AsyncIoOperation, OwnedIoBuffer};

    fn wait_for_completion(data_io: &mut AioDataIo) -> AsyncIoCompletion {
        for _ in 0..1000 {
            if let Some(completion) = data_io.next_completion() {
                return completion;
            }
            sleep(Duration::from_millis(1));
        }

        panic!("timed out waiting for Linux AIO completion");
    }

    #[test]
    fn aio_rejects_duplicate_user_data_for_metadata_ops() {
        let mut file = TempFile::new().unwrap().into_file();
        file.write_all(&[0xa5; 512]).unwrap();
        let fd = file.as_raw_fd();
        let mut data_io = AioDataIo::new(8).unwrap();

        data_io
            .submit_operation(
                fd,
                AsyncIoOperation::read_to_vec(0, OwnedIoBuffer::from_vec(vec![0; 512]), 7),
            )
            .unwrap();

        assert_eq!(
            data_io.submit_fsync(fd, 7).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );

        let completion = wait_for_completion(&mut data_io);
        assert_eq!(completion.user_data, 7);
        assert_eq!(completion.result, 512);
        assert_eq!(
            completion.buffer.unwrap().as_slice(),
            [0xa5; 512].as_slice()
        );
    }

    #[test]
    fn aio_injected_completion_uses_completion_path() {
        let mut data_io = AioDataIo::new(8).unwrap();

        data_io.inject_completion(AsyncIoCompletion::new(9, -libc::EIO, None));

        let completion = data_io.next_completion().unwrap();
        assert_eq!(completion.user_data, 9);
        assert_eq!(completion.result, -libc::EIO);
        assert!(completion.buffer.is_none());
        assert!(data_io.next_completion().is_none());
    }
}
