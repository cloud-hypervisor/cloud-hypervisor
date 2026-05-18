// Copyright © 2023 Intel Corporation
//
// Copyright © 2023 Crusoe Energy Systems LLC
//
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::os::fd::{AsRawFd, RawFd};

use log::warn;
use vmm_sys_util::aio;
use vmm_sys_util::eventfd::EventFd;

use super::common::{duplicate_user_data_error, errno_result, validate_batch};
use super::{AsyncIoCompletion, AsyncIoOperation};

/// Retained Linux AIO queue for owned async data I/O operations.
///
/// Submitted operations are kept in `pending` until their completion event is
/// consumed so the iovec pointers handed to the kernel remain valid for the
/// full lifetime of the operation.
pub struct AioDataIo {
    // Keep this before `pending`: Rust drops fields in declaration order, so
    // dropping the context destroys kernel AIO state before retained
    // operations release the buffers referenced by their iovecs.
    ctx: aio::IoContext,
    // The `EventFd` for completion signals.
    eventfd: EventFd,
    // `in_flight` tracks user_data values accepted by the kernel submission
    // path, including metadata operations that do not retain a buffer.
    in_flight: HashSet<u64>,
    // `pending` owns read/write operations until their events are consumed so
    // their iovecs and backing buffers remain valid while the kernel may use
    // them.
    pending: HashMap<u64, AsyncIoOperation>,
    // `completions` holds locally produced completions and kernel events that
    // have been fetched but not yet returned to the caller.
    completions: VecDeque<AsyncIoCompletion>,
}

impl AioDataIo {
    /// Creates a Linux AIO context and its completion eventfd.
    pub fn new(queue_depth: u32) -> io::Result<Self> {
        Ok(Self {
            ctx: aio::IoContext::new(queue_depth)?,
            eventfd: EventFd::new(libc::EFD_NONBLOCK)?,
            in_flight: HashSet::new(),
            pending: HashMap::new(),
            completions: VecDeque::new(),
        })
    }

    /// Returns the eventfd signaled when completions are available.
    pub fn notifier(&self) -> &EventFd {
        &self.eventfd
    }

    #[allow(unused_unsafe)]
    fn submit_iocbs(ctx: &aio::IoContext, iocbs: &[&mut aio::IoControlBlock]) -> io::Result<usize> {
        // SAFETY: vmm_sys_util currently marks IoContext::submit safe, but
        // io_submit consumes raw pointers asynchronously. Callers must ensure
        // all iovec and buffer memory referenced by each iocb remains valid
        // until completion or failed submission.
        unsafe { ctx.submit(iocbs) }
    }

    /// Submits one owned read or write operation to the queue.
    ///
    /// Submission failures are converted into injected completions so callers
    /// can observe every accepted request through the normal completion path.
    pub fn submit_operation(&mut self, fd: RawFd, op: AsyncIoOperation) -> io::Result<()> {
        validate_batch(
            |user_data| self.in_flight.contains(&user_data),
            std::slice::from_ref(&op),
        )?;

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
            aio_resfd: self.eventfd.as_raw_fd() as u32,
            ..Default::default()
        };
        self.in_flight.insert(user_data);
        self.pending.insert(user_data, op);

        let result = match Self::submit_iocbs(&self.ctx, &[&mut iocb]) {
            Ok(1) => return Ok(()),
            Ok(_) => -libc::EAGAIN,
            Err(e) => errno_result(&e),
        };

        let buffer = self
            .pending
            .remove(&user_data)
            .and_then(AsyncIoOperation::into_completion_buffer);
        self.in_flight.remove(&user_data);
        self.inject_completion(AsyncIoCompletion::new(user_data, result, buffer));
        Ok(())
    }

    /// Submits an fsync operation carrying `user_data`.
    pub fn submit_fsync(&mut self, fd: RawFd, user_data: u64) -> io::Result<()> {
        if self.in_flight.contains(&user_data) {
            return Err(duplicate_user_data_error(user_data));
        }

        let mut iocb = aio::IoControlBlock {
            aio_fildes: fd.as_raw_fd() as u32,
            aio_lio_opcode: aio::IOCB_CMD_FSYNC as u16,
            aio_data: user_data,
            aio_flags: aio::IOCB_FLAG_RESFD,
            aio_resfd: self.eventfd.as_raw_fd() as u32,
            ..Default::default()
        };
        self.in_flight.insert(user_data);
        let result = match Self::submit_iocbs(&self.ctx, &[&mut iocb]) {
            Ok(1) => return Ok(()),
            Ok(_) => -libc::EAGAIN,
            Err(e) => errno_result(&e),
        };

        self.in_flight.remove(&user_data);
        self.inject_completion(AsyncIoCompletion::new(user_data, result, None));
        Ok(())
    }

    /// Injects a completion that did not come from a kernel AIO event.
    ///
    /// The notifier is signaled so callers can drain it with
    /// [`Self::next_completion`].
    pub fn inject_completion(&mut self, completion: AsyncIoCompletion) {
        self.completions.push_back(completion);
        self.eventfd.write(1).unwrap();
    }

    /// Returns the next kernel or injected completion if one is available.
    ///
    /// Consuming a kernel completion returns ownership of any buffer retained
    /// by the corresponding operation.
    pub fn next_completion(&mut self) -> Option<AsyncIoCompletion> {
        if self.completions.is_empty() {
            let mut events = [aio::IoEvent::default(); 32];
            let rc = match self.ctx.get_events(0, &mut events, None) {
                Ok(rc) => rc,
                Err(e) => {
                    warn!("Linux AIO get_events failed: {e}");
                    return None;
                }
            };
            for event in &events[..rc] {
                self.in_flight.remove(&event.data);
                self.completions.push_back(AsyncIoCompletion::new(
                    event.data,
                    event.res as i32,
                    self.pending
                        .remove(&event.data)
                        .and_then(AsyncIoOperation::into_completion_buffer),
                ));
            }
        }

        self.completions.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
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
            std::io::ErrorKind::AlreadyExists
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
