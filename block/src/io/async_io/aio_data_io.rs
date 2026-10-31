// Copyright © 2023 Intel Corporation
//
// Copyright © 2023 Crusoe Energy Systems LLC
//
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::collections::{HashMap, VecDeque};
use std::os::fd::{AsRawFd, RawFd};
use std::{io, slice};

use log::warn;
use vmm_sys_util::aio;
use vmm_sys_util::eventfd::EventFd;

use super::common::{duplicate_user_data_error, errno_result, validate_batch};
use super::{AsyncIoCompletion, AsyncIoOperation, CompletionCommon};

/// An operation queued because the AIO context was full.
///
/// `Data` keeps the operation (and the buffers its iovecs point into) alive
/// until submission succeeds; `Fsync` carries only its `user_data` (no
/// caller-owned buffer).
enum PendingOp {
    Data(AsyncIoOperation),
    Fsync { user_data: u64 },
}

impl PendingOp {
    fn user_data(&self) -> u64 {
        match self {
            PendingOp::Data(op) => op.user_data(),
            PendingOp::Fsync { user_data } => *user_data,
        }
    }
}

/// Retained Linux AIO queue for owned async data I/O operations.
pub struct AioDataIo {
    // Keep this before `in_flight` and `pending`: Rust drops fields in
    // declaration order, so dropping the context destroys kernel AIO state
    // before retained operations release the buffers referenced by their
    // iovecs. Queued (`pending`) operations were never submitted, so their
    // buffers are plain memory and safe to drop at any point.
    ctx: aio::IoContext,
    // `in_flight` tracks every user_data value accepted by the kernel. Owned
    // data operations store `Some(op)` so their iovecs and backing buffers
    // remain valid until completion; metadata operations store `None`.
    in_flight: HashMap<u64, Option<AsyncIoOperation>>,
    // `pending` holds operations accepted but not yet submitted because the
    // AIO context was full. next_completion() retries them once reaped events
    // free context slots. Queued operations are never completed with `-EAGAIN`,
    // which callers such as virtio-blk would surface to the guest as a hard
    // I/O error (same class of bug as the io_uring submission queue, fixed in
    // cloud-hypervisor#9228).
    pending: VecDeque<(RawFd, PendingOp)>,
    completions: CompletionCommon,
}

impl AioDataIo {
    /// Creates a Linux AIO context and its completion eventfd.
    pub fn new(queue_depth: u32) -> io::Result<Self> {
        Ok(Self {
            ctx: aio::IoContext::new(queue_depth)?,
            in_flight: HashMap::new(),
            pending: VecDeque::new(),
            completions: CompletionCommon::new(),
        })
    }

    /// Returns the eventfd signaled when completions are available.
    pub fn notifier(&self) -> &EventFd {
        self.completions.notifier()
    }

    fn is_tracked(&self, user_data: u64) -> bool {
        self.in_flight.contains_key(&user_data)
            || self
                .pending
                .iter()
                .any(|(_, entry)| entry.user_data() == user_data)
    }

    /// Submits one owned read or write operation to the queue.
    ///
    /// If the AIO context is full, the operation is queued and submitted once
    /// reaped events free capacity (see [`Self::next_completion`]). It is never
    /// completed with `-EAGAIN`, which callers such as virtio-blk would
    /// surface to the guest as a hard I/O error.
    pub fn submit_operation(&mut self, fd: RawFd, op: AsyncIoOperation) -> io::Result<()> {
        validate_batch(|user_data| self.is_tracked(user_data), slice::from_ref(&op))?;

        self.pending.push_back((fd, PendingOp::Data(op)));
        self.flush_pending();
        Ok(())
    }

    /// Submits an fsync operation carrying `user_data`.
    pub fn submit_fsync(&mut self, fd: RawFd, user_data: u64) -> io::Result<()> {
        if self.is_tracked(user_data) {
            return Err(duplicate_user_data_error(user_data));
        }

        self.pending
            .push_back((fd, PendingOp::Fsync { user_data }));
        self.flush_pending();
        Ok(())
    }

    /// Submits queued operations while the AIO context has free slots.
    ///
    /// Called when operations are queued and after events are reaped in
    /// [`Self::next_completion`], which is when context capacity is expected
    /// to have freed up.
    fn flush_pending(&mut self) {
        while let Some((fd, entry)) = self.pending.pop_front() {
            match entry {
                PendingOp::Data(op) => {
                    let user_data = op.user_data();
                    match self.submit_data_iocb(fd, &op) {
                        Ok(true) => {
                            self.in_flight.insert(user_data, Some(op));
                        }
                        Ok(false) => {
                            // Context full again: requeue and wait for the
                            // next reaped event to free a slot.
                            self.pending.push_front((fd, PendingOp::Data(op)));
                            return;
                        }
                        Err(result) => {
                            let buffer = op.into_completion_buffer();
                            self.completions
                                .complete(AsyncIoCompletion::new(user_data, result, buffer));
                        }
                    }
                }
                PendingOp::Fsync { user_data } => match self.submit_fsync_iocb(fd, user_data) {
                    Ok(true) => {
                        self.in_flight.insert(user_data, None);
                    }
                    Ok(false) => {
                        self.pending
                            .push_front((fd, PendingOp::Fsync { user_data }));
                        return;
                    }
                    Err(result) => {
                        self.completions
                            .complete(AsyncIoCompletion::new(user_data, result, None));
                    }
                },
            }
        }
    }

    /// Attempts one data-operation AIO submission.
    ///
    /// Ok(true) — accepted by the kernel (the caller must track `user_data`
    /// in `in_flight` so the buffers outlive the in-flight request);
    /// Ok(false) — context full, retry later; Err(result) — any other
    /// failure, surfaced through the completion path as before.
    fn submit_data_iocb(&mut self, fd: RawFd, op: &AsyncIoOperation) -> Result<bool, i32> {
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
            aio_data: op.user_data(),
            aio_flags: aio::IOCB_FLAG_RESFD,
            aio_resfd: self.completions.notifier().as_raw_fd() as u32,
            ..Default::default()
        };
        self.submit_result(&mut iocb)
    }

    /// Attempts one fsync AIO submission (see [`Self::submit_data_iocb`]).
    fn submit_fsync_iocb(&mut self, fd: RawFd, user_data: u64) -> Result<bool, i32> {
        let mut iocb = aio::IoControlBlock {
            aio_fildes: fd.as_raw_fd() as u32,
            aio_lio_opcode: aio::IOCB_CMD_FSYNC as u16,
            aio_data: user_data,
            aio_flags: aio::IOCB_FLAG_RESFD,
            aio_resfd: self.completions.notifier().as_raw_fd() as u32,
            ..Default::default()
        };
        self.submit_result(&mut iocb)
    }

    /// Ok(true) = submitted; Ok(false) = context full (EAGAIN); Err = other errno.
    fn submit_result(&mut self, iocb: &mut aio::IoControlBlock) -> Result<bool, i32> {
        match self.ctx.submit(&[iocb]) {
            Ok(1) => Ok(true),
            // Zero submissions and an explicit EAGAIN both mean the context is
            // full; previously both were completed as -EAGAIN.
            Ok(_) => Ok(false),
            Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => Ok(false),
            Err(e) => Err(errno_result(&e)),
        }
    }

    /// Injects a completion that did not come from a kernel AIO event.
    ///
    /// The notifier is signaled so callers can drain it with
    /// [`Self::next_completion`].
    pub fn inject_completion(&mut self, completion: AsyncIoCompletion) {
        self.completions.complete(completion);
    }

    /// Returns the next kernel or injected completion if one is available.
    ///
    /// Consuming a kernel completion returns ownership of any buffer retained
    /// by the corresponding operation. Reaped events also free AIO context
    /// slots, so queued submissions are retried before reporting that nothing
    /// is available.
    pub fn next_completion(&mut self) -> Option<AsyncIoCompletion> {
        if let Some(completion) = self.completions.next_completed() {
            return Some(completion);
        }

        let mut events = [aio::IoEvent::default(); 32];
        let rc = match self.ctx.get_events(0, &mut events, None) {
            Ok(rc) => rc,
            Err(e) => {
                warn!("Linux AIO get_events failed: {e}");
                return None;
            }
        };
        for event in &events[..rc] {
            self.completions.complete(AsyncIoCompletion::new(
                event.data,
                event.res as i32,
                self.in_flight
                    .remove(&event.data)
                    .flatten()
                    .and_then(AsyncIoOperation::into_completion_buffer),
            ));
        }

        self.flush_pending();

        self.completions.next_completed()
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

    #[test]
    fn aio_queues_submissions_when_context_is_full() {
        let mut file = TempFile::new().unwrap().into_file();
        file.write_all(&[0xa5; 1024]).unwrap();
        let fd = file.as_raw_fd();
        // Depth-1 context: the second submission cannot fit until the first
        // completion is reaped, no matter how fast the first read completes.
        let mut data_io = AioDataIo::new(1).unwrap();

        data_io
            .submit_operation(
                fd,
                AsyncIoOperation::read_to_vec(0, OwnedIoBuffer::from_vec(vec![0; 512]), 7),
            )
            .unwrap();
        data_io
            .submit_operation(
                fd,
                AsyncIoOperation::read_to_vec(512, OwnedIoBuffer::from_vec(vec![0; 512]), 8),
            )
            .unwrap();

        // Both operations must complete with their real results; neither may
        // surface -EAGAIN (the pre-#9228 behavior queued nothing and handed
        // the backpressure signal to virtio-blk as VIRTIO_BLK_S_IOERR).
        let first = wait_for_completion(&mut data_io);
        assert_eq!(first.user_data, 7);
        assert_eq!(first.result, 512);
        let second = wait_for_completion(&mut data_io);
        assert_eq!(second.user_data, 8);
        assert_eq!(second.result, 512);
        assert_eq!(second.buffer.unwrap().as_slice(), [0xa5; 512]);
        assert!(data_io.next_completion().is_none());
    }

    #[test]
    fn aio_rejects_duplicate_user_data_while_queued() {
        let mut file = TempFile::new().unwrap().into_file();
        file.write_all(&[0xa5; 512]).unwrap();
        let fd = file.as_raw_fd();
        let mut data_io = AioDataIo::new(1).unwrap();

        data_io
            .submit_operation(
                fd,
                AsyncIoOperation::read_to_vec(0, OwnedIoBuffer::from_vec(vec![0; 512]), 7),
            )
            .unwrap();
        // The first operation is in flight or queued: the same user_data must
        // be rejected on either path.
        assert_eq!(
            data_io
                .submit_operation(
                    fd,
                    AsyncIoOperation::read_to_vec(0, OwnedIoBuffer::from_vec(vec![0; 512]), 7),
                )
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );

        wait_for_completion(&mut data_io);
    }
}
