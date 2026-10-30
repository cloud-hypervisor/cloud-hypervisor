// Copyright © 2021 Intel Corporation
//
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::collections::{HashMap, VecDeque};
use std::os::fd::{AsRawFd, RawFd};
use std::{io, mem};

use io_uring::register::Restriction;
use io_uring::{IoUring, opcode, squeue, types};
use log::{error, warn};
use vmm_sys_util::eventfd::EventFd;

use super::common::{duplicate_user_data_error, validate_batch};
use super::{AsyncIoCompletion, AsyncIoOperation, CompletionCommon};

// Linux UAPI constant for enabling a ring created with IORING_SETUP_R_DISABLED
const IORING_REGISTER_ENABLE_RINGS: u8 = 12;

/// `io_uring` wrapper for async I/O.
///
/// Holds the `IoUring` and tracks the ops that are pending.
pub struct UringDataIo {
    io_uring: IoUring,
    // `in_flight` tracks every user_data value accepted by the kernel. Owned
    // data operations store `Some(op)` so their iovecs and backing buffers
    // remain valid until completion; metadata operations store `None`.
    in_flight: HashMap<u64, Option<AsyncIoOperation>>,
    // `pending` holds operations accepted but not yet published to the
    // submission queue because it was full. Completion processing publishes
    // them as ring capacity frees up.
    pending: VecDeque<(RawFd, AsyncIoOperation)>,
    completions: CompletionCommon,
    // `needs_submit_retry` is set when SQEs have been published to the ring,
    // but the submit syscall failed (or only partially succeeded) before
    // confirming kernel ownership.
    needs_submit_retry: bool,
}

impl UringDataIo {
    /// Creates an io_uring queue and registers its completion eventfd.
    pub fn new(ring_depth: u32) -> io::Result<Self> {
        let io_uring = IoUring::builder().setup_r_disabled().build(ring_depth)?;
        let completions = CompletionCommon::new();
        io_uring
            .submitter()
            .register_eventfd(completions.notifier().as_raw_fd())?;

        io_uring.submitter().register_restrictions(&mut [
            Restriction::register_op(IORING_REGISTER_ENABLE_RINGS),
            Restriction::sqe_op(opcode::Nop::CODE),
            Restriction::sqe_op(opcode::Readv::CODE),
            Restriction::sqe_op(opcode::Writev::CODE),
            Restriction::sqe_op(opcode::Fsync::CODE),
            Restriction::sqe_flags_allowed(0),
        ])?;
        io_uring.submitter().register_enable_rings()?;

        Ok(Self {
            io_uring,
            in_flight: HashMap::new(),
            pending: VecDeque::new(),
            completions,
            needs_submit_retry: false,
        })
    }

    /// Returns the eventfd signaled when completions are available.
    pub fn notifier(&self) -> &EventFd {
        self.completions.notifier()
    }

    /// Submits one owned read or write operation to the queue.
    pub fn submit_operation(&mut self, fd: RawFd, op: AsyncIoOperation) -> io::Result<()> {
        self.submit_batch(fd, vec![op])
    }

    fn reserve_user_data(&mut self, user_data: u64) -> io::Result<()> {
        if self.in_flight.contains_key(&user_data)
            || self
                .pending
                .iter()
                .any(|(_, op)| op.user_data() == user_data)
        {
            return Err(duplicate_user_data_error(user_data));
        }
        self.in_flight.insert(user_data, None);

        Ok(())
    }

    fn submit_kernel_entry(&mut self, user_data: u64, entry: &squeue::Entry) -> io::Result<()> {
        self.reserve_user_data(user_data)?;

        let (submitter, mut sq, _) = self.io_uring.split();
        // SAFETY: the entry has no caller-owned buffer. `user_data` is retained
        // in `in_flight` until the CQE is consumed.
        if let Err(e) = unsafe { sq.push(entry) } {
            self.in_flight.remove(&user_data);
            return Err(io::Error::other(format!("Submission queue is full: {e:?}")));
        }
        sq.sync();

        match submitter.submit() {
            Ok(_) => {
                // A partial submission leaves the remaining SQEs published;
                // they are retried from next_completion().
                self.needs_submit_retry = !sq.is_empty();
            }
            Err(e) => {
                self.needs_submit_retry = true;
                warn!("io_uring submit failed after SQE was published: {e}");
                self.completions.notifier().write(1).unwrap();
            }
        }

        Ok(())
    }

    /// Submits a batch of owned read and write operations.
    ///
    /// If the io_uring submission queue cannot accept the whole batch, the
    /// operations that do not fit are queued and published once ring capacity
    /// becomes available (see [`Self::next_completion`]). They are never
    /// completed with `-EAGAIN`, which callers such as virtio-blk would
    /// surface to the guest as a hard I/O error.
    pub fn submit_batch(&mut self, fd: RawFd, batch: Vec<AsyncIoOperation>) -> io::Result<()> {
        if batch.is_empty() {
            return Ok(());
        }

        validate_batch(
            |user_data| {
                self.in_flight.contains_key(&user_data)
                    || self
                        .pending
                        .iter()
                        .any(|(_, op)| op.user_data() == user_data)
            },
            &batch,
        )?;

        self.pending.extend(batch.into_iter().map(|op| (fd, op)));
        self.flush_pending();

        Ok(())
    }

    /// Publishes queued operations while the submission queue has room.
    ///
    /// Called when operations are queued and whenever completions are reaped,
    /// which is when ring capacity is expected to have freed up.
    fn flush_pending(&mut self) {
        while !self.pending.is_empty() {
            let (submitter, mut sq, _) = self.io_uring.split();
            let available = sq.capacity() - sq.len();
            if available == 0 {
                // The ring is still full. next_completion() retries once
                // in-flight operations have completed.
                return;
            }

            let mut queued = 0;
            while queued < available {
                let Some((fd, op)) = self.pending.pop_front() else {
                    break;
                };
                let user_data = op.user_data();
                let entry = Self::build_entry(fd, &op);
                self.in_flight.insert(user_data, Some(op));
                // SAFETY: the SQ capacity was checked above. Every iovec's
                // pointer is retained in self.in_flight before the SQ tail is
                // advanced by sync or drop. in_flight only drops the memory
                // after a completion.
                if let Err(e) = unsafe { sq.push(&entry) } {
                    // The ring state changed unexpectedly after the capacity
                    // check. Requeue the operation and retry it later.
                    let op = self.in_flight.remove(&user_data).flatten().unwrap();
                    self.pending.push_front((fd, op));
                    warn!("io_uring submission queue became full after capacity check: {e:?}");
                    break;
                }
                queued += 1;
            }

            if queued == 0 {
                return;
            }

            sq.sync();
            match submitter.submit() {
                Ok(_) => {
                    // A partial submission leaves the remaining SQEs
                    // published; they are retried from next_completion().
                    self.needs_submit_retry = !sq.is_empty();
                }
                Err(e) => {
                    self.needs_submit_retry = true;
                    warn!("io_uring submit failed after SQEs were published: {e}");
                    self.completions.notifier().write(1).unwrap();
                }
            }

            if self.needs_submit_retry {
                return;
            }
        }
    }

    fn build_entry(fd: RawFd, op: &AsyncIoOperation) -> squeue::Entry {
        let iovecs = op.iovecs();
        let fd = types::Fd(fd);
        if op.is_read() {
            opcode::Readv::new(fd, iovecs.as_ptr(), iovecs.len() as u32)
                .offset(op.offset() as u64)
                .build()
                .user_data(op.user_data())
        } else {
            opcode::Writev::new(fd, iovecs.as_ptr(), iovecs.len() as u32)
                .offset(op.offset() as u64)
                .build()
                .user_data(op.user_data())
        }
    }

    /// Submits an io_uring NOP carrying `user_data`.
    pub fn submit_nop(&mut self, user_data: u64) -> io::Result<()> {
        self.submit_kernel_entry(user_data, &opcode::Nop::new().build().user_data(user_data))
    }

    /// Submits an fsync operation carrying `user_data`.
    pub fn submit_fsync(&mut self, fd: RawFd, user_data: u64) -> io::Result<()> {
        self.submit_kernel_entry(
            user_data,
            &opcode::Fsync::new(types::Fd(fd))
                .build()
                .user_data(user_data),
        )
    }

    /// Injects a completion that did not come from a kernel CQE.
    ///
    /// The notifier is signaled so callers can drain it with
    /// [`Self::next_completion`].
    pub fn inject_completion(&mut self, completion: AsyncIoCompletion) {
        self.completions.complete(completion);
    }

    /// Returns the next kernel or injected completion if one is available.
    ///
    /// Consuming a kernel completion returns ownership of any buffer retained
    /// by the corresponding operation.
    pub fn next_completion(&mut self) -> Option<AsyncIoCompletion> {
        if self.needs_submit_retry {
            let submit_result = self.io_uring.submitter().submit();
            match submit_result {
                Ok(_) => {
                    if self.io_uring.submission().is_empty() {
                        self.needs_submit_retry = false;
                    }
                }
                Err(e) => warn!("io_uring retry submit failed for retained SQEs: {e}"),
            }
        }

        // Publish operations that were deferred because the submission queue
        // was full. Completions are exactly when capacity is expected to free
        // up again.
        self.flush_pending();

        if let Some(entry) = self.io_uring.completion().next() {
            let user_data = entry.user_data();
            return Some(AsyncIoCompletion::new(
                user_data,
                entry.result(),
                self.in_flight
                    .remove(&user_data)
                    .flatten()
                    .and_then(AsyncIoOperation::into_completion_buffer),
            ));
        }

        self.completions.next_completed()
    }
}

impl Drop for UringDataIo {
    fn drop(&mut self) {
        // Operations still waiting for submission queue capacity never reached
        // the kernel; dropping them releases their buffers.
        // Closing the ring fd does not cancel io_uring ops that have started.
        // Wait for CQEs before releasing retained iovecs.
        if self.needs_submit_retry {
            if let Err(e) = self.io_uring.submitter().submit() {
                warn!("io_uring drain submit failed for retained SQEs: {e}");
            }
            self.needs_submit_retry = false;
        }

        let max_drain_iterations = self.in_flight.len().saturating_mul(2);
        let mut drain_iterations = 0;
        while !self.in_flight.is_empty() {
            if drain_iterations == max_drain_iterations {
                error!(
                    "io_uring drain abandoned with {} operations still in flight after {} drain iterations",
                    self.in_flight.len(),
                    drain_iterations
                );
                // Keep retained buffers mapped if the ring cannot be drained.
                mem::forget(mem::take(&mut self.in_flight));
                break;
            }
            drain_iterations += 1;

            if let Some(entry) = self.io_uring.completion().next() {
                self.in_flight.remove(&entry.user_data());
                continue;
            }

            // No completion ready: block in the kernel until at least one is.
            if let Err(e) = self.io_uring.submitter().submit_and_wait(1) {
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                error!(
                    "io_uring drain abandoned with {} operations still in flight: {e}",
                    self.in_flight.len()
                );
                // Keep retained buffers mapped if the ring cannot be drained.
                mem::forget(mem::take(&mut self.in_flight));
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::thread::sleep;
    use std::time::Duration;
    use std::{io, ptr};

    use io_uring::{opcode, squeue, types};
    use vmm_sys_util::tempfile::TempFile;

    use super::UringDataIo;
    use crate::async_io::{AsyncIoCompletion, AsyncIoOperation, OwnedIoBuffer};

    fn wait_for_completion(data_io: &mut UringDataIo) -> AsyncIoCompletion {
        for _ in 0..1000 {
            if let Some(completion) = data_io.next_completion() {
                return completion;
            }
            sleep(Duration::from_millis(1));
        }

        panic!("timed out waiting for io_uring completion");
    }

    #[test]
    fn uring_rejects_socket_operations() {
        let mut data_io = UringDataIo::new(8).unwrap();
        let socket = opcode::Socket::new(libc::AF_UNIX, libc::SOCK_STREAM, 0)
            .build()
            .user_data(1);
        data_io.submit_kernel_entry(1, &socket).unwrap();
        let completion = wait_for_completion(&mut data_io);
        if completion.result >= 0 {
            // SAFETY: IORING_OP_SOCKET returned a new owned descriptor.
            drop(unsafe { OwnedFd::from_raw_fd(completion.result) });
        }
        assert_eq!(completion.result, -libc::EACCES);

        let connect = opcode::Connect::new(types::Fd(-1), ptr::null(), 0)
            .build()
            .user_data(2);
        data_io.submit_kernel_entry(2, &connect).unwrap();
        assert_eq!(wait_for_completion(&mut data_io).result, -libc::EACCES);
    }

    #[test]
    fn uring_rejects_sqe_flags() {
        let mut data_io = UringDataIo::new(8).unwrap();
        let nop = opcode::Nop::new()
            .build()
            .flags(squeue::Flags::ASYNC)
            .user_data(1);
        data_io.submit_kernel_entry(1, &nop).unwrap();
        assert_eq!(wait_for_completion(&mut data_io).result, -libc::EACCES);

        data_io.submit_nop(2).unwrap();
        assert_eq!(wait_for_completion(&mut data_io).result, 0);
    }

    #[test]
    fn uring_rejects_registration_changes() {
        let data_io = UringDataIo::new(8).unwrap();
        assert_eq!(
            data_io
                .io_uring
                .submitter()
                .register_eventfd(data_io.notifier().as_raw_fd())
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EACCES)
        );
    }

    #[test]
    fn uring_rejects_duplicate_user_data_for_metadata_ops() {
        let file = TempFile::new().unwrap().into_file();
        file.set_len(512).unwrap();
        let fd = file.as_raw_fd();
        let mut data_io = UringDataIo::new(8).unwrap();

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
        assert_eq!(
            data_io.submit_nop(7).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );

        let completion = wait_for_completion(&mut data_io);
        assert_eq!(completion.user_data, 7);
        assert_eq!(completion.result, 512);
    }

    #[test]
    fn uring_drop_drains_in_flight_operations() {
        let file = TempFile::new().unwrap().into_file();
        file.set_len(8192).unwrap();
        let fd = file.as_raw_fd();
        let mut data_io = UringDataIo::new(8).unwrap();

        for user_data in 0..4 {
            data_io
                .submit_operation(
                    fd,
                    AsyncIoOperation::read_to_vec(
                        0,
                        OwnedIoBuffer::from_vec(vec![0; 512]),
                        user_data,
                    ),
                )
                .unwrap();
        }

        drop(data_io);
    }

    #[test]
    fn uring_queue_full_batch_is_deferred_not_failed() {
        let file = TempFile::new().unwrap().into_file();
        file.set_len(512).unwrap();
        let fd = file.as_raw_fd();
        let mut data_io = UringDataIo::new(1).unwrap();
        let available = {
            let (_, sq, _) = data_io.io_uring.split();
            sq.capacity() - sq.len()
        };
        let batch_len = available + 1;
        let batch: Vec<_> = (0..batch_len as u64)
            .map(|user_data| {
                AsyncIoOperation::read_to_vec(0, OwnedIoBuffer::from_vec(vec![0; 512]), user_data)
            })
            .collect();

        data_io.submit_batch(fd, batch).unwrap();

        // Operations that did not fit must not be failed with -EAGAIN: they
        // stay queued and are submitted once ring capacity frees up, so every
        // request completes normally.
        let mut completed = Vec::new();
        for _ in 0..(batch_len * 8) {
            while let Some(completion) = data_io.next_completion() {
                assert_eq!(completion.result, 512);
                assert!(completion.buffer.is_some());
                completed.push(completion.user_data);
            }
            if completed.len() == batch_len {
                break;
            }
            sleep(Duration::from_millis(1));
        }
        completed.sort_unstable();
        assert_eq!(completed, (0..batch_len as u64).collect::<Vec<_>>());
    }

    #[test]
    fn uring_rejects_duplicate_user_data_while_pending() {
        let mut data_io = UringDataIo::new(1).unwrap();
        // Simulate an operation that could not be published to the ring yet.
        data_io.pending.push_back((
            0,
            AsyncIoOperation::read_to_vec(0, OwnedIoBuffer::from_vec(vec![0; 512]), 7),
        ));

        let duplicate = AsyncIoOperation::read_to_vec(0, OwnedIoBuffer::from_vec(vec![0; 512]), 7);
        assert_eq!(
            data_io.submit_batch(0, vec![duplicate]).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
    }
}
