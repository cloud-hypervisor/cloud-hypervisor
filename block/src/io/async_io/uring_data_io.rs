// Copyright © 2021 Intel Corporation
//
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::collections::{HashMap, VecDeque};
use std::os::fd::{AsRawFd, RawFd};
use std::{io, mem};

use io_uring::{IoUring, opcode, squeue, types};
use log::{error, warn};
use vmm_sys_util::eventfd::EventFd;

use super::common::{duplicate_user_data_error, validate_batch};
use super::{AsyncIoCompletion, AsyncIoOperation};

/// `io_uring` wrapper for async I/O.
///
/// Holds the `IoUring` and its `EventFd`. Tracks ops that are pending.
pub struct UringDataIo {
    io_uring: IoUring,
    // The `EventFd` for completion signals.
    eventfd: EventFd,
    // `in_flight` tracks every user_data value accepted by the kernel. Owned
    // data operations store `Some(op)` so their iovecs and backing buffers
    // remain valid until completion; metadata operations store `None`.
    in_flight: HashMap<u64, Option<AsyncIoOperation>>,
    // `injected` holds locally produced completions so synchronous failures
    // and short-circuited requests use the same drain path as kernel CQEs.
    injected: VecDeque<AsyncIoCompletion>,
    // `needs_submit_retry` is set when SQEs have been published to the ring,
    // but the submit syscall failed before confirming kernel ownership.
    needs_submit_retry: bool,
}

impl UringDataIo {
    /// Creates an io_uring queue and registers its completion eventfd.
    pub fn new(ring_depth: u32) -> io::Result<Self> {
        let io_uring = IoUring::new(ring_depth)?;
        let eventfd = EventFd::new(libc::EFD_NONBLOCK)?;
        io_uring.submitter().register_eventfd(eventfd.as_raw_fd())?;

        Ok(Self {
            io_uring,
            eventfd,
            in_flight: HashMap::new(),
            injected: VecDeque::new(),
            needs_submit_retry: false,
        })
    }

    /// Returns the eventfd signaled when completions are available.
    pub fn notifier(&self) -> &EventFd {
        &self.eventfd
    }

    /// Submits one owned read or write operation to the queue.
    pub fn submit_operation(&mut self, fd: RawFd, op: AsyncIoOperation) -> io::Result<()> {
        self.submit_batch(fd, vec![op])
    }

    fn reserve_user_data(&mut self, user_data: u64) -> io::Result<()> {
        if self.in_flight.contains_key(&user_data) {
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
            Ok(_) => self.needs_submit_retry = false,
            Err(e) => {
                self.needs_submit_retry = true;
                warn!("io_uring submit failed after SQE was published: {e}");
                self.eventfd.write(1).unwrap();
            }
        }

        Ok(())
    }

    /// Submits a batch of owned read and write operations.
    ///
    /// If the io_uring submission queue cannot accept the whole batch, each
    /// operation is completed locally with `-EAGAIN` so callers can observe
    /// every request through the normal completion path.
    pub fn submit_batch(&mut self, fd: RawFd, batch: Vec<AsyncIoOperation>) -> io::Result<()> {
        if batch.is_empty() {
            return Ok(());
        }

        validate_batch(|user_data| self.in_flight.contains_key(&user_data), &batch)?;

        let (submitter, mut sq, _) = self.io_uring.split();
        let available = sq.capacity() - sq.len();
        if batch.len() > available {
            // Not enough space for the batch.
            // Drop sq, which will re-publish an unmodified tail pointer
            drop(sq);
            for op in batch {
                self.injected
                    .push_back(AsyncIoCompletion::from_operation(op, -libc::EAGAIN));
            }
            self.eventfd.write(1).unwrap();
            return Ok(());
        }

        let mut signal_completion = false;
        let mut batch = batch.into_iter();
        while let Some(op) = batch.next() {
            let user_data = op.user_data();
            let entry = Self::build_entry(fd, &op);
            self.in_flight.insert(user_data, Some(op));

            // SAFETY: the SQ capacity was just checked. Every iovec's pointer is retained in
            // self.in_flight before the SQ tail is advanced by sync or drop. in_flight only
            // drops the memory after a completion.
            if let Err(e) = unsafe { sq.push(&entry) } {
                Self::handle_push_failure(
                    &mut self.in_flight,
                    &mut self.injected,
                    user_data,
                    batch.by_ref(),
                    &e,
                );
                signal_completion = true;
                break;
            }
        }

        sq.sync();
        match submitter.submit() {
            Ok(_) => self.needs_submit_retry = false,
            Err(e) => {
                self.needs_submit_retry = true;
                warn!("io_uring submit failed after SQEs were published: {e}");
                signal_completion = true;
            }
        }
        if signal_completion {
            self.eventfd.write(1).unwrap();
        }

        Ok(())
    }

    #[cold]
    fn handle_push_failure(
        in_flight: &mut HashMap<u64, Option<AsyncIoOperation>>,
        injected: &mut VecDeque<AsyncIoCompletion>,
        user_data: u64,
        remaining: impl Iterator<Item = AsyncIoOperation>,
        error: &squeue::PushError,
    ) {
        // Since capacity was just checked, this should only happen if the ring
        // state changed unexpectedly. Keep all affected operations memory safe
        // by returning local completions through the normal path.
        let op = in_flight
            .remove(&user_data)
            .flatten()
            .expect("pending operation missing after failed push");
        injected.push_back(AsyncIoCompletion::from_operation(op, -libc::EAGAIN));
        for op in remaining {
            injected.push_back(AsyncIoCompletion::from_operation(op, -libc::EAGAIN));
        }
        warn!("io_uring submission queue became full after capacity check: {error:?}");
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

    /// Submits a fallocate operation carrying `user_data`.
    pub fn submit_fallocate(
        &mut self,
        fd: RawFd,
        offset: u64,
        length: u64,
        mode: i32,
        user_data: u64,
    ) -> io::Result<()> {
        self.submit_kernel_entry(
            user_data,
            &opcode::Fallocate::new(types::Fd(fd), length)
                .offset(offset)
                .mode(mode)
                .build()
                .user_data(user_data),
        )
    }

    /// Injects a completion that did not come from a kernel CQE.
    ///
    /// The notifier is signaled so callers can drain it with
    /// [`Self::next_completion`].
    pub fn inject_completion(&mut self, completion: AsyncIoCompletion) {
        self.injected.push_back(completion);
        self.eventfd.write(1).unwrap();
    }

    /// Returns the next kernel or injected completion if one is available.
    ///
    /// Consuming a kernel completion returns ownership of any buffer retained
    /// by the corresponding operation.
    pub fn next_completion(&mut self) -> Option<AsyncIoCompletion> {
        if self.needs_submit_retry {
            match self.io_uring.submitter().submit() {
                Ok(_) => self.needs_submit_retry = false,
                Err(e) => warn!("io_uring retry submit failed for retained SQEs: {e}"),
            }
        }

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

        self.injected.pop_front()
    }
}

impl Drop for UringDataIo {
    fn drop(&mut self) {
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
    use std::io;
    use std::os::fd::AsRawFd;
    use std::thread::sleep;
    use std::time::Duration;

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
        assert_eq!(
            data_io
                .submit_fallocate(fd, 0, 512, 0, 7)
                .unwrap_err()
                .kind(),
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
    fn uring_queue_full_batch_completes_each_operation() {
        let file = TempFile::new().unwrap().into_file();
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

        let mut completed = Vec::new();
        while let Some(completion) = data_io.next_completion() {
            assert_eq!(completion.result, -libc::EAGAIN);
            assert!(completion.buffer.is_some());
            completed.push(completion.user_data);
        }
        completed.sort_unstable();
        assert_eq!(completed, (0..batch_len as u64).collect::<Vec<_>>());
    }
}
