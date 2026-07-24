// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, VecDeque};
use std::io;
#[cfg(feature = "io_uring")]
use std::mem;
use std::os::fd::{AsRawFd, RawFd};

use vmm_sys_util::eventfd::EventFd;

use super::common::validate_batch;
use super::{AsyncIoCompletion, AsyncIoOperation};

/// Completion queue and in flight map shared by the aio and uring
/// backends. The map retains each accepted operation so its buffers
/// stay valid until the kernel reports it.
///
/// SAFETY: the retained operations own memory the kernel touches
/// asynchronously, so a backend must drop its kernel handle before this
/// core. Declare the kernel handle field ahead of the `AsyncIoCore` field.
pub(super) struct AsyncIoCore {
    eventfd: EventFd,
    in_flight: HashMap<u64, Option<AsyncIoOperation>>,
    completions: VecDeque<AsyncIoCompletion>,
}

impl AsyncIoCore {
    pub(super) fn new() -> io::Result<Self> {
        Ok(Self {
            eventfd: EventFd::new(libc::EFD_NONBLOCK)?,
            in_flight: HashMap::new(),
            completions: VecDeque::new(),
        })
    }

    pub(super) fn notifier(&self) -> &EventFd {
        &self.eventfd
    }

    pub(super) fn eventfd_raw(&self) -> RawFd {
        self.eventfd.as_raw_fd()
    }

    #[cfg(feature = "io_uring")]
    pub(super) fn signal(&self) {
        self.eventfd.write(1).unwrap();
    }

    pub(super) fn is_in_flight(&self, user_data: u64) -> bool {
        self.in_flight.contains_key(&user_data)
    }

    pub(super) fn validate_batch(&self, batch: &[AsyncIoOperation]) -> io::Result<()> {
        validate_batch(|user_data| self.in_flight.contains_key(&user_data), batch)
    }

    pub(super) fn track(&mut self, user_data: u64, op: Option<AsyncIoOperation>) {
        self.in_flight.insert(user_data, op);
    }

    pub(super) fn take(&mut self, user_data: u64) -> Option<AsyncIoOperation> {
        self.in_flight.remove(&user_data).flatten()
    }

    #[cfg(feature = "io_uring")]
    pub(super) fn in_flight_len(&self) -> usize {
        self.in_flight.len()
    }

    /// Leaks the retained buffers when the kernel cannot be drained.
    #[cfg(feature = "io_uring")]
    pub(super) fn forget_in_flight(&mut self) {
        mem::forget(mem::take(&mut self.in_flight));
    }

    pub(super) fn inject_completion(&mut self, completion: AsyncIoCompletion) {
        self.completions.push_back(completion);
        self.eventfd.write(1).unwrap();
    }

    /// Enqueues a completion without signaling the eventfd again.
    pub(super) fn enqueue_completion(&mut self, completion: AsyncIoCompletion) {
        self.completions.push_back(completion);
    }

    pub(super) fn has_completions(&self) -> bool {
        !self.completions.is_empty()
    }

    pub(super) fn next_completion(&mut self) -> Option<AsyncIoCompletion> {
        self.completions.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::AsyncIoCore;
    use crate::async_io::{AsyncIoCompletion, AsyncIoOperation, OwnedIoBuffer};

    #[test]
    fn completions_signal_only_on_inject() {
        let mut core = AsyncIoCore::new().unwrap();

        core.enqueue_completion(AsyncIoCompletion::new(4, 512, None));
        assert_eq!(
            core.notifier().read().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );

        core.inject_completion(AsyncIoCompletion::new(9, -libc::EIO, None));
        assert_eq!(core.notifier().read().unwrap(), 1);

        assert_eq!(core.next_completion().unwrap().user_data, 4);
        assert_eq!(core.next_completion().unwrap().user_data, 9);
        assert!(core.next_completion().is_none());
    }

    #[test]
    fn in_flight_tracks_and_rejects_duplicates() {
        let mut core = AsyncIoCore::new().unwrap();
        let op = || AsyncIoOperation::read_to_vec(0, OwnedIoBuffer::from_vec(vec![0; 512]), 3);
        core.track(3, Some(op()));
        core.track(4, None);

        assert!(core.is_in_flight(3));
        assert_eq!(
            core.validate_batch(&[op()]).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );

        assert_eq!(core.take(3).unwrap().user_data(), 3);
        assert!(core.take(4).is_none());
        assert!(core.take(3).is_none());
        assert!(!core.is_in_flight(3));
    }
}
