// Copyright 2026 Cloudflare, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// io_uring-based TX path for virtio-net tap devices. Batches multiple
// writev operations into a single io_uring submission, reducing per-packet
// syscall overhead compared to the synchronous writev() path.

use std::os::unix::io::AsRawFd;

use io_uring::{IoUring, opcode, types};
use log::warn;
use vmm_sys_util::eventfd::EventFd;

use crate::Tap;

/// io_uring-accelerated TX submission. Collects packets from the virtio TX
/// queue and submits them as batched Writev SQEs to the tap fd.
pub struct NetTxIoUring {
    ring: IoUring,
    tap_fd: i32,
    /// EventFd signalled when CQEs are ready.
    completion_eventfd: EventFd,
    /// Number of in-flight SQEs awaiting completion.
    inflight: u32,
}

impl NetTxIoUring {
    /// Create a new io_uring TX handler for the given tap device.
    /// `ring_depth` controls the SQ/CQ size (typically the virtio queue size).
    pub fn new(tap: &Tap, ring_depth: u32) -> std::io::Result<Self> {
        let ring = IoUring::new(ring_depth)?;
        let completion_eventfd = EventFd::new(libc::EFD_NONBLOCK)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        ring.submitter()
            .register_eventfd(completion_eventfd.as_raw_fd())?;

        Ok(NetTxIoUring {
            ring,
            tap_fd: tap.as_raw_fd(),
            completion_eventfd,
            inflight: 0,
        })
    }

    /// Returns the eventfd that fires when CQEs are ready. Register this
    /// in the epoll loop alongside the existing queue/tap events.
    pub fn completion_notifier(&self) -> &EventFd {
        &self.completion_eventfd
    }

    /// Submit a batch of TX packets via io_uring Writev. Each entry in
    /// `iovec_batches` is one packet (a slice of iovecs gathered from the
    /// virtio descriptor chain). Returns the number of SQEs submitted.
    ///
    /// # Safety
    /// The iovec pointers must remain valid until the corresponding CQEs
    /// are harvested. The caller must ensure guest memory is pinned.
    pub unsafe fn submit_tx_batch(
        &mut self,
        iovec_batches: &[(u64, *const libc::iovec, u32)], // (user_data, iovecs_ptr, iovecs_len)
    ) -> std::io::Result<u32> {
        let (submitter, mut sq, _) = self.ring.split();
        let mut pushed = 0u32;

        for &(user_data, iovecs_ptr, iovecs_len) in iovec_batches {
            let entry = opcode::Writev::new(types::Fd(self.tap_fd), iovecs_ptr, iovecs_len)
                .build()
                .user_data(user_data);

            if unsafe { sq.push(&entry) }.is_err() {
                // SQ is full, submit what we have and retry.
                sq.sync();
                submitter.submit()?;
                self.inflight += pushed;
                pushed = 0;

                if unsafe { sq.push(&entry) }.is_err() {
                    warn!("io_uring SQ still full after submit, dropping packet");
                    break;
                }
            }
            pushed += 1;
        }

        if pushed > 0 {
            sq.sync();
            submitter.submit()?;
            self.inflight += pushed;
        }

        Ok(pushed)
    }

    /// Harvest completed TX operations. Returns an iterator of
    /// (user_data, result) pairs. Positive result = bytes written,
    /// negative result = negated errno.
    pub fn harvest_completions(&mut self) -> Vec<(u64, i32)> {
        let mut results = Vec::new();
        let cq = self.ring.completion();
        for entry in cq {
            results.push((entry.user_data(), entry.result()));
            self.inflight = self.inflight.saturating_sub(1);
        }
        // Drain the eventfd to avoid spurious epoll wakeups.
        let _ = self.completion_eventfd.read();
        results
    }

    /// Number of SQEs currently in flight.
    pub fn inflight_count(&self) -> u32 {
        self.inflight
    }
}

/// Check if the kernel supports io_uring with the opcodes we need for
/// networking (Writev). Returns false on kernels < 5.6 or when io_uring
/// is disabled via seccomp.
pub fn net_io_uring_is_supported() -> bool {
    let ring = match IoUring::new(2) {
        Ok(r) => r,
        Err(_) => return false,
    };

    let mut probe = io_uring::Probe::new();
    if ring.submitter().register_probe(&mut probe).is_err() {
        return false;
    }

    probe.is_supported(opcode::Writev::CODE)
}
