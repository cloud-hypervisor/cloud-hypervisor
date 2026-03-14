// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! In process micro benchmarks for block layer internals.
//!
//! These run without booting a VM and measure hot path operations
//! (e.g. AIO completion draining) at the syscall level.

use std::os::unix::io::AsRawFd;
use std::time::Instant;

use block::async_io::AsyncIo;
use block::raw_async_aio::RawFileAsyncAio;

use crate::PerformanceTestControl;
use crate::util::{self, BLOCK_SIZE};

/// Submit num_ops AIO writes, wait for them all to land, then time
/// how long it takes to drain every completion via next_completed_request().
///
/// Returns the drain wall clock time in seconds.
pub fn micro_bench_aio_drain(control: &PerformanceTestControl) -> f64 {
    let num_ops = control.num_ops.expect("num_ops required") as usize;
    let tmp = util::sized_tempfile(num_ops);
    let fd = tmp.as_file().as_raw_fd();
    let mut aio = RawFileAsyncAio::new(fd, num_ops as u32).expect("failed to create AIO context");

    let buf = vec![0xA5u8; BLOCK_SIZE as usize];

    // Submit all writes.
    for i in 0..num_ops {
        let iovec = libc::iovec {
            iov_base: buf.as_ptr() as *mut _,
            iov_len: buf.len(),
        };
        aio.write_vectored((i as u64 * BLOCK_SIZE) as libc::off_t, &[iovec], i as u64)
            .expect("write_vectored failed");
    }

    // Wait until the eventfd signals that completions are available.
    util::wait_for_eventfd(aio.notifier());

    // Drain all completions and measure.
    let start = Instant::now();
    let mut drained = 0usize;
    while drained < num_ops {
        if aio.next_completed_request().is_some() {
            drained += 1;
        }
    }
    start.elapsed().as_secs_f64()
}
