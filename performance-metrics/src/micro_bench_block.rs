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
use block::disk_file::AsyncDiskFile;
use block::raw_async_aio::RawFileAsyncAio;

use crate::PerformanceTestControl;
use crate::util::{
    self, BLOCK_SIZE, QCOW_CLUSTER_SIZE, drain_completions, read_iovec, submit_reads,
    submit_writes, write_iovec,
};

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

/// Read num_ops clusters from a prepopulated qcow2 image through the
/// QcowSync async_io path and time the total read_vectored wall clock.
///
/// This exercises the hot read path: L2 lookup via map_clusters_for_read,
/// pread64 for allocated data, and iovec scatter.
///
/// Returns the total read wall clock time in seconds.
pub fn micro_bench_qcow_read(control: &PerformanceTestControl) -> f64 {
    let num_ops = control.num_ops.expect("num_ops required") as usize;
    let (_tmp, disk) = util::qcow_tempfile(num_ops);
    let mut async_io = disk.new_async_io(1).expect("new_async_io failed");

    let mut buf = vec![0u8; QCOW_CLUSTER_SIZE as usize];
    let iovec = read_iovec(&mut buf);

    let start = Instant::now();
    submit_reads(async_io.as_mut(), num_ops, QCOW_CLUSTER_SIZE, &[iovec]);
    let elapsed = start.elapsed().as_secs_f64();

    // Drain completions so Drop is clean.
    drain_completions(async_io.as_mut(), num_ops);

    elapsed
}

/// Write num_ops clusters into an empty qcow2 image through the
/// QcowSync async_io path and time the total write_vectored wall clock.
///
/// This exercises the write allocation path: map_cluster_for_write
/// allocates a new cluster and bumps refcounts, then pwrite_all writes
/// the data.
///
/// Returns the total write wall clock time in seconds.
pub fn micro_bench_qcow_write(control: &PerformanceTestControl) -> f64 {
    let num_ops = control.num_ops.expect("num_ops required") as usize;
    let (_tmp, disk) = util::empty_qcow_tempfile(num_ops);
    let mut async_io = disk.new_async_io(1).expect("new_async_io failed");

    let buf = vec![0xA5u8; QCOW_CLUSTER_SIZE as usize];
    let iovec = write_iovec(&buf);

    let start = Instant::now();
    submit_writes(async_io.as_mut(), num_ops, QCOW_CLUSTER_SIZE, &[iovec]);
    let elapsed = start.elapsed().as_secs_f64();

    // Drain completions so Drop is clean.
    drain_completions(async_io.as_mut(), num_ops);

    elapsed
}
