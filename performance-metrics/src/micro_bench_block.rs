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
    self, BLOCK_SIZE, L2_ENTRIES_PER_TABLE, QCOW_CLUSTER_SIZE, deterministic_permutation,
    drain_async_completions, drain_completions, read_iovec, submit_reads, submit_writes,
    write_iovec,
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

/// Read num_ops clusters from a prepopulated qcow2 image in random order.
///
/// Unlike micro_bench_qcow_read which reads sequentially, this shuffles
/// the cluster indices to exercise L2 cache miss and eviction behaviour
/// under random access patterns.
///
/// Returns the total read wall clock time in seconds.
pub fn micro_bench_qcow_random_read(control: &PerformanceTestControl) -> f64 {
    let num_ops = control.num_ops.expect("num_ops required") as usize;
    let (_tmp, disk) = util::qcow_tempfile(num_ops);
    let mut async_io = disk.new_async_io(1).expect("new_async_io failed");

    let indices = deterministic_permutation(num_ops);

    let mut buf = vec![0u8; QCOW_CLUSTER_SIZE as usize];
    let iovec = read_iovec(&mut buf);

    let start = Instant::now();
    for (seq, &cluster_idx) in indices.iter().enumerate() {
        async_io
            .read_vectored(
                (cluster_idx as u64 * QCOW_CLUSTER_SIZE) as libc::off_t,
                &[iovec],
                seq as u64,
            )
            .expect("read_vectored failed");
    }
    let elapsed = start.elapsed().as_secs_f64();

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

/// Punch holes for num_ops clusters in a prepopulated qcow2 image through
/// the QcowSync async_io path and time the total punch_hole wall clock.
///
/// This exercises the discard path: deallocate_bytes decrements refcounts,
/// frees clusters and issues fallocate punch_hole on the host file.
///
/// Returns the total punch_hole wall clock time in seconds.
pub fn micro_bench_qcow_punch_hole(control: &PerformanceTestControl) -> f64 {
    let num_ops = control.num_ops.expect("num_ops required") as usize;
    let (_tmp, disk) = util::qcow_tempfile(num_ops);
    let mut async_io = disk.new_async_io(1).expect("new_async_io failed");

    let start = Instant::now();
    for i in 0..num_ops {
        async_io
            .punch_hole(i as u64 * QCOW_CLUSTER_SIZE, QCOW_CLUSTER_SIZE, i as u64)
            .expect("punch_hole failed");
    }
    let elapsed = start.elapsed().as_secs_f64();

    // Drain completions so Drop is clean.
    drain_completions(async_io.as_mut(), num_ops);

    elapsed
}

/// Write num_ops clusters into an empty qcow2 image to dirty L2 and
/// refcount metadata, then time a single fsync that flushes all dirty
/// tables to disk.
///
/// This isolates the metadata flush cost which scales with the number
/// of dirty L2 table entries and refcount blocks.
///
/// Returns the fsync wall clock time in seconds.
pub fn micro_bench_qcow_fsync(control: &PerformanceTestControl) -> f64 {
    let num_ops = control.num_ops.expect("num_ops required") as usize;
    let (_tmp, disk) = util::empty_qcow_tempfile(num_ops);
    let mut async_io = disk.new_async_io(1).expect("new_async_io failed");

    // Write num_ops clusters to dirty L2 and refcount metadata.
    let buf = vec![0xA5u8; QCOW_CLUSTER_SIZE as usize];
    let iovec = write_iovec(&buf);
    submit_writes(async_io.as_mut(), num_ops, QCOW_CLUSTER_SIZE, &[iovec]);
    // Drain write completions.
    drain_completions(async_io.as_mut(), num_ops);

    // Time the flush.
    let start = Instant::now();
    async_io.fsync(Some(num_ops as u64)).expect("fsync failed");
    let elapsed = start.elapsed().as_secs_f64();

    drain_completions(async_io.as_mut(), 1);

    elapsed
}

/// Read num_ops clusters from a QCOW2 overlay whose data lives entirely
/// in a raw backing file.
///
/// This exercises the backing file read path: L2 lookup finds no
/// allocated cluster and falls through to the backing file for every
/// read.
///
/// Returns the total read wall clock time in seconds.
pub fn micro_bench_qcow_backing_read(control: &PerformanceTestControl) -> f64 {
    let num_ops = control.num_ops.expect("num_ops required") as usize;
    let (_backing, _overlay, disk) = util::qcow_overlay_tempfile(num_ops);
    let mut async_io = disk.new_async_io(1).expect("new_async_io failed");

    let mut buf = vec![0u8; QCOW_CLUSTER_SIZE as usize];
    let iovec = read_iovec(&mut buf);

    let start = Instant::now();
    submit_reads(async_io.as_mut(), num_ops, QCOW_CLUSTER_SIZE, &[iovec]);
    let elapsed = start.elapsed().as_secs_f64();

    drain_completions(async_io.as_mut(), num_ops);

    elapsed
}

/// Write num_ops clusters into a QCOW2 overlay backed by a raw file.
///
/// Each write triggers copy-on-write: the overlay must allocate a new
/// cluster, update L2 and refcount tables, then write the data.  This
/// measures the COW allocation overhead compared to writing into an
/// empty image (no backing read needed since we overwrite the full
/// cluster).
///
/// Returns the total write wall clock time in seconds.
pub fn micro_bench_qcow_cow_write(control: &PerformanceTestControl) -> f64 {
    let num_ops = control.num_ops.expect("num_ops required") as usize;
    let (_backing, _overlay, disk) = util::qcow_overlay_tempfile(num_ops);
    let mut async_io = disk.new_async_io(1).expect("new_async_io failed");

    let buf = vec![0xBBu8; QCOW_CLUSTER_SIZE as usize];
    let iovec = write_iovec(&buf);

    let start = Instant::now();
    submit_writes(async_io.as_mut(), num_ops, QCOW_CLUSTER_SIZE, &[iovec]);
    let elapsed = start.elapsed().as_secs_f64();

    drain_completions(async_io.as_mut(), num_ops);

    elapsed
}

/// Read num_ops clusters from a zlib compressed QCOW2 image.
///
/// Every cluster is stored compressed, so each read triggers
/// decompression.  This isolates the decompression overhead from
/// the normal allocated-cluster read path.
///
/// Returns the total read wall clock time in seconds.
pub fn micro_bench_qcow_compressed_read(control: &PerformanceTestControl) -> f64 {
    let num_ops = control.num_ops.expect("num_ops required") as usize;
    let (_tmp, disk) = util::compressed_qcow_tempfile(num_ops);
    let mut async_io = disk.new_async_io(1).expect("new_async_io failed");

    let mut buf = vec![0u8; QCOW_CLUSTER_SIZE as usize];
    let iovec = read_iovec(&mut buf);

    let start = Instant::now();
    submit_reads(async_io.as_mut(), num_ops, QCOW_CLUSTER_SIZE, &[iovec]);
    let elapsed = start.elapsed().as_secs_f64();

    drain_completions(async_io.as_mut(), num_ops);

    elapsed
}

/// Issue large multicluster reads from a prepopulated QCOW2 image.
///
/// Each read_vectored call spans `CLUSTERS_PER_READ` contiguous clusters
/// (8 x 64 KiB = 512 KiB).  This exercises the mapping coalesce path
/// where multiple L2 entries are merged into fewer host I/O operations.
/// `num_ops` is the total number of clusters; reads are issued in
/// chunks of CLUSTERS_PER_READ.
///
/// Returns the total read wall clock time in seconds.
pub fn micro_bench_qcow_multi_cluster_read(control: &PerformanceTestControl) -> f64 {
    const CLUSTERS_PER_READ: usize = 8;

    let num_ops = control.num_ops.expect("num_ops required") as usize;
    let (_tmp, disk) = util::qcow_tempfile(num_ops);
    let mut async_io = disk.new_async_io(1).expect("new_async_io failed");

    let read_size = CLUSTERS_PER_READ * QCOW_CLUSTER_SIZE as usize;
    let mut buf = vec![0u8; read_size];
    let iovec = read_iovec(&mut buf);

    let num_reads = num_ops / CLUSTERS_PER_READ;
    let start = Instant::now();
    submit_reads(async_io.as_mut(), num_reads, read_size as u64, &[iovec]);
    let elapsed = start.elapsed().as_secs_f64();

    drain_completions(async_io.as_mut(), num_reads);

    elapsed
}

/// Read one cluster from each of num_ops distinct L2 tables in a
/// sparsely allocated QCOW2 image.
///
/// The clusters are spaced L2_ENTRIES_PER_TABLE apart so every read
/// touches a different L2 table.  With num_ops exceeding the L2 cache
/// capacity (100 entries), this forces eviction on nearly every read
/// and measures the cold L2 cache miss overhead.
///
/// Returns the total read wall clock time in seconds.
pub fn micro_bench_qcow_l2_cache_miss(control: &PerformanceTestControl) -> f64 {
    let num_ops = control.num_ops.expect("num_ops required") as usize;
    let (_tmp, disk) = util::sparse_qcow_tempfile(num_ops);
    let mut async_io = disk.new_async_io(1).expect("new_async_io failed");

    let mut buf = vec![0u8; QCOW_CLUSTER_SIZE as usize];
    let iovec = read_iovec(&mut buf);

    let stride = L2_ENTRIES_PER_TABLE as u64 * QCOW_CLUSTER_SIZE;
    let start = Instant::now();
    submit_reads(async_io.as_mut(), num_ops, stride, &[iovec]);
    let elapsed = start.elapsed().as_secs_f64();

    drain_completions(async_io.as_mut(), num_ops);

    elapsed
}

/// Read num_ops clusters from a prepopulated qcow2 image through the
/// QcowAsync io_uring path and time the total wall clock.
///
/// Unlike micro_bench_qcow_read which uses QcowDiskSync (blocking),
/// this uses QcowDiskAsync where single-allocated-cluster reads go
/// through io_uring for true asynchronous completion.
///
/// Returns the total read wall clock time in seconds.
pub fn micro_bench_qcow_async_read(control: &PerformanceTestControl) -> f64 {
    let num_ops = control.num_ops.expect("num_ops required") as usize;
    let (_tmp, disk) = util::qcow_async_tempfile(num_ops);
    let mut async_io = disk
        .new_async_io(num_ops as u32)
        .expect("new_async_io failed");

    let mut buf = vec![0u8; QCOW_CLUSTER_SIZE as usize];
    let iovec = read_iovec(&mut buf);

    let start = Instant::now();
    submit_reads(async_io.as_mut(), num_ops, QCOW_CLUSTER_SIZE, &[iovec]);

    // Drain all io_uring completions before stopping the clock.
    drain_async_completions(async_io.as_mut(), num_ops);
    start.elapsed().as_secs_f64()
}
