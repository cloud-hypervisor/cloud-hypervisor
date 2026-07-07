// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0

//! Shared benchmark helpers.

use std::fs::File;
use std::io::ErrorKind;
use std::os::unix::fs::FileExt;
use std::process::Command;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use block::async_io::{AsyncIo, GuestMemoryTarget};
use block::formats::qcow::{BackingFileConfig, ImageType, QcowDisk, QcowTempDisk};
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::tempfile::TempFile;

pub const BLOCK_SIZE: u64 = 4096;
pub const QCOW_CLUSTER_SIZE: u64 = 65536;

/// Create a temporary file pre sized to hold `num_blocks` blocks.
pub fn sized_tempfile(num_blocks: usize) -> TempFile {
    let tmp = TempFile::new().expect("failed to create tempfile");
    tmp.as_file()
        .set_len(BLOCK_SIZE * num_blocks as u64)
        .expect("failed to set file length");
    tmp
}

/// Create a QCOW2 image with `num_clusters` allocated clusters and return
/// the tempfile handle.
///
/// Each cluster is default QCOW2 cluster size of 64 KiB. The image is
/// created via `QcowTempDisk::new` then populated with writes via the
/// synchronous AsyncIo backend so that the clusters are actually
/// allocated in the L2 / refcount tables.
fn create_qcow_tempfile(num_clusters: usize) -> TempFile {
    let virtual_size = QCOW_CLUSTER_SIZE * num_clusters as u64;
    let tmp_disk = QcowTempDisk::new(virtual_size, None, false, true, false)
        .expect("failed to create QCOW2 file");
    let buf = vec![0xA5u8; QCOW_CLUSTER_SIZE as usize];
    for i in 0..num_clusters as u64 {
        tmp_disk.disk().write_all_at(i * QCOW_CLUSTER_SIZE, &buf);
    }
    tmp_disk.into_tempfile()
}

/// Create a QCOW2 image with `num_clusters` allocated clusters opened
/// via QcowDisk with synchronous backend.
pub fn qcow_tempfile(num_clusters: usize) -> (TempFile, QcowDisk) {
    let tmp = create_qcow_tempfile(num_clusters);
    let disk = QcowDisk::new(
        tmp.as_file().try_clone().unwrap(),
        false,
        false,
        true,
        false,
    )
    .expect("failed to open QCOW2 via QcowDisk");
    (tmp, disk)
}

/// Create a QCOW2 image with `num_clusters` allocated clusters opened
/// via QcowDisk with io_uring backend.
pub fn qcow_async_tempfile(num_clusters: usize) -> (TempFile, QcowDisk) {
    let tmp = create_qcow_tempfile(num_clusters);
    let disk = QcowDisk::new(tmp.as_file().try_clone().unwrap(), false, false, true, true)
        .expect("failed to open QCOW2 via QcowDisk");
    (tmp, disk)
}

/// Drain `count` completions from a synchronous async_io backend.
pub fn drain_completions(async_io: &mut dyn AsyncIo, count: usize) {
    for _ in 0..count {
        async_io.next_completed_request();
    }
}

/// Build a deterministic pseudo-random permutation of `[0, n)`.
///
/// Uses a Fisher-Yates shuffle seeded by `DefaultHasher` so the
/// permutation is identical across runs.
pub fn deterministic_permutation(n: usize) -> Vec<usize> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut indices: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        let mut h = DefaultHasher::new();
        i.hash(&mut h);
        let j = h.finish() as usize % (i + 1);
        indices.swap(i, j);
    }
    indices
}

/// Create prefaulted guest memory for one reusable I/O range.
///
/// The block microbenchmarks intentionally use this as a hot buffer to keep
/// cache behavior close to the borrowed-iovec benchmarks they replaced.
pub fn guest_memory_buffer(len: usize) -> Arc<GuestMemoryMmap> {
    assert!(
        len <= u32::MAX as usize,
        "GuestMemoryTarget ranges are limited to u32 lengths"
    );
    let total_len = len.max(1);

    let mem = Arc::new(
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0), total_len)])
            .expect("failed to create benchmark guest memory"),
    );
    prefault_guest_memory(&mem, total_len);
    mem
}

fn prefault_guest_memory(mem: &Arc<GuestMemoryMmap>, total_len: usize) {
    const PAGE_SIZE: usize = 4096;

    for offset in (0..total_len).step_by(PAGE_SIZE) {
        mem.write_slice(&[0], GuestAddress(offset as u64))
            .expect("failed to prefault benchmark guest memory");
    }
}

/// Create a target for the reusable benchmark guest-memory range.
pub fn guest_memory_target(mem: &Arc<GuestMemoryMmap>, len: usize) -> GuestMemoryTarget {
    assert!(
        len <= u32::MAX as usize,
        "GuestMemoryTarget ranges are limited to u32 lengths"
    );
    let range = [(GuestAddress(0), len as u32)];

    GuestMemoryTarget::new(Arc::clone(mem), &range).expect("failed to create guest memory target")
}

/// Fill the reusable benchmark guest-memory range with one byte pattern.
pub fn fill_guest_memory(mem: &Arc<GuestMemoryMmap>, len: usize, value: u8) {
    let buf = vec![value; len];
    mem.write_slice(&buf, GuestAddress(0))
        .expect("failed to initialize benchmark guest memory");
}

/// Submit `count` sequential read calls at `stride`-byte intervals.
pub fn submit_reads(
    async_io: &mut dyn AsyncIo,
    mem: &Arc<GuestMemoryMmap>,
    count: usize,
    stride: u64,
    len: usize,
) {
    for i in 0..count {
        let target = guest_memory_target(mem, len);
        async_io
            .read_to_memory((i as u64 * stride) as libc::off_t, target, i as u64)
            .expect("read_to_memory failed");
    }
}

/// Submit `count` sequential write calls at `stride`-byte intervals.
pub fn submit_writes(
    async_io: &mut dyn AsyncIo,
    mem: &Arc<GuestMemoryMmap>,
    count: usize,
    stride: u64,
    len: usize,
) {
    for i in 0..count {
        let target = guest_memory_target(mem, len);
        async_io
            .write_from_memory((i as u64 * stride) as libc::off_t, target, i as u64)
            .expect("write_from_memory failed");
    }
}

/// Drain `count` completions from an asynchronous I/O backend that delivers
/// results via eventfd notification (e.g. io_uring).
pub fn drain_async_completions(async_io: &mut dyn AsyncIo, count: usize) {
    let mut drained = 0usize;
    while drained < count {
        wait_for_eventfd(async_io.notifier());
        while async_io.next_completed_request().is_some() {
            drained += 1;
        }
    }
}

/// Create an empty QCOW2 image sized for `num_clusters` clusters.
/// No data clusters are allocated.
fn create_empty_qcow_tempfile(num_clusters: usize) -> TempFile {
    let virtual_size = QCOW_CLUSTER_SIZE * num_clusters as u64;
    QcowTempDisk::new(virtual_size, None, false, true, false)
        .expect("failed to create qcow2 file")
        .into_tempfile()
}

/// Empty QCOW2 opened via QcowDisk with synchronous backend.
pub fn empty_qcow_tempfile(num_clusters: usize) -> (TempFile, QcowDisk) {
    let tmp = create_empty_qcow_tempfile(num_clusters);
    let disk = QcowDisk::new(
        tmp.as_file().try_clone().unwrap(),
        false,
        false,
        true,
        false,
    )
    .expect("failed to open QCOW2 via QcowDisk");
    (tmp, disk)
}

/// Empty QCOW2 opened via QcowDisk with io_uring backend.
pub fn empty_qcow_async_tempfile(num_clusters: usize) -> (TempFile, QcowDisk) {
    let tmp = create_empty_qcow_tempfile(num_clusters);
    let disk = QcowDisk::new(tmp.as_file().try_clone().unwrap(), false, false, true, true)
        .expect("failed to open QCOW2 via QcowDisk");
    (tmp, disk)
}

/// Create a QCOW2 overlay backed by a raw file with `num_clusters`
/// pre-populated clusters.  Returns (backing_tempfile, overlay_tempfile).
fn create_overlay_tempfiles(num_clusters: usize) -> (TempFile, TempFile) {
    let virtual_size = QCOW_CLUSTER_SIZE * num_clusters as u64;

    let backing = TempFile::new().expect("failed to create backing tempfile");
    {
        let f = backing.as_file();
        f.set_len(virtual_size).expect("set_len failed");
        let buf = vec![0xA5u8; QCOW_CLUSTER_SIZE as usize];
        for i in 0..num_clusters {
            f.write_at(&buf, i as u64 * QCOW_CLUSTER_SIZE)
                .expect("write_at failed");
        }
    }

    let backing_config = BackingFileConfig {
        path: backing.as_path().to_str().unwrap().to_string(),
        format: Some(ImageType::Raw),
    };
    let overlay = QcowTempDisk::new(virtual_size, Some(&backing_config), false, true, false)
        .expect("failed to create overlay qcow2")
        .into_tempfile();

    (backing, overlay)
}

/// QCOW2 overlay with raw backing opened via QcowDisk with synchronous backend.
pub fn qcow_overlay_tempfile(num_clusters: usize) -> (TempFile, TempFile, QcowDisk) {
    let (backing, overlay) = create_overlay_tempfiles(num_clusters);
    let disk = QcowDisk::new(
        overlay.as_file().try_clone().unwrap(),
        false,
        true,
        true,
        false,
    )
    .expect("failed to open overlay QCOW2 via QcowDisk");
    (backing, overlay, disk)
}

/// QCOW2 overlay with raw backing opened via QcowDisk with io_uring backend.
pub fn qcow_async_overlay_tempfile(num_clusters: usize) -> (TempFile, TempFile, QcowDisk) {
    let (backing, overlay) = create_overlay_tempfiles(num_clusters);
    let disk = QcowDisk::new(
        overlay.as_file().try_clone().unwrap(),
        false,
        true,
        true,
        true,
    )
    .expect("failed to open overlay QCOW2 via QcowDisk");
    (backing, overlay, disk)
}

/// Create a zlib compressed QCOW2 image with `num_clusters` clusters
/// via `qemu-img convert -c`.
fn create_compressed_qcow_tempfile(num_clusters: usize) -> TempFile {
    let virtual_size = QCOW_CLUSTER_SIZE * num_clusters as u64;

    let raw_tmp = TempFile::new().expect("failed to create raw tempfile");
    {
        let f = raw_tmp.as_file();
        f.set_len(virtual_size).expect("set_len failed");
        let buf = vec![0xA5u8; QCOW_CLUSTER_SIZE as usize];
        for i in 0..num_clusters {
            f.write_at(&buf, i as u64 * QCOW_CLUSTER_SIZE)
                .expect("write_at failed");
        }
    }

    let qcow_tmp = TempFile::new().expect("failed to create qcow2 tempfile");
    let qcow_path = qcow_tmp.as_path().to_str().unwrap().to_string();
    let raw_path = raw_tmp.as_path().to_str().unwrap().to_string();
    let status = Command::new("qemu-img")
        .args([
            "convert",
            "-f",
            "raw",
            "-O",
            "qcow2",
            "-c",
            "-o",
            "compression_type=zlib",
            &raw_path,
            &qcow_path,
        ])
        .status()
        .expect("failed to run qemu-img");
    assert!(status.success(), "qemu-img convert failed");

    qcow_tmp
}

/// Compressed QCOW2 opened via QcowDisk with synchronous backend.
pub fn compressed_qcow_tempfile(num_clusters: usize) -> (TempFile, QcowDisk) {
    let tmp = create_compressed_qcow_tempfile(num_clusters);
    let path = tmp.as_path().to_str().unwrap().to_string();
    let disk = QcowDisk::new(
        File::open(&path).expect("failed to open compressed qcow2"),
        false,
        false,
        true,
        false,
    )
    .expect("failed to open compressed QCOW2 via QcowDisk");
    (tmp, disk)
}

/// Compressed QCOW2 opened via QcowDisk with io_uring backend.
pub fn compressed_qcow_async_tempfile(num_clusters: usize) -> (TempFile, QcowDisk) {
    let tmp = create_compressed_qcow_tempfile(num_clusters);
    let path = tmp.as_path().to_str().unwrap().to_string();
    let disk = QcowDisk::new(
        File::open(&path).expect("failed to open compressed qcow2"),
        false,
        false,
        true,
        true,
    )
    .expect("failed to open compressed QCOW2 via QcowDisk");
    (tmp, disk)
}

/// Number of data clusters covered by a single L2 table (64 KiB cluster,
/// 8-byte entries -> 8192 entries per L2 table).
pub const L2_ENTRIES_PER_TABLE: usize = QCOW_CLUSTER_SIZE as usize / 8;

/// Create a sparse QCOW2 image with one allocated cluster per L2 table,
/// spanning `num_l2_tables` L2 tables.
fn create_sparse_qcow_tempfile(num_l2_tables: usize) -> TempFile {
    let virtual_size = QCOW_CLUSTER_SIZE * (num_l2_tables as u64 * L2_ENTRIES_PER_TABLE as u64);
    let tmp_disk = QcowTempDisk::new(virtual_size, None, false, true, false)
        .expect("failed to create qcow2 file");
    let buf = vec![0xA5u8; QCOW_CLUSTER_SIZE as usize];
    for i in 0..num_l2_tables as u64 {
        let offset = i * L2_ENTRIES_PER_TABLE as u64 * QCOW_CLUSTER_SIZE;
        tmp_disk.disk().write_all_at(offset, &buf);
    }
    tmp_disk.into_tempfile()
}

/// Sparse QCOW2 opened via QcowDisk with synchronous backend.
pub fn sparse_qcow_tempfile(num_l2_tables: usize) -> (TempFile, QcowDisk) {
    let tmp = create_sparse_qcow_tempfile(num_l2_tables);
    let disk = QcowDisk::new(
        tmp.as_file().try_clone().unwrap(),
        false,
        false,
        true,
        false,
    )
    .expect("failed to open QCOW2 via QcowDisk");
    (tmp, disk)
}

/// Sparse QCOW2 opened via QcowDisk with io_uring backend.
pub fn sparse_qcow_async_tempfile(num_l2_tables: usize) -> (TempFile, QcowDisk) {
    let tmp = create_sparse_qcow_tempfile(num_l2_tables);
    let disk = QcowDisk::new(tmp.as_file().try_clone().unwrap(), false, false, true, true)
        .expect("failed to open QCOW2 via QcowDisk");
    (tmp, disk)
}

/// Spin and wait until the given eventfd becomes readable.
pub fn wait_for_eventfd(notifier: &EventFd) {
    loop {
        match notifier.read() {
            Ok(_) => return,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_micros(50));
            }
            Err(e) => panic!("eventfd read failed: {e}"),
        }
    }
}
