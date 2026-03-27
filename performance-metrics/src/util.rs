// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Shared benchmark helpers.

use std::fs::File;
use std::io::{ErrorKind, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::process::Command;
use std::thread;
use std::time::Duration;

use block::async_io::AsyncIo;
use block::qcow::{BackingFileConfig, ImageType, QcowFile, RawFile};
use block::qcow_async::QcowDiskAsync;
use block::qcow_sync::QcowDiskSync;
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
/// created via `QcowFile::new` then populated with writes so that the
/// clusters are actually allocated in the L2 / refcount tables.
fn create_qcow_tempfile(num_clusters: usize) -> TempFile {
    let tmp = TempFile::new().expect("failed to create tempfile");
    let virtual_size = QCOW_CLUSTER_SIZE * num_clusters as u64;
    let raw = RawFile::new(tmp.as_file().try_clone().unwrap(), false);
    let mut qcow = QcowFile::new(raw, 3, virtual_size, true).expect("failed to create QCOW2 file");
    let buf = vec![0xA5u8; QCOW_CLUSTER_SIZE as usize];
    for i in 0..num_clusters {
        qcow.seek(SeekFrom::Start(i as u64 * QCOW_CLUSTER_SIZE))
            .expect("seek failed");
        qcow.write_all(&buf).expect("write failed");
    }
    qcow.flush().expect("flush failed");
    tmp
}

/// Create a QCOW2 image with `num_clusters` allocated clusters opened
/// via `QcowDiskSync` (blocking I/O backend).
pub fn qcow_tempfile(num_clusters: usize) -> (TempFile, QcowDiskSync) {
    let tmp = create_qcow_tempfile(num_clusters);
    let disk = QcowDiskSync::new(tmp.as_file().try_clone().unwrap(), false, false, true)
        .expect("failed to open QCOW2 via QcowDiskSync");
    (tmp, disk)
}

/// Create a QCOW2 image with `num_clusters` allocated clusters opened
/// via `QcowDiskAsync` (io_uring backend).
pub fn qcow_async_tempfile(num_clusters: usize) -> (TempFile, QcowDiskAsync) {
    let tmp = create_qcow_tempfile(num_clusters);
    let disk = QcowDiskAsync::new(tmp.as_file().try_clone().unwrap(), false, false, true)
        .expect("failed to open QCOW2 via QcowDiskAsync");
    (tmp, disk)
}

/// Drain `count` completions from a synchronous async_io backend.
pub fn drain_completions(async_io: &mut dyn AsyncIo, count: usize) {
    for _ in 0..count {
        async_io.next_completed_request();
    }
}

/// Build an iovec suitable for a read into `buf`.
pub fn read_iovec(buf: &mut [u8]) -> libc::iovec {
    libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    }
}

/// Build an iovec suitable for a write from `buf`.
pub fn write_iovec(buf: &[u8]) -> libc::iovec {
    libc::iovec {
        iov_base: buf.as_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
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

/// Submit `count` sequential read_vectored calls at `stride`-byte intervals.
pub fn submit_reads(async_io: &mut dyn AsyncIo, count: usize, stride: u64, iovec: &[libc::iovec]) {
    for i in 0..count {
        async_io
            .read_vectored((i as u64 * stride) as libc::off_t, iovec, i as u64)
            .expect("read_vectored failed");
    }
}

/// Submit `count` sequential write_vectored calls at `stride`-byte intervals.
pub fn submit_writes(async_io: &mut dyn AsyncIo, count: usize, stride: u64, iovec: &[libc::iovec]) {
    for i in 0..count {
        async_io
            .write_vectored((i as u64 * stride) as libc::off_t, iovec, i as u64)
            .expect("write_vectored failed");
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
    let tmp = TempFile::new().expect("failed to create tempfile");
    let virtual_size = QCOW_CLUSTER_SIZE * num_clusters as u64;
    let raw = RawFile::new(tmp.as_file().try_clone().unwrap(), false);
    QcowFile::new(raw, 3, virtual_size, true).expect("failed to create qcow2 file");
    tmp
}

/// Empty QCOW2 opened via QcowDiskSync.
pub fn empty_qcow_tempfile(num_clusters: usize) -> (TempFile, QcowDiskSync) {
    let tmp = create_empty_qcow_tempfile(num_clusters);
    let disk = QcowDiskSync::new(tmp.as_file().try_clone().unwrap(), false, false, true)
        .expect("failed to open qcow2 via QcowDiskSync");
    (tmp, disk)
}

/// Empty QCOW2 opened via QcowDiskAsync.
pub fn empty_qcow_async_tempfile(num_clusters: usize) -> (TempFile, QcowDiskAsync) {
    let tmp = create_empty_qcow_tempfile(num_clusters);
    let disk = QcowDiskAsync::new(tmp.as_file().try_clone().unwrap(), false, false, true)
        .expect("failed to open qcow2 via QcowDiskAsync");
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

    let overlay = TempFile::new().expect("failed to create overlay tempfile");
    {
        let raw = RawFile::new(overlay.as_file().try_clone().unwrap(), false);
        let backing_config = BackingFileConfig {
            path: backing.as_path().to_str().unwrap().to_string(),
            format: Some(ImageType::Raw),
        };
        QcowFile::new_from_backing(raw, 3, virtual_size, &backing_config, true)
            .expect("failed to create overlay qcow2");
    }

    (backing, overlay)
}

/// QCOW2 overlay with raw backing opened via QcowDiskSync.
pub fn qcow_overlay_tempfile(num_clusters: usize) -> (TempFile, TempFile, QcowDiskSync) {
    let (backing, overlay) = create_overlay_tempfiles(num_clusters);
    let disk = QcowDiskSync::new(overlay.as_file().try_clone().unwrap(), false, true, true)
        .expect("failed to open overlay qcow2 via QcowDiskSync");
    (backing, overlay, disk)
}

/// QCOW2 overlay with raw backing opened via QcowDiskAsync.
pub fn qcow_async_overlay_tempfile(num_clusters: usize) -> (TempFile, TempFile, QcowDiskAsync) {
    let (backing, overlay) = create_overlay_tempfiles(num_clusters);
    let disk = QcowDiskAsync::new(overlay.as_file().try_clone().unwrap(), false, true, true)
        .expect("failed to open overlay qcow2 via QcowDiskAsync");
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

/// Compressed QCOW2 opened via QcowDiskSync.
pub fn compressed_qcow_tempfile(num_clusters: usize) -> (TempFile, QcowDiskSync) {
    let tmp = create_compressed_qcow_tempfile(num_clusters);
    let path = tmp.as_path().to_str().unwrap().to_string();
    let disk = QcowDiskSync::new(
        File::open(&path).expect("failed to open compressed qcow2"),
        false,
        false,
        true,
    )
    .expect("failed to open compressed qcow2 via QcowDiskSync");
    (tmp, disk)
}

/// Compressed QCOW2 opened via QcowDiskAsync.
pub fn compressed_qcow_async_tempfile(num_clusters: usize) -> (TempFile, QcowDiskAsync) {
    let tmp = create_compressed_qcow_tempfile(num_clusters);
    let path = tmp.as_path().to_str().unwrap().to_string();
    let disk = QcowDiskAsync::new(
        File::open(&path).expect("failed to open compressed qcow2"),
        false,
        false,
        true,
    )
    .expect("failed to open compressed qcow2 via QcowDiskAsync");
    (tmp, disk)
}

/// Number of data clusters covered by a single L2 table (64 KiB cluster,
/// 8-byte entries -> 8192 entries per L2 table).
pub const L2_ENTRIES_PER_TABLE: usize = QCOW_CLUSTER_SIZE as usize / 8;

/// Create a sparse QCOW2 image with one allocated cluster per L2 table,
/// spanning `num_l2_tables` L2 tables.
fn create_sparse_qcow_tempfile(num_l2_tables: usize) -> TempFile {
    let virtual_size = QCOW_CLUSTER_SIZE * (num_l2_tables as u64 * L2_ENTRIES_PER_TABLE as u64);
    let tmp = TempFile::new().expect("failed to create tempfile");
    let raw = RawFile::new(tmp.as_file().try_clone().unwrap(), false);
    let mut qcow = QcowFile::new(raw, 3, virtual_size, true).expect("failed to create qcow2 file");
    let buf = vec![0xA5u8; QCOW_CLUSTER_SIZE as usize];
    for i in 0..num_l2_tables {
        let offset = i as u64 * L2_ENTRIES_PER_TABLE as u64 * QCOW_CLUSTER_SIZE;
        qcow.seek(SeekFrom::Start(offset)).expect("seek failed");
        qcow.write_all(&buf).expect("write failed");
    }
    qcow.flush().expect("flush failed");
    tmp
}

/// Sparse QCOW2 opened via QcowDiskSync.
pub fn sparse_qcow_tempfile(num_l2_tables: usize) -> (TempFile, QcowDiskSync) {
    let tmp = create_sparse_qcow_tempfile(num_l2_tables);
    let disk = QcowDiskSync::new(tmp.as_file().try_clone().unwrap(), false, false, true)
        .expect("failed to open qcow2 via QcowDiskSync");
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
