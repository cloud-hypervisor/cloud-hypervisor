// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Shared benchmark helpers.

use std::io::{ErrorKind, Seek, SeekFrom, Write};
use std::thread;
use std::time::Duration;

use block::async_io::AsyncIo;
use block::qcow::{QcowFile, RawFile};
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
