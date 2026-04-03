// Copyright © 2021 Intel Corporation
//
// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

//! QCOW2 async disk backend.

use std::cmp::min;
use std::collections::VecDeque;
use std::fs::File;
use std::io::Error;
use std::os::fd::{AsFd, AsRawFd};
use std::sync::Arc;
use std::{fmt, io};

use io_uring::{IoUring, opcode, types};
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::write_zeroes::{PunchHole, WriteZeroesAt};

use crate::async_io::{AsyncIo, AsyncIoError, AsyncIoResult, BorrowedDiskFd, DiskFileError};
use crate::error::{BlockError, BlockErrorKind, BlockResult, ErrorOp};
use crate::qcow::backing::shared_backing_from;
use crate::qcow::metadata::{
    BackingRead, ClusterReadMapping, ClusterWriteMapping, DeallocAction, QcowMetadata,
};
use crate::qcow::qcow_raw_file::QcowRawFile;
use crate::qcow::{MAX_NESTING_DEPTH, RawFile, parse_qcow};
use crate::qcow_common::{
    gather_from_iovecs, pread_exact, pwrite_all, scatter_to_iovecs, zero_fill_iovecs,
};
use crate::{BatchRequest, RequestType, disk_file};

/// Device level handle for a QCOW2 image.
///
/// Owns the parsed metadata and backing file chain. One instance is
/// created per disk and shared across virtio queues.
pub struct QcowDiskAsync {
    metadata: Arc<QcowMetadata>,
    backing_file: Option<Arc<dyn BackingRead>>,
    sparse: bool,
    data_raw_file: QcowRawFile,
}

impl fmt::Debug for QcowDiskAsync {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QcowDiskAsync")
            .field("sparse", &self.sparse)
            .field("has_backing", &self.backing_file.is_some())
            .finish_non_exhaustive()
    }
}

impl QcowDiskAsync {
    pub fn new(
        file: File,
        direct_io: bool,
        backing_files: bool,
        sparse: bool,
    ) -> BlockResult<Self> {
        let max_nesting_depth = if backing_files { MAX_NESTING_DEPTH } else { 0 };
        let (inner, backing_file, sparse) =
            parse_qcow(RawFile::new(file, direct_io), max_nesting_depth, sparse).map_err(|e| {
                let e = if !backing_files && matches!(e.kind(), BlockErrorKind::Overflow) {
                    e.with_kind(BlockErrorKind::UnsupportedFeature)
                } else {
                    e
                };
                e.with_op(ErrorOp::Open)
            })?;
        let data_raw_file = inner.raw_file.clone();
        Ok(QcowDiskAsync {
            metadata: Arc::new(QcowMetadata::new(inner)),
            backing_file: backing_file.map(shared_backing_from).transpose()?,
            sparse,
            data_raw_file,
        })
    }
}

impl Drop for QcowDiskAsync {
    fn drop(&mut self) {
        self.metadata.shutdown();
    }
}

impl disk_file::DiskSize for QcowDiskAsync {
    fn logical_size(&self) -> BlockResult<u64> {
        Ok(self.metadata.virtual_size())
    }
}

impl disk_file::PhysicalSize for QcowDiskAsync {
    fn physical_size(&self) -> BlockResult<u64> {
        Ok(self.data_raw_file.physical_size()?)
    }
}

impl disk_file::DiskFd for QcowDiskAsync {
    fn fd(&self) -> BorrowedDiskFd<'_> {
        BorrowedDiskFd::new(self.data_raw_file.as_fd().as_raw_fd())
    }
}

impl disk_file::Geometry for QcowDiskAsync {}

impl disk_file::SparseCapable for QcowDiskAsync {
    fn supports_sparse_operations(&self) -> bool {
        true
    }

    fn supports_zero_flag(&self) -> bool {
        true
    }
}

impl disk_file::Resizable for QcowDiskAsync {
    fn resize(&mut self, size: u64) -> BlockResult<()> {
        if self.backing_file.is_some() {
            return Err(BlockError::new(
                BlockErrorKind::UnsupportedFeature,
                DiskFileError::ResizeError(io::Error::other(
                    "resize not supported with backing file",
                )),
            )
            .with_op(ErrorOp::Resize));
        }
        self.metadata.resize(size).map_err(|e| {
            BlockError::new(BlockErrorKind::Io, DiskFileError::ResizeError(e))
                .with_op(ErrorOp::Resize)
        })
    }
}

impl disk_file::DiskFile for QcowDiskAsync {}

impl disk_file::AsyncDiskFile for QcowDiskAsync {
    fn try_clone(&self) -> BlockResult<Box<dyn disk_file::AsyncDiskFile>> {
        Ok(Box::new(QcowDiskAsync {
            metadata: Arc::clone(&self.metadata),
            backing_file: self.backing_file.as_ref().map(Arc::clone),
            sparse: self.sparse,
            data_raw_file: self.data_raw_file.clone(),
        }))
    }

    fn new_async_io(&self, ring_depth: u32) -> BlockResult<Box<dyn AsyncIo>> {
        Ok(Box::new(
            QcowAsync::new(
                Arc::clone(&self.metadata),
                self.data_raw_file.clone(),
                self.backing_file.as_ref().map(Arc::clone),
                self.sparse,
                ring_depth,
            )
            .map_err(|e| BlockError::new(BlockErrorKind::Io, DiskFileError::NewAsyncIo(e)))?,
        ))
    }
}

/// Per queue QCOW2 I/O worker using io_uring.
///
/// Reads against fully allocated single mapping clusters are submitted
/// to io_uring for true asynchronous completion. All other cluster
/// types (zero, compressed, backing) and multi mapping reads fall back
/// to synchronous I/O with synthetic completions.
///
/// Writes are synchronous because metadata allocation must complete
/// before the host offset is known.
pub struct QcowAsync {
    metadata: Arc<QcowMetadata>,
    data_file: QcowRawFile,
    backing_file: Option<Arc<dyn BackingRead>>,
    sparse: bool,
    io_uring: IoUring,
    eventfd: EventFd,
    completion_list: VecDeque<(u64, i32)>,
}

impl QcowAsync {
    fn new(
        metadata: Arc<QcowMetadata>,
        data_file: QcowRawFile,
        backing_file: Option<Arc<dyn BackingRead>>,
        sparse: bool,
        ring_depth: u32,
    ) -> io::Result<Self> {
        let io_uring = IoUring::new(ring_depth)?;
        let eventfd = EventFd::new(libc::EFD_NONBLOCK)?;
        io_uring.submitter().register_eventfd(eventfd.as_raw_fd())?;

        Ok(QcowAsync {
            metadata,
            data_file,
            backing_file,
            sparse,
            io_uring,
            eventfd,
            completion_list: VecDeque::new(),
        })
    }

    fn apply_dealloc_action(&mut self, action: &DeallocAction) {
        match action {
            DeallocAction::PunchHole {
                host_offset,
                length,
            } => {
                let _ = self.data_file.file_mut().punch_hole(*host_offset, *length);
            }
            DeallocAction::WriteZeroes {
                host_offset,
                length,
            } => {
                let _ = self
                    .data_file
                    .file_mut()
                    .write_zeroes_at(*host_offset, *length);
            }
        }
    }
}

impl AsyncIo for QcowAsync {
    fn notifier(&self) -> &EventFd {
        &self.eventfd
    }

    fn read_vectored(
        &mut self,
        offset: libc::off_t,
        iovecs: &[libc::iovec],
        user_data: u64,
    ) -> AsyncIoResult<()> {
        let total_len: usize = iovecs.iter().map(|v| v.iov_len).sum();

        if let Some(host_offset) = Self::resolve_read(
            &self.metadata,
            &self.data_file,
            &self.backing_file,
            offset as u64,
            iovecs,
            total_len,
        )? {
            let fd = self.data_file.as_raw_fd();
            let (submitter, mut sq, _) = self.io_uring.split();

            // SAFETY: fd is valid and iovecs point to valid guest memory.
            unsafe {
                sq.push(
                    &opcode::Readv::new(types::Fd(fd), iovecs.as_ptr(), iovecs.len() as u32)
                        .offset(host_offset)
                        .build()
                        .user_data(user_data),
                )
                .map_err(|_| {
                    AsyncIoError::ReadVectored(Error::other("Submission queue is full"))
                })?;
            };

            sq.sync();
            submitter.submit().map_err(AsyncIoError::ReadVectored)?;
        } else {
            self.completion_list
                .push_back((user_data, total_len as i32));
            self.eventfd.write(1).unwrap();
        }
        Ok(())
    }

    // TODO Make writes async.
    // Writes are synchronous. Async writes require a multi step
    // state machine for COW (backing read, cluster allocation, data
    // write, L2 commit) with per request buffer lifetime tracking
    // and write ordering.
    fn write_vectored(
        &mut self,
        offset: libc::off_t,
        iovecs: &[libc::iovec],
        user_data: u64,
    ) -> AsyncIoResult<()> {
        Self::cow_write_sync(
            offset as u64,
            iovecs,
            &self.metadata,
            &self.data_file,
            &self.backing_file,
        )?;

        let total_len: usize = iovecs.iter().map(|v| v.iov_len).sum();
        self.completion_list
            .push_back((user_data, total_len as i32));
        self.eventfd.write(1).unwrap();
        Ok(())
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        self.metadata.flush().map_err(AsyncIoError::Fsync)?;
        if let Some(user_data) = user_data {
            self.completion_list.push_back((user_data, 0));
            self.eventfd.write(1).unwrap();
        }
        Ok(())
    }

    fn next_completed_request(&mut self) -> Option<(u64, i32)> {
        // Drain io_uring completions first, then synthetic ones.
        self.io_uring
            .completion()
            .next()
            .map(|entry| (entry.user_data(), entry.result()))
            .or_else(|| self.completion_list.pop_front())
    }

    fn punch_hole(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        let virtual_size = self.metadata.virtual_size();
        let cluster_size = self.metadata.cluster_size();

        let result = self
            .metadata
            .deallocate_bytes(
                offset,
                length as usize,
                self.sparse,
                virtual_size,
                cluster_size,
                self.backing_file.as_deref(),
            )
            .map_err(AsyncIoError::PunchHole);

        match result {
            Ok(actions) => {
                for action in &actions {
                    self.apply_dealloc_action(action);
                }
                self.completion_list.push_back((user_data, 0));
                self.eventfd.write(1).unwrap();
                Ok(())
            }
            Err(e) => {
                let errno = if let AsyncIoError::PunchHole(ref io_err) = e {
                    -io_err.raw_os_error().unwrap_or(libc::EIO)
                } else {
                    -libc::EIO
                };
                self.completion_list.push_back((user_data, errno));
                self.eventfd.write(1).unwrap();
                Ok(())
            }
        }
    }

    fn write_zeroes(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        // For QCOW2, zeroing and hole punching are the same operation.
        // Both discard guest data so the range reads back as zero.
        self.punch_hole(offset, length, user_data)
    }

    fn batch_requests_enabled(&self) -> bool {
        true
    }

    fn submit_batch_requests(&mut self, batch_request: &[BatchRequest]) -> AsyncIoResult<()> {
        let (submitter, mut sq, _) = self.io_uring.split();
        let mut needs_submit = false;
        let mut sync_completions: Vec<(u64, i32)> = Vec::new();

        for req in batch_request {
            match req.request_type {
                RequestType::In => {
                    let total_len: usize = req.iovecs.iter().map(|v| v.iov_len).sum();

                    if let Some(host_offset) = Self::resolve_read(
                        &self.metadata,
                        &self.data_file,
                        &self.backing_file,
                        req.offset as u64,
                        &req.iovecs,
                        total_len,
                    )? {
                        let fd = self.data_file.as_raw_fd();
                        // SAFETY: fd is valid and iovecs point to valid guest memory.
                        unsafe {
                            sq.push(
                                &opcode::Readv::new(
                                    types::Fd(fd),
                                    req.iovecs.as_ptr(),
                                    req.iovecs.len() as u32,
                                )
                                .offset(host_offset)
                                .build()
                                .user_data(req.user_data),
                            )
                            .map_err(|_| {
                                AsyncIoError::ReadVectored(Error::other("Submission queue is full"))
                            })?;
                        }
                        needs_submit = true;
                    } else {
                        sync_completions.push((req.user_data, total_len as i32));
                    }
                }
                RequestType::Out => {
                    let total_len: usize = req.iovecs.iter().map(|v| v.iov_len).sum();
                    Self::cow_write_sync(
                        req.offset as u64,
                        &req.iovecs,
                        &self.metadata,
                        &self.data_file,
                        &self.backing_file,
                    )?;
                    sync_completions.push((req.user_data, total_len as i32));
                }
                _ => {
                    unreachable!("Unexpected batch request type: {:?}", req.request_type)
                }
            }
        }

        if needs_submit {
            sq.sync();
            submitter
                .submit()
                .map_err(AsyncIoError::SubmitBatchRequests)?;
        }

        if !sync_completions.is_empty() {
            for c in sync_completions {
                self.completion_list.push_back(c);
            }
            self.eventfd.write(1).unwrap();
        }

        Ok(())
    }
}

impl QcowAsync {
    /// Resolves read mappings for a guest read request.
    ///
    /// Returns `Some(host_offset)` if the entire read falls within a single
    /// allocated cluster (fast path). Otherwise handles the read
    /// synchronously via `scatter_read_sync` and returns `None`.
    #[inline]
    fn resolve_read(
        metadata: &QcowMetadata,
        data_file: &QcowRawFile,
        backing_file: &Option<Arc<dyn BackingRead>>,
        address: u64,
        iovecs: &[libc::iovec],
        total_len: usize,
    ) -> AsyncIoResult<Option<u64>> {
        let has_backing = backing_file.is_some();
        let mappings = metadata
            .map_clusters_for_read(address, total_len, has_backing)
            .map_err(AsyncIoError::ReadVectored)?;

        if mappings.len() == 1
            && let ClusterReadMapping::Allocated {
                offset: host_offset,
                length,
            } = &mappings[0]
            && *length as usize == total_len
        {
            return Ok(Some(*host_offset));
        }

        Self::scatter_read_sync(mappings, iovecs, data_file, backing_file)?;
        Ok(None)
    }

    /// Scatter-read cluster mappings synchronously into iovec buffers.
    #[inline]
    fn scatter_read_sync(
        mappings: Vec<ClusterReadMapping>,
        iovecs: &[libc::iovec],
        data_file: &QcowRawFile,
        backing_file: &Option<Arc<dyn BackingRead>>,
    ) -> AsyncIoResult<()> {
        let mut buf_offset = 0usize;
        for mapping in mappings {
            match mapping {
                ClusterReadMapping::Zero { length } => {
                    // SAFETY: iovecs point to valid guest memory buffers.
                    unsafe {
                        zero_fill_iovecs(iovecs, buf_offset, length as usize);
                    }
                    buf_offset += length as usize;
                }
                ClusterReadMapping::Allocated {
                    offset: host_offset,
                    length,
                } => {
                    let mut buf = vec![0u8; length as usize];
                    pread_exact(data_file.as_raw_fd(), &mut buf, host_offset)
                        .map_err(AsyncIoError::ReadVectored)?;
                    // SAFETY: iovecs point to valid guest memory buffers.
                    unsafe { scatter_to_iovecs(iovecs, buf_offset, &buf) };
                    buf_offset += length as usize;
                }
                ClusterReadMapping::Compressed { data } => {
                    let len = data.len();
                    // SAFETY: iovecs point to valid guest memory buffers.
                    unsafe { scatter_to_iovecs(iovecs, buf_offset, &data) };
                    buf_offset += len;
                }
                ClusterReadMapping::Backing {
                    offset: backing_offset,
                    length,
                } => {
                    let mut buf = vec![0u8; length as usize];
                    backing_file
                        .as_ref()
                        .unwrap()
                        .read_at(backing_offset, &mut buf)
                        .map_err(AsyncIoError::ReadVectored)?;
                    // SAFETY: iovecs point to valid guest memory buffers.
                    unsafe { scatter_to_iovecs(iovecs, buf_offset, &buf) };
                    buf_offset += length as usize;
                }
            }
        }
        Ok(())
    }

    /// Write iovec data cluster-by-cluster with COW from backing file.
    #[inline]
    fn cow_write_sync(
        address: u64,
        iovecs: &[libc::iovec],
        metadata: &QcowMetadata,
        data_file: &QcowRawFile,
        backing_file: &Option<Arc<dyn BackingRead>>,
    ) -> AsyncIoResult<()> {
        let total_len: usize = iovecs.iter().map(|v| v.iov_len).sum();
        let mut buf_offset = 0usize;

        while buf_offset < total_len {
            let curr_addr = address + buf_offset as u64;
            let cluster_size = metadata.cluster_size();
            let intra_offset = metadata.cluster_offset(curr_addr);
            let remaining_in_cluster = (cluster_size - intra_offset) as usize;
            let count = min(total_len - buf_offset, remaining_in_cluster);

            let backing_data = if let Some(backing) = backing_file
                .as_ref()
                .filter(|_| intra_offset != 0 || count < cluster_size as usize)
            {
                let cluster_begin = curr_addr - intra_offset;
                let mut data = vec![0u8; cluster_size as usize];
                backing
                    .read_at(cluster_begin, &mut data)
                    .map_err(AsyncIoError::WriteVectored)?;
                Some(data)
            } else {
                None
            };

            let mapping = metadata
                .map_cluster_for_write(curr_addr, backing_data)
                .map_err(AsyncIoError::WriteVectored)?;

            match mapping {
                ClusterWriteMapping::Allocated {
                    offset: host_offset,
                } => {
                    // SAFETY: iovecs point to valid guest memory buffers.
                    let buf = unsafe { gather_from_iovecs(iovecs, buf_offset, count) };
                    pwrite_all(data_file.as_raw_fd(), &buf, host_offset)
                        .map_err(AsyncIoError::WriteVectored)?;
                }
            }
            buf_offset += count;
        }
        Ok(())
    }
}

#[cfg(test)]
mod unit_tests {
    use std::io::{Seek, SeekFrom, Write};

    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::disk_file::AsyncDiskFile;
    use crate::qcow::{QcowFile, RawFile};
    use crate::{BatchRequest, RequestType};

    fn create_disk_with_data(
        file_size: u64,
        data: &[u8],
        offset: u64,
        sparse: bool,
    ) -> (TempFile, QcowDiskAsync) {
        let temp_file = TempFile::new().unwrap();
        {
            let raw_file = RawFile::new(temp_file.as_file().try_clone().unwrap(), false);
            let mut qcow_file = QcowFile::new(raw_file, 3, file_size, sparse).unwrap();
            qcow_file.seek(SeekFrom::Start(offset)).unwrap();
            qcow_file.write_all(data).unwrap();
            qcow_file.flush().unwrap();
        }
        let disk = QcowDiskAsync::new(
            temp_file.as_file().try_clone().unwrap(),
            false,
            false,
            sparse,
        )
        .unwrap();
        (temp_file, disk)
    }

    fn wait_for_completion(async_io: &mut dyn AsyncIo) -> (u64, i32) {
        loop {
            if let Some(c) = async_io.next_completed_request() {
                return c;
            }
            // Block until the eventfd is signaled (io_uring or synthetic).
            let fd = async_io.notifier().as_raw_fd();
            let mut val = 0u64;
            // SAFETY: reading 8 bytes from a valid eventfd.
            unsafe {
                libc::read(fd, &mut val as *mut u64 as *mut libc::c_void, 8);
            }
        }
    }

    fn async_write(disk: &QcowDiskAsync, offset: u64, data: &[u8]) {
        let mut async_io = disk.new_async_io(1).unwrap();
        let iovec = libc::iovec {
            iov_base: data.as_ptr() as *mut libc::c_void,
            iov_len: data.len(),
        };
        async_io
            .write_vectored(offset as libc::off_t, &[iovec], 2)
            .unwrap();
        let (user_data, result) = wait_for_completion(async_io.as_mut());
        assert_eq!(user_data, 2);
        assert_eq!(
            result as usize,
            data.len(),
            "write should return requested length"
        );
    }

    fn async_read(disk: &QcowDiskAsync, offset: u64, len: usize) -> Vec<u8> {
        let mut async_io = disk.new_async_io(1).unwrap();
        let mut buf = vec![0xFFu8; len];
        let iovec = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        async_io
            .read_vectored(offset as libc::off_t, &[iovec], 1)
            .unwrap();
        let (user_data, result) = wait_for_completion(async_io.as_mut());
        assert_eq!(user_data, 1);
        assert_eq!(result as usize, len, "read should return requested length");
        buf
    }

    #[test]
    fn test_qcow_async_punch_hole_completion() {
        let data = vec![0xDD; 128 * 1024];
        let offset = 0u64;
        let (_temp, disk) = create_disk_with_data(100 * 1024 * 1024, &data, offset, true);

        let mut async_io = disk.new_async_io(1).unwrap();
        async_io.punch_hole(offset, data.len() as u64, 100).unwrap();
        let (user_data, result) = async_io.next_completed_request().unwrap();
        assert_eq!(user_data, 100);
        assert_eq!(result, 0, "punch_hole should succeed");
        drop(async_io);

        let read_buf = async_read(&disk, offset, data.len());
        assert!(
            read_buf.iter().all(|&b| b == 0),
            "Punched hole should read as zeros"
        );
    }

    #[test]
    fn test_qcow_async_write_zeroes_completion() {
        let data = vec![0xAA; 128 * 1024];
        let offset = 0u64;
        let (_temp, disk) = create_disk_with_data(100 * 1024 * 1024, &data, offset, true);

        let mut async_io = disk.new_async_io(1).unwrap();
        async_io
            .write_zeroes(offset, data.len() as u64, 200)
            .unwrap();
        let (user_data, result) = async_io.next_completed_request().unwrap();
        assert_eq!(user_data, 200);
        assert_eq!(result, 0, "write_zeroes should succeed");
        drop(async_io);

        let read_buf = async_read(&disk, offset, data.len());
        assert!(
            read_buf.iter().all(|&b| b == 0),
            "Write zeroes region should read as zeros"
        );
    }

    #[test]
    fn test_qcow_async_write_read_roundtrip() {
        let file_size = 100 * 1024 * 1024;
        let temp_file = TempFile::new().unwrap();
        {
            let raw_file = RawFile::new(temp_file.as_file().try_clone().unwrap(), false);
            QcowFile::new(raw_file, 3, file_size, true).unwrap();
        }
        let disk = QcowDiskAsync::new(temp_file.as_file().try_clone().unwrap(), false, false, true)
            .unwrap();

        let pattern: Vec<u8> = (0..128 * 1024).map(|i| (i % 251) as u8).collect();
        let offset = 64 * 1024;

        async_write(&disk, offset, &pattern);
        let read_buf = async_read(&disk, offset, pattern.len());
        assert_eq!(read_buf, pattern, "read should match written data");
    }

    #[test]
    fn test_qcow_async_read_spanning_cluster_boundary() {
        let cluster_size: u64 = 65536;
        let file_size = 100 * 1024 * 1024;

        // Write distinct patterns into two adjacent clusters.
        let pattern_a = vec![0xAA; cluster_size as usize];
        let pattern_b = vec![0xBB; cluster_size as usize];
        let (_temp, disk) = create_disk_with_data(file_size, &pattern_a, 0, true);
        async_write(&disk, cluster_size, &pattern_b);

        // Read across the boundary: last 4K of cluster 0 + first 4K of cluster 1.
        let read_offset = cluster_size - 4096;
        let read_len = 8192;
        let buf = async_read(&disk, read_offset, read_len);

        assert!(
            buf[..4096].iter().all(|&b| b == 0xAA),
            "first half should come from cluster 0"
        );
        assert!(
            buf[4096..].iter().all(|&b| b == 0xBB),
            "second half should come from cluster 1"
        );
    }

    #[test]
    fn test_qcow_async_batch_mixed_requests() {
        let file_size = 100 * 1024 * 1024;
        let temp_file = TempFile::new().unwrap();
        {
            let raw_file = RawFile::new(temp_file.as_file().try_clone().unwrap(), false);
            QcowFile::new(raw_file, 3, file_size, true).unwrap();
        }
        let disk = QcowDiskAsync::new(temp_file.as_file().try_clone().unwrap(), false, false, true)
            .unwrap();

        let mut async_io = disk.new_async_io(8).unwrap();

        // Prepare write data for two regions.
        let write_a = vec![0xAA; 4096];
        let write_b = vec![0xBB; 4096];
        let offset_a: u64 = 0;
        let offset_b: u64 = 65536;

        let iov_a = libc::iovec {
            iov_base: write_a.as_ptr() as *mut libc::c_void,
            iov_len: write_a.len(),
        };
        let iov_b = libc::iovec {
            iov_base: write_b.as_ptr() as *mut libc::c_void,
            iov_len: write_b.len(),
        };

        let batch = vec![
            BatchRequest {
                offset: offset_a as libc::off_t,
                iovecs: smallvec::smallvec![iov_a],
                user_data: 10,
                request_type: RequestType::Out,
            },
            BatchRequest {
                offset: offset_b as libc::off_t,
                iovecs: smallvec::smallvec![iov_b],
                user_data: 20,
                request_type: RequestType::Out,
            },
        ];

        async_io.submit_batch_requests(&batch).unwrap();

        let mut completions = Vec::new();
        while completions.len() < 2 {
            if let Some(c) = async_io.next_completed_request() {
                completions.push(c);
            }
        }
        completions.sort_by_key(|c| c.0);
        assert_eq!(completions[0], (10, 4096));
        assert_eq!(completions[1], (20, 4096));
        drop(async_io);

        // Batch read both regions back.
        let mut read_a = vec![0u8; 4096];
        let mut read_b = vec![0u8; 4096];
        let riov_a = libc::iovec {
            iov_base: read_a.as_mut_ptr() as *mut libc::c_void,
            iov_len: read_a.len(),
        };
        let riov_b = libc::iovec {
            iov_base: read_b.as_mut_ptr() as *mut libc::c_void,
            iov_len: read_b.len(),
        };

        let mut async_io = disk.new_async_io(8).unwrap();
        let read_batch = vec![
            BatchRequest {
                offset: offset_a as libc::off_t,
                iovecs: smallvec::smallvec![riov_a],
                user_data: 30,
                request_type: RequestType::In,
            },
            BatchRequest {
                offset: offset_b as libc::off_t,
                iovecs: smallvec::smallvec![riov_b],
                user_data: 40,
                request_type: RequestType::In,
            },
        ];

        async_io.submit_batch_requests(&read_batch).unwrap();

        let mut completions = Vec::new();
        while completions.len() < 2 {
            if let Some(c) = async_io.next_completed_request() {
                completions.push(c);
            }
        }
        completions.sort_by_key(|c| c.0);
        assert_eq!(completions[0], (30, 4096));
        assert_eq!(completions[1], (40, 4096));

        assert_eq!(read_a, write_a, "batch read A should match written data");
        assert_eq!(read_b, write_b, "batch read B should match written data");
    }

    #[test]
    fn test_qcow_async_read_unallocated() {
        let file_size = 100 * 1024 * 1024;
        let temp_file = TempFile::new().unwrap();
        {
            let raw_file = RawFile::new(temp_file.as_file().try_clone().unwrap(), false);
            QcowFile::new(raw_file, 3, file_size, true).unwrap();
        }
        let disk = QcowDiskAsync::new(temp_file.as_file().try_clone().unwrap(), false, false, true)
            .unwrap();

        let buf = async_read(&disk, 0, 128 * 1024);
        assert!(
            buf.iter().all(|&b| b == 0),
            "unallocated region should read as zeroes"
        );
    }

    #[test]
    fn test_qcow_async_sub_cluster_write() {
        let cluster_size = 65536usize;
        let file_size = 100 * 1024 * 1024;
        let temp_file = TempFile::new().unwrap();
        {
            let raw_file = RawFile::new(temp_file.as_file().try_clone().unwrap(), false);
            QcowFile::new(raw_file, 3, file_size, true).unwrap();
        }
        let disk = QcowDiskAsync::new(temp_file.as_file().try_clone().unwrap(), false, false, true)
            .unwrap();

        // Write 4K into the middle of a cluster.
        let write_offset = 4096u64;
        let write_len = 4096;
        let pattern = vec![0xCC; write_len];
        async_write(&disk, write_offset, &pattern);

        // Read the entire cluster back.
        let buf = async_read(&disk, 0, cluster_size);

        assert!(
            buf[..write_offset as usize].iter().all(|&b| b == 0),
            "bytes before the write should be zero"
        );
        assert_eq!(
            &buf[write_offset as usize..write_offset as usize + write_len],
            &pattern[..],
            "written region should match"
        );
        assert!(
            buf[write_offset as usize + write_len..]
                .iter()
                .all(|&b| b == 0),
            "bytes after the write should be zero"
        );
    }

    #[test]
    fn test_qcow_async_write_after_punch_hole() {
        let data = vec![0xAA; 64 * 1024];
        let offset = 0u64;
        let (_temp, disk) = create_disk_with_data(100 * 1024 * 1024, &data, offset, true);

        let buf = async_read(&disk, offset, data.len());
        assert!(buf.iter().all(|&b| b == 0xAA));

        let mut async_io = disk.new_async_io(1).unwrap();
        async_io.punch_hole(offset, data.len() as u64, 10).unwrap();
        let (_, result) = wait_for_completion(async_io.as_mut());
        assert_eq!(result, 0);
        drop(async_io);

        let buf = async_read(&disk, offset, data.len());
        assert!(
            buf.iter().all(|&b| b == 0),
            "should be zero after punch hole"
        );

        let new_data = vec![0xBB; 64 * 1024];
        async_write(&disk, offset, &new_data);

        let buf = async_read(&disk, offset, new_data.len());
        assert_eq!(buf, new_data, "should read new data after rewrite");
    }

    #[test]
    fn test_qcow_async_large_sequential_io() {
        let cluster_size = 64 * 1024;
        let num_clusters = 8;
        let total_len = cluster_size * num_clusters;
        let offset = 0u64;

        let mut data = vec![0u8; total_len];
        for (i, chunk) in data.chunks_mut(cluster_size).enumerate() {
            chunk.fill((i + 1) as u8);
        }

        let (_temp, disk) = create_disk_with_data(100 * 1024 * 1024, &data, offset, true);

        let buf = async_read(&disk, offset, total_len);
        assert_eq!(buf.len(), total_len);
        for (i, chunk) in buf.chunks(cluster_size).enumerate() {
            assert!(
                chunk.iter().all(|&b| b == (i + 1) as u8),
                "cluster {i} mismatch"
            );
        }
    }
}
