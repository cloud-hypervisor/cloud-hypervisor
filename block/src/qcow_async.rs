// Copyright © 2021 Intel Corporation
//
// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

//! QCOW2 async disk backend.

use std::collections::VecDeque;
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd};
use std::sync::Arc;
use std::{fmt, io};

use io_uring::IoUring;
use vmm_sys_util::eventfd::EventFd;

use crate::async_io::{AsyncIo, AsyncIoResult, BorrowedDiskFd, DiskFileError};
use crate::disk_file;
use crate::error::{BlockError, BlockErrorKind, BlockResult, ErrorOp};
use crate::qcow::backing::shared_backing_from;
use crate::qcow::metadata::{BackingRead, QcowMetadata};
use crate::qcow::qcow_raw_file::QcowRawFile;
use crate::qcow::{MAX_NESTING_DEPTH, RawFile, parse_qcow};

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
        unimplemented!()
    }

    fn write_vectored(
        &mut self,
        offset: libc::off_t,
        iovecs: &[libc::iovec],
        user_data: u64,
    ) -> AsyncIoResult<()> {
        unimplemented!()
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        unimplemented!()
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
        unimplemented!()
    }

    fn write_zeroes(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        unimplemented!()
    }
}
