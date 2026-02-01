// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};

use vmm_sys_util::eventfd::EventFd;

use crate::async_io::{
    AsyncIo, AsyncIoError, AsyncIoResult, BorrowedDiskFd, DiskFile, DiskFileError, DiskFileResult,
};
use crate::qcow::{MAX_NESTING_DEPTH, QcowFile, RawFile, Result as QcowResult};
use crate::{AsyncAdaptor, BlockBackend};

pub struct QcowDiskSync {
    // FIXME: The Mutex serializes all QCOW2 I/O operations across queues, which
    // is necessary for correctness but eliminates any parallelism benefit from
    // multiqueue. QcowFile has internal mutable state (L2 cache, refcounts, file
    // position) that is not safe to share across threads via Clone.
    //
    // A proper fix would require restructuring QcowFile to separate metadata
    // operations (which need synchronization) from data I/O (which could be
    // parallelized with per queue file descriptors). See #7560 for details.
    qcow_file: Arc<Mutex<QcowFile>>,
}

impl QcowDiskSync {
    pub fn new(file: File, direct_io: bool, backing_files: bool, sparse: bool) -> QcowResult<Self> {
        let max_nesting_depth = if backing_files { MAX_NESTING_DEPTH } else { 0 };
        Ok(QcowDiskSync {
            qcow_file: Arc::new(Mutex::new(QcowFile::from_with_nesting_depth(
                RawFile::new(file, direct_io),
                max_nesting_depth,
                sparse,
            )?)),
        })
    }
}

impl DiskFile for QcowDiskSync {
    fn logical_size(&mut self) -> DiskFileResult<u64> {
        self.qcow_file
            .lock()
            .unwrap()
            .seek(SeekFrom::End(0))
            .map_err(DiskFileError::Size)
    }

    fn physical_size(&mut self) -> DiskFileResult<u64> {
        self.qcow_file.lock().unwrap().physical_size().map_err(|e| {
            let io_inner = match e {
                crate::Error::GetFileMetadata(e) => e,
                _ => unreachable!(),
            };
            DiskFileError::Size(io_inner)
        })
    }

    fn new_async_io(&self, _ring_depth: u32) -> DiskFileResult<Box<dyn AsyncIo>> {
        Ok(Box::new(QcowSync::new(Arc::clone(&self.qcow_file))) as Box<dyn AsyncIo>)
    }

    fn resize(&mut self, size: u64) -> DiskFileResult<()> {
        self.qcow_file
            .lock()
            .unwrap()
            .resize(size)
            .map_err(|e| DiskFileError::ResizeError(io::Error::other(e)))
    }

    fn supports_sparse_operations(&self) -> bool {
        true
    }

    fn supports_zero_flag(&self) -> bool {
        true
    }

    fn fd(&mut self) -> BorrowedDiskFd<'_> {
        BorrowedDiskFd::new(self.qcow_file.lock().unwrap().as_raw_fd())
    }
}

pub struct QcowSync {
    qcow_file: Arc<Mutex<QcowFile>>,
    eventfd: EventFd,
    completion_list: VecDeque<(u64, i32)>,
}

impl QcowSync {
    pub fn new(qcow_file: Arc<Mutex<QcowFile>>) -> Self {
        QcowSync {
            qcow_file,
            eventfd: EventFd::new(libc::EFD_NONBLOCK)
                .expect("Failed creating EventFd for QcowSync"),
            completion_list: VecDeque::new(),
        }
    }
}

impl AsyncAdaptor for QcowFile {}

impl AsyncIo for QcowSync {
    fn notifier(&self) -> &EventFd {
        &self.eventfd
    }

    fn read_vectored(
        &mut self,
        offset: libc::off_t,
        iovecs: &[libc::iovec],
        user_data: u64,
    ) -> AsyncIoResult<()> {
        self.qcow_file.lock().unwrap().read_vectored_sync(
            offset,
            iovecs,
            user_data,
            &self.eventfd,
            &mut self.completion_list,
        )
    }

    fn write_vectored(
        &mut self,
        offset: libc::off_t,
        iovecs: &[libc::iovec],
        user_data: u64,
    ) -> AsyncIoResult<()> {
        self.qcow_file.lock().unwrap().write_vectored_sync(
            offset,
            iovecs,
            user_data,
            &self.eventfd,
            &mut self.completion_list,
        )
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        self.qcow_file.lock().unwrap().fsync_sync(
            user_data,
            &self.eventfd,
            &mut self.completion_list,
        )
    }

    fn next_completed_request(&mut self) -> Option<(u64, i32)> {
        self.completion_list.pop_front()
    }

    fn punch_hole(&mut self, _offset: u64, _length: u64, _user_data: u64) -> AsyncIoResult<()> {
        Err(AsyncIoError::PunchHole(std::io::Error::other(
            "punch_hole not supported for QCOW sync backend",
        )))
    }

    fn write_zeroes(&mut self, _offset: u64, _length: u64, _user_data: u64) -> AsyncIoResult<()> {
        Err(AsyncIoError::WriteZeroes(std::io::Error::other(
            "write_zeroes not supported for QCOW sync backend",
        )))
    }
}
