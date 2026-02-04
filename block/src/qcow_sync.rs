// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};

use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::write_zeroes::PunchHole;

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

    fn punch_hole(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        // For QCOW2, punch_hole calls deallocate_cluster
        let result = self
            .qcow_file
            .lock()
            .unwrap()
            .punch_hole(offset, length)
            .map(|_| 0i32)
            .map_err(AsyncIoError::PunchHole);

        match result {
            Ok(res) => {
                self.completion_list.push_back((user_data, res));
                self.eventfd.write(1).unwrap();
                Ok(())
            }
            Err(e) => {
                // CRITICAL: Always signal completion even on error to avoid hangs
                let errno = if let AsyncIoError::PunchHole(io_err) = &e {
                    let err = io_err.raw_os_error().unwrap_or(libc::EIO);
                    -err
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
        // For QCOW2, write_zeroes is implemented by deallocating clusters via punch_hole.
        // This is more efficient than writing actual zeros and reduces disk usage.
        // Unallocated clusters inherently read as zero in the QCOW2 format.
        let result = self
            .qcow_file
            .lock()
            .unwrap()
            .punch_hole(offset, length)
            .map(|_| 0i32)
            .map_err(AsyncIoError::WriteZeroes);

        match result {
            Ok(res) => {
                self.completion_list.push_back((user_data, res));
                self.eventfd.write(1).unwrap();
                Ok(())
            }
            Err(e) => {
                // Always signal completion even on error to avoid hangs
                let errno = if let AsyncIoError::WriteZeroes(io_err) = &e {
                    let err = io_err.raw_os_error().unwrap_or(libc::EIO);
                    -err
                } else {
                    -libc::EIO
                };
                self.completion_list.push_back((user_data, errno));
                self.eventfd.write(1).unwrap();
                Ok(())
            }
        }
    }
}
