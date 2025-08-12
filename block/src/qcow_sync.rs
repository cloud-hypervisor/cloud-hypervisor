// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::collections::VecDeque;
use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::os::fd::AsRawFd;

use vmm_sys_util::eventfd::EventFd;

use crate::AsyncAdaptor;
use crate::async_io::{
    AsyncIo, AsyncIoResult, BorrowedDiskFd, DiskFile, DiskFileError, DiskFileResult,
};
use crate::qcow::{QcowFile, RawFile, Result as QcowResult};

pub struct QcowDiskSync {
    qcow_file: QcowFile,
}

impl QcowDiskSync {
    pub fn new(file: File, direct_io: bool) -> QcowResult<Self> {
        Ok(QcowDiskSync {
            qcow_file: QcowFile::from(RawFile::new(file, direct_io))?,
        })
    }
}

impl DiskFile for QcowDiskSync {
    fn size(&mut self) -> DiskFileResult<u64> {
        self.qcow_file
            .seek(SeekFrom::End(0))
            .map_err(DiskFileError::Size)
    }

    fn new_async_io(&self, _ring_depth: u32) -> DiskFileResult<Box<dyn AsyncIo>> {
        Ok(Box::new(QcowSync::new(self.qcow_file.clone())) as Box<dyn AsyncIo>)
    }

    fn fd(&mut self) -> BorrowedDiskFd<'_> {
        BorrowedDiskFd::new(self.qcow_file.as_raw_fd())
    }
}

pub struct QcowSync {
    qcow_file: QcowFile,
    eventfd: EventFd,
    completion_list: VecDeque<(u64, i32)>,
}

impl QcowSync {
    pub fn new(qcow_file: QcowFile) -> Self {
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
        self.qcow_file.read_vectored_sync(
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
        self.qcow_file.write_vectored_sync(
            offset,
            iovecs,
            user_data,
            &self.eventfd,
            &mut self.completion_list,
        )
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        self.qcow_file
            .fsync_sync(user_data, &self.eventfd, &mut self.completion_list)
    }

    fn next_completed_request(&mut self) -> Option<(u64, i32)> {
        self.completion_list.pop_front()
    }
}
