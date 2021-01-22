// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use crate::async_io::{AsyncIo, AsyncIoResult, DiskFile, DiskFileResult};
use crate::{disk_size, fsync_sync, read_vectored_sync, write_vectored_sync};
use qcow::{QcowFile, RawFile};
use std::fs::File;
use std::sync::{Arc, Mutex};
use vmm_sys_util::eventfd::EventFd;

pub struct QcowDiskSync {
    qcow_file: QcowFile,
    semaphore: Arc<Mutex<()>>,
}

impl QcowDiskSync {
    pub fn new(file: File, direct_io: bool) -> Self {
        QcowDiskSync {
            qcow_file: QcowFile::from(RawFile::new(file, direct_io))
                .expect("Failed creating QcowFile"),
            semaphore: Arc::new(Mutex::new(())),
        }
    }
}

impl DiskFile for QcowDiskSync {
    fn size(&mut self) -> DiskFileResult<u64> {
        disk_size(&mut self.qcow_file, &mut self.semaphore)
    }

    fn new_async_io(&self, _ring_depth: u32) -> DiskFileResult<Box<dyn AsyncIo>> {
        Ok(Box::new(QcowSync::new(
            self.qcow_file.clone(),
            self.semaphore.clone(),
        )) as Box<dyn AsyncIo>)
    }
}

pub struct QcowSync {
    qcow_file: QcowFile,
    eventfd: EventFd,
    completion_list: Vec<(u64, i32)>,
    semaphore: Arc<Mutex<()>>,
}

impl QcowSync {
    pub fn new(qcow_file: QcowFile, semaphore: Arc<Mutex<()>>) -> Self {
        QcowSync {
            qcow_file,
            eventfd: EventFd::new(libc::EFD_NONBLOCK)
                .expect("Failed creating EventFd for QcowSync"),
            completion_list: Vec::new(),
            semaphore,
        }
    }
}

impl AsyncIo for QcowSync {
    fn notifier(&self) -> &EventFd {
        &self.eventfd
    }

    fn read_vectored(
        &mut self,
        offset: libc::off_t,
        iovecs: Vec<libc::iovec>,
        user_data: u64,
    ) -> AsyncIoResult<()> {
        read_vectored_sync(
            offset,
            iovecs,
            user_data,
            &mut self.qcow_file,
            &self.eventfd,
            &mut self.completion_list,
            &mut self.semaphore,
        )
    }

    fn write_vectored(
        &mut self,
        offset: libc::off_t,
        iovecs: Vec<libc::iovec>,
        user_data: u64,
    ) -> AsyncIoResult<()> {
        write_vectored_sync(
            offset,
            iovecs,
            user_data,
            &mut self.qcow_file,
            &self.eventfd,
            &mut self.completion_list,
            &mut self.semaphore,
        )
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        fsync_sync(
            user_data,
            &mut self.qcow_file,
            &self.eventfd,
            &mut self.completion_list,
            &mut self.semaphore,
        )
    }

    fn complete(&mut self) -> Vec<(u64, i32)> {
        self.completion_list.drain(..).collect()
    }
}
