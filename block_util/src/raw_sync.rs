// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use crate::async_io::{AsyncIo, AsyncIoResult, DiskFile, DiskFileResult};
use crate::{disk_size, fsync_sync, read_vectored_sync, write_vectored_sync};
use qcow::RawFile;
use std::fs::File;
use std::sync::{Arc, Mutex};
use vmm_sys_util::eventfd::EventFd;

pub struct RawFileDiskSync {
    raw_file: RawFile,
    semaphore: Arc<Mutex<()>>,
}

impl RawFileDiskSync {
    pub fn new(file: File, direct_io: bool) -> Self {
        RawFileDiskSync {
            raw_file: RawFile::new(file, direct_io),
            semaphore: Arc::new(Mutex::new(())),
        }
    }
}

impl DiskFile for RawFileDiskSync {
    fn size(&mut self) -> DiskFileResult<u64> {
        disk_size(&mut self.raw_file, &mut self.semaphore)
    }

    fn new_async_io(&self, _ring_depth: u32) -> DiskFileResult<Box<dyn AsyncIo>> {
        Ok(Box::new(RawFileSync::new(
            self.raw_file.clone(),
            self.semaphore.clone(),
        )) as Box<dyn AsyncIo>)
    }
}

pub struct RawFileSync {
    raw_file: RawFile,
    eventfd: EventFd,
    completion_list: Vec<(u64, i32)>,
    semaphore: Arc<Mutex<()>>,
}

impl RawFileSync {
    pub fn new(raw_file: RawFile, semaphore: Arc<Mutex<()>>) -> Self {
        RawFileSync {
            raw_file,
            eventfd: EventFd::new(libc::EFD_NONBLOCK).expect("Failed creating EventFd for RawFile"),
            completion_list: Vec::new(),
            semaphore,
        }
    }
}

impl AsyncIo for RawFileSync {
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
            &mut self.raw_file,
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
            &mut self.raw_file,
            &self.eventfd,
            &mut self.completion_list,
            &mut self.semaphore,
        )
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        fsync_sync(
            user_data,
            &mut self.raw_file,
            &self.eventfd,
            &mut self.completion_list,
            &mut self.semaphore,
        )
    }

    fn complete(&mut self) -> Vec<(u64, i32)> {
        self.completion_list.drain(..).collect()
    }
}
