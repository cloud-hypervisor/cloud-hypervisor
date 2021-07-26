// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use crate::async_io::{AsyncIo, AsyncIoResult, DiskFile, DiskFileError, DiskFileResult};
use crate::{fsync_sync, read_vectored_sync, write_vectored_sync};
use std::fs::File;
use std::ops::DerefMut;
use std::sync::{Arc, Mutex};
use vhdx::vhdx::{Result as VhdxResult, Vhdx};
use vmm_sys_util::eventfd::EventFd;

pub struct VhdxDiskSync {
    vhdx_file: Arc<Mutex<Vhdx>>,
    semaphore: Arc<Mutex<()>>,
}

impl VhdxDiskSync {
    pub fn new(f: File) -> VhdxResult<Self> {
        let vhdx = Vhdx::new(f)?;
        let vhdx_file = Arc::new(Mutex::new(vhdx));

        Ok(VhdxDiskSync {
            vhdx_file,
            semaphore: Arc::new(Mutex::new(())),
        })
    }
}

impl DiskFile for VhdxDiskSync {
    fn size(&mut self) -> DiskFileResult<u64> {
        Ok(self.vhdx_file.lock().unwrap().virtual_disk_size())
    }

    fn new_async_io(&self, _ring_depth: u32) -> DiskFileResult<Box<dyn AsyncIo>> {
        Ok(Box::new(
            VhdxSync::new(self.vhdx_file.clone(), self.semaphore.clone())
                .map_err(DiskFileError::NewAsyncIo)?,
        ) as Box<dyn AsyncIo>)
    }
}

pub struct VhdxSync {
    vhdx_file: Arc<Mutex<Vhdx>>,
    eventfd: EventFd,
    completion_list: Vec<(u64, i32)>,
    semaphore: Arc<Mutex<()>>,
}

impl VhdxSync {
    pub fn new(vhdx_file: Arc<Mutex<Vhdx>>, semaphore: Arc<Mutex<()>>) -> std::io::Result<Self> {
        Ok(VhdxSync {
            vhdx_file,
            eventfd: EventFd::new(libc::EFD_NONBLOCK)?,
            completion_list: Vec::new(),
            semaphore,
        })
    }
}

impl AsyncIo for VhdxSync {
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
            self.vhdx_file.lock().unwrap().deref_mut(),
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
            self.vhdx_file.lock().unwrap().deref_mut(),
            &self.eventfd,
            &mut self.completion_list,
            &mut self.semaphore,
        )
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        fsync_sync(
            user_data,
            self.vhdx_file.lock().unwrap().deref_mut(),
            &self.eventfd,
            &mut self.completion_list,
            &mut self.semaphore,
        )
    }

    fn complete(&mut self) -> Vec<(u64, i32)> {
        self.completion_list.drain(..).collect()
    }
}
