// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex, MutexGuard};

use vmm_sys_util::eventfd::EventFd;

use crate::async_io::{
    AsyncIo, AsyncIoResult, BorrowedDiskFd, DiskFile, DiskFileError, DiskFileResult,
};
use crate::vhdx::{Result as VhdxResult, Vhdx};
use crate::AsyncAdaptor;

pub struct VhdxDiskSync {
    vhdx_file: Arc<Mutex<Vhdx>>,
}

impl VhdxDiskSync {
    pub fn new(f: File) -> VhdxResult<Self> {
        Ok(VhdxDiskSync {
            vhdx_file: Arc::new(Mutex::new(Vhdx::new(f)?)),
        })
    }
}

impl DiskFile for VhdxDiskSync {
    fn size(&mut self) -> DiskFileResult<u64> {
        Ok(self.vhdx_file.lock().unwrap().virtual_disk_size())
    }

    fn new_async_io(&self, _ring_depth: u32) -> DiskFileResult<Box<dyn AsyncIo>> {
        Ok(
            Box::new(VhdxSync::new(self.vhdx_file.clone()).map_err(DiskFileError::NewAsyncIo)?)
                as Box<dyn AsyncIo>,
        )
    }

    fn fd(&mut self) -> BorrowedDiskFd<'_> {
        let lock = self.vhdx_file.lock().unwrap();
        BorrowedDiskFd::new(lock.as_raw_fd())
    }
}

pub struct VhdxSync {
    vhdx_file: Arc<Mutex<Vhdx>>,
    eventfd: EventFd,
    completion_list: VecDeque<(u64, i32)>,
}

impl VhdxSync {
    pub fn new(vhdx_file: Arc<Mutex<Vhdx>>) -> std::io::Result<Self> {
        Ok(VhdxSync {
            vhdx_file,
            eventfd: EventFd::new(libc::EFD_NONBLOCK)?,
            completion_list: VecDeque::new(),
        })
    }
}

impl AsyncAdaptor<Vhdx> for Arc<Mutex<Vhdx>> {
    fn file(&mut self) -> MutexGuard<'_, Vhdx> {
        self.lock().unwrap()
    }
}

impl AsyncIo for VhdxSync {
    fn notifier(&self) -> &EventFd {
        &self.eventfd
    }

    fn read_vectored(
        &mut self,
        offset: libc::off_t,
        iovecs: &[libc::iovec],
        user_data: u64,
    ) -> AsyncIoResult<()> {
        self.vhdx_file.read_vectored_sync(
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
        self.vhdx_file.write_vectored_sync(
            offset,
            iovecs,
            user_data,
            &self.eventfd,
            &mut self.completion_list,
        )
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        self.vhdx_file
            .fsync_sync(user_data, &self.eventfd, &mut self.completion_list)
    }

    fn next_completed_request(&mut self) -> Option<(u64, i32)> {
        self.completion_list.pop_front()
    }
}
