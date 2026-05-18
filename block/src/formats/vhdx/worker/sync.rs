// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use vmm_sys_util::eventfd::EventFd;

use crate::AsyncAdaptor;
use crate::async_io::{AsyncIo, AsyncIoError, AsyncIoResult};
use crate::formats::vhdx::internal::Vhdx;

pub struct VhdxSync {
    vhdx_file: Arc<Mutex<Vhdx>>,
    eventfd: EventFd,
    completion_list: VecDeque<(u64, i32)>,
}

impl VhdxSync {
    pub fn new(vhdx_file: Arc<Mutex<Vhdx>>) -> Self {
        VhdxSync {
            vhdx_file,
            eventfd: EventFd::new(libc::EFD_NONBLOCK)
                .expect("Failed creating EventFd for VhdxSync"),
            completion_list: VecDeque::new(),
        }
    }
}

impl AsyncAdaptor for Vhdx {}

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
        self.vhdx_file.lock().unwrap().read_vectored_sync(
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
        self.vhdx_file.lock().unwrap().write_vectored_sync(
            offset,
            iovecs,
            user_data,
            &self.eventfd,
            &mut self.completion_list,
        )
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        self.vhdx_file.lock().unwrap().fsync_sync(
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
            "punch_hole not supported for VHDX",
        )))
    }

    fn write_zeroes(&mut self, _offset: u64, _length: u64, _user_data: u64) -> AsyncIoResult<()> {
        Err(AsyncIoError::WriteZeroes(std::io::Error::other(
            "write_zeroes not supported for VHDX",
        )))
    }
}
