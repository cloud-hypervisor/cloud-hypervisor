// Copyright © 2021 Intel Corporation
//
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::{Arc, Mutex};

use vmm_sys_util::eventfd::EventFd;

use crate::async_io::{AsyncIo, AsyncIoCompletion, AsyncIoError, AsyncIoOperation, AsyncIoResult};
use crate::formats::vhdx::internal::Vhdx;

pub struct VhdxSync {
    vhdx_file: Arc<Mutex<Vhdx>>,
    eventfd: EventFd,
    completion_list: VecDeque<AsyncIoCompletion>,
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

    fn read_operation(&mut self, op: &mut AsyncIoOperation) -> AsyncIoResult<usize> {
        let offset = op.offset();
        let mut buf = vec![0u8; op.total_len()];
        let mut vhdx = self.vhdx_file.lock().unwrap();
        vhdx.seek(SeekFrom::Start(offset as u64))
            .map_err(AsyncIoError::ReadVectored)?;
        let result = vhdx.read(&mut buf).map_err(AsyncIoError::ReadVectored)?;
        drop(vhdx);

        op.write_bytes_at(0, &buf[..result])
            .map_err(AsyncIoError::ReadVectored)?;
        Ok(result)
    }

    fn write_operation(&mut self, op: &AsyncIoOperation) -> AsyncIoResult<usize> {
        let offset = op.offset();
        let mut buf = vec![0u8; op.total_len()];
        op.read_bytes_at(0, &mut buf)
            .map_err(AsyncIoError::WriteVectored)?;

        let mut vhdx = self.vhdx_file.lock().unwrap();
        vhdx.seek(SeekFrom::Start(offset as u64))
            .map_err(AsyncIoError::WriteVectored)?;
        let result = vhdx.write(&buf).map_err(AsyncIoError::WriteVectored)?;
        Ok(result)
    }
}

impl AsyncIo for VhdxSync {
    fn notifier(&self) -> &EventFd {
        &self.eventfd
    }

    fn submit_data_operation(&mut self, op: AsyncIoOperation) -> AsyncIoResult<()> {
        let is_read = op.is_read();
        let mut op = op;
        let result = if is_read {
            self.read_operation(&mut op)?
        } else {
            self.write_operation(&op)?
        };

        self.completion_list
            .push_back(AsyncIoCompletion::from_operation(op, result as i32));
        self.eventfd.write(1).unwrap();
        Ok(())
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        self.vhdx_file
            .lock()
            .unwrap()
            .flush()
            .map_err(AsyncIoError::Fsync)?;
        if let Some(user_data) = user_data {
            self.completion_list
                .push_back(AsyncIoCompletion::new(user_data, 0, None));
            self.eventfd.write(1).unwrap();
        }
        Ok(())
    }

    fn next_completed_request(&mut self) -> Option<AsyncIoCompletion> {
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
