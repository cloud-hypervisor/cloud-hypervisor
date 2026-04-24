// Copyright © 2021 Intel Corporation
//
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};

use vmm_sys_util::eventfd::EventFd;

use crate::async_io::{
    AsyncIo, AsyncIoCompletion, AsyncIoError, AsyncIoOperation, AsyncIoResult, BorrowedDiskFd,
    DiskFileError,
};
use crate::error::{BlockError, BlockErrorKind, BlockResult, ErrorOp};
use crate::vhdx::{Vhdx, VhdxError};
use crate::{BlockBackend, Error, disk_file};

#[derive(Debug)]
pub struct VhdxDisk {
    // FIXME: The Mutex serializes all VHDX I/O operations across queues, which
    // is necessary for correctness but eliminates any parallelism benefit from
    // multiqueue. Vhdx::clone() shares the underlying file description across
    // threads, so concurrent I/O from multiple queues races on the file offset
    // causing data corruption.
    //
    // A proper fix would require restructuring the VHDX I/O path so that data
    // operations can proceed in parallel with independent file descriptors.
    vhdx_file: Arc<Mutex<Vhdx>>,
}

impl VhdxDisk {
    pub fn new(f: File) -> BlockResult<Self> {
        Ok(VhdxDisk {
            vhdx_file: Arc::new(Mutex::new(Vhdx::new(f).map_err(|e| {
                let kind = match &e {
                    VhdxError::NotVhdx(_)
                    | VhdxError::ParseVhdxHeader(_)
                    | VhdxError::ParseVhdxMetadata(_)
                    | VhdxError::ParseVhdxRegionEntry(_) => BlockErrorKind::InvalidFormat,
                    VhdxError::ReadBatEntry(_) => BlockErrorKind::CorruptImage,
                    VhdxError::ReadFailed(_) | VhdxError::WriteFailed(_) => BlockErrorKind::Io,
                };
                BlockError::new(kind, e).with_op(ErrorOp::Open)
            })?)),
        })
    }
}

impl disk_file::DiskSize for VhdxDisk {
    fn logical_size(&self) -> BlockResult<u64> {
        Ok(self.vhdx_file.lock().unwrap().virtual_disk_size())
    }
}

impl disk_file::PhysicalSize for VhdxDisk {
    fn physical_size(&self) -> BlockResult<u64> {
        self.vhdx_file
            .lock()
            .unwrap()
            .physical_size()
            .map_err(|e| match e {
                Error::GetFileMetadata(io) => {
                    BlockError::new(BlockErrorKind::Io, Error::GetFileMetadata(io))
                }
                _ => unreachable!("unexpected error from Vhdx::physical_size(): {e}"),
            })
    }
}

impl disk_file::DiskFd for VhdxDisk {
    fn fd(&self) -> BorrowedDiskFd<'_> {
        BorrowedDiskFd::new(self.vhdx_file.lock().unwrap().as_raw_fd())
    }
}

impl disk_file::Geometry for VhdxDisk {}

impl disk_file::SparseCapable for VhdxDisk {}

impl disk_file::Resizable for VhdxDisk {
    fn resize(&mut self, _size: u64) -> BlockResult<()> {
        Err(BlockError::new(
            BlockErrorKind::UnsupportedFeature,
            DiskFileError::ResizeError(std::io::Error::other("resize not supported for VHDX")),
        )
        .with_op(ErrorOp::Resize))
    }
}

impl disk_file::DiskFile for VhdxDisk {}

impl disk_file::AsyncDiskFile for VhdxDisk {
    fn try_clone(&self) -> BlockResult<Box<dyn disk_file::AsyncDiskFile>> {
        Ok(Box::new(VhdxDisk {
            vhdx_file: Arc::clone(&self.vhdx_file),
        }))
    }

    fn create_async_io(&self, _ring_depth: u32) -> BlockResult<Box<dyn AsyncIo>> {
        Ok(Box::new(VhdxSync::new(Arc::clone(&self.vhdx_file))))
    }
}

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
