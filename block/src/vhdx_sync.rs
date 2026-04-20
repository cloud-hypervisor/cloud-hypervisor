// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
use std::collections::VecDeque;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};

use vmm_sys_util::eventfd::EventFd;

use crate::async_io::{AsyncIo, AsyncIoError, AsyncIoResult, BorrowedDiskFd, DiskFileError};
use crate::engine::Completion;
use crate::error::{BlockError, BlockErrorKind, BlockResult, ErrorOp};
use crate::vhdx::Vhdx;
use crate::{AsyncAdaptor, BlockBackend, Error, IoBuf, disk_file};

#[derive(Debug)]
pub struct VhdxDiskSync {
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

impl VhdxDiskSync {
    pub fn new(f: File) -> BlockResult<Self> {
        Ok(VhdxDiskSync {
            vhdx_file: Arc::new(Mutex::new(Vhdx::new(f).map_err(|e| {
                BlockError::new(BlockErrorKind::Io, e).with_op(ErrorOp::Open)
            })?)),
        })
    }
}

impl disk_file::DiskSize for VhdxDiskSync {
    fn logical_size(&self) -> BlockResult<u64> {
        Ok(self.vhdx_file.lock().unwrap().virtual_disk_size())
    }
}

impl disk_file::PhysicalSize for VhdxDiskSync {
    fn physical_size(&self) -> BlockResult<u64> {
        self.vhdx_file
            .lock()
            .unwrap()
            .physical_size()
            .map_err(|e| match e {
                Error::GetFileMetadata(io) => {
                    BlockError::new(BlockErrorKind::Io, Error::GetFileMetadata(io))
                }
                _ => BlockError::new(BlockErrorKind::Io, e),
            })
    }
}

impl disk_file::DiskFd for VhdxDiskSync {
    fn fd(&self) -> BorrowedDiskFd<'_> {
        BorrowedDiskFd::new(self.vhdx_file.lock().unwrap().as_raw_fd())
    }
}

impl disk_file::Geometry for VhdxDiskSync {}

impl disk_file::SparseCapable for VhdxDiskSync {}

impl disk_file::Resizable for VhdxDiskSync {
    fn resize(&mut self, _size: u64) -> BlockResult<()> {
        Err(BlockError::new(
            BlockErrorKind::UnsupportedFeature,
            DiskFileError::ResizeError(std::io::Error::other("resize not supported for VHDX")),
        )
        .with_op(ErrorOp::Resize))
    }
}

impl disk_file::DiskFile for VhdxDiskSync {}

impl disk_file::AsyncDiskFile for VhdxDiskSync {
    fn try_clone(&self) -> BlockResult<Box<dyn disk_file::AsyncDiskFile>> {
        Ok(Box::new(VhdxDiskSync {
            vhdx_file: Arc::clone(&self.vhdx_file),
        }))
    }

    fn new_async_io(&self, _ring_depth: u32) -> BlockResult<Box<dyn AsyncIo>> {
        Ok(Box::new(VhdxSync::new(Arc::clone(&self.vhdx_file))))
    }
}

pub struct VhdxSync {
    vhdx_file: Arc<Mutex<Vhdx>>,
    eventfd: EventFd,
    completion_list: VecDeque<Completion>,
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
        iobuf: IoBuf,
        user_data: u64,
    ) -> AsyncIoResult<()> {
        self.vhdx_file.lock().unwrap().read_vectored_sync(
            offset,
            iobuf,
            user_data,
            &self.eventfd,
            &mut self.completion_list,
        )
    }

    fn write_vectored(
        &mut self,
        offset: libc::off_t,
        iobuf: IoBuf,
        user_data: u64,
    ) -> AsyncIoResult<()> {
        self.vhdx_file.lock().unwrap().write_vectored_sync(
            offset,
            iobuf,
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

    fn next_completed_request(&mut self) -> Option<Completion> {
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
