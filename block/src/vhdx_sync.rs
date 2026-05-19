// Copyright © 2021 Intel Corporation
//
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;
use std::fs::File;
use std::io::{IoSlice, IoSliceMut, Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};

use smallvec::SmallVec;
use vmm_sys_util::eventfd::EventFd;

use crate::async_io::{
    AsyncIo, AsyncIoCompletion, AsyncIoError, AsyncIoOperation, AsyncIoResult, BorrowedDiskFd,
    DiskFileError,
};
use crate::error::{BlockError, BlockErrorKind, BlockResult, ErrorOp};
use crate::request::DEFAULT_DESCRIPTOR_VEC_SIZE;
use crate::vhdx::{Vhdx, VhdxError};
use crate::{BlockBackend, Error, disk_file};

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
                _ => unreachable!("unexpected error from Vhdx::physical_size(): {e}"),
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

    // SAFETY: each iovec must describe writable memory that remains valid for
    // this synchronous call. The caller must also ensure that creating a
    // mutable slice from each iovec does not violate Rust aliasing rules.
    unsafe fn read_iovecs(
        &mut self,
        offset: libc::off_t,
        iovecs: &[libc::iovec],
    ) -> AsyncIoResult<usize> {
        let mut slices: SmallVec<[IoSliceMut; DEFAULT_DESCRIPTOR_VEC_SIZE]> =
            SmallVec::with_capacity(iovecs.len());
        for iovec in iovecs.iter() {
            if iovec.iov_len == 0 {
                continue;
            }
            // SAFETY: Guaranteed by read_iovecs' caller.
            let slice = unsafe {
                std::slice::from_raw_parts_mut(iovec.iov_base.cast::<u8>(), iovec.iov_len)
            };
            slices.push(IoSliceMut::new(slice));
        }

        let mut vhdx = self.vhdx_file.lock().unwrap();
        vhdx.seek(SeekFrom::Start(offset as u64))
            .map_err(AsyncIoError::ReadVectored)?;
        let mut result = 0usize;
        for slice in slices.iter_mut() {
            result += vhdx.read(slice).map_err(AsyncIoError::ReadVectored)?;
        }
        Ok(result)
    }

    // SAFETY: each iovec must describe readable memory that remains valid for
    // this synchronous call. The caller must also ensure that creating a shared
    // slice from each iovec does not violate Rust aliasing rules.
    unsafe fn write_iovecs(
        &mut self,
        offset: libc::off_t,
        iovecs: &[libc::iovec],
    ) -> AsyncIoResult<usize> {
        let mut slices: SmallVec<[IoSlice; DEFAULT_DESCRIPTOR_VEC_SIZE]> =
            SmallVec::with_capacity(iovecs.len());
        for iovec in iovecs.iter() {
            if iovec.iov_len == 0 {
                continue;
            }
            // SAFETY: Guaranteed by write_iovecs' caller.
            let slice =
                unsafe { std::slice::from_raw_parts(iovec.iov_base.cast::<u8>(), iovec.iov_len) };
            slices.push(IoSlice::new(slice));
        }

        let mut vhdx = self.vhdx_file.lock().unwrap();
        vhdx.seek(SeekFrom::Start(offset as u64))
            .map_err(AsyncIoError::WriteVectored)?;
        let mut result = 0usize;
        for slice in slices.iter() {
            result += vhdx.write(slice).map_err(AsyncIoError::WriteVectored)?;
        }
        Ok(result)
    }
}

impl AsyncIo for VhdxSync {
    fn notifier(&self) -> &EventFd {
        &self.eventfd
    }

    fn submit_data_operation(&mut self, op: AsyncIoOperation) -> AsyncIoResult<()> {
        let offset = op.offset();
        let is_read = op.is_read();
        let iovecs = op.iovecs();
        let result = if is_read {
            // SAFETY: AsyncIoOperation keeps the iovec target alive for this
            // synchronous call. Host-memory operations also satisfy the
            // aliasing requirement above; guest-memory-backed iovecs remain a
            // temporary unsound VHDX case deferred to a later fix.
            unsafe { self.read_iovecs(offset, iovecs)? }
        } else {
            // SAFETY: AsyncIoOperation keeps the iovec target alive for this
            // synchronous call. Host-memory operations also satisfy the
            // aliasing requirement above; guest-memory-backed iovecs remain a
            // temporary unsound VHDX case deferred to a later fix.
            unsafe { self.write_iovecs(offset, iovecs)? }
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
