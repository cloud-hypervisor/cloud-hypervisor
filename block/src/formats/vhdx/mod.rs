// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

//! VHDX disk format support.
//!
//! Provides [`VhdxDisk`], the `DiskFile` wrapper for dynamic VHDX
//! images.

pub mod internal;
pub(crate) mod worker;

use std::fs::File;
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};

pub use internal::VhdxError;

use self::internal::Vhdx;
use self::worker::sync::VhdxSync;
use crate::async_io::{AsyncIo, BorrowedDiskFd, DiskFileError};
use crate::error::{BlockError, BlockErrorKind, BlockResult, ErrorOp};
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
