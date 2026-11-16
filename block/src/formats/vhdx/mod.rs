// Copyright © 2021 Intel Corporation
//
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0

//! VHDX disk format support.
//!
//! Provides [`VhdxDisk`], the `DiskFile` wrapper for dynamic VHDX
//! images.

mod bat;
mod dynamic;
mod engine_sync;
mod header;
mod metadata;
#[cfg(test)]
mod test_util;

use std::fs::File;
use std::io::Error as IoError;
use std::os::fd::AsRawFd;
use std::sync::{Arc, RwLock};

pub use dynamic::VhdxError;

use self::dynamic::Vhdx;
use self::engine_sync::VhdxSync;
use crate::async_io::{AsyncIo, BorrowedDiskFd, DiskFileError};
use crate::error::{BlockError, BlockErrorKind, BlockResult, ErrorOp};
use crate::{Error, disk_file};

#[derive(Debug)]
pub struct VhdxDisk {
    // Reads take the read lock; writes take the write lock because
    // `write_all_at` mutates the BAT and header.
    vhdx_file: Arc<RwLock<Vhdx>>,
}

impl VhdxDisk {
    pub fn new(f: File, direct_io: bool) -> BlockResult<Self> {
        Ok(VhdxDisk {
            vhdx_file: Arc::new(RwLock::new(Vhdx::new(f, direct_io).map_err(|e| {
                let kind = match &e {
                    VhdxError::ParseVhdxHeader(_)
                    | VhdxError::ParseVhdxMetadata(_)
                    | VhdxError::ParseVhdxRegionEntry(_)
                    | VhdxError::UnsupportedLogReplay => BlockErrorKind::InvalidFormat,
                    VhdxError::ReadBatEntry(_) => BlockErrorKind::CorruptImage,
                };
                BlockError::new(kind, e).with_op(ErrorOp::Open)
            })?)),
        })
    }
}

impl disk_file::DiskSize for VhdxDisk {
    fn logical_size(&self) -> BlockResult<u64> {
        Ok(self.vhdx_file.read().unwrap().virtual_disk_size())
    }
}

impl disk_file::PhysicalSize for VhdxDisk {
    fn physical_size(&self) -> BlockResult<u64> {
        self.vhdx_file
            .read()
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
        BorrowedDiskFd::new(self.vhdx_file.read().unwrap().as_raw_fd())
    }
}

impl disk_file::Geometry for VhdxDisk {}

impl disk_file::SparseCapable for VhdxDisk {}

impl disk_file::Resizable for VhdxDisk {
    fn resize(&mut self, _size: u64) -> BlockResult<()> {
        Err(BlockError::new(
            BlockErrorKind::UnsupportedFeature,
            DiskFileError::ResizeError(IoError::other("resize not supported for VHDX")),
        )
        .with_op(ErrorOp::Resize))
    }
}

impl disk_file::MetadataSync for VhdxDisk {}

impl disk_file::DiskFile for VhdxDisk {}

impl disk_file::AsyncDiskFile for VhdxDisk {
    fn try_clone(&self) -> BlockResult<Box<dyn disk_file::AsyncDiskFile>> {
        Ok(Box::new(VhdxDisk {
            vhdx_file: Arc::clone(&self.vhdx_file),
        }))
    }

    fn create_async_io(&self, _ring_depth: u32) -> BlockResult<Box<dyn AsyncIo>> {
        let size = self.vhdx_file.read().unwrap().virtual_disk_size();
        Ok(Box::new(VhdxSync::new(Arc::clone(&self.vhdx_file), size)))
    }
}
