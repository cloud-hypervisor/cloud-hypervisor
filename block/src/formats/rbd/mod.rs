// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Userspace RBD disk backend backed by librbd.
//!
//! The backend exposes an [`RbdDisk`] that implements the same capability
//! traits as the file-backed formats. Virtio-blk queue workers submit
//! asynchronous I/O through [`RbdAsyncIo`]; no kernel RBD mapping, NBD
//! daemon or hugepages are involved.

mod async_io;
mod image;
mod sys;

use std::sync::Arc;
use std::{fmt, io};

use self::async_io::RbdAsyncIo;
use self::image::RbdImageHandle;
use crate::async_io::{AsyncIo, BorrowedDiskFd};
use crate::disk_file;
use crate::error::{BlockError, BlockErrorKind, BlockResult};
use crate::factory::{DiskOpenOptions, RbdOpenOptions};
use crate::formats::rbd_uri::RbdUri;

/// Opens an RBD disk described by `options.path`.
pub(crate) fn open_rbd(
    options: &DiskOpenOptions<'_>,
) -> BlockResult<Box<dyn disk_file::AsyncFullDiskFile>> {
    let uri = RbdUri::parse(options.path).map_err(|e| e.with_path(options.path))?;
    let disk = RbdDisk::open(&uri, options.readonly, options.rbd)
        .map_err(|e| e.with_path(options.path))?;
    Ok(Box::new(disk))
}

/// A Ceph RBD image exposed as a Cloud Hypervisor disk.
struct RbdDisk {
    uri: RbdUri,
    image: Arc<RbdImageHandle>,
    readonly: bool,
}

impl RbdDisk {
    fn open(uri: &RbdUri, readonly: bool, options: RbdOpenOptions<'_>) -> BlockResult<Self> {
        let image = RbdImageHandle::open(uri, readonly, options)?;
        Ok(Self {
            uri: uri.clone(),
            image,
            readonly,
        })
    }
}

impl fmt::Debug for RbdDisk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RbdDisk")
            .field("pool", &self.uri.pool)
            .field("image", &self.uri.image)
            .field("snapshot", &self.uri.snapshot)
            .field("readonly", &self.readonly)
            .finish()
    }
}

impl disk_file::DiskSize for RbdDisk {
    fn logical_size(&self) -> BlockResult<u64> {
        self.image.size()
    }
}

impl disk_file::PhysicalSize for RbdDisk {
    fn physical_size(&self) -> BlockResult<u64> {
        Err(BlockError::new(
            BlockErrorKind::UnsupportedFeature,
            io::Error::other("RBD images do not expose a host physical size"),
        ))
    }
}

impl disk_file::DiskFd for RbdDisk {
    fn fd(&self) -> Option<BorrowedDiskFd<'_>> {
        None
    }
}

impl disk_file::Geometry for RbdDisk {}

impl disk_file::SparseCapable for RbdDisk {
    fn supports_sparse_operations(&self) -> bool {
        rbd_sys::supports("WRITE_ZEROES")
    }
}

impl disk_file::Resizable for RbdDisk {
    fn resize(&mut self, size: u64) -> BlockResult<()> {
        if self.readonly {
            return Err(BlockError::new(
                BlockErrorKind::UnsupportedFeature,
                io::Error::other("RBD image is read-only"),
            ));
        }
        self.image.resize(size)
    }
}

impl disk_file::MetadataSync for RbdDisk {
    fn sync_metadata(&self) -> BlockResult<()> {
        if self.readonly {
            Ok(())
        } else {
            self.image.flush()
        }
    }
}

impl disk_file::DiskFile for RbdDisk {}

impl disk_file::AsyncDiskFile for RbdDisk {
    fn try_clone(&self) -> BlockResult<Box<dyn disk_file::AsyncDiskFile>> {
        Ok(Box::new(Self {
            uri: self.uri.clone(),
            image: Arc::clone(&self.image),
            readonly: self.readonly,
        }))
    }

    fn create_async_io(&self, _ring_depth: u32) -> BlockResult<Box<dyn AsyncIo>> {
        Ok(Box::new(RbdAsyncIo::new(Arc::clone(&self.image))?))
    }
}
