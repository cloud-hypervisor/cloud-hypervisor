// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Composable disk capability traits for the block crate.
//!
//! Small traits define individual capabilities:
//!
//! - [`DiskSize`] - reported capacity (logical size)
//! - [`PhysicalSize`] - host allocation size
//! - [`DiskFd`] - backing file descriptor access
//! - [`Geometry`] - sector/cluster geometry (default 512B)
//! - [`SparseCapable`] - sparse and zero flag support
//! - [`Resizable`] - online resize
//!
//! [`DiskFile`] is a supertrait that bundles the universal capabilities
//! (`DiskSize` + `Geometry`). [`FullDiskFile`] adds all optional
//! capabilities. [`AsyncDiskFile`] extends `DiskFile` with async I/O
//! construction for virtio queue workers. [`AsyncFullDiskFile`]
//! combines both axes.
//!
//! ```text
//!         DiskFile: DiskSize + Geometry + Sync
//!         /                                     \
//! FullDiskFile:                           AsyncDiskFile:
//!   DiskFile + PhysicalSize +               DiskFile + Unpin
//!   DiskFd + SparseCapable +               try_clone, new_async_io
//!   Resizable
//!         \                                     /
//!          AsyncFullDiskFile: FullDiskFile + AsyncDiskFile
//! ```
//!
//! Readonly accessors take `&self`. Only [`Resizable::resize`] requires
//! `&mut self`. Errors are returned as [`BlockResult`].

use std::fmt::Debug;

use crate::BlockResult;
use crate::async_io::BorrowedDiskFd;

/// Reported capacity of a disk image.
pub trait DiskSize: Send + Debug {
    /// Virtual size of the disk image in bytes (reported capacity).
    fn logical_size(&self) -> BlockResult<u64>;
}

/// Host allocation size of a file-backed disk image.
pub trait PhysicalSize: Send + Debug {
    /// Actual bytes occupied on the host filesystem.
    fn physical_size(&self) -> BlockResult<u64>;
}

/// Backing file descriptor access for disk images backed by a file.
pub trait DiskFd: Send + Debug {
    /// Borrows the underlying file descriptor.
    fn fd(&self) -> BorrowedDiskFd<'_>;
}
