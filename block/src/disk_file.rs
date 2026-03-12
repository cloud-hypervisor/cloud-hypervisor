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
//! - [`HasTopology`] - sector/cluster geometry (default 512B)
//! - [`SparseCapable`] - sparse and zero flag support
//! - [`Resizable`] - online resize
//!
//! [`DiskFile`] is a supertrait that bundles the universal capabilities
//! (`DiskSize` + `HasTopology`). [`FullDiskFile`] adds all optional
//! capabilities. [`AsyncDiskFile`] extends `DiskFile` with async I/O
//! construction for virtio queue workers. [`AsyncFullDiskFile`]
//! combines both axes.
//!
//! ```text
//!         DiskFile: DiskSize + HasTopology + Sync
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

use crate::async_io::{AsyncIo, BorrowedDiskFd};
use crate::{BlockResult, DiskTopology};

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

/// Sector and cluster geometry of a disk image.
///
/// Default returns `DiskTopology::default()` (512B logical/physical).
pub trait HasTopology: Send + Debug {
    /// Returns the disk topology.
    fn topology(&self) -> DiskTopology {
        DiskTopology::default()
    }
}

/// Sparse and zero flag support for thin provisioned disk images.
pub trait SparseCapable: Send + Debug {
    /// Indicates support for sparse operations (punch hole, write zeroes, discard).
    fn supports_sparse_operations(&self) -> bool {
        false
    }

    /// Indicates support for zero flag optimization in WRITE_ZEROES.
    fn supports_zero_flag(&self) -> bool {
        false
    }
}

/// Online resize support for disk images.
pub trait Resizable: Send + Debug {
    /// Resizes the disk image to the given size in bytes.
    fn resize(&mut self, size: u64) -> BlockResult<()>;
}

/// Supertrait bundling universal disk capabilities.
///
/// Every disk format implements `DiskSize` and `HasTopology`.
/// `Sync` is required so that `Arc<dyn DiskFile>` can be shared
/// across threads for concurrent readonly access.
pub trait DiskFile: DiskSize + HasTopology + Sync {}

/// Full capability disk file trait.
///
/// Bundles all optional capabilities on top of [`DiskFile`]:
/// file descriptor access, physical size, sparse operations, and resize.
/// Used by consumers that need feature negotiation without async I/O
/// (e.g. vhost user block).
pub trait FullDiskFile: DiskFile + PhysicalSize + DiskFd + SparseCapable + Resizable {}

/// Blanket implementation: any type implementing all constituent traits
/// automatically satisfies [`FullDiskFile`].
impl<T: DiskFile + PhysicalSize + DiskFd + SparseCapable + Resizable> FullDiskFile for T {}

/// Extended disk file trait for virtio queue workers.
///
/// Adds cloning and async I/O construction on top of [`DiskFile`].
/// `Unpin` is required so trait objects can be moved freely.
pub trait AsyncDiskFile: DiskFile + Unpin {
    /// Creates an independent handle to the same backing storage.
    fn try_clone(&self) -> BlockResult<Box<dyn AsyncDiskFile>>;

    /// Constructs an async I/O engine for the given ring depth.
    fn new_async_io(&self, ring_depth: u32) -> BlockResult<Box<dyn AsyncIo>>;
}
