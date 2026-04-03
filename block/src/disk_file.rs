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
use std::io;

use crate::async_io::{self, AsyncIo, BorrowedDiskFd};
use crate::error::{BlockError, BlockErrorKind};
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
pub trait Geometry: Send + Debug {
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

    /// Indicates support for WRITE_ZEROES requests.
    fn supports_write_zeroes(&self) -> bool {
        self.supports_sparse_operations()
    }

    /// Indicates support for a metadata level zero flag optimization in
    /// virtio `VIRTIO_BLK_T_WRITE_ZEROES` requests. When true, the format
    /// can mark regions as reading zeros via a metadata bit rather than
    /// writing actual zero bytes to disk.
    fn supports_zero_flag(&self) -> bool {
        false
    }
}

/// Live disk resize support.
///
/// Implementations may return an error if the backend does not
/// support resizing (e.g. fixed size formats).
pub trait Resizable: Send + Debug {
    /// Resizes the disk image to the given size in bytes, if the backend supports it.
    fn resize(&mut self, size: u64) -> BlockResult<()>;
}

/// Supertrait bundling universal disk capabilities.
///
/// Every disk format implements `DiskSize` and `Geometry`.
/// `Sync` is required so that `Arc<dyn DiskFile>` can be shared
/// across threads for concurrent readonly access.
pub trait DiskFile: DiskSize + Geometry + Sync {}

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
    /// Creates an independent handle for a queue worker.
    ///
    /// The clone shares internally reference counted state (e.g.
    /// `Arc<Metadata>`) with the original, but owns its own file
    /// descriptor and I/O completion resources. Each virtio queue
    /// gets one clone so that workers can operate in parallel
    /// without contending on I/O state.
    ///
    /// Returns `Box<dyn AsyncDiskFile>` (not `AsyncFullDiskFile`)
    /// because clones only serve as data plane handles for queue
    /// workers. The original remains the control plane for feature
    /// negotiation and configuration.
    fn try_clone(&self) -> BlockResult<Box<dyn AsyncDiskFile>>;

    /// Constructs a per queue async I/O engine.
    ///
    /// # Arguments
    ///
    /// * `ring_depth` - maximum number of in flight I/O operations.
    ///   Callers typically pass the virtio queue size. Must be greater
    ///   than zero. Backends that do not use an async ring (e.g. sync
    ///   fallback implementations) may ignore this value.
    fn new_async_io(&self, ring_depth: u32) -> BlockResult<Box<dyn AsyncIo>>;
}

/// Full capability async disk file trait.
///
/// Combines [`FullDiskFile`] (all optional capabilities) with
/// [`AsyncDiskFile`] (async I/O construction). This is the top level
/// trait for virtio block devices that need both feature negotiation
/// and async queue workers.
///
/// The type narrowing on [`AsyncDiskFile::try_clone`] is intentional:
/// clones only serve as data plane handles for queue workers, while
/// the original `AsyncFullDiskFile` handle remains the control plane
/// for feature negotiation and configuration.
pub trait AsyncFullDiskFile: FullDiskFile + AsyncDiskFile {}

/// Blanket implementation: any type implementing both [`FullDiskFile`]
/// and [`AsyncDiskFile`] automatically satisfies [`AsyncFullDiskFile`].
impl<T: FullDiskFile + AsyncDiskFile> AsyncFullDiskFile for T {}

/// A disk backend that dispatches to either the existing [`async_io::DiskFile`]
/// trait or the next-generation [`AsyncFullDiskFile`] trait.
pub enum DiskBackend {
    /// Existing disk file backend (raw, vhd, vhdx, etc.).
    Legacy(Box<dyn async_io::DiskFile>),
    /// Next-generation disk file backend (qcow2, and more formats as they migrate).
    Next(Box<dyn AsyncFullDiskFile>),
}

impl DiskBackend {
    pub fn logical_size(&mut self) -> BlockResult<u64> {
        match self {
            Self::Legacy(d) => d
                .logical_size()
                .map_err(|e| BlockError::new(BlockErrorKind::Io, io::Error::other(e))),
            Self::Next(d) => d.logical_size(),
        }
    }

    pub fn physical_size(&mut self) -> BlockResult<u64> {
        match self {
            Self::Legacy(d) => d
                .physical_size()
                .map_err(|e| BlockError::new(BlockErrorKind::Io, io::Error::other(e))),
            Self::Next(d) => d.physical_size(),
        }
    }

    pub fn topology(&mut self) -> DiskTopology {
        match self {
            Self::Legacy(d) => d.topology(),
            Self::Next(d) => d.topology(),
        }
    }

    pub fn supports_sparse_operations(&self) -> bool {
        match self {
            Self::Legacy(d) => d.supports_sparse_operations(),
            Self::Next(d) => d.supports_sparse_operations(),
        }
    }

    pub fn supports_write_zeroes(&self) -> bool {
        match self {
            Self::Legacy(d) => d.supports_write_zeroes(),
            Self::Next(d) => d.supports_write_zeroes(),
        }
    }

    pub fn supports_zero_flag(&self) -> bool {
        match self {
            Self::Legacy(d) => d.supports_zero_flag(),
            Self::Next(d) => d.supports_zero_flag(),
        }
    }

    pub fn fd(&mut self) -> BorrowedDiskFd<'_> {
        match self {
            Self::Legacy(d) => d.fd(),
            Self::Next(d) => d.fd(),
        }
    }

    pub fn new_async_io(&self, ring_depth: u32) -> BlockResult<Box<dyn AsyncIo>> {
        match self {
            Self::Legacy(d) => d
                .new_async_io(ring_depth)
                .map_err(|e| BlockError::new(BlockErrorKind::Io, io::Error::other(e))),
            Self::Next(d) => d.new_async_io(ring_depth),
        }
    }

    pub fn resize(&mut self, new_size: u64) -> BlockResult<()> {
        match self {
            Self::Legacy(d) => d.resize(new_size).map_err(|e| match e {
                async_io::DiskFileError::Unsupported => BlockError::new(
                    BlockErrorKind::UnsupportedFeature,
                    io::Error::other("resize not supported"),
                ),
                _ => BlockError::new(BlockErrorKind::Io, io::Error::other(e)),
            }),
            Self::Next(d) => d.resize(new_size),
        }
    }
}
