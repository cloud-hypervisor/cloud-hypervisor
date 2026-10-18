// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Network Block Device (NBD) client backend.
//!
//! Provides [`NbdDisk`], a `DiskFile` whose data lives in a remote NBD
//! export:
//!
//! - `proto` - wire protocol definitions
//! - `handshake` - option negotiation
//! - `conn` - connection setup and blocking commands
//! - `engine_sync` / `engine_uring` - I/O engines
//!
//! Each virtio queue has its own connection, owned by the engine of that
//! queue, so there is no state shared between threads and no
//! synchronization between connections. More than one queue requires the
//! server to advertise `NBD_FLAG_CAN_MULTI_CONN`, which guarantees that
//! the connections see each other's writes and flushes. The connection
//! opened by [`NbdDisk::open`] is handed to the first engine so that
//! servers accepting a single client work with a single queue.

mod conn;
mod engine_sync;
#[cfg(feature = "io_uring")]
mod engine_uring;
mod handshake;
mod proto;
mod request;
mod uri;

use std::sync::Mutex;

use log::info;
use thiserror::Error;

use self::conn::NbdConn;
pub use self::conn::{
    MAX_TCP_KEEPALIVE_COUNT, MAX_TCP_KEEPALIVE_SECS, NbdConnectError, NbdSocketOptions,
    TcpKeepalive,
};
use self::engine_sync::NbdSync;
use self::handshake::NbdExportInfo;
pub use self::handshake::NbdHandshakeError;
use self::proto::*;
pub use self::uri::{NbdUri, NbdUriError};
#[cfg(feature = "io_uring")]
use crate::async_io::DiskFileError;
use crate::async_io::{AsyncIo, BorrowedDiskFd};
use crate::error::{BlockError, BlockErrorKind, BlockResult};
use crate::{DiskTopology, disk_file};

#[derive(Error, Debug)]
pub enum NbdError {
    #[error("Invalid NBD URI")]
    Uri(#[source] NbdUriError),
    #[error("Failed to connect to NBD export")]
    Connect(#[source] NbdConnectError),
    #[error("NBD export {0} is read-only but the disk is not")]
    ReadOnlyExport(String),
    #[error("NBD export {0} does not allow multiple connections, but num_queues={1}")]
    MultiConnUnsupported(String, usize),
    #[error("NBD export {0} changed: size or flags differ from the first connection")]
    ExportChanged(String),
    #[error("Resizing NBD disks is not supported")]
    ResizeUnsupported,
}

impl From<NbdError> for BlockError {
    fn from(e: NbdError) -> Self {
        let kind = match e {
            NbdError::Uri(_) => BlockErrorKind::InvalidFormat,
            NbdError::MultiConnUnsupported(..) | NbdError::ResizeUnsupported => {
                BlockErrorKind::UnsupportedFeature
            }
            _ => BlockErrorKind::Io,
        };
        BlockError::new(kind, e)
    }
}

/// Options for opening an NBD disk.
pub struct NbdOpenOptions<'a> {
    pub uri: &'a str,
    pub readonly: bool,
    pub use_io_uring: bool,
    pub socket: NbdSocketOptions,
    /// Number of virtio queues, each using its own connection.
    pub num_queues: usize,
}

/// DiskFile for an NBD export.
#[derive(Debug)]
pub struct NbdDisk {
    uri: NbdUri,
    socket: NbdSocketOptions,
    info: NbdExportInfo,
    use_io_uring: bool,
    /// Connection opened at open time, consumed by the first engine.
    probe: Mutex<Option<NbdConn>>,
}

impl NbdDisk {
    /// Connects to the export, negotiates it and validates it against
    /// the requested access mode and number of queues.
    pub fn open(options: &NbdOpenOptions<'_>) -> BlockResult<Self> {
        let uri: NbdUri = options.uri.parse().map_err(NbdError::Uri)?;
        let conn = NbdConn::connect(&uri, &options.socket).map_err(NbdError::Connect)?;
        let info = *conn.info();
        info!("Connected to NBD export {uri}: {info:?}");

        if !options.readonly && info.has_flag(NBD_FLAG_READ_ONLY) {
            return Err(NbdError::ReadOnlyExport(uri.to_string()).into());
        }

        if !info.allows_connections(options.num_queues) {
            return Err(NbdError::MultiConnUnsupported(uri.to_string(), options.num_queues).into());
        }

        Ok(Self {
            uri,
            socket: options.socket,
            info,
            use_io_uring: options.use_io_uring,
            probe: Mutex::new(Some(conn)),
        })
    }

    /// Returns the probe connection or, when the device is activated
    /// again (e.g. after a guest reset), opens a new one.
    fn take_connection(&self) -> BlockResult<NbdConn> {
        if let Some(conn) = self.probe.lock().unwrap().take() {
            return Ok(conn);
        }
        let conn = NbdConn::connect(&self.uri, &self.socket).map_err(NbdError::Connect)?;
        let info = conn.info();
        if info.size != self.info.size || info.flags != self.info.flags {
            return Err(NbdError::ExportChanged(self.uri.to_string()).into());
        }
        Ok(conn)
    }
}

impl disk_file::DiskSize for NbdDisk {
    fn logical_size(&self) -> BlockResult<u64> {
        Ok(self.info.size)
    }
}

impl disk_file::PhysicalSize for NbdDisk {
    fn physical_size(&self) -> BlockResult<u64> {
        Ok(self.info.size)
    }
}

impl disk_file::DiskFd for NbdDisk {
    /// NBD disks have no local file.
    fn fd(&self) -> Result<BorrowedDiskFd<'_>, disk_file::DiskFdError> {
        Err(disk_file::DiskFdError::Unsupported)
    }
}

impl disk_file::Geometry for NbdDisk {
    fn topology(&self) -> DiskTopology {
        let logical = u64::from(self.info.min_block).max(512);
        DiskTopology {
            logical_block_size: logical,
            physical_block_size: logical,
            minimum_io_size: logical,
            optimal_io_size: u64::from(self.info.opt_block).max(logical),
        }
    }
}

impl disk_file::SparseCapable for NbdDisk {
    fn supports_sparse_operations(&self) -> bool {
        self.info.has_flag(NBD_FLAG_SEND_TRIM) && self.info.has_flag(NBD_FLAG_SEND_WRITE_ZEROES)
    }
}

impl disk_file::Resizable for NbdDisk {
    fn resize(&mut self, _size: u64) -> BlockResult<()> {
        Err(NbdError::ResizeUnsupported.into())
    }
}

/// Writes are only made durable by guest flush requests, as for raw
/// files.
impl disk_file::MetadataSync for NbdDisk {}

impl disk_file::DiskFile for NbdDisk {}

impl disk_file::AsyncDiskFile for NbdDisk {
    fn try_clone(&self) -> BlockResult<Box<dyn disk_file::AsyncDiskFile>> {
        Ok(Box::new(NbdDisk {
            uri: self.uri.clone(),
            socket: self.socket,
            info: self.info,
            use_io_uring: self.use_io_uring,
            probe: Mutex::new(None),
        }))
    }

    fn create_async_io(&self, _ring_depth: u32) -> BlockResult<Box<dyn AsyncIo>> {
        let conn = self.take_connection()?;

        #[cfg(feature = "io_uring")]
        if self.use_io_uring {
            return Ok(Box::new(engine_uring::NbdUring::new(conn).map_err(
                |e| BlockError::new(BlockErrorKind::Io, DiskFileError::NewAsyncIo(e)),
            )?));
        }

        Ok(Box::new(NbdSync::new(conn)))
    }
}

/// Returns true when the io_uring NBD engine can be used with `socket`.
#[cfg(feature = "io_uring")]
pub(crate) fn io_uring_supported(socket: &NbdSocketOptions) -> bool {
    engine_uring::supported(socket.socket_timeout.is_some())
}

#[cfg(test)]
mod tests;
