// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::result::Result;

use anyhow::anyhow;
use log::info;
use serde_json;
use vm_memory::bitmap::BitmapSlice;
use vm_memory::{
    GuestAddress, GuestAddressSpace, GuestMemory, GuestMemoryAtomic, ReadVolatile,
    VolatileMemoryError, VolatileSlice, WriteVolatile,
};
use vm_migration::protocol::{MemoryRangeTable, Request, Response};
use vm_migration::{MigratableError, Snapshot};

use crate::{GuestMemoryMmap, VmMigrationConfig};

/// Transport-agnostic stream used by the migration protocol.
pub(crate) enum SocketStream {
    Unix(UnixStream),
    Tcp(TcpStream),
}

impl Read for SocketStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            SocketStream::Unix(stream) => stream.read(buf),
            SocketStream::Tcp(stream) => stream.read(buf),
        }
    }
}

impl Write for SocketStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            SocketStream::Unix(stream) => stream.write(buf),
            SocketStream::Tcp(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            SocketStream::Unix(stream) => stream.flush(),
            SocketStream::Tcp(stream) => stream.flush(),
        }
    }
}

impl AsRawFd for SocketStream {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            SocketStream::Unix(s) => s.as_raw_fd(),
            SocketStream::Tcp(s) => s.as_raw_fd(),
        }
    }
}

impl ReadVolatile for SocketStream {
    fn read_volatile<B: BitmapSlice>(
        &mut self,
        buf: &mut VolatileSlice<B>,
    ) -> Result<usize, VolatileMemoryError> {
        match self {
            SocketStream::Unix(s) => s.read_volatile(buf),
            SocketStream::Tcp(s) => s.read_volatile(buf),
        }
    }

    fn read_exact_volatile<B: BitmapSlice>(
        &mut self,
        buf: &mut VolatileSlice<B>,
    ) -> Result<(), VolatileMemoryError> {
        match self {
            SocketStream::Unix(s) => s.read_exact_volatile(buf),
            SocketStream::Tcp(s) => s.read_exact_volatile(buf),
        }
    }
}

impl WriteVolatile for SocketStream {
    fn write_volatile<B: BitmapSlice>(
        &mut self,
        buf: &VolatileSlice<B>,
    ) -> Result<usize, VolatileMemoryError> {
        match self {
            SocketStream::Unix(s) => s.write_volatile(buf),
            SocketStream::Tcp(s) => s.write_volatile(buf),
        }
    }

    fn write_all_volatile<B: BitmapSlice>(
        &mut self,
        buf: &VolatileSlice<B>,
    ) -> Result<(), VolatileMemoryError> {
        match self {
            SocketStream::Unix(s) => s.write_all_volatile(buf),
            SocketStream::Tcp(s) => s.write_all_volatile(buf),
        }
    }
}

/// Extract a UNIX socket path from a "unix:" migration URL.
fn socket_url_to_path(url: &str) -> Result<PathBuf, MigratableError> {
    url.strip_prefix("unix:")
        .ok_or_else(|| {
            MigratableError::MigrateSend(anyhow!("Could not extract path from URL: {url}"))
        })
        .map(|s| s.into())
}

/// Connect to a migration endpoint and return the established stream.
pub(crate) fn send_migration_socket(
    destination_url: &str,
) -> Result<SocketStream, MigratableError> {
    if let Some(address) = destination_url.strip_prefix("tcp:") {
        info!("Connecting to TCP socket at {address}");

        let socket = TcpStream::connect(address).map_err(|e| {
            MigratableError::MigrateSend(anyhow!("Error connecting to TCP socket: {e}"))
        })?;

        Ok(SocketStream::Tcp(socket))
    } else {
        let path = socket_url_to_path(destination_url)?;
        info!("Connecting to UNIX socket at {path:?}");

        let socket = UnixStream::connect(&path).map_err(|e| {
            MigratableError::MigrateSend(anyhow!("Error connecting to UNIX socket: {e}"))
        })?;

        Ok(SocketStream::Unix(socket))
    }
}

/// Bind and accept a migration connection for the receiver side.
pub(crate) fn receive_migration_socket(
    receiver_url: &str,
) -> Result<SocketStream, MigratableError> {
    if let Some(address) = receiver_url.strip_prefix("tcp:") {
        let listener = TcpListener::bind(address).map_err(|e| {
            MigratableError::MigrateReceive(anyhow!("Error binding to TCP socket: {e}"))
        })?;

        let (socket, _addr) = listener.accept().map_err(|e| {
            MigratableError::MigrateReceive(anyhow!(
                "Error accepting connection on TCP socket: {e}"
            ))
        })?;

        Ok(SocketStream::Tcp(socket))
    } else {
        let path = socket_url_to_path(receiver_url)?;
        let listener = UnixListener::bind(&path).map_err(|e| {
            MigratableError::MigrateReceive(anyhow!("Error binding to UNIX socket: {e}"))
        })?;

        let (socket, _addr) = listener.accept().map_err(|e| {
            MigratableError::MigrateReceive(anyhow!(
                "Error accepting connection on UNIX socket: {e}"
            ))
        })?;

        // Remove the UNIX socket file after accepting the connection
        std::fs::remove_file(&path).map_err(|e| {
            MigratableError::MigrateReceive(anyhow!("Error removing UNIX socket file: {e}"))
        })?;

        Ok(SocketStream::Unix(socket))
    }
}

/// Read a response and return Ok(()) if it was a [`Response::Ok`].
pub(crate) fn expect_ok_response(
    socket: &mut SocketStream,
    error: MigratableError,
) -> Result<(), MigratableError> {
    Response::read_from(socket)?
        .ok_or_abandon(socket, error)
        .map(|_| ())
}

/// Send a request and validate that the peer responds with OK.
pub(crate) fn send_request_expect_ok(
    socket: &mut SocketStream,
    request: Request,
    error: MigratableError,
) -> Result<(), MigratableError> {
    request.write_to(socket)?;
    expect_ok_response(socket, error)
}

/// Serialize and send the VM configuration payload.
pub(crate) fn send_config(
    socket: &mut SocketStream,
    config: &VmMigrationConfig,
) -> Result<(), MigratableError> {
    let config_data = serde_json::to_vec(config).unwrap();
    Request::config(config_data.len() as u64).write_to(socket)?;
    socket
        .write_all(&config_data)
        .map_err(MigratableError::MigrateSocket)?;
    expect_ok_response(
        socket,
        MigratableError::MigrateSend(anyhow!("Error during config migration")),
    )
}

/// Serialize and send the VM snapshot payload.
pub(crate) fn send_state(
    socket: &mut SocketStream,
    snapshot: &Snapshot,
) -> Result<(), MigratableError> {
    let snapshot_data = serde_json::to_vec(snapshot).unwrap();
    Request::state(snapshot_data.len() as u64).write_to(socket)?;
    socket
        .write_all(&snapshot_data)
        .map_err(MigratableError::MigrateSocket)?;
    expect_ok_response(
        socket,
        MigratableError::MigrateSend(anyhow!("Error during state migration")),
    )
}

/// Transmits the given [`MemoryRangeTable`] over the wire if there is at
/// least one region.
///
/// Sends a memory migration request, the range table, and the corresponding
/// guest memory regions over the given socket. Waits for acknowledgment
/// from the destination.
pub(crate) fn send_memory_regions(
    guest_memory: &GuestMemoryAtomic<GuestMemoryMmap>,
    ranges: &MemoryRangeTable,
    socket: &mut SocketStream,
) -> Result<(), MigratableError> {
    if ranges.regions().is_empty() {
        return Ok(());
    }

    // Send the memory table
    Request::memory(ranges.length()).write_to(socket)?;
    ranges.write_to(socket)?;

    // And then the memory itself
    let mem = guest_memory.memory();
    for range in ranges.regions() {
        let mut offset: u64 = 0;
        // Here we are manually handling the retry in case we can't read the
        // whole region at once because we can't use the implementation
        // from vm-memory::GuestMemory of write_all_to() as it is not
        // following the correct behavior. For more info about this issue
        // see: https://github.com/rust-vmm/vm-memory/issues/174
        loop {
            let bytes_written = mem
                .write_volatile_to(
                    GuestAddress(range.gpa + offset),
                    socket,
                    (range.length - offset) as usize,
                )
                .map_err(|e| {
                    MigratableError::MigrateSend(anyhow!(
                        "Error transferring memory to socket: {e}"
                    ))
                })?;
            offset += bytes_written as u64;

            if offset == range.length {
                break;
            }
        }
    }
    expect_ok_response(
        socket,
        MigratableError::MigrateSend(anyhow!("Error during dirty memory migration")),
    )
}
