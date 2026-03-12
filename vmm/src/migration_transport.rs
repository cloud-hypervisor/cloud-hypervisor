// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::result::Result;

use anyhow::{Context, anyhow};
use log::info;
use serde_json;
use vm_memory::bitmap::BitmapSlice;
use vm_memory::{
    Bytes, GuestAddress, GuestAddressSpace, GuestMemoryAtomic, ReadVolatile, VolatileMemoryError,
    VolatileSlice, WriteVolatile,
};
use vm_migration::protocol::{Command, MemoryRangeTable, Request, Response};
use vm_migration::{MigratableError, Snapshot};

use crate::{GuestMemoryMmap, VmMigrationConfig};

/// Transport-agnostic listener used to receive connections.
#[derive(Debug)]
pub(crate) enum ReceiveListener {
    Tcp(TcpListener),
    Unix(UnixListener),
}

impl ReceiveListener {
    /// Block until a connection is accepted.
    pub(crate) fn accept(&mut self) -> Result<SocketStream, MigratableError> {
        match self {
            ReceiveListener::Tcp(listener) => listener
                .accept()
                .map(|(socket, _)| SocketStream::Tcp(socket))
                .context("Failed to accept TCP migration connection")
                .map_err(MigratableError::MigrateReceive),
            ReceiveListener::Unix(listener) => listener
                .accept()
                .map(|(socket, _)| SocketStream::Unix(socket))
                .context("Failed to accept Unix migration connection")
                .map_err(MigratableError::MigrateReceive),
        }
    }

    /// Same as [`Self::accept`], but returns `None` if the abort event was signaled.
    fn abortable_accept(
        &mut self,
        abort_event: &impl AsRawFd,
    ) -> Result<Option<SocketStream>, MigratableError> {
        if wait_for_readable(&self, abort_event)
            .context("Error while waiting for socket to become readable")
            .map_err(MigratableError::MigrateReceive)?
        {
            // The listener is readable; accept the connection.
            Ok(Some(self.accept()?))
        } else {
            // The abort event was signaled before any connection arrived.
            Ok(None)
        }
    }
}

impl AsFd for ReceiveListener {
    fn as_fd(&self) -> BorrowedFd<'_> {
        match self {
            ReceiveListener::Tcp(listener) => listener.as_fd(),
            ReceiveListener::Unix(listener) => listener.as_fd(),
        }
    }
}

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

// Wait for `fd` to become readable. In this case, we return true. In case
// `abort_event` was signaled, return false.
fn wait_for_readable(fd: &impl AsFd, abort_event: &impl AsRawFd) -> Result<bool, io::Error> {
    let fd = fd.as_fd().as_raw_fd();
    let abort_event = abort_event.as_raw_fd();

    let mut poll_fds = [
        libc::pollfd {
            fd: abort_event,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];

    loop {
        // SAFETY: This is safe, because the file descriptors are valid and the
        // poll_fds array is properly initialized.
        let ret = unsafe { libc::poll(poll_fds.as_mut_ptr(), poll_fds.len() as libc::nfds_t, -1) };

        if ret >= 0 {
            break;
        }

        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            continue;
        }

        return Err(err);
    }

    if poll_fds[0].revents & libc::POLLIN != 0 {
        return Ok(false);
    }

    if poll_fds[1].revents & libc::POLLIN != 0 {
        return Ok(true);
    }

    Err(io::Error::other(
        "Poll returned, but neither file descriptor is readable?",
    ))
}

/// Extract a UNIX socket path from a "unix:" migration URL.
fn socket_url_to_path(url: &str) -> Result<PathBuf, anyhow::Error> {
    url.strip_prefix("unix:")
        .ok_or_else(|| anyhow!("Could not extract path from URL: {url}"))
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
        let path = socket_url_to_path(destination_url).map_err(MigratableError::MigrateSend)?;
        info!("Connecting to UNIX socket at {path:?}");

        let socket = UnixStream::connect(&path).map_err(|e| {
            MigratableError::MigrateSend(anyhow!("Error connecting to UNIX socket: {e}"))
        })?;

        Ok(SocketStream::Unix(socket))
    }
}

/// Bind a migration listener for the receiver side.
pub(crate) fn receive_migration_listener(
    receiver_url: &str,
) -> Result<ReceiveListener, MigratableError> {
    if let Some(address) = receiver_url.strip_prefix("tcp:") {
        TcpListener::bind(address)
            .map(ReceiveListener::Tcp)
            .context("Error binding to TCP socket")
            .map_err(MigratableError::MigrateReceive)
    } else {
        let path = socket_url_to_path(receiver_url).map_err(MigratableError::MigrateReceive)?;
        UnixListener::bind(&path)
            .map(ReceiveListener::Unix)
            .context("Error binding to UNIX socket")
            .map_err(MigratableError::MigrateReceive)
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
    let config_data = serde_json::to_vec(config)
        .context("Error serializing VM migration config")
        .map_err(MigratableError::MigrateSend)?;
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
    let snapshot_data = serde_json::to_vec(snapshot)
        .context("Error serializing VM snapshot")
        .map_err(MigratableError::MigrateSend)?;
    Request::state(snapshot_data.len() as u64).write_to(socket)?;
    socket
        .write_all(&snapshot_data)
        .map_err(MigratableError::MigrateSocket)?;
    expect_ok_response(
        socket,
        MigratableError::MigrateSend(anyhow!("Error during state migration")),
    )
}

/// Transmits the given [`MemoryRangeTable`] and the corresponding guest memory
/// content over the wire if there is at least one range.
///
/// Sends a memory migration request, the range table, and the corresponding
/// guest memory range over the given socket. Waits for acknowledgment
/// from the destination.
pub(crate) fn send_memory_ranges(
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

/// Receive memory contents for the given request and copy it into guest memory.
pub(crate) fn receive_memory_ranges(
    guest_memory: &GuestMemoryAtomic<GuestMemoryMmap>,
    req: &Request,
    socket: &mut SocketStream,
) -> Result<(), MigratableError> {
    debug_assert_eq!(req.command(), Command::Memory);
    // Read the memory table
    let ranges = MemoryRangeTable::read_from(socket, req.length())?;

    // And then the memory itself
    let mem = guest_memory.memory();

    for range in ranges.regions() {
        let mut offset: u64 = 0;
        // Here we are manually handling the retry in case we can't read the
        // whole region at once because we can't use the implementation
        // from vm-memory::GuestMemory of read_exact_from() as it is not
        // following the correct behavior. For more info about this issue
        // see: https://github.com/rust-vmm/vm-memory/issues/174
        loop {
            let bytes_read = mem
                .read_volatile_from(
                    GuestAddress(range.gpa + offset),
                    socket,
                    (range.length - offset) as usize,
                )
                .map_err(|e| {
                    MigratableError::MigrateReceive(anyhow!(
                        "Error receiving memory from socket: {e}"
                    ))
                })?;
            offset += bytes_read as u64;

            if offset == range.length {
                break;
            }
        }
    }

    Ok(())
}
