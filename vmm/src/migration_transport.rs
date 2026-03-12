// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use std::io::{self, ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::result::Result;
use std::thread;

use anyhow::{Context, anyhow};
use log::{debug, error, info};
use serde_json;
use vm_memory::bitmap::BitmapSlice;
use vm_memory::{
    GuestAddress, GuestAddressSpace, GuestMemory, GuestMemoryAtomic, ReadVolatile,
    VolatileMemoryError, VolatileSlice, WriteVolatile,
};
use vm_migration::protocol::{Command, MemoryRangeTable, Request, Response};
use vm_migration::{MigratableError, Snapshot};
use vmm_sys_util::eventfd::EventFd;

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
        wait_for_readable(&self, abort_event)
            .context("Error while waiting for socket to become readable")
            .map_err(MigratableError::MigrateReceive)?
            .then(|| self.accept())
            .transpose()
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

impl AsFd for SocketStream {
    fn as_fd(&self) -> BorrowedFd<'_> {
        match self {
            SocketStream::Unix(s) => s.as_fd(),
            SocketStream::Tcp(s) => s.as_fd(),
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

    // SAFETY: This is safe, because the file descriptors are valid and the
    // poll_fds array is properly initialized.
    let ret = unsafe { libc::poll(poll_fds.as_mut_ptr(), poll_fds.len() as libc::nfds_t, -1) };

    if ret < 0 {
        return Err(io::Error::last_os_error());
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

/// Struct to keep track of additional connections for receiving VM migration data.
#[derive(Debug)]
pub(crate) struct ReceiveAdditionalConnections {
    /// This thread accepts incoming connections and spawns a new worker for
    /// each connection that handles receiving memory.
    accept_thread: Option<thread::JoinHandle<Result<(), MigratableError>>>,

    /// This fd gets signaled when the migration stops, and will then stop
    /// the [`Self::accept_thread`].
    terminate_fd: EventFd,
}

impl ReceiveAdditionalConnections {
    /// Starts a thread to accept incoming connections and handle them. These
    /// additional connections are used to receive additional memory regions
    /// during VM migration.
    pub(crate) fn new(
        listener: ReceiveListener,
        guest_memory: GuestMemoryAtomic<GuestMemoryMmap>,
    ) -> Result<Self, MigratableError> {
        let event_fd = EventFd::new(0)
            .context("Error creating terminate fd")
            .map_err(MigratableError::MigrateReceive)?;

        let terminate_fd = event_fd
            .try_clone()
            .context("Error cloning terminate fd")
            .map_err(MigratableError::MigrateReceive)?;

        let accept_thread = thread::Builder::new()
            .name("migrate-receive-accept-connections".to_owned())
            .spawn(move || Self::accept_connections(listener, &terminate_fd, &guest_memory))
            .context("Error creating connection accept thread")
            .map_err(MigratableError::MigrateReceive)?;

        Ok(Self {
            accept_thread: Some(accept_thread),
            terminate_fd: event_fd,
        })
    }

    fn accept_connections(
        mut listener: ReceiveListener,
        terminate_fd: &EventFd,
        guest_memory: &GuestMemoryAtomic<GuestMemoryMmap>,
    ) -> Result<(), MigratableError> {
        let mut threads: Vec<thread::JoinHandle<Result<(), MigratableError>>> = Vec::new();
        while let Some(mut socket) = listener.abortable_accept(terminate_fd)? {
            let guest_memory = guest_memory.clone();
            let terminate_fd = terminate_fd
                .try_clone()
                .context("Error cloning terminate fd")
                .map_err(MigratableError::MigrateReceive)?;

            match thread::Builder::new()
                .name(format!("migrate-receive-memory-{}", threads.len()).to_owned())
                .spawn(move || {
                    Self::worker_receive_memory(&mut socket, &terminate_fd, &guest_memory)
                }) {
                Ok(t) => threads.push(t),
                Err(e) => {
                    error!("Error spawning receive-memory thread: {e}");
                    break;
                }
            }
        }

        info!("Stopped accepting additional connections. Cleaning up threads.");

        // We only return the first error we encounter here.
        let mut first_err = Ok(());
        for thread in threads {
            let err = match thread.join() {
                Ok(Ok(())) => None,
                Ok(Err(e)) => Some(e),
                Err(panic) => Some(MigratableError::MigrateReceive(anyhow!(
                    "receive-memory thread panicked: {panic:?}"
                ))),
            };

            if let Some(e) = err
                && first_err.is_ok()
            {
                first_err = Err(e);
            }
        }

        first_err
    }

    // Handles a `Memory` request by writing its payload to the VM memory.
    fn worker_receive_memory(
        mut socket: &mut SocketStream,
        terminate_fd: &EventFd,
        guest_memory: &GuestMemoryAtomic<GuestMemoryMmap>,
    ) -> Result<(), MigratableError> {
        loop {
            if !wait_for_readable(socket, terminate_fd)
                .context("Failed to poll fds")
                .map_err(MigratableError::MigrateReceive)?
            {
                info!("Got signal to tear down connection.");
                return Ok(());
            }

            // We only check whether we should abort when waiting for a new request. If the
            // sender stops sending data mid-request, we will hang forever.

            let req = match Request::read_from(&mut socket) {
                Ok(req) => req,
                Err(MigratableError::MigrateSocket(io_error))
                    if io_error.kind() == ErrorKind::UnexpectedEof =>
                {
                    debug!("Connection closed by peer");
                    return Ok(());
                }
                Err(e) => return Err(e),
            };

            if req.command() != Command::Memory {
                error!(
                    "Dropping connection. Only Memory commands are allowed on additional connections."
                );
                return Err(MigratableError::MigrateReceive(anyhow!(
                    "Received non memory command on migration receive worker: {:?}",
                    req.command()
                )));
            }

            receive_memory_regions(guest_memory, &req, socket)?;
            Response::ok().write_to(socket)?;
        }
    }

    /// Signals to the worker threads that the migration is finished and joins them.
    /// If any thread encountered an error, this error is returned by this function.
    pub(crate) fn cleanup(&mut self) -> Result<(), MigratableError> {
        self.terminate_fd
            .write(1)
            .context("Failed to signal termination to worker threads.")
            .map_err(MigratableError::MigrateReceive)?;
        let _accept_thread = self
            .accept_thread
            .take()
            .context("Accept thread isn't there?")
            .map_err(MigratableError::MigrateReceive)?;
        _accept_thread
            .join()
            .map_err(|panic| {
                MigratableError::MigrateReceive(anyhow!(
                    "Accept connections thread panicked: {panic:?}"
                ))
            })
            .flatten()
    }
}

impl Drop for ReceiveAdditionalConnections {
    fn drop(&mut self) {
        if self.accept_thread.is_some() {
            error!("ReceiveAdditionalConnections did no cleanup!");
            let _ = self.cleanup();
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
        let path = socket_url_to_path(receiver_url)?;
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

/// Receive memory contents for the given range table into guest memory.
pub(crate) fn receive_memory_regions(
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
