// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::result::Result;

use anyhow::{Context, anyhow};
use log::info;
use serde_json;
use vm_migration::protocol::{Request, Response};
use vm_migration::{MigratableError, Snapshot};

use crate::{SocketStream, VmMigrationConfig};

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
        let path = socket_url_to_path(receiver_url).map_err(MigratableError::MigrateSend)?;
        let listener = UnixListener::bind(&path).map_err(|e| {
            MigratableError::MigrateReceive(anyhow!("Error binding to UNIX socket: {e}"))
        })?;

        let (socket, _addr) = listener.accept().map_err(|e| {
            MigratableError::MigrateReceive(anyhow!(
                "Error accepting connection on UNIX socket: {e}"
            ))
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
