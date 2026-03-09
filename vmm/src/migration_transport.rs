// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use std::net::{TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::result::Result;

use anyhow::anyhow;
use log::info;
use vm_migration::MigratableError;

use crate::SocketStream;

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
