// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
//! This module implements our vsock connection state machine. The heavy lifting is done by
//! `connection::VsockConnection`, while this file only defines some constants and helper structs.

use std::ffi::CString;
use std::mem::offset_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::{io, result};

use thiserror::Error;

use super::SocketType;

mod connection;
pub(crate) mod seqpacket;
pub(crate) mod stream;
pub(crate) mod transport;
mod txbuf;

pub(super) use connection::VsockConnection;

/// Creates a non-blocking Unix socket of the given type.
fn new_socket(socket_type: SocketType) -> io::Result<OwnedFd> {
    let kind = match socket_type {
        SocketType::Stream => libc::SOCK_STREAM,
        SocketType::SeqPacket => libc::SOCK_SEQPACKET,
    };
    // SAFETY: socket takes only integer arguments and returns a new owned descriptor.
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            kind | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a newly created socket whose ownership is transferred here.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn path_to_sock_addr(path: &Path) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    if path.as_os_str().is_empty() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let path =
        CString::new(path.as_os_str().as_bytes()).map_err(|_| io::ErrorKind::InvalidInput)?;
    let mut address = libc::sockaddr_un {
        sun_family: libc::AF_UNIX as libc::sa_family_t,
        sun_path: [0; _],
    };
    let bytes = path.as_bytes_with_nul();
    if bytes.len() > address.sun_path.len() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    for (dst, src) in address.sun_path.iter_mut().zip(bytes) {
        *dst = *src as libc::c_char;
    }
    let length = {
        let off = offset_of!(libc::sockaddr_un, sun_path);
        (off + bytes.len()) as libc::socklen_t
    };
    Ok((address, length))
}

fn connect(socket: &impl AsRawFd, path: &Path) -> io::Result<()> {
    let (address, length) = path_to_sock_addr(path)?;
    // SAFETY: address is initialized and length covers its family and terminated path.
    if unsafe {
        libc::connect(
            socket.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            length,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) mod defs {
    /// Vsock connection TX buffer capacity.
    pub(crate) const CONN_TX_BUF_SIZE: u32 = 64 * 1024;

    /// When the guest thinks we have less than this amount of free buffer space,
    /// we will send them a credit update packet.
    pub(crate) const CONN_CREDIT_UPDATE_THRESHOLD: u32 = 4 * 1024;

    /// Connection request timeout, in millis.
    pub(crate) const CONN_REQUEST_TIMEOUT_MS: u64 = 2000;

    /// Connection graceful shutdown timeout, in millis.
    pub(crate) const CONN_SHUTDOWN_TIMEOUT_MS: u64 = 2000;
}

#[derive(Debug, Error)]
pub(super) enum Error {
    /// Attempted to push data to a full TX buffer.
    #[error("TX buffer full")]
    TxBufFull,
    /// An I/O error occurred, when attempting to flush the connection TX buffer.
    #[error("Error flushing TX buffer")]
    TxBufFlush(#[source] io::Error),
    /// An I/O error occurred, when attempting to write data to the host-side stream.
    #[error("Error writing to host side stream")]
    StreamWrite(#[source] io::Error),
    /// An I/O error occurred, when reading packet data.
    #[error("Error reading packet buffer")]
    PktBufRead,
}

type Result<T> = result::Result<T, Error>;

/// A vsock connection state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ConnState {
    /// The connection has been initiated by the host end, but is yet to be confirmed by the guest.
    LocalInit,
    /// The connection has been initiated by the guest, but we are yet to confirm it, by sending
    /// a response packet (VSOCK_OP_RESPONSE).
    PeerInit,
    /// The connection handshake has been performed successfully, and data can now be exchanged.
    Established,
    /// The host (AF_UNIX) socket has been (partially) shut down. The tuple represents the host
    /// R/W indication: (will_not_recv_anymore_data, will_not_send_anymore_data).
    LocalClosed(bool, bool),
    /// A VSOCK_OP_SHUTDOWN packet was received from the guest. The tuple represents the guest R/W
    /// indication: (will_not_recv_anymore_data, will_not_send_anymore_data).
    PeerClosed(bool, bool),
    /// The connection is scheduled to be forcefully terminated as soon as possible.
    Killed,
}

/// An RX indication, used by `VsockConnection` to schedule future `recv_pkt()` responses.
/// For instance, after being notified that there is available data to be read from the host stream
/// (via `notify()`), the connection will store a `PendingRx::Rw` to be later inspected by
/// `recv_pkt()`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PendingRx {
    /// We need to yield a connection request packet (VSOCK_OP_REQUEST).
    Request = 0,
    /// We need to yield a connection response packet (VSOCK_OP_RESPONSE).
    Response = 1,
    /// We need to yield a forceful connection termination packet (VSOCK_OP_RST).
    Rst = 2,
    /// We need to yield a data packet (VSOCK_OP_RW), by reading from the AF_UNIX socket.
    Rw = 3,
    /// We need to yield a credit update packet (VSOCK_OP_CREDIT_UPDATE).
    CreditUpdate = 4,
}
impl PendingRx {
    /// Transform the enum value into a bitmask, that can be used for set operations.
    fn into_mask(self) -> u16 {
        1u16 << (self as u16)
    }
}

/// A set of RX indications (`PendingRx` items).
struct PendingRxSet {
    data: u16,
}

impl PendingRxSet {
    /// Insert an item into the set.
    fn insert(&mut self, it: PendingRx) {
        self.data |= it.into_mask();
    }

    /// Remove an item from the set and return:
    /// - true, if the item was in the set; or
    /// - false, if the item wasn't in the set.
    fn remove(&mut self, it: PendingRx) -> bool {
        let ret = self.contains(it);
        self.data &= !it.into_mask();
        ret
    }

    /// Check if an item is present in this set.
    fn contains(&self, it: PendingRx) -> bool {
        self.data & it.into_mask() != 0
    }

    /// Check if the set is empty.
    fn is_empty(&self) -> bool {
        self.data == 0
    }
}

/// Create a set containing only one item.
impl From<PendingRx> for PendingRxSet {
    fn from(it: PendingRx) -> Self {
        Self {
            data: it.into_mask(),
        }
    }
}
