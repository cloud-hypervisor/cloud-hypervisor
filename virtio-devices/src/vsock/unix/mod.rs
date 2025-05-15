// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//

//! This module implements the Unix Domain Sockets backend for vsock - a mediator between
//! guest-side AF_VSOCK sockets and host-side AF_UNIX sockets. The heavy lifting is performed by
//! `muxer::VsockMuxer`, a connection multiplexer that uses `super::csm::VsockConnection` for
//! handling vsock connection states.
//!
//! Check out `muxer.rs` for a more detailed explanation of the inner workings of this backend.

mod muxer;
mod muxer_killq;
mod muxer_rxq;

pub use muxer::VsockMuxer as VsockUnixBackend;
use thiserror::Error;
pub use Error as VsockUnixError;

mod defs {
    /// Maximum number of established connections that we can handle.
    pub const MAX_CONNECTIONS: usize = 1023;

    /// Size of the muxer RX packet queue.
    pub const MUXER_RXQ_SIZE: usize = 256;

    /// Size of the muxer connection kill queue.
    pub const MUXER_KILLQ_SIZE: usize = 128;
}

#[derive(Error, Debug)]
pub enum Error {
    /// Error converting from UTF-8
    #[error("Error converting from UTF-8")]
    ConvertFromUtf8(#[source] std::str::Utf8Error),
    /// Error registering a new epoll-listening FD.
    #[error("Error registering a new epoll-listening FD")]
    EpollAdd(#[source] std::io::Error),
    /// Error creating an epoll FD.
    #[error("Error creating an epoll FD")]
    EpollFdCreate(#[source] std::io::Error),
    /// The host made an invalid vsock port connection request.
    #[error("The host made an invalid vsock port connection request")]
    InvalidPortRequest,
    /// Error parsing integer.
    #[error("Error parsing integer")]
    ParseInteger(#[source] std::num::ParseIntError),
    /// Error reading stream port.
    #[error("Error reading stream port")]
    ReadStreamPort(#[source] Box<Error>),
    /// Error accepting a new connection from the host-side Unix socket.
    #[error("Error accepting a new connection from the host-side Unix socket")]
    UnixAccept(#[source] std::io::Error),
    /// Error binding to the host-side Unix socket.
    #[error("Error binding to the host-side Unix socket")]
    UnixBind(#[source] std::io::Error),
    /// Error connecting to a host-side Unix socket.
    #[error("Error connecting to a host-side Unix socket")]
    UnixConnect(#[source] std::io::Error),
    /// Error reading from host-side Unix socket.
    #[error("Error reading from host-side Unix socket")]
    UnixRead(#[source] std::io::Error),
    /// Muxer connection limit reached.
    #[error("Muxer connection limit reached")]
    TooManyConnections,
}

type Result<T> = std::result::Result<T, Error>;
type MuxerConnection = super::csm::VsockConnection<std::os::unix::net::UnixStream>;
