// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

// This is only used by the tests module from tap.rs, but we cannot use #[macro_use] unless the
// reference to lazy_static is declared at the root level of the importing crate.
#[cfg(test)]
#[macro_use]
extern crate lazy_static;
extern crate libc;
#[macro_use]
extern crate log;
extern crate net_gen;
extern crate rate_limiter;
extern crate serde;
extern crate virtio_bindings;
extern crate vm_memory;
extern crate vm_virtio;
extern crate vmm_sys_util;

mod mac;
mod open_tap;
mod queue_pair;
mod tap;

use std::io::Error as IoError;
use std::os::unix::io::{FromRawFd, RawFd};
use std::{io, mem, net};

pub use mac::{MacAddr, MAC_ADDR_LEN};
pub use open_tap::{open_tap, Error as OpenTapError};
pub use queue_pair::{NetCounters, NetQueuePair, NetQueuePairError, RxVirtio, TxVirtio};
pub use tap::{Error as TapError, Tap};

#[derive(Debug)]
pub enum Error {
    /// Failed to create a socket.
    CreateSocket(IoError),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Create a sockaddr_in from an IPv4 address, and expose it as
/// an opaque sockaddr suitable for usage by socket ioctls.
fn create_sockaddr(ip_addr: net::Ipv4Addr) -> net_gen::sockaddr {
    // IPv4 addresses big-endian (network order), but Ipv4Addr will give us
    // a view of those bytes directly so we can avoid any endian trickiness.
    let addr_in = net_gen::sockaddr_in {
        sin_family: net_gen::AF_INET as u16,
        sin_port: 0,
        sin_addr: unsafe { mem::transmute(ip_addr.octets()) },
        __pad: [0; 8usize],
    };

    unsafe { mem::transmute(addr_in) }
}

fn create_socket() -> Result<net::UdpSocket> {
    // This is safe since we check the return value.
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(Error::CreateSocket(IoError::last_os_error()));
    }

    // This is safe; nothing else will use or hold onto the raw sock fd.
    Ok(unsafe { net::UdpSocket::from_raw_fd(sock) })
}

fn vnet_hdr_len() -> usize {
    use virtio_bindings::bindings::virtio_net::virtio_net_hdr_v1;
    std::mem::size_of::<virtio_net_hdr_v1>()
}

pub fn register_listener(
    epoll_fd: RawFd,
    fd: RawFd,
    ev_type: epoll::Events,
    data: u64,
) -> std::result::Result<(), io::Error> {
    epoll::ctl(
        epoll_fd,
        epoll::ControlOptions::EPOLL_CTL_ADD,
        fd,
        epoll::Event::new(ev_type, data),
    )
}

pub fn unregister_listener(
    epoll_fd: RawFd,
    fd: RawFd,
    ev_type: epoll::Events,
    data: u64,
) -> std::result::Result<(), io::Error> {
    epoll::ctl(
        epoll_fd,
        epoll::ControlOptions::EPOLL_CTL_DEL,
        fd,
        epoll::Event::new(ev_type, data),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_sockaddr() {
        let addr: net::Ipv4Addr = "10.0.0.1".parse().unwrap();
        let sockaddr = create_sockaddr(addr);

        assert_eq!(sockaddr.sa_family, net_gen::AF_INET as u16);

        let data = &sockaddr.sa_data[..];

        // The first two bytes should represent the port, which is 0.
        assert_eq!(data[0], 0);
        assert_eq!(data[1], 0);

        // The next four bytes should represent the actual IPv4 address, in network order.
        assert_eq!(data[2], 10);
        assert_eq!(data[3], 0);
        assert_eq!(data[4], 0);
        assert_eq!(data[5], 1);
    }
}
