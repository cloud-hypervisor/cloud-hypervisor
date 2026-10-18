// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! NBD connection establishment and blocking transmission helpers.
//!
//! Lost connections are not re-established.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::Duration;
use std::{fmt, mem};

use log::warn;
use thiserror::Error;

use super::handshake::{NbdExportInfo, NbdHandshakeError, negotiate};
use super::proto::*;
use super::uri::{NbdAddress, NbdUri};

/// Timeout applied to connect and to every handshake read/write.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Error, Debug)]
pub enum NbdConnectError {
    #[error("Failed to connect to NBD server {0}")]
    Connect(String, #[source] io::Error),
    #[error("Failed to configure NBD socket")]
    Configure(#[source] io::Error),
    #[error("NBD handshake with {0} failed")]
    Handshake(String, #[source] NbdHandshakeError),
}

/// Connected stream to an NBD server.
#[derive(Debug)]
pub(crate) enum NbdStream {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl NbdStream {
    fn set_timeouts(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Self::Tcp(s) => {
                s.set_read_timeout(timeout)?;
                s.set_write_timeout(timeout)
            }
            Self::Unix(s) => {
                s.set_read_timeout(timeout)?;
                s.set_write_timeout(timeout)
            }
        }
    }

    pub(crate) fn shutdown(&self) {
        let _ = match self {
            Self::Tcp(s) => s.shutdown(Shutdown::Both),
            Self::Unix(s) => s.shutdown(Shutdown::Both),
        };
    }
}

impl Read for NbdStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(s) => s.read(buf),
            Self::Unix(s) => s.read(buf),
        }
    }
}

impl Write for NbdStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(s) => s.write(buf),
            Self::Unix(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tcp(s) => s.flush(),
            Self::Unix(s) => s.flush(),
        }
    }
}

impl AsRawFd for NbdStream {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            Self::Tcp(s) => s.as_raw_fd(),
            Self::Unix(s) => s.as_raw_fd(),
        }
    }
}

/// Connects to `address` with `timeout` applied to TCP connect and to
/// every subsequent socket read/write.
fn connect_stream(address: &NbdAddress, timeout: Duration) -> io::Result<NbdStream> {
    let stream = match address {
        NbdAddress::Tcp { host, port } => {
            let mut last_error = io::Error::new(io::ErrorKind::NotFound, "no address resolved");
            for addr in (host.as_str(), *port).to_socket_addrs()? {
                match TcpStream::connect_timeout(&addr, timeout) {
                    Ok(s) => {
                        s.set_nodelay(true)?;
                        return Ok(NbdStream::Tcp(s));
                    }
                    Err(e) => last_error = e,
                }
            }
            Err(last_error)
        }
        NbdAddress::Unix { path } => UnixStream::connect(path).map(NbdStream::Unix),
    }?;
    stream.set_timeouts(Some(timeout))?;
    Ok(stream)
}

/// Returns a copy of `iovs` restricted to the byte range `[start, start + len)`.
///
/// The range must lie within the total length described by `iovs`.
pub(crate) fn sub_iovecs(iovs: &[libc::iovec], start: usize, len: usize) -> Vec<libc::iovec> {
    let mut out = Vec::new();
    let mut skip = start;
    let mut left = len;
    for iov in iovs {
        if left == 0 {
            break;
        }
        if skip >= iov.iov_len {
            skip -= iov.iov_len;
            continue;
        }
        let n = (iov.iov_len - skip).min(left);
        out.push(libc::iovec {
            // SAFETY: skip < iov_len, so the result stays inside the region.
            iov_base: unsafe { iov.iov_base.cast::<u8>().add(skip) }.cast(),
            iov_len: n,
        });
        left -= n;
        skip = 0;
    }
    debug_assert_eq!(left, 0, "iovec range out of bounds");
    out
}

/// Drops the first `n` bytes from `iovs`.
pub(crate) fn advance_iovecs(iovs: &mut Vec<libc::iovec>, n: usize) {
    let total: usize = iovs.iter().map(|iov| iov.iov_len).sum();
    *iovs = sub_iovecs(iovs, n, total - n);
}

/// Returns the number of bytes described by `iovs`.
pub(crate) fn iovecs_len(iovs: &[libc::iovec]) -> usize {
    iovs.iter().map(|iov| iov.iov_len).sum()
}

/// Builds a `msghdr` describing `iovs`.
pub(crate) fn msghdr_for(iovs: &mut [libc::iovec]) -> libc::msghdr {
    // SAFETY: msghdr is a plain C struct for which all-zero is valid.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = iovs.as_mut_ptr();
    msg.msg_iovlen = iovs.len() as _;
    msg
}

/// One NBD connection in the transmission phase.
#[derive(Debug)]
pub(crate) struct NbdConn {
    stream: NbdStream,
    info: NbdExportInfo,
    next_cookie: u64,
    dead: bool,
}

impl NbdConn {
    /// Connects to the server described by `uri` and completes the handshake.
    pub(crate) fn connect(uri: &NbdUri) -> Result<Self, NbdConnectError> {
        let mut stream = connect_stream(&uri.address, HANDSHAKE_TIMEOUT)
            .map_err(|e| NbdConnectError::Connect(uri.to_string(), e))?;
        let info = negotiate(&mut stream, &uri.export)
            .map_err(|e| NbdConnectError::Handshake(uri.to_string(), e))?;
        stream
            .set_timeouts(None)
            .map_err(NbdConnectError::Configure)?;
        Ok(Self::from_parts(stream, info))
    }

    pub(crate) fn from_parts(stream: NbdStream, info: NbdExportInfo) -> Self {
        Self {
            stream,
            info,
            next_cookie: 1,
            dead: false,
        }
    }

    pub(crate) fn info(&self) -> &NbdExportInfo {
        &self.info
    }

    pub(crate) fn fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }

    #[cfg_attr(not(feature = "io_uring"), allow(dead_code))]
    pub(crate) fn is_dead(&self) -> bool {
        self.dead
    }

    /// Marks the connection unusable and shuts the socket down.
    ///
    /// Logs once; later calls are silent.
    pub(crate) fn mark_dead(&mut self, reason: &dyn fmt::Display) {
        if !self.dead {
            warn!("NBD connection lost, failing all further I/O: {reason}");
            self.dead = true;
            self.stream.shutdown();
        }
    }

    pub(crate) fn next_cookie(&mut self) -> u64 {
        let cookie = self.next_cookie;
        self.next_cookie = self.next_cookie.wrapping_add(1);
        cookie
    }

    /// Sends all bytes described by `iovs`.
    ///
    /// # Safety
    ///
    /// `iovs` must describe memory valid for reads for the duration of the
    /// call.
    unsafe fn send_all(&mut self, mut iovs: Vec<libc::iovec>) -> io::Result<()> {
        while iovecs_len(&iovs) > 0 {
            let msg = msghdr_for(&mut iovs);
            // SAFETY: msg describes iovecs that the caller guarantees are valid
            // for reads for the duration of this call.
            let n = unsafe { libc::sendmsg(self.fd(), &msg, libc::MSG_NOSIGNAL) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            advance_iovecs(&mut iovs, n as usize);
        }
        Ok(())
    }

    /// Fills all bytes described by `iovs`.
    ///
    /// # Safety
    ///
    /// `iovs` must describe memory valid for writes for the duration of the
    /// call.
    unsafe fn recv_all(&mut self, mut iovs: Vec<libc::iovec>) -> io::Result<()> {
        while iovecs_len(&iovs) > 0 {
            let mut msg = msghdr_for(&mut iovs);
            // SAFETY: msg describes iovecs that the caller guarantees are valid
            // for writes for the duration of this call.
            let n = unsafe { libc::recvmsg(self.fd(), &mut msg, libc::MSG_WAITALL) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            advance_iovecs(&mut iovs, n as usize);
        }
        Ok(())
    }

    /// Fills `buf` from the socket.
    fn recv_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        let iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        // SAFETY: iov describes `buf`, which is exclusively borrowed for the
        // duration of this call.
        unsafe { self.recv_all(vec![iov]) }
    }

    /// Sends one command and waits for its simple reply.
    ///
    /// `payload` is sent after the header for `NBD_CMD_WRITE` and filled
    /// from the reply for `NBD_CMD_READ`. Returns the positive errno from
    /// the reply (0 on success). An `Err` means the connection is unusable
    /// and has been marked dead.
    ///
    /// # Safety
    ///
    /// `payload` must describe memory valid for reads (write commands) or
    /// writes (read commands) of its full length for the duration of the
    /// call.
    pub(crate) unsafe fn command(
        &mut self,
        command: u16,
        offset: u64,
        length: u32,
        payload: &[libc::iovec],
    ) -> io::Result<i32> {
        if self.dead {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        // SAFETY: the caller upholds the payload requirements of this function.
        let result = unsafe { self.command_inner(command, offset, length, payload) };
        if let Err(e) = &result {
            self.mark_dead(e);
        }
        result
    }

    /// # Safety
    ///
    /// Same as [`Self::command`].
    unsafe fn command_inner(
        &mut self,
        command: u16,
        offset: u64,
        length: u32,
        payload: &[libc::iovec],
    ) -> io::Result<i32> {
        let cookie = self.next_cookie();
        let mut header = NbdRequest {
            flags: 0,
            command,
            cookie,
            offset,
            length,
        }
        .encode();
        let mut iovs = vec![libc::iovec {
            iov_base: header.as_mut_ptr().cast(),
            iov_len: header.len(),
        }];
        if command == NBD_CMD_WRITE {
            iovs.extend_from_slice(payload);
        }
        // SAFETY: the header iovec describes `header`, which outlives this
        // call, and the caller guarantees the payload is valid for reads.
        unsafe { self.send_all(iovs)? };
        if command == NBD_CMD_DISC {
            return Ok(0);
        }

        let mut reply = [0u8; NBD_SIMPLE_REPLY_SIZE];
        self.recv_exact(&mut reply)?;
        let reply = NbdSimpleReply::decode(&reply)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad NBD reply magic"))?;
        if reply.cookie != cookie {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected NBD reply cookie {}", reply.cookie),
            ));
        }
        let errno = nbd_errno_to_errno(reply.error);
        if command == NBD_CMD_READ && errno == 0 {
            // SAFETY: the caller guarantees the payload is valid for writes.
            unsafe { self.recv_all(payload.to_vec())? };
        }
        Ok(errno)
    }

    /// Sends `NBD_CMD_DISC` if the connection is alive, then shuts the
    /// socket down.
    ///
    /// No other operation may be in progress on the socket.
    pub(crate) fn disconnect(&mut self) {
        if !self.dead {
            // SAFETY: NBD_CMD_DISC carries no payload.
            let _ = unsafe { self.command(NBD_CMD_DISC, 0, 0, &[]) };
        }
        self.close();
    }

    /// Shuts the socket down without notifying the server.
    pub(crate) fn close(&mut self) {
        self.dead = true;
        self.stream.shutdown();
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn conn_from_unix(stream: UnixStream, info: NbdExportInfo) -> NbdConn {
        NbdConn::from_parts(NbdStream::Unix(stream), info)
    }

    #[test]
    fn sub_iovecs_ranges() {
        let mut a = [0u8; 4];
        let mut b = [0u8; 6];
        let iovs = [
            libc::iovec {
                iov_base: a.as_mut_ptr().cast(),
                iov_len: a.len(),
            },
            libc::iovec {
                iov_base: b.as_mut_ptr().cast(),
                iov_len: b.len(),
            },
        ];
        let sub = sub_iovecs(&iovs, 2, 5);
        assert_eq!(sub.len(), 2);
        assert_eq!(sub[0].iov_len, 2);
        assert_eq!(sub[0].iov_base as usize, a.as_ptr() as usize + 2);
        assert_eq!(sub[1].iov_len, 3);
        assert_eq!(sub[1].iov_base as usize, b.as_ptr() as usize);

        let sub = sub_iovecs(&iovs, 4, 6);
        assert_eq!(sub.len(), 1);
        assert_eq!(sub[0].iov_base as usize, b.as_ptr() as usize);

        let mut v = iovs.to_vec();
        advance_iovecs(&mut v, 5);
        assert_eq!(iovecs_len(&v), 5);
        assert_eq!(v[0].iov_base as usize, b.as_ptr() as usize + 1);
    }
}
