// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Structs for Unix Domain Socket listener and endpoint.

#![allow(dead_code)]

use libc::{c_void, iovec};
use std::io::ErrorKind;
use std::marker::PhantomData;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::{mem, slice};

use super::message::*;
use super::sock_ctrl_msg::ScmSocket;
use super::{Error, Result};

/// Unix domain socket listener for accepting incoming connections.
pub struct Listener {
    fd: UnixListener,
    path: String,
}

impl Listener {
    /// Create a unix domain socket listener.
    ///
    /// # Return:
    /// * - the new Listener object on success.
    /// * - SocketError: failed to create listener socket.
    pub fn new(path: &str, unlink: bool) -> Result<Self> {
        if unlink {
            let _ = std::fs::remove_file(path);
        }
        let fd = UnixListener::bind(path).map_err(Error::SocketError)?;
        Ok(Listener {
            fd,
            path: path.to_string(),
        })
    }

    /// Accept an incoming connection.
    ///
    /// # Return:
    /// * - Some(UnixStream): new UnixStream object if new incoming connection is available.
    /// * - None: no incoming connection available.
    /// * - SocketError: errors from accept().
    pub fn accept(&self) -> Result<Option<UnixStream>> {
        loop {
            match self.fd.accept() {
                Ok((socket, _addr)) => return Ok(Some(socket)),
                Err(e) => {
                    match e.kind() {
                        // No incoming connection available.
                        ErrorKind::WouldBlock => return Ok(None),
                        // New connection closed by peer.
                        ErrorKind::ConnectionAborted => return Ok(None),
                        // Interrupted by signals, retry
                        ErrorKind::Interrupted => continue,
                        _ => return Err(Error::SocketError(e)),
                    }
                }
            }
        }
    }

    /// Change blocking status on the listener.
    ///
    /// # Return:
    /// * - () on success.
    /// * - SocketError: failure from set_nonblocking().
    pub fn set_nonblocking(&self, block: bool) -> Result<()> {
        self.fd.set_nonblocking(block).map_err(Error::SocketError)
    }
}

impl AsRawFd for Listener {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.path.clone());
    }
}

/// Unix domain socket endpoint for vhost-user connection.
pub(super) struct Endpoint<R: Req> {
    sock: UnixStream,
    _r: PhantomData<R>,
}

impl<R: Req> Endpoint<R> {
    /// Create a new stream by connecting to server at `str`.
    ///
    /// # Return:
    /// * - the new Endpoint object on success.
    /// * - SocketConnect: failed to connect to peer.
    pub fn connect(path: &str) -> Result<Self> {
        let sock = UnixStream::connect(path).map_err(Error::SocketConnect)?;
        Ok(Self::from_stream(sock))
    }

    /// Create an endpoint from a stream object.
    pub fn from_stream(sock: UnixStream) -> Self {
        Endpoint {
            sock,
            _r: PhantomData,
        }
    }

    /// Sends bytes from scatter-gather vectors over the socket with optional attached file
    /// descriptors.
    ///
    /// # Return:
    /// * - number of bytes sent on success
    /// * - SocketRetry: temporary error caused by signals or short of resources.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    pub fn send_iovec(&mut self, iovs: &[&[u8]], fds: Option<&[RawFd]>) -> Result<usize> {
        let rfds = match fds {
            Some(rfds) => rfds,
            _ => &[],
        };
        self.sock.send_with_fds(iovs, rfds).map_err(Into::into)
    }

    /// Sends bytes from a slice over the socket with optional attached file descriptors.
    ///
    /// # Return:
    /// * - number of bytes sent on success
    /// * - SocketRetry: temporary error caused by signals or short of resources.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    pub fn send_slice(&mut self, data: &[u8], fds: Option<&[RawFd]>) -> Result<usize> {
        self.send_iovec(&[data], fds)
    }

    /// Sends a header-only message with optional attached file descriptors.
    ///
    /// # Return:
    /// * - number of bytes sent on success
    /// * - SocketRetry: temporary error caused by signals or short of resources.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    /// * - PartialMessage: received a partial message.
    pub fn send_header(
        &mut self,
        hdr: &VhostUserMsgHeader<R>,
        fds: Option<&[RawFd]>,
    ) -> Result<()> {
        // Safe because there can't be other mutable referance to hdr.
        let iovs = unsafe {
            [slice::from_raw_parts(
                hdr as *const VhostUserMsgHeader<R> as *const u8,
                mem::size_of::<VhostUserMsgHeader<R>>(),
            )]
        };
        let bytes = self.send_iovec(&iovs[..], fds)?;
        if bytes != mem::size_of::<VhostUserMsgHeader<R>>() {
            return Err(Error::PartialMessage);
        }
        Ok(())
    }

    /// Send a message with header and body. Optional file descriptors may be attached to
    /// the message.
    ///
    /// # Return:
    /// * - number of bytes sent on success
    /// * - SocketRetry: temporary error caused by signals or short of resources.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    /// * - PartialMessage: received a partial message.
    pub fn send_message<T: Sized>(
        &mut self,
        hdr: &VhostUserMsgHeader<R>,
        body: &T,
        fds: Option<&[RawFd]>,
    ) -> Result<()> {
        // Safe because there can't be other mutable referance to hdr and body.
        let iovs = unsafe {
            [
                slice::from_raw_parts(
                    hdr as *const VhostUserMsgHeader<R> as *const u8,
                    mem::size_of::<VhostUserMsgHeader<R>>(),
                ),
                slice::from_raw_parts(body as *const T as *const u8, mem::size_of::<T>()),
            ]
        };
        let bytes = self.send_iovec(&iovs[..], fds)?;
        if bytes != mem::size_of::<VhostUserMsgHeader<R>>() + mem::size_of::<T>() {
            return Err(Error::PartialMessage);
        }
        Ok(())
    }

    /// Send a message with header, body and payload. Optional file descriptors
    /// may also be attached to the message.
    ///
    /// # Return:
    /// * - number of bytes sent on success
    /// * - SocketRetry: temporary error caused by signals or short of resources.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    /// * - OversizedMsg: message size is too big.
    /// * - PartialMessage: received a partial message.
    /// * - IncorrectFds: wrong number of attached fds.
    pub fn send_message_with_payload<T: Sized, P: Sized>(
        &mut self,
        hdr: &VhostUserMsgHeader<R>,
        body: &T,
        payload: &[P],
        fds: Option<&[RawFd]>,
    ) -> Result<()> {
        let len = payload.len() * mem::size_of::<P>();
        if len > MAX_MSG_SIZE - mem::size_of::<T>() {
            return Err(Error::OversizedMsg);
        }
        if let Some(fd_arr) = fds {
            if fd_arr.len() > MAX_ATTACHED_FD_ENTRIES {
                return Err(Error::IncorrectFds);
            }
        }

        // Safe because there can't be other mutable reference to hdr, body and payload.
        let iovs = unsafe {
            [
                slice::from_raw_parts(
                    hdr as *const VhostUserMsgHeader<R> as *const u8,
                    mem::size_of::<VhostUserMsgHeader<R>>(),
                ),
                slice::from_raw_parts(body as *const T as *const u8, mem::size_of::<T>()),
                slice::from_raw_parts(payload.as_ptr() as *const u8, len),
            ]
        };
        let total = mem::size_of::<VhostUserMsgHeader<R>>() + mem::size_of::<T>() + len;
        let len = self.send_iovec(&iovs, fds)?;
        if len != total {
            return Err(Error::PartialMessage);
        }
        Ok(())
    }

    /// Reads bytes from the socket into the given scatter/gather vectors.
    ///
    /// # Return:
    /// * - (number of bytes received, buf) on success
    /// * - SocketRetry: temporary error caused by signals or short of resources.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    pub fn recv_data(&mut self, len: usize) -> Result<(usize, Vec<u8>)> {
        let mut rbuf = vec![0u8; len];
        let mut iovs = [iovec {
            iov_base: rbuf.as_mut_ptr() as *mut c_void,
            iov_len: len,
        }];
        let (bytes, _) = self.sock.recv_with_fds(&mut iovs, &mut [])?;
        Ok((bytes, rbuf))
    }

    /// Reads bytes from the socket into the given scatter/gather vectors with optional attached
    /// file descriptors.
    ///
    /// The underlying communication channel is a Unix domain socket in STREAM mode. It's a little
    /// tricky to pass file descriptors through such a communication channel. Let's assume that a
    /// sender sending a message with some file descriptors attached. To successfully receive those
    /// attached file descriptors, the receiver must obey following rules:
    ///   1) file descriptors are attached to a message.
    ///   2) message(packet) boundaries must be respected on the receive side.
    /// In other words, recvmsg() operations must not cross the packet boundary, otherwise the
    /// attached file descriptors will get lost.
    ///
    /// # Return:
    /// * - (number of bytes received, [received fds]) on success
    /// * - SocketRetry: temporary error caused by signals or short of resources.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    pub fn recv_into_iovec(&mut self, iovs: &mut [iovec]) -> Result<(usize, Option<Vec<RawFd>>)> {
        let mut fd_array = vec![0; MAX_ATTACHED_FD_ENTRIES];
        let (bytes, fds) = self.sock.recv_with_fds(iovs, &mut fd_array)?;
        let rfds = match fds {
            0 => None,
            n => {
                let mut fds = Vec::with_capacity(n);
                fds.extend_from_slice(&fd_array[0..n]);
                Some(fds)
            }
        };

        Ok((bytes, rfds))
    }

    /// Reads bytes from the socket into a new buffer with optional attached
    /// file descriptors. Received file descriptors are set close-on-exec.
    ///
    /// # Return:
    /// * - (number of bytes received, buf, [received fds]) on success.
    /// * - SocketRetry: temporary error caused by signals or short of resources.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    pub fn recv_into_buf(
        &mut self,
        buf_size: usize,
    ) -> Result<(usize, Vec<u8>, Option<Vec<RawFd>>)> {
        let mut buf = vec![0u8; buf_size];
        let (bytes, rfds) = {
            let mut iovs = [iovec {
                iov_base: buf.as_mut_ptr() as *mut c_void,
                iov_len: buf_size,
            }];
            self.recv_into_iovec(&mut iovs)?
        };
        Ok((bytes, buf, rfds))
    }

    /// Receive a header-only message with optional attached file descriptors.
    /// Note, only the first MAX_ATTACHED_FD_ENTRIES file descriptors will be
    /// accepted and all other file descriptor will be discard silently.
    ///
    /// # Return:
    /// * - (message header, [received fds]) on success.
    /// * - SocketRetry: temporary error caused by signals or short of resources.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    /// * - PartialMessage: received a partial message.
    /// * - InvalidMessage: received a invalid message.
    pub fn recv_header(&mut self) -> Result<(VhostUserMsgHeader<R>, Option<Vec<RawFd>>)> {
        let mut hdr = VhostUserMsgHeader::default();
        let mut iovs = [iovec {
            iov_base: (&mut hdr as *mut VhostUserMsgHeader<R>) as *mut c_void,
            iov_len: mem::size_of::<VhostUserMsgHeader<R>>(),
        }];
        let (bytes, rfds) = self.recv_into_iovec(&mut iovs[..])?;

        if bytes != mem::size_of::<VhostUserMsgHeader<R>>() {
            return Err(Error::PartialMessage);
        } else if !hdr.is_valid() {
            return Err(Error::InvalidMessage);
        }

        Ok((hdr, rfds))
    }

    /// Receive a message with optional attached file descriptors.
    /// Note, only the first MAX_ATTACHED_FD_ENTRIES file descriptors will be
    /// accepted and all other file descriptor will be discard silently.
    ///
    /// # Return:
    /// * - (message header, message body, [received fds]) on success.
    /// * - SocketRetry: temporary error caused by signals or short of resources.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    /// * - PartialMessage: received a partial message.
    /// * - InvalidMessage: received a invalid message.
    pub fn recv_body<T: Sized + Default + VhostUserMsgValidator>(
        &mut self,
    ) -> Result<(VhostUserMsgHeader<R>, T, Option<Vec<RawFd>>)> {
        let mut hdr = VhostUserMsgHeader::default();
        let mut body: T = Default::default();
        let mut iovs = [
            iovec {
                iov_base: (&mut hdr as *mut VhostUserMsgHeader<R>) as *mut c_void,
                iov_len: mem::size_of::<VhostUserMsgHeader<R>>(),
            },
            iovec {
                iov_base: (&mut body as *mut T) as *mut c_void,
                iov_len: mem::size_of::<T>(),
            },
        ];
        let (bytes, rfds) = self.recv_into_iovec(&mut iovs[..])?;

        let total = mem::size_of::<VhostUserMsgHeader<R>>() + mem::size_of::<T>();
        if bytes != total {
            return Err(Error::PartialMessage);
        } else if !hdr.is_valid() || !body.is_valid() {
            return Err(Error::InvalidMessage);
        }

        Ok((hdr, body, rfds))
    }

    /// Receive a message with header and optional content. Callers need to
    /// pre-allocate a big enough buffer to receive the message body and
    /// optional payload. If there are attached file descriptor associated
    /// with the message, the first MAX_ATTACHED_FD_ENTRIES file descriptors
    /// will be accepted and all other file descriptor will be discard
    /// silently.
    ///
    /// # Return:
    /// * - (message header, message size, [received fds]) on success.
    /// * - SocketRetry: temporary error caused by signals or short of resources.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    /// * - PartialMessage: received a partial message.
    /// * - InvalidMessage: received a invalid message.
    pub fn recv_body_into_buf(
        &mut self,
        buf: &mut [u8],
    ) -> Result<(VhostUserMsgHeader<R>, usize, Option<Vec<RawFd>>)> {
        let mut hdr = VhostUserMsgHeader::default();
        let mut iovs = [
            iovec {
                iov_base: (&mut hdr as *mut VhostUserMsgHeader<R>) as *mut c_void,
                iov_len: mem::size_of::<VhostUserMsgHeader<R>>(),
            },
            iovec {
                iov_base: buf.as_mut_ptr() as *mut c_void,
                iov_len: buf.len(),
            },
        ];
        let (bytes, rfds) = self.recv_into_iovec(&mut iovs[..])?;

        if bytes < mem::size_of::<VhostUserMsgHeader<R>>() {
            return Err(Error::PartialMessage);
        } else if !hdr.is_valid() {
            return Err(Error::InvalidMessage);
        }

        Ok((hdr, bytes - mem::size_of::<VhostUserMsgHeader<R>>(), rfds))
    }

    /// Receive a message with optional payload and attached file descriptors.
    /// Note, only the first MAX_ATTACHED_FD_ENTRIES file descriptors will be
    /// accepted and all other file descriptor will be discard silently.
    ///
    /// # Return:
    /// * - (message header, message body, size of payload, [received fds]) on success.
    /// * - SocketRetry: temporary error caused by signals or short of resources.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    /// * - PartialMessage: received a partial message.
    /// * - InvalidMessage: received a invalid message.
    #[cfg_attr(feature = "cargo-clippy", allow(clippy::type_complexity))]
    pub fn recv_payload_into_buf<T: Sized + Default + VhostUserMsgValidator>(
        &mut self,
        buf: &mut [u8],
    ) -> Result<(VhostUserMsgHeader<R>, T, usize, Option<Vec<RawFd>>)> {
        let mut hdr = VhostUserMsgHeader::default();
        let mut body: T = Default::default();
        let mut iovs = [
            iovec {
                iov_base: (&mut hdr as *mut VhostUserMsgHeader<R>) as *mut c_void,
                iov_len: mem::size_of::<VhostUserMsgHeader<R>>(),
            },
            iovec {
                iov_base: (&mut body as *mut T) as *mut c_void,
                iov_len: mem::size_of::<T>(),
            },
            iovec {
                iov_base: buf.as_mut_ptr() as *mut c_void,
                iov_len: buf.len(),
            },
        ];
        let (bytes, rfds) = self.recv_into_iovec(&mut iovs[..])?;

        let total = mem::size_of::<VhostUserMsgHeader<R>>() + mem::size_of::<T>();
        if bytes < total {
            return Err(Error::PartialMessage);
        } else if !hdr.is_valid() || !body.is_valid() {
            return Err(Error::InvalidMessage);
        }

        Ok((hdr, body, bytes - total, rfds))
    }

    /// Close all raw file descriptors.
    pub fn close_rfds(rfds: Option<Vec<RawFd>>) {
        if let Some(fds) = rfds {
            for fd in fds {
                // safe because the rawfds are valid and we don't care about the result.
                let _ = unsafe { libc::close(fd) };
            }
        }
    }
}

impl<T: Req> AsRawFd for Endpoint<T> {
    fn as_raw_fd(&self) -> RawFd {
        self.sock.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    extern crate tempfile;

    use self::tempfile::tempfile;
    use super::*;
    use libc;
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::io::FromRawFd;

    const UNIX_SOCKET_LISTENER: &'static str = "/tmp/vhost_user_test_rust_listener";
    const UNIX_SOCKET_CONNECTION: &'static str = "/tmp/vhost_user_test_rust_connection";
    const UNIX_SOCKET_DATA: &'static str = "/tmp/vhost_user_test_rust_data";
    const UNIX_SOCKET_FD: &'static str = "/tmp/vhost_user_test_rust_fd";
    const UNIX_SOCKET_SEND: &'static str = "/tmp/vhost_user_test_rust_send";

    #[test]
    fn create_listener() {
        let _ = Listener::new(UNIX_SOCKET_LISTENER, true).unwrap();
    }

    #[test]
    fn accept_connection() {
        let listener = Listener::new(UNIX_SOCKET_CONNECTION, true).unwrap();
        listener.set_nonblocking(true).unwrap();

        // accept on a fd without incoming connection
        let conn = listener.accept().unwrap();
        assert!(conn.is_none());

        listener.set_nonblocking(true).unwrap();

        // accept on a closed fd
        unsafe {
            libc::close(listener.as_raw_fd());
        }
        let conn2 = listener.accept();
        assert!(conn2.is_err());
    }

    #[test]
    fn send_data() {
        let listener = Listener::new(UNIX_SOCKET_DATA, true).unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut master = Endpoint::<MasterReq>::connect(UNIX_SOCKET_DATA).unwrap();
        let sock = listener.accept().unwrap().unwrap();
        let mut slave = Endpoint::<MasterReq>::from_stream(sock);

        let buf1 = vec![0x1, 0x2, 0x3, 0x4];
        let mut len = master.send_slice(&buf1[..], None).unwrap();
        assert_eq!(len, 4);
        let (bytes, buf2, _) = slave.recv_into_buf(0x1000).unwrap();
        assert_eq!(bytes, 4);
        assert_eq!(&buf1[..], &buf2[..bytes]);

        len = master.send_slice(&buf1[..], None).unwrap();
        assert_eq!(len, 4);
        let (bytes, buf2, _) = slave.recv_into_buf(0x2).unwrap();
        assert_eq!(bytes, 2);
        assert_eq!(&buf1[..2], &buf2[..]);
        let (bytes, buf2, _) = slave.recv_into_buf(0x2).unwrap();
        assert_eq!(bytes, 2);
        assert_eq!(&buf1[2..], &buf2[..]);
    }

    #[test]
    fn send_fd() {
        let listener = Listener::new(UNIX_SOCKET_FD, true).unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut master = Endpoint::<MasterReq>::connect(UNIX_SOCKET_FD).unwrap();
        let sock = listener.accept().unwrap().unwrap();
        let mut slave = Endpoint::<MasterReq>::from_stream(sock);

        let mut fd = tempfile().unwrap();
        write!(fd, "test").unwrap();

        // Normal case for sending/receiving file descriptors
        let buf1 = vec![0x1, 0x2, 0x3, 0x4];
        let len = master
            .send_slice(&buf1[..], Some(&[fd.as_raw_fd()]))
            .unwrap();
        assert_eq!(len, 4);

        let (bytes, buf2, rfds) = slave.recv_into_buf(4).unwrap();
        assert_eq!(bytes, 4);
        assert_eq!(&buf1[..], &buf2[..]);
        assert!(rfds.is_some());
        let fds = rfds.unwrap();
        {
            assert_eq!(fds.len(), 1);
            let mut file = unsafe { File::from_raw_fd(fds[0]) };
            let mut content = String::new();
            file.seek(SeekFrom::Start(0)).unwrap();
            file.read_to_string(&mut content).unwrap();
            assert_eq!(content, "test");
        }

        // Following communication pattern should work:
        // Sending side: data(header, body) with fds
        // Receiving side: data(header) with fds, data(body)
        let len = master
            .send_slice(
                &buf1[..],
                Some(&[fd.as_raw_fd(), fd.as_raw_fd(), fd.as_raw_fd()]),
            )
            .unwrap();
        assert_eq!(len, 4);

        let (bytes, buf2, rfds) = slave.recv_into_buf(0x2).unwrap();
        assert_eq!(bytes, 2);
        assert_eq!(&buf1[..2], &buf2[..]);
        assert!(rfds.is_some());
        let fds = rfds.unwrap();
        {
            assert_eq!(fds.len(), 3);
            let mut file = unsafe { File::from_raw_fd(fds[1]) };
            let mut content = String::new();
            file.seek(SeekFrom::Start(0)).unwrap();
            file.read_to_string(&mut content).unwrap();
            assert_eq!(content, "test");
        }
        let (bytes, buf2, rfds) = slave.recv_into_buf(0x2).unwrap();
        assert_eq!(bytes, 2);
        assert_eq!(&buf1[2..], &buf2[..]);
        assert!(rfds.is_none());

        // Following communication pattern should not work:
        // Sending side: data(header, body) with fds
        // Receiving side: data(header), data(body) with fds
        let len = master
            .send_slice(
                &buf1[..],
                Some(&[fd.as_raw_fd(), fd.as_raw_fd(), fd.as_raw_fd()]),
            )
            .unwrap();
        assert_eq!(len, 4);

        let (bytes, buf4) = slave.recv_data(2).unwrap();
        assert_eq!(bytes, 2);
        assert_eq!(&buf1[..2], &buf4[..]);
        let (bytes, buf2, rfds) = slave.recv_into_buf(0x2).unwrap();
        assert_eq!(bytes, 2);
        assert_eq!(&buf1[2..], &buf2[..]);
        assert!(rfds.is_none());

        // Following communication pattern should work:
        // Sending side: data, data with fds
        // Receiving side: data, data with fds
        let len = master.send_slice(&buf1[..], None).unwrap();
        assert_eq!(len, 4);
        let len = master
            .send_slice(
                &buf1[..],
                Some(&[fd.as_raw_fd(), fd.as_raw_fd(), fd.as_raw_fd()]),
            )
            .unwrap();
        assert_eq!(len, 4);

        let (bytes, buf2, rfds) = slave.recv_into_buf(0x4).unwrap();
        assert_eq!(bytes, 4);
        assert_eq!(&buf1[..], &buf2[..]);
        assert!(rfds.is_none());

        let (bytes, buf2, rfds) = slave.recv_into_buf(0x2).unwrap();
        assert_eq!(bytes, 2);
        assert_eq!(&buf1[..2], &buf2[..]);
        assert!(rfds.is_some());
        let fds = rfds.unwrap();
        {
            assert_eq!(fds.len(), 3);
            let mut file = unsafe { File::from_raw_fd(fds[1]) };
            let mut content = String::new();
            file.seek(SeekFrom::Start(0)).unwrap();
            file.read_to_string(&mut content).unwrap();
            assert_eq!(content, "test");
        }
        let (bytes, buf2, rfds) = slave.recv_into_buf(0x2).unwrap();
        assert_eq!(bytes, 2);
        assert_eq!(&buf1[2..], &buf2[..]);
        assert!(rfds.is_none());

        // Following communication pattern should not work:
        // Sending side: data1, data2 with fds
        // Receiving side: data + partial of data2, left of data2 with fds
        let len = master.send_slice(&buf1[..], None).unwrap();
        assert_eq!(len, 4);
        let len = master
            .send_slice(
                &buf1[..],
                Some(&[fd.as_raw_fd(), fd.as_raw_fd(), fd.as_raw_fd()]),
            )
            .unwrap();
        assert_eq!(len, 4);

        let (bytes, _) = slave.recv_data(5).unwrap();
        assert_eq!(bytes, 5);

        let (bytes, _, rfds) = slave.recv_into_buf(0x4).unwrap();
        assert_eq!(bytes, 3);
        assert!(rfds.is_none());

        // If the target fd array is too small, extra file descriptors will get lost.
        let len = master
            .send_slice(
                &buf1[..],
                Some(&[fd.as_raw_fd(), fd.as_raw_fd(), fd.as_raw_fd()]),
            )
            .unwrap();
        assert_eq!(len, 4);

        let (bytes, _, rfds) = slave.recv_into_buf(0x4).unwrap();
        assert_eq!(bytes, 4);
        assert!(rfds.is_some());

        Endpoint::<MasterReq>::close_rfds(rfds);
        Endpoint::<MasterReq>::close_rfds(None);
    }

    #[test]
    fn send_recv() {
        let listener = Listener::new(UNIX_SOCKET_SEND, true).unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut master = Endpoint::<MasterReq>::connect(UNIX_SOCKET_SEND).unwrap();
        let sock = listener.accept().unwrap().unwrap();
        let mut slave = Endpoint::<MasterReq>::from_stream(sock);

        let mut hdr1 =
            VhostUserMsgHeader::new(MasterReq::GET_FEATURES, 0, mem::size_of::<u64>() as u32);
        hdr1.set_need_reply(true);
        let features1 = 0x1u64;
        master.send_message(&hdr1, &features1, None).unwrap();

        let mut features2 = 0u64;
        let slice = unsafe {
            slice::from_raw_parts_mut(
                (&mut features2 as *mut u64) as *mut u8,
                mem::size_of::<u64>(),
            )
        };
        let (hdr2, bytes, rfds) = slave.recv_body_into_buf(slice).unwrap();
        assert_eq!(hdr1, hdr2);
        assert_eq!(bytes, 8);
        assert_eq!(features1, features2);
        assert!(rfds.is_none());

        master.send_header(&hdr1, None).unwrap();
        let (hdr2, rfds) = slave.recv_header().unwrap();
        assert_eq!(hdr1, hdr2);
        assert!(rfds.is_none());
    }
}
