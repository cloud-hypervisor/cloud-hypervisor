// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: Apache-2.0
//

use std::ffi::CString;
use std::io;
use std::mem::{offset_of, size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr::null_mut;
use std::slice::from_raw_parts;

pub(crate) struct SeqPacketSocket(OwnedFd);

impl AsRawFd for SeqPacketSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl SeqPacketSocket {
    pub(crate) fn new() -> io::Result<Self> {
        // SAFETY: socket takes only integer arguments and returns a new owned descriptor.
        let fd = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd is a newly created socket whose ownership is transferred here.
        let socket = Self(unsafe { OwnedFd::from_raw_fd(fd) });
        socket.enable_passcred()?;
        Ok(socket)
    }

    fn enable_passcred(&self) -> io::Result<()> {
        let enabled: libc::c_int = 1;
        // SAFETY: enabled is initialized and its address and length are valid for this call.
        if unsafe {
            libc::setsockopt(
                self.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PASSCRED,
                (&enabled as *const libc::c_int).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn path_to_sock_addr(path: &Path) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
        if path.as_os_str().is_empty() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let path =
            CString::new(path.as_os_str().as_bytes()).map_err(|_| io::ErrorKind::InvalidInput)?;
        // SAFETY: an all-zero sockaddr_un is valid before initializing its fields.
        let mut address: libc::sockaddr_un = unsafe { zeroed() };
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
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

    pub(crate) fn connect(&self, path: &Path) -> io::Result<()> {
        let (address, length) = Self::path_to_sock_addr(path)?;
        // SAFETY: address is initialized and length covers its family and terminated path.
        if unsafe {
            libc::connect(
                self.as_raw_fd(),
                (&address as *const libc::sockaddr_un).cast(),
                length,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(crate) fn bind(&self, path: &Path) -> io::Result<()> {
        let (address, length) = Self::path_to_sock_addr(path)?;
        // SAFETY: address is initialized and length covers its family and terminated path.
        if unsafe {
            libc::bind(
                self.as_raw_fd(),
                (&address as *const libc::sockaddr_un).cast(),
                length,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(crate) fn listen(&self) -> io::Result<()> {
        // SAFETY: self owns a bound socket descriptor. Listen does not access process memory.
        if unsafe { libc::listen(self.as_raw_fd(), 128) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(crate) fn accept(&self) -> io::Result<Self> {
        // SAFETY: socket owns the listening descriptor. Null pointers omit the peer address.
        let fd = unsafe {
            libc::accept4(
                self.as_raw_fd(),
                null_mut(),
                null_mut(),
                libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd is a newly accepted socket whose ownership is transferred here.
        let socket = Self(unsafe { OwnedFd::from_raw_fd(fd) });
        socket.enable_passcred()?;
        Ok(socket)
    }

    pub(crate) fn send_record(&self, data: &[u8]) -> io::Result<()> {
        // SAFETY: data is readable for its entire length and the socket owns its descriptor.
        let count = unsafe {
            libc::send(
                self.as_raw_fd(),
                data.as_ptr().cast(),
                data.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        if count as usize != data.len() {
            return Err(io::ErrorKind::WriteZero.into());
        }
        Ok(())
    }

    pub(crate) fn receive_record(&self, data: &mut [u8]) -> io::Result<Option<usize>> {
        let mut control = [0usize; 160];
        let mut iov = libc::iovec {
            iov_base: data.as_mut_ptr().cast(),
            iov_len: data.len(),
        };
        let mut message: libc::msghdr = {
            // SAFETY: an all-zero msghdr is valid before assigning its buffer fields.
            let mut buf: libc::msghdr = unsafe { zeroed() };
            buf.msg_iov = &mut iov;
            buf.msg_iovlen = 1;
            buf.msg_control = control.as_mut_ptr().cast();
            buf.msg_controllen = size_of_val(&control) as _;
            buf
        };
        // SAFETY: all message buffers are initialized, writable, aligned and live for the call.
        let count = unsafe {
            libc::recvmsg(
                self.as_raw_fd(),
                &mut message,
                libc::MSG_TRUNC | libc::MSG_CMSG_CLOEXEC,
            )
        };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut credentials = false;
        let mut received_rights = false;
        // SAFETY: recvmsg initialized the ancillary headers within the aligned control buffer.
        let mut next_header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        while !next_header.is_null() {
            // SAFETY: next_header points to an initialized header within the control buffer.
            let header = unsafe { &*next_header };
            // SAFETY: the header and control buffer remain valid during traversal.
            next_header = unsafe { libc::CMSG_NXTHDR(&message, header) };
            if header.cmsg_level != libc::SOL_SOCKET {
                continue;
            }
            if header.cmsg_type == libc::SCM_CREDENTIALS {
                credentials = true;
            }
            if header.cmsg_type != libc::SCM_RIGHTS {
                continue;
            }
            received_rights = true;
            // SAFETY: CMSG_LEN computes a header size without dereferencing pointers.
            let header_length = unsafe { libc::CMSG_LEN(0) };
            let length = header.cmsg_len.saturating_sub(header_length as _) as _;
            // SAFETY: the kernel initialized the descriptor bytes within this control message.
            let descriptors = unsafe { from_raw_parts(libc::CMSG_DATA(header), length) };
            for bytes in descriptors.as_chunks::<{ size_of::<RawFd>() }>().0 {
                // SAFETY: recvmsg transferred ownership of each received file descriptor.
                drop(unsafe { OwnedFd::from_raw_fd(RawFd::from_ne_bytes(*bytes)) });
            }
        }
        if received_rights {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "File descriptor passing is not supported",
            ));
        }
        if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        if count == 0 && !credentials {
            Ok(None)
        } else {
            Ok(Some(count as usize))
        }
    }
}
