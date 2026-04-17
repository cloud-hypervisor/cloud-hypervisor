// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// Copyright (c) 2020 Ant Financial
// Copyright (c) 2026 Demi Marie Obenour
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This includes lots of code from the vhost-user crate, but generalized.

use std::ffi::c_void;
use std::fs::File;
use std::io::ErrorKind;
use std::os::fd::{AsFd, AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd};
use std::os::unix::net::UnixStream;
use std::process;

use libc::iovec;
use log::error;
use vhost::vhost_user::Error;
use vhost::vhost_user::message::{MAX_ATTACHED_FD_ENTRIES, MAX_MSG_SIZE};
use virtio_queue::{Queue, QueueT as _};
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::{
    ByteValued, Bytes as _, GuestAddress, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap,
};
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::sock_ctrl_msg::ScmSocket as _;

// SAFETY: is POD
unsafe impl ByteValued for VhostUserMsgHeader {}
#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
pub struct VhostUserMsgHeader {
    pub request: u32,
    pub flags: u32,
    pub size: u32,
}

pub type Translate<'a> = &'a mut dyn FnMut(GuestAddress, usize) -> std::io::Result<GuestAddress>;

pub enum FdRearm {
    Neither,
    Socket,
    Queue,
}

pub struct Fds<'a> {
    pub queue_in: &'a EventFd,
    pub queue_out: &'a EventFd,
    pub socket: Option<BorrowedFd<'a>>,
}

pub struct VirtioVhostUserQueuePair {
    front2back_queue: Queue,
    back2front_queue: Queue,
    front2back_queue_evt: EventFd,
    back2front_queue_evt: EventFd,
    socket: Option<UnixStream>,
    incoming_data: Vec<u8>,
    outgoing_buf: Vec<u8>,
    files_for_cycle: Vec<Option<OwnedFd>>,
    offset: usize,
    mem: GuestMemoryAtomic<GuestMemoryMmap<AtomicBitmap>>,
}

fn validate_hdr(buf: &mut [u8]) -> Result<(VhostUserMsgHeader, &mut [u8]), Error> {
    let (hdr, body) = buf.split_at_mut(size_of::<VhostUserMsgHeader>());
    let &hdr = VhostUserMsgHeader::from_slice(hdr).expect("length correct");
    let version = hdr.flags & 3;
    if version != 1 {
        error!("virtio-vhost-user: Bad version {version}");
        return Err(Error::InvalidMessage);
    }
    Ok((hdr, body))
}

impl VirtioVhostUserQueuePair {
    pub fn new(
        front2back_queue: Queue,
        back2front_queue: Queue,
        front2back_queue_evt: EventFd,
        back2front_queue_evt: EventFd,
        socket: Option<UnixStream>,
        mem: GuestMemoryAtomic<GuestMemoryMmap<AtomicBitmap>>,
    ) -> Self {
        Self {
            front2back_queue,
            back2front_queue,
            front2back_queue_evt,
            back2front_queue_evt,
            socket,
            incoming_data: Vec::new(),
            outgoing_buf: Vec::new(),
            files_for_cycle: Vec::new(),
            offset: 0,
            mem,
        }
    }

    /// Sets the file descriptor to use for the socket.
    /// Does not close the socket on success
    /// (so socket.as_raw_fd() is still a valid fd).
    pub fn set_socket(&mut self, socket: UnixStream) -> Result<(), Error> {
        if self.socket.is_some() {
            return Err(Error::InvalidMessage);
        }
        self.socket = Some(socket);
        Ok(())
    }

    pub fn fds(&self) -> Fds<'_> {
        Fds {
            queue_in: &self.front2back_queue_evt,
            queue_out: &self.back2front_queue_evt,
            socket: self.socket.as_ref().map(AsFd::as_fd),
        }
    }

    /// Send an outgoing message if possible.
    ///
    /// Returns true if a full message was successfully sent.
    ///
    /// If the function returns true, the buffer and outgoing FD queue
    /// will be empty.
    ///
    /// # Errors
    ///
    /// Fails if there is an I/O error on the socket.
    fn send_message(&mut self) -> Result<bool, Error> {
        let buf: &[u8] = &self.outgoing_buf;
        if buf.is_empty() {
            return Ok(true);
        }
        let hdr = VhostUserMsgHeader::from_slice(&buf[..size_of::<VhostUserMsgHeader>()])
            .expect("length correct");
        assert_eq!(hdr.flags & 3, 1, "bad version in outgoing message");
        assert!(hdr.size >= size_of::<VhostUserMsgHeader>() as u32);
        assert!(hdr.size <= MAX_MSG_SIZE as u32);
        assert_eq!(hdr.size as usize, buf.len());
        let buf = &buf[..self.offset];
        let Some(socket) = &self.socket else {
            error!(
                "No socket yet - did the backend place buffers on its request or reply queue without getting an FD from the frontend?"
            );
            return Err(Error::FeatureMismatch);
        };
        loop {
            // SAFETY: FFI with valid parameters
            let v = unsafe {
                libc::send(
                    socket.as_raw_fd(),
                    buf.as_ptr().cast(),
                    buf.len(),
                    libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
                )
            };
            if v == -1 {
                let e = std::io::Error::last_os_error();
                let errno = e.raw_os_error().unwrap();
                if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                    break Ok(false);
                }
                if errno != libc::EINTR {
                    break Err(Error::ReqHandlerError(e));
                }
            } else {
                let v: usize = v.try_into().unwrap();
                if v > buf.len() {
                    process::abort();
                }
                self.offset += v;
                if self.offset == buf.len() {
                    self.outgoing_buf.clear();
                    self.offset = 0;
                    break Ok(true);
                }
            }
        }
    }

    /// Send an outgoing message if possible.
    ///
    /// On success, the first element of the returned tuple indicates
    /// which file descriptors need to be polled.  The second element
    /// indicates whether the queue interrupt needs to be triggered.
    ///
    /// The callback will be called for each message sent.  It is allowed
    /// to modify the message's contents but not its header.  It can
    /// reject the message by returning an error.
    ///
    /// # Errors
    ///
    /// Fails if there is an I/O error on the socket or if the callback
    /// returns an error.
    #[allow(clippy::type_complexity)] // pulling this out leads to borrowck error
    pub(super) fn process_outgoing<'a>(
        &mut self,
        mut access_platform: Option<Translate<'a>>,
        max_messages: usize,
        process_message: &mut dyn FnMut(VhostUserMsgHeader, &mut [u8]) -> Result<(), Error>,
    ) -> Result<(FdRearm, bool), Error> {
        let mut used_descs = false;
        for _ in 0..max_messages {
            if !self.send_message()? {
                return Ok((FdRearm::Socket, used_descs));
            }
            let Some(mut desc_chain) = self
                .back2front_queue
                .pop_descriptor_chain(self.mem.memory())
            else {
                return Ok((FdRearm::Queue, used_descs));
            };
            used_descs = true;
            let Some(desc) = desc_chain.next() else {
                error!("virtio-vhost-user: descriptor chain is empty");
                return Err(Error::InvalidMessage);
            };
            let mem = desc_chain.memory();
            if desc.is_write_only() {
                error!("virito-vhost-user: descriptor is write-only");
                return Err(Error::InvalidMessage);
            }
            let desc_len = desc.len() as usize;
            if desc_len < size_of::<VhostUserMsgHeader>() {
                error!("virtio-vhost-user: descriptor too short");
                return Err(Error::InvalidMessage);
            }
            if desc_len > MAX_MSG_SIZE {
                error!("virtio-vhost-user: descriptor too long");
                return Err(Error::InvalidMessage);
            }
            self.outgoing_buf.resize(desc_len, 0);
            let mut addr = desc.addr();
            if let Some(ref mut translate) = access_platform {
                addr = translate(addr, desc_len).map_err(Error::ReqHandlerError)?;
            }
            if let Err(e) = mem.read_slice(&mut self.outgoing_buf, addr) {
                error!("virtio-vhost-user: Problem reading guest data: {e}");
                return Err(Error::InvalidMessage);
            }

            let (hdr, buf) = validate_hdr(&mut self.outgoing_buf)?;
            process_message(hdr, buf)?;
            if desc_chain.next().is_some() {
                error!("virtio-vhost-user: guest provided chained descriptors");
                return Err(Error::InvalidMessage);
            }
        }
        Ok((FdRearm::Neither, used_descs))
    }

    fn extend_buffer(&mut self, min_size: usize) -> std::io::Result<bool> {
        let Some(socket) = &self.socket else {
            error!(
                "No socket yet - did the backend place buffers on its request or reply queue without getting an FD from the frontend?"
            );
            return Err(std::io::Error::from(ErrorKind::InvalidData));
        };
        while min_size > self.incoming_data.len() {
            let extra_space = min_size - self.incoming_data.len();
            self.incoming_data.reserve(extra_space);
            let ptr: *mut c_void = self.incoming_data.as_mut_ptr().cast();
            // SAFETY: current_len points to before the end of the vec's capacity,
            // as at least one byte was reserved after it.
            let ptr = unsafe { ptr.add(self.incoming_data.len()) };
            let mut iov = [iovec {
                iov_base: ptr,
                iov_len: extra_space,
            }];

            let mut fd_array = vec![-1; MAX_ATTACHED_FD_ENTRIES];

            // SAFETY: anything can be written into unallocated capacity of a Vec<u8>
            let recv_res = unsafe { socket.recv_with_fds(&mut iov[..], &mut fd_array) };
            let (len, num_fds) = match recv_res {
                Ok(e) => e,
                Err(e) => match e.errno() {
                    libc::EAGAIN => return Ok(false),
                    libc::EINTR => continue,
                    e => return Err(std::io::Error::from_raw_os_error(e)),
                },
            };

            assert!(len <= extra_space);
            // SAFETY: the extra space has been reserved,
            // has been initialized by the kernel, and does
            // not exceed the spare capacity.
            unsafe {
                self.incoming_data.set_len(self.incoming_data.len() + len);
            }

            for &fd in fd_array.iter().take(num_fds) {
                assert!(fd >= 0);
                // SAFETY: we have the ownership of `fd`.
                let fd = unsafe { File::from_raw_fd(fd) };
                self.files_for_cycle.push(Some(fd.into()));
            }
        }
        Ok(true)
    }

    /// Process incoming data on the vhost-user socket.
    ///
    /// Returns true if a full message was received, or false if
    /// all data has been consumed.  In the latter case, if
    /// edge-triggered file descriptor watching is used, the watch
    /// must be re-armed.
    ///
    /// # Errors
    ///
    /// Returns an error if the callback returns an error or an
    /// invalid message was received.
    fn socket_rx(&mut self) -> Result<bool, Error> {
        let min_size = size_of::<VhostUserMsgHeader>();
        // TODO: better error
        if !self.extend_buffer(min_size).map_err(Error::SocketError)? {
            return Ok(false);
        }
        let msg_size = validate_hdr(&mut self.incoming_data)?.0.size;
        if msg_size > MAX_MSG_SIZE.try_into().unwrap() {
            error!("Bad message from frontend: size is {msg_size} (limit {MAX_MSG_SIZE})");
            return Err(Error::InvalidMessage);
        }
        self.extend_buffer(msg_size as usize)
            .map_err(Error::SocketError)
    }

    /// Process an incoming message from the frontend if possible.
    ///
    /// The callback will be invoked for each such message.
    /// The file descriptor slice provided will only contain `Some`
    /// entries, but the callback is free to consume them (replace them
    /// with `None`).  File descriptors not consumed will be lost.
    ///
    /// Returns `Ok(true)` if a message was processed and `Ok(false)`
    /// if there was no message processed.
    ///
    /// # Errors
    ///
    /// Returns an error if the callback returns an error or an
    /// invalid message was received.
    #[allow(clippy::type_complexity)] // pulling this out leads to borrowck error
    pub(super) fn process_incoming<'a>(
        &mut self,
        mut access_platform: Option<Translate<'a>>,
        max_messages: usize,
        process_message: &mut dyn FnMut(
            VhostUserMsgHeader,
            &mut [u8],
            &mut [Option<OwnedFd>],
        ) -> Result<(), Error>,
    ) -> Result<(FdRearm, bool), Error> {
        let mut used_descs = false;
        for _ in 0..max_messages {
            if !self.socket_rx()? {
                return Ok((FdRearm::Socket, used_descs));
            }
            let Some(mut desc_chain) = self
                .front2back_queue
                .pop_descriptor_chain(self.mem.memory())
            else {
                return Ok((FdRearm::Queue, used_descs));
            };

            let desc = match desc_chain.next() {
                Some(desc) => desc,
                None => return Err(Error::InvalidParam),
            };

            if !desc.is_write_only() {
                // TODO: better error
                return Err(Error::InvalidParam);
            }

            let desc_len = usize::try_from(desc.len()).unwrap();
            if desc_len < self.incoming_data.len() {
                error!("Vhost-user incoming buffer too small!");
                return Err(Error::InvalidParam);
            }
            let (hdr, body) = self
                .incoming_data
                .split_at_mut(size_of::<VhostUserMsgHeader>());
            let &hdr = VhostUserMsgHeader::from_slice(hdr).unwrap();

            used_descs = true;
            let mem = desc_chain.memory();
            let mut addr = desc.addr();
            if let Some(ref mut translate) = access_platform {
                addr = translate(addr, desc_len).map_err(Error::ReqHandlerError)?;
            }
            process_message(hdr, body, &mut self.files_for_cycle)?;
            if let Err(e) = mem.write_slice(&self.incoming_data, addr) {
                error!("virtio-vhost-user: Problem writing guest data: {e}");
                return Err(Error::InvalidMessage);
            }
        }
        Ok((FdRearm::Neither, used_descs))
    }
}
