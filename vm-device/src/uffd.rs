// Copyright © 2026 Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0

//! Transport-independent actions for an external userfaultfd backend.

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::{iter, thread};

use sendfd::{RecvWithFd, SendWithFd};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmaRegion {
    pub virt_addr: u64,
    pub size: u64,
    pub offset: u64,
    pub fault_size: u64,
    pub prot: i32,
    pub flags: i32,
    pub backing_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobRange {
    pub device_offset: u64,
    pub blob_offset: u64,
    pub len: u64,
}

pub enum Request<'a> {
    Handshake {
        uffd: RawFd,
        register_mode: u64,
        features: u64,
        regions: &'a [VmaRegion],
        backing_fds: &'a [RawFd],
        managed: bool,
    },
    AddRegion {
        region: &'a VmaRegion,
        backing_fd: Option<RawFd>,
    },
    RemoveRegion {
        host_addr: u64,
        len: u64,
    },
}

#[derive(Debug)]
pub enum Response {
    Ack,
    FdRanges {
        more: bool,
        ranges: Vec<BlobRange>,
        fds: Vec<OwnedFd>,
    },
}

pub trait Transport: Send + Sync {
    fn send_request(&self, sock: &UnixStream, request: &Request<'_>) -> io::Result<()>;

    fn recv_response(&self, sock: &UnixStream, nonblocking: bool) -> io::Result<Option<Response>>;
}

pub struct UffdBlock {
    sock: UnixStream,
    transport: Box<dyn Transport>,
    managed: bool,
}

impl UffdBlock {
    pub fn new(sock_path: impl AsRef<Path>, managed: bool) -> io::Result<Self> {
        Self::new_with_transport(sock_path, managed, BinaryTransport)
    }

    pub fn new_with_transport<T: Transport + 'static>(
        sock_path: impl AsRef<Path>,
        managed: bool,
        transport: T,
    ) -> io::Result<Self> {
        Ok(Self {
            sock: UnixStream::connect(sock_path)?,
            transport: Box::new(transport),
            managed,
        })
    }

    pub fn handshake(
        &self,
        uffd: RawFd,
        register_mode: u64,
        features: u64,
        regions: &[VmaRegion],
        backing_fds: &[RawFd],
    ) -> io::Result<()> {
        self.send_and_ack(&Request::Handshake {
            uffd,
            register_mode,
            features,
            regions,
            backing_fds,
            managed: self.managed,
        })?;
        self.sock.set_nonblocking(!self.managed)
    }

    pub fn recv_response(&self) -> io::Result<Option<Response>> {
        self.transport.recv_response(&self.sock, true)
    }

    pub fn add_region(&self, region: &VmaRegion, backing_fd: Option<RawFd>) -> io::Result<()> {
        self.send_and_ack(&Request::AddRegion { region, backing_fd })
    }

    pub fn remove_region(&self, host_addr: u64, len: u64) -> io::Result<()> {
        self.send_and_ack(&Request::RemoveRegion { host_addr, len })
    }

    pub fn socket_fd(&self) -> RawFd {
        self.sock.as_raw_fd()
    }

    fn send_and_ack(&self, request: &Request<'_>) -> io::Result<()> {
        self.transport.send_request(&self.sock, request)?;
        match self
            .transport
            .recv_response(&self.sock, false)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::WouldBlock, "Response is not available"))?
        {
            Response::Ack => Ok(()),
            Response::FdRanges { .. } => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Expected acknowledgement response",
            )),
        }
    }
}

// Binary transport

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct BinaryTransport;

const COMMAND_HANDSHAKE: u16 = 0x0a;
const COMMAND_ADD_REGION: u16 = 0x0b;
const COMMAND_REMOVE_REGION: u16 = 0x0c;
const PROTOCOL_VERSION: u16 = 1;

const HANDSHAKE_FLAG_MANAGED: u8 = 1 << 0;
const HANDSHAKE_FLAG_ACK_REQUIRED: u8 = 1 << 2;
const HANDSHAKE_FLAG_BACKING_FDS: u8 = 1 << 3;
const UFFD_MODE_MISSING: u8 = 1 << 0;
const UFFD_MODE_WP: u8 = 1 << 1;
const UFFD_MODE_WP_ASYNC: u8 = 1 << 2;
const UFFDIO_REGISTER_MODE_MISSING: u64 = 1 << 0;
const UFFDIO_REGISTER_MODE_WP: u64 = 1 << 1;
const UFFD_FEATURE_WP_ASYNC: u64 = 1 << 15;

const STATUS_OK: u16 = 1;
const REPLY_ACK: u16 = 0;
const REPLY_FD_RANGES: u16 = 1;
const FD_RANGES_FLAG_MORE: u16 = 1 << 0;

const HEADER_SIZE: usize = 16;
const REGION_SIZE: usize = 48;
const REMOVE_REGION_SIZE: usize = 16;
const RANGE_SIZE: usize = 24;
const MAX_RECV_FDS: usize = 64;

impl Transport for BinaryTransport {
    fn send_request(&self, sock: &UnixStream, request: &Request<'_>) -> io::Result<()> {
        let (message, fds) = encode_request(request);
        if fds.is_empty() {
            (&*sock).write_all(&message)
        } else {
            sock.send_with_fd(&message, &fds)?;
            Ok(())
        }
    }

    fn recv_response(&self, sock: &UnixStream, nonblocking: bool) -> io::Result<Option<Response>> {
        let Some((header, fds)) = recv_header(sock, nonblocking)? else {
            return Ok(None);
        };
        let status = u16::from_le_bytes(header[0..2].try_into().unwrap());
        let reply_type = u16::from_le_bytes(header[2..4].try_into().unwrap());
        let reply_headers = &header[4..8];
        let len = u64::from_le_bytes(header[8..16].try_into().unwrap());
        if status != STATUS_OK {
            return Err(io::Error::other("External UFFD server returned an error"));
        }

        match reply_type {
            REPLY_ACK if len == 0 && fds.is_empty() => Ok(Some(Response::Ack)),
            REPLY_ACK => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Acknowledgement carries data",
            )),
            REPLY_FD_RANGES => {
                let mut payload = vec![0; len as usize];
                recv_exact(sock, &mut payload, nonblocking)?;
                let ranges = decode_ranges(&payload)?;
                let fd_count = u16::from_le_bytes(reply_headers[2..4].try_into().unwrap());
                if ranges.len() != usize::from(fd_count) || ranges.len() != fds.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "FdRanges count does not match attached file descriptors",
                    ));
                }
                let flags = u16::from_le_bytes(reply_headers[0..2].try_into().unwrap());
                Ok(Some(Response::FdRanges {
                    more: flags & FD_RANGES_FLAG_MORE != 0,
                    ranges,
                    fds,
                }))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unexpected reply type 0x{reply_type:04x}"),
            )),
        }
    }
}

fn encode_request(request: &Request<'_>) -> (Vec<u8>, Vec<RawFd>) {
    match request {
        Request::Handshake {
            uffd,
            register_mode,
            features,
            regions,
            backing_fds,
            managed,
        } => {
            let mut flags = HANDSHAKE_FLAG_ACK_REQUIRED;
            if *managed {
                flags |= HANDSHAKE_FLAG_MANAGED;
            }
            if !backing_fds.is_empty() {
                flags |= HANDSHAKE_FLAG_BACKING_FDS;
            }
            let mut headers = [0; 6];
            headers[0..2].copy_from_slice(&PROTOCOL_VERSION.to_le_bytes());
            headers[2] = flags;
            headers[3] = encode_uffd_modes(*register_mode, *features);
            headers[4..6].copy_from_slice(&(regions.len() as u16).to_le_bytes());

            let mut message =
                encode_header(COMMAND_HANDSHAKE, headers, regions.len() * REGION_SIZE);
            for region in *regions {
                encode_region(&mut message, region);
            }
            let fds = iter::once(*uffd)
                .chain(backing_fds.iter().copied())
                .collect();
            (message, fds)
        }
        Request::AddRegion { region, backing_fd } => {
            let mut message = encode_header(COMMAND_ADD_REGION, [0; 6], REGION_SIZE);
            encode_region(&mut message, region);
            (message, backing_fd.iter().copied().collect())
        }
        Request::RemoveRegion { host_addr, len } => {
            let mut message = encode_header(COMMAND_REMOVE_REGION, [0; 6], REMOVE_REGION_SIZE);
            message.extend_from_slice(&host_addr.to_le_bytes());
            message.extend_from_slice(&len.to_le_bytes());
            (message, Vec::new())
        }
    }
}

fn encode_header(command: u16, headers: [u8; 6], payload_len: usize) -> Vec<u8> {
    let mut message = Vec::with_capacity(HEADER_SIZE + payload_len);
    message.extend_from_slice(&command.to_le_bytes());
    message.extend_from_slice(&headers);
    message.extend_from_slice(&(payload_len as u64).to_le_bytes());
    message
}

fn encode_uffd_modes(register_mode: u64, features: u64) -> u8 {
    let mut modes = 0;
    if register_mode & UFFDIO_REGISTER_MODE_MISSING != 0 {
        modes |= UFFD_MODE_MISSING;
    }
    if register_mode & UFFDIO_REGISTER_MODE_WP != 0 {
        modes |= UFFD_MODE_WP;
        if features & UFFD_FEATURE_WP_ASYNC != 0 {
            modes |= UFFD_MODE_WP_ASYNC;
        }
    }
    modes
}

fn encode_region(message: &mut Vec<u8>, region: &VmaRegion) {
    message.extend_from_slice(&region.virt_addr.to_le_bytes());
    message.extend_from_slice(&region.size.to_le_bytes());
    message.extend_from_slice(&region.offset.to_le_bytes());
    message.extend_from_slice(&region.fault_size.to_le_bytes());
    message.extend_from_slice(&region.prot.to_le_bytes());
    message.extend_from_slice(&region.flags.to_le_bytes());
    message.extend_from_slice(&region.backing_offset.to_le_bytes());
}

fn decode_ranges(payload: &[u8]) -> io::Result<Vec<BlobRange>> {
    let (entries, remainder) = payload.as_chunks::<RANGE_SIZE>();
    if !remainder.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid FdRanges payload",
        ));
    }
    Ok(entries
        .iter()
        .map(|entry| BlobRange {
            device_offset: u64::from_le_bytes(entry[0..8].try_into().unwrap()),
            blob_offset: u64::from_le_bytes(entry[8..16].try_into().unwrap()),
            len: u64::from_le_bytes(entry[16..24].try_into().unwrap()),
        })
        .collect())
}

fn recv_header(
    sock: &UnixStream,
    nonblocking: bool,
) -> io::Result<Option<([u8; HEADER_SIZE], Vec<OwnedFd>)>> {
    let mut header = [0; HEADER_SIZE];
    let mut raw_fds = [0; MAX_RECV_FDS];
    let (read, fd_count) = match sock.recv_with_fd(&mut header, &mut raw_fds) {
        Ok(value) => value,
        Err(error) if nonblocking && error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
        Err(error) => return Err(error),
    };
    if read == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "External UFFD server closed the socket",
        ));
    }
    let fds = raw_fds[..fd_count]
        .iter()
        // SAFETY: recv_with_fd returned each descriptor with ownership.
        .map(|fd| unsafe { OwnedFd::from_raw_fd(*fd) })
        .collect();
    recv_exact(sock, &mut header[read..], nonblocking)?;
    Ok(Some((header, fds)))
}

fn recv_exact(sock: &UnixStream, buf: &mut [u8], nonblocking: bool) -> io::Result<()> {
    let mut offset = 0;
    while offset < buf.len() {
        match (&*sock).read(&mut buf[offset..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "External UFFD server closed while reading a response",
                ));
            }
            Ok(count) => offset += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if nonblocking && error.kind() == io::ErrorKind::WouldBlock => {
                thread::yield_now();
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
