// Copyright (C) 2026 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! UFFD block backend for on-demand page fault handling via an external server.
//!
//! Supports zero-copy: the server responds with blob fds that are MAP_FIXED directly
//! over the faulting region, avoiding any data copy into guest memory.
//!
//! For servers that do not support this protocol, the socket simply receives
//! no messages and the event handler becomes a no-op with no overhead.

use std::fs::File;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::FileExt;
use std::os::unix::net::UnixStream;
use std::{fmt, io};

use libc::MAP_FAILED;
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

use crate::uffd;

/// Message type enum for UFFD protocol.
#[derive(Debug, Clone, Copy, Default, Serialize_repr, Deserialize_repr, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    /// Handshake message.
    #[default]
    Handshake = 0,
    /// Page fault notification.
    PageFault = 1,
}

/// Fault handling policy for UFFD.
#[derive(Debug, Clone, Copy, Default, Serialize_repr, Deserialize_repr, PartialEq, Eq)]
#[repr(u8)]
pub enum FaultPolicy {
    /// Zero-copy mode: send fd to client, let client do mmap.
    #[default]
    Zerocopy = 0,
    /// Copy mode: use UFFDIO_COPY to copy data directly.
    Copy = 1,
}

/// VMA region information for userfaultfd registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmaRegion {
    /// Base host virtual address of this region.
    pub base_host_virt_addr: u64,
    /// Size of the region in bytes.
    pub size: usize,
    /// Offset in the backend.
    pub offset: u64,
    /// Page size for this region.
    pub page_size: usize,
    /// Page size in KiB (legacy, defaults to 0).
    #[serde(default)]
    pub page_size_kib: usize,
    /// Memory protection flags (defaults to `PROT_READ`).
    #[serde(default = "default_prot")]
    pub prot: i32,
    /// Mmap flags (defaults to `MAP_PRIVATE`).
    /// Note: `MAP_FIXED` is added by the handler when doing mmap.
    #[serde(default = "default_flags")]
    pub flags: i32,
}

fn default_prot() -> i32 {
    libc::PROT_READ
}

fn default_flags() -> i32 {
    libc::MAP_PRIVATE
}

impl Default for VmaRegion {
    fn default() -> Self {
        Self {
            base_host_virt_addr: 0,
            size: 0,
            offset: 0,
            page_size: 4096,
            page_size_kib: 0,
            prot: default_prot(),
            flags: default_flags(),
        }
    }
}

/// Handshake request to the UFFD server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeRequest {
    /// Message type (defaults to Handshake).
    #[serde(default)]
    pub r#type: MessageType,
    /// VMA regions to register.
    pub regions: Vec<VmaRegion>,
    /// Fault handling policy (defaults to Zerocopy).
    #[serde(default)]
    pub policy: FaultPolicy,
}

/// Page fault response from the UFFD server.
#[derive(Debug, Serialize, Deserialize)]
pub struct PageFaultResponse {
    pub ranges: Vec<BlobRange>,
}

/// A single range within a page fault response.
#[derive(Debug, Serialize, Deserialize)]
pub struct BlobRange {
    pub len: usize,
    pub blob_offset: u64,
    pub block_offset: u64,
}

const RECV_BUF_SIZE: usize = 4096;
const MAX_FDS: usize = 16;

/// Inline UFFD block backend that connects to an external UFFD server via
/// Unix socket for zero-copy on-demand page resolution and fault recovery.
///
/// Two-phase initialization:
/// 1. `UffdBlock::new(sock_path, policy)` — connects to the server.
/// 2. `block.handshake(uffd_fd, regions)` — performs protocol handshake.
pub struct UffdBlock {
    sock_path: String,
    sock: UnixStream,
    policy: FaultPolicy,
    uffd_fd: Option<OwnedFd>,
    regions: Vec<VmaRegion>,
}

impl fmt::Debug for UffdBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UffdBlock")
            .field("sock_path", &self.sock_path)
            .field("sock_fd", &self.sock.as_raw_fd())
            .field("policy", &self.policy)
            .field("uffd_fd", &self.uffd_fd.as_ref().map(|fd| fd.as_raw_fd()))
            .field("regions", &self.regions)
            .finish()
    }
}

impl UffdBlock {
    /// Create a new UffdBlock, connecting to the server at `sock_path`.
    /// Call [`handshake`] to complete initialization.
    pub fn new(sock_path: &str, policy: FaultPolicy) -> io::Result<Self> {
        let sock = UnixStream::connect(sock_path)?;
        Ok(Self {
            sock_path: sock_path.to_string(),
            sock,
            policy,
            uffd_fd: None,
            regions: Vec::new(),
        })
    }

    /// Perform a formal protocol handshake with the UFFD server.
    pub fn handshake(&mut self, uffd_fd: OwnedFd, regions: Vec<VmaRegion>) -> io::Result<()> {
        let request = HandshakeRequest {
            r#type: MessageType::Handshake,
            regions: regions.clone(),
            policy: self.policy,
        };
        let json_data = serde_json::to_string(&request)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        self.sock
            .send_with_fd(json_data.as_bytes(), uffd_fd.as_raw_fd())?;
        self.sock.set_nonblocking(true)?;

        self.uffd_fd = Some(uffd_fd);
        self.regions = regions;
        Ok(())
    }

    /// Handle a page fault response by mmapping blob fds in a zero-copy manner.
    pub fn handle_response(&self) -> io::Result<bool> {
        let mut data = [0u8; RECV_BUF_SIZE];
        let mut fds = [0i32; MAX_FDS];

        let iov = libc::iovec {
            iov_base: data.as_mut_ptr().cast(),
            iov_len: data.len(),
        };
        // SAFETY: iov points to a valid buffer, fds is a valid slice for receiving fds.
        let (bytes_read, fd_count) = unsafe { self.sock.recv_with_fds(&mut [iov], &mut fds) }
            .map_err(|e| io::Error::from_raw_os_error(e.errno()))?;

        // Take ownership of received fds so they are closed on any early return.
        // SAFETY: fds[0..fd_count] contain valid file descriptors received via sendfd.
        let received_fds: Vec<File> = fds[..fd_count]
            .iter()
            .map(|&fd| unsafe { File::from_raw_fd(fd) })
            .collect();

        if bytes_read == 0 {
            // connection closed
            return Ok(false);
        }

        let json_str = std::str::from_utf8(&data[..bytes_read])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let response: PageFaultResponse = serde_json::from_str(json_str)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        if received_fds.len() != response.ranges.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "fd count {} != ranges count {}",
                    received_fds.len(),
                    response.ranges.len()
                ),
            ));
        }

        for (range, file) in response.ranges.iter().zip(received_fds.iter()) {
            let region = self.regions.iter().find(|r| {
                range.block_offset >= r.offset && range.block_offset < r.offset + r.size as u64
            });
            let region = match region {
                Some(r) => r,
                None => {
                    let block_offset = range.block_offset;
                    warn!("UffdBlock: block_offset 0x{block_offset:x} not in any region");
                    continue;
                }
            };

            let target_addr = region.base_host_virt_addr + (range.block_offset - region.offset);
            // SAFETY: We are calling mmap with a valid fd and checking the result.
            let map_addr = unsafe {
                libc::mmap(
                    target_addr as *mut _,
                    range.len,
                    region.prot,
                    region.flags | libc::MAP_FIXED,
                    file.as_raw_fd(),
                    range.blob_offset as i64,
                )
            };
            if map_addr == MAP_FAILED {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ENOMEM) {
                    warn!("UffdBlock: mmap ENOMEM at 0x{target_addr:x}, fallback to uffd copy");
                    self.copy_fallback(file, target_addr, range.len, range.blob_offset)?;
                } else {
                    warn!("UffdBlock: mmap failed for 0x{target_addr:x}: {err}");
                }
                continue;
            }

            if let Err(e) = uffd::wake(self.uffd_fd(), target_addr, range.len as u64) {
                warn!("UffdBlock: failed to wake page at 0x{target_addr:x}: {e}");
            }
        }

        Ok(true)
    }

    /// Fallback when mmap hits vm.max_map_count: read from blob fd, then UFFDIO_COPY.
    ///
    /// NOTE: This uses an intermediate buffer + UFFDIO_COPY for Linux 5.10 compatibility.
    /// UFFDIO_CONTINUE (zero-copy: pread directly into guest memory + continue) requires
    /// Linux 5.13+. When all deployments upgrade to 5.13+, this can be optimized to:
    ///   1. pread() directly into target_addr (guest memory)
    ///   2. uffd_continue(target_addr, len) to resolve the fault
    ///
    /// Since this is a fallback path (triggered only when mmap hits vm.max_map_count),
    /// the extra copy is acceptable for now.
    fn copy_fallback(
        &self,
        file: &File,
        target_addr: u64,
        len: usize,
        blob_offset: u64,
    ) -> io::Result<()> {
        let mut buf = vec![0u8; len];
        file.read_at(&mut buf, blob_offset)?;

        match uffd::copy(self.uffd_fd(), target_addr, buf.as_ptr(), len as u64) {
            Ok(()) => Ok(()),
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                if let Err(e) = uffd::wake(self.uffd_fd(), target_addr, len as u64) {
                    warn!("UffdBlock: failed to wake page at 0x{target_addr:x}: {e}");
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Returns the raw file descriptor of the underlying Unix socket.
    pub fn sock_fd(&self) -> RawFd {
        self.sock.as_raw_fd()
    }

    fn uffd_fd(&self) -> BorrowedFd<'_> {
        self.uffd_fd.as_ref().expect("handshake not called").as_fd()
    }
}

/// Shared epoll loop for zero-copy UFFD handling.
///
/// Watches `stop_event` and the UffdBlock socket fd; dispatches incoming
/// `PageFaultResponse` messages until stopped or the connection closes.
/// Log messages use the current thread name as prefix.
///
/// Signals readiness via `ready_tx` after epoll setup succeeds.
pub fn uffd_handler_loop(
    uffd_block: &UffdBlock,
    stop_event: &EventFd,
    ready_tx: &std::sync::mpsc::SyncSender<()>,
) -> io::Result<()> {
    let label = std::thread::current()
        .name()
        .unwrap_or("uffd-handler")
        .to_owned();
    let sock_fd = uffd_block.sock_fd();

    const EVENT_STOP: u64 = 0;
    const EVENT_SOCK: u64 = 1;

    let epoll_fd = epoll::create(true).map_err(io::Error::other)?;
    // SAFETY: epoll_fd is valid and owned by this scope.
    let _epoll_file = unsafe { File::from_raw_fd(epoll_fd) };

    epoll::ctl(
        epoll_fd,
        epoll::ControlOptions::EPOLL_CTL_ADD,
        stop_event.as_raw_fd(),
        epoll::Event::new(epoll::Events::EPOLLIN, EVENT_STOP),
    )
    .map_err(io::Error::other)?;

    epoll::ctl(
        epoll_fd,
        epoll::ControlOptions::EPOLL_CTL_ADD,
        sock_fd,
        epoll::Event::new(epoll::Events::EPOLLIN, EVENT_SOCK),
    )
    .map_err(io::Error::other)?;

    ready_tx.send(()).ok();

    let mut events = vec![epoll::Event::new(epoll::Events::empty(), 0); 2];
    loop {
        let num_events = match epoll::wait(epoll_fd, -1, &mut events) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };

        for event in events.iter().take(num_events) {
            if event.data == EVENT_STOP {
                stop_event.read().ok();
                info!("{label}: stop event received");
                return Ok(());
            }
            if event.data == EVENT_SOCK {
                loop {
                    match uffd_block.handle_response() {
                        Ok(true) => {}
                        Ok(false) => {
                            info!("{label}: connection closed");
                            return Ok(());
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => {
                            error!("{label}: error: {e}");
                            return Err(e);
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;

    use vmm_sys_util::sock_ctrl_msg::ScmSocket;
    use vmm_sys_util::tempdir::TempDir;

    use super::*;

    fn test_vma_regions() -> Vec<VmaRegion> {
        vec![
            VmaRegion {
                base_host_virt_addr: 0x7f0000000000,
                size: 0x100000,
                offset: 0,
                page_size: 4096,
                page_size_kib: 4,
                prot: libc::PROT_READ | libc::PROT_WRITE,
                flags: libc::MAP_PRIVATE,
            },
            VmaRegion {
                base_host_virt_addr: 0x7f0000100000,
                size: 0x200000,
                offset: 0x100000,
                page_size: 4096,
                page_size_kib: 4,
                prot: libc::PROT_READ,
                flags: libc::MAP_SHARED,
            },
        ]
    }

    // ─── MessageType / FaultPolicy serialization ──────────────────────────────

    #[test]
    fn test_message_type_serde_repr() {
        assert_eq!(MessageType::Handshake as u8, 0);
        assert_eq!(MessageType::PageFault as u8, 1);

        let json = serde_json::to_string(&MessageType::PageFault).unwrap();
        assert_eq!(json, "1");

        let v: MessageType = serde_json::from_str("0").unwrap();
        assert_eq!(v, MessageType::Handshake);
        let v: MessageType = serde_json::from_str("1").unwrap();
        assert_eq!(v, MessageType::PageFault);
    }

    #[test]
    fn test_fault_policy_serde_repr() {
        assert_eq!(FaultPolicy::Zerocopy as u8, 0);
        assert_eq!(FaultPolicy::Copy as u8, 1);

        let json = serde_json::to_string(&FaultPolicy::Copy).unwrap();
        assert_eq!(json, "1");

        let v: FaultPolicy = serde_json::from_str("0").unwrap();
        assert_eq!(v, FaultPolicy::Zerocopy);
        let v: FaultPolicy = serde_json::from_str("1").unwrap();
        assert_eq!(v, FaultPolicy::Copy);
    }

    #[test]
    fn test_fault_policy_default() {
        assert_eq!(FaultPolicy::default(), FaultPolicy::Zerocopy);
    }

    #[test]
    fn test_message_type_default() {
        assert_eq!(MessageType::default(), MessageType::Handshake);
    }

    // ─── VmaRegion serialization ──────────────────────────────────────────────

    #[test]
    fn test_vma_region_defaults() {
        let json = r#"{"base_host_virt_addr":100,"size":4096,"offset":0,"page_size":4096}"#;
        let r: VmaRegion = serde_json::from_str(json).unwrap();
        assert_eq!(r.base_host_virt_addr, 100);
        assert_eq!(r.size, 4096);
        assert_eq!(r.page_size_kib, 0);
        assert_eq!(r.prot, libc::PROT_READ);
        assert_eq!(r.flags, libc::MAP_PRIVATE);
    }

    #[test]
    fn test_vma_region_default_trait() {
        let r = VmaRegion::default();
        assert_eq!(r.base_host_virt_addr, 0);
        assert_eq!(r.size, 0);
        assert_eq!(r.offset, 0);
        assert_eq!(r.page_size, 4096);
        assert_eq!(r.page_size_kib, 0);
        assert_eq!(r.prot, libc::PROT_READ);
        assert_eq!(r.flags, libc::MAP_PRIVATE);
    }

    #[test]
    fn test_vma_region_explicit() {
        let r = VmaRegion {
            base_host_virt_addr: 0x1000,
            size: 0x2000,
            offset: 0x100,
            page_size: 2097152,
            page_size_kib: 2048,
            prot: libc::PROT_READ | libc::PROT_WRITE,
            flags: libc::MAP_SHARED,
        };
        let json = serde_json::to_string(&r).unwrap();
        let r2: VmaRegion = serde_json::from_str(&json).unwrap();
        assert_eq!(r2.base_host_virt_addr, 0x1000);
        assert_eq!(r2.size, 0x2000);
        assert_eq!(r2.offset, 0x100);
        assert_eq!(r2.page_size, 2097152);
        assert_eq!(r2.page_size_kib, 2048);
        assert_eq!(r2.prot, libc::PROT_READ | libc::PROT_WRITE);
        assert_eq!(r2.flags, libc::MAP_SHARED);
    }

    #[test]
    fn test_vma_region_default_flags_is_map_private() {
        assert_eq!(default_flags(), libc::MAP_PRIVATE);
    }

    #[test]
    fn test_vma_region_default_prot_is_prot_read() {
        assert_eq!(default_prot(), libc::PROT_READ);
    }

    // ─── HandshakeRequest serialization ───────────────────────────────────────

    #[test]
    fn test_handshake_request_serde() {
        let req = HandshakeRequest {
            r#type: MessageType::Handshake,
            regions: test_vma_regions(),
            policy: FaultPolicy::Zerocopy,
        };
        let json = serde_json::to_string(&req).unwrap();
        let req2: HandshakeRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req2.r#type, MessageType::Handshake);
        assert_eq!(req2.policy, FaultPolicy::Zerocopy);
        assert_eq!(req2.regions.len(), 2);
        assert_eq!(req2.regions[0].base_host_virt_addr, 0x7f0000000000);
        assert_eq!(req2.regions[1].size, 0x200000);
    }

    #[test]
    fn test_handshake_request_defaults() {
        let json = r#"{"regions":[]}"#;
        let req: HandshakeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.r#type, MessageType::Handshake);
        assert_eq!(req.policy, FaultPolicy::Zerocopy);
        assert!(req.regions.is_empty());
    }

    // ─── PageFaultResponse deserialization ────────────────────────────────────

    #[test]
    fn test_page_fault_response_deser() {
        let json = r#"{"ranges":[{"len":4096,"blob_offset":0,"block_offset":0}]}"#;
        let resp: PageFaultResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.ranges.len(), 1);
        assert_eq!(resp.ranges[0].len, 4096);
        assert_eq!(resp.ranges[0].blob_offset, 0);
        assert_eq!(resp.ranges[0].block_offset, 0);
    }

    #[test]
    fn test_page_fault_response_multiple_ranges() {
        let json = r#"{"ranges":[
            {"len":4096,"blob_offset":0,"block_offset":0},
            {"len":8192,"blob_offset":4096,"block_offset":4096}
        ]}"#;
        let resp: PageFaultResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.ranges.len(), 2);
        assert_eq!(resp.ranges[1].len, 8192);
        assert_eq!(resp.ranges[1].blob_offset, 4096);
        assert_eq!(resp.ranges[1].block_offset, 4096);
    }

    // ─── UffdBlock new + handshake ────────────────────────────────────────────

    #[test]
    fn test_uffd_block_new_connection_error() {
        let result = UffdBlock::new("/tmp/nonexistent_uffd_test.sock", FaultPolicy::Zerocopy);
        result.unwrap_err();
    }

    #[test]
    fn test_uffd_block_new_and_handshake() {
        let tmp_dir = TempDir::new().unwrap();
        let sock_path = tmp_dir.as_path().join("test.sock");
        let sock_path_str = sock_path.to_str().unwrap().to_string();

        let listener = UnixListener::bind(&sock_path).unwrap();
        let regions = test_vma_regions();

        // Use an eventfd as a stand-in for the uffd fd — any valid fd works
        // since it's just sent via SCM_RIGHTS during handshake.
        // SAFETY: eventfd(0, 0) returns a valid fd on success; File::from_raw_fd takes ownership.
        let uffd_fd = OwnedFd::from(unsafe { File::from_raw_fd(libc::eventfd(0, 0)) });
        let uffd_raw = uffd_fd.as_raw_fd();

        let mut block = UffdBlock::new(&sock_path_str, FaultPolicy::Zerocopy).unwrap();

        let client_thread = std::thread::spawn(move || {
            block.handshake(uffd_fd, regions.clone()).unwrap();
            (block, regions)
        });

        // Server side: accept and verify handshake
        let (stream, _) = listener.accept().unwrap();
        let mut buf = vec![0u8; 4096];
        let (bytes_read, file) = stream.recv_with_fd(&mut buf).unwrap();
        buf.truncate(bytes_read);

        let received: HandshakeRequest =
            serde_json::from_slice(&buf).expect("Invalid JSON from handshake");
        assert_eq!(received.r#type, MessageType::Handshake);
        assert_eq!(received.regions.len(), 2);
        assert_eq!(received.regions[0].base_host_virt_addr, 0x7f0000000000);
        assert_eq!(received.regions[0].prot, libc::PROT_READ | libc::PROT_WRITE);
        assert_eq!(received.regions[0].flags, libc::MAP_PRIVATE);
        assert_eq!(received.regions[1].flags, libc::MAP_SHARED);
        assert_eq!(received.policy, FaultPolicy::Zerocopy);

        // Verify we received a file descriptor via SCM_RIGHTS
        assert!(file.is_some());

        let (block, regions) = client_thread.join().unwrap();
        assert_eq!(block.sock_path, sock_path_str);
        assert_eq!(block.uffd_fd.as_ref().unwrap().as_raw_fd(), uffd_raw);
        assert_eq!(block.regions.len(), regions.len());
        assert_eq!(block.policy, FaultPolicy::Zerocopy);
    }

    #[test]
    fn test_uffd_block_handshake_copy_policy() {
        let tmp_dir = TempDir::new().unwrap();
        let sock_path = tmp_dir.as_path().join("test.sock");
        let sock_path_str = sock_path.to_str().unwrap().to_string();

        let listener = UnixListener::bind(&sock_path).unwrap();
        let regions = test_vma_regions();
        // SAFETY: eventfd(0, 0) returns a valid fd on success; File::from_raw_fd takes ownership.
        let uffd_fd = OwnedFd::from(unsafe { File::from_raw_fd(libc::eventfd(0, 0)) });

        let mut block = UffdBlock::new(&sock_path_str, FaultPolicy::Copy).unwrap();

        let client_thread = std::thread::spawn(move || {
            block.handshake(uffd_fd, regions).unwrap();
            block
        });

        let (stream, _) = listener.accept().unwrap();
        let mut buf = vec![0u8; 4096];
        let (bytes_read, _) = stream.recv_with_fd(&mut buf).unwrap();
        buf.truncate(bytes_read);

        let received: HandshakeRequest = serde_json::from_slice(&buf).unwrap();
        assert_eq!(received.policy, FaultPolicy::Copy);

        let block = client_thread.join().unwrap();
        assert_eq!(block.policy, FaultPolicy::Copy);
    }

    // ─── handle_response tests ────────────────────────────────────────────────

    #[test]
    fn test_handle_response_would_block() {
        let tmp_dir = TempDir::new().unwrap();
        let sock_path = tmp_dir.as_path().join("test.sock");
        let sock_path_str = sock_path.to_str().unwrap().to_string();

        let listener = UnixListener::bind(&sock_path).unwrap();
        // SAFETY: eventfd(0, 0) returns a valid fd on success; File::from_raw_fd takes ownership.
        let uffd_fd = OwnedFd::from(unsafe { File::from_raw_fd(libc::eventfd(0, 0)) });

        let mut block = UffdBlock::new(&sock_path_str, FaultPolicy::Zerocopy).unwrap();

        let client_thread = std::thread::spawn(move || {
            block.handshake(uffd_fd, test_vma_regions()).unwrap();
            block
        });

        // Accept and drain handshake
        let (stream, _) = listener.accept().unwrap();
        let mut buf = vec![0u8; 4096];
        let _ = stream.recv_with_fd(&mut buf).unwrap();

        let block = client_thread.join().unwrap();

        // No data sent, non-blocking socket → WouldBlock
        let err = block.handle_response().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn test_handle_response_connection_closed() {
        let tmp_dir = TempDir::new().unwrap();
        let sock_path = tmp_dir.as_path().join("test.sock");
        let sock_path_str = sock_path.to_str().unwrap().to_string();

        let listener = UnixListener::bind(&sock_path).unwrap();
        // SAFETY: eventfd(0, 0) returns a valid fd on success; File::from_raw_fd takes ownership.
        let uffd_fd = OwnedFd::from(unsafe { File::from_raw_fd(libc::eventfd(0, 0)) });

        let mut block = UffdBlock::new(&sock_path_str, FaultPolicy::Zerocopy).unwrap();

        let client_thread = std::thread::spawn(move || {
            block.handshake(uffd_fd, test_vma_regions()).unwrap();
            block
        });

        // Accept, drain handshake, then close server side
        let (stream, _) = listener.accept().unwrap();
        let mut buf = vec![0u8; 4096];
        let _ = stream.recv_with_fd(&mut buf).unwrap();
        drop(stream);

        let block = client_thread.join().unwrap();

        // Set blocking so recv returns 0 (connection closed) instead of WouldBlock
        block.sock.set_nonblocking(false).unwrap();
        assert!(!block.handle_response().unwrap());
    }

    #[test]
    fn test_handle_response_fd_range_mismatch() {
        let tmp_dir = TempDir::new().unwrap();
        let sock_path = tmp_dir.as_path().join("test.sock");
        let sock_path_str = sock_path.to_str().unwrap().to_string();

        let listener = UnixListener::bind(&sock_path).unwrap();
        // SAFETY: eventfd(0, 0) returns a valid fd on success; File::from_raw_fd takes ownership.
        let uffd_fd = OwnedFd::from(unsafe { File::from_raw_fd(libc::eventfd(0, 0)) });

        let mut block = UffdBlock::new(&sock_path_str, FaultPolicy::Zerocopy).unwrap();

        let client_thread = std::thread::spawn(move || {
            block.handshake(uffd_fd, test_vma_regions()).unwrap();
            block
        });

        // Accept and drain handshake
        let (stream, _) = listener.accept().unwrap();
        let mut buf = vec![0u8; 4096];
        let _ = stream.recv_with_fd(&mut buf).unwrap();

        // Send a response with 2 ranges but only 1 fd → mismatch
        let response = r#"{"ranges":[{"len":4096,"blob_offset":0,"block_offset":0},{"len":4096,"blob_offset":4096,"block_offset":4096}]}"#;
        let tmp_file = tempfile::NamedTempFile::new().unwrap();
        stream
            .send_with_fd(response.as_bytes(), tmp_file.as_raw_fd())
            .unwrap();

        let block = client_thread.join().unwrap();

        // Set blocking temporarily to read the response
        block.sock.set_nonblocking(false).unwrap();
        let err = block.handle_response().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("fd count"));
    }

    #[test]
    fn test_handle_response_invalid_json() {
        let tmp_dir = TempDir::new().unwrap();
        let sock_path = tmp_dir.as_path().join("test.sock");
        let sock_path_str = sock_path.to_str().unwrap().to_string();

        let listener = UnixListener::bind(&sock_path).unwrap();
        // SAFETY: eventfd(0, 0) returns a valid fd on success; File::from_raw_fd takes ownership.
        let uffd_fd = OwnedFd::from(unsafe { File::from_raw_fd(libc::eventfd(0, 0)) });

        let mut block = UffdBlock::new(&sock_path_str, FaultPolicy::Zerocopy).unwrap();

        let client_thread = std::thread::spawn(move || {
            block.handshake(uffd_fd, test_vma_regions()).unwrap();
            block
        });

        let (stream, _) = listener.accept().unwrap();
        let mut buf = vec![0u8; 4096];
        let _ = stream.recv_with_fd(&mut buf).unwrap();

        // Send invalid JSON — pass a valid fd since send_with_fd requires it
        stream
            .send_with_fd(&b"not json{}"[..], stream.as_raw_fd())
            .unwrap();

        let block = client_thread.join().unwrap();

        block.sock.set_nonblocking(false).unwrap();
        let err = block.handle_response().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    // ─── UffdBlock debug ──────────────────────────────────────────────────────

    #[test]
    fn test_uffd_block_debug() {
        let tmp_dir = TempDir::new().unwrap();
        let sock_path = tmp_dir.as_path().join("test.sock");
        let sock_path_str = sock_path.to_str().unwrap().to_string();

        let listener = UnixListener::bind(&sock_path).unwrap();
        // SAFETY: eventfd(0, 0) returns a valid fd on success; File::from_raw_fd takes ownership.
        let uffd_fd = OwnedFd::from(unsafe { File::from_raw_fd(libc::eventfd(0, 0)) });

        let mut block = UffdBlock::new(&sock_path_str, FaultPolicy::Copy).unwrap();
        block.handshake(uffd_fd, test_vma_regions()).unwrap();

        let debug_str = format!("{block:?}");
        assert!(debug_str.contains("test.sock"));
        assert!(debug_str.contains("Copy"));
        assert!(debug_str.contains("sock_fd"));

        // Drain the server side so the listener can be dropped
        let (stream, _) = listener.accept().unwrap();
        let mut buf = vec![0u8; 4096];
        let _ = stream.recv_with_fd(&mut buf);
    }

    // ─── uffd_handler_loop stop ───────────────────────────────────────────────

    #[test]
    fn test_uffd_handler_loop_stop() {
        let tmp_dir = TempDir::new().unwrap();
        let sock_path = tmp_dir.as_path().join("test.sock");
        let sock_path_str = sock_path.to_str().unwrap().to_string();

        let listener = UnixListener::bind(&sock_path).unwrap();
        // SAFETY: eventfd(0, 0) returns a valid fd on success; File::from_raw_fd takes ownership.
        let uffd_fd = OwnedFd::from(unsafe { File::from_raw_fd(libc::eventfd(0, 0)) });

        let mut block = UffdBlock::new(&sock_path_str, FaultPolicy::Zerocopy).unwrap();

        let client_thread = std::thread::spawn(move || {
            block.handshake(uffd_fd, test_vma_regions()).unwrap();
            block
        });

        // Accept and drain handshake so client thread finishes
        let (stream, _) = listener.accept().unwrap();
        let mut buf = vec![0u8; 4096];
        let _ = stream.recv_with_fd(&mut buf).unwrap();

        let block = client_thread.join().unwrap();
        let stop_event = EventFd::new(libc::EFD_NONBLOCK).unwrap();

        // Write to stop_event to signal the loop to exit
        stop_event.write(1).unwrap();

        let (ready_tx, _ready_rx) = std::sync::mpsc::sync_channel(1);
        let _sock_fd = block.sock_fd();
        let handle = std::thread::Builder::new()
            .name("test-uffd-handler".into())
            .spawn(move || uffd_handler_loop(&block, &stop_event, &ready_tx))
            .unwrap();

        // The loop should exit promptly due to the stop event.
        let result = handle.join().expect("handler loop should exit cleanly");
        result.unwrap();
    }
}
