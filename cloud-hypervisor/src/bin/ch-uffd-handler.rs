// Copyright (C) 2026 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Example zero-copy UFFD handler for Cloud Hypervisor.
//!
//! Listens on a Unix socket, receives a UFFD file descriptor from
//! cloud-hypervisor (via the handshake), polls it for page faults,
//! and sends back `PageFaultResponse` messages with the blob fd
//! so the VMM can `mmap(MAP_FIXED)` the data zero-copy.
//!
//! Usage:
//!   ch-uffd-handler --socket /tmp/handler.sock --file /path/to/data
//!
//! The `--file` is the backing data file whose contents are mapped
//! into guest memory on page faults.  For snapshot restore, this is
//! the `memory-ranges` file from the snapshot directory.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::io::{AsRawFd, IntoRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};

use vmm::uffd_block::{BlobRange, FaultPolicy, HandshakeRequest, PageFaultResponse, VmaRegion};
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

// ─── UFFD ioctls ────────────────────────────────────────────────────────────

const UFFDIO: u64 = 0xAA;
const _UFFDIO_COPY: u64 = 0x03;

/// Wait for the uffd fd to become readable using poll().
fn wait_for_uffd(uffd_fd: RawFd) -> io::Result<bool> {
    let mut pfd = libc::pollfd {
        fd: uffd_fd,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        // SAFETY: pfd is a valid pollfd struct on the stack.
        let ret = unsafe { libc::poll(&mut pfd, 1, -1) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        if pfd.revents & libc::POLLHUP != 0 {
            return Ok(false); // uffd closed
        }
        return Ok(true); // readable
    }
}

/// Read a userfaultfd event from the uffd file descriptor.
/// Returns the fault address or None if no pagefault event.
fn uffd_read_event(uffd_fd: RawFd) -> io::Result<Option<u64>> {
    #[repr(C)]
    struct UffdMsg {
        event: u8,
        _reserved1: u8,
        _reserved2: u16,
        _reserved3: u32,
        arg: UffdMsgArg,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    union UffdMsgArg {
        pagefault: UffdMsgPagefault,
        _pad: [u64; 3],
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    struct UffdMsgPagefault {
        flags: u64,
        address: u64,
        _feat: UffdMsgFeat,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    union UffdMsgFeat {
        ptid: u32,
        _pad: u64,
    }

    const UFFD_EVENT_PAGEFAULT: u8 = 0x12;
    const UFFD_EVENT_UNMAP: u8 = 0x16;

    let mut msg = std::mem::MaybeUninit::<UffdMsg>::zeroed();
    // SAFETY: msg is a valid zeroed buffer of the correct size for a uffd_msg.
    let n = unsafe {
        libc::read(
            uffd_fd,
            msg.as_mut_ptr().cast(),
            std::mem::size_of::<UffdMsg>(),
        )
    };

    if n < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EAGAIN) {
            return Ok(None);
        }
        return Err(err);
    }

    if n != std::mem::size_of::<UffdMsg>() as isize {
        return Ok(None);
    }

    // SAFETY: We verified the read returned exactly size_of::<UffdMsg>() bytes.
    let msg = unsafe { msg.assume_init() };

    if msg.event == UFFD_EVENT_PAGEFAULT {
        // SAFETY: We checked the event type is PAGEFAULT, so the pagefault union variant is valid.
        let addr = unsafe { msg.arg.pagefault.address };
        Ok(Some(addr))
    } else if msg.event == UFFD_EVENT_UNMAP {
        // UNMAP events are generated when mmap(MAP_FIXED) replaces a
        // uffd-registered VMA.  Reading the event is sufficient to
        // unblock the mmap caller and wake the faulting thread.
        // SAFETY: UNMAP events also use the pagefault union variant.
        let addr = unsafe { msg.arg.pagefault.address };
        eprintln!("UNMAP event: addr=0x{addr:x}");
        Ok(None)
    } else {
        eprintln!("Unexpected uffd event type: {}", msg.event);
        Ok(None)
    }
}

/// UFFDIO_COPY: copy data to resolve a page fault
fn uffd_copy(uffd_fd: RawFd, dst: u64, src: *const u8, len: u64) -> io::Result<()> {
    #[repr(C)]
    struct UffdCopy {
        dst: u64,
        src: u64,
        len: u64,
        mode: u64,
        copy: i64,
    }

    let mut copy = UffdCopy {
        dst,
        src: src as u64,
        len,
        mode: 0,
        copy: 0,
    };

    // UFFDIO_COPY = _IOWR(0xAA, 0x03, struct uffdio_copy) = 0xC028AA03
    let ioctl_num: u64 = (_UFFDIO_COPY)
        | (UFFDIO << 8)
        | (((std::mem::size_of::<UffdCopy>() as u64) & 0x3FFF) << 16)
        | (3u64 << 30); // _IOWR direction bits
    // SAFETY: uffd_fd is a valid userfaultfd, copy is a valid UffdCopy struct.
    let ret = unsafe { libc::ioctl(uffd_fd, ioctl_num as libc::Ioctl, &mut copy as *mut _) };

    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

// ─── Handler ────────────────────────────────────────────────────────────────

struct Handler {
    stream: UnixStream,
    file: File,
    data_size: u64,
    regions: Vec<VmaRegion>,
    policy: FaultPolicy,
    uffd_fd: RawFd,
}

impl Handler {
    fn run(listener: &UnixListener, file: File) -> io::Result<()> {
        let data_size = file.metadata()?.len();
        eprintln!(
            "Data file size: {data_size} bytes ({:.2} MB)",
            data_size as f64 / 1048576.0
        );

        eprintln!("Waiting for connection...");
        let (stream, _) = listener.accept()?;
        eprintln!("Client connected");

        let mut handler = Handler {
            stream,
            file,
            data_size,
            regions: Vec::new(),
            policy: FaultPolicy::Zerocopy, // updated by handshake
            uffd_fd: -1,
        };

        handler.handshake()?;

        handler.event_loop()
    }

    fn handshake(&mut self) -> io::Result<()> {
        let mut buf = vec![0u8; 65536];
        let (bytes_read, file) = self.stream.recv_with_fd(&mut buf)?;
        let uffd_file = file.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "no uffd fd received in handshake",
            )
        })?;
        buf.truncate(bytes_read);

        let json_str =
            std::str::from_utf8(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let request: HandshakeRequest = serde_json::from_str(json_str)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        eprintln!(
            "Handshake: {} regions, policy {:?}",
            request.regions.len(),
            request.policy
        );
        for (i, r) in request.regions.iter().enumerate() {
            eprintln!(
                "  Region[{i}]: base=0x{:x}, size=0x{:x} ({:.2} MB), offset=0x{:x}, page_size={}",
                r.base_host_virt_addr,
                r.size,
                r.size as f64 / 1048576.0,
                r.offset,
                r.page_size
            );
        }

        self.regions = request.regions;
        self.policy = request.policy;
        self.uffd_fd = uffd_file.into_raw_fd();
        eprintln!("Received uffd fd: {}", self.uffd_fd);

        Ok(())
    }

    fn event_loop(&mut self) -> io::Result<()> {
        let mut fault_count: u64 = 0;

        loop {
            // Wait for uffd fd to become readable (blocks until a page fault occurs)
            match wait_for_uffd(self.uffd_fd) {
                Ok(true) => {}
                Ok(false) => {
                    eprintln!("UFFD closed (POLLHUP) after {fault_count} faults");
                    return Ok(());
                }
                Err(e) => {
                    eprintln!("poll() error after {fault_count} faults: {e}");
                    return Err(e);
                }
            }

            // Read all available events (uffd is non-blocking)
            while let Some(fault_addr) = uffd_read_event(self.uffd_fd)? {
                fault_count += 1;
                if fault_count <= 5 || fault_count.is_multiple_of(1000) {
                    eprintln!("Page fault #{fault_count}: addr=0x{fault_addr:x}");
                }
                self.handle_fault(fault_addr)?;
            }
        }
    }

    fn handle_fault(&mut self, fault_addr: u64) -> io::Result<()> {
        // Find which region this fault belongs to
        let region = self
            .regions
            .iter()
            .find(|r| {
                fault_addr >= r.base_host_virt_addr
                    && fault_addr < r.base_host_virt_addr + r.size as u64
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("fault addr 0x{fault_addr:x} not in any region"),
                )
            })?;

        let page_size = if region.page_size > 0 {
            region.page_size
        } else {
            4096
        };

        // Align fault address down to page boundary
        let aligned_addr = fault_addr & !(page_size as u64 - 1);
        let offset_in_region = aligned_addr - region.base_host_virt_addr;
        let file_offset = region.offset + offset_in_region;

        // Clamp len to not exceed region or file boundary
        let remaining_region = region.size as u64 - offset_in_region;
        let remaining_file = self.data_size.saturating_sub(file_offset);
        let len = page_size
            .min(remaining_region as usize)
            .min(remaining_file as usize);

        if len == 0 {
            // Zero-fill for pages beyond the file
            let buf = vec![0u8; page_size];
            uffd_copy(self.uffd_fd, aligned_addr, buf.as_ptr(), page_size as u64)?;
            return Ok(());
        }

        match self.policy {
            FaultPolicy::Zerocopy => {
                // block_offset is relative to the first region's base
                let block_offset = offset_in_region + region.offset;

                let response = PageFaultResponse {
                    ranges: vec![BlobRange {
                        len,
                        blob_offset: file_offset,
                        block_offset,
                    }],
                };

                let json = serde_json::to_string(&response)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

                self.stream
                    .send_with_fd(json.as_bytes(), self.file.as_raw_fd())?;
            }
            FaultPolicy::Copy => {
                // Read from file and UFFDIO_COPY
                let mut buf = vec![0u8; len];
                // SAFETY: file fd is valid, buf is a valid mutable buffer, file_offset is within bounds.
                let n = unsafe {
                    libc::pread(
                        self.file.as_raw_fd(),
                        buf.as_mut_ptr().cast(),
                        len,
                        file_offset as i64,
                    )
                };
                if n < 0 {
                    return Err(io::Error::last_os_error());
                }
                // Zero-fill remainder if short read
                if (n as usize) < page_size {
                    buf.resize(page_size, 0);
                }
                uffd_copy(self.uffd_fd, aligned_addr, buf.as_ptr(), page_size as u64)?;
            }
        }

        Ok(())
    }
}

// ─── Main ───────────────────────────────────────────────────────────────────

fn print_usage() {
    eprintln!("Usage: ch-uffd-handler --socket <path> --file <path>");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --socket <path>   Unix socket path to listen on");
    eprintln!("  --file <path>     Backing data file (e.g. snapshot memory-ranges file)");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut socket_path = None;
    let mut file_path = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--socket" | "-s" => {
                i += 1;
                socket_path = args.get(i).cloned();
            }
            "--file" | "-f" => {
                i += 1;
                file_path = args.get(i).cloned();
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => {
                eprintln!("Unknown option: {other}");
                print_usage();
                std::process::exit(1);
            }
        }
        i += 1;
    }

    let socket_path = match socket_path {
        Some(p) => p,
        None => {
            eprintln!("Error: --socket is required");
            print_usage();
            std::process::exit(1);
        }
    };

    let file_path = match file_path {
        Some(p) => p,
        None => {
            eprintln!("Error: --file is required");
            print_usage();
            std::process::exit(1);
        }
    };

    eprintln!("ch-uffd-handler starting");
    eprintln!("  Socket: {socket_path}");
    eprintln!("  File: {file_path}");

    let file = match OpenOptions::new().read(true).write(true).open(&file_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to open {file_path}: {e}");
            std::process::exit(1);
        }
    };

    // Remove stale socket
    let _ = std::fs::remove_file(&socket_path);

    let listener = match UnixListener::bind(&socket_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind {socket_path}: {e}");
            std::process::exit(1);
        }
    };

    eprintln!("Listening on {socket_path}...");

    if let Err(e) = Handler::run(&listener, file) {
        eprintln!("Handler error: {e}");
        std::process::exit(1);
    }
}
