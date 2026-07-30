// Copyright © 2026 Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0

//! Minimal userfaultfd bindings for demand-paged snapshot restore.
//!
//! Prefers `/dev/userfaultfd` (Linux 6.1+) over the `userfaultfd(2)` syscall
//! to create a fault descriptor, falling back to the syscall when the device
//! is unavailable. Then uses `UFFDIO_API` / `UFFDIO_REGISTER` / `UFFDIO_COPY`
//! ioctls to handle page faults from a background thread.
//!
//! Unlike an mmap(MAP_PRIVATE) overlay approach, UFFD does not replace the
//! original memory mapping, so it remains compatible with VFIO device
//! passthrough and shared-memory-backed guest RAM.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Error, Read};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::FileExt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};

use ondemand_block::{HANDSHAKE_FLAG_MANAGED, UffdBlock, VmaRegion};
use vm_migration::protocol::{MemoryRange, Request, Response, Status};
use vmm_sys_util::eventfd::EventFd;

use crate::migration::transport::SocketStream;
use crate::userfaultfd;

#[repr(C)]
pub(crate) struct UffdioApi {
    pub api: u64,
    pub features: u64,
    pub ioctls: u64,
}

#[repr(C)]
pub(crate) struct UffdioRegister {
    pub range_start: u64,
    pub range_len: u64,
    pub mode: u64,
    pub ioctls: u64,
}

#[repr(C)]
pub(crate) struct UffdioCopy {
    pub dst: u64,
    pub src: u64,
    pub len: u64,
    pub mode: u64,
    pub copy: i64,
}

/// Flat representation of `struct uffd_msg` (32 bytes).
///
/// The kernel struct contains an 8-byte header followed by a 24-byte
/// union (`arg`). We only use the `arg.pagefault` variant, so the
/// union is flattened into its pagefault fields here. The trailing
/// 8 bytes (`arg.pagefault.feat` + padding) are unused.
#[repr(C)]
pub(crate) struct UffdMsg {
    pub event: u8,
    _reserved1: u8,
    _reserved2: u16,
    _reserved3: u32,
    pub pf_flags: u64,
    pub pf_address: u64,
    _pad: [u8; 8],
}

const _: () = assert!(size_of::<UffdMsg>() == 32);

/// Try to obtain a userfaultfd via /dev/userfaultfd (Linux 6.1+).
///
/// This bypasses the capability and sysctl checks that gate the syscall,
/// requiring only file permissions on the device node.
fn try_dev_userfaultfd() -> Result<OwnedFd, Error> {
    let dev = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/userfaultfd")?;
    let flags = libc::O_CLOEXEC | libc::O_NONBLOCK;
    // SAFETY: USERFAULTFD_IOC_NEW on a valid /dev/userfaultfd fd returns a new
    // userfaultfd file descriptor.
    let fd = unsafe {
        libc::ioctl(
            dev.as_raw_fd(),
            userfaultfd::USERFAULTFD_IOC_NEW as libc::Ioctl,
            flags,
        )
    };
    if fd < 0 {
        return Err(Error::last_os_error());
    }
    // SAFETY: the ioctl returned a valid fd above.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Create a userfaultfd file descriptor and perform the API handshake.
///
/// Prefers `/dev/userfaultfd` (no capability/sysctl requirements, just file
/// permissions) and falls back to the `userfaultfd(2)` syscall.
pub(crate) fn create(required_features: u64) -> Result<OwnedFd, Error> {
    let fd = match try_dev_userfaultfd() {
        Ok(fd) => fd,
        Err(_) => {
            // SAFETY: `userfaultfd` syscall with O_CLOEXEC | O_NONBLOCK flags.
            let raw =
                unsafe { libc::syscall(libc::SYS_userfaultfd, libc::O_CLOEXEC | libc::O_NONBLOCK) };
            if raw < 0 {
                return Err(Error::last_os_error());
            }
            // SAFETY: the syscall returned a valid fd above.
            unsafe { OwnedFd::from_raw_fd(raw as RawFd) }
        }
    };

    let mut api = UffdioApi {
        api: userfaultfd::UFFD_API,
        features: required_features,
        ioctls: 0,
    };
    // SAFETY: `api` is a valid, correctly-sized struct for this ioctl.
    let ret = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            userfaultfd::UFFDIO_API as libc::Ioctl,
            &mut api,
        )
    };
    if ret < 0 {
        return Err(Error::last_os_error());
    }

    Ok(fd)
}

/// Register a memory range for missing-page fault handling.
pub(crate) fn register(fd: BorrowedFd<'_>, addr: u64, len: u64) -> Result<u64, Error> {
    let mut reg = UffdioRegister {
        range_start: addr,
        range_len: len,
        mode: userfaultfd::UFFDIO_REGISTER_MODE_MISSING,
        ioctls: 0,
    };
    // SAFETY: `reg` is a valid, correctly-sized struct for this ioctl.
    let ret = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            userfaultfd::UFFDIO_REGISTER as libc::Ioctl,
            &mut reg,
        )
    };
    if ret < 0 {
        return Err(Error::last_os_error());
    }
    Ok(reg.ioctls)
}

/// Resolve a page fault by copying data into the faulted address.
pub(crate) fn copy(fd: BorrowedFd<'_>, dst: u64, src: *const u8, len: u64) -> Result<(), Error> {
    let mut cp = UffdioCopy {
        dst,
        src: src as u64,
        len,
        mode: 0,
        copy: 0,
    };
    // SAFETY: `cp` is a valid, correctly-sized struct for this ioctl.
    let ret = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            userfaultfd::UFFDIO_COPY as libc::Ioctl,
            &mut cp,
        )
    };
    if ret < 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

#[repr(C)]
struct UffdioRange {
    start: u64,
    len: u64,
}

/// A guest memory range registered with userfaultfd, plus where its bytes
/// live for the data source.
pub(crate) struct UffdRange {
    pub host_addr: u64,
    pub length: u64,
    pub source_offset: u64,
    pub page_size: u64,
}

impl UffdRange {
    pub fn num_pages(&self) -> u64 {
        self.length.div_ceil(self.page_size)
    }

    pub fn page_addr(&self, page_idx: u64) -> u64 {
        self.host_addr + page_idx * self.page_size
    }

    pub fn page_source_offset(&self, page_idx: u64) -> u64 {
        self.source_offset + page_idx * self.page_size
    }

    pub fn page_index_of(&self, addr: u64) -> Option<u64> {
        let page_addr = addr & !(self.page_size - 1);
        (page_addr >= self.host_addr && page_addr < self.host_addr + self.length)
            .then(|| (page_addr - self.host_addr) / self.page_size)
    }
}

/// Result of a page fault being resolved.
pub(crate) enum FaultResolution {
    /// Page installed.
    Served,
    /// Indicates the page couldn't be installed and it's worth retrying.
    Retry,
}

/// Provider of guest-memory page contents for a UFFD handler.
pub(crate) trait UffdMemorySource: Send {
    fn resolve(
        &mut self,
        uffd_fd: BorrowedFd<'_>,
        range: &UffdRange,
        page_idx: u64,
    ) -> Result<FaultResolution, io::Error>;
}

/// Source that reads pages from a local snapshot file.
pub(crate) struct FileUffdMemorySource {
    file: File,
    buf: Vec<u8>,
}

impl FileUffdMemorySource {
    pub fn new(file: File) -> Self {
        Self {
            file,
            buf: Vec::new(),
        }
    }
}

impl UffdMemorySource for FileUffdMemorySource {
    fn resolve(
        &mut self,
        uffd_fd: BorrowedFd<'_>,
        range: &UffdRange,
        page_idx: u64,
    ) -> Result<FaultResolution, io::Error> {
        let page_size = range.page_size as usize;
        let page_addr = range.page_addr(page_idx);
        let file_pos = range.page_source_offset(page_idx);

        if self.buf.len() < page_size {
            self.buf.resize(page_size, 0);
        }
        self.file
            .read_exact_at(&mut self.buf[..page_size], file_pos)?;

        match copy(uffd_fd, page_addr, self.buf.as_ptr(), range.page_size) {
            Ok(()) => Ok(FaultResolution::Served),
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                // Installed concurrently. Wake any blocked threads.
                if let Err(e) = wake(uffd_fd, page_addr, range.page_size) {
                    log::warn!("UFFDIO_WAKE failed at {page_addr:#x}: {e}");
                }
                Ok(FaultResolution::Served)
            }
            Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => Ok(FaultResolution::Retry),
            Err(e) => Err(e),
        }
    }
}

/// Memory source that provides pages content over a socket.
pub(crate) struct SocketUffdMemorySource {
    stream: SocketStream,
    shared_backing: bool,
    buf: Vec<u8>,
}

impl SocketUffdMemorySource {
    pub fn new(stream: SocketStream, shared_backing: bool) -> Self {
        Self {
            stream,
            shared_backing,
            buf: Vec::new(),
        }
    }

    /// Returns the length of the inline page payload the peer is about to send
    /// (0 when the page was written directly into shared memory).
    fn request_page(&mut self, gpa: u64, len: u64) -> Result<u64, io::Error> {
        Request::page_fault()
            .write_to(&mut self.stream)
            .map_err(io_other)?;
        MemoryRange { gpa, length: len }
            .write_to(&mut self.stream)
            .map_err(io_other)?;

        let resp = Response::read_from(&mut self.stream).map_err(io_other)?;
        match resp.status() {
            Status::Ok => Ok(resp.length()),
            s => Err(io::Error::other(format!(
                "peer returned {s:?} for PageFault at gpa={gpa:#x} len={len}",
            ))),
        }
    }
}

impl UffdMemorySource for SocketUffdMemorySource {
    fn resolve(
        &mut self,
        uffd_fd: BorrowedFd<'_>,
        range: &UffdRange,
        page_idx: u64,
    ) -> Result<FaultResolution, io::Error> {
        let page_size = range.page_size;
        let page_addr = range.page_addr(page_idx);
        let page_gpa = range.page_source_offset(page_idx);

        let resp_len = self.request_page(page_gpa, page_size)?;

        if self.shared_backing {
            if resp_len != 0 {
                return Err(io::Error::other(format!(
                    "shared-backing PageFault response carried {resp_len} unexpected bytes",
                )));
            }
            match wake(uffd_fd, page_addr, page_size) {
                Ok(()) => Ok(FaultResolution::Served),
                Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => Ok(FaultResolution::Retry),
                Err(e) => Err(e),
            }
        } else {
            if resp_len != page_size {
                return Err(io::Error::other(format!(
                    "inline PageFault response length {resp_len} != page size {page_size}",
                )));
            }
            let len = page_size as usize;
            if self.buf.len() < len {
                self.buf.resize(len, 0);
            }
            self.stream.read_exact(&mut self.buf[..len])?;
            match copy(uffd_fd, page_addr, self.buf.as_ptr(), page_size) {
                Ok(()) => Ok(FaultResolution::Served),
                Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                    if let Err(e) = wake(uffd_fd, page_addr, page_size) {
                        log::warn!("UFFDIO_WAKE failed at {page_addr:#x}: {e}");
                    }
                    Ok(FaultResolution::Served)
                }
                Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => Ok(FaultResolution::Retry),
                Err(e) => Err(e),
            }
        }
    }
}

impl Drop for SocketUffdMemorySource {
    fn drop(&mut self) {
        // SAFETY: the fd is valid for the duration of this borrow.
        unsafe { libc::shutdown(self.stream.as_fd().as_raw_fd(), libc::SHUT_RDWR) };
    }
}

#[allow(dead_code)]
pub(crate) struct ExternalUffdConfig {
    pub socket_path: PathBuf,
    pub uffd: OwnedFd,
    pub regions: Vec<VmaRegion>,
    pub handshake_flags: u8,
    pub uffd_modes: u8,
    pub backing_fds: Vec<OwnedFd>,
}

#[allow(dead_code)]
pub(crate) struct ExternalUffdHandler {
    block: Arc<UffdBlock>,
    worker: Option<ExternalUffdWorker>,
}

#[allow(dead_code)]
struct ExternalUffdWorker {
    stop_evt: EventFd,
    result_rx: Receiver<io::Result<()>>,
    stopping: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

#[allow(dead_code)]
impl ExternalUffdHandler {
    pub(crate) fn new(
        name: &str,
        config: ExternalUffdConfig,
        exit_evt: Option<EventFd>,
    ) -> io::Result<Self> {
        let mut block = UffdBlock::new(&config.socket_path)?;
        let backing_fds = config
            .backing_fds
            .iter()
            .map(AsRawFd::as_raw_fd)
            .collect::<Vec<_>>();
        block.handshake(
            config.uffd,
            config.regions,
            config.handshake_flags,
            config.uffd_modes,
            &backing_fds,
        )?;
        let block = Arc::new(block);

        let worker = if config.handshake_flags & HANDSHAKE_FLAG_MANAGED == 0 {
            let exit_evt = exit_evt.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Customized external UFFD handler requires an exit event",
                )
            })?;
            Some(ExternalUffdWorker::spawn(name, &block, exit_evt)?)
        } else {
            None
        };

        Ok(Self { block, worker })
    }

    /// Add or update a region in a managed external UFFD session.
    pub(crate) fn add_region(
        &mut self,
        region: VmaRegion,
        backing_fd: Option<RawFd>,
    ) -> io::Result<()> {
        self.block_mut()?.add_region(region, backing_fd)
    }

    /// Remove a region from a managed external UFFD session.
    pub(crate) fn remove_region(&mut self, host_addr: u64, len: u64) -> io::Result<()> {
        self.block_mut()?.remove_region(host_addr, len)
    }

    fn block_mut(&mut self) -> io::Result<&mut UffdBlock> {
        Arc::get_mut(&mut self.block).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "External UFFD block is in use by a response worker",
            )
        })
    }
}

#[allow(dead_code)]
impl ExternalUffdWorker {
    fn spawn(name: &str, block: &Arc<UffdBlock>, exit_evt: EventFd) -> io::Result<Self> {
        let thread_block = Arc::clone(block);
        let stop_evt = EventFd::new(libc::EFD_NONBLOCK)?;
        let thread_stop_evt = stop_evt.try_clone()?;
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (result_tx, result_rx) = mpsc::sync_channel(1);
        let stopping = Arc::new(AtomicBool::new(false));
        let thread_stopping = Arc::clone(&stopping);
        let thread_name = format!("external-uffd-{name}");
        let thread = thread::Builder::new().name(thread_name).spawn(move || {
            let result = catch_unwind(AssertUnwindSafe(|| {
                const STOP_EVENT: u64 = 0;
                const SOCKET_EVENT: u64 = 1;

                let epoll_fd = epoll::create(true).map_err(io::Error::other)?;
                // SAFETY: epoll::create returned a fresh descriptor owned here.
                let _epoll_file = unsafe { File::from_raw_fd(epoll_fd) };
                epoll::ctl(
                    epoll_fd,
                    epoll::ControlOptions::EPOLL_CTL_ADD,
                    thread_stop_evt.as_raw_fd(),
                    epoll::Event::new(epoll::Events::EPOLLIN, STOP_EVENT),
                )
                .map_err(io::Error::other)?;
                epoll::ctl(
                    epoll_fd,
                    epoll::ControlOptions::EPOLL_CTL_ADD,
                    thread_block.sock_fd(),
                    epoll::Event::new(
                        epoll::Events::EPOLLIN | epoll::Events::EPOLLHUP,
                        SOCKET_EVENT,
                    ),
                )
                .map_err(io::Error::other)?;

                ready_tx.send(()).ok();

                let mut events = [epoll::Event::new(epoll::Events::empty(), 0); 2];
                loop {
                    let count = epoll::wait(epoll_fd, -1, &mut events).map_err(io::Error::other)?;
                    for event in events.iter().take(count) {
                        match event.data {
                            STOP_EVENT => {
                                thread_stop_evt.read().ok();
                                return Ok(());
                            }
                            SOCKET_EVENT => {
                                if event.events & epoll::Events::EPOLLIN.bits() == 0 {
                                    return Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "External UFFD server closed the socket",
                                    ));
                                }
                                while thread_block.handle_response_zerocopy()? {}
                            }
                            _ => {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "Unexpected external UFFD epoll event",
                                ));
                            }
                        }
                    }
                }
            }))
            .unwrap_or_else(|_| Err(io::Error::other("External UFFD handler thread panicked")));

            if let Err(error) = &result
                && !thread_stopping.load(Ordering::Acquire)
            {
                log::error!("External UFFD backend failed: {error}");
                exit_evt.write(1).ok();
            }
            result_tx.send(result).ok();
        })?;

        if ready_rx.recv().is_err() {
            thread.join().ok();
            return match result_rx.try_recv() {
                Ok(Err(error)) => Err(error),
                _ => Err(io::Error::other("External UFFD handler failed to start")),
            };
        }
        if let Ok(Err(error)) = result_rx.try_recv() {
            thread.join().ok();
            return Err(error);
        }

        Ok(Self {
            stop_evt,
            result_rx,
            stopping,
            thread: Some(thread),
        })
    }
}

impl Drop for ExternalUffdHandler {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.as_mut() {
            worker.stopping.store(true, Ordering::Release);
            worker.stop_evt.write(1).ok();
            // Interrupt a partial response read before joining the handler.
            // SAFETY: block owns a valid socket for the duration of this call.
            unsafe { libc::shutdown(self.block.sock_fd(), libc::SHUT_RDWR) };
            if let Some(thread) = worker.thread.take() {
                thread.join().ok();
            }
            match worker.result_rx.try_recv() {
                Ok(Err(error)) => {
                    log::error!("External UFFD handler terminated with error: {error}");
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    log::warn!("External UFFD handler terminated without a result");
                }
                _ => {}
            }
        }
    }
}

fn io_other<E: fmt::Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}

/// Wake threads waiting on a fault in the given range without copying data.
///
/// Needed after UFFDIO_COPY returns EEXIST: the page was already resolved
/// by a concurrent fault, but any additional threads blocked on that page
/// may not have been woken.
pub(crate) fn wake(fd: BorrowedFd<'_>, addr: u64, len: u64) -> Result<(), Error> {
    let mut range = UffdioRange { start: addr, len };
    // SAFETY: `range` is a valid, correctly-sized struct for this ioctl.
    let ret = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            userfaultfd::UFFDIO_WAKE as libc::Ioctl,
            &mut range,
        )
    };
    if ret < 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}
