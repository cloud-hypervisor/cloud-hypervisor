// Copyright © 2026 Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0

//! Minimal userfaultfd bindings for demand-paged snapshot restore.
//!
//! Uses the `userfaultfd(2)` syscall (available since Linux 4.3) to create a
//! fault descriptor, then `UFFDIO_API` / `UFFDIO_REGISTER` / `UFFDIO_COPY`
//! ioctls to handle page faults from a background thread.
//!
//! Unlike an mmap(MAP_PRIVATE) overlay approach, UFFD does not replace the
//! original memory mapping, so it remains compatible with VFIO device
//! passthrough and shared-memory-backed guest RAM.

use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

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

const _: () = assert!(std::mem::size_of::<UffdMsg>() == 32);

/// Create a userfaultfd file descriptor and perform the API handshake.
pub(crate) fn create(required_features: u64) -> Result<OwnedFd, std::io::Error> {
    // SAFETY: `userfaultfd` syscall with O_CLOEXEC | O_NONBLOCK flags.
    let fd = unsafe { libc::syscall(libc::SYS_userfaultfd, libc::O_CLOEXEC | libc::O_NONBLOCK) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the syscall returned a valid fd above.
    let fd = unsafe { OwnedFd::from_raw_fd(fd as std::os::unix::io::RawFd) };

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
        return Err(std::io::Error::last_os_error());
    }

    Ok(fd)
}

/// Register a memory range for missing-page fault handling.
pub(crate) fn register(fd: BorrowedFd<'_>, addr: u64, len: u64) -> Result<u64, std::io::Error> {
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
        return Err(std::io::Error::last_os_error());
    }
    Ok(reg.ioctls)
}

/// Resolve a page fault by copying data into the faulted address.
pub(crate) fn copy(
    fd: BorrowedFd<'_>,
    dst: u64,
    src: *const u8,
    len: u64,
) -> Result<(), std::io::Error> {
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
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[repr(C)]
struct UffdioRange {
    start: u64,
    len: u64,
}

/// Wake threads waiting on a fault in the given range without copying data.
///
/// Needed after UFFDIO_COPY returns EEXIST: the page was already resolved
/// by a concurrent fault, but any additional threads blocked on that page
/// may not have been woken.
pub(crate) fn wake(fd: BorrowedFd<'_>, addr: u64, len: u64) -> Result<(), std::io::Error> {
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
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
