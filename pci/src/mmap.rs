// Copyright © 2025 Demi Marie Obenour
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! Helpers for `mmap()`

use core::ffi::c_int;
use core::ptr::null_mut;
use std::io::{Error, ErrorKind};
use std::os::fd::{AsRawFd as _, BorrowedFd};

use libc::size_t;

/// A region of `mmap()`-allocated memory that calls `munmap()` when dropped.
/// This guarantees that the buffer is valid and that its address space
/// will be reserved.  The address space is not guaranteed to be accessible.
/// Atomic access to the data will not cause undefined behavior but might
/// cause SIGSEGV or SIGBUS.  Non-atomic access will generally cause data
/// races and thus Undefined Behavior.
#[derive(Debug)]
pub struct MmapRegion {
    addr: *mut u8,
    len: size_t,
}

impl Drop for MmapRegion {
    fn drop(&mut self) {
        // SAFETY: guaranteed by type validity invariant
        unsafe { assert_eq!(libc::munmap(self.addr as *mut _, self.len), 0) }
    }
}
// SAFETY: the caller is responsible for avoiding data races
unsafe impl Send for MmapRegion {}
// SAFETY: the caller is responsible for avoiding data races
unsafe impl Sync for MmapRegion {}

impl MmapRegion {
    #[inline]
    pub fn addr(&self) -> *mut u8 {
        self.addr
    }

    /// Return the length of the region.
    /// This function promises that the return value fits in [`libc::size_t`]
    /// and in [`isize`] and `unsafe` code can rely on this.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Create an [`MmapRegion`] using `mmap` of a file descriptor.
    pub fn mmap(
        len: u64,
        prot: c_int,
        fd: BorrowedFd,
        offset1: u64,
        offset2: u64,
    ) -> std::io::Result<Self> {
        const BAD_LENGTH: &str = "Offsets must fit in libc::off_t";
        const BAD_OFFSET: &str = "Mapping length must fit \
in both isize and libc::size_t";
        let Some(offset) = offset1.checked_add(offset2) else {
            return Err(Error::new(ErrorKind::InvalidInput, BAD_OFFSET));
        };
        let Ok(offset) = libc::off_t::try_from(offset) else {
            return Err(Error::new(ErrorKind::InvalidInput, BAD_OFFSET));
        };
        if isize::try_from(len).is_err() {
            return Err(Error::new(ErrorKind::InvalidInput, BAD_LENGTH));
        }
        let Ok(len) = libc::size_t::try_from(len) else {
            return Err(Error::new(ErrorKind::InvalidInput, BAD_LENGTH));
        };

        assert!(
            (prot & !(libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC)) == 0,
            "bad protection"
        );
        let flags = libc::MAP_SHARED;
        // SAFETY: FFI call with correct parameters.
        let addr = unsafe { libc::mmap(null_mut(), len, prot, flags, fd.as_raw_fd(), offset) };
        if addr == libc::MAP_FAILED {
            Err(Error::last_os_error())
        } else {
            let addr = addr as _;
            Ok(Self { addr, len })
        }
    }
}
