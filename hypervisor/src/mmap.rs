// Copyright © 2025 Demi Marie Obenour
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! Helpers for `mmap()`

use core::ffi::{c_int, c_void};
use core::marker::PhantomData;
use core::ptr::null_mut;
use std::io::{Error, ErrorKind};
use std::os::fd::{AsRawFd as _, BorrowedFd};

use libc::{off_t, size_t};
use vm_memory::bitmap::Bitmap;
use vm_memory::GuestRegionMmap;

/// A region of mmap()-allocated memory that calls `munmap()` when dropped.
/// This guarantees that the buffer is valid and that its address space
/// will be reserved.  The address space is not guaranteed to be accessible.
/// Atomic access to the data will not cause undefined behavior but might
/// cause SIGSEGV or SIGBUS.  Non-atomic access will generally cause data
/// races and thus Undefined Behavior.
#[derive(Debug)]
pub struct MmapRegion {
    addr: *mut c_void,
    len: size_t,
}

impl Drop for MmapRegion {
    fn drop(&mut self) {
        // SAFETY: guaranteed by type validity invariant
        unsafe { assert_eq!(libc::munmap(self.addr, self.len), 0) }
    }
}

/// A borrowed region of mmap()-allocated memory.
/// This guarantees that the buffer is valid and that its address space
/// will be reserved.  The address space is not guaranteed to be accessible.
/// Atomic access to the data will not cause undefined behavior but might
/// cause SIGSEGV or SIGBUS.  Non-atomic access will generally cause data
/// races and thus Undefined Behavior.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct BorrowedMmapRegion<'a> {
    addr: *mut c_void,
    len: size_t,
    _phantom: PhantomData<&'a ()>,
}

// SAFETY: the caller is responsible for avoiding data races
unsafe impl<'a> Send for BorrowedMmapRegion<'a> {}
// SAFETY: the caller is responsible for avoiding data races
unsafe impl<'a> Sync for BorrowedMmapRegion<'a> {}
// SAFETY: the caller is responsible for avoiding data races
unsafe impl Send for MmapRegion {}
// SAFETY: the caller is responsible for avoiding data races
unsafe impl Sync for MmapRegion {}

impl<'a> BorrowedMmapRegion<'a> {
    /// Create an [`MmapRegion`] from a pointer and length.
    ///
    /// # Safety
    ///
    /// The address space must be safe to pass to `munmap`.
    pub unsafe fn new(addr: *mut c_void, len: size_t) -> Self {
        assert!(!addr.is_null());
        Self {
            addr,
            len,
            _phantom: PhantomData,
        }
    }

    pub fn addr(&self) -> *mut c_void {
        self.addr
    }

    pub fn len(&self) -> size_t {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl<'a, T: Bitmap> From<&'a GuestRegionMmap<T>> for BorrowedMmapRegion<'a> {
    fn from(other: &'a GuestRegionMmap<T>) -> Self {
        Self {
            addr: other.as_ptr() as *mut _,
            len: other.size(),
            _phantom: PhantomData,
        }
    }
}

impl MmapRegion {
    /// Create an [`MmapRegion`] from a pointer and length.
    ///
    /// # Safety
    ///
    /// The address space must be safe to pass to `munmap`.
    pub unsafe fn new(addr: *mut c_void, len: size_t) -> Self {
        assert!(!addr.is_null());
        Self { addr, len }
    }

    pub fn addr(&self) -> *mut c_void {
        self.addr
    }

    pub fn len(&self) -> size_t {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Create an [`MmapRegion`] using `mmap` of a file descriptor.
    ///
    /// # Safety
    ///
    /// The file descriptor must be valid for mmap(), and the other
    /// arguments must be valid.
    #[inline(never)]
    unsafe fn _mmap(
        len: Result<size_t, ()>,
        prot: c_int,
        fd: BorrowedFd,
        offset: Result<off_t, ()>,
    ) -> std::io::Result<Self> {
        const BAD_LENGTH: &str = "Offsets must not be negative and must fit in libc::off_t";
        const BAD_OFFSET: &str = "Mapping length must not be negative and must fit \
in both isize and libc::size_t";

        let offset = match offset {
            Ok(offset) if offset >= 0 => offset,
            _ => return Err(Error::new(ErrorKind::InvalidInput, BAD_OFFSET)),
        };

        let len = match len {
            Ok(len) if isize::try_from(len).is_ok() => len,
            _ => return Err(Error::new(ErrorKind::InvalidInput, BAD_LENGTH)),
        };

        let flags = libc::MAP_SHARED;
        let addr = libc::mmap(null_mut(), len, prot, flags, fd.as_raw_fd(), offset);
        if addr == libc::MAP_FAILED {
            Err(Error::last_os_error())
        } else {
            Ok(Self { addr, len })
        }
    }

    /// Create an [`MmapRegion`] using `mmap` of a file descriptor.
    ///
    /// # Safety
    ///
    /// The file descriptor must be valid for mmap(), and the prot
    /// and flags arguments must be valid.
    pub unsafe fn mmap<T, U>(
        len: T,
        prot: c_int,
        fd: BorrowedFd,
        offset: U,
    ) -> std::io::Result<Self>
    where
        size_t: TryFrom<T>,
        off_t: TryFrom<U>,
    {
        let len = len.try_into().map_err(drop);
        let offset = offset.try_into().map_err(drop);
        // SAFETY: guaranteed by caller
        unsafe { Self::_mmap(len, prot, fd, offset) }
    }

    pub fn borrow(&self) -> BorrowedMmapRegion<'_> {
        BorrowedMmapRegion {
            addr: self.addr,
            len: self.len,
            _phantom: PhantomData,
        }
    }
}
