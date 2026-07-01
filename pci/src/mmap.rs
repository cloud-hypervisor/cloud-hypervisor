// Copyright © 2025 Demi Marie Obenour
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! Helpers for `mmap()`

use core::ffi::{c_int, c_void};
use core::ptr::null_mut;
use std::io::{self, Error, ErrorKind};
use std::os::fd::{AsRawFd as _, BorrowedFd};

use libc::size_t;
use log::warn;
use vm_allocator::page_size::get_page_size;

const TWO_MIB: usize = 2 * 1024 * 1024;
const ONE_GIB: usize = 1024 * 1024 * 1024;

/// # SAFETY
///
/// Callers must guarantee that the range can be passed to munmap().
unsafe fn munmap(addr: *mut c_void, len: size_t) {
    // SAFETY: see function comment
    let ret = unsafe { libc::munmap(addr, len) };

    if ret != 0 {
        warn!(
            "Failed to munmap region address {:p} length 0x{:x}, {}, leaking...",
            addr,
            len,
            Error::last_os_error()
        );
    }
}

fn find_alignment(len: size_t) -> usize {
    if len >= ONE_GIB {
        ONE_GIB
    } else if len >= TWO_MIB {
        TWO_MIB
    } else {
        get_page_size() as usize
    }
}

fn reserve_mapping(reserve: size_t, alignment: usize) -> io::Result<(*mut c_void, *mut c_void)> {
    // SAFETY: FFI call. Reserving address space with a NULL hint and no fd.
    let base = unsafe {
        libc::mmap(
            null_mut(),
            reserve,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
            -1,
            0,
        )
    };
    if base == libc::MAP_FAILED {
        return Err(Error::last_os_error());
    }

    let aligned = (base as usize).next_multiple_of(alignment) as *mut c_void;

    Ok((base, aligned))
}

fn trim_mapping(base: *mut c_void, reserve: size_t, aligned: *mut c_void, len: size_t) {
    let base_addr = base as usize;
    let aligned_addr = aligned as usize;

    let head_len = aligned_addr - base_addr;
    if head_len > 0 {
        // SAFETY: [base, base+head_len) is a valid region
        unsafe {
            munmap(base, head_len);
        }
    }

    let tail_addr = aligned_addr + len;
    let tail_len = (base_addr + reserve) - tail_addr;
    if tail_len > 0 {
        // SAFETY: [tail_addr, tail_addr+tail_len) is a valid region
        unsafe {
            munmap(tail_addr as *mut c_void, tail_len);
        }
    }
}

fn allocate_aligned_mapping(
    len: size_t,
    prot: c_int,
    fd: BorrowedFd,
    offset: libc::off_t,
) -> io::Result<*mut c_void> {
    let alignment = find_alignment(len);
    let Some(reserve) = len.checked_add(alignment) else {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Length+Alignment overflows",
        ));
    };

    let (base, aligned) = reserve_mapping(reserve, alignment)?;
    trim_mapping(base, reserve, aligned, len);

    // SAFETY: FFI call. MAP_FIXED is safe here because it only replaces the
    // remaining anonymous reservation we just created.
    let addr = unsafe {
        libc::mmap(
            aligned,
            len,
            prot,
            libc::MAP_SHARED | libc::MAP_FIXED,
            fd.as_raw_fd(),
            offset,
        )
    };
    if addr == libc::MAP_FAILED {
        let err = Error::last_os_error();
        // SAFETY: [aligned, aligned+len) is a valid region
        unsafe {
            munmap(aligned, len);
        };
        return Err(err);
    }

    Ok(addr)
}

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
        unsafe {
            munmap(self.addr.cast(), self.len);
        }
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
    ) -> io::Result<Self> {
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

        let addr = allocate_aligned_mapping(len, prot, fd, offset)?;

        Ok(Self {
            addr: addr.cast(),
            len,
        })
    }
}
