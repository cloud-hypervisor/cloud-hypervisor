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
    let page_size = get_page_size() as usize;
    if len >= ONE_GIB {
        ONE_GIB
    } else {
        len.next_power_of_two().max(page_size)
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

fn tail_trim_range(
    base_addr: usize,
    reserve: size_t,
    aligned_addr: usize,
    len: size_t,
) -> (usize, size_t) {
    let page_size = get_page_size() as usize;
    let mapped_end = aligned_addr + len;
    // munmap() requires a page-aligned address, so trim from the next page.
    let tail_addr = mapped_end.next_multiple_of(page_size);
    let tail_len = (base_addr + reserve) - tail_addr;
    assert!(tail_len > 0);

    (tail_addr, tail_len)
}

/// # SAFETY
///
/// Callers must make sure base and aligned come from the same valid mapping
/// from mmap.
unsafe fn trim_mapping(base: *mut c_void, reserve: size_t, aligned: *mut c_void, len: size_t) {
    let base_addr = base as usize;
    let aligned_addr = aligned as usize;

    let head_len = aligned_addr - base_addr;
    if head_len > 0 {
        // SAFETY: [base, base+head_len) is a valid region
        unsafe {
            munmap(base, head_len);
        }
    }

    let (tail_addr, tail_len) = tail_trim_range(base_addr, reserve, aligned_addr, len);
    // SAFETY: [tail_addr, tail_addr+tail_len) is a valid region
    unsafe {
        munmap(tail_addr as *mut c_void, tail_len);
    }
}

fn allocate_aligned_mapping(
    len: size_t,
    prot: c_int,
    fd: BorrowedFd,
    offset: libc::off_t,
) -> io::Result<*mut c_void> {
    let alignment = find_alignment(len);

    if alignment == get_page_size() as usize {
        // SAFETY: FFI call with correct parameters.
        let addr = unsafe {
            libc::mmap(
                null_mut(),
                len,
                prot,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                offset,
            )
        };
        if addr == libc::MAP_FAILED {
            return Err(Error::last_os_error());
        }
        return Ok(addr);
    }

    let Some(reserve) = len.checked_add(alignment) else {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Length+Alignment overflows",
        ));
    };

    let (base, aligned) = reserve_mapping(reserve, alignment)?;
    // SAFETY: base and aligned are from the same mmap region
    unsafe {
        trim_mapping(base, reserve, aligned, len);
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    fn tail_trim_range_from_len(base_addr: usize, len: size_t) -> (usize, size_t) {
        let alignment = find_alignment(len);
        let reserve = len.checked_add(alignment).unwrap();
        let aligned_addr = base_addr.next_multiple_of(alignment);

        tail_trim_range(base_addr, reserve, aligned_addr, len)
    }

    #[test]
    fn find_alignment_scales_with_length() {
        let page_size = get_page_size() as usize;

        // Sub-page and page-sized mappings only need page alignment.
        assert_eq!(find_alignment(1), page_size);
        assert_eq!(find_alignment(page_size), page_size);

        // Larger mappings round up to the next power of two.
        assert_eq!(
            find_alignment(page_size + 1),
            (page_size + 1).next_power_of_two()
        );
        assert!(find_alignment(page_size + 1) > page_size);

        // The alignment is capped at 1 GiB.
        assert_eq!(find_alignment(ONE_GIB), ONE_GIB);
        assert_eq!(find_alignment(ONE_GIB + 1), ONE_GIB);
        assert_eq!(find_alignment(2 * ONE_GIB), ONE_GIB);
    }

    #[test]
    fn tail_trim_range_rounds_non_page_sized_len_up() {
        let page_size = get_page_size() as usize;
        let base_addr = 0x1000_0000;
        let len = page_size * 3 + 1;
        let alignment = find_alignment(len);

        let (tail_addr, tail_len) = tail_trim_range_from_len(base_addr, len);

        // The tail starts at the first page boundary past the mapping ...
        assert_eq!(tail_addr, base_addr + page_size * 4);
        assert_eq!(tail_addr % page_size, 0);
        // ... and reaches the end of the reserved region.
        assert_eq!(tail_addr + tail_len, base_addr + len + alignment);
    }

    #[test]
    fn tail_trim_range_uses_exact_end_for_page_sized_len() {
        let page_size = get_page_size() as usize;
        let base_addr = 0x1000_0000;
        let len = page_size * 3;
        let alignment = find_alignment(len);

        let (tail_addr, tail_len) = tail_trim_range_from_len(base_addr, len);

        // A page-aligned end needs no rounding.
        assert_eq!(tail_addr, base_addr + len);
        assert_eq!(tail_addr + tail_len, base_addr + len + alignment);
    }

    #[test]
    fn tail_trim_range_trims_after_partial_final_page() {
        let page_size = get_page_size() as usize;
        let base_addr = 0x1000_0000;
        let len = page_size * 512 + 1;
        let alignment = find_alignment(len);

        let (tail_addr, tail_len) = tail_trim_range_from_len(base_addr, len);

        assert_eq!(tail_addr, base_addr + page_size * 513);
        assert_eq!(tail_addr % page_size, 0);
        assert_eq!(tail_addr + tail_len, base_addr + len + alignment);
    }
}
