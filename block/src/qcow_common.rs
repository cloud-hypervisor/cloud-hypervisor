// Copyright © 2021 Intel Corporation
//
// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

//! Shared helpers for QCOW2 sync and async backends.
//!
//! Position-independent I/O (`pread_exact`, `pwrite_all`) and iovec
//! scatter/gather helpers used by both `qcow_sync` and `qcow_async`.

use std::cmp::min;
use std::os::fd::RawFd;
use std::{io, ptr, slice};

// -- Position independent I/O helpers --
//
// Duplicated file descriptors share the kernel file description and thus the
// file position. Using seek then read from multiple queues races on that
// shared position. pread64 and pwrite64 are atomic and never touch the position.

/// Read exactly the requested bytes at offset, looping on short reads.
pub fn pread_exact(fd: RawFd, buf: &mut [u8], offset: u64) -> io::Result<()> {
    let mut total = 0usize;
    while total < buf.len() {
        // SAFETY: buf and fd are valid for the lifetime of the call.
        let ret = unsafe {
            libc::pread64(
                fd,
                buf[total..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - total,
                (offset + total as u64) as libc::off_t,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        if ret == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        total += ret as usize;
    }
    Ok(())
}

/// Write all bytes to fd at offset, looping on short writes.
pub fn pwrite_all(fd: RawFd, buf: &[u8], offset: u64) -> io::Result<()> {
    let mut total = 0usize;
    while total < buf.len() {
        // SAFETY: buf and fd are valid for the lifetime of the call.
        let ret = unsafe {
            libc::pwrite64(
                fd,
                buf[total..].as_ptr() as *const libc::c_void,
                buf.len() - total,
                (offset + total as u64) as libc::off_t,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        if ret == 0 {
            return Err(io::Error::other("pwrite64 wrote 0 bytes"));
        }
        total += ret as usize;
    }
    Ok(())
}

// -- iovec helper functions --
//
// Operate on the iovec array as a flat byte stream.

/// Copy data into iovecs starting at the given byte offset.
///
/// # Safety
/// Caller must ensure iovecs point to valid, writable memory of sufficient size.
pub unsafe fn scatter_to_iovecs(iovecs: &[libc::iovec], start: usize, data: &[u8]) {
    let mut remaining = data;
    let mut pos = 0usize;
    for iov in iovecs {
        let iov_end = pos + iov.iov_len;
        if iov_end <= start || remaining.is_empty() {
            pos = iov_end;
            continue;
        }
        let iov_start = start.saturating_sub(pos);
        let available = iov.iov_len - iov_start;
        let count = min(available, remaining.len());
        // SAFETY: iov_base is valid for iov_len bytes per caller contract.
        unsafe {
            let dst = (iov.iov_base as *mut u8).add(iov_start);
            ptr::copy_nonoverlapping(remaining.as_ptr(), dst, count);
        }
        remaining = &remaining[count..];
        if remaining.is_empty() {
            break;
        }
        pos = iov_end;
    }
}

/// Zero fill iovecs starting at the given byte offset for the given length.
///
/// # Safety
/// Caller must ensure iovecs point to valid, writable memory of sufficient size.
pub unsafe fn zero_fill_iovecs(iovecs: &[libc::iovec], start: usize, len: usize) {
    let mut remaining = len;
    let mut pos = 0usize;
    for iov in iovecs {
        let iov_end = pos + iov.iov_len;
        if iov_end <= start || remaining == 0 {
            pos = iov_end;
            continue;
        }
        let iov_start = start.saturating_sub(pos);
        let available = iov.iov_len - iov_start;
        let count = min(available, remaining);
        // SAFETY: iov_base is valid for iov_len bytes per caller contract.
        unsafe {
            let dst = (iov.iov_base as *mut u8).add(iov_start);
            ptr::write_bytes(dst, 0, count);
        }
        remaining -= count;
        if remaining == 0 {
            break;
        }
        pos = iov_end;
    }
}

/// Gather bytes from iovecs starting at the given byte offset into a Vec.
///
/// # Safety
/// Caller must ensure iovecs point to valid, readable memory of sufficient size.
pub unsafe fn gather_from_iovecs(iovecs: &[libc::iovec], start: usize, len: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(len);
    let mut remaining = len;
    let mut pos = 0usize;
    for iov in iovecs {
        let iov_end = pos + iov.iov_len;
        if iov_end <= start || remaining == 0 {
            pos = iov_end;
            continue;
        }
        let iov_start = start.saturating_sub(pos);
        let available = iov.iov_len - iov_start;
        let count = min(available, remaining);
        // SAFETY: iov_base is valid for iov_len bytes per caller contract.
        unsafe {
            let src = (iov.iov_base as *const u8).add(iov_start);
            result.extend_from_slice(slice::from_raw_parts(src, count));
        }
        remaining -= count;
        if remaining == 0 {
            break;
        }
        pos = iov_end;
    }
    result
}
