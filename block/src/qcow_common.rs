// Copyright © 2021 Intel Corporation
//
// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

//! Shared helpers for QCOW2 sync and async backends.
//!
//! Position-independent I/O (`pread_exact`, `pwrite_all`) and iovec
//! scatter/gather helpers used by both `qcow_sync` and `qcow_async`.

use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::cmp::min;
use std::os::fd::RawFd;
use std::{io, ptr, slice};

use crate::qcow::decoder::Decoder;

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

/// Allocate a buffer and pread exactly `len` bytes at `offset`.
pub fn pread_alloc(fd: RawFd, offset: u64, len: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    pread_exact(fd, &mut buf, offset)?;
    Ok(buf)
}

/// Decompress a full QCOW2 cluster from compressed data.
///
/// Returns a `cluster_size` byte buffer with the decompressed cluster
/// content. Fails if the decoder does not produce exactly `cluster_size`
/// bytes.
pub fn decompress_cluster(
    compressed: &[u8],
    cluster_size: usize,
    decoder: &dyn Decoder,
) -> io::Result<Vec<u8>> {
    let mut decompressed = vec![0u8; cluster_size];
    let n = decoder
        .decode(compressed, &mut decompressed)
        .map_err(|_| io::Error::from_raw_os_error(libc::EIO))?;
    if n != cluster_size {
        return Err(io::Error::from_raw_os_error(libc::EIO));
    }
    Ok(decompressed)
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

/// RAII wrapper for an aligned heap buffer required by O_DIRECT.
pub struct AlignedBuf {
    ptr: *mut u8,
    layout: Layout,
}

impl AlignedBuf {
    pub fn new(size: usize, alignment: usize) -> io::Result<Self> {
        let size = size.max(1).next_multiple_of(alignment);
        let layout = Layout::from_size_align(size, alignment)
            .map_err(|e| io::Error::other(format!("invalid aligned layout: {e}")))?;
        // SAFETY: layout has non-zero size.
        let ptr = unsafe { alloc_zeroed(layout) };
        if ptr.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "aligned allocation failed",
            ));
        }
        Ok(AlignedBuf { ptr, layout })
    }

    pub fn as_mut_slice(&mut self, len: usize) -> &mut [u8] {
        let len = len.min(self.layout.size());
        // SAFETY: ptr is valid for layout.size() bytes; len <= layout.size().
        unsafe { slice::from_raw_parts_mut(self.ptr, len) }
    }

    pub fn as_slice(&self, len: usize) -> &[u8] {
        let len = len.min(self.layout.size());
        // SAFETY: ptr is valid for layout.size() bytes; len <= layout.size().
        unsafe { slice::from_raw_parts(self.ptr, len) }
    }

    #[cfg(test)]
    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    #[cfg(test)]
    pub fn ptr(&self) -> *const u8 {
        self.ptr
    }
}

impl Drop for AlignedBuf {
    fn drop(&mut self) {
        // SAFETY: ptr was allocated by alloc_zeroed with self.layout.
        unsafe { dealloc(self.ptr, self.layout) };
    }
}

/// Read into `buf` via an aligned bounce buffer when O_DIRECT requires it.
pub fn aligned_pread(fd: RawFd, buf: &mut [u8], offset: u64, alignment: usize) -> io::Result<()> {
    if alignment == 0
        || ((buf.as_ptr() as usize).is_multiple_of(alignment)
            && buf.len().is_multiple_of(alignment)
            && (offset as usize).is_multiple_of(alignment))
    {
        return pread_exact(fd, buf, offset);
    }

    let aligned_offset = offset & !(alignment as u64 - 1);
    let head = (offset - aligned_offset) as usize;
    let aligned_len = (head + buf.len()).next_multiple_of(alignment);
    let mut bounce = AlignedBuf::new(aligned_len, alignment)?;
    pread_exact(fd, bounce.as_mut_slice(aligned_len), aligned_offset)?;
    buf.copy_from_slice(&bounce.as_slice(aligned_len)[head..head + buf.len()]);
    Ok(())
}

/// Write `buf` via an aligned bounce buffer when O_DIRECT requires it.
pub fn aligned_pwrite(fd: RawFd, buf: &[u8], offset: u64, alignment: usize) -> io::Result<()> {
    if alignment == 0
        || ((buf.as_ptr() as usize).is_multiple_of(alignment)
            && buf.len().is_multiple_of(alignment)
            && (offset as usize).is_multiple_of(alignment))
    {
        return pwrite_all(fd, buf, offset);
    }

    let aligned_offset = offset & !(alignment as u64 - 1);
    let head = (offset - aligned_offset) as usize;
    let aligned_len = (head + buf.len()).next_multiple_of(alignment);
    let mut bounce = AlignedBuf::new(aligned_len, alignment)?;

    // Read-modify-write: read the existing aligned region, overlay our data.
    pread_exact(fd, bounce.as_mut_slice(aligned_len), aligned_offset)?;
    bounce.as_mut_slice(aligned_len)[head..head + buf.len()].copy_from_slice(buf);
    pwrite_all(fd, bounce.as_slice(aligned_len), aligned_offset)
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

/// Gather bytes from iovecs starting at the given byte offset into `dst`.
///
/// # Safety
/// Caller must ensure iovecs point to valid, readable memory of sufficient size.
pub unsafe fn gather_from_iovecs_into(iovecs: &[libc::iovec], start: usize, dst: &mut [u8]) {
    let len = dst.len();
    let mut written = 0usize;
    let mut pos = 0usize;
    for iov in iovecs {
        let iov_end = pos + iov.iov_len;
        if iov_end <= start || written == len {
            pos = iov_end;
            continue;
        }
        let iov_start = start.saturating_sub(pos);
        let available = iov.iov_len - iov_start;
        let count = min(available, len - written);
        // SAFETY: iov_base is valid for iov_len bytes per caller contract.
        unsafe {
            let src = (iov.iov_base as *const u8).add(iov_start);
            ptr::copy_nonoverlapping(src, dst.as_mut_ptr().add(written), count);
        }
        written += count;
        if written == len {
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
    let mut result = vec![0u8; len];
    // SAFETY: caller guarantees iovecs are valid; result has len bytes.
    unsafe { gather_from_iovecs_into(iovecs, start, &mut result) };
    result
}
