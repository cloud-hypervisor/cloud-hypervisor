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

#[cfg(test)]
pub(crate) mod unit_tests {
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};

    use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
    use flate2::write::DeflateEncoder;
    use flate2::Compression;

    const COMPRESSED_FLAG: u64 = 1 << 62;
    const CLUSTER_USED_FLAG: u64 = 1 << 63;
    const COMPRESSED_SECTOR_SIZE: u64 = 512;

    const HEADER_CLUSTER_BITS_OFFSET: u64 = 20;
    const HEADER_L1_SIZE_OFFSET: u64 = 36;
    const HEADER_L1_TABLE_OFFSET: u64 = 40;

    const L1_L2_ADDR_MASK: u64 = 0x00ff_ffff_ffff_fe00;

    fn make_compressed_l2_entry(host_offset: u64, compressed_len: usize, cluster_bits: u32) -> u64 {
        let compressed_size_shift = 62 - (cluster_bits - 8);
        let intra_sector_offset = host_offset & (COMPRESSED_SECTOR_SIZE - 1);
        let total_bytes = compressed_len as u64 + intra_sector_offset;
        let nsectors = total_bytes.div_ceil(COMPRESSED_SECTOR_SIZE);
        let addr_part = host_offset & ((1 << compressed_size_shift) - 1);
        let size_part = (nsectors - 1) << compressed_size_shift;
        COMPRESSED_FLAG | size_part | addr_part
    }

    /// Compress every allocated cluster in a QCOW2 image file in place.
    ///
    /// Walks L1 -> L2 tables, compresses each standard cluster with raw
    /// deflate, appends the compressed payload at the end of the file,
    /// and rewrites the L2 entry with the compressed layout.
    pub fn compress_allocated_clusters(file: &mut File) {
        file.seek(SeekFrom::Start(HEADER_CLUSTER_BITS_OFFSET))
            .unwrap();
        let cluster_bits = file.read_u32::<BigEndian>().unwrap();
        let cluster_size = 1u64 << cluster_bits;

        file.seek(SeekFrom::Start(HEADER_L1_SIZE_OFFSET)).unwrap();
        let l1_size = file.read_u32::<BigEndian>().unwrap();

        file.seek(SeekFrom::Start(HEADER_L1_TABLE_OFFSET)).unwrap();
        let l1_table_offset = file.read_u64::<BigEndian>().unwrap();

        let entries_per_l2 = cluster_size / 8;

        let mut append_offset = file.seek(SeekFrom::End(0)).unwrap();
        append_offset = (append_offset + 511) & !511;

        for l1_idx in 0..l1_size as u64 {
            let l1_entry_offset = l1_table_offset + l1_idx * 8;
            file.seek(SeekFrom::Start(l1_entry_offset)).unwrap();
            let l1_entry = file.read_u64::<BigEndian>().unwrap();

            let l2_table_addr = l1_entry & L1_L2_ADDR_MASK;
            if l2_table_addr == 0 {
                continue;
            }

            for l2_idx in 0..entries_per_l2 {
                let l2_entry_offset = l2_table_addr + l2_idx * 8;
                file.seek(SeekFrom::Start(l2_entry_offset)).unwrap();
                let l2_entry = file.read_u64::<BigEndian>().unwrap();

                if l2_entry & CLUSTER_USED_FLAG == 0 || l2_entry & COMPRESSED_FLAG != 0 {
                    continue;
                }

                let host_cluster_addr = l2_entry & L1_L2_ADDR_MASK;
                if host_cluster_addr == 0 {
                    continue;
                }

                let mut cluster_data = vec![0u8; cluster_size as usize];
                file.seek(SeekFrom::Start(host_cluster_addr)).unwrap();
                file.read_exact(&mut cluster_data).unwrap();

                let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(&cluster_data).unwrap();
                let compressed = encoder.finish().unwrap();

                file.seek(SeekFrom::Start(append_offset)).unwrap();
                file.write_all(&compressed).unwrap();

                // The L2 entry encodes the compressed size in units of
                // 512 byte sectors. The reader decodes the sector count
                // back and computes: nsectors * 512 - (addr & 511).
                // Because addr is 512 aligned, this yields nsectors * 512
                // which rounds up to the next sector boundary. The file
                // must contain enough bytes for that rounded up pread.
                let padded_len = (compressed.len() + 511) & !511;
                if padded_len > compressed.len() {
                    let padding = vec![0u8; padded_len - compressed.len()];
                    file.write_all(&padding).unwrap();
                }

                let new_entry =
                    make_compressed_l2_entry(append_offset, compressed.len(), cluster_bits);
                file.seek(SeekFrom::Start(l2_entry_offset)).unwrap();
                file.write_u64::<BigEndian>(new_entry).unwrap();

                append_offset += padded_len as u64;
            }
        }

        file.flush().unwrap();
    }
}
