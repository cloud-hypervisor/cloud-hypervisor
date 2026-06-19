// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::os::unix::fs::FileExt;
use std::{io, slice};

/// RAII aligned heap buffer for O_DIRECT I/O.
///
/// Handles the alignment math for offset and length, allocating a buffer
/// that satisfies O_DIRECT constraints. The caller's logical data lives
/// at `as_slice()`/`as_mut_slice()` (accounting for head padding when the
/// requested offset is not alignment-aligned). The full aligned region is
/// used internally for pread/pwrite via `FileExt`.
pub(crate) struct AlignedBuffer {
    ptr: *mut u8,
    layout: Layout,
    head_pad: usize,
    user_len: usize,
    aligned_len: usize,
    aligned_offset: u64,
}

impl AlignedBuffer {
    /// Create a new aligned buffer for I/O at `offset` of `len` bytes with
    /// the given `alignment` requirement.
    ///
    /// When offset and length are already aligned, `head_pad == 0` and the
    /// full buffer equals the user's logical portion (no overhead).
    pub fn new(offset: u64, len: usize, alignment: usize) -> io::Result<Self> {
        if alignment == 0 || !alignment.is_power_of_two() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "alignment must be a non-zero power of two",
            ));
        }

        let mask = alignment as u64 - 1;
        let aligned_offset = offset & !mask;
        let head_pad = (offset - aligned_offset) as usize;
        let min_len = head_pad
            .checked_add(len)
            .ok_or_else(|| io::Error::other("aligned buffer length overflow"))?;
        let aligned_len = if min_len == 0 {
            0
        } else {
            let remainder = min_len % alignment;
            if remainder == 0 {
                min_len
            } else {
                min_len
                    .checked_add(alignment - remainder)
                    .ok_or_else(|| io::Error::other("aligned buffer length overflow"))?
            }
        };

        // alloc_zeroed is UB on a zero-sized layout, so round the allocation
        // up to one alignment unit for the zero-length case. The padding is
        // never exposed: as_slice/full_slice report aligned_len/user_len (0).
        let layout = Layout::from_size_align(aligned_len.max(alignment), alignment)
            .map_err(|e| io::Error::other(format!("invalid aligned layout: {e}")))?;
        // SAFETY: layout has non-zero size.
        let ptr = unsafe { alloc_zeroed(layout) };
        if ptr.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "aligned allocation failed",
            ));
        }

        Ok(AlignedBuffer {
            ptr,
            layout,
            head_pad,
            user_len: len,
            aligned_len,
            aligned_offset,
        })
    }

    /// The caller's logical portion of the buffer (read-only).
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: ptr is valid for layout.size() bytes; head_pad + user_len <= layout.size().
        unsafe { slice::from_raw_parts(self.ptr.add(self.head_pad), self.user_len) }
    }

    /// The caller's logical portion of the buffer (mutable).
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: ptr is valid for layout.size() bytes; head_pad + user_len <= layout.size().
        unsafe { slice::from_raw_parts_mut(self.ptr.add(self.head_pad), self.user_len) }
    }

    fn full_slice(&self) -> &[u8] {
        // SAFETY: ptr is valid for layout.size() bytes; aligned_len <= layout.size().
        unsafe { slice::from_raw_parts(self.ptr, self.aligned_len) }
    }

    fn full_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: ptr is valid for layout.size() bytes; aligned_len <= layout.size().
        unsafe { slice::from_raw_parts_mut(self.ptr, self.aligned_len) }
    }

    /// Read into the buffer from `f`, tolerating a short read at EOF.
    ///
    /// Returns the number of caller-logical bytes now valid in `as_slice()`,
    /// accounting for head padding and any short read.
    pub fn read_from(&mut self, f: &impl FileExt) -> io::Result<usize> {
        let mut total = 0usize;
        while total < self.aligned_len {
            let offset = self
                .aligned_offset
                .checked_add(total as u64)
                .ok_or_else(|| io::Error::other("aligned buffer offset overflow"))?;
            match f.read_at(&mut self.full_mut_slice()[total..], offset) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(total.saturating_sub(self.head_pad).min(self.user_len))
    }

    /// Write the full aligned region from this buffer to `f`.
    pub fn write_to(&self, f: &impl FileExt) -> io::Result<()> {
        f.write_all_at(self.full_slice(), self.aligned_offset)
    }
}

impl Drop for AlignedBuffer {
    fn drop(&mut self) {
        // SAFETY: ptr was allocated by alloc_zeroed with self.layout.
        unsafe { dealloc(self.ptr, self.layout) };
    }
}

// SAFETY: The buffer is a plain heap allocation with no interior references.
unsafe impl Send for AlignedBuffer {}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::os::unix::fs::FileExt;

    use vmm_sys_util::tempfile::TempFile;

    use super::*;

    fn create_pattern_file(size: usize) -> TempFile {
        let tf = TempFile::new().unwrap();
        let pattern: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        tf.as_file().write_all(&pattern).unwrap();
        tf.as_file().sync_all().unwrap();
        tf
    }

    #[test]
    fn test_read_aligned() {
        let size = 4096usize;
        let tf = create_pattern_file(size);
        let alignment = 512;

        let mut abuf = AlignedBuffer::new(0, size, alignment).unwrap();
        abuf.read_from(tf.as_file()).unwrap();

        let expected: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        assert_eq!(abuf.as_slice(), &expected[..]);
    }

    #[test]
    fn test_zero_len_is_noop() {
        let tf = create_pattern_file(512);
        let mut abuf = AlignedBuffer::new(100, 0, 512).unwrap();

        abuf.read_from(tf.as_file()).unwrap();
        abuf.write_to(tf.as_file()).unwrap();

        assert!(abuf.as_slice().is_empty());
        assert!(abuf.as_mut_slice().is_empty());
    }

    #[test]
    fn test_read_unaligned_offset() {
        let file_size = 8192usize;
        let tf = create_pattern_file(file_size);
        let alignment = 512;

        let offset = 100u64;
        let len = 200usize;
        let mut abuf = AlignedBuffer::new(offset, len, alignment).unwrap();
        abuf.read_from(tf.as_file()).unwrap();

        let expected: Vec<u8> = (offset as usize..offset as usize + len)
            .map(|i| (i % 251) as u8)
            .collect();
        assert_eq!(abuf.as_slice(), &expected[..]);
    }

    #[test]
    fn test_write_aligned() {
        let size = 4096usize;
        let tf = create_pattern_file(size);
        let alignment = 512;

        let data: Vec<u8> = (0..size).map(|i| ((i + 1) % 251) as u8).collect();
        let mut abuf = AlignedBuffer::new(0, size, alignment).unwrap();
        abuf.as_mut_slice().copy_from_slice(&data);
        abuf.write_to(tf.as_file()).unwrap();

        let mut readback = vec![0u8; size];
        tf.as_file().read_exact_at(&mut readback, 0).unwrap();
        assert_eq!(readback, data);
    }

    #[test]
    fn test_write_unaligned_offset_rmw() {
        let file_size = 8192usize;
        let tf = create_pattern_file(file_size);
        let alignment = 512;

        let offset = 100u64;
        let len = 200usize;
        let data: Vec<u8> = (0..len).map(|i| ((i + 1) % 239) as u8).collect();

        let mut abuf = AlignedBuffer::new(offset, len, alignment).unwrap();
        abuf.read_from(tf.as_file()).unwrap();
        abuf.as_mut_slice().copy_from_slice(&data);
        abuf.write_to(tf.as_file()).unwrap();

        let mut whole = vec![0u8; file_size];
        tf.as_file().read_exact_at(&mut whole, 0).unwrap();

        let before: Vec<u8> = (0..offset as usize).map(|i| (i % 251) as u8).collect();
        assert_eq!(&whole[..offset as usize], &before[..]);
        assert_eq!(&whole[offset as usize..offset as usize + len], &data[..]);
        let after_start = offset as usize + len;
        let after: Vec<u8> = (after_start..file_size).map(|i| (i % 251) as u8).collect();
        assert_eq!(&whole[after_start..], &after[..]);
    }

    #[test]
    fn test_4096_alignment() {
        let file_size = 16384usize;
        let tf = create_pattern_file(file_size);
        let alignment = 4096;

        let offset = 4096u64;
        let len = 4096usize;
        let data: Vec<u8> = (0..len).map(|i| ((i + 1) % 239) as u8).collect();

        let mut abuf = AlignedBuffer::new(offset, len, alignment).unwrap();
        abuf.read_from(tf.as_file()).unwrap();
        abuf.as_mut_slice().copy_from_slice(&data);
        abuf.write_to(tf.as_file()).unwrap();

        let mut abuf = AlignedBuffer::new(offset, len, alignment).unwrap();
        abuf.read_from(tf.as_file()).unwrap();
        assert_eq!(abuf.as_slice(), &data[..]);

        let mut whole = vec![0u8; file_size];
        tf.as_file().read_exact_at(&mut whole, 0).unwrap();
        let before: Vec<u8> = (0..offset as usize).map(|i| (i % 251) as u8).collect();
        assert_eq!(&whole[..offset as usize], &before[..]);
        let after_start = offset as usize + len;
        let after: Vec<u8> = (after_start..file_size).map(|i| (i % 251) as u8).collect();
        assert_eq!(&whole[after_start..], &after[..]);
    }
}
