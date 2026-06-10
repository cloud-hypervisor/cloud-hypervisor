// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

//! Sparse file-copy helpers shared between snapshot/restore paths (the
//! `MemoryManager` snapshot writer and the offload daemon). Holes are
//! detected via `lseek(SEEK_DATA)`/`lseek(SEEK_HOLE)` and left as holes in
//! the destination, with a dense fallback when the source filesystem does
//! not support sparse-seek.

use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::fs::FileExt;

/// Find the next populated (data) extent in `[cursor, end)` of `fd`,
/// driven by `lseek(SEEK_DATA)` / `lseek(SEEK_HOLE)`. Returns
/// `Ok(Some((offset, len)))` for the next data extent within the window,
/// or `Ok(None)` if there is no more data. Returns `Err` if the fd or
/// filesystem does not support `SEEK_HOLE` (e.g. hugetlbfs) or for any
/// other I/O error. Callers should treat a first-call error as "fall
/// back to the dense path".
pub fn next_data_extent(
    fd: BorrowedFd<'_>,
    cursor: u64,
    end: u64,
) -> io::Result<Option<(u64, u64)>> {
    let raw = fd.as_raw_fd();
    // SAFETY: BorrowedFd guarantees the fd is valid for the lifetime of
    // the borrow; lseek does not consume or close it.
    let data_off = unsafe { libc::lseek(raw, cursor as i64, libc::SEEK_DATA) };
    if data_off < 0 {
        let e = io::Error::last_os_error();
        // ENXIO from SEEK_DATA means there is no more data at or after
        // cursor. Any other error means the filesystem does not support
        // SEEK_HOLE; the caller falls back to the dense path.
        return if e.raw_os_error() == Some(libc::ENXIO) {
            Ok(None)
        } else {
            Err(e)
        };
    }
    let data_off = data_off as u64;
    if data_off >= end {
        return Ok(None);
    }
    // SAFETY: same as above.
    let hole_off = unsafe { libc::lseek(raw, data_off as i64, libc::SEEK_HOLE) };
    if hole_off < 0 {
        return Err(io::Error::last_os_error());
    }
    let hole_off = (hole_off as u64).min(end);
    Ok(Some((data_off, hole_off - data_off)))
}

/// Copy `[src_offset, src_offset+len)` of `src` to `dst` at `dst_offset`,
/// writing only the populated extents so `dst` keeps its holes. `dst` must
/// already be sized (e.g. via `set_len`). Returns `Ok(true)` if the region
/// was written sparsely, or `Ok(false)` if `SEEK_HOLE` is unsupported on the
/// source fd (caller should fall back to a dense copy).
pub fn write_region_sparse(
    src: &File,
    src_offset: u64,
    dst: &File,
    dst_offset: u64,
    len: u64,
) -> io::Result<bool> {
    let src_fd = src.as_fd();
    let end = src_offset
        .checked_add(len)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "range overflow"))?;

    // First call to next_data_extent doubles as a SEEK_HOLE-support probe:
    // a non-ENXIO error means the filesystem doesn't support sparse-seek;
    // tell the caller to use the dense path instead.
    let mut next = match next_data_extent(src_fd, src_offset, end) {
        Ok(opt) => opt,
        Err(_) => return Ok(false),
    };

    const CHUNK: usize = 1 << 20;
    let mut buf = vec![0u8; CHUNK];

    while let Some((data_off, ext_len)) = next {
        debug_assert!(data_off >= src_offset);
        let in_region = data_off
            .checked_sub(src_offset)
            .expect("extent precedes src_offset");
        let mut written = 0u64;
        while written < ext_len {
            let this = ((ext_len - written) as usize).min(CHUNK);
            let slice = &mut buf[..this];
            let read = src.read_at(slice, data_off + written)?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "read_at returned 0 inside data extent",
                ));
            }
            let mut wrote_total = 0;
            while wrote_total < read {
                let n = dst.write_at(
                    &slice[wrote_total..read],
                    dst_offset + in_region + written + wrote_total as u64,
                )?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write_at returned 0",
                    ));
                }
                wrote_total += n;
            }
            written += read as u64;
        }
        // Subsequent next_data_extent failures are real I/O errors, not
        // unsupported-FS, since the first probe succeeded.
        next = next_data_extent(src_fd, data_off + ext_len, end)?;
    }
    Ok(true)
}
