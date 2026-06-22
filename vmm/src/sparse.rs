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

/// Copy `[src_offset, src_offset+len)` of `src` to `dst` at `dst_offset`,
/// keeping `dst` sparse when the source filesystem supports `SEEK_HOLE` and
/// falling back to a dense byte copy otherwise (e.g. hugetlbfs). `dst` must
/// already be sized (e.g. via `set_len`). This is the sparse-or-dense wrapper
/// shared by all file-to-file copy consumers (e.g. the offload daemon).
pub fn copy_region(
    src: &File,
    src_offset: u64,
    dst: &File,
    dst_offset: u64,
    len: u64,
) -> io::Result<()> {
    if write_region_sparse(src, src_offset, dst, dst_offset, len)? {
        return Ok(());
    }
    // Dense fallback: source filesystem lacks SEEK_HOLE (e.g. hugetlbfs).
    const CHUNK: usize = 1 << 20;
    let mut buf = vec![0u8; CHUNK];
    let mut done = 0u64;
    while done < len {
        let this = ((len - done) as usize).min(CHUNK);
        src.read_exact_at(&mut buf[..this], src_offset + done)?;
        dst.write_all_at(&buf[..this], dst_offset + done)?;
        done += this as u64;
    }
    Ok(())
}

#[cfg(test)]
mod unit_tests {
    use std::io::Write;
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd};
    use std::os::unix::fs::FileExt;

    use super::{next_data_extent, write_region_sparse};

    fn make_memfd(size: u64) -> std::fs::File {
        // SAFETY: memfd_create is a self-contained syscall; we own the
        // returned fd.
        let fd = unsafe { libc::syscall(libc::SYS_memfd_create, c"sparse-test".as_ptr(), 0u32) };
        assert!(fd >= 0, "memfd_create failed");
        // SAFETY: memfd_create returned a valid fd that we now own; wrap it
        // in File so it is closed on drop.
        let f = unsafe { std::fs::File::from_raw_fd(fd as i32) };
        f.set_len(size).unwrap();
        f
    }

    fn collect_extents(
        fd: BorrowedFd<'_>,
        start: u64,
        end: u64,
    ) -> std::io::Result<Vec<(u64, u64)>> {
        let mut out = Vec::new();
        let mut cursor = start;
        while let Some((off, len)) = next_data_extent(fd, cursor, end)? {
            out.push((off, len));
            cursor = off + len;
        }
        Ok(out)
    }

    /// Punch an explicit hole into `f`. Tests use this instead of relying on
    /// "didn't write here" to mean "is a hole": modern shmem/tmpfs may
    /// allocate a multi-page folio on the first write and report the whole
    /// folio as data, so per-page hole tracking after a partial write is
    /// not portable. `fallocate(PUNCH_HOLE)` is the explicit "deallocate
    /// these pages" syscall and is honored on every Linux filesystem we
    /// run tests on (tmpfs, ext4, xfs, btrfs).
    fn punch_hole(f: &std::fs::File, off: u64, len: u64) {
        // SAFETY: FFI call; f is a valid open fd for the duration of the
        // call.
        let r = unsafe {
            libc::fallocate(
                f.as_raw_fd(),
                libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                off as libc::off_t,
                len as libc::off_t,
            )
        };
        assert_eq!(
            r,
            0,
            "fallocate PUNCH_HOLE off={off} len={len}: {}",
            std::io::Error::last_os_error(),
        );
    }

    /// Build a file with a deterministic sparse layout: write each `(off,
    /// len, byte)` data extent, then punch every gap into a real hole.
    /// The resulting `SEEK_DATA`/`SEEK_HOLE` extents match `data` exactly,
    /// regardless of folio/THP allocation policy on the backing FS.
    fn sparse_layout(f: &std::fs::File, total: u64, data: &[(u64, u64, u8)]) {
        f.set_len(total).unwrap();
        for &(off, len, byte) in data {
            f.write_all_at(&vec![byte; len as usize], off).unwrap();
        }
        let mut sorted: Vec<(u64, u64)> = data.iter().map(|&(o, l, _)| (o, l)).collect();
        sorted.sort_unstable();
        let mut cursor = 0u64;
        for (off, len) in sorted {
            assert!(off >= cursor, "overlapping data extents");
            if off > cursor {
                punch_hole(f, cursor, off - cursor);
            }
            cursor = off + len;
        }
        if cursor < total {
            punch_hole(f, cursor, total - cursor);
        }
    }

    #[test]
    fn empty_memfd_has_no_data_extents() {
        let f = make_memfd(4096 * 16);
        let extents = collect_extents(f.as_fd(), 0, 4096 * 16).unwrap();
        assert!(extents.is_empty(), "got {extents:?}");
    }

    #[test]
    fn written_pages_show_as_data_extents() {
        let f = make_memfd(0);
        sparse_layout(
            &f,
            4096 * 16,
            &[(4096 * 2, 4096, 0xAB), (4096 * 5, 4096 * 2, 0xCD)],
        );
        let extents = collect_extents(f.as_fd(), 0, 4096 * 16).unwrap();
        assert_eq!(extents, vec![(4096 * 2, 4096), (4096 * 5, 4096 * 2)]);
    }

    #[test]
    fn enumeration_respects_window() {
        let f = make_memfd(4096 * 16);
        // Fully populate the file, then leave it as one big data extent.
        f.write_all_at(&vec![0xEEu8; 4096 * 16], 0).unwrap();
        let extents = collect_extents(f.as_fd(), 4096 * 4, 4096 * 8).unwrap();
        assert_eq!(extents, vec![(4096 * 4, 4096 * 4)]);
    }

    #[test]
    fn dense_file_yields_single_extent() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(&vec![0xEEu8; 4096 * 8]).unwrap();
        let f = tmp.reopen().unwrap();
        let extents = collect_extents(f.as_fd(), 0, 4096 * 8).unwrap();
        assert_eq!(extents, vec![(0, 4096 * 8)]);
    }

    #[test]
    fn sparse_file_yields_extents_at_written_positions() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let f = tmp.reopen().unwrap();
        sparse_layout(&f, 4096 * 16, &[(4096 * 4, 4096 * 2, 0x55)]);
        let extents = collect_extents(f.as_fd(), 0, 4096 * 16).unwrap();
        assert_eq!(extents, vec![(4096 * 4, 4096 * 2)]);
    }

    #[test]
    fn single_extent_at_zero_offset() {
        let src = make_memfd(0);
        sparse_layout(&src, 4096 * 16, &[(4096 * 3, 4096 * 2, 0x42)]);

        // Pre-fill dst with a sentinel byte so we can verify that
        // write_region_sparse only wrote where the source had data: any
        // byte outside the source-data extent must remain the sentinel.
        // This is FS-independent (does not depend on whether the dst
        // filesystem reports holes after a partial write).
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let dst = tmp.reopen().unwrap();
        dst.write_all_at(&vec![0xFE; 4096 * 16], 0).unwrap();

        let used = write_region_sparse(&src, 0, &dst, 0, 4096 * 16).unwrap();
        assert!(used);

        let buf = std::fs::read(tmp.path()).unwrap();
        assert!(buf[..4096 * 3].iter().all(|&b| b == 0xFE));
        assert!(buf[4096 * 3..4096 * 5].iter().all(|&b| b == 0x42));
        assert!(buf[4096 * 5..].iter().all(|&b| b == 0xFE));
    }

    #[test]
    fn two_regions_in_same_destination_file_at_dst_offset() {
        let src_a = make_memfd(0);
        sparse_layout(&src_a, 4096 * 16, &[(4096, 4096 * 2, 0xAA)]);
        let src_b = make_memfd(0);
        sparse_layout(&src_b, 4096 * 16, &[(4096 * 5, 4096 * 3, 0xBB)]);

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let dst = tmp.reopen().unwrap();
        sparse_layout(&dst, 4096 * 32, &[]);

        let _ = write_region_sparse(&src_a, 0, &dst, 0, 4096 * 16).unwrap();
        let _ = write_region_sparse(&src_b, 0, &dst, 4096 * 16, 4096 * 16).unwrap();

        let buf = std::fs::read(tmp.path()).unwrap();
        assert!(buf[..4096].iter().all(|&b| b == 0));
        assert!(buf[4096..4096 * 3].iter().all(|&b| b == 0xAA));
        assert!(buf[4096 * 3..4096 * 16].iter().all(|&b| b == 0));
        assert!(buf[4096 * 16..4096 * 21].iter().all(|&b| b == 0));
        assert!(buf[4096 * 21..4096 * 24].iter().all(|&b| b == 0xBB));
        assert!(buf[4096 * 24..].iter().all(|&b| b == 0));
    }

    #[test]
    fn extent_at_non_zero_src_offset() {
        let src = make_memfd(0);
        sparse_layout(&src, 4096 * 32, &[(4096 * 20, 4096 * 2, 0x77)]);

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let dst = tmp.reopen().unwrap();
        sparse_layout(&dst, 4096 * 16, &[]);

        let used = write_region_sparse(&src, 4096 * 16, &dst, 0, 4096 * 16).unwrap();
        assert!(used);

        let buf = std::fs::read(tmp.path()).unwrap();
        assert!(buf[..4096 * 4].iter().all(|&b| b == 0));
        assert!(buf[4096 * 4..4096 * 6].iter().all(|&b| b == 0x77));
        assert!(buf[4096 * 6..].iter().all(|&b| b == 0));
    }

    /// Round-trip: write two regions sparsely into a snapshot file, then
    /// read them back using the same next_data_extent + read_at pattern
    /// that fill_saved_regions uses. Verifies the restore path recovers
    /// the original content including holes.
    #[test]
    fn round_trip_sparse_write_then_read() {
        let src_a = make_memfd(0);
        sparse_layout(&src_a, 4096 * 16, &[(4096 * 2, 4096 * 3, 0xAA)]);

        let src_b = make_memfd(0);
        sparse_layout(&src_b, 4096 * 16, &[(4096 * 10, 4096 * 4, 0xBB)]);

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let dst = tmp.reopen().unwrap();
        let total = 4096u64 * 32;
        sparse_layout(&dst, total, &[]);

        write_region_sparse(&src_a, 0, &dst, 0, 4096 * 16).unwrap();
        write_region_sparse(&src_b, 0, &dst, 4096 * 16, 4096 * 16).unwrap();

        // Read back using next_data_extent + read_at, mirroring
        // fill_saved_regions's sparse restore path.
        let snap = tmp.reopen().unwrap();
        let regions: Vec<(u64, u64)> = vec![(0, 4096 * 16), (4096 * 16, 4096 * 16)];
        let mut restored = vec![0u8; total as usize];

        for &(file_cursor, region_len) in &regions {
            let end = file_cursor + region_len;
            let mut cursor = file_cursor;
            while let Some((data_off, ext_len)) =
                next_data_extent(snap.as_fd(), cursor, end).unwrap()
            {
                let in_region = (data_off - file_cursor) as usize;
                let dst_start = file_cursor as usize + in_region;
                snap.read_at(
                    &mut restored[dst_start..dst_start + ext_len as usize],
                    data_off,
                )
                .unwrap();
                cursor = data_off + ext_len;
            }
        }

        // Verify content matches a dense read.
        let dense = std::fs::read(tmp.path()).unwrap();
        assert_eq!(restored, dense);

        // Verify the actual data landed in the right places.
        assert!(restored[..4096 * 2].iter().all(|&b| b == 0));
        assert!(restored[4096 * 2..4096 * 5].iter().all(|&b| b == 0xAA));
        assert!(restored[4096 * 5..4096 * 26].iter().all(|&b| b == 0));
        assert!(restored[4096 * 26..4096 * 30].iter().all(|&b| b == 0xBB));
        assert!(restored[4096 * 30..].iter().all(|&b| b == 0));
    }
}
