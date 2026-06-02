// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::os::fd::RawFd;

use super::aligned_range;
use crate::async_io::{AsyncIoOperation, OwnedIoBuffer};
use crate::pwrite_all;

/// Read into `buf` from `fd` at `offset`. Loops on short reads,
/// retries `EINTR`, and zero pads the tail past EOF so the caller
/// always sees a fully populated buffer. Returns the number of bytes
/// actually read from the file (zero padding excluded).
fn pread_padded(fd: RawFd, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        let off = i64::try_from(offset + total as u64)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        // SAFETY: buf[total..] is a valid mutable slice of buf.len() - total bytes.
        let n =
            unsafe { libc::pread64(fd, buf[total..].as_mut_ptr().cast(), buf.len() - total, off) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            break;
        }
        total += n as usize;
    }
    buf[total..].fill(0);
    Ok(total)
}

/// Run `op` against `fd` via an aligned bounce buffer. `alignment`
/// must be a power of two. Returns the number of logical bytes moved.
pub fn submit_rmw(fd: RawFd, op: &mut AsyncIoOperation, alignment: u64) -> io::Result<i64> {
    let offset =
        u64::try_from(op.offset()).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let total_len = op.total_len() as u64;
    let range = aligned_range(offset, total_len, alignment)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty or overflowing range"))?;

    let mut bounce = OwnedIoBuffer::new(range.aligned_len as usize, alignment as usize)?;
    let head = range.head_pad as usize;
    let tail = head + total_len as usize;

    if op.is_read() {
        pread_padded(fd, bounce.as_mut_slice(), range.aligned_offset)?;
        op.write_bytes_at(0, &bounce.as_slice()[head..tail])?;
    } else {
        if range.head_pad != 0 || range.tail_pad != 0 {
            if range.aligned_len <= alignment {
                pread_padded(
                    fd,
                    &mut bounce.as_mut_slice()[..alignment as usize],
                    range.aligned_offset,
                )?;
            } else {
                if range.head_pad != 0 {
                    pread_padded(
                        fd,
                        &mut bounce.as_mut_slice()[..alignment as usize],
                        range.aligned_offset,
                    )?;
                }
                if range.tail_pad != 0 {
                    let tail_off = (range.aligned_len - alignment) as usize;
                    let disk_off = range.aligned_offset + tail_off as u64;
                    pread_padded(fd, &mut bounce.as_mut_slice()[tail_off..], disk_off)?;
                }
            }
        }
        op.read_bytes_at(0, &mut bounce.as_mut_slice()[head..tail])?;
        pwrite_all(fd, bounce.as_slice(), range.aligned_offset)?;
    }

    Ok(total_len as i64)
}

/// Read `buf.len()` bytes from `fd` at `offset`, routing through an
/// aligned bounce buffer when needed. Bytes past EOF are zero filled.
pub fn pread_aligned(fd: RawFd, buf: &mut [u8], offset: u64, alignment: u64) -> io::Result<()> {
    if alignment == 0 || slice_is_aligned(buf, offset, alignment) {
        pread_padded(fd, buf, offset)?;
        return Ok(());
    }

    let range = aligned_range(offset, buf.len() as u64, alignment)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty or overflowing range"))?;
    let mut bounce = OwnedIoBuffer::new(range.aligned_len as usize, alignment as usize)?;
    pread_padded(fd, bounce.as_mut_slice(), range.aligned_offset)?;
    let head = range.head_pad as usize;
    buf.copy_from_slice(&bounce.as_slice()[head..head + buf.len()]);
    Ok(())
}

/// Write `buf` to `fd` at `offset`, routing through an aligned bounce
/// buffer when needed, preserving any surrounding bytes in the head
/// and tail blocks.
pub fn pwrite_aligned(fd: RawFd, buf: &[u8], offset: u64, alignment: u64) -> io::Result<()> {
    if alignment == 0 || slice_is_aligned(buf, offset, alignment) {
        pwrite_all(fd, buf, offset)?;
        return Ok(());
    }

    let range = aligned_range(offset, buf.len() as u64, alignment)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty or overflowing range"))?;
    let mut bounce = OwnedIoBuffer::new(range.aligned_len as usize, alignment as usize)?;
    pread_padded(fd, bounce.as_mut_slice(), range.aligned_offset)?;
    let head = range.head_pad as usize;
    bounce.as_mut_slice()[head..head + buf.len()].copy_from_slice(buf);
    pwrite_all(fd, bounce.as_slice(), range.aligned_offset)?;
    Ok(())
}

fn slice_is_aligned(buf: &[u8], offset: u64, alignment: u64) -> bool {
    let a = alignment as usize;
    (buf.as_ptr() as usize).is_multiple_of(a)
        && buf.len().is_multiple_of(a)
        && (offset as usize).is_multiple_of(a)
}

#[cfg(test)]
mod unit_tests {
    use std::io::Write;
    use std::os::fd::AsRawFd;

    use vmm_sys_util::tempfile::TempFile;

    use super::*;

    fn submit_rmw_read(fd: RawFd, offset: u64, len: usize, alignment: u64) -> Vec<u8> {
        let buf = OwnedIoBuffer::from_vec(vec![0u8; len]);
        let mut op = AsyncIoOperation::read_to_vec(offset as libc::off_t, buf, 0);
        let n = submit_rmw(fd, &mut op, alignment).unwrap();
        assert_eq!(n, len as i64);
        op.into_completion_buffer().unwrap().as_slice().to_vec()
    }

    fn submit_rmw_write(fd: RawFd, offset: u64, data: &[u8], alignment: u64) {
        let buf = OwnedIoBuffer::from_vec(data.to_vec());
        let mut op = AsyncIoOperation::write_from_vec(offset as libc::off_t, buf, 0);
        let n = submit_rmw(fd, &mut op, alignment).unwrap();
        assert_eq!(n, data.len() as i64);
    }

    fn pattern(range: std::ops::Range<usize>) -> Vec<u8> {
        range.map(|i| (i % 251) as u8).collect()
    }

    fn create_pattern_file(size: usize) -> (TempFile, RawFd) {
        let tf = TempFile::new().unwrap();
        let mut f = tf.as_file();
        f.write_all(&pattern(0..size)).unwrap();
        let fd = f.as_raw_fd();
        (tf, fd)
    }

    fn read_back(fd: RawFd, size: usize) -> Vec<u8> {
        let mut out = vec![0u8; size];
        let n = pread_padded(fd, &mut out, 0).unwrap();
        assert_eq!(n, size);
        out
    }

    #[test]
    fn submit_rmw_pread_cases() {
        let cases: &[(usize, u64, usize, &str)] = &[
            (8192, 100, 4096 - 100, "head only"),
            (8192, 0, 100, "tail only"),
            (8192, 100, 200, "head and tail in same block"),
            (16384, 100, 8200, "multi block span"),
        ];
        for &(file_size, offset, len, label) in cases {
            let (_tf, fd) = create_pattern_file(file_size);
            let got = submit_rmw_read(fd, offset, len, 4096);
            let expected = pattern(offset as usize..offset as usize + len);
            assert_eq!(got, expected, "case {label}");
        }
    }

    #[test]
    fn submit_rmw_pwrite_cases() {
        let cases: &[(usize, u64, usize, &str)] = &[
            (8192, 100, 4096 - 100, "head only"),
            (8192, 0, 100, "tail only"),
            (8192, 100, 200, "head and tail in same block"),
            (16384, 100, 8200, "multi block span"),
        ];
        for &(file_size, offset, len, label) in cases {
            let (_tf, fd) = create_pattern_file(file_size);
            let data: Vec<u8> = (0..len).map(|i| ((i + 1) % 239) as u8).collect();
            submit_rmw_write(fd, offset, &data, 4096);
            let whole = read_back(fd, file_size);
            let off = offset as usize;
            assert_eq!(&whole[..off], &pattern(0..off)[..], "before {label}");
            assert_eq!(&whole[off..off + len], &data[..], "written {label}");
            assert_eq!(
                &whole[off + len..],
                &pattern(off + len..file_size)[..],
                "after {label}"
            );
        }
    }
}
