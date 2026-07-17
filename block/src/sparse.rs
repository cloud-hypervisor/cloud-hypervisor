// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

// Helpers for issuing `BLKDISCARD` / `BLKZEROOUT` ioctls on block devices,
// and the `punch_hole` / `write_zeroes` dispatchers used by the raw I/O
// backends.
//
// The kernel ioctl numbers and argument layout are stable userspace ABI
// (see `include/uapi/linux/fs.h`):
//
// ```c
// #define BLKDISCARD  _IO(0x12, 119)   /* arg: const __u64 range[2] = { start, len } */
// #define BLKZEROOUT  _IO(0x12, 127)   /* arg: const __u64 range[2] = { start, len } */
// ```
//
// The kernel does `copy_from_user(range, arg, sizeof(range))`, i.e. it reads
// 16 bytes through the single pointer it is given, so we must pass a single
// `__u64[2]` array rather than two separate `*const u64` pointers.

use std::io;
use std::os::unix::io::{AsRawFd, RawFd};

use vmm_sys_util::write_zeroes::{PunchHole, WriteZeroesAt};

use crate::AlignedFile;

// `_IO(0x12, 119)` — issue a discard request to a block device.
pub const BLKDISCARD: libc::c_ulong = 0x1277;
// `_IO(0x12, 127)` — write zeroes to a range of a block device, with a
// kernel-side fallback to writing zero pages when the hardware has no native
// `WRITE_ZEROES`.
pub const BLKZEROOUT: libc::c_ulong = 0x127f;

// Issue a `BLK*` range ioctl with proper `[start, len]` argument.
fn blk_range_ioctl(fd: RawFd, request: libc::c_ulong, offset: u64, length: u64) -> io::Result<()> {
    let range: [u64; 2] = [offset, length];
    // SAFETY: `fd` is a valid block-device fd owned by the caller; `&range`
    // is a 16-byte array matching the kernel's expected `__u64[2]` layout
    // and lives for the duration of the call.
    let ret = unsafe { libc::ioctl(fd, request as _, &range) };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

// Discard (TRIM/UNMAP) the byte range `[offset, offset + length)` on the
// block device referenced by `fd`.
pub(crate) fn blkdiscard(fd: RawFd, offset: u64, length: u64) -> io::Result<()> {
    blk_range_ioctl(fd, BLKDISCARD, offset, length)
}

// Zero the byte range `[offset, offset + length)` on the block device
// referenced by `fd`. The kernel falls back to writing explicit zero pages
// when the device has no hardware `WRITE_ZEROES`.
pub(crate) fn blkzeroout(fd: RawFd, offset: u64, length: u64) -> io::Result<()> {
    blk_range_ioctl(fd, BLKZEROOUT, offset, length)
}

// Punch a hole in `fd` over the byte range `[offset, offset + length)`.
//
// On block devices the kernel rejects `fallocate(PUNCH_HOLE)` (notably ZFS
// zvols), so route through `BLKDISCARD` instead. On regular files use
// `PunchHole`, falling back to `WriteZeroesAt` on EOPNOTSUPP (e.g. tmpfs).
pub(crate) fn punch_hole(
    file: &mut AlignedFile,
    is_blkdev: bool,
    offset: u64,
    length: u64,
) -> io::Result<()> {
    if is_blkdev {
        return match blkdiscard(file.as_raw_fd(), offset, length) {
            Ok(()) => Ok(()),
            Err(e) if e.raw_os_error() == Some(libc::EOPNOTSUPP) => Ok(()),
            Err(e) => Err(e),
        };
    }
    match file.punch_hole(offset, length) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::EOPNOTSUPP) => {
            file.write_all_zeroes_at(offset, length as usize)?;
            Ok(())
        }
        Err(e) => Err(e),
    }
}

// Zero the byte range `[offset, offset + length)` in `fd`.
//
// Uses `BLKZEROOUT` on block devices (see [`punch_hole`] for the rationale)
// and `WriteZeroesAt` on regular files, which tries fallocate and falls
// back to positional writes on EOPNOTSUPP (e.g. tmpfs).
pub(crate) fn write_zeroes(
    file: &mut AlignedFile,
    is_blkdev: bool,
    offset: u64,
    length: u64,
) -> io::Result<()> {
    if is_blkdev {
        return blkzeroout(file.as_raw_fd(), offset, length);
    }
    file.write_all_zeroes_at(offset, length as usize)?;
    Ok(())
}

