// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Shared I/O infrastructure for all disk format backends.
//!
//! Contains the async I/O trait, request handling, and file locking
//! helpers.

pub mod async_io;
pub mod fcntl;
pub mod request;

use std::io;
use std::os::fd::RawFd;

/// Write all of `buf` to `fd` at `offset` via `pwrite64`. Loops on
/// short writes, retries `EINTR`, and returns `WriteZero` if the
/// syscall returns zero before the buffer is exhausted.
pub(crate) fn pwrite_all(fd: RawFd, buf: &[u8], offset: u64) -> io::Result<()> {
    let mut total = 0;
    while total < buf.len() {
        let off = i64::try_from(offset + total as u64)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        // SAFETY: buf[total..] is a valid slice of buf.len() - total bytes.
        let n = unsafe { libc::pwrite64(fd, buf[total..].as_ptr().cast(), buf.len() - total, off) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            return Err(io::Error::from(io::ErrorKind::WriteZero));
        }
        total += n as usize;
    }
    Ok(())
}
