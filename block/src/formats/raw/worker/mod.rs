// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Sync/async I/O workers for raw images.
//!
//! Each backend implements the [`AsyncIo`](crate::async_io::AsyncIo)
//! trait.

use std::os::unix::fs::FileExt;

use crate::AlignedFile;
use crate::async_io::{AsyncIoError, AsyncIoOperation, AsyncIoResult};

pub(crate) mod async_aio;
#[cfg(feature = "io_uring")]
pub(crate) mod async_uring;
pub(crate) mod sync;
#[cfg(test)]
pub(crate) mod tests;

/// True when `op` satisfies `alignment` and can go straight to the kernel.
pub(crate) fn operation_is_aligned(op: &AsyncIoOperation, alignment: u64) -> bool {
    if alignment == 0 {
        return true;
    }
    if !(op.offset() as u64).is_multiple_of(alignment) {
        return false;
    }
    op.iovecs().iter().all(|iov| {
        (iov.iov_base as u64).is_multiple_of(alignment)
            && (iov.iov_len as u64).is_multiple_of(alignment)
    })
}

/// Runs an unaligned O_DIRECT operation synchronously through `aligned_file`.
pub(crate) fn run_unaligned_operation(
    aligned_file: &AlignedFile,
    op: &mut AsyncIoOperation,
) -> AsyncIoResult<i32> {
    let offset = op.offset() as u64;
    let total_len = op.total_len();
    let mut buf = vec![0u8; total_len];

    if op.is_read() {
        let n = aligned_file
            .read_at(&mut buf, offset)
            .map_err(AsyncIoError::ReadVectored)?;
        op.write_bytes_at(0, &buf[..n])
            .map_err(AsyncIoError::ReadVectored)?;
        Ok(n as i32)
    } else {
        op.read_bytes_at(0, &mut buf)
            .map_err(AsyncIoError::WriteVectored)?;
        let n = aligned_file
            .write_at(&buf, offset)
            .map_err(AsyncIoError::WriteVectored)?;
        Ok(n as i32)
    }
}
