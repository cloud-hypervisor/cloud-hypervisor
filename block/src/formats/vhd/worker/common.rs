// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io;

use crate::async_io::{AsyncIoError, AsyncIoOperation, AsyncIoResult};

pub(super) fn validate_operation_bounds(op: &AsyncIoOperation, size: u64) -> AsyncIoResult<()> {
    let offset = u64::try_from(op.offset()).map_err(|_| bounds_error(op, size))?;
    let len = u64::try_from(op.total_len()).map_err(|_| bounds_error(op, size))?;
    let end = offset
        .checked_add(len)
        .ok_or_else(|| bounds_error(op, size))?;

    if end > size {
        return Err(bounds_error(op, size));
    }

    Ok(())
}

fn bounds_error(op: &AsyncIoOperation, size: u64) -> AsyncIoError {
    let error = io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "Invalid request offset {} and length {}, can't exceed file size {}",
            op.offset(),
            op.total_len(),
            size
        ),
    );
    if op.is_read() {
        AsyncIoError::ReadVectored(error)
    } else {
        AsyncIoError::WriteVectored(error)
    }
}
