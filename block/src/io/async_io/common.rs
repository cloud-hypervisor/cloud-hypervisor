// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

//! Helpers used by both aio and uring async io.

use std::collections::HashSet;
use std::io;

use super::AsyncIoOperation;

/// Converts an I/O error into the negative errno form used in completions.
pub(super) fn errno_result(error: &io::Error) -> i32 {
    -error.raw_os_error().unwrap_or(libc::EIO)
}

/// Builds the error returned when a new request reuses in-flight `user_data`.
pub(super) fn duplicate_user_data_error(user_data: u64) -> io::Error {
    io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!("duplicate async I/O user_data {user_data}"),
    )
}

/// Validates that a batch has unique `user_data` not already in flight.
pub(super) fn validate_batch<F>(mut is_in_flight: F, batch: &[AsyncIoOperation]) -> io::Result<()>
where
    F: FnMut(u64) -> bool,
{
    let mut seen = HashSet::with_capacity(batch.len());

    for op in batch {
        let user_data = op.user_data();
        if is_in_flight(user_data) || !seen.insert(user_data) {
            return Err(duplicate_user_data_error(user_data));
        }
    }

    Ok(())
}
