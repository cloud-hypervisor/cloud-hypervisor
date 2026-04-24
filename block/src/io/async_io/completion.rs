// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use super::{AsyncIoOperation, OwnedIoBuffer};

/// Completion returned by an owned async I/O backend.
///
/// The completion carries the caller provided `user_data`, the result,
/// and any owned buffer that can now be dropped.
#[derive(Debug)]
pub struct AsyncIoCompletion {
    /// Caller provided identifier associated with the submitted operation.
    pub user_data: u64,
    /// I/O result reported by the backend.
    ///
    /// Successful operations report a non-negative byte count. Failed
    /// operations report a negative errno value.
    pub result: i32,
    /// The backing buffer that can now be dropped or re-used.
    pub buffer: Option<OwnedIoBuffer>,
}

impl AsyncIoCompletion {
    /// Creates a completion from its parts.
    pub fn new(user_data: u64, result: i32, buffer: Option<OwnedIoBuffer>) -> Self {
        Self {
            user_data,
            result,
            buffer,
        }
    }

    /// Creates a completion by consuming the operation that just completed.
    ///
    /// This returns ownership of any completion buffer carried by the
    /// operation.
    pub fn from_operation(op: AsyncIoOperation, result: i32) -> Self {
        let user_data = op.user_data();
        Self::new(user_data, result, op.into_completion_buffer())
    }
}
