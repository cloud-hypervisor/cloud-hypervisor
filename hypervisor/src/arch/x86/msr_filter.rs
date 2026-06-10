// Copyright © 2025 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

/// Parameters for filtering read and/or write accesses to a range of MSRs.
#[derive(Debug, Clone, Copy, Default)]
pub struct MsrFilterRange<'a> {
    /// The type of operation(s) to filter: `1 << 0`, `1 << 1`, `(1 << 0) | (1 << 1)` refers to read, write, read and write respectively.
    // TODO: Consider using an enum here
    pub flags: u32,
    /// The number of MSRs in this filter range.
    pub nmsrs: u32,
    /// The first MSR index the bitmap starts at.
    pub base: u32,
    /// For bit position P ( 0 <= P <= nmsrs), the operations in `flags` are allowed for MSR:= base + P if the bit is set, otherwise they are denied.
    pub bitmap: &'a [u8],
}

impl<'a> MsrFilterRange<'a> {
    /// Modify the `flags` so that the ops in the bitmap refer to both reads and writes.
    pub fn with_read_write_flags(mut self) -> Self {
        self.flags = 1 | (1 << 1);
        self
    }
}
