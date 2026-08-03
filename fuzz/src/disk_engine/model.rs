// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Shadow model of the disk contents. Bytes an op leaves unpredictable are
//! marked unknown and not checked.

/// Known contents of a disk, byte by byte.
pub struct Model {
    data: Vec<u8>,
    unknown: Vec<bool>,
}

impl Model {
    /// A model of a blank `size` byte disk.
    pub fn new(size: usize) -> Self {
        Self {
            data: vec![0; size],
            unknown: vec![false; size],
        }
    }

    /// Records a write of `bytes` at `offset`.
    pub fn record_write(&mut self, offset: u64, bytes: &[u8]) {
        let Some(range) = self.range(offset, bytes.len()) else {
            return;
        };
        let written = range.end - range.start;
        self.data[range.clone()].copy_from_slice(&bytes[..written]);
        self.unknown[range].fill(false);
    }

    /// Records that `len` bytes at `offset` now read back as zeroes.
    pub fn record_zeroes(&mut self, offset: u64, len: usize) {
        let Some(range) = self.range(offset, len) else {
            return;
        };
        self.data[range.clone()].fill(0);
        self.unknown[range].fill(false);
    }

    /// Records that `len` bytes at `offset` are unpredictable.
    pub fn record_unknown(&mut self, offset: u64, len: usize) {
        let Some(range) = self.range(offset, len) else {
            return;
        };
        self.unknown[range].fill(true);
    }

    /// Checks `bytes` read at `offset`, describing the first mismatch.
    pub fn check(&self, offset: u64, bytes: &[u8]) -> Result<(), String> {
        let Some(range) = self.range(offset, bytes.len()) else {
            return Ok(());
        };

        for (i, index) in range.enumerate() {
            if self.unknown[index] {
                continue;
            }
            if bytes[i] != self.data[index] {
                return Err(format!(
                    "offset {} byte {i}: read {:#04x}, model {:#04x}",
                    offset, bytes[i], self.data[index]
                ));
            }
        }

        Ok(())
    }

    /// Resizes the model, dropping all knowledge of the contents.
    pub fn resize(&mut self, size: usize) {
        self.data.clear();
        self.data.resize(size, 0);
        self.unknown.clear();
        self.unknown.resize(size, true);
    }

    /// Clips `offset` and `len` to the modelled range.
    fn range(&self, offset: u64, len: usize) -> Option<std::ops::Range<usize>> {
        let start = usize::try_from(offset).ok()?;
        if start >= self.data.len() || len == 0 {
            return None;
        }
        let end = start.saturating_add(len).min(self.data.len());
        Some(start..end)
    }
}
