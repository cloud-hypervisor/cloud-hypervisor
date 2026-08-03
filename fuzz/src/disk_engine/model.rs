// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Shadow model of the disk contents.
//!
//! The model tracks what the guest visible contents of the disk must be after
//! the ops the executor has run so far. It is only usable when the fuzzer
//! starts from a valid template image whose contents are known, so the image
//! parsing targets run without it.
//!
//! Every byte is either known, and then the model holds its value, or
//! unknown, and then it is skipped when read back data is checked. Ops that
//! only partially succeed, or whose effect on the contents is not guaranteed
//! by the format, mark their range unknown rather than guessing.

/// Known contents of a disk, byte by byte.
pub struct Model {
    data: Vec<u8>,
    unknown: Vec<bool>,
}

impl Model {
    /// Creates a model of a freshly created image of `size` bytes, which
    /// reads back as all zeroes.
    pub fn new(size: usize) -> Self {
        Self {
            data: vec![0; size],
            unknown: vec![false; size],
        }
    }

    /// Returns the modelled disk size in bytes.
    pub fn len(&self) -> usize {
        self.data.len()
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

    /// Records that the contents of `len` bytes at `offset` are no longer
    /// predictable.
    pub fn record_unknown(&mut self, offset: u64, len: usize) {
        let Some(range) = self.range(offset, len) else {
            return;
        };
        self.unknown[range].fill(true);
    }

    /// Checks read back `bytes` from `offset` against the model.
    ///
    /// Returns a description of the first mismatch, if any.
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
