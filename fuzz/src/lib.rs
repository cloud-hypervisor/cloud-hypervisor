// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Shared harness code for the fuzz targets.

pub mod disk_engine;

/// Reads the fuzzer input cyclically, so that short inputs can drive long
/// operation sequences. An empty input reads as zeros.
pub struct FuzzCursor<'a> {
    bytes: &'a [u8],
    index: usize,
}

impl<'a> FuzzCursor<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self::with_index(bytes, 0)
    }

    pub fn with_index(bytes: &'a [u8], index: usize) -> Self {
        Self { bytes, index }
    }

    pub fn next_u8(&mut self) -> u8 {
        if self.bytes.is_empty() {
            return 0;
        }
        let value = self.bytes[self.index % self.bytes.len()];
        self.index = self.index.wrapping_add(1);
        value
    }

    pub fn next_u16(&mut self) -> u16 {
        u16::from_le_bytes([self.next_u8(), self.next_u8()])
    }

    pub fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes([
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
        ])
    }

    pub fn next_u64(&mut self) -> u64 {
        u64::from_le_bytes([
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
        ])
    }

    pub fn next_bool(&mut self) -> bool {
        self.next_u8() & 1 != 0
    }

    pub fn fill_slice(&mut self, out: &mut [u8]) {
        for b in out {
            *b = self.next_u8();
        }
    }
}
