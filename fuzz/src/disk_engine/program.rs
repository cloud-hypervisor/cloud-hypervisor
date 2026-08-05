// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Op program driven against the disk image engine.

use arbitrary::Arbitrary;

use crate::disk_engine::format::OpenConfig;

/// Largest number of ops executed from one program.
pub const MAX_OPS: usize = 64;

/// Bytes covered by one L2 table of the small cluster qcow2 template.
const L2_SPAN: u64 = crate::disk_engine::formats::qcow2::SMALL_L2_SPAN;

/// Largest number of L2 tables one [`Op::Sweep`] walks: more than the 100
/// the qcow2 engine caches. Sweeps longer than the template wrap around.
const MAX_SWEEP: u64 = 192;

/// Largest byte count of a data op, and the size of guest memory.
pub const MAX_OP_LEN: usize = 64 << 10;

/// A disk offset. [`OpOffset::Wild`] reaches the bounds checks.
#[derive(Arbitrary, Clone, Copy, Debug)]
pub enum OpOffset {
    /// Sector index, wrapped into the reported size.
    Sector(u16),
    /// Byte offset, wrapped into the reported size.
    Byte(u32),
    /// Position `size * n / 256`.
    Fraction(u8),
    /// Offset used unmodified, including values that do not fit an `off_t`.
    Wild(u64),
}

impl OpOffset {
    /// Resolves the offset against a disk of `size` bytes.
    pub fn resolve(self, size: u64) -> u64 {
        let size = size.max(1);
        match self {
            OpOffset::Sector(sector) => (u64::from(sector) * 512) % size,
            OpOffset::Byte(offset) => u64::from(offset) % size,
            OpOffset::Fraction(n) => size / 256 * u64::from(n),
            OpOffset::Wild(offset) => offset,
        }
    }
}

/// A byte count for a data op, capped at [`MAX_OP_LEN`].
#[derive(Arbitrary, Clone, Copy, Debug)]
pub struct OpLen(pub u16);

impl OpLen {
    /// Returns the capped byte count.
    pub fn get(self) -> usize {
        usize::from(self.0).min(MAX_OP_LEN)
    }
}

/// One operation on the engine.
#[derive(Arbitrary, Clone, Debug)]
pub enum Op {
    /// Read into an owned host buffer.
    ReadVec { offset: OpOffset, len: OpLen },
    /// Write from an owned host buffer.
    WriteVec {
        offset: OpOffset,
        len: OpLen,
        seed: u8,
    },
    /// Read into guest memory.
    ReadMem { offset: OpOffset, len: OpLen },
    /// Write from guest memory.
    WriteMem {
        offset: OpOffset,
        len: OpLen,
        seed: u8,
    },
    /// Discard a range, dropping its allocation.
    PunchHole { offset: OpOffset, len: OpLen },
    /// Zero a range, possibly through a metadata flag.
    WriteZeroes { offset: OpOffset, len: OpLen },
    /// Flush, with or without asking for a completion.
    Fsync { completion: bool },
    /// Resize the disk, in KiB, capped by the executor.
    Resize { size_kib: u16 },
    /// Replace the I/O engine with a freshly created one.
    RecreateIo { ring_depth: u8 },
    /// Continue on an I/O engine created from a cloned disk handle.
    UseClone { ring_depth: u8 },
    /// Query every capability trait.
    QueryCaps,
    /// Write one sector into each of a run of L2 tables, then read them all
    /// back, so a table the cache evicts badly shows up as a mismatch.
    Sweep { first: u8, tables: u8, seed: u8 },
}

impl Op {
    /// Returns the offsets one [`Op::Sweep`] writes.
    pub fn sweep_offsets(first: u8, tables: u8, size: u64) -> impl Iterator<Item = u64> {
        let size = size.max(1);
        let count = u64::from(tables) % MAX_SWEEP + 1;
        let first = u64::from(first);
        (0..count).map(move |i| (first + i) * L2_SPAN % size)
    }
}

/// An open configuration plus the ops to run against it.
#[derive(Arbitrary, Debug)]
pub struct Program {
    /// How the image is opened.
    pub open: OpenConfig,
    /// Which of the format's template images to run against.
    pub template: u8,
    /// Ring depth for the first I/O engine.
    pub ring_depth: u8,
    /// Ops to execute, truncated to [`MAX_OPS`].
    pub ops: Vec<Op>,
}

impl Program {
    /// Returns the ops to execute.
    pub fn ops(&self) -> &[Op] {
        let len = self.ops.len().min(MAX_OPS);
        &self.ops[..len]
    }

    /// Returns a usable ring depth.
    pub fn ring_depth(&self) -> u32 {
        ring_depth(self.ring_depth)
    }
}

/// Maps a fuzzer byte to a ring depth accepted by the engine.
pub fn ring_depth(raw: u8) -> u32 {
    u32::from(raw) % 64 + 1
}

/// The fixed program the image targets run: every op once, with bounded
/// I/O, then offsets no image can satisfy.
pub fn default_program() -> Vec<Op> {
    vec![
        Op::QueryCaps,
        Op::ReadVec {
            offset: OpOffset::Byte(0),
            len: OpLen(4096),
        },
        Op::ReadVec {
            offset: OpOffset::Fraction(128),
            len: OpLen(65535),
        },
        Op::ReadMem {
            offset: OpOffset::Fraction(255),
            len: OpLen(512),
        },
        Op::WriteVec {
            offset: OpOffset::Byte(0),
            len: OpLen(4096),
            seed: 0xa5,
        },
        Op::WriteMem {
            offset: OpOffset::Fraction(128),
            len: OpLen(8192),
            seed: 0x5a,
        },
        Op::Fsync { completion: true },
        Op::ReadVec {
            offset: OpOffset::Byte(0),
            len: OpLen(4096),
        },
        Op::WriteZeroes {
            offset: OpOffset::Fraction(128),
            len: OpLen(8192),
        },
        Op::PunchHole {
            offset: OpOffset::Fraction(64),
            len: OpLen(8192),
        },
        Op::ReadVec {
            offset: OpOffset::Fraction(64),
            len: OpLen(8192),
        },
        Op::UseClone { ring_depth: 16 },
        Op::ReadVec {
            offset: OpOffset::Sector(1),
            len: OpLen(512),
        },
        Op::Resize { size_kib: 4096 },
        Op::WriteVec {
            offset: OpOffset::Fraction(255),
            len: OpLen(512),
            seed: 0x3c,
        },
        Op::RecreateIo { ring_depth: 1 },
        Op::ReadVec {
            offset: OpOffset::Wild(u64::MAX - 511),
            len: OpLen(512),
        },
        Op::WriteVec {
            offset: OpOffset::Wild(1 << 63),
            len: OpLen(512),
            seed: 0xff,
        },
        Op::Fsync { completion: false },
        Op::QueryCaps,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    // One sweep must cover more than 100 distinct, table aligned offsets.
    #[test]
    fn a_sweep_can_outrun_the_l2_cache() {
        let size = 4 << 20;
        let offsets: Vec<u64> = Op::sweep_offsets(0, 191, size).collect();
        assert_eq!(offsets.len(), 192);

        let distinct: std::collections::BTreeSet<u64> = offsets.iter().copied().collect();
        assert!(
            distinct.len() > 100,
            "{} distinct tables, the cache holds 100",
            distinct.len()
        );
        for offset in offsets {
            assert!(offset < size, "offset {offset} is outside the disk");
            assert_eq!(offset % L2_SPAN, 0, "offset {offset} is not table aligned");
        }
    }

    // A sweep stays inside any disk.
    #[test]
    fn a_sweep_stays_inside_the_disk() {
        for size in [1, 512, 4096, L2_SPAN, 1 << 20] {
            for offset in Op::sweep_offsets(u8::MAX, u8::MAX, size) {
                assert!(offset < size.max(1), "size {size}, offset {offset}");
            }
        }
    }
}
