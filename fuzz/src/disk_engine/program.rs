// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Op program driven against the disk image engine.

use arbitrary::Arbitrary;

use crate::disk_engine::format::OpenConfig;

/// Largest number of ops executed from one program.
pub const MAX_OPS: usize = 64;

/// Largest byte count for a single data op.
///
/// This also sizes the guest memory region shared by all guest memory ops.
pub const MAX_OP_LEN: usize = 64 << 10;

/// A disk offset selected by the fuzzer.
///
/// The in range variants keep offsets inside the disk, where the interesting
/// translation logic lives, while [`OpOffset::Wild`] reaches the overflow and
/// out of bounds checks.
#[derive(Arbitrary, Clone, Copy, Debug)]
pub enum OpOffset {
    /// Sector index, wrapped into the reported size.
    Sector(u16),
    /// Byte offset, wrapped into the reported size.
    Byte(u32),
    /// Position at `size * n / 256`, so a program can name the middle or the
    /// tail of a disk of any size.
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

/// The fixed program run by the image parsing targets.
///
/// It walks the whole capability surface once with a bounded amount of I/O:
/// reads at the start, middle and tail, writes and read backs, both sparse
/// ops, a flush, a clone, a resize, and finally offsets that no image can
/// satisfy.
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
