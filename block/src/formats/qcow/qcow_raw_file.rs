// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::fmt::Debug;
use std::io::{self, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};
use std::os::unix::fs::FileExt;

use byteorder::{BigEndian, WriteBytesExt};
use vmm_sys_util::write_zeroes::WriteZeroesAt;

use crate::aligned_file::AlignedFile;

// Type aliases for the refcount read/write function pointers
type RefcountReader = fn(&mut AlignedFile, u64, usize) -> io::Result<Vec<u64>>;
type RefcountWriter = fn(&mut AlignedFile, u64, &[u64]) -> io::Result<()>;

/// Big-endian file access trait.
pub(super) trait BeUint: Sized + Copy {
    fn from_be_slice(bytes: &[u8]) -> u64;
    fn write_be<W: Write>(w: &mut W, val: Self) -> io::Result<()>;
}

impl BeUint for u8 {
    #[inline(always)]
    fn from_be_slice(bytes: &[u8]) -> u64 {
        bytes[0] as u64
    }
    #[inline(always)]
    fn write_be<W: Write>(w: &mut W, val: Self) -> io::Result<()> {
        w.write_u8(val)
    }
}

impl BeUint for u16 {
    #[inline(always)]
    fn from_be_slice(bytes: &[u8]) -> u64 {
        u16::from_be_bytes([bytes[0], bytes[1]]) as u64
    }
    #[inline(always)]
    fn write_be<W: Write>(w: &mut W, val: Self) -> io::Result<()> {
        w.write_u16::<BigEndian>(val)
    }
}

impl BeUint for u32 {
    #[inline(always)]
    fn from_be_slice(bytes: &[u8]) -> u64 {
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64
    }
    #[inline(always)]
    fn write_be<W: Write>(w: &mut W, val: Self) -> io::Result<()> {
        w.write_u32::<BigEndian>(val)
    }
}

impl BeUint for u64 {
    #[inline(always)]
    fn from_be_slice(bytes: &[u8]) -> u64 {
        u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])
    }
    #[inline(always)]
    fn write_be<W: Write>(w: &mut W, val: Self) -> io::Result<()> {
        w.write_u64::<BigEndian>(val)
    }
}

/// Read byte-aligned refcounts.
fn read_refcount<T: BeUint>(
    file: &mut AlignedFile,
    offset: u64,
    count: usize,
) -> io::Result<Vec<u64>> {
    let bytes_per_entry = size_of::<T>();
    let mut data = vec![0u8; count * bytes_per_entry];
    file.read_exact_at(&mut data, offset)?;
    Ok(data
        .chunks_exact(bytes_per_entry)
        .map(T::from_be_slice)
        .collect())
}

/// Write byte-aligned refcounts.
fn write_refcount<T: BeUint + TryFrom<u64>>(
    file: &mut AlignedFile,
    offset: u64,
    table: &[u64],
) -> io::Result<()>
where
    <T as TryFrom<u64>>::Error: Debug,
{
    let bytes_per_entry = size_of::<T>();
    let mut buffer = Vec::with_capacity(table.len() * bytes_per_entry);
    for &val in table {
        let converted = T::try_from(val).expect("refcount values are validated on increment");
        T::write_be(&mut buffer, converted)?;
    }
    file.write_all_at(&buffer, offset)
}

/// Read sub-byte refcounts. Bit 0 is the least significant bit.
fn read_refcount_subbyte<const BITS: usize>(
    file: &mut AlignedFile,
    offset: u64,
    count: usize,
) -> io::Result<Vec<u64>> {
    const { assert!(BITS == 1 || BITS == 2 || BITS == 4) };
    let entries_per_byte = 8 / BITS;
    let mask = (1u64 << BITS) - 1;
    let bytes_needed = count.div_ceil(entries_per_byte);
    let mut bytes = vec![0u8; bytes_needed];
    file.read_exact_at(&mut bytes, offset)?;

    let mut table = vec![0u64; count];
    for (i, val) in table.iter_mut().enumerate() {
        let byte_idx = i / entries_per_byte;
        let bit_offset = (i % entries_per_byte) * BITS;
        *val = (bytes[byte_idx] as u64 >> bit_offset) & mask;
    }
    Ok(table)
}

/// Write sub-byte refcounts. Bit 0 is the least significant bit.
fn write_refcount_subbyte<const BITS: usize>(
    file: &mut AlignedFile,
    offset: u64,
    table: &[u64],
) -> io::Result<()> {
    const { assert!(BITS == 1 || BITS == 2 || BITS == 4) };
    let entries_per_byte = 8 / BITS;
    let mask = (1u64 << BITS) - 1;
    let mut buffer = Vec::with_capacity(table.len().div_ceil(entries_per_byte));

    for chunk in table.chunks(entries_per_byte) {
        let mut byte = 0u8;
        for (i, &val) in chunk.iter().enumerate() {
            let bit_offset = i * BITS;
            byte |= ((val & mask) << bit_offset) as u8;
        }
        buffer.push(byte);
    }
    file.write_all_at(&buffer, offset)
}

/// A qcow file. Allows reading/writing clusters and appending clusters.
#[derive(Debug)]
pub(super) struct QcowRawFile {
    file: AlignedFile,
    cluster_size: u64,
    cluster_mask: u64,
    refcount_block_entries: u64,
    read_refcount_fn: RefcountReader,
    write_refcount_fn: RefcountWriter,
}

impl QcowRawFile {
    /// Creates a `QcowRawFile` from the given `File`, `None` is returned if `cluster_size` is not
    /// a power of two or refcount_bits is invalid.
    pub(super) fn from(file: AlignedFile, cluster_size: u64, refcount_bits: u64) -> Option<Self> {
        if !cluster_size.is_power_of_two() {
            return None;
        }

        let (read_refcount_fn, write_refcount_fn): (RefcountReader, RefcountWriter) =
            match refcount_bits {
                1 => (read_refcount_subbyte::<1>, write_refcount_subbyte::<1>),
                2 => (read_refcount_subbyte::<2>, write_refcount_subbyte::<2>),
                4 => (read_refcount_subbyte::<4>, write_refcount_subbyte::<4>),
                8 => (read_refcount::<u8>, write_refcount::<u8>),
                16 => (read_refcount::<u16>, write_refcount::<u16>),
                32 => (read_refcount::<u32>, write_refcount::<u32>),
                64 => (read_refcount::<u64>, write_refcount::<u64>),
                _ => return None,
            };

        // For sub-byte refcounts (1,2,4 bits), entries pack multiple per byte
        let refcount_block_entries = cluster_size * 8 / refcount_bits;

        Some(QcowRawFile {
            file,
            cluster_size,
            cluster_mask: cluster_size - 1,
            refcount_block_entries,
            read_refcount_fn,
            write_refcount_fn,
        })
    }

    /// Reads `count` 64 bit offsets and returns them as a vector.
    /// `mask` optionally `&`s out some of the bits on the file.
    pub(super) fn read_pointer_table(
        &mut self,
        offset: u64,
        count: u64,
        mask: Option<u64>,
    ) -> io::Result<Vec<u64>> {
        let mut bytes = vec![0u8; count as usize * size_of::<u64>()];
        self.file.read_exact_at(&mut bytes, offset)?;
        let m = mask.unwrap_or(u64::MAX);
        let table = bytes
            .as_chunks::<{ size_of::<u64>() }>()
            .0
            .iter()
            .map(|c| u64::from_be_bytes(*c) & m)
            .collect();
        Ok(table)
    }

    /// Reads a cluster's worth of 64 bit offsets and returns them as a vector.
    /// `mask` optionally `&`s out some of the bits on the file.
    pub(super) fn read_pointer_cluster(
        &mut self,
        offset: u64,
        mask: Option<u64>,
    ) -> io::Result<Vec<u64>> {
        let count = self.cluster_size / size_of::<u64>() as u64;
        self.read_pointer_table(offset, count, mask)
    }

    /// Writes a pointer table to `offset` in the file.
    /// Entries are computed on-the-fly by the callback.
    ///
    /// The callback may perform metadata I/O on this `QcowRawFile`, so all
    /// entries are materialized before the final positional write.
    pub(super) fn write_pointer_table<'a, T: Copy + 'a>(
        &mut self,
        offset: u64,
        entries: impl Iterator<Item = &'a T>,
        mut f: impl FnMut(&mut QcowRawFile, T) -> io::Result<u64>,
    ) -> io::Result<()> {
        let mut buffer = Vec::with_capacity(entries.size_hint().0 * size_of::<u64>());
        for addr in entries {
            let entry = f(self, *addr)?;
            buffer.extend_from_slice(&entry.to_be_bytes());
        }
        self.file.write_all_at(&buffer, offset)
    }

    /// Writes a pointer table directly without transforming values.
    ///
    /// Uses the same materialize-then-write path as `write_pointer_table`.
    pub(super) fn write_pointer_table_direct<'a>(
        &mut self,
        offset: u64,
        entries: impl Iterator<Item = &'a u64>,
    ) -> io::Result<()> {
        let mut buffer = Vec::with_capacity(entries.size_hint().0 * size_of::<u64>());
        for &entry in entries {
            buffer.extend_from_slice(&entry.to_be_bytes());
        }
        self.file.write_all_at(&buffer, offset)
    }

    /// Read a refcount block from the file and returns a Vec containing the block.
    /// Always returns a cluster's worth of data.
    #[inline]
    pub(super) fn read_refcount_block(&mut self, offset: u64) -> io::Result<Vec<u64>> {
        (self.read_refcount_fn)(&mut self.file, offset, self.refcount_block_entries as usize)
    }

    /// Writes a refcount block to the file.
    #[inline]
    pub(super) fn write_refcount_block(&mut self, offset: u64, table: &[u64]) -> io::Result<()> {
        (self.write_refcount_fn)(&mut self.file, offset, table)
    }

    /// Allocates a new cluster at the end of the current file, return the address.
    pub(super) fn add_cluster_end(
        &mut self,
        max_valid_cluster_offset: u64,
    ) -> io::Result<Option<u64>> {
        // Determine where the new end of the file should be and set_len, which
        // translates to truncate(2).
        let file_end: u64 = self.physical_size()?;
        let new_cluster_address: u64 = (file_end + self.cluster_size - 1) & !self.cluster_mask;

        if new_cluster_address > max_valid_cluster_offset {
            return Ok(None);
        }

        self.file.set_len(new_cluster_address + self.cluster_size)?;

        Ok(Some(new_cluster_address))
    }

    /// Returns a reference to the underlying file.
    pub(super) fn file(&self) -> &AlignedFile {
        &self.file
    }

    /// Returns a mutable reference to the underlying file.
    pub(super) fn file_mut(&mut self) -> &mut AlignedFile {
        &mut self.file
    }

    /// Returns the size of the file's clusters.
    pub(super) fn cluster_size(&self) -> u64 {
        self.cluster_size
    }

    /// Returns the offset of `address` within a cluster.
    pub(super) fn cluster_offset(&self, address: u64) -> u64 {
        address & self.cluster_mask
    }

    /// Returns the base address of the cluster containing `address`.
    pub(super) fn cluster_address(&self, address: u64) -> u64 {
        address & !self.cluster_mask
    }

    /// Zeros out a cluster in the file.
    pub(super) fn zero_cluster(&mut self, address: u64) -> io::Result<()> {
        let cluster_size = self.cluster_size as usize;
        self.file.write_all_zeroes_at(address, cluster_size)?;
        Ok(())
    }

    /// Writes
    pub(super) fn write_cluster(&mut self, address: u64, data: &[u8]) -> io::Result<()> {
        let cluster_size = self.cluster_size as usize;
        self.file.write_all_at(&data[0..cluster_size], address)
    }

    pub(super) fn physical_size(&self) -> io::Result<u64> {
        self.file.metadata().map(|m| m.len())
    }
}

impl Clone for QcowRawFile {
    fn clone(&self) -> Self {
        QcowRawFile {
            file: self.file.try_clone().expect("QcowRawFile cloning failed"),
            cluster_size: self.cluster_size,
            cluster_mask: self.cluster_mask,
            refcount_block_entries: self.refcount_block_entries,
            read_refcount_fn: self.read_refcount_fn,
            write_refcount_fn: self.write_refcount_fn,
        }
    }
}

impl AsRawFd for QcowRawFile {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl AsFd for QcowRawFile {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}

#[cfg(test)]
mod unit_tests {
    use std::io::Read;
    use std::os::unix::fs::FileExt;

    use vmm_sys_util::tempfile::TempFile;

    use super::*;

    fn be_bytes(entries: &[u64]) -> Vec<u8> {
        let mut v = Vec::with_capacity(size_of_val(entries));
        for e in entries {
            v.extend_from_slice(&e.to_be_bytes());
        }
        v
    }

    fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
        haystack
            .windows(needle.len())
            .enumerate()
            .filter(|(_, w)| *w == needle)
            .map(|(i, _)| i)
            .collect()
    }

    const CLUSTER_SIZE: u64 = 0x10000; // 64 KiB
    const TARGET_OFFSET: u64 = 0x1000; // where the table must be written
    const FAR_OFFSET: u64 = 0x9000; // where the callback reads (refcount block)
    const FILE_LEN: u64 = 0x40000; // 256 KiB filler so all offsets are valid

    fn make_qcow_raw() -> (TempFile, QcowRawFile) {
        make_qcow_raw_bits(16)
    }

    fn make_qcow_raw_bits(refcount_bits: u64) -> (TempFile, QcowRawFile) {
        let temp_file = TempFile::new().unwrap();
        temp_file.as_file().set_len(FILE_LEN).unwrap();

        let file = temp_file.as_file().try_clone().unwrap();
        let raw = AlignedFile::new(file, false);
        let qcow_raw =
            QcowRawFile::from(raw, CLUSTER_SIZE, refcount_bits).expect("QcowRawFile::from");
        (temp_file, qcow_raw)
    }

    #[test]
    fn write_pointer_table_lands_at_offset_despite_callback_seek() {
        let (temp_file, mut qcow) = make_qcow_raw();
        let entries: Vec<u64> = vec![0x1111_2222_3333_4444u64; 8]; // 64 bytes

        qcow.write_pointer_table(TARGET_OFFSET, entries.iter(), |q, addr| {
            let _ = q.read_refcount_block(FAR_OFFSET)?;
            Ok(addr)
        })
        .expect("write_pointer_table");

        let expected = be_bytes(&entries);
        let mut verify = temp_file.as_file().try_clone().unwrap();
        let mut whole = Vec::new();
        verify.read_to_end(&mut whole).unwrap();
        let found_at = find_all(&whole, &expected);

        let mut at_target = vec![0u8; expected.len()];
        verify.read_exact_at(&mut at_target, TARGET_OFFSET).unwrap();

        assert_eq!(
            at_target, expected,
            "pointer table did NOT land at TARGET_OFFSET {TARGET_OFFSET:#x}; \
             found matching bytes at {found_at:x?}"
        );
    }

    #[test]
    fn write_pointer_table_direct_lands_at_offset() {
        let (temp_file, mut qcow) = make_qcow_raw();
        let entries: Vec<u64> = vec![0xAAAA_BBBB_CCCC_DDDDu64; 8];

        qcow.write_pointer_table_direct(TARGET_OFFSET, entries.iter())
            .expect("write_pointer_table_direct");

        let expected = be_bytes(&entries);
        let verify = temp_file.as_file().try_clone().unwrap();
        let mut at_target = vec![0u8; expected.len()];
        verify.read_exact_at(&mut at_target, TARGET_OFFSET).unwrap();

        assert_eq!(
            at_target, expected,
            "write_pointer_table_direct did not land at {TARGET_OFFSET:#x}"
        );
    }

    #[test]
    fn read_pointer_table_round_trips() {
        let (_temp_file, mut qcow) = make_qcow_raw();
        let entries: Vec<u64> = vec![
            0x0000_0000_0000_0000,
            0x0011_2233_4455_6677,
            0x8899_aabb_ccdd_eeff,
            0xffff_ffff_ffff_ffff,
        ];

        qcow.write_pointer_table_direct(TARGET_OFFSET, entries.iter())
            .expect("write_pointer_table_direct");

        let read_back = qcow
            .read_pointer_table(TARGET_OFFSET, entries.len() as u64, None)
            .expect("read_pointer_table");

        assert_eq!(read_back, entries);
    }

    #[test]
    fn read_pointer_table_applies_mask() {
        let (_temp_file, mut qcow) = make_qcow_raw();
        let entries: Vec<u64> = vec![0xffff_ffff_ffff_ffffu64; 4];
        let mask = 0x00ff_ffff_ffff_fe00u64;

        qcow.write_pointer_table_direct(TARGET_OFFSET, entries.iter())
            .expect("write_pointer_table_direct");

        let read_back = qcow
            .read_pointer_table(TARGET_OFFSET, entries.len() as u64, Some(mask))
            .expect("read_pointer_table");

        assert!(read_back.iter().all(|&e| e == mask));
    }

    #[test]
    fn write_cluster_then_zero_cluster_round_trips() {
        let (temp_file, mut qcow) = make_qcow_raw();
        let cluster_size = CLUSTER_SIZE as usize;
        let data: Vec<u8> = (0..cluster_size).map(|i| (i % 251) as u8).collect();

        qcow.write_cluster(CLUSTER_SIZE, &data)
            .expect("write_cluster");

        let verify = temp_file.as_file().try_clone().unwrap();
        let mut buf = vec![0u8; cluster_size];
        verify.read_exact_at(&mut buf, CLUSTER_SIZE).unwrap();
        assert_eq!(buf, data);

        qcow.zero_cluster(CLUSTER_SIZE).expect("zero_cluster");

        verify.read_exact_at(&mut buf, CLUSTER_SIZE).unwrap();
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn refcount_block_round_trips() {
        let (_temp_file, mut qcow) = make_qcow_raw_bits(16);
        let count = qcow.refcount_block_entries as usize;
        let table: Vec<u64> = (0..count).map(|i| (i % 251) as u64).collect();

        qcow.write_refcount_block(TARGET_OFFSET, &table)
            .expect("write_refcount_block");
        let read_back = qcow
            .read_refcount_block(TARGET_OFFSET)
            .expect("read_refcount_block");

        assert_eq!(read_back, table);
    }

    #[test]
    fn refcount_block_subbyte_round_trips() {
        let (_temp_file, mut qcow) = make_qcow_raw_bits(4);
        let count = qcow.refcount_block_entries as usize;
        let table: Vec<u64> = (0..count).map(|i| (i % 16) as u64).collect();

        qcow.write_refcount_block(TARGET_OFFSET, &table)
            .expect("write_refcount_block");
        let read_back = qcow
            .read_refcount_block(TARGET_OFFSET)
            .expect("read_refcount_block");

        assert_eq!(read_back, table);
    }

    #[test]
    fn add_cluster_end_appends_aligned_cluster() {
        let (_temp_file, mut qcow) = make_qcow_raw();
        let before = qcow.physical_size().unwrap();

        let addr = qcow
            .add_cluster_end(u64::MAX)
            .expect("add_cluster_end")
            .expect("a cluster was allocated");

        assert_eq!(addr % CLUSTER_SIZE, 0);
        assert!(addr >= before);
        assert_eq!(qcow.physical_size().unwrap(), addr + CLUSTER_SIZE);
    }

    #[test]
    fn add_cluster_end_respects_max_offset() {
        let (_temp_file, mut qcow) = make_qcow_raw();
        assert!(qcow.add_cluster_end(0).unwrap().is_none());
    }
}
