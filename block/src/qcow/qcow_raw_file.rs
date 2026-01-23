// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::mem::size_of;
use std::os::fd::{AsRawFd, RawFd};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use vmm_sys_util::write_zeroes::WriteZeroes;

use super::RawFile;

// Type aliases for the refcount read/write function pointers
type RefcountReader = fn(&mut RawFile, usize) -> io::Result<Vec<u64>>;
type RefcountWriter = fn(&mut RawFile, &[u64]) -> io::Result<()>;

/// Big-endian file access trait.
trait BeUint: Sized + Copy {
    fn from_slice(bytes: &[u8]) -> u64;
    fn write<W: Write>(w: &mut W, val: u64) -> io::Result<()>;
}

impl BeUint for u8 {
    #[inline(always)]
    fn from_slice(bytes: &[u8]) -> u64 {
        bytes[0] as u64
    }
    #[inline(always)]
    fn write<W: Write>(w: &mut W, val: u64) -> io::Result<()> {
        w.write_u8(val as u8)
    }
}

impl BeUint for u16 {
    #[inline(always)]
    fn from_slice(bytes: &[u8]) -> u64 {
        u16::from_be_bytes([bytes[0], bytes[1]]) as u64
    }
    #[inline(always)]
    fn write<W: Write>(w: &mut W, val: u64) -> io::Result<()> {
        w.write_u16::<BigEndian>(val as u16)
    }
}

impl BeUint for u32 {
    #[inline(always)]
    fn from_slice(bytes: &[u8]) -> u64 {
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64
    }
    #[inline(always)]
    fn write<W: Write>(w: &mut W, val: u64) -> io::Result<()> {
        w.write_u32::<BigEndian>(val as u32)
    }
}

impl BeUint for u64 {
    #[inline(always)]
    fn from_slice(bytes: &[u8]) -> u64 {
        u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])
    }
    #[inline(always)]
    fn write<W: Write>(w: &mut W, val: u64) -> io::Result<()> {
        w.write_u64::<BigEndian>(val)
    }
}

/// Read byte-aligned refcounts.
fn read_refcount<T: BeUint>(file: &mut RawFile, count: usize) -> io::Result<Vec<u64>> {
    let bytes_per_entry = size_of::<T>();
    let mut data = vec![0u8; count * bytes_per_entry];
    file.read_exact(&mut data)?;
    Ok(data
        .chunks_exact(bytes_per_entry)
        .map(T::from_slice)
        .collect())
}

/// Write byte-aligned refcounts.
fn write_refcount<T: BeUint>(file: &mut RawFile, table: &[u64]) -> io::Result<()> {
    let bytes_per_entry = size_of::<T>();
    let mut buffer = BufWriter::with_capacity(table.len() * bytes_per_entry, file);
    for &val in table {
        T::write(&mut buffer, val)?;
    }
    buffer.flush()
}

/// Read sub-byte refcounts. Bit 0 is the least significant bit.
fn read_refcount_subbyte<const BITS: usize>(
    file: &mut RawFile,
    count: usize,
) -> io::Result<Vec<u64>> {
    const { assert!(BITS == 1 || BITS == 2 || BITS == 4) };
    let entries_per_byte = 8 / BITS;
    let mask = (1u64 << BITS) - 1;
    let bytes_needed = count.div_ceil(entries_per_byte);
    let mut bytes = vec![0u8; bytes_needed];
    file.read_exact(&mut bytes)?;

    let mut table = vec![0u64; count];
    for (i, val) in table.iter_mut().enumerate() {
        let byte_idx = i / entries_per_byte;
        let bit_offset = (i % entries_per_byte) * BITS;
        *val = (bytes[byte_idx] as u64 >> bit_offset) & mask;
    }
    Ok(table)
}

/// Write sub-byte refcounts. Bit 0 is the least significant bit.
fn write_refcount_subbyte<const BITS: usize>(file: &mut RawFile, table: &[u64]) -> io::Result<()> {
    const { assert!(BITS == 1 || BITS == 2 || BITS == 4) };
    let entries_per_byte = 8 / BITS;
    let mask = (1u64 << BITS) - 1;
    let mut buffer = BufWriter::with_capacity(table.len().div_ceil(entries_per_byte), file);

    for chunk in table.chunks(entries_per_byte) {
        let mut byte = 0u8;
        for (i, &val) in chunk.iter().enumerate() {
            let bit_offset = i * BITS;
            byte |= ((val & mask) << bit_offset) as u8;
        }
        buffer.write_u8(byte)?;
    }
    buffer.flush()
}

/// A qcow file. Allows reading/writing clusters and appending clusters.
#[derive(Debug)]
pub struct QcowRawFile {
    file: RawFile,
    cluster_size: u64,
    cluster_mask: u64,
    refcount_block_entries: u64,
    read_refcount_fn: RefcountReader,
    write_refcount_fn: RefcountWriter,
}

impl QcowRawFile {
    /// Creates a `QcowRawFile` from the given `File`, `None` is returned if `cluster_size` is not
    /// a power of two or refcount_bits is invalid.
    pub fn from(file: RawFile, cluster_size: u64, refcount_bits: u64) -> Option<Self> {
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
    pub fn read_pointer_table(
        &mut self,
        offset: u64,
        count: u64,
        mask: Option<u64>,
    ) -> io::Result<Vec<u64>> {
        let mut table = vec![0; count as usize];
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.read_u64_into::<BigEndian>(&mut table)?;
        if let Some(m) = mask {
            for ptr in &mut table {
                *ptr &= m;
            }
        }
        Ok(table)
    }

    /// Reads a cluster's worth of 64 bit offsets and returns them as a vector.
    /// `mask` optionally `&`s out some of the bits on the file.
    pub fn read_pointer_cluster(&mut self, offset: u64, mask: Option<u64>) -> io::Result<Vec<u64>> {
        let count = self.cluster_size / size_of::<u64>() as u64;
        self.read_pointer_table(offset, count, mask)
    }

    /// Internal helper for creating a buffered writer for pointer tables.
    #[inline]
    fn setup_pointer_table_writer<T>(
        &mut self,
        offset: u64,
        entries: &impl Iterator<Item = T>,
    ) -> io::Result<BufWriter<RawFile>> {
        self.file.seek(SeekFrom::Start(offset))?;
        let my_file = self.file.try_clone()?;
        let capacity = entries.size_hint().0 * size_of::<u64>();
        Ok(BufWriter::with_capacity(capacity, my_file))
    }

    /// Writes a pointer table to `offset` in the file.
    /// Entries are computed on-the-fly by the callback.
    pub fn write_pointer_table<'a, T: Copy + 'a>(
        &mut self,
        offset: u64,
        entries: impl Iterator<Item = &'a T>,
        mut f: impl FnMut(&mut QcowRawFile, T) -> io::Result<u64>,
    ) -> io::Result<()> {
        let mut buffer = self.setup_pointer_table_writer(offset, &entries)?;

        for addr in entries {
            let entry = f(self, *addr)?;
            buffer.write_u64::<BigEndian>(entry)?;
        }
        buffer.flush()?;
        Ok(())
    }

    /// Writes a pointer table directly without transforming values.
    pub fn write_pointer_table_direct<'a>(
        &mut self,
        offset: u64,
        entries: impl Iterator<Item = &'a u64>,
    ) -> io::Result<()> {
        let mut buffer = self.setup_pointer_table_writer(offset, &entries)?;

        for &entry in entries {
            buffer.write_u64::<BigEndian>(entry)?;
        }
        buffer.flush()?;
        Ok(())
    }

    /// Read a refcount block from the file and returns a Vec containing the block.
    /// Always returns a cluster's worth of data.
    #[inline]
    pub fn read_refcount_block(&mut self, offset: u64) -> io::Result<Vec<u64>> {
        self.file.seek(SeekFrom::Start(offset))?;
        (self.read_refcount_fn)(&mut self.file, self.refcount_block_entries as usize)
    }

    /// Writes a refcount block to the file.
    #[inline]
    pub fn write_refcount_block(&mut self, offset: u64, table: &[u64]) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(offset))?;
        (self.write_refcount_fn)(&mut self.file, table)
    }

    /// Allocates a new cluster at the end of the current file, return the address.
    pub fn add_cluster_end(&mut self, max_valid_cluster_offset: u64) -> io::Result<Option<u64>> {
        // Determine where the new end of the file should be and set_len, which
        // translates to truncate(2).
        let file_end: u64 = self.file.seek(SeekFrom::End(0))?;
        let new_cluster_address: u64 = (file_end + self.cluster_size - 1) & !self.cluster_mask;

        if new_cluster_address > max_valid_cluster_offset {
            return Ok(None);
        }

        self.file.set_len(new_cluster_address + self.cluster_size)?;

        Ok(Some(new_cluster_address))
    }

    /// Returns a mutable reference to the underlying file.
    pub fn file_mut(&mut self) -> &mut RawFile {
        &mut self.file
    }

    /// Returns the size of the file's clusters.
    pub fn cluster_size(&self) -> u64 {
        self.cluster_size
    }

    /// Returns the offset of `address` within a cluster.
    pub fn cluster_offset(&self, address: u64) -> u64 {
        address & self.cluster_mask
    }

    /// Returns the base address of the cluster containing `address`.
    pub fn cluster_address(&self, address: u64) -> u64 {
        address & !self.cluster_mask
    }

    /// Zeros out a cluster in the file.
    pub fn zero_cluster(&mut self, address: u64) -> io::Result<()> {
        let cluster_size = self.cluster_size as usize;
        self.file.seek(SeekFrom::Start(address))?;
        self.file.write_zeroes(cluster_size)?;
        Ok(())
    }

    /// Writes
    pub fn write_cluster(&mut self, address: u64, data: &[u8]) -> io::Result<()> {
        let cluster_size = self.cluster_size as usize;
        self.file.seek(SeekFrom::Start(address))?;
        self.file.write_all(&data[0..cluster_size])
    }

    pub fn physical_size(&self) -> Result<u64, std::io::Error> {
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
