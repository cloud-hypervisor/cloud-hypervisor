// Copyright © 2021 Intel Corporation
//
// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

//! Shared helpers for QCOW2 sync and async backends.
//!
//! Position-independent I/O helpers used by both `qcow_sync` and `qcow_async`.

use std::io;
use std::os::fd::RawFd;

#[cfg(test)]
use super::internal;
use super::internal::decoder::Decoder;

// -- Position independent I/O helpers --
//
// Duplicated file descriptors share the kernel file description and thus the
// file position. Using seek then read from multiple queues races on that
// shared position. pread64 and pwrite64 are atomic and never touch the position.

/// Read exactly the requested bytes at offset, looping on short reads.
pub fn pread_exact(fd: RawFd, buf: &mut [u8], offset: u64) -> io::Result<()> {
    let mut total = 0usize;
    while total < buf.len() {
        // SAFETY: buf and fd are valid for the lifetime of the call.
        let ret = unsafe {
            libc::pread64(
                fd,
                buf[total..].as_mut_ptr().cast(),
                buf.len() - total,
                (offset + total as u64) as libc::off_t,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        if ret == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        total += ret as usize;
    }
    Ok(())
}

/// Allocate a buffer and pread exactly `len` bytes at `offset`.
pub fn pread_alloc(fd: RawFd, offset: u64, len: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    pread_exact(fd, &mut buf, offset)?;
    Ok(buf)
}

/// Decompress a full QCOW2 cluster from compressed data.
///
/// Returns a `cluster_size` byte buffer with the decompressed cluster
/// content. Fails if the decoder does not produce exactly `cluster_size`
/// bytes.
pub fn decompress_cluster(
    compressed: &[u8],
    cluster_size: usize,
    decoder: &dyn Decoder,
) -> io::Result<Vec<u8>> {
    let mut decompressed = vec![0u8; cluster_size];
    let n = decoder
        .decode(compressed, &mut decompressed)
        .map_err(|_| io::Error::from_raw_os_error(libc::EIO))?;
    if n != cluster_size {
        return Err(io::Error::from_raw_os_error(libc::EIO));
    }
    Ok(decompressed)
}

/// Write all bytes to fd at offset, looping on short writes.
pub fn pwrite_all(fd: RawFd, buf: &[u8], offset: u64) -> io::Result<()> {
    let mut total = 0usize;
    while total < buf.len() {
        // SAFETY: buf and fd are valid for the lifetime of the call.
        let ret = unsafe {
            libc::pwrite64(
                fd,
                buf[total..].as_ptr().cast(),
                buf.len() - total,
                (offset + total as u64) as libc::off_t,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        if ret == 0 {
            return Err(io::Error::other("pwrite64 wrote 0 bytes"));
        }
        total += ret as usize;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod unit_tests {
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::FileExt;
    use std::os::unix::io::AsRawFd;

    use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
    use flate2::Compression;
    use flate2::write::DeflateEncoder;
    use vmm_sys_util::tempfile::TempFile;

    use super::internal::decoder::ZlibDecoder;
    use super::{decompress_cluster, pread_alloc};

    const COMPRESSED_FLAG: u64 = 1 << 62;
    const CLUSTER_USED_FLAG: u64 = 1 << 63;
    const COMPRESSED_SECTOR_SIZE: u64 = 512;

    const HEADER_CLUSTER_BITS_OFFSET: u64 = 20;
    const HEADER_L1_SIZE_OFFSET: u64 = 36;
    const HEADER_L1_TABLE_OFFSET: u64 = 40;

    const L1_L2_ADDR_MASK: u64 = 0x00ff_ffff_ffff_fe00;

    fn make_compressed_l2_entry(host_offset: u64, compressed_len: usize, cluster_bits: u32) -> u64 {
        let compressed_size_shift = 62 - (cluster_bits - 8);
        let intra_sector_offset = host_offset & (COMPRESSED_SECTOR_SIZE - 1);
        let total_bytes = compressed_len as u64 + intra_sector_offset;
        let nsectors = total_bytes.div_ceil(COMPRESSED_SECTOR_SIZE);
        let addr_part = host_offset & ((1 << compressed_size_shift) - 1);
        let size_part = (nsectors - 1) << compressed_size_shift;
        COMPRESSED_FLAG | size_part | addr_part
    }

    /// Compress every allocated cluster in a QCOW2 image file in place.
    ///
    /// Walks L1 -> L2 tables, compresses each standard cluster with raw
    /// deflate, appends the compressed payload at the end of the file,
    /// and rewrites the L2 entry with the compressed layout.
    pub fn compress_allocated_clusters(file: &mut File) {
        file.seek(SeekFrom::Start(HEADER_CLUSTER_BITS_OFFSET))
            .unwrap();
        let cluster_bits = file.read_u32::<BigEndian>().unwrap();
        let cluster_size = 1u64 << cluster_bits;

        file.seek(SeekFrom::Start(HEADER_L1_SIZE_OFFSET)).unwrap();
        let l1_size = file.read_u32::<BigEndian>().unwrap();

        file.seek(SeekFrom::Start(HEADER_L1_TABLE_OFFSET)).unwrap();
        let l1_table_offset = file.read_u64::<BigEndian>().unwrap();

        let entries_per_l2 = cluster_size / 8;

        let mut append_offset = file.seek(SeekFrom::End(0)).unwrap();
        append_offset = (append_offset + 511) & !511;

        for l1_idx in 0..l1_size as u64 {
            let l1_entry_offset = l1_table_offset + l1_idx * 8;
            file.seek(SeekFrom::Start(l1_entry_offset)).unwrap();
            let l1_entry = file.read_u64::<BigEndian>().unwrap();

            let l2_table_addr = l1_entry & L1_L2_ADDR_MASK;
            if l2_table_addr == 0 {
                continue;
            }

            for l2_idx in 0..entries_per_l2 {
                let l2_entry_offset = l2_table_addr + l2_idx * 8;
                file.seek(SeekFrom::Start(l2_entry_offset)).unwrap();
                let l2_entry = file.read_u64::<BigEndian>().unwrap();

                if l2_entry & CLUSTER_USED_FLAG == 0 || l2_entry & COMPRESSED_FLAG != 0 {
                    continue;
                }

                let host_cluster_addr = l2_entry & L1_L2_ADDR_MASK;
                if host_cluster_addr == 0 {
                    continue;
                }

                let mut cluster_data = vec![0u8; cluster_size as usize];
                file.seek(SeekFrom::Start(host_cluster_addr)).unwrap();
                file.read_exact(&mut cluster_data).unwrap();

                let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(&cluster_data).unwrap();
                let compressed = encoder.finish().unwrap();

                file.seek(SeekFrom::Start(append_offset)).unwrap();
                file.write_all(&compressed).unwrap();

                // The L2 entry encodes the compressed size in units of
                // 512 byte sectors. The reader decodes the sector count
                // back and computes: nsectors * 512 - (addr & 511).
                // Because addr is 512 aligned, this yields nsectors * 512
                // which rounds up to the next sector boundary. The file
                // must contain enough bytes for that rounded up pread.
                let padded_len = (compressed.len() + 511) & !511;
                if padded_len > compressed.len() {
                    let padding = vec![0u8; padded_len - compressed.len()];
                    file.write_all(&padding).unwrap();
                }

                let new_entry =
                    make_compressed_l2_entry(append_offset, compressed.len(), cluster_bits);
                file.seek(SeekFrom::Start(l2_entry_offset)).unwrap();
                file.write_u64::<BigEndian>(new_entry).unwrap();

                append_offset += padded_len as u64;
            }
        }

        file.flush().unwrap();
    }

    #[test]
    fn test_pread_alloc() {
        let temp = TempFile::new().unwrap();
        let file = temp.as_file();
        let data: Vec<u8> = (0..=255).cycle().take(4096).collect();
        file.write_all_at(&data, 0).unwrap();

        let buf = pread_alloc(file.as_raw_fd(), 0, 4096).unwrap();
        assert_eq!(buf, data);

        let buf = pread_alloc(file.as_raw_fd(), 100, 200).unwrap();
        assert_eq!(buf, &data[100..300]);

        pread_alloc(file.as_raw_fd(), 4000, 200).unwrap_err();
    }

    #[test]
    fn test_decompress_cluster() {
        let cluster_size = 65536;
        let original: Vec<u8> = (0..=255).cycle().take(cluster_size).collect();

        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&original).unwrap();
        let compressed = encoder.finish().unwrap();

        let result = decompress_cluster(&compressed, cluster_size, &ZlibDecoder {}).unwrap();
        assert_eq!(result, original);
    }

    #[test]
    fn test_decompress_cluster_corrupt_input() {
        let corrupt = vec![0xffu8; 64];
        let err = decompress_cluster(&corrupt, 65536, &ZlibDecoder {}).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EIO));
    }
}
