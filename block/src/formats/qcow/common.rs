// Copyright © 2021 Intel Corporation
//
// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

//! Shared helpers for QCOW2 sync and async backends.

use std::cmp::min;
use std::io;
use std::os::unix::fs::FileExt;
use std::sync::Arc;

use vmm_sys_util::write_zeroes::{PunchHole, WriteZeroesAt};

use super::decoder::Decoder;
use super::metadata::{
    BackingRead, ClusterReadMapping, ClusterWriteMapping, DeallocAction, QcowMetadata,
};
use super::qcow_raw_file::QcowRawFile;
use crate::async_io::{AsyncIoError, AsyncIoOperation, AsyncIoResult};

/// Decompress a full QCOW2 cluster from compressed data.
///
/// Returns a `cluster_size` byte buffer with the decompressed cluster
/// content. Fails if the decoder does not produce exactly `cluster_size`
/// bytes.
pub(super) fn decompress_cluster(
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

/// Applies one deallocation action to the data file and refcount table.
pub(super) fn apply_dealloc_action(
    metadata: &QcowMetadata,
    data_file: &mut QcowRawFile,
    action: &DeallocAction,
) -> io::Result<()> {
    match action {
        DeallocAction::PunchHole {
            host_offset,
            length,
        } => {
            data_file.file_mut().punch_hole(*host_offset, *length)?;
            metadata.complete_punch_hole(*host_offset);
            Ok(())
        }
        DeallocAction::WriteZeroes {
            host_offset,
            length,
        } => data_file
            .file_mut()
            .write_zeroes_at(*host_offset, *length)
            .map(|_| ()),
    }
}

/// Deallocates a byte range and returns the completion result, 0 on
/// success or a negative errno on the first failing action.
pub(super) fn deallocate_range_result(
    metadata: &QcowMetadata,
    data_file: &mut QcowRawFile,
    offset: u64,
    length: usize,
    sparse: bool,
    write_zeroes: bool,
    backing_file: Option<&dyn BackingRead>,
) -> i32 {
    let wrap_error: fn(io::Error) -> AsyncIoError = if write_zeroes {
        AsyncIoError::WriteZeroes
    } else {
        AsyncIoError::PunchHole
    };
    let result = metadata
        .deallocate_bytes(offset, length, sparse, write_zeroes, backing_file)
        .and_then(|actions| {
            let mut first_error = None;
            for action in &actions {
                if let Err(e) = apply_dealloc_action(metadata, data_file, action) {
                    first_error.get_or_insert(e);
                }
            }
            first_error.map_or(Ok(()), Err)
        })
        .map_err(wrap_error);
    match result {
        Ok(()) => 0,
        Err(AsyncIoError::PunchHole(e) | AsyncIoError::WriteZeroes(e)) => {
            -e.raw_os_error().unwrap_or(libc::EIO)
        }
        Err(_) => -libc::EIO,
    }
}

/// Writes an operation to the data file cluster by cluster, allocating
/// and copying up backing data as needed. Writes are synchronous because
/// the host offset is only known after the metadata allocation.
pub(super) fn cow_write_sync(
    address: u64,
    op: &AsyncIoOperation,
    metadata: &QcowMetadata,
    data_file: &QcowRawFile,
    backing_file: &Option<Arc<dyn BackingRead>>,
    cluster_size: u64,
) -> AsyncIoResult<()> {
    let total_len = op.total_len();
    let mut buf_offset = 0usize;

    while buf_offset < total_len {
        let curr_addr = address + buf_offset as u64;
        let intra_offset = curr_addr & (cluster_size - 1);
        let remaining_in_cluster = (cluster_size - intra_offset) as usize;
        let count = min(total_len - buf_offset, remaining_in_cluster);

        let backing_data = if let Some(backing) = backing_file
            .as_ref()
            .filter(|_| intra_offset != 0 || count < cluster_size as usize)
        {
            let cluster_begin = curr_addr - intra_offset;
            let mut data = vec![0u8; cluster_size as usize];
            backing
                .read_at(cluster_begin, &mut data)
                .map_err(AsyncIoError::WriteVectored)?;
            Some(data)
        } else {
            None
        };

        let mapping = metadata
            .map_cluster_for_write(curr_addr, backing_data)
            .map_err(AsyncIoError::WriteVectored)?;

        match mapping {
            ClusterWriteMapping::Allocated {
                offset: host_offset,
            } => {
                let mut buf = vec![0u8; count];
                op.read_bytes_at(buf_offset, &mut buf)
                    .map_err(AsyncIoError::WriteVectored)?;
                data_file
                    .file()
                    .write_all_at(&buf, host_offset)
                    .map_err(AsyncIoError::WriteVectored)?;
            }
        }
        buf_offset += count;
    }
    Ok(())
}

/// Reads cluster mappings synchronously into an owned operation, filling
/// holes, decompressing, and reading from the backing file as each
/// mapping requires.
pub(super) fn scatter_read_sync(
    mappings: Vec<ClusterReadMapping>,
    op: &mut AsyncIoOperation,
    data_file: &QcowRawFile,
    backing_file: &Option<Arc<dyn BackingRead>>,
    cluster_size: u64,
    decoder: &dyn Decoder,
) -> AsyncIoResult<()> {
    if let [ClusterReadMapping::Allocated { offset, length }] = mappings.as_slice()
        && op.is_read()
        && *length as usize == op.total_len()
    {
        // SAFETY: the iovecs come from op, which owns the destination
        // memory for the duration of this call.
        let n = unsafe { data_file.file().read_vectored_at(op.iovecs(), *offset) };
        if matches!(n, Ok(n) if n == op.total_len()) {
            return Ok(());
        }
    }

    let mut buf_offset = 0usize;
    for mapping in mappings {
        match mapping {
            ClusterReadMapping::Zero { length } => {
                op.fill_zeroes_at(buf_offset, length as usize)
                    .map_err(AsyncIoError::ReadVectored)?;
                buf_offset += length as usize;
            }
            ClusterReadMapping::Allocated {
                offset: host_offset,
                length,
            } => {
                let len = length as usize;
                let mut buf = vec![0u8; len];
                data_file
                    .file()
                    .read_exact_at(&mut buf, host_offset)
                    .map_err(AsyncIoError::ReadVectored)?;
                op.write_bytes_at(buf_offset, &buf)
                    .map_err(AsyncIoError::ReadVectored)?;
                buf_offset += len;
            }
            ClusterReadMapping::Compressed {
                host_offset,
                compressed_size,
                cluster_offset,
                length,
            } => {
                let mut compressed = vec![0u8; compressed_size];
                data_file
                    .file()
                    .read_exact_at(&mut compressed, host_offset)
                    .map_err(AsyncIoError::ReadVectored)?;
                let decompressed = decompress_cluster(&compressed, cluster_size as usize, decoder)
                    .map_err(AsyncIoError::ReadVectored)?;
                op.write_bytes_at(
                    buf_offset,
                    &decompressed[cluster_offset..cluster_offset + length],
                )
                .map_err(AsyncIoError::ReadVectored)?;
                buf_offset += length;
            }
            ClusterReadMapping::Backing {
                offset: backing_offset,
                length,
            } => {
                let mut buf = vec![0u8; length as usize];
                backing_file
                    .as_ref()
                    .unwrap()
                    .read_at(backing_offset, &mut buf)
                    .map_err(AsyncIoError::ReadVectored)?;
                op.write_bytes_at(buf_offset, &buf)
                    .map_err(AsyncIoError::ReadVectored)?;
                buf_offset += length as usize;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use std::fs::File;
    use std::io::Write;
    use std::os::unix::fs::FileExt;

    use flate2::Compression;
    use flate2::write::DeflateEncoder;
    use vmm_sys_util::tempfile::TempFile;

    use super::super::decoder::ZlibDecoder;
    use super::super::metadata::ClusterReadMapping;
    use super::super::qcow_raw_file::QcowRawFile;
    use super::{decompress_cluster, scatter_read_sync};
    use crate::aligned_file::AlignedFile;
    use crate::async_io::{AsyncIoOperation, OwnedIoBuffer};

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
    pub fn compress_allocated_clusters(file: &mut File) {
        let mut buf4 = [0u8; 4];
        file.read_exact_at(&mut buf4, HEADER_CLUSTER_BITS_OFFSET)
            .unwrap();
        let cluster_bits = u32::from_be_bytes(buf4);
        let cluster_size = 1u64 << cluster_bits;

        file.read_exact_at(&mut buf4, HEADER_L1_SIZE_OFFSET)
            .unwrap();
        let l1_size = u32::from_be_bytes(buf4);

        let mut buf8 = [0u8; 8];
        file.read_exact_at(&mut buf8, HEADER_L1_TABLE_OFFSET)
            .unwrap();
        let l1_table_offset = u64::from_be_bytes(buf8);

        let entries_per_l2 = cluster_size / 8;

        let mut append_offset = file.metadata().unwrap().len();
        append_offset = (append_offset + 511) & !511;

        for l1_idx in 0..l1_size as u64 {
            let l1_entry_offset = l1_table_offset + l1_idx * 8;
            file.read_exact_at(&mut buf8, l1_entry_offset).unwrap();
            let l1_entry = u64::from_be_bytes(buf8);

            let l2_table_addr = l1_entry & L1_L2_ADDR_MASK;
            if l2_table_addr == 0 {
                continue;
            }

            for l2_idx in 0..entries_per_l2 {
                let l2_entry_offset = l2_table_addr + l2_idx * 8;
                file.read_exact_at(&mut buf8, l2_entry_offset).unwrap();
                let l2_entry = u64::from_be_bytes(buf8);

                if l2_entry & CLUSTER_USED_FLAG == 0 || l2_entry & COMPRESSED_FLAG != 0 {
                    continue;
                }

                let host_cluster_addr = l2_entry & L1_L2_ADDR_MASK;
                if host_cluster_addr == 0 {
                    continue;
                }

                let mut cluster_data = vec![0u8; cluster_size as usize];
                file.read_exact_at(&mut cluster_data, host_cluster_addr)
                    .unwrap();

                let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(&cluster_data).unwrap();
                let compressed = encoder.finish().unwrap();

                file.write_all_at(&compressed, append_offset).unwrap();

                let padded_len = (compressed.len() + 511) & !511;
                if padded_len > compressed.len() {
                    let padding = vec![0u8; padded_len - compressed.len()];
                    file.write_all_at(&padding, append_offset + compressed.len() as u64)
                        .unwrap();
                }

                let new_entry =
                    make_compressed_l2_entry(append_offset, compressed.len(), cluster_bits);
                file.write_all_at(&new_entry.to_be_bytes(), l2_entry_offset)
                    .unwrap();

                append_offset += padded_len as u64;
            }
        }

        file.flush().unwrap();
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

    #[test]
    fn single_full_mapping_short_read_errors() {
        // The mapping claims 200 bytes but the file holds only 100.
        let src: Vec<u8> = (0..100u8).collect();
        let tmp = TempFile::new().unwrap();
        tmp.as_file().write_all(&src).unwrap();
        tmp.as_file().sync_all().unwrap();

        let aligned = AlignedFile::new(tmp.as_file().try_clone().unwrap(), false);
        let data_file = QcowRawFile::from(aligned, 65536, 16).unwrap();

        let mut op = AsyncIoOperation::read_to_vec(0, OwnedIoBuffer::from_vec(vec![0u8; 200]), 1);
        let mappings = vec![ClusterReadMapping::Allocated {
            offset: 0,
            length: 200,
        }];

        assert!(
            scatter_read_sync(mappings, &mut op, &data_file, &None, 65536, &ZlibDecoder {})
                .is_err()
        );
    }

    #[test]
    fn single_full_mapping_reads_fast_path() {
        let cluster = 65536usize;
        let src: Vec<u8> = (0..cluster).map(|i| (i % 251) as u8).collect();
        let tmp = TempFile::new().unwrap();
        tmp.as_file().write_all(&src).unwrap();
        tmp.as_file().sync_all().unwrap();

        let aligned = AlignedFile::new(tmp.as_file().try_clone().unwrap(), false);
        let data_file = QcowRawFile::from(aligned, cluster as u64, 16).unwrap();

        let mut op =
            AsyncIoOperation::read_to_vec(0, OwnedIoBuffer::from_vec(vec![0u8; cluster]), 1);
        let mappings = vec![ClusterReadMapping::Allocated {
            offset: 0,
            length: cluster as u64,
        }];

        scatter_read_sync(
            mappings,
            &mut op,
            &data_file,
            &None,
            cluster as u64,
            &ZlibDecoder {},
        )
        .unwrap();

        let buffer = op.into_completion_buffer().unwrap();
        assert_eq!(buffer.as_slice(), src.as_slice());
    }
}
