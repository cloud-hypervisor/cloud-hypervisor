// Copyright © 2021 Intel Corporation
//
// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

//! Shared helpers for QCOW2 sync and async backends.

use std::io;

use super::decoder::Decoder;

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

#[cfg(test)]
pub(crate) mod unit_tests {
    use std::fs::File;
    use std::io::Write;
    use std::os::unix::fs::FileExt;

    use flate2::Compression;
    use flate2::write::DeflateEncoder;

    use super::super::decoder::ZlibDecoder;
    use super::decompress_cluster;

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
}
