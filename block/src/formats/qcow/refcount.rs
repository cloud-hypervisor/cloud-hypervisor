// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::{io, result};

use libc::EINVAL;
use thiserror::Error;

use super::metadata::ClusterOffsets;
use super::qcow_raw_file::QcowRawFile;
use super::util::cluster_addr_is_valid;
use super::vec_cache::{CacheMap, Cacheable, VecCache};

fn write_refcount_block(
    raw_file: &mut QcowRawFile,
    addr: u64,
    block: &VecCache<u64>,
    max_valid: u64,
) -> io::Result<()> {
    if !cluster_addr_is_valid(addr, raw_file.cluster_size(), max_valid) {
        return Err(io::Error::from_raw_os_error(EINVAL));
    }
    raw_file.write_refcount_block(addr, block.get_values())
}

#[derive(Debug, Error)]
pub enum Error {
    /// `EvictingCache` - Error writing a refblock from the cache to disk.
    #[error("Failed to write a refblock from the cache to disk")]
    EvictingRefCounts(#[source] io::Error),
    /// `InvalidIndex` - Address requested isn't within the range of the disk.
    #[error("Address requested is not within the range of the disk")]
    InvalidIndex,
    /// `RefblockUnaligned` - Refcount block offset is not cluster aligned.
    #[error("Refcount block offset {0:#x} is not cluster aligned")]
    RefblockUnaligned(u64),
    /// `NeedCluster` - Handle this error by reading the cluster and calling the function again.
    #[error("Cluster with addr={0} needs to be read")]
    NeedCluster(u64),
    /// `NeedNewCluster` - Handle this error by allocating a cluster and calling the function again.
    #[error("New cluster needs to be allocated for refcounts")]
    NeedNewCluster,
    /// `ReadingRefCounts` - Error reading the file into the refcount cache.
    #[error("Failed to read the file into the refcount cache")]
    ReadingRefCounts(#[source] io::Error),
    /// `RefcountOverflow` - Refcount value exceeds maximum for the refcount width.
    #[error("Refcount value {value} exceeds {refcount_bits}-bit max ({max})")]
    RefcountOverflow {
        value: u64,
        max: u64,
        refcount_bits: u64,
    },
}

pub(super) type Result<T> = result::Result<T, Error>;

/// Represents the refcount entries for an open qcow file.
#[derive(Clone, Debug)]
pub(super) struct RefCount {
    ref_table: VecCache<u64>,
    block_offsets: ClusterOffsets,
    refcount_table_offset: u64,
    refblock_cache: CacheMap<VecCache<u64>>,
    refcount_block_entries: u64, // number of refcounts in a cluster.
    cluster_size: u64,
    max_valid_cluster_offset: u64,
    max_refcount: u64,  // maximum refcount value for this image's refcount_order
    refcount_bits: u64, // number of bits per refcount entry
}

impl RefCount {
    /// Creates a `RefCount` from `file`, reading the refcount table from `refcount_table_offset`.
    /// `refcount_table_entries` specifies the number of refcount blocks used by this image.
    /// `refcount_block_entries` indicates the number of refcounts in each refcount block.
    /// `refcount_bits` is the number of bits per refcount (1, 2, 4, 8, 16, 32, or 64).
    /// Each refcount table entry points to a refcount block.
    pub(super) fn new(
        raw_file: &mut QcowRawFile,
        refcount_table_offset: u64,
        refcount_table_entries: u64,
        refcount_block_entries: u64,
        cluster_size: u64,
        refcount_bits: u64,
    ) -> io::Result<RefCount> {
        let ref_table = VecCache::from_vec(raw_file.read_pointer_table(
            refcount_table_offset,
            refcount_table_entries,
            None,
        )?);
        // All three factors come from the untrusted image, so reject
        // geometries whose product overflows a u64.
        let max_valid_cluster_offset = (ref_table.len() as u64)
            .checked_mul(refcount_block_entries)
            .and_then(|clusters| clusters.checked_sub(1))
            .and_then(|max_index| max_index.checked_mul(cluster_size))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "QCOW2 refcount table addresses more clusters than fit a 64-bit offset",
                )
            })?;
        let max_refcount = if refcount_bits >= 64 {
            u64::MAX
        } else {
            (1u64 << refcount_bits) - 1
        };
        Ok(RefCount {
            block_offsets: ClusterOffsets::new(ref_table.get_values()),
            ref_table,
            refcount_table_offset,
            refblock_cache: CacheMap::new(50),
            refcount_block_entries,
            cluster_size,
            max_valid_cluster_offset,
            max_refcount,
            refcount_bits,
        })
    }

    /// Returns the number of refcounts per block.
    pub(super) fn refcounts_per_block(&self) -> u64 {
        self.refcount_block_entries
    }

    /// Returns the maximum valid cluster offset in the raw file for this refcount table.
    pub(super) fn max_valid_cluster_offset(&self) -> u64 {
        self.max_valid_cluster_offset
    }

    pub(super) fn overlaps_blocks(&self, addr: u64, size: u64) -> bool {
        self.block_offsets
            .overlaps(addr, size, self.cluster_size, None)
    }

    fn set_block_addr(&mut self, index: usize, addr: u64) {
        self.block_offsets.replace(self.ref_table[index], addr);
        self.ref_table[index] = addr;
    }

    /// Returns `NeedNewCluster` if a new cluster needs to be allocated for refcounts. If an
    /// existing cluster needs to be read, `NeedCluster(addr)` is returned. The Caller should
    /// allocate a cluster or read the required one and call this function again with the cluster.
    /// On success, an optional address of a dropped cluster is returned. The dropped cluster can
    /// be reused for other purposes.
    pub(super) fn set_cluster_refcount(
        &mut self,
        raw_file: &mut QcowRawFile,
        cluster_address: u64,
        refcount: u64,
        mut new_cluster: Option<(u64, VecCache<u64>)>,
    ) -> Result<Option<u64>> {
        if refcount > self.max_refcount {
            return Err(Error::RefcountOverflow {
                value: refcount,
                max: self.max_refcount,
                refcount_bits: self.refcount_bits,
            });
        }

        let (table_index, block_index) = self.get_refcount_index(cluster_address);

        let block_addr_disk = *self.ref_table.get(table_index).ok_or(Error::InvalidIndex)?;

        // Fill the cache if this block isn't yet there.
        if !self.refblock_cache.contains_key(table_index) {
            // Need a new cluster
            if let Some((addr, table)) = new_cluster.take() {
                self.set_block_addr(table_index, addr);
                let ref_table = &self.ref_table;
                let max_valid = self.max_valid_cluster_offset;
                self.refblock_cache
                    .insert(table_index, table, |index, evicted| {
                        let addr = ref_table[index];
                        write_refcount_block(raw_file, addr, &evicted, max_valid)
                    })
                    .map_err(Error::EvictingRefCounts)?;
            } else {
                if block_addr_disk == 0 {
                    return Err(Error::NeedNewCluster);
                }
                return Err(Error::NeedCluster(block_addr_disk));
            }
        }

        // Unwrap is safe here as the entry was filled directly above.
        let dropped_cluster = if self.refblock_cache.get(table_index).unwrap().dirty() {
            None
        } else {
            // Free the previously used block and use a new one. Writing modified counts to new
            // blocks keeps the on-disk state consistent even if it's out of date.
            if let Some((addr, _)) = new_cluster.take() {
                self.set_block_addr(table_index, addr);
                Some(block_addr_disk)
            } else {
                return Err(Error::NeedNewCluster);
            }
        };

        self.refblock_cache.get_mut(table_index).unwrap()[block_index] = refcount;
        Ok(dropped_cluster)
    }

    /// Flush the dirty refcount blocks. This must be done before flushing the table that points to
    /// the blocks.
    pub(super) fn flush_blocks(&mut self, raw_file: &mut QcowRawFile) -> io::Result<()> {
        for (table_index, block) in self.refblock_cache.iter_mut().filter(|(_k, v)| v.dirty()) {
            write_refcount_block(
                raw_file,
                self.ref_table[*table_index],
                block,
                self.max_valid_cluster_offset,
            )?;
            block.mark_clean();
        }
        Ok(())
    }

    /// Flush the refcount table that keeps the address of the refcounts blocks.
    /// Returns true if the table changed since the previous `flush_table()` call.
    pub(super) fn flush_table(&mut self, raw_file: &mut QcowRawFile) -> io::Result<bool> {
        if self.ref_table.dirty() {
            raw_file
                .write_pointer_table_direct(self.refcount_table_offset, self.ref_table.iter())?;
            self.ref_table.mark_clean();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Gets the refcount for a cluster with the given address.
    pub(super) fn get_cluster_refcount(
        &mut self,
        raw_file: &mut QcowRawFile,
        address: u64,
    ) -> Result<u64> {
        let (table_index, block_index) = self.get_refcount_index(address);
        let block_addr_disk = *self.ref_table.get(table_index).ok_or(Error::InvalidIndex)?;
        if block_addr_disk == 0 {
            return Ok(0);
        }
        if block_addr_disk & (self.cluster_size - 1) != 0 {
            return Err(Error::RefblockUnaligned(block_addr_disk));
        }
        if !self.refblock_cache.contains_key(table_index) {
            let table = VecCache::from_vec(
                raw_file
                    .read_refcount_block(block_addr_disk)
                    .map_err(Error::ReadingRefCounts)?,
            );
            let ref_table = &self.ref_table;
            let max_valid = self.max_valid_cluster_offset;
            self.refblock_cache
                .insert(table_index, table, |index, evicted| {
                    let addr = ref_table[index];
                    write_refcount_block(raw_file, addr, &evicted, max_valid)
                })
                .map_err(Error::EvictingRefCounts)?;
        }
        Ok(self.refblock_cache.get(table_index).unwrap()[block_index])
    }

    // Gets the address of the refcount block and the index into the block for the given address.
    fn get_refcount_index(&self, address: u64) -> (usize, usize) {
        let block_index = (address / self.cluster_size) % self.refcount_block_entries;
        let refcount_table_index = (address / self.cluster_size) / self.refcount_block_entries;
        (refcount_table_index as usize, block_index as usize)
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::os::unix::fs::FileExt;

    use vmm_sys_util::tempfile::TempFile;

    use super::super::qcow_raw_file::QcowRawFile;
    use super::RefCount;
    use crate::aligned_file::AlignedFile;

    fn test_refcounts() -> (TempFile, QcowRawFile, RefCount) {
        let cluster_size = 512;
        let temp = TempFile::new().unwrap();
        temp.as_file().set_len(8 * cluster_size).unwrap();
        temp.as_file().write_all_at(&[0xa5; 512], 0).unwrap();
        let mut raw = QcowRawFile::from(
            AlignedFile::new(temp.as_file().try_clone().unwrap(), false),
            cluster_size,
            16,
        )
        .unwrap();
        let refs = RefCount::new(
            &mut raw,
            cluster_size,
            3,
            cluster_size * 8 / 16,
            cluster_size,
            16,
        )
        .unwrap();
        (temp, raw, refs)
    }

    #[test]
    fn invalid_refcount_writeback_targets_are_rejected() {
        use super::super::vec_cache::{CacheMap, VecCache};

        let cluster_size = 512;
        let block_entries = cluster_size * 8 / 16;
        for addr in [0, 1, cluster_size + 1, 3 * block_entries * cluster_size] {
            for path in ["flush", "read eviction", "write eviction"] {
                let (temp, mut raw_file, mut refs) = test_refcounts();
                refs.set_block_addr(0, addr);
                refs.set_block_addr(1, 3 * cluster_size);
                refs.refblock_cache = CacheMap::new(1);
                refs.refblock_cache
                    .insert(
                        0,
                        VecCache::new(block_entries as usize),
                        |_, _| unreachable!(),
                    )
                    .unwrap();
                let mut before = [0u8; 4096];
                temp.as_file().read_exact_at(&mut before, 0).unwrap();

                let err = match path {
                    "flush" => refs.flush_blocks(&mut raw_file).unwrap_err(),
                    "read eviction" => match refs
                        .get_cluster_refcount(&mut raw_file, block_entries * cluster_size)
                    {
                        Err(super::Error::EvictingRefCounts(err)) => err,
                        result => panic!("expected eviction error, got {result:?}"),
                    },
                    _ => match refs.set_cluster_refcount(
                        &mut raw_file,
                        block_entries * cluster_size,
                        1,
                        Some((3 * cluster_size, VecCache::new(block_entries as usize))),
                    ) {
                        Err(super::Error::EvictingRefCounts(err)) => err,
                        result => panic!("expected eviction error, got {result:?}"),
                    },
                };
                assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
                let mut after = [0u8; 4096];
                temp.as_file().read_exact_at(&mut after, 0).unwrap();
                assert_eq!(before, after);
            }
        }
    }

    // A refcount table whose entry count, refcounts-per-block and cluster size
    // all come from the image can describe more clusters than a 64-bit byte
    // offset can address. With `cluster_bits = 21` (`cluster_size = 2^21`),
    // `refcount_order = 0` (`refcount_bits = 1`, so `refcount_block_entries =
    // 2^24`) and a 2^20-entry table, the offset bound computed in
    // `RefCount::new` overflows a u64. It must be rejected rather than wrap.
    #[test]
    fn new_rejects_refcount_geometry_that_overflows_a_64_bit_offset() {
        let cluster_size: u64 = 1 << 21;
        let refcount_bits: u64 = 1;
        let refcount_block_entries = cluster_size * 8 / refcount_bits;
        let refcount_table_entries: u64 = 1 << 20;

        let temp = TempFile::new().unwrap();
        temp.as_file()
            .set_len(refcount_table_entries * size_of::<u64>() as u64 + cluster_size)
            .unwrap();
        let file = AlignedFile::new(temp.into_file(), false);
        let mut raw_file = QcowRawFile::from(file, cluster_size, refcount_bits)
            .expect("cluster size and refcount width are valid");

        let err = RefCount::new(
            &mut raw_file,
            0,
            refcount_table_entries,
            refcount_block_entries,
            cluster_size,
            refcount_bits,
        )
        .expect_err("an overflowing refcount geometry must be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
