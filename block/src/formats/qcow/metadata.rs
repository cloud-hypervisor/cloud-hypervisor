// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

//! QCOW2 metadata with lock based synchronization.
//!
//! QcowMetadata wraps the in memory QCOW2 metadata tables behind a single
//! coarse RwLock. This separates metadata lookup from data I/O, allowing
//! data reads and writes to proceed without holding the metadata lock.
//!
//! On L2 cache hit, map_clusters_for_read only needs a read lock with
//! pure shared reference access on the cache. Cache misses and all write
//! operations upgrade to a write lock.

use std::cmp::min;
use std::os::unix::fs::FileExt;
use std::sync::{Arc, RwLock};
use std::{io, mem};

use libc::{EINVAL, EIO};
use vmm_sys_util::write_zeroes::WriteZeroesAt;

use super::decoder::Decoder;
use super::qcow_raw_file::QcowRawFile;
use super::refcount::RefCount;
use super::util::{
    div_round_up_u64, l1_entry_make, l2_entry_compressed_cluster_layout, l2_entry_is_compressed,
    l2_entry_is_empty, l2_entry_is_zero, l2_entry_make_std, l2_entry_make_zero,
    l2_entry_make_zero_plain, l2_entry_std_cluster_addr,
};
use super::vec_cache::{CacheMap, Cacheable, VecCache};
use super::{QcowHeader, refcount};

/// Describes how to satisfy a guest read for a single cluster region.
///
/// Returned by QcowMetadata::map_clusters_for_read. The caller performs
/// the actual data I/O using its own per queue file descriptor without
/// holding the metadata lock.
#[derive(Debug)]
pub(super) enum ClusterReadMapping {
    /// The cluster is not allocated and the guest should see zeros.
    /// This covers both truly unallocated clusters where the L1 or L2
    /// entry is zero and clusters with the ZERO flag set.
    Zero { length: u64 },

    /// The cluster is allocated at the given host file offset.
    /// The offset is the exact byte position combining cluster base and
    /// intra cluster offset. The length is the number of bytes to read,
    /// bounded by cluster boundary and guest request.
    Allocated { offset: u64, length: u64 },

    /// The cluster is compressed. The host file offset and compressed byte
    /// count are extracted from the L2 entry under the read lock. The caller
    /// reads the compressed data with pread on its own fd, decompresses
    /// into a cluster sized buffer, then slices the requested range.
    Compressed {
        host_offset: u64,
        compressed_size: usize,
        cluster_offset: usize,
        length: usize,
    },

    /// The cluster is not allocated in this layer but may exist in a backing
    /// file. The caller should delegate to the backing file at the given
    /// guest offset for the specified length in bytes.
    Backing { offset: u64, length: u64 },
}

/// Describes how to satisfy a guest write for a single cluster region.
///
/// Returned by QcowMetadata::map_cluster_for_write. The caller performs
/// the actual data I/O using its own per queue file descriptor without
/// holding the metadata lock.
#[derive(Debug)]
pub(super) enum ClusterWriteMapping {
    /// The write target is at the given host file offset.
    /// This covers both already allocated clusters and freshly allocated ones.
    /// The offset is the exact byte position combining cluster base and
    /// intra cluster offset.
    Allocated { offset: u64 },
}

/// Trait for reading from a backing file in a thread safe manner.
///
/// Used by QcowMetadata::deallocate_bytes so it can read COW data
/// from the backing file without knowing the concrete backing type.
pub(crate) trait BackingRead: Send + Sync {
    fn read_at(&self, address: u64, buf: &mut [u8]) -> io::Result<()>;
}

/// Action that the caller must perform after deallocate_bytes.
#[derive(Debug)]
pub(super) enum DeallocAction {
    /// Punch a hole at the given host file offset for a full cluster.
    PunchHole { host_offset: u64, length: u64 },
    /// Write zeros at the given host file offset for a partial cluster.
    WriteZeroes { host_offset: u64, length: usize },
}

/// Shared QCOW2 metadata protected by a coarse RwLock.
///
/// Holds the L1 table, L2 cache and refcount state in memory. L2 table
/// entries and refcount blocks are read from disk on cache miss and
/// written back on eviction or when dirty.
///
/// One instance is shared via Arc across all virtio blk queues. Each
/// queue holds its own QcowRawFile clone for data I/O.
///
/// Steady state guest I/O is read dominant at the metadata level. Every
/// read and every write to an already allocated cluster only needs an
/// L1 to L2 lookup, which completes under a shared read lock. Only
/// cluster allocation, L2 cache eviction and resize take the exclusive
/// write lock, so contention stays low and queues scale.
pub(super) struct QcowMetadata {
    inner: RwLock<QcowState>,
    decoder: Arc<dyn Decoder>,
}

/// The actual metadata state, accessible only through the RwLock.
pub(crate) struct QcowState {
    pub(crate) header: QcowHeader,
    pub(crate) l1_table: VecCache<u64>,
    pub(crate) l2_entries: u64,
    pub(crate) l2_cache: CacheMap<VecCache<u64>>,
    pub(crate) refcounts: RefCount,
    pub(crate) avail_clusters: Vec<u64>,
    pub(crate) unref_clusters: Vec<u64>,
    /// Dedicated file descriptor for metadata I/O covering L2 table reads,
    /// refcount block reads and dirty eviction writes. This is a dup clone
    /// of the original fd, separate from the per queue data I/O fds.
    pub(crate) raw_file: QcowRawFile,
}

impl QcowMetadata {
    pub(crate) fn new(inner: QcowState) -> Self {
        QcowMetadata {
            decoder: Arc::from(inner.header.get_decoder()),
            inner: RwLock::new(inner),
        }
    }

    /// Maps a multicluster guest read range to a list of read mappings.
    ///
    /// This walks the range in cluster sized steps under a single lock
    /// acquisition, reducing lock roundtrips for large reads. The returned
    /// mappings are ordered by guest address and ready for io_uring
    /// submission. The caller can coalesce adjacent allocated entries into
    /// fewer submissions.
    ///
    /// On the read lock fast path, if all L2 tables are cached, the lookup
    /// is pure memory access with no I/O and concurrent readers are allowed.
    ///
    /// On the write lock slow path, if an L2 cache miss occurs, the L2
    /// table is read from disk via the metadata fd, the cache is populated
    /// and the mapping is returned.
    ///
    /// The has_backing_file flag indicates whether a backing file exists,
    /// needed to distinguish zero versus backing for unallocated clusters.
    pub(super) fn map_clusters_for_read(
        &self,
        address: u64,
        total_length: usize,
        has_backing_file: bool,
    ) -> io::Result<Vec<ClusterReadMapping>> {
        let inner = self.inner.read().unwrap();
        let cluster_size = inner.raw_file.cluster_size();
        let mut mappings = Vec::new();
        let mut mapped = 0usize;
        let mut need_write_lock = false;

        // Fast path, try all chunks under read lock
        while mapped < total_length {
            let curr_addr = address + mapped as u64;
            let offset_in_cluster = inner.raw_file.cluster_offset(curr_addr) as usize;
            let count = min(
                total_length - mapped,
                cluster_size as usize - offset_in_cluster,
            );

            match inner.try_map_read(curr_addr, count, has_backing_file)? {
                Some(mapping) => mappings.push(mapping),
                None => {
                    need_write_lock = true;
                    break;
                }
            }
            mapped += count;
        }

        if !need_write_lock {
            return Ok(mappings);
        }

        // Slow path, drop read lock, take write lock, redo from where we stopped
        drop(inner);
        let mut inner = self.inner.write().unwrap();

        // Remap everything under write lock for consistency since the L2 cache
        // may have been evicted between the read to write lock transition.
        mappings.clear();
        mapped = 0;

        while mapped < total_length {
            let curr_addr = address + mapped as u64;
            let offset_in_cluster = inner.raw_file.cluster_offset(curr_addr) as usize;
            let count = min(
                total_length - mapped,
                cluster_size as usize - offset_in_cluster,
            );

            mappings.push(inner.map_read_with_populate(curr_addr, count, has_backing_file)?);
            mapped += count;
        }

        Ok(mappings)
    }

    /// Maps a guest write address to a write mapping.
    ///
    /// Always takes a write lock since writes may need to allocate clusters,
    /// update L2 entries and update refcounts.
    ///
    /// The backing_data parameter is the COW source. If the cluster is
    /// unallocated and a backing file exists, the caller should have already
    /// read the backing cluster data and pass it here. If None, the new
    /// cluster is zeroed.
    pub(super) fn map_cluster_for_write(
        &self,
        address: u64,
        backing_data: Option<Vec<u8>>,
    ) -> io::Result<ClusterWriteMapping> {
        let mut inner = self.inner.write().unwrap();
        inner.map_write(address, backing_data)
    }

    pub(super) fn flush(&self) -> io::Result<()> {
        let mut inner = self.inner.write().unwrap();
        inner.sync_caches()?;
        let mut unref = mem::take(&mut inner.unref_clusters);
        inner.avail_clusters.append(&mut unref);
        Ok(())
    }

    /// Flushes dirty metadata caches and clears the dirty bit for
    /// clean shutdown.
    pub(super) fn shutdown(&self) {
        let mut inner = self.inner.write().unwrap();
        let _ = inner.sync_caches();
        let QcowState {
            ref mut header,
            ref mut raw_file,
            ..
        } = *inner;
        if raw_file.file().is_writable() {
            let _ = header.set_dirty_bit(raw_file.file_mut(), false);
        }
    }

    /// Resizes the QCOW2 image to the given new size. Only grow is
    /// supported, shrink would require walking all L2 tables to reclaim
    /// clusters beyond the new size and risks data loss.
    ///
    /// Returns an error if the new size is smaller than the current size.
    pub(super) fn resize(&self, new_size: u64) -> io::Result<()> {
        let mut inner = self.inner.write().unwrap();
        inner.resize(new_size)
    }

    /// Deallocates a range of bytes. Full clusters are deallocated via metadata.
    /// If `zero_marker` is true, full-cluster deallocation records a logical
    /// zero instead of an empty entry where backing data could otherwise be
    /// exposed. Partial clusters need the caller to write zeros. This method
    /// returns a list of actions the caller should take.
    pub(crate) fn deallocate_bytes(
        &self,
        address: u64,
        length: usize,
        sparse: bool,
        zero_marker: bool,
        backing_file: Option<&dyn BackingRead>,
    ) -> io::Result<Vec<DeallocAction>> {
        if address.checked_add(length as u64).is_none() {
            return Ok(Vec::new());
        }
        let mut inner = self.inner.write().unwrap();
        let mut actions = Vec::new();

        let file_end = inner.header.size;
        let cluster_size = inner.raw_file.cluster_size();
        let remaining_in_file = file_end.saturating_sub(address);
        let write_count = min(length as u64, remaining_in_file) as usize;

        let mut nwritten = 0usize;
        while nwritten < write_count {
            let curr_addr = address + nwritten as u64;
            let offset_in_cluster = inner.raw_file.cluster_offset(curr_addr) as usize;
            let count = min(
                write_count - nwritten,
                cluster_size as usize - offset_in_cluster,
            );

            if count == cluster_size as usize {
                let punch_offset = inner.deallocate_cluster(
                    curr_addr,
                    sparse,
                    zero_marker && backing_file.is_some(),
                )?;
                if let Some(host_offset) = punch_offset {
                    actions.push(DeallocAction::PunchHole {
                        host_offset,
                        length: cluster_size,
                    });
                }
            } else {
                // Partial cluster - COW from backing to preserve non zeroed bytes,
                // then the caller writes zeros to the partial range.
                let backing_data = if let Some(backing) = backing_file {
                    let cluster_begin = curr_addr - offset_in_cluster as u64;
                    let mut data = vec![0u8; cluster_size as usize];
                    backing.read_at(cluster_begin, &mut data)?;
                    Some(data)
                } else {
                    None
                };
                let mapping = inner.map_write(curr_addr, backing_data)?;
                let ClusterWriteMapping::Allocated { offset } = mapping;
                actions.push(DeallocAction::WriteZeroes {
                    host_offset: offset,
                    length: count,
                });
            }

            nwritten += count;
        }
        Ok(actions)
    }

    /// Makes a fully deallocated data cluster eligible for reuse after the
    /// caller has successfully completed the corresponding host punch-hole.
    ///
    /// The cluster is deliberately kept out of both free lists while the
    /// destructive host operation is pending. Publishing it to
    /// `unref_clusters` (rather than directly to `avail_clusters`) preserves
    /// the existing rule that metadata must be flushed before a freed cluster
    /// can be allocated again.
    pub(super) fn complete_punch_hole(&self, host_offset: u64) {
        self.inner.write().unwrap().unref_clusters.push(host_offset);
    }

    pub(super) fn virtual_size(&self) -> u64 {
        self.inner.read().unwrap().header.size
    }

    pub(super) fn cluster_size(&self) -> u64 {
        self.inner.read().unwrap().raw_file.cluster_size()
    }

    /// Returns the shared decoder matching the image compression type.
    pub(super) fn decoder(&self) -> Arc<dyn Decoder> {
        Arc::clone(&self.decoder)
    }

    #[cfg(test)]
    pub(super) fn header(&self) -> QcowHeader {
        self.inner.read().unwrap().header.clone()
    }

    #[cfg(test)]
    pub(super) fn free_list_len(&self) -> usize {
        let inner = self.inner.read().unwrap();
        inner.avail_clusters.len() + inner.unref_clusters.len()
    }

    #[cfg(test)]
    pub(super) fn cluster_refcount(&self, address: u64) -> io::Result<u64> {
        let mut inner = self.inner.write().unwrap();
        let QcowState {
            refcounts,
            raw_file,
            ..
        } = &mut *inner;
        refcounts
            .get_cluster_refcount(raw_file, address)
            .map_err(|e| io::Error::other(format!("get_cluster_refcount: {e}")))
    }
}

impl Drop for QcowMetadata {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl QcowState {
    /// Fast path read mapping under read lock only. Returns None on cache
    /// miss.
    ///
    /// All access here is through shared reference. CacheMap::get,
    /// VecCache::get and index operations are all shared reference compatible.
    fn try_map_read(
        &self,
        address: u64,
        count: usize,
        has_backing_file: bool,
    ) -> io::Result<Option<ClusterReadMapping>> {
        if address >= self.header.size {
            return Err(io::Error::from_raw_os_error(EINVAL));
        }

        let l1_index = self.l1_table_index(address) as usize;
        let l2_addr_disk = match self.l1_table.get(l1_index) {
            Some(&addr) => addr,
            None => return Err(io::Error::from_raw_os_error(EINVAL)),
        };

        if l2_addr_disk == 0 {
            return Ok(Some(self.unallocated_read_mapping(
                address,
                count,
                has_backing_file,
            )));
        }

        let l2_table = match self.l2_cache.get(l1_index) {
            Some(table) => table,
            None => return Ok(None), // cache miss, need write lock
        };

        let l2_index = self.l2_table_index(address) as usize;
        let l2_entry = l2_table[l2_index];

        // Compressed entries: extract layout from L2 entry under read lock.
        // The caller reads and decompresses on its own fd without holding
        // the metadata lock.
        if l2_entry_is_compressed(l2_entry) {
            let (host_offset, compressed_size) =
                l2_entry_compressed_cluster_layout(l2_entry, self.header.cluster_bits);
            let cluster_offset = self.raw_file.cluster_offset(address) as usize;
            return Ok(Some(ClusterReadMapping::Compressed {
                host_offset,
                compressed_size,
                cluster_offset,
                length: count,
            }));
        }

        if l2_entry_is_empty(l2_entry) {
            Ok(Some(self.unallocated_read_mapping(
                address,
                count,
                has_backing_file,
            )))
        } else if l2_entry_is_zero(l2_entry) {
            Ok(Some(ClusterReadMapping::Zero {
                length: count as u64,
            }))
        } else {
            let cluster_addr = l2_entry_std_cluster_addr(l2_entry);
            if !self.is_refcount_addressable_cluster_offset(cluster_addr) {
                // Fall through to write lock path which sets the corrupt bit
                return Ok(None);
            }
            let intra_offset = self.raw_file.cluster_offset(address);
            Ok(Some(ClusterReadMapping::Allocated {
                offset: cluster_addr + intra_offset,
                length: count as u64,
            }))
        }
    }

    /// Slow path read mapping. Requires exclusive access to populate cache.
    fn map_read_with_populate(
        &mut self,
        address: u64,
        count: usize,
        has_backing_file: bool,
    ) -> io::Result<ClusterReadMapping> {
        if address >= self.header.size {
            return Err(io::Error::from_raw_os_error(EINVAL));
        }

        let l1_index = self.l1_table_index(address) as usize;
        let l2_addr_disk = match self.l1_table.get(l1_index) {
            Some(&addr) => addr,
            None => return Err(io::Error::from_raw_os_error(EINVAL)),
        };

        if l2_addr_disk == 0 {
            return Ok(self.unallocated_read_mapping(address, count, has_backing_file));
        }

        // Populate cache if needed as this does I/O via the metadata raw file
        self.cache_l2_cluster(l1_index, l2_addr_disk)?;

        let l2_index = self.l2_table_index(address) as usize;
        let l2_entry = self.l2_cache.get(l1_index).unwrap()[l2_index];

        if l2_entry_is_empty(l2_entry) {
            Ok(self.unallocated_read_mapping(address, count, has_backing_file))
        } else if l2_entry_is_compressed(l2_entry) {
            let (host_offset, compressed_size) =
                l2_entry_compressed_cluster_layout(l2_entry, self.header.cluster_bits);
            let cluster_offset = self.raw_file.cluster_offset(address) as usize;
            Ok(ClusterReadMapping::Compressed {
                host_offset,
                compressed_size,
                cluster_offset,
                length: count,
            })
        } else if l2_entry_is_zero(l2_entry) {
            Ok(ClusterReadMapping::Zero {
                length: count as u64,
            })
        } else {
            let cluster_addr = l2_entry_std_cluster_addr(l2_entry);
            self.reject_invalid_cluster_offset(cluster_addr)?;
            let intra_offset = self.raw_file.cluster_offset(address);
            Ok(ClusterReadMapping::Allocated {
                offset: cluster_addr + intra_offset,
                length: count as u64,
            })
        }
    }

    fn unallocated_read_mapping(
        &self,
        address: u64,
        count: usize,
        has_backing_file: bool,
    ) -> ClusterReadMapping {
        if has_backing_file {
            ClusterReadMapping::Backing {
                offset: address,
                length: count as u64,
            }
        } else {
            ClusterReadMapping::Zero {
                length: count as u64,
            }
        }
    }

    /// Write path mapping. Always called under write lock.
    fn map_write(
        &mut self,
        address: u64,
        backing_data: Option<Vec<u8>>,
    ) -> io::Result<ClusterWriteMapping> {
        if address >= self.header.size {
            return Err(io::Error::from_raw_os_error(EINVAL));
        }

        let l1_index = self.l1_table_index(address) as usize;
        let l2_addr_disk = match self.l1_table.get(l1_index) {
            Some(&addr) => addr,
            None => return Err(io::Error::from_raw_os_error(EINVAL)),
        };
        let l2_index = self.l2_table_index(address) as usize;

        self.cache_l2_cluster_alloc(l1_index, l2_addr_disk)?;

        let l2_entry = self.l2_cache.get(l1_index).unwrap()[l2_index];
        let cluster_addr = if l2_entry_is_compressed(l2_entry) {
            let decompressed_cluster = self.decompress_l2_cluster(l2_entry)?;
            let cluster_addr = self.append_data_cluster(None)?;
            let nwritten = self
                .raw_file
                .file_mut()
                .write_at(&decompressed_cluster, cluster_addr)?;
            if nwritten != decompressed_cluster.len() {
                self.set_corrupt_bit_best_effort();
                return Err(io::Error::from_raw_os_error(EIO));
            }
            self.update_cluster_addr(l1_index, l2_index, cluster_addr)?;
            self.deallocate_compressed_cluster(l2_entry)?;
            cluster_addr
        } else if l2_entry_is_empty(l2_entry) || l2_entry_is_zero(l2_entry) {
            let cluster_addr = if l2_entry_is_zero(l2_entry) {
                self.append_zeroed_data_cluster()?
            } else {
                self.append_data_cluster(backing_data)?
            };
            self.update_cluster_addr(l1_index, l2_index, cluster_addr)?;
            cluster_addr
        } else {
            let cluster_addr = l2_entry_std_cluster_addr(l2_entry);
            self.reject_invalid_cluster_offset(cluster_addr)?;
            cluster_addr
        };

        let intra_offset = self.raw_file.cluster_offset(address);
        Ok(ClusterWriteMapping::Allocated {
            offset: cluster_addr + intra_offset,
        })
    }

    // -- Address computation helpers --

    fn l1_table_index(&self, address: u64) -> u64 {
        (address / self.raw_file.cluster_size()) / self.l2_entries
    }

    fn l2_table_index(&self, address: u64) -> u64 {
        (address / self.raw_file.cluster_size()) % self.l2_entries
    }

    fn is_refcount_addressable_cluster_offset(&self, cluster_addr: u64) -> bool {
        cluster_addr & (self.raw_file.cluster_size() - 1) == 0
            && cluster_addr <= self.refcounts.max_valid_cluster_offset()
    }

    fn reject_invalid_cluster_offset(&mut self, cluster_addr: u64) -> io::Result<()> {
        if self.is_refcount_addressable_cluster_offset(cluster_addr) {
            Ok(())
        } else {
            self.set_corrupt_bit_best_effort();
            Err(io::Error::from_raw_os_error(EIO))
        }
    }

    // -- Cache and allocation operations requiring exclusive access --

    /// Populates the L2 cache for read operations without allocation.
    fn cache_l2_cluster(&mut self, l1_index: usize, l2_addr_disk: u64) -> io::Result<()> {
        if !self.l2_cache.contains_key(l1_index) {
            self.reject_invalid_cluster_offset(l2_addr_disk)?;
            let l2_table =
                VecCache::from_vec(self.raw_file.read_pointer_cluster(l2_addr_disk, None)?);
            let l1_table = &self.l1_table;
            let raw_file = &mut self.raw_file;
            self.l2_cache.insert(l1_index, l2_table, |index, evicted| {
                raw_file.write_pointer_table_direct(l1_table[index], evicted.iter())
            })?;
        }
        Ok(())
    }

    /// Populates the L2 cache for write operations and may allocate a new
    /// L2 table, establishing its refcount ownership before L1 can reference it.
    fn cache_l2_cluster_alloc(&mut self, l1_index: usize, l2_addr_disk: u64) -> io::Result<()> {
        if !self.l2_cache.contains_key(l1_index) {
            let l2_table = if l2_addr_disk == 0 {
                // Set the new L2 table's refcount to 1 before the L1 entry points at it.
                let new_addr = self.get_new_cluster(None)?;
                self.set_cluster_refcount_track_freed(new_addr, 1)?;
                self.l1_table[l1_index] = new_addr;
                VecCache::new(self.l2_entries as usize)
            } else {
                self.reject_invalid_cluster_offset(l2_addr_disk)?;
                VecCache::from_vec(self.raw_file.read_pointer_cluster(l2_addr_disk, None)?)
            };
            let l1_table = &self.l1_table;
            let raw_file = &mut self.raw_file;
            self.l2_cache.insert(l1_index, l2_table, |index, evicted| {
                raw_file.write_pointer_table_direct(l1_table[index], evicted.iter())
            })?;
        }
        Ok(())
    }

    /// Allocates a new cluster from the free list or by extending the file.
    fn get_new_cluster(&mut self, initial_data: Option<Vec<u8>>) -> io::Result<u64> {
        if let Some(free_cluster) = self.avail_clusters.pop() {
            if free_cluster == 0 {
                self.set_corrupt_bit_best_effort();
                return Err(io::Error::from_raw_os_error(EIO));
            }
            if let Some(initial_data) = initial_data {
                self.raw_file.write_cluster(free_cluster, &initial_data)?;
            } else {
                self.raw_file.zero_cluster(free_cluster)?;
            }
            return Ok(free_cluster);
        }

        let max_valid = self.refcounts.max_valid_cluster_offset();
        if let Some(new_cluster) = self.raw_file.add_cluster_end(max_valid)? {
            if new_cluster == 0 {
                self.set_corrupt_bit_best_effort();
                return Err(io::Error::from_raw_os_error(EIO));
            }
            if let Some(initial_data) = initial_data {
                self.raw_file.write_cluster(new_cluster, &initial_data)?;
            }
            Ok(new_cluster)
        } else {
            log::error!("No free clusters in get_new_cluster()");
            Err(io::Error::from_raw_os_error(libc::ENOSPC))
        }
    }

    /// Allocates a data cluster and sets its refcount to 1.
    fn append_data_cluster(&mut self, initial_data: Option<Vec<u8>>) -> io::Result<u64> {
        let new_addr = self.get_new_cluster(initial_data)?;
        self.set_cluster_refcount_track_freed(new_addr, 1)?;
        Ok(new_addr)
    }

    /// Allocates a data cluster and zeroes it without building a cluster-sized buffer.
    fn append_zeroed_data_cluster(&mut self) -> io::Result<u64> {
        let new_addr = self.get_new_cluster(None)?;
        let cluster_size = self.raw_file.cluster_size() as usize;
        self.raw_file
            .file_mut()
            .write_zeroes_at(new_addr, cluster_size)?;
        self.set_cluster_refcount_track_freed(new_addr, 1)?;
        Ok(new_addr)
    }

    /// Updates the L1 and L2 tables to point to a new cluster address.
    fn update_cluster_addr(
        &mut self,
        l1_index: usize,
        l2_index: usize,
        cluster_addr: u64,
    ) -> io::Result<()> {
        let relocation = if self.l2_cache.get(l1_index).unwrap().dirty() {
            None
        } else {
            // Allocate the new cluster for the relocated L2 table before
            // releasing the old one: if this allocation fails (ENOSPC at
            // allocator exhaustion) the old table must stay off the free
            // lists, or a later allocation would hand it out and overwrite a
            // live L2 table (issue #8606). The cluster will be written when
            // the cache is flushed.
            let new_addr = self.get_new_cluster(None)?;
            self.set_cluster_refcount_track_freed(new_addr, 1)?;
            Some((self.l1_table[l1_index], new_addr))
        };

        // Prepare the replacement L2 contents before switching L1. If the
        // old-table refcount drop then fails, sync_caches() can still write a
        // complete replacement table rather than publishing an empty cluster.
        self.l2_cache.get_mut(l1_index).unwrap()[l2_index] = l2_entry_make_std(cluster_addr);

        if let Some((old_l2, new_addr)) = relocation {
            self.l1_table[l1_index] = new_addr; // marks l1_table dirty via IndexMut
            if old_l2 != 0 {
                self.set_cluster_refcount_track_freed(old_l2, 0)?;
                self.unref_clusters.push(old_l2);
            }
        }
        Ok(())
    }

    /// Resizes the image to the given new size. Only grow is supported,
    /// shrink would require walking all L2 tables to reclaim clusters
    /// beyond the new size and risks data loss.
    fn resize(&mut self, new_size: u64) -> io::Result<()> {
        let current_size = self.header.size;

        if new_size == current_size {
            return Ok(());
        }

        if new_size < current_size {
            return Err(io::Error::other("shrinking QCOW2 images is not supported"));
        }

        let cluster_size = self.raw_file.cluster_size();
        let entries_per_cluster = cluster_size / size_of::<u64>() as u64;
        let new_clusters = div_round_up_u64(new_size, cluster_size);
        let needed_l1_entries = div_round_up_u64(new_clusters, entries_per_cluster) as u32;

        if needed_l1_entries > self.header.l1_size {
            self.grow_l1_table(needed_l1_entries)?;
        }

        self.header.size = new_size;

        self.header
            .write_to(self.raw_file.file_mut())
            .map_err(|e| io::Error::other(format!("failed to write header during resize: {e}")))?;

        self.raw_file.file_mut().sync_all()?;

        Ok(())
    }

    /// Grows the L1 table to accommodate at least the requested number of entries.
    fn grow_l1_table(&mut self, new_l1_size: u32) -> io::Result<()> {
        let old_l1_size = self.header.l1_size;
        let old_l1_offset = self.header.l1_table_offset;
        let cluster_size = self.raw_file.cluster_size();

        let new_l1_bytes = new_l1_size as u64 * size_of::<u64>() as u64;
        let new_l1_clusters = div_round_up_u64(new_l1_bytes, cluster_size);

        // Allocate contiguous clusters at file end for new L1 table
        let file_size = self.raw_file.physical_size()?;
        let new_l1_offset = self.raw_file.cluster_address(file_size + cluster_size - 1);

        let new_file_end = new_l1_offset + new_l1_clusters * cluster_size;
        self.raw_file.file_mut().set_len(new_file_end)?;

        // Set refcounts for the contiguous range
        for i in 0..new_l1_clusters {
            self.set_cluster_refcount_track_freed(new_l1_offset + i * cluster_size, 1)?;
        }

        let mut new_l1_data = vec![0u64; new_l1_size as usize];
        let old_entries = self.l1_table.get_values();
        new_l1_data[..old_entries.len()].copy_from_slice(old_entries);

        for l2_addr in new_l1_data.iter_mut() {
            if *l2_addr != 0 {
                let refcount = self
                    .refcounts
                    .get_cluster_refcount(&mut self.raw_file, *l2_addr)
                    .map_err(|e| {
                        io::Error::other(format!("failed to get refcount during resize: {e}"))
                    })?;
                *l2_addr = l1_entry_make(*l2_addr, refcount == 1);
            }
        }

        // Write the new L1 table to disk
        self.raw_file
            .write_pointer_table_direct(new_l1_offset, new_l1_data.iter())?;

        self.raw_file.file_mut().sync_all()?;

        self.header.l1_size = new_l1_size;
        self.header.l1_table_offset = new_l1_offset;

        self.header
            .write_to(self.raw_file.file_mut())
            .map_err(|e| io::Error::other(format!("failed to write header during resize: {e}")))?;

        self.raw_file.file_mut().sync_all()?;

        // Free old L1 table clusters
        let old_l1_bytes = old_l1_size as u64 * size_of::<u64>() as u64;
        let old_l1_clusters = div_round_up_u64(old_l1_bytes, cluster_size);
        for i in 0..old_l1_clusters {
            let cluster_addr = old_l1_offset + i * cluster_size;
            // Best effort: the old L1 clusters are no longer reachable,
            // so a refcount update failure just leaks space.
            let _ = self.set_cluster_refcount(cluster_addr, 0);
        }

        // Update L1 table cache
        self.l1_table.extend(new_l1_size as usize);

        Ok(())
    }

    /// Deallocates a cluster at the given guest address.
    ///
    /// If sparse is true, fully deallocates and returns the host offset if
    /// the underlying storage should be punched after the refcount dropped
    /// to zero. If sparse is false, uses the zero flag optimization when
    /// possible. If `zero_marker` is true, empty entries are replaced with
    /// logical-zero entries so reads do not fall through to backing data.
    ///
    /// Returns None if no host punch_hole is needed.
    fn deallocate_cluster(
        &mut self,
        address: u64,
        sparse: bool,
        zero_marker: bool,
    ) -> io::Result<Option<u64>> {
        if address >= self.header.size {
            return Err(io::Error::from_raw_os_error(EINVAL));
        }

        let l1_index = self.l1_table_index(address) as usize;
        let l2_addr_disk = match self.l1_table.get(l1_index) {
            Some(&addr) => addr,
            None => return Err(io::Error::from_raw_os_error(EINVAL)),
        };
        let l2_index = self.l2_table_index(address) as usize;
        let dealloc_entry = if zero_marker {
            l2_entry_make_zero_plain()
        } else {
            0
        };

        if l2_addr_disk == 0 {
            if zero_marker {
                self.cache_l2_cluster_alloc(l1_index, l2_addr_disk)?;
                self.l2_cache.get_mut(l1_index).unwrap()[l2_index] = dealloc_entry;
            }
            return Ok(None);
        }

        self.cache_l2_cluster(l1_index, l2_addr_disk)?;

        let l2_entry = self.l2_cache.get(l1_index).unwrap()[l2_index];
        if l2_entry_is_empty(l2_entry) {
            if zero_marker {
                self.l2_cache.get_mut(l1_index).unwrap()[l2_index] = dealloc_entry;
            }
            return Ok(None);
        }
        // Compressed entries may use bit 0 as part of their layout, so they
        // must be classified before zero-flagged standard entries.
        if l2_entry_is_compressed(l2_entry) {
            self.deallocate_compressed_cluster(l2_entry)?;
            self.l2_cache.get_mut(l1_index).unwrap()[l2_index] = dealloc_entry;
            return Ok(None);
        }
        if l2_entry_is_zero(l2_entry) {
            return Ok(None);
        }

        let cluster_addr = l2_entry_std_cluster_addr(l2_entry);
        self.reject_invalid_cluster_offset(cluster_addr)?;
        let refcount = self
            .refcounts
            .get_cluster_refcount(&mut self.raw_file, cluster_addr)
            .map_err(|e| {
                if matches!(e, refcount::Error::RefblockUnaligned(_)) {
                    self.set_corrupt_bit_best_effort();
                }
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to get cluster refcount: {e}"),
                )
            })?;
        if refcount == 0 {
            return Err(io::Error::from_raw_os_error(EINVAL));
        }

        if sparse {
            let new_refcount = refcount - 1;
            self.set_cluster_refcount_track_freed(cluster_addr, new_refcount)?;
            self.l2_cache.get_mut(l1_index).unwrap()[l2_index] = dealloc_entry;
            if new_refcount == 0 {
                // The caller still has to punch this range in the host file.
                // Do not publish it to either free list until that destructive
                // operation has completed, otherwise another queue can reuse
                // the cluster before the delayed punch runs.
                return Ok(Some(cluster_addr));
            }
        } else if refcount == 1 {
            self.l2_cache.get_mut(l1_index).unwrap()[l2_index] = l2_entry_make_zero(cluster_addr);
        } else {
            self.set_cluster_refcount_track_freed(cluster_addr, refcount - 1)?;
            self.l2_cache.get_mut(l1_index).unwrap()[l2_index] = dealloc_entry;
        }
        Ok(None)
    }

    /// Sets refcount for a cluster, tracking any newly freed clusters.
    fn set_cluster_refcount_track_freed(&mut self, address: u64, refcount: u64) -> io::Result<()> {
        let mut newly_unref = self.set_cluster_refcount(address, refcount)?;
        self.unref_clusters.append(&mut newly_unref);
        Ok(())
    }

    /// Sets the refcount for a cluster. Returns freed cluster addresses.
    fn set_cluster_refcount(&mut self, address: u64, refcount: u64) -> io::Result<Vec<u64>> {
        let mut added_clusters = Vec::new();
        let mut unref_clusters = Vec::new();
        let mut refcount_set = false;
        let mut new_cluster = None;

        while !refcount_set {
            match self.refcounts.set_cluster_refcount(
                &mut self.raw_file,
                address,
                refcount,
                new_cluster.take(),
            ) {
                Ok(None) => {
                    refcount_set = true;
                }
                Ok(Some(freed_cluster)) => {
                    let mut freed = self.set_cluster_refcount(freed_cluster, 0)?;
                    unref_clusters.push(freed_cluster);
                    unref_clusters.append(&mut freed);
                    refcount_set = true;
                }
                Err(refcount::Error::EvictingRefCounts(e)) => {
                    return Err(e);
                }
                Err(refcount::Error::InvalidIndex) => {
                    self.set_corrupt_bit_best_effort();
                    return Err(io::Error::from_raw_os_error(EINVAL));
                }
                Err(refcount::Error::NeedCluster(addr)) => {
                    new_cluster = Some((
                        addr,
                        VecCache::from_vec(self.raw_file.read_refcount_block(addr)?),
                    ));
                }
                Err(refcount::Error::NeedNewCluster) => {
                    let addr = self.get_new_cluster(None)?;
                    added_clusters.push(addr);
                    new_cluster = Some((
                        addr,
                        VecCache::new(self.refcounts.refcounts_per_block() as usize),
                    ));
                }
                Err(refcount::Error::ReadingRefCounts(e)) => {
                    return Err(e);
                }
                Err(refcount::Error::RefcountOverflow { .. }) => {
                    return Err(io::Error::from_raw_os_error(EINVAL));
                }
                Err(refcount::Error::RefblockUnaligned(_)) => {
                    self.set_corrupt_bit_best_effort();
                    return Err(io::Error::from_raw_os_error(EIO));
                }
            }
        }

        for addr in added_clusters {
            self.set_cluster_refcount(addr, 1)?;
        }
        Ok(unref_clusters)
    }

    /// Flushes all dirty metadata to disk.
    fn sync_caches(&mut self) -> io::Result<()> {
        // Write out all dirty L2 tables.
        for (l1_index, l2_table) in self.l2_cache.iter_mut().filter(|(_k, v)| v.dirty()) {
            let addr = self.l1_table[*l1_index];
            if addr != 0 {
                self.raw_file
                    .write_pointer_table_direct(addr, l2_table.iter())?;
            } else {
                self.set_corrupt_bit_best_effort();
                return Err(io::Error::from_raw_os_error(EINVAL));
            }
            l2_table.mark_clean();
        }
        // Write the modified refcount blocks.
        self.refcounts.flush_blocks(&mut self.raw_file)?;
        // Sync metadata and data clusters.
        self.raw_file.file_mut().sync_all()?;

        // Push L1 table and refcount table last.
        let mut sync_required = if self.l1_table.dirty() {
            let refcounts = &mut self.refcounts;
            self.raw_file.write_pointer_table(
                self.header.l1_table_offset,
                self.l1_table.iter(),
                |raw_file, l2_addr| {
                    if l2_addr == 0 {
                        Ok(0)
                    } else {
                        let refcount = refcounts
                            .get_cluster_refcount(raw_file, l2_addr)
                            .map_err(|e| io::Error::other(super::Error::GettingRefcount(e)))?;
                        Ok(l1_entry_make(l2_addr, refcount == 1))
                    }
                },
            )?;
            self.l1_table.mark_clean();
            true
        } else {
            false
        };
        sync_required |= self.refcounts.flush_table(&mut self.raw_file)?;
        if sync_required {
            self.raw_file.file_mut().sync_data()?;
        }

        Ok(())
    }

    /// Decompresses a compressed cluster, returning the raw decompressed bytes.
    fn decompress_l2_cluster(&mut self, l2_entry: u64) -> io::Result<Vec<u8>> {
        let (compressed_addr, compressed_size) =
            l2_entry_compressed_cluster_layout(l2_entry, self.header.cluster_bits);
        let mut compressed = vec![0u8; compressed_size];
        self.raw_file
            .file_mut()
            .read_exact_at(&mut compressed, compressed_addr)?;
        let decoder = self.header.get_decoder();
        let cluster_size = self.raw_file.cluster_size() as usize;
        let mut decompressed = vec![0u8; cluster_size];
        let decompressed_size = decoder
            .decode(&compressed, &mut decompressed)
            .map_err(|_| {
                self.set_corrupt_bit_best_effort();
                io::Error::from_raw_os_error(EIO)
            })?;
        if decompressed_size as u64 != self.raw_file.cluster_size() {
            self.set_corrupt_bit_best_effort();
            return Err(io::Error::from_raw_os_error(EIO));
        }
        Ok(decompressed)
    }

    /// Deallocates the clusters spanned by a compressed L2 entry.
    fn deallocate_compressed_cluster(&mut self, l2_entry: u64) -> io::Result<()> {
        let (compressed_addr, compressed_size) =
            l2_entry_compressed_cluster_layout(l2_entry, self.header.cluster_bits);
        let cluster_size = self.raw_file.cluster_size();

        // Calculate the end of the compressed data region
        let compressed_clusters_end = self.raw_file.cluster_address(
            compressed_addr                // Start of compressed data
            + compressed_size as u64       // Add size to get end address
            + cluster_size
                - 1, // Catch possibly partially used last cluster
        );

        // Decrement refcount for each cluster spanned by the compressed data
        let mut addr = self.raw_file.cluster_address(compressed_addr);
        while addr < compressed_clusters_end {
            let refcount = self
                .refcounts
                .get_cluster_refcount(&mut self.raw_file, addr)
                .map_err(|e| {
                    if matches!(e, refcount::Error::RefblockUnaligned(_)) {
                        self.set_corrupt_bit_best_effort();
                    }
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("failed to get cluster refcount: {e}"),
                    )
                })?;
            if refcount > 0 {
                self.set_cluster_refcount_track_freed(addr, refcount - 1)?;
            }
            addr += cluster_size;
        }
        Ok(())
    }

    /// Best effort attempt to mark the image corrupt.
    fn set_corrupt_bit_best_effort(&mut self) {
        if let Err(e) = self.header.set_corrupt_bit(self.raw_file.file_mut()) {
            log::warn!("Failed to persist corrupt bit: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    // Regression for the ENOSPC unwind on the relocate-on-write path: when
    // the allocation for the relocated table fails, the still-referenced old
    // L2 table must not be left on the free lists (issue #8606).
    #[test]
    fn failed_l2_relocate_keeps_live_table_off_free_lists() {
        let cluster_size: u64 = 1 << 16;
        let temp = super::super::QcowTempDisk::new(64 * cluster_size, None, false, true, false)
            .unwrap()
            .into_tempfile();
        let raw = crate::AlignedFile::new(temp.as_file().try_clone().unwrap(), false);
        let (mut inner, _backing, _sparse) =
            super::super::parser::parse_qcow(raw, 0, true).unwrap();

        // Materialize an L2 table plus one data cluster, then flush so the
        // next write to the region takes the relocate-on-write path.
        let super::ClusterWriteMapping::Allocated {
            offset: data_cluster,
        } = inner.map_write(0, None).expect("initial write");
        inner.sync_caches().expect("flush");
        let live_l2 = inner.l1_table[0];
        assert_ne!(live_l2, 0);

        // Exhaust the allocator down to two reusable clusters: shrink the
        // refcount horizon so the file cannot grow, and leave exactly enough
        // for the data cluster of the next write plus the refcount-block
        // relocation it triggers, but nothing for relocating its L2 table.
        let file_clusters = inner
            .raw_file
            .file_mut()
            .metadata()
            .unwrap()
            .len()
            .div_ceil(cluster_size);
        inner.refcounts = super::super::refcount::RefCount::new(
            &mut inner.raw_file,
            inner.header.refcount_table_offset,
            1,
            file_clusters,
            cluster_size,
            16,
        )
        .unwrap();
        let freed = super::mem::take(&mut inner.unref_clusters);
        assert!(
            !freed.is_empty(),
            "the first write must have relocated the refcount block, freeing its old cluster"
        );
        inner.avail_clusters.clear();
        inner.avail_clusters.push(data_cluster);
        inner.avail_clusters.extend(freed);

        let err = inner
            .map_write(cluster_size, None)
            .expect_err("relocation must fail with the allocator exhausted");
        assert_eq!(err.raw_os_error(), Some(libc::ENOSPC));
        assert!(
            inner.avail_clusters.is_empty(),
            "the failure must land on the L2 relocation, with every candidate consumed"
        );

        assert_eq!(
            inner.l1_table[0], live_l2,
            "L1 must still reference the old table after the failed write"
        );
        assert!(
            !inner.unref_clusters.contains(&live_l2) && !inner.avail_clusters.contains(&live_l2),
            "a still-referenced L2 table must never enter the free lists"
        );
    }

    // The same defect is reached constantly by images holding compressed
    // clusters: writing to a compressed cluster always takes the
    // decompress -> append_data_cluster -> update_cluster_addr path, so every
    // such write relocates its L2 table.
    #[test]
    fn failed_l2_relocate_after_compressed_write_keeps_live_table() {
        use std::os::unix::fs::FileExt;

        const COMPRESSED_FLAG: u64 = 1 << 62;
        let cluster_size: u64 = 1 << 16;
        let temp = super::super::QcowTempDisk::new(64 * cluster_size, None, false, true, false)
            .unwrap()
            .into_tempfile();

        // Seed an L2 table plus a data cluster, flush, then compress that data
        // cluster in place so re-writing it takes the compressed path.
        {
            let raw = crate::AlignedFile::new(temp.as_file().try_clone().unwrap(), false);
            let (mut inner, _backing, _sparse) =
                super::super::parser::parse_qcow(raw, 0, true).unwrap();
            inner
                .map_write(0, Some(vec![0xab; cluster_size as usize]))
                .expect("seed write");
            inner.sync_caches().expect("flush");
        }
        super::super::common::tests::compress_allocated_clusters(
            &mut temp.as_file().try_clone().unwrap(),
        );

        // Re-open so the L2 cache reflects the on-disk compressed entry.
        let raw = crate::AlignedFile::new(temp.as_file().try_clone().unwrap(), false);
        let (mut inner, _backing, _sparse) =
            super::super::parser::parse_qcow(raw, 0, true).unwrap();
        let live_l2 = inner.l1_table[0];
        assert_ne!(live_l2, 0);

        // An already allocated plain cluster would be written in place with no
        // relocation, so confirm the seed really is compressed.
        let mut entry = [0u8; 8];
        temp.as_file().read_exact_at(&mut entry, live_l2).unwrap();
        assert_ne!(
            u64::from_be_bytes(entry) & COMPRESSED_FLAG,
            0,
            "the seed cluster must be compressed to trigger the relocation"
        );

        // Cap file growth at the current horizon and leave exactly two free
        // clusters: enough for the write's data cluster and the refcount block
        // relocation it triggers, but nothing for relocating the L2 table.
        let file_clusters = inner
            .raw_file
            .file_mut()
            .metadata()
            .unwrap()
            .len()
            .div_ceil(cluster_size);
        inner.refcounts = super::super::refcount::RefCount::new(
            &mut inner.raw_file,
            inner.header.refcount_table_offset,
            1,
            file_clusters,
            cluster_size,
            16,
        )
        .unwrap();
        let mut free = super::mem::take(&mut inner.avail_clusters);
        free.retain(|&c| c != live_l2 && c != 0);
        assert!(free.len() >= 2, "need two free clusters for the budget");
        inner.avail_clusters.clear();
        inner.avail_clusters.push(free[0]);
        inner.avail_clusters.push(free[1]);

        let err = inner
            .map_write(0, None)
            .expect_err("the L2 relocation must fail with the allocator exhausted");
        assert_eq!(err.raw_os_error(), Some(libc::ENOSPC));

        assert_eq!(
            inner.l1_table[0], live_l2,
            "L1 must still reference the old table after the failed write"
        );
        assert!(
            !inner.unref_clusters.contains(&live_l2) && !inner.avail_clusters.contains(&live_l2),
            "a still-referenced L2 table must never enter the free lists"
        );
    }

    #[test]
    fn fresh_l2_enospc_reopen_does_not_reuse_live_table() {
        let cluster_size: u64 = 1 << 16;
        let temp = super::super::QcowTempDisk::new(4 * cluster_size, None, false, true, false)
            .unwrap()
            .into_tempfile();

        let live_l2 = {
            let raw = crate::AlignedFile::new(temp.as_file().try_clone().unwrap(), false);
            let (mut inner, _backing, _sparse) =
                super::super::parser::parse_qcow(raw, 0, true).unwrap();
            assert_eq!(inner.l1_table[0], 0);

            // Add exactly two addressable clusters and cap file growth there. On
            // baseline the fresh L2 consumes the higher cluster, the data/refcount
            // path consumes the lower one, and ENOSPC drops the deferred L2 owner.
            // With ownership-before-publication the lower cluster can instead be
            // consumed by refcount-block relocation before data allocation fails.
            let file_size = inner.raw_file.file_mut().metadata().unwrap().len();
            assert_eq!(file_size % cluster_size, 0);
            inner
                .raw_file
                .file_mut()
                .set_len(file_size + 2 * cluster_size)
                .unwrap();
            let file_clusters = (file_size + 2 * cluster_size) / cluster_size;
            inner.refcounts = super::super::refcount::RefCount::new(
                &mut inner.raw_file,
                inner.header.refcount_table_offset,
                1,
                file_clusters,
                cluster_size,
                16,
            )
            .unwrap();
            inner.avail_clusters.clear();
            inner.unref_clusters.clear();
            inner.avail_clusters.push(file_size);
            inner.avail_clusters.push(file_size + cluster_size);

            let err = inner
                .map_write(0, None)
                .expect_err("allocator exhaustion must fail the first write");
            assert_eq!(err.raw_os_error(), Some(libc::ENOSPC));

            let live_l2 = inner.l1_table[0];
            assert_ne!(live_l2, 0, "the failed write must have wired a fresh L2");

            let _metadata = super::QcowMetadata::new(inner);
            live_l2
        };

        let raw = crate::AlignedFile::new(temp.as_file().try_clone().unwrap(), false);
        let (mut reopened, _backing, _sparse) =
            super::super::parser::parse_qcow(raw, 0, true).unwrap();
        assert_eq!(reopened.l1_table[0], live_l2);

        let live_refcount = {
            let super::QcowState {
                refcounts,
                raw_file,
                ..
            } = &mut reopened;
            refcounts.get_cluster_refcount(raw_file, live_l2).unwrap()
        };
        let live_marked_free = reopened.avail_clusters.contains(&live_l2);
        let next_allocation = reopened
            .get_new_cluster(None)
            .expect("allocator should return a cluster other than live_l2");

        assert_ne!(
            next_allocation, live_l2,
            "clean reopen allocator must not return a still-referenced L2 cluster"
        );
        assert!(
            !live_marked_free,
            "clean reopen must keep a referenced fresh L2 out of the free list"
        );
        assert_eq!(
            live_refcount, 1,
            "clean reopen must retain ownership for the referenced fresh L2"
        );
    }

    #[test]
    fn successful_l2_relocation_releases_old_table() {
        let cluster_size: u64 = 1 << 16;
        let temp = super::super::QcowTempDisk::new(64 * cluster_size, None, false, true, false)
            .unwrap()
            .into_tempfile();
        let raw = crate::AlignedFile::new(temp.as_file().try_clone().unwrap(), false);
        let (mut inner, _backing, _sparse) =
            super::super::parser::parse_qcow(raw, 0, true).unwrap();

        inner.map_write(0, None).expect("initial write");
        inner.sync_caches().expect("make the current L2 clean");
        let old_l2 = inner.l1_table[0];
        assert_ne!(old_l2, 0);

        inner
            .map_write(cluster_size, None)
            .expect("relocate clean L2");
        let relocated_l2 = inner.l1_table[0];
        assert_ne!(relocated_l2, 0);
        assert_ne!(relocated_l2, old_l2);

        let (old_refcount, relocated_refcount) = {
            let super::QcowState {
                refcounts,
                raw_file,
                ..
            } = &mut inner;
            (
                refcounts.get_cluster_refcount(raw_file, old_l2).unwrap(),
                refcounts
                    .get_cluster_refcount(raw_file, relocated_l2)
                    .unwrap(),
            )
        };
        assert_eq!(
            old_refcount, 0,
            "successful relocation must release the old L2 refcount"
        );
        assert_eq!(
            relocated_refcount, 1,
            "successful relocation must retain ownership for the replacement L2"
        );
        assert!(
            inner.unref_clusters.contains(&old_l2),
            "the released old L2 must wait for metadata flush before reuse"
        );
        assert!(
            !inner.avail_clusters.contains(&old_l2),
            "the old L2 must not be reusable before metadata flush"
        );
        assert!(
            !inner.unref_clusters.contains(&relocated_l2)
                && !inner.avail_clusters.contains(&relocated_l2),
            "the replacement L2 must stay off the free lists"
        );

        let metadata = super::QcowMetadata::new(inner);
        metadata.flush().expect("publish the released old L2");
        let inner = metadata.inner.read().unwrap();
        assert!(
            inner.avail_clusters.contains(&old_l2),
            "metadata flush must make the released old L2 reusable"
        );
        assert!(
            !inner.avail_clusters.contains(&relocated_l2),
            "metadata flush must keep the replacement L2 allocated"
        );
    }

    #[test]
    fn zero_marker_fresh_l2_keeps_refcount_owner() {
        let cluster_size: u64 = 1 << 16;
        let temp = super::super::QcowTempDisk::new(4 * cluster_size, None, false, true, false)
            .unwrap()
            .into_tempfile();
        let raw = crate::AlignedFile::new(temp.as_file().try_clone().unwrap(), false);
        let (mut inner, _backing, _sparse) =
            super::super::parser::parse_qcow(raw, 0, true).unwrap();
        assert_eq!(inner.l1_table[0], 0);

        inner
            .deallocate_cluster(0, true, true)
            .expect("zero-marker deallocation must allocate its metadata table");
        let live_l2 = inner.l1_table[0];
        assert_ne!(live_l2, 0);
        let refcount = {
            let super::QcowState {
                refcounts,
                raw_file,
                ..
            } = &mut inner;
            refcounts.get_cluster_refcount(raw_file, live_l2).unwrap()
        };
        assert_eq!(refcount, 1);
    }
}
