// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

#![allow(dead_code)] // wired in by qcow_sync
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
use std::io::{self, Seek};
use std::mem;
use std::sync::RwLock;

use libc::{EINVAL, EIO};

use super::qcow_raw_file::QcowRawFile;
use super::refcount::RefCount;
use super::util::{
    div_round_up_u64, l1_entry_make, l2_entry_compressed_cluster_layout, l2_entry_is_compressed,
    l2_entry_is_empty, l2_entry_is_zero, l2_entry_make_std, l2_entry_make_zero,
    l2_entry_std_cluster_addr,
};
use super::vec_cache::{CacheMap, Cacheable, VecCache};
use super::{QcowHeader, refcount};

/// Describes how to satisfy a guest read for a single cluster region.
///
/// Returned by QcowMetadata::map_clusters_for_read. The caller performs
/// the actual data I/O using its own per queue file descriptor without
/// holding the metadata lock.
#[derive(Debug)]
pub enum ClusterReadMapping {
    /// The cluster is not allocated and the guest should see zeros.
    /// This covers both truly unallocated clusters where the L1 or L2
    /// entry is zero and clusters with the ZERO flag set.
    Zero { length: u64 },

    /// The cluster is allocated at the given host file offset.
    /// The offset is the exact byte position combining cluster base and
    /// intra cluster offset. The length is the number of bytes to read,
    /// bounded by cluster boundary and guest request.
    Allocated { offset: u64, length: u64 },

    /// The cluster is compressed. The decompressed data is returned inline
    /// because decompression is a CPU only operation that was done under the
    /// write lock to access the raw compressed bytes from disk.
    ///
    /// The data field contains exactly the bytes the guest requested, already
    /// sliced from the decompressed cluster.
    Compressed { data: Vec<u8> },

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
pub enum ClusterWriteMapping {
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
pub enum DeallocAction {
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
pub struct QcowMetadata {
    inner: RwLock<QcowState>,
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
    pub fn map_clusters_for_read(
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
    pub fn map_cluster_for_write(
        &self,
        address: u64,
        backing_data: Option<Vec<u8>>,
    ) -> io::Result<ClusterWriteMapping> {
        let mut inner = self.inner.write().unwrap();
        inner.map_write(address, backing_data)
    }

    pub fn flush(&self) -> io::Result<()> {
        let mut inner = self.inner.write().unwrap();
        inner.sync_caches()?;
        let mut unref = mem::take(&mut inner.unref_clusters);
        inner.avail_clusters.append(&mut unref);
        Ok(())
    }

    /// Flushes dirty metadata caches and clears the dirty bit for
    /// clean shutdown.
    pub fn shutdown(&self) {
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
    pub fn resize(&self, new_size: u64) -> io::Result<()> {
        let mut inner = self.inner.write().unwrap();
        inner.resize(new_size)
    }

    /// Deallocates a cluster at the given guest address.
    ///
    /// Returns the host offset when the caller should punch a hole in
    /// sparse mode after the refcount dropped to zero. Returns None if
    /// no host level action is needed.
    pub fn deallocate_cluster(&self, address: u64, sparse: bool) -> io::Result<Option<u64>> {
        let mut inner = self.inner.write().unwrap();
        inner.deallocate_cluster(address, sparse)
    }

    /// Deallocates a range of bytes. Full clusters are deallocated via metadata.
    /// Partial clusters need the caller to write zeros. This method returns a
    /// list of actions the caller should take.
    pub(crate) fn deallocate_bytes(
        &self,
        address: u64,
        length: usize,
        sparse: bool,
        virtual_size: u64,
        cluster_size: u64,
        backing_file: Option<&dyn BackingRead>,
    ) -> io::Result<Vec<DeallocAction>> {
        if address.checked_add(length as u64).is_none() {
            return Ok(Vec::new());
        }
        let mut inner = self.inner.write().unwrap();
        let mut actions = Vec::new();

        let file_end = virtual_size;
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
                let punch_offset = inner.deallocate_cluster(curr_addr, sparse)?;
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

    pub fn virtual_size(&self) -> u64 {
        self.inner.read().unwrap().header.size
    }

    pub fn cluster_size(&self) -> u64 {
        self.inner.read().unwrap().raw_file.cluster_size()
    }

    /// Returns the intra cluster byte offset for a given guest address.
    pub fn cluster_offset(&self, address: u64) -> u64 {
        self.inner.read().unwrap().raw_file.cluster_offset(address)
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

        // Compressed entries require disk I/O for decompression - can't do
        // that under a read lock. Fall through to the write lock path.
        if l2_entry_is_compressed(l2_entry) {
            return Ok(None);
        }

        if l2_entry_is_empty(l2_entry) {
            Ok(Some(self.unallocated_read_mapping(
                address,
                count,
                has_backing_file,
            )))
        } else if l2_entry_is_zero(l2_entry) {
            // Match original QcowFile::file_read semantics where zero flagged
            // entries fall through to backing file when one exists or return
            // zeros otherwise.
            Ok(Some(self.unallocated_read_mapping(
                address,
                count,
                has_backing_file,
            )))
        } else {
            let cluster_addr = l2_entry_std_cluster_addr(l2_entry);
            let cluster_size = self.raw_file.cluster_size();
            if cluster_addr & (cluster_size - 1) != 0 {
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
            // Under write lock we can do I/O for decompression
            let decompressed = self.decompress_l2_cluster(l2_entry)?;
            let start = self.raw_file.cluster_offset(address) as usize;
            let end = start
                .checked_add(count)
                .ok_or_else(|| io::Error::from_raw_os_error(EINVAL))?;
            if end > decompressed.len() {
                return Err(io::Error::from_raw_os_error(EINVAL));
            }
            Ok(ClusterReadMapping::Compressed {
                data: decompressed[start..end].to_vec(),
            })
        } else if l2_entry_is_zero(l2_entry) {
            // Match original QcowFile::file_read semantics where zero flagged
            // entries fall through to backing file when one exists or return
            // zeros otherwise.
            Ok(self.unallocated_read_mapping(address, count, has_backing_file))
        } else {
            let cluster_addr = l2_entry_std_cluster_addr(l2_entry);
            let cluster_size = self.raw_file.cluster_size();
            if cluster_addr & (cluster_size - 1) != 0 {
                self.set_corrupt_bit_best_effort();
                return Err(io::Error::from_raw_os_error(EIO));
            }
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

    /// Maps a single cluster region for a sequential read.
    pub(crate) fn map_cluster_read(
        &mut self,
        address: u64,
        count: usize,
        has_backing_file: bool,
    ) -> io::Result<ClusterReadMapping> {
        match self.try_map_read(address, count, has_backing_file)? {
            Some(mapping) => Ok(mapping),
            None => self.map_read_with_populate(address, count, has_backing_file),
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

        let mut set_refcounts = Vec::new();

        if let Some(new_addr) = self.cache_l2_cluster_alloc(l1_index, l2_addr_disk)? {
            set_refcounts.push((new_addr, 1));
        }

        let l2_entry = self.l2_cache.get(l1_index).unwrap()[l2_index];
        let cluster_addr = if l2_entry_is_compressed(l2_entry) {
            let decompressed_cluster = self.decompress_l2_cluster(l2_entry)?;
            let cluster_addr = self.append_data_cluster(None)?;
            self.update_cluster_addr(l1_index, l2_index, cluster_addr, &mut set_refcounts)?;
            self.raw_file
                .file_mut()
                .seek(io::SeekFrom::Start(cluster_addr))?;
            let nwritten = io::Write::write(self.raw_file.file_mut(), &decompressed_cluster)?;
            if nwritten != decompressed_cluster.len() {
                self.set_corrupt_bit_best_effort();
                return Err(io::Error::from_raw_os_error(EIO));
            }
            self.deallocate_compressed_cluster(l2_entry)?;
            cluster_addr
        } else if l2_entry_is_empty(l2_entry) || l2_entry_is_zero(l2_entry) {
            let cluster_addr = self.append_data_cluster(backing_data)?;
            self.update_cluster_addr(l1_index, l2_index, cluster_addr, &mut set_refcounts)?;
            cluster_addr
        } else {
            // Already allocated - validate alignment
            let cluster_addr = l2_entry_std_cluster_addr(l2_entry);
            if cluster_addr & (self.raw_file.cluster_size() - 1) != 0 {
                self.set_corrupt_bit_best_effort();
                return Err(io::Error::from_raw_os_error(EIO));
            }
            cluster_addr
        };

        // Apply deferred refcount updates
        for (addr, refcount) in set_refcounts {
            self.set_cluster_refcount_track_freed(addr, refcount)?;
        }

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

    // -- Cache and allocation operations requiring exclusive access --

    /// Populates the L2 cache for read operations without allocation.
    fn cache_l2_cluster(&mut self, l1_index: usize, l2_addr_disk: u64) -> io::Result<()> {
        if !self.l2_cache.contains_key(l1_index) {
            let cluster_size = self.raw_file.cluster_size();
            if l2_addr_disk & (cluster_size - 1) != 0 {
                self.set_corrupt_bit_best_effort();
                return Err(io::Error::from_raw_os_error(EIO));
            }
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
    /// L2 table. Returns the address of the newly allocated cluster if any.
    fn cache_l2_cluster_alloc(
        &mut self,
        l1_index: usize,
        l2_addr_disk: u64,
    ) -> io::Result<Option<u64>> {
        let mut new_cluster: Option<u64> = None;
        if !self.l2_cache.contains_key(l1_index) {
            let l2_table = if l2_addr_disk == 0 {
                // Allocate a new cluster to store the L2 table
                let new_addr = self.get_new_cluster(None)?;
                new_cluster = Some(new_addr);
                self.l1_table[l1_index] = new_addr;
                VecCache::new(self.l2_entries as usize)
            } else {
                let cluster_size = self.raw_file.cluster_size();
                if l2_addr_disk & (cluster_size - 1) != 0 {
                    self.set_corrupt_bit_best_effort();
                    return Err(io::Error::from_raw_os_error(EIO));
                }
                VecCache::from_vec(self.raw_file.read_pointer_cluster(l2_addr_disk, None)?)
            };
            let l1_table = &self.l1_table;
            let raw_file = &mut self.raw_file;
            self.l2_cache.insert(l1_index, l2_table, |index, evicted| {
                raw_file.write_pointer_table_direct(l1_table[index], evicted.iter())
            })?;
        }
        Ok(new_cluster)
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

    /// Updates the L1 and L2 tables to point to a new cluster address.
    fn update_cluster_addr(
        &mut self,
        l1_index: usize,
        l2_index: usize,
        cluster_addr: u64,
        set_refcounts: &mut Vec<(u64, u64)>,
    ) -> io::Result<()> {
        if !self.l2_cache.get(l1_index).unwrap().dirty() {
            // Free the previously used cluster if one exists. Modified tables are always
            // written to new clusters so the L1 table can be committed to disk after they
            // are and L1 never points at an invalid table.
            let addr = self.l1_table[l1_index];
            if addr != 0 {
                self.unref_clusters.push(addr);
                set_refcounts.push((addr, 0));
            }

            // Allocate a new cluster to store the L2 table and update the L1 table to point
            // to the new table. The cluster will be written when the cache is flushed.
            let new_addr = self.get_new_cluster(None)?;
            set_refcounts.push((new_addr, 1));
            self.l1_table[l1_index] = new_addr; // marks l1_table dirty via IndexMut
        }
        // Write the L2 entry - IndexMut marks the L2 table dirty automatically.
        self.l2_cache.get_mut(l1_index).unwrap()[l2_index] = l2_entry_make_std(cluster_addr);
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

        self.raw_file.file_mut().rewind()?;
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
        let file_size = self.raw_file.file_mut().seek(io::SeekFrom::End(0))?;
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

        self.raw_file.file_mut().rewind()?;
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
    /// possible.
    ///
    /// Returns None if no host punch_hole is needed.
    pub(super) fn deallocate_cluster(
        &mut self,
        address: u64,
        sparse: bool,
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

        if l2_addr_disk == 0 {
            return Ok(None);
        }

        self.cache_l2_cluster(l1_index, l2_addr_disk)?;

        let l2_entry = self.l2_cache.get(l1_index).unwrap()[l2_index];
        if l2_entry_is_empty(l2_entry) || l2_entry_is_zero(l2_entry) {
            return Ok(None);
        }

        if l2_entry_is_compressed(l2_entry) {
            self.deallocate_compressed_cluster(l2_entry)?;
            self.l2_cache.get_mut(l1_index).unwrap()[l2_index] = 0;
            return Ok(None);
        }

        let cluster_addr = l2_entry_std_cluster_addr(l2_entry);
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
            self.l2_cache.get_mut(l1_index).unwrap()[l2_index] = 0;
            if new_refcount == 0 {
                self.unref_clusters.push(cluster_addr);
                return Ok(Some(cluster_addr));
            }
        } else if refcount == 1 {
            self.l2_cache.get_mut(l1_index).unwrap()[l2_index] = l2_entry_make_zero(cluster_addr);
        } else {
            self.set_cluster_refcount_track_freed(cluster_addr, refcount - 1)?;
            self.l2_cache.get_mut(l1_index).unwrap()[l2_index] = 0;
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
    pub(super) fn sync_caches(&mut self) -> io::Result<()> {
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
        self.raw_file
            .file_mut()
            .seek(io::SeekFrom::Start(compressed_addr))?;
        let mut compressed = vec![0u8; compressed_size];
        io::Read::read_exact(self.raw_file.file_mut(), &mut compressed)?;
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
