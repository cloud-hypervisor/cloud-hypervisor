// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

//! Pure helper functions and constants for QCOW2 L1/L2 table entry
//! manipulation and integer arithmetic. Shared across the `qcow` submodules.

/// Nesting depth limit for disk formats that can open other disk files.
pub(crate) const MAX_NESTING_DEPTH: u32 = 10;

// bits 0-8 and 56-63 are reserved.
pub(super) const L1_TABLE_OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;
pub(super) const L2_TABLE_OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;
// Flags
pub(super) const ZERO_FLAG: u64 = 1 << 0;
pub(super) const COMPRESSED_FLAG: u64 = 1 << 62;
pub(super) const COMPRESSED_SECTOR_SIZE: u64 = 512;
pub(super) const CLUSTER_USED_FLAG: u64 = 1 << 63;

/// Check if L2 entry is empty (unallocated).
pub(super) fn l2_entry_is_empty(l2_entry: u64) -> bool {
    l2_entry == 0
}

/// Check bit 0 - only valid for standard clusters.
pub(super) fn l2_entry_is_zero(l2_entry: u64) -> bool {
    l2_entry & ZERO_FLAG != 0
}

/// Check if L2 entry refers to a compressed cluster.
pub(super) fn l2_entry_is_compressed(l2_entry: u64) -> bool {
    l2_entry & COMPRESSED_FLAG != 0
}

/// Get file offset and size of compressed cluster data.
pub(super) fn l2_entry_compressed_cluster_layout(l2_entry: u64, cluster_bits: u32) -> (u64, usize) {
    let compressed_size_shift = 62 - (cluster_bits - 8);
    let compressed_size_mask = (1 << (cluster_bits - 8)) - 1;
    let compressed_cluster_addr = l2_entry & ((1 << compressed_size_shift) - 1);
    let nsectors = (l2_entry >> compressed_size_shift & compressed_size_mask) + 1;
    let compressed_cluster_size = ((nsectors * COMPRESSED_SECTOR_SIZE)
        - (compressed_cluster_addr & (COMPRESSED_SECTOR_SIZE - 1)))
        as usize;
    (compressed_cluster_addr, compressed_cluster_size)
}

/// Get file offset of standard (non-compressed) cluster.
pub(super) fn l2_entry_std_cluster_addr(l2_entry: u64) -> u64 {
    l2_entry & L2_TABLE_OFFSET_MASK
}

/// Make L2 entry for standard (non-compressed) cluster.
pub(super) fn l2_entry_make_std(cluster_addr: u64) -> u64 {
    (cluster_addr & L2_TABLE_OFFSET_MASK) | CLUSTER_USED_FLAG
}

/// Make L2 entry for preallocated zero cluster.
pub(super) fn l2_entry_make_zero(cluster_addr: u64) -> u64 {
    (cluster_addr & L2_TABLE_OFFSET_MASK) | CLUSTER_USED_FLAG | ZERO_FLAG
}

/// Make L1 entry with optional flags.
pub(super) fn l1_entry_make(cluster_addr: u64, refcount_is_one: bool) -> u64 {
    (cluster_addr & L1_TABLE_OFFSET_MASK) | (refcount_is_one as u64 * CLUSTER_USED_FLAG)
}

/// Ceiling of the division of `dividend`/`divisor`.
pub(super) fn div_round_up_u32(dividend: u32, divisor: u32) -> u32 {
    dividend / divisor + u32::from(!dividend.is_multiple_of(divisor))
}

/// Ceiling of the division of `dividend`/`divisor`.
pub(super) fn div_round_up_u64(dividend: u64, divisor: u64) -> u64 {
    dividend / divisor + u64::from(!dividend.is_multiple_of(divisor))
}
