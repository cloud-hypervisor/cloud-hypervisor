// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Helpers for constructing and inspecting QCOW2 test images.

use std::fs::File;
use std::os::unix::fs::FileExt;

pub(super) mod header_field {
    pub(crate) const CLUSTER_BITS: usize = 20;
    pub(crate) const SIZE: usize = 24;
    pub(crate) const CRYPT_METHOD: usize = 32;
    pub(crate) const L1_SIZE: usize = 36;
    pub(crate) const L1_TABLE_OFFSET: usize = 40;
    pub(crate) const REFCOUNT_TABLE_OFFSET: usize = 48;
    pub(crate) const REFCOUNT_TABLE_CLUSTERS: usize = 56;
    pub(crate) const NB_SNAPSHOTS: usize = 60;
    pub(crate) const INCOMPATIBLE_FEATURES: usize = 72;
    pub(crate) const AUTOCLEAR_FEATURES: usize = 88;
    pub(crate) const REFCOUNT_ORDER: usize = 96;
    pub(crate) const HEADER_LENGTH: usize = 100;
}

pub(super) fn patch_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

pub(super) fn patch_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}

pub(super) fn read_u64_at(file: &File, offset: u64) -> u64 {
    let mut bytes = [0; 8];
    file.read_exact_at(&mut bytes, offset).unwrap();
    u64::from_be_bytes(bytes)
}

pub(super) fn write_u64_at(file: &File, offset: u64, value: u64) {
    file.write_all_at(&value.to_be_bytes(), offset).unwrap();
}
