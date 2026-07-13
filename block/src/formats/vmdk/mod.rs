// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Flat VMDK block backend.
//!
//! Supports the `monolithicFlat` and `twoGbMaxExtentFlat` create types with
//! synchronous, extent-aware I/O.

mod descriptor;

pub use descriptor::{has_descriptor_header, is_flat_vmdk};
