// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Disk format implementations.
//!
//! Each format lives in its own submodule with a `DiskFile` wrapper,
//! format specific internals, and sync/async I/O workers.

pub mod raw;
pub mod vhd;
pub mod vhdx;
