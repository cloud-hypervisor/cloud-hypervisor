// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Shared harness code for the Cloud Hypervisor fuzz targets.
//!
//! [`disk_engine`] is the format agnostic fuzzing framework for the disk
//! image engine in the `block` crate.

pub mod disk_engine;
