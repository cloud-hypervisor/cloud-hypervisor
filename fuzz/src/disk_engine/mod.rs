// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Format agnostic fuzzing framework for the disk image engine.
//!
//! # Fuzzed boundary
//!
//! The disk image engine is everything between the point where untrusted
//! image bytes are parsed ([`block::factory::open_disk`] and the per format
//! constructors) and the trait contract the rest of the VMM consumes
//! ([`block::disk_file::AsyncFullDiskFile`] and [`block::async_io::AsyncIo`]).
//! Virtio request parsing sits above that line and is fuzzed by the `block`
//! target instead.
//!

mod format;
mod image;

pub use crate::disk_engine::format::{DiskFormat, OpenConfig};
pub use crate::disk_engine::image::{image_file, image_memfd, scratch_dir};
