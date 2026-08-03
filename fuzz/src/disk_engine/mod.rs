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

mod executor;
mod format;
mod image;
mod model;
mod program;

pub use crate::disk_engine::executor::Executor;
pub use crate::disk_engine::format::{DiskFormat, OpenConfig};
pub use crate::disk_engine::image::{image_file, image_memfd, scratch_dir};
pub use crate::disk_engine::model::Model;
pub use crate::disk_engine::program::{
    default_program, Op, OpLen, OpOffset, Program, MAX_OPS, MAX_OP_LEN,
};
