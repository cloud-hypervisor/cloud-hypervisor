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
//! # Target families
//!
//! Each format gets two targets so that every target has one coherent,
//! mutation friendly input space:
//!
//! - `disk_<format>` calls [`fuzz_image`]: the whole input is the image, and
//!   a fixed op program runs against whatever the engine made of it. Corpus
//!   entries are real disk images, so `qemu-img` output can be dropped in
//!   unmodified. This targets the parsers.
//! - `disk_<format>_ops` calls [`fuzz_program`]: the image is a valid
//!   template built by the format adapter and the input is an arbitrary op
//!   program. Because the image is well formed, the executor can run a shadow
//!   model of the disk contents and check read back data. This targets the
//!   offset translation, allocation and sparse handling logic.
//!
//! # Adding a format
//!
//! Implement [`DiskFormat`] for the new format, then add two targets that call
//! [`fuzz_image`] and [`fuzz_program`] with the new adapter. Nothing else in
//! the framework is format specific.

mod executor;
mod format;
mod image;
mod model;
mod program;

use std::path::PathBuf;

use libfuzzer_sys::Corpus;

pub use crate::disk_engine::executor::Executor;
pub use crate::disk_engine::format::{DiskFormat, OpenConfig};
pub use crate::disk_engine::image::{image_file, image_memfd, scratch_dir};
pub use crate::disk_engine::model::Model;
pub use crate::disk_engine::program::{
    default_program, Op, OpLen, OpOffset, Program, MAX_OPS, MAX_OP_LEN,
};

/// Fuzzes the format parsers with `bytes` as the complete disk image.
///
/// The image is materialized in a memfd, opened through the format adapter,
/// and driven with [`default_program`]. Contents are unknown, so the
/// executor runs without the shadow model and only checks the invariants that
/// hold for any image (completion accounting, reported byte counts, stable
/// reported size).
pub fn fuzz_image<F: DiskFormat>(bytes: &[u8]) -> Corpus {
    if bytes.len() > F::MAX_IMAGE_LEN {
        return Corpus::Reject;
    }

    let Ok((file, path)) = materialize::<F>(bytes) else {
        return Corpus::Reject;
    };

    // Cover the format sniffing path with the same bytes. The result is not
    // asserted: the target forces its own format so that malformed images
    // still reach the parser under test.
    if let Ok(mut probe) = file.try_clone() {
        let _ = block::detect_image_type(&mut probe);
    }

    let Ok(disk) = F::open(file, path.as_deref(), &OpenConfig::default()) else {
        return Corpus::Keep;
    };

    if let Some(mut executor) = Executor::<F>::new(disk, 1, false) {
        executor.run(&default_program());
    }

    Corpus::Keep
}

/// Fuzzes the engine op handling with an arbitrary program.
///
/// The image is the format adapter's valid template, so the executor runs
/// with the shadow model enabled and read back data is checked against it.
///
/// Only formats that build a template in process can be fuzzed this way, so
/// a missing template is a harness error rather than a finding.
pub fn fuzz_program<F: DiskFormat>(program: &Program) -> Corpus {
    let template =
        F::template().unwrap_or_else(|| panic!("{}: format has no template image", F::NAME));
    let Ok((file, path)) = materialize::<F>(template) else {
        return Corpus::Reject;
    };

    // A template that does not open means the adapter is broken, which is a
    // harness bug rather than a finding, so fail loudly.
    let disk = F::open(file, path.as_deref(), &program.open)
        .unwrap_or_else(|e| panic!("{}: template image failed to open: {e}", F::NAME));

    let Some(mut executor) = Executor::<F>::new(disk, program.ring_depth(), true) else {
        return Corpus::Reject;
    };
    executor.run(program.ops());

    Corpus::Keep
}

/// Materializes an image the way the format needs it.
///
/// Most formats get a memfd, which keeps an iteration off the filesystem. A
/// format that resolves sibling files relative to the image gets a real file
/// in a scratch directory instead.
fn materialize<F: DiskFormat>(bytes: &[u8]) -> std::io::Result<(std::fs::File, Option<PathBuf>)> {
    if F::NEEDS_PATH {
        let (file, path) = image_file(F::NAME, bytes)?;
        Ok((file, Some(path)))
    } else {
        Ok((image_memfd(F::NAME, bytes)?, None))
    }
}
