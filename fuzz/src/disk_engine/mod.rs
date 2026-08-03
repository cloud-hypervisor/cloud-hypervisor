// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Format agnostic fuzzing of the disk image engine, from image parsing to
//! the `AsyncFullDiskFile` and `AsyncIo` contract.
//!
//! - `disk_<format>` ([`fuzz_image`]): the input is the image.
//! - `disk_<format>_ops` ([`fuzz_program`]): the input is an op program run
//!   against a template and checked by a shadow model.

mod executor;
mod format;
mod image;
mod model;
mod program;

use std::path::PathBuf;

use block::ImageType;
use libfuzzer_sys::Corpus;

pub use crate::disk_engine::executor::Executor;
pub use crate::disk_engine::format::{DiskFormat, OpenConfig};
pub use crate::disk_engine::image::{image_file, image_memfd, scratch_dir};
pub use crate::disk_engine::model::Model;
pub use crate::disk_engine::program::{
    default_program, Op, OpLen, OpOffset, Program, MAX_OPS, MAX_OP_LEN,
};

/// Fuzzes a format parser with `bytes` as the image, then runs
/// [`default_program`] without a model.
pub fn fuzz_image<F: DiskFormat>(bytes: &[u8]) -> Corpus {
    if bytes.len() > F::MAX_IMAGE_LEN {
        return Corpus::Reject;
    }

    let Ok((file, path)) = materialize::<F>(bytes) else {
        return Corpus::Reject;
    };

    // Also probe image type validation, once per type since each call confirms
    // one type. The answers are not asserted.
    if let Ok(mut probe) = file.try_clone() {
        for image_type in [
            ImageType::Qcow2,
            ImageType::FixedVhd,
            ImageType::Vhdx,
            ImageType::FlatVmdk,
        ] {
            let _ = block::validate_image_type(&mut probe, image_type);
        }
    }

    let Ok(disk) = F::open(file, path.as_deref(), &OpenConfig::default()) else {
        return Corpus::Keep;
    };

    if let Some(mut executor) = Executor::<F>::new(disk, 1, false) {
        executor.run(&default_program());
    }

    Corpus::Keep
}

/// Fuzzes a format's I/O path with `program`, under the shadow model.
pub fn fuzz_program<F: DiskFormat>(program: &Program) -> Corpus {
    let template =
        F::template().unwrap_or_else(|| panic!("{}: format has no template image", F::NAME));
    let Ok((file, path)) = materialize::<F>(template) else {
        return Corpus::Reject;
    };

    // A template that fails to open is a harness bug.
    let disk = F::open(file, path.as_deref(), &program.open)
        .unwrap_or_else(|e| panic!("{}: template image failed to open: {e}", F::NAME));

    let Some(mut executor) = Executor::<F>::new(disk, program.ring_depth(), true) else {
        return Corpus::Reject;
    };
    executor.run(program.ops());

    Corpus::Keep
}

/// Writes `bytes` to a memfd, or to a scratch file for `NEEDS_PATH` formats.
fn materialize<F: DiskFormat>(bytes: &[u8]) -> std::io::Result<(std::fs::File, Option<PathBuf>)> {
    if F::NEEDS_PATH {
        let (file, path) = image_file(F::NAME, bytes)?;
        Ok((file, Some(path)))
    } else {
        Ok((image_memfd(F::NAME, bytes)?, None))
    }
}
