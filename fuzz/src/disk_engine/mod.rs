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
pub mod formats;
mod image;
mod model;
mod program;

use std::collections::{HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::PathBuf;
use std::sync::Mutex;

use block::ImageType;
use libfuzzer_sys::Corpus;

pub use crate::disk_engine::executor::Executor;
pub use crate::disk_engine::format::{DiskFormat, OpenConfig};
pub use crate::disk_engine::image::{image_file, image_memfd, scratch_dir};
pub use crate::disk_engine::model::Model;
pub use crate::disk_engine::program::{
    default_program, Op, OpLen, OpOffset, Program, MAX_OPS, MAX_OP_LEN,
};

/// How many inputs failing [`DiskFormat::magic_ok`] are kept per length
/// class. Parsers do work before the magic check, so some must be kept.
const NON_MAGIC_BUDGET: usize = 8;

/// Length class of an input, its binary magnitude, so the budget keeps short
/// inputs too.
fn length_class(len: usize) -> u32 {
    usize::BITS - len.leading_zeros()
}

/// Whether to keep an input that failed the magic check.
fn keep_non_magic(bytes: &[u8]) -> Corpus {
    static SEEN: Mutex<Option<HashMap<u32, HashSet<u64>>>> = Mutex::new(None);

    let mut hasher = DefaultHasher::new();
    bytes.hash(&mut hasher);
    let digest = hasher.finish();

    let Ok(mut guard) = SEEN.lock() else {
        return Corpus::Reject;
    };
    let seen = guard
        .get_or_insert_with(HashMap::new)
        .entry(length_class(bytes.len()))
        .or_default();
    if seen.len() < NON_MAGIC_BUDGET && seen.insert(digest) {
        Corpus::Keep
    } else {
        Corpus::Reject
    }
}

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

    // Inputs without the magic are still opened.
    let verdict = if F::magic_ok(bytes) {
        Corpus::Keep
    } else {
        keep_non_magic(bytes)
    };

    let Ok(disk) = F::open(file, path.as_deref(), &OpenConfig::default()) else {
        return verdict;
    };

    if let Some(mut executor) = Executor::<F>::new(disk, 1, false) {
        executor.run(&default_program());
    }

    verdict
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_classes_separate_magnitudes() {
        assert_eq!(length_class(0), 0);
        assert_eq!(length_class(1), 1);
        assert_eq!(length_class(511), length_class(300));
        assert_ne!(length_class(511), length_class(512));
    }

    // A megabyte of rejects must not use up the budget for tiny inputs.
    #[test]
    fn the_non_magic_budget_is_per_length_class() {
        let kept = |bytes: &[u8]| matches!(keep_non_magic(bytes), Corpus::Keep);

        // Fill one class.
        for i in 0..NON_MAGIC_BUDGET {
            assert!(kept(&[i as u8; 4096]), "input {i} of the budget");
        }
        assert!(!kept(&[0xaa; 4096]), "the class budget is spent");
        // A repeat is not kept.
        assert!(!kept(&[0u8; 4096]));

        // A different magnitude has its own budget.
        assert!(kept(b"1"), "a one byte input is a different class");
        assert!(kept(b"12"));
    }
}
