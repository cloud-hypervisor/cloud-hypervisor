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
//! Format sniffing is not part of either family: it accepts every byte
//! string, so a corpus driven by it fills up with inputs that no single
//! format can open. It gets its own target, [`fuzz_detect`], whose input
//! space is "any image of any format".
//!
//! Backing chains are not part of either family either. A qcow2 image names
//! its backing file by path, so the harness has to sandbox the filesystem
//! before the engine sees it, and the input is two images rather than one.
//! That lives in [`formats::qcow2_chain`], behind `disk_qcow2_chain`.
//!
//! # Adding a format
//!
//! Implement [`DiskFormat`] for the new format, then add two targets that call
//! [`fuzz_image`] and [`fuzz_program`] with the new adapter. Nothing else in
//! the framework is format specific.

mod executor;
mod format;
pub mod formats;
mod image;
mod model;
mod program;
pub mod sandbox;
#[cfg(test)]
mod selftest;

use std::collections::{HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::PathBuf;
use std::sync::Mutex;

use libfuzzer_sys::Corpus;

pub use crate::disk_engine::executor::Executor;
pub use crate::disk_engine::format::{DiskFormat, OpenConfig};
pub use crate::disk_engine::image::{
    image_file, image_memfd, scratch_dir, template_file, template_memfd,
};
pub use crate::disk_engine::model::Model;
pub use crate::disk_engine::program::{
    default_program, Op, OpLen, OpOffset, Program, MAX_OPS, MAX_OP_LEN,
};

/// How many distinct inputs that fail [`DiskFormat::magic_ok`] a process
/// keeps per length class.
///
/// Rejecting all of them would be wrong: a parser does real work before it
/// looks at the magic. `VhdFooter::new` queries the device size, does the
/// length arithmetic that finds the footer and computes the footer checksum,
/// and `VhdxHeader::new` reads and checksums both headers, all before the
/// signature test, and those paths are reached only by inputs that then fail
/// it. Measured per region on the campaign corpora, dropping every non magic
/// input loses 7 regions in `block` for `disk_vhd`, 3 for `disk_vhdx`, 9 for
/// `disk_vmdk` and 2 for `disk_qcow2`, so the budget is what keeps those
/// paths alive.
const NON_MAGIC_BUDGET: usize = 8;

/// Length class of an input, used to spread [`NON_MAGIC_BUDGET`] over input
/// sizes rather than over arrival order.
///
/// A flat budget is not enough. What the code in front of a magic check
/// branches on is the length: `FileTypeIdentifier::new` fails its eight byte
/// read (block/src/formats/vhdx/header.rs:99) and the VMDK descriptor reader
/// refuses a file shorter than four bytes
/// (block/src/formats/vmdk/descriptor.rs:83) only for inputs far smaller than
/// anything else in the corpus. A first come first served budget fills up
/// with megabyte sized rejects and those regions go uncovered, which is
/// measurable: a flat budget of 64 still lost exactly those two regions on
/// the campaign corpora. Bucketing by binary magnitude keeps one of every
/// size.
fn length_class(len: usize) -> u32 {
    usize::BITS - len.leading_zeros()
}

/// Decides whether an input that failed the magic check is worth keeping.
///
/// The budget is per process, per target and per length class, which is all
/// libFuzzer needs: the point is to stop an unbounded number of near
/// identical rejects from accumulating, not to pick the best ones.
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

/// Fuzzes the format parsers with `bytes` as the complete disk image.
///
/// The image is materialized in a memfd, opened through the format adapter,
/// and driven with [`default_program`]. Contents are unknown, so the
/// executor runs without the shadow model and only checks the invariants that
/// hold for any image (completion accounting, reported byte counts, stable
/// reported size).
///
/// An input that does not carry the format's identifying bytes is still
/// opened, so the code in front of the magic check stays covered, but it is
/// only retained while the [`NON_MAGIC_BUDGET`] for its length class lasts. Without that, the corpus
/// drowns in inputs that can never reach the parser: measured on a campaign
/// corpus, 634 of the 666 disk_vhd rejections were the `conectix` cookie
/// alone, and only 6 of 764 entries, 0.8%, opened at all.
pub fn fuzz_image<F: DiskFormat>(bytes: &[u8]) -> Corpus {
    if bytes.len() > F::MAX_IMAGE_LEN {
        return Corpus::Reject;
    }

    let Ok((file, path)) = materialize::<F>(bytes) else {
        return Corpus::Reject;
    };

    // The magic check is on the harness side, but the open is not: the
    // parser's own rejection path is part of what this target fuzzes.
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

/// Largest input [`fuzz_detect`] hands to the sniffer.
///
/// The sniffer only ever reads the first alignment sized block and, for the
/// VHD and VMDK probes, the tail of the file, so a large input costs the
/// materialization and buys nothing. The cap is the largest
/// [`DiskFormat::MAX_IMAGE_LEN`] in the tree so that a real image of any
/// supported format still fits.
const MAX_DETECT_LEN: usize = 16 << 20;

/// Fuzzes the image type sniffer with `bytes` as the complete image.
///
/// [`block::detect_image_type`] is what `factory::open_disk` runs before any
/// format specific parser, so it sees every byte string a guest owner can
/// point the VMM at, and it is the one piece of the engine whose input space
/// really is "anything". It used to be probed from [`fuzz_image`] with the
/// same bytes, which made every `disk_<format>` corpus pay for it: an input
/// that can never open as VHDX still found new edges in the qcow2, VHD and
/// VMDK sniffers and was kept in the `disk_vhdx` corpus forever. Measured on
/// a campaign corpus, 717 of 872 `disk_vhdx` entries failed the eight byte
/// `vhdxfile` signature yet persisted. Sniffing therefore gets its own
/// target, seeded with images of every format.
pub fn fuzz_detect(bytes: &[u8]) -> Corpus {
    if bytes.len() > MAX_DETECT_LEN {
        return Corpus::Reject;
    }

    let Ok(mut file) = image_memfd("detect", bytes) else {
        return Corpus::Reject;
    };

    // The result is not asserted: a sniffer answer is only a guess, and every
    // answer including `Raw` is a legitimate one for arbitrary bytes.
    let _ = block::detect_image_type(&mut file);

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
    let Ok((file, path)) = materialize_template::<F>(template) else {
        return Corpus::Reject;
    };

    // A template image names no backing file, but the switch is forced off
    // regardless: the shadow model this target runs with assumes that a
    // discarded cluster reads back as zeroes, which stops being true the
    // moment an image has a backing file. Backing chains are fuzzed by
    // `disk_qcow2_chain`, which runs without the model.
    let open = OpenConfig {
        backing: false,
        ..program.open
    };

    // A template that does not open means the adapter is broken, which is a
    // harness bug rather than a finding, so fail loudly.
    let disk = F::open(file, path.as_deref(), &open)
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

/// Materializes the format's fixed template image.
///
/// Same placement as [`materialize`], but the buffer is known to be the same
/// on every iteration, so only its non-zero pages are written. That is what
/// makes an operation target over a multi megabyte image affordable: see
/// [`crate::disk_engine::image::template_memfd`].
///
/// The buffer is `'static` because the page map cache holds onto its
/// identity: see [`crate::disk_engine::image::template_memfd`]. Every
/// template comes out of a `OnceLock`, so this costs nothing.
fn materialize_template<F: DiskFormat>(
    bytes: &'static [u8],
) -> std::io::Result<(std::fs::File, Option<PathBuf>)> {
    if F::NEEDS_PATH {
        let (file, path) = template_file(F::NAME, bytes)?;
        Ok((file, Some(path)))
    } else {
        Ok((template_memfd(F::NAME, bytes)?, None))
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

    // The budget has to be per length class: a run that sees a megabyte of
    // rejects first must still keep the tiny inputs that reach the length
    // checks in front of a magic check.
    #[test]
    fn the_non_magic_budget_is_per_length_class() {
        let kept = |bytes: &[u8]| matches!(keep_non_magic(bytes), Corpus::Keep);

        // Fill one class.
        for i in 0..NON_MAGIC_BUDGET {
            assert!(kept(&[i as u8; 4096]), "input {i} of the budget");
        }
        assert!(!kept(&[0xaa; 4096]), "the class budget is spent");
        // A repeat of an input already seen is not kept either.
        assert!(!kept(&[0u8; 4096]));

        // A different magnitude has its own budget.
        assert!(kept(b"1"), "a one byte input is a different class");
        assert!(kept(b"12"));
    }
}
