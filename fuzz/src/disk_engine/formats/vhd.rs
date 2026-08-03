// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Fixed VHD adapter.

use std::fs::File;
use std::path::Path;

use block::disk_file::AsyncFullDiskFile;
use block::error::BlockResult;
use block::formats::vhd::VhdDisk;

use crate::disk_engine::format::{DiskFormat, OpenConfig};

/// Fixed VHD images, as opened by [`VhdDisk`].
///
/// The io_uring backend is not selected: the `block` crate only builds it
/// with its `io_uring` feature, which the fuzz crate does not enable, and a
/// kernel ring per iteration would dominate the run time anyway.
///
/// There is no template image because the `block` crate parses a VHD footer
/// but never writes one, and a footer built inside the fuzzer would encode
/// the harness author's reading of the format rather than the code under
/// test. The parser is fuzzed through the image target instead.
pub struct Vhd;

impl DiskFormat for Vhd {
    const NAME: &'static str = "vhd";

    fn open(
        file: File,
        _path: Option<&Path>,
        config: &OpenConfig,
    ) -> BlockResult<Box<dyn AsyncFullDiskFile>> {
        let disk = VhdDisk::new(file, false, config.direct)?;
        Ok(Box::new(disk))
    }
}

/// Length of the hard disk footer, from `VHD_FOOTER_LEN` in the parser under
/// test (block/src/formats/vhd/footer.rs:13).
const FOOTER_LEN: usize = 512;

/// Byte range of the `checksum` field inside the footer, from
/// `VHD_CHECKSUM_RANGE` (block/src/formats/vhd/footer.rs:29).
const CHECKSUM_OFFSET: usize = 64;
const CHECKSUM_LEN: usize = 4;

/// Recomputes the footer checksum [`VhdDisk`] verifies while opening `image`.
///
/// `VhdFooter::validate_fixed` rejects an image whose stored checksum differs
/// from the one it computes over the footer
/// (block/src/formats/vhd/footer.rs:186-191), so every value changing byte
/// mutation of the footer is refused at open and the fuzzer never reaches the
/// code behind it. Rewriting the checksum after mutating keeps structural
/// mutations of the footer alive.
///
/// The algorithm mirrors `footer_checksum`
/// (block/src/formats/vhd/footer.rs:33-41): sum all 512 footer bytes as a
/// wrapping `u32` with the checksum field taken as zero, and store the
/// bitwise NOT of that sum in the field. Unlike VHDX, the field is **big
/// endian**.
///
/// The footer is the *last* 512 bytes of the image, not the first, so callers
/// must pass the buffer already trimmed to its post mutation length.
/// A buffer shorter than a footer is left alone, so this is safe to call on
/// arbitrary, short or non VHD buffers.
pub fn repair_footer_checksum(image: &mut [u8]) {
    let Some(start) = image.len().checked_sub(FOOTER_LEN) else {
        // Too short to hold a footer; the parser rejects it before it looks
        // at any checksum, so there is nothing to repair.
        return;
    };
    let footer = &mut image[start..];

    footer[CHECKSUM_OFFSET..CHECKSUM_OFFSET + CHECKSUM_LEN].fill(0);
    let sum = footer
        .iter()
        .fold(0u32, |acc, b| acc.wrapping_add(u32::from(*b)));
    let checksum = !sum;
    footer[CHECKSUM_OFFSET..CHECKSUM_OFFSET + CHECKSUM_LEN]
        .copy_from_slice(&checksum.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disk_engine::image::image_memfd;

    /// A minimal fixed VHD: one sector of data plus a footer the parser
    /// accepts. The field layout is the one `VhdFooter::new` reads
    /// (block/src/formats/vhd/footer.rs:88-105); everything it does not
    /// validate is left zero.
    fn seed_vhd() -> Vec<u8> {
        let mut image = vec![0u8; 512 + FOOTER_LEN];
        {
            let footer = &mut image[512..];
            footer[0..8].copy_from_slice(b"conectix");
            // file_format_version 1.0
            footer[12..16].copy_from_slice(&0x0001_0000u32.to_be_bytes());
            // data_offset: all ones, as a fixed image requires
            footer[16..24].copy_from_slice(&u64::MAX.to_be_bytes());
            // current_size: the 512 data bytes ahead of the footer
            footer[48..56].copy_from_slice(&512u64.to_be_bytes());
            // disk_type 2, fixed hard disk
            footer[60..64].copy_from_slice(&2u32.to_be_bytes());
        }
        repair_footer_checksum(&mut image);
        image
    }

    fn open_result(bytes: &[u8]) -> Result<(), String> {
        let file = image_memfd("vhd", bytes).map_err(|e| e.to_string())?;
        block::formats::vhd::VhdDisk::new(file, false, false)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    // The mutator is only useful if the checksum it writes is the one the
    // parser verifies: a repaired mutation must get past the checksum test.
    //
    // Repair is necessary, not sufficient. The footer also carries a cookie,
    // a format version, a data offset and a disk type the parser validates,
    // so a mutation of one of those is still rejected for a reason that has
    // nothing to do with the checksum. The offsets below are chosen to
    // separate the two: they are checksum protected but otherwise
    // unconstrained.
    #[test]
    fn repair_makes_a_mutated_footer_open_again() {
        let seed = seed_vhd();
        assert!(open_result(&seed).is_ok(), "the unmodified seed must open");

        for (label, offset) in [
            ("features", 512 + 8),
            ("time_stamp", 512 + 24),
            ("creator_application", 512 + 28),
            ("unique_id", 512 + 68),
            ("reserved padding", 512 + 400),
        ] {
            let mut mutated = seed.clone();
            mutated[offset] ^= 0xff;
            let raw = open_result(&mutated);
            repair_footer_checksum(&mut mutated);
            let repaired = open_result(&mutated);
            println!(
                "{label:24} raw={:<28} repaired={}",
                raw.as_ref().err().map(String::as_str).unwrap_or("ok"),
                repaired.as_ref().err().map(String::as_str).unwrap_or("ok")
            );
            assert!(raw.is_err(), "{label}: a raw mutation must be rejected");
            assert!(repaired.is_ok(), "{label}: the repaired mutation must open");
        }
    }

    // Repair is not sufficient: a mutation of a field the parser constrains
    // stays rejected even with a correct checksum, which is the branch the
    // unrepaired fraction of mutations is meant to keep reachable.
    #[test]
    fn repair_does_not_rescue_a_constrained_field() {
        for (label, offset) in [
            ("cookie", 512),
            ("file_format_version", 512 + 13),
            ("data_offset", 512 + 16),
            ("disk_type", 512 + 63),
        ] {
            let mut mutated = seed_vhd();
            mutated[offset] ^= 0xff;
            repair_footer_checksum(&mut mutated);
            assert!(
                open_result(&mutated).is_err(),
                "{label}: a repaired checksum must not rescue an invalid field"
            );
        }
    }

    // Short and non-VHD buffers must not panic.
    #[test]
    fn repair_tolerates_junk() {
        for len in [0usize, 1, 511, 512, 4096] {
            let mut buf = vec![0x5au8; len];
            repair_footer_checksum(&mut buf);
        }
    }

    // The empirical claim the mutator rests on: byte mutations of the footer
    // are essentially all rejected without repair, and essentially all
    // accepted with it.
    #[test]
    fn repair_restores_the_open_rate() {
        let seed = seed_vhd();
        // Offsets the parser does not constrain, so the checksum is the only
        // thing standing between a mutation and a successful open.
        let free: Vec<usize> = (8..12)
            .chain(24..48)
            .chain(56..60)
            .chain(68..FOOTER_LEN)
            .filter(|o| !(CHECKSUM_OFFSET..CHECKSUM_OFFSET + CHECKSUM_LEN).contains(o))
            .collect();

        let mut raw_ok = 0usize;
        let mut repaired_ok = 0usize;
        let mut total = 0usize;
        // A cheap deterministic value source; no rand dependency needed.
        let mut state = 0x1234_5678u32;
        for _ in 0..2000 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let offset = 512 + free[(state >> 8) as usize % free.len()];
            let delta = ((state >> 24) as u8) | 1;

            let mut mutated = seed.clone();
            mutated[offset] ^= delta;
            total += 1;
            if open_result(&mutated).is_ok() {
                raw_ok += 1;
            }
            repair_footer_checksum(&mut mutated);
            if open_result(&mutated).is_ok() {
                repaired_ok += 1;
            }
        }
        println!("raw {raw_ok}/{total} open, repaired {repaired_ok}/{total} open");
        assert_eq!(raw_ok, 0, "unrepaired footer mutations must not open");
        assert!(
            repaired_ok * 100 >= total * 90,
            "repaired footer mutations must open at least 90% of the time, got {repaired_ok}/{total}"
        );
    }
}
