// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! VHDX adapter.

use std::fs::File;
use std::path::Path;

use block::disk_file::AsyncFullDiskFile;
use block::error::BlockResult;
use block::formats::vhdx::VhdxDisk;

use crate::disk_engine::format::{DiskFormat, OpenConfig};

/// Dynamic VHDX images, as opened by [`VhdxDisk`]. There is no template: the
/// `block` crate cannot write a VHDX.
pub struct Vhdx;

impl DiskFormat for Vhdx {
    const NAME: &'static str = "vhdx";

    // A parseable VHDX is 8 to 10 MiB.
    const MAX_IMAGE_LEN: usize = 16 << 20;

    // A VHDX read covers the whole request or fails.
    const NO_SHORT_READS: bool = true;

    // Mirrors the `VHDX_SIGN` test in `FileTypeIdentifier::new`.
    fn magic_ok(bytes: &[u8]) -> bool {
        bytes.len() >= FILE_SIGNATURE.len() && bytes[..FILE_SIGNATURE.len()] == *FILE_SIGNATURE
    }

    fn open(
        file: File,
        _path: Option<&Path>,
        config: &OpenConfig,
    ) -> BlockResult<Box<dyn AsyncFullDiskFile>> {
        let disk = VhdxDisk::new(file, config.direct)?;
        Ok(Box::new(disk))
    }
}

/// `VHDX_SIGN` in the parser.
const FILE_SIGNATURE: &[u8; 8] = b"vhdxfile";

/// Offsets and sizes of the checksummed structures, as in the parser.
const HEADER_1_START: usize = 64 * 1024;
const HEADER_2_START: usize = 128 * 1024;
const REGION_TABLE_1_START: usize = 192 * 1024;
const REGION_TABLE_2_START: usize = 256 * 1024;
const HEADER_SIZE: usize = 4 * 1024;
const REGION_SIZE: usize = 64 * 1024;

/// Offset of the checksum in both `Header` and `RegionTableHeader`.
const CHECKSUM_OFFSET: usize = 4;

/// `HEADER_SIGN` in the parser.
const HEADER_SIGNATURE: &[u8; 4] = b"head";

/// `REGION_SIGN` in the parser.
const REGION_SIGNATURE: &[u8; 4] = b"regi";

/// The structures the parser checksums, as `(start, length)` pairs.
const CHECKSUMMED: [(usize, usize); 4] = [
    (HEADER_1_START, HEADER_SIZE),
    (HEADER_2_START, HEADER_SIZE),
    (REGION_TABLE_1_START, REGION_SIZE),
    (REGION_TABLE_2_START, REGION_SIZE),
];

/// Recomputes the four CRC-32C checksums as `calculate_checksum` does,
/// stored little endian. Structures past the end of `image` are skipped.
pub fn repair_checksums(image: &mut [u8]) {
    for (start, len) in CHECKSUMMED {
        let Some(buffer) = image.get_mut(start..start.wrapping_add(len)) else {
            // Past the end of the image.
            continue;
        };

        buffer[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4].fill(0);
        let mut crc = crc_any::CRC::crc32c();
        crc.digest(&*buffer);
        let checksum = crc.get_crc() as u32;
        buffer[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4].copy_from_slice(&checksum.to_le_bytes());
    }
}

/// Restores the file, header and region table signatures. Call before
/// [`repair_checksums`], since the signatures are checksummed.
pub fn restore_signatures(image: &mut [u8]) {
    if let Some(sign) = image.get_mut(..FILE_SIGNATURE.len()) {
        sign.copy_from_slice(FILE_SIGNATURE);
    }

    for (start, signature) in [
        (HEADER_1_START, HEADER_SIGNATURE),
        (HEADER_2_START, HEADER_SIGNATURE),
        (REGION_TABLE_1_START, REGION_SIGNATURE),
        (REGION_TABLE_2_START, REGION_SIGNATURE),
    ] {
        if let Some(sign) = image.get_mut(start..start + signature.len()) {
            sign.copy_from_slice(signature);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::process::Command;

    use super::*;
    use crate::disk_engine::image::image_memfd;

    // qemu-img locks the file, so each test uses its own name.
    fn qemu_vhdx(name: &str) -> Option<Vec<u8>> {
        let dir = std::env::temp_dir().join("vhdx-mutator-check");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join(format!("{name}.vhdx"));
        let _ = fs::remove_file(&path);
        let status = Command::new("qemu-img")
            .args([
                "create",
                "-f",
                "vhdx",
                "-o",
                "subformat=dynamic,block_size=1M",
            ])
            .arg(&path)
            .arg("16M")
            .status()
            .ok()?;
        status.success().then(|| fs::read(&path).ok())?
    }

    fn open_result(bytes: &[u8]) -> Result<(), String> {
        let file = image_memfd("vhdx", bytes).map_err(|e| e.to_string())?;
        block::formats::vhdx::VhdxDisk::new(file, false)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    // A repaired checksum must let an unconstrained byte mutation open.
    #[test]
    fn repair_makes_a_mutated_structure_open_again() {
        let Some(seed) = qemu_vhdx("checksum-repair") else {
            eprintln!("skipping: qemu-img unavailable");
            return;
        };
        assert!(open_result(&seed).is_ok(), "the unmodified seed must open");

        for (label, offset) in [
            ("header 1 reserved", 0x1_0100),
            ("header 2 reserved", 0x2_0100),
            ("region table 1 padding", 0x3_8000),
            ("region table 2 padding", 0x4_8000),
        ] {
            let offset = offset as usize;
            if offset >= seed.len() {
                continue;
            }
            let mut mutated = seed.clone();
            mutated[offset] ^= 0xff;
            let raw = open_result(&mutated);
            repair_checksums(&mut mutated);
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

    // Short and non-VHDX buffers must not panic.
    #[test]
    fn repair_tolerates_junk() {
        for len in [0usize, 1, 4096, 100_000] {
            let mut buf = vec![0x5au8; len];
            repair_checksums(&mut buf);
            restore_signatures(&mut buf);
        }
    }

    // Restoring the signatures before the checksums rescues a mutated one.
    #[test]
    fn restoring_the_signatures_rescues_a_mutated_image() {
        let Some(seed) = qemu_vhdx("signature-restore") else {
            eprintln!("skipping: qemu-img unavailable");
            return;
        };

        for (label, offsets) in [
            ("file type identifier", vec![0]),
            ("header signatures", vec![HEADER_1_START, HEADER_2_START]),
            (
                "region table signatures",
                vec![REGION_TABLE_1_START, REGION_TABLE_2_START],
            ),
        ] {
            if offsets.iter().any(|o| *o >= seed.len()) {
                continue;
            }
            let mut mutated = seed.clone();
            for offset in &offsets {
                mutated[*offset] ^= 0xff;
            }
            repair_checksums(&mut mutated);
            assert!(
                open_result(&mutated).is_err(),
                "{label}: a broken signature must be rejected"
            );

            // The mutator's order.
            restore_signatures(&mut mutated);
            repair_checksums(&mut mutated);
            assert!(
                open_result(&mutated).is_ok(),
                "{label}: a restored image must open again"
            );
        }
    }

    // Signature and checksum rejections must be separately reachable.
    #[test]
    fn the_unrepaired_fractions_reach_distinct_rejections() {
        let Some(seed) = qemu_vhdx("rejection-branches") else {
            eprintln!("skipping: qemu-img unavailable");
            return;
        };

        // seed % 8 == 0: signatures left mutated, checksums repaired.
        let mut signature_branch = seed.clone();
        signature_branch[HEADER_1_START] ^= 0xff;
        signature_branch[HEADER_2_START] ^= 0xff;
        repair_checksums(&mut signature_branch);
        assert!(open_result(&signature_branch).is_err());

        // seed % 8 == 1: signatures restored, checksums left mutated.
        let mut checksum_branch = seed.clone();
        checksum_branch[HEADER_1_START] ^= 0xff;
        checksum_branch[HEADER_1_START + CHECKSUM_OFFSET] ^= 0xff;
        checksum_branch[HEADER_2_START + CHECKSUM_OFFSET] ^= 0xff;
        restore_signatures(&mut checksum_branch);
        let err = open_result(&checksum_branch).expect_err("must be rejected");
        println!("checksum branch: {err}");
        assert!(Vhdx::magic_ok(&checksum_branch));
    }
}
