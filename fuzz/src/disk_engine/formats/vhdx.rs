// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! VHDX adapter.

use std::fs::File;
use std::path::Path;
use std::sync::OnceLock;

use block::disk_file::AsyncFullDiskFile;
use block::error::BlockResult;
use block::formats::vhdx::VhdxDisk;

use crate::disk_engine::format::{DiskFormat, OpenConfig};

/// Virtual size of the template, pinned by its self test.
pub const TEMPLATE_LOGICAL_SIZE: u64 = 4 << 20;

/// Length of the template file. An empty dynamic VHDX is 8 MiB.
const TEMPLATE_LEN: usize = 8 << 20;

/// The non-zero runs of `qemu-img create -f vhdx -o
/// subformat=dynamic,block_size=1M t.vhdx 4M`: the file type identifier,
/// both headers and region tables, four zero BAT entries and the metadata
/// region. Stored as runs, the template is reviewable and independent of the
/// host's qemu.
const TEMPLATE_RUNS: [(usize, &str); 11] = [
    (0x000000, "7668647866696c65510045004d00550020007600310030002e0032002e0031"),
    (0x010000, "68656164763f022f40a3b97400000000968d9ca5c1574f418f461232fa33ff932bc1289d3cd44c73b882f83d656353e5"),
    (0x010042, "010000001000000010"),
    (0x020000, "6865616401a3faad41a3b97400000000968d9ca5c1574f418f461232fa33ff932bc1289d3cd44c73b882f83d656353e5"),
    (0x020042, "010000001000000010"),
    (0x030000, "7265676983ce6f2c02000000000000006677c22d23f600429d64115e9bfd4a080000200000000000000010000000000006a27c8b90479a4bb8fe575f050f886e0000300000000000000010"),
    (0x040000, "7265676983ce6f2c02000000000000006677c22d23f600429d64115e9bfd4a080000200000000000000010000000000006a27c8b90479a4bb8fe575f050f886e0000300000000000000010"),
    (0x200000, "02000000000000000200000000000000020000000000000002"),
    (0x300000, "6d65746164617461000005"),
    (0x300020, "3767a1ca36fa434db3b633f0aa44e76b000001000800000004000000000000002442a52f1bcd7648b2115dbed83bf4b808000100080000000600000000000000ab12cabee6b2234593efc309e000c746100001001000000006000000000000001dbf41816fa90947ba47f233a8faab5f20000100040000000600000000000000c748a3cd5d4471449cc9e9885251c556240001000400000006"),
    (0x310002, "1000000000000000400000000000dd83c75228904fd484ece3b363199ea3000200000002"),
];

/// Expands [`TEMPLATE_RUNS`] into the full image.
fn build_template() -> Vec<u8> {
    let mut image = vec![0u8; TEMPLATE_LEN];

    for (offset, hex) in TEMPLATE_RUNS {
        assert!(
            hex.len().is_multiple_of(2),
            "run at {offset:#x} is half a byte"
        );
        let bytes: Vec<u8> = hex
            .as_bytes()
            .chunks(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).expect("the run table is ASCII");
                u8::from_str_radix(text, 16).expect("the run table is hexadecimal")
            })
            .collect();
        image[offset..offset + bytes.len()].copy_from_slice(&bytes);
    }

    image
}

/// Dynamic VHDX images, as opened by [`VhdxDisk`].
pub struct Vhdx;

impl DiskFormat for Vhdx {
    const NAME: &'static str = "vhdx";

    // A parseable VHDX is 8 to 10 MiB.
    const MAX_IMAGE_LEN: usize = 16 << 20;

    // `Vhdx::sector_range` refuses unaligned offsets and lengths.
    const IO_ALIGNMENT: u64 = 512;

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

    fn template() -> Option<&'static [u8]> {
        static TEMPLATE: OnceLock<Vec<u8>> = OnceLock::new();

        Some(TEMPLATE.get_or_init(build_template))
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
    use crate::disk_engine::image::{image_memfd, template_memfd};
    use crate::disk_engine::selftest::assert_template_is_sound;
    use crate::disk_engine::{Executor, Op, OpLen, OpOffset};

    /// See `disk_engine::selftest`.
    #[test]
    fn the_template_is_a_blank_four_mib_disk() {
        assert_template_is_sound::<Vhdx>(TEMPLATE_LOGICAL_SIZE);
    }

    /// Regression test for a write to an unallocated block landing at the block
    /// base instead of the sector's offset.
    #[test]
    fn the_model_catches_a_misplaced_block_allocating_write() {
        // Sector 1 of the unallocated block 1.
        let offset = (1 << 20) + 512;
        let program = vec![
            Op::WriteVec {
                offset: OpOffset::Byte(offset),
                len: OpLen(512),
                seed: 0x11,
            },
            Op::ReadVec {
                offset: OpOffset::Byte(offset),
                len: OpLen(512),
            },
        ];

        let template = Vhdx::template().expect("vhdx has a template");
        let file = template_memfd(Vhdx::NAME, template).expect("memfd");
        let disk = Vhdx::open(file, None, &OpenConfig::default()).expect("the template opens");
        let mut executor = Executor::<Vhdx>::new(disk, 1, true).expect("executor");
        // Panics on a read back mismatch.
        executor.run(&program);
    }

    /// Pins the shape of the run table.
    #[test]
    fn the_run_table_expands_to_the_qemu_image() {
        let template = Vhdx::template().expect("vhdx has a template");
        assert_eq!(template.len(), TEMPLATE_LEN);
        assert_eq!(
            template.iter().filter(|byte| **byte != 0).count(),
            333,
            "the number of non-zero bytes in the template changed"
        );
        assert!(Vhdx::magic_ok(template));
    }

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
