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

/// Dynamic VHDX images, as opened by [`VhdxDisk`].
///
/// There is no template image: building a valid VHDX means writing the file
/// identifier, both headers with their checksums, the region table, the BAT
/// and a metadata region, and the `block` crate has no writer for any of
/// that. The parser is fuzzed through the image target instead.
pub struct Vhdx;

impl DiskFormat for Vhdx {
    const NAME: &'static str = "vhdx";

    // VHDX places its BAT region at 2 MiB and its metadata region at 3 MiB,
    // so a parseable image is several MiB before it holds any data: an empty
    // one is exactly 8 MiB and a populated one runs to 9 or 10 MiB. The
    // default budget would reject those.
    const MAX_IMAGE_LEN: usize = 16 << 20;

    // The engine refuses an offset or a length that is not a multiple of the
    // logical sector size before it does anything else
    // (block/src/formats/vhdx/parser.rs:100 and 111 for reads, 149 and 160
    // for writes), so an unshaped program would be rejected at the door and
    // the shadow model would never see a byte. 512 is the
    // `LogicalSectorSize` metadata item of the template.
    const IO_ALIGNMENT: u64 = 512;

    // A VHDX read is all or error. `io::read` loops until every requested
    // sector is accounted for and returns early with an error on any entry
    // it cannot serve, so the `Ok(read_count)` it reaches
    // (block/src/formats/vhdx/io.rs:141) always covers the whole request; an
    // unallocated block is left as the zeroes the buffer already holds. A
    // length that is not a multiple of the sector size is rejected up front
    // (block/src/formats/vhdx/parser.rs:102), which is a rejection rather
    // than a short read.
    //
    // The check is on reads only, but the write path is built the same way:
    // it serves each sector run with `write_all_at` and propagates any
    // failure with `?` (block/src/formats/vhdx/io.rs:202 and 213), so it too
    // returns either the full count or an error.
    //
    // The capacity is not file backed, so `CAPACITY_FILE_TAIL` stays
    // `None`: a dynamic VHDX allocates payload blocks on demand, so its file
    // is routinely smaller than the virtual disk size.
    const NO_SHORT_READS: bool = true;

    // `FileTypeIdentifier::new` rejects an image whose first eight bytes are
    // not "vhdxfile" (block/src/formats/vhdx/header.rs:101), before anything
    // else in the file is looked at. Measured on a campaign corpus, 717 of
    // 872 entries failed exactly this.
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

/// The file type identifier, from `VHDX_SIGN` in the parser under test
/// (block/src/formats/vhdx/header.rs:17). It is the first eight bytes of the
/// file and the first thing `VhdxHeader::new` checks.
const FILE_SIGNATURE: &[u8; 8] = b"vhdxfile";

/// Offsets and sizes of the checksummed VHDX structures, taken from the
/// parser under test in `block/src/formats/vhdx/header.rs`:
///
/// - `HEADER_1_START` = 64 KiB and `HEADER_2_START` = 128 KiB (lines 22-23),
/// - `REGION_TABLE_1_START` = 192 KiB and `REGION_TABLE_2_START` = 256 KiB
///   (lines 24-25),
/// - `HEADER_SIZE` = 4 KiB and `REGION_SIZE` = 64 KiB (lines 27-28).
const HEADER_1_START: usize = 64 * 1024;
const HEADER_2_START: usize = 128 * 1024;
const REGION_TABLE_1_START: usize = 192 * 1024;
const REGION_TABLE_2_START: usize = 256 * 1024;
const HEADER_SIZE: usize = 4 * 1024;
const REGION_SIZE: usize = 64 * 1024;

/// Byte offset of the `checksum` field inside both `Header` and
/// `RegionTableHeader`. Both structures start with a `u32` signature followed
/// by the `u32` checksum (header.rs lines 111-113 and 193-195), and the parser
/// passes `size_of::<u32>()` as the checksum offset when it verifies them
/// (header.rs lines 138 and 214).
const CHECKSUM_OFFSET: usize = 4;

/// Signature of a VHDX `Header` structure, from `HEADER_SIGN`
/// (block/src/formats/vhdx/header.rs:18).
const HEADER_SIGNATURE: &[u8; 4] = b"head";

/// Signature of a VHDX `RegionTableHeader`, from `REGION_SIGN`
/// (block/src/formats/vhdx/header.rs:19).
const REGION_SIGNATURE: &[u8; 4] = b"regi";

/// The structures the parser checksums, as `(start, length)` pairs.
const CHECKSUMMED: [(usize, usize); 4] = [
    (HEADER_1_START, HEADER_SIZE),
    (HEADER_2_START, HEADER_SIZE),
    (REGION_TABLE_1_START, REGION_SIZE),
    (REGION_TABLE_2_START, REGION_SIZE),
];

/// Recomputes every checksum [`VhdxDisk`] verifies while opening `image`.
///
/// `VhdxHeader::new` rejects an image unless both headers and both region
/// tables carry a correct CRC-32C (block/src/formats/vhdx/header.rs lines
/// 348-355), so a byte level mutation of any of those four structures makes
/// the image unopenable and the fuzzer never reaches the code behind the
/// header. Rewriting the checksums after mutating keeps structural mutations
/// alive.
///
/// The algorithm mirrors `calculate_checksum` (header.rs lines 434-448):
/// zero the 32 bit checksum field, run CRC-32C over the whole structure, and
/// store the result little endian in that field.
///
/// Structures that do not fit in `image` are skipped, so this is safe to call
/// on arbitrary, short or non VHDX buffers.
pub fn repair_checksums(image: &mut [u8]) {
    for (start, len) in CHECKSUMMED {
        let Some(buffer) = image.get_mut(start..start.wrapping_add(len)) else {
            // The structure is past the end of the image; the parser would
            // fail its read_exact_at anyway, so there is nothing to repair.
            continue;
        };

        buffer[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4].fill(0);
        let mut crc = crc_any::CRC::crc32c();
        crc.digest(&*buffer);
        let checksum = crc.get_crc() as u32;
        buffer[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4].copy_from_slice(&checksum.to_le_bytes());
    }
}

/// Restores the signatures that identify a VHDX file and its structures.
///
/// `VhdxHeader::new` tests four signatures before it verifies any checksum:
/// the eight byte `vhdxfile` file type identifier at offset 0
/// (block/src/formats/vhdx/header.rs:101), and the `head` and `regi`
/// signatures at the start of each header and each region table
/// (lines 134 and 210). A mutation that lands on one of them makes the image
/// unopenable for a reason that has nothing to do with the structure it
/// changed, and repairing the checksums does not help: the signature is
/// checked first. Measured on a campaign corpus, 717 of 872 disk_vhdx entries
/// failed the file type identifier alone.
///
/// Call this *before* [`repair_checksums`]: the header and region signatures
/// are inside the checksummed areas.
///
/// Structures that do not fit in `image` are skipped, so this is safe to call
/// on arbitrary, short or non VHDX buffers.
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
    use std::io::Write;
    use std::process::Command;

    use super::*;
    use crate::disk_engine::image::image_memfd;

    // `name` keeps concurrently running tests off each other's image:
    // qemu-img takes a lock on the file it creates.
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

    // The mutator is only useful if the checksum it writes is the one the
    // parser verifies: a repaired mutation must get past the checksum test.
    //
    // Repair is necessary, not sufficient. A region table entry also carries
    // a GUID naming the region and an offset and length the parser validates,
    // so a mutation there can still be rejected for a reason that has nothing
    // to do with the checksum. The offsets below are chosen to separate the
    // two: bytes inside the header structures, and padding past the region
    // table entries, are checksum protected but otherwise unconstrained.
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

    // The mutator writes the signatures back before recomputing the
    // checksums, so a mutation that landed on one still reaches the parser.
    //
    // The headers and the region tables come in pairs and the parser accepts
    // an image as long as one of each pair is valid, so a case that has to be
    // rejected breaks both copies.
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

            // The mutator's order: signatures first, checksums over them
            // after.
            restore_signatures(&mut mutated);
            repair_checksums(&mut mutated);
            assert!(
                open_result(&mutated).is_ok(),
                "{label}: a restored image must open again"
            );
        }
    }

    // Both rejection branches the mutator leaves reachable have to be
    // reachable separately: a signature is tested before the checksum of the
    // structure it introduces.
    #[test]
    fn the_unrepaired_fractions_reach_distinct_rejections() {
        let Some(seed) = qemu_vhdx("rejection-branches") else {
            eprintln!("skipping: qemu-img unavailable");
            return;
        };

        // seed % 8 == 0: signatures left mutated, checksums recomputed.
        let mut signature_branch = seed.clone();
        signature_branch[HEADER_1_START] ^= 0xff;
        signature_branch[HEADER_2_START] ^= 0xff;
        repair_checksums(&mut signature_branch);
        assert!(open_result(&signature_branch).is_err());

        // seed % 8 == 1: signatures restored, checksums left mutated. The
        // image is still identifiably a VHDX, which is what lets the parser
        // get as far as the checksum test.
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
