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

    fn open(
        file: File,
        _path: Option<&Path>,
        config: &OpenConfig,
    ) -> BlockResult<Box<dyn AsyncFullDiskFile>> {
        let disk = VhdxDisk::new(file, config.direct)?;
        Ok(Box::new(disk))
    }
}

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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::process::Command;

    use super::*;
    use crate::disk_engine::image::image_memfd;

    fn qemu_vhdx() -> Option<Vec<u8>> {
        let dir = std::env::temp_dir().join("vhdx-mutator-check");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("seed.vhdx");
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
        let Some(seed) = qemu_vhdx() else {
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
        }
    }
}
