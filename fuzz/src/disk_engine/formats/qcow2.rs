// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! QCOW2 adapter.

use std::fs::{self, File};
use std::path::Path;
use std::sync::OnceLock;

use block::disk_file::AsyncFullDiskFile;
use block::error::BlockResult;
use block::formats::qcow::{QcowDisk, QcowTempDisk};

use crate::disk_engine::format::{DiskFormat, OpenConfig};

/// Virtual size of the default template image.
///
/// Large enough to span several clusters, and so several L2 entries, while
/// staying small enough to keep the shadow model cheap.
const TEMPLATE_SIZE: u64 = 1 << 20;

/// Cluster size of the small cluster template, as a power of two.
///
/// `MIN_CLUSTER_BITS` in the parser under test
/// (block/src/formats/qcow/header.rs:75), so 512 byte clusters.
const SMALL_CLUSTER_BITS: u32 = 9;

/// Virtual size of the small cluster template.
///
/// With 512 byte clusters an L2 table holds `512 / 8 = 64` entries and so
/// covers `64 * 512 = 32 KiB` of the disk. The L2 cache holds 100 tables
/// (block/src/formats/qcow/parser.rs:539), so its eviction path needs more
/// than `100 * 32 KiB = 3.2 MiB` of the disk live at once. Four MiB gives
/// 128 tables, comfortably past the cache, and still fits under the shadow
/// model's 8 MiB limit so the eviction runs with the read back oracle on.
const SMALL_TEMPLATE_SIZE: u64 = 4 << 20;

/// Bytes covered by one L2 table of the small cluster template.
pub const SMALL_L2_SPAN: u64 = (1 << SMALL_CLUSTER_BITS) / 8 * (1 << SMALL_CLUSTER_BITS);

/// The magic every qcow image starts with, from `QCOW_MAGIC`
/// (block/src/formats/qcow/header.rs:70), big endian on disk.
const QCOW_MAGIC: &[u8; 4] = b"QFI\xfb";

/// QCOW2 images, as opened by [`QcowDisk`].
pub struct Qcow2;

impl DiskFormat for Qcow2 {
    const NAME: &'static str = "qcow2";

    // Discarding a cluster leaves it unallocated, which reads back as zeroes
    // only when the image has no backing file. The framework never enables
    // backing files, so the guarantee holds.
    const PUNCH_HOLE_READS_ZEROES: bool = true;

    // A qcow2 read reports the whole requested length or fails:
    // `QcowSync::read_operation` returns `total_len`
    // (block/src/formats/qcow/engine_sync.rs:67), because an unallocated
    // cluster is filled with zeroes by the scatter read rather than left
    // short.
    //
    // The capacity is not file backed, so `CAPACITY_FILE_TAIL` stays
    // `None`: a sparse image holds only the clusters that were written, and
    // its file is routinely far smaller than the virtual disk size.
    const NO_SHORT_READS: bool = true;

    // `QcowHeader::new` rejects an image whose first four bytes are not the
    // QCOW magic (block/src/formats/qcow/header.rs:382, QCOW_MAGIC at line
    // 70), before it reads any other field.
    fn magic_ok(bytes: &[u8]) -> bool {
        bytes.len() >= QCOW_MAGIC.len() && bytes[..QCOW_MAGIC.len()] == *QCOW_MAGIC
    }

    fn open(
        file: File,
        _path: Option<&Path>,
        config: &OpenConfig,
    ) -> BlockResult<Box<dyn AsyncFullDiskFile>> {
        let disk = QcowDisk::new(file, config.direct, false, config.sparse, false)?;
        Ok(Box::new(disk))
    }

    fn template() -> Option<&'static [u8]> {
        static TEMPLATE: OnceLock<Vec<u8>> = OnceLock::new();

        let template = TEMPLATE.get_or_init(|| {
            let disk = QcowTempDisk::new(TEMPLATE_SIZE, None, false, true, false)
                .expect("failed to create the qcow2 template image");
            // Dropping the disk handle flushes the metadata into the file.
            let file = disk.into_tempfile();
            fs::read(file.as_path()).expect("failed to read the qcow2 template image")
        });

        Some(template)
    }

    // An odd index picks the small cluster image, so a program reaches
    // either layout and neither is the only one fuzzed.
    fn template_variant(variant: u8) -> Option<&'static [u8]> {
        if variant.is_multiple_of(2) {
            return Self::template();
        }

        static SMALL: OnceLock<Vec<u8>> = OnceLock::new();

        let template = SMALL.get_or_init(|| {
            let disk = QcowTempDisk::new_with_cluster_bits(
                SMALL_TEMPLATE_SIZE,
                None,
                false,
                true,
                false,
                SMALL_CLUSTER_BITS,
            )
            .expect("failed to create the small cluster qcow2 template image");
            let file = disk.into_tempfile();
            fs::read(file.as_path()).expect("failed to read the small cluster qcow2 template")
        });

        Some(template)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disk_engine::selftest::assert_template_is_sound;

    /// The same guard the VHDX template gets: a template that opens but is
    /// not a blank disk of the pinned size makes `disk_qcow2_ops` an
    /// expensive no-op. See `disk_engine::selftest`.
    #[test]
    fn the_template_is_a_blank_one_mib_disk() {
        assert_template_is_sound::<Qcow2>(TEMPLATE_SIZE);
    }
}
