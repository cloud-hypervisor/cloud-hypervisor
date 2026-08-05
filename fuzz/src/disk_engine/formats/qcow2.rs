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

/// Virtual size of the default template.
const TEMPLATE_SIZE: u64 = 1 << 20;

/// Cluster bits of the small cluster template: `MIN_CLUSTER_BITS`.
const SMALL_CLUSTER_BITS: u32 = 9;

/// Virtual size of the small cluster template: 128 L2 tables of 32 KiB, more
/// than the 100 the engine caches, within the model's 8 MiB limit.
const SMALL_TEMPLATE_SIZE: u64 = 4 << 20;

/// Bytes covered by one L2 table of the small cluster template.
pub const SMALL_L2_SPAN: u64 = (1 << SMALL_CLUSTER_BITS) / 8 * (1 << SMALL_CLUSTER_BITS);

/// `QCOW_MAGIC` as stored on disk.
const QCOW_MAGIC: &[u8; 4] = b"QFI\xfb";

/// QCOW2 images, as opened by [`QcowDisk`].
pub struct Qcow2;

impl DiskFormat for Qcow2 {
    const NAME: &'static str = "qcow2";

    // Holds because no template has a backing file.
    const PUNCH_HOLE_READS_ZEROES: bool = true;

    // An unallocated cluster is zero filled, never short.
    const NO_SHORT_READS: bool = true;

    // Mirrors the `QCOW_MAGIC` test in `QcowHeader::new`.
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

    // Odd indices select the small cluster template.
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

    // The default template is a single L2 table.
    fn sweeps_metadata_cache(variant: u8) -> bool {
        !variant.is_multiple_of(2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disk_engine::selftest::assert_template_is_sound;

    /// See `disk_engine::selftest`.
    #[test]
    fn the_template_is_a_blank_one_mib_disk() {
        assert_template_is_sound::<Qcow2>(TEMPLATE_SIZE);
    }
}
