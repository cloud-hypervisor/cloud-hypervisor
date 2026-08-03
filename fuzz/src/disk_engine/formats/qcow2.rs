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

/// Virtual size of the template image.
///
/// Large enough to span several clusters, and so several L2 entries, while
/// staying small enough to keep the shadow model cheap.
const TEMPLATE_SIZE: u64 = 1 << 20;

/// QCOW2 images, as opened by [`QcowDisk`].
pub struct Qcow2;

impl DiskFormat for Qcow2 {
    const NAME: &'static str = "qcow2";

    // Discarding a cluster leaves it unallocated, which reads back as zeroes
    // only when the image has no backing file. The framework never enables
    // backing files, so the guarantee holds.
    const PUNCH_HOLE_READS_ZEROES: bool = true;

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
}
