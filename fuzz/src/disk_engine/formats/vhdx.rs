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
