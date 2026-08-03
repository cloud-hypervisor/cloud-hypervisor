// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Format adapter trait.

use std::fs::File;
use std::path::Path;

use arbitrary::Arbitrary;
use block::disk_file::AsyncFullDiskFile;
use block::error::BlockResult;

/// Open options handed to a format adapter. Backing files are never opened.
#[derive(Arbitrary, Clone, Copy, Debug, Default)]
pub struct OpenConfig {
    /// Open the image with the direct I/O alignment rules.
    pub direct: bool,
    /// Advertise sparse operations to the engine.
    pub sparse: bool,
}

/// A disk image format the framework can fuzz.
pub trait DiskFormat {
    /// Format name, used for memfd names and assertion messages.
    const NAME: &'static str;

    /// Whether an accepted op completes before `submit_data_operation` returns,
    /// making a missing completion a finding.
    const COMPLETES_INLINE: bool = true;

    /// Whether the image must be a real file, because it names sibling files by
    /// relative path.
    const NEEDS_PATH: bool = false;

    /// Largest image handed to this format. Larger inputs are rejected.
    const MAX_IMAGE_LEN: usize = 8 << 20;

    /// Whether the capacity only changes through a successful resize.
    const FIXED_CAPACITY: bool = true;

    /// Whether a successful `punch_hole` makes the range read back as zeroes.
    const PUNCH_HOLE_READS_ZEROES: bool = false;

    /// Opens `file` as this format. `path` is `Some` only with `NEEDS_PATH`.
    fn open(
        file: File,
        path: Option<&Path>,
        config: &OpenConfig,
    ) -> BlockResult<Box<dyn AsyncFullDiskFile>>;

    /// A valid image that reads back as zeroes and is identical on every run,
    /// or `None` if the format has no operation target.
    fn template() -> Option<&'static [u8]> {
        None
    }
}
