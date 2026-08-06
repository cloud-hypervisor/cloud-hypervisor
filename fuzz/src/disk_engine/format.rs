// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Format adapter trait.

use std::fs::File;
use std::path::Path;

use arbitrary::Arbitrary;
use block::disk_file::AsyncFullDiskFile;
use block::error::BlockResult;

/// Open options handed to a format adapter.
#[derive(Arbitrary, Clone, Copy, Debug, Default)]
pub struct OpenConfig {
    /// Open the image with the direct I/O alignment rules.
    pub direct: bool,
    /// Advertise sparse operations to the engine.
    pub sparse: bool,
    /// Open backing files named by the image. Never fuzzer selected: only a
    /// target that confines the filesystem may set it.
    #[arbitrary(value = false)]
    pub backing: bool,
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

    /// `Some(tail)` if the disk data sits in the image file followed by `tail`
    /// bytes of metadata, so the capacity may not exceed
    /// `physical_size() - tail`. `None` makes no claim.
    const CAPACITY_FILE_TAIL: Option<u64> = None;

    /// Whether a successful read always transfers the whole request.
    const NO_SHORT_READS: bool = false;

    /// Whether a successful `punch_hole` makes the range read back as zeroes.
    const PUNCH_HOLE_READS_ZEROES: bool = false;

    /// Alignment the engine requires of data ops. The executor aligns in-range
    /// offsets and lengths to it. Must divide `MAX_OP_LEN`.
    const IO_ALIGNMENT: u64 = 1;

    /// Whether `bytes` carry the format's identifying bytes, mirroring the
    /// parser's first check. Other inputs are still opened, but only kept in
    /// the corpus within a small budget.
    fn magic_ok(_bytes: &[u8]) -> bool {
        true
    }

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
