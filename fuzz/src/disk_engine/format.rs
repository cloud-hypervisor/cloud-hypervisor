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
///
/// Backing file support is deliberately absent: a fuzzed image names its
/// backing file by path, so enabling it would let the corpus open arbitrary
/// host files from inside the fuzzer. Fuzzing backing chains needs a
/// controlled path namespace and is left to a follow-up.
#[derive(Arbitrary, Clone, Copy, Debug, Default)]
pub struct OpenConfig {
    /// Open the image with the direct I/O alignment rules.
    pub direct: bool,
    /// Advertise sparse operations (discard, write zeroes) to the engine.
    pub sparse: bool,
}

/// A disk image format that the framework can fuzz.
///
/// An adapter only has to say how to turn a `File` into an engine handle and
/// how to produce one valid image of its own format.
pub trait DiskFormat {
    /// Format name, used for memfd names and assertion messages.
    const NAME: &'static str;

    /// Whether the I/O backend completes operations before
    /// `submit_data_operation` returns.
    ///
    /// Synchronous backends do, so a missing completion is a lost request and
    /// the executor treats it as a finding. Asynchronous backends may need a
    /// notifier wakeup first, and set this to `false`.
    const COMPLETES_INLINE: bool = true;

    /// Whether the image has to exist as a real file rather than a memfd.
    ///
    /// A format whose image references sibling files by relative path, such as
    /// a VMDK descriptor naming its extents, can only be opened from a
    /// directory. The framework then materializes the image in a scratch
    /// directory and passes its path to [`DiskFormat::open`].
    const NEEDS_PATH: bool = false;

    /// Largest image the framework will hand to this format.
    ///
    /// Inputs above this size are rejected instead of being fed to the
    /// parser: they cost time without reaching new states. Formats whose
    /// metadata reaches far into the file need a larger budget, so 8 MiB is
    /// only a default.
    const MAX_IMAGE_LEN: usize = 8 << 20;

    /// Whether the reported capacity only ever changes through a successful
    /// resize.
    ///
    /// Formats that grow their backing file on a write past the end, such as
    /// raw images, set this to `false` and lose the capacity invariants.
    const FIXED_CAPACITY: bool = true;

    /// Whether a successful `punch_hole` guarantees that the range reads back
    /// as zeroes.
    ///
    /// When `false`, the executor marks discarded ranges as unknown in the
    /// shadow model instead of expecting zeroes.
    const PUNCH_HOLE_READS_ZEROES: bool = false;

    /// Opens `file` as this format.
    ///
    /// `path` is `Some` only when [`DiskFormat::NEEDS_PATH`] is set; a memfd
    /// backed image has no meaningful path.
    fn open(
        file: File,
        path: Option<&Path>,
        config: &OpenConfig,
    ) -> BlockResult<Box<dyn AsyncFullDiskFile>>;

    /// Returns the bytes of a valid, freshly created image of this format,
    /// for the formats that can build one in process.
    ///
    /// The image must read back as all zeroes so that the shadow model can
    /// start from a known state, and it must be byte identical on every run
    /// so that a crash reproduces from its input alone. Adapters build it
    /// once per process.
    ///
    /// A format that has no in process image builder returns `None` and gets
    /// no operation program target; its parser is still fuzzed by the image
    /// target.
    fn template() -> Option<&'static [u8]> {
        None
    }
}
