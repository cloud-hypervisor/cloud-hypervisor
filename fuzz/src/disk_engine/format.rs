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
/// [`OpenConfig::backing`] is not fuzzer selectable: it is set by the
/// harness, never derived from input bytes. A fuzzed image names its backing
/// file by path, so a target that enables it has to sandbox the name space
/// first, which only `disk_qcow2_chain` does, and enabling it under the
/// shadow model would be unsound besides: with a backing file a discarded
/// cluster reads through to the backing data rather than as zeroes.
#[derive(Arbitrary, Clone, Copy, Debug, Default)]
pub struct OpenConfig {
    /// Open the image with the direct I/O alignment rules.
    pub direct: bool,
    /// Advertise sparse operations (discard, write zeroes) to the engine.
    pub sparse: bool,
    /// Open backing files named by the image.
    ///
    /// Fixed at `false` for a fuzzer generated configuration; only a target
    /// that has confined the filesystem may set it.
    #[arbitrary(value = false)]
    pub backing: bool,
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

    /// How the image file backs the capacity the format advertises.
    ///
    /// `Some(tail)` says the disk data lives directly in the image file,
    /// followed by `tail` bytes of trailing metadata, so a capacity larger
    /// than `physical_size() - tail` is storage that does not exist: a read
    /// inside it cannot be served and a write inside it grows the file past
    /// what was provisioned. A fixed VHD is exactly that layout, with a 512
    /// byte footer.
    ///
    /// `None`, the default, makes no claim. It is the only sound value for a
    /// sparse format such as qcow2 or VHDX, whose file holds only the
    /// allocated clusters, and for a multi file format such as flat VMDK,
    /// whose data lives in extent files that the image file merely names.
    const CAPACITY_FILE_TAIL: Option<u64> = None;

    /// Whether a read the engine accepted and completed successfully always
    /// transfers the whole requested length.
    ///
    /// A block backend has no way to tell its caller which bytes of a partly
    /// filled buffer are real, so a short read that reports success leaves
    /// the guest reading whatever its buffer held before. Formats whose read
    /// path is all-or-error, or which fill unallocated ranges themselves, set
    /// this and get the check. The default is off because a read served
    /// straight from a file can legitimately stop at end of file.
    ///
    /// Reads only: the check says nothing about writes.
    const NO_SHORT_READS: bool = false;

    /// Whether a successful `punch_hole` guarantees that the range reads back
    /// as zeroes.
    ///
    /// When `false`, the executor marks discarded ranges as unknown in the
    /// shadow model instead of expecting zeroes.
    const PUNCH_HOLE_READS_ZEROES: bool = false;

    /// Granularity the engine requires data ops to be aligned to.
    ///
    /// A format whose engine refuses an offset or a length that is not a
    /// multiple of its logical sector size gets almost nothing out of a
    /// uniformly random program: a `u16` length is a multiple of 512 in 0.2%
    /// of cases, so 99.8% of the data ops in a generated program would be
    /// rejected before reaching any translation logic, and the shadow model
    /// would have nothing to check. The executor therefore snaps in range
    /// offsets down and lengths up to this value.
    ///
    /// Misaligned requests stay reachable: [`crate::disk_engine::OpOffset::Wild`]
    /// offsets are passed through untouched, and the image target drives
    /// [`crate::disk_engine::default_program`], whose 65535 byte read is not
    /// a multiple of any sector size.
    ///
    /// Must divide [`crate::disk_engine::MAX_OP_LEN`], so that rounding a
    /// length up cannot exceed the guest memory region.
    const IO_ALIGNMENT: u64 = 1;

    /// Whether `bytes` carries the bytes that identify this format.
    ///
    /// This is the harness side mirror of the first check the parser makes,
    /// and it exists so that [`fuzz_image`](super::fuzz_image) can tell
    /// "this input is a mutation of an image of my format" from "this input
    /// is a byte string that will never be one". An input that fails it is
    /// still handed to [`DiskFormat::open`], because the code in front of the
    /// magic check is worth covering, but it is only retained in the corpus
    /// while the budget in [`fuzz_image`](super::fuzz_image) lasts.
    ///
    /// The default accepts everything, so a format that has no identifying
    /// bytes keeps the old behaviour.
    ///
    /// Implementations must mirror the parser rather than the specification:
    /// a check the parser does not make would drop inputs the parser would
    /// have accepted.
    fn magic_ok(_bytes: &[u8]) -> bool {
        true
    }

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
