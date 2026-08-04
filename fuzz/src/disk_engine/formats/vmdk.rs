// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Flat VMDK adapter.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::{Component, Path};

use block::disk_file::AsyncFullDiskFile;
use block::error::{BlockError, BlockErrorKind, BlockResult};
use block::formats::vmdk::VmdkDisk;

use crate::disk_engine::format::{DiskFormat, OpenConfig};
use crate::disk_engine::image::scratch_dir;

/// Size of each extent file the harness provides.
const EXTENT_LEN: u64 = 1 << 20;

/// The first line of every descriptor, from `VMDK_DESCRIPTOR_HEADER` in the
/// parser under test (block/src/formats/vmdk/descriptor.rs:19).
const DESCRIPTOR_HEADER: &str = "# Disk DescriptorFile";

/// Extent names the harness creates in the scratch directory.
///
/// A descriptor referring to one of these opens successfully and reaches the
/// extent aware I/O engine; any other name fails at open, which is the same
/// path a missing extent takes in production. The names are the ones
/// `qemu-img` derives from an image called `image.vmdk`, plus the ones the
/// generated seeds use.
const EXTENTS: [&str; 6] = [
    "image-flat.vmdk",
    "image-f001.vmdk",
    "image-f002.vmdk",
    "flat-flat.vmdk",
    "two-f001.vmdk",
    "two-f002.vmdk",
];

/// Flat VMDK images, as opened by [`VmdkDisk`].
///
/// A VMDK image is a text descriptor that names its data extents as separate
/// files, so unlike every other format here it cannot be fuzzed from a memfd:
/// the engine resolves extent names against the descriptor's directory. The
/// harness therefore materializes the descriptor in a scratch directory that
/// already holds the extent files.
///
/// There is no template image: the `block` crate parses descriptors but never
/// writes one.
pub struct Vmdk;

impl Vmdk {
    /// Creates the extent files a descriptor may refer to, and resets them so
    /// that one iteration cannot observe what an earlier one wrote.
    fn reset_extents(dir: &Path) -> BlockResult<()> {
        for name in EXTENTS {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(dir.join(name))
                .map_err(|e| BlockError::new(BlockErrorKind::Io, e))?;
            file.set_len(EXTENT_LEN)
                .map_err(|e| BlockError::new(BlockErrorKind::Io, e))?;
        }
        Ok(())
    }

    /// Rejects a descriptor that names an extent outside the scratch
    /// directory.
    ///
    /// The engine resolves an extent name against the descriptor's directory
    /// with `openat2` and `resolve: 0`, which anchors an absolute name at the
    /// filesystem root and follows `..` out of the directory, and it opens
    /// the extent writable. A corpus entry could therefore reach and
    /// overwrite any file on the host. That is unacceptable in a fuzzer, and
    /// it is the same reason backing files are not enabled for qcow2.
    /// Fuzzing that branch safely needs a filesystem sandbox rather than a
    /// scratch directory.
    ///
    /// Only names made entirely of [`Component::Normal`] components are
    /// allowed: that rejects absolute paths, root and prefix components, `..`
    /// and `.` alike.
    fn names_escaping_extent(descriptor: &str) -> bool {
        descriptor.lines().any(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if !matches!(parts.len(), 4 | 5) {
                return false;
            }
            let name = Path::new(parts[3].trim_matches('"'));
            name.is_absolute() || !name.components().all(|c| matches!(c, Component::Normal(_)))
        })
    }
}

impl DiskFormat for Vmdk {
    const NAME: &'static str = "vmdk";

    // The descriptor names its extents relative to its own directory.
    const NEEDS_PATH: bool = true;

    // A descriptor is a small text file; the data lives in the extents.
    const MAX_IMAGE_LEN: usize = 64 << 10;

    // `parse_header` rejects a descriptor whose first line is not exactly
    // "# Disk DescriptorFile" (block/src/formats/vmdk/descriptor.rs:133,
    // VMDK_DESCRIPTOR_HEADER at line 19), and `read_descriptor` rejects one
    // that is not UTF-8 (line 118). Both run before anything else is parsed.
    //
    // The parser compares the line with its trailing whitespace stripped, so
    // this does too: a check the parser does not make would drop inputs it
    // would have accepted.
    fn magic_ok(bytes: &[u8]) -> bool {
        let Ok(text) = std::str::from_utf8(bytes) else {
            return false;
        };
        text.lines()
            .next()
            .is_some_and(|line| line.trim_end() == DESCRIPTOR_HEADER)
    }

    // Neither new invariant holds for a flat VMDK, so both keep their
    // conservative default.
    //
    // The capacity is the sum of the extent sizes the descriptor declares,
    // and the data lives in those separate files rather than in the image
    // file, so `physical_size` says nothing about it.
    //
    // A read can legitimately come up short: an extent declared longer than
    // the file behind it makes the buffered path stop at end of file
    // (block/src/formats/vmdk/engine_sync.rs:100) and the spanning path
    // break out of its loop (block/src/formats/vmdk/engine_sync.rs:180),
    // both reporting the partial count as a success. A fuzzed descriptor
    // declares extent sizes freely, so this is reachable by construction.

    fn open(
        file: File,
        path: Option<&Path>,
        config: &OpenConfig,
    ) -> BlockResult<Box<dyn AsyncFullDiskFile>> {
        let path = path.expect("vmdk images are path backed");
        let dir = path
            .parent()
            .unwrap_or_else(|| scratch_dir(Self::NAME).expect("scratch directory"));

        // Read positionally: `try_clone` is dup(2) and shares the file
        // cursor with the engine, so a probe that moved it would leave the
        // guard and the parser looking at different bytes.
        let mut raw = vec![0u8; Self::MAX_IMAGE_LEN];
        let len = file
            .read_at(&mut raw, 0)
            .map_err(|e| BlockError::new(BlockErrorKind::Io, e))?;
        let descriptor = String::from_utf8_lossy(&raw[..len]);

        if Self::names_escaping_extent(&descriptor) {
            return Err(BlockError::from_kind(BlockErrorKind::UnsupportedFeature));
        }

        Self::reset_extents(dir)?;

        // The fuzzer drives the writable path, so it asks for a writable
        // open and lets the descriptor's own access field decide per extent.
        let disk = VmdkDisk::new(file, path, false, config.direct)?;
        Ok(Box::new(disk))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disk_engine::image::image_file;

    fn descriptor(name: &str) -> String {
        format!("# Disk DescriptorFile\nversion=1\ncreateType=\"monolithicFlat\"\nRW 2048 FLAT \"{name}\" 0\n")
    }

    // The engine opens extents writable through openat2 with resolve: 0,
    // which follows `..` out of the scratch directory, so a descriptor that
    // escapes must never reach it.
    #[test]
    fn traversing_extent_names_are_rejected() {
        for name in [
            "../../../../tmp/victim",
            "..",
            "./image-flat.vmdk",
            "sub/../../tmp/victim",
            "/tmp/victim",
            "/etc/passwd",
        ] {
            assert!(
                Vmdk::names_escaping_extent(&descriptor(name)),
                "{name} must be rejected"
            );
        }
    }

    // `magic_ok` decides whether a corpus entry is a descriptor at all, so it
    // has to agree with the header line test the parser makes.
    #[test]
    fn magic_ok_tracks_the_descriptor_header() {
        assert!(Vmdk::magic_ok(descriptor("image-flat.vmdk").as_bytes()));
        // The parser trims trailing whitespace off the header line.
        assert!(Vmdk::magic_ok(b"# Disk DescriptorFile \nversion=1\n"));
        assert!(!Vmdk::magic_ok(b"# Disk Descriptor\n"));
        assert!(!Vmdk::magic_ok(b"version=1\n# Disk DescriptorFile\n"));
        assert!(!Vmdk::magic_ok(b""));
        assert!(!Vmdk::magic_ok(&[0xff, 0xfe, 0xfd]));
    }

    #[test]
    fn plain_extent_names_are_accepted() {
        for name in ["image-flat.vmdk", "two-f001.vmdk"] {
            assert!(
                !Vmdk::names_escaping_extent(&descriptor(name)),
                "{name} must be accepted"
            );
        }
    }

    // The guard has to hold at the harness entry point, not just in
    // isolation: `open` reads the descriptor positionally, so it sees the
    // same bytes the engine parses.
    #[test]
    fn open_refuses_a_traversing_descriptor() {
        let bytes = descriptor("../../../../tmp/victim");
        let (file, path) = image_file("vmdk", bytes.as_bytes()).expect("scratch image");
        let err = Vmdk::open(file, Some(&path), &OpenConfig::default())
            .err()
            .expect("a descriptor escaping the scratch directory must be refused");
        assert_eq!(err.kind(), BlockErrorKind::UnsupportedFeature);
        assert!(
            !Path::new("/tmp/victim").exists(),
            "the harness must not have created /tmp/victim"
        );
    }
}
