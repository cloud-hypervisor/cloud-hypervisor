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

/// `VMDK_DESCRIPTOR_HEADER` in the parser.
const DESCRIPTOR_HEADER: &str = "# Disk DescriptorFile";

/// Extent names the harness creates and zeroes before every open.
const EXTENTS: [&str; 6] = [
    "image-flat.vmdk",
    "image-f001.vmdk",
    "image-f002.vmdk",
    "flat-flat.vmdk",
    "two-f001.vmdk",
    "two-f002.vmdk",
];

/// Flat VMDK images, as opened by [`VmdkDisk`]. The descriptor is written to
/// a scratch directory holding the extent files it may name. There is no
/// template: the `block` crate cannot write a descriptor.
pub struct Vmdk;

impl Vmdk {
    /// Creates and zeroes the extent files a descriptor may name.
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

    /// Whether the descriptor names an extent that is not all
    /// [`Component::Normal`]. The engine resolves such names without
    /// confinement and opens them writable.
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

    // Mirrors `read_descriptor` and `parse_header`: UTF-8 and the header line.
    fn magic_ok(bytes: &[u8]) -> bool {
        let Ok(text) = std::str::from_utf8(bytes) else {
            return false;
        };
        text.lines()
            .next()
            .is_some_and(|line| line.trim_end() == DESCRIPTOR_HEADER)
    }

    // No capacity or short read invariants: the data lives in extent files, and
    // an extent longer than its file reads short.

    fn open(
        file: File,
        path: Option<&Path>,
        config: &OpenConfig,
    ) -> BlockResult<Box<dyn AsyncFullDiskFile>> {
        let path = path.expect("vmdk images are path backed");
        let dir = path
            .parent()
            .unwrap_or_else(|| scratch_dir(Self::NAME).expect("scratch directory"));

        // Read positionally: the engine shares the file cursor.
        let mut raw = vec![0u8; Self::MAX_IMAGE_LEN];
        let len = file
            .read_at(&mut raw, 0)
            .map_err(|e| BlockError::new(BlockErrorKind::Io, e))?;
        let descriptor = String::from_utf8_lossy(&raw[..len]);

        if Self::names_escaping_extent(&descriptor) {
            return Err(BlockError::from_kind(BlockErrorKind::UnsupportedFeature));
        }

        Self::reset_extents(dir)?;

        // A writable open. The descriptor's access field decides per extent.
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

    // Escaping extent names must never reach the engine.
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

    // `magic_ok` must track the parser's header check.
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

    // The guard also holds at `Vmdk::open`.
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
