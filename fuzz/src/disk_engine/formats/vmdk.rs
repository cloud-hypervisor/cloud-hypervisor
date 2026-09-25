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
use libfuzzer_sys::Corpus;

use crate::disk_engine::format::{DiskFormat, OpenConfig};
use crate::disk_engine::image::scratch_dir;
use crate::disk_engine::{fuzz_image, sandbox};

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

/// The `disk_vmdk_ops` template: two `RW` extents of different lengths, the
/// second at a non-zero base offset, so spanning I/O and the offset
/// arithmetic are under the model.
const TEMPLATE: &str = "\
# Disk DescriptorFile
version=1
CID=fffffffe
parentCID=ffffffff
createType=\"twoGbMaxExtentFlat\"

# Extent description
RW 2048 FLAT \"image-f001.vmdk\" 0
RW 1024 FLAT \"image-f002.vmdk\" 1

# The Disk Data Base
ddb.virtualHWVersion = \"4\"
";

/// Virtual size of [`TEMPLATE`]: the sum of its extent lengths.
pub const TEMPLATE_LOGICAL_SIZE: u64 = (2048 + 1024) * 512;

/// Virtual offset where [`TEMPLATE`]'s first extent ends.
pub const TEMPLATE_EXTENT_BOUNDARY: u64 = 2048 * 512;

/// One byte over the parser's 1 MiB descriptor limit, so the engine rather
/// than the harness refuses an oversized descriptor.
const MAX_FUZZ_DESCRIPTOR_LEN: usize = (1 << 20) + 1;

/// Fuzzes the flat VMDK parser under Landlock, refusing every input if
/// confinement fails: this bypasses the production `backing_files` gate.
pub fn fuzz_vmdk(bytes: &[u8]) -> Corpus {
    let dir = scratch_dir(Vmdk::NAME).unwrap_or_else(|e| {
        eprintln!("disk_vmdk: scratch directory setup failed: {e}");
        std::process::exit(2);
    });
    if !sandbox::confine(dir) {
        return Corpus::Reject;
    }

    fuzz_image::<Vmdk>(bytes)
}

/// Flat VMDK images, as opened by [`VmdkDisk`]. The descriptor is written to
/// a scratch directory holding the extent files it may name.
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

    // See `MAX_FUZZ_DESCRIPTOR_LEN`.
    const MAX_IMAGE_LEN: usize = MAX_FUZZ_DESCRIPTOR_LEN;

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
        let file_len = file
            .metadata()
            .map_err(|e| BlockError::new(BlockErrorKind::Io, e))?
            .len();
        let mut raw = vec![0u8; file_len.min(Self::MAX_IMAGE_LEN as u64) as usize];
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

    fn template() -> Option<&'static [u8]> {
        Some(TEMPLATE.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::disk_engine::image::image_file;
    use crate::disk_engine::selftest::assert_template_is_sound;
    use crate::disk_engine::{Executor, Op, OpLen, OpOffset};

    /// Serializes tests that reset the shared extent files.
    static TEMPLATE_IO: Mutex<()> = Mutex::new(());

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

    /// See `disk_engine::selftest`.
    #[test]
    fn the_template_is_a_blank_one_and_a_half_mib_disk() {
        let _guard = TEMPLATE_IO.lock().unwrap_or_else(|e| e.into_inner());
        assert_template_is_sound::<Vmdk>(TEMPLATE_LOGICAL_SIZE);
    }

    /// Pins the template properties the operation target relies on.
    #[test]
    fn the_template_descriptor_is_the_pinned_layout() {
        let text = std::str::from_utf8(Vmdk::template().expect("vmdk has a template"))
            .expect("the template is ASCII");
        assert!(Vmdk::magic_ok(text.as_bytes()));
        assert!(text.lines().any(|line| line == "# Extent description"));

        let extents: Vec<Vec<&str>> = text
            .lines()
            .filter(|line| line.starts_with("RW ") || line.starts_with("RDONLY "))
            .map(|line| line.split_whitespace().collect())
            .collect();
        assert_eq!(extents.len(), 2, "a single extent never spans");

        let mut virtual_start = 0u64;
        for (index, parts) in extents.iter().enumerate() {
            assert_eq!(parts.len(), 5, "an extent line without a base offset");
            assert_eq!(parts[2], "FLAT");
            let name = parts[3].trim_matches('"');
            assert!(
                !Path::new(name).is_absolute(),
                "{name}: the template must use relative extent names only"
            );
            assert!(
                EXTENTS.contains(&name),
                "{name} is not created and reset by the harness"
            );
            let sectors: u64 = parts[1].parse().expect("a sector count");
            let base: u64 = parts[4].parse().expect("a base offset");
            assert!(
                base * 512 + sectors * 512 <= EXTENT_LEN,
                "{name} does not fit the {EXTENT_LEN} byte extent files"
            );
            if index == 1 {
                assert!(base > 0, "a zero base offset hides the offset arithmetic");
            }
            virtual_start += sectors * 512;
            if index == 0 {
                assert_eq!(virtual_start, TEMPLATE_EXTENT_BOUNDARY);
            }
        }
        assert_eq!(virtual_start, TEMPLATE_LOGICAL_SIZE);
    }

    /// The model must catch a misplaced spanning write. Each write is read back
    /// through the other path, since an error both paths share cancels out.
    /// Both cache modes.
    #[test]
    fn the_model_catches_a_misplaced_spanning_write() {
        let _guard = TEMPLATE_IO.lock().unwrap_or_else(|e| e.into_inner());
        let straddle = TEMPLATE_EXTENT_BOUNDARY - 512;
        let tail = TEMPLATE_LOGICAL_SIZE - 4096;
        let program = vec![
            // Spanning: 512 bytes into extent 1, 1536 into extent 2.
            Op::WriteVec {
                offset: OpOffset::Byte(straddle as u32),
                len: OpLen(2048),
                seed: 0x27,
            },
            // The far side alone, through `single_extent_io`.
            Op::ReadVec {
                offset: OpOffset::Byte(TEMPLATE_EXTENT_BOUNDARY as u32),
                len: OpLen(1536),
            },
            // The near side alone.
            Op::ReadVec {
                offset: OpOffset::Byte(straddle as u32),
                len: OpLen(512),
            },
            // Both sides spanning.
            Op::ReadVec {
                offset: OpOffset::Byte(straddle as u32),
                len: OpLen(2048),
            },
            // A tail write, read back spanning.
            Op::WriteVec {
                offset: OpOffset::Byte(tail as u32),
                len: OpLen(4096),
                seed: 0x93,
            },
            Op::ReadVec {
                offset: OpOffset::Byte(straddle as u32),
                len: OpLen(65535),
            },
        ];

        let template = Vmdk::template().expect("vmdk has a template");
        for direct in [false, true] {
            let (file, path) =
                crate::disk_engine::materialize_template::<Vmdk>(template).expect("template");
            let config = OpenConfig {
                direct,
                ..OpenConfig::default()
            };
            let disk = Vmdk::open(file, path.as_deref(), &config).expect("the template opens");
            let mut executor = Executor::<Vmdk>::new(disk, 1, true).expect("executor");
            // Panics on a read back mismatch.
            executor.run(&program);
        }
    }

    /// The parser's 1 MiB limit must be reachable from both sides. Padding
    /// after the DDB line is ignored.
    #[test]
    fn the_descriptor_size_limit_is_reachable_from_both_sides() {
        // Opening resets the shared extent files.
        let _guard = TEMPLATE_IO.lock().unwrap_or_else(|e| e.into_inner());
        const LIMIT: usize = 1 << 20;
        assert_eq!(Vmdk::MAX_IMAGE_LEN, LIMIT + 1);

        // Its own path, so no other test can replace the descriptor.
        let path = scratch_dir(Vmdk::NAME)
            .expect("scratch directory")
            .join("boundary.vmdk");
        let open = |len: usize| {
            let mut descriptor = TEMPLATE.as_bytes().to_vec();
            descriptor.resize(len - 1, b'#');
            descriptor.push(b'\n');
            std::fs::write(&path, &descriptor).expect("boundary descriptor");

            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .expect("boundary descriptor");
            Vmdk::open(file, Some(&path), &OpenConfig::default())
        };

        let disk = open(LIMIT).expect("a 1 MiB descriptor must open");
        assert_eq!(
            disk.logical_size().expect("the descriptor reports a size"),
            TEMPLATE_LOGICAL_SIZE
        );
        drop(disk);

        let err = open(LIMIT + 1)
            .err()
            .expect("a descriptor over 1 MiB must be refused");
        let cause = err
            .downcast_ref::<std::io::Error>()
            .expect("the engine's descriptor read error");
        assert!(
            cause.to_string().contains("maximum descriptor size"),
            "the engine refused the descriptor for another reason: {cause}"
        );

        let _ = std::fs::remove_file(&path);
    }
}
