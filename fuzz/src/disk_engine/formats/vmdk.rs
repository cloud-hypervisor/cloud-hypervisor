// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Flat VMDK adapter.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::{Component, Path};
use std::sync::atomic::{AtomicBool, Ordering};

use block::disk_file::AsyncFullDiskFile;
use block::error::{BlockError, BlockErrorKind, BlockResult};
use block::formats::vmdk::VmdkDisk;
use libfuzzer_sys::Corpus;

use crate::disk_engine::format::{DiskFormat, OpenConfig};
use crate::disk_engine::image::scratch_dir;
use crate::disk_engine::{fuzz_image, sandbox};

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

/// Placeholder a descriptor uses to name the scratch directory.
///
/// An extent name may be absolute, and the engine treats an absolute name
/// very differently from a relative one: it anchors resolution at the
/// filesystem root and deliberately does not apply `RESOLVE_BENEATH`
/// (block/src/formats/vmdk/flat.rs:141 and :190). That arm cannot be fuzzed
/// by naming a real absolute path, because the only absolute path that is
/// safe to open here is one inside the scratch directory, and the scratch
/// directory carries the process id so no fixed corpus entry can name it.
///
/// A descriptor therefore writes the placeholder, and the harness expands it
/// into the scratch directory before the parser reads the file. The
/// expansion is a pure function of the input, so an input still reproduces
/// on its own: what varies between processes is the directory the harness
/// itself creates, exactly as it already does for relative names.
const SCRATCH_TOKEN: &str = "/@fuzz-scratch@";

/// Whether this process is confined to its scratch directory, and therefore
/// whether an absolute extent name may be admitted at all.
///
/// An absolute name is the one arm the kernel does not confine: resolution
/// is anchored at the filesystem root without `RESOLVE_BENEATH`, so a
/// symlink planted anywhere along the name is followed out of the scratch
/// directory and the extent behind it is opened *writable*. The lexical
/// guard cannot see that: every component of
/// `<scratch>/link/victim` is a [`Component::Normal`], and `O_NOFOLLOW`
/// only ever guards the final one.
///
/// So the arm is only fuzzed when the process itself is confined, and the
/// default is `false`: a harness that never called [`confine`] - a unit
/// test, or a future caller of [`Vmdk::open`] - refuses absolute names
/// outright and keeps the `RESOLVE_BENEATH` backstop the relative arm has.
static CONFINED: AtomicBool = AtomicBool::new(false);

/// Confines the process to `dir` and records whether it worked.
///
/// Called once, before the first iteration. The result gates the absolute
/// extent arm rather than the whole target: without confinement the relative
/// arm is still fuzzed, and it is still covered by `RESOLVE_BENEATH`.
fn confine(dir: &Path) -> bool {
    // The extent opener anchors an absolute name by opening `/`, so the
    // ruleset has to allow a directory open outside the scratch directory.
    // It allows nothing beneath one: opening the extent *file* behind the
    // symlink is what stays denied.
    let confined = sandbox::confine(dir, sandbox::Directories::ListAnywhere);
    CONFINED.store(confined, Ordering::Relaxed);
    confined
}

/// Fuzzes the flat VMDK descriptor parser and extent layout.
///
/// The confinement comes first, for the reason [`CONFINED`] gives: the
/// harness name guard is lexical, and the engine's absolute extent arm opens
/// files writable with no kernel confinement behind it.
pub fn fuzz_vmdk(bytes: &[u8]) -> Corpus {
    let Ok(dir) = scratch_dir(Vmdk::NAME) else {
        return Corpus::Reject;
    };
    confine(dir);

    fuzz_image::<Vmdk>(bytes)
}

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

    /// Expands [`SCRATCH_TOKEN`] in `descriptor` into the scratch directory.
    ///
    /// Returns `None` when there is nothing to expand, so the common case
    /// pays nothing.
    fn expand_scratch_token(descriptor: &str, dir: &Path) -> Option<String> {
        if !descriptor.contains(SCRATCH_TOKEN) {
            return None;
        }
        Some(descriptor.replace(SCRATCH_TOKEN, &dir.to_string_lossy()))
    }

    /// Rejects a descriptor that names an extent outside the scratch
    /// directory.
    ///
    /// The engine resolves an extent name against the descriptor's directory
    /// with `openat2`, and for an absolute name it anchors at the filesystem
    /// root without `RESOLVE_BENEATH`, and it opens the extent writable. A
    /// corpus entry could therefore reach and overwrite any file on the
    /// host, which is unacceptable in a fuzzer.
    ///
    /// A relative name is accepted when every component is
    /// [`Component::Normal`]: that rejects root and prefix components, `..`
    /// and `.` alike. An absolute name is accepted only when the process is
    /// confined (`absolute_allowed`), and then only when it starts with the
    /// scratch directory and every component after it is `Normal`.
    ///
    /// The lexical test alone is *not* enough for an absolute name, which is
    /// why it is gated: `<scratch>/link/victim` is all `Normal` components
    /// and still leaves the directory when `link` is a symlink, because the
    /// absolute arm drops `RESOLVE_BENEATH` and `O_NOFOLLOW` only guards the
    /// final component. Landlock is what refuses that open; without it the
    /// name is refused here instead.
    fn names_escaping_extent(descriptor: &str, dir: &Path, absolute_allowed: bool) -> bool {
        descriptor.lines().any(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if !matches!(parts.len(), 4 | 5) {
                return false;
            }
            let name = Path::new(parts[3].trim_matches('"'));
            let rest = if name.is_absolute() {
                if !absolute_allowed {
                    return true;
                }
                match name.strip_prefix(dir) {
                    Ok(rest) => rest,
                    Err(_) => return true,
                }
            } else {
                name
            };
            // An empty remainder is the scratch directory itself, which is
            // not an extent.
            rest.components().next().is_none()
                || !rest.components().all(|c| matches!(c, Component::Normal(_)))
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
        let mut descriptor = String::from_utf8_lossy(&raw[..len]).into_owned();

        // The placeholder is expanded in the file itself, because the parser
        // reads the descriptor from there and the expanded name has to be
        // the one it resolves.
        if let Some(expanded) = Self::expand_scratch_token(&descriptor, dir) {
            file.write_all_at(expanded.as_bytes(), 0)
                .map_err(|e| BlockError::new(BlockErrorKind::Io, e))?;
            file.set_len(expanded.len() as u64)
                .map_err(|e| BlockError::new(BlockErrorKind::Io, e))?;
            descriptor = expanded;
        }

        if Self::names_escaping_extent(&descriptor, dir, CONFINED.load(Ordering::Relaxed)) {
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
    use crate::disk_engine::image::{image_file, scratch_dir};

    fn descriptor(name: &str) -> String {
        format!("# Disk DescriptorFile\nversion=1\ncreateType=\"monolithicFlat\"\nRW 2048 FLAT \"{name}\" 0\n")
    }

    /// A descriptor the parser accepts in full, so that an open reaches the
    /// extent opener rather than stopping at the layout.
    fn openable_descriptor(name: &str) -> String {
        format!(
            "# Disk DescriptorFile\nversion=1\nCID=fffffffe\nparentCID=ffffffff\n\
             createType=\"monolithicFlat\"\n\n# Extent description\n\
             RW 2048 FLAT \"{name}\" 0\n\n# The Disk Data Base\n\
             ddb.virtualHWVersion = \"4\"\n"
        )
    }

    fn scratch() -> &'static Path {
        scratch_dir(Vmdk::NAME).expect("scratch directory")
    }

    // The engine opens extents writable, and for an absolute name it
    // resolves from the filesystem root without RESOLVE_BENEATH, so a
    // descriptor that escapes the scratch directory must never reach it.
    #[test]
    fn traversing_extent_names_are_rejected() {
        let dir = scratch();
        for name in [
            "../../../../tmp/victim".to_string(),
            "..".to_string(),
            "./image-flat.vmdk".to_string(),
            "sub/../../tmp/victim".to_string(),
            "/tmp/victim".to_string(),
            "/etc/passwd".to_string(),
            // Absolute, and inside the scratch directory only until the
            // components after it are followed.
            format!("{}/../../tmp/victim", dir.display()),
            // The scratch directory itself is not an extent.
            dir.display().to_string(),
            // A directory whose name merely starts with the scratch path.
            format!("{}-evil/image-flat.vmdk", dir.display()),
        ] {
            assert!(
                Vmdk::names_escaping_extent(&descriptor(&name), dir, true),
                "{name} must be rejected"
            );
        }
    }

    // The absolute arm of the engine's extent opener is only reachable with
    // an absolute name, and the only absolute name that is safe to give it
    // is one inside the scratch directory the harness owns.
    #[test]
    fn absolute_names_inside_the_scratch_directory_are_accepted() {
        let dir = scratch();
        for name in [
            format!("{}/image-flat.vmdk", dir.display()),
            format!("{}/extents/s001.vmdk", dir.display()),
        ] {
            assert!(
                !Vmdk::names_escaping_extent(&descriptor(&name), dir, true),
                "{name} must be accepted"
            );
            assert!(
                Vmdk::names_escaping_extent(&descriptor(&name), dir, false),
                "{name} must be refused without confinement"
            );
        }
    }

    // A corpus entry cannot know the scratch path, so it writes the
    // placeholder and the harness expands it. The expansion has to produce a
    // name the guard then accepts, or the arm stays unreachable.
    #[test]
    fn the_scratch_token_expands_to_an_accepted_absolute_name() {
        let dir = scratch();
        let raw = descriptor(&format!("{SCRATCH_TOKEN}/image-flat.vmdk"));
        assert!(
            Vmdk::names_escaping_extent(&raw, dir, true),
            "the unexpanded placeholder is not a valid name"
        );

        let expanded = Vmdk::expand_scratch_token(&raw, dir).expect("the token must expand");
        assert!(expanded.contains(&dir.display().to_string()));
        assert!(!Vmdk::names_escaping_extent(&expanded, dir, true));
        assert!(Vmdk::expand_scratch_token("no token here", dir).is_none());
    }

    // A name that is lexically inside the scratch directory but traverses a
    // symlink out of it is exactly what the guard cannot see, so it must be
    // refused for as long as nothing else can refuse it: an unconfined
    // process admits no absolute name at all.
    #[test]
    fn absolute_names_need_the_confinement() {
        let dir = scratch();
        for name in [
            format!("{}/image-flat.vmdk", dir.display()),
            format!("{}/link/victim", dir.display()),
        ] {
            assert!(
                Vmdk::names_escaping_extent(&descriptor(&name), dir, false),
                "{name} must be refused while the process is not confined"
            );
        }
        // The default is unconfined, so a caller that never confined the
        // process gets the refusing policy without asking for it.
        assert!(!CONFINED.load(Ordering::Relaxed));
    }

    // What the confinement is for. The absolute arm resolves from the
    // filesystem root without RESOLVE_BENEATH and opens the extent writable,
    // and O_NOFOLLOW only guards the final component, so a symlink planted
    // inside the scratch directory reaches a file outside it with every
    // component of the name a plain `Component::Normal`. The lexical guard
    // admits that name by construction; Landlock is what refuses the open.
    //
    // Ignored by default because it confines the whole test process, and a
    // test that ran after it would lose its own scratch directory. Run it on
    // its own:
    //
    //     cargo test --lib -- --ignored --exact \
    //         disk_engine::formats::vmdk::tests::a_symlink_out_of_the_scratch_directory_is_denied
    #[test]
    #[ignore = "confines the whole test process"]
    fn a_symlink_out_of_the_scratch_directory_is_denied() {
        let dir = scratch();
        std::fs::create_dir_all(dir).expect("scratch directory");

        // The victim lives outside the scratch directory, and the symlink to
        // it lives inside: every component of the extent name below is a
        // plain name.
        let outside =
            std::env::temp_dir().join(format!("ch-fuzz-vmdk-outside-{}", std::process::id()));
        std::fs::create_dir_all(&outside).expect("victim directory");
        let victim = outside.join("victim");
        std::fs::write(&victim, b"UNTOUCHED").expect("victim file");
        let link = dir.join("link");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&outside, &link).expect("symlink into the scratch directory");
        // Opened before the confinement, because afterwards not even this
        // test may open a path outside the scratch directory - which is the
        // point. An already open descriptor keeps working.
        let handle = File::open(&victim).expect("victim handle");

        assert!(confine(dir), "the process must be confined");

        let escaping = openable_descriptor(&format!("{}/link/victim", dir.display()));
        let (file, path) = image_file("vmdk", escaping.as_bytes()).expect("scratch image");
        let err = Vmdk::open(file, Some(&path), &OpenConfig::default())
            .err()
            .expect("an extent name traversing a symlink out of the scratch directory");
        // Not merely an error: the open has to be denied by the kernel, or
        // the test would pass on a descriptor that never reached the opener.
        let denied = format!("{err:?}").contains("PermissionDenied");
        eprintln!("escaping extent name refused: {err:?}");
        assert!(denied, "the open must be denied, got {err:?}");
        let mut seen = [0u8; 9];
        handle.read_at(&mut seen, 0).expect("victim contents");
        assert_eq!(
            &seen, b"UNTOUCHED",
            "the victim file must not have been written"
        );
        assert_eq!(
            handle.metadata().expect("victim metadata").len(),
            9,
            "the victim file must not have been resized"
        );

        // And the arm the absolute name exists to cover still works, so the
        // confinement bought the refusal and not the coverage.
        let legitimate = openable_descriptor(&format!("{}/image-flat.vmdk", dir.display()));
        let (file, path) = image_file("vmdk", legitimate.as_bytes()).expect("scratch image");
        Vmdk::open(file, Some(&path), &OpenConfig::default())
            .expect("an absolute extent name inside the scratch directory must still open");
        eprintln!("absolute extent name inside the scratch directory: opened");
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
                !Vmdk::names_escaping_extent(&descriptor(name), scratch(), true),
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
