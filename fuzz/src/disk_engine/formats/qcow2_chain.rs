// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! QCOW2 backing chain adapter.
//!
//! Reaches the backing file code `disk_qcow2` never opens. Backing names are
//! host paths, so the harness admits only plain names in its scratch
//! directory and runs under Landlock. There is no shadow model: a discarded
//! cluster reads through to the backing image.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path};

use block::disk_file::AsyncFullDiskFile;
use block::error::{BlockError, BlockErrorKind, BlockResult};
use block::formats::qcow::QcowDisk;
use libfuzzer_sys::Corpus;

use crate::disk_engine::executor::Executor;
use crate::disk_engine::format::{DiskFormat, OpenConfig};
use crate::disk_engine::formats::qcow2::Qcow2;
use crate::disk_engine::image::{image_file, scratch_dir};
use crate::disk_engine::program::default_program;
use crate::disk_engine::sandbox;

/// Largest image half of an input.
const MAX_HALF_LEN: usize = 2 << 20;

/// Name the backing image is always written under.
const DEFAULT_BACKING_NAME: &str = "backing.img";

/// A fixed empty raw file, so a three deep chain can terminate.
const LEAF_NAME: &str = "leaf.raw";

/// Size of that file.
const LEAF_LEN: u64 = 1 << 20;

/// Longest backing name the harness materializes (`NAME_MAX`).
const MAX_NAME_LEN: usize = 255;

/// What the harness makes of the backing name in an image header.
#[derive(Debug, Eq, PartialEq)]
pub enum BackingName {
    /// The image names no backing file.
    Absent,
    /// The image names a plain file in the scratch directory.
    Safe(String),
    /// The image names something the harness will not resolve.
    Escaping,
}

/// QCOW2 images opened with backing files enabled.
pub struct Qcow2Chain;

impl Qcow2Chain {
    /// Classifies the backing name in a qcow2 header before the engine can open
    /// it. Fails closed: anything that is not provably absent or a plain file
    /// name is [`BackingName::Escaping`].
    pub fn backing_name(bytes: &[u8]) -> BackingName {
        // magic, version, backing_file_offset, backing_file_size.
        if bytes.len() < 20 {
            return BackingName::Absent;
        }
        let offset = u64::from_be_bytes(bytes[8..16].try_into().expect("8 bytes"));
        let size = u32::from_be_bytes(bytes[16..20].try_into().expect("4 bytes"));
        if offset == 0 || size == 0 {
            return BackingName::Absent;
        }

        let Ok(start) = usize::try_from(offset) else {
            return BackingName::Escaping;
        };
        let Some(end) = start.checked_add(size as usize) else {
            return BackingName::Escaping;
        };
        if end > bytes.len() || size as usize > MAX_NAME_LEN {
            return BackingName::Escaping;
        }
        let Ok(name) = std::str::from_utf8(&bytes[start..end]) else {
            return BackingName::Escaping;
        };

        if Self::is_plain_name(name) {
            BackingName::Safe(name.to_string())
        } else {
            BackingName::Escaping
        }
    }

    /// Whether `name` is a single [`Component::Normal`] without a NUL. The
    /// engine joins it onto the image directory without normalising it.
    fn is_plain_name(name: &str) -> bool {
        if name.is_empty() || name.len() > MAX_NAME_LEN || name.contains('\0') {
            return false;
        }
        let path = Path::new(name);
        if path.is_absolute() {
            return false;
        }
        let mut components = path.components();
        matches!(components.next(), Some(Component::Normal(c)) if c == name)
            && components.next().is_none()
    }

    /// Empties the scratch directory, so no input sees earlier inputs' files.
    fn reset_scratch(dir: &Path) -> std::io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                fs::remove_file(entry.path())?;
            }
        }
        Ok(())
    }

    /// Writes `bytes` into the scratch directory under `name`.
    fn write_backing(dir: &Path, name: &str, bytes: &[u8]) -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(dir.join(name))?;
        file.write_all(bytes)
    }

    /// Creates [`LEAF_NAME`].
    fn write_leaf(dir: &Path) -> std::io::Result<()> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(dir.join(LEAF_NAME))?;
        file.set_len(LEAF_LEN)
    }
}

impl DiskFormat for Qcow2Chain {
    const NAME: &'static str = "qcow2-chain";

    // `parse_qcow` resolves backing names through /proc/self/fd, which cannot
    // anchor a memfd.
    const NEEDS_PATH: bool = true;

    const MAX_IMAGE_LEN: usize = MAX_HALF_LEN;

    // Same as plain qcow2.
    const NO_SHORT_READS: bool = Qcow2::NO_SHORT_READS;

    // A discarded cluster reads through to the backing image.
    const PUNCH_HOLE_READS_ZEROES: bool = false;

    fn magic_ok(bytes: &[u8]) -> bool {
        Qcow2::magic_ok(bytes)
    }

    fn open(
        file: File,
        path: Option<&Path>,
        config: &OpenConfig,
    ) -> BlockResult<Box<dyn AsyncFullDiskFile>> {
        // Checked here too, so no caller can skip the guard.
        if config.backing {
            let path = path.expect("a backing chain image is path backed");
            let bytes = fs::read(path).map_err(|e| BlockError::new(BlockErrorKind::Io, e))?;
            if Self::backing_name(&bytes) == BackingName::Escaping {
                return Err(BlockError::from_kind(BlockErrorKind::UnsupportedFeature));
            }
        }

        let disk = QcowDisk::new(file, config.direct, config.backing, config.sparse, false)?;
        Ok(Box::new(disk))
    }
}

/// Splits an input into the image and its backing image.
fn split(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = bytes.split_at_checked(4)?;
    let top_len = u32::from_le_bytes(len.try_into().expect("4 bytes")) as usize;
    Some(rest.split_at(top_len.min(rest.len())))
}

/// Fuzzes qcow2 backing chains. Refuses every input without Landlock.
pub fn fuzz_chain(bytes: &[u8]) -> Corpus {
    let dir = scratch_dir(Qcow2Chain::NAME).unwrap_or_else(|e| {
        eprintln!("disk_qcow2_chain: scratch directory setup failed: {e}");
        std::process::exit(2);
    });
    if !sandbox::confine(dir) {
        return Corpus::Reject;
    }

    let Some((top, backing)) = split(bytes) else {
        return Corpus::Reject;
    };
    if top.len() > MAX_HALF_LEN || backing.len() > MAX_HALF_LEN {
        return Corpus::Reject;
    }
    // Rejections before the backing code are `disk_qcow2`'s job.
    if !Qcow2Chain::magic_ok(top) {
        return Corpus::Reject;
    }

    // The backing image may name a further backing file, so check it too.
    let names = [
        Qcow2Chain::backing_name(top),
        Qcow2Chain::backing_name(backing),
    ];
    if names.contains(&BackingName::Escaping) {
        return Corpus::Reject;
    }

    if Qcow2Chain::reset_scratch(dir).is_err() {
        return Corpus::Reject;
    }
    // Write the backing image under every name the chain asks for, then the top
    // image, so a self-referencing chain recurses to `MAX_NESTING_DEPTH`.
    if Qcow2Chain::write_backing(dir, DEFAULT_BACKING_NAME, backing).is_err() {
        return Corpus::Reject;
    }
    if Qcow2Chain::write_leaf(dir).is_err() {
        return Corpus::Reject;
    }
    for name in &names {
        if let BackingName::Safe(name) = name {
            if Qcow2Chain::write_backing(dir, name, backing).is_err() {
                return Corpus::Reject;
            }
        }
    }

    let Ok((file, path)) = image_file(Qcow2Chain::NAME, top) else {
        return Corpus::Reject;
    };

    let config = OpenConfig {
        backing: true,
        // Reaches the copy-on-write arm of `deallocate_bytes`.
        sparse: true,
        ..OpenConfig::default()
    };
    let Ok(disk) = Qcow2Chain::open(file, Some(&path), &config) else {
        return Corpus::Keep;
    };

    // No model: a discarded cluster reads through to the backing image.
    if let Some(mut executor) = Executor::<Qcow2Chain>::new(disk, 1, false) {
        executor.run(&default_program());
    }

    Corpus::Keep
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use block::async_io::{AsyncIoOperation, OwnedIoBuffer};

    use super::*;

    /// Byte the backing image is filled with.
    const PATTERN: u8 = 0xa5;

    /// Builds a two image chain with `qemu-img`. The base holds [`PATTERN`].
    fn qemu_chain() -> Option<(Vec<u8>, Vec<u8>)> {
        let dir = std::env::temp_dir().join("qcow2-chain-check");
        let _ = fs::create_dir_all(&dir);
        for name in ["source.raw", "base.qcow2", "top.qcow2"] {
            let _ = fs::remove_file(dir.join(name));
        }

        fs::write(dir.join("source.raw"), vec![PATTERN; 1 << 20]).ok()?;
        let qemu = |args: &[&str]| -> Option<bool> {
            Some(
                Command::new("qemu-img")
                    .current_dir(&dir)
                    .args(args)
                    .status()
                    .ok()?
                    .success(),
            )
        };
        if !qemu(&["convert", "-O", "qcow2", "source.raw", "base.qcow2"])?
            || !qemu(&[
                "create",
                "-f",
                "qcow2",
                "-F",
                "qcow2",
                "-b",
                "base.qcow2",
                "top.qcow2",
                "1M",
            ])?
        {
            return None;
        }

        Some((
            fs::read(dir.join("top.qcow2")).ok()?,
            fs::read(dir.join("base.qcow2")).ok()?,
        ))
    }

    /// Builds a minimal v3 header naming `name` as its backing file.
    fn image_with_backing(name: &str) -> Vec<u8> {
        let mut image = vec![0u8; 1 << 16];
        image[0..4].copy_from_slice(b"QFI\xfb");
        image[4..8].copy_from_slice(&3u32.to_be_bytes());
        let offset: u64 = 512;
        image[8..16].copy_from_slice(&offset.to_be_bytes());
        image[16..20].copy_from_slice(&(name.len() as u32).to_be_bytes());
        // cluster_bits = 16, so the name stays inside the first cluster.
        image[20..24].copy_from_slice(&16u32.to_be_bytes());
        image[24..32].copy_from_slice(&(1u64 << 20).to_be_bytes());
        let at = offset as usize;
        image[at..at + name.len()].copy_from_slice(name.as_bytes());
        image
    }

    // Escaping names must never reach the engine.
    #[test]
    fn traversing_backing_names_are_refused() {
        for name in [
            "../../../../tmp/victim",
            "..",
            "./backing.img",
            "sub/../../tmp/victim",
            "sub/backing.img",
            "/tmp/victim",
            "/etc/passwd",
            "back\0ing.img",
        ] {
            assert_eq!(
                Qcow2Chain::backing_name(&image_with_backing(name)),
                BackingName::Escaping,
                "{name:?} must be refused"
            );
        }
    }

    #[test]
    fn plain_backing_names_are_accepted() {
        for name in ["backing.img", "base.qcow2", "image.qcow2-chain"] {
            assert_eq!(
                Qcow2Chain::backing_name(&image_with_backing(name)),
                BackingName::Safe(name.to_string()),
                "{name} must be accepted"
            );
        }
    }

    // No backing file is normal. An unreadable name is refused.
    #[test]
    fn a_header_without_a_backing_file_is_absent() {
        let mut image = image_with_backing("backing.img");
        image[8..16].copy_from_slice(&0u64.to_be_bytes());
        assert_eq!(Qcow2Chain::backing_name(&image), BackingName::Absent);

        let mut image = image_with_backing("backing.img");
        image[16..20].copy_from_slice(&0u32.to_be_bytes());
        assert_eq!(Qcow2Chain::backing_name(&image), BackingName::Absent);

        assert_eq!(Qcow2Chain::backing_name(b"QFI\xfb"), BackingName::Absent);
    }

    // Fail closed on a name the guard cannot read.
    #[test]
    fn an_unreadable_name_is_refused() {
        let mut image = image_with_backing("backing.img");
        image[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(Qcow2Chain::backing_name(&image), BackingName::Escaping);

        let mut image = image_with_backing("backing.img");
        // Past the end of the input.
        image[16..20].copy_from_slice(&(1u32 << 20).to_be_bytes());
        assert_eq!(Qcow2Chain::backing_name(&image), BackingName::Escaping);

        let mut image = image_with_backing("backing.img");
        image[512] = 0xff;
        assert_eq!(Qcow2Chain::backing_name(&image), BackingName::Escaping);
    }

    // The length prefix is clamped, not refused.
    #[test]
    fn the_length_prefix_is_clamped() {
        let mut input = 4u32.to_le_bytes().to_vec();
        input.extend_from_slice(b"topsbacking");
        let (top, backing) = split(&input).expect("split");
        assert_eq!(top, b"tops");
        assert_eq!(backing, b"backing");

        let mut input = u32::MAX.to_le_bytes().to_vec();
        input.extend_from_slice(b"tops");
        let (top, backing) = split(&input).expect("split");
        assert_eq!(top, b"tops");
        assert!(backing.is_empty());

        assert!(split(b"abc").is_none());
    }

    // The guard also holds at `Qcow2Chain::open`.
    #[test]
    fn open_refuses_a_traversing_backing_name() {
        let victim = Path::new("/tmp/ch-fuzz-victim-qcow2-chain");
        let _ = fs::remove_file(victim);

        let bytes = image_with_backing("../../../../tmp/ch-fuzz-victim-qcow2-chain");
        let (file, path) = image_file(Qcow2Chain::NAME, &bytes).expect("scratch image");
        let config = OpenConfig {
            backing: true,
            ..OpenConfig::default()
        };
        let err = Qcow2Chain::open(file, Some(&path), &config)
            .err()
            .expect("a backing name escaping the scratch directory must be refused");
        assert_eq!(err.kind(), BlockErrorKind::UnsupportedFeature);
        assert!(
            !victim.exists(),
            "the harness must not have created the victim file"
        );
    }

    // A plain name must still open and read through to the backing image.
    #[test]
    fn open_accepts_a_plain_backing_name_and_reads_through_it() {
        let Some((top, backing)) = qemu_chain() else {
            eprintln!("skipping: qemu-img unavailable");
            return;
        };
        assert_eq!(
            Qcow2Chain::backing_name(&top),
            BackingName::Safe("base.qcow2".to_string()),
            "qemu-img writes the backing name as a plain relative name"
        );

        let dir = scratch_dir(Qcow2Chain::NAME).expect("scratch directory");
        Qcow2Chain::write_backing(dir, "base.qcow2", &backing).expect("backing image");
        let (file, path) = image_file(Qcow2Chain::NAME, &top).expect("scratch image");
        let config = OpenConfig {
            backing: true,
            sparse: true,
            ..OpenConfig::default()
        };
        let disk =
            Qcow2Chain::open(file, Some(&path), &config).expect("a plain backing name must open");

        // An unallocated top cluster must read the backing pattern.
        let mut io = disk.create_async_io(1).expect("async io");
        let buffer = OwnedIoBuffer::from_vec(vec![0u8; 4096]);
        io.submit_data_operation(AsyncIoOperation::read_to_vec(0, buffer, 1))
            .expect("read submitted");
        let completion = io.next_completed_request().expect("read completed");
        assert_eq!(completion.result, 4096, "the read must succeed in full");
        assert_eq!(
            completion.buffer.as_ref().expect("buffer").as_slice(),
            vec![PATTERN; 4096]
        );
    }
}
