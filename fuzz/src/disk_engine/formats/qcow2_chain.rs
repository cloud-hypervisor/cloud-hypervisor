// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! QCOW2 backing chain adapter.
//!
//! # What this reaches that `disk_qcow2` cannot
//!
//! A qcow2 image may name a backing file, and everything the `block` crate
//! does with one hangs off that name: the `Raw` versus `Qcow2` dispatch and
//! the recursive open in `BackingFile::new`
//! (block/src/formats/qcow/parser.rs:174), the whole of
//! block/src/formats/qcow/backing.rs, the `MAX_NESTING_DEPTH` bound
//! (block/src/formats/qcow/util.rs:13) and the copy on write from backing arm
//! of `deallocate_bytes` (block/src/formats/qcow/metadata.rs:321). None of it
//! is reachable from `disk_qcow2`, which opens every image with
//! `backing_files: false`.
//!
//! # Why it needs its own target
//!
//! The name is a path, and the engine resolves a relative one against the
//! directory of the image that stores it and opens it without confinement.
//! Feeding it fuzzer bytes is only safe inside a sandbox, so the sandbox and
//! the two image input space live here rather than in the plain image
//! target.
//!
//! It also has to stay away from the shadow model. [`Qcow2`] declares
//! `PUNCH_HOLE_READS_ZEROES`, which is true only for an image without a
//! backing file: a discarded cluster in an image that has one reads *through*
//! to the backing data, not as zeroes, so a model that expected zeroes would
//! report data corruption that is not there. This target therefore runs the
//! fixed [`default_program`] with the model off, and
//! [`crate::disk_engine::fuzz_program`] forces backing files off, so the two
//! never meet.
//!
//! # Input encoding
//!
//! ```text
//! [u32 LE top_len][top_len bytes: the image][remaining bytes: the backing image]
//! ```
//!
//! Both halves are fuzzer controlled, which is what makes a malformed backing
//! image, and so `Qcow2Backing::read_clusters` over broken metadata,
//! reachable. `top_len` is clamped to what the input holds rather than
//! rejected: it is a harness framing field with no safety meaning, and a
//! mutation that grows it should still run.

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
///
/// Both halves are capped well below the 8 MiB default: a backing chain is
/// two images per iteration, and a qcow2 that `qemu-img` writes for a 1 MiB
/// disk is a few hundred kilobytes.
const MAX_HALF_LEN: usize = 2 << 20;

/// Name the backing image is always written under.
///
/// A seed can name it, and a mutation that destroys the name in the header
/// still leaves a file the engine can open under the name the other seeds
/// use.
const DEFAULT_BACKING_NAME: &str = "backing.img";

/// Name of the fixed, empty raw file the harness also provides.
///
/// An input carries two images, so a chain built only out of them closes on
/// itself: whatever the second image names is a file the harness wrote the
/// second image to, and the engine then recurses until `MAX_NESTING_DEPTH`
/// refuses the open, which means a three deep chain never reads anything. A
/// fixed raw file terminates one, because any file is a valid raw backing, so
/// a middle image that names it makes the nested `ClusterReadMapping::Backing`
/// arm of `Qcow2Backing::read_clusters` reachable.
const LEAF_NAME: &str = "leaf.raw";

/// Size of that file.
const LEAF_LEN: u64 = 1 << 20;

/// Longest backing name the harness will materialize.
///
/// `MAX_BACKING_FILE_SIZE` in the parser is 1023 bytes, but a file name is
/// bounded by `NAME_MAX`, and a longer one could only ever fail at `open`.
const MAX_NAME_LEN: usize = 255;

/// What the harness makes of the backing name in an image header.
#[derive(Debug, Eq, PartialEq)]
pub enum BackingName {
    /// The image provably names no backing file, so nothing is opened.
    Absent,
    /// The image names a plain file, which the harness materializes in the
    /// scratch directory.
    Safe(String),
    /// The image names something the harness will not resolve.
    Escaping,
}

/// QCOW2 images opened with backing files enabled.
pub struct Qcow2Chain;

impl Qcow2Chain {
    /// Reads the backing file name out of a qcow2 header and classifies it.
    ///
    /// The harness has to parse this itself, out of the raw input bytes,
    /// because the decision has to be made *before* the `block` crate opens
    /// anything: by the time `BackingFile::new` runs, the file is already
    /// open. The two fields are the ones `QcowHeader::new` reads,
    /// `backing_file_offset` as a big endian `u64` at bytes 8..16 and
    /// `backing_file_size` as a big endian `u32` at bytes 16..20
    /// (block/src/formats/qcow/header.rs:217), and the name is that many
    /// bytes at that offset (block/src/formats/qcow/header.rs:467).
    ///
    /// The classification fails closed. [`BackingName::Absent`] is returned
    /// only when the header provably opens nothing: a zero offset or a zero
    /// size, either of which `QcowHeader::new` turns into an error or into no
    /// backing file at all. Everything the harness cannot read and check as a
    /// single plain file name, including a name that runs past the end of the
    /// input or is not UTF-8, is [`BackingName::Escaping`] and the input is
    /// refused, even where the parser would have rejected it anyway.
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

    /// Whether `name` is a single plain file name inside the scratch
    /// directory.
    ///
    /// The engine joins a relative backing name onto the directory of the
    /// image that stores it (block/src/formats/qcow/parser.rs:317) with
    /// `Path::join` and no normalisation, so `..` walks straight out of the
    /// scratch directory and an absolute name replaces it outright. Only a
    /// name that is exactly one [`Component::Normal`] is allowed: that turns
    /// away absolute paths, root and prefix components, `..`, `.`, the empty
    /// name and, unlike the VMDK guard, subdirectories too, since the harness
    /// creates none. An embedded NUL is refused as well, so that what the
    /// harness checked and what the engine passes to `open` cannot differ.
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

    /// Removes every file left in the scratch directory.
    ///
    /// An iteration may create a file under any plain name the input asks
    /// for, so without this the directory grows without bound and, worse, an
    /// input could open a backing image a previous input created, which would
    /// make a crash depend on the run rather than on the input.
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

    /// Creates the fixed raw file that terminates a chain, see [`LEAF_NAME`].
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

    // The backing name is resolved against the directory of the image that
    // stores it, through /proc/self/fd (block/src/formats/qcow/parser.rs:319),
    // so the image cannot be a memfd: that readlink names a deleted
    // /memfd:... path and the name would be resolved against the working
    // directory instead.
    const NEEDS_PATH: bool = true;

    const MAX_IMAGE_LEN: usize = MAX_HALF_LEN;

    // Inherited from the plain qcow2 adapter, which documents both.
    const NO_SHORT_READS: bool = Qcow2::NO_SHORT_READS;

    // Deliberately *not* inherited: with a backing file a discarded cluster
    // reads through to the backing data rather than as zeroes. The default of
    // false is the only sound value here, and this target runs without a
    // shadow model anyway.
    const PUNCH_HOLE_READS_ZEROES: bool = false;

    fn magic_ok(bytes: &[u8]) -> bool {
        Qcow2::magic_ok(bytes)
    }

    fn open(
        file: File,
        path: Option<&Path>,
        config: &OpenConfig,
    ) -> BlockResult<Box<dyn AsyncFullDiskFile>> {
        // The guard is repeated at the open, not only where the input is
        // split, so that no future caller can reach `QcowDisk::new` with
        // backing files enabled and an unchecked name.
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
///
/// Returns `None` only for an input too short to carry the length prefix.
fn split(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = bytes.split_at_checked(4)?;
    let top_len = u32::from_le_bytes(len.try_into().expect("4 bytes")) as usize;
    Some(rest.split_at(top_len.min(rest.len())))
}

/// Fuzzes the qcow2 backing chain code with a fuzzer built chain.
///
/// The sandbox comes first: the harness name guard is the only thing between
/// a corpus entry and an arbitrary host path, so the target refuses to run at
/// all when the process cannot be confined as well.
pub fn fuzz_chain(bytes: &[u8]) -> Corpus {
    let Ok(dir) = scratch_dir(Qcow2Chain::NAME) else {
        return Corpus::Reject;
    };
    if !sandbox::confine(dir, sandbox::Directories::ScratchOnly) {
        return Corpus::Reject;
    }

    let Some((top, backing)) = split(bytes) else {
        return Corpus::Reject;
    };
    if top.len() > MAX_HALF_LEN || backing.len() > MAX_HALF_LEN {
        return Corpus::Reject;
    }
    // The rejection paths in front of the backing code are `disk_qcow2`'s
    // job; an input that cannot open is worth nothing here.
    if !Qcow2Chain::magic_ok(top) {
        return Corpus::Reject;
    }

    // Both images are checked: the backing image's own header can name a
    // further backing file, and that is exactly the nested chain this target
    // is here to reach, so its name is as untrusted as the top one's.
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
    // The backing bytes are written under every name the chain asks for, so
    // a mutation of the name field still opens something, and a chain that
    // names itself recurses until `MAX_NESTING_DEPTH` stops it. The top image
    // is written last, so a name that collides with it still ends up holding
    // the top image and the chain closes on itself rather than on stale
    // bytes.
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
        // Sparse ops are what reach the copy on write from backing arm of
        // `deallocate_bytes` (block/src/formats/qcow/metadata.rs:321).
        sparse: true,
        ..OpenConfig::default()
    };
    let Ok(disk) = Qcow2Chain::open(file, Some(&path), &config) else {
        return Corpus::Keep;
    };

    // No shadow model: the image contents are unknown, and punch hole over a
    // backing file does not read back as zeroes.
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

    /// Builds a real two image chain with `qemu-img`, the top image naming
    /// the base by a plain relative name, and returns their bytes.
    ///
    /// The base holds a known pattern so that a read served through the
    /// chain can be told from a read of a hole.
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

    /// Builds a minimal v3 header carrying `name` as its backing file name.
    ///
    /// Only the fields the guard reads have to be right; the rest is what
    /// `QcowHeader::new` needs to get that far.
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

    // The engine joins a relative name onto the image's own directory with
    // no normalisation and then opens it, so a name that escapes must never
    // get that far.
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

    // A header that opens no backing file at all must not be confused with
    // one that names something unreadable: the first is normal, the second
    // is refused.
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

    // Fail closed: a name the harness cannot read out of the input is
    // refused rather than assumed harmless.
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

    // The framing field is clamped, not refused: it carries no safety
    // meaning and a mutation that grows it should still run.
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

    // The guard has to hold at the entry point the engine is reached
    // through, not only in isolation.
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

    // The other half of the guard: a legitimate relative name must still
    // open, and the data must actually come from the backing image, or the
    // target would only be proving that it can refuse things.
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

        // An unallocated cluster of the top image has to come back as the
        // backing pattern rather than as zeroes, or the chain was not
        // followed and the target would only be proving that it can refuse
        // things.
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
