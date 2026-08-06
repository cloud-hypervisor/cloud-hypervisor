// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Backing storage for fuzzed disk images.

use std::collections::HashMap;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::os::unix::io::{FromRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

/// Creates an empty anonymous file.
fn memfd(name: &str) -> io::Result<File> {
    let name = CString::new(name).map_err(io::Error::other)?;
    // SAFETY: FFI call with a valid NUL terminated name and no flags.
    let fd = unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: memfd_create returned a fresh descriptor owned by nobody else.
    Ok(unsafe { File::from_raw_fd(fd as RawFd) })
}

/// Writes `bytes` to a new memfd.
pub fn image_memfd(name: &str, bytes: &[u8]) -> io::Result<File> {
    let mut file = memfd(name)?;
    file.write_all(bytes)?;
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

/// Page granularity at which template zeroes are skipped.
const SPARSE_PAGE: usize = 4096;

/// Indices of the non-zero pages of a template, computed once per buffer.
/// Keyed by address and length, since a format may have several templates.
fn template_pages(bytes: &'static [u8]) -> Arc<Vec<usize>> {
    /// Page maps keyed by template address and length.
    type PageMaps = HashMap<(usize, usize), Arc<Vec<usize>>>;

    static CACHE: Mutex<Option<PageMaps>> = Mutex::new(None);

    let key = (bytes.as_ptr() as usize, bytes.len());
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let cache = guard.get_or_insert_with(PageMaps::new);
    Arc::clone(cache.entry(key).or_insert_with(|| {
        Arc::new(
            bytes
                .chunks(SPARSE_PAGE)
                .enumerate()
                .filter(|(_, page)| page.iter().any(|byte| *byte != 0))
                .map(|(index, _)| index)
                .collect(),
        )
    }))
}

/// Writes `pages` of `bytes` into an empty `file`, leaving holes elsewhere.
fn write_template(file: &File, bytes: &[u8], pages: &[usize]) -> io::Result<()> {
    file.set_len(bytes.len() as u64)?;
    for index in pages {
        let start = index * SPARSE_PAGE;
        let end = (start + SPARSE_PAGE).min(bytes.len());
        file.write_all_at(&bytes[start..end], start as u64)?;
    }
    Ok(())
}

/// Writes a template to a new memfd, skipping its zero pages.
pub fn template_memfd(name: &str, bytes: &'static [u8]) -> io::Result<File> {
    let pages = template_pages(bytes);
    let mut file = memfd(name)?;
    write_template(&file, bytes, &pages)?;
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

/// The per-process scratch directories, removed at exit.
static SCRATCH: OnceLock<Mutex<HashMap<String, &'static Path>>> = OnceLock::new();
static SCRATCH_CLEANUP_REGISTERED: OnceLock<()> = OnceLock::new();

/// Removes the scratch directories. A confined process empties them, but can
/// only remove the directories themselves if it may write to `TMPDIR`.
extern "C" fn remove_scratch_dir() {
    if let Some(dirs) = SCRATCH.get() {
        let dirs = dirs.lock().unwrap_or_else(|e| e.into_inner());
        for dir in dirs.values() {
            let _ = fs::remove_dir_all(dir);
        }
    }
}

/// The per-process scratch directory for path backed images.
pub fn scratch_dir(name: &str) -> io::Result<&'static Path> {
    let scratch = SCRATCH.get_or_init(|| Mutex::new(HashMap::new()));
    let mut dirs = scratch.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(dir) = dirs.get(name) {
        return Ok(dir);
    }

    let dir = std::env::temp_dir().join(format!("ch-fuzz-{name}-{}", std::process::id()));
    fs::create_dir_all(&dir)?;
    let dir: &'static Path = Box::leak(dir.into_boxed_path());
    dirs.insert(name.to_owned(), dir);
    SCRATCH_CLEANUP_REGISTERED.get_or_init(|| {
        // SAFETY: FFI call registering a handler that only reads statics.
        unsafe { libc::atexit(remove_scratch_dir) };
    });
    Ok(dir)
}

/// Opens the scratch image for `name`, emptied.
fn scratch_image(name: &str) -> io::Result<(File, PathBuf)> {
    let path = scratch_dir(name)?.join(format!("image.{name}"));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)?;
    Ok((file, path))
}

/// Writes `bytes` to the scratch image, at a stable path.
pub fn image_file(name: &str, bytes: &[u8]) -> io::Result<(File, PathBuf)> {
    let (mut file, path) = scratch_image(name)?;
    file.write_all(bytes)?;
    file.seek(SeekFrom::Start(0))?;
    Ok((file, path))
}

/// Writes a template to the scratch image, skipping its zero pages.
pub fn template_file(name: &str, bytes: &'static [u8]) -> io::Result<(File, PathBuf)> {
    let pages = template_pages(bytes);
    let (mut file, path) = scratch_image(name)?;
    // Unwritten pages of the truncated file read back as zeroes.
    write_template(&file, bytes, &pages)?;
    file.seek(SeekFrom::Start(0))?;
    Ok((file, path))
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;

    // A sparsely written template must equal its buffer.
    #[test]
    fn template_materialization_reproduces_the_buffer() {
        let mut bytes = vec![0u8; 3 * SPARSE_PAGE + 17];
        bytes[0] = 0xff;
        bytes[SPARSE_PAGE - 1] = 0x01;
        // Page 2 stays zero and is never written.
        bytes[2 * SPARSE_PAGE + 5] = 0xaa;
        bytes[3 * SPARSE_PAGE + 16] = 0x5a;
        // Templates are 'static.
        let bytes: &'static [u8] = Box::leak(bytes.into_boxed_slice());

        // The second round uses the cached page map.
        for round in 0..2 {
            let mut file = template_memfd("sparse-test", bytes).expect("memfd");
            let mut read_back = Vec::new();
            file.read_to_end(&mut read_back).expect("read back");
            assert_eq!(read_back, bytes, "round {round}");
        }
        assert_eq!(*template_pages(bytes), vec![0, 2, 3]);

        // Empty and all-zero buffers.
        for len in [0usize, 1, SPARSE_PAGE, SPARSE_PAGE + 1] {
            let zeroes: &'static [u8] = Box::leak(vec![0u8; len].into_boxed_slice());
            let mut file = template_memfd("zero-test", zeroes).expect("memfd");
            let mut read_back = Vec::new();
            file.read_to_end(&mut read_back).expect("read back");
            assert_eq!(read_back, zeroes, "{len} zero bytes");
        }
    }

    // Two templates of one format must not share a page map.
    #[test]
    fn two_templates_of_one_format_do_not_share_a_page_map() {
        let mut large = vec![0u8; 32 * SPARSE_PAGE];
        large[0] = 0x1;
        large[31 * SPARSE_PAGE] = 0x2;
        let large: &'static [u8] = Box::leak(large.into_boxed_slice());

        let mut small = vec![0u8; 2560];
        small[7] = 0x3;
        let small: &'static [u8] = Box::leak(small.into_boxed_slice());

        // Both orders, twice each, to cover the uncached and cached paths.
        for round in 0..2 {
            for (which, bytes) in [("large", large), ("small", small)] {
                let mut file = template_memfd("variant-test", bytes).expect("memfd");
                let mut read_back = Vec::new();
                file.read_to_end(&mut read_back).expect("read back");
                assert_eq!(read_back.len(), bytes.len(), "{which}, round {round}");
                assert_eq!(read_back, bytes, "{which}, round {round}");
            }
        }

        // Each map is distinct and cached.
        assert_eq!(*template_pages(large), vec![0, 31]);
        assert_eq!(*template_pages(small), vec![0]);
        assert!(Arc::ptr_eq(&template_pages(large), &template_pages(large)));
        assert!(Arc::ptr_eq(&template_pages(small), &template_pages(small)));
        assert!(!Arc::ptr_eq(&template_pages(large), &template_pages(small)));
    }

    // Rewriting a shorter image must not leave the old tail behind.
    #[test]
    fn a_rewritten_scratch_image_keeps_no_tail() {
        let long = vec![0xa5u8; 2 * SPARSE_PAGE];
        let (_file, path) = image_file("sparse-file-test", &long).expect("scratch image");
        assert_eq!(
            fs::metadata(&path).expect("metadata").len(),
            long.len() as u64
        );

        let short = vec![0u8; 8];
        let (_file, path) = image_file("sparse-file-test", &short).expect("scratch image");
        assert_eq!(fs::read(&path).expect("read back"), short);
    }

    #[test]
    fn scratch_dir_surfaces_creation_failure_and_allows_retry() {
        let name = format!("creation-failure-retry-{}", std::process::id());
        let path = std::env::temp_dir().join(format!("ch-fuzz-{name}-{}", std::process::id()));
        let _blocker = File::create(&path).expect("create scratch directory blocker");

        let error = scratch_dir(&name).expect_err("a file must block directory creation");
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        fs::remove_file(&path).expect("remove scratch directory blocker");

        let dir = scratch_dir(&name).expect("retry scratch directory creation");
        assert!(dir.is_dir());
        fs::remove_dir_all(dir).expect("remove test scratch directory");
    }

    #[test]
    fn scratch_dirs_are_isolated_by_name() {
        let first_name = format!("format-isolation-first-{}", std::process::id());
        let second_name = format!("format-isolation-second-{}", std::process::id());
        let first = scratch_dir(&first_name).expect("first scratch directory");
        let second = scratch_dir(&second_name).expect("second scratch directory");

        assert_ne!(first, second);
        assert_eq!(
            scratch_dir(&first_name).expect("repeated first lookup"),
            first
        );
        assert_eq!(
            scratch_dir(&second_name).expect("repeated second lookup"),
            second
        );
        assert!(first.to_string_lossy().contains(&first_name));
        assert!(second.to_string_lossy().contains(&second_name));

        fs::remove_dir_all(first).expect("remove first test scratch directory");
        fs::remove_dir_all(second).expect("remove second test scratch directory");
    }
}
