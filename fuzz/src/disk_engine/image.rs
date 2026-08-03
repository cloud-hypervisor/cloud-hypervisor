// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Backing storage for fuzzed disk images.

use std::collections::HashMap;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::os::unix::io::{FromRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// Writes `bytes` to a new memfd.
pub fn image_memfd(name: &str, bytes: &[u8]) -> io::Result<File> {
    let name = CString::new(name).map_err(io::Error::other)?;
    // SAFETY: FFI call with a valid NUL terminated name and no flags.
    let fd = unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: memfd_create returned a fresh descriptor owned by nobody else.
    let mut file: File = unsafe { File::from_raw_fd(fd as RawFd) };
    file.write_all(bytes)?;
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

/// Writes `bytes` to the scratch image, at a stable path.
pub fn image_file(name: &str, bytes: &[u8]) -> io::Result<(File, PathBuf)> {
    let path = scratch_dir(name)?.join(format!("image.{name}"));
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)?;
    file.write_all(bytes)?;
    file.seek(SeekFrom::Start(0))?;
    Ok((file, path))
}

#[cfg(test)]
mod tests {
    use super::*;

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
