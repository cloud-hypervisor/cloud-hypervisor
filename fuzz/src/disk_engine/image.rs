// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Backing storage for fuzzed disk images.

use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::os::unix::io::{FromRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Materializes `bytes` as an anonymous file.
///
/// A memfd keeps the image in tmpfs so a fuzz iteration never touches the
/// filesystem, and the descriptor is closed when the returned `File` drops.
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

/// Returns the per process scratch directory for path backed images.
///
/// Formats that resolve sibling files relative to the image need a real
/// directory. One is created per process and reused, so an iteration only
/// rewrites the image itself.
pub fn scratch_dir(name: &str) -> io::Result<&'static Path> {
    static DIR: OnceLock<PathBuf> = OnceLock::new();

    let dir = DIR.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("ch-fuzz-{name}-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        dir
    });
    Ok(dir.as_path())
}

/// Materializes `bytes` as a real file inside the scratch directory.
///
/// The path is stable across iterations so that a format resolving siblings
/// relative to it sees the same directory every time.
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
