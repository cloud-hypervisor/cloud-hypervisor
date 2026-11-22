// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;

use crate::vm_config::CpusConfig;

pub(crate) fn open_cgroup_threads(cpus: &CpusConfig) -> io::Result<Option<File>> {
    let cgroup = if let Some(path) = &cpus.cgroup {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH)
            .open(path)?;
        if !file.metadata()?.is_dir() {
            return OpenOptions::new().write(true).open(path).map(Some);
        }
        file
    } else {
        return Ok(None);
    };

    // SAFETY: `cgroup` is an open descriptor, the path is NUL-terminated and
    // the return value is checked.
    let fd = unsafe {
        libc::openat(
            cgroup.as_raw_fd(),
            c"cgroup.threads".as_ptr(),
            libc::O_WRONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `openat` returned a new descriptor that nothing else owns.
    Ok(Some(File::from(unsafe { OwnedFd::from_raw_fd(fd) })))
}

pub(crate) fn join_cgroup(mut cgroup_threads: &File) -> io::Result<()> {
    // The kernel reads "0" as the TID of the writing thread.
    cgroup_threads.write_all(b"0")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;

    use super::*;

    #[test]
    fn test_open_cgroup_threads() {
        assert!(
            open_cgroup_threads(&CpusConfig::default())
                .unwrap()
                .is_none()
        );

        let cgroup = tempfile::tempdir().unwrap();
        let threads = cgroup.path().join("cgroup.threads");
        fs::write(&threads, "").unwrap();
        let read_back = || fs::read_to_string(&threads).unwrap();

        let by_path = CpusConfig {
            cgroup: Some(cgroup.path().to_owned()),
            ..Default::default()
        };
        let file = open_cgroup_threads(&by_path).unwrap().unwrap();
        join_cgroup(&file).unwrap();
        assert_eq!(read_back(), "0");

        let links = tempfile::tempdir().unwrap();
        let link = links.path().join("vcpu-threads");
        symlink(&threads, &link).unwrap();
        for path in [threads.clone(), link] {
            let by_file_path = CpusConfig {
                cgroup: Some(path),
                ..Default::default()
            };
            fs::write(&threads, "").unwrap();
            let file = open_cgroup_threads(&by_file_path).unwrap().unwrap();
            join_cgroup(&file).unwrap();
            assert_eq!(read_back(), "0");
        }

        let missing = CpusConfig {
            cgroup: Some(cgroup.path().join("missing")),
            ..Default::default()
        };
        assert_eq!(
            open_cgroup_threads(&missing).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }
}
