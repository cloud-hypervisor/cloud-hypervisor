// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

//! Unix sockets bound under an exclusive lock on their path.
//!
//! A socket file outlives the process that bound it, so a run that crashed
//! leaves it behind and the next start fails with EADDRINUSE. Removing the
//! leftover unconditionally would clobber a socket bound by a live instance,
//! so it is removed while holding a lock on a sidecar "<socket>.lock" file.

use std::fs::{File, OpenOptions};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::{fs, io};

use block::fcntl::{LockError, LockGranularity, LockType, try_acquire_lock};
use thiserror::Error;

/// Errors associated with locked Unix sockets
#[derive(Debug, Error)]
pub(crate) enum LockedUnixListenerError {
    /// The socket is already in use by another running instance
    #[error("Socket {0:?} is already in use by another running instance")]
    InUse(PathBuf),

    /// Error creating socket
    #[error("Error creating socket")]
    Io(#[source] io::Error),
}

struct SocketLock {
    _file: File,
    path: PathBuf,
}

impl SocketLock {
    fn acquire(socket_path: &Path) -> Result<Self, LockedUnixListenerError> {
        let mut path = socket_path.to_path_buf().into_os_string();
        path.push(".lock");
        let path = PathBuf::from(path);
        // Retry, as the previous owner may unlink the file between open() and lock.
        loop {
            let file = OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(&path)
                .map_err(LockedUnixListenerError::Io)?;

            match try_acquire_lock(&file, LockType::Write, LockGranularity::WholeFile) {
                Ok(()) => {}
                Err(LockError::AlreadyLocked) => {
                    return Err(LockedUnixListenerError::InUse(socket_path.to_path_buf()));
                }
                Err(LockError::Io(e)) => return Err(LockedUnixListenerError::Io(e)),
            }

            // A lock on a file that was unlinked meanwhile guards nothing.
            let locked = file.metadata().map_err(LockedUnixListenerError::Io)?;
            match fs::metadata(&path) {
                Ok(current) if current.dev() == locked.dev() && current.ino() == locked.ino() => {
                    return Ok(Self { _file: file, path });
                }
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(LockedUnixListenerError::Io(e)),
            }
        }
    }
}

impl Drop for SocketLock {
    fn drop(&mut self) {
        fs::remove_file(&self.path).ok();
    }
}

/// A bound Unix socket together with the lock guarding its path.
///
/// The lock is held for as long as the socket is bound and released by the
/// kernel when the process exits, including on a crash.
pub struct LockedUnixListener {
    listener: UnixListener,
    _lock: SocketLock,
    path: PathBuf,
}

impl LockedUnixListener {
    /// Binds the socket, removing a stale one left behind by a crashed run.
    ///
    /// Fails with [`LockedUnixListenerError::InUse`] if another instance is bound to this
    /// path.
    pub(crate) fn bind(socket_path: &Path) -> Result<Self, LockedUnixListenerError> {
        let lock = SocketLock::acquire(socket_path)?;
        // We hold the lock, so a socket here is stale from a crash; remove it
        // (only an actual socket, not another file at this path). metadata()
        // rather than symlink_metadata() to avoid lstat(), which the vmm
        // thread's seccomp filter does not allow.
        if fs::metadata(socket_path).is_ok_and(|m| m.file_type().is_socket()) {
            fs::remove_file(socket_path).map_err(LockedUnixListenerError::Io)?;
        }

        let listener = UnixListener::bind(socket_path).map_err(LockedUnixListenerError::Io)?;

        Ok(Self {
            listener,
            _lock: lock,
            path: socket_path.to_path_buf(),
        })
    }

    pub(crate) fn listener(&self) -> &UnixListener {
        &self.listener
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl AsFd for LockedUnixListener {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.listener.as_fd()
    }
}

impl AsRawFd for LockedUnixListener {
    fn as_raw_fd(&self) -> RawFd {
        self.listener.as_raw_fd()
    }
}

impl Drop for LockedUnixListener {
    fn drop(&mut self) {
        // `self._lock` is still held while this runs, so it cannot unlink a
        // socket bound by another instance.
        fs::remove_file(&self.path).ok();
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixStream;
    use std::thread;

    use vmm_sys_util::tempdir::TempDir;

    use super::*;

    #[test]
    fn test_stale_socket_is_replaced() {
        let tmp_dir = TempDir::new_with_prefix("/tmp/locked-socket").unwrap();
        let path = tmp_dir.as_path().join("test.sock");

        // Leave a socket behind on the path, as a crashed instance would.
        {
            let _listener = UnixListener::bind(&path).unwrap();
        }
        assert_eq!(
            UnixListener::bind(&path).unwrap_err().kind(),
            io::ErrorKind::AddrInUse
        );

        // Nobody holds the lock, so the stale socket is removed before bind.
        LockedUnixListener::bind(&path).unwrap();
    }

    #[test]
    fn test_socket_in_use_is_protected() {
        let tmp_dir = TempDir::new_with_prefix("/tmp/locked-socket").unwrap();
        let path = tmp_dir.as_path().join("test.sock");

        {
            let _socket = LockedUnixListener::bind(&path).unwrap();
            assert!(matches!(
                LockedUnixListener::bind(&path),
                Err(LockedUnixListenerError::InUse(p)) if p == path
            ));
        }

        // The guard has been dropped, so the path can be taken again.
        LockedUnixListener::bind(&path).unwrap();
    }

    #[test]
    fn test_lock_is_not_held_on_an_unlinked_lock_file() {
        let tmp_dir = TempDir::new_with_prefix("/tmp/locked-socket").unwrap();
        let path = tmp_dir.as_path().join("test.sock");

        // The lock file is unlinked on release, racing with the other open.
        let contend = || {
            for _ in 0..20_000 {
                if let Ok(lock) = SocketLock::acquire(&path) {
                    let locked = lock._file.metadata().unwrap();
                    let current = fs::metadata(&lock.path).unwrap();
                    assert_eq!((locked.dev(), locked.ino()), (current.dev(), current.ino()));
                }
            }
        };
        thread::scope(|s| {
            s.spawn(contend);
            s.spawn(contend);
        });
    }

    #[test]
    fn test_drop_unlinks_the_socket_and_lock() {
        let tmp_dir = TempDir::new_with_prefix("/tmp/locked-socket").unwrap();
        let path = tmp_dir.as_path().join("test.sock");
        let mut lock_path = path.clone().into_os_string();
        lock_path.push(".lock");
        let lock_path = PathBuf::from(lock_path);

        {
            let _socket = LockedUnixListener::bind(&path).unwrap();
            assert!(path.exists());
            assert!(lock_path.exists());
        }
        assert!(!path.exists());
        assert!(!lock_path.exists());
    }

    #[test]
    fn test_failed_bind_unlinks_the_lock() {
        let tmp_dir = TempDir::new_with_prefix("/tmp/locked-socket").unwrap();
        let path = tmp_dir.as_path().join("test.sock");
        let mut lock_path = path.clone().into_os_string();
        lock_path.push(".lock");
        let lock_path = PathBuf::from(lock_path);
        fs::write(&path, "not a socket").unwrap();

        assert!(LockedUnixListener::bind(&path).is_err());
        assert!(!lock_path.exists());
    }

    #[test]
    fn test_cloned_fd_shares_the_socket() {
        let tmp_dir = TempDir::new_with_prefix("/tmp/locked-socket").unwrap();
        let path = tmp_dir.as_path().join("test.sock");

        let socket = LockedUnixListener::bind(&path).unwrap();
        // A dup of the listener accepts connections to the same socket, while
        // the guard keeps ownership of the original fd.
        let cloned = UnixListener::from(socket.as_fd().try_clone_to_owned().unwrap());
        let _client = UnixStream::connect(&path).unwrap();
        cloned.accept().unwrap();
    }
}
