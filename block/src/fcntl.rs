// Copyright © 2025 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

//! Helpers for advisory file locking.
//!
//! Under the hood, the implementation uses OFD locks for the entire file,
//! as described in [[0]]. The advantage over `F_SETLKW` (currently used by
//! Rust std: `File::try_lock()`) is that only the very last `close()` on a
//! file descriptor releases the lock. This prevents mistakes and unexpected
//! behavior.
//!
//! [0]: <https://apenwarr.ca/log/20101213>.

use std::fmt::Debug;
use std::io;
use std::os::fd::{AsRawFd, RawFd};

use thiserror::Error;

/// Errors that can happen when working with file locks.
#[derive(Error, Debug)]
pub enum LockError {
    /// The file is already locked.
    ///
    /// A call to [`get_lock_state`] can help to identify the reason.
    #[error("The file is already locked")]
    AlreadyLocked,
    /// IO error.
    #[error("The lock state could not be checked or set")]
    Io(#[source] io::Error),
}

/// Commands for use with [`fcntl`].
#[allow(non_camel_case_types)]
enum FcntlArg<'a> {
    /// Set an OFD lock from the given lock description.
    F_OFD_SETLK(&'a libc::flock),
    /// Get the first OFD lock for the given lock description.
    F_OFD_GETLK(&'a mut libc::flock),
}

/// Wrapper for [`libc::fcntl`] that properly sets the function arguments.
fn fcntl(fd: RawFd, arg: FcntlArg) -> libc::c_int {
    // SAFETY: We use a valid FD.
    unsafe {
        match arg {
            FcntlArg::F_OFD_SETLK(flock) => libc::fcntl(fd, libc::F_OFD_SETLK, flock),
            FcntlArg::F_OFD_GETLK(flock) => libc::fcntl(fd, libc::F_OFD_GETLK, flock),
        }
    }
}

/// Describes the type of lock you want to set.
#[derive(Clone, Copy, Debug)]
pub enum LockType {
    /// Clear a lock.
    Unlock,
    /// Set a write lock (exclusive).
    Write,
    /// Set a read lock (shared).
    Read,
}

impl LockType {
    pub const fn to_libc_val(self) -> libc::c_int {
        match self {
            Self::Unlock => libc::F_UNLCK as libc::c_int,
            Self::Write => libc::F_WRLCK as libc::c_int,
            Self::Read => libc::F_RDLCK as libc::c_int,
        }
    }
}

/// Describes the current state of a lock.
#[derive(Debug)]
pub enum LockState {
    /// No lock set.
    Unlocked,
    /// Locked for reading (non-exclusive).
    SharedRead,
    /// Locked for writing (exclusive mode).
    ExclusiveWrite,
}

impl LockState {
    fn new(value: libc::c_int) -> Self {
        const F_UNLCK: libc::c_int = libc::F_UNLCK as libc::c_int;
        const F_WRLCK: libc::c_int = libc::F_WRLCK as libc::c_int;
        const F_RDLCK: libc::c_int = libc::F_RDLCK as libc::c_int;
        match value {
            F_UNLCK => Self::Unlocked,
            F_WRLCK => Self::ExclusiveWrite,
            F_RDLCK => Self::SharedRead,
            // This is so unlikely that we want to avoid the complexity of
            // coping with this error case. Can only fail if either Linux
            // is broken or memory is messed up.
            other => panic!("Unexpected lock state: {other}"),
        }
    }
}

/// Returns a [`struct@libc::flock`] structure for the whole file.
const fn get_flock(lock_type: LockType) -> libc::flock {
    libc::flock {
        l_type: lock_type.to_libc_val() as libc::c_short,
        l_whence: libc::SEEK_SET as libc::c_short,
        l_start: 0,
        l_len: 0, /* EOF */
        l_pid: 0, /* filled by callee */
    }
}

/// Tries to acquire a lock using [`fcntl`] with respect to the given
/// parameters.
///
/// Please note that `fcntl()` OFD locks are **advisory locks**, which do not
/// prevent to `open()` a file if a lock is already placed.
///
/// # Parameters
/// - `file`: The file to acquire a lock for [`LockType`]. The file's state will
///   be logically mutated, but not technically.
/// - `lock_type`: The [`LockType`]
pub fn try_acquire_lock<Fd: AsRawFd>(file: Fd, lock_type: LockType) -> Result<(), LockError> {
    let flock = get_flock(lock_type);

    let res = fcntl(file.as_raw_fd(), FcntlArg::F_OFD_SETLK(&flock));
    match res {
        0 => Ok(()),
        -1 => {
            let io_error = io::Error::last_os_error();
            let errno = io_error.raw_os_error().unwrap();
            match errno {
                // See man page for error code:
                // <https://man7.org/linux/man-pages/man2/fcntl.2.html>
                libc::EAGAIN | libc::EACCES => Err(LockError::AlreadyLocked),
                _ => Err(LockError::Io(io_error)),
            }
        }
        val => panic!("Unexpected return value from fcntl(): {val}"),
    }
}

/// Clears a lock.
///
/// # Parameters
/// - `file`: The file to clear all locks for [`LockType`].
pub fn clear_lock<Fd: AsRawFd>(file: Fd) -> Result<(), LockError> {
    try_acquire_lock(file, LockType::Unlock)
}

/// Returns the current lock state using [`fcntl`] with respect to the given
/// parameters.
///
/// # Parameters
/// - `file`: The file for which to get the lock state.
pub fn get_lock_state<Fd: AsRawFd>(file: Fd) -> Result<LockState, LockError> {
    let mut flock = get_flock(LockType::Write);
    let res = fcntl(file.as_raw_fd(), FcntlArg::F_OFD_GETLK(&mut flock));
    match res {
        0 => {
            let state = flock.l_type as libc::c_int;
            let state = LockState::new(state);
            Ok(state)
        }
        -1 => {
            let io_error = io::Error::last_os_error();
            Err(LockError::Io(io_error))
        }
        val => panic!("Unexpected return value from fcntl(): {val}"),
    }
}
