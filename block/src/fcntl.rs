// Copyright © 2025 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

//! Helpers for advisory file locking following best-practices described in
//! <https://apenwarr.ca/log/20101213>.

use std::convert::TryFrom;
use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;

use nix::errno::Errno;
use nix::fcntl;
use nix::fcntl::FcntlArg;

#[derive(Clone, Copy, Debug)]
pub enum LockType {
    Unlock,
    Write,
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

#[derive(Debug)]
pub enum LockState {
    /// No lock set.
    Unlocked,
    /// Locked for reading (non-exclusive).
    SharedRead,
    /// Locked for writing (exclusive mode).
    ExclusiveWrite,
}

#[derive(Debug, Copy, Clone)]
pub struct InvalidLockStateError(u32);

impl Display for InvalidLockStateError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid lock state ({})", self.0)
    }
}

impl Error for InvalidLockStateError {}

impl TryFrom<libc::c_int> for LockState {
    type Error = InvalidLockStateError;

    fn try_from(value: libc::c_int) -> Result<Self, Self::Error> {
        const F_UNLCK: libc::c_int = libc::F_UNLCK as libc::c_int;
        const F_WRLCK: libc::c_int = libc::F_WRLCK as libc::c_int;
        const F_RDLCK: libc::c_int = libc::F_RDLCK as libc::c_int;
        match value {
            F_UNLCK => Ok(Self::Unlocked),
            F_WRLCK => Ok(Self::ExclusiveWrite),
            F_RDLCK => Ok(Self::SharedRead),
            _ => Err(InvalidLockStateError(value as u32)),
        }
    }
}

impl Display for LockState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExclusiveWrite => f.write_str("Exclusive Write Lock"),
            Self::SharedRead => f.write_str("Shared Read Lock"),
            Self::Unlocked => f.write_str("Unlocked"),
        }
    }
}

#[derive(Debug)]
pub enum FileLockError {
    AlreadyLocked,
    IoError(io::Error),
}

impl Display for FileLockError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            FileLockError::AlreadyLocked => f.write_str("The file is already locked"),
            FileLockError::IoError(e) => {
                write!(f, "{e}")
            }
        }
    }
}

impl Error for FileLockError {}

#[derive(Debug)]
pub enum GetLockError {
    LockState(InvalidLockStateError),
    Io(io::Error),
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
/// Please note that `fcntl()` locks are **advisory locks**, which do not
/// prevent to `open()` a file if a lock is already placed.
///
/// # Parameters
/// - `file`: The file to acquire a lock for [`LockType`]. The files state will be
///   (although not technically) logically mutated.
/// - `lock_type`: The [`LockType`]
pub fn try_acquire_lock<Fd: std::os::fd::AsRawFd>(
    file: Fd,
    lock_type: LockType,
) -> Result<(), FileLockError> {
    let flock = get_flock(lock_type);

    let res = fcntl::fcntl(file.as_raw_fd(), FcntlArg::F_OFD_SETLK(&flock));
    match res {
        Ok(_) => Ok(()),
        // See man page for error code:
        // <https://man7.org/linux/man-pages/man2/fcntl.2.html>
        Err(Errno::EAGAIN | Errno::EACCES) => Err(FileLockError::AlreadyLocked),
        Err(_e) => Err(FileLockError::IoError(io::Error::last_os_error())),
    }
}

/// Tries to clear a lock.
///
/// # Parameters
/// - `file`: The file to clear all locks for [`LockType`].
pub fn try_clear_lock<Fd: std::os::fd::AsRawFd>(file: Fd) -> Result<(), FileLockError> {
    try_acquire_lock(file, LockType::Unlock)
}

/// Returns the current lock state using [`fcntl`] with respect to the given
/// parameters.
///
/// # Parameters
/// - `file`: The file to acquire a lock for [`LockType`]
pub fn get_lock_state(file: &File) -> Result<LockState, GetLockError> {
    let mut flock = get_flock(LockType::Write);
    let ret = fcntl::fcntl(file.as_raw_fd(), FcntlArg::F_OFD_GETLK(&mut flock))
        .map_err(|_e| GetLockError::Io(io::Error::last_os_error()))?;
    if ret != 0 {
        Err(GetLockError::Io(io::Error::last_os_error()))
    } else {
        let state = flock.l_type as libc::c_int;
        let state = LockState::try_from(state).map_err(GetLockError::LockState)?;
        Ok(state)
    }
}
