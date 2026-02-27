// Copyright © 2026 Demi Marie Obenour <demiobenour@gmail.com>
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::fs::File;
use std::io::ErrorKind;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};

use rustix::fs::{Mode, OFlags, ResolveFlags};
use thiserror::Error;
use vmm_sys_util::eventfd::EventFd;

/// Errors that can occur when checking if a file descriptor is an eventfd.
#[derive(Debug, Error)]
pub enum Error {
    /// The given file descriptor is not an eventfd
    #[error("The given file descriptor is not an EventFD")]
    NotEventFd,
    /// General I/O error occurred.
    #[error("General I/O error")]
    IO(#[source] std::io::Error),
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::IO(value)
    }
}

/// A wrapper around the root of a procfs.
#[derive(Debug)]
pub struct ProcRoot {
    root_fd: OwnedFd,
}

/// A struct that allows checking if a provided file descriptor is an eventfd.
///
/// It is better to reuse this struct many times, rather than to create one for
/// each [`Self::check_is_eventfd`] call.
#[derive(Debug)]
pub struct EventfdChecker {
    root: ProcRoot,
    st_dev: u64,
    is_anon_inode: bool,
}

/// Get a [`BorrowedFd`] out of an [`EventFd`].
/// The returned [`BorrowedFd`] will live for just as long as the
/// [`EventFd`].
pub fn borrow_eventfd<'a>(eventfd: &'a EventFd) -> BorrowedFd<'a> {
    // SAFETY: event_fd.as_raw_fd() returns valid FD,
    // which stays open until it is dropped.
    unsafe { BorrowedFd::borrow_raw(eventfd.as_raw_fd()) }
}

/// Convert an [`EventFd`] to an [`OwnedFd`].
pub fn unwrap_eventfd(eventfd: EventFd) -> OwnedFd {
    let fd = eventfd.as_raw_fd();
    core::mem::forget(eventfd);
    // SAFETY: event_fd.as_raw_fd() returns valid FD,
    // and we just forgot the eventfd so its destructor won't get called.
    unsafe { OwnedFd::from_raw_fd(fd) }
}

impl AsFd for ProcRoot {
    /// Obtains a file descriptor guaranteed to point to the root directory
    /// of a procfs.
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.root_fd.as_fd()
    }
}

impl AsRawFd for ProcRoot {
    /// Obtains a file descriptor guaranteed to point to the root directory
    /// of a procfs.
    fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
        self.root_fd.as_raw_fd()
    }
}

impl TryFrom<OwnedFd> for ProcRoot {
    type Error = std::io::Error;

    // whether dev_t converting to u64 is useless might be platform-dependent
    #[allow(clippy::useless_conversion)]
    fn try_from(root_fd: OwnedFd) -> Result<Self, Self::Error> {
        let statfs_res = rustix::fs::fstatfs(root_fd.as_fd())?;
        if statfs_res.f_type != libc::PROC_SUPER_MAGIC {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "File descriptor doesn't refer to a procfs file",
            ));
        }
        let stat_res = rustix::fs::fstat(root_fd.as_fd())?;
        if stat_res.st_ino != 1 {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "File descriptor doesn't refer to a procfs root directory",
            ));
        }
        Ok(Self { root_fd })
    }
}

impl ProcRoot {
    /// Open the root of /proc and check that it is in fact
    /// the root of a procfs.
    pub fn new() -> std::io::Result<Self> {
        Self::try_from(OwnedFd::from(File::open("/proc")?))
    }
}

impl EventfdChecker {
    /// Create an [`EventfdChecker`].
    pub fn new() -> std::io::Result<Self> {
        Self::from_proc_root(ProcRoot::new()?)
    }

    /// Create an [`EventfdChecker`] from a [`ProcRoot`].
    // whether converting pid_t to c_long is useless is platform-dependent
    #[allow(clippy::useless_conversion)]
    pub fn from_proc_root(root: ProcRoot) -> std::io::Result<Self> {
        let event_fd = EventFd::new(libc::EFD_CLOEXEC)?;
        let event_fd = borrow_eventfd(&event_fd);
        let stat_info = rustix::fs::fstat(event_fd)?;
        let statfs_info = rustix::fs::fstatfs(event_fd)?;

        Ok(Self {
            root,
            st_dev: stat_info.st_dev.into(),
            // 0x09041934 is ANON_INODE_FS_MAGIC
            is_anon_inode: statfs_info.f_type == 0x09041934,
        })
    }

    pub fn root(&self) -> &ProcRoot {
        &self.root
    }

    /// Returns whether the provided file descriptor is an eventfd.
    ///
    /// This uses a two-step approach:
    ///
    /// 1. It checks if the file has the same st_dev as a known eventfd.
    /// 2. If eventfds are anonymous inodes (as they currently are),
    ///    checks that readlink on /proc/thread-self/fd/FD_NUM returns
    ///    "anon_inode:[eventfd]".  This check is conditional because
    ///    Linux does not guarantee that eventfds will always be anonymous
    ///    inodes.  Pidfds used to be anonymous inodes but no longer are.
    ///
    /// # Errors
    ///
    /// Returns an error if an I/O error occurs.
    pub fn check_is_eventfd(&self, fd: BorrowedFd) -> Result<bool, std::io::Error> {
        let stat_info = rustix::fs::fstat(fd).unwrap();
        if stat_info.st_dev != self.st_dev {
            return Ok(false);
        }
        Ok(!self.is_anon_inode || {
            let path = format!("thread-self/fd/{}", fd.as_raw_fd());
            let child_fd = rustix::fs::openat2(
                self.root.root_fd.as_fd(),
                path,
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
                // thread-self is a symlink, but only points down, not up.
                // Detect if anything is mounted over something that would
                // be crossed and fail if so.
                ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_XDEV | ResolveFlags::BENEATH,
            )
            .unwrap();
            let link_res = rustix::fs::readlinkat(child_fd.as_fd(), "", vec![]).unwrap();
            &*link_res == c"anon_inode:[eventfd]"
        })
    }

    /// Check if the provided file descriptor is an eventfd.
    ///
    /// If it is, wraps it in an [`EventFd`] and returns Ok.
    ///
    /// # Errors
    ///
    /// Returns an error if the file descriptor is not an EventFd, or if an I/O
    /// error is returned. The error includes the original FD unchanged.
    pub fn convert_to_eventfd(&self, fd: OwnedFd) -> Result<EventFd, (OwnedFd, Error)> {
        match self.check_is_eventfd(fd.as_fd()) {
            Ok(true) => Ok(
                // SAFETY: self.check_is_eventfd() checked that this is in fact an eventfd,
                // and fd.into_raw_fd() always produces a valid open file descriptor.
                unsafe { EventFd::from_raw_fd(fd.into_raw_fd()) },
            ),
            Ok(false) => Err((fd, Error::NotEventFd)),
            Err(e) => Err((fd, Error::IO(e))),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use super::*;

    #[test]
    fn timerfd_not_eventfd() {
        // SAFETY: FFI call with correct arguments
        let timer_fd = unsafe { libc::timerfd_create(libc::CLOCK_REALTIME, libc::TFD_CLOEXEC) };
        assert!(timer_fd >= 0);
        // SAFETY: timer_fd was checked to not be -1 and otherwise timerfd_create returns valid FD.
        let timer_fd = unsafe { OwnedFd::from_raw_fd(timer_fd) };
        check_not_eventfd(timer_fd);
    }

    fn check_not_eventfd(fd: OwnedFd) {
        let p = EventfdChecker::new().unwrap();
        let fd_num = fd.as_raw_fd();
        assert!(
            !p.check_is_eventfd(fd.as_fd()).unwrap(),
            "Non-eventfd found to be eventfd"
        );
        match p.convert_to_eventfd(fd) {
            Ok(_) => panic!("Non-eventfd found to be eventfd"),
            Err((orig_fd, Error::NotEventFd)) => assert_eq!(orig_fd.as_raw_fd(), fd_num),
            Err((_, Error::IO(e))) => panic!("I/O error {e}"),
        }
    }

    #[test]
    // whether converting pid_t to c_long is useless is platform-dependent
    #[allow(clippy::useless_conversion)]
    fn pidfd_not_eventfd() {
        // SAFETY: FFI call with valid arguments and valid argument types.
        let pidfd =
            unsafe { libc::syscall(libc::SYS_pidfd_open, libc::c_long::from(libc::getpid()), 0) };
        assert!(pidfd >= 0);
        // SAFETY: pidfd is a valid FD, as shown by it being >= 0 and the return value
        // of a syscall that returns a valid pidfd or negative number
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd.try_into().unwrap()) };
        check_not_eventfd(pidfd);
    }

    #[test]
    fn dev_null_not_eventfd() {
        let null_fd = File::open("/dev/null").unwrap().into();
        check_not_eventfd(null_fd);
    }

    #[test]
    fn dir_not_eventfd() {
        let dev_fd = File::open("/dev").unwrap().into();
        check_not_eventfd(dev_fd);
    }

    #[test]
    fn proc_self_not_eventfd() {
        let dev_fd = File::open("/proc/self/exe").unwrap().into();
        check_not_eventfd(dev_fd);
    }

    #[test]
    fn dev_null_not_proc_root() {
        ProcRoot::try_from(OwnedFd::from(File::open("/dev/null").unwrap())).unwrap_err();
    }

    #[test]
    fn proc_self_not_proc_root() {
        ProcRoot::try_from(OwnedFd::from(File::open("/proc/self").unwrap())).unwrap_err();
    }

    #[test]
    fn eventfd_is_eventfd() {
        let p = EventfdChecker::new().unwrap();
        let eventfd = EventFd::new(0).unwrap();
        let raw_fd_num = eventfd.as_raw_fd();
        assert_eq!(
            p.convert_to_eventfd(unwrap_eventfd(eventfd))
                .unwrap()
                .as_raw_fd(),
            raw_fd_num
        );
    }
}
