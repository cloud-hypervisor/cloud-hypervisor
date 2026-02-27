// Copyright © 2026 Demi Marie Obenour <demiobenour@gmail.com>
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::{ErrorKind, Read};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};

use rustix::fs::{Mode, OFlags, ResolveFlags};
use thiserror::Error;
use vmm_sys_util::eventfd::EventFd;

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

pub struct ProcRoot {
    root_fd: OwnedFd,
}
impl ProcRoot {
    pub fn new() -> std::io::Result<Self> {
        Self::new_from_fd(File::open("/proc")?.into())
    }
    pub fn new_from_fd(root_fd: OwnedFd) -> std::io::Result<Self> {
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

    /// Returns whether the provided file descriptor is an eventfd.
    ///
    /// # Errors
    ///
    /// Returns an error if an I/O error occurs, or if the kernel provides
    /// junk in /proc/thread-self/fdinfo/FILE_DESCRIPTOR.
    pub fn check_is_eventfd(&self, fd: BorrowedFd) -> Result<bool, std::io::Error> {
        let path = format!("thread-self/fdinfo/{}", fd.as_raw_fd());
        let child_fd = File::from(rustix::fs::openat2(
            self.root_fd.as_fd(),
            path,
            OFlags::NOCTTY | OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            // thread-self is a symlink, but only points down, not up
            ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_XDEV | ResolveFlags::BENEATH,
        )?);
        let mut buf = vec![];
        let size = child_fd.take(4096).read_to_end(&mut buf)?;
        if buf.contains(&b'\0') || buf.last() != Some(&b'\n') || size != buf.len() || size >= 4096 {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "bad data from /proc/thread-self/fdinfo/FD",
            ));
        }
        let mut is_eventfd = false;
        for line in buf[..size - 1].split(|&a| a == b'\n') {
            let mut iterator = line.splitn(2, |&a| a == b':');
            // splitn always returns at least one item
            let prefix = iterator.next().unwrap();
            if iterator.next().is_none() {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "bad data from /proc/thread-self/fdinfo/FD (no colon)",
                ));
            }
            if prefix.starts_with(b"eventfd-") {
                is_eventfd = true;
                break;
            }
            // Guard against a driver that doesn't sanitize values
            // in key-value pairs.  Driver-specific keys generally contain '-'.
            // Common keys never do.  Some buggy kernel code has newline injection bugs,
            // so detect them.
            if prefix.contains(&b'-') || prefix == b"exp_name" || prefix == b"link_type" {
                break;
            }
        }
        Ok(is_eventfd)
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

    use super::*;
    #[test]
    fn check_eventfd() {
        let null_fd = std::fs::File::open("/dev/null").unwrap();
        let p = ProcRoot::new().unwrap();
        let eventfd = EventFd::new(0).unwrap();
        let raw_fd_num = eventfd.as_raw_fd();
        // SAFETY: as_raw_fd() returns valid FD
        let borrowed_eventfd = unsafe { BorrowedFd::borrow_raw(raw_fd_num) };
        assert!(p.check_is_eventfd(borrowed_eventfd).unwrap());
        assert!(!p.check_is_eventfd(null_fd.as_fd()).unwrap());
        core::mem::forget(eventfd);
        // SAFETY: as_raw_fd() returns valid FD and EventFd has been forgotten.
        let eventfd = unsafe { OwnedFd::from_raw_fd(raw_fd_num) };
        // Convert the FD to an EventFd, then forget it on success to avoid double-close.
        let new_eventfd = p.convert_to_eventfd(eventfd).unwrap();
        assert_eq!(new_eventfd.as_raw_fd(), raw_fd_num);
        drop(new_eventfd);
        let raw_proc_fd = OwnedFd::from(null_fd.try_clone().unwrap());
        let raw_proc_fd_num = raw_proc_fd.as_raw_fd();
        match p.convert_to_eventfd(raw_proc_fd).unwrap_err() {
            (orig_fd, Error::NotEventFd) => assert_eq!(orig_fd.as_raw_fd(), raw_proc_fd_num),
            (_, Error::IO(e)) => panic!("I/O error {e}"),
        }
    }
}
