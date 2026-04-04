// Copyright © 2026 Demi Marie Obenour <demiobenour@gmail.com>
//
// SPDX-License-Identifier: Apache-2.0

use std::ffi::{CStr, c_int, c_long};
use std::fs::File;
use std::io::ErrorKind;
use std::mem::{self, MaybeUninit};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};

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

#[cfg(test)]
/// Convert an [`EventFd`] to an [`OwnedFd`].
fn unwrap_eventfd(eventfd: EventFd) -> OwnedFd {
    let fd = eventfd.into_raw_fd();
    // SAFETY: event_fd.into_raw_fd() returns valid FD we own.
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

// Caller must ensure that if the callback returns 0, its arg is initialized.
// Caller must also ensure that the callback does not convert its pointer
// argument to a reference.
unsafe fn os_err<T, U: FnOnce(*mut T) -> c_int>(cb: U) -> Result<T, std::io::Error> {
    // SAFETY: MaybeUninit can have any bit pattern
    let mut buf = unsafe { mem::zeroed::<MaybeUninit<T>>() };
    match cb(buf.as_mut_ptr()) {
        0 => Ok({
            // SAFETY: caller promises that if r is 0, val is initialized
            // with valid values by the OS.
            unsafe { buf.assume_init() }
        }),
        -1 => Err(std::io::Error::last_os_error()),
        _ => panic!("bad return value from syscall"),
    }
}

fn fstatfs(fd: BorrowedFd) -> std::io::Result<libc::statfs64> {
    // SAFETY: callback will call libc function with correct arguments,
    // and if it returns 0 kernel initialized struct.
    unsafe { os_err(|ptr| libc::fstatfs64(fd.as_raw_fd(), ptr)) }
}

/// Safe wrapper around fstat64
pub fn fstat(fd: BorrowedFd) -> std::io::Result<libc::stat64> {
    // SAFETY: callback will call libc function with correct arguments,
    // and if it returns 0 kernel initialized struct.
    unsafe { os_err(|ptr| libc::fstat64(fd.as_raw_fd(), ptr)) }
}

/// Safe wrapper around openat2()
pub fn openat2(
    fd: BorrowedFd,
    path: &CStr,
    flags: u64,
    mode: u64,
    resolve: u64,
) -> std::io::Result<OwnedFd> {
    // SAFETY: This is C code directly translated to Rust.
    let r = {
        // SAFETY: man 2 openat2 states that open_how can (and must) be zero-initialized
        let mut how: MaybeUninit<libc::open_how> = unsafe { std::mem::zeroed() };
        let ptr = how.as_mut_ptr();

        // SAFETY: write to struct fields via ptr::write
        unsafe {
            (&raw mut (*ptr).flags).write(flags);
            (&raw mut (*ptr).mode).write(mode);
            (&raw mut (*ptr).resolve).write(resolve);
        };
        // Ensure that casting from usize to c_long loses no information.
        const _: () = assert!(size_of::<c_long>() == size_of::<usize>());
        const _: () = assert!(size_of::<*mut u8>() == size_of::<usize>());
        // SAFETY: FFI call with correct arguments.  See man 2 openat2.
        unsafe {
            libc::syscall(
                libc::SYS_openat2 as c_long,
                fd.as_raw_fd() as c_long,
                path.as_ptr().expose_provenance() as c_long,
                ptr.expose_provenance() as c_long,
                size_of::<libc::open_how>() as c_long,
            )
        }
    };
    match r {
        -1 => Err(std::io::Error::last_os_error()),
        fd if fd >= 0 && fd <= c_int::MAX as _ => Ok({
            // SAFETY: Linux returned valid FD
            unsafe { OwnedFd::from_raw_fd(fd as _) }
        }),
        _ => panic!("Bad return value from syscall"),
    }
}

impl TryFrom<OwnedFd> for ProcRoot {
    type Error = std::io::Error;

    // whether dev_t converting to u64 is useless might be platform-dependent
    #[allow(clippy::useless_conversion)]
    fn try_from(root_fd: OwnedFd) -> Result<Self, Self::Error> {
        #[allow(clippy::unnecessary_cast)] // musl vs glibc signedness difference
        if fstatfs(root_fd.as_fd())?.f_type as i64 != libc::PROC_SUPER_MAGIC as i64 {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "File descriptor doesn't refer to a procfs file",
            ));
        }
        if fstat(root_fd.as_fd())?.st_ino != 1 {
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
        let stat_info = fstat(event_fd)?;
        let statfs_info = fstatfs(event_fd)?;

        Ok(Self {
            root,
            st_dev: stat_info.st_dev.into(),
            // 0x09041934 is ANON_INODE_FS_MAGIC
            is_anon_inode: statfs_info.f_type == 0x09041934,
        })
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
    pub fn check_is_eventfd(&self, fd: BorrowedFd) -> std::io::Result<bool> {
        // If st_dev is different than the expected one, this can't be an eventfd.
        if fstat(fd)?.st_dev != self.st_dev {
            return Ok(false);
        }
        // If eventfds don't use an anonymous inode, they use their own filesystem.
        // In that case, the st_dev check is sufficient.
        if !self.is_anon_inode {
            return Ok(true);
        }
        const EXPECTED_NAME: &[u8] = b"anon_inode:[eventfd]";
        let path = format!("thread-self/fd/{}\0", fd.as_raw_fd());
        let child_fd = openat2(
            self.root.root_fd.as_fd(),
            CStr::from_bytes_with_nul(path.as_bytes()).unwrap(),
            (libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC) as _,
            0,
            libc::RESOLVE_NO_MAGICLINKS | libc::RESOLVE_NO_XDEV | libc::RESOLVE_BENEATH,
        )?;
        let mut buf = [0u8; EXPECTED_NAME.len() + 1];
        // SAFETY: FFI call with correct arguments
        let r = unsafe {
            libc::readlinkat(
                child_fd.as_raw_fd(),
                c"".as_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };
        if r == -1 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(r == EXPECTED_NAME.len().try_into().unwrap()
                && &buf[..EXPECTED_NAME.len()] == EXPECTED_NAME)
        }
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
        const _: () = assert!(size_of::<EventFd>() == size_of::<OwnedFd>());
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
