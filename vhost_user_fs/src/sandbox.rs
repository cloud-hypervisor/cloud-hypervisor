// Copyright 2020 Red Hat, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::CString;
use std::os::unix::io::RawFd;
use std::{fmt, fs, io};

use tempdir::TempDir;

#[derive(Debug)]
pub enum Error {
    /// Failed to bind mount `/proc/self/fd` into a temporary directory.
    BindMountProcSelfFd(io::Error),
    /// Failed to bind mount shared directory.
    BindMountSharedDir(io::Error),
    /// Failed to change to the old root directory.
    ChdirOldRoot(io::Error),
    /// Failed to change to the new root directory.
    ChdirNewRoot(io::Error),
    /// Failed to clean the properties of the mount point.
    CleanMount(io::Error),
    /// Failed to create a temporary directory.
    CreateTempDir(io::Error),
    /// Call to libc::fork returned an error.
    Fork(io::Error),
    /// Error bind-mounting a directory.
    MountBind(io::Error),
    /// Failed to mount old root.
    MountOldRoot(io::Error),
    /// Error mounting proc.
    MountProc(io::Error),
    /// Failed to mount new root.
    MountNewRoot(io::Error),
    /// Error mounting target directory.
    MountTarget(io::Error),
    /// Failed to open new root.
    OpenNewRoot(io::Error),
    /// Failed to open old root.
    OpenOldRoot(io::Error),
    /// Failed to open `/proc/self/fd`.
    OpenProcSelfFd(io::Error),
    /// Error switching root directory.
    PivotRoot(io::Error),
    /// Failed to remove temporary directory.
    RmdirTempDir(io::Error),
    /// Failed to lazily unmount old root.
    UmountOldRoot(io::Error),
    /// Failed to lazily unmount temporary directory.
    UmountTempDir(io::Error),
    /// Call to libc::unshare returned an error.
    Unshare(io::Error),
    /// Failed to read procfs.
    ReadProc(io::Error),
    /// Failed to parse `/proc/sys/fs/nr_open`.
    InvalidNrOpen(std::num::ParseIntError),
    /// Failed to set rlimit.
    SetRlimit(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "vhost_user_fs_sandbox_error: {:?}", self)
    }
}

/// A helper for creating a sandbox for isolating the service.
pub struct Sandbox {
    /// The directory that is going to be shared with the VM. The sandbox will be constructed on top
    /// of this directory.
    shared_dir: String,
    /// A file descriptor for `/proc/self/fd` obtained from the sandboxed context.
    proc_self_fd: Option<RawFd>,
}

impl Sandbox {
    pub fn new(shared_dir: String) -> Self {
        Sandbox {
            shared_dir,
            proc_self_fd: None,
        }
    }

    // Make `self.shared_dir` our root directory, and get an isolated file descriptor for
    // `/proc/self/fd`.
    //
    // This is based on virtiofsd's setup_namespaces() and setup_mounts(), and it's very similar to
    // the strategy used in containers. Consists on a careful sequence of mounts and bind-mounts to
    // ensure it's not possible to escape the sandbox through `self.shared_dir` nor the file
    // descriptor obtained for `/proc/self/fd`.
    //
    // It's ugly, but it's the only way until Linux implements a proper containerization API.
    fn setup_mounts(&mut self) -> Result<(), Error> {
        // Ensure our mount changes don't affect the parent mount namespace.
        let c_root_dir = CString::new("/").unwrap();
        let ret = unsafe {
            libc::mount(
                std::ptr::null(),
                c_root_dir.as_ptr(),
                std::ptr::null(),
                libc::MS_SLAVE | libc::MS_REC,
                std::ptr::null(),
            )
        };
        if ret != 0 {
            return Err(Error::CleanMount(std::io::Error::last_os_error()));
        }

        // Mount `/proc` in this context.
        let c_proc_dir = CString::new("/proc").unwrap();
        let c_proc_fs = CString::new("proc").unwrap();
        let ret = unsafe {
            libc::mount(
                c_proc_fs.as_ptr(),
                c_proc_dir.as_ptr(),
                c_proc_fs.as_ptr(),
                libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_NOSUID | libc::MS_RELATIME,
                std::ptr::null(),
            )
        };
        if ret != 0 {
            return Err(Error::MountProc(std::io::Error::last_os_error()));
        }

        // Bind-mount `/proc/self/fd` info a temporary directory, preventing access to ancestor
        // directories.
        let c_proc_self_fd = CString::new("/proc/self/fd").unwrap();
        let tmp_dir = TempDir::new("vhostuserfs-")
            .map_err(|_| Error::CreateTempDir(std::io::Error::last_os_error()))?;
        let c_tmp_dir = CString::new(tmp_dir.into_path().to_str().unwrap()).unwrap();
        let ret = unsafe {
            libc::mount(
                c_proc_self_fd.as_ptr(),
                c_tmp_dir.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        };
        if ret < 0 {
            return Err(Error::BindMountProcSelfFd(std::io::Error::last_os_error()));
        }

        // Obtain a file descriptor for `/proc/self/fd` through the bind-mounted temporary directory.
        let proc_self_fd = unsafe { libc::open(c_tmp_dir.as_ptr(), libc::O_PATH) };
        if proc_self_fd < 0 {
            return Err(Error::OpenProcSelfFd(std::io::Error::last_os_error()));
        }
        self.proc_self_fd = Some(proc_self_fd);

        // Now that we have a file descriptor for `/proc/self/fd`, we no longer need the bind-mount.
        // Unmount it and remove the temporary directory.
        let ret = unsafe { libc::umount2(c_tmp_dir.as_ptr(), libc::MNT_DETACH) };
        if ret < 0 {
            return Err(Error::UmountTempDir(std::io::Error::last_os_error()));
        }
        let ret = unsafe { libc::rmdir(c_tmp_dir.as_ptr()) };
        if ret < 0 {
            return Err(Error::RmdirTempDir(std::io::Error::last_os_error()));
        }

        // Bind-mount `self.shared_dir` on itself so we can use as new root on `pivot_root` syscall.
        let c_shared_dir = CString::new(self.shared_dir.clone()).unwrap();
        let ret = unsafe {
            libc::mount(
                c_shared_dir.as_ptr(),
                c_shared_dir.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND | libc::MS_REC,
                std::ptr::null(),
            )
        };
        if ret < 0 {
            return Err(Error::BindMountSharedDir(std::io::Error::last_os_error()));
        }

        // Get a file descriptor to our old root so we can reference it after switching root.
        let oldroot_fd = unsafe {
            libc::open(
                c_root_dir.as_ptr(),
                libc::O_DIRECTORY | libc::O_RDONLY | libc::O_CLOEXEC,
            )
        };
        if oldroot_fd < 0 {
            return Err(Error::OpenOldRoot(std::io::Error::last_os_error()));
        }

        // Get a file descriptor to the new root so we can reference it after switching root.
        let newroot_fd = unsafe {
            libc::open(
                c_shared_dir.as_ptr(),
                libc::O_DIRECTORY | libc::O_RDONLY | libc::O_CLOEXEC,
            )
        };
        if newroot_fd < 0 {
            return Err(Error::OpenNewRoot(std::io::Error::last_os_error()));
        }

        // Change to new root directory to prepare for `pivot_root` syscall.
        let ret = unsafe { libc::fchdir(newroot_fd) };
        if ret < 0 {
            return Err(Error::ChdirNewRoot(std::io::Error::last_os_error()));
        }

        // Call to `pivot_root` using `.` as both new and old root.
        let c_current_dir = CString::new(".").unwrap();
        let ret = unsafe {
            libc::syscall(
                libc::SYS_pivot_root,
                c_current_dir.as_ptr(),
                c_current_dir.as_ptr(),
            )
        };
        if ret < 0 {
            return Err(Error::PivotRoot(std::io::Error::last_os_error()));
        }

        // Change to old root directory to prepare for cleaning up and unmounting it.
        let ret = unsafe { libc::fchdir(oldroot_fd) };
        if ret < 0 {
            return Err(Error::ChdirOldRoot(std::io::Error::last_os_error()));
        }

        // Clean up old root to avoid mount namespace propagation.
        let c_empty = CString::new("").unwrap();
        let ret = unsafe {
            libc::mount(
                c_empty.as_ptr(),
                c_current_dir.as_ptr(),
                c_empty.as_ptr(),
                libc::MS_SLAVE | libc::MS_REC,
                std::ptr::null(),
            )
        };
        if ret != 0 {
            return Err(Error::CleanMount(std::io::Error::last_os_error()));
        }

        // Lazily unmount old root.
        let ret = unsafe { libc::umount2(c_current_dir.as_ptr(), libc::MNT_DETACH) };
        if ret < 0 {
            return Err(Error::UmountOldRoot(std::io::Error::last_os_error()));
        }

        // Change to new root.
        let ret = unsafe { libc::fchdir(newroot_fd) };
        if ret < 0 {
            return Err(Error::ChdirNewRoot(std::io::Error::last_os_error()));
        }

        // We no longer need these file descriptors, so close them.
        unsafe { libc::close(newroot_fd) };
        unsafe { libc::close(oldroot_fd) };

        Ok(())
    }

    /// Sets the limit of open files to the max possible.
    fn setup_nofile_rlimit(&self) -> Result<(), Error> {
        // /proc/sys/fs/nr_open is a sysctl file that shows the maximum number
        // of file-handles a process can allocate.
        let path = "/proc/sys/fs/nr_open";
        let max_str = fs::read_to_string(path).map_err(|e| Error::ReadProc(e))?;
        let max = max_str
            .trim()
            .parse()
            .map_err(|e| Error::InvalidNrOpen(e))?;

        let limit = libc::rlimit {
            rlim_cur: max,
            rlim_max: max,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) };
        if ret < 0 {
            Err(Error::SetRlimit(std::io::Error::last_os_error()))
        } else {
            Ok(())
        }
    }

    /// Set up sandbox, fork and jump into it.
    ///
    /// On success, the returned value will be the PID of the child for the parent and `None` for
    /// the child itself, with the latter running isolated in `self.shared_dir`.
    pub fn enter(&mut self) -> Result<Option<i32>, Error> {
        let uid = unsafe { libc::geteuid() };

        let flags = if uid == 0 {
            libc::CLONE_NEWPID | libc::CLONE_NEWNS | libc::CLONE_NEWNET
        } else {
            // If running as an unprivileged user, rely on user_namespaces(7) for isolation. The
            // main limitation of this strategy is that only the current uid/gid are mapped into
            // the new namespace, so most operations on permissions will fail.
            libc::CLONE_NEWPID | libc::CLONE_NEWNS | libc::CLONE_NEWNET | libc::CLONE_NEWUSER
        };

        let ret = unsafe { libc::unshare(flags) };
        if ret != 0 {
            return Err(Error::Unshare(std::io::Error::last_os_error()));
        }

        let child = unsafe { libc::fork() };
        match child {
            0 => {
                // This is the child. Request to receive SIGTERM on parent's death.
                unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) };
                self.setup_nofile_rlimit()?;
                self.setup_mounts()?;
                Ok(None)
            }
            x if x > 0 => {
                // This is the parent.
                Ok(Some(child))
            }
            _ => Err(Error::Fork(std::io::Error::last_os_error())),
        }
    }

    pub fn get_proc_self_fd(&self) -> Option<RawFd> {
        self.proc_self_fd
    }
}
