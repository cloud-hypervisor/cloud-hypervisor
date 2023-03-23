// Copyright 2021, 2023 Alyssa Ross <hi@alyssa.is>
// SPDX-License-Identifier: Apache-2.0

use crate::clone3::{clone3, clone_args, CLONE_CLEAR_SIGHAND};
use libc::{
    c_int, c_void, close, getpgrp, ioctl, pipe2, poll, pollfd, setsid, sigemptyset, siginfo_t,
    sigprocmask, syscall, tcsetpgrp, SYS_close_range, ENOSYS, O_CLOEXEC, POLLERR, SIGWINCH,
    SIG_SETMASK, STDERR_FILENO, TIOCSCTTY,
};
use seccompiler::{apply_filter, BpfProgram};
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fs::{read_dir, File};
use std::io::{self, ErrorKind, Read, Write};
use std::iter::once;
use std::mem::size_of;
use std::mem::MaybeUninit;
use std::os::unix::prelude::*;
use std::process::exit;
use std::ptr::null_mut;
use vmm_sys_util::signal::register_signal_handler;

thread_local! {
    // The tty file descriptor is stored in a global variable so it
    // can be accessed by a signal handler.
    static TX: RefCell<Option<File>> = RefCell::new(None);
}

fn with_tx<R, F: FnOnce(&File) -> R>(f: F) -> R {
    TX.with(|tx| f(tx.borrow().as_ref().unwrap()))
}

// This function has to be safe to call from a signal handler, and
// therefore must not panic.
fn notify() {
    if let Err(e) = with_tx(|mut tx| tx.write_all(b"\n")) {
        if e.kind() == ErrorKind::BrokenPipe {
            exit(0);
        }
        exit(1);
    }
}

extern "C" fn sigwinch_handler(_signo: c_int, _info: *mut siginfo_t, _unused: *mut c_void) {
    notify();
}

fn unblock_all_signals() -> io::Result<()> {
    let mut set = MaybeUninit::uninit();
    // SAFETY: set is a correct structure for sigemptyset
    if unsafe { sigemptyset(set.as_mut_ptr()) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: set is initialized above
    let set = unsafe { set.assume_init() };

    // SAFETY: all arguments are correct
    if unsafe { sigprocmask(SIG_SETMASK, &set, null_mut()) } == -1 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

/// # Safety
///
/// Caller is responsible for ensuring all file descriptors not listed
/// in `keep_fds` are not accessed after this point, and that no other
/// thread is opening file descriptors while this function is
/// running.
unsafe fn close_fds_fallback(keep_fds: &BTreeSet<RawFd>) {
    // We collect these instead of iterating through them, because we
    // don't want to close the descriptor for /proc/self/fd while
    // we're iterating through it.
    let open_fds: BTreeSet<RawFd> = read_dir("/proc/self/fd")
        .unwrap()
        .map(Result::unwrap)
        .filter_map(|s| s.file_name().into_string().ok()?.parse().ok())
        .collect();

    for fd in open_fds.difference(keep_fds) {
        close(*fd);
    }
}

/// # Safety
///
/// Caller is responsible for ensuring all file descriptors not listed
/// in `keep_fds` are not accessed after this point, and that no other
/// thread is opening file descriptors while this function is
/// running.
unsafe fn close_unused_fds(keep_fds: &mut [RawFd]) {
    keep_fds.sort();

    // Iterate over the gaps between descriptors we want to keep.
    let firsts = keep_fds.iter().map(|fd| fd + 1);
    for (i, first) in once(0).chain(firsts).enumerate() {
        // The next fd is the one at i, because the indexes in the
        // iterator are offset by one due to the initial 0.
        let next_keep_fd = keep_fds.get(i);
        let last = next_keep_fd.map(|fd| fd - 1).unwrap_or(RawFd::MAX);

        if first > last {
            continue;
        }

        if syscall(SYS_close_range, first, last, 0) == -1 {
            // The kernel might be too old to have close_range, in
            // which case we need to fall back to an uglier method.
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(ENOSYS) {
                return close_fds_fallback(&keep_fds.iter().copied().collect());
            }

            panic!("close_range: {e}");
        }
    }
}

fn sigwinch_listener_main(seccomp_filter: BpfProgram, tx: File, pty: File) -> ! {
    let pty_fd = pty.into_raw_fd();

    // SAFETY: any references to these file descriptors are
    // unreachable, because this function never returns.
    unsafe {
        close_unused_fds(&mut [STDERR_FILENO, tx.as_raw_fd(), pty_fd]);
    }

    TX.with(|opt| opt.replace(Some(tx)));

    unblock_all_signals().unwrap();

    if !seccomp_filter.is_empty() {
        apply_filter(&seccomp_filter).unwrap();
    }

    register_signal_handler(SIGWINCH, sigwinch_handler).unwrap();

    // SAFETY: FFI calls
    unsafe {
        // Create a new session (and therefore a new process group).
        assert_ne!(setsid(), -1);

        // Set the tty to be this process's controlling terminal.
        assert_ne!(ioctl(pty_fd, TIOCSCTTY, 0), -1);

        // Become the foreground process group of the tty.
        assert_ne!(tcsetpgrp(pty_fd, getpgrp()), -1);

        // Close the PTY fd
        assert_ne!(close(pty_fd), -1);
    }

    notify();

    // Wait for the pipe to close, indicating the parent has exited.
    with_tx(|tx| {
        let mut pollfd = pollfd {
            fd: tx.as_raw_fd(),
            events: 0,
            revents: 0,
        };

        // SAFETY: FFI call with valid arguments
        while unsafe { poll(&mut pollfd, 1, -1) } == -1 {
            let e = io::Error::last_os_error();
            assert!(
                matches!(e.kind(), ErrorKind::Interrupted | ErrorKind::WouldBlock),
                "poll: {e}"
            );
        }

        assert_eq!(pollfd.revents, POLLERR);
    });

    exit(0);
}

pub fn start_sigwinch_listener(seccomp_filter: BpfProgram, tty_sub: File) -> io::Result<File> {
    let mut pipe = [-1; 2];
    // SAFETY: FFI call with valid arguments
    if unsafe { pipe2(pipe.as_mut_ptr(), O_CLOEXEC) } == -1 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: pipe[0] is valid
    let mut rx = unsafe { File::from_raw_fd(pipe[0]) };
    // SAFETY: pipe[1] is valid
    let tx = unsafe { File::from_raw_fd(pipe[1]) };

    let mut args = clone_args::default();
    args.flags |= CLONE_CLEAR_SIGHAND;

    // SAFETY: FFI call
    match unsafe { clone3(&mut args, size_of::<clone_args>()) } {
        -1 => return Err(io::Error::last_os_error()),
        0 => {
            sigwinch_listener_main(seccomp_filter, tx, tty_sub);
        }
        _ => (),
    }

    drop(tx);

    // Wait for a notification indicating readiness.
    rx.read_exact(&mut [0])?;

    Ok(rx)
}
