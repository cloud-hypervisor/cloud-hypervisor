// Copyright 2021 Alyssa Ross <hi@alyssa.is>
// SPDX-License-Identifier: Apache-2.0

use crate::clone3::{clone3, clone_args, CLONE_CLEAR_SIGHAND};
use libc::{
    c_int, c_void, close, getpgrp, ioctl, pipe2, poll, pollfd, setsid, sigemptyset, siginfo_t,
    sigprocmask, tcsetpgrp, O_CLOEXEC, POLLERR, SIGWINCH, SIG_SETMASK, STDIN_FILENO, STDOUT_FILENO,
    TIOCSCTTY,
};
use seccompiler::{apply_filter, BpfProgram};
use std::cell::RefCell;
use std::fs::File;
use std::io::{self, ErrorKind, Read, Write};
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
    if unsafe { sigemptyset(set.as_mut_ptr()) } == -1 {
        return Err(io::Error::last_os_error());
    }
    let set = unsafe { set.assume_init() };

    if unsafe { sigprocmask(SIG_SETMASK, &set, null_mut()) } == -1 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

fn sigwinch_listener_main(seccomp_filter: BpfProgram, tx: File, tty: &File) -> ! {
    TX.with(|opt| opt.replace(Some(tx)));

    unsafe {
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
    }

    unblock_all_signals().unwrap();

    apply_filter(&seccomp_filter).unwrap();

    register_signal_handler(SIGWINCH, sigwinch_handler).unwrap();

    unsafe {
        // Create a new session (and therefore a new process group).
        assert_ne!(setsid(), -1);

        // Set the tty to be this process's controlling terminal.
        assert_ne!(ioctl(tty.as_raw_fd(), TIOCSCTTY, 0), -1);

        // Become the foreground process group of the tty.
        assert_ne!(tcsetpgrp(tty.as_raw_fd(), getpgrp()), -1);
    }

    notify();

    // Wait for the pipe to close, indicating the parent has exited.
    with_tx(|tx| {
        let mut pollfd = pollfd {
            fd: tx.as_raw_fd(),
            events: 0,
            revents: 0,
        };

        while unsafe { poll(&mut pollfd, 1, -1) } == -1 {
            let e = io::Error::last_os_error();
            if !matches!(e.kind(), ErrorKind::Interrupted | ErrorKind::WouldBlock) {
                panic!("poll: {}", e);
            }
        }

        assert_eq!(pollfd.revents, POLLERR);
    });

    exit(0);
}

pub fn start_sigwinch_listener(seccomp_filter: BpfProgram, pty: &File) -> io::Result<File> {
    let mut pipe = [-1; 2];
    if unsafe { pipe2(pipe.as_mut_ptr(), O_CLOEXEC) } == -1 {
        return Err(io::Error::last_os_error());
    }

    let mut rx = unsafe { File::from_raw_fd(pipe[0]) };
    let tx = unsafe { File::from_raw_fd(pipe[1]) };

    let mut args = clone_args::default();
    args.flags |= CLONE_CLEAR_SIGHAND;

    match unsafe { clone3(&mut args, size_of::<clone_args>()) } {
        -1 => return Err(io::Error::last_os_error()),
        0 => {
            drop(rx);
            sigwinch_listener_main(seccomp_filter, tx, pty);
        }
        _ => (),
    }

    drop(tx);

    // Wait for a notification indicating readiness.
    rx.read_exact(&mut [0])?;

    Ok(rx)
}
