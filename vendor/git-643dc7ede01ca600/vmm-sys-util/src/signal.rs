// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

use libc::{
    c_int, c_void, pthread_kill, pthread_sigmask, pthread_t, sigaction, sigaddset, sigemptyset,
    siginfo_t, sigismember, sigpending, sigset_t, sigtimedwait, timespec, EAGAIN, EINTR, EINVAL,
    SIGHUP, SIGSYS, SIG_BLOCK, SIG_UNBLOCK,
};

use errno;
use std::fmt::{self, Display};
use std::io;
use std::mem;
use std::os::unix::thread::JoinHandleExt;
use std::ptr::{null, null_mut};
use std::result;
use std::thread::JoinHandle;

#[derive(Debug)]
pub enum Error {
    /// Couldn't create a sigset.
    CreateSigset(errno::Error),
    /// The wrapped signal has already been blocked.
    SignalAlreadyBlocked(c_int),
    /// Failed to check if the requested signal is in the blocked set already.
    CompareBlockedSignals(errno::Error),
    /// The signal could not be blocked.
    BlockSignal(errno::Error),
    /// The signal mask could not be retrieved.
    RetrieveSignalMask(i32),
    /// The signal could not be unblocked.
    UnblockSignal(errno::Error),
    /// Failed to wait for given signal.
    ClearWaitPending(errno::Error),
    /// Failed to get pending signals.
    ClearGetPending(errno::Error),
    /// Failed to check if given signal is in the set of pending signals.
    ClearCheckPending(errno::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            CreateSigset(e) => write!(f, "couldn't create a sigset: {}", e),
            SignalAlreadyBlocked(num) => write!(f, "signal {} already blocked", num),
            CompareBlockedSignals(e) => write!(
                f,
                "failed to check whether requested signal is in the blocked set: {}",
                e,
            ),
            BlockSignal(e) => write!(f, "signal could not be blocked: {}", e),
            RetrieveSignalMask(errno) => write!(
                f,
                "failed to retrieve signal mask: {}",
                io::Error::from_raw_os_error(*errno),
            ),
            UnblockSignal(e) => write!(f, "signal could not be unblocked: {}", e),
            ClearWaitPending(e) => write!(f, "failed to wait for given signal: {}", e),
            ClearGetPending(e) => write!(f, "failed to get pending signals: {}", e),
            ClearCheckPending(e) => write!(
                f,
                "failed to check whether given signal is in the pending set: {}",
                e,
            ),
        }
    }
}

pub type SignalResult<T> = result::Result<T, Error>;
type SiginfoHandler = extern "C" fn(num: c_int, info: *mut siginfo_t, _unused: *mut c_void) -> ();

pub enum SignalHandler {
    Siginfo(SiginfoHandler),
    // TODO add a`SimpleHandler` when `libc` adds `sa_handler` support to `sigaction`.
}

impl SignalHandler {
    fn set_flags(act: &mut sigaction, flag: c_int) {
        act.sa_flags = flag;
    }
}
/// Fills a `sigaction` structure from of the signal handler.
/// Refer to http://man7.org/linux/man-pages/man7/signal.7.html
impl Into<sigaction> for SignalHandler {
    fn into(self) -> sigaction {
        let mut act: sigaction = unsafe { mem::zeroed() };
        match self {
            SignalHandler::Siginfo(function) => {
                act.sa_sigaction = function as *const () as usize;
            }
        }
        act
    }
}

extern "C" {
    fn __libc_current_sigrtmin() -> c_int;
    fn __libc_current_sigrtmax() -> c_int;
}

/// Returns the minimum (inclusive) real-time signal number.
#[allow(non_snake_case)]
fn SIGRTMIN() -> c_int {
    unsafe { __libc_current_sigrtmin() }
}

/// Returns the maximum (inclusive) real-time signal number.
#[allow(non_snake_case)]
fn SIGRTMAX() -> c_int {
    unsafe { __libc_current_sigrtmax() }
}

/// Verifies that a signal number is valid: for VCPU signals, it needs to be enclosed within the OS
/// limits for realtime signals, and the remaining ones need to be between the minimum (SIGHUP) and
/// maximum (SIGSYS) values.
pub fn validate_signal_num(num: c_int, for_vcpu: bool) -> errno::Result<c_int> {
    if for_vcpu {
        let actual_num = num + SIGRTMIN();
        if actual_num <= SIGRTMAX() {
            return Ok(actual_num);
        }
    } else if SIGHUP <= num && num <= SIGSYS {
        return Ok(num);
    }
    Err(errno::Error::new(EINVAL))
}

/// Registers `handler` as the signal handler of signum `num`.
///
/// Uses `sigaction` to register the handler.
///
/// This is considered unsafe because the given handler will be called asynchronously, interrupting
/// whatever the thread was doing and therefore must only do async-signal-safe operations.
/// flags: SA_SIGINFO or SA_RESTART if wants to restart after signal received.
pub unsafe fn register_signal_handler(
    num: i32,
    handler: SignalHandler,
    for_vcpu: bool,
    flag: c_int,
) -> errno::Result<()> {
    let num = validate_signal_num(num, for_vcpu)?;
    let mut act: sigaction = handler.into();
    SignalHandler::set_flags(&mut act, flag);
    match sigaction(num, &act, null_mut()) {
        0 => Ok(()),
        _ => errno::errno_result(),
    }
}

/// Creates `sigset` from an array of signal numbers.
///
/// This is a helper function used when we want to manipulate signals.
pub fn create_sigset(signals: &[c_int]) -> errno::Result<sigset_t> {
    // sigset will actually be initialized by sigemptyset below.
    let mut sigset: sigset_t = unsafe { mem::zeroed() };

    // Safe - return value is checked.
    let ret = unsafe { sigemptyset(&mut sigset) };
    if ret < 0 {
        return errno::errno_result();
    }

    for signal in signals {
        // Safe - return value is checked.
        let ret = unsafe { sigaddset(&mut sigset, *signal) };
        if ret < 0 {
            return errno::errno_result();
        }
    }

    Ok(sigset)
}

/// Retrieves the signal mask of the current thread as a vector of c_ints.
pub fn get_blocked_signals() -> SignalResult<Vec<c_int>> {
    let mut mask = Vec::new();

    // Safe - return values are checked.
    unsafe {
        let mut old_sigset: sigset_t = mem::zeroed();
        let ret = pthread_sigmask(SIG_BLOCK, null(), &mut old_sigset as *mut sigset_t);
        if ret < 0 {
            return Err(Error::RetrieveSignalMask(ret));
        }

        for num in 0..=SIGRTMAX() {
            if sigismember(&old_sigset, num) > 0 {
                mask.push(num);
            }
        }
    }

    Ok(mask)
}

/// Masks given signal.
///
/// If signal is already blocked the call will fail with Error::SignalAlreadyBlocked
/// result.
pub fn block_signal(num: c_int) -> SignalResult<()> {
    let sigset = create_sigset(&[num]).map_err(Error::CreateSigset)?;

    // Safe - return values are checked.
    unsafe {
        let mut old_sigset: sigset_t = mem::zeroed();
        let ret = pthread_sigmask(SIG_BLOCK, &sigset, &mut old_sigset as *mut sigset_t);
        if ret < 0 {
            return Err(Error::BlockSignal(errno::Error::last()));
        }
        let ret = sigismember(&old_sigset, num);
        if ret < 0 {
            return Err(Error::CompareBlockedSignals(errno::Error::last()));
        } else if ret > 0 {
            return Err(Error::SignalAlreadyBlocked(num));
        }
    }
    Ok(())
}

/// Unmasks given signal.
pub fn unblock_signal(num: c_int) -> SignalResult<()> {
    let sigset = create_sigset(&[num]).map_err(Error::CreateSigset)?;

    // Safe - return value is checked.
    let ret = unsafe { pthread_sigmask(SIG_UNBLOCK, &sigset, null_mut()) };
    if ret < 0 {
        return Err(Error::UnblockSignal(errno::Error::last()));
    }
    Ok(())
}

/// Clears pending signal.
pub fn clear_signal(num: c_int) -> SignalResult<()> {
    let sigset = create_sigset(&[num]).map_err(Error::CreateSigset)?;

    while {
        // This is safe as we are rigorously checking return values
        // of libc calls.
        unsafe {
            let mut siginfo: siginfo_t = mem::zeroed();
            let ts = timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            // Attempt to consume one instance of pending signal. If signal
            // is not pending, the call will fail with EAGAIN or EINTR.
            let ret = sigtimedwait(&sigset, &mut siginfo, &ts);
            if ret < 0 {
                let e = errno::Error::last();
                match e.errno() {
                    EAGAIN | EINTR => {}
                    _ => {
                        return Err(Error::ClearWaitPending(errno::Error::last()));
                    }
                }
            }

            // This sigset will be actually filled with `sigpending` call.
            let mut chkset: sigset_t = mem::zeroed();
            // See if more instances of the signal are pending.
            let ret = sigpending(&mut chkset);
            if ret < 0 {
                return Err(Error::ClearGetPending(errno::Error::last()));
            }

            let ret = sigismember(&chkset, num);
            if ret < 0 {
                return Err(Error::ClearCheckPending(errno::Error::last()));
            }

            // This is do-while loop condition.
            ret != 0
        }
    } {}

    Ok(())
}

/// Trait for threads that can be signalled via `pthread_kill`.
///
/// Note that this is only useful for signals between SIGRTMIN and SIGRTMAX because these are
/// guaranteed to not be used by the C runtime.
///
/// This is marked unsafe because the implementation of this trait must guarantee that the returned
/// pthread_t is valid and has a lifetime at least that of the trait object.
pub unsafe trait Killable {
    fn pthread_handle(&self) -> pthread_t;

    /// Sends the signal `num + SIGRTMIN` to this killable thread.
    ///
    /// The value of `num + SIGRTMIN` must not exceed `SIGRTMAX`.
    fn kill(&self, num: i32) -> errno::Result<()> {
        let num = validate_signal_num(num, true)?;

        // Safe because we ensure we are using a valid pthread handle, a valid signal number, and
        // check the return result.
        let ret = unsafe { pthread_kill(self.pthread_handle(), num) };
        if ret < 0 {
            return errno::errno_result();
        }
        Ok(())
    }
}

// Safe because we fulfill our contract of returning a genuine pthread handle.
unsafe impl<T> Killable for JoinHandle<T> {
    fn pthread_handle(&self) -> pthread_t {
        // JoinHandleExt::as_pthread_t gives c_ulong, convert it to the
        // type that the libc crate expects
        assert_eq!(mem::size_of::<pthread_t>(), mem::size_of::<usize>());
        self.as_pthread_t() as usize as pthread_t
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libc::SA_SIGINFO;
    use std::thread;
    use std::time::Duration;

    static mut SIGNAL_HANDLER_CALLED: bool = false;

    extern "C" fn handle_signal(_: c_int, _: *mut siginfo_t, _: *mut c_void) {
        unsafe {
            SIGNAL_HANDLER_CALLED = true;
        }
    }

    #[test]
    fn test_register_signal_handler() {
        unsafe {
            // testing bad value
            assert!(register_signal_handler(
                SIGRTMAX(),
                SignalHandler::Siginfo(handle_signal),
                true,
                SA_SIGINFO
            )
            .is_err());
            format!(
                "{:?}",
                register_signal_handler(
                    SIGRTMAX(),
                    SignalHandler::Siginfo(handle_signal),
                    true,
                    SA_SIGINFO
                )
            );
            assert!(register_signal_handler(
                0,
                SignalHandler::Siginfo(handle_signal),
                true,
                SA_SIGINFO
            )
            .is_ok());
            assert!(register_signal_handler(
                libc::SIGSYS,
                SignalHandler::Siginfo(handle_signal),
                false,
                SA_SIGINFO
            )
            .is_ok());
        }
    }

    #[test]
    #[allow(clippy::empty_loop)]
    fn test_killing_thread() {
        let killable = thread::spawn(|| thread::current().id());
        let killable_id = killable.join().unwrap();
        assert_ne!(killable_id, thread::current().id());

        // We install a signal handler for the specified signal; otherwise the whole process will
        // be brought down when the signal is received, as part of the default behaviour. Signal
        // handlers are global, so we install this before starting the thread.
        unsafe {
            register_signal_handler(0, SignalHandler::Siginfo(handle_signal), true, SA_SIGINFO)
                .expect("failed to register vcpu signal handler");
        }

        let killable = thread::spawn(|| loop {});

        let res = killable.kill(SIGRTMAX());
        assert!(res.is_err());
        format!("{:?}", res);

        unsafe {
            assert!(!SIGNAL_HANDLER_CALLED);
        }

        assert!(killable.kill(0).is_ok());

        // We're waiting to detect that the signal handler has been called.
        const MAX_WAIT_ITERS: u32 = 20;
        let mut iter_count = 0;
        loop {
            thread::sleep(Duration::from_millis(100));

            if unsafe { SIGNAL_HANDLER_CALLED } {
                break;
            }

            iter_count += 1;
            // timeout if we wait too long
            assert!(iter_count <= MAX_WAIT_ITERS);
        }

        // Our signal handler doesn't do anything which influences the killable thread, so the
        // previous signal is effectively ignored. If we were to join killable here, we would block
        // forever as the loop keeps running. Since we don't join, the thread will become detached
        // as the handle is dropped, and will be killed when the process/main thread exits.
    }
}
