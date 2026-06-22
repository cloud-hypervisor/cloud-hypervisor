//! Phase 1 portability primitive: a macOS `EventFd` shim.
//!
//! Cloud Hypervisor uses `vmm-sys-util::EventFd` (Linux `eventfd(2)`) in ~85
//! files for irqfd/ioeventfd and device signalling. macOS has no `eventfd`, so
//! the port needs a drop-in replacement with the same counter semantics that is
//! also pollable via `kqueue`. This implements that with a self-pipe plus an
//! atomic counter, mirroring the subset of the `vmm-sys-util` API the VMM uses.
//!
//! Semantics (non-semaphore eventfd): `write(v)` adds `v` to the counter;
//! `read()` returns the accumulated value and resets it to zero, returning
//! `WouldBlock` when the counter is zero. The underlying read fd becomes
//! readable exactly when the counter is non-zero, so it integrates with an
//! event loop just like a real eventfd.
#![allow(dead_code)]

use std::io;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const O_NONBLOCK: i32 = 0x0004;
const O_CLOEXEC: i32 = 0x0100_0000;
const F_SETFL: i32 = 4;

unsafe extern "C" {
    fn pipe(fds: *mut i32) -> i32;
    fn read(fd: i32, buf: *mut core::ffi::c_void, n: usize) -> isize;
    fn write(fd: i32, buf: *const core::ffi::c_void, n: usize) -> isize;
    fn close(fd: i32) -> i32;
    fn fcntl(fd: i32, cmd: i32, arg: i32) -> i32;
    fn dup(fd: i32) -> i32;
}

pub const EFD_NONBLOCK: i32 = O_NONBLOCK;

struct Inner {
    rd: RawFd,
    wr: RawFd,
    count: AtomicU64,
}

impl Drop for Inner {
    fn drop(&mut self) {
        // SAFETY: we own these fds.
        unsafe {
            close(self.rd);
            close(self.wr);
        }
    }
}

#[derive(Clone)]
pub struct EventFd {
    inner: Arc<Inner>,
}

impl EventFd {
    pub fn new(flags: i32) -> io::Result<EventFd> {
        let mut fds = [0i32; 2];
        // SAFETY: `fds` is a valid 2-element array.
        if unsafe { pipe(fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let (rd, wr) = (fds[0], fds[1]);
        // Read end non-blocking so read() can drain without blocking; honor
        // EFD_NONBLOCK on both ends, always set CLOEXEC.
        let rd_flags = O_NONBLOCK | O_CLOEXEC;
        let wr_flags = (flags & O_NONBLOCK) | O_CLOEXEC;
        // SAFETY: FFI on fds we own.
        unsafe {
            fcntl(rd, F_SETFL, rd_flags);
            fcntl(wr, F_SETFL, wr_flags);
        }
        Ok(EventFd {
            inner: Arc::new(Inner {
                rd,
                wr,
                count: AtomicU64::new(0),
            }),
        })
    }

    /// Add `v` to the counter and make the read end readable.
    pub fn write(&self, v: u64) -> io::Result<()> {
        if v == 0 {
            return Ok(());
        }
        let prev = self.inner.count.fetch_add(v, Ordering::SeqCst);
        if prev == 0 {
            // Transition empty -> non-empty: push one byte so pollers wake up.
            let b = [1u8; 1];
            // SAFETY: writing 1 byte from a valid buffer to our pipe.
            let n = unsafe { write(self.inner.wr, b.as_ptr() as *const _, 1) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() != io::ErrorKind::WouldBlock {
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// Return the accumulated counter and reset to zero, or `WouldBlock`.
    pub fn read(&self) -> io::Result<u64> {
        // Drain any wake-up bytes (non-blocking).
        let mut buf = [0u8; 64];
        loop {
            // SAFETY: reading into a valid local buffer from our pipe.
            let n = unsafe { read(self.inner.rd, buf.as_mut_ptr() as *mut _, buf.len()) };
            if n <= 0 {
                break;
            }
        }
        let v = self.inner.count.swap(0, Ordering::SeqCst);
        if v == 0 {
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        } else {
            Ok(v)
        }
    }

    /// Duplicate the handle (shares the counter), like `EventFd::try_clone`.
    pub fn try_clone(&self) -> io::Result<EventFd> {
        Ok(EventFd {
            inner: self.inner.clone(),
        })
    }

    /// Raw read fd, for registering with a `kqueue`-based event loop.
    pub fn as_raw_fd(&self) -> RawFd {
        self.inner.rd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_accumulates_and_resets() {
        let efd = EventFd::new(EFD_NONBLOCK).unwrap();
        efd.write(3).unwrap();
        efd.write(4).unwrap();
        assert_eq!(efd.read().unwrap(), 7);
        // Drained: next read would block.
        assert!(efd.read().is_err());
    }

    #[test]
    fn clone_shares_counter() {
        let a = EventFd::new(EFD_NONBLOCK).unwrap();
        let b = a.try_clone().unwrap();
        a.write(10).unwrap();
        // Reading via the clone observes the same counter.
        assert_eq!(b.read().unwrap(), 10);
    }
}
