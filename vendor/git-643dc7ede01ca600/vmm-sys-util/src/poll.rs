// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

use std::cell::{Cell, Ref, RefCell};
use std::cmp::min;
use std::fs::File;
use std::i32;
use std::i64;
use std::marker::PhantomData;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::ptr::null_mut;
use std::slice;
use std::thread;
use std::time::Duration;

use libc::{
    c_int, epoll_create1, epoll_ctl, epoll_event, epoll_wait, EINTR, EPOLLHUP, EPOLLIN, EPOLLOUT,
    EPOLL_CLOEXEC, EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLL_CTL_MOD,
};

use crate::{errno_result, Error, Result};

macro_rules! handle_eintr_errno {
    ($x:expr) => {{
        let mut res;
        loop {
            res = $x;
            if res != -1 || Error::last() != Error::new(EINTR) {
                break;
            }
        }
        res
    }};
}

const POLL_CONTEXT_MAX_EVENTS: usize = 16;

/// EpollEvents wraps raw epoll_events, it should only be used with EpollContext.
pub struct EpollEvents(RefCell<[epoll_event; POLL_CONTEXT_MAX_EVENTS]>);

impl EpollEvents {
    pub fn new() -> EpollEvents {
        EpollEvents(RefCell::new(
            [epoll_event { events: 0, u64: 0 }; POLL_CONTEXT_MAX_EVENTS],
        ))
    }
}

impl Default for EpollEvents {
    fn default() -> Self {
        Self::new()
    }
}

/// Trait for a token that can be associated with an `fd` in a `PollContext`.
///
/// Simple enums that have no or primitive variant data can use the `#[derive(PollToken)]`
/// custom derive to implement this trait.
pub trait PollToken {
    /// Converts this token into a u64 that can be turned back into a token via `from_raw_token`.
    fn as_raw_token(&self) -> u64;

    /// Converts a raw token as returned from `as_raw_token` back into a token.
    ///
    /// It is invalid to give a raw token that was not returned via `as_raw_token` from the same
    /// `Self`. The implementation can expect that this will never happen as a result of its usage
    /// in `PollContext`.
    fn from_raw_token(data: u64) -> Self;
}

impl PollToken for usize {
    fn as_raw_token(&self) -> u64 {
        *self as u64
    }

    fn from_raw_token(data: u64) -> Self {
        data as Self
    }
}

impl PollToken for u64 {
    fn as_raw_token(&self) -> u64 {
        *self as u64
    }

    fn from_raw_token(data: u64) -> Self {
        data as Self
    }
}

impl PollToken for u32 {
    fn as_raw_token(&self) -> u64 {
        u64::from(*self)
    }

    fn from_raw_token(data: u64) -> Self {
        data as Self
    }
}

impl PollToken for u16 {
    fn as_raw_token(&self) -> u64 {
        u64::from(*self)
    }

    fn from_raw_token(data: u64) -> Self {
        data as Self
    }
}

impl PollToken for u8 {
    fn as_raw_token(&self) -> u64 {
        u64::from(*self)
    }

    fn from_raw_token(data: u64) -> Self {
        data as Self
    }
}

impl PollToken for () {
    fn as_raw_token(&self) -> u64 {
        0
    }

    fn from_raw_token(_data: u64) -> Self {}
}

/// An event returned by `PollContext::wait`.
pub struct PollEvent<'a, T> {
    event: &'a epoll_event,
    token: PhantomData<T>, // Needed to satisfy usage of T
}

impl<'a, T: PollToken> PollEvent<'a, T> {
    /// Gets the token associated in `PollContext::add` with this event.
    pub fn token(&self) -> T {
        T::from_raw_token(self.event.u64)
    }

    /// True if the `fd` associated with this token in `PollContext::add` is readable.
    pub fn readable(&self) -> bool {
        self.event.events & (EPOLLIN as u32) != 0
    }

    /// True if the `fd` associated with this token in `PollContext::add` has been hungup on.
    pub fn hungup(&self) -> bool {
        self.event.events & (EPOLLHUP as u32) != 0
    }
}

/// An iterator over some (sub)set of events returned by `PollContext::wait`.
pub struct PollEventIter<'a, I, T>
where
    I: Iterator<Item = &'a epoll_event>,
{
    mask: u32,
    iter: I,
    tokens: PhantomData<[T]>, // Needed to satisfy usage of T
}

impl<'a, I, T> Iterator for PollEventIter<'a, I, T>
where
    I: Iterator<Item = &'a epoll_event>,
    T: PollToken,
{
    type Item = PollEvent<'a, T>;
    fn next(&mut self) -> Option<Self::Item> {
        let mask = self.mask;
        self.iter
            .find(|event| (event.events & mask) != 0)
            .map(|event| PollEvent {
                event,
                token: PhantomData,
            })
    }
}

/// The list of event returned by `PollContext::wait`.
pub struct PollEvents<'a, T> {
    count: usize,
    events: Ref<'a, [epoll_event; POLL_CONTEXT_MAX_EVENTS]>,
    tokens: PhantomData<[T]>, // Needed to satisfy usage of T
}

impl<'a, T: PollToken> PollEvents<'a, T> {
    /// Copies the events to an owned structure so the reference to this (and by extension
    /// `PollContext`) can be dropped.
    pub fn to_owned(&self) -> PollEventsOwned<T> {
        PollEventsOwned {
            count: self.count,
            events: RefCell::new(*self.events),
            tokens: PhantomData,
        }
    }

    /// Iterates over each event.
    pub fn iter(&self) -> PollEventIter<slice::Iter<epoll_event>, T> {
        PollEventIter {
            mask: 0xffff_ffff,
            iter: self.events[..self.count].iter(),
            tokens: PhantomData,
        }
    }

    /// Iterates over each readable event.
    pub fn iter_readable(&self) -> PollEventIter<slice::Iter<epoll_event>, T> {
        PollEventIter {
            mask: EPOLLIN as u32,
            iter: self.events[..self.count].iter(),
            tokens: PhantomData,
        }
    }

    /// Iterates over each hungup event.
    pub fn iter_hungup(&self) -> PollEventIter<slice::Iter<epoll_event>, T> {
        PollEventIter {
            mask: EPOLLHUP as u32,
            iter: self.events[..self.count].iter(),
            tokens: PhantomData,
        }
    }
}

/// A deep copy of the event records from `PollEvents`.
pub struct PollEventsOwned<T> {
    count: usize,
    events: RefCell<[epoll_event; POLL_CONTEXT_MAX_EVENTS]>,
    tokens: PhantomData<T>, // Needed to satisfy usage of T
}

impl<T: PollToken> PollEventsOwned<T> {
    /// Takes a reference to the events so that they can be iterated via methods in `PollEvents`.
    pub fn as_ref(&self) -> PollEvents<T> {
        PollEvents {
            count: self.count,
            events: self.events.borrow(),
            tokens: PhantomData,
        }
    }
}

/// Watching events taken by PollContext.
pub struct WatchingEvents(u32);

impl WatchingEvents {
    /// Returns empty Events.
    #[inline(always)]
    pub fn empty() -> WatchingEvents {
        WatchingEvents(0)
    }

    /// Build Events from raw epoll events (defined in epoll_ctl(2)).
    #[inline(always)]
    pub fn new(raw: u32) -> WatchingEvents {
        WatchingEvents(raw)
    }

    /// Set read events.
    #[inline(always)]
    pub fn set_read(self) -> WatchingEvents {
        WatchingEvents(self.0 | EPOLLIN as u32)
    }

    /// Set write events.
    #[inline(always)]
    pub fn set_write(self) -> WatchingEvents {
        WatchingEvents(self.0 | EPOLLOUT as u32)
    }

    /// Get the underlying epoll events.
    pub fn get_raw(&self) -> u32 {
        self.0
    }
}

/// EpollContext wraps linux epoll. It provides similar interface to PollContext.
/// It is thread safe while PollContext is not. It requires user to pass in a reference of
/// EpollEvents while PollContext does not. Always use PollContext if you don't need to access the
/// same epoll from different threads.
pub struct EpollContext<T> {
    epoll_ctx: File,
    // Needed to satisfy usage of T
    tokens: PhantomData<[T]>,
}

impl<T: PollToken> EpollContext<T> {
    /// Creates a new `EpollContext`.
    pub fn new() -> Result<EpollContext<T>> {
        // Safe because we check the return value.
        let epoll_fd = unsafe { epoll_create1(EPOLL_CLOEXEC) };
        if epoll_fd < 0 {
            return errno_result();
        }
        Ok(EpollContext {
            epoll_ctx: unsafe { File::from_raw_fd(epoll_fd) },
            tokens: PhantomData,
        })
    }

    /// Adds the given `fd` to this context and associates the given `token` with the `fd`'s
    /// readable events.
    ///
    /// A `fd` can only be added once and does not need to be kept open. If the `fd` is dropped and
    /// there were no duplicated file descriptors (i.e. adding the same descriptor with a different
    /// FD number) added to this context, events will not be reported by `wait` anymore.
    pub fn add(&self, fd: &AsRawFd, token: T) -> Result<()> {
        self.add_fd_with_events(fd, WatchingEvents::empty().set_read(), token)
    }

    /// Adds the given `fd` to this context, watching for the specified events and associates the
    /// given 'token' with those events.
    ///
    /// A `fd` can only be added once and does not need to be kept open. If the `fd` is dropped and
    /// there were no duplicated file descriptors (i.e. adding the same descriptor with a different
    /// FD number) added to this context, events will not be reported by `wait` anymore.
    pub fn add_fd_with_events(&self, fd: &AsRawFd, events: WatchingEvents, token: T) -> Result<()> {
        let mut evt = epoll_event {
            events: events.get_raw(),
            u64: token.as_raw_token(),
        };
        // Safe because we give a valid epoll FD and FD to watch, as well as a valid epoll_event
        // structure. Then we check the return value.
        let ret = unsafe {
            epoll_ctl(
                self.epoll_ctx.as_raw_fd(),
                EPOLL_CTL_ADD,
                fd.as_raw_fd(),
                &mut evt,
            )
        };
        if ret < 0 {
            return errno_result();
        };
        Ok(())
    }

    /// If `fd` was previously added to this context, the watched events will be replaced with
    /// `events` and the token associated with it will be replaced with the given `token`.
    pub fn modify(&self, fd: &AsRawFd, events: WatchingEvents, token: T) -> Result<()> {
        let mut evt = epoll_event {
            events: events.0,
            u64: token.as_raw_token(),
        };
        // Safe because we give a valid epoll FD and FD to modify, as well as a valid epoll_event
        // structure. Then we check the return value.
        let ret = unsafe {
            epoll_ctl(
                self.epoll_ctx.as_raw_fd(),
                EPOLL_CTL_MOD,
                fd.as_raw_fd(),
                &mut evt,
            )
        };
        if ret < 0 {
            return errno_result();
        };
        Ok(())
    }

    /// Deletes the given `fd` from this context.
    ///
    /// If an `fd`'s token shows up in the list of hangup events, it should be removed using this
    /// method or by closing/dropping (if and only if the fd was never dup()'d/fork()'d) the `fd`.
    /// Failure to do so will cause the `wait` method to always return immediately, causing ~100%
    /// CPU load.
    pub fn delete(&self, fd: &AsRawFd) -> Result<()> {
        // Safe because we give a valid epoll FD and FD to stop watching. Then we check the return
        // value.
        let ret = unsafe {
            epoll_ctl(
                self.epoll_ctx.as_raw_fd(),
                EPOLL_CTL_DEL,
                fd.as_raw_fd(),
                null_mut(),
            )
        };
        if ret < 0 {
            return errno_result();
        };
        Ok(())
    }

    /// Waits for any events to occur in FDs that were previously added to this context.
    ///
    /// The events are level-triggered, meaning that if any events are unhandled (i.e. not reading
    /// for readable events and not closing for hungup events), subsequent calls to `wait` will
    /// return immediately. The consequence of not handling an event perpetually while calling
    /// `wait` is that the callers loop will degenerated to busy loop polling, pinning a CPU to
    /// ~100% usage.
    pub fn wait<'a>(&self, events: &'a EpollEvents) -> Result<PollEvents<'a, T>> {
        self.wait_timeout(events, Duration::new(i64::MAX as u64, 0))
    }

    /// Like `wait` except will only block for a maximum of the given `timeout`.
    ///
    /// This may return earlier than `timeout` with zero events if the duration indicated exceeds
    /// system limits.
    pub fn wait_timeout<'a>(
        &self,
        events: &'a EpollEvents,
        timeout: Duration,
    ) -> Result<PollEvents<'a, T>> {
        let timeout_millis = if timeout.as_secs() as i64 == i64::max_value() {
            // We make the convenient assumption that 2^63 seconds is an effectively unbounded time
            // frame. This is meant to mesh with `wait` calling us with no timeout.
            -1
        } else {
            // In cases where we the number of milliseconds would overflow an i32, we substitute the
            // maximum timeout which is ~24.8 days.
            let millis = timeout
                .as_secs()
                .checked_mul(1_000)
                .and_then(|ms| ms.checked_add(u64::from(timeout.subsec_nanos()) / 1_000_000))
                .unwrap_or(i32::max_value() as u64);
            min(i32::max_value() as u64, millis) as i32
        };
        let ret = {
            let mut epoll_events = events.0.borrow_mut();
            let max_events = epoll_events.len() as c_int;
            // Safe because we give an epoll context and a properly sized epoll_events array
            // pointer, which we trust the kernel to fill in properly.
            unsafe {
                handle_eintr_errno!(epoll_wait(
                    self.epoll_ctx.as_raw_fd(),
                    &mut epoll_events[0],
                    max_events,
                    timeout_millis
                ))
            }
        };
        if ret < 0 {
            return errno_result();
        }
        let epoll_events = events.0.borrow();
        let events = PollEvents {
            count: ret as usize,
            events: epoll_events,
            tokens: PhantomData,
        };
        Ok(events)
    }
}

impl<T: PollToken> AsRawFd for EpollContext<T> {
    fn as_raw_fd(&self) -> RawFd {
        self.epoll_ctx.as_raw_fd()
    }
}

impl<T: PollToken> IntoRawFd for EpollContext<T> {
    fn into_raw_fd(self) -> RawFd {
        self.epoll_ctx.into_raw_fd()
    }
}

/// Used to poll multiple objects that have file descriptors.
///
/// # Example
///
/// ```
/// # use vmm_sys_util::{Result, EventFd, PollContext, PollEvents};
/// # fn test() -> Result<()> {
///     let evt1 = EventFd::new(0)?;
///     let evt2 = EventFd::new(0)?;
///     evt2.write(1)?;
///
///     let ctx: PollContext<u32> = PollContext::new()?;
///     ctx.add(&evt1, 1)?;
///     ctx.add(&evt2, 2)?;
///
///     let pollevents: PollEvents<u32> = ctx.wait()?;
///     let tokens: Vec<u32> = pollevents.iter_readable().map(|e| e.token()).collect();
///     assert_eq!(&tokens[..], &[2]);
/// #   Ok(())
/// # }
/// ```
pub struct PollContext<T> {
    epoll_ctx: EpollContext<T>,

    // We use a RefCell here so that the `wait` method only requires an immutable self reference
    // while returning the events (encapsulated by PollEvents). Without the RefCell, `wait` would
    // hold a mutable reference that lives as long as its returned reference (i.e. the PollEvents),
    // even though that reference is immutable. This is terribly inconvenient for the caller because
    // the borrow checking would prevent them from using `delete` and `add` while the events are in
    // scope.
    events: EpollEvents,

    // Hangup busy loop detection variables. See `check_for_hungup_busy_loop`.
    hangups: Cell<usize>,
    max_hangups: Cell<usize>,
}

impl<T: PollToken> PollContext<T> {
    /// Creates a new `PollContext`.
    pub fn new() -> Result<PollContext<T>> {
        Ok(PollContext {
            epoll_ctx: EpollContext::new()?,
            events: EpollEvents::new(),
            hangups: Cell::new(0),
            max_hangups: Cell::new(0),
        })
    }

    /// Adds the given `fd` to this context and associates the given `token` with the `fd`'s
    /// readable events.
    ///
    /// A `fd` can only be added once and does not need to be kept open. If the `fd` is dropped and
    /// there were no duplicated file descriptors (i.e. adding the same descriptor with a different
    /// FD number) added to this context, events will not be reported by `wait` anymore.
    pub fn add(&self, fd: &AsRawFd, token: T) -> Result<()> {
        self.add_fd_with_events(fd, WatchingEvents::empty().set_read(), token)
    }

    /// Adds the given `fd` to this context, watching for the specified events and associates the
    /// given 'token' with those events.
    ///
    /// A `fd` can only be added once and does not need to be kept open. If the `fd` is dropped and
    /// there were no duplicated file descriptors (i.e. adding the same descriptor with a different
    /// FD number) added to this context, events will not be reported by `wait` anymore.
    pub fn add_fd_with_events(&self, fd: &AsRawFd, events: WatchingEvents, token: T) -> Result<()> {
        self.epoll_ctx.add_fd_with_events(fd, events, token)?;
        self.hangups.set(0);
        self.max_hangups.set(self.max_hangups.get() + 1);
        Ok(())
    }

    /// If `fd` was previously added to this context, the watched events will be replaced with
    /// `events` and the token associated with it will be replaced with the given `token`.
    pub fn modify(&self, fd: &AsRawFd, events: WatchingEvents, token: T) -> Result<()> {
        self.epoll_ctx.modify(fd, events, token)
    }

    /// Deletes the given `fd` from this context.
    ///
    /// If an `fd`'s token shows up in the list of hangup events, it should be removed using this
    /// method or by closing/dropping (if and only if the fd was never dup()'d/fork()'d) the `fd`.
    /// Failure to do so will cause the `wait` method to always return immediately, causing ~100%
    /// CPU load.
    pub fn delete(&self, fd: &AsRawFd) -> Result<()> {
        self.epoll_ctx.delete(fd)?;
        self.hangups.set(0);
        self.max_hangups.set(self.max_hangups.get() - 1);
        Ok(())
    }

    // This method determines if the the user of wait is misusing the `PollContext` by leaving FDs
    // in this `PollContext` that have been shutdown or hungup on. Such an FD will cause `wait` to
    // return instantly with a hungup event. If that FD is perpetually left in this context, a busy
    // loop burning ~100% of one CPU will silently occur with no human visible malfunction.
    //
    // How do we know if the client of this context is ignoring hangups? A naive implementation
    // would trigger if consecutive wait calls yield hangup events, but there are legitimate cases
    // for this, such as two distinct sockets becoming hungup across two consecutive wait calls. A
    // smarter implementation would only trigger if `delete` wasn't called between waits that
    // yielded hangups. Sadly `delete` isn't the only way to remove an FD from this context. The
    // other way is for the client to close the hungup FD, which automatically removes it from this
    // context. Assuming that the client always uses close, this implementation would too eagerly
    // trigger.
    //
    // The implementation used here keeps an upper bound of FDs in this context using a counter
    // hooked into add/delete (which is imprecise because close can also remove FDs without us
    // knowing). The number of consecutive (no add or delete in between) hangups yielded by wait
    // calls is counted and compared to the upper bound. If the upper bound is exceeded by the
    // consecutive hangups, the implementation triggers the check and logs.
    //
    // This implementation has false negatives because the upper bound can be completely too high,
    // in the worst case caused by only using close instead of delete. However, this method has the
    // advantage of always triggering eventually genuine busy loop cases, requires no dynamic
    // allocations, is fast and constant time to compute, and has no false positives.
    fn check_for_hungup_busy_loop(&self, new_hangups: usize) {
        let old_hangups = self.hangups.get();
        let max_hangups = self.max_hangups.get();
        if old_hangups <= max_hangups && old_hangups + new_hangups > max_hangups {
            warn!(
                "busy poll wait loop with hungup FDs detected on thread {}",
                thread::current().name().unwrap_or("")
            );
            // This panic is helpful for tests of this functionality.
            #[cfg(test)]
            panic!("hungup busy loop detected");
        }
        self.hangups.set(old_hangups + new_hangups);
    }

    /// Waits for any events to occur in FDs that were previously added to this context.
    ///
    /// The events are level-triggered, meaning that if any events are unhandled (i.e. not reading
    /// for readable events and not closing for hungup events), subsequent calls to `wait` will
    /// return immediately. The consequence of not handling an event perpetually while calling
    /// `wait` is that the callers loop will degenerated to busy loop polling, pinning a CPU to
    /// ~100% usage.
    ///
    /// # Panics
    /// Panics if the returned `PollEvents` structure is not dropped before subsequent `wait` calls.
    pub fn wait(&self) -> Result<PollEvents<T>> {
        self.wait_timeout(Duration::new(i64::MAX as u64, 0))
    }

    /// Like `wait` except will only block for a maximum of the given `timeout`.
    ///
    /// This may return earlier than `timeout` with zero events if the duration indicated exceeds
    /// system limits.
    pub fn wait_timeout(&self, timeout: Duration) -> Result<PollEvents<T>> {
        let events = self.epoll_ctx.wait_timeout(&self.events, timeout)?;
        let hangups = events.iter_hungup().count();
        self.check_for_hungup_busy_loop(hangups);
        Ok(events)
    }
}

impl<T: PollToken> AsRawFd for PollContext<T> {
    fn as_raw_fd(&self) -> RawFd {
        self.epoll_ctx.as_raw_fd()
    }
}

impl<T: PollToken> IntoRawFd for PollContext<T> {
    fn into_raw_fd(self) -> RawFd {
        self.epoll_ctx.into_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eventfd::EventFd;
    use std::os::unix::net::UnixStream;
    use std::time::Instant;

    #[test]
    fn test_poll_context() {
        let evt1 = EventFd::new(0).unwrap();
        let evt2 = EventFd::new(0).unwrap();
        evt1.write(1).unwrap();
        evt2.write(1).unwrap();
        let ctx: PollContext<u32> = PollContext::new().unwrap();
        ctx.add(&evt1, 1).unwrap();
        ctx.add(&evt2, 2).unwrap();

        let mut evt_count = 0;
        while evt_count < 2 {
            for event in ctx.wait().unwrap().iter_readable() {
                evt_count += 1;
                match event.token() {
                    1 => {
                        evt1.read().unwrap();
                        ctx.delete(&evt1).unwrap();
                    }
                    2 => {
                        evt2.read().unwrap();
                        ctx.delete(&evt2).unwrap();
                    }
                    _ => panic!("unexpected token"),
                };
            }
        }
        assert_eq!(evt_count, 2);
    }

    #[test]
    fn test_poll_context_overflow() {
        const EVT_COUNT: usize = POLL_CONTEXT_MAX_EVENTS * 2 + 1;
        let ctx: PollContext<usize> = PollContext::new().unwrap();
        let mut evts = Vec::with_capacity(EVT_COUNT);
        for i in 0..EVT_COUNT {
            let evt = EventFd::new(0).unwrap();
            evt.write(1).unwrap();
            ctx.add(&evt, i).unwrap();
            evts.push(evt);
        }
        let mut evt_count = 0;
        while evt_count < EVT_COUNT {
            for event in ctx.wait().unwrap().iter_readable() {
                evts[event.token()].read().unwrap();
                evt_count += 1;
            }
        }
    }

    #[test]
    #[should_panic]
    fn test_poll_context_hungup() {
        let (s1, s2) = UnixStream::pair().unwrap();
        let ctx: PollContext<u32> = PollContext::new().unwrap();
        ctx.add(&s1, 1).unwrap();

        // Causes s1 to receive hangup events, which we purposefully ignore to trip the detection
        // logic in `PollContext`.
        drop(s2);

        // Should easily panic within this many iterations.
        for _ in 0..1000 {
            ctx.wait().unwrap();
        }
    }

    #[test]
    fn test_poll_context_timeout() {
        let ctx: PollContext<u32> = PollContext::new().unwrap();
        let dur = Duration::from_millis(10);
        let start_inst = Instant::now();
        ctx.wait_timeout(dur).unwrap();
        assert!(start_inst.elapsed() >= dur);
    }

}
