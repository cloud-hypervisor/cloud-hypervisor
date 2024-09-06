// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2023 Crusoe Energy Systems LLC
// SPDX-License-Identifier: Apache-2.0

use crate::{RateLimiter, TokenType};
use core::panic::AssertUnwindSafe;
use std::fs::File;
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::result;
use std::sync::{Arc, Mutex};
use std::thread;
use thiserror::Error;
use vmm_sys_util::eventfd::EventFd;

/// Errors associated with rate-limiter group.
#[derive(Debug, Error)]
pub enum Error {
    /// Cannot create thread
    #[error("Error spawning rate-limiter thread {0}")]
    ThreadSpawn(#[source] io::Error),

    /// Cannot create epoll context.
    #[error("Error creating epoll context: {0}")]
    Epoll(#[source] io::Error),

    /// Cannot create EventFd.
    #[error("Error creating EventFd: {0}")]
    EventFd(#[source] io::Error),

    /// Cannot create RateLimiter.
    #[error("Error creating RateLimiter: {0}")]
    RateLimiter(#[source] io::Error),

    /// Cannot read from EventFd.
    #[error("Error reading from EventFd: {0}")]
    EventFdRead(#[source] io::Error),

    /// Cannot write to EventFd.
    #[error("Error writing to EventFd: {0}")]
    EventFdWrite(#[source] io::Error),
}

/// Handle to a RateLimiterGroup
///
/// The RateLimiterGroupHandle may be used in exactly the same way as
/// the RateLimiter type. When the RateLimiter within a RateLimiterGroup
/// is unblocked, each RateLimiterGroupHandle will be notified.
pub struct RateLimiterGroupHandle {
    eventfd: Arc<EventFd>,
    inner: Arc<RateLimiterGroupInner>,
}

impl RateLimiterGroupHandle {
    fn new(inner: Arc<RateLimiterGroupInner>) -> result::Result<Self, Error> {
        let eventfd = Arc::new(EventFd::new(0).map_err(Error::EventFd)?);
        inner.handles.lock().unwrap().push(eventfd.clone());
        Ok(Self { eventfd, inner })
    }

    /// Attempts to consume tokens and returns whether that is possible.
    ///
    /// If rate limiting is disabled on provided `token_type`, this function will always succeed.
    pub fn consume(&self, tokens: u64, token_type: TokenType) -> bool {
        self.inner.rate_limiter.consume(tokens, token_type)
    }

    /// Adds tokens of `token_type` to their respective bucket.
    ///
    /// Can be used to *manually* add tokens to a bucket. Useful for reverting a
    /// `consume()` if needed.
    pub fn manual_replenish(&self, tokens: u64, token_type: TokenType) {
        self.inner.rate_limiter.manual_replenish(tokens, token_type)
    }

    /// This function needs to be called every time there is an event on the
    /// FD provided by this object's `AsRawFd` trait implementation.
    ///
    /// # Errors
    ///
    /// If the rate limiter is disabled or is not blocked, an error is returned.
    pub fn event_handler(&self) -> Result<(), Error> {
        self.eventfd.read().map_err(Error::EventFdRead).map(|_| ())
    }

    /// Returns whether this rate limiter is blocked.
    ///
    /// The limiter 'blocks' when a `consume()` operation fails because there was not enough
    /// budget for it.
    /// An event will be generated on the exported FD when the limiter 'unblocks'.
    pub fn is_blocked(&self) -> bool {
        self.inner.rate_limiter.is_blocked()
    }
}

impl Clone for RateLimiterGroupHandle {
    fn clone(&self) -> Self {
        RateLimiterGroupHandle::new(self.inner.clone()).unwrap()
    }
}

impl AsRawFd for RateLimiterGroupHandle {
    fn as_raw_fd(&self) -> RawFd {
        self.eventfd.as_raw_fd()
    }
}

impl Drop for RateLimiterGroupHandle {
    fn drop(&mut self) {
        let mut handles = self.inner.handles.lock().unwrap();
        let index = handles
            .iter()
            .position(|handle| handle.as_raw_fd() == self.eventfd.as_raw_fd())
            .expect("RateLimiterGroupHandle must be subscribed to RateLimiterGroup");
        handles.remove(index);
    }
}

struct RateLimiterGroupInner {
    id: String,
    rate_limiter: RateLimiter,
    handles: Mutex<Vec<Arc<EventFd>>>,
}

/// A RateLimiterGroup is an extension of RateLimiter that enables rate-limiting
/// the aggregate io consumption of multiple consumers.
pub struct RateLimiterGroup {
    inner: Arc<RateLimiterGroupInner>,
    epoll_file: File,
    kill_evt: EventFd,
    epoll_thread: Option<thread::JoinHandle<()>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
enum EpollDispatch {
    Kill = 1,
    Unblocked = 2,
    Unknown,
}

impl From<u64> for EpollDispatch {
    fn from(v: u64) -> Self {
        use EpollDispatch::*;
        match v {
            1 => Kill,
            2 => Unblocked,
            _ => Unknown,
        }
    }
}

impl RateLimiterGroup {
    /// Create a new RateLimiterGroup.
    pub fn new(
        id: &str,
        bytes_total_capacity: u64,
        bytes_one_time_burst: u64,
        bytes_complete_refill_time_ms: u64,
        ops_total_capacity: u64,
        ops_one_time_burst: u64,
        ops_complete_refill_time_ms: u64,
    ) -> result::Result<Self, Error> {
        let rate_limiter = RateLimiter::new(
            bytes_total_capacity,
            bytes_one_time_burst,
            bytes_complete_refill_time_ms,
            ops_total_capacity,
            ops_one_time_burst,
            ops_complete_refill_time_ms,
        )
        .map_err(Error::RateLimiter)?;

        let epoll_fd = epoll::create(true).map_err(Error::Epoll)?;
        let kill_evt = EventFd::new(0).map_err(Error::EventFd)?;

        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            kill_evt.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, EpollDispatch::Kill as u64),
        )
        .map_err(Error::Epoll)?;

        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            rate_limiter.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, EpollDispatch::Unblocked as u64),
        )
        .map_err(Error::Epoll)?;

        // Use 'File' to enforce closing on 'epoll_fd'
        // SAFETY: epoll_fd is valid
        let epoll_file = unsafe { File::from_raw_fd(epoll_fd) };

        Ok(Self {
            inner: Arc::new(RateLimiterGroupInner {
                id: id.to_string(),
                rate_limiter,
                handles: Mutex::new(Vec::new()),
            }),
            epoll_file,
            kill_evt,
            epoll_thread: None,
        })
    }

    /// Create a new RateLimiterGroupHandle.
    pub fn new_handle(&self) -> result::Result<RateLimiterGroupHandle, Error> {
        RateLimiterGroupHandle::new(self.inner.clone())
    }

    /// Start a worker thread to broadcast an event to each RateLimiterGroupHandle
    /// when the RateLimiter becomes unblocked.
    pub fn start_thread(&mut self, exit_evt: EventFd) -> result::Result<(), Error> {
        let inner = self.inner.clone();
        let epoll_fd = self.epoll_file.as_raw_fd();
        thread::Builder::new()
            .name(format!("rate-limit-group-{}", inner.id))
            .spawn(move || {
                let res = std::panic::catch_unwind(AssertUnwindSafe(move || {
                    const EPOLL_EVENTS_LEN: usize = 2;

                    let mut events =
                        [epoll::Event::new(epoll::Events::empty(), 0); EPOLL_EVENTS_LEN];

                    loop {
                        let num_events = match epoll::wait(epoll_fd, -1, &mut events[..]) {
                            Ok(res) => res,
                            Err(e) => {
                                if e.kind() == io::ErrorKind::Interrupted {
                                    continue;
                                } else {
                                    return Err(Error::Epoll(e));
                                }
                            }
                        };

                        for event in events.iter().take(num_events) {
                            let dispatch_event: EpollDispatch = event.data.into();
                            match dispatch_event {
                                EpollDispatch::Unknown => {
                                    let event = event.data;
                                    warn!("Unknown rate-limiter loop event: {}", event);
                                }
                                EpollDispatch::Unblocked => {
                                    inner.rate_limiter.event_handler().unwrap();
                                    let handles = inner.handles.lock().unwrap();
                                    for handle in handles.iter() {
                                        handle.write(1).map_err(Error::EventFdWrite)?
                                    }
                                }
                                EpollDispatch::Kill => {
                                    info!(
                                        "KILL_EVENT received, stopping rate-limit-group epoll loop"
                                    );
                                    return Ok(());
                                }
                            }
                        }
                    }
                }));

                match res {
                    Ok(res) => {
                        if let Err(e) = res {
                            error!("Error running rate-limit-group worker: {:?}", e);
                            exit_evt.write(1).unwrap();
                        }
                    }
                    Err(_) => {
                        error!("rate-limit-group worker panicked");
                        exit_evt.write(1).unwrap();
                    }
                };
            })
            .map(|thread| self.epoll_thread.insert(thread))
            .map_err(Error::ThreadSpawn)?;

        Ok(())
    }
}

impl Drop for RateLimiterGroup {
    fn drop(&mut self) {
        self.kill_evt.write(1).unwrap();

        if let Some(t) = self.epoll_thread.take() {
            if let Err(e) = t.join() {
                error!("Error joining thread: {:?}", e);
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::RateLimiterGroupHandle;
    use crate::{group::RateLimiterGroup, TokenBucket, TokenType, REFILL_TIMER_INTERVAL_MS};
    use std::{os::fd::AsRawFd, thread, time::Duration};
    use vmm_sys_util::eventfd::EventFd;

    impl RateLimiterGroupHandle {
        pub fn bandwidth(&self) -> Option<TokenBucket> {
            let guard = self.inner.rate_limiter.inner.lock().unwrap();
            guard.bandwidth.clone()
        }

        pub fn ops(&self) -> Option<TokenBucket> {
            let guard = self.inner.rate_limiter.inner.lock().unwrap();
            guard.ops.clone()
        }
    }

    #[test]
    fn test_rate_limiter_group_new() {
        let l = RateLimiterGroup::new("test", 1000, 1001, 1002, 1003, 1004, 1005).unwrap();
        let h = l.new_handle().unwrap();
        let bw = h.bandwidth().unwrap();
        assert_eq!(bw.capacity(), 1000);
        assert_eq!(bw.one_time_burst(), 1001);
        assert_eq!(bw.refill_time_ms(), 1002);
        assert_eq!(bw.budget(), 1000);

        let ops = h.ops().unwrap();
        assert_eq!(ops.capacity(), 1003);
        assert_eq!(ops.one_time_burst(), 1004);
        assert_eq!(ops.refill_time_ms(), 1005);
        assert_eq!(ops.budget(), 1003);
    }

    #[test]
    fn test_rate_limiter_group_manual_replenish() {
        // rate limiter with limit of 1000 bytes/s and 1000 ops/s
        let l = RateLimiterGroup::new("test", 1000, 0, 1000, 1000, 0, 1000).unwrap();
        let h = l.new_handle().unwrap();

        // consume 123 bytes
        assert!(h.consume(123, TokenType::Bytes));
        h.manual_replenish(23, TokenType::Bytes);
        {
            let bytes_tb = h.bandwidth().unwrap();
            assert_eq!(bytes_tb.budget(), 900);
        }
        // consume 123 ops
        assert!(h.consume(123, TokenType::Ops));
        h.manual_replenish(23, TokenType::Ops);
        {
            let bytes_tb = h.ops().unwrap();
            assert_eq!(bytes_tb.budget(), 900);
        }
    }

    #[test]
    fn test_rate_limiter_group_bandwidth() {
        // rate limiter with limit of 1000 bytes/s
        let mut l = RateLimiterGroup::new("test", 1000, 0, 1000, 0, 0, 0).unwrap();
        l.start_thread(EventFd::new(0).unwrap()).unwrap();

        let h = l.new_handle().unwrap();

        // limiter should not be blocked
        assert!(!h.is_blocked());
        // raw FD for this disabled should be valid
        assert!(h.as_raw_fd() > 0);

        // ops/s limiter should be disabled so consume(whatever) should work
        assert!(h.consume(u64::MAX, TokenType::Ops));

        // do full 1000 bytes
        assert!(h.consume(1000, TokenType::Bytes));
        // try and fail on another 100
        assert!(!h.consume(100, TokenType::Bytes));
        // since consume failed, limiter should be blocked now
        assert!(h.is_blocked());
        // wait half the timer period
        thread::sleep(Duration::from_millis(REFILL_TIMER_INTERVAL_MS / 2));
        // limiter should still be blocked
        assert!(h.is_blocked());
        // wait the other half of the timer period
        thread::sleep(Duration::from_millis(REFILL_TIMER_INTERVAL_MS / 2));
        // the timer_fd should have an event on it by now
        assert!(h.event_handler().is_ok());
        // limiter should now be unblocked
        assert!(!h.is_blocked());
        // try and succeed on another 100 bytes this time
        assert!(h.consume(100, TokenType::Bytes));
    }

    #[test]
    fn test_rate_limiter_group_ops() {
        // rate limiter with limit of 1000 ops/s
        let mut l = RateLimiterGroup::new("test", 0, 0, 0, 1000, 0, 1000).unwrap();
        l.start_thread(EventFd::new(0).unwrap()).unwrap();

        let h = l.new_handle().unwrap();

        // limiter should not be blocked
        assert!(!h.is_blocked());
        // raw FD for this disabled should be valid
        assert!(h.as_raw_fd() > 0);

        // bytes/s limiter should be disabled so consume(whatever) should work
        assert!(h.consume(u64::MAX, TokenType::Bytes));

        // do full 1000 ops
        assert!(h.consume(1000, TokenType::Ops));
        // try and fail on another 100
        assert!(!h.consume(100, TokenType::Ops));
        // since consume failed, limiter should be blocked now
        assert!(h.is_blocked());
        // wait half the timer period
        thread::sleep(Duration::from_millis(REFILL_TIMER_INTERVAL_MS / 2));
        // limiter should still be blocked
        assert!(h.is_blocked());
        // wait the other half of the timer period
        thread::sleep(Duration::from_millis(REFILL_TIMER_INTERVAL_MS / 2));
        // the timer_fd should have an event on it by now
        assert!(h.event_handler().is_ok());
        // limiter should now be unblocked
        assert!(!h.is_blocked());
        // try and succeed on another 100 ops this time
        assert!(h.consume(100, TokenType::Ops));
    }

    #[test]
    fn test_rate_limiter_group_full() {
        // rate limiter with limit of 1000 bytes/s and 1000 ops/s
        let mut l = RateLimiterGroup::new("test", 1000, 0, 1000, 1000, 0, 1000).unwrap();
        l.start_thread(EventFd::new(0).unwrap()).unwrap();

        let h = l.new_handle().unwrap();

        // limiter should not be blocked
        assert!(!h.is_blocked());
        // raw FD for this disabled should be valid
        assert!(h.as_raw_fd() > 0);

        // do full 1000 bytes
        assert!(h.consume(1000, TokenType::Ops));
        // do full 1000 bytes
        assert!(h.consume(1000, TokenType::Bytes));
        // try and fail on another 100 ops
        assert!(!h.consume(100, TokenType::Ops));
        // try and fail on another 100 bytes
        assert!(!h.consume(100, TokenType::Bytes));
        // since consume failed, limiter should be blocked now
        assert!(h.is_blocked());
        // wait half the timer period
        thread::sleep(Duration::from_millis(REFILL_TIMER_INTERVAL_MS / 2));
        // limiter should still be blocked
        assert!(h.is_blocked());
        // wait the other half of the timer period
        thread::sleep(Duration::from_millis(REFILL_TIMER_INTERVAL_MS / 2));
        // the timer_fd should have an event on it by now
        assert!(h.event_handler().is_ok());
        // limiter should now be unblocked
        assert!(!h.is_blocked());
        // try and succeed on another 100 ops this time
        assert!(h.consume(100, TokenType::Ops));
        // try and succeed on another 100 bytes this time
        assert!(h.consume(100, TokenType::Bytes));
    }

    #[test]
    fn test_rate_limiter_group_overconsumption() {
        // initialize the rate limiter
        let mut l = RateLimiterGroup::new("test", 1000, 0, 1000, 1000, 0, 1000).unwrap();
        l.start_thread(EventFd::new(0).unwrap()).unwrap();

        let h = l.new_handle().unwrap();

        // try to consume 2.5x the bucket size
        // we are "borrowing" 1.5x the bucket size in tokens since
        // the bucket is full
        assert!(h.consume(2500, TokenType::Bytes));

        // check that even after a whole second passes, the rate limiter
        // is still blocked
        thread::sleep(Duration::from_millis(1000));
        assert!(h.is_blocked());

        // after 1.5x the replenish time has passed, the rate limiter
        // is available again
        thread::sleep(Duration::from_millis(500));
        assert!(h.event_handler().is_ok());
        assert!(!h.is_blocked());

        // reset the rate limiter
        let mut l = RateLimiterGroup::new("test", 1000, 0, 1000, 1000, 0, 1000).unwrap();
        l.start_thread(EventFd::new(0).unwrap()).unwrap();

        let h = l.new_handle().unwrap();
        // try to consume 1.5x the bucket size
        // we are "borrowing" 1.5x the bucket size in tokens since
        // the bucket is full, should arm the timer to 0.5x replenish
        // time, which is 500 ms
        assert!(h.consume(1500, TokenType::Bytes));

        // check that after more than the minimum refill time,
        // the rate limiter is still blocked
        thread::sleep(Duration::from_millis(200));
        assert!(h.is_blocked());

        // try to consume some tokens, which should fail as the timer
        // is still active
        assert!(!h.consume(100, TokenType::Bytes));
        assert!(h.is_blocked());

        // check that after the minimum refill time, the timer was not
        // overwritten and the rate limiter is still blocked from the
        // borrowing we performed earlier
        thread::sleep(Duration::from_millis(100));
        assert!(h.is_blocked());
        assert!(!h.consume(100, TokenType::Bytes));

        // after waiting out the full duration, rate limiter should be
        // available again
        thread::sleep(Duration::from_millis(200));
        assert!(h.event_handler().is_ok());
        assert!(!h.is_blocked());
        assert!(h.consume(100, TokenType::Bytes));
    }
}
