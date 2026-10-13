// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![deny(missing_docs)]
//! # Rate Limiter
//!
//! Provides a rate limiter written in Rust useful for IO operations that need to
//! be throttled.
//!
//! ## Behavior
//!
//! The rate limiter starts off as 'unblocked' with two token buckets configured
//! with the values passed in the `RateLimiter::new()` constructor.
//! All subsequent accounting is done independently for each token bucket based
//! on the `TokenType` used. If any of the buckets runs out of budget, the limiter
//! goes in the 'blocked' state. At this point an internal timer is set up which
//! will later 'wake up' the user in order to retry sending data. The 'wake up'
//! notification will be dispatched as an event on the FD provided by the `AsRawFD`
//! trait implementation.
//!
//! The contract is that the user shall also call the `event_handler()` method on
//! receipt of such an event.
//!
//! The token buckets are replenished every time a `consume()` is called, before
//! actually trying to consume the requested amount of tokens. The amount of tokens
//! replenished is automatically calculated to respect the `complete_refill_time`
//! configuration parameter provided by the user. Plain token buckets never
//! replenish above their respective `size`.
//!
//! Each token bucket can start off with a `one_time_burst` initial extra capacity
//! on top of their `size`. This initial extra credit does not replenish and
//! can be used for an initial burst of data.
//!
//! Bounded bursts combine sustained credit with a peak-rate meter; see
//! [`TokenBucket::new_with_burst`].
//!
//! The granularity for 'wake up' events when the rate limiter is blocked is
//! currently hardcoded to `100 milliseconds`.
//!
//! ## Limitations
//!
//! This rate limiter implementation relies on the *Linux kernel's timerfd* so its
//! usage is limited to Linux systems.
//!
//! Another particularity of this implementation is that it is not self-driving.
//! It is meant to be used in an external event loop and thus implements the `AsRawFd`
//! trait and provides an *event-handler* as part of its API. This *event-handler*
//! needs to be called by the user on every event on the rate limiter's `AsRawFd` FD.

use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use std::{cmp, io};

use log::error;
use thiserror::Error;
use vmm_sys_util::timerfd::TimerFd;

/// Module for group rate limiting.
pub mod group;

#[derive(Error, Debug)]
/// Describes the errors that may occur while handling rate limiter events.
pub enum Error {
    /// The event handler was called spuriously.
    #[error("Event handler was called spuriously: {0}")]
    SpuriousRateLimiterEvent(&'static str),
    /// The event handler encounters while TimerFd::wait()
    #[error("Failed to wait for the timer")]
    TimerFdWaitError(#[source] io::Error),
}

// Interval at which the refill timer will run when limiter is at capacity.
const REFILL_TIMER_INTERVAL_MS: u64 = 100;
const TIMER_REFILL_DUR: Duration = Duration::from_millis(REFILL_TIMER_INTERVAL_MS);

const NANOSEC_IN_ONE_MILLISEC: u64 = 1_000_000;

// Euclid's two-thousand-year-old algorithm for finding the greatest common divisor.
fn gcd(x: u64, y: u64) -> u64 {
    let mut x = x;
    let mut y = y;
    while y != 0 {
        let t = y;
        y = x % y;
        x = t;
    }
    x
}

/// Enum describing the outcomes of a `reduce()` call on a `TokenBucket`.
#[derive(Clone, Debug, PartialEq)]
pub enum BucketReduction {
    /// There are not enough tokens to complete the operation.
    Failure,
    /// A part of the available tokens have been consumed.
    Success,
    /// A number of tokens `inner` times larger than the bucket size have been consumed.
    OverConsumption(f64),
}

/// TokenBucket provides a lower level interface to rate limiting with a
/// configurable refill-rate and either initial extra credit or bounded bursts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenBucket {
    // Bucket defining traits.
    size: u64,
    // Initial burst size (number of free initial tokens, that can be consumed at no cost)
    one_time_burst: u64,
    // Complete refill time in milliseconds.
    refill_time: u64,

    // Internal state descriptors.
    budget: u64,
    last_update: Instant,

    // Fields used for pre-processing optimizations.
    processed_capacity: u64,
    processed_refill_time: u128,
    burst: Option<Box<Burst>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Meter {
    capacity: u64,
    // Exact level = level + remainder / processed_refill_time, with a nonnegative
    // remainder smaller than the denominator. Splitting it avoids capacity * time overflow.
    level: i128,
    remainder: u128,
    processed_capacity: u64,
    processed_refill_time: u128,
}

impl Meter {
    fn new(capacity: u64, size: u64, refill_time_ns: u128) -> Self {
        // gcd(a, b) == gcd(a, b % a) keeps the GCD argument within u64.
        let common_factor = gcd(size, (refill_time_ns % u128::from(size)) as u64);
        Self {
            capacity,
            level: i128::from(capacity),
            remainder: 0,
            processed_capacity: size / common_factor,
            processed_refill_time: refill_time_ns / u128::from(common_factor),
        }
    }

    fn refill(&mut self, elapsed_ns: u64) {
        let refill = u128::from(elapsed_ns) * u128::from(self.processed_capacity);
        let whole = refill / self.processed_refill_time;
        let fraction = refill % self.processed_refill_time + self.remainder;
        let whole = whole + fraction / self.processed_refill_time;
        let needed = (i128::from(self.capacity) - self.level) as u128;
        if whole >= needed {
            self.level = i128::from(self.capacity);
            self.remainder = 0;
        } else {
            self.level += whole as i128;
            self.remainder = fraction % self.processed_refill_time;
        }
    }

    fn refill_to(&mut self, elapsed_ns: u64, ceiling: u64) {
        self.refill(elapsed_ns);
        if self.level >= i128::from(ceiling) {
            self.level = i128::from(ceiling);
            self.remainder = 0;
        }
    }

    fn refill_with_spill(&mut self, elapsed_ns: u64, ceiling: u64) -> u64 {
        // Round up the fill time so a fractional nanosecond never refills both meters.
        let needed = (i128::from(ceiling) - self.level).max(0) as u128;
        let fill_ns = needed
            .checked_mul(self.processed_refill_time)
            .and_then(|scaled| scaled.checked_sub(self.remainder))
            .map(|scaled| scaled.div_ceil(u128::from(self.processed_capacity)));
        self.refill_to(elapsed_ns, ceiling);
        fill_ns.map_or(0, |fill_ns| {
            u128::from(elapsed_ns).saturating_sub(fill_ns) as u64
        })
    }

    fn admits(&self, tokens: u64) -> bool {
        i128::from(tokens) <= self.level || (tokens > self.capacity && self.level >= 0)
    }

    fn delay_ns(&self) -> f64 {
        if self.level >= 0 {
            return 0.0;
        }
        let debt = (-self.level) as u128;
        let rate = u128::from(self.processed_capacity);
        if let Some(scaled_debt) = debt.checked_mul(self.processed_refill_time) {
            return (scaled_debt - self.remainder).div_ceil(rate) as f64;
        }
        // Only enormous configurations exceed u128; the public delay ratio is
        // already floating point, and converting before multiplication avoids overflow.
        ((debt as f64 * self.processed_refill_time as f64 - self.remainder as f64) / rate as f64)
            .ceil()
    }

    fn replenish(&mut self, tokens: u64) {
        self.level += i128::from(tokens);
        if self.level >= i128::from(self.capacity) {
            self.level = i128::from(self.capacity);
            self.remainder = 0;
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Burst {
    // Keep the total depth for oversized admission; refill applies the base ceiling.
    sustained: Meter,
    peak: Meter,
    credit: Option<Meter>,
    // MAX waits for the timer; finite values cover the retry grace after it fires.
    starved_ns: Option<u64>,
}

impl Burst {
    fn refill(&mut self, mut elapsed_ns: u64) {
        self.peak.refill(elapsed_ns);
        if self.credit.is_none() {
            self.sustained.refill(elapsed_ns);
            return;
        }
        if let Some(grace_ns) = self.starved_ns {
            let pending_ns = elapsed_ns.min(grace_ns);
            let credit = self.credit.as_ref().unwrap();
            let ceiling = self.sustained.capacity - credit.level as u64;
            self.sustained.refill_to(pending_ns, ceiling);
            elapsed_ns -= pending_ns;
            if grace_ns == u64::MAX {
                return;
            }
            let remaining_ns = grace_ns - pending_ns;
            self.starved_ns = Some(remaining_ns);
            if remaining_ns > 0 {
                return;
            }
            self.leave_starvation();
        }
        let credit = self.credit.as_mut().unwrap();
        let base_capacity = self.sustained.capacity - credit.capacity;
        let spill_ns = self.sustained.refill_with_spill(elapsed_ns, base_capacity);
        credit.refill(spill_ns);
    }

    fn leave_starvation(&mut self) {
        if let Some(credit) = self.credit.as_mut() {
            let base_capacity = i128::from(self.sustained.capacity - credit.capacity);
            let whole_excess = self.sustained.level - base_capacity;
            let fractional_token = i128::from(self.sustained.remainder > 0);
            let transfer = (whole_excess + fractional_token).max(0) as u64;
            self.sustained.level -= i128::from(transfer);
            // A fractional base level is below D-credit, so rounding the transfer
            // up still fits Dc. Filling credit discards its old fraction as usual.
            credit.replenish(transfer);
        }
        self.starved_ns = None;
    }

    fn budget(&self) -> u64 {
        (self.sustained.level + self.credit.as_ref().map_or(0, |credit| credit.level)).max(0) as u64
    }

    fn replenish(&mut self, mut tokens: u64) {
        self.peak.replenish(tokens);
        if let Some(credit) = self.credit.as_mut() {
            let refund = tokens.min(credit.capacity - credit.level as u64);
            credit.replenish(refund);
            tokens -= refund;
            self.sustained.replenish(tokens);
            let ceiling = if self.starved_ns.is_some() {
                self.sustained.capacity - credit.level as u64
            } else {
                self.sustained.capacity - credit.capacity
            };
            if self.sustained.level >= i128::from(ceiling) {
                self.sustained.level = i128::from(ceiling);
                self.sustained.remainder = 0;
            }
        } else {
            self.sustained.replenish(tokens);
        }
    }

    fn reduce(&mut self, tokens: u64, elapsed_ns: u64, refill_time_ms: u64) -> BucketReduction {
        self.refill(elapsed_ns);
        let admits = if self.credit.is_some() {
            tokens <= self.budget()
                || (tokens > self.sustained.capacity && self.sustained.level >= 0)
        } else {
            self.sustained.admits(tokens)
        };
        if !admits || !self.peak.admits(tokens) {
            // Waiting demand must accrue only sustained-rate tokens, regardless of request size.
            self.starved_ns = self.credit.as_ref().map(|_| u64::MAX);
            return BucketReduction::Failure;
        }
        if let Some(credit) = self.credit.as_mut() {
            let base_tokens = tokens.min(self.sustained.level.max(0) as u64);
            self.sustained.level -= i128::from(base_tokens);
            let credit_tokens = (tokens - base_tokens).min(credit.level as u64);
            credit.level -= i128::from(credit_tokens);
            self.sustained.level -= i128::from(tokens - base_tokens - credit_tokens);
            if self.sustained.level < 0 {
                credit.remainder = 0;
            }
        } else {
            self.sustained.level -= i128::from(tokens);
        }
        self.peak.level -= i128::from(tokens);
        let delay_ns = self.sustained.delay_ns().max(self.peak.delay_ns());
        if delay_ns > 0.0 {
            self.starved_ns = self.credit.as_ref().map(|_| u64::MAX);
            BucketReduction::OverConsumption(
                delay_ns / (refill_time_ms as f64 * NANOSEC_IN_ONE_MILLISEC as f64),
            )
        } else {
            self.leave_starvation();
            BucketReduction::Success
        }
    }
}

impl TokenBucket {
    /// Creates a `TokenBucket` wrapped in an `Option`.
    ///
    /// TokenBucket created is of `size` total capacity and takes `complete_refill_time_ms`
    /// milliseconds to go from zero tokens to total capacity. The `one_time_burst` is initial
    /// extra credit on top of total capacity, that does not replenish and which can be used
    /// for an initial burst of data.
    ///
    /// If the `size` or the `complete refill time` are zero, then `None` is returned.
    pub fn new(size: u64, one_time_burst: u64, complete_refill_time_ms: u64) -> Option<Self> {
        // If either token bucket capacity or refill time is 0, disable limiting.
        if size == 0 || complete_refill_time_ms == 0 {
            return None;
        }
        // Formula for computing current refill amount:
        // refill_token_count = (delta_time * size) / (complete_refill_time_ms * 1_000_000)
        // In order to avoid overflows, simplify the fractions by computing greatest common divisor.

        let complete_refill_time_ns =
            u128::from(complete_refill_time_ms) * u128::from(NANOSEC_IN_ONE_MILLISEC);
        // Get the greatest common factor between `size` and `complete_refill_time_ns`.
        let common_factor = gcd(size, (complete_refill_time_ns % u128::from(size)) as u64);
        // The division will be exact since `common_factor` is a factor of `size`.
        let processed_capacity: u64 = size / common_factor;
        // The division will be exact since `common_factor` is a factor of `complete_refill_time_ns`.
        let processed_refill_time = complete_refill_time_ns / u128::from(common_factor);

        Some(TokenBucket {
            size,
            one_time_burst,
            refill_time: complete_refill_time_ms,
            // Start off full.
            budget: size,
            // Last updated is now.
            last_update: Instant::now(),
            processed_capacity,
            processed_refill_time,
            burst: None,
        })
    }

    /// Creates a bounded burst bucket.
    ///
    /// The sustained rate is `size` tokens per `complete_refill_time_ms`, with
    /// credit capacity `burst_rate * burst_seconds` (saturating on overflow).
    /// A second meter caps the peak rate at `burst_rate` tokens per second with
    /// one second of peak credit. Both start full, both must admit a request,
    /// and oversized requests retain debt until repaid.
    /// One-time burst credit does not apply to this mode.
    ///
    /// Nonzero `burst_recharge_seconds` selects idle recharge time, within one
    /// nanosecond per base-full transition. Blocked demand and the 100 ms retry
    /// grace after its timer fires refill only at the sustained rate.
    /// Zero recharge, a period no longer than the base refill time, or no credit
    /// beyond one second of sustained rate retains implicit recharge.
    ///
    /// Returns `None` if `size` or the refill time is zero. A zero burst rate or
    /// duration instead creates a plain bucket without one-time burst credit.
    pub fn new_with_burst(
        size: u64,
        complete_refill_time_ms: u64,
        burst_rate: u64,
        burst_seconds: u64,
        burst_recharge_seconds: u64,
    ) -> Option<Self> {
        if size == 0 || complete_refill_time_ms == 0 {
            return None;
        }
        if burst_rate == 0 || burst_seconds == 0 {
            return Self::new(size, 0, complete_refill_time_ms);
        }
        let capacity = burst_rate.saturating_mul(burst_seconds);
        let refill_ns = u128::from(complete_refill_time_ms) * u128::from(NANOSEC_IN_ONE_MILLISEC);
        let mut sustained = Meter::new(capacity, size, refill_ns);
        let credit = if burst_recharge_seconds == 0 {
            None
        } else {
            let base_capacity = (u128::from(size) * 1000)
                .div_ceil(u128::from(complete_refill_time_ms))
                .min(u128::from(capacity)) as u64;
            let base_refill_ns = u128::from(base_capacity) * sustained.processed_refill_time
                / u128::from(sustained.processed_capacity);
            (u128::from(burst_recharge_seconds) * 1_000_000_000)
                .checked_sub(base_refill_ns)
                .filter(|credit_ns| *credit_ns > 0 && base_capacity < capacity)
                .map(|credit_ns| {
                    sustained.level = i128::from(base_capacity);
                    let credit_capacity = capacity - base_capacity;
                    Meter::new(credit_capacity, credit_capacity, credit_ns)
                })
        };
        Some(Self {
            size,
            one_time_burst: 0,
            refill_time: complete_refill_time_ms,
            budget: 0,
            last_update: Instant::now(),
            processed_capacity: 0,
            processed_refill_time: 0,
            burst: Some(Box::new(Burst {
                sustained,
                peak: Meter::new(burst_rate, burst_rate, 1_000_000_000),
                credit,
                starved_ns: None,
            })),
        })
    }

    /// Attempts to consume `tokens` from the bucket and returns whether the action succeeded.
    // TODO (Issue #259): handle cases where a single request is larger than the full capacity
    // for such cases we need to support partial fulfilment of requests
    pub fn reduce(&mut self, mut tokens: u64) -> BucketReduction {
        if let Some(burst) = self.burst.as_mut() {
            let now = Instant::now();
            // Cap elapsed time so the refill product fits u128.
            let elapsed_ns = now
                .duration_since(self.last_update)
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64;
            self.last_update = now;
            return burst.reduce(tokens, elapsed_ns, self.refill_time);
        }
        // First things first: consume the one-time-burst budget.
        if self.one_time_burst > 0 {
            // We still have burst budget for *all* tokens requests.
            if self.one_time_burst >= tokens {
                self.one_time_burst -= tokens;
                self.last_update = Instant::now();
                // No need to continue to the refill process, we still have burst budget to consume from.
                return BucketReduction::Success;
            }
            // We still have burst budget for *some* of the tokens requests.
            // The tokens left unfulfilled will be consumed from current `self.budget`.
            tokens -= self.one_time_burst;
            self.one_time_burst = 0;
        }

        // Compute time passed since last refill/update.
        let time_delta = self.last_update.elapsed().as_nanos() as u64;
        self.last_update = Instant::now();

        // At each 'time_delta' nanoseconds the bucket should refill with:
        // refill_amount = (time_delta * size) / (complete_refill_time_ms * 1_000_000)
        // `processed_capacity` and `processed_refill_time` are the result of simplifying above
        // fraction formula with their greatest-common-factor.
        let refill = u128::from(time_delta) * u128::from(self.processed_capacity)
            / self.processed_refill_time;
        self.budget = (u128::from(self.budget) + refill).min(u128::from(self.size)) as u64;

        if tokens > self.budget {
            // This operation requests a bandwidth higher than the bucket size
            if tokens > self.size {
                error!(
                    "Consumed {} tokens from bucket of size {}",
                    tokens, self.size
                );
                // Empty the bucket and report an overconsumption of
                // (remaining tokens / size) times larger than the bucket size
                tokens -= self.budget;
                self.budget = 0;
                return BucketReduction::OverConsumption(tokens as f64 / self.size as f64);
            }
            // If not enough tokens consume() fails, return false.
            return BucketReduction::Failure;
        }

        self.budget -= tokens;
        BucketReduction::Success
    }

    /// "Manually" adds tokens to bucket.
    pub fn replenish(&mut self, tokens: u64) {
        if let Some(burst) = self.burst.as_mut() {
            let now = Instant::now();
            let elapsed_ns = now
                .duration_since(self.last_update)
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64;
            self.last_update = now;
            burst.refill(elapsed_ns);
            burst.replenish(tokens);
            return;
        }
        // This means we are still during the burst interval.
        // Of course there is a very small chance  that the last reduce() also used up burst
        // budget which should now be replenished, but for performance and code-complexity
        // reasons we're just gonna let that slide since it's practically inconsequential.
        if self.one_time_burst > 0 {
            self.one_time_burst += tokens;
            return;
        }
        self.budget = cmp::min(self.budget + tokens, self.size);
    }

    fn block_timer_expired(&mut self) {
        if let Some(burst) = self.burst.as_mut()
            && burst.starved_ns.is_some()
        {
            let now = Instant::now();
            let elapsed_ns = now
                .duration_since(self.last_update)
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64;
            self.last_update = now;
            burst.refill(elapsed_ns);
            burst.starved_ns = Some(REFILL_TIMER_INTERVAL_MS * NANOSEC_IN_ONE_MILLISEC);
        }
    }

    /// Returns the sustained credit depth (`burst_rate * burst_seconds` in burst
    /// mode), or the configured size of a plain bucket.
    pub fn capacity(&self) -> u64 {
        self.burst
            .as_ref()
            .map_or(self.size, |b| b.sustained.capacity)
    }

    /// Returns the remaining one-time burst budget (zero in bounded burst mode).
    pub fn one_time_burst(&self) -> u64 {
        self.one_time_burst
    }

    /// Returns the configured sustained-rate refill interval in milliseconds.
    pub fn refill_time_ms(&self) -> u64 {
        self.refill_time
    }

    /// Returns whole sustained tokens available, excluding one-time burst credit.
    /// Debt is reported as zero.
    pub fn budget(&self) -> u64 {
        self.burst.as_ref().map_or(self.budget, |b| b.budget())
    }
}

/// Enum that describes the type of token used.
#[derive(Copy, Clone)]
pub enum TokenType {
    /// Token type used for bandwidth limiting.
    Bytes,
    /// Token type used for operations/second limiting.
    Ops,
}

/// Enum that describes the type of token bucket update.
pub enum BucketUpdate {
    /// No Update - same as before.
    None,
    /// Rate Limiting is disabled on this bucket.
    Disabled,
    /// Rate Limiting enabled with updated bucket.
    Update(TokenBucket),
}

/// Rate Limiter that works on both bandwidth and ops/s limiting.
///
/// Bandwidth (bytes/s) and ops/s limiting can be used at the same time or individually.
///
/// Implementation uses a single timer through TimerFd to refresh either or
/// both token buckets.
///
/// Its internal buckets are 'passively' replenished as they're being used (as
/// part of `consume()` operations).
/// A timer is enabled and used to 'actively' replenish the token buckets when
/// limiting is in effect and `consume()` operations are disabled.
///
/// RateLimiters will generate events on the FDs provided by their `AsRawFd` trait
/// implementation. These events are meant to be consumed by the user of this struct.
/// On each such event, the user must call the `event_handler()` method.
pub struct RateLimiter {
    inner: Mutex<RateLimiterInner>,

    // Internal flag that quickly determines timer state.
    timer_active: AtomicBool,
}

struct RateLimiterInner {
    bandwidth: Option<TokenBucket>,
    ops: Option<TokenBucket>,

    timer_fd: TimerFd,
}

impl RateLimiterInner {
    // Arm the timer of the rate limiter with the provided `Duration` (which will fire only once).
    fn activate_timer(&mut self, dur: Duration, flag: &AtomicBool) {
        // Panic when failing to arm the timer (same handling in crate TimerFd::set_state())
        self.timer_fd
            .reset(dur, None)
            .expect("Can't arm the timer (unexpected 'timerfd_settime' failure).");
        flag.store(true, Ordering::Relaxed);
    }
}

impl RateLimiter {
    /// Creates a new Rate Limiter that can limit on both bytes/s and ops/s.
    ///
    /// # Arguments
    ///
    /// * `bytes_total_capacity` - the total capacity of the `TokenType::Bytes` token bucket.
    /// * `bytes_one_time_burst` - initial extra credit on top of `bytes_total_capacity`,
    ///   that does not replenish and which can be used for an initial burst of data.
    /// * `bytes_complete_refill_time_ms` - number of milliseconds for the `TokenType::Bytes`
    ///   token bucket to go from zero Bytes to `bytes_total_capacity` Bytes.
    /// * `ops_total_capacity` - the total capacity of the `TokenType::Ops` token bucket.
    /// * `ops_one_time_burst` - initial extra credit on top of `ops_total_capacity`,
    ///   that does not replenish and which can be used for an initial burst of data.
    /// * `ops_complete_refill_time_ms` - number of milliseconds for the `TokenType::Ops` token
    ///   bucket to go from zero Ops to `ops_total_capacity` Ops.
    ///
    /// If either bytes/ops *size* or *refill_time* are **zero**, the limiter
    /// is **disabled** for that respective token type.
    ///
    /// # Errors
    ///
    /// If the timerfd creation fails, an error is returned.
    pub fn new(
        bytes_total_capacity: u64,
        bytes_one_time_burst: u64,
        bytes_complete_refill_time_ms: u64,
        ops_total_capacity: u64,
        ops_one_time_burst: u64,
        ops_complete_refill_time_ms: u64,
    ) -> io::Result<Self> {
        let bytes_token_bucket = TokenBucket::new(
            bytes_total_capacity,
            bytes_one_time_burst,
            bytes_complete_refill_time_ms,
        );

        let ops_token_bucket = TokenBucket::new(
            ops_total_capacity,
            ops_one_time_burst,
            ops_complete_refill_time_ms,
        );

        Self::from_buckets(bytes_token_bucket, ops_token_bucket)
    }

    /// Creates a limiter from optional plain or bounded burst buckets.
    ///
    /// `None` disables limiting for that token type.
    ///
    /// # Errors
    ///
    /// Returns an error if creating or configuring the timerfd fails.
    pub fn from_buckets(
        bandwidth: Option<TokenBucket>,
        ops: Option<TokenBucket>,
    ) -> io::Result<Self> {
        // We'll need a timer_fd, even if our current config effectively disables rate limiting,
        // because `Self::update_buckets()` might re-enable it later, and we might be
        // seccomp-blocked from creating the timer_fd at that time.
        let timer_fd = TimerFd::new()?;
        // Note: vmm_sys_util::TimerFd::new() open the fd w/o O_NONBLOCK. We manually add this flag
        // so that `Self::event_handler` won't be blocked with `vmm_sys_util::TimerFd::wait()`.
        // SAFETY: FFI calls.
        let ret = unsafe {
            let fd = timer_fd.as_raw_fd();
            let mut flags = libc::fcntl(fd, libc::F_GETFL);
            flags |= libc::O_NONBLOCK;
            libc::fcntl(fd, libc::F_SETFL, flags)
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(RateLimiter {
            inner: Mutex::new(RateLimiterInner {
                bandwidth,
                ops,
                timer_fd,
            }),
            timer_active: AtomicBool::new(false),
        })
    }

    /// Attempts to consume tokens and returns whether that is possible.
    ///
    /// If rate limiting is disabled on provided `token_type`, this function will always succeed.
    pub fn consume(&self, tokens: u64, token_type: TokenType) -> bool {
        // If the timer is active, we can't consume tokens from any bucket and the function fails.
        if self.is_blocked() {
            return false;
        }
        let mut guard = self.inner.lock().unwrap();
        // Identify the required token bucket.
        let token_bucket = match token_type {
            TokenType::Bytes => guard.bandwidth.as_mut(),
            TokenType::Ops => guard.ops.as_mut(),
        };
        // Try to consume from the token bucket.
        if let Some(bucket) = token_bucket {
            let refill_time = bucket.refill_time_ms();
            match bucket.reduce(tokens) {
                // When we report budget is over, there will be no further calls here,
                // register a timer to replenish the bucket and resume processing;
                // make sure there is only one running timer for this limiter.
                BucketReduction::Failure => {
                    if !self.is_blocked() {
                        guard.activate_timer(TIMER_REFILL_DUR, &self.timer_active);
                    }
                    false
                }
                // The operation succeeded and further calls can be made.
                BucketReduction::Success => true,
                // The operation succeeded as the tokens have been consumed
                // but the timer still needs to be armed.
                BucketReduction::OverConsumption(ratio) => {
                    // The operation "borrowed" a number of tokens `ratio` times
                    // greater than the size of the bucket, and since it takes
                    // `refill_time` milliseconds to fill an empty bucket, in
                    // order to enforce the bandwidth limit we need to prevent
                    // further calls to the rate limiter for
                    // `ratio * refill_time` milliseconds.
                    // Round up: a zero timerfd duration disarms it and would
                    // leave the limiter blocked forever on a sub-ms debt.
                    guard.activate_timer(
                        Duration::from_millis((ratio * refill_time as f64).ceil() as u64),
                        &self.timer_active,
                    );
                    true
                }
            }
        } else {
            // If bucket is not present rate limiting is disabled on token type,
            // consume() will always succeed.
            true
        }
    }

    /// Adds tokens of `token_type` to their respective bucket.
    ///
    /// Can be used to *manually* add tokens to a bucket. Useful for reverting a
    /// `consume()` if needed.
    pub fn manual_replenish(&self, tokens: u64, token_type: TokenType) {
        let mut guard = self.inner.lock().unwrap();
        // Identify the required token bucket.
        let token_bucket = match token_type {
            TokenType::Bytes => guard.bandwidth.as_mut(),
            TokenType::Ops => guard.ops.as_mut(),
        };
        // Add tokens to the token bucket.
        if let Some(bucket) = token_bucket {
            bucket.replenish(tokens);
        }
    }

    /// Returns whether this rate limiter is blocked.
    ///
    /// The limiter 'blocks' when a `consume()` operation fails because there was not enough
    /// budget for it.
    /// An event will be generated on the exported FD when the limiter 'unblocks'.
    pub fn is_blocked(&self) -> bool {
        self.timer_active.load(Ordering::Relaxed)
    }

    /// This function needs to be called every time there is an event on the
    /// FD provided by this object's `AsRawFd` trait implementation.
    ///
    /// # Errors
    ///
    /// If the rate limiter is disabled or is not blocked, an error is returned.
    pub fn event_handler(&self) -> Result<(), Error> {
        let mut guard = self.inner.lock().unwrap();
        loop {
            // Note: As we manually added the `O_NONBLOCK` flag to the FD, the following
            // `timer_fd::wait()` won't block (which is different from its default behavior.)
            match guard.timer_fd.wait() {
                Err(e) => {
                    let err: io::Error = e.into();
                    match err.kind() {
                        io::ErrorKind::Interrupted => (),
                        io::ErrorKind::WouldBlock => {
                            return Err(Error::SpuriousRateLimiterEvent(
                                "Rate limiter event handler called without a present timer",
                            ));
                        }
                        _ => return Err(Error::TimerFdWaitError(err)),
                    }
                }
                _ => {
                    if let Some(bucket) = guard.bandwidth.as_mut() {
                        bucket.block_timer_expired();
                    }
                    if let Some(bucket) = guard.ops.as_mut() {
                        bucket.block_timer_expired();
                    }
                    self.timer_active.store(false, Ordering::Relaxed);
                    return Ok(());
                }
            }
        }
    }

    /// Updates the parameters of the token buckets associated with this RateLimiter.
    // TODO: Please note that, right now, the buckets become full after being updated.
    pub fn update_buckets(&mut self, bytes: BucketUpdate, ops: BucketUpdate) {
        let guard = self.inner.get_mut().unwrap();
        match bytes {
            BucketUpdate::Disabled => guard.bandwidth = None,
            BucketUpdate::Update(tb) => guard.bandwidth = Some(tb),
            BucketUpdate::None => (),
        }
        match ops {
            BucketUpdate::Disabled => guard.ops = None,
            BucketUpdate::Update(tb) => guard.ops = Some(tb),
            BucketUpdate::None => (),
        }
    }
}

impl AsRawFd for RateLimiter {
    /// Provides a FD which needs to be monitored for POLLIN events.
    ///
    /// This object's `event_handler()` method must be called on such events.
    ///
    /// Will return a negative value if rate limiting is disabled on both
    /// token types.
    fn as_raw_fd(&self) -> RawFd {
        let guard = self.inner.lock().unwrap();
        guard.timer_fd.as_raw_fd()
    }
}

impl Default for RateLimiter {
    /// Default RateLimiter is a no-op limiter with infinite budget.
    fn default() -> Self {
        // Safe to unwrap since this will not attempt to create timer_fd.
        RateLimiter::new(0, 0, 0, 0, 0, 0).expect("Failed to build default RateLimiter")
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::{fmt, thread};

    use super::*;

    impl TokenBucket {
        // Resets the token bucket: budget set to max capacity and last-updated set to now.
        fn reset(&mut self) {
            self.budget = self.size;
            self.last_update = Instant::now();
        }

        fn get_last_update(&self) -> &Instant {
            &self.last_update
        }

        fn get_processed_capacity(&self) -> u64 {
            self.processed_capacity
        }

        fn get_processed_refill_time(&self) -> u128 {
            self.processed_refill_time
        }

        // After a restore, we cannot be certain that the last_update field has the same value.
        #[expect(dead_code)]
        fn partial_eq(&self, other: &TokenBucket) -> bool {
            (other.capacity() == self.capacity())
                && (other.one_time_burst() == self.one_time_burst())
                && (other.refill_time_ms() == self.refill_time_ms())
                && (other.budget() == self.budget())
        }
    }

    impl RateLimiter {
        fn bandwidth(&self) -> Option<TokenBucket> {
            let guard = self.inner.lock().unwrap();
            guard.bandwidth.clone()
        }

        fn ops(&self) -> Option<TokenBucket> {
            let guard = self.inner.lock().unwrap();
            guard.ops.clone()
        }
    }

    impl PartialEq for RateLimiter {
        fn eq(&self, other: &RateLimiter) -> bool {
            let self_guard = self.inner.lock().unwrap();
            let other_guard = other.inner.lock().unwrap();
            self_guard.bandwidth == other_guard.bandwidth && self_guard.ops == other_guard.ops
        }
    }

    impl fmt::Debug for RateLimiter {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            let guard = self.inner.lock().unwrap();
            write!(
                f,
                "RateLimiter {{ bandwidth: {:?}, ops: {:?} }}",
                guard.bandwidth, guard.ops
            )
        }
    }

    #[test]
    fn test_token_bucket_create() {
        let before = Instant::now();
        let tb = TokenBucket::new(1000, 0, 1000).unwrap();
        assert_eq!(tb.capacity(), 1000);
        assert_eq!(tb.budget(), 1000);
        assert!(*tb.get_last_update() >= before);
        let after = Instant::now();
        assert!(*tb.get_last_update() <= after);
        assert_eq!(tb.get_processed_capacity(), 1);
        assert_eq!(tb.get_processed_refill_time(), 1_000_000);

        // Verify invalid bucket configurations result in `None`.
        assert!(TokenBucket::new(0, 1234, 1000).is_none());
        assert!(TokenBucket::new(100, 1234, 0).is_none());
        assert!(TokenBucket::new(0, 1234, 0).is_none());
    }

    #[test]
    fn test_token_bucket_preprocess() {
        let tb = TokenBucket::new(1000, 0, 1000).unwrap();
        assert_eq!(tb.get_processed_capacity(), 1);
        assert_eq!(
            tb.get_processed_refill_time(),
            u128::from(NANOSEC_IN_ONE_MILLISEC)
        );

        let thousand = 1000;
        let tb = TokenBucket::new(3 * 7 * 11 * 19 * thousand, 0, 7 * 11 * 13 * 17).unwrap();
        assert_eq!(tb.get_processed_capacity(), 3 * 19);
        assert_eq!(
            tb.get_processed_refill_time(),
            u128::from(13 * 17 * (NANOSEC_IN_ONE_MILLISEC / thousand))
        );
    }

    #[test]
    fn test_token_bucket_reduce() {
        // token bucket with capacity 1000 and refill time of 1000 milliseconds
        // allowing rate of 1 token/ms.
        let capacity = 1000;
        let refill_ms = 1000;
        let mut tb = TokenBucket::new(capacity, 0, refill_ms as u64).unwrap();

        assert_eq!(tb.reduce(123), BucketReduction::Success);
        assert_eq!(tb.budget(), capacity - 123);

        thread::sleep(Duration::from_millis(123));
        assert_eq!(tb.reduce(1), BucketReduction::Success);
        assert_eq!(tb.budget(), capacity - 1);
        assert_eq!(tb.reduce(100), BucketReduction::Success);
        assert_eq!(tb.reduce(capacity), BucketReduction::Failure);

        // token bucket with capacity 1000 and refill time of 1000 milliseconds
        let mut tb = TokenBucket::new(1000, 1100, 1000).unwrap();
        // safely assuming the thread can run these 3 commands in less than 500ms
        assert_eq!(tb.reduce(1000), BucketReduction::Success);
        assert_eq!(tb.one_time_burst(), 100);
        assert_eq!(tb.reduce(500), BucketReduction::Success);
        assert_eq!(tb.one_time_burst(), 0);
        assert_eq!(tb.reduce(500), BucketReduction::Success);
        assert_eq!(tb.reduce(500), BucketReduction::Failure);
        thread::sleep(Duration::from_millis(500));
        assert_eq!(tb.reduce(500), BucketReduction::Success);
        thread::sleep(Duration::from_millis(1000));
        assert_eq!(tb.reduce(2500), BucketReduction::OverConsumption(1.5));

        let before = Instant::now();
        tb.reset();
        assert_eq!(tb.capacity(), 1000);
        assert_eq!(tb.budget(), 1000);
        assert!(*tb.get_last_update() >= before);
        let after = Instant::now();
        assert!(*tb.get_last_update() <= after);
    }

    #[test]
    fn test_rate_limiter_default() {
        let l = RateLimiter::default();

        // limiter should not be blocked
        assert!(!l.is_blocked());
        // limiter should be disabled so consume(whatever) should work
        assert!(l.consume(u64::MAX, TokenType::Ops));
        assert!(l.consume(u64::MAX, TokenType::Bytes));
        // calling the handler without there having been an event should error
        l.event_handler().unwrap_err();
        assert_eq!(
            format!("{:?}", l.event_handler().err().unwrap()),
            "SpuriousRateLimiterEvent(\
             \"Rate limiter event handler called without a present timer\")"
        );
    }

    #[test]
    fn test_rate_limiter_new() {
        let l = RateLimiter::new(1000, 1001, 1002, 1003, 1004, 1005).unwrap();
        let bw = l.bandwidth().unwrap();
        assert_eq!(bw.capacity(), 1000);
        assert_eq!(bw.one_time_burst(), 1001);
        assert_eq!(bw.refill_time_ms(), 1002);
        assert_eq!(bw.budget(), 1000);

        let ops = l.ops().unwrap();
        assert_eq!(ops.capacity(), 1003);
        assert_eq!(ops.one_time_burst(), 1004);
        assert_eq!(ops.refill_time_ms(), 1005);
        assert_eq!(ops.budget(), 1003);
    }

    #[test]
    fn test_rate_limiter_manual_replenish() {
        // rate limiter with limit of 1000 bytes/s and 1000 ops/s
        let l = RateLimiter::new(1000, 0, 1000, 1000, 0, 1000).unwrap();

        // consume 123 bytes
        assert!(l.consume(123, TokenType::Bytes));
        l.manual_replenish(23, TokenType::Bytes);
        {
            let bytes_tb = l.bandwidth().unwrap();
            assert_eq!(bytes_tb.budget(), 900);
        }
        // consume 123 ops
        assert!(l.consume(123, TokenType::Ops));
        l.manual_replenish(23, TokenType::Ops);
        {
            let bytes_tb = l.ops().unwrap();
            assert_eq!(bytes_tb.budget(), 900);
        }
    }

    #[test]
    fn test_rate_limiter_bandwidth() {
        // rate limiter with limit of 1000 bytes/s
        let l = RateLimiter::new(1000, 0, 1000, 0, 0, 0).unwrap();

        // limiter should not be blocked
        assert!(!l.is_blocked());
        // raw FD for this disabled should be valid
        assert!(l.as_raw_fd() > 0);

        // ops/s limiter should be disabled so consume(whatever) should work
        assert!(l.consume(u64::MAX, TokenType::Ops));

        // do full 1000 bytes
        assert!(l.consume(1000, TokenType::Bytes));
        // try and fail on another 100
        assert!(!l.consume(100, TokenType::Bytes));
        // since consume failed, limiter should be blocked now
        assert!(l.is_blocked());
        // wait half the timer period
        thread::sleep(Duration::from_millis(REFILL_TIMER_INTERVAL_MS / 2));
        // limiter should still be blocked
        assert!(l.is_blocked());
        // wait the other half of the timer period
        thread::sleep(Duration::from_millis(REFILL_TIMER_INTERVAL_MS / 2));
        // the timer_fd should have an event on it by now
        l.event_handler().unwrap();
        // limiter should now be unblocked
        assert!(!l.is_blocked());
        // try and succeed on another 100 bytes this time
        assert!(l.consume(100, TokenType::Bytes));
    }

    #[test]
    fn test_rate_limiter_ops() {
        // rate limiter with limit of 1000 ops/s
        let l = RateLimiter::new(0, 0, 0, 1000, 0, 1000).unwrap();

        // limiter should not be blocked
        assert!(!l.is_blocked());
        // raw FD for this disabled should be valid
        assert!(l.as_raw_fd() > 0);

        // bytes/s limiter should be disabled so consume(whatever) should work
        assert!(l.consume(u64::MAX, TokenType::Bytes));

        // do full 1000 ops
        assert!(l.consume(1000, TokenType::Ops));
        // try and fail on another 100
        assert!(!l.consume(100, TokenType::Ops));
        // since consume failed, limiter should be blocked now
        assert!(l.is_blocked());
        // wait half the timer period
        thread::sleep(Duration::from_millis(REFILL_TIMER_INTERVAL_MS / 2));
        // limiter should still be blocked
        assert!(l.is_blocked());
        // wait the other half of the timer period
        thread::sleep(Duration::from_millis(REFILL_TIMER_INTERVAL_MS / 2));
        // the timer_fd should have an event on it by now
        l.event_handler().unwrap();
        // limiter should now be unblocked
        assert!(!l.is_blocked());
        // try and succeed on another 100 ops this time
        assert!(l.consume(100, TokenType::Ops));
    }

    #[test]
    fn test_rate_limiter_full() {
        // rate limiter with limit of 1000 bytes/s and 1000 ops/s
        let l = RateLimiter::new(1000, 0, 1000, 1000, 0, 1000).unwrap();

        // limiter should not be blocked
        assert!(!l.is_blocked());
        // raw FD for this disabled should be valid
        assert!(l.as_raw_fd() > 0);

        // do full 1000 bytes
        assert!(l.consume(1000, TokenType::Ops));
        // do full 1000 bytes
        assert!(l.consume(1000, TokenType::Bytes));
        // try and fail on another 100 ops
        assert!(!l.consume(100, TokenType::Ops));
        // try and fail on another 100 bytes
        assert!(!l.consume(100, TokenType::Bytes));
        // since consume failed, limiter should be blocked now
        assert!(l.is_blocked());
        // wait half the timer period
        thread::sleep(Duration::from_millis(REFILL_TIMER_INTERVAL_MS / 2));
        // limiter should still be blocked
        assert!(l.is_blocked());
        // wait the other half of the timer period
        thread::sleep(Duration::from_millis(REFILL_TIMER_INTERVAL_MS / 2));
        // the timer_fd should have an event on it by now
        l.event_handler().unwrap();
        // limiter should now be unblocked
        assert!(!l.is_blocked());
        // try and succeed on another 100 ops this time
        assert!(l.consume(100, TokenType::Ops));
        // try and succeed on another 100 bytes this time
        assert!(l.consume(100, TokenType::Bytes));
    }

    #[test]
    fn test_rate_limiter_overconsumption() {
        // initialize the rate limiter
        let l = RateLimiter::new(1000, 0, 1000, 1000, 0, 1000).unwrap();
        // try to consume 2.5x the bucket size
        // we are "borrowing" 1.5x the bucket size in tokens since
        // the bucket is full
        assert!(l.consume(2500, TokenType::Bytes));

        // check that even after a whole second passes, the rate limiter
        // is still blocked
        thread::sleep(Duration::from_millis(1000));
        l.event_handler().unwrap_err();
        assert!(l.is_blocked());

        // after 1.5x the replenish time has passed, the rate limiter
        // is available again
        thread::sleep(Duration::from_millis(500));
        l.event_handler().unwrap();
        assert!(!l.is_blocked());

        // reset the rate limiter
        let l = RateLimiter::new(1000, 0, 1000, 1000, 0, 1000).unwrap();
        // try to consume 1.5x the bucket size
        // we are "borrowing" 1.5x the bucket size in tokens since
        // the bucket is full, should arm the timer to 0.5x replenish
        // time, which is 500 ms
        assert!(l.consume(1500, TokenType::Bytes));

        // check that after more than the minimum refill time,
        // the rate limiter is still blocked
        thread::sleep(Duration::from_millis(200));
        l.event_handler().unwrap_err();
        assert!(l.is_blocked());

        // try to consume some tokens, which should fail as the timer
        // is still active
        assert!(!l.consume(100, TokenType::Bytes));
        l.event_handler().unwrap_err();
        assert!(l.is_blocked());

        // check that after the minimum refill time, the timer was not
        // overwritten and the rate limiter is still blocked from the
        // borrowing we performed earlier
        thread::sleep(Duration::from_millis(100));
        l.event_handler().unwrap_err();
        assert!(l.is_blocked());
        assert!(!l.consume(100, TokenType::Bytes));

        // after waiting out the full duration, rate limiter should be
        // available again
        thread::sleep(Duration::from_millis(200));
        l.event_handler().unwrap();
        assert!(!l.is_blocked());
        assert!(l.consume(100, TokenType::Bytes));
    }

    #[test]
    fn test_rate_limiter_sub_millisecond_overconsumption() {
        let l = RateLimiter::new(20480, 0, 1000, 0, 0, 0).unwrap();

        // A one-byte overconsumption creates a debt of less than one millisecond.
        assert!(l.consume(20481, TokenType::Bytes));
        assert!(l.is_blocked());

        thread::sleep(Duration::from_millis(10));
        l.event_handler().unwrap();
        assert!(!l.is_blocked());
    }

    #[test]
    fn test_update_buckets() {
        let mut x = RateLimiter::new(1000, 2000, 1000, 10, 20, 1000).unwrap();

        let initial_bw = x.bandwidth();
        let initial_ops = x.ops();

        x.update_buckets(BucketUpdate::None, BucketUpdate::None);
        assert_eq!(x.bandwidth(), initial_bw);
        assert_eq!(x.ops(), initial_ops);

        let new_bw = TokenBucket::new(123, 0, 57).unwrap();
        let new_ops = TokenBucket::new(321, 12346, 89).unwrap();
        x.update_buckets(
            BucketUpdate::Update(new_bw.clone()),
            BucketUpdate::Update(new_ops.clone()),
        );

        {
            let mut guard = x.inner.lock().unwrap();
            // We have manually adjust the last_update field, because it changes when update_buckets()
            // constructs new buckets (and thus gets a different value for last_update). We do this so
            // it makes sense to test the following assertions.
            guard.bandwidth.as_mut().unwrap().last_update = new_bw.last_update;
            guard.ops.as_mut().unwrap().last_update = new_ops.last_update;
        }

        assert_eq!(x.bandwidth(), Some(new_bw));
        assert_eq!(x.ops(), Some(new_ops));

        x.update_buckets(BucketUpdate::Disabled, BucketUpdate::Disabled);
        assert_eq!(x.bandwidth(), None);
        assert_eq!(x.ops(), None);
    }

    #[test]
    fn test_rate_limiter_debug() {
        let l = RateLimiter::new(1, 2, 3, 4, 5, 6).unwrap();
        assert_eq!(
            format!("{l:?}"),
            format!(
                "RateLimiter {{ bandwidth: {:?}, ops: {:?} }}",
                l.bandwidth(),
                l.ops()
            ),
        );
    }

    fn burst_reduce(bucket: &mut TokenBucket, tokens: u64, elapsed_ms: u64) -> BucketReduction {
        bucket.burst.as_mut().unwrap().reduce(
            tokens,
            elapsed_ms * NANOSEC_IN_ONE_MILLISEC,
            bucket.refill_time,
        )
    }

    #[test]
    fn test_burst_peak_cap() {
        let mut bucket = TokenBucket::new_with_burst(10, 1000, 101, 2, 0).unwrap();
        assert_eq!(bucket.capacity(), 202);
        assert_eq!(bucket.one_time_burst(), 0);
        assert_eq!(bucket.burst.as_ref().unwrap().peak.capacity, 101);
        for _ in 0..101 {
            assert_eq!(burst_reduce(&mut bucket, 1, 0), BucketReduction::Success);
        }
        let before = bucket.burst.clone();
        assert_eq!(burst_reduce(&mut bucket, 1, 0), BucketReduction::Failure);
        assert_eq!(bucket.burst, before);
        assert_eq!(bucket.budget(), 101);
    }

    #[test]
    fn test_burst_exhaustion_and_idle_refill() {
        let mut bucket = TokenBucket::new_with_burst(10, 1000, 100, 1, 0).unwrap();
        assert_eq!(burst_reduce(&mut bucket, 100, 0), BucketReduction::Success);
        assert_eq!(bucket.budget(), 0);
        for _ in 0..20 {
            assert_eq!(burst_reduce(&mut bucket, 10, 100), BucketReduction::Failure);
            assert_eq!(burst_reduce(&mut bucket, 1, 0), BucketReduction::Success);
            assert_eq!(bucket.budget(), 0);
        }
        assert_eq!(burst_reduce(&mut bucket, 0, 1000), BucketReduction::Success);
        assert_eq!(bucket.budget(), 10);
        assert_eq!(bucket.burst.as_ref().unwrap().peak.level, 100);
        assert_eq!(
            burst_reduce(&mut bucket, 0, 20_000),
            BucketReduction::Success
        );
        assert_eq!(bucket.budget(), 100);
        assert_eq!(bucket.burst.as_ref().unwrap().peak.level, 100);
    }

    #[test]
    fn test_burst_atomic_admission() {
        let mut bucket = TokenBucket::new_with_burst(10, 1000, 100, 1, 0).unwrap();
        // Peak FAIL / sustained OK, sustained FAIL / peak OK, and peak OVER /
        // sustained FAIL must never partially debit either meter.
        for (sustained, peak, tokens) in [(100, 0, 1), (0, 100, 1), (-1, 100, 101), (100, -1, 101)]
        {
            let burst = bucket.burst.as_mut().unwrap();
            burst.sustained.level = sustained;
            burst.peak.level = peak;
            let before = bucket.burst.clone();
            assert_eq!(
                burst_reduce(&mut bucket, tokens, 0),
                BucketReduction::Failure
            );
            assert_eq!(bucket.burst, before);
        }
        {
            let burst = bucket.burst.as_mut().unwrap();
            burst.sustained.level = 100;
            burst.peak.level = 0;
        }
        assert_eq!(
            burst_reduce(&mut bucket, 101, 0),
            BucketReduction::OverConsumption(1.01),
        );
        let burst = bucket.burst.as_ref().unwrap();
        assert_eq!(burst.sustained.level, -1);
        assert_eq!(burst.peak.level, -101);
        assert_eq!(bucket.budget(), 0);
        // The slower sustained meter, rather than the peak meter, can set the delay.
        bucket.burst.as_mut().unwrap().sustained.level = 0;
        bucket.burst.as_mut().unwrap().peak.level = 100;
        assert_eq!(
            burst_reduce(&mut bucket, 101, 0),
            BucketReduction::OverConsumption(10.1),
        );
    }

    #[test]
    fn test_burst_debt_retention() {
        let mut bucket = TokenBucket::new_with_burst(100, 1000, 100, 10, 0).unwrap();
        assert_eq!(
            burst_reduce(&mut bucket, 200, 0),
            BucketReduction::OverConsumption(1.0),
        );
        let before = bucket.burst.clone();
        assert_eq!(burst_reduce(&mut bucket, 200, 0), BucketReduction::Failure);
        assert_eq!(bucket.burst, before);
        assert_eq!(
            burst_reduce(&mut bucket, 200, 999),
            BucketReduction::Failure
        );
        assert_eq!(
            burst_reduce(&mut bucket, 200, 1),
            BucketReduction::OverConsumption(2.0),
        );
        // Every subsequent 200-token request requires 2000 ms at B = 100.
        for _ in 0..20 {
            assert_eq!(
                burst_reduce(&mut bucket, 200, 1999),
                BucketReduction::Failure
            );
            assert_eq!(
                burst_reduce(&mut bucket, 200, 1),
                BucketReduction::OverConsumption(2.0),
            );
        }
    }

    #[test]
    fn test_burst_fractional_refill() {
        for rate in (1..10).chain([19]) {
            let mut bucket = TokenBucket::new_with_burst(rate, 1000, rate, 2, 0).unwrap();
            let peak_capacity = bucket.burst.as_ref().unwrap().peak.capacity;
            assert_eq!(
                burst_reduce(&mut bucket, peak_capacity, 0),
                BucketReduction::Success,
            );
            let mut admitted = 0;
            for _ in 0..1000 {
                match burst_reduce(&mut bucket, 1, 1) {
                    BucketReduction::Success => admitted += 1,
                    BucketReduction::Failure => {}
                    outcome => panic!("Unexpected fractional refill outcome: {outcome:?}"),
                }
            }
            assert_eq!(admitted, rate);
            assert_eq!(bucket.burst.as_ref().unwrap().peak.level, 0);
            let mut bucket = TokenBucket::new_with_burst(rate, 1000, rate, 2, 0).unwrap();
            assert_eq!(burst_reduce(&mut bucket, rate, 0), BucketReduction::Success);
            let mut admitted = 0;
            for _ in 0..100 {
                let mut outcome = burst_reduce(&mut bucket, 1, REFILL_TIMER_INTERVAL_MS);
                while outcome == BucketReduction::Success {
                    admitted += 1;
                    outcome = burst_reduce(&mut bucket, 1, 0);
                }
                assert_eq!(outcome, BucketReduction::Failure);
            }
            assert_eq!(admitted, rate * 10);
        }
    }

    #[test]
    fn test_burst_byte_rate_with_fixed_probes() {
        let rate = 10_000_000;
        let request = 384 * 1024;
        let mut bucket = TokenBucket::new_with_burst(rate, 1000, rate, 2, 0).unwrap();
        while burst_reduce(&mut bucket, request, 0) == BucketReduction::Success {}
        let mut admitted = 0;
        for _ in 0..100 {
            let mut outcome = burst_reduce(&mut bucket, request, REFILL_TIMER_INTERVAL_MS);
            while outcome == BucketReduction::Success {
                admitted += request;
                outcome = burst_reduce(&mut bucket, request, 0);
            }
            assert_eq!(outcome, BucketReduction::Failure);
        }
        assert!(admitted.abs_diff(rate * 10) < request);
    }

    #[test]
    fn test_burst_last_update_and_refund() {
        let mut bucket = TokenBucket::new_with_burst(10, 1000, 100, 2, 0).unwrap();
        assert_eq!(burst_reduce(&mut bucket, 10, 0), BucketReduction::Success);
        bucket.last_update = Instant::now() - Duration::from_millis(100);
        assert_eq!(bucket.reduce(1), BucketReduction::Success);
        assert_eq!(bucket.budget(), 190);
        assert_eq!(bucket.burst.as_ref().unwrap().peak.level, 99);

        let limiter = RateLimiter::from_buckets(None, Some(bucket)).unwrap();
        limiter.manual_replenish(1, TokenType::Ops);
        let bucket = limiter.ops().unwrap();
        assert_eq!(bucket.budget(), 191);
        assert_eq!(bucket.burst.as_ref().unwrap().peak.level, 100);
        limiter.manual_replenish(u64::MAX, TokenType::Ops);
        let bucket = limiter.ops().unwrap();
        assert_eq!(bucket.budget(), 200);
        assert_eq!(bucket.burst.as_ref().unwrap().peak.level, 100);

        let mut bucket = TokenBucket::new_with_burst(10, 1000, 100, 2, 0).unwrap();
        assert_eq!(
            burst_reduce(&mut bucket, 201, 0),
            BucketReduction::OverConsumption(1.01),
        );
        bucket.replenish(100);
        assert_eq!(bucket.budget(), 99);
        assert_eq!(bucket.burst.as_ref().unwrap().peak.level, -1);
    }

    #[test]
    fn test_burst_sub_ms_overconsumption_timer() {
        let limiter = RateLimiter::from_buckets(
            None,
            TokenBucket::new_with_burst(10_000, 1000, 10_000, 1, 0),
        )
        .unwrap();
        assert!(limiter.consume(10_001, TokenType::Ops));
        assert!(limiter.is_blocked());
        thread::sleep(Duration::from_millis(5));
        limiter.event_handler().unwrap();
        assert!(!limiter.is_blocked());
    }

    #[test]
    fn test_burst_constructor_edges() {
        assert!(TokenBucket::new_with_burst(0, 1000, 100, 1, 0).is_none());
        assert!(TokenBucket::new_with_burst(10, 0, 100, 1, 0).is_none());
        for (rate, seconds) in [(0, 1), (100, 0), (0, 0)] {
            let mut bucket = TokenBucket::new_with_burst(10, 1000, rate, seconds, 0).unwrap();
            let plain = TokenBucket::new(10, 0, 1000).unwrap();
            bucket.last_update = plain.last_update;
            assert_eq!(bucket, plain);
        }
        for (rate, seconds) in [(0, 1), (1, 0)] {
            let mut bucket = TokenBucket::new_with_burst(1, 1 << 58, rate, seconds, 0).unwrap();
            assert_eq!(bucket.reduce(1), BucketReduction::Success);
            assert_eq!(bucket.reduce(1), BucketReduction::Failure);
        }
        for (size, refill, rate, seconds) in [
            (1, u64::MAX, u64::MAX, u64::MAX),
            (u64::MAX, u64::MAX, u64::MAX, 1),
            (u64::MAX, 1, u64::MAX, 1),
            (1, u64::MAX, 1, 1),
        ] {
            for recharge in [0, u64::MAX] {
                let mut bucket =
                    TokenBucket::new_with_burst(size, refill, rate, seconds, recharge).unwrap();
                assert_eq!(bucket.capacity(), rate.saturating_mul(seconds));
                assert!(matches!(
                    burst_reduce(&mut bucket, u64::MAX, 0),
                    BucketReduction::Success | BucketReduction::OverConsumption(_)
                ));
                bucket.burst.as_mut().unwrap().refill(u64::MAX);
                bucket.replenish(u64::MAX);
            }
        }
    }

    #[test]
    fn test_burst_recharge_timing_and_partial_credit() {
        for recharge in [20, 80] {
            for elapsed_ms in [500, 1000, 1500, 10_000, recharge * 1000 - 1] {
                let mut bucket =
                    TokenBucket::new_with_burst(5000, 1000, 20_000, 10, recharge).unwrap();
                let burst = bucket.burst.as_mut().unwrap();
                burst.sustained.level = 0;
                burst.credit.as_mut().unwrap().level = 0;
                assert_eq!(
                    burst_reduce(&mut bucket, 0, elapsed_ms),
                    BucketReduction::Success
                );
                let elapsed = elapsed_ms as f64 / 1000.0;
                let expected = (5000.0 * elapsed).min(5000.0)
                    + 195_000.0 * ((elapsed - 1.0) / (recharge as f64 - 1.0)).clamp(0.0, 1.0);
                assert!((bucket.budget() as f64 - expected).abs() <= 1.0);
                assert!(bucket.budget() < bucket.capacity());
                assert_eq!(
                    burst_reduce(&mut bucket, 0, recharge * 1000 - elapsed_ms + 1),
                    BucketReduction::Success
                );
                assert_eq!(bucket.budget(), 200_000);
                let burst = bucket.burst.as_ref().unwrap();
                assert_eq!(burst.sustained.remainder, 0);
                assert_eq!(burst.credit.as_ref().unwrap().remainder, 0);
            }
            let mut bucket = TokenBucket::new_with_burst(5000, 1000, 20_000, 10, recharge).unwrap();
            let burst = bucket.burst.as_mut().unwrap();
            burst.sustained.level = 0;
            burst.credit.as_mut().unwrap().level = 0;
            assert_eq!(
                burst_reduce(&mut bucket, 0, recharge * 1000),
                BucketReduction::Success
            );
            assert_eq!(bucket.budget(), bucket.capacity());
        }
    }

    #[test]
    fn test_burst_recharge_fractional_spill() {
        let mut meter = Meter::new(2, 3, 1_000_000_000);
        meter.level = 0;
        assert_eq!(meter.refill_with_spill(333_333_333, 1), 0);
        assert_eq!(meter.level, 0);
        assert_eq!(meter.refill_with_spill(2, 1), 1);
        assert_eq!(meter.level, 1);
        assert_eq!(meter.remainder, 0);
        assert_eq!(meter.refill_with_spill(100, 1), 100);

        let mut meter = Meter::new(u64::MAX, 1, u128::MAX);
        meter.level = -1;
        assert_eq!(meter.refill_with_spill(1, u64::MAX), 0);
        assert_eq!(meter.level, -1);
        assert_eq!(meter.remainder, 1);
    }

    #[test]
    fn test_burst_recharge_saturated_requests() {
        for (rate, peak, request) in [(50, 200, 1), (5000, 20_000, 20_000)] {
            let mut bucket = TokenBucket::new_with_burst(rate, 1000, peak, 10, 20).unwrap();
            while burst_reduce(&mut bucket, request, 0) == BucketReduction::Success {}
            let mut admitted = 0_u64;
            // Discard the initial burst before measuring steady-state throughput.
            for probe in 0..5000 {
                let mut outcome = burst_reduce(&mut bucket, request, REFILL_TIMER_INTERVAL_MS);
                while outcome == BucketReduction::Success {
                    if probe >= 1000 {
                        admitted += request;
                    }
                    outcome = burst_reduce(&mut bucket, request, 0);
                }
                assert_eq!(outcome, BucketReduction::Failure);
            }
            assert!(admitted.abs_diff(rate * 400) < request);
            let credit = bucket.burst.as_ref().unwrap().credit.as_ref().unwrap();
            assert_eq!(credit.level, 0);
        }
    }

    #[test]
    fn test_burst_recharge_full_depth_cycles() {
        let mut bucket = TokenBucket::new_with_burst(5000, 1000, 20_000, 10, 20).unwrap();
        assert_eq!(
            burst_reduce(&mut bucket, 200_000, 0),
            BucketReduction::OverConsumption(9.0)
        );
        let burst = bucket.burst.as_mut().unwrap();
        burst.refill(9_000_000_000);
        assert_eq!(burst.sustained.level, 45_000);
        assert_eq!(burst.credit.as_ref().unwrap().level, 0);
        burst.starved_ns = Some(100_000_000);
        burst.refill(100_000_000);
        assert_eq!(burst.starved_ns, None);
        assert_eq!(burst.sustained.level, 5000);
        assert_eq!(burst.credit.as_ref().unwrap().level, 40_500);
        let credit_ns = (154_500_u64 * 19_000_000_000).div_ceil(195_000);
        burst.refill(credit_ns - 1);
        assert_eq!(burst.budget(), 199_999);
        burst.refill(1);
        assert_eq!(burst.budget(), 200_000);

        // A debt wait is not idle: D-sized attempts every P need not attain D/P.
        let mut bucket = TokenBucket::new_with_burst(5000, 1000, 20_000, 10, 20).unwrap();
        let mut outcome = burst_reduce(&mut bucket, 200_000, 0);
        let mut admitted = 0_u64;
        for _ in 0..100 {
            let wait_ms = match outcome {
                BucketReduction::Failure => REFILL_TIMER_INTERVAL_MS,
                BucketReduction::OverConsumption(ratio) => (ratio * 1000.0).ceil() as u64,
                BucketReduction::Success => panic!("Full-depth charge must owe peak debt"),
            };
            let burst = bucket.burst.as_mut().unwrap();
            burst.refill(wait_ms * NANOSEC_IN_ONE_MILLISEC);
            burst.starved_ns = Some(100_000_000);
            outcome = burst_reduce(&mut bucket, 200_000, 20_000 - wait_ms);
            if matches!(outcome, BucketReduction::OverConsumption(_)) {
                admitted += 200_000;
            }
        }
        assert!(admitted / (100 * 20) <= 10_000);
    }

    #[test]
    fn test_burst_recharge_one_token_cycles() {
        let rate = 50;
        let peak = 200;
        let depth = 2000;
        let recharge = 20;
        let mut bucket = TokenBucket::new_with_burst(rate, 1000, peak, 10, recharge).unwrap();
        let mut admitted = 0_u64;
        let mut elapsed_ms = 0_u64;
        for _ in 0..20 {
            for _ in 0..peak {
                assert_eq!(burst_reduce(&mut bucket, 1, 0), BucketReduction::Success);
                admitted += 1;
            }
            while bucket.budget() > 0 {
                assert_eq!(burst_reduce(&mut bucket, 1, 5), BucketReduction::Success);
                admitted += 1;
                elapsed_ms += 5;
            }
            assert_eq!(
                burst_reduce(&mut bucket, 0, recharge * 1000),
                BucketReduction::Success
            );
            elapsed_ms += recharge * 1000;
            assert_eq!(bucket.budget(), depth);
        }
        let average = admitted as f64 * 1000.0 / elapsed_ms as f64;
        let bound =
            (peak * (depth - rate)) as f64 / (depth - peak + recharge * (peak - rate)) as f64;
        assert!(average <= bound);
        assert!(average > bound * 0.995);
    }

    #[test]
    fn test_burst_recharge_atomic_admission() {
        let mut bucket = TokenBucket::new_with_burst(10, 1000, 100, 2, 5).unwrap();
        for (base, credit, peak, tokens) in [
            (10, 190, 0, 1),
            (0, 0, 100, 1),
            (5, 6, 100, 12),
            (-1, 0, 100, 201),
            (10, 190, -1, 201),
        ] {
            let burst = bucket.burst.as_mut().unwrap();
            burst.sustained.level = base;
            burst.credit.as_mut().unwrap().level = credit;
            burst.peak.level = peak;
            let before = (
                burst.sustained.clone(),
                burst.credit.clone(),
                burst.peak.clone(),
            );
            assert_eq!(
                burst_reduce(&mut bucket, tokens, 0),
                BucketReduction::Failure
            );
            let burst = bucket.burst.as_ref().unwrap();
            assert_eq!(burst.starved_ns, Some(u64::MAX));
            assert_eq!(
                (
                    burst.sustained.clone(),
                    burst.credit.clone(),
                    burst.peak.clone()
                ),
                before
            );
        }
        let burst = bucket.burst.as_mut().unwrap();
        burst.sustained.level = 5;
        burst.credit.as_mut().unwrap().level = 6;
        burst.peak.level = 100;
        assert_eq!(burst_reduce(&mut bucket, 9, 0), BucketReduction::Success);
        let burst = bucket.burst.as_ref().unwrap();
        assert_eq!(burst.sustained.level, 0);
        assert_eq!(burst.credit.as_ref().unwrap().level, 2);
        assert_eq!(burst.peak.level, 91);
        assert_eq!(burst.starved_ns, None);
    }

    #[test]
    fn test_burst_recharge_debt_and_credit_first_refund() {
        let mut bucket = TokenBucket::new_with_burst(10, 1000, 100, 2, 5).unwrap();
        assert_eq!(
            burst_reduce(&mut bucket, 400, 0),
            BucketReduction::OverConsumption(20.0)
        );
        let burst = bucket.burst.as_mut().unwrap();
        assert_eq!(burst.sustained.level, -200);
        assert_eq!(burst.credit.as_ref().unwrap().level, 0);
        assert_eq!(burst.peak.level, -300);
        burst.refill(10_000_000_000);
        assert_eq!(burst.sustained.level, -100);
        assert_eq!(burst.credit.as_ref().unwrap().level, 0);
        burst.refill(10_000_000_000);
        assert_eq!(burst.sustained.level, 0);
        assert_eq!(burst.credit.as_ref().unwrap().level, 0);
        burst.replenish(5);
        assert_eq!(burst.credit.as_ref().unwrap().level, 5);
        assert_eq!(burst.sustained.level, 0);
        burst.replenish(190);
        assert_eq!(burst.credit.as_ref().unwrap().level, 190);
        assert_eq!(burst.sustained.level, 5);
        burst.replenish(u64::MAX);
        assert_eq!(burst.budget(), 200);
        assert_eq!(burst.sustained.level, 10);
        assert_eq!(burst.sustained.remainder, 0);
        assert_eq!(burst.credit.as_ref().unwrap().remainder, 0);
        assert_eq!(burst.peak.level, 100);

        // The public refund refills elapsed idle time before restoring credit.
        burst.sustained.level = 0;
        burst.credit.as_mut().unwrap().level = 0;
        bucket.last_update = Instant::now() - Duration::from_secs(1);
        bucket.replenish(1);
        let burst = bucket.burst.as_ref().unwrap();
        assert_eq!(burst.sustained.level, 10);
        assert_eq!(burst.credit.as_ref().unwrap().level, 1);
    }

    #[test]
    fn test_burst_recharge_starved_transition() {
        let mut bucket = TokenBucket::new_with_burst(10, 1000, 100, 2, 5).unwrap();
        let burst = bucket.burst.as_mut().unwrap();
        burst.sustained.level = 0;
        burst.credit.as_mut().unwrap().level = 0;
        assert_eq!(burst_reduce(&mut bucket, 100, 0), BucketReduction::Failure);
        bucket.burst.as_mut().unwrap().refill(5_000_000_000);
        let burst = bucket.burst.as_ref().unwrap();
        assert_eq!(burst.starved_ns, Some(u64::MAX));
        assert_eq!(burst.sustained.level, 50);
        assert_eq!(burst.credit.as_ref().unwrap().level, 0);
        assert_eq!(burst_reduce(&mut bucket, 1, 0), BucketReduction::Success);
        let burst = bucket.burst.as_ref().unwrap();
        assert_eq!(burst.starved_ns, None);
        assert_eq!(burst.sustained.level, 10);
        assert_eq!(burst.credit.as_ref().unwrap().level, 39);
        assert_eq!(bucket.budget(), 49);
        assert_eq!(burst.sustained.remainder, 0);

        assert_eq!(burst_reduce(&mut bucket, 200, 0), BucketReduction::Failure);
        bucket.burst.as_mut().unwrap().refill(u64::MAX);
        assert_eq!(bucket.budget(), 200);
        assert_eq!(bucket.burst.as_ref().unwrap().sustained.remainder, 0);
        assert_eq!(burst_reduce(&mut bucket, 0, 0), BucketReduction::Success);
        let burst = bucket.burst.as_ref().unwrap();
        assert_eq!(burst.sustained.level, 10);
        assert_eq!(burst.credit.as_ref().unwrap().level, 190);
        assert_eq!(burst.credit.as_ref().unwrap().remainder, 0);
    }

    #[test]
    fn test_burst_recharge_constructor_edges() {
        for recharge in [0, 1] {
            let bucket = TokenBucket::new_with_burst(10, 1000, 100, 2, recharge).unwrap();
            assert!(bucket.burst.as_ref().unwrap().credit.is_none());
            assert_eq!(bucket.budget(), 200);
        }
        let bucket = TokenBucket::new_with_burst(1, 3000, 1, 2, 3).unwrap();
        assert!(bucket.burst.as_ref().unwrap().credit.is_none());
        let bucket = TokenBucket::new_with_burst(10, 1000, 10, 1, 100).unwrap();
        assert!(bucket.burst.as_ref().unwrap().credit.is_none());
        assert_eq!(bucket.budget(), 10);

        let mut bucket =
            TokenBucket::new_with_burst(2_000_000_001, 4_000_000_000_000, 1, 10, 2).unwrap();
        let burst = bucket.burst.as_mut().unwrap();
        burst.sustained.level = 0;
        burst.credit.as_mut().unwrap().level = 0;
        burst.refill(2_000_000_000);
        assert_eq!(burst.budget(), 1);
        burst.refill(1);
        assert_eq!(burst.budget(), 10);
    }

    #[test]
    fn test_burst_recharge_queued_peak_debt() {
        let mut bucket = TokenBucket::new_with_burst(512, 1000, 1024, 4, 2).unwrap();
        let mut outcome = burst_reduce(&mut bucket, 4096, 0);
        let mut elapsed_ms = 0_u64;
        let mut admitted = 0_u64;
        while admitted < 4096 * 100 {
            let wait_ms = match outcome {
                BucketReduction::Failure => REFILL_TIMER_INTERVAL_MS,
                BucketReduction::OverConsumption(ratio) => (ratio * 1000.0).ceil() as u64,
                BucketReduction::Success => panic!("Full-depth charge must owe peak debt"),
            };
            let burst = bucket.burst.as_mut().unwrap();
            assert_eq!(burst.starved_ns, Some(u64::MAX));
            burst.refill(wait_ms * NANOSEC_IN_ONE_MILLISEC);
            burst.starved_ns = Some(100_000_000);
            elapsed_ms += wait_ms;
            outcome = burst_reduce(&mut bucket, 4096, 0);
            if matches!(outcome, BucketReduction::OverConsumption(_)) {
                admitted += 4096;
            }
        }
        let average = admitted as f64 * 1000.0 / elapsed_ms as f64;
        assert!((average - 512.0).abs() < 512.0 * 0.02);
    }

    #[test]
    fn test_burst_recharge_idle_after_debt_timer() {
        let mut bucket = TokenBucket::new_with_burst(10, 1000, 100, 2, 5).unwrap();
        assert_eq!(
            burst_reduce(&mut bucket, 200, 0),
            BucketReduction::OverConsumption(1.0)
        );
        let burst = bucket.burst.as_mut().unwrap();
        burst.refill(1_000_000_000);
        burst.starved_ns = Some(100_000_000);
        burst.refill(4_050_000_000);
        assert_eq!(burst.starved_ns, None);
        assert!(burst.budget() < 200);
        burst.refill(50_000_000);
        assert_eq!(burst.budget(), 200);
    }

    #[test]
    fn test_burst_recharge_failing_retry_within_grace() {
        let mut bucket = TokenBucket::new_with_burst(10, 1000, 100, 2, 5).unwrap();
        let burst = bucket.burst.as_mut().unwrap();
        burst.sustained.level = 0;
        burst.credit.as_mut().unwrap().level = 0;
        assert_eq!(burst_reduce(&mut bucket, 100, 0), BucketReduction::Failure);
        let burst = bucket.burst.as_mut().unwrap();
        burst.refill(100_000_000);
        burst.starved_ns = Some(100_000_000);
        assert_eq!(burst_reduce(&mut bucket, 100, 50), BucketReduction::Failure);
        let burst = bucket.burst.as_mut().unwrap();
        assert_eq!(burst.starved_ns, Some(u64::MAX));
        burst.refill(10_000_000_000);
        assert_eq!(burst.sustained.level, 101);
        assert_eq!(
            burst.sustained.remainder,
            burst.sustained.processed_refill_time / 2
        );
        assert_eq!(burst.credit.as_ref().unwrap().level, 0);
        assert_eq!(burst.starved_ns, Some(u64::MAX));
    }

    #[test]
    fn test_burst_recharge_fractional_starved_transition() {
        let mut bucket = TokenBucket::new_with_burst(3, 1000, 10, 1, 2).unwrap();
        assert_eq!(burst_reduce(&mut bucket, 10, 0), BucketReduction::Success);
        assert_eq!(burst_reduce(&mut bucket, 10, 0), BucketReduction::Failure);
        assert_eq!(burst_reduce(&mut bucket, 1, 1500), BucketReduction::Success);
        let burst = bucket.burst.as_ref().unwrap();
        assert_eq!(burst.starved_ns, None);
        assert_eq!(burst.budget(), 3);
        assert_eq!(burst.sustained.level, 2);
        assert_eq!(
            burst.sustained.remainder,
            burst.sustained.processed_refill_time / 2
        );
        assert_eq!(burst.credit.as_ref().unwrap().level, 1);
        assert_eq!(burst.credit.as_ref().unwrap().remainder, 0);
    }

    #[test]
    fn test_rate_limiter_recharge_timer_ends_starvation() {
        let bucket = TokenBucket::new_with_burst(10, 1000, 100, 2, 5).unwrap();
        let mut limiter = RateLimiter::from_buckets(Some(bucket.clone()), Some(bucket)).unwrap();
        {
            let guard = limiter.inner.get_mut().unwrap();
            for bucket in [&mut guard.bandwidth, &mut guard.ops].into_iter().flatten() {
                let burst = bucket.burst.as_mut().unwrap();
                burst.sustained.level = 0;
                burst.credit.as_mut().unwrap().level = 0;
                burst.starved_ns = Some(u64::MAX);
                bucket.last_update = Instant::now() - Duration::from_secs(1);
            }
            guard
                .timer_fd
                .reset(Duration::from_millis(1), None)
                .unwrap();
        }
        limiter.timer_active.store(true, Ordering::Relaxed);
        thread::sleep(Duration::from_millis(5));
        limiter.event_handler().unwrap();
        assert!(!limiter.is_blocked());
        let guard = limiter.inner.get_mut().unwrap();
        for bucket in [&mut guard.bandwidth, &mut guard.ops].into_iter().flatten() {
            let burst = bucket.burst.as_mut().unwrap();
            assert_eq!(burst.starved_ns, Some(100_000_000));
            assert_eq!(burst.credit.as_ref().unwrap().level, 0);
            assert!(burst.sustained.level >= 10);
            burst.refill(5_100_000_000);
            assert_eq!(burst.starved_ns, None);
            assert_eq!(burst.budget(), 200);
        }
    }
}
