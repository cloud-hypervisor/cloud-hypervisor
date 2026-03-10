// Copyright © 2026 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

//! Module for [`MemoryMigrationContext`].

use std::fmt;
use std::fmt::Display;
use std::time::{Duration, Instant};

use crate::protocol::MemoryRangeTable;

/// Internal metrics for the precopy migration phase.
///
/// The context aggregates runtime statistics such as iteration count,
/// transferred bytes, durations, bandwidth, and estimated downtime.
/// These metrics allow the migration logic to make decisions based on
/// observed runtime behavior, for example terminating further iterations
/// once the expected downtime falls below a configured threshold.
///
/// The structure is updated both between iterations and during an
/// iteration so that it always reflects the most recent state.
#[derive(Debug, PartialEq)]
pub struct MemoryMigrationContext {
    /// Current iteration: 0 initial total transmission, >0 delta transmission.
    pub iteration: usize,
    /// Total bytes sent across all iterations.
    total_sent_bytes: u64,
    /// Total bytes to send in the current iteration.
    pub current_iteration_total_bytes: u64,
    /// The currently measured bandwidth.
    ///
    /// This is updated (at least) after each completed iteration.
    bandwidth_bytes_per_second: f64,
    /// Calculated downtime in milliseconds regarding the current bandwidth and
    /// the remaining memory.
    ///
    /// This is only `None` for iteration 0.
    ///
    /// Please note that this ignores any additional migration overhead and
    /// only looks at the memory transfer itself.
    estimated_downtime: Option<Duration>,
    /// Begin of the memory migration.
    migration_begin: Instant,
    /// Duration of the memory migration.
    ///
    /// This is only `None` until the last iteration is finished.
    migration_duration: Option<Duration>,
    /// Begin of the current iteration.
    iteration_begin: Instant,
    /// Duration of the current iteration.
    ///
    /// This includes the transmission, all logging, and update of any metrics.
    ///
    /// This is only `None` for iteration 0.
    iteration_duration: Option<Duration>,
    /// Begin of the current transfer.
    transfer_begin: Instant,
    /// Duration of the current transfer.
    ///
    /// This is only `None` for iteration 0.
    transfer_duration: Option<Duration>,
}

impl MemoryMigrationContext {
    /// Creates a new context.
    ///
    /// Please note that you should create this struct right before the precopy
    /// memory migration starts, as the field `migration_begin` is set to
    /// [`Instant::now`].
    pub fn new() -> Self {
        Self {
            iteration: 0,
            total_sent_bytes: 0,
            current_iteration_total_bytes: 0,
            bandwidth_bytes_per_second: 0.0,
            estimated_downtime: None,
            migration_begin: Instant::now(),
            migration_duration: None,
            // Will be updated soon -> so this value is never read
            iteration_begin: Instant::now(),
            iteration_duration: None,
            // Will be updated soon -> so this value is never read
            transfer_begin: Instant::now(),
            transfer_duration: None,
        }
    }

    /// Updates the metrics right before the transfer over the wire.
    ///
    /// Supposed to be called once per precopy memory iteration.
    ///
    /// This helps to feed the "is converged?" with fresh metrics to
    /// potentially stop the precopy phase.
    pub fn update_metrics_before_transfer(
        &mut self,
        iteration_begin: Instant,
        iteration_table: &MemoryRangeTable,
    ) {
        self.iteration_begin = iteration_begin;
        self.current_iteration_total_bytes = iteration_table.effective_size();
        self.estimated_downtime = if self.current_iteration_total_bytes == 0 {
            Some(Duration::ZERO)
        } else if self.bandwidth_bytes_per_second == 0.0 {
            // Only happens on the very first iteration
            None
        } else {
            let calculated_downtime_s =
                self.current_iteration_total_bytes as f64 / (self.bandwidth_bytes_per_second);
            Some(Duration::from_secs_f64(calculated_downtime_s))
        }
    }

    /// Updates the metrics right after the transfer over the wire.
    ///
    /// Supposed to be called once per precopy memory iteration.
    ///
    /// This updates the bandwidth and ensures that
    /// [`Self::update_metrics_before_transfer`] operates on fresh metrics on
    /// the new iteration.
    ///
    /// # Panics
    ///
    /// If the transfer duration is longer than the iteration duration, this
    /// function panics. This can never happen with real-world data but in
    /// artificial unit test scenarios.
    pub fn update_metrics_after_transfer(
        &mut self,
        transfer_begin: Instant,
        transfer_duration: Duration,
    ) {
        self.transfer_begin = transfer_begin;
        self.transfer_duration = Some(transfer_duration);
        self.total_sent_bytes += self.current_iteration_total_bytes;
        self.bandwidth_bytes_per_second =
            Self::calculate_bandwidth(self.current_iteration_total_bytes, transfer_duration);

        // We might have a few operations after that before the loop starts
        // (e.g., logging) again, but practically, this is negligible for this
        // metric.
        self.iteration_duration = Some(self.iteration_begin.elapsed());

        // Catch programming errors:
        // unwrap is fine as both values are set by now
        assert!(
            self.iteration_duration.unwrap() >= self.transfer_duration.unwrap(),
            "iteration_duration must be larger than transfer_duration: {}ms < {}ms",
            self.iteration_duration.unwrap().as_millis(),
            self.transfer_duration.unwrap().as_millis(),
        );
    }

    /// Finalizes the metrics.
    ///
    /// From now on, the metrics are considered finalized and should not be
    /// modified. They can be stored for further analysis.
    #[inline]
    pub fn finalize(&mut self) {
        // Any overhead from the function call is negligible.
        self.migration_duration = Some(self.migration_begin.elapsed());
    }

    /// Returns the average bandwidth over the whole duration of the migration.
    #[inline]
    pub fn average_bandwidth(&self) -> f64 {
        Self::calculate_bandwidth(self.total_sent_bytes, self.migration_begin.elapsed())
    }

    /// Calculates the bandwidth in bytes per second.
    ///
    /// Returns `0.0` if the duration is zero to avoid division by zero.
    #[inline]
    fn calculate_bandwidth(bytes: u64, duration: Duration) -> f64 {
        if duration == Duration::ZERO {
            0.0
        } else {
            bytes as f64 / duration.as_secs_f64()
        }
    }
}

impl Default for MemoryMigrationContext {
    fn default() -> Self {
        Self::new()
    }
}

// The display format must be a compact one-liner to enable concise log messages per iteration.
impl Display for MemoryMigrationContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let curr_mib = self.current_iteration_total_bytes.div_ceil(1024 * 1024);
        let total_mib = self.total_sent_bytes.div_ceil(1024 * 1024);

        // Current bandwidth in MiB/s
        let curr_bw_mib_s = self.bandwidth_bytes_per_second / 1024.0 / 1024.0;

        // Time elapsed since memory migration start.
        let elapsed = self
            .migration_duration
            .unwrap_or_else(|| Instant::now() - self.migration_begin)
            .as_secs_f64();

        // Internally, this again evaluates `self.migration_begin.elapsed()`
        // but this is negligible.
        let avg_bw_mib_s = self.average_bandwidth() / 1024.0 / 1024.0;

        // Transfer duration and iteration overhead
        let transfer_s = self.transfer_duration.map_or(0.0, |d| d.as_secs_f64());
        let iteration_overhead_ms = self
            .iteration_duration
            .and_then(|iter| {
                self.transfer_duration.map(|tr| {
                    // This is guaranteed by update_metrics_after_transfer()
                    assert!(iter >= tr);
                    (iter - tr).as_millis()
                })
            })
            .unwrap_or(0);

        let est_downtime_ms = self.estimated_downtime.map_or(0, |d| d.as_millis());

        write!(
            f,
            "iter={} \
            curr={curr_mib}MiB \
            total={total_mib}MiB \
            bw={curr_bw_mib_s:.2}MiB/s \
            transfer={transfer_s:.2}s \
            overhead={iteration_overhead_ms}ms \
            est_downtime={est_downtime_ms}ms \
            elapsed={elapsed:.2}s \
            avg_bw={avg_bw_mib_s:.2}MiB/s",
            self.iteration,
        )
    }
}

#[cfg(test)]
mod unit_tests {
    use std::time::{Duration, Instant};

    use super::*;
    use crate::protocol::MemoryRange;

    fn make_table(bytes: u64) -> MemoryRangeTable {
        let mut table = MemoryRangeTable::default();
        if bytes > 0 {
            table.push(MemoryRange {
                gpa: 0,
                length: bytes,
            });
        }
        table
    }

    /// A controlled migration scenario with fixed timing offsets.
    ///
    /// ```text
    /// migration_begin
    ///   + 1.0s -> iteration_begin
    ///   + 1.1s -> transfer_begin
    ///   + 2.0s -> transfer ends   (transfer_duration = 0.9s)
    ///   + 2.1s -> iteration ends  (iteration_duration = 1.1s, overhead = 0.2s)
    /// ```
    struct Scenario {
        migration_begin: Instant,
        iteration_begin: Instant,
        transfer_begin: Instant,
        transfer_duration: Duration,
    }

    impl Scenario {
        /// We use a fixed point in the past so all offsets are in the past too,
        /// meaning elapsed() calls in the code under test will be >= our durations.
        const FIXPOINT_PAST: Duration = Duration::from_secs(10);

        fn new() -> Self {
            // Use a fixed point in the past so all offsets are in the past too,
            // meaning elapsed() calls in the code under test will be >= our durations.
            let migration_begin = Instant::now() - Self::FIXPOINT_PAST;
            Self {
                migration_begin,
                iteration_begin: migration_begin + Duration::from_millis(1000),
                transfer_begin: migration_begin + Duration::from_millis(1100),
                transfer_duration: Duration::from_millis(900),
            }
        }

        fn make_ctx(&self) -> MemoryMigrationContext {
            let mut ctx = MemoryMigrationContext::new();
            // Override migration_begin with our controlled value.
            ctx.migration_begin = self.migration_begin;
            ctx
        }
    }

    #[test]
    fn before_transfer_updates_begin_and_bytes() {
        let s = Scenario::new();
        let mut ctx = s.make_ctx();

        ctx.update_metrics_before_transfer(s.iteration_begin, &make_table(4096));

        assert_eq!(ctx.iteration_begin, s.iteration_begin);
        assert_eq!(ctx.current_iteration_total_bytes, 4096);
    }

    #[test]
    fn before_transfer_estimated_downtime() {
        let s = Scenario::new();
        let mut ctx = s.make_ctx();

        // Empty table -> zero downtime regardless of bandwidth
        ctx.update_metrics_before_transfer(s.iteration_begin, &make_table(0));
        assert_eq!(ctx.estimated_downtime, Some(Duration::ZERO));

        // No bandwidth yet -> None
        ctx.update_metrics_before_transfer(s.iteration_begin, &make_table(1024));
        assert_eq!(ctx.estimated_downtime, None);

        // 1024 B/s, 1024 bytes -> 1s
        ctx.bandwidth_bytes_per_second = 1024.0;
        ctx.update_metrics_before_transfer(s.iteration_begin, &make_table(1024));
        assert_eq!(ctx.estimated_downtime, Some(Duration::from_secs(1)));
    }

    #[test]
    fn after_transfer_updates_timing_and_bandwidth() {
        let s = Scenario::new();
        let mut ctx = s.make_ctx();

        ctx.update_metrics_before_transfer(s.iteration_begin, &make_table(1024));
        ctx.update_metrics_after_transfer(s.transfer_begin, s.transfer_duration);

        assert_eq!(ctx.transfer_begin, s.transfer_begin);
        assert_eq!(ctx.transfer_duration, Some(s.transfer_duration));
        // 1024 bytes / 0.9s
        assert_eq!(ctx.bandwidth_bytes_per_second, 1024.0 / 0.9);
        // iteration_duration = time from iteration_begin until now (>= transfer_duration)
        assert!(ctx.iteration_duration.unwrap() >= s.transfer_duration);
        // Zero transfer_duration -> bandwidth is 0.0, no division by zero
        ctx.update_metrics_before_transfer(s.iteration_begin, &make_table(1024));
        ctx.update_metrics_after_transfer(s.transfer_begin, Duration::ZERO);
        assert_eq!(ctx.bandwidth_bytes_per_second, 0.0);

        // Check finalize() sets migration duration
        assert_eq!(ctx.migration_duration, None);
        ctx.finalize();
        assert!(matches!(ctx.migration_duration, Some(d) if d >= Scenario::FIXPOINT_PAST));
    }

    #[test]
    fn two_iterations_accumulate_bytes_and_feed_downtime_estimate() {
        let s = Scenario::new();
        let mut ctx = s.make_ctx();

        // Iteration 0: no bandwidth yet -> downtime is None
        ctx.update_metrics_before_transfer(s.iteration_begin, &make_table(1024));
        assert_eq!(ctx.estimated_downtime, None);
        ctx.update_metrics_after_transfer(s.transfer_begin, s.transfer_duration);
        assert_eq!(ctx.total_sent_bytes, 1024);

        // Iteration 1: bandwidth now known -> downtime is Some
        ctx.update_metrics_before_transfer(s.iteration_begin, &make_table(2048));
        assert!(ctx.estimated_downtime.is_some());
        ctx.update_metrics_after_transfer(s.transfer_begin, s.transfer_duration);
        assert_eq!(ctx.total_sent_bytes, 1024 + 2048);

        // Check finalize() sets migration duration
        assert_eq!(ctx.migration_duration, None);
        ctx.finalize();
        assert!(matches!(ctx.migration_duration, Some(d) if d >= Scenario::FIXPOINT_PAST));
    }

    #[test]
    /// The display format is specifically crafted to be very insightful in logs.
    /// Therefore, we have a dedicated test for that format.
    fn display_format() {
        let s = Scenario::new();
        let mut ctx = s.make_ctx();

        // Iteration 0: 1 MiB in 1s
        ctx.update_metrics_before_transfer(s.iteration_begin, &make_table(1024 * 1024));
        ctx.update_metrics_after_transfer(s.transfer_begin, Duration::from_secs(1));
        ctx.iteration += 1;

        // Iteration 1: 512 KiB in 1s; fix migration_duration for deterministic elapsed/avg_bw
        ctx.update_metrics_before_transfer(s.iteration_begin, &make_table(512 * 1024));
        ctx.update_metrics_after_transfer(s.transfer_begin, Duration::from_secs(1));

        ctx.migration_duration = Some(Duration::from_secs(2));
        let out = ctx.to_string();

        assert_eq!(
            out,
            "iter=1 curr=1MiB total=2MiB bw=0.50MiB/s transfer=1.00s overhead=8000ms est_downtime=500ms elapsed=2.00s avg_bw=0.15MiB/s"
        );

        // Should change elapsed() time!
        // Since this is at least 10s, we never face timing issues in CI!
        ctx.finalize();
        let out2 = ctx.to_string();
        assert_ne!(out2, out, "elapsed time should have changed! is={out2}");
    }
}
