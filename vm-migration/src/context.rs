// Copyright © 2026 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

//! Module for context and metrics of migrations.
//!
//! Main exports:
//! - [`OngoingMigrationContext`]
//! - [`CompletedMigrationContext`]
//! - [`MemoryMigrationContext`]

use std::fmt;
use std::fmt::{Display, Formatter};
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::protocol::MemoryRangeTable;

/// Metrics of the VM downtime during a migration.
///
/// By downtime, we mean the time between the VM pause() and the corresponding
/// resume() on the destination. This downtime covers the time when the vCPUs
/// didn't execute a single instruction. The network downtime might be longer
/// and is not covered by this type.
///
/// This metric is only relevant for the migration of running VMs.
#[derive(Debug, PartialEq)]
pub struct DowntimeContext {
    /// The effective downtime Cloud Hypervisor observed (from the migration sender).
    ///
    /// This is roughly the sum of all the other durations.
    pub effective_downtime: Duration,
    /// The time of the final memory iteration.
    pub final_memory_iteration_dur: Duration,
    /// The time needed to aggregate the final VM state (i.e., snapshotting it).
    pub state_dur: Duration,
    /// The time needed to send the final VM state including deserializing it on
    /// the destination
    pub send_state_dur: Duration,
    /// The time of the completion request. This includes resuming the VM (if it
    /// was running before the migration).
    pub complete_dur: Duration,
}

impl Display for DowntimeContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            // Caution: This format is specifically crafted for the VMM log
            "{}ms (final_iter:{}ms state:{}ms send_state:{}ms complete:{}ms)",
            self.effective_downtime.as_millis(),
            self.final_memory_iteration_dur.as_millis(),
            self.state_dur.as_millis(),
            self.send_state_dur.as_millis(),
            self.complete_dur.as_millis()
        )
    }
}

/// The internal metrics of a completed migration.
///
/// The properties of this type help to investigate timings of the migration,
/// with specific focus on the VM downtime.
///
/// This type is static once it was created and should not change.
#[derive(Debug, PartialEq)]
pub struct CompletedMigrationContext {
    /// Total duration of the migration.
    pub migration_dur: Duration,
    pub downtime_ctx: DowntimeContext,
    /// The finalized context of the memory migration.
    pub memory_ctx: MemoryMigrationContext,
}

impl CompletedMigrationContext {
    fn new(
        migration_dur: Duration,
        effective_downtime: Duration,
        state_dur: Duration,
        send_state_dur: Duration,
        complete_dur: Duration,
        memory_ctx: MemoryMigrationContext,
    ) -> Self {
        Self {
            migration_dur,
            downtime_ctx: DowntimeContext {
                effective_downtime,
                final_memory_iteration_dur: memory_ctx.iteration_duration.unwrap_or_default(),
                state_dur,
                send_state_dur,
                complete_dur,
            },
            memory_ctx,
        }
    }
}

/// Error returned when the migration context is advanced in an invalid order.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MigrationContextError {
    /// The memory migration context was not finalized before transition.
    #[error("memory migration context should be finalized before pausing the VM")]
    MemoryContextNotFinalized,
    /// The transition to `VmPaused` was attempted from an invalid state.
    #[error("memory migration should only advance from the Begin state")]
    InvalidVmPausedTransition,
    /// Finalization was attempted before memory migration completed.
    #[error("migration should only finalize after memory migration completed")]
    InvalidFinalizeTransition,
}

/// Holds context and metrics about the current ongoing migration.
///
/// This is a state-machine to properly reflect the intermediate states and
/// their properties. This machine does not have a `Completed` variant in favor
/// of [`CompletedMigrationContext`], which is easier to work with.
#[derive(Debug, PartialEq)]
pub enum OngoingMigrationContext {
    /// Migration started.
    Begin {
        /// Begin of the migration.
        migration_begin: Instant,
    },
    /// VM memory fully transferred to the destination and the VM is paused.
    VmPaused {
        /// Begin of the migration.
        migration_begin: Instant,
        /// Downtime begin of the migration.
        downtime_begin: Instant,
        /// The finalized context of the memory migration.
        finalized_memory_ctx: MemoryMigrationContext,
    },
}

impl OngoingMigrationContext {
    /// Creates a new context.
    pub fn new() -> Self {
        Self::Begin {
            migration_begin: Instant::now(),
        }
    }

    /// Marks the memory migration as completed and records when downtime
    /// started. The VM is now in paused state.
    pub fn set_vm_paused(
        &mut self,
        downtime_begin: Instant,
        finalized_memory_ctx: MemoryMigrationContext,
    ) -> Result<(), MigrationContextError> {
        if finalized_memory_ctx.migration_duration.is_none() {
            return Err(MigrationContextError::MemoryContextNotFinalized);
        }
        let migration_begin = match self {
            Self::Begin { migration_begin } => *migration_begin,
            _ => return Err(MigrationContextError::InvalidVmPausedTransition),
        };
        *self = Self::VmPaused {
            migration_begin,
            downtime_begin,
            finalized_memory_ctx,
        };
        Ok(())
    }

    /// Finalizes the metrics and returns a [`CompletedMigrationContext`].
    ///
    /// This should be called right after the completed migration was
    /// acknowledged by the receiver. From now on, the metrics are considered
    /// finalized and should not be modified. They can be stored for further
    /// analysis.
    ///
    /// # Arguments
    /// - `state_dur`: The time needed to aggregate the final VM state (i.e.,
    ///   snapshotting it).
    /// - `send_state_dur`:  The time needed to send the final VM state
    ///   including deserializing it on the destination.
    /// - `complete_dur`: The time of the completion request. This includes
    ///   resuming the VM (if it was running before the migration).
    pub fn finalize(
        self,
        state_dur: Duration,
        send_state_dur: Duration,
        complete_dur: Duration,
    ) -> Result<CompletedMigrationContext, MigrationContextError> {
        let (migration_begin, downtime_begin, finalized_memory_ctx) = match self {
            Self::VmPaused {
                migration_begin,
                downtime_begin,
                finalized_memory_ctx,
            } => (migration_begin, downtime_begin, finalized_memory_ctx),
            _ => return Err(MigrationContextError::InvalidFinalizeTransition),
        };

        Ok(CompletedMigrationContext::new(
            migration_begin.elapsed(),
            downtime_begin.elapsed(),
            state_dur,
            send_state_dur,
            complete_dur,
            finalized_memory_ctx,
        ))
    }
}

impl Default for OngoingMigrationContext {
    fn default() -> Self {
        Self::new()
    }
}

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
    pub estimated_downtime: Option<Duration>,
    /// Begin of the memory migration.
    pub migration_begin: Instant,
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
    pub iteration_duration: Option<Duration>,
    /// Begin of the current transfer.
    transfer_begin: Instant,
    /// Duration of the current transfer.
    ///
    /// This is only `None` for iteration 0.
    pub transfer_duration: Option<Duration>,
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

    /// Calculates the overhead of an iteration.
    ///
    /// This is the additional time next to the transfer time and includes
    /// fetching and parsing the dirty log, for example.
    fn iteration_overhead(&self) -> Duration {
        self.iteration_duration
            .and_then(|iter| {
                self.transfer_duration.map(|tr| {
                    // This is guaranteed by update_metrics_after_transfer()
                    assert!(iter >= tr);
                    iter - tr
                })
            })
            .unwrap_or_default()
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
        let iteration_overhead_ms = self.iteration_overhead().as_millis();

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
    use super::*;

    /// Tests for [`CompletedMigrationContext`] and [`OngoingMigrationContext`].
    mod migration_ctx_tests {
        use super::*;

        #[test]
        fn memory_migrated_and_vm_paused_records_transition() {
            let mut ctx = OngoingMigrationContext::new();
            let downtime_begin = Instant::now();

            let mut memory_ctx = MemoryMigrationContext::new();
            memory_ctx.finalize();

            ctx.set_vm_paused(downtime_begin, memory_ctx)
                .expect("migration context should transition to VmPaused after memory migration");

            assert!(matches!(
                ctx,
                OngoingMigrationContext::VmPaused {
                    downtime_begin: recorded_downtime_begin,
                    ..
                } if recorded_downtime_begin == downtime_begin
            ));
        }

        #[test]
        fn finalize_returns_completed_context() {
            let mut ctx = OngoingMigrationContext::new();
            let downtime_begin = Instant::now() - Duration::from_millis(10);

            let mut memory_ctx = MemoryMigrationContext::new();
            memory_ctx.finalize();

            ctx.set_vm_paused(downtime_begin, memory_ctx)
                .expect("migration context should transition to VmPaused after memory migration");

            let completed = ctx
                .finalize(
                    Duration::from_millis(1),
                    Duration::from_millis(2),
                    Duration::from_millis(3),
                )
                .expect("migration context should finalize after memory migration completed");

            assert_eq!(completed.downtime_ctx.state_dur, Duration::from_millis(1));
            assert_eq!(
                completed.downtime_ctx.send_state_dur,
                Duration::from_millis(2)
            );
            assert_eq!(
                completed.downtime_ctx.complete_dur,
                Duration::from_millis(3)
            );
            assert!(completed.downtime_ctx.effective_downtime >= Duration::from_millis(10));
            assert!(completed.migration_dur > Duration::ZERO);
            assert!(completed.memory_ctx.migration_duration.is_some());
        }

        #[test]
        fn finalize_errors_before_memory_migration_completed() {
            let err = OngoingMigrationContext::new()
                .finalize(Duration::ZERO, Duration::ZERO, Duration::ZERO)
                .unwrap_err();

            assert_eq!(err, MigrationContextError::InvalidFinalizeTransition);
        }
    }

    /// Tests for [`MemoryMigrationContext`].
    mod memory_migration_ctx_tests {
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
}
