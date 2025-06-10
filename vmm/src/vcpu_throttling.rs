// Copyright © 2025 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0

use std::ops::Deref;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use std::thread::{sleep, JoinHandle};
use std::time::{Duration, Instant};

use vm_migration::Pausable;

use crate::cpu::CpuManager;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum ThreadState {
    /// Waiting for next event.
    Waiting,
    /// Ongoing vCPU throttling.
    ///
    /// The inner value shows the current throttling percentage in range `1..=99`.
    Throttling(u8 /* `1..=99` */),
    /// Thread is shutting down gracefully.
    Exiting,
}

impl ThreadState {
    /// Returns the currently throttling level in percent.
    fn throttle_percent(&self) -> u8 {
        match self {
            ThreadState::Throttling(val) => *val,
            _ => 0,
        }
    }
}

/// Type to indicate state change acknowledgments between the handler and the
/// thread.
///
/// See:
/// - [`VcpuThrottleThreadHandle::CHANGE_ACK`]
/// - [`VcpuThrottleThreadHandle::CHANGE_NACK`]
type StateChangeAckT = bool;

type SynchronizedStateInner = (StateChangeAckT, ThreadState);
type SynchronizedState = (Mutex<SynchronizedStateInner>, Condvar);

/// Handler for controlling the vCPU throttle thread.
///
/// vCPU throttling is needed for live-migration of memory-intensive workloads.
/// The current design assumes that all vCPUs are throttled equally.
///
/// # States and Transitions
/// - `Waiting` -> `Throttle(x %)`, `Exit`
/// - `Throttle(x %)` -> `Waiting`, `Throttle(y %)`
/// - `Exit`
pub struct VcpuThrottleThreadHandle {
    /// Thread state wrapped by synchronization primitives.
    shared_state: Arc<SynchronizedState>,
    /// The underlying thread handle.
    // Option so that we can .take() the value later
    thread_handle: Option<JoinHandle<()>>,
}

impl VcpuThrottleThreadHandle {
    /// The timeslice for a throttling cycle (vCPU pause & resume).
    const TIMESLICE_MS: u64 = 500; // QEMU uses here 5000ms

    const THREAD_NAME: &'static str = "vcpu-throttle";

    /// State change acknowledge by thread.
    const CHANGE_ACK: StateChangeAckT = true;
    /// State change not yet acknowledge by thread.
    const CHANGE_NACK: StateChangeAckT = false;

    /// Waits for the thread to ACK the state.
    fn wait_for_thread_ack(&self, guard: MutexGuard<SynchronizedStateInner>) {
        debug!("Waiting for thread to ACK waiting state");
        let _guard = self
            .shared_state
            .1
            .wait_while(guard, |(ack, _)| *ack == Self::CHANGE_ACK);
        debug!("Thread has ACKed waiting state");
    }

    /// Updates the state of the thread, and - depending on the state change -
    /// waits for the state to become effective gracefully.
    ///
    /// This function behaves differently depending on the new [`ThreadState`]:
    /// - [`ThreadState::Waiting`]: Waits until thread is in wait state
    /// - [`ThreadState::Throttling`]: Returns right away and let the thread
    ///   start its work. In case of an ongoing throttling cycle
    ///   (vCPU pause & resume), the new state will be applied when the next
    ///   cycle starts.
    /// - [`ThreadState::Exiting`]: Returns right away as the thread exits
    ///   gracefully.
    fn set_state(&self, new_state: ThreadState) {
        let mut lock = self.shared_state.0.lock().unwrap();
        let (ack, current_thread_state) = &mut *lock;

        // Panic to catch bugs in the higher management layers.
        assert_ne!(new_state, *current_thread_state);

        *ack = Self::CHANGE_NACK;
        let old_thread_state = *current_thread_state;
        *current_thread_state = new_state;
        debug!("Setting new thread state: {new_state:?}");

        // This is the only state where the thread is actively waiting for new
        // commands. Unblock it.
        if old_thread_state == ThreadState::Waiting {
            self.shared_state.1.notify_one();
        }

        // The only state transition where we care for a synchronization.
        if new_state == ThreadState::Waiting {
            self.wait_for_thread_ack(lock);
        }
    }

    /// Helper that executes a callback and then sleeps. Ensures that the time
    /// to execute the callback is taken into the account and subtracted from
    /// the sleep time. In other words: The function takes as long as
    /// `target_duration`.
    fn run_min_execution_time_or_sleep(cb: &impl Fn(), target_duration: Duration) {
        let begin = Instant::now();
        cb();
        let cb_duration = begin.elapsed();
        debug!("cb_duration: {}ms", cb_duration.as_millis());
        let sleep_duration = target_duration.saturating_sub(cb_duration);
        if sleep_duration.as_millis() > 0 {
            sleep(sleep_duration);
        }
    }

    /// Helper for [`Self::build_thread_fn`] returning the function that performs
    /// the actual throttling.
    fn thread_fn_inner(
        shared_state: &SynchronizedState,
        throttle_callback: &impl Fn(),
        unthrottle_callback: &impl Fn(),
    ) {
        loop {
            let shared_state_guard = shared_state.0.lock().unwrap();
            let (_, thread_state) = &*shared_state_guard;
            if !matches!(*thread_state, ThreadState::Throttling(_)) {
                // Return to the control loop in case of a state change.
                break;
            }

            let throttle_percentage = thread_state.throttle_percent() as u64;

            // Dropping early, so that calls to `set_state` don't block.
            drop(shared_state_guard);

            let wait_ms_vcpus = Self::TIMESLICE_MS * throttle_percentage / 100;
            let wait_ms_thread = Self::TIMESLICE_MS - wait_ms_vcpus;

            // pause vCPUs
            Self::run_min_execution_time_or_sleep(
                throttle_callback,
                Duration::from_millis(wait_ms_vcpus),
            );
            // let vCPUs run
            Self::run_min_execution_time_or_sleep(
                unthrottle_callback,
                Duration::from_millis(wait_ms_thread),
            );
        }
    }

    /// Returns the threads main function.
    ///
    /// This wraps the actual throttling with the necessary thread state and
    /// lifecycle management.
    fn build_thread_fn(
        shared_state: Arc<SynchronizedState>,
        throttle_callback: impl Fn() + Send + 'static,
        unthrottle_callback: impl Fn() + Send + 'static,
    ) -> impl Fn() {
        move || {
            // In the outer loop, we gracefully wait for commands.
            'control: loop {
                let mut shared_state_guard = shared_state.0.lock().unwrap();

                // Handle special waiting case: go to sleep and replace state_guard
                let shared_state_guard = if shared_state_guard.deref().1 == ThreadState::Waiting {
                    // Notify handler we are waiting.
                    shared_state_guard.0 = Self::CHANGE_ACK;
                    shared_state.1.notify_one();

                    // Wait for a state change.
                    shared_state
                        .1
                        .wait_while(shared_state_guard, |(ack, _)| *ack == Self::CHANGE_NACK)
                        .unwrap()
                } else {
                    shared_state_guard
                };

                let (_ack, thread_state) = &*shared_state_guard;
                match *thread_state {
                    ThreadState::Exiting => {
                        break 'control;
                    }
                    ThreadState::Waiting => {
                        continue 'control;
                    }
                    ThreadState::Throttling(_) => {}
                }

                // Release lock early to enable handler to change the thread's
                // state while vCPU throttling is ongoing.
                drop(shared_state_guard);
                Self::thread_fn_inner(&shared_state, &throttle_callback, &unthrottle_callback);
            }
            debug!("thread exited gracefully");
        }
    }

    /// Spawns a new thread and returning a handle to it.
    ///
    /// This function returns when the thread gracefully arrived in
    /// [`ThreadState::Waiting`].
    ///
    /// # Parameters
    /// - `cpu_manager`: CPU manager to pause and resume vCPUs
    pub fn new_from_cpu_manager(cpu_manager: &Arc<Mutex<CpuManager>>) -> Self {
        let throttle_callback = {
            let cpu_manager = cpu_manager.clone();
            Box::new(move || cpu_manager.lock().unwrap().pause().unwrap())
        };

        let unthrottle_callback = {
            let cpu_manager = cpu_manager.clone();
            Box::new(move || cpu_manager.lock().unwrap().resume().unwrap())
        };

        Self::new(throttle_callback, unthrottle_callback)
    }

    /// Spawns a new thread and returning a handle to it.
    ///
    /// This function returns when the thread gracefully arrived in
    /// [`ThreadState::Waiting`].
    ///
    /// # Parameters
    /// - `throttle_callback`: Function putting all vCPUs into pause state. The
    ///   function must not perform any artificial delay itself.
    /// - `unthrottle_callback`: Function putting all vCPUs back into running
    ///   state. The function must not perform any artificial delay itself.
    fn new(
        throttle_callback: Box<dyn Fn() + Send + 'static>,
        unthrottle_callback: Box<dyn Fn() + Send + 'static>,
    ) -> Self {
        let initial_state = (Self::CHANGE_NACK, ThreadState::Waiting);
        let shared_state = Arc::new((Mutex::new(initial_state), Condvar::new()));

        let handle = {
            let thread_fn =
                Self::build_thread_fn(shared_state.clone(), throttle_callback, unthrottle_callback);
            thread::Builder::new()
                .name(String::from(Self::THREAD_NAME))
                .spawn(thread_fn)
                .expect("should spawn thread")
        };

        let this = Self {
            shared_state,
            thread_handle: Some(handle),
        };

        let guard = this.shared_state.0.lock().unwrap();
        this.wait_for_thread_ack(guard);

        this
    }

    /// Set's the throttle percentage to a value in range `0..=99` and updates
    /// the thread's state.
    ///
    /// Setting the value back to `0` brings the thread back into a waiting
    /// state. This is a convenient wrapper around [`Self::set_state`].
    ///
    /// In case of an ongoing throttling cycle (vCPU pause & resume), the new
    /// will be applied when the cycle ends.
    ///
    /// # Panic
    /// Panics, if `percent_new` is not in range `0..=99`.
    pub fn set_throttle_percent(&self, percent_new: u8) {
        assert!(
            percent_new <= 100,
            "setting a percentage of 100 or above is not allowed: {percent_new}%"
        );

        // We have no problematic race condition here as in normal operation
        // there is exactly one thread calling these functions.
        let percent_old = self.throttle_percent();

        // Return early, no action needed.
        if percent_old == percent_new {
            return;
        }

        if percent_new == 0 {
            self.set_state(ThreadState::Waiting);
        } else {
            self.set_state(ThreadState::Throttling(percent_new));
        }
    }

    /// Get the current throttle percentage in range `0..=99`.
    ///
    /// Please note that the value is not synchronized.
    pub fn throttle_percent(&self) -> u8 {
        let shared_state_guard = self.shared_state.0.lock().unwrap();
        let state = shared_state_guard.deref().1;
        state.throttle_percent()
    }

    /// Stops and terminates the thread gracefully.
    ///
    /// Waits for the thread to finish.
    pub fn stop(&mut self) {
        if let Some(handle) = self.thread_handle.take() {
            self.set_state(ThreadState::Exiting);
            handle.join().expect("thread should have succeeded");
        }
    }
}

impl Drop for VcpuThrottleThreadHandle {
    fn drop(&mut self) {
        // Idempotent; in case this wasn't called.
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    /*fn setup_stderr_logger() {
        use log::{LevelFilter, Metadata, Record};;
        struct Logger;

        impl log::Log for Logger {
            fn enabled(&self, _metadata: &Metadata) -> bool {
                true
            }

            fn log(&self, record: &Record) {
                eprintln!("{}: {}", record.level(), record.args());
            }

            fn flush(&self) {}
        }

        static LOGGER: Logger = Logger;
        log::set_logger(&LOGGER).unwrap();
        log::set_max_level(LevelFilter::max());
    }*/

    #[test]
    fn test_thread_lifecycle() {
        //setup_stderr_logger();

        // Dummy CpuManager
        let cpus_throttled = Arc::new(AtomicBool::new(false));
        let throttle_callback = {
            let cpus_running = cpus_throttled.clone();
            Box::new(move || {
                let old = cpus_running.swap(true, Ordering::SeqCst);
                assert_eq!(old, false);
            })
        };
        let unthrottle_callback = {
            let cpus_running = cpus_throttled.clone();
            Box::new(move || {
                let old = cpus_running.swap(false, Ordering::SeqCst);
                assert_eq!(old, true);
            })
        };

        let mut handler = VcpuThrottleThreadHandle::new(throttle_callback, unthrottle_callback);
        handler.set_state(ThreadState::Throttling(5));
        sleep(Duration::from_millis(
            VcpuThrottleThreadHandle::TIMESLICE_MS,
        ));
        handler.set_state(ThreadState::Throttling(10));
        sleep(Duration::from_millis(
            VcpuThrottleThreadHandle::TIMESLICE_MS,
        ));

        // Assume we aborted vCPU throttling (or the live-migration at all).
        handler.set_state(ThreadState::Waiting);
        handler.set_state(ThreadState::Throttling(5));
        sleep(Duration::from_millis(
            VcpuThrottleThreadHandle::TIMESLICE_MS,
        ));
        handler.set_state(ThreadState::Throttling(10));
        sleep(Duration::from_millis(
            VcpuThrottleThreadHandle::TIMESLICE_MS,
        ));

        handler.stop();
    }
}
