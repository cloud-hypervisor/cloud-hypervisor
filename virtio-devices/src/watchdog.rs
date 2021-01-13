// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
//
// Copyright © 2020 Intel Corporation
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

use super::Error as DeviceError;
use super::{
    ActivateError, ActivateResult, EpollHelper, EpollHelperError, EpollHelperHandler, Queue,
    VirtioCommon, VirtioDevice, VirtioDeviceType, EPOLL_HELPER_EVENT_LAST, VIRTIO_F_VERSION_1,
};
use crate::seccomp_filters::{get_seccomp_filter, Thread};
use crate::{VirtioInterrupt, VirtioInterruptType};
use anyhow::anyhow;
use seccomp::{SeccompAction, SeccompFilter};
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::result;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::Instant;
use vm_memory::{Bytes, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};
use vm_migration::{
    Migratable, MigratableError, Pausable, Snapshot, SnapshotDataSection, Snapshottable,
    Transportable,
};
use vmm_sys_util::eventfd::EventFd;

const QUEUE_SIZE: u16 = 8;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE];

// New descriptors are pending on the virtio queue.
const QUEUE_AVAIL_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;
// Timer expired
const TIMER_EXPIRED_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 2;

// Number of seconds to check to see if there has been a ping
// This needs to match what the driver is using.
const WATCHDOG_TIMER_INTERVAL: i64 = 15;

// Number of seconds since last ping to trigger reboot
const WATCHDOG_TIMEOUT: u64 = WATCHDOG_TIMER_INTERVAL as u64 + 5;

struct WatchdogEpollHandler {
    queues: Vec<Queue>,
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    queue_evt: EventFd,
    kill_evt: EventFd,
    pause_evt: EventFd,
    timer: File,
    last_ping_time: Arc<Mutex<Option<Instant>>>,
    reset_evt: EventFd,
}

impl WatchdogEpollHandler {
    // The main queue is very simple - the driver "pings" the device by passing it a (write-only)
    // descriptor. In response the device writes a 1 into the descriptor and returns it to the driver
    fn process_queue(&mut self) -> bool {
        let queue = &mut self.queues[0];
        let mut used_desc_heads = [(0, 0); QUEUE_SIZE as usize];
        let mut used_count = 0;
        let mem = self.mem.memory();
        for avail_desc in queue.iter(&mem) {
            let mut len = 0;

            if avail_desc.is_write_only() && mem.write_obj(1u8, avail_desc.addr).is_ok() {
                len = avail_desc.len;
                // If this is the first "ping" then setup the timer
                if self.last_ping_time.lock().unwrap().is_none() {
                    info!(
                        "First ping received. Starting timer (every {} seconds)",
                        WATCHDOG_TIMER_INTERVAL
                    );
                    if let Err(e) = timerfd_setup(&self.timer, WATCHDOG_TIMER_INTERVAL) {
                        error!("Error programming timer fd: {:?}", e);
                    }
                }
                self.last_ping_time.lock().unwrap().replace(Instant::now());
            }

            used_desc_heads[used_count] = (avail_desc.index, len);
            used_count += 1;
        }

        for &(desc_index, len) in &used_desc_heads[..used_count] {
            queue.add_used(&mem, desc_index, len);
        }
        used_count > 0
    }

    fn signal_used_queue(&self) -> result::Result<(), DeviceError> {
        self.interrupt_cb
            .trigger(&VirtioInterruptType::Queue, Some(&self.queues[0]))
            .map_err(|e| {
                error!("Failed to signal used queue: {:?}", e);
                DeviceError::FailedSignalingUsedQueue(e)
            })
    }

    fn run(
        &mut self,
        paused: Arc<AtomicBool>,
        paused_sync: Arc<Barrier>,
    ) -> result::Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;
        helper.add_event(self.queue_evt.as_raw_fd(), QUEUE_AVAIL_EVENT)?;
        helper.add_event(self.timer.as_raw_fd(), TIMER_EXPIRED_EVENT)?;
        helper.run(paused, paused_sync, self)?;

        Ok(())
    }
}

impl EpollHelperHandler for WatchdogEpollHandler {
    fn handle_event(&mut self, _helper: &mut EpollHelper, event: &epoll::Event) -> bool {
        let ev_type = event.data as u16;
        match ev_type {
            QUEUE_AVAIL_EVENT => {
                if let Err(e) = self.queue_evt.read() {
                    error!("Failed to get queue event: {:?}", e);
                    return true;
                } else if self.process_queue() {
                    if let Err(e) = self.signal_used_queue() {
                        error!("Failed to signal used queue: {:?}", e);
                        return true;
                    }
                }
            }
            TIMER_EXPIRED_EVENT => {
                // When reading from the timerfd you get 8 bytes indicating
                // the number of times this event has elapsed since the last read.
                let mut buf = vec![0; 8];
                if let Err(e) = self.timer.read_exact(&mut buf) {
                    error!("Error reading from timer fd: {:}", e);
                    return true;
                }
                if let Some(last_ping_time) = self.last_ping_time.lock().unwrap().as_ref() {
                    let now = Instant::now();
                    let gap = now.duration_since(*last_ping_time).as_secs();
                    if gap > WATCHDOG_TIMEOUT {
                        error!("Watchdog triggered: {} seconds since last ping", gap);
                        self.reset_evt.write(1).ok();
                    }
                }
                return false;
            }
            _ => {
                error!("Unexpected event: {}", ev_type);
                return true;
            }
        }
        false
    }
}

/// Virtio device for exposing a watchdog to the guest
pub struct Watchdog {
    common: VirtioCommon,
    id: String,
    seccomp_action: SeccompAction,
    reset_evt: EventFd,
    last_ping_time: Arc<Mutex<Option<Instant>>>,
    timer: File,
}

#[derive(Serialize, Deserialize)]
pub struct WatchdogState {
    pub avail_features: u64,
    pub acked_features: u64,
    pub enabled: bool,
}

impl Watchdog {
    /// Create a new virtio watchdog device that will reboot VM if the guest hangs
    pub fn new(
        id: String,
        reset_evt: EventFd,
        seccomp_action: SeccompAction,
    ) -> io::Result<Watchdog> {
        let avail_features = 1u64 << VIRTIO_F_VERSION_1;
        let timer_fd = timerfd_create().map_err(|e| {
            error!("Failed to create timer fd {}", e);
            e
        })?;
        let timer = unsafe { File::from_raw_fd(timer_fd) };
        Ok(Watchdog {
            common: VirtioCommon {
                device_type: VirtioDeviceType::TYPE_WATCHDOG as u32,
                queue_sizes: QUEUE_SIZES.to_vec(),
                paused_sync: Some(Arc::new(Barrier::new(2))),
                avail_features,
                ..Default::default()
            },
            id,
            seccomp_action,
            reset_evt,
            last_ping_time: Arc::new(Mutex::new(None)),
            timer,
        })
    }

    fn state(&self) -> WatchdogState {
        WatchdogState {
            avail_features: self.common.avail_features,
            acked_features: self.common.acked_features,
            enabled: self.last_ping_time.lock().unwrap().is_some(),
        }
    }

    fn set_state(&mut self, state: &WatchdogState) -> io::Result<()> {
        self.common.avail_features = state.avail_features;
        self.common.acked_features = state.acked_features;
        // When restoring enable the watchdog if it was previously enabled. We reset the timer
        // to ensure that we don't unnecesarily reboot due to the offline time.
        if state.enabled {
            self.last_ping_time.lock().unwrap().replace(Instant::now());
        }
        Ok(())
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.common.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
    }
}

fn timerfd_create() -> Result<RawFd, io::Error> {
    let res = unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, 0) };
    if res < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(res as RawFd)
    }
}

fn timerfd_setup(timer: &File, secs: i64) -> Result<(), io::Error> {
    let periodic = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: secs,
            tv_nsec: 0,
        },
        it_value: libc::timespec {
            tv_sec: secs,
            tv_nsec: 0,
        },
    };

    let res =
        unsafe { libc::timerfd_settime(timer.as_raw_fd(), 0, &periodic, std::ptr::null_mut()) };

    if res < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

impl VirtioDevice for Watchdog {
    fn device_type(&self) -> u32 {
        self.common.device_type
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.common.queue_sizes
    }

    fn features(&self) -> u64 {
        self.common.avail_features
    }

    fn ack_features(&mut self, value: u64) {
        self.common.ack_features(value)
    }

    fn activate(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        interrupt_cb: Arc<dyn VirtioInterrupt>,
        queues: Vec<Queue>,
        mut queue_evts: Vec<EventFd>,
    ) -> ActivateResult {
        self.common.activate(&queues, &queue_evts, &interrupt_cb)?;
        let kill_evt = self
            .common
            .kill_evt
            .as_ref()
            .unwrap()
            .try_clone()
            .map_err(|e| {
                error!("Failed to clone kill_evt eventfd: {}", e);
                ActivateError::BadActivate
            })?;
        let pause_evt = self
            .common
            .pause_evt
            .as_ref()
            .unwrap()
            .try_clone()
            .map_err(|e| {
                error!("Failed to clone pause_evt eventfd: {}", e);
                ActivateError::BadActivate
            })?;

        let reset_evt = self.reset_evt.try_clone().map_err(|e| {
            error!("Failed to clone reset_evt eventfd: {}", e);
            ActivateError::BadActivate
        })?;

        let timer = self.timer.try_clone().map_err(|e| {
            error!("Failed to clone timer fd: {}", e);
            ActivateError::BadActivate
        })?;

        let mut handler = WatchdogEpollHandler {
            queues,
            mem,
            interrupt_cb,
            queue_evt: queue_evts.remove(0),
            kill_evt,
            pause_evt,
            timer,
            last_ping_time: self.last_ping_time.clone(),
            reset_evt,
        };

        let paused = self.common.paused.clone();
        let paused_sync = self.common.paused_sync.clone();
        let mut epoll_threads = Vec::new();
        // Retrieve seccomp filter for virtio_watchdog thread
        let virtio_watchdog_seccomp_filter =
            get_seccomp_filter(&self.seccomp_action, Thread::VirtioWatchdog)
                .map_err(ActivateError::CreateSeccompFilter)?;
        thread::Builder::new()
            .name(self.id.clone())
            .spawn(move || {
                if let Err(e) = SeccompFilter::apply(virtio_watchdog_seccomp_filter) {
                    error!("Error applying seccomp filter: {:?}", e);
                } else if let Err(e) = handler.run(paused, paused_sync.unwrap()) {
                    error!("Error running worker: {:?}", e);
                }
            })
            .map(|thread| epoll_threads.push(thread))
            .map_err(|e| {
                error!("failed to clone the virtio-watchdog epoll thread: {}", e);
                ActivateError::BadActivate
            })?;

        self.common.epoll_threads = Some(epoll_threads);

        Ok(())
    }

    fn reset(&mut self) -> Option<(Arc<dyn VirtioInterrupt>, Vec<EventFd>)> {
        self.common.reset()
    }
}

impl Pausable for Watchdog {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        info!("Watchdog paused - disabling timer");
        timerfd_setup(&self.timer, 0)
            .map_err(|e| MigratableError::Pause(anyhow!("Error clearing timer: {:?}", e)))?;
        self.common.pause()
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        // Reset the timer on pause if it was previously used
        if self.last_ping_time.lock().unwrap().is_some() {
            info!(
                "Watchdog resumed - enabling timer (every {} seconds)",
                WATCHDOG_TIMER_INTERVAL
            );
            self.last_ping_time.lock().unwrap().replace(Instant::now());
            timerfd_setup(&self.timer, WATCHDOG_TIMER_INTERVAL)
                .map_err(|e| MigratableError::Resume(anyhow!("Error setting timer: {:?}", e)))?;
        }
        self.common.resume()
    }
}

impl Snapshottable for Watchdog {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        let snapshot =
            serde_json::to_vec(&self.state()).map_err(|e| MigratableError::Snapshot(e.into()))?;

        let mut watchdog_snapshot = Snapshot::new(self.id.as_str());
        watchdog_snapshot.add_data_section(SnapshotDataSection {
            id: format!("{}-section", self.id),
            snapshot,
        });

        Ok(watchdog_snapshot)
    }

    fn restore(&mut self, snapshot: Snapshot) -> std::result::Result<(), MigratableError> {
        if let Some(watchdog_section) = snapshot.snapshot_data.get(&format!("{}-section", self.id))
        {
            let watchdog_state = match serde_json::from_slice(&watchdog_section.snapshot) {
                Ok(state) => state,
                Err(error) => {
                    return Err(MigratableError::Restore(anyhow!(
                        "Could not deserialize watchdog {}",
                        error
                    )))
                }
            };

            return self.set_state(&watchdog_state).map_err(|e| {
                MigratableError::Restore(anyhow!("Could not restore watchdog state {:?}", e))
            });
        }

        Err(MigratableError::Restore(anyhow!(
            "Could not find watchdog snapshot section"
        )))
    }
}

impl Transportable for Watchdog {}
impl Migratable for Watchdog {}
