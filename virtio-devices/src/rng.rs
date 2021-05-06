// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::Error as DeviceError;
use super::{
    ActivateError, ActivateResult, EpollHelper, EpollHelperError, EpollHelperHandler, Queue,
    VirtioCommon, VirtioDevice, VirtioDeviceType, EPOLL_HELPER_EVENT_LAST, VIRTIO_F_IOMMU_PLATFORM,
    VIRTIO_F_VERSION_1,
};
use crate::seccomp_filters::{get_seccomp_filter, Thread};
use crate::{VirtioInterrupt, VirtioInterruptType};
use seccomp::{SeccompAction, SeccompFilter};
use std::fs::File;
use std::io;
use std::os::unix::io::AsRawFd;
use std::result;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Barrier};
use std::thread;
use vm_memory::{Bytes, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
use vmm_sys_util::eventfd::EventFd;

const QUEUE_SIZE: u16 = 256;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE];

// New descriptors are pending on the virtio queue.
const QUEUE_AVAIL_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;

struct RngEpollHandler {
    queues: Vec<Queue>,
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
    random_file: File,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    queue_evt: EventFd,
    kill_evt: EventFd,
    pause_evt: EventFd,
}

impl RngEpollHandler {
    fn process_queue(&mut self) -> bool {
        let queue = &mut self.queues[0];

        let mut used_desc_heads = [(0, 0); QUEUE_SIZE as usize];
        let mut used_count = 0;
        let mem = self.mem.memory();
        for avail_desc in queue.iter(&mem) {
            let mut len = 0;

            // Drivers can only read from the random device.
            if avail_desc.is_write_only() {
                // Fill the read with data from the random device on the host.
                if mem
                    .read_from(
                        avail_desc.addr,
                        &mut self.random_file,
                        avail_desc.len as usize,
                    )
                    .is_ok()
                {
                    len = avail_desc.len;
                }
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
        helper.run(paused, paused_sync, self)?;

        Ok(())
    }
}

impl EpollHelperHandler for RngEpollHandler {
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
            _ => {
                error!("Unexpected event: {}", ev_type);
                return true;
            }
        }
        false
    }
}

/// Virtio device for exposing entropy to the guest OS through virtio.
pub struct Rng {
    common: VirtioCommon,
    id: String,
    random_file: Option<File>,
    seccomp_action: SeccompAction,
}

#[derive(Serialize, Deserialize)]
pub struct RngState {
    pub avail_features: u64,
    pub acked_features: u64,
}

impl Rng {
    /// Create a new virtio rng device that gets random data from /dev/urandom.
    pub fn new(
        id: String,
        path: &str,
        iommu: bool,
        seccomp_action: SeccompAction,
    ) -> io::Result<Rng> {
        let random_file = File::open(path)?;
        let mut avail_features = 1u64 << VIRTIO_F_VERSION_1;

        if iommu {
            avail_features |= 1u64 << VIRTIO_F_IOMMU_PLATFORM;
        }

        Ok(Rng {
            common: VirtioCommon {
                device_type: VirtioDeviceType::Rng as u32,
                queue_sizes: QUEUE_SIZES.to_vec(),
                paused_sync: Some(Arc::new(Barrier::new(2))),
                avail_features,
                min_queues: 1,
                ..Default::default()
            },
            id,
            random_file: Some(random_file),
            seccomp_action,
        })
    }

    fn state(&self) -> RngState {
        RngState {
            avail_features: self.common.avail_features,
            acked_features: self.common.acked_features,
        }
    }

    fn set_state(&mut self, state: &RngState) {
        self.common.avail_features = state.avail_features;
        self.common.acked_features = state.acked_features;
    }
}

impl Drop for Rng {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.common.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
    }
}

impl VirtioDevice for Rng {
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
                error!("failed to clone kill_evt eventfd: {}", e);
                ActivateError::BadActivate
            })?;
        let pause_evt = self
            .common
            .pause_evt
            .as_ref()
            .unwrap()
            .try_clone()
            .map_err(|e| {
                error!("failed to clone pause_evt eventfd: {}", e);
                ActivateError::BadActivate
            })?;

        if let Some(file) = self.random_file.as_ref() {
            let random_file = file.try_clone().map_err(|e| {
                error!("failed cloning rng source: {}", e);
                ActivateError::BadActivate
            })?;
            let mut handler = RngEpollHandler {
                queues,
                mem,
                random_file,
                interrupt_cb,
                queue_evt: queue_evts.remove(0),
                kill_evt,
                pause_evt,
            };

            let paused = self.common.paused.clone();
            let paused_sync = self.common.paused_sync.clone();
            let mut epoll_threads = Vec::new();
            // Retrieve seccomp filter for virtio_rng thread
            let virtio_rng_seccomp_filter =
                get_seccomp_filter(&self.seccomp_action, Thread::VirtioRng)
                    .map_err(ActivateError::CreateSeccompFilter)?;
            thread::Builder::new()
                .name(self.id.clone())
                .spawn(move || {
                    if let Err(e) = SeccompFilter::apply(virtio_rng_seccomp_filter) {
                        error!("Error applying seccomp filter: {:?}", e);
                    } else if let Err(e) = handler.run(paused, paused_sync.unwrap()) {
                        error!("Error running worker: {:?}", e);
                    }
                })
                .map(|thread| epoll_threads.push(thread))
                .map_err(|e| {
                    error!("failed to clone the virtio-rng epoll thread: {}", e);
                    ActivateError::BadActivate
                })?;

            self.common.epoll_threads = Some(epoll_threads);

            event!("virtio-device", "activated", "id", &self.id);
            return Ok(());
        }
        Err(ActivateError::BadActivate)
    }

    fn reset(&mut self) -> Option<Arc<dyn VirtioInterrupt>> {
        let result = self.common.reset();
        event!("virtio-device", "reset", "id", &self.id);
        result
    }
}

impl Pausable for Rng {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        self.common.pause()
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        self.common.resume()
    }
}

impl Snapshottable for Rng {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        Snapshot::new_from_state(&self.id, &self.state())
    }

    fn restore(&mut self, snapshot: Snapshot) -> std::result::Result<(), MigratableError> {
        self.set_state(&snapshot.to_state(&self.id)?);
        Ok(())
    }
}

impl Transportable for Rng {}
impl Migratable for Rng {}
