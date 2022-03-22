// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::Error as DeviceError;
use super::{
    ActivateError, ActivateResult, EpollHelper, EpollHelperError, EpollHelperHandler, VirtioCommon,
    VirtioDevice, VirtioDeviceType, EPOLL_HELPER_EVENT_LAST, VIRTIO_F_IOMMU_PLATFORM,
    VIRTIO_F_VERSION_1,
};
use crate::seccomp_filters::Thread;
use crate::thread_helper::spawn_virtio_thread;
use crate::GuestMemoryMmap;
use crate::{VirtioInterrupt, VirtioInterruptType};
use seccompiler::SeccompAction;
use std::fs::File;
use std::io;
use std::os::unix::io::AsRawFd;
use std::result;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Barrier};
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;
use virtio_queue::Queue;
use vm_memory::{Bytes, GuestMemoryAtomic};
use vm_migration::VersionMapped;
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
use vm_virtio::{AccessPlatform, Translatable};
use vmm_sys_util::eventfd::EventFd;

const QUEUE_SIZE: u16 = 256;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE];

// New descriptors are pending on the virtio queue.
const QUEUE_AVAIL_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;

struct RngEpollHandler {
    queues: Vec<Queue<GuestMemoryAtomic<GuestMemoryMmap>>>,
    random_file: File,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    queue_evt: EventFd,
    kill_evt: EventFd,
    pause_evt: EventFd,
    access_platform: Option<Arc<dyn AccessPlatform>>,
}

impl RngEpollHandler {
    fn process_queue(&mut self) -> bool {
        let queue = &mut self.queues[0];

        let mut used_desc_heads = [(0, 0); QUEUE_SIZE as usize];
        let mut used_count = 0;
        for mut desc_chain in queue.iter().unwrap() {
            let desc = desc_chain.next().unwrap();
            let mut len = 0;

            // Drivers can only read from the random device.
            if desc.is_write_only() {
                // Fill the read with data from the random device on the host.
                if desc_chain
                    .memory()
                    .read_from(
                        desc.addr()
                            .translate(self.access_platform.as_ref(), desc.len() as usize),
                        &mut self.random_file,
                        desc.len() as usize,
                    )
                    .is_ok()
                {
                    len = desc.len();
                }
            }

            used_desc_heads[used_count] = (desc_chain.head_index(), len);
            used_count += 1;
        }

        for &(desc_index, len) in &used_desc_heads[..used_count] {
            queue.add_used(desc_index, len).unwrap();
        }
        used_count > 0
    }

    fn signal_used_queue(&self) -> result::Result<(), DeviceError> {
        self.interrupt_cb
            .trigger(VirtioInterruptType::Queue(0))
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
    exit_evt: EventFd,
}

#[derive(Versionize)]
pub struct RngState {
    pub avail_features: u64,
    pub acked_features: u64,
}

impl VersionMapped for RngState {}

impl Rng {
    /// Create a new virtio rng device that gets random data from /dev/urandom.
    pub fn new(
        id: String,
        path: &str,
        iommu: bool,
        seccomp_action: SeccompAction,
        exit_evt: EventFd,
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
            exit_evt,
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
        _mem: GuestMemoryAtomic<GuestMemoryMmap>,
        interrupt_cb: Arc<dyn VirtioInterrupt>,
        queues: Vec<Queue<GuestMemoryAtomic<GuestMemoryMmap>>>,
        mut queue_evts: Vec<EventFd>,
        _resample_evt: Option<EventFd>,
    ) -> ActivateResult {
        self.common.activate(&queues, &queue_evts, &interrupt_cb)?;
        let (kill_evt, pause_evt) = self.common.dup_eventfds();

        if let Some(file) = self.random_file.as_ref() {
            let random_file = file.try_clone().map_err(|e| {
                error!("failed cloning rng source: {}", e);
                ActivateError::BadActivate
            })?;
            let mut handler = RngEpollHandler {
                queues,
                random_file,
                interrupt_cb,
                queue_evt: queue_evts.remove(0),
                kill_evt,
                pause_evt,
                access_platform: self.common.access_platform.clone(),
            };

            let paused = self.common.paused.clone();
            let paused_sync = self.common.paused_sync.clone();
            let mut epoll_threads = Vec::new();
            spawn_virtio_thread(
                &self.id,
                &self.seccomp_action,
                Thread::VirtioRng,
                &mut epoll_threads,
                &self.exit_evt,
                move || {
                    if let Err(e) = handler.run(paused, paused_sync.unwrap()) {
                        error!("Error running worker: {:?}", e);
                    }
                },
            )?;

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

    fn set_access_platform(&mut self, access_platform: Arc<dyn AccessPlatform>) {
        self.common.set_access_platform(access_platform)
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
        Snapshot::new_from_versioned_state(&self.id, &self.state())
    }

    fn restore(&mut self, snapshot: Snapshot) -> std::result::Result<(), MigratableError> {
        self.set_state(&snapshot.to_versioned_state(&self.id)?);
        Ok(())
    }
}

impl Transportable for Rng {}
impl Migratable for Rng {}
