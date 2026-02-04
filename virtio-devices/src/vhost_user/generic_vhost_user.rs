// Copyright 2019 Intel Corporation. All Rights Reserved.
// Copyright 2025 Demi Marie Obenour.
// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::{result, thread};

use event_monitor::event;
use log::{error, info, warn};
use seccompiler::SeccompAction;
use serde::{Deserialize, Serialize};
use vhost::vhost_user::message::{
    VhostUserConfigFlags, VhostUserProtocolFeatures, VhostUserVirtioFeatures,
};
use vhost::vhost_user::{FrontendReqHandler, VhostUserFrontend, VhostUserFrontendReqHandler};
use virtio_queue::Queue;
use vm_device::UserspaceMapping;
use vm_memory::GuestMemoryAtomic;
use vm_migration::protocol::MemoryRangeTable;
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
use vmm_sys_util::eventfd::EventFd;

use super::vu_common_ctrl::VhostUserHandle;
use super::{Error, Result};
use crate::seccomp_filters::Thread;
use crate::thread_helper::spawn_virtio_thread;
use crate::vhost_user::VhostUserCommon;
use crate::{
    ActivateResult, GuestMemoryMmap, GuestRegionMmap, MmapRegion, VIRTIO_F_IOMMU_PLATFORM,
    VirtioCommon, VirtioDevice, VirtioInterrupt, VirtioSharedMemoryList,
};

#[derive(Serialize, Deserialize)]
pub struct State {
    pub avail_features: u64,
    pub acked_features: u64,
    pub acked_protocol_features: u64,
    pub vu_num_queues: usize,
    pub backend_req_support: bool,
}

struct BackendReqHandler {}
impl VhostUserFrontendReqHandler for BackendReqHandler {}
pub struct GenericVhostUser {
    common: VirtioCommon,
    vu_common: VhostUserCommon,
    id: String,
    // Hold ownership of the memory that is allocated for the device
    // which will be automatically dropped when the device is dropped
    cache: Option<(VirtioSharedMemoryList, MmapRegion)>,
    seccomp_action: SeccompAction,
    guest_memory: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    epoll_thread: Option<thread::JoinHandle<()>>,
    exit_evt: EventFd,
    iommu: bool,
    cfg_warning: AtomicBool,
}

impl GenericVhostUser {
    /// Create a new generic vhost-user device.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        path: &str,
        request_queue_sizes: Vec<u16>,
        device_type: u32,
        cache: Option<(VirtioSharedMemoryList, MmapRegion)>,
        seccomp_action: SeccompAction,
        exit_evt: EventFd,
        iommu: bool,
        state: Option<State>,
    ) -> Result<GenericVhostUser> {
        // Calculate the actual number of queues needed.
        let num_queues = request_queue_sizes.len();

        // Connect to the vhost-user socket.
        let mut vu = VhostUserHandle::connect_vhost_user(false, path, num_queues as u64, false)?;

        let (avail_features, acked_features, acked_protocol_features, vu_num_queues, paused) =
            if let Some(state) = state {
                info!("Restoring generic vhost-user {id}");
                vu.set_protocol_features_vhost_user(
                    state.acked_features,
                    state.acked_protocol_features,
                )?;

                (
                    state.avail_features,
                    state.acked_features,
                    state.acked_protocol_features,
                    state.vu_num_queues,
                    true,
                )
            } else {
                let avail_protocol_features = VhostUserProtocolFeatures::CONFIG
                    | VhostUserProtocolFeatures::MQ
                    | VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS
                    | VhostUserProtocolFeatures::REPLY_ACK
                    | VhostUserProtocolFeatures::INFLIGHT_SHMFD
                    | VhostUserProtocolFeatures::LOG_SHMFD;

                let avail_features = super::DEFAULT_VIRTIO_FEATURES;

                let (acked_features, acked_protocol_features) =
                    vu.negotiate_features_vhost_user(avail_features, avail_protocol_features)?;

                let backend_num_queues =
                    if acked_protocol_features & VhostUserProtocolFeatures::MQ.bits() != 0 {
                        vu.socket_handle()
                            .get_queue_num()
                            .map_err(Error::VhostUserGetQueueMaxNum)?
                            as usize
                    } else {
                        num_queues
                    };

                if num_queues > backend_num_queues {
                    error!(
                        "generic vhost-user requested too many queues ({num_queues}) \
since the backend only supports {backend_num_queues}\n",
                    );
                    return Err(Error::BadQueueNum);
                }
                // Create virtio-vhost-user device configuration.
                (
                    acked_features,
                    // If part of the available features that have been acked, the
                    // PROTOCOL_FEATURES bit must be already set through the VIRTIO
                    // acked features as we know the guest would never ack it, thus
                    // the feature would be lost.
                    acked_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits(),
                    acked_protocol_features,
                    num_queues,
                    false,
                )
            };

        Ok(GenericVhostUser {
            common: VirtioCommon {
                device_type,
                avail_features,
                acked_features,
                queue_sizes: request_queue_sizes,
                paused_sync: Some(Arc::new(Barrier::new(2))),
                min_queues: 1,
                paused: Arc::new(AtomicBool::new(paused)),
                ..Default::default()
            },
            vu_common: VhostUserCommon {
                vu: Some(Arc::new(Mutex::new(vu))),
                acked_protocol_features,
                socket_path: path.to_string(),
                vu_num_queues,
                ..Default::default()
            },
            id,
            cache,
            seccomp_action,
            guest_memory: None,
            epoll_thread: None,
            exit_evt,
            iommu,
            cfg_warning: AtomicBool::new(false),
        })
    }

    fn state(&self) -> State {
        State {
            avail_features: self.common.avail_features,
            acked_features: self.common.acked_features,
            acked_protocol_features: self.vu_common.acked_protocol_features,
            vu_num_queues: self.vu_common.vu_num_queues,
            backend_req_support: false,
        }
    }

    #[cold]
    #[inline(never)]
    fn warn_no_config_access(&self) {
        if self
            .cfg_warning
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            warn!(
                "Attempt to read config space, but backend does not support config \
space access. Reads will return 0xFF and writes will be ignored."
            );
        }
    }
}

impl Drop for GenericVhostUser {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.common.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
        self.common.wait_for_epoll_threads();
        if let Some(thread) = self.epoll_thread.take()
            && let Err(e) = thread.join()
        {
            error!("Error joining thread: {e:?}");
        }
    }
}

impl VirtioDevice for GenericVhostUser {
    fn device_type(&self) -> u32 {
        self.common.device_type
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.common.queue_sizes
    }

    fn features(&self) -> u64 {
        let mut features = self.common.avail_features;
        if self.iommu {
            features |= 1u64 << VIRTIO_F_IOMMU_PLATFORM;
        }
        features
    }

    fn ack_features(&mut self, value: u64) {
        self.common.ack_features(value);
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        if (VhostUserProtocolFeatures::CONFIG.bits() & self.state().acked_protocol_features) == 0 {
            self.warn_no_config_access();

            data.fill(0xFF);
            return;
        }
        if let Err(e) = self
            .vu_common
            .vu
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .socket_handle()
            .get_config(
                offset.try_into().unwrap(),
                data.len().try_into().unwrap(),
                VhostUserConfigFlags::empty(),
                data,
            )
            .map(|(_, config)| data.copy_from_slice(&config))
        {
            panic!("Failed getting generic vhost-user configuration: {e}");
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        if (VhostUserProtocolFeatures::CONFIG.bits() & self.state().acked_protocol_features) == 0 {
            self.warn_no_config_access();
            return;
        }
        if let Err(e) = self
            .vu_common
            .vu
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .socket_handle()
            .set_config(
                offset.try_into().unwrap(),
                VhostUserConfigFlags::WRITABLE,
                data,
            )
        {
            panic!("Failed setting generic vhost-user configuration: {e}");
        }
    }

    fn activate(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        interrupt_cb: Arc<dyn VirtioInterrupt>,
        queues: Vec<(usize, Queue, EventFd)>,
    ) -> ActivateResult {
        self.common.activate(&queues, interrupt_cb.clone())?;
        self.guest_memory = Some(mem.clone());

        let backend_req_handler: Option<FrontendReqHandler<BackendReqHandler>> = None;
        // Run a dedicated thread for handling potential reconnections with
        // the backend.
        let (kill_evt, pause_evt) = self.common.dup_eventfds();

        let mut handler = self.vu_common.activate(
            mem,
            &queues,
            interrupt_cb,
            self.common.acked_features,
            backend_req_handler,
            kill_evt,
            pause_evt,
        )?;

        let paused = self.common.paused.clone();
        let paused_sync = self.common.paused_sync.clone();

        let mut epoll_threads = Vec::new();
        spawn_virtio_thread(
            &self.id,
            &self.seccomp_action,
            Thread::VirtioGenericVhostUser,
            &mut epoll_threads,
            &self.exit_evt,
            move || handler.run(&paused, paused_sync.as_ref().unwrap()),
        )?;
        self.epoll_thread = Some(epoll_threads.remove(0));

        event!("virtio-device", "activated", "id", &self.id);
        Ok(())
    }

    fn reset(&mut self) -> Option<Arc<dyn VirtioInterrupt>> {
        // We first must resume the virtio thread if it was paused.
        if self.common.pause_evt.take().is_some() {
            self.common.resume().ok()?;
        }

        if let Some(vu) = &self.vu_common.vu
            && let Err(e) = vu.lock().unwrap().reset_vhost_user()
        {
            error!("Failed to reset vhost-user daemon: {e:?}");
            return None;
        }

        if let Some(kill_evt) = self.common.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }

        event!("virtio-device", "reset", "id", &self.id);

        // Return the interrupt
        Some(self.common.interrupt_cb.take().unwrap())
    }

    fn shutdown(&mut self) {
        self.vu_common.shutdown();
    }

    fn get_shm_regions(&self) -> Option<VirtioSharedMemoryList> {
        self.cache.as_ref().map(|cache| cache.0.clone())
    }

    fn set_shm_regions(
        &mut self,
        shm_regions: VirtioSharedMemoryList,
    ) -> std::result::Result<(), crate::Error> {
        if let Some(cache) = self.cache.as_mut() {
            cache.0 = shm_regions;
            Ok(())
        } else {
            Err(crate::Error::SetShmRegionsNotSupported)
        }
    }

    fn add_memory_region(
        &mut self,
        region: &Arc<GuestRegionMmap>,
    ) -> std::result::Result<(), crate::Error> {
        self.vu_common.add_memory_region(&self.guest_memory, region)
    }

    fn userspace_mappings(&self) -> Vec<UserspaceMapping> {
        let mut mappings = Vec::new();
        if let Some(cache) = self.cache.as_ref() {
            mappings.push(UserspaceMapping {
                mem_slot: cache.0.mem_slot,
                addr: cache.0.addr,
                mapping: cache.0.mapping.clone(),
                mergeable: false,
            });
        }

        mappings
    }
}

impl Pausable for GenericVhostUser {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        self.vu_common.pause()?;
        self.common.pause()
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        self.common.resume()?;

        if let Some(epoll_thread) = &self.epoll_thread {
            epoll_thread.thread().unpark();
        }

        self.vu_common.resume()
    }
}

impl Snapshottable for GenericVhostUser {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        self.vu_common.snapshot(&self.state())
    }
}
impl Transportable for GenericVhostUser {}

impl Migratable for GenericVhostUser {
    fn start_dirty_log(&mut self) -> std::result::Result<(), MigratableError> {
        self.vu_common.start_dirty_log(&self.guest_memory)
    }

    fn stop_dirty_log(&mut self) -> std::result::Result<(), MigratableError> {
        self.vu_common.stop_dirty_log()
    }

    fn dirty_log(&mut self) -> std::result::Result<MemoryRangeTable, MigratableError> {
        self.vu_common.dirty_log(&self.guest_memory)
    }

    fn start_migration(&mut self) -> std::result::Result<(), MigratableError> {
        self.vu_common.start_migration()
    }

    fn complete_migration(&mut self) -> std::result::Result<(), MigratableError> {
        self.vu_common
            .complete_migration(self.common.kill_evt.take())
    }
}
