// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::result;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Barrier, Mutex};

use event_monitor::event;
use log::{error, info};
use seccompiler::SeccompAction;
use serde::{Deserialize, Serialize};
use serde_with::{Bytes, serde_as};
use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost::vhost_user::{FrontendReqHandler, VhostUserFrontend, VhostUserFrontendReqHandler};
use vm_device::UserspaceMapping;
use vm_memory::{ByteValued, GuestMemoryAtomic};
use vm_migration::protocol::MemoryRangeTable;
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
use vmm_sys_util::eventfd::EventFd;

use super::vu_common_ctrl::VhostUserHandle;
use super::{DEFAULT_VIRTIO_FEATURES, Error, Result};
use crate::seccomp_filters::Thread;
use crate::thread_helper::spawn_virtio_thread;
use crate::vhost_user::{VhostUserCommon, VhostUserState};
use crate::{
    ActivateResult, GuestMemoryMmap, GuestRegionMmap, MmapRegion, VIRTIO_F_ACCESS_PLATFORM,
    VirtioCommon, VirtioDevice, VirtioDeviceType, VirtioInterrupt, VirtioSharedMemoryList,
};

const NUM_QUEUE_OFFSET: usize = 1;
const DEFAULT_QUEUE_NUMBER: usize = 2;

pub type State = VhostUserState<VirtioFsConfig>;

struct BackendReqHandler {}
impl VhostUserFrontendReqHandler for BackendReqHandler {}

pub const VIRTIO_FS_TAG_LEN: usize = 36;
#[serde_as]
#[derive(Copy, Clone, Serialize, Deserialize)]
#[repr(C, packed)]
pub struct VirtioFsConfig {
    #[serde_as(as = "Bytes")]
    pub tag: [u8; VIRTIO_FS_TAG_LEN],
    pub num_request_queues: u32,
}

impl Default for VirtioFsConfig {
    fn default() -> Self {
        VirtioFsConfig {
            tag: [0; VIRTIO_FS_TAG_LEN],
            num_request_queues: 0,
        }
    }
}

// SAFETY: only a series of integers
unsafe impl ByteValued for VirtioFsConfig {}

pub struct Fs {
    vu_common: VhostUserCommon,
    id: String,
    config: VirtioFsConfig,
    // Hold ownership of the memory that is allocated for the device
    // which will be automatically dropped when the device is dropped
    cache: Option<(VirtioSharedMemoryList, MmapRegion)>,
    seccomp_action: SeccompAction,
    guest_memory: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    exit_evt: EventFd,
    access_platform_enabled: bool,
}

impl Fs {
    /// Create a new virtio-fs device.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        path: &str,
        tag: &str,
        req_num_queues: usize,
        queue_size: u16,
        cache: Option<(VirtioSharedMemoryList, MmapRegion)>,
        seccomp_action: SeccompAction,
        exit_evt: EventFd,
        access_platform_enabled: bool,
        state: Option<State>,
    ) -> Result<Fs> {
        // Calculate the actual number of queues needed.
        let num_queues = NUM_QUEUE_OFFSET + req_num_queues;

        // Connect to the vhost-user socket.
        let mut vu = VhostUserHandle::connect_vhost_user(false, path, num_queues as u64, false)?;

        let (
            avail_features,
            acked_features,
            acked_protocol_features,
            vu_num_queues,
            config,
            paused,
            vring_bases,
        ) = if let Some(state) = state {
            info!("Restoring vhost-user-fs {id}");

            vu.set_protocol_features_vhost_user(
                state.acked_features,
                state.acked_protocol_features,
            )?;

            vu.restore_state(&state)?;

            (
                state.avail_features,
                state.acked_features,
                state.acked_protocol_features,
                state.vu_num_queues,
                state.config,
                true,
                state.vring_bases,
            )
        } else {
            // Filling device and vring features VMM supports.
            let avail_features = DEFAULT_VIRTIO_FEATURES;

            let avail_protocol_features = VhostUserProtocolFeatures::MQ
                | VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS
                | VhostUserProtocolFeatures::REPLY_ACK
                | VhostUserProtocolFeatures::INFLIGHT_SHMFD
                | VhostUserProtocolFeatures::LOG_SHMFD
                | VhostUserProtocolFeatures::DEVICE_STATE;

            let (acked_features, acked_protocol_features) =
                vu.negotiate_features_vhost_user(avail_features, avail_protocol_features)?;

            let backend_num_queues =
                if acked_protocol_features & VhostUserProtocolFeatures::MQ.bits() != 0 {
                    vu.socket_handle()
                        .get_queue_num()
                        .map_err(Error::VhostUserGetQueueMaxNum)? as usize
                } else {
                    DEFAULT_QUEUE_NUMBER
                };

            if num_queues > backend_num_queues {
                error!(
                    "vhost-user-fs requested too many queues ({num_queues}) since the backend only supports {backend_num_queues}\n"
                );
                return Err(Error::BadQueueNum);
            }

            // Create virtio-fs device configuration.
            let mut config = VirtioFsConfig::default();
            let tag_bytes_slice = tag.as_bytes();
            let len = if tag_bytes_slice.len() < config.tag.len() {
                tag_bytes_slice.len()
            } else {
                config.tag.len()
            };
            config.tag[..len].copy_from_slice(tag_bytes_slice[..len].as_ref());
            config.num_request_queues = req_num_queues as u32;

            (
                acked_features,
                // If part of the available features that have been acked, the
                // PROTOCOL_FEATURES bit must be already set through the VIRTIO
                // acked features as we know the guest would never ack it, thus
                // the feature would be lost.
                acked_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits(),
                acked_protocol_features,
                num_queues,
                config,
                false,
                None,
            )
        };

        Ok(Fs {
            vu_common: VhostUserCommon {
                virtio_common: VirtioCommon {
                    device_type: VirtioDeviceType::Fs as u32,
                    avail_features,
                    acked_features,
                    queue_sizes: vec![queue_size; num_queues],
                    paused_sync: Some(Arc::new(Barrier::new(2))),
                    min_queues: 1,
                    paused: Arc::new(AtomicBool::new(paused)),
                    ..Default::default()
                },
                vu: Some(Arc::new(Mutex::new(vu))),
                acked_protocol_features,
                socket_path: path.to_string(),
                vu_num_queues,
                vring_bases,
                ..Default::default()
            },
            id,
            config,
            cache,
            seccomp_action,
            guest_memory: None,
            exit_evt,
            access_platform_enabled,
        })
    }

    fn state(&self) -> std::result::Result<State, MigratableError> {
        self.vu_common.state(self.config)
    }
}

impl Drop for Fs {
    fn drop(&mut self) {
        self.vu_common.shutdown();
    }
}

impl VirtioDevice for Fs {
    fn device_type(&self) -> u32 {
        self.vu_common.virtio_common.device_type
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.vu_common.virtio_common.queue_sizes
    }

    fn features(&self) -> u64 {
        let mut features = self.vu_common.virtio_common.avail_features;
        if self.access_platform_enabled {
            features |= 1u64 << VIRTIO_F_ACCESS_PLATFORM;
        }
        features
    }

    fn ack_features(&mut self, value: u64) {
        self.vu_common.virtio_common.ack_features(value);
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        self.read_config_from_slice(self.config.as_slice(), offset, data);
    }

    fn activate(&mut self, context: crate::device::ActivationContext) -> ActivateResult {
        let crate::device::ActivationContext {
            mem,
            interrupt_cb,
            queues,
            ..
        } = context;
        self.vu_common
            .virtio_common
            .activate(&queues, interrupt_cb.clone())?;
        self.guest_memory = Some(mem.clone());

        let backend_req_handler: Option<FrontendReqHandler<BackendReqHandler>> = None;
        // Run a dedicated thread for handling potential reconnections with
        // the backend.
        let (kill_evt, pause_evt) = self.vu_common.virtio_common.dup_eventfds();

        let mut handler = self.vu_common.activate(
            mem,
            &queues,
            interrupt_cb,
            self.vu_common.virtio_common.acked_features,
            backend_req_handler,
            kill_evt,
            pause_evt,
        )?;

        let paused = self.vu_common.virtio_common.paused.clone();
        let paused_sync = self.vu_common.virtio_common.paused_sync.clone();

        let mut epoll_threads = Vec::new();
        spawn_virtio_thread(
            &self.id,
            &self.seccomp_action,
            Thread::VirtioVhostFs,
            &mut epoll_threads,
            &self.exit_evt,
            move || handler.run(&paused, paused_sync.as_ref().unwrap()),
        )?;
        self.vu_common.epoll_thread = Some(epoll_threads.remove(0));

        event!("virtio-device", "activated", "id", &self.id);
        Ok(())
    }

    fn reset(&mut self) -> Option<Arc<dyn VirtioInterrupt>> {
        self.vu_common.reset(&self.id)
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

impl Pausable for Fs {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        self.vu_common.pause()?;
        self.vu_common.virtio_common.pause()
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        self.vu_common.virtio_common.resume()?;

        if let Some(epoll_thread) = &self.vu_common.epoll_thread {
            epoll_thread.thread().unpark();
        }

        self.vu_common.resume()
    }
}

impl Snapshottable for Fs {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        self.vu_common.snapshot(&self.state()?)
    }
}
impl Transportable for Fs {}

impl Migratable for Fs {
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
        self.vu_common.complete_migration()
    }
}
