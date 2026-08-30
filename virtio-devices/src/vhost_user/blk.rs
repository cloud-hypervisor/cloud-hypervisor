// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::mem::offset_of;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Barrier, Mutex};
use std::{io, result};

use block::VirtioBlockConfig;
use log::{error, info};
use seccompiler::SeccompAction;
use vhost::vhost_user::message::{
    VhostUserConfigFlags, VhostUserProtocolFeatures, VhostUserVirtioFeatures,
};
use vhost::vhost_user::{FrontendReqHandler, VhostUserFrontend, VhostUserFrontendReqHandler};
use virtio_bindings::virtio_blk::{
    VIRTIO_BLK_F_BLK_SIZE, VIRTIO_BLK_F_CONFIG_WCE, VIRTIO_BLK_F_DISCARD, VIRTIO_BLK_F_FLUSH,
    VIRTIO_BLK_F_GEOMETRY, VIRTIO_BLK_F_MQ, VIRTIO_BLK_F_RO, VIRTIO_BLK_F_SEG_MAX,
    VIRTIO_BLK_F_SIZE_MAX, VIRTIO_BLK_F_TOPOLOGY, VIRTIO_BLK_F_WRITE_ZEROES,
};
use vm_memory::ByteValued;
use vm_migration::protocol::MemoryRangeTable;
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
use vmm_sys_util::eventfd::EventFd;

use super::super::{ActivateResult, VirtioCommon, VirtioDevice, VirtioDeviceType};
use super::vu_common_ctrl::{VhostUserConfig, VhostUserHandle};
use super::{DEFAULT_VIRTIO_FEATURES, Error, Result};
use crate::device::ActivationContext;
use crate::seccomp_filters::Thread;
use crate::vhost_user::{VhostUserCommon, VhostUserState};
use crate::{GuestRegionMmap, VIRTIO_F_ACCESS_PLATFORM, VirtioInterrupt, VirtioInterruptType};

const DEFAULT_QUEUE_NUMBER: usize = 1;

pub type State = VhostUserState<VirtioBlockConfig>;

fn get_block_config(vu: &mut VhostUserHandle, num_queues: usize) -> Result<VirtioBlockConfig> {
    let config_len = size_of::<VirtioBlockConfig>();
    let config_space = vec![0u8; config_len];
    let (_, config_space) = vu
        .socket_handle()
        .get_config(
            0,
            config_len as u32,
            VhostUserConfigFlags::WRITABLE,
            config_space.as_slice(),
        )
        .map_err(Error::VhostUserGetConfig)?;
    let mut config = VirtioBlockConfig::default();
    if let Some(backend_config) = VirtioBlockConfig::from_slice(config_space.as_slice()) {
        config = *backend_config;
        config.num_queues = num_queues as u16;
    }

    Ok(config)
}

struct BackendReqHandler {
    vu: Arc<Mutex<VhostUserHandle>>,
    config: Arc<Mutex<VirtioBlockConfig>>,
    num_queues: usize,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
}

impl VhostUserFrontendReqHandler for BackendReqHandler {
    fn handle_config_change(&self) -> io::Result<u64> {
        let mut vu = self.vu.lock().unwrap();
        let config = get_block_config(&mut vu, self.num_queues).map_err(|e| {
            error!("Failed to refresh vhost-user-blk configuration: {e:?}");
            io::Error::other(e)
        })?;
        *self.config.lock().unwrap() = config;
        self.interrupt_cb
            .trigger(VirtioInterruptType::Config)
            .map_err(|e| {
                error!("Failed to signal vhost-user-blk config change: {e:?}");
                io::Error::other(e)
            })?;
        Ok(0)
    }
}

pub struct Blk {
    vu_common: VhostUserCommon,
    id: String,
    config: Arc<Mutex<VirtioBlockConfig>>,
    seccomp_action: SeccompAction,
    exit_evt: EventFd,
    access_platform_enabled: bool,
}

impl Blk {
    /// Create a new vhost-user-blk device
    pub fn new(
        id: String,
        vu_cfg: VhostUserConfig,
        seccomp_action: SeccompAction,
        exit_evt: EventFd,
        access_platform_enabled: bool,
        state: Option<State>,
    ) -> Result<Blk> {
        let num_queues = vu_cfg.num_queues;

        let mut vu = VhostUserHandle::connect_vhost_user(
            false,
            &vu_cfg.socket,
            num_queues as u64,
            false,
            &exit_evt,
            |_| Ok(()),
        )?;

        let (
            avail_features,
            acked_features,
            acked_protocol_features,
            vu_num_queues,
            config,
            paused,
            vring_bases,
        ) = if let Some(state) = state {
            info!("Restoring vhost-user-block {id}");

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
            let mut avail_features = (1 << VIRTIO_BLK_F_SIZE_MAX)
                | (1 << VIRTIO_BLK_F_SEG_MAX)
                | (1 << VIRTIO_BLK_F_GEOMETRY)
                | (1 << VIRTIO_BLK_F_RO)
                | (1 << VIRTIO_BLK_F_BLK_SIZE)
                | (1 << VIRTIO_BLK_F_FLUSH)
                | (1 << VIRTIO_BLK_F_TOPOLOGY)
                | (1 << VIRTIO_BLK_F_CONFIG_WCE)
                | (1 << VIRTIO_BLK_F_DISCARD)
                | (1 << VIRTIO_BLK_F_WRITE_ZEROES)
                | DEFAULT_VIRTIO_FEATURES;

            if num_queues > 1 {
                avail_features |= 1 << VIRTIO_BLK_F_MQ;
            }

            let avail_protocol_features = VhostUserProtocolFeatures::CONFIG
                | VhostUserProtocolFeatures::MQ
                | VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS
                | VhostUserProtocolFeatures::REPLY_ACK
                | VhostUserProtocolFeatures::INFLIGHT_SHMFD
                | VhostUserProtocolFeatures::LOG_SHMFD
                | VhostUserProtocolFeatures::DEVICE_STATE
                | VhostUserProtocolFeatures::BACKEND_REQ;

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
                    "vhost-user-blk requested too many queues ({num_queues}) since the backend only supports {backend_num_queues}\n"
                );
                return Err(Error::BadQueueNum);
            }

            let config = get_block_config(&mut vu, num_queues)?;

            (
                acked_features,
                // If part of the available features that have been acked,
                // the PROTOCOL_FEATURES bit must be already set through
                // the VIRTIO acked features as we know the guest would
                // never ack it, thus the feature would be lost.
                acked_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits(),
                acked_protocol_features,
                num_queues,
                config,
                false,
                None,
            )
        };

        Ok(Blk {
            vu_common: VhostUserCommon {
                virtio_common: VirtioCommon {
                    device_type: VirtioDeviceType::Block as u32,
                    queue_sizes: vec![vu_cfg.queue_size; num_queues],
                    avail_features,
                    acked_features,
                    paused_sync: Some(Arc::new(Barrier::new(2))),
                    min_queues: DEFAULT_QUEUE_NUMBER as u16,
                    paused: Arc::new(AtomicBool::new(paused)),
                    ..Default::default()
                },
                vu: Some(Arc::new(Mutex::new(vu))),
                acked_protocol_features,
                socket_path: vu_cfg.socket,
                vu_num_queues,
                vring_bases,
                ..Default::default()
            },
            id,
            config: Arc::new(Mutex::new(config)),
            seccomp_action,
            exit_evt,
            access_platform_enabled,
        })
    }

    fn state(&self) -> result::Result<State, MigratableError> {
        self.vu_common.state(*self.config.lock().unwrap())
    }
}

impl Drop for Blk {
    fn drop(&mut self) {
        self.vu_common.shutdown();
    }
}

impl VirtioDevice for Blk {
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
        self.read_config_from_slice(self.config.lock().unwrap().as_slice(), offset, data);
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        // The "writeback" field is the only mutable field
        let writeback_offset = offset_of!(VirtioBlockConfig, writeback) as u64;
        if offset != writeback_offset || data.len() != size_of::<u8>() {
            error!(
                "Attempt to write to read-only field: offset {:x} length {}",
                offset,
                data.len()
            );
            return;
        }

        if let Some(vu) = &self.vu_common.vu {
            let mut vu = vu.lock().unwrap();
            let result = vu
                .socket_handle()
                .set_config(offset as u32, VhostUserConfigFlags::WRITABLE, data)
                .map_err(Error::VhostUserSetConfig);
            self.config.lock().unwrap().writeback = data[0];

            if let Err(e) = result {
                error!(
                    "Failed setting vhost-user-blk configuration for socket {} at offset 0x{offset:x} with length {}: {e:?}",
                    self.vu_common.socket_path,
                    data.len()
                );
            }
        } else {
            self.config.lock().unwrap().writeback = data[0];
        }
    }

    fn activate(&mut self, context: ActivationContext) -> ActivateResult {
        let ActivationContext {
            mem,
            interrupt_cb,
            queues,
            device_status,
        } = context;
        self.vu_common
            .virtio_common
            .activate(&queues, interrupt_cb.clone())?;

        let backend_req_handler = if self.vu_common.acked_protocol_features
            & VhostUserProtocolFeatures::BACKEND_REQ.bits()
            != 0
        {
            let mut handler = FrontendReqHandler::new(Arc::new(BackendReqHandler {
                vu: self.vu_common.vu.as_ref().unwrap().clone(),
                config: self.config.clone(),
                num_queues: self.vu_common.virtio_common.queue_sizes.len(),
                interrupt_cb: interrupt_cb.clone(),
            }))
            .map_err(|e| {
                crate::ActivateError::VhostUserSetup(Error::FrontendReqHandlerCreation(e))
            })?;

            if self.vu_common.acked_protocol_features & VhostUserProtocolFeatures::REPLY_ACK.bits()
                != 0
            {
                handler.set_reply_ack_flag(true);
            }

            Some(handler)
        } else {
            None
        };

        // Run a dedicated thread for handling potential reconnections with
        // the backend.
        let (kill_evt, pause_evt) = self.vu_common.virtio_common.dup_eventfds()?;

        let mut handler = self.vu_common.activate(
            mem,
            &queues,
            interrupt_cb.clone(),
            self.vu_common.virtio_common.acked_features,
            backend_req_handler,
            kill_evt,
            pause_evt,
        )?;

        let paused = self.vu_common.virtio_common.paused.clone();
        let paused_sync = self.vu_common.virtio_common.paused_sync.clone();

        self.vu_common.spawn_worker(
            &self.id,
            &self.seccomp_action,
            Thread::VirtioVhostBlock,
            &self.exit_evt,
            device_status.clone(),
            interrupt_cb.clone(),
            move || handler.run(&paused, paused_sync.as_ref().unwrap()),
        )?;

        Ok(())
    }

    fn reset(&mut self) {
        self.vu_common.reset(&self.id);
    }

    fn shutdown(&mut self) {
        self.vu_common.shutdown();
    }

    fn add_memory_region(
        &mut self,
        region: &Arc<GuestRegionMmap>,
    ) -> result::Result<(), crate::Error> {
        self.vu_common.add_memory_region(region)
    }
}

impl Pausable for Blk {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        self.vu_common.pause()?;
        self.vu_common.virtio_common.pause()
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        self.vu_common.virtio_common.resume()?;
        self.vu_common.resume()
    }
}

impl Snapshottable for Blk {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> result::Result<Snapshot, MigratableError> {
        self.vu_common.snapshot(&self.state()?)
    }
}
impl Transportable for Blk {}

impl Migratable for Blk {
    fn start_dirty_log(&mut self) -> result::Result<(), MigratableError> {
        self.vu_common.start_dirty_log()
    }

    fn stop_dirty_log(&mut self) -> result::Result<(), MigratableError> {
        self.vu_common.stop_dirty_log()
    }

    fn dirty_log(&mut self) -> result::Result<MemoryRangeTable, MigratableError> {
        self.vu_common.dirty_log()
    }

    fn start_migration(&mut self) -> result::Result<(), MigratableError> {
        self.vu_common.start_migration()
    }

    fn complete_migration(&mut self) -> result::Result<(), MigratableError> {
        self.vu_common.complete_migration()
    }
}
