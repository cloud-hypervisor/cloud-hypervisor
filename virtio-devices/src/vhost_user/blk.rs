// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::super::{
    ActivateError, ActivateResult, Queue, VirtioCommon, VirtioDevice, VirtioDeviceType,
};
use super::handler::*;
use super::vu_common_ctrl::*;
use super::{Error, Result};
use crate::seccomp_filters::{get_seccomp_filter, Thread};
use crate::VirtioInterrupt;
use block_util::VirtioBlockConfig;
use seccomp::{SeccompAction, SeccompFilter};
use std::mem;
use std::ops::Deref;
use std::os::unix::io::AsRawFd;
use std::result;
use std::sync::{Arc, Barrier};
use std::thread;
use std::vec::Vec;
use vhost::vhost_user::message::VhostUserConfigFlags;
use vhost::vhost_user::message::VHOST_USER_CONFIG_OFFSET;
use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost::vhost_user::{Master, VhostUserMaster, VhostUserMasterReqHandler};
use vhost::VhostBackend;
use virtio_bindings::bindings::virtio_blk::*;
use virtio_bindings::bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use vm_memory::{
    ByteValued, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap, GuestRegionMmap,
};
use vm_migration::{Migratable, MigratableError, Pausable, Snapshottable, Transportable};
use vmm_sys_util::eventfd::EventFd;

struct SlaveReqHandler {}
impl VhostUserMasterReqHandler for SlaveReqHandler {}

pub struct Blk {
    common: VirtioCommon,
    id: String,
    vhost_user_blk: Master,
    config: VirtioBlockConfig,
    seccomp_action: SeccompAction,
    guest_memory: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    acked_protocol_features: u64,
}

impl Blk {
    /// Create a new vhost-user-blk device
    pub fn new(id: String, vu_cfg: VhostUserConfig, seccomp_action: SeccompAction) -> Result<Blk> {
        let mut vhost_user_blk = Master::connect(&vu_cfg.socket, vu_cfg.num_queues as u64)
            .map_err(Error::VhostUserCreateMaster)?;

        // Filling device and vring features VMM supports.
        let mut avail_features = 1 << VIRTIO_BLK_F_SEG_MAX
            | 1 << VIRTIO_BLK_F_RO
            | 1 << VIRTIO_BLK_F_BLK_SIZE
            | 1 << VIRTIO_BLK_F_FLUSH
            | 1 << VIRTIO_BLK_F_TOPOLOGY
            | 1 << VIRTIO_RING_F_EVENT_IDX
            | 1 << VIRTIO_BLK_F_CONFIG_WCE
            | 1 << VIRTIO_F_VERSION_1
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

        if vu_cfg.num_queues > 1 {
            avail_features |= 1 << VIRTIO_BLK_F_MQ;
        }

        // Set vhost-user owner.
        vhost_user_blk
            .set_owner()
            .map_err(Error::VhostUserSetOwner)?;

        // Get features from backend, do negotiation to get a feature collection which
        // both VMM and backend support.
        let backend_features = vhost_user_blk
            .get_features()
            .map_err(Error::VhostUserGetFeatures)?;
        avail_features &= backend_features;
        // Set features back is required by the vhost crate mechanism, since the
        // later vhost call will check if features is filled in master before execution.
        vhost_user_blk
            .set_features(avail_features)
            .map_err(Error::VhostUserSetFeatures)?;

        // Identify if protocol features are supported by the slave.
        let mut acked_features = 0;
        let mut acked_protocol_features = 0;
        if avail_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() != 0 {
            acked_features |= VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

            let mut protocol_features = vhost_user_blk
                .get_protocol_features()
                .map_err(Error::VhostUserGetProtocolFeatures)?;
            protocol_features &= VhostUserProtocolFeatures::CONFIG
                | VhostUserProtocolFeatures::MQ
                | VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS;
            vhost_user_blk
                .set_protocol_features(protocol_features)
                .map_err(Error::VhostUserSetProtocolFeatures)?;

            acked_protocol_features = protocol_features.bits();
        }
        // Get the max queues number from backend, and the queue number set
        // should be less than this max queue number.
        let max_queues_num = vhost_user_blk
            .get_queue_num()
            .map_err(Error::VhostUserGetQueueMaxNum)?;

        if vu_cfg.num_queues > max_queues_num as usize {
            error!("vhost-user-blk has queue number: {} larger than the max queue number: {} backend allowed\n",
                vu_cfg.num_queues, max_queues_num);
            return Err(Error::BadQueueNum);
        }
        let config_len = mem::size_of::<VirtioBlockConfig>();
        let config_space: Vec<u8> = vec![0u8; config_len as usize];
        let (_, config_space) = vhost_user_blk
            .get_config(
                VHOST_USER_CONFIG_OFFSET,
                config_len as u32,
                VhostUserConfigFlags::WRITABLE,
                config_space.as_slice(),
            )
            .unwrap();
        let mut config = VirtioBlockConfig::default();
        if let Some(backend_config) = VirtioBlockConfig::from_slice(config_space.as_slice()) {
            config = *backend_config;
            // Only set num_queues value(u16).
            config.num_queues = vu_cfg.num_queues as u16;
        }

        // Send set_vring_base here, since it could tell backends, like SPDK,
        // how many virt queues to be handled, which backend required to know
        // at early stage.
        for i in 0..vu_cfg.num_queues {
            vhost_user_blk
                .set_vring_base(i, 0)
                .map_err(Error::VhostUserSetVringBase)?;
        }

        Ok(Blk {
            common: VirtioCommon {
                device_type: VirtioDeviceType::Block as u32,
                queue_sizes: vec![vu_cfg.queue_size; vu_cfg.num_queues],
                avail_features,
                acked_features,
                paused_sync: Some(Arc::new(Barrier::new(vu_cfg.num_queues + 1))),
                min_queues: 1,
                ..Default::default()
            },
            id,
            vhost_user_blk,
            config,
            seccomp_action,
            guest_memory: None,
            acked_protocol_features,
        })
    }
}

impl Drop for Blk {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.common.kill_evt.take() {
            if let Err(e) = kill_evt.write(1) {
                error!("failed to kill vhost-user-blk: {:?}", e);
            }
        }
    }
}

impl VirtioDevice for Blk {
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

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        self.read_config_from_slice(self.config.as_slice(), offset, data);
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        // The "writeback" field is the only mutable field
        let writeback_offset =
            (&self.config.writeback as *const _ as u64) - (&self.config as *const _ as u64);
        if offset != writeback_offset || data.len() != std::mem::size_of_val(&self.config.writeback)
        {
            error!(
                "Attempt to write to read-only field: offset {:x} length {}",
                offset,
                data.len()
            );
            return;
        }

        self.config.writeback = data[0];
        self.vhost_user_blk
            .set_config(offset as u32, VhostUserConfigFlags::WRITABLE, data)
            .expect("Failed to set config");
    }

    fn activate(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        interrupt_cb: Arc<dyn VirtioInterrupt>,
        queues: Vec<Queue>,
        queue_evts: Vec<EventFd>,
    ) -> ActivateResult {
        self.common.activate(&queues, &queue_evts, &interrupt_cb)?;

        self.guest_memory = Some(mem.clone());

        let mut vu_interrupt_list = setup_vhost_user(
            &mut self.vhost_user_blk,
            &mem.memory(),
            queues,
            queue_evts,
            &interrupt_cb,
            self.common.acked_features,
        )
        .map_err(ActivateError::VhostUserBlkSetup)?;

        let mut epoll_threads = Vec::new();
        for i in 0..vu_interrupt_list.len() {
            let mut interrupt_list_sub: Vec<(Option<EventFd>, Queue)> = Vec::with_capacity(1);
            interrupt_list_sub.push(vu_interrupt_list.remove(0));

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

            let mut handler = VhostUserEpollHandler::<SlaveReqHandler>::new(VhostUserEpollConfig {
                interrupt_cb: interrupt_cb.clone(),
                kill_evt,
                pause_evt,
                vu_interrupt_list: interrupt_list_sub,
                slave_req_handler: None,
            });

            let paused = self.common.paused.clone();
            let paused_sync = self.common.paused_sync.clone();
            let virtio_vhost_blk_seccomp_filter =
                get_seccomp_filter(&self.seccomp_action, Thread::VirtioVhostBlk)
                    .map_err(ActivateError::CreateSeccompFilter)?;
            thread::Builder::new()
                .name(format!("{}_q{}", self.id.clone(), i))
                .spawn(move || {
                    if let Err(e) = SeccompFilter::apply(virtio_vhost_blk_seccomp_filter) {
                        error!("Error applying seccomp filter: {:?}", e);
                    } else if let Err(e) = handler.run(paused, paused_sync.unwrap()) {
                        error!("Error running worker: {:?}", e);
                    }
                })
                .map(|thread| epoll_threads.push(thread))
                .map_err(|e| {
                    error!("failed to clone virtio epoll thread: {}", e);
                    ActivateError::BadActivate
                })?;
        }
        self.common.epoll_threads = Some(epoll_threads);

        event!("virtio-device", "activated", "id", &self.id);
        Ok(())
    }

    fn reset(&mut self) -> Option<Arc<dyn VirtioInterrupt>> {
        // We first must resume the virtio thread if it was paused.
        if self.common.pause_evt.take().is_some() {
            self.common.resume().ok()?;
        }

        if let Err(e) = reset_vhost_user(&mut self.vhost_user_blk, self.common.queue_sizes.len()) {
            error!("Failed to reset vhost-user daemon: {:?}", e);
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
        let _ = unsafe { libc::close(self.vhost_user_blk.as_raw_fd()) };
    }

    fn add_memory_region(
        &mut self,
        region: &Arc<GuestRegionMmap>,
    ) -> std::result::Result<(), crate::Error> {
        if self.acked_protocol_features & VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS.bits() != 0
        {
            add_memory_region(&mut self.vhost_user_blk, region)
                .map_err(crate::Error::VhostUserAddMemoryRegion)
        } else if let Some(guest_memory) = &self.guest_memory {
            update_mem_table(&mut self.vhost_user_blk, guest_memory.memory().deref())
                .map_err(crate::Error::VhostUserUpdateMemory)
        } else {
            Ok(())
        }
    }
}

impl Pausable for Blk {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        self.common.pause()
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        self.common.resume()
    }
}

impl Snapshottable for Blk {
    fn id(&self) -> String {
        self.id.clone()
    }
}
impl Transportable for Blk {}
impl Migratable for Blk {}
