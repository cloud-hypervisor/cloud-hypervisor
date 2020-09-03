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
use libc::EFD_NONBLOCK;
use seccomp::{SeccompAction, SeccompFilter};
use std::mem;
use std::os::unix::io::AsRawFd;
use std::result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::vec::Vec;
use vhost_rs::vhost_user::message::VhostUserConfigFlags;
use vhost_rs::vhost_user::message::VHOST_USER_CONFIG_OFFSET;
use vhost_rs::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_rs::vhost_user::{Master, VhostUserMaster, VhostUserMasterReqHandler};
use vhost_rs::VhostBackend;
use virtio_bindings::bindings::virtio_blk::*;
use virtio_bindings::bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use vm_memory::{ByteValued, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};
use vm_migration::{Migratable, MigratableError, Pausable, Snapshottable, Transportable};
use vmm_sys_util::eventfd::EventFd;

struct SlaveReqHandler {}
impl VhostUserMasterReqHandler for SlaveReqHandler {}

pub struct Blk {
    common: VirtioCommon,
    id: String,
    vhost_user_blk: Master,
    kill_evt: Option<EventFd>,
    pause_evt: Option<EventFd>,
    config: VirtioBlockConfig,
    queue_sizes: Vec<u16>,
    queue_evts: Option<Vec<EventFd>>,
    interrupt_cb: Option<Arc<dyn VirtioInterrupt>>,
    epoll_threads: Option<Vec<thread::JoinHandle<()>>>,
    paused: Arc<AtomicBool>,
    paused_sync: Arc<Barrier>,
    seccomp_action: SeccompAction,
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
        if avail_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() != 0 {
            acked_features |= VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

            let mut protocol_features = vhost_user_blk
                .get_protocol_features()
                .map_err(Error::VhostUserGetProtocolFeatures)?;
            protocol_features |= VhostUserProtocolFeatures::MQ;
            protocol_features &= !VhostUserProtocolFeatures::INFLIGHT_SHMFD;
            vhost_user_blk
                .set_protocol_features(protocol_features)
                .map_err(Error::VhostUserSetProtocolFeatures)?;
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
                avail_features,
                acked_features,
            },
            id,
            vhost_user_blk,
            kill_evt: None,
            pause_evt: None,
            config,
            queue_sizes: vec![vu_cfg.queue_size; vu_cfg.num_queues],
            queue_evts: None,
            interrupt_cb: None,
            epoll_threads: None,
            paused: Arc::new(AtomicBool::new(false)),
            paused_sync: Arc::new(Barrier::new(vu_cfg.num_queues + 1)),
            seccomp_action,
        })
    }
}

impl Drop for Blk {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            if let Err(e) = kill_evt.write(1) {
                error!("failed to kill vhost-user-blk: {:?}", e);
            }
        }
    }
}

impl VirtioDevice for Blk {
    fn device_type(&self) -> u32 {
        VirtioDeviceType::TYPE_BLOCK as u32
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.queue_sizes
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
        let (self_kill_evt, kill_evt) = EventFd::new(EFD_NONBLOCK)
            .and_then(|e| Ok((e.try_clone()?, e)))
            .map_err(|e| {
                error!("failed creating kill EventFd pair: {}", e);
                ActivateError::BadActivate
            })?;
        self.kill_evt = Some(self_kill_evt);

        let (self_pause_evt, pause_evt) = EventFd::new(EFD_NONBLOCK)
            .and_then(|e| Ok((e.try_clone()?, e)))
            .map_err(|e| {
                error!("failed creating pause EventFd pair: {}", e);
                ActivateError::BadActivate
            })?;
        self.pause_evt = Some(self_pause_evt);

        // Save the interrupt EventFD as we need to return it on reset
        // but clone it to pass into the thread.
        self.interrupt_cb = Some(interrupt_cb.clone());

        let mut tmp_queue_evts: Vec<EventFd> = Vec::new();
        for queue_evt in queue_evts.iter() {
            // Save the queue EventFD as we need to return it on reset
            // but clone it to pass into the thread.
            tmp_queue_evts.push(queue_evt.try_clone().map_err(|e| {
                error!("failed to clone queue EventFd: {}", e);
                ActivateError::BadActivate
            })?);
        }
        self.queue_evts = Some(tmp_queue_evts);

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
        for _ in 0..vu_interrupt_list.len() {
            let mut interrupt_list_sub: Vec<(Option<EventFd>, Queue)> = Vec::with_capacity(1);
            interrupt_list_sub.push(vu_interrupt_list.remove(0));

            let mut handler = VhostUserEpollHandler::<SlaveReqHandler>::new(VhostUserEpollConfig {
                interrupt_cb: interrupt_cb.clone(),
                kill_evt: kill_evt.try_clone().unwrap(),
                pause_evt: pause_evt.try_clone().unwrap(),
                vu_interrupt_list: interrupt_list_sub,
                slave_req_handler: None,
            });

            let paused = self.paused.clone();
            let paused_sync = self.paused_sync.clone();
            let virtio_vhost_blk_seccomp_filter =
                get_seccomp_filter(&self.seccomp_action, Thread::VirtioVhostBlk)
                    .map_err(ActivateError::CreateSeccompFilter)?;
            thread::Builder::new()
                .name("vhost_blk".to_string())
                .spawn(move || {
                    if let Err(e) = SeccompFilter::apply(virtio_vhost_blk_seccomp_filter) {
                        error!("Error applying seccomp filter: {:?}", e);
                    } else if let Err(e) = handler.run(paused, paused_sync) {
                        error!("Error running worker: {:?}", e);
                    }
                })
                .map(|thread| epoll_threads.push(thread))
                .map_err(|e| {
                    error!("failed to clone virtio epoll thread: {}", e);
                    ActivateError::BadActivate
                })?;
        }
        self.epoll_threads = Some(epoll_threads);

        Ok(())
    }

    fn reset(&mut self) -> Option<(Arc<dyn VirtioInterrupt>, Vec<EventFd>)> {
        // We first must resume the virtio thread if it was paused.
        if self.pause_evt.take().is_some() {
            self.resume().ok()?;
        }

        if let Err(e) = reset_vhost_user(&mut self.vhost_user_blk, self.queue_sizes.len()) {
            error!("Failed to reset vhost-user daemon: {:?}", e);
            return None;
        }

        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }

        // Return the interrupt and queue EventFDs
        Some((
            self.interrupt_cb.take().unwrap(),
            self.queue_evts.take().unwrap(),
        ))
    }

    fn shutdown(&mut self) {
        let _ = unsafe { libc::close(self.vhost_user_blk.as_raw_fd()) };
    }

    fn update_memory(&mut self, mem: &GuestMemoryMmap) -> std::result::Result<(), crate::Error> {
        update_mem_table(&mut self.vhost_user_blk, mem).map_err(crate::Error::VhostUserUpdateMemory)
    }
}

virtio_pausable!(Blk);
impl Snapshottable for Blk {
    fn id(&self) -> String {
        self.id.clone()
    }
}
impl Transportable for Blk {}
impl Migratable for Blk {}
