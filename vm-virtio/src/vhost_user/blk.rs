// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::super::{ActivateError, ActivateResult, Queue, VirtioDevice, VirtioDeviceType};
use super::handler::*;
use super::vu_common_ctrl::*;
use super::Error as DeviceError;
use super::{Error, Result};
use crate::block::VirtioBlockConfig;
use crate::VirtioInterrupt;
use libc;
use libc::EFD_NONBLOCK;
use std::cmp;
use std::io::Write;
use std::mem;
use std::os::unix::io::AsRawFd;
use std::result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::vec::Vec;
use vhost_rs::vhost_user::message::VhostUserConfigFlags;
use vhost_rs::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_rs::vhost_user::{Master, VhostUserMaster, VhostUserMasterReqHandler};
use vhost_rs::VhostBackend;
use virtio_bindings::bindings::virtio_blk::*;
use vm_device::{Migratable, MigratableError, Pausable, Snapshotable};
use vm_memory::{ByteValued, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};
use vmm_sys_util::eventfd::EventFd;

struct SlaveReqHandler {}
impl VhostUserMasterReqHandler for SlaveReqHandler {}

pub struct Blk {
    vhost_user_blk: Master,
    kill_evt: Option<EventFd>,
    pause_evt: Option<EventFd>,
    avail_features: u64,
    acked_features: u64,
    config: VirtioBlockConfig,
    queue_sizes: Vec<u16>,
    queue_evts: Option<Vec<EventFd>>,
    interrupt_cb: Option<Arc<dyn VirtioInterrupt>>,
    epoll_threads: Option<Vec<thread::JoinHandle<result::Result<(), DeviceError>>>>,
    paused: Arc<AtomicBool>,
}

impl Blk {
    /// Create a new vhost-user-blk device
    pub fn new(wce: bool, vu_cfg: VhostUserConfig) -> Result<Blk> {
        let mut vhost_user_blk = Master::connect(&vu_cfg.sock, vu_cfg.num_queues as u64)
            .map_err(Error::VhostUserCreateMaster)?;

        // Filling device and vring features VMM supports.
        let mut avail_features = 1 << VIRTIO_BLK_F_SEG_MAX
            | 1 << VIRTIO_BLK_F_RO
            | 1 << VIRTIO_BLK_F_BLK_SIZE
            | 1 << VIRTIO_BLK_F_FLUSH
            | 1 << VIRTIO_BLK_F_TOPOLOGY
            | 1 << VIRTIO_F_VERSION_1
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

        if wce {
            avail_features |= 1 << VIRTIO_BLK_F_CONFIG_WCE;
        }

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
                0,
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
            vhost_user_blk,
            kill_evt: None,
            pause_evt: None,
            avail_features,
            acked_features,
            config,
            queue_sizes: vec![vu_cfg.queue_size; vu_cfg.num_queues],
            queue_evts: None,
            interrupt_cb: None,
            epoll_threads: None,
            paused: Arc::new(AtomicBool::new(false)),
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
        self.avail_features
    }

    fn ack_features(&mut self, value: u64) {
        let mut v = value;
        // Check if the guest is ACK'ing a feature that we didn't claim to have.
        let unrequested_features = v & !self.avail_features;
        if unrequested_features != 0 {
            warn!("Received acknowledge request for unknown feature: {:x}", v);
            // Don't count these features as acked.
            v &= !unrequested_features;
        }
        self.acked_features |= v;
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_slice = self.config.as_slice();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&config_slice[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let config_slice = self.config.as_mut_slice();
        let data_len = data.len() as u64;
        let config_len = config_slice.len() as u64;
        if offset + data_len > config_len {
            error!("Failed to write config space");
            return;
        }
        self.vhost_user_blk
            .set_config(offset as u32, VhostUserConfigFlags::WRITABLE, data)
            .expect("Failed to set config");
        let (_, right) = config_slice.split_at_mut(offset as usize);
        right.copy_from_slice(&data[..]);
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
            self.acked_features,
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
            thread::Builder::new()
                .name("vhost_user_blk".to_string())
                .spawn(move || handler.run(paused))
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
}

virtio_pausable!(Blk);
impl Snapshotable for Blk {}
impl Migratable for Blk {}
