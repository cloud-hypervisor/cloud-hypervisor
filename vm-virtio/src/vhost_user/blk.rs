// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::super::{ActivateError, ActivateResult, Queue, VirtioDevice, VirtioDeviceType};
use super::handler::*;
use super::vu_common_ctrl::*;
use super::Error as DeviceError;
use super::{Error, Result};
use crate::VirtioInterrupt;
use arc_swap::ArcSwap;
use libc;
use libc::EFD_NONBLOCK;
use std::cmp;
use std::io::Write;
use std::mem;
use std::ptr::null;
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
use vm_memory::GuestMemoryMmap;
use vmm_sys_util::eventfd::EventFd;

macro_rules! offset_of {
    ($ty:ty, $field:ident) => {
        unsafe { &(*(null() as *const $ty)).$field as *const _ as usize }
    };
}

struct SlaveReqHandler {}
impl VhostUserMasterReqHandler for SlaveReqHandler {}

pub struct Blk {
    vhost_user_blk: Master,
    kill_evt: Option<EventFd>,
    pause_evt: Option<EventFd>,
    avail_features: u64,
    acked_features: u64,
    config_space: Vec<u8>,
    queue_sizes: Vec<u16>,
    queue_evts: Option<Vec<EventFd>>,
    interrupt_cb: Option<Arc<dyn VirtioInterrupt>>,
    epoll_thread: Option<Vec<thread::JoinHandle<result::Result<(), DeviceError>>>>,
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

        let config_len = mem::size_of::<virtio_blk_config>();
        let config_space: Vec<u8> = vec![0u8; config_len as usize];

        let (_, mut config_space) = vhost_user_blk
            .get_config(
                0,
                config_len as u32,
                VhostUserConfigFlags::WRITABLE,
                config_space.as_slice(),
            )
            .unwrap();

        let queue_num_offset = offset_of!(virtio_blk_config, num_queues);
        // Only set num_queues value(u16).
        let num_queues_slice = (vu_cfg.num_queues as u16).to_le_bytes();
        config_space[queue_num_offset..queue_num_offset + mem::size_of::<u16>()]
            .copy_from_slice(&num_queues_slice);

        Ok(Blk {
            vhost_user_blk,
            kill_evt: None,
            pause_evt: None,
            avail_features,
            acked_features,
            config_space,
            queue_sizes: vec![vu_cfg.queue_size; vu_cfg.num_queues],
            queue_evts: None,
            interrupt_cb: None,
            epoll_thread: None,
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

    fn features(&self, page: u32) -> u32 {
        match page {
            0 => self.avail_features as u32,
            1 => (self.avail_features >> 32) as u32,
            _ => {
                warn!("Received request for unknown features page: {}", page);
                0u32
            }
        }
    }

    fn ack_features(&mut self, page: u32, value: u32) {
        let mut v = match page {
            0 => u64::from(value),
            1 => u64::from(value) << 32,
            _ => {
                warn!("Cannot acknowledge unknown features page: {}", page);
                0u64
            }
        };

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
        let config_len = self.config_space.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&self.config_space[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let data_len = data.len() as u64;
        let config_len = self.config_space.len() as u64;
        if offset + data_len > config_len {
            error!("Failed to write config space");
            return;
        }
        // In fact, write_config() only handle wce value in vhost-user-blk.
        // so, we can only set wce value here.
        if self.config_space[offset as usize] == data[0] {
            return;
        }
        self.vhost_user_blk
            .set_config(offset as u32, VhostUserConfigFlags::WRITABLE, data)
            .expect("Failed to set config");
        self.config_space[offset as usize] = data[0];
    }

    fn activate(
        &mut self,
        mem: Arc<ArcSwap<GuestMemoryMmap>>,
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

        let vu_interrupt_list = setup_vhost_user(
            &mut self.vhost_user_blk,
            mem.load().as_ref(),
            queues,
            queue_evts,
            &interrupt_cb,
            self.acked_features,
        )
        .map_err(ActivateError::VhostUserBlkSetup)?;

        let mut handler = VhostUserEpollHandler::<SlaveReqHandler>::new(VhostUserEpollConfig {
            interrupt_cb,
            kill_evt,
            pause_evt,
            vu_interrupt_list,
            slave_req_handler: None,
        });

        let paused = self.paused.clone();
        let mut epoll_threads = Vec::new();
        thread::Builder::new()
            .name("vhost_user_blk".to_string())
            .spawn(move || handler.run(paused))
            .map(|thread| epoll_threads.push(thread))
            .map_err(|e| {
                error!("failed to clone virtio epoll thread: {}", e);
                ActivateError::BadActivate
            })?;

        self.epoll_thread = Some(epoll_threads);

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
}

virtio_pausable!(Blk);
impl Snapshotable for Blk {}
impl Migratable for Blk {}
