// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::super::{
    ActivateError, ActivateResult, Queue, VirtioCommon, VirtioDevice, VirtioDeviceType,
};
use super::vu_common_ctrl::{
    add_memory_region, connect_vhost_user, negotiate_features_vhost_user, reset_vhost_user,
    setup_vhost_user, update_mem_table, VhostUserConfig,
};
use super::{Error, Result, DEFAULT_VIRTIO_FEATURES};
use crate::vhost_user::{Inflight, VhostUserEpollHandler};
use crate::VirtioInterrupt;
use crate::{GuestMemoryMmap, GuestRegionMmap};
use block_util::VirtioBlockConfig;
use std::mem;
use std::ops::Deref;
use std::os::unix::io::AsRawFd;
use std::result;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::vec::Vec;
use vhost::vhost_user::message::VhostUserConfigFlags;
use vhost::vhost_user::message::VHOST_USER_CONFIG_OFFSET;
use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost::vhost_user::{Master, MasterReqHandler, VhostUserMaster, VhostUserMasterReqHandler};
use vhost::VhostBackend;
use virtio_bindings::bindings::virtio_blk::{
    VIRTIO_BLK_F_BLK_SIZE, VIRTIO_BLK_F_CONFIG_WCE, VIRTIO_BLK_F_DISCARD, VIRTIO_BLK_F_FLUSH,
    VIRTIO_BLK_F_GEOMETRY, VIRTIO_BLK_F_MQ, VIRTIO_BLK_F_RO, VIRTIO_BLK_F_SEG_MAX,
    VIRTIO_BLK_F_SIZE_MAX, VIRTIO_BLK_F_TOPOLOGY, VIRTIO_BLK_F_WRITE_ZEROES,
};
use vm_memory::{ByteValued, GuestAddressSpace, GuestMemoryAtomic};
use vm_migration::{Migratable, MigratableError, Pausable, Snapshottable, Transportable};
use vmm_sys_util::eventfd::EventFd;

const DEFAULT_QUEUE_NUMBER: usize = 1;

struct SlaveReqHandler {}
impl VhostUserMasterReqHandler for SlaveReqHandler {}

pub struct Blk {
    common: VirtioCommon,
    id: String,
    vhost_user_blk: Arc<Mutex<Master>>,
    config: VirtioBlockConfig,
    guest_memory: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    acked_protocol_features: u64,
    socket_path: String,
    epoll_thread: Option<thread::JoinHandle<()>>,
}

impl Blk {
    /// Create a new vhost-user-blk device
    pub fn new(id: String, vu_cfg: VhostUserConfig) -> Result<Blk> {
        let num_queues = vu_cfg.num_queues;

        let mut vhost_user_blk =
            connect_vhost_user(false, &vu_cfg.socket, num_queues as u64, false)?;

        // Filling device and vring features VMM supports.
        let mut avail_features = 1 << VIRTIO_BLK_F_SIZE_MAX
            | 1 << VIRTIO_BLK_F_SEG_MAX
            | 1 << VIRTIO_BLK_F_GEOMETRY
            | 1 << VIRTIO_BLK_F_RO
            | 1 << VIRTIO_BLK_F_BLK_SIZE
            | 1 << VIRTIO_BLK_F_FLUSH
            | 1 << VIRTIO_BLK_F_TOPOLOGY
            | 1 << VIRTIO_BLK_F_CONFIG_WCE
            | 1 << VIRTIO_BLK_F_DISCARD
            | 1 << VIRTIO_BLK_F_WRITE_ZEROES
            | DEFAULT_VIRTIO_FEATURES;

        if num_queues > 1 {
            avail_features |= 1 << VIRTIO_BLK_F_MQ;
        }

        let avail_protocol_features = VhostUserProtocolFeatures::CONFIG
            | VhostUserProtocolFeatures::MQ
            | VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS
            | VhostUserProtocolFeatures::REPLY_ACK
            | VhostUserProtocolFeatures::INFLIGHT_SHMFD;

        let (acked_features, acked_protocol_features) = negotiate_features_vhost_user(
            &mut vhost_user_blk,
            avail_features,
            avail_protocol_features,
        )?;

        let backend_num_queues =
            if acked_protocol_features & VhostUserProtocolFeatures::MQ.bits() != 0 {
                vhost_user_blk
                    .get_queue_num()
                    .map_err(Error::VhostUserGetQueueMaxNum)? as usize
            } else {
                DEFAULT_QUEUE_NUMBER
            };

        if num_queues > backend_num_queues {
            error!("vhost-user-blk requested too many queues ({}) since the backend only supports {}\n",
                num_queues, backend_num_queues);
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
            .map_err(Error::VhostUserGetConfig)?;
        let mut config = VirtioBlockConfig::default();
        if let Some(backend_config) = VirtioBlockConfig::from_slice(config_space.as_slice()) {
            config = *backend_config;
            config.num_queues = num_queues as u16;
        }

        // Send set_vring_base here, since it could tell backends, like SPDK,
        // how many virt queues to be handled, which backend required to know
        // at early stage.
        for i in 0..num_queues {
            vhost_user_blk
                .set_vring_base(i, 0)
                .map_err(Error::VhostUserSetVringBase)?;
        }

        Ok(Blk {
            common: VirtioCommon {
                device_type: VirtioDeviceType::Block as u32,
                queue_sizes: vec![vu_cfg.queue_size; num_queues],
                avail_features: acked_features,
                acked_features: 0,
                paused_sync: Some(Arc::new(Barrier::new(2))),
                min_queues: DEFAULT_QUEUE_NUMBER as u16,
                ..Default::default()
            },
            id,
            vhost_user_blk: Arc::new(Mutex::new(vhost_user_blk)),
            config,
            guest_memory: None,
            acked_protocol_features,
            socket_path: vu_cfg.socket,
            epoll_thread: None,
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
        if let Err(e) = self
            .vhost_user_blk
            .lock()
            .unwrap()
            .set_config(offset as u32, VhostUserConfigFlags::WRITABLE, data)
            .map_err(Error::VhostUserSetConfig)
        {
            error!("Failed setting vhost-user-blk configuration: {:?}", e);
        }
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

        let slave_req_handler: Option<MasterReqHandler<SlaveReqHandler>> = None;

        // The backend acknowledged features must contain the protocol feature
        // bit in case it was initially set but lost through the features
        // negotiation with the guest.
        let backend_acked_features = self.common.acked_features
            | (self.common.avail_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits());

        let mut inflight: Option<Inflight> =
            if self.acked_protocol_features & VhostUserProtocolFeatures::INFLIGHT_SHMFD.bits() != 0
            {
                Some(Inflight::default())
            } else {
                None
            };

        setup_vhost_user(
            &mut self.vhost_user_blk.lock().unwrap(),
            &mem.memory(),
            queues.clone(),
            queue_evts.iter().map(|q| q.try_clone().unwrap()).collect(),
            &interrupt_cb,
            backend_acked_features,
            &slave_req_handler,
            inflight.as_mut(),
        )
        .map_err(ActivateError::VhostUserBlkSetup)?;

        // Run a dedicated thread for handling potential reconnections with
        // the backend.
        let (kill_evt, pause_evt) = self.common.dup_eventfds();

        let mut handler: VhostUserEpollHandler<SlaveReqHandler> = VhostUserEpollHandler {
            vu: self.vhost_user_blk.clone(),
            mem,
            kill_evt,
            pause_evt,
            queues,
            queue_evts,
            virtio_interrupt: interrupt_cb,
            acked_features: backend_acked_features,
            acked_protocol_features: self.acked_protocol_features,
            socket_path: self.socket_path.clone(),
            server: false,
            slave_req_handler: None,
            inflight,
        };

        let paused = self.common.paused.clone();
        let paused_sync = self.common.paused_sync.clone();

        thread::Builder::new()
            .name(self.id.to_string())
            .spawn(move || {
                if let Err(e) = handler.run(paused, paused_sync.unwrap()) {
                    error!("Error running vhost-user-blk worker: {:?}", e);
                }
            })
            .map(|thread| self.epoll_thread = Some(thread))
            .map_err(|e| {
                error!("failed to clone queue EventFd: {}", e);
                ActivateError::BadActivate
            })?;

        Ok(())
    }

    fn reset(&mut self) -> Option<Arc<dyn VirtioInterrupt>> {
        // We first must resume the virtio thread if it was paused.
        if self.common.pause_evt.take().is_some() {
            self.common.resume().ok()?;
        }

        if let Err(e) = reset_vhost_user(
            &mut self.vhost_user_blk.lock().unwrap(),
            self.common.queue_sizes.len(),
        ) {
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
        let _ = unsafe { libc::close(self.vhost_user_blk.lock().unwrap().as_raw_fd()) };
    }

    fn add_memory_region(
        &mut self,
        region: &Arc<GuestRegionMmap>,
    ) -> std::result::Result<(), crate::Error> {
        if self.acked_protocol_features & VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS.bits() != 0
        {
            add_memory_region(&mut self.vhost_user_blk.lock().unwrap(), region)
                .map_err(crate::Error::VhostUserAddMemoryRegion)
        } else if let Some(guest_memory) = &self.guest_memory {
            update_mem_table(
                &mut self.vhost_user_blk.lock().unwrap(),
                guest_memory.memory().deref(),
            )
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
        self.common.resume()?;

        if let Some(epoll_thread) = &self.epoll_thread {
            epoll_thread.thread().unpark();
        }
        Ok(())
    }
}

impl Snapshottable for Blk {
    fn id(&self) -> String {
        self.id.clone()
    }
}
impl Transportable for Blk {}
impl Migratable for Blk {}
