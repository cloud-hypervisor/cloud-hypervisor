// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::super::{
    ActivateError, ActivateResult, Queue, VirtioCommon, VirtioDevice, VirtioDeviceType,
};
use super::vu_common_ctrl::{VhostUserConfig, VhostUserHandle};
use super::{Error, Result, DEFAULT_VIRTIO_FEATURES};
use crate::vhost_user::{Inflight, VhostUserEpollHandler};
use crate::VirtioInterrupt;
use crate::{GuestMemoryMmap, GuestRegionMmap};
use anyhow::anyhow;
use block_util::VirtioBlockConfig;
use std::mem;
use std::ops::Deref;
use std::os::unix::io::AsRawFd;
use std::result;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::vec::Vec;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;
use vhost::vhost_user::message::VhostUserConfigFlags;
use vhost::vhost_user::message::VHOST_USER_CONFIG_OFFSET;
use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost::vhost_user::{MasterReqHandler, VhostUserMaster, VhostUserMasterReqHandler};
use virtio_bindings::bindings::virtio_blk::{
    VIRTIO_BLK_F_BLK_SIZE, VIRTIO_BLK_F_CONFIG_WCE, VIRTIO_BLK_F_DISCARD, VIRTIO_BLK_F_FLUSH,
    VIRTIO_BLK_F_GEOMETRY, VIRTIO_BLK_F_MQ, VIRTIO_BLK_F_RO, VIRTIO_BLK_F_SEG_MAX,
    VIRTIO_BLK_F_SIZE_MAX, VIRTIO_BLK_F_TOPOLOGY, VIRTIO_BLK_F_WRITE_ZEROES,
};
use vm_memory::{Address, ByteValued, GuestAddressSpace, GuestMemory, GuestMemoryAtomic};
use vm_migration::{
    protocol::MemoryRangeTable, Migratable, MigratableError, Pausable, Snapshot, Snapshottable,
    Transportable, VersionMapped,
};
use vmm_sys_util::eventfd::EventFd;

const DEFAULT_QUEUE_NUMBER: usize = 1;

#[derive(Versionize)]
pub struct State {
    pub avail_features: u64,
    pub acked_features: u64,
    pub config: VirtioBlockConfig,
}

impl VersionMapped for State {}

struct SlaveReqHandler {}
impl VhostUserMasterReqHandler for SlaveReqHandler {}

pub struct Blk {
    common: VirtioCommon,
    id: String,
    vu: Option<Arc<Mutex<VhostUserHandle>>>,
    config: VirtioBlockConfig,
    guest_memory: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    acked_protocol_features: u64,
    socket_path: String,
    epoll_thread: Option<thread::JoinHandle<()>>,
    vu_num_queues: usize,
    migration_started: bool,
}

impl Blk {
    /// Create a new vhost-user-blk device
    pub fn new(id: String, vu_cfg: VhostUserConfig) -> Result<Blk> {
        let num_queues = vu_cfg.num_queues;

        let mut vu =
            VhostUserHandle::connect_vhost_user(false, &vu_cfg.socket, num_queues as u64, false)?;

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
            | VhostUserProtocolFeatures::INFLIGHT_SHMFD
            | VhostUserProtocolFeatures::LOG_SHMFD;

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
            error!("vhost-user-blk requested too many queues ({}) since the backend only supports {}\n",
                num_queues, backend_num_queues);
            return Err(Error::BadQueueNum);
        }

        let config_len = mem::size_of::<VirtioBlockConfig>();
        let config_space: Vec<u8> = vec![0u8; config_len as usize];
        let (_, config_space) = vu
            .socket_handle()
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
            vu: Some(Arc::new(Mutex::new(vu))),
            config,
            guest_memory: None,
            acked_protocol_features,
            socket_path: vu_cfg.socket,
            epoll_thread: None,
            vu_num_queues: num_queues,
            migration_started: false,
        })
    }

    fn state(&self) -> State {
        State {
            avail_features: self.common.avail_features,
            acked_features: self.common.acked_features,
            config: self.config,
        }
    }

    fn set_state(&mut self, state: &State) {
        self.common.avail_features = state.avail_features;
        self.common.acked_features = state.acked_features;
        self.config = state.config;
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
        if let Some(vu) = &self.vu {
            if let Err(e) = vu
                .lock()
                .unwrap()
                .socket_handle()
                .set_config(offset as u32, VhostUserConfigFlags::WRITABLE, data)
                .map_err(Error::VhostUserSetConfig)
            {
                error!("Failed setting vhost-user-blk configuration: {:?}", e);
            }
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

        if self.vu.is_none() {
            error!("Missing vhost-user handle");
            return Err(ActivateError::BadActivate);
        }
        let vu = self.vu.as_ref().unwrap();
        vu.lock()
            .unwrap()
            .setup_vhost_user(
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
            vu: vu.clone(),
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

        if let Some(vu) = &self.vu {
            if let Err(e) = vu
                .lock()
                .unwrap()
                .reset_vhost_user(self.common.queue_sizes.len())
            {
                error!("Failed to reset vhost-user daemon: {:?}", e);
                return None;
            }
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
        if let Some(vu) = &self.vu {
            let _ = unsafe { libc::close(vu.lock().unwrap().socket_handle().as_raw_fd()) };
        }
    }

    fn add_memory_region(
        &mut self,
        region: &Arc<GuestRegionMmap>,
    ) -> std::result::Result<(), crate::Error> {
        if let Some(vu) = &self.vu {
            if self.acked_protocol_features & VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS.bits()
                != 0
            {
                return vu
                    .lock()
                    .unwrap()
                    .add_memory_region(region)
                    .map_err(crate::Error::VhostUserAddMemoryRegion);
            } else if let Some(guest_memory) = &self.guest_memory {
                return vu
                    .lock()
                    .unwrap()
                    .update_mem_table(guest_memory.memory().deref())
                    .map_err(crate::Error::VhostUserUpdateMemory);
            }
        }
        Ok(())
    }
}

impl Pausable for Blk {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        if let Some(vu) = &self.vu {
            vu.lock()
                .unwrap()
                .pause_vhost_user(self.vu_num_queues)
                .map_err(|e| {
                    MigratableError::Pause(anyhow!("Error pausing vhost-user-blk backend: {:?}", e))
                })?;
        }

        self.common.pause()
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        self.common.resume()?;

        if let Some(epoll_thread) = &self.epoll_thread {
            epoll_thread.thread().unpark();
        }

        if let Some(vu) = &self.vu {
            vu.lock()
                .unwrap()
                .resume_vhost_user(self.vu_num_queues)
                .map_err(|e| {
                    MigratableError::Resume(anyhow!(
                        "Error resuming vhost-user-blk backend: {:?}",
                        e
                    ))
                })
        } else {
            Ok(())
        }
    }
}

impl Snapshottable for Blk {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        let snapshot = Snapshot::new_from_versioned_state(&self.id(), &self.state())?;

        if self.migration_started {
            self.shutdown();
        }

        Ok(snapshot)
    }

    fn restore(&mut self, snapshot: Snapshot) -> std::result::Result<(), MigratableError> {
        self.set_state(&snapshot.to_versioned_state(&self.id)?);
        Ok(())
    }
}
impl Transportable for Blk {}

impl Migratable for Blk {
    fn start_dirty_log(&mut self) -> std::result::Result<(), MigratableError> {
        self.migration_started = true;
        if let Some(vu) = &self.vu {
            if let Some(guest_memory) = &self.guest_memory {
                let last_ram_addr = guest_memory.memory().last_addr().raw_value();
                vu.lock()
                    .unwrap()
                    .start_dirty_log(last_ram_addr)
                    .map_err(|e| {
                        MigratableError::StartDirtyLog(anyhow!(
                            "Error starting migration for vhost-user-blk backend: {:?}",
                            e
                        ))
                    })
            } else {
                Err(MigratableError::StartDirtyLog(anyhow!(
                    "Missing guest memory"
                )))
            }
        } else {
            Ok(())
        }
    }

    fn stop_dirty_log(&mut self) -> std::result::Result<(), MigratableError> {
        self.migration_started = false;
        if let Some(vu) = &self.vu {
            vu.lock().unwrap().stop_dirty_log().map_err(|e| {
                MigratableError::StopDirtyLog(anyhow!(
                    "Error stopping migration for vhost-user-blk backend: {:?}",
                    e
                ))
            })
        } else {
            Ok(())
        }
    }

    fn dirty_log(&mut self) -> std::result::Result<MemoryRangeTable, MigratableError> {
        if let Some(vu) = &self.vu {
            if let Some(guest_memory) = &self.guest_memory {
                let last_ram_addr = guest_memory.memory().last_addr().raw_value();
                vu.lock().unwrap().dirty_log(last_ram_addr).map_err(|e| {
                    MigratableError::DirtyLog(anyhow!(
                        "Error retrieving dirty ranges from vhost-user-blk backend: {:?}",
                        e
                    ))
                })
            } else {
                Err(MigratableError::DirtyLog(anyhow!("Missing guest memory")))
            }
        } else {
            Ok(MemoryRangeTable::default())
        }
    }
}
