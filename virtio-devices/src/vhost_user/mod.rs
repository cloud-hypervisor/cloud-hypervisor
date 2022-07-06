// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    ActivateError, EpollHelper, EpollHelperError, EpollHelperHandler, GuestMemoryMmap,
    GuestRegionMmap, VirtioInterrupt, EPOLL_HELPER_EVENT_LAST, VIRTIO_F_IN_ORDER,
    VIRTIO_F_NOTIFICATION_DATA, VIRTIO_F_ORDER_PLATFORM, VIRTIO_F_RING_EVENT_IDX,
    VIRTIO_F_RING_INDIRECT_DESC, VIRTIO_F_VERSION_1,
};
use anyhow::anyhow;
use std::io;
use std::ops::Deref;
use std::os::unix::io::AsRawFd;
use std::sync::{atomic::AtomicBool, Arc, Barrier, Mutex};
use versionize::Versionize;
use vhost::vhost_user::message::{
    VhostUserInflight, VhostUserProtocolFeatures, VhostUserVirtioFeatures,
};
use vhost::vhost_user::{MasterReqHandler, VhostUserMasterReqHandler};
use vhost::Error as VhostError;
use virtio_queue::Error as QueueError;
use virtio_queue::Queue;
use vm_memory::{
    mmap::MmapRegionError, Address, Error as MmapError, GuestAddressSpace, GuestMemory,
    GuestMemoryAtomic,
};
use vm_migration::{protocol::MemoryRangeTable, MigratableError, Snapshot, VersionMapped};
use vmm_sys_util::eventfd::EventFd;
use vu_common_ctrl::VhostUserHandle;

pub mod blk;
pub mod fs;
pub mod net;
pub mod vu_common_ctrl;

pub use self::blk::Blk;
pub use self::fs::*;
pub use self::net::Net;
pub use self::vu_common_ctrl::VhostUserConfig;

#[derive(Debug)]
pub enum Error {
    /// Failed accepting connection.
    AcceptConnection(io::Error),
    /// Invalid available address.
    AvailAddress,
    /// Queue number  is not correct
    BadQueueNum,
    /// Failed binding vhost-user socket.
    BindSocket(io::Error),
    /// Creating kill eventfd failed.
    CreateKillEventFd(io::Error),
    /// Cloning kill eventfd failed.
    CloneKillEventFd(io::Error),
    /// Invalid descriptor table address.
    DescriptorTableAddress,
    /// Signal used queue failed.
    FailedSignalingUsedQueue(io::Error),
    /// Failed to read vhost eventfd.
    MemoryRegions(MmapError),
    /// Failed removing socket path
    RemoveSocketPath(io::Error),
    /// Failed to create master.
    VhostUserCreateMaster(VhostError),
    /// Failed to open vhost device.
    VhostUserOpen(VhostError),
    /// Connection to socket failed.
    VhostUserConnect,
    /// Get features failed.
    VhostUserGetFeatures(VhostError),
    /// Get queue max number failed.
    VhostUserGetQueueMaxNum(VhostError),
    /// Get protocol features failed.
    VhostUserGetProtocolFeatures(VhostError),
    /// Get vring base failed.
    VhostUserGetVringBase(VhostError),
    /// Vhost-user Backend not support vhost-user protocol.
    VhostUserProtocolNotSupport,
    /// Set owner failed.
    VhostUserSetOwner(VhostError),
    /// Reset owner failed.
    VhostUserResetOwner(VhostError),
    /// Set features failed.
    VhostUserSetFeatures(VhostError),
    /// Set protocol features failed.
    VhostUserSetProtocolFeatures(VhostError),
    /// Set mem table failed.
    VhostUserSetMemTable(VhostError),
    /// Set vring num failed.
    VhostUserSetVringNum(VhostError),
    /// Set vring addr failed.
    VhostUserSetVringAddr(VhostError),
    /// Set vring base failed.
    VhostUserSetVringBase(VhostError),
    /// Set vring call failed.
    VhostUserSetVringCall(VhostError),
    /// Set vring kick failed.
    VhostUserSetVringKick(VhostError),
    /// Set vring enable failed.
    VhostUserSetVringEnable(VhostError),
    /// Failed to create vhost eventfd.
    VhostIrqCreate(io::Error),
    /// Failed to read vhost eventfd.
    VhostIrqRead(io::Error),
    /// Failed to read vhost eventfd.
    VhostUserMemoryRegion(MmapError),
    /// Failed to create the master request handler from slave.
    MasterReqHandlerCreation(vhost::vhost_user::Error),
    /// Set slave request fd failed.
    VhostUserSetSlaveRequestFd(vhost::Error),
    /// Add memory region failed.
    VhostUserAddMemReg(VhostError),
    /// Failed getting the configuration.
    VhostUserGetConfig(VhostError),
    /// Failed setting the configuration.
    VhostUserSetConfig(VhostError),
    /// Failed getting inflight shm log.
    VhostUserGetInflight(VhostError),
    /// Failed setting inflight shm log.
    VhostUserSetInflight(VhostError),
    /// Failed setting the log base.
    VhostUserSetLogBase(VhostError),
    /// Invalid used address.
    UsedAddress,
    /// Invalid features provided from vhost-user backend
    InvalidFeatures,
    /// Missing file descriptor for the region.
    MissingRegionFd,
    /// Missing IrqFd
    MissingIrqFd,
    /// Failed getting the available index.
    GetAvailableIndex(QueueError),
    /// Migration is not supported by this vhost-user device.
    MigrationNotSupported,
    /// Failed creating memfd.
    MemfdCreate(io::Error),
    /// Failed truncating the file size to the expected size.
    SetFileSize(io::Error),
    /// Failed to set the seals on the file.
    SetSeals(io::Error),
    /// Failed creating new mmap region
    NewMmapRegion(MmapRegionError),
    /// Could not find the shm log region
    MissingShmLogRegion,
}
type Result<T> = std::result::Result<T, Error>;

pub const DEFAULT_VIRTIO_FEATURES: u64 = 1 << VIRTIO_F_RING_INDIRECT_DESC
    | 1 << VIRTIO_F_RING_EVENT_IDX
    | 1 << VIRTIO_F_VERSION_1
    | 1 << VIRTIO_F_IN_ORDER
    | 1 << VIRTIO_F_ORDER_PLATFORM
    | 1 << VIRTIO_F_NOTIFICATION_DATA
    | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

const HUP_CONNECTION_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;
const SLAVE_REQ_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 2;

#[derive(Default)]
pub struct Inflight {
    pub info: VhostUserInflight,
    pub fd: Option<std::fs::File>,
}

pub struct VhostUserEpollHandler<S: VhostUserMasterReqHandler> {
    pub vu: Arc<Mutex<VhostUserHandle>>,
    pub mem: GuestMemoryAtomic<GuestMemoryMmap>,
    pub kill_evt: EventFd,
    pub pause_evt: EventFd,
    pub queues: Vec<(usize, Queue, EventFd)>,
    pub virtio_interrupt: Arc<dyn VirtioInterrupt>,
    pub acked_features: u64,
    pub acked_protocol_features: u64,
    pub socket_path: String,
    pub server: bool,
    pub slave_req_handler: Option<MasterReqHandler<S>>,
    pub inflight: Option<Inflight>,
}

impl<S: VhostUserMasterReqHandler> VhostUserEpollHandler<S> {
    pub fn run(
        &mut self,
        paused: Arc<AtomicBool>,
        paused_sync: Arc<Barrier>,
    ) -> std::result::Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;
        helper.add_event_custom(
            self.vu.lock().unwrap().socket_handle().as_raw_fd(),
            HUP_CONNECTION_EVENT,
            epoll::Events::EPOLLHUP,
        )?;

        if let Some(slave_req_handler) = &self.slave_req_handler {
            helper.add_event(slave_req_handler.as_raw_fd(), SLAVE_REQ_EVENT)?;
        }

        helper.run(paused, paused_sync, self)?;

        Ok(())
    }

    fn reconnect(&mut self, helper: &mut EpollHelper) -> std::result::Result<(), EpollHelperError> {
        helper.del_event_custom(
            self.vu.lock().unwrap().socket_handle().as_raw_fd(),
            HUP_CONNECTION_EVENT,
            epoll::Events::EPOLLHUP,
        )?;

        let mut vhost_user = VhostUserHandle::connect_vhost_user(
            self.server,
            &self.socket_path,
            self.queues.len() as u64,
            true,
        )
        .map_err(|e| {
            EpollHelperError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("failed connecting vhost-user backend{:?}", e),
            ))
        })?;

        // Initialize the backend
        vhost_user
            .reinitialize_vhost_user(
                self.mem.memory().deref(),
                self.queues
                    .iter()
                    .map(|(i, q, e)| (*i, vm_virtio::clone_queue(q), e.try_clone().unwrap()))
                    .collect(),
                &self.virtio_interrupt,
                self.acked_features,
                self.acked_protocol_features,
                &self.slave_req_handler,
                self.inflight.as_mut(),
            )
            .map_err(|e| {
                EpollHelperError::IoError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed reconnecting vhost-user backend{:?}", e),
                ))
            })?;

        helper.add_event_custom(
            vhost_user.socket_handle().as_raw_fd(),
            HUP_CONNECTION_EVENT,
            epoll::Events::EPOLLHUP,
        )?;

        // Update vhost-user reference
        let mut vu = self.vu.lock().unwrap();
        *vu = vhost_user;

        Ok(())
    }
}

impl<S: VhostUserMasterReqHandler> EpollHelperHandler for VhostUserEpollHandler<S> {
    fn handle_event(&mut self, helper: &mut EpollHelper, event: &epoll::Event) -> bool {
        let ev_type = event.data as u16;
        match ev_type {
            HUP_CONNECTION_EVENT => {
                if let Err(e) = self.reconnect(helper) {
                    error!("failed to reconnect vhost-user backend: {:?}", e);
                    return true;
                }
            }
            SLAVE_REQ_EVENT => {
                if let Some(slave_req_handler) = self.slave_req_handler.as_mut() {
                    if let Err(e) = slave_req_handler.handle_request() {
                        error!("Failed to handle request from vhost-user backend: {:?}", e);
                        return true;
                    }
                }
            }
            _ => {
                error!("Unknown event for vhost-user thread");
                return true;
            }
        }

        false
    }
}

#[derive(Default)]
pub struct VhostUserCommon {
    pub vu: Option<Arc<Mutex<VhostUserHandle>>>,
    pub acked_protocol_features: u64,
    pub socket_path: String,
    pub vu_num_queues: usize,
    pub migration_started: bool,
    pub server: bool,
}

impl VhostUserCommon {
    #[allow(clippy::too_many_arguments)]
    pub fn activate<T: VhostUserMasterReqHandler>(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        queues: Vec<(usize, Queue, EventFd)>,
        interrupt_cb: Arc<dyn VirtioInterrupt>,
        acked_features: u64,
        slave_req_handler: Option<MasterReqHandler<T>>,
        kill_evt: EventFd,
        pause_evt: EventFd,
    ) -> std::result::Result<VhostUserEpollHandler<T>, ActivateError> {
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
                queues
                    .iter()
                    .map(|(i, q, e)| (*i, vm_virtio::clone_queue(q), e.try_clone().unwrap()))
                    .collect(),
                &interrupt_cb,
                acked_features,
                &slave_req_handler,
                inflight.as_mut(),
            )
            .map_err(ActivateError::VhostUserBlkSetup)?;

        Ok(VhostUserEpollHandler {
            vu: vu.clone(),
            mem,
            kill_evt,
            pause_evt,
            queues,
            virtio_interrupt: interrupt_cb,
            acked_features,
            acked_protocol_features: self.acked_protocol_features,
            socket_path: self.socket_path.clone(),
            server: self.server,
            slave_req_handler,
            inflight,
        })
    }

    pub fn restore_backend_connection(&mut self, acked_features: u64) -> Result<()> {
        let mut vu = VhostUserHandle::connect_vhost_user(
            self.server,
            &self.socket_path,
            self.vu_num_queues as u64,
            false,
        )?;

        vu.set_protocol_features_vhost_user(acked_features, self.acked_protocol_features)?;

        self.vu = Some(Arc::new(Mutex::new(vu)));

        Ok(())
    }

    pub fn shutdown(&mut self) {
        if let Some(vu) = &self.vu {
            let _ = unsafe { libc::close(vu.lock().unwrap().socket_handle().as_raw_fd()) };
        }

        // Remove socket path if needed
        if self.server {
            let _ = std::fs::remove_file(&self.socket_path);
        }
    }

    pub fn add_memory_region(
        &mut self,
        guest_memory: &Option<GuestMemoryAtomic<GuestMemoryMmap>>,
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
            } else if let Some(guest_memory) = guest_memory {
                return vu
                    .lock()
                    .unwrap()
                    .update_mem_table(guest_memory.memory().deref())
                    .map_err(crate::Error::VhostUserUpdateMemory);
            }
        }
        Ok(())
    }

    pub fn pause(&mut self) -> std::result::Result<(), MigratableError> {
        if let Some(vu) = &self.vu {
            vu.lock().unwrap().pause_vhost_user().map_err(|e| {
                MigratableError::Pause(anyhow!("Error pausing vhost-user-blk backend: {:?}", e))
            })
        } else {
            Ok(())
        }
    }

    pub fn resume(&mut self) -> std::result::Result<(), MigratableError> {
        if let Some(vu) = &self.vu {
            vu.lock().unwrap().resume_vhost_user().map_err(|e| {
                MigratableError::Resume(anyhow!("Error resuming vhost-user-blk backend: {:?}", e))
            })
        } else {
            Ok(())
        }
    }

    pub fn snapshot<T>(
        &mut self,
        id: &str,
        state: &T,
    ) -> std::result::Result<Snapshot, MigratableError>
    where
        T: Versionize + VersionMapped,
    {
        let snapshot = Snapshot::new_from_versioned_state(id, state)?;

        if self.migration_started {
            self.shutdown();
        }

        Ok(snapshot)
    }

    pub fn start_dirty_log(
        &mut self,
        guest_memory: &Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    ) -> std::result::Result<(), MigratableError> {
        if let Some(vu) = &self.vu {
            if let Some(guest_memory) = guest_memory {
                let last_ram_addr = guest_memory.memory().last_addr().raw_value();
                vu.lock()
                    .unwrap()
                    .start_dirty_log(last_ram_addr)
                    .map_err(|e| {
                        MigratableError::StartDirtyLog(anyhow!(
                            "Error starting migration for vhost-user backend: {:?}",
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

    pub fn stop_dirty_log(&mut self) -> std::result::Result<(), MigratableError> {
        if let Some(vu) = &self.vu {
            vu.lock().unwrap().stop_dirty_log().map_err(|e| {
                MigratableError::StopDirtyLog(anyhow!(
                    "Error stopping migration for vhost-user backend: {:?}",
                    e
                ))
            })
        } else {
            Ok(())
        }
    }

    pub fn dirty_log(
        &mut self,
        guest_memory: &Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    ) -> std::result::Result<MemoryRangeTable, MigratableError> {
        if let Some(vu) = &self.vu {
            if let Some(guest_memory) = guest_memory {
                let last_ram_addr = guest_memory.memory().last_addr().raw_value();
                vu.lock().unwrap().dirty_log(last_ram_addr).map_err(|e| {
                    MigratableError::DirtyLog(anyhow!(
                        "Error retrieving dirty ranges from vhost-user backend: {:?}",
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

    pub fn start_migration(&mut self) -> std::result::Result<(), MigratableError> {
        self.migration_started = true;
        Ok(())
    }

    pub fn complete_migration(
        &mut self,
        kill_evt: Option<EventFd>,
    ) -> std::result::Result<(), MigratableError> {
        self.migration_started = false;

        // Make sure the device thread is killed in order to prevent from
        // reconnections to the socket.
        if let Some(kill_evt) = kill_evt {
            kill_evt.write(1).map_err(|e| {
                MigratableError::CompleteMigration(anyhow!(
                    "Error killing vhost-user thread: {:?}",
                    e
                ))
            })?;
        }

        // Drop the vhost-user handler to avoid further calls to fail because
        // the connection with the backend has been closed.
        self.vu = None;

        Ok(())
    }
}
