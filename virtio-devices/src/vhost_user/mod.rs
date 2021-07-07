// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    EpollHelper, EpollHelperError, EpollHelperHandler, GuestMemoryMmap, Queue, VirtioInterrupt,
    EPOLL_HELPER_EVENT_LAST, VIRTIO_F_IN_ORDER, VIRTIO_F_NOTIFICATION_DATA,
    VIRTIO_F_ORDER_PLATFORM, VIRTIO_F_RING_EVENT_IDX, VIRTIO_F_RING_INDIRECT_DESC,
    VIRTIO_F_VERSION_1,
};
use std::io;
use std::ops::Deref;
use std::os::unix::io::AsRawFd;
use std::sync::{atomic::AtomicBool, Arc, Barrier, Mutex};
use vhost::vhost_user::message::{VhostUserInflight, VhostUserVirtioFeatures};
use vhost::vhost_user::{Master, MasterReqHandler, VhostUserMasterReqHandler};
use vhost::Error as VhostError;
use vm_memory::{Error as MmapError, GuestAddressSpace, GuestMemoryAtomic};
use vm_virtio::Error as VirtioError;
use vmm_sys_util::eventfd::EventFd;
use vu_common_ctrl::{connect_vhost_user, reinitialize_vhost_user};

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
    /// Invalid used address.
    UsedAddress,
    /// Invalid features provided from vhost-user backend
    InvalidFeatures,
    /// Missing file descriptor for the region.
    MissingRegionFd,
    /// Missing IrqFd
    MissingIrqFd,
    /// Failed getting the available index.
    GetAvailableIndex(VirtioError),
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
    pub vu: Arc<Mutex<Master>>,
    pub mem: GuestMemoryAtomic<GuestMemoryMmap>,
    pub kill_evt: EventFd,
    pub pause_evt: EventFd,
    pub queues: Vec<Queue>,
    pub queue_evts: Vec<EventFd>,
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
            self.vu.lock().unwrap().as_raw_fd(),
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
            self.vu.lock().unwrap().as_raw_fd(),
            HUP_CONNECTION_EVENT,
            epoll::Events::EPOLLHUP,
        )?;

        let mut vhost_user = connect_vhost_user(
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
        reinitialize_vhost_user(
            &mut vhost_user,
            self.mem.memory().deref(),
            self.queues.clone(),
            self.queue_evts
                .iter()
                .map(|q| q.try_clone().unwrap())
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
            vhost_user.as_raw_fd(),
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
