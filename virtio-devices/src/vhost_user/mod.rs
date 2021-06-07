// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    EpollHelper, EpollHelperError, EpollHelperHandler, GuestMemoryMmap, Queue, VirtioInterrupt,
    EPOLL_HELPER_EVENT_LAST, VIRTIO_F_IN_ORDER, VIRTIO_F_NOTIFICATION_DATA,
    VIRTIO_F_ORDER_PLATFORM, VIRTIO_F_RING_EVENT_IDX, VIRTIO_F_RING_INDIRECT_DESC,
    VIRTIO_F_RING_PACKED, VIRTIO_F_VERSION_1,
};
use seccomp::SeccompAction;
use std::io;
use std::ops::Deref;
use std::os::unix::io::AsRawFd;
use std::sync::{atomic::AtomicBool, Arc, Barrier, Mutex};
use std::thread;
use vhost::vhost_user::message::VhostUserVirtioFeatures;
use vhost::vhost_user::Master;
use vhost::Error as VhostError;
use vm_memory::{Error as MmapError, GuestAddressSpace, GuestMemoryAtomic};
use vm_virtio::Error as VirtioError;
use vmm_sys_util::eventfd::EventFd;
use vu_common_ctrl::{connect_vhost_user, reinitialize_vhost_user, setup_slave_channel};

pub mod blk;
pub mod fs;
mod handler;
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
    | 1 << VIRTIO_F_RING_PACKED
    | 1 << VIRTIO_F_IN_ORDER
    | 1 << VIRTIO_F_ORDER_PLATFORM
    | 1 << VIRTIO_F_NOTIFICATION_DATA
    | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

const HUP_CONNECTION_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;

pub struct ReconnectEpollHandler {
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
    pub paused: Option<Arc<AtomicBool>>,
    pub paused_sync: Option<Arc<Barrier>>,
    pub slave_req_handler: Option<Arc<SlaveReqHandler>>,
    pub seccomp_action: Option<SeccompAction>,
    pub slave_thread: Arc<Mutex<Option<thread::JoinHandle<()>>>>,
    pub id: String,
    pub disconnect_evt: Option<EventFd>,
}

impl ReconnectEpollHandler {
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
        helper.run(paused, paused_sync, self)?;

        Ok(())
    }

    fn dup_eventfds(&self) -> (EventFd, EventFd) {
        (
            self.kill_evt.try_clone().unwrap(),
            self.pause_evt.try_clone().unwrap(),
        )
    }

    fn reconnect(&mut self, helper: &mut EpollHelper) -> std::result::Result<(), EpollHelperError> {
        helper.del_event_custom(
            self.vu.lock().unwrap().as_raw_fd(),
            HUP_CONNECTION_EVENT,
            epoll::Events::EPOLLHUP,
        )?;

        // Tell the slave thread to exit
        if let Some(disconnect_evt) = self.disconnect_evt.as_ref() {
            disconnect_evt.write(1).map_err(|e| {
                EpollHelperError::IoError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to write disconnection eventfd{:?}", e),
                ))
            })?;
        }

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
        )
        .map_err(|e| {
            EpollHelperError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("failed reconnecting vhost-user backend{:?}", e),
            ))
        })?;

        if let Some(handler) = self.slave_req_handler.as_ref() {
            if let Some(disconnect_evt) = self.disconnect_evt.as_ref() {
                let paused = self.paused.as_ref().unwrap().clone();
                let paused_sync = self.paused_sync.clone();
                let (kill_evt, pause_evt) = self.dup_eventfds();
                self.slave_thread = Arc::new(Mutex::new(None));
                setup_slave_channel(
                    &mut vhost_user,
                    handler.clone(),
                    kill_evt,
                    pause_evt,
                    paused,
                    paused_sync,
                    &mut self.slave_thread.lock().unwrap(),
                    self.id.clone(),
                    self.seccomp_action.as_ref().unwrap(),
                    disconnect_evt.try_clone().unwrap(),
                )
                .map_err(|e| {
                    EpollHelperError::IoError(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("failed create vhost-user slave channel{:?}", e),
                    ))
                })?;
            }
        }

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

impl EpollHelperHandler for ReconnectEpollHandler {
    fn handle_event(&mut self, helper: &mut EpollHelper, event: &epoll::Event) -> bool {
        let ev_type = event.data as u16;
        match ev_type {
            HUP_CONNECTION_EVENT => {
                if let Err(e) = self.reconnect(helper) {
                    error!("failed to reconnect vhost-user backend: {:?}", e);
                    return true;
                }
            }
            _ => {
                error!("Unknown event for vhost-user reconnection thread");
                return true;
            }
        }

        false
    }
}
