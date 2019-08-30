// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate epoll;
extern crate net_util;
extern crate vhost_rs;
extern crate virtio_bindings;
extern crate vm_memory;

use std;
use std::io;
use vhost_rs::Error as VhostError;
use vm_memory::Error as MmapError;

pub mod fs;
mod handler;
pub mod net;
pub mod vu_common_ctrl;

pub use self::fs::*;
pub use self::net::Net;
pub use self::vu_common_ctrl::VhostUserConfig;

#[derive(Debug)]
pub enum Error {
    /// Invalid available address.
    AvailAddress,
    /// Queue number  is not correct
    BadQueueNum,
    /// Creating kill eventfd failed.
    CreateKillEventFd(io::Error),
    /// Cloning kill eventfd failed.
    CloneKillEventFd(io::Error),
    /// Invalid descriptor table address.
    DescriptorTableAddress,
    /// Create Epoll eventfd failed
    EpollCreateFd(io::Error),
    /// Epoll ctl error
    EpollCtl(io::Error),
    /// Epoll wait error
    EpollWait(io::Error),
    /// Read queue failed.
    FailedReadingQueue(io::Error),
    /// Signal used queue failed.
    FailedSignalingUsedQueue(io::Error),
    /// Failed to read vhost eventfd.
    MemoryRegions(MmapError),
    /// Failed to create master.
    VhostUserCreateMaster(VhostError),
    /// Failed to open vhost device.
    VhostUserOpen(VhostError),
    /// Connection to socket failed.
    VhostUserConnect(vhost_rs::Error),
    /// Get features failed.
    VhostUserGetFeatures(VhostError),
    /// Get protocol features failed.
    VhostUserGetProtocolFeatures(VhostError),
    /// Vhost-user Backend not support vhost-user protocol.
    VhostUserProtocolNotSupport,
    /// Set owner failed.
    VhostUserSetOwner(VhostError),
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
    /// Vhost-user setup vring failed.
    VhostUserSetupVringFailed,
    /// Failed to create vhost eventfd.
    VhostIrqCreate(io::Error),
    /// Failed to read vhost eventfd.
    VhostIrqRead(io::Error),
    /// Failed to read vhost eventfd.
    VhostUserMemoryRegion(MmapError),
    /// Failed to handle vhost-user slave request.
    VhostUserSlaveRequest(vhost_rs::vhost_user::Error),
    /// Failed to create the master request handler from slave.
    MasterReqHandlerCreation(vhost_rs::vhost_user::Error),
    /// Set slave request fd failed.
    VhostUserSetSlaveRequestFd(vhost_rs::Error),
    /// Invalid used address.
    UsedAddress,
}
type Result<T> = std::result::Result<T, Error>;
