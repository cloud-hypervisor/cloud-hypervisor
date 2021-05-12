// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io;
use vhost::Error as VhostError;
use vm_memory::Error as MmapError;

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
    /// Failed to create master.
    VhostUserCreateMaster(VhostError),
    /// Failed to open vhost device.
    VhostUserOpen(VhostError),
    /// Connection to socket failed.
    VhostUserConnect(vhost::Error),
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
    /// Invalid used address.
    UsedAddress,
    /// Invalid features provided from vhost-user backend
    InvalidFeatures,
    /// Missing file descriptor for the region.
    MissingRegionFd,
    /// Missing IrqFd
    MissingIrqFd,
}
type Result<T> = std::result::Result<T, Error>;
