// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

//! Implements virtio devices, queues, and transport mechanisms.

extern crate arc_swap;
extern crate epoll;
#[macro_use]
extern crate log;
#[cfg(feature = "pci_support")]
extern crate pci;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate vhost_rs;
extern crate virtio_bindings;
extern crate vm_device;
extern crate vm_memory;

use std::io;

#[macro_use]
mod device;
pub mod balloon;
pub mod block;
#[cfg(feature = "io_uring")]
pub mod block_io_uring;
mod console;
pub mod epoll_helper;
mod iommu;
pub mod mem;
pub mod net;
pub mod net_util;
mod pmem;
mod rng;
pub mod seccomp_filters;
pub mod transport;
pub mod vhost_user;
pub mod vsock;

pub use self::balloon::*;
pub use self::block::*;
#[cfg(feature = "io_uring")]
pub use self::block_io_uring::*;
pub use self::console::*;
pub use self::device::*;
pub use self::epoll_helper::*;
pub use self::iommu::*;
pub use self::mem::*;
pub use self::net::*;
pub use self::net_util::*;
pub use self::pmem::*;
pub use self::rng::*;
pub use self::vsock::*;
use vm_virtio::{queue::*, VirtioDeviceType};

const DEVICE_INIT: u32 = 0x00;
const DEVICE_ACKNOWLEDGE: u32 = 0x01;
const DEVICE_DRIVER: u32 = 0x02;
const DEVICE_DRIVER_OK: u32 = 0x04;
const DEVICE_FEATURES_OK: u32 = 0x08;
const DEVICE_FAILED: u32 = 0x80;

const VIRTIO_F_VERSION_1: u32 = 32;
const VIRTIO_F_IOMMU_PLATFORM: u32 = 33;
const VIRTIO_F_IN_ORDER: u32 = 35;

#[allow(dead_code)]
const INTERRUPT_STATUS_USED_RING: u32 = 0x1;
#[allow(dead_code)]
const INTERRUPT_STATUS_CONFIG_CHANGED: u32 = 0x2;
#[cfg(feature = "pci_support")]
const VIRTIO_MSI_NO_VECTOR: u16 = 0xffff;

#[derive(Debug)]
pub enum ActivateError {
    EpollCtl(std::io::Error),
    BadActivate,
    /// Queue number is not correct
    BadQueueNum,
    /// Failed to clone Kill event
    CloneKillEventFd,
    /// Failed to create Vhost-user interrupt eventfd
    VhostIrqCreate,
    /// Failed to setup vhost-user daemon.
    VhostUserSetup(vhost_user::Error),
    /// Failed to setup vhost-user daemon.
    VhostUserNetSetup(vhost_user::Error),
    /// Failed to setup vhost-user daemon.
    VhostUserBlkSetup(vhost_user::Error),
    /// Failed to reset vhost-user daemon.
    VhostUserReset(vhost_user::Error),
    /// Cannot create seccomp filter
    CreateSeccompFilter(seccomp::SeccompError),
}

pub type ActivateResult = std::result::Result<(), ActivateError>;

pub type DeviceEventT = u16;

#[derive(Debug)]
pub enum Error {
    FailedReadingQueue {
        event_type: &'static str,
        underlying: io::Error,
    },
    FailedSignalingUsedQueue(io::Error),
    PayloadExpected,
    UnknownEvent {
        device: &'static str,
        event: DeviceEventT,
    },
    IoError(io::Error),
    EpollCreateFd(io::Error),
    EpollCtl(io::Error),
    EpollWait(io::Error),
    FailedSignalingDriver(io::Error),
    VhostUserUpdateMemory(vhost_user::Error),
    EventfdError(io::Error),
    SetShmRegionsNotSupported,
    EpollHander(String),
    NoMemoryConfigured,
    NetQueuePair(::net_util::NetQueuePairError),
}
