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

#[macro_use]
extern crate event_monitor;
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;

use std::convert::TryInto;
use std::io;

#[macro_use]
mod device;
pub mod balloon;
pub mod block;
mod console;
pub mod epoll_helper;
mod iommu;
pub mod mem;
pub mod net;
mod pmem;
mod rng;
pub mod seccomp_filters;
mod thread_helper;
pub mod transport;
pub mod vhost_user;
pub mod vsock;
pub mod watchdog;

pub use self::balloon::*;
pub use self::block::*;
pub use self::console::*;
pub use self::device::*;
pub use self::epoll_helper::*;
pub use self::iommu::*;
pub use self::mem::*;
pub use self::net::*;
pub use self::pmem::*;
pub use self::rng::*;
pub use self::vsock::*;
pub use self::watchdog::*;
use vm_memory::{bitmap::AtomicBitmap, GuestAddress, GuestMemory};
use vm_virtio::{queue::*, VirtioDeviceType};

type GuestMemoryMmap = vm_memory::GuestMemoryMmap<AtomicBitmap>;
type GuestRegionMmap = vm_memory::GuestRegionMmap<AtomicBitmap>;
type MmapRegion = vm_memory::MmapRegion<AtomicBitmap>;

const DEVICE_INIT: u32 = 0x00;
const DEVICE_ACKNOWLEDGE: u32 = 0x01;
const DEVICE_DRIVER: u32 = 0x02;
const DEVICE_DRIVER_OK: u32 = 0x04;
const DEVICE_FEATURES_OK: u32 = 0x08;
const DEVICE_FAILED: u32 = 0x80;

const VIRTIO_F_RING_INDIRECT_DESC: u32 = 28;
const VIRTIO_F_RING_EVENT_IDX: u32 = 29;
const VIRTIO_F_VERSION_1: u32 = 32;
const VIRTIO_F_IOMMU_PLATFORM: u32 = 33;
const VIRTIO_F_IN_ORDER: u32 = 35;
const VIRTIO_F_ORDER_PLATFORM: u32 = 36;
#[allow(dead_code)]
const VIRTIO_F_SR_IOV: u32 = 37;
const VIRTIO_F_NOTIFICATION_DATA: u32 = 38;

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
    /// Failed to setup vhost-user-fs daemon.
    VhostUserFsSetup(vhost_user::Error),
    /// Failed to setup vhost-user-net daemon.
    VhostUserNetSetup(vhost_user::Error),
    /// Failed to setup vhost-user-blk daemon.
    VhostUserBlkSetup(vhost_user::Error),
    /// Failed to reset vhost-user daemon.
    VhostUserReset(vhost_user::Error),
    /// Cannot create seccomp filter
    CreateSeccompFilter(seccompiler::Error),
    /// Cannot create rate limiter
    CreateRateLimiter(std::io::Error),
}

pub type ActivateResult = std::result::Result<(), ActivateError>;

pub type DeviceEventT = u16;

#[derive(Debug)]
pub enum Error {
    FailedSignalingUsedQueue(io::Error),
    IoError(io::Error),
    VhostUserUpdateMemory(vhost_user::Error),
    VhostUserAddMemoryRegion(vhost_user::Error),
    SetShmRegionsNotSupported,
    NetQueuePair(::net_util::NetQueuePairError),
    ApplySeccompFilter(seccompiler::Error),
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct TokenBucketConfig {
    pub size: u64,
    pub one_time_burst: Option<u64>,
    pub refill_time: u64,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RateLimiterConfig {
    pub bandwidth: Option<TokenBucketConfig>,
    pub ops: Option<TokenBucketConfig>,
}

impl TryInto<rate_limiter::RateLimiter> for RateLimiterConfig {
    type Error = io::Error;

    fn try_into(self) -> std::result::Result<rate_limiter::RateLimiter, Self::Error> {
        let bw = self.bandwidth.unwrap_or_default();
        let ops = self.ops.unwrap_or_default();
        rate_limiter::RateLimiter::new(
            bw.size,
            bw.one_time_burst.unwrap_or(0),
            bw.refill_time,
            ops.size,
            ops.one_time_burst.unwrap_or(0),
            ops.refill_time,
        )
    }
}

/// Convert an absolute address into an address space (GuestMemory)
/// to a host pointer and verify that the provided size define a valid
/// range within a single memory region.
/// Return None if it is out of bounds or if addr+size overlaps a single region.
pub fn get_host_address_range<M: GuestMemory>(
    mem: &M,
    addr: GuestAddress,
    size: usize,
) -> Option<*mut u8> {
    if mem.check_range(addr, size) {
        Some(mem.get_host_address(addr).unwrap())
    } else {
        None
    }
}
