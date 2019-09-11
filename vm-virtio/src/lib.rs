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
extern crate epoll;
#[macro_use]
extern crate log;
#[cfg(feature = "pci_support")]
extern crate pci;
extern crate vhost_rs;
extern crate virtio_bindings;
extern crate vm_memory;

use std::fmt;
use std::io;

mod block;
mod console;
mod device;
pub mod net;
mod pmem;
mod queue;
mod rng;
pub mod vsock;

pub mod transport;
pub mod vhost_user;

pub use self::block::*;
pub use self::console::*;
pub use self::device::*;
pub use self::net::*;
pub use self::pmem::*;
pub use self::queue::*;
pub use self::rng::*;
pub use self::vsock::*;

const DEVICE_INIT: u32 = 0x00;
const DEVICE_ACKNOWLEDGE: u32 = 0x01;
const DEVICE_DRIVER: u32 = 0x02;
const DEVICE_DRIVER_OK: u32 = 0x04;
const DEVICE_FEATURES_OK: u32 = 0x08;
const DEVICE_FAILED: u32 = 0x80;

const VIRTIO_F_VERSION_1: u32 = 32;
const VIRTIO_F_IN_ORDER: u32 = 35;

// Types taken from linux/virtio_ids.h
#[derive(Copy, Clone)]
#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[repr(C)]
enum VirtioDeviceType {
    TYPE_NET = 1,
    TYPE_BLOCK = 2,
    TYPE_CONSOLE = 3,
    TYPE_RNG = 4,
    TYPE_BALLOON = 5,
    TYPE_9P = 9,
    TYPE_GPU = 16,
    TYPE_INPUT = 18,
    TYPE_VSOCK = 19,
    TYPE_FS = 26,
    TYPE_PMEM = 27,
    TYPE_UNKNOWN = 0xFF,
}

impl From<u32> for VirtioDeviceType {
    fn from(t: u32) -> Self {
        match t {
            1 => VirtioDeviceType::TYPE_NET,
            2 => VirtioDeviceType::TYPE_BLOCK,
            4 => VirtioDeviceType::TYPE_RNG,
            5 => VirtioDeviceType::TYPE_BALLOON,
            9 => VirtioDeviceType::TYPE_9P,
            16 => VirtioDeviceType::TYPE_GPU,
            18 => VirtioDeviceType::TYPE_INPUT,
            19 => VirtioDeviceType::TYPE_VSOCK,
            26 => VirtioDeviceType::TYPE_FS,
            27 => VirtioDeviceType::TYPE_PMEM,
            _ => VirtioDeviceType::TYPE_UNKNOWN,
        }
    }
}

// In order to use the `{}` marker, the trait `fmt::Display` must be implemented
// manually for the type VirtioDeviceType.
impl fmt::Display for VirtioDeviceType {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let output = match *self {
            VirtioDeviceType::TYPE_NET => "net",
            VirtioDeviceType::TYPE_BLOCK => "block",
            VirtioDeviceType::TYPE_RNG => "rng",
            VirtioDeviceType::TYPE_BALLOON => "balloon",
            VirtioDeviceType::TYPE_GPU => "gpu",
            VirtioDeviceType::TYPE_9P => "9p",
            VirtioDeviceType::TYPE_VSOCK => "vsock",
            VirtioDeviceType::TYPE_FS => "fs",
            VirtioDeviceType::TYPE_PMEM => "pmem",
            _ => return Err(std::fmt::Error),
        };
        write!(f, "{}", output)
    }
}

#[allow(dead_code)]
const INTERRUPT_STATUS_USED_RING: u32 = 0x1;
#[allow(dead_code)]
const INTERRUPT_STATUS_CONFIG_CHANGED: u32 = 0x2;

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
}

pub type ActivateResult = std::result::Result<(), ActivateError>;

pub type DeviceEventT = u16;

#[derive(Debug)]
pub enum Error {
    FailedReadingQueue {
        event_type: &'static str,
        underlying: io::Error,
    },
    FailedReadTap,
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
}
