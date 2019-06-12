// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

//! Emulates virtual and hardware devices.
extern crate byteorder;
extern crate epoll;
extern crate kvm_bindings;
extern crate kvm_ioctls;
extern crate libc;
#[macro_use]
extern crate log;
extern crate vm_device;
extern crate vm_memory;
extern crate vmm_sys_util;

pub mod i8042;
pub mod serial;

use std::fs::File;
use std::{io, result};

pub mod ioapic;

pub use self::i8042::I8042Device;
pub use self::serial::Serial;

pub type DeviceEventT = u16;

/// The payload is used to handle events where the internal state of the VirtIO device
/// needs to be changed.
pub enum EpollHandlerPayload {
    /// DrivePayload(disk_image)
    DrivePayload(File),
    /// Events that do not need a payload.
    Empty,
}

type Result<T> = std::result::Result<T, Error>;

pub trait EpollHandler: Send {
    fn handle_event(
        &mut self,
        device_event: DeviceEventT,
        event_flags: u32,
        payload: EpollHandlerPayload,
    ) -> Result<()>;
}

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
}

pub trait Interrupt: Send {
    fn deliver(&self) -> result::Result<(), std::io::Error>;
}
