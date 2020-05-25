// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

//! Emulates virtual and hardware devices.
extern crate anyhow;
#[macro_use]
extern crate bitflags;
extern crate byteorder;
extern crate epoll;
extern crate libc;
#[macro_use]
extern crate log;
#[cfg(feature = "acpi")]
extern crate acpi_tables;
extern crate serde;
extern crate vm_device;
extern crate vm_memory;
extern crate vm_migration;
extern crate vmm_sys_util;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

use std::fs::File;
use std::io;

#[cfg(feature = "acpi")]
mod acpi;
mod bus;
#[cfg(target_arch = "aarch64")]
pub mod gic;
pub mod interrupt_controller;
#[cfg(target_arch = "x86_64")]
pub mod ioapic;
pub mod legacy;

#[cfg(feature = "acpi")]
pub use self::acpi::{AcpiGEDDevice, AcpiShutdownDevice};
pub use self::bus::{Bus, BusDevice, Error as BusError};

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

bitflags! {
    pub struct HotPlugNotificationFlags: u8 {
        const NO_DEVICES_CHANGED = 0;
        const CPU_DEVICES_CHANGED = 0b1;
        const MEMORY_DEVICES_CHANGED = 0b10;
        const PCI_DEVICES_CHANGED = 0b100;
    }
}
