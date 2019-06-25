// Copyright © 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
#![deny(missing_docs)]

//! A device model crate for virtual machine.
//!
//! This services as a base crate for concrete device crate(s) in rust-vmm.
//! It focuses on defining common traits that can/should be used by any
//! device implementation as well as providing unified interfaces for rest
//! of the rust-vmm code that works on device but does not necessarily to
//! know the implementation details of the device.

extern crate vm_memory;

pub mod device;
pub mod device_manager;

pub use self::device::{Device, DeviceDescriptor, IoResource, IoType};
pub use self::device_manager::{DeviceManager, Error as DeviceManagerError, Range, Result};
