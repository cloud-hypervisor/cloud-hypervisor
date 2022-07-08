// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2020, Microsoft Corporation
//
// Copyright 2018-2019 CrowdStrike, Inc.
//
// Copyright 2020, ARM Limited
//

use std::os::unix::io::AsRawFd;
use thiserror::Error;

#[derive(Error, Debug)]
///
/// Enum for device error
pub enum HypervisorDeviceError {
    ///
    /// Set device attribute error
    ///
    #[error("Failed to set device attribute: {0}")]
    SetDeviceAttribute(#[source] anyhow::Error),
    ///
    /// Get device attribute error
    ///
    #[error("Failed to get device attribute: {0}")]
    GetDeviceAttribute(#[source] anyhow::Error),
}

///
/// Result type for returning from a function
///
pub type Result<T> = std::result::Result<T, HypervisorDeviceError>;

///
/// Trait to represent a device
///
/// This crate provides a hypervisor-agnostic interfaces for device
///
pub trait Device: Send + Sync + AsRawFd {
    /// Set device attribute.
    fn set_device_attr(&self, attr: &DeviceAttr) -> Result<()>;
    /// Get device attribute.
    fn get_device_attr(&self, attr: &mut DeviceAttr) -> Result<()>;
}

#[derive(Copy, Clone)]
pub enum _DeviceAttr {
    Kvm(kvm_bindings::kvm_device_attr),
    Mshv(mshv_bindings::mshv_device_attr),
}

#[derive(Copy, Clone)]
pub struct DeviceAttr {
    attr: _DeviceAttr,
}

impl DeviceAttr {
    pub fn attr(&self) -> _DeviceAttr {
        self.attr.clone()
    }

    pub fn set_attr(&mut self, new_attr: _DeviceAttr) -> () {
        self.attr = new_attr;
    }

    pub fn from_kvm(attr: kvm_bindings::kvm_device_attr) -> DeviceAttr {
        DeviceAttr {
            attr: _DeviceAttr::Kvm(attr),
        }
    }

    pub fn from_mshv(attr: mshv_bindings::mshv_device_attr) -> DeviceAttr {
        DeviceAttr {
            attr: _DeviceAttr::Mshv(attr),
        }
    }
}