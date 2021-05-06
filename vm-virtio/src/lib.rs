// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

//! Implements virtio queues

#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;

use std::fmt;

pub mod queue;
pub use queue::*;

pub type VirtioIommuRemapping =
    Box<dyn Fn(u64) -> std::result::Result<u64, std::io::Error> + Send + Sync>;

pub const VIRTIO_MSI_NO_VECTOR: u16 = 0xffff;

// Types taken from linux/virtio_ids.h
#[derive(Copy, Clone, Debug)]
#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[repr(C)]
pub enum VirtioDeviceType {
    Net = 1,
    Block = 2,
    Console = 3,
    Rng = 4,
    Balloon = 5,
    Fs9P = 9,
    Gpu = 16,
    Input = 18,
    Vsock = 19,
    Iommu = 23,
    Mem = 24,
    Fs = 26,
    Pmem = 27,
    Watchdog = 35, // Temporary until official number allocated
    Unknown = 0xFF,
}

impl From<u32> for VirtioDeviceType {
    fn from(t: u32) -> Self {
        match t {
            1 => VirtioDeviceType::Net,
            2 => VirtioDeviceType::Block,
            3 => VirtioDeviceType::Console,
            4 => VirtioDeviceType::Rng,
            5 => VirtioDeviceType::Balloon,
            9 => VirtioDeviceType::Fs9P,
            16 => VirtioDeviceType::Gpu,
            18 => VirtioDeviceType::Input,
            19 => VirtioDeviceType::Vsock,
            23 => VirtioDeviceType::Iommu,
            24 => VirtioDeviceType::Mem,
            26 => VirtioDeviceType::Fs,
            27 => VirtioDeviceType::Pmem,
            35 => VirtioDeviceType::Watchdog,
            _ => VirtioDeviceType::Unknown,
        }
    }
}

// In order to use the `{}` marker, the trait `fmt::Display` must be implemented
// manually for the type VirtioDeviceType.
impl fmt::Display for VirtioDeviceType {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let output = match *self {
            VirtioDeviceType::Net => "net",
            VirtioDeviceType::Block => "block",
            VirtioDeviceType::Console => "console",
            VirtioDeviceType::Rng => "rng",
            VirtioDeviceType::Balloon => "balloon",
            VirtioDeviceType::Gpu => "gpu",
            VirtioDeviceType::Fs9P => "9p",
            VirtioDeviceType::Input => "input",
            VirtioDeviceType::Vsock => "vsock",
            VirtioDeviceType::Iommu => "iommu",
            VirtioDeviceType::Mem => "mem",
            VirtioDeviceType::Fs => "fs",
            VirtioDeviceType::Pmem => "pmem",
            VirtioDeviceType::Watchdog => "watchdog",
            VirtioDeviceType::Unknown => "UNKNOWN",
        };
        write!(f, "{}", output)
    }
}
