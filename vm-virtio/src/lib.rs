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

// Types taken from linux/virtio_ids.h
#[derive(Copy, Clone, Debug)]
#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[repr(C)]
pub enum VirtioDeviceType {
    TYPE_NET = 1,
    TYPE_BLOCK = 2,
    TYPE_CONSOLE = 3,
    TYPE_RNG = 4,
    TYPE_BALLOON = 5,
    TYPE_9P = 9,
    TYPE_GPU = 16,
    TYPE_INPUT = 18,
    TYPE_VSOCK = 19,
    TYPE_IOMMU = 23,
    TYPE_MEM = 24,
    TYPE_FS = 26,
    TYPE_PMEM = 27,
    TYPE_WATCHDOG = 35, // Temporary until official number allocated
    TYPE_UNKNOWN = 0xFF,
}

impl From<u32> for VirtioDeviceType {
    fn from(t: u32) -> Self {
        match t {
            1 => VirtioDeviceType::TYPE_NET,
            2 => VirtioDeviceType::TYPE_BLOCK,
            3 => VirtioDeviceType::TYPE_CONSOLE,
            4 => VirtioDeviceType::TYPE_RNG,
            5 => VirtioDeviceType::TYPE_BALLOON,
            9 => VirtioDeviceType::TYPE_9P,
            16 => VirtioDeviceType::TYPE_GPU,
            18 => VirtioDeviceType::TYPE_INPUT,
            19 => VirtioDeviceType::TYPE_VSOCK,
            23 => VirtioDeviceType::TYPE_IOMMU,
            24 => VirtioDeviceType::TYPE_MEM,
            26 => VirtioDeviceType::TYPE_FS,
            27 => VirtioDeviceType::TYPE_PMEM,
            28 => VirtioDeviceType::TYPE_WATCHDOG,
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
            VirtioDeviceType::TYPE_CONSOLE => "console",
            VirtioDeviceType::TYPE_RNG => "rng",
            VirtioDeviceType::TYPE_BALLOON => "balloon",
            VirtioDeviceType::TYPE_GPU => "gpu",
            VirtioDeviceType::TYPE_9P => "9p",
            VirtioDeviceType::TYPE_INPUT => "input",
            VirtioDeviceType::TYPE_VSOCK => "vsock",
            VirtioDeviceType::TYPE_IOMMU => "iommu",
            VirtioDeviceType::TYPE_MEM => "mem",
            VirtioDeviceType::TYPE_FS => "fs",
            VirtioDeviceType::TYPE_PMEM => "pmem",
            VirtioDeviceType::TYPE_WATCHDOG => "watchdog",
            VirtioDeviceType::TYPE_UNKNOWN => "UNKNOWN",
        };
        write!(f, "{}", output)
    }
}
