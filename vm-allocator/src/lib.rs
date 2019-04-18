// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Copyright © 2019 Intel Corporation
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Manages system resources that can be allocated to VMs and their devices.

extern crate libc;
extern crate vm_memory;

mod address;
mod system;

pub use crate::address::AddressAllocator;
pub use crate::system::SystemAllocator;
