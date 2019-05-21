// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Copyright © 2019 Intel Corporation
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
#![deny(missing_docs)]

//! Manages system resources that can be allocated to VMs and their devices.

extern crate libc;
extern crate vm_memory;

mod address;
mod system;

pub use crate::address::AddressAllocator;
pub use crate::system::SystemAllocator;
