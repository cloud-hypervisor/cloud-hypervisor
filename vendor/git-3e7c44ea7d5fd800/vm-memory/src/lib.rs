// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Traits for allocating, handling and interacting with the VM's physical memory.
//!
//! For a typical hypervisor, there are seveval components, such as boot loader, virtual device
//! drivers, virtio backend drivers and vhost drivers etc, that need to access VM's physical memory.
//! This crate aims to provide a set of stable traits to decouple VM memory consumers from VM
//! memory providers. Based on these traits, VM memory consumers could access VM's physical memory
//! without knowing the implementation details of the VM memory provider. Thus hypervisor
//! components, such as boot loader, virtual device drivers, virtio backend drivers and vhost
//! drivers etc, could be shared and reused by multiple hypervisors.

#![deny(missing_docs)]

extern crate libc;

#[cfg(test)]
#[macro_use]
extern crate matches;

#[macro_use]
pub mod address;
pub use address::{Address, AddressValue};

pub mod bytes;
pub use bytes::{ByteValued, Bytes};

pub mod endian;
pub use endian::{Be16, Be32, Be64, BeSize, Le16, Le32, Le64, LeSize};

pub mod guest_memory;
pub use guest_memory::{
    Error as GuestMemoryError, GuestAddress, GuestMemory, GuestMemoryRegion, GuestUsize,
    MemoryRegionAddress, Result as GuestMemoryResult,
};

#[cfg(all(feature = "backend-mmap", unix))]
mod mmap_unix;

#[cfg(all(feature = "backend-mmap", windows))]
mod mmap_windows;

#[cfg(feature = "backend-mmap")]
pub mod mmap;
#[cfg(feature = "backend-mmap")]
pub use mmap::{GuestMemoryMmap, GuestRegionMmap, MmapError, MmapRegion};

pub mod volatile_memory;
pub use volatile_memory::{
    Error as VolatileMemoryError, Result as VolatileMemoryResult, VolatileMemory, VolatileRef,
    VolatileSlice,
};
