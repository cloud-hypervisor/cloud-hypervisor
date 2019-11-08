// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! [Virtual Function I/O (VFIO) API](https://www.kernel.org/doc/Documentation/vfio.txt)
//!
//! Many modern system now provide DMA and interrupt remapping facilities to help ensure I/O
//! devices behave within the boundaries they've been allotted. This includes x86 hardware with
//! AMD-Vi and Intel VT-d, POWER systems with Partitionable Endpoints (PEs) and embedded PowerPC
//! systems such as Freescale PAMU. The VFIO driver is an IOMMU/device agnostic framework for
//! exposing direct device access to userspace, in a secure, IOMMU protected environment.
//! In other words, the VFIO framework allows safe, non-privileged, userspace drivers.
//!
//! Why do we want that?  Virtual machines often make use of direct device access ("device
//! assignment") when configured for the highest possible I/O performance. From a device and host
//! perspective, this simply turns the VM into a userspace driver, with the benefits of
//! significantly reduced latency, higher bandwidth, and direct use of bare-metal device drivers.
//!
//! Devices are the main target of any I/O driver.  Devices typically create a programming
//! interface made up of I/O access, interrupts, and DMA.  Without going into the details of each
//! of these, DMA is by far the most critical aspect for maintaining a secure environment as
//! allowing a device read-write access to system memory imposes the greatest risk to the overall
//! system integrity.
//!
//! To help mitigate this risk, many modern IOMMUs now incorporate isolation properties into what
//! was, in many cases, an interface only meant for translation (ie. solving the addressing
//! problems of devices with limited address spaces).  With this, devices can now be isolated
//! from each other and from arbitrary memory access, thus allowing things like secure direct
//! assignment of devices into virtual machines.
//!
//! While for the most part an IOMMU may have device level granularity, any system is susceptible
//! to reduced granularity. The IOMMU API therefore supports a notion of IOMMU groups. A group is
//! a set of devices which is isolatable from all other devices in the system. Groups are therefore
//! the unit of ownership used by VFIO.
//!
//! While the group is the minimum granularity that must be used to ensure secure user access, it's
//! not necessarily the preferred granularity. In IOMMUs which make use of page tables, it may be
//! possible to share a set of page tables between different groups, reducing the overhead both to
//! the platform (reduced TLB thrashing, reduced duplicate page tables), and to the user
//! (programming only a single set of translations). For this reason, VFIO makes use of a container
//! class, which may hold one or more groups. A container is created by simply opening the
//! /dev/vfio/vfio character device.
//!
//! This crate is a safe wrapper around the Linux kernel's VFIO interfaces, which offering safe
//! wrappers for:
//! - [VFIO Container](struct.VfioContainer.html) using the `VfioContainer` structure
//! - [VFIO Device](struct.VfioDevice.html) using the `VfioDevice` structure
//!
//! # Platform support
//!
//! - x86_64
//!
//! **NOTE:** The list of available ioctls is not extensive.

#![deny(missing_docs)]

#[macro_use]
extern crate vmm_sys_util;

mod vfio_device;
mod vfio_ioctls;

pub use vfio_device::{VfioContainer, VfioDevice, VfioError, VfioIrq};

use std::mem::size_of;

/// Returns a `Vec<T>` with a size in bytes at least as large as `size_in_bytes`.
fn vec_with_size_in_bytes<T: Default>(size_in_bytes: usize) -> Vec<T> {
    let rounded_size = (size_in_bytes + size_of::<T>() - 1) / size_of::<T>();
    let mut v = Vec::with_capacity(rounded_size);
    for _ in 0..rounded_size {
        v.push(T::default())
    }
    v
}

/// The kvm API has many structs that resemble the following `Foo` structure:
///
/// ```
/// #[repr(C)]
/// struct Foo {
///    some_data: u32
///    entries: __IncompleteArrayField<__u32>,
/// }
/// ```
///
/// In order to allocate such a structure, `size_of::<Foo>()` would be too small because it would not
/// include any space for `entries`. To make the allocation large enough while still being aligned
/// for `Foo`, a `Vec<Foo>` is created. Only the first element of `Vec<Foo>` would actually be used
/// as a `Foo`. The remaining memory in the `Vec<Foo>` is for `entries`, which must be contiguous
/// with `Foo`. This function is used to make the `Vec<Foo>` with enough space for `count` entries.
pub fn vec_with_array_field<T: Default, F>(count: usize) -> Vec<T> {
    let element_space = count * size_of::<F>();
    let vec_size_bytes = size_of::<T>() + element_space;
    vec_with_size_in_bytes(vec_size_bytes)
}
