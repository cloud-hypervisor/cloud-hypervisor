// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//

//#![deny(missing_docs)]
//! Virtual Function I/O (VFIO) API
extern crate byteorder;
extern crate devices;
extern crate kvm_bindings;
extern crate kvm_ioctls;
extern crate log;
extern crate pci;
extern crate vfio_bindings;
extern crate vm_allocator;
extern crate vm_memory;
#[macro_use]
extern crate vmm_sys_util;

mod vfio_device;
mod vfio_ioctls;
mod vfio_pci;

pub use vfio_device::{VfioDevice, VfioError};
pub use vfio_pci::{VfioPciDevice, VfioPciError};
