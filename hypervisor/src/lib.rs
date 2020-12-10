// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2020, Microsoft Corporation
//
// Copyright 2018-2019 CrowdStrike, Inc.
//
//

//! A generic abstraction around hypervisor functionality
//!
//! This crate offers a trait abstraction for underlying hypervisors
//!
//! # Platform support
//!
//! - x86_64
//! - arm64
//!

#[macro_use]
extern crate anyhow;
#[cfg(target_arch = "x86_64")]
#[macro_use]
extern crate log;
extern crate serde;
extern crate serde_derive;
extern crate serde_json;
extern crate thiserror;

/// Architecture specific definitions
#[macro_use]
pub mod arch;

#[cfg(feature = "kvm")]
/// KVM implementation module
pub mod kvm;

/// Microsoft Hypervisor implementation module
#[cfg(all(feature = "mshv", target_arch = "x86_64"))]
pub mod mshv;

/// Hypevisor related module
pub mod hypervisor;

/// Vm related module
pub mod vm;

/// CPU related module
mod cpu;

/// Device related module
mod device;

pub use crate::hypervisor::{Hypervisor, HypervisorError};
pub use cpu::{HypervisorCpuError, Vcpu, VmExit};
pub use device::{Device, HypervisorDeviceError};
#[cfg(feature = "kvm")]
pub use kvm::*;
#[cfg(all(feature = "mshv", target_arch = "x86_64"))]
pub use mshv::*;
pub use vm::{DataMatch, HypervisorVmError, Vm};

use std::sync::Arc;

pub fn new() -> std::result::Result<Arc<dyn Hypervisor>, HypervisorError> {
    #[cfg(feature = "kvm")]
    let hv = kvm::KvmHypervisor::new()?;

    #[cfg(feature = "mshv")]
    let hv = mshv::MshvHypervisor::new()?;

    Ok(Arc::new(hv))
}
