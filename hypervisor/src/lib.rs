// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2020, Microsoft  Corporation
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

/// KVM implementation module
pub mod kvm;

/// Hypevisor related module
pub mod hypervisor;

/// Vm related module
pub mod vm;

/// Architecture specific definitions
pub mod arch;

/// CPU related module
mod cpu;

pub use crate::hypervisor::{Hypervisor, HypervisorError};
pub use cpu::{HypervisorCpuError, Vcpu};
pub use kvm::*;
pub use vm::{DataMatch, HypervisorVmError, Vm};
