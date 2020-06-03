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

/// Vm related module
pub mod vm;

/// CPU related module
mod cpu;

pub use cpu::{HypervisorCpuError, Vcpu};
pub use kvm::*;
