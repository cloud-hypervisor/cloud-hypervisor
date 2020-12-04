// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2020, Microsoft Corporation
//
// Copyright 2018-2019 CrowdStrike, Inc.
//
//
use crate::vm::Vm;
#[cfg(target_arch = "x86_64")]
use crate::x86_64::{CpuId, MsrList};
#[cfg(all(feature = "kvm", target_arch = "x86_64"))]
use kvm_ioctls::Cap;
use std::sync::Arc;

use thiserror::Error;

#[derive(Error, Debug)]
///
///
pub enum HypervisorError {
    ///
    /// Vm creation failure
    ///
    #[error("Failed to create Vm: {0}")]
    VmCreate(#[source] anyhow::Error),
    ///
    /// Vm setup failure
    ///
    #[error("Failed to setup Vm: {0}")]
    VmSetup(#[source] anyhow::Error),
    ///
    /// API version error
    ///
    #[error("Failed to get API Version: {0}")]
    GetApiVersion(#[source] anyhow::Error),
    ///
    /// Vcpu mmap error
    ///
    #[error("Failed to get Vcpu Mmap: {0}")]
    GetVcpuMmap(#[source] anyhow::Error),
    ///
    /// Max Vcpu error
    ///
    #[error("Failed to get number of max vcpus: {0}")]
    GetMaxVcpu(#[source] anyhow::Error),
    ///
    /// CpuId error
    ///
    #[error("Failed to get cpuid: {0}")]
    GetCpuId(#[source] anyhow::Error),
    ///
    /// Failed to retrieve list of MSRs.
    ///
    #[error("Failed to get the list of supported MSRs: {0}")]
    GetMsrList(#[source] anyhow::Error),
    ///
    /// API version is not compatible
    ///
    #[error("Incompatible API version")]
    IncompatibleApiVersion,
}

///
/// Result type for returning from a function
///
pub type Result<T> = std::result::Result<T, HypervisorError>;

///
/// Trait to represent a Hypervisor
///
/// This crate provides a hypervisor-agnostic interfaces
///
pub trait Hypervisor: Send + Sync {
    ///
    /// Create a Vm using the underlying hypervisor
    /// Return a hypervisor-agnostic Vm trait object
    ///
    fn create_vm(&self) -> Result<Arc<dyn Vm>>;
    #[cfg(feature = "kvm")]
    ///
    /// Returns the size of the memory mapping required to use the vcpu's structures
    ///
    fn get_vcpu_mmap_size(&self) -> Result<usize>;
    #[cfg(feature = "kvm")]
    ///
    /// Gets the recommended maximum number of VCPUs per VM.
    ///
    fn get_max_vcpus(&self) -> Result<usize>;
    #[cfg(feature = "kvm")]
    ///
    /// Gets the recommended number of VCPUs per VM.
    ///
    fn get_nr_vcpus(&self) -> Result<usize>;
    #[cfg(all(feature = "kvm", target_arch = "x86_64"))]
    ///
    /// Checks if a particular `Cap` is available.
    ///
    fn check_capability(&self, c: Cap) -> bool;
    #[cfg(target_arch = "x86_64")]
    ///
    /// Get the supported CpuID
    ///
    fn get_cpuid(&self) -> Result<CpuId>;
    ///
    /// Check particular extensions if any
    ///
    fn check_required_extensions(&self) -> Result<()>;
    #[cfg(target_arch = "x86_64")]
    ///
    /// Retrieve the list of MSRs supported by the hypervisor.
    ///
    fn get_msr_list(&self) -> Result<MsrList>;
}
