// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2020, Microsoft Corporation
//
// Copyright 2018-2019 CrowdStrike, Inc.
//
//
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64;
use std::sync::Arc;

use thiserror::Error;

use crate::HypervisorType;
#[cfg(target_arch = "x86_64")]
use crate::arch::x86::CpuIdEntry;
#[cfg(target_arch = "x86_64")]
use crate::cpu::CpuVendor;
#[cfg(feature = "tdx")]
use crate::kvm::TdxCapabilities;
use crate::vm::Vm;

#[derive(Error, Debug)]
pub enum HypervisorError {
    ///
    /// Hypervisor availability check error
    ///
    #[error("Failed to check availability of the hypervisor")]
    HypervisorAvailableCheck(#[source] anyhow::Error),
    ///
    /// hypervisor creation error
    ///
    #[error("Failed to create the hypervisor")]
    HypervisorCreate(#[source] anyhow::Error),
    ///
    /// Vm creation failure
    ///
    #[error("Failed to create Vm")]
    VmCreate(#[source] anyhow::Error),
    ///
    /// Vm setup failure
    ///
    #[error("Failed to setup Vm")]
    VmSetup(#[source] anyhow::Error),
    ///
    /// API version error
    ///
    #[error("Failed to get API Version")]
    GetApiVersion(#[source] anyhow::Error),
    ///
    /// CpuId error
    ///
    #[error("Failed to get cpuid")]
    GetCpuId(#[source] anyhow::Error),
    ///
    /// Failed to retrieve list of MSRs.
    ///
    #[error("Failed to get the list of supported MSRs")]
    GetMsrList(#[source] anyhow::Error),
    ///
    /// API version is not compatible
    ///
    #[error("Incompatible API version")]
    IncompatibleApiVersion,
    ///
    /// Checking extensions failed
    ///
    #[error("Checking extensions")]
    CheckExtensions(#[source] anyhow::Error),
    ///
    /// Failed to retrieve TDX capabilities
    ///
    #[error("Failed to retrieve TDX capabilities")]
    TdxCapabilities(#[source] anyhow::Error),
    ///
    /// Failed to set partition property
    ///
    #[error("Failed to set partition property")]
    SetPartitionProperty(#[source] anyhow::Error),
    ///
    /// Running on an unsupported CPU
    ///
    #[error("Unsupported CPU")]
    UnsupportedCpu(#[source] anyhow::Error),
    ///
    /// Launching a VM with unsupported VM Type
    ///
    #[error("Unsupported VmType")]
    UnsupportedVmType(),
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
    /// Returns the type of the hypervisor
    ///
    fn hypervisor_type(&self) -> HypervisorType;
    ///
    /// Create a Vm using the underlying hypervisor
    /// Return a hypervisor-agnostic Vm trait object
    ///
    fn create_vm(&self) -> Result<Arc<dyn Vm>>;
    ///
    /// Create a Vm of a specific type using the underlying hypervisor
    /// Return a hypervisor-agnostic Vm trait object
    ///
    fn create_vm_with_type(&self, _vm_type: u64) -> Result<Arc<dyn Vm>> {
        unreachable!()
    }
    ///
    /// Create a Vm of a specific type using the underlying hypervisor, passing memory size
    /// Return a hypervisor-agnostic Vm trait object
    ///
    fn create_vm_with_type_and_memory(
        &self,
        _vm_type: u64,
        #[cfg(feature = "sev_snp")] _mem_size: u64,
    ) -> Result<Arc<dyn Vm>> {
        unreachable!()
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Get the supported CpuID
    ///
    fn get_supported_cpuid(&self) -> Result<Vec<CpuIdEntry>>;
    ///
    /// Check particular extensions if any
    ///
    fn check_required_extensions(&self) -> Result<()> {
        Ok(())
    }
    #[cfg(target_arch = "aarch64")]
    ///
    /// Retrieve AArch64 host maximum IPA size supported by KVM
    ///
    fn get_host_ipa_limit(&self) -> i32;
    ///
    /// Retrieve TDX capabilities
    ///
    #[cfg(feature = "tdx")]
    fn tdx_capabilities(&self) -> Result<TdxCapabilities> {
        unimplemented!()
    }
    ///
    /// Get the number of supported hardware breakpoints
    ///
    fn get_guest_debug_hw_bps(&self) -> usize {
        unimplemented!()
    }

    /// Get maximum number of vCPUs
    fn get_max_vcpus(&self) -> u32;
    #[cfg(target_arch = "x86_64")]
    ///
    /// Determine CPU vendor
    ///
    fn get_cpu_vendor(&self) -> CpuVendor {
        // SAFETY: call cpuid with valid leaves
        unsafe {
            let leaf = x86_64::__cpuid(0x0);

            if leaf.ebx == 0x756e_6547 && leaf.ecx == 0x6c65_746e && leaf.edx == 0x4965_6e69 {
                // Vendor string GenuineIntel
                CpuVendor::Intel
            } else if leaf.ebx == 0x6874_7541 && leaf.ecx == 0x444d_4163 && leaf.edx == 0x6974_6e65
            {
                // Vendor string AuthenticAMD
                CpuVendor::AMD
            } else {
                // Not known yet, the corresponding manufacturer manual should contain the
                // necessary info. See also https://wiki.osdev.org/CPUID#CPU_Vendor_ID_String
                CpuVendor::default()
            }
        }
    }
}
