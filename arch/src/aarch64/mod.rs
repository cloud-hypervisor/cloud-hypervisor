// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod layout;

use crate::RegionType;
use kvm_ioctls::*;
use vm_memory::{GuestAddress, GuestMemoryMmap, GuestUsize};

/// Stub function that needs to be implemented when aarch64 functionality is added.
pub fn arch_memory_regions(size: GuestUsize) -> Vec<(GuestAddress, usize, RegionType)> {
    vec![(GuestAddress(0), size as usize, RegionType::Ram)]
}

#[derive(Debug, Copy, Clone)]
/// Specifies the entry point address where the guest must start
/// executing code.
pub struct EntryPoint {
    /// Address in guest memory where the guest must start execution
    pub entry_addr: GuestAddress,
}

/// Stub function that needs to be implemented when aarch64 functionality is added.
pub fn configure_system(
    _guest_mem: &GuestMemoryMmap,
    _cmdline_addr: GuestAddress,
    _cmdline_size: usize,
    _num_cpus: u8,
    _rsdp_addr: Option<GuestAddress>,
) -> super::Result<()> {
    Ok(())
}

/// Stub function that needs to be implemented when aarch64 functionality is added.
pub fn get_reserved_mem_addr() -> usize {
    0
}

pub fn get_host_cpu_phys_bits() -> u8 {
    // The value returned here is used to determine the physical address space size
    // for a VM (IPA size).
    // In recent kernel versions, the maxium IPA size supported by the host can be
    // known by querying cap KVM_CAP_ARM_VM_IPA_SIZE. And the IPA size for a
    // guest can be configured smaller.
    // But in Cloud-Hypervisor we simply use the maxium value for the VM.
    // Reference https://lwn.net/Articles/766767/.
    //
    // The correct way to query KVM_CAP_ARM_VM_IPA_SIZE is via rust-vmm/kvm-ioctls,
    // which wraps all IOCTL's and provides easy interface to user hypervisors.
    // For now the cap hasn't been supported. A separate patch will be submitted to
    // rust-vmm to add it.
    // So a hardcoded value is used here as a temporary solution.
    // It will be replace once rust-vmm/kvm-ioctls is ready.
    //
    40
}

pub fn check_required_kvm_extensions(kvm: &Kvm) -> super::Result<()> {
    if !kvm.check_extension(Cap::SignalMsi) {
        return Err(super::Error::CapabilityMissing(Cap::SignalMsi));
    }
    Ok(())
}
