// Copyright 2020 Arm Limited (or its affiliates). All rights reserved.
// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Module for the flattened device tree.
pub mod fdt;
/// Module for the global interrupt controller configuration.
pub mod gic;
mod gicv2;
mod gicv3;
/// Layout for this aarch64 system.
pub mod layout;
/// Logic for configuring aarch64 registers.
pub mod regs;

use crate::RegionType;
use aarch64::gic::GICDevice;
use kvm_ioctls::*;
use std::collections::HashMap;
use std::ffi::CStr;
use std::fmt::Debug;
use vm_memory::{
    Address, GuestAddress, GuestMemory, GuestMemoryAtomic, GuestMemoryMmap, GuestUsize,
};

#[derive(Debug, Copy, Clone)]
/// Specifies the entry point address where the guest must start
/// executing code.
pub struct EntryPoint {
    /// Address in guest memory where the guest must start execution
    pub entry_addr: GuestAddress,
}

pub fn configure_vcpu(
    _fd: &VcpuFd,
    _id: u8,
    _kernel_entry_point: Option<EntryPoint>,
    _vm_memory: &GuestMemoryAtomic<GuestMemoryMmap>,
) -> super::Result<()> {
    unimplemented!();
}

/// Errors thrown while configuring aarch64 system.
#[derive(Debug)]
pub enum Error {
    /// Failed to create a Flattened Device Tree for this aarch64 VM.
    SetupFDT(fdt::Error),
    /// Failed to compute the initrd address.
    InitrdAddress,
}

impl From<Error> for super::Error {
    fn from(e: Error) -> super::Error {
        super::Error::AArch64Setup(e)
    }
}

pub use self::fdt::DeviceInfoForFDT;
use crate::DeviceType;

pub fn arch_memory_regions(size: GuestUsize) -> Vec<(GuestAddress, usize, RegionType)> {
    let mut regions = Vec::new();
    // 0 ~ 256 MiB: Reserved
    regions.push((
        GuestAddress(0),
        layout::PCI_DEVICES_MAPPED_IO_START as usize,
        RegionType::Reserved,
    ));

    // 256 MiB ~ 1 G: MMIO space
    regions.push((
        GuestAddress(layout::PCI_DEVICES_MAPPED_IO_START),
        layout::PCI_DEVICES_MAPPED_IO_SIZE as usize,
        RegionType::SubRegion,
    ));

    // 1G  ~ 2G: reserved. The leading 256M for PCIe MMCONFIG space
    regions.push((
        layout::PCI_MMCONFIG_START,
        (layout::RAM_64BIT_START - layout::PCI_MMCONFIG_START.0) as usize,
        RegionType::Reserved,
    ));

    regions.push((
        GuestAddress(layout::RAM_64BIT_START),
        size as usize,
        RegionType::Ram,
    ));

    regions
}

/// Configures the system and should be called once per vm before starting vcpu threads.
///
/// # Arguments
///
/// * `guest_mem` - The memory to be used by the guest.
/// * `num_cpus` - Number of virtual CPUs the guest will have.
#[allow(clippy::too_many_arguments)]
#[allow(unused_variables)]
pub fn configure_system<T: DeviceInfoForFDT + Clone + Debug>(
    guest_mem: &GuestMemoryMmap,
    cmdline_cstring: &CStr,
    vcpu_mpidr: Vec<u64>,
    device_info: &HashMap<(DeviceType, String), T>,
    gic_device: &Box<dyn GICDevice>,
    initrd: &Option<super::InitramfsConfig>,
) -> super::Result<()> {
    let dtb = fdt::create_fdt(
        guest_mem,
        cmdline_cstring,
        vcpu_mpidr,
        device_info,
        gic_device,
        initrd,
    )
    .map_err(Error::SetupFDT)?;

    Ok(())
}

/// Returns the memory address where the kernel could be loaded.
pub fn get_kernel_start() -> u64 {
    layout::RAM_64BIT_START
}

// Auxiliary function to get the address where the device tree blob is loaded.
fn get_fdt_addr(mem: &GuestMemoryMmap) -> u64 {
    // If the memory allocated is smaller than the size allocated for the FDT,
    // we return the start of the DRAM so that
    // we allow the code to try and load the FDT.

    if let Some(addr) = mem.last_addr().checked_sub(layout::FDT_MAX_SIZE as u64 - 1) {
        if mem.address_in_range(addr) {
            return addr.raw_value();
        }
    }

    layout::RAM_64BIT_START
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arch_memory_regions_dram() {
        let regions = arch_memory_regions((1usize << 32) as u64); //4GB
        assert_eq!(4, regions.len());
        assert_eq!(GuestAddress(layout::RAM_64BIT_START), regions[3].0);
        assert_eq!(1usize << 32, regions[3].1);
        assert_eq!(RegionType::Ram, regions[3].2);
    }

    #[test]
    fn test_get_fdt_addr() {
        let mut regions = Vec::new();

        regions.push((
            GuestAddress(layout::RAM_64BIT_START),
            (layout::FDT_MAX_SIZE - 0x1000) as usize,
        ));
        let mem = GuestMemoryMmap::from_ranges(&regions).expect("Cannot initialize memory");
        assert_eq!(get_fdt_addr(&mem), layout::RAM_64BIT_START);
        regions.clear();

        regions.push((
            GuestAddress(layout::RAM_64BIT_START),
            (layout::FDT_MAX_SIZE) as usize,
        ));
        let mem = GuestMemoryMmap::from_ranges(&regions).expect("Cannot initialize memory");
        assert_eq!(get_fdt_addr(&mem), layout::RAM_64BIT_START);
        regions.clear();

        regions.push((
            GuestAddress(layout::RAM_64BIT_START),
            (layout::FDT_MAX_SIZE + 0x1000) as usize,
        ));
        let mem = GuestMemoryMmap::from_ranges(&regions).expect("Cannot initialize memory");
        assert_eq!(get_fdt_addr(&mem), 0x1000 + layout::RAM_64BIT_START);
        regions.clear();
    }
}
