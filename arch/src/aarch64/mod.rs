// Copyright 2020 Arm Limited (or its affiliates). All rights reserved.
// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Module for the flattened device tree.
pub mod fdt;
/// Module for the global interrupt controller configuration.
pub mod gic;
/// Layout for this aarch64 system.
pub mod layout;
/// Logic for configuring aarch64 registers.
pub mod regs;
/// Module for loading UEFI binary.
pub mod uefi;

pub use self::fdt::DeviceInfoForFdt;
use crate::{DeviceType, GuestMemoryMmap, NumaNodes, RegionType};
use gic::GicDevice;
use log::{log_enabled, Level};
use std::collections::HashMap;
use std::convert::TryInto;
use std::ffi::CStr;
use std::fmt::Debug;
use std::sync::Arc;
use vm_memory::{
    Address, GuestAddress, GuestAddressSpace, GuestMemory, GuestMemoryAtomic, GuestUsize,
};

/// Errors thrown while configuring aarch64 system.
#[derive(Debug)]
pub enum Error {
    /// Failed to create a FDT.
    SetupFdt,

    /// Failed to write FDT to memory.
    WriteFdtToMemory(fdt::Error),

    /// Failed to create a GIC.
    SetupGic(gic::Error),

    /// Failed to compute the initramfs address.
    InitramfsAddress,

    /// Error configuring the general purpose registers
    RegsConfiguration(regs::Error),

    /// Error configuring the MPIDR register
    VcpuRegMpidr(hypervisor::HypervisorCpuError),
}

impl From<Error> for super::Error {
    fn from(e: Error) -> super::Error {
        super::Error::AArch64Setup(e)
    }
}

#[derive(Debug, Copy, Clone)]
/// Specifies the entry point address where the guest must start
/// executing code.
pub struct EntryPoint {
    /// Address in guest memory where the guest must start execution
    pub entry_addr: GuestAddress,
}

/// Configure the specified VCPU, and return its MPIDR.
pub fn configure_vcpu(
    fd: &Arc<dyn hypervisor::Vcpu>,
    id: u8,
    kernel_entry_point: Option<EntryPoint>,
    vm_memory: &GuestMemoryAtomic<GuestMemoryMmap>,
) -> super::Result<u64> {
    if let Some(kernel_entry_point) = kernel_entry_point {
        regs::setup_regs(
            fd,
            id,
            kernel_entry_point.entry_addr.raw_value(),
            &vm_memory.memory(),
        )
        .map_err(Error::RegsConfiguration)?;
    }

    let mpidr = fd.read_mpidr().map_err(Error::VcpuRegMpidr)?;
    Ok(mpidr)
}

pub fn arch_memory_regions(size: GuestUsize) -> Vec<(GuestAddress, usize, RegionType)> {
    // Normally UEFI should be loaded to a flash area at the beginning of memory.
    // But now flash memory type is not supported.
    // As a workaround, we take 4 MiB memory from the main RAM for UEFI.
    // As a result, the RAM that the guest can see is less than what has been
    // assigned in command line, when ACPI and UEFI is enabled.
    let ram_deduction = if cfg!(feature = "acpi") {
        layout::UEFI_SIZE
    } else {
        0
    };

    vec![
        // 0 ~ 4 MiB: Reserved for UEFI space
        #[cfg(feature = "acpi")]
        (GuestAddress(0), layout::UEFI_SIZE as usize, RegionType::Ram),
        #[cfg(not(feature = "acpi"))]
        (
            GuestAddress(0),
            layout::UEFI_SIZE as usize,
            RegionType::Reserved,
        ),
        // 4 MiB ~ 256 MiB: Gic and legacy devices
        (
            GuestAddress(layout::UEFI_SIZE),
            (layout::MEM_32BIT_DEVICES_START.0 - layout::UEFI_SIZE) as usize,
            RegionType::Reserved,
        ),
        // 256 MiB ~ 768 MiB: MMIO space
        (
            layout::MEM_32BIT_DEVICES_START,
            layout::MEM_32BIT_DEVICES_SIZE as usize,
            RegionType::SubRegion,
        ),
        // 768 MiB ~ 1 GiB: reserved. The leading 256M for PCIe MMCONFIG space
        (
            layout::PCI_MMCONFIG_START,
            layout::PCI_MMCONFIG_SIZE as usize,
            RegionType::Reserved,
        ),
        // 1 GiB ~ : Ram
        (
            GuestAddress(layout::RAM_64BIT_START),
            (size - ram_deduction) as usize,
            RegionType::Ram,
        ),
    ]
}

/// Configures the system and should be called once per vm before starting vcpu threads.
#[allow(clippy::too_many_arguments)]
pub fn configure_system<T: DeviceInfoForFdt + Clone + Debug, S: ::std::hash::BuildHasher>(
    guest_mem: &GuestMemoryMmap,
    cmdline_cstring: &CStr,
    vcpu_mpidr: Vec<u64>,
    vcpu_topology: Option<(u8, u8, u8)>,
    device_info: &HashMap<(DeviceType, String), T, S>,
    initrd: &Option<super::InitramfsConfig>,
    pci_space_address: &(u64, u64),
    gic_device: &dyn GicDevice,
    numa_nodes: &NumaNodes,
) -> super::Result<()> {
    let fdt_final = fdt::create_fdt(
        guest_mem,
        cmdline_cstring,
        vcpu_mpidr,
        vcpu_topology,
        device_info,
        gic_device,
        initrd,
        pci_space_address,
        numa_nodes,
    )
    .map_err(|_| Error::SetupFdt)?;

    if log_enabled!(Level::Debug) {
        fdt::print_fdt(&fdt_final);
    }

    fdt::write_fdt_to_memory(fdt_final, guest_mem).map_err(Error::WriteFdtToMemory)?;

    Ok(())
}

/// Returns the memory address where the initramfs could be loaded.
pub fn initramfs_load_addr(
    guest_mem: &GuestMemoryMmap,
    initramfs_size: usize,
) -> super::Result<u64> {
    let round_to_pagesize = |size| (size + (super::PAGE_SIZE - 1)) & !(super::PAGE_SIZE - 1);
    match guest_mem
        .last_addr()
        .checked_sub(round_to_pagesize(initramfs_size) as u64 - 1)
    {
        Some(offset) => {
            if guest_mem.address_in_range(offset) {
                Ok(offset.raw_value())
            } else {
                Err(super::Error::AArch64Setup(Error::InitramfsAddress))
            }
        }
        None => Err(super::Error::AArch64Setup(Error::InitramfsAddress)),
    }
}

/// Returns the memory address where the kernel could be loaded.
pub fn get_kernel_start() -> u64 {
    layout::KERNEL_START
}

///Return guest memory address where the uefi should be loaded.
pub fn get_uefi_start() -> u64 {
    layout::UEFI_START
}

// Auxiliary function to get the address where the device tree blob is loaded.
fn get_fdt_addr() -> u64 {
    layout::FDT_START
}

pub fn get_host_cpu_phys_bits() -> u8 {
    // A dummy hypervisor created only for querying the host IPA size and will
    // be freed after the query.
    let hv = hypervisor::new().unwrap();
    let host_cpu_phys_bits = hv.get_host_ipa_limit().try_into().unwrap();
    if host_cpu_phys_bits == 0 {
        // Host kernel does not support `get_host_ipa_limit`,
        // we return the default value 40 here.
        40
    } else {
        host_cpu_phys_bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arch_memory_regions_dram() {
        let regions = arch_memory_regions((1usize << 32) as u64); //4GB
        assert_eq!(5, regions.len());
        assert_eq!(GuestAddress(layout::RAM_64BIT_START), regions[4].0);
        assert_eq!(1usize << 32, regions[4].1);
        assert_eq!(RegionType::Ram, regions[4].2);
    }
}
