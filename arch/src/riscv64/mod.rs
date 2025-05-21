// Copyright © 2024 Institute of Software, CAS. All rights reserved.
// Copyright 2020 Arm Limited (or its affiliates). All rights reserved.
// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Module for the flattened device tree.
pub mod fdt;
/// Layout for this riscv64 system.
pub mod layout;

use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};

use hypervisor::arch::riscv64::aia::Vaia;
use log::{log_enabled, Level};
use thiserror::Error;
use vm_memory::{Address, GuestAddress, GuestMemory, GuestMemoryAtomic};

pub use self::fdt::DeviceInfoForFdt;
use crate::{DeviceType, GuestMemoryMmap, PciSpaceInfo, RegionType};

pub const _NSIG: i32 = 65;

/// Errors thrown while configuring riscv64 system.
#[derive(Debug, Error)]
pub enum Error {
    /// Failed to create a FDT.
    #[error("Failed to create a FDT")]
    SetupFdt,

    /// Failed to write FDT to memory.
    #[error("Failed to write FDT to memory")]
    WriteFdtToMemory(#[source] fdt::Error),

    /// Failed to create a AIA.
    #[error("Failed to create a AIA")]
    SetupAia,

    /// Failed to compute the initramfs address.
    #[error("Failed to compute the initramfs address")]
    InitramfsAddress,

    /// Error configuring the general purpose registers
    #[error("Error configuring the general purpose registers")]
    RegsConfiguration(#[source] hypervisor::HypervisorCpuError),
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
    vcpu: &Arc<dyn hypervisor::Vcpu>,
    id: u8,
    boot_setup: Option<(EntryPoint, &GuestMemoryAtomic<GuestMemoryMmap>)>,
) -> super::Result<()> {
    if let Some((kernel_entry_point, _guest_memory)) = boot_setup {
        vcpu.setup_regs(
            id,
            kernel_entry_point.entry_addr.raw_value(),
            layout::FDT_START.raw_value(),
        )
        .map_err(Error::RegsConfiguration)?;
    }

    Ok(())
}

pub fn arch_memory_regions() -> Vec<(GuestAddress, usize, RegionType)> {
    vec![
        // 0 MiB ~ 256 MiB: AIA and legacy devices
        (
            GuestAddress(0),
            layout::MEM_32BIT_DEVICES_START.0 as usize,
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
        // 1GiB ~ inf: RAM
        (layout::RAM_START, usize::MAX, RegionType::Ram),
    ]
}

/// Configures the system and should be called once per vm before starting vcpu threads.
#[allow(clippy::too_many_arguments)]
pub fn configure_system<T: DeviceInfoForFdt + Clone + Debug, S: ::std::hash::BuildHasher>(
    guest_mem: &GuestMemoryMmap,
    cmdline: &str,
    num_vcpu: u32,
    device_info: &HashMap<(DeviceType, String), T, S>,
    initrd: &Option<super::InitramfsConfig>,
    pci_space_info: &[PciSpaceInfo],
    aia_device: &Arc<Mutex<dyn Vaia>>,
) -> super::Result<()> {
    let fdt_final = fdt::create_fdt(
        guest_mem,
        cmdline,
        num_vcpu,
        device_info,
        aia_device,
        initrd,
        pci_space_info,
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
                Err(super::Error::PlatformSpecific(Error::InitramfsAddress))
            }
        }
        None => Err(super::Error::PlatformSpecific(Error::InitramfsAddress)),
    }
}

pub fn get_host_cpu_phys_bits(_hypervisor: &Arc<dyn hypervisor::Hypervisor>) -> u8 {
    40
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arch_memory_regions_dram() {
        let regions = arch_memory_regions();
        assert_eq!(4, regions.len());
        assert_eq!(layout::RAM_START, regions[3].0);
        assert_eq!(RegionType::Ram, regions[3].2);
    }
}
