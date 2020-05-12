// Copyright © 2020, Oracle and/or its affiliates.
//
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

mod gdt;
pub mod interrupts;
pub mod layout;
#[cfg(not(feature = "acpi"))]
mod mptable;
pub mod regs;
use crate::InitramfsConfig;
use crate::RegionType;
use kvm_ioctls::*;
use linux_loader::loader::bootparam::{boot_params, setup_header};
use linux_loader::loader::elf::start_info::{
    hvm_memmap_table_entry, hvm_modlist_entry, hvm_start_info,
};
use std::mem;
use vm_memory::{
    Address, ByteValued, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion,
    GuestUsize,
};

#[derive(Debug, Copy, Clone)]
pub enum BootProtocol {
    LinuxBoot,
    PvhBoot,
}

impl ::std::fmt::Display for BootProtocol {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            BootProtocol::LinuxBoot => write!(f, "Linux 64-bit boot protocol"),
            BootProtocol::PvhBoot => write!(f, "PVH boot protocol"),
        }
    }
}

#[derive(Debug, Copy, Clone)]
/// Specifies the entry point address where the guest must start
/// executing code, as well as which of the supported boot protocols
/// is to be used to configure the guest initial state.
pub struct EntryPoint {
    /// Address in guest memory where the guest must start execution
    pub entry_addr: GuestAddress,
    /// Specifies which boot protocol to use
    pub protocol: BootProtocol,
}

const E820_RAM: u32 = 1;
const E820_RESERVED: u32 = 2;

// This is a workaround to the Rust enforcement specifying that any implementation of a foreign
// trait (in this case `DataInit`) where:
// *    the type that is implementing the trait is foreign or
// *    all of the parameters being passed to the trait (if there are any) are also foreign
// is prohibited.
#[derive(Copy, Clone, Default)]
struct StartInfoWrapper(hvm_start_info);

// It is safe to initialize StartInfoWrapper which is a wrapper over `hvm_start_info` (a series of ints).
unsafe impl ByteValued for StartInfoWrapper {}

#[derive(Copy, Clone, Default)]
struct MemmapTableEntryWrapper(hvm_memmap_table_entry);

unsafe impl ByteValued for MemmapTableEntryWrapper {}

#[derive(Copy, Clone, Default)]
struct ModlistEntryWrapper(hvm_modlist_entry);

unsafe impl ByteValued for ModlistEntryWrapper {}

// This is a workaround to the Rust enforcement specifying that any implementation of a foreign
// trait (in this case `DataInit`) where:
// *    the type that is implementing the trait is foreign or
// *    all of the parameters being passed to the trait (if there are any) are also foreign
// is prohibited.
#[derive(Copy, Clone, Default)]
struct BootParamsWrapper(boot_params);

// It is safe to initialize BootParamsWrap which is a wrapper over `boot_params` (a series of ints).
unsafe impl ByteValued for BootParamsWrapper {}

#[derive(Debug)]
pub enum Error {
    /// Invalid e820 setup params.
    E820Configuration,
    #[cfg(not(feature = "acpi"))]
    /// Error writing MP table to memory.
    MpTableSetup(mptable::Error),
}

impl From<Error> for super::Error {
    fn from(e: Error) -> super::Error {
        super::Error::X86_64Setup(e)
    }
}

/// Returns a Vec of the valid memory addresses.
/// These should be used to configure the GuestMemory structure for the platform.
/// For x86_64 all addresses are valid from the start of the kernel except a
/// carve out at the end of 32bit address space.
pub fn arch_memory_regions(size: GuestUsize) -> Vec<(GuestAddress, usize, RegionType)> {
    let reserved_memory_gap_start = layout::MEM_32BIT_RESERVED_START
        .checked_add(layout::MEM_32BIT_DEVICES_SIZE)
        .expect("32-bit reserved region is too large");

    let requested_memory_size = GuestAddress(size as u64);
    let mut regions = Vec::new();

    // case1: guest memory fits before the gap
    if size as u64 <= layout::MEM_32BIT_RESERVED_START.raw_value() {
        regions.push((GuestAddress(0), size as usize, RegionType::Ram));
    // case2: guest memory extends beyond the gap
    } else {
        // push memory before the gap
        regions.push((
            GuestAddress(0),
            layout::MEM_32BIT_RESERVED_START.raw_value() as usize,
            RegionType::Ram,
        ));
        regions.push((
            layout::RAM_64BIT_START,
            requested_memory_size.unchecked_offset_from(layout::MEM_32BIT_RESERVED_START) as usize,
            RegionType::Ram,
        ));
    }

    // Add the 32-bit device memory hole as a sub region.
    regions.push((
        layout::MEM_32BIT_RESERVED_START,
        layout::MEM_32BIT_DEVICES_SIZE as usize,
        RegionType::SubRegion,
    ));

    // Add the 32-bit reserved memory hole as a sub region.
    regions.push((
        reserved_memory_gap_start,
        (layout::MEM_32BIT_RESERVED_SIZE - layout::MEM_32BIT_DEVICES_SIZE) as usize,
        RegionType::Reserved,
    ));

    regions
}

/// Configures the system and should be called once per vm before starting vcpu threads.
///
/// # Arguments
///
/// * `guest_mem` - The memory to be used by the guest.
/// * `cmdline_addr` - Address in `guest_mem` where the kernel command line was loaded.
/// * `cmdline_size` - Size of the kernel command line in bytes including the null terminator.
/// * `num_cpus` - Number of virtual CPUs the guest will have.
#[allow(clippy::too_many_arguments)]
pub fn configure_system(
    guest_mem: &GuestMemoryMmap,
    cmdline_addr: GuestAddress,
    cmdline_size: usize,
    initramfs: &Option<InitramfsConfig>,
    _num_cpus: u8,
    setup_hdr: Option<setup_header>,
    rsdp_addr: Option<GuestAddress>,
    boot_prot: BootProtocol,
) -> super::Result<()> {
    // Note that this puts the mptable at the last 1k of Linux's 640k base RAM
    #[cfg(not(feature = "acpi"))]
    mptable::setup_mptable(guest_mem, _num_cpus).map_err(Error::MpTableSetup)?;

    // Check that the RAM is not smaller than the RSDP start address
    if let Some(rsdp_addr) = rsdp_addr {
        if rsdp_addr.0 > guest_mem.last_addr().0 {
            return Err(super::Error::RSDPPastRamEnd);
        }
    }

    match boot_prot {
        BootProtocol::PvhBoot => {
            configure_pvh(guest_mem, cmdline_addr, initramfs, rsdp_addr)?;
        }
        BootProtocol::LinuxBoot => {
            configure_64bit_boot(
                guest_mem,
                cmdline_addr,
                cmdline_size,
                initramfs,
                setup_hdr,
                rsdp_addr,
            )?;
        }
    }

    Ok(())
}

fn configure_pvh(
    guest_mem: &GuestMemoryMmap,
    cmdline_addr: GuestAddress,
    initramfs: &Option<InitramfsConfig>,
    rsdp_addr: Option<GuestAddress>,
) -> super::Result<()> {
    const XEN_HVM_START_MAGIC_VALUE: u32 = 0x336ec578;

    let mut start_info: StartInfoWrapper = StartInfoWrapper(hvm_start_info::default());

    start_info.0.magic = XEN_HVM_START_MAGIC_VALUE;
    start_info.0.version = 1; // pvh has version 1
    start_info.0.nr_modules = 0;
    start_info.0.cmdline_paddr = cmdline_addr.raw_value() as u64;
    start_info.0.memmap_paddr = layout::MEMMAP_START.raw_value();

    if let Some(rsdp_addr) = rsdp_addr {
        start_info.0.rsdp_paddr = rsdp_addr.0;
    }

    if let Some(initramfs_config) = initramfs {
        // The initramfs has been written to guest memory already, here we just need to
        // create the module structure that describes it.
        let ramdisk_mod: ModlistEntryWrapper = ModlistEntryWrapper(hvm_modlist_entry {
            paddr: initramfs_config.address.raw_value(),
            size: initramfs_config.size as u64,
            ..Default::default()
        });

        start_info.0.nr_modules += 1;
        start_info.0.modlist_paddr = layout::MODLIST_START.raw_value();

        // Write the modlist struct to guest memory.
        guest_mem
            .write_obj(ramdisk_mod, layout::MODLIST_START)
            .map_err(super::Error::ModlistSetup)?;
    }

    // Vector to hold the memory maps which needs to be written to guest memory
    // at MEMMAP_START after all of the mappings are recorded.
    let mut memmap: Vec<hvm_memmap_table_entry> = Vec::new();

    // Create the memory map entries.
    add_memmap_entry(&mut memmap, 0, layout::EBDA_START.raw_value(), E820_RAM)?;

    let mem_end = guest_mem.last_addr();

    if mem_end < layout::MEM_32BIT_RESERVED_START {
        add_memmap_entry(
            &mut memmap,
            layout::HIGH_RAM_START.raw_value(),
            mem_end.unchecked_offset_from(layout::HIGH_RAM_START) + 1,
            E820_RAM,
        )?;
    } else {
        add_memmap_entry(
            &mut memmap,
            layout::HIGH_RAM_START.raw_value(),
            layout::MEM_32BIT_RESERVED_START.unchecked_offset_from(layout::HIGH_RAM_START),
            E820_RAM,
        )?;
        if mem_end > layout::RAM_64BIT_START {
            add_memmap_entry(
                &mut memmap,
                layout::RAM_64BIT_START.raw_value(),
                mem_end.unchecked_offset_from(layout::RAM_64BIT_START) + 1,
                E820_RAM,
            )?;
        }
    }

    add_memmap_entry(
        &mut memmap,
        layout::PCI_MMCONFIG_START.0,
        layout::PCI_MMCONFIG_SIZE,
        E820_RESERVED,
    )?;

    start_info.0.memmap_entries = memmap.len() as u32;

    // Copy the vector with the memmap table to the MEMMAP_START address
    // which is already saved in the memmap_paddr field of hvm_start_info struct.
    let mut memmap_start_addr = layout::MEMMAP_START;

    guest_mem
        .checked_offset(
            memmap_start_addr,
            mem::size_of::<hvm_memmap_table_entry>() * start_info.0.memmap_entries as usize,
        )
        .ok_or(super::Error::MemmapTablePastRamEnd)?;

    // For every entry in the memmap vector, create a MemmapTableEntryWrapper
    // and write it to guest memory.
    for memmap_entry in memmap {
        let map_entry_wrapper: MemmapTableEntryWrapper = MemmapTableEntryWrapper(memmap_entry);

        guest_mem
            .write_obj(map_entry_wrapper, memmap_start_addr)
            .map_err(|_| super::Error::MemmapTableSetup)?;
        memmap_start_addr =
            memmap_start_addr.unchecked_add(mem::size_of::<hvm_memmap_table_entry>() as u64);
    }

    // The hvm_start_info struct itself must be stored at PVH_START_INFO
    // address, and %rbx will be initialized to contain PVH_INFO_START prior to
    // starting the guest, as required by the PVH ABI.
    let start_info_addr = layout::PVH_INFO_START;

    guest_mem
        .checked_offset(start_info_addr, mem::size_of::<hvm_start_info>())
        .ok_or(super::Error::StartInfoPastRamEnd)?;

    // Write the start_info struct to guest memory.
    guest_mem
        .write_obj(start_info, start_info_addr)
        .map_err(|_| super::Error::StartInfoSetup)?;

    Ok(())
}

fn add_memmap_entry(
    memmap: &mut Vec<hvm_memmap_table_entry>,
    addr: u64,
    size: u64,
    mem_type: u32,
) -> Result<(), Error> {
    // Add the table entry to the vector
    memmap.push(hvm_memmap_table_entry {
        addr,
        size,
        type_: mem_type,
        reserved: 0,
    });

    Ok(())
}

fn configure_64bit_boot(
    guest_mem: &GuestMemoryMmap,
    cmdline_addr: GuestAddress,
    cmdline_size: usize,
    initramfs: &Option<InitramfsConfig>,
    setup_hdr: Option<setup_header>,
    rsdp_addr: Option<GuestAddress>,
) -> super::Result<()> {
    const KERNEL_BOOT_FLAG_MAGIC: u16 = 0xaa55;
    const KERNEL_HDR_MAGIC: u32 = 0x53726448;
    const KERNEL_LOADER_OTHER: u8 = 0xff;
    const KERNEL_MIN_ALIGNMENT_BYTES: u32 = 0x1000000; // Must be non-zero.

    let mut params: BootParamsWrapper = BootParamsWrapper(boot_params::default());

    if let Some(hdr) = setup_hdr {
        // We should use the header if the loader provides one (e.g. from a bzImage).
        params.0.hdr = hdr;
    } else {
        params.0.hdr.boot_flag = KERNEL_BOOT_FLAG_MAGIC;
        params.0.hdr.header = KERNEL_HDR_MAGIC;
        params.0.hdr.kernel_alignment = KERNEL_MIN_ALIGNMENT_BYTES;
    };

    // Common bootparams settings
    if params.0.hdr.type_of_loader == 0 {
        params.0.hdr.type_of_loader = KERNEL_LOADER_OTHER;
    }
    params.0.hdr.cmd_line_ptr = cmdline_addr.raw_value() as u32;
    params.0.hdr.cmdline_size = cmdline_size as u32;

    if let Some(initramfs_config) = initramfs {
        params.0.hdr.ramdisk_image = initramfs_config.address.raw_value() as u32;
        params.0.hdr.ramdisk_size = initramfs_config.size as u32;
    }

    add_e820_entry(&mut params.0, 0, layout::EBDA_START.raw_value(), E820_RAM)?;

    let mem_end = guest_mem.last_addr();
    if mem_end < layout::MEM_32BIT_RESERVED_START {
        add_e820_entry(
            &mut params.0,
            layout::HIGH_RAM_START.raw_value(),
            mem_end.unchecked_offset_from(layout::HIGH_RAM_START) + 1,
            E820_RAM,
        )?;
    } else {
        add_e820_entry(
            &mut params.0,
            layout::HIGH_RAM_START.raw_value(),
            layout::MEM_32BIT_RESERVED_START.unchecked_offset_from(layout::HIGH_RAM_START),
            E820_RAM,
        )?;
        if mem_end > layout::RAM_64BIT_START {
            add_e820_entry(
                &mut params.0,
                layout::RAM_64BIT_START.raw_value(),
                mem_end.unchecked_offset_from(layout::RAM_64BIT_START) + 1,
                E820_RAM,
            )?;
        }
    }

    add_e820_entry(
        &mut params.0,
        layout::PCI_MMCONFIG_START.0,
        layout::PCI_MMCONFIG_SIZE,
        E820_RESERVED,
    )?;

    if let Some(rsdp_addr) = rsdp_addr {
        params.0.acpi_rsdp_addr = rsdp_addr.0;
    }

    let zero_page_addr = layout::ZERO_PAGE_START;
    guest_mem
        .checked_offset(zero_page_addr, mem::size_of::<boot_params>())
        .ok_or(super::Error::ZeroPagePastRamEnd)?;
    guest_mem
        .write_obj(params, zero_page_addr)
        .map_err(super::Error::ZeroPageSetup)?;

    Ok(())
}

/// Add an e820 region to the e820 map.
/// Returns Ok(()) if successful, or an error if there is no space left in the map.
fn add_e820_entry(
    params: &mut boot_params,
    addr: u64,
    size: u64,
    mem_type: u32,
) -> Result<(), Error> {
    if params.e820_entries >= params.e820_table.len() as u8 {
        return Err(Error::E820Configuration);
    }

    params.e820_table[params.e820_entries as usize].addr = addr;
    params.e820_table[params.e820_entries as usize].size = size;
    params.e820_table[params.e820_entries as usize].type_ = mem_type;
    params.e820_entries += 1;

    Ok(())
}

/// Returns the memory address where the initramfs could be loaded.
pub fn initramfs_load_addr(
    guest_mem: &GuestMemoryMmap,
    initramfs_size: usize,
) -> super::Result<u64> {
    let first_region = guest_mem
        .find_region(GuestAddress::new(0))
        .ok_or(super::Error::InitramfsAddress)?;
    // It's safe to cast to usize because the size of a region can't be greater than usize.
    let lowmem_size = first_region.len() as usize;

    if lowmem_size < initramfs_size {
        return Err(super::Error::InitramfsAddress);
    }

    let aligned_addr: u64 = ((lowmem_size - initramfs_size) & !(crate::pagesize() - 1)) as u64;
    Ok(aligned_addr)
}

pub fn get_host_cpu_phys_bits() -> u8 {
    use std::arch::x86_64;
    unsafe {
        let leaf = x86_64::__cpuid(0x8000_0000);

        // Detect and handle AMD SME (Secure Memory Encryption) properly.
        // Some physical address bits may become reserved when the feature is enabled.
        // See AMD64 Architecture Programmer's Manual Volume 2, Section 7.10.1
        let reduced = if leaf.eax >= 0x8000_001f
            && leaf.ebx == 0x6874_7541    // Vendor ID: AuthenticAMD
            && leaf.ecx == 0x444d_4163
            && leaf.edx == 0x6974_6e65
            && x86_64::__cpuid(0x8000_001f).eax & 0x1 != 0
        {
            (x86_64::__cpuid(0x8000_001f).ebx >> 6) & 0x3f
        } else {
            0
        };

        if leaf.eax >= 0x8000_0008 {
            let leaf = x86_64::__cpuid(0x8000_0008);
            ((leaf.eax & 0xff) - reduced) as u8
        } else {
            36
        }
    }
}

pub fn check_required_kvm_extensions(kvm: &Kvm) -> super::Result<()> {
    if !kvm.check_extension(Cap::SignalMsi) {
        return Err(super::Error::CapabilityMissing(Cap::SignalMsi));
    }
    if !kvm.check_extension(Cap::TscDeadlineTimer) {
        return Err(super::Error::CapabilityMissing(Cap::TscDeadlineTimer));
    }
    if !kvm.check_extension(Cap::SplitIrqchip) {
        return Err(super::Error::CapabilityMissing(Cap::SplitIrqchip));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use linux_loader::loader::bootparam::boot_e820_entry;

    #[test]
    fn regions_lt_4gb() {
        let regions = arch_memory_regions(1 << 29 as GuestUsize);
        assert_eq!(3, regions.len());
        assert_eq!(GuestAddress(0), regions[0].0);
        assert_eq!(1usize << 29, regions[0].1);
    }

    #[test]
    fn regions_gt_4gb() {
        let regions = arch_memory_regions((1 << 32 as GuestUsize) + 0x8000);
        assert_eq!(4, regions.len());
        assert_eq!(GuestAddress(0), regions[0].0);
        assert_eq!(GuestAddress(1 << 32), regions[1].0);
    }

    #[test]
    fn test_system_configuration() {
        let no_vcpus = 4;
        let gm = GuestMemoryMmap::from_ranges(&vec![(GuestAddress(0), 0x10000)]).unwrap();
        let config_err = configure_system(
            &gm,
            GuestAddress(0),
            0,
            &None,
            1,
            None,
            Some(layout::RSDP_POINTER),
            BootProtocol::LinuxBoot,
        );
        assert!(config_err.is_err());

        // Now assigning some memory that falls before the 32bit memory hole.
        let mem_size = 128 << 20;
        let arch_mem_regions = arch_memory_regions(mem_size);
        let ram_regions: Vec<(GuestAddress, usize)> = arch_mem_regions
            .iter()
            .filter(|r| r.2 == RegionType::Ram)
            .map(|r| (r.0, r.1))
            .collect();
        let gm = GuestMemoryMmap::from_ranges(&ram_regions).unwrap();
        configure_system(
            &gm,
            GuestAddress(0),
            0,
            &None,
            no_vcpus,
            None,
            None,
            BootProtocol::LinuxBoot,
        )
        .unwrap();

        configure_system(
            &gm,
            GuestAddress(0),
            0,
            &None,
            no_vcpus,
            None,
            None,
            BootProtocol::PvhBoot,
        )
        .unwrap();

        // Now assigning some memory that is equal to the start of the 32bit memory hole.
        let mem_size = 3328 << 20;
        let arch_mem_regions = arch_memory_regions(mem_size);
        let ram_regions: Vec<(GuestAddress, usize)> = arch_mem_regions
            .iter()
            .filter(|r| r.2 == RegionType::Ram)
            .map(|r| (r.0, r.1))
            .collect();
        let gm = GuestMemoryMmap::from_ranges(&ram_regions).unwrap();
        configure_system(
            &gm,
            GuestAddress(0),
            0,
            &None,
            no_vcpus,
            None,
            None,
            BootProtocol::LinuxBoot,
        )
        .unwrap();

        configure_system(
            &gm,
            GuestAddress(0),
            0,
            &None,
            no_vcpus,
            None,
            None,
            BootProtocol::PvhBoot,
        )
        .unwrap();

        // Now assigning some memory that falls after the 32bit memory hole.
        let mem_size = 3330 << 20;
        let arch_mem_regions = arch_memory_regions(mem_size);
        let ram_regions: Vec<(GuestAddress, usize)> = arch_mem_regions
            .iter()
            .filter(|r| r.2 == RegionType::Ram)
            .map(|r| (r.0, r.1))
            .collect();
        let gm = GuestMemoryMmap::from_ranges(&ram_regions).unwrap();
        configure_system(
            &gm,
            GuestAddress(0),
            0,
            &None,
            no_vcpus,
            None,
            None,
            BootProtocol::LinuxBoot,
        )
        .unwrap();

        configure_system(
            &gm,
            GuestAddress(0),
            0,
            &None,
            no_vcpus,
            None,
            None,
            BootProtocol::PvhBoot,
        )
        .unwrap();
    }

    #[test]
    fn test_add_e820_entry() {
        let e820_table = [(boot_e820_entry {
            addr: 0x1,
            size: 4,
            type_: 1,
        }); 128];

        let expected_params = boot_params {
            e820_table,
            e820_entries: 1,
            ..Default::default()
        };

        let mut params: boot_params = Default::default();
        add_e820_entry(
            &mut params,
            e820_table[0].addr,
            e820_table[0].size,
            e820_table[0].type_,
        )
        .unwrap();
        assert_eq!(
            format!("{:?}", params.e820_table[0]),
            format!("{:?}", expected_params.e820_table[0])
        );
        assert_eq!(params.e820_entries, expected_params.e820_entries);

        // Exercise the scenario where the field storing the length of the e820 entry table is
        // is bigger than the allocated memory.
        params.e820_entries = params.e820_table.len() as u8 + 1;
        assert!(add_e820_entry(
            &mut params,
            e820_table[0].addr,
            e820_table[0].size,
            e820_table[0].type_
        )
        .is_err());
    }

    #[test]
    fn test_add_memmap_entry() {
        let mut memmap: Vec<hvm_memmap_table_entry> = Vec::new();

        let expected_memmap = vec![
            hvm_memmap_table_entry {
                addr: 0x0,
                size: 0x1000,
                type_: E820_RAM,
                ..Default::default()
            },
            hvm_memmap_table_entry {
                addr: 0x10000,
                size: 0xa000,
                type_: E820_RESERVED,
                ..Default::default()
            },
        ];

        add_memmap_entry(&mut memmap, 0, 0x1000, E820_RAM).unwrap();
        add_memmap_entry(&mut memmap, 0x10000, 0xa000, E820_RESERVED).unwrap();

        assert_eq!(format!("{:?}", memmap), format!("{:?}", expected_memmap));
    }
}
