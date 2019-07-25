// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

mod gdt;
pub mod interrupts;
pub mod layout;
mod mptable;
pub mod regs;

use crate::RegionType;
use linux_loader::loader::bootparam::{boot_params, setup_header, E820_RAM};
use std::mem;
use vm_memory::{
    Address, ByteValued, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap, GuestUsize,
};

// This is a workaround to the Rust enforcement specifying that any implementation of a foreign
// trait (in this case `DataInit`) where:
// *    the type that is implementing the trait is foreign or
// *    all of the parameters being passed to the trait (if there are any) are also foreign
// is prohibited.
#[derive(Copy, Clone, Default)]
struct BootParamsWrapper(boot_params);

// It is safe to initialize BootParamsWrap which is a wrapper over `boot_params` (a series of ints).
unsafe impl ByteValued for BootParamsWrapper {}

#[derive(Debug, PartialEq)]
pub enum Error {
    /// Invalid e820 setup params.
    E820Configuration,
    /// Error writing MP table to memory.
    MpTableSetup(mptable::Error),
}

impl From<Error> for super::Error {
    fn from(e: Error) -> super::Error {
        super::Error::X86_64Setup(e)
    }
}

// Where BIOS/VGA magic would live on a real PC.
const EBDA_START: GuestAddress = GuestAddress(0x9fc00);
const FIRST_ADDR_PAST_32BITS: GuestAddress = GuestAddress(1 << 32);

// Our 32-bit memory gap starts at 3G.
const MEM_32BIT_GAP_START: GuestAddress = GuestAddress(0xc000_0000);

// Our 32-bit memory gap size is 1GB.
const MEM_32BIT_GAP_SIZE: GuestUsize = (1024 << 20);

// We reserve 768MB in our memory gap for 32-bit devices (e.g. 32-bit PCI BARs).
const MEM_32BIT_DEVICES_GAP_SIZE: GuestUsize = (768 << 20);

/// Returns a Vec of the valid memory addresses.
/// These should be used to configure the GuestMemory structure for the platform.
/// For x86_64 all addresses are valid from the start of the kernel except a
/// carve out at the end of 32bit address space.
pub fn arch_memory_regions(size: GuestUsize) -> Vec<(GuestAddress, usize, RegionType)> {
    let reserved_memory_gap_start = MEM_32BIT_GAP_START
        .checked_add(MEM_32BIT_DEVICES_GAP_SIZE)
        .expect("32-bit reserved region is too large");

    let requested_memory_size = GuestAddress(size as u64);
    let mut regions = Vec::new();

    // case1: guest memory fits before the gap
    if size as u64 <= MEM_32BIT_GAP_START.raw_value() {
        regions.push((GuestAddress(0), size as usize, RegionType::Ram));
    // case2: guest memory extends beyond the gap
    } else {
        // push memory before the gap
        regions.push((
            GuestAddress(0),
            MEM_32BIT_GAP_START.raw_value() as usize,
            RegionType::Ram,
        ));
        regions.push((
            FIRST_ADDR_PAST_32BITS,
            requested_memory_size.unchecked_offset_from(MEM_32BIT_GAP_START) as usize,
            RegionType::Ram,
        ));
    }

    // Add the 32-bit device memory hole as a sub region.
    regions.push((
        MEM_32BIT_GAP_START,
        MEM_32BIT_DEVICES_GAP_SIZE as usize,
        RegionType::SubRegion,
    ));

    // Add the 32-bit reserved memory hole as a sub region.
    regions.push((
        reserved_memory_gap_start,
        (MEM_32BIT_GAP_SIZE - MEM_32BIT_DEVICES_GAP_SIZE) as usize,
        RegionType::Reserved,
    ));

    regions
}

/// X86 specific memory hole/memory mapped devices/reserved area.
pub fn get_32bit_gap_start() -> GuestAddress {
    FIRST_ADDR_PAST_32BITS
        .checked_sub(MEM_32BIT_GAP_SIZE)
        .expect("32-bit hole is too large")
}

/// Configures the system and should be called once per vm before starting vcpu threads.
///
/// # Arguments
///
/// * `guest_mem` - The memory to be used by the guest.
/// * `cmdline_addr` - Address in `guest_mem` where the kernel command line was loaded.
/// * `cmdline_size` - Size of the kernel command line in bytes including the null terminator.
/// * `num_cpus` - Number of virtual CPUs the guest will have.
pub fn configure_system(
    guest_mem: &GuestMemoryMmap,
    cmdline_addr: GuestAddress,
    cmdline_size: usize,
    num_cpus: u8,
    setup_hdr: Option<setup_header>,
) -> super::Result<()> {
    const KERNEL_BOOT_FLAG_MAGIC: u16 = 0xaa55;
    const KERNEL_HDR_MAGIC: u32 = 0x53726448;
    const KERNEL_LOADER_OTHER: u8 = 0xff;
    const KERNEL_MIN_ALIGNMENT_BYTES: u32 = 0x1000000; // Must be non-zero.
    let first_addr_past_32bits = FIRST_ADDR_PAST_32BITS;
    let end_32bit_gap_start = get_32bit_gap_start();

    let himem_start = super::HIMEM_START;

    // Note that this puts the mptable at the last 1k of Linux's 640k base RAM
    mptable::setup_mptable(guest_mem, num_cpus).map_err(Error::MpTableSetup)?;

    let mut params: BootParamsWrapper = BootParamsWrapper(boot_params::default());

    if setup_hdr.is_some() {
        params.0.hdr = setup_hdr.unwrap();
        params.0.hdr.cmd_line_ptr = cmdline_addr.raw_value() as u32;
        params.0.hdr.cmdline_size = cmdline_size as u32;
    } else {
        params.0.hdr.type_of_loader = KERNEL_LOADER_OTHER;
        params.0.hdr.boot_flag = KERNEL_BOOT_FLAG_MAGIC;
        params.0.hdr.header = KERNEL_HDR_MAGIC;
        params.0.hdr.cmd_line_ptr = cmdline_addr.raw_value() as u32;
        params.0.hdr.cmdline_size = cmdline_size as u32;
        params.0.hdr.kernel_alignment = KERNEL_MIN_ALIGNMENT_BYTES;
    };

    add_e820_entry(&mut params.0, 0, EBDA_START.raw_value(), E820_RAM)?;

    let mem_end = guest_mem.end_addr();
    if mem_end < end_32bit_gap_start {
        add_e820_entry(
            &mut params.0,
            himem_start.raw_value(),
            mem_end.unchecked_offset_from(himem_start),
            E820_RAM,
        )?;
    } else {
        add_e820_entry(
            &mut params.0,
            himem_start.raw_value(),
            end_32bit_gap_start.unchecked_offset_from(himem_start),
            E820_RAM,
        )?;
        if mem_end > first_addr_past_32bits {
            add_e820_entry(
                &mut params.0,
                first_addr_past_32bits.raw_value(),
                mem_end.unchecked_offset_from(first_addr_past_32bits),
                E820_RAM,
            )?;
        }
    }

    let zero_page_addr = layout::ZERO_PAGE_START;
    guest_mem
        .checked_offset(zero_page_addr, mem::size_of::<boot_params>())
        .ok_or(super::Error::ZeroPagePastRamEnd)?;
    guest_mem
        .write_obj(params, zero_page_addr)
        .map_err(|_| super::Error::ZeroPageSetup)?;

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
    if params.e820_entries >= params.e820_map.len() as u8 {
        return Err(Error::E820Configuration);
    }

    params.e820_map[params.e820_entries as usize].addr = addr;
    params.e820_map[params.e820_entries as usize].size = size;
    params.e820_map[params.e820_entries as usize].type_ = mem_type;
    params.e820_entries += 1;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use linux_loader::loader::bootparam::e820entry;

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
    fn test_32bit_gap() {
        assert_eq!(
            get_32bit_gap_start(),
            FIRST_ADDR_PAST_32BITS
                .checked_sub(MEM_32BIT_GAP_SIZE as u64)
                .expect("32-bit hole is too large")
        );
    }

    #[test]
    fn test_system_configuration() {
        let no_vcpus = 4;
        let gm = GuestMemoryMmap::new(&vec![(GuestAddress(0), 0x10000)]).unwrap();
        let config_err = configure_system(&gm, GuestAddress(0), 0, 1, None);
        assert!(config_err.is_err());
        assert_eq!(
            config_err.unwrap_err(),
            super::super::Error::X86_64Setup(super::Error::MpTableSetup(
                mptable::Error::NotEnoughMemory
            ))
        );

        // Now assigning some memory that falls before the 32bit memory hole.
        let mem_size = 128 << 20;
        let arch_mem_regions = arch_memory_regions(mem_size);
        let ram_regions: Vec<(GuestAddress, usize)> = arch_mem_regions
            .iter()
            .filter(|r| r.2 == RegionType::Ram)
            .map(|r| (r.0, r.1))
            .collect();
        let gm = GuestMemoryMmap::new(&ram_regions).unwrap();
        configure_system(&gm, GuestAddress(0), 0, no_vcpus, None).unwrap();

        // Now assigning some memory that is equal to the start of the 32bit memory hole.
        let mem_size = 3328 << 20;
        let arch_mem_regions = arch_memory_regions(mem_size);
        let ram_regions: Vec<(GuestAddress, usize)> = arch_mem_regions
            .iter()
            .filter(|r| r.2 == RegionType::Ram)
            .map(|r| (r.0, r.1))
            .collect();
        let gm = GuestMemoryMmap::new(&ram_regions).unwrap();
        configure_system(&gm, GuestAddress(0), 0, no_vcpus, None).unwrap();

        // Now assigning some memory that falls after the 32bit memory hole.
        let mem_size = 3330 << 20;
        let arch_mem_regions = arch_memory_regions(mem_size);
        let ram_regions: Vec<(GuestAddress, usize)> = arch_mem_regions
            .iter()
            .filter(|r| r.2 == RegionType::Ram)
            .map(|r| (r.0, r.1))
            .collect();
        let gm = GuestMemoryMmap::new(&ram_regions).unwrap();
        configure_system(&gm, GuestAddress(0), 0, no_vcpus, None).unwrap();
    }

    #[test]
    fn test_add_e820_entry() {
        let e820_map = [(e820entry {
            addr: 0x1,
            size: 4,
            type_: 1,
        }); 128];

        let expected_params = boot_params {
            e820_map,
            e820_entries: 1,
            ..Default::default()
        };

        let mut params: boot_params = Default::default();
        add_e820_entry(
            &mut params,
            e820_map[0].addr,
            e820_map[0].size,
            e820_map[0].type_,
        )
        .unwrap();
        assert_eq!(
            format!("{:?}", params.e820_map[0]),
            format!("{:?}", expected_params.e820_map[0])
        );
        assert_eq!(params.e820_entries, expected_params.e820_entries);

        // Exercise the scenario where the field storing the length of the e820 entry table is
        // is bigger than the allocated memory.
        params.e820_entries = params.e820_map.len() as u8 + 1;
        assert!(add_e820_entry(
            &mut params,
            e820_map[0].addr,
            e820_map[0].size,
            e820_map[0].type_
        )
        .is_err());
    }
}
