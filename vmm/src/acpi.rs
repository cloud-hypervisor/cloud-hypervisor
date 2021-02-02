// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
use crate::cpu::CpuManager;
use crate::device_manager::DeviceManager;
use crate::memory_manager::MemoryManager;
use crate::vm::NumaNodes;
#[cfg(target_arch = "x86_64")]
use acpi_tables::sdt::GenericAddress;
use acpi_tables::{aml::Aml, rsdp::Rsdp, sdt::Sdt};

use bitflags::bitflags;
use std::sync::{Arc, Mutex};
use vm_memory::GuestRegionMmap;
use vm_memory::{Address, ByteValued, Bytes, GuestAddress, GuestMemoryMmap, GuestMemoryRegion};

#[repr(packed)]
#[derive(Default)]
struct PciRangeEntry {
    pub base_address: u64,
    pub segment: u16,
    pub start: u8,
    pub end: u8,
    _reserved: u32,
}

#[repr(packed)]
#[derive(Default)]
struct MemoryAffinity {
    pub type_: u8,
    pub length: u8,
    pub proximity_domain: u32,
    _reserved1: u16,
    pub base_addr_lo: u32,
    pub base_addr_hi: u32,
    pub length_lo: u32,
    pub length_hi: u32,
    _reserved2: u32,
    pub flags: u32,
    _reserved3: u64,
}

#[repr(packed)]
#[derive(Default)]
struct ProcessorLocalX2ApicAffinity {
    pub type_: u8,
    pub length: u8,
    _reserved1: u16,
    pub proximity_domain: u32,
    pub x2apic_id: u32,
    pub flags: u32,
    pub clock_domain: u32,
    _reserved2: u32,
}

bitflags! {
    pub struct MemAffinityFlags: u32 {
        const NOFLAGS = 0;
        const ENABLE = 0b1;
        const HOTPLUGGABLE = 0b10;
        const NON_VOLATILE = 0b100;
    }
}

impl MemoryAffinity {
    fn from_region(
        region: &Arc<GuestRegionMmap>,
        proximity_domain: u32,
        flags: MemAffinityFlags,
    ) -> Self {
        let base_addr = region.start_addr().raw_value();
        let base_addr_lo = (base_addr & 0xffff_ffff) as u32;
        let base_addr_hi = (base_addr >> 32) as u32;
        let length = region.len() as u64;
        let length_lo = (length & 0xffff_ffff) as u32;
        let length_hi = (length >> 32) as u32;

        MemoryAffinity {
            type_: 1,
            length: 40,
            proximity_domain,
            base_addr_lo,
            base_addr_hi,
            length_lo,
            length_hi,
            flags: flags.bits(),
            ..Default::default()
        }
    }
}

pub fn create_dsdt_table(
    device_manager: &Arc<Mutex<DeviceManager>>,
    cpu_manager: &Arc<Mutex<CpuManager>>,
    memory_manager: &Arc<Mutex<MemoryManager>>,
) -> Sdt {
    // DSDT
    let mut dsdt = Sdt::new(*b"DSDT", 36, 6, *b"CLOUDH", *b"CHDSDT  ", 1);

    dsdt.append_slice(device_manager.lock().unwrap().to_aml_bytes().as_slice());
    dsdt.append_slice(cpu_manager.lock().unwrap().to_aml_bytes().as_slice());
    dsdt.append_slice(memory_manager.lock().unwrap().to_aml_bytes().as_slice());

    dsdt
}

pub fn create_acpi_tables(
    guest_mem: &GuestMemoryMmap,
    device_manager: &Arc<Mutex<DeviceManager>>,
    cpu_manager: &Arc<Mutex<CpuManager>>,
    memory_manager: &Arc<Mutex<MemoryManager>>,
    numa_nodes: &NumaNodes,
) -> GuestAddress {
    let rsdp_offset = arch::layout::RSDP_POINTER;
    let mut tables: Vec<u64> = Vec::new();

    // DSDT
    let dsdt = create_dsdt_table(device_manager, cpu_manager, memory_manager);
    let dsdt_offset = rsdp_offset.checked_add(Rsdp::len() as u64).unwrap();
    guest_mem
        .write_slice(dsdt.as_slice(), dsdt_offset)
        .expect("Error writing DSDT table");

    // FACP aka FADT
    // Revision 6 of the ACPI FADT table is 276 bytes long
    let mut facp = Sdt::new(*b"FACP", 276, 6, *b"CLOUDH", *b"CHFACP  ", 1);

    // PM_TMR_BLK I/O port
    #[cfg(target_arch = "x86_64")]
    facp.write(76, 0xb008u32);

    // HW_REDUCED_ACPI, RESET_REG_SUP, TMR_VAL_EXT
    let fadt_flags: u32 = 1 << 20 | 1 << 10 | 1 << 8;
    facp.write(112, fadt_flags);

    // RESET_REG
    #[cfg(target_arch = "x86_64")]
    facp.write(116, GenericAddress::io_port_address::<u8>(0x3c0));
    // RESET_VALUE
    #[cfg(target_arch = "x86_64")]
    facp.write(128, 1u8);

    facp.write(131, 3u8); // FADT minor version
    facp.write(140, dsdt_offset.0); // X_DSDT

    // X_PM_TMR_BLK
    #[cfg(target_arch = "x86_64")]
    facp.write(208, GenericAddress::io_port_address::<u32>(0xb008));

    // SLEEP_CONTROL_REG
    #[cfg(target_arch = "x86_64")]
    facp.write(244, GenericAddress::io_port_address::<u8>(0x3c0));
    // SLEEP_STATUS_REG
    #[cfg(target_arch = "x86_64")]
    facp.write(256, GenericAddress::io_port_address::<u8>(0x3c0));

    facp.write(268, b"CLOUDHYP"); // Hypervisor Vendor Identity

    facp.update_checksum();
    let facp_offset = dsdt_offset.checked_add(dsdt.len() as u64).unwrap();
    guest_mem
        .write_slice(facp.as_slice(), facp_offset)
        .expect("Error writing FACP table");
    tables.push(facp_offset.0);

    // MADT
    let madt = cpu_manager.lock().unwrap().create_madt();
    let madt_offset = facp_offset.checked_add(facp.len() as u64).unwrap();
    guest_mem
        .write_slice(madt.as_slice(), madt_offset)
        .expect("Error writing MADT table");
    tables.push(madt_offset.0);

    // MCFG
    let mut mcfg = Sdt::new(*b"MCFG", 36, 1, *b"CLOUDH", *b"CHMCFG  ", 1);

    // MCFG reserved 8 bytes
    mcfg.append(0u64);

    // 32-bit PCI enhanced configuration mechanism
    mcfg.append(PciRangeEntry {
        base_address: arch::layout::PCI_MMCONFIG_START.0,
        segment: 0,
        start: 0,
        end: 0,
        ..Default::default()
    });

    let mcfg_offset = madt_offset.checked_add(madt.len() as u64).unwrap();
    guest_mem
        .write_slice(mcfg.as_slice(), mcfg_offset)
        .expect("Error writing MCFG table");
    tables.push(mcfg_offset.0);

    // SRAT and SLIT
    // Only created if the NUMA nodes list is not empty.
    let (prev_tbl_len, prev_tbl_off) = if numa_nodes.is_empty() {
        (mcfg.len(), mcfg_offset)
    } else {
        // SRAT
        let mut srat = Sdt::new(*b"SRAT", 36, 3, *b"CLOUDH", *b"CHSRAT  ", 1);
        // SRAT reserved 12 bytes
        srat.append_slice(&[0u8; 12]);

        // Check the MemoryAffinity structure is the right size as expected by
        // the ACPI specification.
        assert_eq!(std::mem::size_of::<MemoryAffinity>(), 40);

        for (node_id, node) in numa_nodes.iter() {
            let proximity_domain = *node_id as u32;

            for region in node.memory_regions() {
                srat.append(MemoryAffinity::from_region(
                    region,
                    proximity_domain,
                    MemAffinityFlags::ENABLE,
                ))
            }

            for region in node.hotplug_regions() {
                srat.append(MemoryAffinity::from_region(
                    region,
                    proximity_domain,
                    MemAffinityFlags::ENABLE | MemAffinityFlags::HOTPLUGGABLE,
                ))
            }

            for cpu in node.cpus() {
                let x2apic_id = *cpu as u32;

                // Flags
                // - Enabled = 1 (bit 0)
                // - Reserved bits 1-31
                let flags = 1;

                srat.append(ProcessorLocalX2ApicAffinity {
                    type_: 2,
                    length: 24,
                    proximity_domain,
                    x2apic_id,
                    flags,
                    clock_domain: 0,
                    ..Default::default()
                });
            }
        }

        let srat_offset = mcfg_offset.checked_add(mcfg.len() as u64).unwrap();
        guest_mem
            .write_slice(srat.as_slice(), srat_offset)
            .expect("Error writing SRAT table");
        tables.push(srat_offset.0);

        // SLIT
        let mut slit = Sdt::new(*b"SLIT", 36, 1, *b"CLOUDH", *b"CHSLIT  ", 1);
        // Number of System Localities on 8 bytes.
        slit.append(numa_nodes.len() as u64);

        let existing_nodes: Vec<u32> = numa_nodes.keys().cloned().collect();
        for (node_id, node) in numa_nodes.iter() {
            let distances = node.distances();
            for i in existing_nodes.iter() {
                let dist: u8 = if *node_id == *i {
                    10
                } else if let Some(distance) = distances.get(i) {
                    *distance as u8
                } else {
                    20
                };

                slit.append(dist);
            }
        }

        let slit_offset = srat_offset.checked_add(srat.len() as u64).unwrap();
        guest_mem
            .write_slice(slit.as_slice(), slit_offset)
            .expect("Error writing SRAT table");
        tables.push(slit_offset.0);

        (slit.len(), slit_offset)
    };

    // XSDT
    let mut xsdt = Sdt::new(*b"XSDT", 36, 1, *b"CLOUDH", *b"CHXSDT  ", 1);
    for table in tables {
        xsdt.append(table);
    }
    xsdt.update_checksum();

    let xsdt_offset = prev_tbl_off.checked_add(prev_tbl_len as u64).unwrap();
    guest_mem
        .write_slice(xsdt.as_slice(), xsdt_offset)
        .expect("Error writing XSDT table");

    // RSDP
    let rsdp = Rsdp::new(*b"CLOUDH", xsdt_offset.0);
    guest_mem
        .write_slice(rsdp.as_slice(), rsdp_offset)
        .expect("Error writing RSDP");

    rsdp_offset
}
