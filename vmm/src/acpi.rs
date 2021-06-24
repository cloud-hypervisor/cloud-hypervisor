// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
use crate::cpu::CpuManager;
use crate::device_manager::DeviceManager;
use crate::memory_manager::MemoryManager;
use crate::vm::NumaNodes;
use crate::{GuestMemoryMmap, GuestRegionMmap};
use acpi_tables::sdt::GenericAddress;
use acpi_tables::{aml::Aml, rsdp::Rsdp, sdt::Sdt};
#[cfg(target_arch = "aarch64")]
use arch::aarch64::DeviceInfoForFdt;
#[cfg(target_arch = "aarch64")]
use arch::DeviceType;

use bitflags::bitflags;
use std::sync::{Arc, Mutex};
use vm_memory::{Address, ByteValued, Bytes, GuestAddress, GuestMemoryRegion};

/* Values for Type in APIC sub-headers */
#[cfg(target_arch = "x86_64")]
pub const ACPI_APIC_PROCESSOR: u8 = 0;
#[cfg(target_arch = "x86_64")]
pub const ACPI_APIC_IO: u8 = 1;
#[cfg(target_arch = "x86_64")]
pub const ACPI_APIC_XRUPT_OVERRIDE: u8 = 2;
#[cfg(target_arch = "aarch64")]
pub const ACPI_APIC_GENERIC_CPU_INTERFACE: u8 = 11;
#[cfg(target_arch = "aarch64")]
pub const ACPI_APIC_GENERIC_DISTRIBUTOR: u8 = 12;
#[cfg(target_arch = "aarch64")]
pub const ACPI_APIC_GENERIC_REDISTRIBUTOR: u8 = 14;
#[cfg(target_arch = "aarch64")]
pub const ACPI_APIC_GENERIC_TRANSLATOR: u8 = 15;

#[allow(dead_code)]
#[repr(packed)]
#[derive(Default)]
struct PciRangeEntry {
    pub base_address: u64,
    pub segment: u16,
    pub start: u8,
    pub end: u8,
    _reserved: u32,
}

#[allow(dead_code)]
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

#[allow(dead_code)]
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

#[allow(dead_code)]
#[repr(packed)]
#[derive(Default)]
struct ViotVirtioPciNode {
    pub type_: u8,
    _reserved: u8,
    pub length: u16,
    pub pci_segment: u16,
    pub pci_bdf_number: u16,
    _reserved2: [u8; 8],
}

#[allow(dead_code)]
#[repr(packed)]
#[derive(Default)]
struct ViotPciRangeNode {
    pub type_: u8,
    _reserved: u8,
    pub length: u16,
    pub endpoint_start: u32,
    pub pci_segment_start: u16,
    pub pci_segment_end: u16,
    pub pci_bdf_start: u16,
    pub pci_bdf_end: u16,
    pub output_node: u16,
    _reserved2: [u8; 6],
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

fn create_facp_table(dsdt_offset: GuestAddress) -> Sdt {
    // Revision 6 of the ACPI FADT table is 276 bytes long
    let mut facp = Sdt::new(*b"FACP", 276, 6, *b"CLOUDH", *b"CHFACP  ", 1);

    // x86_64 specific fields
    #[cfg(target_arch = "x86_64")]
    {
        // PM_TMR_BLK I/O port
        facp.write(76, 0xb008u32);
        // RESET_REG
        facp.write(116, GenericAddress::io_port_address::<u8>(0x3c0));
        // RESET_VALUE
        facp.write(128, 1u8);
        // X_PM_TMR_BLK
        facp.write(208, GenericAddress::io_port_address::<u32>(0xb008));
        // SLEEP_CONTROL_REG
        facp.write(244, GenericAddress::io_port_address::<u8>(0x3c0));
        // SLEEP_STATUS_REG
        facp.write(256, GenericAddress::io_port_address::<u8>(0x3c0));
    }

    // aarch64 specific fields
    #[cfg(target_arch = "aarch64")]
    // ARM_BOOT_ARCH: enable PSCI with HVC enable-method
    facp.write(129, 3u16);

    // Architecture common fields
    // HW_REDUCED_ACPI, RESET_REG_SUP, TMR_VAL_EXT
    let fadt_flags: u32 = 1 << 20 | 1 << 10 | 1 << 8;
    facp.write(112, fadt_flags);
    // FADT minor version
    facp.write(131, 3u8);
    // X_DSDT
    facp.write(140, dsdt_offset.0);
    // Hypervisor Vendor Identity
    facp.write(268, b"CLOUDHYP");

    facp.update_checksum();

    facp
}

fn create_mcfg_table() -> Sdt {
    let mut mcfg = Sdt::new(*b"MCFG", 36, 1, *b"CLOUDH", *b"CHMCFG  ", 1);

    // MCFG reserved 8 bytes
    mcfg.append(0u64);

    // 32-bit PCI enhanced configuration mechanism
    mcfg.append(PciRangeEntry {
        base_address: arch::layout::PCI_MMCONFIG_START.0,
        segment: 0,
        start: 0,
        end: ((arch::layout::PCI_MMCONFIG_SIZE - 1) >> 20) as u8,
        ..Default::default()
    });
    mcfg
}

fn create_srat_table(numa_nodes: &NumaNodes) -> Sdt {
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
    srat
}

fn create_slit_table(numa_nodes: &NumaNodes) -> Sdt {
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
    slit
}

#[cfg(target_arch = "aarch64")]
fn create_gtdt_table() -> Sdt {
    const ARCH_TIMER_NS_EL2_IRQ: u32 = 10;
    const ARCH_TIMER_VIRT_IRQ: u32 = 11;
    const ARCH_TIMER_S_EL1_IRQ: u32 = 13;
    const ARCH_TIMER_NS_EL1_IRQ: u32 = 14;
    const ACPI_GTDT_INTERRUPT_MODE_LEVEL: u32 = 0;
    const ACPI_GTDT_CAP_ALWAYS_ON: u32 = 1 << 2;

    let irqflags: u32 = ACPI_GTDT_INTERRUPT_MODE_LEVEL;
    // GTDT
    let mut gtdt = Sdt::new(*b"GTDT", 104, 2, *b"CLOUDH", *b"CHGTDT  ", 1);
    // Secure EL1 Timer GSIV
    gtdt.write(48, (ARCH_TIMER_S_EL1_IRQ + 16) as u32);
    // Secure EL1 Timer Flags
    gtdt.write(52, irqflags);
    // Non-Secure EL1 Timer GSIV
    gtdt.write(56, (ARCH_TIMER_NS_EL1_IRQ + 16) as u32);
    // Non-Secure EL1 Timer Flags
    gtdt.write(60, (irqflags | ACPI_GTDT_CAP_ALWAYS_ON) as u32);
    // Virtual EL1 Timer GSIV
    gtdt.write(64, (ARCH_TIMER_VIRT_IRQ + 16) as u32);
    // Virtual EL1 Timer Flags
    gtdt.write(68, irqflags);
    // EL2 Timer GSIV
    gtdt.write(72, (ARCH_TIMER_NS_EL2_IRQ + 16) as u32);
    // EL2 Timer Flags
    gtdt.write(76, irqflags);

    gtdt.update_checksum();

    gtdt
}

#[cfg(target_arch = "aarch64")]
fn create_spcr_table(base_address: u64, gsi: u32) -> Sdt {
    // SPCR
    let mut spcr = Sdt::new(*b"SPCR", 80, 2, *b"CLOUDH", *b"CHSPCR  ", 1);
    // Interface Type
    spcr.write(36, 3u8);
    // Base Address in format ACPI Generic Address Structure
    spcr.write(40, GenericAddress::mmio_address::<u8>(base_address));
    // Interrupt Type: Bit[3] ARMH GIC interrupt
    spcr.write(52, (1 << 3) as u8);
    // Global System Interrupt used by the UART
    spcr.write(54, (gsi as u32).to_le());
    // Baud Rate: 3 = 9600
    spcr.write(58, 3u8);
    // Stop Bits: 1 Stop bit
    spcr.write(60, 1u8);
    // Flow Control: Bit[1] = RTS/CTS hardware flow control
    spcr.write(61, (1 << 1) as u8);
    // PCI Device ID: Not a PCI device
    spcr.write(64, 0xffff_u16);
    // PCI Vendor ID: Not a PCI device
    spcr.write(66, 0xffff_u16);

    spcr.update_checksum();

    spcr
}

#[cfg(target_arch = "aarch64")]
fn create_iort_table() -> Sdt {
    const ACPI_IORT_NODE_ITS_GROUP: u8 = 0x00;
    const ACPI_IORT_NODE_PCI_ROOT_COMPLEX: u8 = 0x02;

    // IORT
    let mut iort = Sdt::new(*b"IORT", 124, 2, *b"CLOUDH", *b"CHIORT  ", 1);
    // Nodes: PCI Root Complex, ITS
    // Note: We currently do not support SMMU
    iort.write(36, (2u32).to_le());
    iort.write(40, (48u32).to_le());

    // ITS group node
    iort.write(48, ACPI_IORT_NODE_ITS_GROUP as u8);
    // Length of the ITS group node in bytes
    iort.write(49, (24u16).to_le());
    // ITS counts
    iort.write(64, (1u32).to_le());

    // Root Complex Node
    iort.write(72, ACPI_IORT_NODE_PCI_ROOT_COMPLEX as u8);
    // Length of the root complex node in bytes
    iort.write(73, (52u16).to_le());
    // Mapping counts
    iort.write(80, (1u32).to_le());
    // Offset from the start of the RC node to the start of its Array of ID mappings
    iort.write(84, (32u32).to_le());
    // Fully coherent device
    iort.write(88, (1u32).to_le());
    // CCA = CPM = DCAS = 1
    iort.write(95, 3u8);
    // Identity RID mapping covering the whole input RID range
    iort.write(108, (0xffff_u32).to_le());
    // id_mapping_array_output_reference should be
    // the ITS group node (the first node) if no SMMU
    iort.write(116, (48u32).to_le());

    iort.update_checksum();

    iort
}

fn create_viot_table(iommu_bdf: u32, devices_bdf: &[u32]) -> Sdt {
    // VIOT
    let mut viot = Sdt::new(*b"VIOT", 36, 0, *b"CLOUDH", *b"CHVIOT  ", 0);
    // Node count
    viot.append((devices_bdf.len() + 1) as u16);
    // Node offset
    viot.append(48u16);
    // VIOT reserved 8 bytes
    viot.append_slice(&[0u8; 8]);

    // Virtio-iommu based on virtio-pci node
    viot.append(ViotVirtioPciNode {
        type_: 3,
        length: 16,
        pci_segment: 0,
        pci_bdf_number: iommu_bdf as u16,
        ..Default::default()
    });

    for device_bdf in devices_bdf {
        viot.append(ViotPciRangeNode {
            type_: 1,
            length: 24,
            endpoint_start: *device_bdf,
            pci_segment_start: 0,
            pci_segment_end: 0,
            pci_bdf_start: *device_bdf as u16,
            pci_bdf_end: *device_bdf as u16,
            output_node: 48,
            ..Default::default()
        });
    }

    viot
}

pub fn create_acpi_tables(
    guest_mem: &GuestMemoryMmap,
    device_manager: &Arc<Mutex<DeviceManager>>,
    cpu_manager: &Arc<Mutex<CpuManager>>,
    memory_manager: &Arc<Mutex<MemoryManager>>,
    numa_nodes: &NumaNodes,
) -> GuestAddress {
    let mut prev_tbl_len: u64;
    let mut prev_tbl_off: GuestAddress;
    let rsdp_offset = arch::layout::RSDP_POINTER;
    let mut tables: Vec<u64> = Vec::new();

    // DSDT
    let dsdt = create_dsdt_table(device_manager, cpu_manager, memory_manager);
    let dsdt_offset = rsdp_offset.checked_add(Rsdp::len() as u64).unwrap();
    guest_mem
        .write_slice(dsdt.as_slice(), dsdt_offset)
        .expect("Error writing DSDT table");

    // FACP aka FADT
    let facp = create_facp_table(dsdt_offset);
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
    prev_tbl_len = madt.len() as u64;
    prev_tbl_off = madt_offset;

    // GTDT
    #[cfg(target_arch = "aarch64")]
    {
        let gtdt = create_gtdt_table();
        let gtdt_offset = prev_tbl_off.checked_add(prev_tbl_len).unwrap();
        guest_mem
            .write_slice(gtdt.as_slice(), gtdt_offset)
            .expect("Error writing GTDT table");
        tables.push(gtdt_offset.0);
        prev_tbl_len = gtdt.len() as u64;
        prev_tbl_off = gtdt_offset;
    }

    // MCFG
    let mcfg = create_mcfg_table();
    let mcfg_offset = prev_tbl_off.checked_add(prev_tbl_len).unwrap();
    guest_mem
        .write_slice(mcfg.as_slice(), mcfg_offset)
        .expect("Error writing MCFG table");
    tables.push(mcfg_offset.0);
    prev_tbl_len = mcfg.len() as u64;
    prev_tbl_off = mcfg_offset;

    // SPCR
    #[cfg(target_arch = "aarch64")]
    {
        let is_serial_on = device_manager
            .lock()
            .unwrap()
            .get_device_info()
            .clone()
            .get(&(DeviceType::Serial, DeviceType::Serial.to_string()))
            .is_some();
        let serial_device_addr = arch::layout::LEGACY_SERIAL_MAPPED_IO_START;
        let serial_device_irq = if is_serial_on {
            device_manager
                .lock()
                .unwrap()
                .get_device_info()
                .clone()
                .get(&(DeviceType::Serial, DeviceType::Serial.to_string()))
                .unwrap()
                .irq()
        } else {
            // If serial is turned off, add a fake device with invalid irq.
            31
        };
        let spcr = create_spcr_table(serial_device_addr, serial_device_irq);
        let spcr_offset = prev_tbl_off.checked_add(prev_tbl_len).unwrap();
        guest_mem
            .write_slice(spcr.as_slice(), spcr_offset)
            .expect("Error writing SPCR table");
        tables.push(spcr_offset.0);
        prev_tbl_len = spcr.len() as u64;
        prev_tbl_off = spcr_offset;
    }

    // SRAT and SLIT
    // Only created if the NUMA nodes list is not empty.
    if !numa_nodes.is_empty() {
        // SRAT
        let srat = create_srat_table(numa_nodes);
        let srat_offset = prev_tbl_off.checked_add(prev_tbl_len).unwrap();
        guest_mem
            .write_slice(srat.as_slice(), srat_offset)
            .expect("Error writing SRAT table");
        tables.push(srat_offset.0);

        // SLIT
        let slit = create_slit_table(numa_nodes);
        let slit_offset = srat_offset.checked_add(srat.len() as u64).unwrap();
        guest_mem
            .write_slice(slit.as_slice(), slit_offset)
            .expect("Error writing SRAT table");
        tables.push(slit_offset.0);

        prev_tbl_len = slit.len() as u64;
        prev_tbl_off = slit_offset;
    };

    #[cfg(target_arch = "aarch64")]
    {
        let iort = create_iort_table();
        let iort_offset = prev_tbl_off.checked_add(prev_tbl_len).unwrap();
        guest_mem
            .write_slice(iort.as_slice(), iort_offset)
            .expect("Error writing IORT table");
        tables.push(iort_offset.0);
        prev_tbl_len = iort.len() as u64;
        prev_tbl_off = iort_offset;
    }

    // VIOT
    if let Some((iommu_bdf, devices_bdf)) = device_manager.lock().unwrap().iommu_attached_devices()
    {
        let viot = create_viot_table(*iommu_bdf, devices_bdf);

        let viot_offset = prev_tbl_off.checked_add(prev_tbl_len).unwrap();
        guest_mem
            .write_slice(viot.as_slice(), viot_offset)
            .expect("Error writing VIOT table");
        tables.push(viot_offset.0);
        prev_tbl_len = viot.len() as u64;
        prev_tbl_off = viot_offset;
    }

    // XSDT
    let mut xsdt = Sdt::new(*b"XSDT", 36, 1, *b"CLOUDH", *b"CHXSDT  ", 1);
    for table in tables {
        xsdt.append(table);
    }
    xsdt.update_checksum();
    let xsdt_offset = prev_tbl_off.checked_add(prev_tbl_len).unwrap();
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
