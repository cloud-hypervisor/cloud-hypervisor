// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
use std::sync::{Arc, Mutex};
use std::time::Instant;

use acpi_tables::Aml;
use acpi_tables::rsdp::Rsdp;
#[cfg(target_arch = "aarch64")]
use acpi_tables::sdt::GenericAddress;
use acpi_tables::sdt::Sdt;
#[cfg(target_arch = "aarch64")]
use arch::DeviceType;
use arch::NumaNodes;
#[cfg(target_arch = "aarch64")]
use arch::aarch64::DeviceInfoForFdt;
use bitflags::bitflags;
use log::info;
use pci::PciBdf;
use tracer::trace_scoped;
use vm_memory::{Address, Bytes, GuestAddress, GuestMemoryRegion};
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::cpu::CpuManager;
use crate::device_manager::DeviceManager;
use crate::memory_manager::MemoryManager;
use crate::pci_segment::PciSegment;
use crate::{GuestMemoryMmap, GuestRegionMmap};

/* Values for Type in APIC sub-headers */
#[cfg(target_arch = "x86_64")]
pub const ACPI_X2APIC_PROCESSOR: u8 = 9;
#[cfg(target_arch = "x86_64")]
pub const ACPI_APIC_IO: u8 = 1;
#[cfg(target_arch = "x86_64")]
pub const ACPI_APIC_XRUPT_OVERRIDE: u8 = 2;
#[cfg(target_arch = "aarch64")]
pub const ACPI_APIC_GENERIC_CPU_INTERFACE: u8 = 11;
#[cfg(target_arch = "aarch64")]
pub const ACPI_APIC_GENERIC_DISTRIBUTOR: u8 = 12;
#[cfg(target_arch = "aarch64")]
pub const ACPI_APIC_GIC_MSI_FRAME: u8 = 13;
#[cfg(target_arch = "aarch64")]
pub const ACPI_APIC_GENERIC_REDISTRIBUTOR: u8 = 14;
#[cfg(target_arch = "aarch64")]
pub const ACPI_APIC_GENERIC_TRANSLATOR: u8 = 15;
#[cfg(target_arch = "riscv64")]
pub const ACPI_RISC_V_IMSIC: u8 = 0x19;
#[cfg(target_arch = "riscv64")]
pub const ACPI_RISC_V_APLIC: u8 = 0x1A;

#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Default, IntoBytes, Immutable, FromBytes)]
struct PciRangeEntry {
    pub base_address: u64,
    pub segment: u16,
    pub start: u8,
    pub end: u8,
    _reserved: u32,
}

#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Default, IntoBytes, Immutable, FromBytes)]
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
#[repr(C, packed)]
#[derive(Default, IntoBytes, Immutable, FromBytes)]
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

#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Default, IntoBytes, Immutable, FromBytes)]
struct ProcessorGiccAffinity {
    pub type_: u8,
    pub length: u8,
    pub proximity_domain: u32,
    pub acpi_processor_uid: u32,
    pub flags: u32,
    pub clock_domain: u32,
}

bitflags! {
    #[derive(Copy, Clone)]
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
        Self::from_range(
            region.start_addr().raw_value(),
            region.len(),
            proximity_domain,
            flags,
        )
    }

    fn from_range(
        base_addr: u64,
        size: u64,
        proximity_domain: u32,
        flags: MemAffinityFlags,
    ) -> Self {
        let base_addr_lo = (base_addr & 0xffff_ffff) as u32;
        let base_addr_hi = (base_addr >> 32) as u32;
        let length_lo = (size & 0xffff_ffff) as u32;
        let length_hi = (size >> 32) as u32;

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
#[repr(C, packed)]
#[derive(Default, IntoBytes, Immutable, FromBytes)]
struct ViotVirtioPciNode {
    pub type_: u8,
    _reserved: u8,
    pub length: u16,
    pub pci_segment: u16,
    pub pci_bdf_number: u16,
    _reserved2: [u8; 8],
}

#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Default, IntoBytes, Immutable, FromBytes)]
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
    trace_scoped!("create_dsdt_table");
    // DSDT
    let mut dsdt = Sdt::new(*b"DSDT", 36, 6, *b"CLOUDH", *b"CHDSDT  ", 1);

    let mut bytes = Vec::new();

    device_manager.lock().unwrap().to_aml_bytes(&mut bytes);
    cpu_manager.lock().unwrap().to_aml_bytes(&mut bytes);
    memory_manager.lock().unwrap().to_aml_bytes(&mut bytes);
    dsdt.append_slice(&bytes);

    dsdt
}

const FACP_DSDT_OFFSET: usize = 140;

fn create_facp_table(dsdt_offset: GuestAddress, device_manager: &Arc<Mutex<DeviceManager>>) -> Sdt {
    trace_scoped!("create_facp_table");

    // Revision 6 of the ACPI FADT table is 276 bytes long
    let mut facp = Sdt::new(*b"FACP", 276, 6, *b"CLOUDH", *b"CHFACP  ", 1);

    {
        let device_manager = device_manager.lock().unwrap();
        if let Some(address) = device_manager.acpi_platform_addresses().reset_reg_address {
            // RESET_REG
            facp.write(116, address);
            // RESET_VALUE
            facp.write(128, 1u8);
        }

        if let Some(address) = device_manager
            .acpi_platform_addresses()
            .sleep_control_reg_address
        {
            // SLEEP_CONTROL_REG
            facp.write(244, address);
        }

        if let Some(address) = device_manager
            .acpi_platform_addresses()
            .sleep_status_reg_address
        {
            // SLEEP_STATUS_REG
            facp.write(256, address);
        }

        if let Some(address) = device_manager.acpi_platform_addresses().pm_timer_address {
            // X_PM_TMR_BLK
            facp.write(208, address);
        }
    }

    // aarch64 specific fields
    #[cfg(target_arch = "aarch64")]
    // ARM_BOOT_ARCH: enable PSCI with HVC enable-method
    facp.write(129, 3u16);

    // Architecture common fields
    // HW_REDUCED_ACPI, RESET_REG_SUP, TMR_VAL_EXT
    let fadt_flags: u32 = (1 << 20) | (1 << 10) | (1 << 8);
    facp.write(112, fadt_flags);
    // FADT minor version
    facp.write(131, 3u8);
    // X_DSDT
    facp.write(FACP_DSDT_OFFSET, dsdt_offset.0);
    // Hypervisor Vendor Identity
    facp.write_bytes(268, b"CLOUDHYP");

    facp.update_checksum();

    facp
}

fn create_mcfg_table(pci_segments: &[PciSegment]) -> Sdt {
    let mut mcfg = Sdt::new(*b"MCFG", 36, 1, *b"CLOUDH", *b"CHMCFG  ", 1);

    // MCFG reserved 8 bytes
    mcfg.append(0u64);

    for segment in pci_segments {
        // 32-bit PCI enhanced configuration mechanism
        mcfg.append(PciRangeEntry {
            base_address: segment.mmio_config_address,
            segment: segment.id,
            start: 0,
            end: 0,
            ..Default::default()
        });
    }
    mcfg
}

fn create_tpm2_table() -> Sdt {
    let mut tpm = Sdt::new(*b"TPM2", 52, 3, *b"CLOUDH", *b"CHTPM2  ", 1);

    tpm.write(36, 0_u16); //Platform Class
    tpm.write(38, 0_u16); // Reserved Space
    tpm.write(40, 0xfed4_0040_u64); // Address of Control Area
    tpm.write(48, 7_u32); //Start Method

    tpm.update_checksum();
    tpm
}

fn create_srat_table(
    numa_nodes: &NumaNodes,
    #[cfg(target_arch = "x86_64")] topology: Option<(u16, u16, u16, u16)>,
) -> Sdt {
    let mut srat = Sdt::new(*b"SRAT", 36, 3, *b"CLOUDH", *b"CHSRAT  ", 1);
    // SRAT reserved 12 bytes
    srat.append_slice(&[0u8; 12]);

    // Check the MemoryAffinity structure is the right size as expected by
    // the ACPI specification.
    assert_eq!(std::mem::size_of::<MemoryAffinity>(), 40);

    for (node_id, node) in numa_nodes.iter() {
        let proximity_domain = *node_id;

        for region in &node.memory_regions {
            srat.append(MemoryAffinity::from_region(
                region,
                proximity_domain,
                MemAffinityFlags::ENABLE,
            ));
        }

        for region in &node.hotplug_regions {
            srat.append(MemoryAffinity::from_region(
                region,
                proximity_domain,
                MemAffinityFlags::ENABLE | MemAffinityFlags::HOTPLUGGABLE,
            ));
        }

        for cpu in &node.cpus {
            #[cfg(target_arch = "x86_64")]
            let x2apic_id = arch::x86_64::get_x2apic_id(*cpu, topology);
            #[cfg(target_arch = "aarch64")]
            let x2apic_id = *cpu;

            // Flags
            // - Enabled = 1 (bit 0)
            // - Reserved bits 1-31
            let flags = 1;

            #[cfg(target_arch = "x86_64")]
            srat.append(ProcessorLocalX2ApicAffinity {
                type_: 2,
                length: 24,
                proximity_domain,
                x2apic_id,
                flags,
                clock_domain: 0,
                ..Default::default()
            });
            #[cfg(target_arch = "aarch64")]
            srat.append(ProcessorGiccAffinity {
                type_: 3,
                length: 18,
                proximity_domain,
                acpi_processor_uid: x2apic_id,
                flags,
                clock_domain: 0,
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
        let distances = &node.distances;
        for i in existing_nodes.iter() {
            let dist: u8 = if *node_id == *i {
                10
            } else if let Some(distance) = distances.get(i) {
                *distance
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
    gtdt.write(48, ARCH_TIMER_S_EL1_IRQ + 16);
    // Secure EL1 Timer Flags
    gtdt.write(52, irqflags);
    // Non-Secure EL1 Timer GSIV
    gtdt.write(56, ARCH_TIMER_NS_EL1_IRQ + 16);
    // Non-Secure EL1 Timer Flags
    gtdt.write(60, irqflags | ACPI_GTDT_CAP_ALWAYS_ON);
    // Virtual EL1 Timer GSIV
    gtdt.write(64, ARCH_TIMER_VIRT_IRQ + 16);
    // Virtual EL1 Timer Flags
    gtdt.write(68, irqflags);
    // EL2 Timer GSIV
    gtdt.write(72, ARCH_TIMER_NS_EL2_IRQ + 16);
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
    spcr.write(54, gsi.to_le());
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
fn create_dbg2_table(base_address: u64) -> Sdt {
    let namespace = "_SB_.COM1";
    let debug_device_info_offset = 44usize;
    let debug_device_info_len: u16 = 22 /* BaseAddressRegisterOffset */ +
                       12 /* BaseAddressRegister */ +
                       4 /* AddressSize */ +
                       namespace.len() as u16 + 1 /* zero-terminated */;
    let tbl_len: u32 = debug_device_info_offset as u32 + debug_device_info_len as u32;
    let mut dbg2 = Sdt::new(*b"DBG2", tbl_len, 0, *b"CLOUDH", *b"CHDBG2  ", 1);

    /* OffsetDbgDeviceInfo */
    dbg2.write_u32(36, 44);
    /* NumberDbgDeviceInfo */
    dbg2.write_u32(40, 1);

    /* Debug Device Information structure */
    /* Offsets are calculated from the start of this structure. */
    let namespace_offset = 38u16;
    let base_address_register_offset = 22u16;
    let address_size_offset = 34u16;
    /* Revision */
    dbg2.write_u8(debug_device_info_offset, 0);
    /* Length */
    dbg2.write_u16(debug_device_info_offset + 1, debug_device_info_len);
    /* NumberofGenericAddressRegisters */
    dbg2.write_u8(debug_device_info_offset + 3, 1);
    /* NameSpaceStringLength */
    dbg2.write_u16(debug_device_info_offset + 4, namespace.len() as u16 + 1);
    /* NameSpaceStringOffset */
    dbg2.write_u16(debug_device_info_offset + 6, namespace_offset);
    /* OemDataLength */
    dbg2.write_u16(debug_device_info_offset + 8, 0);
    /* OemDataOffset */
    dbg2.write_u16(debug_device_info_offset + 10, 0);
    /* Port Type */
    dbg2.write_u16(debug_device_info_offset + 12, 0x8000);
    /* Port Subtype */
    dbg2.write_u16(debug_device_info_offset + 14, 0x0003);
    /* Reserved */
    dbg2.write_u16(debug_device_info_offset + 16, 0);
    /* BaseAddressRegisterOffset */
    dbg2.write_u16(debug_device_info_offset + 18, base_address_register_offset);
    /* AddressSizeOffset */
    dbg2.write_u16(debug_device_info_offset + 20, address_size_offset);
    /* BaseAddressRegister */
    dbg2.write(
        debug_device_info_offset + base_address_register_offset as usize,
        GenericAddress::mmio_address::<u8>(base_address),
    );
    /* AddressSize */
    dbg2.write_u32(
        debug_device_info_offset + address_size_offset as usize,
        0x1000,
    );
    /* NamespaceString, zero-terminated ASCII */
    for (k, c) in namespace.chars().enumerate() {
        dbg2.write_u8(
            debug_device_info_offset + namespace_offset as usize + k,
            c as u8,
        );
    }
    dbg2.write_u8(
        debug_device_info_offset + namespace_offset as usize + namespace.len(),
        0,
    );

    dbg2.update_checksum();

    dbg2
}

#[cfg(target_arch = "aarch64")]
#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Default, IntoBytes, Immutable, FromBytes)]
struct IortBodyBase {
    pub num_nodes: u32,
    pub offset_first_node: u32,
    _reserved: u32,
}

#[cfg(target_arch = "aarch64")]
#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Default, IntoBytes, Immutable, FromBytes)]
struct IortNodeCommon {
    pub type_: u8,
    pub length: u16,
    pub revision: u8,
    pub node_id: u32,
    pub num_id_mappings: u32,
    pub id_mappings_array_offset: u32,
}

#[cfg(target_arch = "aarch64")]
#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Default, IntoBytes, Immutable, FromBytes)]
struct IortIdMapping {
    pub input_base: u32,
    pub num_ids: u32,
    pub output_base: u32,
    pub output_reference: u32,
    pub flags: u32,
}

#[cfg(target_arch = "aarch64")]
#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Default, IntoBytes, Immutable, FromBytes)]
struct IortMemoryAccessProperties {
    pub cca: u32,
    pub ah: u8,
    _reserved: u16,
    pub maf: u8,
}

#[cfg(target_arch = "aarch64")]
#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Default, IntoBytes, Immutable, FromBytes)]
struct IortItsGroupBase {
    pub common: IortNodeCommon,
    pub its_count: u32,
    // GIC ITS identifiers follow: array of `u32`
}

#[cfg(target_arch = "aarch64")]
#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Default, IntoBytes, Immutable, FromBytes)]
struct IortPciRootComplexBase {
    pub common: IortNodeCommon,
    pub mem_access_props: IortMemoryAccessProperties,
    pub ats_attribute: u32,
    pub pci_segment_number: u32,
    pub memory_address_size_limit: u8,
    _reserved: [u8; 3],
    // ID mappings follow: array of `struct IortIdMapping`
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn align_to_8_bytes(len: usize) -> usize {
    (8 - (len % 8)) % 8
}

#[cfg(target_arch = "aarch64")]
// Generate IORT table based on Spec Revision E.b:
// https://developer.arm.com/documentation/den0049/eb/?lang=en
fn create_iort_table(pci_segments: &[PciSegment]) -> Sdt {
    const ACPI_IORT_HEADER_SIZE: u32 = 36;
    const ACPI_IORT_REVISION: u8 = 3;
    const ACPI_IORT_NODE_ITS_GROUP: u8 = 0x00;
    const ACPI_IORT_NODE_PCI_ROOT_COMPLEX: u8 = 0x02;

    // IORT header
    let mut iort = Sdt::new(
        *b"IORT",
        ACPI_IORT_HEADER_SIZE,
        ACPI_IORT_REVISION,
        *b"CLOUDH",
        *b"CHIORT  ",
        1,
    );
    assert_eq!(iort.len(), ACPI_IORT_HEADER_SIZE as usize);

    // The IORT table contains:
    // - IortBodyBase
    // - 1 x ITS Group Node
    // - N x PCI Root Complex Node (N = number of pci segments)
    let num_nodes = (1 + pci_segments.len()) as u32;
    // First node is the ITS Group Node located right after the IORT Body Base
    let offset_its_node = iort.len() + std::mem::size_of::<IortBodyBase>();
    assert!(align_to_8_bytes(offset_its_node) == 0); // Ensure the ITS node is 8-byte aligned
    iort.append(IortBodyBase {
        num_nodes,
        offset_first_node: offset_its_node as u32,
        _reserved: 0,
    });
    assert!(iort.len() == offset_its_node);

    // ITS Group Node contains:
    // - IortItsGroupBase
    // - ITS Identifiers Array: Array of u32 ITS IDs
    //   Currently contains a single ITS with ID 0, which matches the
    //   `translation_id` field of the `GisIts`` structure in the MADT table.
    let its_id_array = [0u32; 1];
    let its_count = its_id_array.len();
    let its_group_node_size =
        std::mem::size_of::<IortItsGroupBase>() + its_count * std::mem::size_of::<u32>();
    let padding = align_to_8_bytes(iort.len() + its_group_node_size);
    iort.append(IortItsGroupBase {
        common: IortNodeCommon {
            type_: ACPI_IORT_NODE_ITS_GROUP,
            length: (its_group_node_size + padding) as u16,
            revision: 1,
            node_id: 0, // todo
            num_id_mappings: 0,
            id_mappings_array_offset: 0,
        },
        its_count: its_count as u32,
    });
    iort.append(its_id_array);
    iort.append_slice(&vec![0u8; padding]); // Add padding to align to 8 bytes

    // Create PCI Root Complex Node for each PCI segment
    for segment in pci_segments.iter() {
        assert!(align_to_8_bytes(iort.len()) == 0); // Ensure each node is 8-byte aligned

        // Each PCI Root Complex Node contains:
        // - IortPciRootComplexBase
        // - ID mapping Array: Array of IortIdMapping
        //   Currently contains a single mapping that maps all device IDs
        //   in the segment to the ITS Group Node.
        let num_id_mappings = 1;
        let node_size = std::mem::size_of::<IortPciRootComplexBase>()
            + num_id_mappings * std::mem::size_of::<IortIdMapping>();
        let padding = align_to_8_bytes(iort.len() + node_size);
        iort.append(IortPciRootComplexBase {
            common: IortNodeCommon {
                type_: ACPI_IORT_NODE_PCI_ROOT_COMPLEX,
                length: (node_size + padding) as u16,
                revision: 3,
                node_id: segment.id as u32, // todo to avoid conflict with ITS node IDs
                num_id_mappings: num_id_mappings as u32,
                // ID mapping array starts right after `IortPciRootComplexBase`
                id_mappings_array_offset: std::mem::size_of::<IortPciRootComplexBase>() as u32,
            },
            mem_access_props: IortMemoryAccessProperties {
                cca: 1, // Fully coherent device
                ah: 0,
                _reserved: 0,
                maf: 3, // CPM = DCAS = 1
            },
            ats_attribute: 0,
            pci_segment_number: segment.id as u32,
            memory_address_size_limit: 64u8,
            _reserved: [0; 3],
        });
        // ID Mapping for this Root Complex
        // Maps 256 device IDs (1 bus × 32 devices × 8 functions)
        assert!(segment.id < 256, "Up to 256 PCI segments are supported.");
        iort.append(IortIdMapping {
            input_base: 0,
            // The number of IDs in the range minus one:
            // This should cover all the devices of a segment:
            // 1 (bus) x 32 (devices) x 8 (functions) = 256
            // Note: Currently only 1 bus is supported in a segment.
            num_ids: 255,
            // Output base maps to ITS device IDs which must match the
            // device ID encoding used in KVM MSI routing setup, which
            // shares the same limitation - only 1 bus per segment and
            // up to 256 segments.
            // See: https://github.com/cloud-hypervisor/cloud-hypervisor/commit/c9374d87ac453d49185aa7b734df089444166484
            output_base: (256 * segment.id) as u32,
            // Output reference node is the ITS group node as there is no SMMU node
            output_reference: offset_its_node as u32,
            flags: 0,
        });
        iort.append_slice(&vec![0u8; padding]); // Add padding to align to 8 bytes
    }

    iort.update_checksum();

    iort
}

fn create_viot_table(iommu_bdf: &PciBdf, devices_bdf: &[PciBdf]) -> Sdt {
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
        pci_segment: iommu_bdf.segment(),
        pci_bdf_number: iommu_bdf.into(),
        ..Default::default()
    });

    for device_bdf in devices_bdf {
        viot.append(ViotPciRangeNode {
            type_: 1,
            length: 24,
            endpoint_start: device_bdf.into(),
            pci_segment_start: device_bdf.segment(),
            pci_segment_end: device_bdf.segment(),
            pci_bdf_start: device_bdf.into(),
            pci_bdf_end: device_bdf.into(),
            output_node: 48,
            ..Default::default()
        });
    }

    viot
}

// Generate ACPI tables based on the given DSDT address
//
// # Returns
//
// * `Rsdp` is the generated RSDP.
// * `Vec<u8>` contains the generated bytes for ACPI tables.
// * `Vec<u64>` contains a list of table pointers stored in XSDT.
fn create_acpi_tables_internal(
    dsdt_addr: GuestAddress,
    device_manager: &Arc<Mutex<DeviceManager>>,
    cpu_manager: &Arc<Mutex<CpuManager>>,
    memory_manager: &Arc<Mutex<MemoryManager>>,
    numa_nodes: &NumaNodes,
    tpm_enabled: bool,
) -> (Rsdp, Vec<u8>, Vec<u64>) {
    // Generated bytes for ACPI tables
    let mut tables_bytes: Vec<u8> = Vec::new();
    // List of table pointers stored in XSDT
    let mut xsdt_table_pointers: Vec<u64> = Vec::new();

    // DSDT
    let dsdt = create_dsdt_table(device_manager, cpu_manager, memory_manager);
    tables_bytes.extend_from_slice(dsdt.as_slice());

    // FACP aka FADT
    let facp = create_facp_table(dsdt_addr, device_manager);
    let facp_addr = dsdt_addr.checked_add(dsdt.len() as u64).unwrap();
    tables_bytes.extend_from_slice(facp.as_slice());
    xsdt_table_pointers.push(facp_addr.0);

    // MADT
    #[cfg(target_arch = "aarch64")]
    let vgic = device_manager
        .lock()
        .unwrap()
        .get_interrupt_controller()
        .unwrap()
        .lock()
        .unwrap()
        .get_vgic()
        .unwrap();
    let madt = cpu_manager.lock().unwrap().create_madt(
        #[cfg(target_arch = "aarch64")]
        vgic,
    );
    let madt_addr = facp_addr.checked_add(facp.len() as u64).unwrap();
    tables_bytes.extend_from_slice(madt.as_slice());
    xsdt_table_pointers.push(madt_addr.0);
    let mut prev_tbl_len = madt.len() as u64;
    let mut prev_tbl_addr = madt_addr;

    // PPTT
    #[cfg(target_arch = "aarch64")]
    {
        let pptt = cpu_manager.lock().unwrap().create_pptt();
        let pptt_addr = prev_tbl_addr.checked_add(prev_tbl_len).unwrap();
        tables_bytes.extend_from_slice(pptt.as_slice());
        xsdt_table_pointers.push(pptt_addr.0);
        prev_tbl_len = pptt.len() as u64;
        prev_tbl_addr = pptt_addr;
    }

    // GTDT
    #[cfg(target_arch = "aarch64")]
    {
        let gtdt = create_gtdt_table();
        let gtdt_addr = prev_tbl_addr.checked_add(prev_tbl_len).unwrap();
        tables_bytes.extend_from_slice(gtdt.as_slice());
        xsdt_table_pointers.push(gtdt_addr.0);
        prev_tbl_len = gtdt.len() as u64;
        prev_tbl_addr = gtdt_addr;
    }

    // MCFG
    let mcfg = create_mcfg_table(device_manager.lock().unwrap().pci_segments());
    let mcfg_addr = prev_tbl_addr.checked_add(prev_tbl_len).unwrap();
    tables_bytes.extend_from_slice(mcfg.as_slice());
    xsdt_table_pointers.push(mcfg_addr.0);
    prev_tbl_len = mcfg.len() as u64;
    prev_tbl_addr = mcfg_addr;

    // SPCR and DBG2
    #[cfg(target_arch = "aarch64")]
    {
        let is_serial_on = device_manager
            .lock()
            .unwrap()
            .get_device_info()
            .clone()
            .contains_key(&(DeviceType::Serial, DeviceType::Serial.to_string()));
        let serial_device_addr = arch::layout::LEGACY_SERIAL_MAPPED_IO_START.raw_value();
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

        // SPCR
        let spcr = create_spcr_table(serial_device_addr, serial_device_irq);
        let spcr_addr = prev_tbl_addr.checked_add(prev_tbl_len).unwrap();
        tables_bytes.extend_from_slice(spcr.as_slice());
        xsdt_table_pointers.push(spcr_addr.0);
        prev_tbl_len = spcr.len() as u64;
        prev_tbl_addr = spcr_addr;

        // DBG2
        let dbg2 = create_dbg2_table(serial_device_addr);
        let dbg2_addr = prev_tbl_addr.checked_add(prev_tbl_len).unwrap();
        tables_bytes.extend_from_slice(dbg2.as_slice());
        xsdt_table_pointers.push(dbg2_addr.0);
        prev_tbl_len = dbg2.len() as u64;
        prev_tbl_addr = dbg2_addr;
    }

    if tpm_enabled {
        // TPM2 Table
        let tpm2 = create_tpm2_table();
        let tpm2_addr = prev_tbl_addr.checked_add(prev_tbl_len).unwrap();
        tables_bytes.extend_from_slice(tpm2.as_slice());
        xsdt_table_pointers.push(tpm2_addr.0);

        prev_tbl_len = tpm2.len() as u64;
        prev_tbl_addr = tpm2_addr;
    }
    // SRAT and SLIT
    // Only created if the NUMA nodes list is not empty.
    if !numa_nodes.is_empty() {
        #[cfg(target_arch = "x86_64")]
        let topology = cpu_manager.lock().unwrap().get_vcpu_topology();
        // SRAT
        let srat = create_srat_table(
            numa_nodes,
            #[cfg(target_arch = "x86_64")]
            topology,
        );
        let srat_addr = prev_tbl_addr.checked_add(prev_tbl_len).unwrap();
        tables_bytes.extend_from_slice(srat.as_slice());
        xsdt_table_pointers.push(srat_addr.0);

        // SLIT
        let slit = create_slit_table(numa_nodes);
        let slit_addr = srat_addr.checked_add(srat.len() as u64).unwrap();
        tables_bytes.extend_from_slice(slit.as_slice());
        xsdt_table_pointers.push(slit_addr.0);

        prev_tbl_len = slit.len() as u64;
        prev_tbl_addr = slit_addr;
    }

    #[cfg(target_arch = "aarch64")]
    {
        let iort = create_iort_table(device_manager.lock().unwrap().pci_segments());
        let iort_addr = prev_tbl_addr.checked_add(prev_tbl_len).unwrap();
        tables_bytes.extend_from_slice(iort.as_slice());
        xsdt_table_pointers.push(iort_addr.0);
        prev_tbl_len = iort.len() as u64;
        prev_tbl_addr = iort_addr;
    }

    // VIOT
    if let Some((iommu_bdf, devices_bdf)) = device_manager.lock().unwrap().iommu_attached_devices()
    {
        let viot = create_viot_table(iommu_bdf, devices_bdf);

        let viot_addr = prev_tbl_addr.checked_add(prev_tbl_len).unwrap();
        tables_bytes.extend_from_slice(viot.as_slice());
        xsdt_table_pointers.push(viot_addr.0);
        prev_tbl_len = viot.len() as u64;
        prev_tbl_addr = viot_addr;
    }

    // XSDT
    let mut xsdt = Sdt::new(*b"XSDT", 36, 1, *b"CLOUDH", *b"CHXSDT  ", 1);
    for table_pointer in &xsdt_table_pointers {
        xsdt.append(*table_pointer);
    }
    xsdt.update_checksum();
    let xsdt_addr = prev_tbl_addr.checked_add(prev_tbl_len).unwrap();
    tables_bytes.extend_from_slice(xsdt.as_slice());

    // RSDP
    let rsdp = Rsdp::new(*b"CLOUDH", xsdt_addr.0);

    (rsdp, tables_bytes, xsdt_table_pointers)
}

#[cfg(feature = "fw_cfg")]
pub fn create_acpi_tables_for_fw_cfg(
    device_manager: &Arc<Mutex<DeviceManager>>,
    cpu_manager: &Arc<Mutex<CpuManager>>,
    memory_manager: &Arc<Mutex<MemoryManager>>,
    numa_nodes: &NumaNodes,
    tpm_enabled: bool,
) -> Result<(), crate::vm::Error> {
    let dsdt_offset = GuestAddress(0);
    let (rsdp, table_bytes, xsdt_table_pointers) = create_acpi_tables_internal(
        dsdt_offset,
        device_manager,
        cpu_manager,
        memory_manager,
        numa_nodes,
        tpm_enabled,
    );
    let mut pointer_offsets: Vec<usize> = vec![];
    let mut checksums: Vec<(usize, usize)> = vec![];

    let xsdt_addr = rsdp.xsdt_addr.get() as usize;
    let xsdt_checksum = (xsdt_addr, table_bytes.len() - xsdt_addr);

    // create pointer offsets (use location of pointers in XSDT table)
    // XSDT doesn't have a pointer to DSDT so we use FACP's pointer to DSDT
    let facp_offset = xsdt_table_pointers[0] as usize;
    pointer_offsets.push(facp_offset + FACP_DSDT_OFFSET);
    let mut current_offset = xsdt_addr + 36;
    for _ in 0..xsdt_table_pointers.len() {
        pointer_offsets.push(current_offset);
        current_offset += 8;
    }

    // create (offset, len) pairs for firmware to calculate
    // table checksums and verify ACPI tables
    let mut i = 0;
    while i < xsdt_table_pointers.len() - 1 {
        let current_table_offset = xsdt_table_pointers[i];
        let current_table_length = xsdt_table_pointers[i + 1] - current_table_offset;
        checksums.push((current_table_offset as usize, current_table_length as usize));
        i += 1;
    }
    checksums.push((
        xsdt_table_pointers[xsdt_table_pointers.len() - 1] as usize,
        0,
    ));
    checksums.push(xsdt_checksum);

    device_manager
        .lock()
        .unwrap()
        .fw_cfg()
        .expect("fw_cfg must be present")
        .lock()
        .unwrap()
        .add_acpi(rsdp, table_bytes, checksums, pointer_offsets)
        .map_err(crate::vm::Error::CreatingAcpiTables)
}

pub fn create_acpi_tables(
    guest_mem: &GuestMemoryMmap,
    device_manager: &Arc<Mutex<DeviceManager>>,
    cpu_manager: &Arc<Mutex<CpuManager>>,
    memory_manager: &Arc<Mutex<MemoryManager>>,
    numa_nodes: &NumaNodes,
    tpm_enabled: bool,
) -> GuestAddress {
    trace_scoped!("create_acpi_tables");

    let start_time = Instant::now();
    let rsdp_addr = arch::layout::RSDP_POINTER;
    let dsdt_addr = rsdp_addr.checked_add(Rsdp::len() as u64).unwrap();

    let (rsdp, tables_bytes, _xsdt_table_pointers) = create_acpi_tables_internal(
        dsdt_addr,
        device_manager,
        cpu_manager,
        memory_manager,
        numa_nodes,
        tpm_enabled,
    );

    guest_mem
        .write_slice(rsdp.as_bytes(), rsdp_addr)
        .expect("Error writing RSDP");

    guest_mem
        .write_slice(tables_bytes.as_slice(), dsdt_addr)
        .expect("Error writing ACPI tables");

    info!(
        "Generated ACPI tables: took {}µs size = {}",
        Instant::now().duration_since(start_time).as_micros(),
        Rsdp::len() + tables_bytes.len(),
    );

    rsdp_addr
}

#[cfg(feature = "tdx")]
pub fn create_acpi_tables_tdx(
    device_manager: &Arc<Mutex<DeviceManager>>,
    cpu_manager: &Arc<Mutex<CpuManager>>,
    memory_manager: &Arc<Mutex<MemoryManager>>,
    numa_nodes: &NumaNodes,
) -> Vec<Sdt> {
    // DSDT
    let mut tables = vec![create_dsdt_table(
        device_manager,
        cpu_manager,
        memory_manager,
    )];

    // FACP aka FADT
    tables.push(create_facp_table(GuestAddress(0), device_manager));

    // MADT
    tables.push(cpu_manager.lock().unwrap().create_madt());

    // MCFG
    tables.push(create_mcfg_table(
        device_manager.lock().unwrap().pci_segments(),
    ));

    // SRAT and SLIT
    // Only created if the NUMA nodes list is not empty.
    if !numa_nodes.is_empty() {
        #[cfg(target_arch = "x86_64")]
        let topology = cpu_manager.lock().unwrap().get_vcpu_topology();

        // SRAT
        tables.push(create_srat_table(
            numa_nodes,
            #[cfg(target_arch = "x86_64")]
            topology,
        ));

        // SLIT
        tables.push(create_slit_table(numa_nodes));
    }

    // VIOT
    if let Some((iommu_bdf, devices_bdf)) = device_manager.lock().unwrap().iommu_attached_devices()
    {
        tables.push(create_viot_table(iommu_bdf, devices_bdf));
    }

    tables
}
