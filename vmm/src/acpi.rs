// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
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
use log::{info, warn};
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

// ACPI 6.6 Section 5.2.16.6 - Generic Initiator Affinity Structure
// Associates devices (e.g., GPUs, NVMe, accelerators) with NUMA proximity domains
//
// Device Handle Type values per ACPI 6.6 spec:
//   0 = ACPI device handle (uses HID and UID)
//   1 = PCI device handle (uses Segment and BDF)
//
// Note: Some older Linux kernel versions may incorrectly expect
// device_handle_type=0 for PCI devices.
#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Default, IntoBytes, Immutable, FromBytes)]
struct GenericInitiatorAffinity {
    pub type_: u8,
    pub length: u8,
    _reserved1: u8,
    pub device_handle_type: u8,
    pub proximity_domain: u32,
    pub device_handle: [u8; 16],
    pub flags: u32,
    _reserved2: u32,
}

impl GenericInitiatorAffinity {
    #[allow(dead_code)]
    fn from_acpi_device(hid: u64, uid: u32, proximity_domain: u32) -> Self {
        let mut device_handle = [0u8; 16];
        // ACPI 6.6 Table 5-66: ACPI device handle
        // Bytes 0-7: Hardware ID (HID) as 64-bit value
        // Bytes 8-11: Unique ID (UID) as 32-bit value
        device_handle[0..8].copy_from_slice(&hid.to_le_bytes());
        device_handle[8..12].copy_from_slice(&uid.to_le_bytes());
        // Bytes 12-15: Reserved
        GenericInitiatorAffinity {
            type_: 5,
            length: 32,
            _reserved1: 0,
            device_handle_type: 0, // 0 = ACPI
            proximity_domain,
            device_handle,
            flags: 1,
            _reserved2: 0,
        }
    }

    fn from_pci_bdf(bdf: PciBdf, proximity_domain: u32) -> Self {
        let mut device_handle = [0u8; 16];
        let segment = bdf.segment();
        let bus = bdf.bus();
        let device = bdf.device();
        let function = bdf.function();

        // ACPI 6.6 Table 5-66: PCI Device Handle
        device_handle[0] = (segment & 0xff) as u8;
        device_handle[1] = ((segment >> 8) & 0xff) as u8;
        device_handle[2] = bus;
        device_handle[3] = bus;
        device_handle[4] = device;
        device_handle[5] = device;
        device_handle[6] = function;
        device_handle[7] = function;
        // Bytes 8-15 remain 0 (Reserved)

        GenericInitiatorAffinity {
            type_: 5,
            length: 32,
            _reserved1: 0,
            device_handle_type: 1, // 1 = PCI
            proximity_domain,
            device_handle,
            flags: 1,
            _reserved2: 0,
        }
    }
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
        region: &GuestRegionMmap,
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
    device_manager: &DeviceManager,
    cpu_manager: &CpuManager,
    memory_manager: &MemoryManager,
) -> Sdt {
    trace_scoped!("create_dsdt_table");
    // DSDT
    let mut dsdt = Sdt::new(*b"DSDT", 36, 6, *b"CLOUDH", *b"CHDSDT  ", 1);

    let mut bytes = Vec::new();

    device_manager.to_aml_bytes(&mut bytes);
    cpu_manager.to_aml_bytes(&mut bytes);
    memory_manager.to_aml_bytes(&mut bytes);
    dsdt.append_slice(&bytes);

    dsdt
}

const FACP_DSDT_OFFSET: usize = 140;

fn create_facp_table(dsdt_offset: GuestAddress, device_manager: &DeviceManager) -> Sdt {
    trace_scoped!("create_facp_table");

    // Revision 6 of the ACPI FADT table is 276 bytes long
    let mut facp = Sdt::new(*b"FACP", 276, 6, *b"CLOUDH", *b"CHFACP  ", 1);

    {
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
    device_manager: &DeviceManager,
    #[cfg(target_arch = "x86_64")] topology: Option<(u16, u16, u16, u16)>,
) -> Sdt {
    let mut srat = Sdt::new(*b"SRAT", 36, 3, *b"CLOUDH", *b"CHSRAT  ", 1);
    // SRAT reserved 12 bytes
    srat.append_slice(&[0u8; 12]);

    // Check the MemoryAffinity structure is the right size as expected by
    // the ACPI specification.
    assert_eq!(std::mem::size_of::<MemoryAffinity>(), 40);
    // Confirm struct size matches ACPI 6.6 spec
    assert_eq!(std::mem::size_of::<GenericInitiatorAffinity>(), 32);
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

        // Add Generic Initiator Affinity structures for device-only NUMA nodes
        if let Some(device_id) = &node.device_id {
            // Resolve device_id to guest BDF
            if let Some(bdf) = device_manager.get_device_bdf(device_id) {
                srat.append(GenericInitiatorAffinity::from_pci_bdf(
                    bdf,
                    proximity_domain,
                ));
            } else {
                warn!("Generic Initiator: device_id '{device_id}' not found in device manager");
            }
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
            // When forward distance config is missing
            // we can derive it using distance symmetry
            } else if let Some(destination) = numa_nodes.get(i) {
                destination.distances.get(node_id).copied().unwrap_or(20)
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
    device_manager: &DeviceManager,
    cpu_manager: &CpuManager,
    memory_manager: &MemoryManager,
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
        .get_interrupt_controller()
        .unwrap()
        .lock()
        .unwrap()
        .get_vgic()
        .unwrap();
    let madt = cpu_manager.create_madt(
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
        let pptt = cpu_manager.create_pptt();
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
    let mcfg = create_mcfg_table(device_manager.pci_segments());
    let mcfg_addr = prev_tbl_addr.checked_add(prev_tbl_len).unwrap();
    tables_bytes.extend_from_slice(mcfg.as_slice());
    xsdt_table_pointers.push(mcfg_addr.0);
    prev_tbl_len = mcfg.len() as u64;
    prev_tbl_addr = mcfg_addr;

    // SPCR and DBG2
    #[cfg(target_arch = "aarch64")]
    {
        let is_serial_on = device_manager
            .get_device_info()
            .clone()
            .contains_key(&(DeviceType::Serial, DeviceType::Serial.to_string()));
        let serial_device_addr = arch::layout::LEGACY_SERIAL_MAPPED_IO_START.raw_value();
        let serial_device_irq = if is_serial_on {
            device_manager
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
        let topology = cpu_manager.get_vcpu_topology();
        // SRAT
        let srat = create_srat_table(
            numa_nodes,
            device_manager,
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
        let iort = create_iort_table(device_manager.pci_segments());
        let iort_addr = prev_tbl_addr.checked_add(prev_tbl_len).unwrap();
        tables_bytes.extend_from_slice(iort.as_slice());
        xsdt_table_pointers.push(iort_addr.0);
        prev_tbl_len = iort.len() as u64;
        prev_tbl_addr = iort_addr;
    }

    // VIOT
    if let Some((iommu_bdf, devices_bdf)) = device_manager.iommu_attached_devices() {
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
    device_manager: &DeviceManager,
    cpu_manager: &CpuManager,
    memory_manager: &MemoryManager,
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
        .fw_cfg()
        .expect("fw_cfg must be present")
        .lock()
        .unwrap()
        .add_acpi(rsdp, table_bytes, checksums, pointer_offsets)
        .map_err(crate::vm::Error::CreatingAcpiTables)
}

pub fn create_acpi_tables(
    guest_mem: &GuestMemoryMmap,
    device_manager: &DeviceManager,
    cpu_manager: &CpuManager,
    memory_manager: &MemoryManager,
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
    device_manager: &DeviceManager,
    cpu_manager: &CpuManager,
    memory_manager: &MemoryManager,
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
    tables.push(cpu_manager.create_madt());

    // MCFG
    tables.push(create_mcfg_table(device_manager.pci_segments()));

    // SRAT and SLIT
    // Only created if the NUMA nodes list is not empty.
    if !numa_nodes.is_empty() {
        #[cfg(target_arch = "x86_64")]
        let topology = cpu_manager.get_vcpu_topology();

        // SRAT
        tables.push(create_srat_table(
            numa_nodes,
            device_manager,
            #[cfg(target_arch = "x86_64")]
            topology,
        ));

        // SLIT
        tables.push(create_slit_table(numa_nodes));
    }

    // VIOT
    if let Some((iommu_bdf, devices_bdf)) = device_manager.iommu_attached_devices() {
        tables.push(create_viot_table(iommu_bdf, devices_bdf));
    }

    tables
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generic_initiator_affinity_size() {
        // ACPI spec requires Generic Initiator Affinity Structure to be exactly 32 bytes
        assert_eq!(
            std::mem::size_of::<GenericInitiatorAffinity>(),
            32,
            "GenericInitiatorAffinity must be exactly 32 bytes per ACPI 6.6 spec"
        );
    }

    #[test]
    fn test_generic_initiator_from_pci_bdf() {
        // Test creating Generic Initiator from PCI BDF
        // segment:bus:device:function = 0000:00:05.0
        let bdf = PciBdf::new(0, 0, 5, 0);
        let proximity_domain = 1;

        let gi = GenericInitiatorAffinity::from_pci_bdf(bdf, proximity_domain);

        // Verify structure fields
        assert_eq!(gi.type_, 5, "Type must be 5 for Generic Initiator");
        assert_eq!(gi.length, 32, "Length must be 32 bytes");
        assert_eq!(gi._reserved1, 0, "Reserved field must be 0");
        assert_eq!(
            gi.device_handle_type, 1,
            "Device handle type must be 1 for PCI per ACPI 6.6 spec"
        );
        // Copy packed fields to local variables to avoid unaligned references
        let gi_proximity_domain = gi.proximity_domain;
        let gi_flags = gi.flags;
        let gi_reserved2 = gi._reserved2;
        assert_eq!(
            gi_proximity_domain, proximity_domain,
            "Proximity domain must match input"
        );
        assert_eq!(gi_flags, 1, "Flags must be 1 (enabled)");
        assert_eq!(gi_reserved2, 0, "Reserved field must be 0");

        // Verify PCI BDF encoding in device_handle
        // ACPI 6.6 Table 5-66 format:
        // Bytes 0-1: PCI Segment (little-endian)
        // Byte 2: Start Bus Number
        // Byte 3: End Bus Number
        // Byte 4: Start Device Number
        // Byte 5: End Device Number
        // Byte 6: Start Function
        // Byte 7: End Function
        // Bytes 8-15: Reserved
        let expected_handle: [u8; 16] = [
            0, 0, 0, 0, 5, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Reserved
        ];
        assert_eq!(
            gi.device_handle, expected_handle,
            "Device handle must encode PCI BDF correctly per ACPI 6.6 Table 5-66"
        );
    }

    #[test]
    fn test_generic_initiator_multiple_numa_nodes() {
        // Test Generic Initiators assigned to different NUMA nodes
        let bdf0 = PciBdf::new(0, 0, 4, 0);
        let bdf1 = PciBdf::new(0, 0, 5, 0);

        let gi0 = GenericInitiatorAffinity::from_pci_bdf(bdf0, 0);
        let gi1 = GenericInitiatorAffinity::from_pci_bdf(bdf1, 1);

        // Copy packed fields to local variables to avoid unaligned references
        let gi0_proximity_domain = gi0.proximity_domain;
        let gi1_proximity_domain = gi1.proximity_domain;
        assert_eq!(gi0_proximity_domain, 0);
        assert_eq!(gi1_proximity_domain, 1);

        // Verify both have correct type and length
        assert_eq!(gi0.type_, 5);
        assert_eq!(gi0.length, 32);
        assert_eq!(gi1.type_, 5);
        assert_eq!(gi1.length, 32);
    }

    #[test]
    fn test_generic_initiator_repr_c_layout() {
        // Verify the struct has correct C representation for ACPI table
        // This ensures field offsets match ACPI spec
        let gi = GenericInitiatorAffinity {
            type_: 5,
            length: 32,
            _reserved1: 0,
            device_handle_type: 1,
            proximity_domain: 1,
            device_handle: [0u8; 16],
            flags: 1,
            _reserved2: 0,
        };

        // Convert to bytes and verify layout
        // SAFETY: `gi` is a local, initialized struct. Because it is `repr(packed)`,
        // there is no internal padding, making every byte within it
        // safe to read. Casting to `u8` satisfies alignment requirements.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &gi as *const GenericInitiatorAffinity as *const u8,
                std::mem::size_of::<GenericInitiatorAffinity>(),
            )
        };

        // Verify field positions per ACPI 6.6 spec
        assert_eq!(bytes[0], 5, "Offset 0: Type");
        assert_eq!(bytes[1], 32, "Offset 1: Length");
        assert_eq!(bytes[2], 0, "Offset 2: Reserved");
        assert_eq!(bytes[3], 1, "Offset 3: Device Handle Type (1=PCI per spec)");
        // Proximity domain at offset 4-7 (u32 little-endian)
        assert_eq!(bytes[4], 1);
        assert_eq!(bytes[5], 0);
        assert_eq!(bytes[6], 0);
        assert_eq!(bytes[7], 0);
        // Device handle at offset 8-23 (16 bytes)
        // Flags at offset 24-27 (u32 little-endian)
        assert_eq!(bytes[24], 1);
        // Reserved at offset 28-31
    }

    #[test]
    fn test_generic_initiator_acpi_device_handle() {
        // Test ACPI device handle (device_handle_type=0) for completeness
        // This validates HID and UID encoding per ACPI 6.6 spec (Table 5.65)
        let hid: u64 = 0x0123456789ABCDEF;
        let uid: u32 = 0x12345678;
        let proximity_domain = 2;

        let gi = GenericInitiatorAffinity::from_acpi_device(hid, uid, proximity_domain);

        // Verify structure fields
        assert_eq!(gi.type_, 5, "Type must be 5 for Generic Initiator");
        assert_eq!(gi.length, 32, "Length must be 32 bytes");
        assert_eq!(gi._reserved1, 0, "Reserved field must be 0");
        assert_eq!(
            gi.device_handle_type, 0,
            "Device handle type must be 0 for ACPI per ACPI 6.6 spec"
        );
        // Copy packed fields to local variables to avoid unaligned references
        let gi_proximity_domain = gi.proximity_domain;
        let gi_flags = gi.flags;
        let gi_reserved2 = gi._reserved2;
        assert_eq!(
            gi_proximity_domain, proximity_domain,
            "Proximity domain must match input"
        );
        assert_eq!(gi_flags, 1, "Flags must be 1 (enabled)");
        assert_eq!(gi_reserved2, 0, "Reserved field must be 0");

        // Verify ACPI device handle encoding
        // Expected format per ACPI 6.6 Table 5.65:
        // Bytes 0-7: HID (64-bit, little-endian)
        // Bytes 8-11: UID (32-bit, little-endian)
        // Bytes 12-15: Reserved
        let expected_handle: [u8; 16] = [
            0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01, // HID
            0x78, 0x56, 0x34, 0x12, // UID
            0, 0, 0, 0, // Reserved
        ];
        assert_eq!(
            gi.device_handle, expected_handle,
            "Device handle must encode HID and UID correctly"
        );
    }
}
