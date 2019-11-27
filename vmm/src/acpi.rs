// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
use acpi_tables::{
    aml,
    aml::Aml,
    rsdp::RSDP,
    sdt::{GenericAddress, SDT},
};
use vm_memory::{GuestAddress, GuestMemoryMmap};

use vm_memory::{Address, ByteValued, Bytes};

use std::convert::TryInto;

use arch::layout;

#[repr(packed)]
struct LocalAPIC {
    pub r#type: u8,
    pub length: u8,
    pub processor_id: u8,
    pub apic_id: u8,
    pub flags: u32,
}

#[repr(packed)]
#[derive(Default)]
struct IOAPIC {
    pub r#type: u8,
    pub length: u8,
    pub ioapic_id: u8,
    _reserved: u8,
    pub apic_address: u32,
    pub gsi_base: u32,
}

#[repr(packed)]
#[derive(Default)]
struct InterruptSourceOverride {
    pub r#type: u8,
    pub length: u8,
    pub bus: u8,
    pub source: u8,
    pub gsi: u32,
    pub flags: u16,
}

#[repr(packed)]
#[derive(Default)]
struct PCIRangeEntry {
    pub base_address: u64,
    pub segment: u16,
    pub start: u8,
    pub end: u8,
    _reserved: u32,
}

#[repr(packed)]
#[derive(Default)]
struct IortParavirtIommuNode {
    pub type_: u8,
    pub length: u16,
    pub revision: u8,
    _reserved1: u32,
    pub num_id_mappings: u32,
    pub ref_id_mappings: u32,
    pub device_id: u32,
    _reserved2: [u32; 3],
    pub model: u32,
    pub flags: u32,
    _reserved3: [u32; 4],
}

#[repr(packed)]
#[derive(Default)]
struct IortPciRootComplexNode {
    pub type_: u8,
    pub length: u16,
    pub revision: u8,
    _reserved1: u32,
    pub num_id_mappings: u32,
    pub ref_id_mappings: u32,
    pub mem_access_props: IortMemoryAccessProperties,
    pub ats_attr: u32,
    pub pci_seg_num: u32,
    pub mem_addr_size_limit: u8,
    _reserved2: [u8; 3],
}

#[repr(packed)]
#[derive(Default)]
struct IortMemoryAccessProperties {
    pub cca: u32,
    pub ah: u8,
    _reserved: u16,
    pub maf: u8,
}

#[repr(packed)]
#[derive(Default)]
struct IortIdMapping {
    pub input_base: u32,
    pub num_of_ids: u32,
    pub ouput_base: u32,
    pub output_ref: u32,
    pub flags: u32,
}

struct CPU {
    cpu_id: u8,
}

const MADT_CPU_ENABLE_FLAG: usize = 0;

impl aml::Aml for CPU {
    fn to_aml_bytes(&self) -> Vec<u8> {
        let lapic = LocalAPIC {
            r#type: 0,
            length: 8,
            processor_id: self.cpu_id,
            apic_id: self.cpu_id,
            flags: 1 << MADT_CPU_ENABLE_FLAG,
        };

        let mut mat_data: Vec<u8> = Vec::new();
        mat_data.resize(std::mem::size_of_val(&lapic), 0);
        unsafe { *(mat_data.as_mut_ptr() as *mut LocalAPIC) = lapic };

        aml::Device::new(
            format!("C{:03}", self.cpu_id).as_str().into(),
            vec![
                &aml::Name::new("_HID".into(), &"ACPI0007"),
                &aml::Name::new("_UID".into(), &self.cpu_id),
                /*
                _STA return value:
                Bit [0] – Set if the device is present.
                Bit [1] – Set if the device is enabled and decoding its resources.
                Bit [2] – Set if the device should be shown in the UI.
                Bit [3] – Set if the device is functioning properly (cleared if device failed its diagnostics).
                Bit [4] – Set if the battery is present.
                Bits [31:5] – Reserved (must be cleared).
                */
                &aml::Method::new(
                    "_STA".into(),
                    0,
                    false,
                    // Call into CSTA method which will interrogate device
                    vec![&aml::Return::new(&aml::MethodCall::new(
                        "CSTA".into(),
                        vec![&self.cpu_id],
                    ))],
                ),
                // The Linux kernel expects every CPU device to have a _MAT entry
                // containing the LAPIC for this processor with the enabled bit set
                // even it if is disabled in the MADT (non-boot CPU)
                &aml::Name::new("_MAT".into(), &aml::Buffer::new(mat_data)),
            ],
        )
        .to_aml_bytes()
    }
}

struct CPUMethods {
    max_vcpus: u8,
}

impl Aml for CPUMethods {
    fn to_aml_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            // CPU status method
            &aml::Method::new(
                "CSTA".into(),
                1,
                true,
                vec![
                    // Take lock defined above
                    &aml::Acquire::new("\\_SB_.PRES.CPLK".into(), 0xfff),
                    // Write CPU number (in first argument) to I/O port via field
                    &aml::Store::new(&aml::Path::new("\\_SB_.PRES.CSEL"), &aml::Arg(0)),
                    &aml::Store::new(&aml::Local(0), &aml::ZERO),
                    // Check if CPEN bit is set, if so make the local variable 0xf (see _STA for details of meaning)
                    &aml::If::new(
                        &aml::Equal::new(&aml::Path::new("\\_SB_.PRES.CPEN"), &aml::ONE),
                        vec![&aml::Store::new(&aml::Local(0), &0xfu8)],
                    ),
                    // Release lock
                    &aml::Release::new("\\_SB_.PRES.CPLK".into()),
                    // Return 0 or 0xf
                    &aml::Return::new(&aml::Local(0)),
                ],
            )
            .to_aml_bytes(),
        );

        let mut paths = Vec::new();
        for cpu_id in 0..self.max_vcpus {
            paths.push(aml::Path::new(format!("C{:03}", cpu_id).as_str()))
        }
        let mut notify_methods = Vec::new();

        for cpu_id in 0..self.max_vcpus {
            notify_methods.push(aml::Notify::new(&paths[usize::from(cpu_id)], &aml::ONE));
        }

        let mut notify_methods_inner: Vec<&dyn Aml> = Vec::new();
        for notify_method in notify_methods.iter() {
            notify_methods_inner.push(notify_method);
        }

        bytes.extend_from_slice(
            // Notify all vCPUs
            &aml::Method::new("CTFY".into(), 0, true, notify_methods_inner).to_aml_bytes(),
        );
        bytes
    }
}

fn create_cpu_data(max_vcpus: u8) -> Vec<u8> {
    let mut bytes = Vec::new();
    // CPU hotplug controller
    bytes.extend_from_slice(
        &aml::Device::new(
            "_SB_.PRES".into(),
            vec![
                &aml::Name::new("_HID".into(), &aml::EISAName::new("PNP0A06")),
                // Mutex to protect concurrent access as we write to choose CPU and then read back status
                &aml::Mutex::new("CPLK".into(), 0),
                // I/O port for CPU controller
                &aml::Name::new(
                    "_CRS".into(),
                    &aml::ResourceTemplate::new(vec![&aml::IO::new(0x0cd8, 0x0cd8, 0x01, 0x0c)]),
                ),
                // OpRegion and Fields map I/O port into individual field values
                &aml::OpRegion::new("PRST".into(), aml::OpRegionSpace::SystemIO, 0x0cd8, 0x0c),
                &aml::Field::new(
                    "PRST".into(),
                    aml::FieldAccessType::Byte,
                    aml::FieldUpdateRule::WriteAsZeroes,
                    vec![
                        aml::FieldEntry::Reserved(32),
                        aml::FieldEntry::Named(*b"CPEN", 1),
                        aml::FieldEntry::Named(*b"CINS", 1),
                        aml::FieldEntry::Named(*b"CRMV", 1),
                        aml::FieldEntry::Named(*b"CEJ0", 1),
                        aml::FieldEntry::Reserved(4),
                        aml::FieldEntry::Named(*b"CCMD", 8),
                    ],
                ),
                &aml::Field::new(
                    "PRST".into(),
                    aml::FieldAccessType::DWord,
                    aml::FieldUpdateRule::Preserve,
                    vec![
                        aml::FieldEntry::Named(*b"CSEL", 32),
                        aml::FieldEntry::Reserved(32),
                        aml::FieldEntry::Named(*b"CDAT", 32),
                    ],
                ),
            ],
        )
        .to_aml_bytes(),
    );

    // CPU devices
    let hid = aml::Name::new("_HID".into(), &"ACPI0010");
    let uid = aml::Name::new("_CID".into(), &aml::EISAName::new("PNP0A05"));
    // Bundle methods together under a common object
    let methods = CPUMethods { max_vcpus };
    let mut cpu_data_inner: Vec<&dyn aml::Aml> = vec![&hid, &uid, &methods];

    let mut cpu_devices = Vec::new();
    for cpu_id in 0..max_vcpus {
        let cpu_device = CPU { cpu_id };

        cpu_devices.push(cpu_device);
    }

    for cpu_device in cpu_devices.iter() {
        cpu_data_inner.push(cpu_device);
    }

    bytes.extend_from_slice(&aml::Device::new("_SB_.CPUS".into(), cpu_data_inner).to_aml_bytes());
    bytes
}

pub fn create_dsdt_table(
    serial_enabled: bool,
    start_of_device_area: GuestAddress,
    end_of_device_area: GuestAddress,
    max_vcpus: u8,
) -> SDT {
    let pci_dsdt_data = aml::Device::new(
        "_SB_.PCI0".into(),
        vec![
            &aml::Name::new("_HID".into(), &aml::EISAName::new("PNP0A08")),
            &aml::Name::new("_CID".into(), &aml::EISAName::new("PNP0A03")),
            &aml::Name::new("_ADR".into(), &aml::ZERO),
            &aml::Name::new("_SEG".into(), &aml::ZERO),
            &aml::Name::new("_UID".into(), &aml::ZERO),
            &aml::Name::new("SUPP".into(), &aml::ZERO),
            &aml::Name::new(
                "_CRS".into(),
                &aml::ResourceTemplate::new(vec![
                    &aml::AddressSpace::new_bus_number(0x0u16, 0xffu16),
                    &aml::IO::new(0xcf8, 0xcf8, 1, 0x8),
                    &aml::AddressSpace::new_io(0x0u16, 0xcf7u16),
                    &aml::AddressSpace::new_io(0xd00u16, 0xffffu16),
                    &aml::AddressSpace::new_memory(
                        aml::AddressSpaceCachable::NotCacheable,
                        true,
                        layout::MEM_32BIT_DEVICES_START.0 as u32,
                        (layout::MEM_32BIT_DEVICES_START.0 + layout::MEM_32BIT_DEVICES_SIZE - 1)
                            as u32,
                    ),
                    &aml::AddressSpace::new_memory(
                        aml::AddressSpaceCachable::NotCacheable,
                        true,
                        start_of_device_area.0,
                        end_of_device_area.0,
                    ),
                ]),
            ),
        ],
    )
    .to_aml_bytes();

    let mbrd_dsdt_data = aml::Device::new(
        "_SB_.MBRD".into(),
        vec![
            &aml::Name::new("_HID".into(), &aml::EISAName::new("PNP0C02")),
            &aml::Name::new("_UID".into(), &aml::ZERO),
            &aml::Name::new(
                "_CRS".into(),
                &aml::ResourceTemplate::new(vec![&aml::Memory32Fixed::new(
                    true,
                    layout::PCI_MMCONFIG_START.0 as u32,
                    layout::PCI_MMCONFIG_SIZE as u32,
                )]),
            ),
        ],
    )
    .to_aml_bytes();

    let com1_dsdt_data = aml::Device::new(
        "_SB_.COM1".into(),
        vec![
            &aml::Name::new("_HID".into(), &aml::EISAName::new("PNP0501")),
            &aml::Name::new("_UID".into(), &aml::ZERO),
            &aml::Name::new(
                "_CRS".into(),
                &aml::ResourceTemplate::new(vec![
                    &aml::Interrupt::new(true, true, false, false, 4),
                    &aml::IO::new(0x3f8, 0x3f8, 0, 0x8),
                ]),
            ),
        ],
    )
    .to_aml_bytes();

    let s5_sleep_data =
        aml::Name::new("_S5_".into(), &aml::Package::new(vec![&5u8])).to_aml_bytes();

    let cpu_data = create_cpu_data(max_vcpus);

    // DSDT
    let mut dsdt = SDT::new(*b"DSDT", 36, 6, *b"CLOUDH", *b"CHDSDT  ", 1);
    dsdt.append_slice(pci_dsdt_data.as_slice());
    dsdt.append_slice(mbrd_dsdt_data.as_slice());
    if serial_enabled {
        dsdt.append_slice(com1_dsdt_data.as_slice());
    }
    dsdt.append_slice(s5_sleep_data.as_slice());
    dsdt.append_slice(cpu_data.as_slice());

    dsdt
}

pub fn create_acpi_tables(
    guest_mem: &GuestMemoryMmap,
    boot_vcpus: u8,
    max_vcpus: u8,
    serial_enabled: bool,
    start_of_device_area: GuestAddress,
    end_of_device_area: GuestAddress,
    virt_iommu: Option<(u32, &[u32])>,
) -> GuestAddress {
    // RSDP is at the EBDA
    let rsdp_offset = layout::RSDP_POINTER;
    let mut tables: Vec<u64> = Vec::new();

    // DSDT
    let dsdt = create_dsdt_table(
        serial_enabled,
        start_of_device_area,
        end_of_device_area,
        max_vcpus,
    );
    let dsdt_offset = rsdp_offset.checked_add(RSDP::len() as u64).unwrap();
    guest_mem
        .write_slice(dsdt.as_slice(), dsdt_offset)
        .expect("Error writing DSDT table");

    // FACP aka FADT
    // Revision 6 of the ACPI FADT table is 276 bytes long
    let mut facp = SDT::new(*b"FACP", 276, 6, *b"CLOUDH", *b"CHFACP  ", 1);

    // HW_REDUCED_ACPI and RESET_REG_SUP
    let fadt_flags: u32 = 1 << 20 | 1 << 10;
    facp.write(112, fadt_flags);

    // RESET_REG
    facp.write(116, GenericAddress::io_port_address(0x3c0));
    // RESET_VALUE
    facp.write(128, 1u8);

    facp.write(131, 3u8); // FADT minor version
    facp.write(140, dsdt_offset.0); // X_DSDT

    // SLEEP_CONTROL_REG
    facp.write(244, GenericAddress::io_port_address(0x3c0));
    // SLEEP_STATUS_REG
    facp.write(256, GenericAddress::io_port_address(0x3c0));

    facp.write(268, b"CLOUDHYP"); // Hypervisor Vendor Identity

    facp.update_checksum();
    let facp_offset = dsdt_offset.checked_add(dsdt.len() as u64).unwrap();
    guest_mem
        .write_slice(facp.as_slice(), facp_offset)
        .expect("Error writing FACP table");
    tables.push(facp_offset.0);

    // MADT
    let mut madt = SDT::new(*b"APIC", 44, 5, *b"CLOUDH", *b"CHMADT  ", 1);
    madt.write(36, layout::APIC_START);

    // This is also checked in the commandline parsing.
    assert!(boot_vcpus <= max_vcpus);

    for cpu in 0..max_vcpus {
        let lapic = LocalAPIC {
            r#type: 0,
            length: 8,
            processor_id: cpu,
            apic_id: cpu,
            flags: if cpu < boot_vcpus {
                1 << MADT_CPU_ENABLE_FLAG
            } else {
                0
            },
        };
        madt.append(lapic);
    }

    madt.append(IOAPIC {
        r#type: 1,
        length: 12,
        ioapic_id: 0,
        apic_address: layout::IOAPIC_START.0 as u32,
        gsi_base: 0,
        ..Default::default()
    });

    madt.append(InterruptSourceOverride {
        r#type: 2,
        length: 10,
        bus: 0,
        source: 4,
        gsi: 4,
        flags: 0,
    });

    let madt_offset = facp_offset.checked_add(facp.len() as u64).unwrap();
    guest_mem
        .write_slice(madt.as_slice(), madt_offset)
        .expect("Error writing MADT table");
    tables.push(madt_offset.0);

    // MCFG
    let mut mcfg = SDT::new(*b"MCFG", 36, 1, *b"CLOUDH", *b"CHMCFG  ", 1);

    // MCFG reserved 8 bytes
    mcfg.append(0u64);

    // 32-bit PCI enhanced configuration mechanism
    mcfg.append(PCIRangeEntry {
        base_address: layout::PCI_MMCONFIG_START.0,
        segment: 0,
        start: 0,
        end: 0xff,
        ..Default::default()
    });

    let mcfg_offset = madt_offset.checked_add(madt.len() as u64).unwrap();
    guest_mem
        .write_slice(mcfg.as_slice(), mcfg_offset)
        .expect("Error writing MCFG table");
    tables.push(mcfg_offset.0);

    let (prev_tbl_len, prev_tbl_off) = if let Some((iommu_id, dev_ids)) = &virt_iommu {
        // IORT
        let mut iort = SDT::new(*b"IORT", 36, 1, *b"CLOUDH", *b"CHIORT  ", 1);
        // IORT number of nodes
        iort.append(2u32);
        // IORT offset to array of IORT nodes
        iort.append(48u32);
        // IORT reserved 4 bytes
        iort.append(0u32);
        // IORT paravirtualized IOMMU node
        iort.append(IortParavirtIommuNode {
            type_: 128,
            length: 56,
            revision: 0,
            num_id_mappings: 0,
            ref_id_mappings: 56,
            device_id: *iommu_id,
            model: 1,
            ..Default::default()
        });

        let num_entries = dev_ids.len();
        let length: u16 = (36 + (20 * num_entries)).try_into().unwrap();

        // IORT PCI root complex node
        iort.append(IortPciRootComplexNode {
            type_: 2,
            length,
            revision: 0,
            num_id_mappings: num_entries as u32,
            ref_id_mappings: 36,
            ats_attr: 0,
            pci_seg_num: 0,
            mem_addr_size_limit: 255,
            ..Default::default()
        });

        for dev_id in dev_ids.iter() {
            // IORT ID mapping
            iort.append(IortIdMapping {
                input_base: *dev_id,
                num_of_ids: 1,
                ouput_base: *dev_id,
                output_ref: 48,
                flags: 0,
            });
        }

        let iort_offset = mcfg_offset.checked_add(mcfg.len() as u64).unwrap();
        guest_mem
            .write_slice(iort.as_slice(), iort_offset)
            .expect("Error writing IORT table");
        tables.push(iort_offset.0);

        (iort.len(), iort_offset)
    } else {
        (mcfg.len(), mcfg_offset)
    };

    // XSDT
    let mut xsdt = SDT::new(*b"XSDT", 36, 1, *b"CLOUDH", *b"CHXSDT  ", 1);
    for table in tables {
        xsdt.append(table);
    }
    xsdt.update_checksum();

    let xsdt_offset = prev_tbl_off.checked_add(prev_tbl_len as u64).unwrap();
    guest_mem
        .write_slice(xsdt.as_slice(), xsdt_offset)
        .expect("Error writing XSDT table");

    // RSDP
    let rsdp = RSDP::new(*b"CLOUDH", xsdt_offset.0);
    guest_mem
        .write_slice(rsdp.as_slice(), rsdp_offset)
        .expect("Error writing RSDP");

    rsdp_offset
}
