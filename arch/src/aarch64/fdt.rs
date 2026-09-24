// Copyright 2020 Arm Limited (or its affiliates). All rights reserved.
// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::HashMap;
use std::ffi::CStr;
use std::fmt::Debug;
use std::hash::BuildHasher;
use std::sync::{Arc, Mutex};
use std::{cmp, result, str};

use byteorder::{BigEndian, ByteOrder};
use fdt_parser::node::FdtNode;
use hypervisor::arch::aarch64::gic::Vgic;
use hypervisor::arch::aarch64::regs::{
    AARCH64_ARCH_TIMER_HYP_IRQ, AARCH64_ARCH_TIMER_PHYS_NONSECURE_IRQ,
    AARCH64_ARCH_TIMER_PHYS_SECURE_IRQ, AARCH64_ARCH_TIMER_VIRT_IRQ, AARCH64_PMU_PPI_INDEX,
};
use log::{debug, info};
use thiserror::Error;
use vm_fdt::{FdtWriter, FdtWriterResult};
use vm_memory::{
    Address, ByteValued, Bytes, GuestAddress, GuestMemoryBackend, GuestMemoryError,
    GuestMemoryRegion,
};

use super::super::{DeviceType, GuestMemoryMmap, InitramfsConfig};
use super::cache::{CacheTopologyInfo, read_cache_topology};
use super::layout::{
    GIC_V2M_COMPATIBLE, GICV2M_SPI_BASE, GICV2M_SPI_NUM, IRQ_BASE, MEM_32BIT_DEVICES_SIZE,
    MEM_32BIT_DEVICES_START, MEM_PCI_IO_SIZE, MEM_PCI_IO_START, PCI_HIGH_BASE,
    PCI_MMIO_CONFIG_SIZE_PER_SEGMENT,
};
use crate::{NumaNodes, PciSpaceInfo};

// This is a value for uniquely identifying the FDT node declaring the interrupt controller.
const GIC_PHANDLE: u32 = 1;
// This is a value for uniquely identifying the FDT node declaring the MSI controller.
const MSI_PHANDLE: u32 = 2;
// This is a value for uniquely identifying the FDT node containing the clock definition.
const CLOCK_PHANDLE: u32 = 3;
// This is a value for uniquely identifying the FDT node containing the gpio controller.
const GPIO_PHANDLE: u32 = 4;
// This is a value for virtio-iommu. Now only one virtio-iommu device is supported.
const VIRTIO_IOMMU_PHANDLE: u32 = 5;
// NOTE: Keep FIRST_VCPU_PHANDLE the last PHANDLE defined.
// This is a value for uniquely identifying the FDT node containing the first vCPU.
// The last number of vCPU phandle depends on the number of vCPUs.
const FIRST_VCPU_PHANDLE: u32 = 8;

// This is a value for uniquely identifying the FDT node containing the L2 cache info
const L2_CACHE_PHANDLE: u32 = 6;
// This is a value for uniquely identifying the FDT node containing the L3 cache info
const L3_CACHE_PHANDLE: u32 = 7;
// Read the documentation specified when appending the root node to the FDT.
const ADDRESS_CELLS: u32 = 0x2;
const SIZE_CELLS: u32 = 0x2;

// As per kvm tool and
// https://www.kernel.org/doc/Documentation/devicetree/bindings/interrupt-controller/arm%2Cgic.txt
// Look for "The 1st cell..."
const GIC_FDT_IRQ_TYPE_SPI: u32 = 0;
const GIC_FDT_IRQ_TYPE_PPI: u32 = 1;

// From https://elixir.bootlin.com/linux/v4.9.62/source/include/dt-bindings/interrupt-controller/irq.h#L17
const IRQ_TYPE_EDGE_RISING: u32 = 1;
const IRQ_TYPE_LEVEL_HI: u32 = 4;

// Keys and Buttons
// System Power Down
const KEY_POWER: u32 = 116;

/// Trait for devices to be added to the Flattened Device Tree.
pub trait DeviceInfoForFdt {
    /// Returns the address where this device will be loaded.
    fn addr(&self) -> u64;
    /// Returns the associated interrupt for this device.
    fn irq(&self) -> u32;
    /// Returns the amount of memory that needs to be reserved for this device.
    fn length(&self) -> u64;
}

/// Errors thrown while configuring the Flattened Device Tree for aarch64.
#[derive(Debug, Error)]
pub enum Error {
    /// Failure in writing FDT in memory.
    #[error("Failure in writing FDT in memory")]
    WriteFdtToMemory(#[source] GuestMemoryError),

    /// FDT blob exceeds maximum allowed size (`FDT_MAX_SIZE`).
    #[error("FDT size ({0} bytes) exceeds maximum allowed size ({1} bytes)")]
    FdtTooLarge(usize, u64),

    /// EFI memory map exceeds the reserved space before `ACPI_START`.
    #[error("EFI memory map size ({0} bytes) exceeds reserved size ({1} bytes)")]
    EfiMmapTooLarge(u64, u64),
}
type Result<T> = result::Result<T, Error>;

// UEFI 2.8 Specification definitions for FDT-based UEFI/ACPI discovery.
// Linux's `early_init_dt_scan_chosen()` parses `linux,uefi-system-table` and
// `linux,uefi-mmap-*` under `/chosen` to initialize EFI config tables (`efi_init()`)
// and discover the ACPI 2.0 RSDP (`RSDP_POINTER`) and SMBIOS 3.0 entrypoint
// (`SMBIOS_START`) during direct `--kernel` boot.
const EFI_SYSTEM_TABLE_SIGNATURE: u64 = 0x5453_5953_2049_4249; // "IBI SYST"
const EFI_2_80_SYSTEM_TABLE_REVISION: u32 = (2 << 16) | 80;

// EFI_ACPI_20_TABLE_GUID: 8868e871-e4f1-11d3-bc22-0080c73c8881
const EFI_ACPI_20_TABLE_GUID: [u8; 16] = [
    0x71, 0xe8, 0x68, 0x88, 0xf1, 0xe4, 0xd3, 0x11, 0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81,
];

// SMBIOS3_TABLE_GUID: f2fd1544-9794-4a2c-992e-e5bbcf20e394
const SMBIOS3_TABLE_GUID: [u8; 16] = [
    0x44, 0x15, 0xfd, 0xf2, 0x94, 0x97, 0x2c, 0x4a, 0x99, 0x2e, 0xe5, 0xbb, 0xcf, 0x20, 0xe3, 0x94,
];

// EFI_RT_PROPERTIES_TABLE_GUID: eb66918a-7eef-402a-842e-931d21c38ae9
const EFI_RT_PROPERTIES_TABLE_GUID: [u8; 16] = [
    0x8a, 0x91, 0x66, 0xeb, 0xef, 0x7e, 0x2a, 0x40, 0x84, 0x2e, 0x93, 0x1d, 0x21, 0xc3, 0x8a, 0xe9,
];

const EFI_RT_PROPERTIES_TABLE_VERSION: u16 = 0x1;

// EFI Memory Types and Attributes (UEFI 2.8 Section 7.2)
const EFI_RESERVED_MEMORY_TYPE: u32 = 0;
const EFI_CONVENTIONAL_MEMORY: u32 = 7;
const EFI_MEMORY_WB: u64 = 0x8;
const EFI_MEMORY_DESCRIPTOR_VERSION: u32 = 1;
const EFI_PAGE_SIZE: u64 = 4096;

/// UEFI Specification 2.8 Section 4.2 - `EFI_TABLE_HEADER`
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct EfiTableHeader {
    signature: u64,
    revision: u32,
    header_size: u32,
    crc32: u32,
    reserved: u32,
}

const _: () = assert!(size_of::<EfiTableHeader>() == 24);
// SAFETY: `EfiTableHeader` is `#[repr(C)]` with no padding and contains only plain integer fields.
unsafe impl ByteValued for EfiTableHeader {}

/// UEFI Specification 2.8 Section 4.3 - `EFI_SYSTEM_TABLE` (64-bit)
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct EfiSystemTable {
    hdr: EfiTableHeader,
    firmware_vendor: u64,
    firmware_revision: u32,
    _pad: u32,
    console_in_handle: u64,
    con_in: u64,
    console_out_handle: u64,
    con_out: u64,
    standard_error_handle: u64,
    std_err: u64,
    runtime_services: u64,
    boot_services: u64,
    number_of_table_entries: u64,
    configuration_table: u64,
}

const _: () = assert!(size_of::<EfiSystemTable>() == 120);
// SAFETY: `EfiSystemTable` is `#[repr(C)]` with explicit padding (`_pad`) and contains only POD types.
unsafe impl ByteValued for EfiSystemTable {}

/// UEFI Specification 2.8 Section 4.6 - `EFI_CONFIGURATION_TABLE` (64-bit)
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct EfiConfigurationTable {
    vendor_guid: [u8; 16],
    vendor_table: u64,
}

const _: () = assert!(size_of::<EfiConfigurationTable>() == 24);
// SAFETY: `EfiConfigurationTable` is `#[repr(C)]` with no padding and contains only POD types.
unsafe impl ByteValued for EfiConfigurationTable {}

/// UEFI Specification 2.8 Section 4.6 - `EFI_RT_PROPERTIES_TABLE`
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct EfiRtPropertiesTable {
    version: u16,
    length: u16,
    runtime_services_supported: u32,
}

const _: () = assert!(size_of::<EfiRtPropertiesTable>() == 8);
// SAFETY: `EfiRtPropertiesTable` is `#[repr(C)]` with no padding and contains only plain integer fields.
unsafe impl ByteValued for EfiRtPropertiesTable {}

/// UEFI Specification 2.8 Section 7.2 - `EFI_MEMORY_DESCRIPTOR`
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct EfiMemoryDescriptor {
    r#type: u32,
    _pad: u32,
    physical_start: u64,
    virtual_start: u64,
    number_of_pages: u64,
    attribute: u64,
}

const _: () = assert!(size_of::<EfiMemoryDescriptor>() == 40);
// SAFETY: `EfiMemoryDescriptor` is `#[repr(C)]` with explicit padding (`_pad`) and contains only plain integers.
unsafe impl ByteValued for EfiMemoryDescriptor {}

/// Creates the flattened device tree for this aarch64 VM.
#[expect(clippy::too_many_arguments)]
pub fn create_fdt<T: DeviceInfoForFdt + Clone + Debug, S: BuildHasher>(
    guest_mem: &GuestMemoryMmap,
    cmdline: &str,
    vcpu_mpidr: &[u64],
    vcpu_topology: Option<(u16, u16, u16, u16)>,
    device_info: &HashMap<(DeviceType, String), T, S>,
    gic_device: &Arc<Mutex<dyn Vgic>>,
    initrd: &Option<InitramfsConfig>,
    pci_space_info: &[PciSpaceInfo],
    numa_nodes: &NumaNodes,
    virtio_iommu_bdf: Option<u32>,
    pmu_supported: bool,
) -> FdtWriterResult<Vec<u8>> {
    // Allocate stuff necessary for the holding the blob.
    let mut fdt = FdtWriter::new().unwrap();

    // For an explanation why these nodes were introduced in the blob take a look at
    // the "Device Node Requirements" chapter of the Devicetree Specification.
    // https://www.devicetree.org/specifications/

    // Header or the root node as per above mentioned documentation.
    let root_node = fdt.begin_node("")?;
    fdt.property_string("compatible", "linux,dummy-virt")?;
    // For info on #address-cells and size-cells read "Note about cells and address representation"
    // from the above mentioned txt file.
    fdt.property_u32("#address-cells", ADDRESS_CELLS)?;
    fdt.property_u32("#size-cells", SIZE_CELLS)?;
    // This is not mandatory but we use it to point the root node to the node
    // containing description of the interrupt controller for this VM.
    fdt.property_u32("interrupt-parent", GIC_PHANDLE)?;
    create_cpu_nodes(&mut fdt, vcpu_mpidr, vcpu_topology, numa_nodes)?;
    create_memory_node(&mut fdt, guest_mem, numa_nodes)?;
    create_chosen_node(&mut fdt, cmdline, initrd, guest_mem)?;
    create_gic_node(&mut fdt, gic_device)?;
    create_timer_node(&mut fdt)?;
    if pmu_supported {
        create_pmu_node(&mut fdt)?;
    }
    create_clock_node(&mut fdt)?;
    create_psci_node(&mut fdt)?;
    create_devices_node(&mut fdt, device_info)?;
    create_pci_nodes(&mut fdt, pci_space_info, virtio_iommu_bdf)?;
    if numa_nodes.len() > 1 {
        create_distance_map_node(&mut fdt, numa_nodes)?;
    }

    // End Header node.
    fdt.end_node(root_node)?;

    let fdt_final = fdt.finish()?;

    Ok(fdt_final)
}

/// Standard IEEE 802.3 CRC32 used for `EFI_TABLE_HEADER.CRC32` (UEFI 2.8 Section 4.2).
fn efi_crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xffff_ffff;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ 0xedb8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

fn write_uefi_tables(guest_mem: &GuestMemoryMmap) -> Result<()> {
    // 1. Write UCS-2 NUL-terminated Firmware Vendor string ("Cloud Hypervisor")
    let vendor_utf16: Vec<u16> = "Cloud Hypervisor\0".encode_utf16().collect();
    let mut vendor_bytes = Vec::with_capacity(vendor_utf16.len() * 2);
    for ch in vendor_utf16 {
        vendor_bytes.extend_from_slice(&ch.to_le_bytes());
    }
    guest_mem
        .write_slice(&vendor_bytes, super::layout::UEFI_FW_VENDOR_START)
        .map_err(Error::WriteFdtToMemory)?;

    // 2. Write EFI_RT_PROPERTIES_TABLE with RuntimeServicesSupported = 0 so the
    //    Linux kernel knows no runtime service calls are supported.
    let rt_prop = EfiRtPropertiesTable {
        version: EFI_RT_PROPERTIES_TABLE_VERSION,
        length: size_of::<EfiRtPropertiesTable>() as u16,
        runtime_services_supported: 0,
    };
    guest_mem
        .write_obj(rt_prop, super::layout::UEFI_RT_PROP_START)
        .map_err(Error::WriteFdtToMemory)?;

    // 3. Write the 3 EFI_CONFIGURATION_TABLE entries:
    //    - Entry 0: EFI_ACPI_20_TABLE_GUID -> RSDP_POINTER (0x4020_0000)
    //    - Entry 1: SMBIOS3_TABLE_GUID -> SMBIOS_START (0x403f_0000)
    //    - Entry 2: EFI_RT_PROPERTIES_TABLE_GUID -> UEFI_RT_PROP_START (0x401f_0180)
    let config_tables = [
        EfiConfigurationTable {
            vendor_guid: EFI_ACPI_20_TABLE_GUID,
            vendor_table: super::layout::RSDP_POINTER.0,
        },
        EfiConfigurationTable {
            vendor_guid: SMBIOS3_TABLE_GUID,
            vendor_table: super::layout::SMBIOS_START.0,
        },
        EfiConfigurationTable {
            vendor_guid: EFI_RT_PROPERTIES_TABLE_GUID,
            vendor_table: super::layout::UEFI_RT_PROP_START.0,
        },
    ];
    let config_entry_size = size_of::<EfiConfigurationTable>() as u64;
    for (idx, entry) in config_tables.iter().enumerate() {
        let addr = GuestAddress(
            super::layout::UEFI_CONFIG_TABLE_START.0 + (idx as u64) * config_entry_size,
        );
        guest_mem
            .write_obj(*entry, addr)
            .map_err(Error::WriteFdtToMemory)?;
    }

    // 4. Construct EFI_SYSTEM_TABLE, compute IEEE 802.3 CRC32 over the 120-byte
    //    table (with hdr.crc32 = 0), and write it to UEFI_SYSTAB_START.
    let mut systab = EfiSystemTable {
        hdr: EfiTableHeader {
            signature: EFI_SYSTEM_TABLE_SIGNATURE,
            revision: EFI_2_80_SYSTEM_TABLE_REVISION,
            header_size: size_of::<EfiSystemTable>() as u32,
            crc32: 0,
            reserved: 0,
        },
        firmware_vendor: super::layout::UEFI_FW_VENDOR_START.0,
        firmware_revision: 1,
        _pad: 0,
        console_in_handle: 0,
        con_in: 0,
        console_out_handle: 0,
        con_out: 0,
        standard_error_handle: 0,
        std_err: 0,
        runtime_services: 0,
        boot_services: 0,
        number_of_table_entries: config_tables.len() as u64,
        configuration_table: super::layout::UEFI_CONFIG_TABLE_START.0,
    };
    systab.hdr.crc32 = efi_crc32(systab.as_slice());

    guest_mem
        .write_obj(systab, super::layout::UEFI_SYSTAB_START)
        .map_err(Error::WriteFdtToMemory)?;

    Ok(())
}

fn build_efi_mmap_descriptors(guest_mem: &GuestMemoryMmap) -> Vec<EfiMemoryDescriptor> {
    let mut descriptors = Vec::new();

    // Descriptor 0: Reserve the 2 MiB FDT + UEFI System Table + Memory Map area (0x4000_0000 .. 0x4020_0000).
    // Setting `attribute: EFI_MEMORY_WB` keeps `[0x4000_0000 .. 0x4020_0000)` in `memblock.memory`
    // (as `MEMBLOCK_NOMAP` due to `EFI_RESERVED_MEMORY_TYPE`) when `efi_init()` rebuilds memblock,
    // preserving `memblock_start_of_DRAM()` at `RAM_START` (0x4000_0000).
    descriptors.push(EfiMemoryDescriptor {
        r#type: EFI_RESERVED_MEMORY_TYPE,
        _pad: 0,
        physical_start: super::layout::FDT_START.0,
        virtual_start: 0,
        number_of_pages: (super::layout::ACPI_START.0 - super::layout::FDT_START.0) / EFI_PAGE_SIZE,
        attribute: EFI_MEMORY_WB,
    });

    // Descriptor 1: Reserve the 2 MiB ACPI + SMBIOS tables area (0x4020_0000 .. 0x4040_0000).
    // Setting `attribute: EFI_MEMORY_WB` ensures `acpi_os_ioremap()` maps the ACPI tables as
    // normal write-back memory (`PAGE_KERNEL`) rather than `PROT_DEVICE_nGnRnE`, avoiding
    // alignment faults on unaligned table accesses.
    descriptors.push(EfiMemoryDescriptor {
        r#type: EFI_RESERVED_MEMORY_TYPE,
        _pad: 0,
        physical_start: super::layout::ACPI_START.0,
        virtual_start: 0,
        number_of_pages: (super::layout::KERNEL_START.0 - super::layout::ACPI_START.0)
            / EFI_PAGE_SIZE,
        attribute: EFI_MEMORY_WB,
    });

    // Remaining descriptors: Usable guest RAM starting at KERNEL_START (0x4040_0000)
    let usable_ram_start = super::layout::KERNEL_START.0;
    for region in guest_mem.iter() {
        let region_start = region.start_addr().raw_value();
        let region_end = region_start + region.len();
        let start = cmp::max(region_start, usable_ram_start);
        if region_end > start {
            let pages = (region_end - start) / EFI_PAGE_SIZE;
            if pages > 0 {
                descriptors.push(EfiMemoryDescriptor {
                    r#type: EFI_CONVENTIONAL_MEMORY,
                    _pad: 0,
                    physical_start: start,
                    virtual_start: 0,
                    number_of_pages: pages,
                    attribute: EFI_MEMORY_WB,
                });
            }
        }
    }

    descriptors
}

fn write_efi_mmap(guest_mem: &GuestMemoryMmap) -> Result<()> {
    let descriptors = build_efi_mmap_descriptors(guest_mem);
    let desc_size = size_of::<EfiMemoryDescriptor>() as u64;
    let mmap_size = (descriptors.len() as u64).saturating_mul(desc_size);
    let max_mmap_size = super::layout::ACPI_START.0 - super::layout::UEFI_MMAP_START.0;
    if mmap_size > max_mmap_size {
        return Err(Error::EfiMmapTooLarge(mmap_size, max_mmap_size));
    }
    for (idx, desc) in descriptors.iter().enumerate() {
        let addr = GuestAddress(super::layout::UEFI_MMAP_START.0 + (idx as u64) * desc_size);
        guest_mem
            .write_obj(*desc, addr)
            .map_err(Error::WriteFdtToMemory)?;
    }
    Ok(())
}

pub fn write_fdt_to_memory(fdt_final: &[u8], guest_mem: &GuestMemoryMmap) -> Result<()> {
    if fdt_final.len() as u64 > super::layout::FDT_MAX_SIZE {
        return Err(Error::FdtTooLarge(
            fdt_final.len(),
            super::layout::FDT_MAX_SIZE,
        ));
    }

    // Write FDT to memory.
    guest_mem
        .write_slice(fdt_final, super::layout::FDT_START)
        .map_err(Error::WriteFdtToMemory)?;

    // Write stub UEFI System Table, Configuration Tables, and EFI Memory Map so
    // the guest Linux kernel can discover ACPI and SMBIOS tables on direct kernel boot.
    write_uefi_tables(guest_mem)?;
    write_efi_mmap(guest_mem)?;

    Ok(())
}

// Following are the auxiliary function for creating the different nodes that we append to our FDT.
fn create_cpu_nodes(
    fdt: &mut FdtWriter,
    vcpu_mpidr: &[u64],
    vcpu_topology: Option<(u16, u16, u16, u16)>,
    numa_nodes: &NumaNodes,
) -> FdtWriterResult<()> {
    // See https://github.com/torvalds/linux/blob/master/Documentation/devicetree/bindings/arm/cpus.yaml.
    let cpus_node = fdt.begin_node("cpus")?;
    fdt.property_u32("#address-cells", 0x1)?;
    fdt.property_u32("#size-cells", 0x0)?;

    let num_cpus = vcpu_mpidr.len();
    let (threads_per_core, cores_per_die, dies_per_package, packages) =
        vcpu_topology.unwrap_or((1, 1, 1, 1));
    let cores_per_package = cores_per_die * dies_per_package;
    let max_cpus: u32 =
        threads_per_core as u32 * cores_per_die as u32 * dies_per_package as u32 * packages as u32;

    // Add cache info.
    let cache_info = read_cache_topology();
    let cache_exist = cache_info.is_some();
    let CacheTopologyInfo {
        l1_d_cache_size,
        l1_d_cache_line_size,
        l1_d_cache_sets,
        l1_i_cache_size,
        l1_i_cache_line_size,
        l1_i_cache_sets,
        l2_cache_size,
        l2_cache_line_size,
        l2_cache_sets,
        l3_cache_size,
        l3_cache_line_size,
        l3_cache_sets,
        l2_cache_shared,
        l3_cache_shared,
    } = cache_info.unwrap_or_default();

    // Arm boot protocol requires a minimal Device Tree
    // https://docs.kernel.org/arch/arm64/booting.html
    // As Generic initiators are supported only in ACPI
    // When a guest kernel does not boot under "acpi=force" mode it can
    // hang due to conflicting numa information present in FDT which
    // does not support Generic Initiators
    let has_generic_initiator = numa_nodes.values().any(|node| node.device_id.is_some());
    if has_generic_initiator {
        info!("Skipping NUMA CPU node encoding in FDT with Generic Initiator devices");
    }

    for (cpu_id, mpidr) in vcpu_mpidr.iter().enumerate().take(num_cpus) {
        let cpu_name = format!("cpu@{cpu_id:x}");
        let cpu_node = fdt.begin_node(&cpu_name)?;
        fdt.property_string("device_type", "cpu")?;
        fdt.property_string("compatible", "arm,arm-v8")?;
        if num_cpus > 1 {
            // This is required on armv8 64-bit. See aforementioned documentation.
            fdt.property_string("enable-method", "psci")?;
        }
        // Set the field to first 24 bits of the MPIDR - Multiprocessor Affinity Register.
        // See http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0488c/BABHBJCI.html.
        fdt.property_u32("reg", (mpidr & 0x7FFFFF) as u32)?;
        fdt.property_u32("phandle", cpu_id as u32 + FIRST_VCPU_PHANDLE)?;

        // Skipping NUMA encoding in FDT when Generic Initiator devices
        // are present allowed such guest kernels to boot properly and
        // rely solely on ACPI tables to setup NUMA
        if numa_nodes.len() > 1 && !has_generic_initiator {
            for numa_node_idx in 0..numa_nodes.len() {
                let numa_node = numa_nodes.get(&(numa_node_idx as u32));
                if numa_node.unwrap().cpus.contains(&(cpu_id as u32)) {
                    fdt.property_u32("numa-node-id", numa_node_idx as u32)?;
                }
            }
        }

        if cache_exist && l1_d_cache_size != 0 && l1_i_cache_size != 0 {
            // Add cache info.
            fdt.property_u32("d-cache-size", l1_d_cache_size)?;
            fdt.property_u32("d-cache-line-size", l1_d_cache_line_size)?;
            fdt.property_u32("d-cache-sets", l1_d_cache_sets)?;

            fdt.property_u32("i-cache-size", l1_i_cache_size)?;
            fdt.property_u32("i-cache-line-size", l1_i_cache_line_size)?;
            fdt.property_u32("i-cache-sets", l1_i_cache_sets)?;

            if l2_cache_size != 0 && !l2_cache_shared {
                fdt.property_u32(
                    "next-level-cache",
                    cpu_id as u32 + max_cpus + FIRST_VCPU_PHANDLE + L2_CACHE_PHANDLE,
                )?;

                let l2_cache_name = "l2-cache0";
                let l2_cache_node = fdt.begin_node(l2_cache_name)?;
                // PHANDLE is used to mark device node, and PHANDLE is unique. To avoid phandle
                // conflicts with other device nodes, consider the previous CPU PHANDLE, so the
                // CPU L2 cache PHANDLE must start from the largest CPU PHANDLE plus 1.
                fdt.property_u32(
                    "phandle",
                    cpu_id as u32 + max_cpus + FIRST_VCPU_PHANDLE + L2_CACHE_PHANDLE,
                )?;

                fdt.property_string("compatible", "cache")?;
                fdt.property_u32("cache-size", l2_cache_size)?;
                fdt.property_u32("cache-line-size", l2_cache_line_size)?;
                fdt.property_u32("cache-sets", l2_cache_sets)?;
                fdt.property_u32("cache-level", 2)?;

                if l3_cache_size != 0 && l3_cache_shared {
                    let package_id: u32 = cpu_id as u32 / cores_per_package as u32;
                    fdt.property_u32(
                        "next-level-cache",
                        package_id
                            + num_cpus as u32
                            + max_cpus
                            + FIRST_VCPU_PHANDLE
                            + L2_CACHE_PHANDLE
                            + L3_CACHE_PHANDLE,
                    )?;
                }

                fdt.end_node(l2_cache_node)?;
            }
        }

        fdt.end_node(cpu_node)?;
    }

    if cache_exist && l3_cache_size != 0 && !l2_cache_shared && l3_cache_shared {
        let mut i: u32 = 0;
        while i < packages.into() {
            let l3_cache_name = format!("l3-cache{i}");
            let l3_cache_node = fdt.begin_node(&l3_cache_name)?;
            // ARM L3 cache is generally shared within the package (socket), so the
            // L3 cache node pointed to by the CPU in the package has the same L3
            // cache PHANDLE. The L3 cache phandle must start from the largest L2
            // cache PHANDLE plus 1 to avoid duplication.
            fdt.property_u32(
                "phandle",
                i + num_cpus as u32
                    + max_cpus
                    + FIRST_VCPU_PHANDLE
                    + L2_CACHE_PHANDLE
                    + L3_CACHE_PHANDLE,
            )?;

            fdt.property_string("compatible", "cache")?;
            fdt.property_null("cache-unified")?;
            fdt.property_u32("cache-size", l3_cache_size)?;
            fdt.property_u32("cache-line-size", l3_cache_line_size)?;
            fdt.property_u32("cache-sets", l3_cache_sets)?;
            fdt.property_u32("cache-level", 3)?;
            fdt.end_node(l3_cache_node)?;

            i += 1;
        }
    }

    if let Some(topology) = vcpu_topology {
        let (threads_per_core, cores_per_die, dies_per_package, packages) = topology;
        let cores_per_package = cores_per_die * dies_per_package;
        let cpu_map_node = fdt.begin_node("cpu-map")?;

        // Create device tree nodes with regard of above mapping.
        for package_idx in 0..packages {
            let package_name = format!("socket{package_idx:x}");
            let package_node = fdt.begin_node(&package_name)?;

            // Cluster is the container of cores, and it is mandatory in the CPU topology.
            // Add a default "cluster0" in each socket/package.
            let cluster_node = fdt.begin_node("cluster0")?;

            for core_idx in 0..cores_per_package {
                let core_name = format!("core{core_idx:x}");
                let core_node = fdt.begin_node(&core_name)?;

                for thread_idx in 0..threads_per_core {
                    let thread_name = format!("thread{thread_idx:x}");
                    let thread_node = fdt.begin_node(&thread_name)?;
                    let cpu_idx = threads_per_core * cores_per_package * package_idx
                        + threads_per_core * core_idx
                        + thread_idx;
                    fdt.property_u32("cpu", cpu_idx as u32 + FIRST_VCPU_PHANDLE)?;
                    fdt.end_node(thread_node)?;
                }

                fdt.end_node(core_node)?;
            }
            fdt.end_node(cluster_node)?;
            fdt.end_node(package_node)?;
        }
        fdt.end_node(cpu_map_node)?;
    } else {
        debug!("Boot using device tree, CPU topology is not (correctly) specified");
    }

    fdt.end_node(cpus_node)?;

    Ok(())
}

fn create_memory_node(
    fdt: &mut FdtWriter,
    guest_mem: &GuestMemoryMmap,
    numa_nodes: &NumaNodes,
) -> FdtWriterResult<()> {
    // See https://github.com/torvalds/linux/blob/58ae0b51506802713aa0e9956d1853ba4c722c98/Documentation/devicetree/bindings/numa.txt
    // for NUMA setting in memory node.
    let has_generic_initiator = numa_nodes.values().any(|node| node.device_id.is_some());
    if has_generic_initiator {
        info!("Skipping NUMA memory node encoding in FDT with Generic Initiator devices");
    }
    // Skipping NUMA encoding in FDT when Generic Initiator devices
    // are present allowed guest kernels to boot and
    // rely solely on ACPI tables to setup NUMA
    if numa_nodes.len() > 1 && !has_generic_initiator {
        for numa_node_idx in 0..numa_nodes.len() {
            let numa_node = numa_nodes.get(&(numa_node_idx as u32));
            let mut mem_reg_prop: Vec<u64> = Vec::new();
            let mut node_memory_addr: u64 = 0;
            // Each memory zone of numa will have its own memory node, but
            // different numa nodes should not share same memory zones.
            for memory_region in numa_node.unwrap().memory_regions.iter() {
                let memory_region_start_addr: u64 = memory_region.start_addr().raw_value();
                let memory_region_size: u64 = memory_region.size() as u64;
                mem_reg_prop.push(memory_region_start_addr);
                mem_reg_prop.push(memory_region_size);
                // Set the node address the first non-zero region address
                if node_memory_addr == 0 {
                    node_memory_addr = memory_region_start_addr;
                }
            }
            // Only create a memory node if this NUMA node has memory regions
            if !mem_reg_prop.is_empty() {
                let memory_node_name = format!("memory@{node_memory_addr:x}");
                let memory_node = fdt.begin_node(&memory_node_name)?;
                fdt.property_string("device_type", "memory")?;
                fdt.property_array_u64("reg", &mem_reg_prop)?;
                fdt.property_u32("numa-node-id", numa_node_idx as u32)?;
                fdt.end_node(memory_node)?;
            }
        }
    } else {
        // Note: memory regions from "GuestMemoryBackend" are sorted and non-zero sized.
        let ram_regions = {
            let mut ram_regions = Vec::new();
            let mut current_start = guest_mem
                .iter()
                .next()
                .map(GuestMemoryRegion::start_addr)
                .expect("GuestMemoryBackend must have one memory region at least")
                .raw_value();
            let mut current_end = current_start;

            for (start, size) in guest_mem
                .iter()
                .map(|m| (m.start_addr().raw_value(), m.len()))
            {
                if current_end == start {
                    // This zone is continuous with the previous one.
                    current_end += size;
                } else {
                    ram_regions.push((current_start, current_end));

                    current_start = start;
                    current_end = start + size;
                }
            }

            ram_regions.push((current_start, current_end));

            ram_regions
        };

        if ram_regions.len() > 2 {
            panic!(
                "There should be up to two non-continuous regions, divided by the
                    gap at the end of 32bit address space."
            );
        }

        // Create the memory node for memory region before the gap
        {
            let (first_region_start, first_region_end) = ram_regions
                .first()
                .expect("There should be at last one memory region");
            let ram_start = super::layout::RAM_START.raw_value();
            let mem_32bit_reserved_start = super::layout::MEM_32BIT_RESERVED_START.raw_value();

            if !((first_region_start <= &ram_start)
                && (first_region_end > &ram_start)
                && (first_region_end <= &mem_32bit_reserved_start))
            {
                panic!(
                    "Unexpected first memory region layout: (start: 0x{first_region_start:08x}, end: 0x{first_region_end:08x}).
                    ram_start: 0x{ram_start:08x}, mem_32bit_reserved_start: 0x{mem_32bit_reserved_start:08x}"
                );
            }

            let mem_size = first_region_end - ram_start;
            let mem_reg_prop = [ram_start, mem_size];
            let memory_node_name = format!("memory@{ram_start:x}");
            let memory_node = fdt.begin_node(&memory_node_name)?;
            fdt.property_string("device_type", "memory")?;
            fdt.property_array_u64("reg", &mem_reg_prop)?;
            fdt.end_node(memory_node)?;
        }

        // Create the memory map entry for memory region after the gap if any
        if let Some((second_region_start, second_region_end)) = ram_regions.get(1) {
            let ram_64bit_start = super::layout::RAM_64BIT_START.raw_value();

            if second_region_start != &ram_64bit_start {
                panic!(
                    "Unexpected second memory region layout: start: 0x{second_region_start:08x}, ram_64bit_start: 0x{ram_64bit_start:08x}"
                );
            }

            let mem_size = second_region_end - ram_64bit_start;
            let mem_reg_prop = [ram_64bit_start, mem_size];
            let memory_node_name = format!("memory@{ram_64bit_start:x}");
            let memory_node = fdt.begin_node(&memory_node_name)?;
            fdt.property_string("device_type", "memory")?;
            fdt.property_array_u64("reg", &mem_reg_prop)?;
            fdt.end_node(memory_node)?;
        }
    }

    Ok(())
}

fn create_chosen_node(
    fdt: &mut FdtWriter,
    cmdline: &str,
    initrd: &Option<InitramfsConfig>,
    guest_mem: &GuestMemoryMmap,
) -> FdtWriterResult<()> {
    let chosen_node = fdt.begin_node("chosen")?;
    fdt.property_string("bootargs", cmdline)?;

    if let Some(initrd_config) = initrd {
        let initrd_start = initrd_config.address.raw_value();
        let initrd_end = initrd_config.address.raw_value() + initrd_config.size as u64;
        fdt.property_u64("linux,initrd-start", initrd_start)?;
        fdt.property_u64("linux,initrd-end", initrd_end)?;
    }

    // Advertise stub UEFI System Table and EFI Memory Map so the Linux kernel's
    // `early_init_dt_scan_chosen()` -> `efi_init()` path discovers ACPI (RSDP)
    // and SMBIOS 3.0 tables during direct `--kernel` boot without UEFI firmware.
    let num_mmap_entries = build_efi_mmap_descriptors(guest_mem).len() as u32;
    let desc_size = size_of::<EfiMemoryDescriptor>() as u32;
    fdt.property_u64(
        "linux,uefi-system-table",
        super::layout::UEFI_SYSTAB_START.0,
    )?;
    fdt.property_u64("linux,uefi-mmap-start", super::layout::UEFI_MMAP_START.0)?;
    fdt.property_u32("linux,uefi-mmap-size", num_mmap_entries * desc_size)?;
    fdt.property_u32("linux,uefi-mmap-desc-size", desc_size)?;
    fdt.property_u32("linux,uefi-mmap-desc-ver", EFI_MEMORY_DESCRIPTOR_VERSION)?;

    fdt.end_node(chosen_node)?;

    Ok(())
}

fn create_gic_node(fdt: &mut FdtWriter, gic_device: &Arc<Mutex<dyn Vgic>>) -> FdtWriterResult<()> {
    let gic_reg_prop = gic_device.lock().unwrap().device_properties();

    let intc_node = fdt.begin_node("intc")?;

    fdt.property_string("compatible", gic_device.lock().unwrap().fdt_compatibility())?;
    fdt.property_null("interrupt-controller")?;
    // "interrupt-cells" field specifies the number of cells needed to encode an
    // interrupt source. The type shall be a <u32> and the value shall be 3 if no PPI affinity description
    // is required.
    fdt.property_u32("#interrupt-cells", 3)?;
    fdt.property_array_u64("reg", &gic_reg_prop)?;
    fdt.property_u32("phandle", GIC_PHANDLE)?;
    fdt.property_u32("#address-cells", 2)?;
    fdt.property_u32("#size-cells", 2)?;
    fdt.property_null("ranges")?;

    let gic_intr_prop = [
        GIC_FDT_IRQ_TYPE_PPI,
        gic_device.lock().unwrap().fdt_maint_irq(),
        IRQ_TYPE_LEVEL_HI,
    ];
    fdt.property_array_u32("interrupts", &gic_intr_prop)?;

    if gic_device.lock().unwrap().msi_compatible() {
        let msic_node = fdt.begin_node("msic")?;
        let msi_compatibility = gic_device.lock().unwrap().msi_compatibility().to_string();

        fdt.property_string("compatible", msi_compatibility.as_str())?;
        fdt.property_null("msi-controller")?;
        fdt.property_u32("phandle", MSI_PHANDLE)?;
        let msi_reg_prop = gic_device.lock().unwrap().msi_properties();
        fdt.property_array_u64("reg", &msi_reg_prop)?;

        if msi_compatibility == GIC_V2M_COMPATIBLE {
            fdt.property_u32("arm,msi-base-spi", GICV2M_SPI_BASE)?;
            fdt.property_u32("arm,msi-num-spis", GICV2M_SPI_NUM)?;
        }

        fdt.end_node(msic_node)?;
    }

    fdt.end_node(intc_node)?;

    Ok(())
}

fn create_clock_node(fdt: &mut FdtWriter) -> FdtWriterResult<()> {
    // The Advanced Peripheral Bus (APB) is part of the Advanced Microcontroller Bus Architecture
    // (AMBA) protocol family. It defines a low-cost interface that is optimized for minimal power
    // consumption and reduced interface complexity.
    // PCLK is the clock source and this node defines exactly the clock for the APB.
    let clock_node = fdt.begin_node("apb-pclk")?;
    fdt.property_string("compatible", "fixed-clock")?;
    fdt.property_u32("#clock-cells", 0x0)?;
    fdt.property_u32("clock-frequency", 24000000)?;
    fdt.property_string("clock-output-names", "clk24mhz")?;
    fdt.property_u32("phandle", CLOCK_PHANDLE)?;
    fdt.end_node(clock_node)?;

    Ok(())
}

fn create_timer_node(fdt: &mut FdtWriter) -> FdtWriterResult<()> {
    // See
    // https://github.com/torvalds/linux/blob/master/Documentation/devicetree/bindings/timer/arm%2Carch_timer.yaml
    // These are fixed interrupt numbers for the timer device.
    let irqs = [
        AARCH64_ARCH_TIMER_PHYS_SECURE_IRQ,
        AARCH64_ARCH_TIMER_PHYS_NONSECURE_IRQ,
        AARCH64_ARCH_TIMER_VIRT_IRQ,
        AARCH64_ARCH_TIMER_HYP_IRQ,
    ];
    let compatible = "arm,armv8-timer";

    let mut timer_reg_cells: Vec<u32> = Vec::new();
    for &irq in irqs.iter() {
        timer_reg_cells.push(GIC_FDT_IRQ_TYPE_PPI);
        timer_reg_cells.push(irq);
        timer_reg_cells.push(IRQ_TYPE_LEVEL_HI);
    }

    let timer_node = fdt.begin_node("timer")?;
    fdt.property_string("compatible", compatible)?;
    fdt.property_null("always-on")?;
    fdt.property_array_u32("interrupts", &timer_reg_cells)?;
    fdt.end_node(timer_node)?;

    Ok(())
}

fn create_psci_node(fdt: &mut FdtWriter) -> FdtWriterResult<()> {
    let compatible = "arm,psci-0.2";
    let psci_node = fdt.begin_node("psci")?;
    fdt.property_string("compatible", compatible)?;
    // Two methods available: hvc and smc.
    // As per documentation, PSCI calls between a guest and hypervisor may use the HVC conduit instead of SMC.
    // So, since we are using kvm, we need to use hvc.
    fdt.property_string("method", "hvc")?;
    fdt.end_node(psci_node)?;

    Ok(())
}

fn create_virtio_node<T: DeviceInfoForFdt + Clone + Debug>(
    fdt: &mut FdtWriter,
    dev_info: &T,
) -> FdtWriterResult<()> {
    let device_reg_prop = [dev_info.addr(), dev_info.length()];
    let irq = [GIC_FDT_IRQ_TYPE_SPI, dev_info.irq(), IRQ_TYPE_EDGE_RISING];

    let virtio_node = fdt.begin_node(&format!("virtio_mmio@{:x}", dev_info.addr()))?;
    fdt.property_string("compatible", "virtio,mmio")?;
    fdt.property_array_u64("reg", &device_reg_prop)?;
    fdt.property_array_u32("interrupts", &irq)?;
    fdt.property_u32("interrupt-parent", GIC_PHANDLE)?;
    fdt.end_node(virtio_node)?;

    Ok(())
}

fn create_serial_node<T: DeviceInfoForFdt + Clone + Debug>(
    fdt: &mut FdtWriter,
    dev_info: &T,
) -> FdtWriterResult<()> {
    let compatible = b"arm,pl011\0arm,primecell\0";
    let serial_reg_prop = [dev_info.addr(), dev_info.length()];
    let irq = [
        GIC_FDT_IRQ_TYPE_SPI,
        dev_info.irq() - IRQ_BASE,
        IRQ_TYPE_EDGE_RISING,
    ];

    let serial_node = fdt.begin_node(&format!("pl011@{:x}", dev_info.addr()))?;
    fdt.property("compatible", compatible)?;
    fdt.property_array_u64("reg", &serial_reg_prop)?;
    fdt.property_u32("clocks", CLOCK_PHANDLE)?;
    fdt.property_string("clock-names", "apb_pclk")?;
    fdt.property_array_u32("interrupts", &irq)?;
    fdt.end_node(serial_node)?;

    Ok(())
}

fn create_rtc_node<T: DeviceInfoForFdt + Clone + Debug>(
    fdt: &mut FdtWriter,
    dev_info: &T,
) -> FdtWriterResult<()> {
    let compatible = b"arm,pl031\0arm,primecell\0";
    let rtc_reg_prop = [dev_info.addr(), dev_info.length()];
    let irq = [
        GIC_FDT_IRQ_TYPE_SPI,
        dev_info.irq() - IRQ_BASE,
        IRQ_TYPE_LEVEL_HI,
    ];

    let rtc_node = fdt.begin_node(&format!("rtc@{:x}", dev_info.addr()))?;
    fdt.property("compatible", compatible)?;
    fdt.property_array_u64("reg", &rtc_reg_prop)?;
    fdt.property_array_u32("interrupts", &irq)?;
    fdt.property_u32("clocks", CLOCK_PHANDLE)?;
    fdt.property_string("clock-names", "apb_pclk")?;
    fdt.end_node(rtc_node)?;

    Ok(())
}

fn create_gpio_node<T: DeviceInfoForFdt + Clone + Debug>(
    fdt: &mut FdtWriter,
    dev_info: &T,
) -> FdtWriterResult<()> {
    // PL061 GPIO controller node
    let compatible = b"arm,pl061\0arm,primecell\0";
    let gpio_reg_prop = [dev_info.addr(), dev_info.length()];
    let irq = [
        GIC_FDT_IRQ_TYPE_SPI,
        dev_info.irq() - IRQ_BASE,
        IRQ_TYPE_EDGE_RISING,
    ];

    let gpio_node = fdt.begin_node(&format!("pl061@{:x}", dev_info.addr()))?;
    fdt.property("compatible", compatible)?;
    fdt.property_array_u64("reg", &gpio_reg_prop)?;
    fdt.property_array_u32("interrupts", &irq)?;
    fdt.property_null("gpio-controller")?;
    fdt.property_u32("#gpio-cells", 2)?;
    fdt.property_u32("clocks", CLOCK_PHANDLE)?;
    fdt.property_string("clock-names", "apb_pclk")?;
    fdt.property_u32("phandle", GPIO_PHANDLE)?;
    fdt.end_node(gpio_node)?;

    // gpio-keys node
    let gpio_keys_node = fdt.begin_node("gpio-keys")?;
    fdt.property_string("compatible", "gpio-keys")?;
    fdt.property_u32("#size-cells", 0)?;
    fdt.property_u32("#address-cells", 1)?;
    let gpio_keys_poweroff_node = fdt.begin_node("button@1")?;
    fdt.property_string("label", "GPIO Key Poweroff")?;
    fdt.property_u32("linux,code", KEY_POWER)?;
    let gpios = [GPIO_PHANDLE, 3, 0];
    fdt.property_array_u32("gpios", &gpios)?;
    fdt.end_node(gpio_keys_poweroff_node)?;
    fdt.end_node(gpio_keys_node)?;

    Ok(())
}

// https://www.kernel.org/doc/Documentation/devicetree/bindings/arm/fw-cfg.txt
#[cfg(feature = "fw_cfg")]
fn create_fw_cfg_node<T: DeviceInfoForFdt + Clone + Debug>(
    fdt: &mut FdtWriter,
    dev_info: &T,
) -> FdtWriterResult<()> {
    // FwCfg node
    let fw_cfg_node = fdt.begin_node(&format!("fw-cfg@{:x}", dev_info.addr()))?;
    fdt.property("compatible", b"qemu,fw-cfg-mmio\0")?;
    fdt.property_array_u64("reg", &[dev_info.addr(), dev_info.length()])?;
    fdt.property_null("dma-coherent")?;
    fdt.end_node(fw_cfg_node)?;

    Ok(())
}

fn create_devices_node<T: DeviceInfoForFdt + Clone + Debug, S: BuildHasher>(
    fdt: &mut FdtWriter,
    dev_info: &HashMap<(DeviceType, String), T, S>,
) -> FdtWriterResult<()> {
    // Create one temp Vec to store all virtio devices
    let mut ordered_virtio_device: Vec<&T> = Vec::new();

    for ((device_type, _device_id), info) in dev_info {
        match device_type {
            DeviceType::Gpio => create_gpio_node(fdt, info)?,
            DeviceType::Rtc => create_rtc_node(fdt, info)?,
            DeviceType::Serial => create_serial_node(fdt, info)?,
            DeviceType::Virtio(_) => {
                ordered_virtio_device.push(info);
            }
            #[cfg(feature = "fw_cfg")]
            DeviceType::FwCfg => create_fw_cfg_node(fdt, info)?,
        }
    }

    // Sort out virtio devices by address from low to high and insert them into fdt table.
    ordered_virtio_device.sort_by_key(|&a| a.addr());
    // Current address allocation strategy in cloud-hypervisor is: the first created device
    // will be allocated to higher address. Here we reverse the vector to make sure that
    // the older created device will appear in front of the newer created device in FDT.
    ordered_virtio_device.reverse();
    for ordered_device_info in ordered_virtio_device.drain(..) {
        create_virtio_node(fdt, ordered_device_info)?;
    }

    Ok(())
}

fn create_pmu_node(fdt: &mut FdtWriter) -> FdtWriterResult<()> {
    let compatible = "arm,armv8-pmuv3";
    let irq = [
        GIC_FDT_IRQ_TYPE_PPI,
        AARCH64_PMU_PPI_INDEX,
        IRQ_TYPE_LEVEL_HI,
    ];

    let pmu_node = fdt.begin_node("pmu")?;
    fdt.property_string("compatible", compatible)?;
    fdt.property_array_u32("interrupts", &irq)?;
    fdt.end_node(pmu_node)?;
    Ok(())
}

fn create_pci_nodes(
    fdt: &mut FdtWriter,
    pci_device_info: &[PciSpaceInfo],
    virtio_iommu_bdf: Option<u32>,
) -> FdtWriterResult<()> {
    // Add node for PCIe controller.
    // See Documentation/devicetree/bindings/pci/host-generic-pci.txt in the kernel
    // and https://elinux.org/Device_Tree_Usage.
    // In multiple PCI segments setup, each PCI segment needs a PCI node.
    for pci_device_info_elem in pci_device_info.iter() {
        // EDK2 requires the PCIe high space above 4G address.
        // The actual space in CLH follows the RAM. If the RAM space is small, the PCIe high space
        // could fall below 4G.
        // Here we cut off PCI device space below 8G in FDT to workaround the EDK2 check.
        // But the address written in ACPI is not impacted.
        let (pci_device_base_64bit, pci_device_size_64bit) =
            if pci_device_info_elem.pci_device_space_start < PCI_HIGH_BASE.raw_value() {
                (
                    PCI_HIGH_BASE.raw_value(),
                    pci_device_info_elem.pci_device_space_size
                        - (PCI_HIGH_BASE.raw_value() - pci_device_info_elem.pci_device_space_start),
                )
            } else {
                (
                    pci_device_info_elem.pci_device_space_start,
                    pci_device_info_elem.pci_device_space_size,
                )
            };
        // There is no specific requirement of the 32bit MMIO range, and
        // therefore at least we can make these ranges 4K aligned.
        let pci_device_size_32bit: u64 =
            MEM_32BIT_DEVICES_SIZE / ((1 << 12) * pci_device_info.len() as u64) * (1 << 12);
        let pci_device_base_32bit: u64 = MEM_32BIT_DEVICES_START.0
            + pci_device_size_32bit * pci_device_info_elem.pci_segment_id as u64;

        let ranges = [
            // io addresses. Since AArch64 will not use IO address,
            // we can set the same IO address range for every segment.
            0x1000000,
            0_u32,
            0_u32,
            (MEM_PCI_IO_START.0 >> 32) as u32,
            MEM_PCI_IO_START.0 as u32,
            (MEM_PCI_IO_SIZE >> 32) as u32,
            MEM_PCI_IO_SIZE as u32,
            // mmio addresses
            0x2000000,                            // (ss = 10: 32-bit memory space)
            (pci_device_base_32bit >> 32) as u32, // PCI address
            pci_device_base_32bit as u32,
            (pci_device_base_32bit >> 32) as u32, // CPU address
            pci_device_base_32bit as u32,
            (pci_device_size_32bit >> 32) as u32, // size
            pci_device_size_32bit as u32,
            // device addresses
            0x3000000,                            // (ss = 11: 64-bit memory space)
            (pci_device_base_64bit >> 32) as u32, // PCI address
            pci_device_base_64bit as u32,
            (pci_device_base_64bit >> 32) as u32, // CPU address
            pci_device_base_64bit as u32,
            (pci_device_size_64bit >> 32) as u32, // size
            pci_device_size_64bit as u32,
        ];
        let bus_range = [0, 0]; // Only bus 0
        let reg = [
            pci_device_info_elem.mmio_config_address,
            PCI_MMIO_CONFIG_SIZE_PER_SEGMENT,
        ];
        // See kernel document Documentation/devicetree/bindings/pci/pci-msi.txt
        let msi_map = [
            // rid-base: A single cell describing the first RID matched by the entry.
            0x0,
            // msi-controller: A single phandle to an MSI controller.
            MSI_PHANDLE,
            // msi-base: An msi-specifier describing the msi-specifier produced for the
            // first RID matched by the entry.
            (pci_device_info_elem.pci_segment_id as u32) << 8,
            // length: A single cell describing how many consecutive RIDs are matched
            // following the rid-base.
            0x100,
        ];

        let pci_node_name = format!("pci@{:x}", pci_device_info_elem.mmio_config_address);
        let pci_node = fdt.begin_node(&pci_node_name)?;

        fdt.property_string("compatible", "pci-host-ecam-generic")?;
        fdt.property_string("device_type", "pci")?;
        fdt.property_array_u32("ranges", &ranges)?;
        fdt.property_array_u32("bus-range", &bus_range)?;
        fdt.property_u32(
            "linux,pci-domain",
            pci_device_info_elem.pci_segment_id as u32,
        )?;
        fdt.property_u32("#address-cells", 3)?;
        fdt.property_u32("#size-cells", 2)?;
        fdt.property_array_u64("reg", &reg)?;
        fdt.property_u32("#interrupt-cells", 1)?;
        fdt.property_null("interrupt-map")?;
        fdt.property_null("interrupt-map-mask")?;
        fdt.property_null("dma-coherent")?;
        fdt.property_array_u32("msi-map", &msi_map)?;
        fdt.property_u32("msi-parent", MSI_PHANDLE)?;

        if pci_device_info_elem.pci_segment_id == 0
            && let Some(virtio_iommu_bdf) = virtio_iommu_bdf
        {
            // See kernel document Documentation/devicetree/bindings/pci/pci-iommu.txt
            // for 'iommu-map' attribute setting.
            let iommu_map = [
                0_u32,
                VIRTIO_IOMMU_PHANDLE,
                0_u32,
                virtio_iommu_bdf,
                virtio_iommu_bdf + 1,
                VIRTIO_IOMMU_PHANDLE,
                virtio_iommu_bdf + 1,
                0xffff - virtio_iommu_bdf,
            ];
            fdt.property_array_u32("iommu-map", &iommu_map)?;

            // See kernel document Documentation/devicetree/bindings/virtio/iommu.txt
            // for virtio-iommu node settings.
            let virtio_iommu_node_name = format!("virtio_iommu@{virtio_iommu_bdf:x}");
            let virtio_iommu_node = fdt.begin_node(&virtio_iommu_node_name)?;
            fdt.property_u32("#iommu-cells", 1)?;
            fdt.property_string("compatible", "virtio,pci-iommu")?;

            // 'reg' is a five-cell address encoded as
            // (phys.hi phys.mid phys.lo size.hi size.lo). phys.hi should contain the
            // device's BDF as 0b00000000 bbbbbbbb dddddfff 00000000. The other cells
            // should be zero.
            let reg = [virtio_iommu_bdf << 8, 0_u32, 0_u32, 0_u32, 0_u32];
            fdt.property_array_u32("reg", &reg)?;
            fdt.property_u32("phandle", VIRTIO_IOMMU_PHANDLE)?;

            fdt.end_node(virtio_iommu_node)?;
        }

        fdt.end_node(pci_node)?;
    }

    Ok(())
}

fn create_distance_map_node(fdt: &mut FdtWriter, numa_nodes: &NumaNodes) -> FdtWriterResult<()> {
    // When Generic Initiator nodes are present, skip ALL FDT NUMA information.
    // Let ACPI (which supports Generic Initiator via SRAT Type 5) handle the entire NUMA topology.
    // FDT cannot represent Generic Initiator nodes, and mixing FDT + ACPI NUMA info causes conflicts.
    let has_generic_initiator = numa_nodes.values().any(|node| node.device_id.is_some());
    if has_generic_initiator {
        info!("Skipping NUMA distance map encoding in FDT with Generic Initiator devices");
        return Ok(());
    }
    // At this point, we know there are no Generic Initiator nodes
    let mut numa_ids: Vec<u32> = numa_nodes.keys().cloned().collect();

    // If we only have one node, no distance map is needed
    if numa_ids.len() <= 1 {
        return Ok(());
    }

    let distance_map_node = fdt.begin_node("distance-map")?;
    fdt.property_string("compatible", "numa-distance-map-v1")?;
    // Construct the distance matrix.
    // 1. We use the word entry to describe a distance from a node to
    // its destination, e.g. 0 -> 1 = 20 is described as <0 1 20>.
    // 2. Each entry represents distance from first node to second node.
    // The distances are equal in either direction.
    // 3. The distance from a node to self (local distance) is represented
    // with value 10 and all internode distance should be represented with
    // a value greater than 10.
    // 4. distance-matrix should have entries in lexicographical ascending
    // order of nodes.
    numa_ids.sort_unstable(); // lexicographical order
    let mut distance_matrix = Vec::new();
    // Iterate over actual numa IDs instead of 0..len()
    for numa_id in numa_ids.iter() {
        let numa_node = &numa_nodes[numa_id];
        for dest_numa_id in numa_ids.iter() {
            if *numa_id == *dest_numa_id {
                distance_matrix.push(*numa_id);
                distance_matrix.push(*dest_numa_id);
                distance_matrix.push(10_u32);
                continue;
            }

            distance_matrix.push(*numa_id);
            distance_matrix.push(*dest_numa_id);
            // Use user-specified distance, checking both directions for symmetry
            let distance = if let Some(&dist) = numa_node.distances.get(dest_numa_id) {
                // Forward direction: current node -> dest node
                dist
            } else if let Some(dest_node) = numa_nodes.get(dest_numa_id) {
                // Reverse direction for symmetry: dest node -> current node
                dest_node.distances.get(numa_id).copied().unwrap_or(20)
            } else {
                // Default distance when neither direction is specified
                20
            };
            distance_matrix.push(distance as u32);
        }
    }
    fdt.property_array_u32("distance-matrix", distance_matrix.as_ref())?;
    fdt.end_node(distance_map_node)?;

    Ok(())
}

// Parse the DTB binary and print for debugging
pub fn print_fdt(dtb: &[u8]) {
    match fdt_parser::Fdt::new(dtb) {
        Ok(fdt) => {
            if let Some(root) = fdt.find_node("/") {
                debug!("Printing the FDT:");
                print_node(root, 0);
            } else {
                debug!("Failed to find root node in FDT for debugging.");
            }
        }
        Err(_) => debug!("Failed to parse FDT for debugging."),
    }
}

fn print_node(node: FdtNode<'_, '_>, n_spaces: usize) {
    debug!("{:indent$}{}/", "", node.name, indent = n_spaces);
    for property in node.properties() {
        let name = property.name;

        // If the property is 'compatible', its value requires special handling.
        // The u8 array could contain multiple null-terminated strings.
        // We copy the original array and simply replace all 'null' characters with spaces.
        let value = if name == "compatible" {
            let mut compatible = vec![0u8; 256];
            let handled_value = property
                .value
                .iter()
                .map(|&c| if c == 0 { b' ' } else { c })
                .collect::<Vec<_>>();
            let len = cmp::min(255, handled_value.len());
            compatible[..len].copy_from_slice(&handled_value[..len]);
            compatible[..(len + 1)].to_vec()
        } else {
            property.value.to_vec()
        };
        let value = &value;

        // Now the value can be either:
        //   - A null-terminated C string, or
        //   - Binary data
        // We follow a very simple logic to present the value:
        //   - At first, try to convert it to CStr and print,
        //   - If failed, print it as u32 array.
        let value_result = match CStr::from_bytes_with_nul(value) {
            Ok(value_cstr) => value_cstr.to_str().ok(),
            Err(_e) => None,
        };

        if let Some(value_str) = value_result {
            debug!(
                "{:indent$}{} : {:#?}",
                "",
                name,
                value_str,
                indent = (n_spaces + 2)
            );
        } else {
            let mut array = Vec::with_capacity(256);
            array.resize(value.len() / 4, 0u32);
            BigEndian::read_u32_into(value, &mut array);
            debug!(
                "{:indent$}{} : {:X?}",
                "",
                name,
                array,
                indent = (n_spaces + 2)
            );
        }
    }

    // Print children nodes if there is any
    for child in node.children() {
        print_node(child, n_spaces + 2);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::NumaNode;

    // Helper function to create a simple NumaNode for testing
    fn create_test_numa_node(cpus: Vec<u32>, device_id: Option<String>) -> NumaNode {
        NumaNode {
            memory_regions: Vec::new(),
            hotplug_regions: Vec::new(),
            cpus,
            pci_segments: Vec::new(),
            distances: BTreeMap::new(),
            memory_zones: Vec::new(),
            device_id,
        }
    }

    #[test]
    fn test_fdt_generic_initiator_detection_and_skip() {
        // No Generic Initiator - should not skip FDT NUMA
        let mut numa_nodes = BTreeMap::new();
        numa_nodes.insert(0, create_test_numa_node(vec![0, 1], None));
        numa_nodes.insert(1, create_test_numa_node(vec![2, 3], None));

        let has_gi = numa_nodes.values().any(|node| node.device_id.is_some());
        assert!(
            !has_gi,
            "Should not detect Generic Initiator when none present"
        );

        // One Generic Initiator - should skip FDT NUMA
        let mut numa_nodes = BTreeMap::new();
        numa_nodes.insert(0, create_test_numa_node(vec![0, 1], None));
        numa_nodes.insert(1, create_test_numa_node(vec![], Some("vfio0".to_string())));

        let has_gi = numa_nodes.values().any(|node| node.device_id.is_some());
        assert!(has_gi, "Should detect Generic Initiator when present");

        let mut fdt = FdtWriter::new().unwrap();
        let result = create_distance_map_node(&mut fdt, &numa_nodes);
        assert!(result.is_ok(), "Should skip distance map when GI present");

        // Multiple Generic Initiators - should skip FDT NUMA
        let mut numa_nodes = BTreeMap::new();
        numa_nodes.insert(0, create_test_numa_node(vec![0, 1], None));
        numa_nodes.insert(1, create_test_numa_node(vec![], Some("vfio0".to_string())));
        numa_nodes.insert(2, create_test_numa_node(vec![], Some("vfio1".to_string())));

        let has_gi = numa_nodes.values().any(|node| node.device_id.is_some());
        assert!(has_gi, "Should detect multiple Generic Initiators");
    }

    #[test]
    fn test_fdt_distance_map() {
        // Single NUMA node - should skip distance map
        let mut numa_nodes = BTreeMap::new();
        numa_nodes.insert(0, create_test_numa_node(vec![0, 1], None));

        let mut fdt = FdtWriter::new().unwrap();
        let result = create_distance_map_node(&mut fdt, &numa_nodes);
        assert!(result.is_ok(), "Should skip distance map for single node");

        // Empty NUMA nodes - should handle gracefully
        let numa_nodes = BTreeMap::new();
        let mut fdt = FdtWriter::new().unwrap();
        let result = create_distance_map_node(&mut fdt, &numa_nodes);
        assert!(result.is_ok(), "Should handle empty NUMA nodes");

        // Non-contiguous NUMA IDs (0, 2, 5) with distance symmetry
        let mut numa_nodes = BTreeMap::new();

        let mut node0 = create_test_numa_node(vec![0], None);
        node0.distances.insert(2, 20);
        // node0 has no explicit distance to node5

        let mut node2 = create_test_numa_node(vec![1], None);
        node2.distances.insert(0, 20);
        node2.distances.insert(5, 25);

        let mut node5 = create_test_numa_node(vec![2], None);
        node5.distances.insert(0, 30);
        node5.distances.insert(2, 25);
        // node5->node0 (should be used for node0->node5)

        numa_nodes.insert(0, node0);
        numa_nodes.insert(2, node2);
        numa_nodes.insert(5, node5);

        // Verify IDs are sorted lexicographically
        let mut numa_ids: Vec<u32> = numa_nodes.keys().cloned().collect();
        numa_ids.sort_unstable();
        assert_eq!(numa_ids, vec![0, 2, 5]);

        let mut fdt = FdtWriter::new().unwrap();
        let result = create_distance_map_node(&mut fdt, &numa_nodes);
        assert!(
            result.is_ok(),
            "Should handle non-contiguous IDs and symmetry"
        );

        // Default distance (20) when no distance specified in either direction
        let mut numa_nodes = BTreeMap::new();
        numa_nodes.insert(0, create_test_numa_node(vec![0], None));
        numa_nodes.insert(1, create_test_numa_node(vec![1], None));
        // Neither node has distance to the other

        let mut fdt = FdtWriter::new().unwrap();
        let result = create_distance_map_node(&mut fdt, &numa_nodes);
        assert!(result.is_ok(), "Should default to 20 for missing distances");
    }

    #[test]
    fn test_chosen_node_uefi_properties() {
        let ram_start = super::super::layout::RAM_START;
        let guest_mem = GuestMemoryMmap::from_ranges(&[(ram_start, 64 << 20)]).unwrap();

        let mut fdt = FdtWriter::new().unwrap();
        let root = fdt.begin_node("").unwrap();
        create_chosen_node(&mut fdt, "console=ttyAMA0", &None, &guest_mem).unwrap();
        fdt.end_node(root).unwrap();
        let fdt_bytes = fdt.finish().unwrap();

        let parsed = fdt_parser::Fdt::new(&fdt_bytes).unwrap();
        let chosen = parsed
            .find_node("/chosen")
            .expect("/chosen node must exist");

        let systab_prop = chosen
            .property("linux,uefi-system-table")
            .expect("linux,uefi-system-table must exist");
        assert_eq!(
            BigEndian::read_u64(systab_prop.value),
            super::super::layout::UEFI_SYSTAB_START.0
        );

        let mmap_start_prop = chosen
            .property("linux,uefi-mmap-start")
            .expect("linux,uefi-mmap-start must exist");
        assert_eq!(
            BigEndian::read_u64(mmap_start_prop.value),
            super::super::layout::UEFI_MMAP_START.0
        );

        let desc_size_prop = chosen
            .property("linux,uefi-mmap-desc-size")
            .expect("linux,uefi-mmap-desc-size must exist");
        let desc_size = BigEndian::read_u32(desc_size_prop.value);
        assert_eq!(desc_size, size_of::<EfiMemoryDescriptor>() as u32);

        let desc_ver_prop = chosen
            .property("linux,uefi-mmap-desc-ver")
            .expect("linux,uefi-mmap-desc-ver must exist");
        assert_eq!(
            BigEndian::read_u32(desc_ver_prop.value),
            EFI_MEMORY_DESCRIPTOR_VERSION
        );

        let mmap_size_prop = chosen
            .property("linux,uefi-mmap-size")
            .expect("linux,uefi-mmap-size must exist");
        // 2 reserved descriptors + 1 conventional RAM descriptor = 3 descriptors
        assert_eq!(BigEndian::read_u32(mmap_size_prop.value), 3 * desc_size);
    }

    #[test]
    fn test_write_fdt_to_memory_uefi_tables() {
        let ram_start = super::super::layout::RAM_START;
        let ram_size: usize = 64 << 20; // 64 MiB
        let guest_mem = GuestMemoryMmap::from_ranges(&[(ram_start, ram_size)]).unwrap();

        let dummy_fdt = [0xd0, 0x0d, 0xfe, 0xed];
        write_fdt_to_memory(&dummy_fdt, &guest_mem).unwrap();

        // 1. Verify EFI System Table at UEFI_SYSTAB_START (0x401f_0000)
        let mut systab: EfiSystemTable = guest_mem
            .read_obj(super::super::layout::UEFI_SYSTAB_START)
            .unwrap();
        assert_eq!(systab.hdr.signature, EFI_SYSTEM_TABLE_SIGNATURE);
        assert_eq!(systab.hdr.revision, EFI_2_80_SYSTEM_TABLE_REVISION);
        assert_eq!(systab.hdr.header_size as usize, size_of::<EfiSystemTable>());
        assert_eq!(
            systab.firmware_vendor,
            super::super::layout::UEFI_FW_VENDOR_START.0
        );
        assert_eq!(systab.number_of_table_entries, 3);
        assert_eq!(
            systab.configuration_table,
            super::super::layout::UEFI_CONFIG_TABLE_START.0
        );

        // Verify IEEE 802.3 CRC32 checksum of EfiSystemTable
        let recorded_crc = systab.hdr.crc32;
        assert_ne!(recorded_crc, 0);
        systab.hdr.crc32 = 0;
        let computed_crc = efi_crc32(systab.as_slice());
        assert_eq!(recorded_crc, computed_crc);

        // 2. Verify UCS-2 Firmware Vendor string ("Cloud Hypervisor\0")
        let expected_utf16: Vec<u16> = "Cloud Hypervisor\0".encode_utf16().collect();
        for (i, expected_ch) in expected_utf16.iter().enumerate() {
            let ch: u16 = guest_mem
                .read_obj(GuestAddress(
                    super::super::layout::UEFI_FW_VENDOR_START.0 + (i as u64) * 2,
                ))
                .unwrap();
            assert_eq!(ch, *expected_ch);
        }

        // 3. Verify EFI Configuration Table entries (ACPI 2.0, SMBIOS 3.0, RT Properties)
        let entry_size = size_of::<EfiConfigurationTable>() as u64;
        let cfg0: EfiConfigurationTable = guest_mem
            .read_obj(super::super::layout::UEFI_CONFIG_TABLE_START)
            .unwrap();
        assert_eq!(cfg0.vendor_guid, EFI_ACPI_20_TABLE_GUID);
        assert_eq!(cfg0.vendor_table, super::super::layout::RSDP_POINTER.0);

        let cfg1: EfiConfigurationTable = guest_mem
            .read_obj(GuestAddress(
                super::super::layout::UEFI_CONFIG_TABLE_START.0 + entry_size,
            ))
            .unwrap();
        assert_eq!(cfg1.vendor_guid, SMBIOS3_TABLE_GUID);
        assert_eq!(cfg1.vendor_table, super::super::layout::SMBIOS_START.0);

        let cfg2: EfiConfigurationTable = guest_mem
            .read_obj(GuestAddress(
                super::super::layout::UEFI_CONFIG_TABLE_START.0 + 2 * entry_size,
            ))
            .unwrap();
        assert_eq!(cfg2.vendor_guid, EFI_RT_PROPERTIES_TABLE_GUID);
        assert_eq!(
            cfg2.vendor_table,
            super::super::layout::UEFI_RT_PROP_START.0
        );

        // 4. Verify EFI RT Properties Table
        let rt_prop: EfiRtPropertiesTable = guest_mem
            .read_obj(super::super::layout::UEFI_RT_PROP_START)
            .unwrap();
        assert_eq!(rt_prop.version, EFI_RT_PROPERTIES_TABLE_VERSION);
        assert_eq!(rt_prop.length as usize, size_of::<EfiRtPropertiesTable>());
        assert_eq!(rt_prop.runtime_services_supported, 0);

        // 5. Verify EFI Memory Map descriptors at UEFI_MMAP_START (0x401f_1000)
        let desc_size = size_of::<EfiMemoryDescriptor>() as u64;
        let desc0: EfiMemoryDescriptor = guest_mem
            .read_obj(super::super::layout::UEFI_MMAP_START)
            .unwrap();
        assert_eq!(desc0.r#type, EFI_RESERVED_MEMORY_TYPE);
        assert_eq!(desc0.physical_start, super::super::layout::FDT_START.0);
        assert_eq!(
            desc0.number_of_pages,
            (super::super::layout::ACPI_START.0 - super::super::layout::FDT_START.0)
                / EFI_PAGE_SIZE
        );
        assert_eq!(desc0.attribute, EFI_MEMORY_WB);

        let desc1: EfiMemoryDescriptor = guest_mem
            .read_obj(GuestAddress(
                super::super::layout::UEFI_MMAP_START.0 + desc_size,
            ))
            .unwrap();
        assert_eq!(desc1.r#type, EFI_RESERVED_MEMORY_TYPE);
        assert_eq!(desc1.physical_start, super::super::layout::ACPI_START.0);
        assert_eq!(
            desc1.number_of_pages,
            (super::super::layout::KERNEL_START.0 - super::super::layout::ACPI_START.0)
                / EFI_PAGE_SIZE
        );
        assert_eq!(desc1.attribute, EFI_MEMORY_WB);

        let desc2: EfiMemoryDescriptor = guest_mem
            .read_obj(GuestAddress(
                super::super::layout::UEFI_MMAP_START.0 + 2 * desc_size,
            ))
            .unwrap();
        assert_eq!(desc2.r#type, EFI_CONVENTIONAL_MEMORY);
        assert_eq!(desc2.physical_start, super::super::layout::KERNEL_START.0);
        assert_eq!(
            desc2.number_of_pages,
            ((ram_start.0 + ram_size as u64) - super::super::layout::KERNEL_START.0)
                / EFI_PAGE_SIZE
        );
        assert_eq!(desc2.attribute, EFI_MEMORY_WB);

        // 6. Verify oversized FDT is rejected before overwriting UEFI_SYSTAB_START
        let oversized_fdt = vec![0u8; (super::super::layout::FDT_MAX_SIZE as usize) + 1];
        let err = write_fdt_to_memory(&oversized_fdt, &guest_mem).unwrap_err();
        assert!(matches!(err, Error::FdtTooLarge(_, _)));
    }
}
