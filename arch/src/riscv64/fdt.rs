// Copyright © 2024 Institute of Software, CAS. All rights reserved.
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
use std::sync::{Arc, Mutex};
use std::{cmp, result, str};

use byteorder::{BigEndian, ByteOrder};
use hypervisor::arch::riscv64::aia::Vaia;
use thiserror::Error;
use vm_fdt::{FdtWriter, FdtWriterResult};
use vm_memory::{Address, Bytes, GuestMemory, GuestMemoryError, GuestMemoryRegion};

use super::super::{DeviceType, GuestMemoryMmap, InitramfsConfig};
use super::layout::{
    IRQ_BASE, MEM_32BIT_DEVICES_SIZE, MEM_32BIT_DEVICES_START, MEM_PCI_IO_SIZE, MEM_PCI_IO_START,
    PCI_HIGH_BASE, PCI_MMIO_CONFIG_SIZE_PER_SEGMENT,
};
use crate::PciSpaceInfo;

const AIA_APLIC_PHANDLE: u32 = 1;
const AIA_IMSIC_PHANDLE: u32 = 2;
const CPU_INTC_BASE_PHANDLE: u32 = 3;
const CPU_BASE_PHANDLE: u32 = 256 + CPU_INTC_BASE_PHANDLE;
// Read the documentation specified when appending the root node to the FDT.
const ADDRESS_CELLS: u32 = 0x2;
const SIZE_CELLS: u32 = 0x2;

// From https://elixir.bootlin.com/linux/v6.10/source/include/dt-bindings/interrupt-controller/irq.h#L14
const _IRQ_TYPE_EDGE_RISING: u32 = 1;
const IRQ_TYPE_LEVEL_HI: u32 = 4;

const S_MODE_EXT_IRQ: u32 = 9;

/// Trait for devices to be added to the Flattened Device Tree.
pub trait DeviceInfoForFdt {
    /// Returns the address where this device will be loaded.
    fn addr(&self) -> u64;
    /// Returns the associated interrupt for this device.
    fn irq(&self) -> u32;
    /// Returns the amount of memory that needs to be reserved for this device.
    fn length(&self) -> u64;
}

/// Errors thrown while configuring the Flattened Device Tree for riscv64.
#[derive(Debug, Error)]
pub enum Error {
    /// Failure in writing FDT in memory.
    #[error("Failure in writing FDT in memory: {0}")]
    WriteFdtToMemory(#[source] GuestMemoryError),
}
type Result<T> = result::Result<T, Error>;

/// Creates the flattened device tree for this riscv64 VM.
#[allow(clippy::too_many_arguments)]
pub fn create_fdt<T: DeviceInfoForFdt + Clone + Debug, S: ::std::hash::BuildHasher>(
    guest_mem: &GuestMemoryMmap,
    cmdline: &str,
    num_vcpu: u32,
    device_info: &HashMap<(DeviceType, String), T, S>,
    aia_device: &Arc<Mutex<dyn Vaia>>,
    initrd: &Option<InitramfsConfig>,
    pci_space_info: &[PciSpaceInfo],
) -> FdtWriterResult<Vec<u8>> {
    // Allocate stuff necessary for the holding the blob.
    let mut fdt = FdtWriter::new()?;

    // For an explanation why these nodes were introduced in the blob take a look at
    // https://github.com/devicetree-org/devicetree-specification/releases/tag/v0.4
    // In chapter 3.

    // Header or the root node as per above mentioned documentation.
    let root_node = fdt.begin_node("")?;
    fdt.property_string("compatible", "linux,dummy-virt")?;
    // For info on #address-cells and size-cells resort to Table 3.1 Root Node
    // Properties
    fdt.property_u32("#address-cells", ADDRESS_CELLS)?;
    fdt.property_u32("#size-cells", SIZE_CELLS)?;
    create_cpu_nodes(&mut fdt, num_vcpu)?;
    create_memory_node(&mut fdt, guest_mem)?;
    create_chosen_node(&mut fdt, cmdline, initrd)?;
    create_aia_node(&mut fdt, aia_device)?;
    create_devices_node(&mut fdt, device_info)?;
    create_pci_nodes(&mut fdt, pci_space_info)?;

    // End Header node.
    fdt.end_node(root_node)?;

    let fdt_final = fdt.finish()?;

    Ok(fdt_final)
}

pub fn write_fdt_to_memory(fdt_final: Vec<u8>, guest_mem: &GuestMemoryMmap) -> Result<()> {
    // Write FDT to memory.
    guest_mem
        .write_slice(fdt_final.as_slice(), super::layout::FDT_START)
        .map_err(Error::WriteFdtToMemory)?;
    Ok(())
}

// Following are the auxiliary function for creating the different nodes that we append to our FDT.
fn create_cpu_nodes(fdt: &mut FdtWriter, num_cpus: u32) -> FdtWriterResult<()> {
    // See https://elixir.bootlin.com/linux/v6.10/source/Documentation/devicetree/bindings/riscv/cpus.yaml
    let cpus = fdt.begin_node("cpus")?;
    // As per documentation, on RISC-V 64-bit systems value should be set to 1.
    fdt.property_u32("#address-cells", 0x01)?;
    fdt.property_u32("#size-cells", 0x0)?;
    // TODO: Retrieve CPU frequency from cpu timer regs
    let timebase_frequency: u32 = 0x989680;
    fdt.property_u32("timebase-frequency", timebase_frequency)?;

    for cpu_index in 0..num_cpus {
        let cpu = fdt.begin_node(&format!("cpu@{:x}", cpu_index))?;
        fdt.property_string("device_type", "cpu")?;
        fdt.property_string("compatible", "riscv")?;
        fdt.property_string("mmu-type", "sv48")?;
        fdt.property_string("riscv,isa", "rv64imafdc_smaia_ssaia")?;
        fdt.property_string("status", "okay")?;
        fdt.property_u32("reg", cpu_index)?;
        fdt.property_u32("phandle", CPU_BASE_PHANDLE + cpu_index)?;

        // interrupt controller node
        let intc_node = fdt.begin_node("interrupt-controller")?;
        fdt.property_string("compatible", "riscv,cpu-intc")?;
        fdt.property_u32("#interrupt-cells", 1u32)?;
        fdt.property_null("interrupt-controller")?;
        fdt.property_u32("phandle", CPU_INTC_BASE_PHANDLE + cpu_index)?;
        fdt.end_node(intc_node)?;

        fdt.end_node(cpu)?;
    }

    fdt.end_node(cpus)?;

    Ok(())
}

fn create_memory_node(fdt: &mut FdtWriter, guest_mem: &GuestMemoryMmap) -> FdtWriterResult<()> {
    // Note: memory regions from "GuestMemory" are sorted and non-zero sized.
    let ram_regions = {
        let mut ram_regions = Vec::new();
        let mut current_start = guest_mem
            .iter()
            .next()
            .map(GuestMemoryRegion::start_addr)
            .expect("GuestMemory must have one memory region at least")
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

    let mut mem_reg_property = Vec::new();
    for region in ram_regions {
        let mem_size = region.1 - region.0;
        mem_reg_property.push(region.0);
        mem_reg_property.push(mem_size);
    }

    let ram_start = super::layout::RAM_START.raw_value();
    let memory_node_name = format!("memory@{:x}", ram_start);
    let memory_node = fdt.begin_node(&memory_node_name)?;
    fdt.property_string("device_type", "memory")?;
    fdt.property_array_u64("reg", &mem_reg_property)?;
    fdt.end_node(memory_node)?;

    Ok(())
}

fn create_chosen_node(
    fdt: &mut FdtWriter,
    cmdline: &str,
    initrd: &Option<InitramfsConfig>,
) -> FdtWriterResult<()> {
    let chosen_node = fdt.begin_node("chosen")?;
    fdt.property_string("bootargs", cmdline)?;

    if let Some(initrd_config) = initrd {
        let initrd_start = initrd_config.address.raw_value();
        let initrd_end = initrd_config.address.raw_value() + initrd_config.size as u64;
        fdt.property_u64("linux,initrd-start", initrd_start)?;
        fdt.property_u64("linux,initrd-end", initrd_end)?;
    }

    fdt.end_node(chosen_node)?;

    Ok(())
}

fn create_aia_node(fdt: &mut FdtWriter, aia_device: &Arc<Mutex<dyn Vaia>>) -> FdtWriterResult<()> {
    // IMSIC
    if aia_device.lock().unwrap().msi_compatible() {
        use super::layout::IMSIC_START;
        let imsic_name = format!("imsics@{:x}", IMSIC_START.0);
        let imsic_node = fdt.begin_node(&imsic_name)?;

        fdt.property_string(
            "compatible",
            aia_device.lock().unwrap().imsic_compatibility(),
        )?;
        let imsic_reg_prop = aia_device.lock().unwrap().imsic_properties();
        fdt.property_array_u32("reg", &imsic_reg_prop)?;
        fdt.property_u32("#interrupt-cells", 0u32)?;
        fdt.property_null("interrupt-controller")?;
        fdt.property_null("msi-controller")?;
        // TODO complete num-ids
        fdt.property_u32("riscv,num-ids", 2047u32)?;
        fdt.property_u32("phandle", AIA_IMSIC_PHANDLE)?;

        let mut irq_cells = Vec::new();
        let num_cpus = aia_device.lock().unwrap().vcpu_count();
        for i in 0..num_cpus {
            irq_cells.push(CPU_INTC_BASE_PHANDLE + i);
            irq_cells.push(S_MODE_EXT_IRQ);
        }
        fdt.property_array_u32("interrupts-extended", &irq_cells)?;

        fdt.end_node(imsic_node)?;
    }

    // APLIC
    use super::layout::APLIC_START;
    let aplic_name = format!("aplic@{:x}", APLIC_START.0);
    let aplic_node = fdt.begin_node(&aplic_name)?;

    fdt.property_string(
        "compatible",
        aia_device.lock().unwrap().aplic_compatibility(),
    )?;
    let reg_cells = aia_device.lock().unwrap().aplic_properties();
    fdt.property_array_u32("reg", &reg_cells)?;
    fdt.property_u32("#interrupt-cells", 2u32)?;
    fdt.property_null("interrupt-controller")?;
    // TODO complete num-srcs
    fdt.property_u32("riscv,num-sources", 96u32)?;
    fdt.property_u32("phandle", AIA_APLIC_PHANDLE)?;
    fdt.property_u32("msi-parent", AIA_IMSIC_PHANDLE)?;

    fdt.end_node(aplic_node)?;

    Ok(())
}

fn create_serial_node<T: DeviceInfoForFdt + Clone + Debug>(
    fdt: &mut FdtWriter,
    dev_info: &T,
) -> FdtWriterResult<()> {
    let serial_reg_prop = [dev_info.addr(), dev_info.length()];
    let irq = [dev_info.irq() - IRQ_BASE, IRQ_TYPE_LEVEL_HI];

    let serial_node = fdt.begin_node(&format!("serial@{:x}", dev_info.addr()))?;
    fdt.property_string("compatible", "ns16550a")?;
    fdt.property_array_u64("reg", &serial_reg_prop)?;
    fdt.property_u32("clock-frequency", 3686400)?;
    fdt.property_u32("interrupt-parent", AIA_APLIC_PHANDLE)?;
    fdt.property_array_u32("interrupts", &irq)?;
    fdt.end_node(serial_node)?;

    Ok(())
}

fn create_devices_node<T: DeviceInfoForFdt + Clone + Debug, S: ::std::hash::BuildHasher>(
    fdt: &mut FdtWriter,
    dev_info: &HashMap<(DeviceType, String), T, S>,
) -> FdtWriterResult<()> {
    for ((device_type, _device_id), info) in dev_info {
        match device_type {
            DeviceType::Serial => create_serial_node(fdt, info)?,
            DeviceType::Virtio(_) => unreachable!(),
        }
    }

    Ok(())
}

fn create_pci_nodes(fdt: &mut FdtWriter, pci_device_info: &[PciSpaceInfo]) -> FdtWriterResult<()> {
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
            AIA_IMSIC_PHANDLE,
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
        fdt.property_u32("msi-parent", AIA_IMSIC_PHANDLE)?;

        fdt.end_node(pci_node)?;
    }

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

fn print_node(node: fdt_parser::node::FdtNode<'_, '_>, n_spaces: usize) {
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
            Ok(value_cstr) => match value_cstr.to_str() {
                Ok(value_str) => Some(value_str),
                Err(_e) => None,
            },
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
        };
    }

    // Print children nodes if there is any
    for child in node.children() {
        print_node(child, n_spaces + 2);
    }
}
