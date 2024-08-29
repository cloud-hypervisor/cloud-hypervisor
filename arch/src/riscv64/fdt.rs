// Copyright © 2024, Institute of Software, CAS. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use byteorder::{BigEndian, ByteOrder};
// use hypervisor::arch::riscv64::aia::Vaia;
use std::cmp;
use std::collections::HashMap;
use std::ffi::CStr;
use std::fmt::Debug;
use std::result;
use std::str;
use std::sync::{Arc, Mutex};

use super::super::DeviceType;
use super::super::GuestMemoryMmap;
use super::super::InitramfsConfig;
use super::layout::{
    IRQ_BASE, MEM_32BIT_DEVICES_SIZE, MEM_32BIT_DEVICES_START, MEM_PCI_IO_SIZE, MEM_PCI_IO_START,
    PCI_HIGH_BASE, PCI_MMIO_CONFIG_SIZE_PER_SEGMENT,
};
use std::fs;
use std::path::Path;
use thiserror::Error;
use vm_fdt::{FdtWriter, FdtWriterResult};
use vm_memory::{Address, Bytes, GuestMemory, GuestMemoryError, GuestMemoryRegion};

const CPU_BASE_PHANDLE: u32 = 0x100;

const AIA_APLIC_PHANDLE: u32 = 2;
const AIA_IMSIC_PHANDLE: u32 = 3;
const CPU_INTC_BASE_PHANDLE: u32 = 4;
// Read the documentation specified when appending the root node to the FDT.
const ADDRESS_CELLS: u32 = 0x2;
const SIZE_CELLS: u32 = 0x2;

// From https://elixir.bootlin.com/linux/v6.10/source/include/dt-bindings/interrupt-controller/irq.h#L14
const IRQ_TYPE_EDGE_RISING: u32 = 1;
const IRQ_TYPE_LEVEL_HI: u32 = 4;

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
    WriteFdtToMemory(GuestMemoryError),
}
type Result<T> = result::Result<T, Error>;

/// Creates the flattened device tree for this riscv64 VM.
#[allow(clippy::too_many_arguments)]
pub fn create_fdt<T: DeviceInfoForFdt + Clone + Debug, S: ::std::hash::BuildHasher>(
    guest_mem: &GuestMemoryMmap,
    cmdline: &str,
    num_cpus: u32,
    vcpu_topology: Option<(u8, u8, u8)>,
    device_info: &HashMap<(DeviceType, String), T, S>,
    aia_device: &Arc<Mutex<dyn Vaia>>,
    initrd: &Option<InitramfsConfig>,
) -> FdtWriterResult<Vec<u8>> {
    // Allocate stuff necessary for storing the blob.
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
    create_cpu_nodes(&mut fdt, num_cpus, vcpu_topology)?;
    create_memory_node(&mut fdt, guest_mem)?;
    create_chosen_node(&mut fdt, cmdline, initrd)?;
    create_aia_node(&mut fdt, aia_device)?;
    create_devices_node(&mut fdt, device_info)?;

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
fn create_cpu_nodes(fdt: &mut FdtWriter, num_cpus: u32) -> Result<(), FdtError> {
    // See https://elixir.bootlin.com/linux/v6.10/source/Documentation/devicetree/bindings/riscv/cpus.yaml
    let cpus = fdt.begin_node("cpus")?;
    // As per documentation, on RISC-V 64-bit systems value should be set to 1.
    fdt.property_u32("#address-cells", 0x01)?;
    fdt.property_u32("#size-cells", 0x0)?;
    // Retrieve CPU frequency from cpu timer regs
    let timebase_frequency: u32 = 369999;
    fdt.property_u32("timebase-frequency", timebase_frequency);

    for cpu_index in 0..num_cpus {
        let cpu = fdt.begin_node(&format!("cpu@{:x}", cpu_index))?;
        fdt.property_string("device_type", "cpu")?;
        fdt.property_string("compatible", "riscv")?;
        fdt.property_string("mmy-type", "sv48")?;
        fdt.property_string("riscv,isa", "rv64iafdcsu_smaia_ssaia")?;
        fdt.property_string("status", "okay")?;
        fdt.property_u64("reg", cpu_index as u64)?;
        fdt.property_u32("phandle", CPU_BASE_PHANDLE + cpu_index)?;
        fdt.end_node(cpu)?;

        // interrupt controller node
        let intc_node = fdt.begin_node("interrupt-controller")?;
        fdt.property_string("compatible", "riscv,cpu-intc")?;
        fdt.property_u32("#interrupt-cells", 1u32)?;
        fdt.property_array_u32("interrupt-controller", &Vec::new())?;
        fdt.property_u32("phandle", CPU_INTC_BASE_PHANDLE + cpu_index)?;
        fdt.end_node(intc_node)?;
    }
    fdt.end_node(cpus)?;

    Ok(())
}

fn create_memory_node(
    fdt: &mut FdtWriter,
    guest_mem: &GuestMemoryMmap,
) -> FdtWriterResult<()> {
    unimplemented!()
}

fn create_chosen_node(
    fdt: &mut FdtWriter,
    cmdline: &str,
    initrd: &Option<InitramfsConfig>,
) -> FdtWriterResult<()> {
    unimplemented!()
}

fn create_aia_node(fdt: &mut FdtWriter, aia_device: &Arc<Mutex<dyn Vaia>>) -> FdtWriterResult<()> {
    unimplemented!()
}

fn create_virtio_node<T: DeviceInfoForFdt + Clone + Debug>(
    fdt: &mut FdtWriter,
    dev_info: &T,
) -> FdtWriterResult<()> {
    unimplemented!()
}

fn create_serial_node<T: DeviceInfoForFdt + Clone + Debug>(
    fdt: &mut FdtWriter,
    dev_info: &T,
) -> FdtWriterResult<()> {
    unimplemented!()
}

fn create_rtc_node<T: DeviceInfoForFdt + Clone + Debug>(
    fdt: &mut FdtWriter,
    dev_info: &T,
) -> FdtWriterResult<()> {
    unimplemented!()
}

fn create_devices_node<T: DeviceInfoForFdt + Clone + Debug, S: ::std::hash::BuildHasher>(
    fdt: &mut FdtWriter,
    dev_info: &HashMap<(DeviceType, String), T, S>,
) -> FdtWriterResult<()> {
    unimplemented!()
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
