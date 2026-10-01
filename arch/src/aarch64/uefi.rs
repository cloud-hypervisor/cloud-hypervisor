// Copyright 2020 Arm Limited (or its affiliates). All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::{Read, Seek, SeekFrom};
use std::os::fd::AsFd;
use std::result;

use crc_any::CRCu32;
use thiserror::Error;
use uuid::Uuid;
use vm_memory::{
    ByteValued, Bytes, GuestAddress, GuestMemory, GuestMemoryBackend, GuestMemoryRegion,
};

use super::layout;
use crate::GuestMemoryMmap;

/// Errors while loading UEFI or writing boot tables.
#[derive(Debug, Error)]
pub enum Error {
    /// Unable to seek to UEFI image start.
    #[error("Unable to seek to UEFI image start")]
    SeekUefiStart,
    /// Unable to seek to UEFI image end.
    #[error("Unable to seek to UEFI image end")]
    SeekUefiEnd,
    /// UEFI image too big.
    #[error("UEFI image too big")]
    UefiTooBig,
    /// Unable to read UEFI image
    #[error("Unable to read UEFI image")]
    ReadUefiImage,
    #[error("UEFI memory map is too large")]
    MemoryMapTooLarge,
    #[error("Failed to write UEFI tables")]
    WriteTables(#[source] vm_memory::GuestMemoryError),
}
type Result<T> = result::Result<T, Error>;

pub(super) const MEMORY_MAP_START: GuestAddress = GuestAddress(layout::EFI_TABLES_START.0 + 0x1000);
pub(super) const MEMORY_DESCRIPTOR_SIZE: u32 = size_of::<MemoryDescriptor>() as u32;

const EFI_CONVENTIONAL_MEMORY: u32 = 7;
const EFI_ACPI_RECLAIM_MEMORY: u32 = 9;
const EFI_MEMORY_WB: u64 = 8;

const EFI_ACPI_20_TABLE_GUID: Uuid = Uuid::from_u128(0x8868e871_e4f1_11d3_bc22_0080c73c8881);
const EFI_SMBIOS3_TABLE_GUID: Uuid = Uuid::from_u128(0xf2fd1544_9794_4a2c_992e_e5bbcf20e394);
const EFI_RT_PROPERTIES_TABLE_GUID: Uuid = Uuid::from_u128(0xeb66918a_7eef_402a_842e_931d21c38ae9);
const LINUX_EFI_MEMRESERVE_TABLE_GUID: Uuid =
    Uuid::from_u128(0x888eb0c6_8ede_4ff5_a8f0_9aee5cb977c2);

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct SystemTable {
    signature: u64,
    revision: u32,
    header_size: u32,
    crc32: u32,
    reserved: u32,
    firmware_vendor: u64,
    firmware_revision: u32,
    padding: u32,
    console_in_handle: u64,
    console_in: u64,
    console_out_handle: u64,
    console_out: u64,
    stderr_handle: u64,
    stderr: u64,
    runtime_services: u64,
    boot_services: u64,
    number_of_table_entries: u64,
    configuration_table: u64,
}

// SAFETY: All fields are integers and the packed layout has no implicit padding.
unsafe impl ByteValued for SystemTable {}

#[repr(C)]
#[derive(Clone, Copy)]
struct ConfigurationTable {
    guid: [u8; 16],
    table: u64,
}

// SAFETY: All fields are integers and the C layout has no implicit padding.
unsafe impl ByteValued for ConfigurationTable {}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct MemoryDescriptor {
    memory_type: u32,
    padding: u32,
    physical_start: u64,
    virtual_start: u64,
    number_of_pages: u64,
    attribute: u64,
}

// SAFETY: All fields are integers and the C layout has no implicit padding.
unsafe impl ByteValued for MemoryDescriptor {}

pub(super) fn create_uefi_stub_tables(
    guest_mem: &GuestMemoryMmap,
    rsdp: GuestAddress,
) -> Result<u32> {
    let configuration_table = layout::EFI_TABLES_START.0 + size_of::<SystemTable>() as u64;
    let runtime_properties = configuration_table + 4 * size_of::<ConfigurationTable>() as u64;
    let memory_reserve = runtime_properties + 8;
    let firmware_vendor = memory_reserve + 16;
    let mut system_table = SystemTable {
        signature: 0x5453_5953_2049_4249,
        revision: (2 << 16) | 80,
        header_size: size_of::<SystemTable>() as u32,
        firmware_vendor,
        number_of_table_entries: 4,
        configuration_table,
        ..Default::default()
    };
    let mut crc32 = CRCu32::crc32();
    crc32.digest(system_table.as_slice());
    system_table.crc32 = crc32.get_crc();
    guest_mem
        .write_obj(system_table, layout::EFI_TABLES_START)
        .map_err(Error::WriteTables)?;

    for (index, table) in [
        ConfigurationTable {
            guid: EFI_ACPI_20_TABLE_GUID.to_bytes_le(),
            table: rsdp.0,
        },
        ConfigurationTable {
            guid: EFI_SMBIOS3_TABLE_GUID.to_bytes_le(),
            table: layout::SMBIOS_START.0,
        },
        ConfigurationTable {
            guid: EFI_RT_PROPERTIES_TABLE_GUID.to_bytes_le(),
            table: runtime_properties,
        },
        ConfigurationTable {
            guid: LINUX_EFI_MEMRESERVE_TABLE_GUID.to_bytes_le(),
            table: memory_reserve,
        },
    ]
    .into_iter()
    .enumerate()
    {
        guest_mem
            .write_obj(
                table,
                GuestAddress(
                    configuration_table + (index * size_of::<ConfigurationTable>()) as u64,
                ),
            )
            .map_err(Error::WriteTables)?;
    }
    // EFI_RT_PROPERTIES_TABLE: version 1, length 8, no runtime services.
    guest_mem
        .write_obj([1u16, 8, 0, 0], GuestAddress(runtime_properties))
        .map_err(Error::WriteTables)?;
    guest_mem
        .write_obj([0u64; 2], GuestAddress(memory_reserve))
        .map_err(Error::WriteTables)?;
    let vendor: Vec<u8> = "Cloud Hypervisor\0"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    guest_mem
        .write_slice(&vendor, GuestAddress(firmware_vendor))
        .map_err(Error::WriteTables)?;

    let mut memory_map = vec![MemoryDescriptor {
        memory_type: EFI_ACPI_RECLAIM_MEMORY,
        physical_start: layout::RAM_START.0,
        number_of_pages: (layout::KERNEL_START.0 - layout::RAM_START.0) >> 12,
        attribute: EFI_MEMORY_WB,
        ..Default::default()
    }];
    for region in guest_mem.iter() {
        let start = region.start_addr().0.max(layout::KERNEL_START.0);
        let end = region.start_addr().0 + region.len();
        if start < end {
            memory_map.push(MemoryDescriptor {
                memory_type: EFI_CONVENTIONAL_MEMORY,
                physical_start: start,
                number_of_pages: (end - start) >> 12,
                attribute: EFI_MEMORY_WB,
                ..Default::default()
            });
        }
    }
    let memory_map_size = memory_map.len() * size_of::<MemoryDescriptor>();
    if MEMORY_MAP_START.0 + memory_map_size as u64
        > layout::EFI_TABLES_START.0 + layout::EFI_TABLES_MAX_SIZE
    {
        return Err(Error::MemoryMapTooLarge);
    }
    for (index, descriptor) in memory_map.into_iter().enumerate() {
        guest_mem
            .write_obj(
                descriptor,
                GuestAddress(MEMORY_MAP_START.0 + (index * size_of::<MemoryDescriptor>()) as u64),
            )
            .map_err(Error::WriteTables)?;
    }
    Ok(memory_map_size as u32)
}

pub fn load_uefi<F, M: GuestMemory>(
    guest_mem: &M,
    guest_addr: GuestAddress,
    uefi_image: &mut F,
) -> Result<()>
where
    F: Read + Seek + AsFd,
{
    let uefi_size = uefi_image
        .seek(SeekFrom::End(0))
        .map_err(|_| Error::SeekUefiEnd)? as usize;

    // edk2 image on virtual platform is smaller than 3M
    if uefi_size > 0x300000 {
        return Err(Error::UefiTooBig);
    }
    uefi_image.rewind().map_err(|_| Error::SeekUefiStart)?;
    guest_mem
        .read_exact_volatile_from(guest_addr, &mut uefi_image.as_fd(), uefi_size)
        .map_err(|_| Error::ReadUefiImage)
}
