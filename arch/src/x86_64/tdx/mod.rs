// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::str::FromStr;

use thiserror::Error;
use uuid::Uuid;
use vm_memory::{ByteValued, Bytes, GuestAddress, GuestMemoryError};

use crate::GuestMemoryMmap;

#[derive(Error, Debug)]
pub enum TdvfError {
    #[error("Failed read TDVF descriptor: {0}")]
    ReadDescriptor(#[source] std::io::Error),
    #[error("Failed read TDVF descriptor offset: {0}")]
    ReadDescriptorOffset(#[source] std::io::Error),
    #[error("Failed read GUID table: {0}")]
    ReadGuidTable(#[source] std::io::Error),
    #[error("Invalid descriptor signature")]
    InvalidDescriptorSignature,
    #[error("Invalid descriptor size")]
    InvalidDescriptorSize,
    #[error("Invalid descriptor version")]
    InvalidDescriptorVersion,
    #[error("Failed to write HOB details to guest memory: {0}")]
    GuestMemoryWriteHob(#[source] GuestMemoryError),
    #[error("Failed to create Uuid: {0}")]
    UuidCreation(#[source] uuid::Error),
}

const TABLE_FOOTER_GUID: &str = "96b582de-1fb2-45f7-baea-a366c55a082d";
const TDVF_METADATA_OFFSET_GUID: &str = "e47a6535-984a-4798-865e-4685a7bf8ec2";

// TDVF_DESCRIPTOR
#[repr(C, packed)]
#[derive(Default)]
pub struct TdvfDescriptor {
    signature: [u8; 4],
    length: u32,
    version: u32,
    num_sections: u32, // NumberOfSectionEntry
}

// TDVF_SECTION
#[repr(C, packed)]
#[derive(Clone, Copy, Default, Debug)]
pub struct TdvfSection {
    pub data_offset: u32,
    pub data_size: u32, // RawDataSize
    pub address: u64,   // MemoryAddress
    pub size: u64,      // MemoryDataSize
    pub r#type: TdvfSectionType,
    pub attributes: u32,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Default)]
pub enum TdvfSectionType {
    Bfv,
    Cfv,
    TdHob,
    TempMem,
    PermMem,
    Payload,
    PayloadParam,
    #[default]
    Reserved = 0xffffffff,
}

fn tdvf_descriptor_offset(file: &mut File) -> Result<(SeekFrom, bool), TdvfError> {
    // Let's first try to identify the presence of the table footer GUID
    file.seek(SeekFrom::End(-0x30))
        .map_err(TdvfError::ReadGuidTable)?;
    let mut table_footer_guid: [u8; 16] = [0; 16];
    file.read_exact(&mut table_footer_guid)
        .map_err(TdvfError::ReadGuidTable)?;
    let uuid =
        Uuid::from_slice_le(table_footer_guid.as_slice()).map_err(TdvfError::UuidCreation)?;
    let expected_uuid = Uuid::from_str(TABLE_FOOTER_GUID).map_err(TdvfError::UuidCreation)?;
    if uuid == expected_uuid {
        // Retrieve the table size
        file.seek(SeekFrom::End(-0x32))
            .map_err(TdvfError::ReadGuidTable)?;
        let mut table_size: [u8; 2] = [0; 2];
        file.read_exact(&mut table_size)
            .map_err(TdvfError::ReadGuidTable)?;
        let table_size = u16::from_le_bytes(table_size) as usize;
        let mut table: Vec<u8> = vec![0; table_size];

        // Read the entire table
        file.seek(SeekFrom::End(-(table_size as i64 + 0x20)))
            .map_err(TdvfError::ReadGuidTable)?;
        file.read_exact(table.as_mut_slice())
            .map_err(TdvfError::ReadGuidTable)?;

        // Let's start from the top and go backward down the table.
        // We start after the footer GUID and the table length.
        let mut offset = table_size - 18;

        debug!("Parsing GUID structure");
        while offset >= 18 {
            let entry_uuid = Uuid::from_slice_le(&table[offset - 16..offset])
                .map_err(TdvfError::UuidCreation)?;
            let entry_size =
                u16::from_le_bytes(table[offset - 18..offset - 16].try_into().unwrap()) as usize;
            debug!(
                "Entry GUID = {}, size = {}",
                entry_uuid.hyphenated().to_string(),
                entry_size
            );

            // Avoid going through an infinite loop if the entry size is 0
            if entry_size == 0 {
                break;
            }

            offset -= entry_size;

            let expected_uuid =
                Uuid::from_str(TDVF_METADATA_OFFSET_GUID).map_err(TdvfError::UuidCreation)?;
            if entry_uuid == expected_uuid && entry_size == 22 {
                return Ok((
                    SeekFrom::End(
                        -(u32::from_le_bytes(table[offset..offset + 4].try_into().unwrap()) as i64),
                    ),
                    true,
                ));
            }
        }
    }

    // If we end up here, this means the firmware doesn't support the new way
    // of exposing the TDVF descriptor offset through the table of GUIDs.
    // That's why we fallback onto the deprecated method.

    // The 32-bit offset to the TDVF metadata is located 32 bytes from
    // the end of the file.
    // See "TDVF Metadata Pointer" in "TDX Virtual Firmware Design Guide
    file.seek(SeekFrom::End(-0x20))
        .map_err(TdvfError::ReadDescriptorOffset)?;

    let mut descriptor_offset: [u8; 4] = [0; 4];
    file.read_exact(&mut descriptor_offset)
        .map_err(TdvfError::ReadDescriptorOffset)?;

    Ok((
        SeekFrom::Start(u32::from_le_bytes(descriptor_offset) as u64),
        false,
    ))
}

pub fn parse_tdvf_sections(file: &mut File) -> Result<(Vec<TdvfSection>, bool), TdvfError> {
    let (descriptor_offset, guid_found) = tdvf_descriptor_offset(file)?;

    file.seek(descriptor_offset)
        .map_err(TdvfError::ReadDescriptor)?;

    let mut descriptor: TdvfDescriptor = Default::default();
    // SAFETY: we read exactly the size of the descriptor header
    file.read_exact(unsafe {
        std::slice::from_raw_parts_mut(
            &mut descriptor as *mut _ as *mut u8,
            std::mem::size_of::<TdvfDescriptor>(),
        )
    })
    .map_err(TdvfError::ReadDescriptor)?;

    if &descriptor.signature != b"TDVF" {
        return Err(TdvfError::InvalidDescriptorSignature);
    }

    if descriptor.length as usize
        != std::mem::size_of::<TdvfDescriptor>()
            + std::mem::size_of::<TdvfSection>() * descriptor.num_sections as usize
    {
        return Err(TdvfError::InvalidDescriptorSize);
    }

    if descriptor.version != 1 {
        return Err(TdvfError::InvalidDescriptorVersion);
    }

    let mut sections = Vec::new();
    sections.resize_with(descriptor.num_sections as usize, TdvfSection::default);

    // SAFETY: we read exactly the advertised sections
    file.read_exact(unsafe {
        std::slice::from_raw_parts_mut(
            sections.as_mut_ptr() as *mut u8,
            descriptor.num_sections as usize * std::mem::size_of::<TdvfSection>(),
        )
    })
    .map_err(TdvfError::ReadDescriptor)?;

    Ok((sections, guid_found))
}

#[repr(u16)]
#[derive(Copy, Clone, Debug, Default)]
enum HobType {
    Handoff = 0x1,
    ResourceDescriptor = 0x3,
    GuidExtension = 0x4,
    #[default]
    Unused = 0xfffe,
    EndOfHobList = 0xffff,
}

#[repr(C, packed)]
#[derive(Copy, Clone, Default, Debug)]
struct HobHeader {
    r#type: HobType,
    length: u16,
    reserved: u32,
}

#[repr(C, packed)]
#[derive(Copy, Clone, Default, Debug)]
struct HobHandoffInfoTable {
    header: HobHeader,
    version: u32,
    boot_mode: u32,
    efi_memory_top: u64,
    efi_memory_bottom: u64,
    efi_free_memory_top: u64,
    efi_free_memory_bottom: u64,
    efi_end_of_hob_list: u64,
}

#[repr(C, packed)]
#[derive(Copy, Clone, Default, Debug)]
struct EfiGuid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[repr(C, packed)]
#[derive(Copy, Clone, Default, Debug)]
struct HobResourceDescriptor {
    header: HobHeader,
    owner: EfiGuid,
    resource_type: u32,
    resource_attribute: u32,
    physical_start: u64,
    resource_length: u64,
}

#[repr(C, packed)]
#[derive(Copy, Clone, Default, Debug)]
struct HobGuidType {
    header: HobHeader,
    name: EfiGuid,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Default)]
pub enum PayloadImageType {
    #[default]
    ExecutablePayload,
    BzImage,
    RawVmLinux,
}

#[repr(C, packed)]
#[derive(Copy, Clone, Default, Debug)]
pub struct PayloadInfo {
    pub image_type: PayloadImageType,
    pub entry_point: u64,
}

#[repr(C, packed)]
#[derive(Copy, Clone, Default, Debug)]
struct TdPayload {
    guid_type: HobGuidType,
    payload_info: PayloadInfo,
}

// SAFETY: data structure only contain a series of integers
unsafe impl ByteValued for HobHeader {}
// SAFETY: data structure only contain a series of integers
unsafe impl ByteValued for HobHandoffInfoTable {}
// SAFETY: data structure only contain a series of integers
unsafe impl ByteValued for HobResourceDescriptor {}
// SAFETY: data structure only contain a series of integers
unsafe impl ByteValued for HobGuidType {}
// SAFETY: data structure only contain a series of integers
unsafe impl ByteValued for PayloadInfo {}
// SAFETY: data structure only contain a series of integers
unsafe impl ByteValued for TdPayload {}

pub struct TdHob {
    start_offset: u64,
    current_offset: u64,
}

fn align_hob(v: u64) -> u64 {
    v.div_ceil(8) * 8
}

impl TdHob {
    fn update_offset<T>(&mut self) {
        self.current_offset = align_hob(self.current_offset + std::mem::size_of::<T>() as u64)
    }

    pub fn start(offset: u64) -> TdHob {
        // Leave a gap to place the HandoffTable at the start as it can only be filled in later
        let mut hob = TdHob {
            start_offset: offset,
            current_offset: offset,
        };
        hob.update_offset::<HobHandoffInfoTable>();
        hob
    }

    pub fn finish(&mut self, mem: &GuestMemoryMmap) -> Result<(), TdvfError> {
        // Write end
        let end = HobHeader {
            r#type: HobType::EndOfHobList,
            length: std::mem::size_of::<HobHeader>() as u16,
            reserved: 0,
        };
        info!("Writing HOB end {:x} {:x?}", self.current_offset, end);
        mem.write_obj(end, GuestAddress(self.current_offset))
            .map_err(TdvfError::GuestMemoryWriteHob)?;
        self.update_offset::<HobHeader>();

        // Write handoff, delayed as it needs end of HOB list
        let efi_end_of_hob_list = self.current_offset;
        let handoff = HobHandoffInfoTable {
            header: HobHeader {
                r#type: HobType::Handoff,
                length: std::mem::size_of::<HobHandoffInfoTable>() as u16,
                reserved: 0,
            },
            version: 0x9,
            boot_mode: 0,
            efi_memory_top: 0,
            efi_memory_bottom: 0,
            efi_free_memory_top: 0,
            efi_free_memory_bottom: 0,
            efi_end_of_hob_list,
        };
        info!("Writing HOB start {:x} {:x?}", self.start_offset, handoff);
        mem.write_obj(handoff, GuestAddress(self.start_offset))
            .map_err(TdvfError::GuestMemoryWriteHob)
    }

    pub fn add_resource(
        &mut self,
        mem: &GuestMemoryMmap,
        physical_start: u64,
        resource_length: u64,
        resource_type: u32,
        resource_attribute: u32,
    ) -> Result<(), TdvfError> {
        let resource_descriptor = HobResourceDescriptor {
            header: HobHeader {
                r#type: HobType::ResourceDescriptor,
                length: std::mem::size_of::<HobResourceDescriptor>() as u16,
                reserved: 0,
            },
            owner: EfiGuid::default(),
            resource_type,
            resource_attribute,
            physical_start,
            resource_length,
        };
        info!(
            "Writing HOB resource {:x} {:x?}",
            self.current_offset, resource_descriptor
        );
        mem.write_obj(resource_descriptor, GuestAddress(self.current_offset))
            .map_err(TdvfError::GuestMemoryWriteHob)?;
        self.update_offset::<HobResourceDescriptor>();
        Ok(())
    }

    pub fn add_memory_resource(
        &mut self,
        mem: &GuestMemoryMmap,
        physical_start: u64,
        resource_length: u64,
        ram: bool,
        guid_found: bool,
    ) -> Result<(), TdvfError> {
        self.add_resource(
            mem,
            physical_start,
            resource_length,
            if ram {
                if guid_found {
                    0x7 /* EFI_RESOURCE_MEMORY_UNACCEPTED */
                } else {
                    0 /* EFI_RESOURCE_SYSTEM_MEMORY */
                }
            } else if guid_found {
                0 /* EFI_RESOURCE_SYSTEM_MEMORY */
            } else {
                0x5 /*EFI_RESOURCE_MEMORY_RESERVED */
            },
            /* TODO:
             * QEMU currently fills it in like this:
             * EFI_RESOURCE_ATTRIBUTE_PRESENT | EFI_RESOURCE_ATTRIBUTE_INITIALIZED | EFI_RESOURCE_ATTRIBUTE_TESTED
             * which differs from the spec (due to TDVF implementation issue?)
             */
            0x7,
        )
    }

    pub fn add_mmio_resource(
        &mut self,
        mem: &GuestMemoryMmap,
        physical_start: u64,
        resource_length: u64,
    ) -> Result<(), TdvfError> {
        self.add_resource(
            mem,
            physical_start,
            resource_length,
            0x1, /* EFI_RESOURCE_MEMORY_MAPPED_IO */
            /*
             * EFI_RESOURCE_ATTRIBUTE_PRESENT | EFI_RESOURCE_ATTRIBUTE_INITIALIZED | EFI_RESOURCE_ATTRIBUTE_UNCACHEABLE
             */
            0x403,
        )
    }

    pub fn add_acpi_table(
        &mut self,
        mem: &GuestMemoryMmap,
        table_content: &[u8],
    ) -> Result<(), TdvfError> {
        // We already know the HobGuidType size is 8 bytes multiple, but we
        // need the total size to be 8 bytes multiple. That is why the ACPI
        // table size must be 8 bytes multiple as well.
        let length = std::mem::size_of::<HobGuidType>() as u16
            + align_hob(table_content.len() as u64) as u16;
        let hob_guid_type = HobGuidType {
            header: HobHeader {
                r#type: HobType::GuidExtension,
                length,
                reserved: 0,
            },
            // ACPI_TABLE_HOB_GUID
            // 0x6a0c5870, 0xd4ed, 0x44f4, {0xa1, 0x35, 0xdd, 0x23, 0x8b, 0x6f, 0xc, 0x8d }
            name: EfiGuid {
                data1: 0x6a0c_5870,
                data2: 0xd4ed,
                data3: 0x44f4,
                data4: [0xa1, 0x35, 0xdd, 0x23, 0x8b, 0x6f, 0xc, 0x8d],
            },
        };
        info!(
            "Writing HOB ACPI table {:x} {:x?} {:x?}",
            self.current_offset, hob_guid_type, table_content
        );
        mem.write_obj(hob_guid_type, GuestAddress(self.current_offset))
            .map_err(TdvfError::GuestMemoryWriteHob)?;
        let current_offset = self.current_offset + std::mem::size_of::<HobGuidType>() as u64;

        // In case the table is quite large, let's make sure we can handle
        // retrying until everything has been correctly copied.
        let mut offset: usize = 0;
        loop {
            let bytes_written = mem
                .write(
                    &table_content[offset..],
                    GuestAddress(current_offset + offset as u64),
                )
                .map_err(TdvfError::GuestMemoryWriteHob)?;
            offset += bytes_written;
            if offset >= table_content.len() {
                break;
            }
        }
        self.current_offset += length as u64;

        Ok(())
    }

    pub fn add_payload(
        &mut self,
        mem: &GuestMemoryMmap,
        payload_info: PayloadInfo,
    ) -> Result<(), TdvfError> {
        let payload = TdPayload {
            guid_type: HobGuidType {
                header: HobHeader {
                    r#type: HobType::GuidExtension,
                    length: std::mem::size_of::<TdPayload>() as u16,
                    reserved: 0,
                },
                // HOB_PAYLOAD_INFO_GUID
                // 0xb96fa412, 0x461f, 0x4be3, {0x8c, 0xd, 0xad, 0x80, 0x5a, 0x49, 0x7a, 0xc0
                name: EfiGuid {
                    data1: 0xb96f_a412,
                    data2: 0x461f,
                    data3: 0x4be3,
                    data4: [0x8c, 0xd, 0xad, 0x80, 0x5a, 0x49, 0x7a, 0xc0],
                },
            },
            payload_info,
        };
        info!(
            "Writing HOB TD_PAYLOAD {:x} {:x?}",
            self.current_offset, payload
        );
        mem.write_obj(payload, GuestAddress(self.current_offset))
            .map_err(TdvfError::GuestMemoryWriteHob)?;
        self.update_offset::<TdPayload>();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn test_parse_tdvf_sections() {
        let mut f = std::fs::File::open("tdvf.fd").unwrap();
        let (sections, _) = parse_tdvf_sections(&mut f).unwrap();
        for section in sections {
            eprintln!("{section:x?}")
        }
    }
}
