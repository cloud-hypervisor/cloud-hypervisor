// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
use crate::GuestMemoryMmap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use thiserror::Error;
use vm_memory::{ByteValued, Bytes, GuestAddress, GuestMemoryError};

#[derive(Error, Debug)]
pub enum TdvfError {
    #[error("Failed read TDVF descriptor: {0}")]
    ReadDescriptor(#[source] std::io::Error),
    #[error("Failed read TDVF descriptor offset: {0}")]
    ReadDescriptorOffset(#[source] std::io::Error),
    #[error("Invalid descriptor signature")]
    InvalidDescriptorSignature,
    #[error("Invalid descriptor size")]
    InvalidDescriptorSize,
    #[error("Invalid descriptor version")]
    InvalidDescriptorVersion,
    #[error("Failed to write HOB details to guest memory: {0}")]
    GuestMemoryWriteHob(#[source] GuestMemoryError),
}

// TDVF_DESCRIPTOR
#[repr(packed)]
pub struct TdvfDescriptor {
    signature: [u8; 4],
    length: u32,
    version: u32,
    num_sections: u32, // NumberOfSectionEntry
}

// TDVF_SECTION
#[repr(packed)]
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
#[derive(Clone, Copy, Debug)]
pub enum TdvfSectionType {
    Bfv,
    Cfv,
    TdHob,
    TempMem,
    Reserved = 0xffffffff,
}

impl Default for TdvfSectionType {
    fn default() -> Self {
        TdvfSectionType::Reserved
    }
}

pub fn parse_tdvf_sections(file: &mut File) -> Result<Vec<TdvfSection>, TdvfError> {
    // The 32-bit offset to the TDVF metadata is located 32 bytes from
    // the end of the file.
    // See "TDVF Metadata Pointer" in "TDX Virtual Firmware Design Guide
    file.seek(SeekFrom::End(-0x20))
        .map_err(TdvfError::ReadDescriptorOffset)?;

    let mut descriptor_offset: [u8; 4] = [0; 4];
    file.read_exact(&mut descriptor_offset)
        .map_err(TdvfError::ReadDescriptorOffset)?;
    let descriptor_offset = u32::from_le_bytes(descriptor_offset) as u64;

    file.seek(SeekFrom::Start(descriptor_offset))
        .map_err(TdvfError::ReadDescriptor)?;

    let mut descriptor: TdvfDescriptor = unsafe { std::mem::zeroed() };
    // Safe as we read exactly the size of the descriptor header
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

    // Safe as we read exactly the advertised sections
    file.read_exact(unsafe {
        std::slice::from_raw_parts_mut(
            sections.as_mut_ptr() as *mut u8,
            descriptor.num_sections as usize * std::mem::size_of::<TdvfSection>(),
        )
    })
    .map_err(TdvfError::ReadDescriptor)?;

    Ok(sections)
}

#[repr(u16)]
#[derive(Copy, Clone, Debug)]
enum HobType {
    Handoff = 0x1,
    ResourceDescriptor = 0x3,
    Unused = 0xfffe,
    EndOfHobList = 0xffff,
}

impl Default for HobType {
    fn default() -> Self {
        HobType::Unused
    }
}

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
struct HobHeader {
    r#type: HobType,
    length: u16,
    reserved: u32,
}
unsafe impl ByteValued for HobHeader {}

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
struct HobHandoffInfoTable {
    header: HobHeader,
    version: u32,
    efi_memory_top: u64,
    efi_memory_bottom: u64,
    efi_free_memory_top: u64,
    efi_free_memory_bottom: u64,
    efi_end_of_hob_list: u64,
}
unsafe impl ByteValued for HobHandoffInfoTable {}

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
struct EfiGuid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
struct HobResourceDescriptor {
    header: HobHeader,
    owner: EfiGuid,
    resource_type: u32,
    resource_attribute: u32,
    physical_start: u64,
    resource_length: u64,
}
unsafe impl ByteValued for HobResourceDescriptor {}

pub struct TdHob {
    start_offset: u64,
    current_offset: u64,
}

fn align_hob(v: u64) -> u64 {
    (v + 7) / 8 * 8
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
    ) -> Result<(), TdvfError> {
        self.add_resource(
            mem,
            physical_start,
            resource_length,
            if ram {
                0 /* EFI_RESOURCE_SYSTEM_MEMORY */
            } else {
                0x5 /*EFI_RESOURCE_MEMORY_RESERVED */
            },
            /* TODO:
             * QEMU currently fills it in like this:
             * EFI_RESOURCE_ATTRIBUTE_PRESENT | EFI_RESOURCE_ATTRIBUTE_INITIALIZED | EFI_RESOURCE_ATTRIBUTE_ENCRYPTED | EFI_RESOURCE_ATTRIBUTE_TESTED
             * which differs from the spec (due to TDVF implementation issue?)
             */
            0x04000007,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn test_parse_tdvf_sections() {
        let mut f = std::fs::File::open("tdvf.fd").unwrap();
        let sections = parse_tdvf_sections(&mut f).unwrap();
        for section in sections {
            eprintln!("{:x?}", section)
        }
    }
}
