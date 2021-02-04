// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use thiserror::Error;

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
