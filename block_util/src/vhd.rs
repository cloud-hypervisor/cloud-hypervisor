// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryInto;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

#[derive(Clone, Copy)]
pub struct VhdFooter {
    cookie: u64,
    features: u32,
    file_format_version: u32,
    data_offset: u64,
    time_stamp: u32,
    creator_application: u32,
    creator_version: u32,
    creator_host_os: u32,
    original_size: u64,
    current_size: u64,
    disk_geometry: u32,
    disk_type: u32,
    checksum: u32,
    unique_id: u128,
    saved_state: u8,
}

impl VhdFooter {
    pub fn new(file: &mut File) -> std::io::Result<VhdFooter> {
        // We must create a buffer aligned on 512 bytes with a size being a
        // multiple of 512 bytes as the file might be opened with O_DIRECT flag.
        #[repr(align(512))]
        struct Sector {
            data: [u8; 512],
        }
        let mut s = Sector { data: [0; 512] };

        // Place the cursor 512 bytes before the end of the file, as this is
        // where the footer starts.
        file.seek(SeekFrom::End(-512))?;

        // Fill in the VhdFooter structure
        file.read_exact(&mut s.data)?;

        Ok(VhdFooter {
            cookie: u64::from_be_bytes(s.data[0..8].try_into().unwrap()),
            features: u32::from_be_bytes(s.data[8..12].try_into().unwrap()),
            file_format_version: u32::from_be_bytes(s.data[12..16].try_into().unwrap()),
            data_offset: u64::from_be_bytes(s.data[16..24].try_into().unwrap()),
            time_stamp: u32::from_be_bytes(s.data[24..28].try_into().unwrap()),
            creator_application: u32::from_be_bytes(s.data[28..32].try_into().unwrap()),
            creator_version: u32::from_be_bytes(s.data[32..36].try_into().unwrap()),
            creator_host_os: u32::from_be_bytes(s.data[36..40].try_into().unwrap()),
            original_size: u64::from_be_bytes(s.data[40..48].try_into().unwrap()),
            current_size: u64::from_be_bytes(s.data[48..56].try_into().unwrap()),
            disk_geometry: u32::from_be_bytes(s.data[56..60].try_into().unwrap()),
            disk_type: u32::from_be_bytes(s.data[60..64].try_into().unwrap()),
            checksum: u32::from_be_bytes(s.data[64..68].try_into().unwrap()),
            unique_id: u128::from_be_bytes(s.data[68..84].try_into().unwrap()),
            saved_state: u8::from_be_bytes(s.data[84..85].try_into().unwrap()),
        })
    }

    pub fn cookie(&self) -> u64 {
        self.cookie
    }
    pub fn features(&self) -> u32 {
        self.features
    }
    pub fn file_format_version(&self) -> u32 {
        self.file_format_version
    }
    pub fn data_offset(&self) -> u64 {
        self.data_offset
    }
    pub fn time_stamp(&self) -> u32 {
        self.time_stamp
    }
    pub fn creator_application(&self) -> u32 {
        self.creator_application
    }
    pub fn creator_version(&self) -> u32 {
        self.creator_version
    }
    pub fn creator_host_os(&self) -> u32 {
        self.creator_host_os
    }
    pub fn original_size(&self) -> u64 {
        self.original_size
    }
    pub fn current_size(&self) -> u64 {
        self.current_size
    }
    pub fn disk_geometry(&self) -> u32 {
        self.disk_geometry
    }
    pub fn disk_type(&self) -> u32 {
        self.disk_type
    }
    pub fn checksum(&self) -> u32 {
        self.checksum
    }
    pub fn unique_id(&self) -> u128 {
        self.unique_id
    }
    pub fn saved_state(&self) -> u8 {
        self.saved_state
    }
}

/// Determine image type through file parsing.
pub fn is_fixed_vhd(f: &mut File) -> std::io::Result<bool> {
    let footer = VhdFooter::new(f)?;

    // "conectix" => 0x636f6e6563746978
    Ok(footer.cookie() == 0x636f6e6563746978
        && footer.file_format_version() == 0x0001_0000
        && footer.data_offset() == 0xffff_ffff_ffff_ffff
        && footer.disk_type() == 0x2)
}
