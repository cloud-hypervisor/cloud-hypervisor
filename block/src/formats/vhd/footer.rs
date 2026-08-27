// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io;
use std::ops::Range;
use std::os::unix::fs::FileExt;

use crate::{AlignedFile, query_device_size};

/// A VHD footer occupies the last sector of the file.
pub(super) const VHD_FOOTER_LEN: u64 = 512;

/// "conectix", the cookie every hard disk footer begins with.
const VHD_COOKIE: u64 = 0x636f_6e65_6374_6978;

/// The only file format version the specification defines: 1.0.
const VHD_FILE_FORMAT_VERSION: u32 = 0x0001_0000;

/// A fixed image has no dynamic disk header, so its data offset is
/// 0xFFFFFFFFFFFFFFFF.
const VHD_FIXED_DATA_OFFSET: u64 = 0xffff_ffff_ffff_ffff;

/// Disk type 2 is a fixed hard disk (3 is dynamic, 4 differencing).
const VHD_DISK_TYPE_FIXED: u32 = 2;

/// The checksum field, at offset 64, covers the whole footer.
const VHD_CHECKSUM_RANGE: Range<usize> = 64..68;

/// The footer checksum: the one's complement of the sum of the footer
/// bytes with the checksum field itself taken as zero.
fn footer_checksum(sector: &[u8; VHD_FOOTER_LEN as usize]) -> u32 {
    let sum = sector
        .iter()
        .enumerate()
        .filter(|(i, _)| !VHD_CHECKSUM_RANGE.contains(i))
        .fold(0u32, |acc, (_, b)| acc.wrapping_add(u32::from(*b)));

    !sum
}

/// Build a 512 byte footer from `template`, zero padded, carrying the
/// checksum the specification defines for it.
#[cfg(test)]
pub(super) fn checksummed_footer(template: &[u8]) -> Vec<u8> {
    let mut sector = [0u8; VHD_FOOTER_LEN as usize];
    sector[..template.len()].copy_from_slice(template);
    let checksum = footer_checksum(&sector);
    sector[VHD_CHECKSUM_RANGE].copy_from_slice(&checksum.to_be_bytes());

    sector.to_vec()
}

// Production code uses: cookie, file_format_version, data_offset,
// current_size, disk_type. The remaining fields are parsed for VHD
// spec completeness and exercised only by unit tests.
#[derive(Clone, Copy)]
#[cfg_attr(not(test), expect(dead_code))]
pub(super) struct VhdFooter {
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
    computed_checksum: u32,
    unique_id: u128,
    saved_state: u8,
}

impl VhdFooter {
    pub(super) fn new(file: &mut File) -> io::Result<VhdFooter> {
        let aligned = AlignedFile::new(file.try_clone()?, true);
        let size = query_device_size(file)?.0;
        let footer_offset = size.checked_sub(VHD_FOOTER_LEN).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "file too small for VHD footer")
        })?;
        let mut sector = [0u8; VHD_FOOTER_LEN as usize];
        aligned.read_exact_at(&mut sector, footer_offset)?;

        Ok(VhdFooter {
            cookie: u64::from_be_bytes(sector[0..8].try_into().unwrap()),
            features: u32::from_be_bytes(sector[8..12].try_into().unwrap()),
            file_format_version: u32::from_be_bytes(sector[12..16].try_into().unwrap()),
            data_offset: u64::from_be_bytes(sector[16..24].try_into().unwrap()),
            time_stamp: u32::from_be_bytes(sector[24..28].try_into().unwrap()),
            creator_application: u32::from_be_bytes(sector[28..32].try_into().unwrap()),
            creator_version: u32::from_be_bytes(sector[32..36].try_into().unwrap()),
            creator_host_os: u32::from_be_bytes(sector[36..40].try_into().unwrap()),
            original_size: u64::from_be_bytes(sector[40..48].try_into().unwrap()),
            current_size: u64::from_be_bytes(sector[48..56].try_into().unwrap()),
            disk_geometry: u32::from_be_bytes(sector[56..60].try_into().unwrap()),
            disk_type: u32::from_be_bytes(sector[60..64].try_into().unwrap()),
            checksum: u32::from_be_bytes(sector[64..68].try_into().unwrap()),
            computed_checksum: footer_checksum(&sector),
            unique_id: u128::from_be_bytes(sector[68..84].try_into().unwrap()),
            saved_state: u8::from_be_bytes(sector[84..85].try_into().unwrap()),
        })
    }

    #[cfg(test)]
    pub fn cookie(&self) -> u64 {
        self.cookie
    }
    #[cfg(test)]
    pub fn features(&self) -> u32 {
        self.features
    }
    #[cfg(test)]
    pub fn file_format_version(&self) -> u32 {
        self.file_format_version
    }
    #[cfg(test)]
    pub fn data_offset(&self) -> u64 {
        self.data_offset
    }
    #[cfg(test)]
    pub fn time_stamp(&self) -> u32 {
        self.time_stamp
    }
    #[cfg(test)]
    pub fn creator_application(&self) -> u32 {
        self.creator_application
    }
    #[cfg(test)]
    pub fn creator_version(&self) -> u32 {
        self.creator_version
    }
    #[cfg(test)]
    pub fn creator_host_os(&self) -> u32 {
        self.creator_host_os
    }
    #[cfg(test)]
    pub fn original_size(&self) -> u64 {
        self.original_size
    }
    pub(super) fn current_size(&self) -> u64 {
        self.current_size
    }
    #[cfg(test)]
    pub fn disk_geometry(&self) -> u32 {
        self.disk_geometry
    }
    #[cfg(test)]
    pub fn disk_type(&self) -> u32 {
        self.disk_type
    }

    pub(super) fn validate_fixed(&self) -> io::Result<()> {
        fn invalid_data(msg: String) -> io::Error {
            io::Error::new(io::ErrorKind::InvalidData, msg)
        }

        if self.cookie != VHD_COOKIE {
            return Err(invalid_data(format!(
                "VHD footer cookie is {:#018x}, not \"conectix\"",
                self.cookie
            )));
        }
        if self.file_format_version != VHD_FILE_FORMAT_VERSION {
            return Err(invalid_data(format!(
                "VHD file format version is {:#010x}, not 1.0",
                self.file_format_version
            )));
        }
        if self.data_offset != VHD_FIXED_DATA_OFFSET {
            return Err(invalid_data(format!(
                "VHD data offset is {:#018x}, not the all ones a fixed image requires",
                self.data_offset
            )));
        }
        if self.disk_type != VHD_DISK_TYPE_FIXED {
            return Err(invalid_data(format!(
                "VHD disk type is {}, not 2 (fixed hard disk)",
                self.disk_type
            )));
        }
        if self.checksum != self.computed_checksum {
            return Err(invalid_data(format!(
                "VHD footer checksum is {:#010x}, computed {:#010x}",
                self.checksum, self.computed_checksum
            )));
        }

        Ok(())
    }

    #[cfg(test)]
    pub fn checksum(&self) -> u32 {
        self.checksum
    }
    #[cfg(test)]
    pub fn unique_id(&self) -> u128 {
        self.unique_id
    }
    #[cfg(test)]
    pub fn saved_state(&self) -> u8 {
        self.saved_state
    }
}

/// Returns true when the file contains a fixed VHD footer.
pub fn is_fixed_vhd(f: &mut File) -> io::Result<bool> {
    let footer = match VhdFooter::new(f) {
        Ok(footer) => footer,
        Err(e) if e.kind() == io::ErrorKind::InvalidInput => return Ok(false),
        Err(e) => return Err(e),
    };

    Ok(footer.validate_fixed().is_ok())
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{Seek, SeekFrom, Write};

    use vmm_sys_util::tempfile::TempFile;

    use super::{VhdFooter, checksummed_footer, is_fixed_vhd};

    fn valid_fixed_vhd_footer() -> Vec<u8> {
        vec![
            0x63, 0x6f, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x78, // cookie
            0x00, 0x00, 0x00, 0x02, // features
            0x00, 0x01, 0x00, 0x00, // file format version
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // data offset
            0x27, 0xa6, 0xa6, 0x5d, // time stamp
            0x71, 0x65, 0x6d, 0x75, // creator application
            0x00, 0x05, 0x00, 0x03, // creator version
            0x57, 0x69, 0x32, 0x6b, // creator host os
            0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, // original size
            0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, // current size
            0x11, 0xe0, 0x10, 0x3f, // disk geometry
            0x00, 0x00, 0x00, 0x02, // disk type
            0x00, 0x00, 0x00, 0x00, // checksum
            0x98, 0x7b, 0xb1, 0xcd, 0x84, 0x14, 0x41, 0xfc, 0xa4, 0xab, 0xd0, 0x69, 0x45, 0x2b,
            0xf2, 0x23, // unique id
            0x00, // saved state
        ]
    }

    fn valid_dynamic_vhd_footer() -> Vec<u8> {
        vec![
            0x63, 0x6f, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x78, // cookie
            0x00, 0x00, 0x00, 0x02, // features
            0x00, 0x01, 0x00, 0x00, // file format version
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // data offset
            0x27, 0xa6, 0xa6, 0x5d, // time stamp
            0x71, 0x65, 0x6d, 0x75, // creator application
            0x00, 0x05, 0x00, 0x03, // creator version
            0x57, 0x69, 0x32, 0x6b, // creator host os
            0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, // original size
            0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, // current size
            0x11, 0xe0, 0x10, 0x3f, // disk geometry
            0x00, 0x00, 0x00, 0x03, // disk type
            0x00, 0x00, 0x00, 0x00, // checksum
            0x98, 0x7b, 0xb1, 0xcd, 0x84, 0x14, 0x41, 0xfc, 0xa4, 0xab, 0xd0, 0x69, 0x45, 0x2b,
            0xf2, 0x23, // unique id
            0x00, // saved state
        ]
    }

    fn with_file<F>(footer: &[u8], mut testfn: F)
    where
        F: FnMut(File),
    {
        let mut disk_file: File = TempFile::new().unwrap().into_file();
        disk_file.set_len(0x1000_0200).unwrap();
        disk_file.seek(SeekFrom::Start(0x1000_0000)).unwrap();
        disk_file.write_all(footer).unwrap();

        testfn(disk_file); // File closed when the function exits.
    }

    #[test]
    fn test_check_vhd_footer() {
        with_file(
            &checksummed_footer(&valid_fixed_vhd_footer()),
            |mut file: File| {
                let vhd_footer = VhdFooter::new(&mut file).expect("Failed to create VHD footer");
                assert_eq!(vhd_footer.cookie(), 0x636f_6e65_6374_6978);
                assert_eq!(vhd_footer.features(), 0x0000_0002);
                assert_eq!(vhd_footer.file_format_version(), 0x0001_0000);
                assert_eq!(vhd_footer.data_offset(), 0xffff_ffff_ffff_ffff);
                assert_eq!(vhd_footer.time_stamp(), 0x27a6_a65d);
                assert_eq!(vhd_footer.creator_application(), 0x7165_6d75);
                assert_eq!(vhd_footer.creator_version(), 0x0005_0003);
                assert_eq!(vhd_footer.creator_host_os(), 0x5769_326b);
                assert_eq!(vhd_footer.original_size(), 0x0000_0000_1000_0000);
                assert_eq!(vhd_footer.current_size(), 0x0000_0000_1000_0000);
                assert_eq!(vhd_footer.disk_geometry(), 0x11e0_103f);
                assert_eq!(vhd_footer.disk_type(), 0x0000_0002);
                assert_eq!(vhd_footer.checksum(), 0xffff_e5e5);
                assert_eq!(
                    vhd_footer.unique_id(),
                    0x987b_b1cd_8414_41fc_a4ab_d069_452b_f223
                );
                assert_eq!(vhd_footer.saved_state(), 0x00);
            },
        );
    }

    #[test]
    fn test_is_fixed_vhd() {
        with_file(
            &checksummed_footer(&valid_fixed_vhd_footer()),
            |mut file: File| {
                assert!(is_fixed_vhd(&mut file).unwrap());
            },
        );
    }

    #[test]
    fn test_is_fixed_vhd_rejects_a_bad_checksum() {
        let mut footer = checksummed_footer(&valid_fixed_vhd_footer());
        let stored = u32::from_be_bytes(footer[64..68].try_into().unwrap());
        footer[64..68].copy_from_slice(&stored.wrapping_add(1).to_be_bytes());

        with_file(&footer, |mut file: File| {
            assert!(!is_fixed_vhd(&mut file).unwrap());
        });
    }

    #[test]
    fn test_is_fixed_vhd_rejects_an_unset_checksum() {
        with_file(&valid_fixed_vhd_footer(), |mut file: File| {
            assert!(!is_fixed_vhd(&mut file).unwrap());
        });
    }

    #[test]
    fn test_is_not_fixed_vhd() {
        with_file(
            &checksummed_footer(&valid_dynamic_vhd_footer()),
            |mut file: File| {
                assert!(!(is_fixed_vhd(&mut file).unwrap()));
            },
        );
    }

    #[test]
    fn test_is_fixed_vhd_short_file_is_not_vhd() {
        let mut file: File = TempFile::new().unwrap().into_file();
        file.write_all(b"# Disk DescriptorFile\n").unwrap();
        assert!(!is_fixed_vhd(&mut file).unwrap());
    }
}
