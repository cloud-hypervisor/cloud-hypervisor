// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::btree_map::BTreeMap;
use std::os::unix::fs::FileExt;
use std::{io, result};

use thiserror::Error;
use uuid::Uuid;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::aligned_file::AlignedFile;

const VHDX_SIGN: u64 = 0x656C_6966_7864_6876; // "vhdxfile"
const HEADER_SIGN: u32 = 0x6461_6568; // "head"
const REGION_SIGN: u32 = 0x6967_6572; // "regi"

const FILE_START: u64 = 0; // The first element
const HEADER_1_START: u64 = 64 * 1024; // Header 1 start in Bytes
const HEADER_2_START: u64 = 128 * 1024; // Header 2 start in Bytes
pub(super) const REGION_TABLE_1_START: u64 = 192 * 1024; // Region 1 start in Bytes
const REGION_TABLE_2_START: u64 = 256 * 1024; // Region 2 start in Bytes

const HEADER_SIZE: u64 = 4 * 1024; // Each header is 64 KiB, but only first 4 kiB contains info
const REGION_SIZE: u64 = 64 * 1024; // Each region size is 64 KiB

const REGION_ENTRY_REQUIRED: u32 = 1;

// VHDX stores GUIDs using little-endian GUID byte order.
const BAT_GUID: [u8; 16] = [
    0x66, 0x77, 0xc2, 0x2d, 0x23, 0xf6, 0x00, 0x42, 0x9d, 0x64, 0x11, 0x5e, 0x9b, 0xfd, 0x4a, 0x08,
];
const MDR_GUID: [u8; 16] = [
    0x06, 0xa2, 0x7c, 0x8b, 0x90, 0x47, 0x9a, 0x4b, 0xb8, 0xfe, 0x57, 0x5f, 0x05, 0x0f, 0x88, 0x6e,
];

#[derive(Error, Debug)]
pub enum VhdxHeaderError {
    #[error("Region GUID is not unique")]
    DuplicateRegionEntry,
    #[error("Checksum doesn't match for {0}")]
    InvalidChecksum(String),
    #[error("Invalid entry count")]
    InvalidEntryCount,
    #[error("Not a valid VHDx header")]
    InvalidHeaderSign,
    #[error("Not a valid VHDx region")]
    InvalidRegionSign,
    #[error("Not a VHDx file")]
    InvalidVHDXSign,
    #[error("No valid header found")]
    NoValidHeader,
    #[error("Failed to read File Type Identifier {0}")]
    ReadFileTypeIdentifier(#[source] io::Error),
    #[error("Failed to read headers {0}")]
    ReadHeader(#[source] io::Error),
    #[error("Failed to read region table entries {0}")]
    ReadRegionTableEntries(#[source] io::Error),
    #[error("Failed to read region table header {0}")]
    ReadRegionTableHeader(#[source] io::Error),
    #[error("Failed to read region entries")]
    RegionEntryCollectionFailed,
    #[error("Region entry file offset ({0}) and length ({1}) overflow u64")]
    RegionEntryOverflow(u64 /* start */, usize /* length */),
    #[error("Overlapping regions found")]
    RegionOverlap,
    #[error("Reserved region has non-zero value")]
    ReservedIsNonZero,
    #[error("Header sequence number would overflow")]
    SequenceNumberOverflow,
    #[error("We do not recognize this entry")]
    UnrecognizedRegionEntry,
    #[error("Failed to write header {0}")]
    WriteHeader(#[source] io::Error),
}

pub(super) type Result<T> = result::Result<T, VhdxHeaderError>;

#[derive(Clone, Debug)]
pub(super) struct FileTypeIdentifier {
    pub _signature: u64,
}

impl FileTypeIdentifier {
    /// Reads the File Type Identifier structure from a reference VHDx file
    pub(super) fn new(f: &AlignedFile) -> Result<FileTypeIdentifier> {
        let mut buf = [0u8; size_of::<u64>()];
        f.read_exact_at(&mut buf, FILE_START)
            .map_err(VhdxHeaderError::ReadFileTypeIdentifier)?;
        let _signature = u64::from_le_bytes(buf);
        if _signature != VHDX_SIGN {
            return Err(VhdxHeaderError::InvalidVHDXSign);
        }

        Ok(FileTypeIdentifier { _signature })
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
pub(super) struct Header {
    pub signature: u32,
    pub checksum: u32,
    pub sequence_number: u64,
    pub file_write_guid: u128,
    pub data_write_guid: u128,
    pub log_guid: u128,
    pub log_version: u16,
    pub version: u16,
    pub log_length: u32,
    pub log_offset: u64,
}

impl Header {
    /// Reads the Header structure from a reference VHDx file
    pub(super) fn new(f: &AlignedFile, start: u64) -> Result<Header> {
        // Read the whole header into a buffer. We will need it for
        // calculating checksum.
        let mut buffer = [0; HEADER_SIZE as usize];
        f.read_exact_at(&mut buffer, start)
            .map_err(VhdxHeaderError::ReadHeader)?;

        let header = Header::read_from_prefix(&buffer).unwrap().0;
        if header.signature != HEADER_SIGN {
            return Err(VhdxHeaderError::InvalidHeaderSign);
        }

        let new_checksum = calculate_checksum(&mut buffer, size_of::<u32>());
        if header.checksum != new_checksum {
            return Err(VhdxHeaderError::InvalidChecksum(String::from("Header")));
        }

        Ok(header)
    }

    /// Creates and returns new updated header from the provided current header
    fn update_header(
        f: &AlignedFile,
        current_header: &Header,
        change_data_guid: bool,
        file_write_guid: u128,
        start: u64,
    ) -> Result<Header> {
        let mut buffer = [0u8; HEADER_SIZE as usize];
        let data_write_guid = if change_data_guid {
            Uuid::new_v4().as_u128()
        } else {
            current_header.data_write_guid
        };

        let file_write_guid = if file_write_guid == 0 {
            current_header.file_write_guid
        } else {
            file_write_guid
        };

        let sequence_number = current_header
            .sequence_number
            .checked_add(1)
            .ok_or(VhdxHeaderError::SequenceNumberOverflow)?;

        let mut new_header = Header {
            signature: current_header.signature,
            checksum: 0,
            sequence_number,
            file_write_guid,
            data_write_guid,
            log_guid: current_header.log_guid,
            log_version: current_header.log_version,
            version: current_header.version,
            log_length: current_header.log_length,
            log_offset: current_header.log_offset,
        };

        new_header.write_to_prefix(&mut buffer).unwrap();
        new_header.checksum = calculate_checksum(&mut buffer, size_of::<u32>());
        new_header.write_to_prefix(&mut buffer).unwrap();

        f.write_all_at(&buffer, start)
            .map_err(VhdxHeaderError::WriteHeader)?;

        Ok(new_header)
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, FromBytes)]
struct RegionTableHeader {
    pub signature: u32,
    pub checksum: u32,
    pub entry_count: u32,
    pub reserved: u32,
}

impl RegionTableHeader {
    /// Reads the Region Table Header structure from a reference VHDx file
    pub(crate) fn new(f: &AlignedFile, start: u64) -> Result<RegionTableHeader> {
        // Read the whole header into a buffer. We will need it for calculating
        // checksum.
        let mut buffer = [0u8; REGION_SIZE as usize];
        f.read_exact_at(&mut buffer, start)
            .map_err(VhdxHeaderError::ReadRegionTableHeader)?;

        let region_table_header = RegionTableHeader::read_from_prefix(&buffer).unwrap().0;
        if region_table_header.signature != REGION_SIGN {
            return Err(VhdxHeaderError::InvalidRegionSign);
        }

        let new_checksum = calculate_checksum(&mut buffer, size_of::<u32>());
        if region_table_header.checksum != new_checksum {
            return Err(VhdxHeaderError::InvalidChecksum(String::from("Region")));
        }

        if region_table_header.entry_count > 2047 {
            return Err(VhdxHeaderError::InvalidEntryCount);
        }

        if region_table_header.reserved != 0 {
            return Err(VhdxHeaderError::ReservedIsNonZero);
        }

        Ok(region_table_header)
    }
}

/// Returns `true` if the half-open byte ranges `[a_start, a_end)` and
/// `[b_start, b_end)` overlap.
fn ranges_overlap(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool {
    a_start < a_end && b_start < b_end && a_start < b_end && b_start < a_end
}

pub(super) struct RegionInfo {
    pub bat_entry: RegionTableEntry,
    pub mdr_entry: RegionTableEntry,
}

impl RegionInfo {
    /// Collect all entries in a BTreeMap from the Region Table and identifies
    /// BAT and metadata regions
    pub(super) fn new(f: &AlignedFile, region_start: u64, entry_count: u32) -> Result<RegionInfo> {
        let mut bat_entry: Option<RegionTableEntry> = None;
        let mut mdr_entry: Option<RegionTableEntry> = None;

        let mut offset = 0;
        let mut region_entries = BTreeMap::new();

        let mut buffer = [0; REGION_SIZE as usize];
        // Read after the Region Table Header
        f.read_exact_at(
            &mut buffer,
            region_start + size_of::<RegionTableHeader>() as u64,
        )
        .map_err(VhdxHeaderError::ReadRegionTableEntries)?;

        for _ in 0..entry_count {
            let entry = RegionTableEntry::read_from_bytes(
                &buffer[offset..offset + size_of::<RegionTableEntry>()],
            )
            .unwrap();

            offset += size_of::<RegionTableEntry>();
            let start = entry.file_offset;
            let end = start.checked_add(entry.length as u64).ok_or(
                VhdxHeaderError::RegionEntryOverflow(start, entry.length as usize),
            )?;

            for (region_ent_start, region_ent_end) in region_entries.values() {
                if ranges_overlap(start, end, *region_ent_start, *region_ent_end) {
                    return Err(VhdxHeaderError::RegionOverlap);
                }
            }

            if region_entries.insert(entry.guid, (start, end)).is_some() {
                return Err(VhdxHeaderError::DuplicateRegionEntry);
            }

            if entry.guid == BAT_GUID {
                bat_entry = Some(entry);
                continue;
            }

            if entry.guid == MDR_GUID {
                mdr_entry = Some(entry);
                continue;
            }

            if (entry.required & REGION_ENTRY_REQUIRED) == 1 {
                // This implementation doesn't recognize this field.
                // Therefore, according to the spec, we are throwing an error.
                return Err(VhdxHeaderError::UnrecognizedRegionEntry);
            }
        }

        let (Some(bat_entry), Some(mdr_entry)) = (bat_entry, mdr_entry) else {
            region_entries.clear();
            return Err(VhdxHeaderError::RegionEntryCollectionFailed);
        };

        Ok(RegionInfo {
            bat_entry,
            mdr_entry,
        })
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, FromBytes)]
pub(super) struct RegionTableEntry {
    guid: [u8; 16],
    pub file_offset: u64,
    pub length: u32,
    pub required: u32,
}

/// Contains the information from the header of a VHDx file
#[derive(Clone, Debug)]
pub(super) struct VhdxHeader {
    _file_type_identifier: FileTypeIdentifier,
    header: Header,
    header_offset: u64,
    region_table_1: RegionTableHeader,
    _region_table_2: RegionTableHeader,
}

impl VhdxHeader {
    /// Creates a VhdxHeader from a reference to a file
    pub(super) fn new(f: &AlignedFile) -> Result<VhdxHeader> {
        let file_type_identifier = FileTypeIdentifier::new(f)?;
        let (header_offset, header) = Self::current_header(
            Header::new(f, HEADER_1_START),
            Header::new(f, HEADER_2_START),
        )?;
        Ok(VhdxHeader {
            _file_type_identifier: file_type_identifier,
            header,
            header_offset,
            region_table_1: RegionTableHeader::new(f, REGION_TABLE_1_START)?,
            _region_table_2: RegionTableHeader::new(f, REGION_TABLE_2_START)?,
        })
    }

    /// Select the current header and its file offset.
    fn current_header(header_1: Result<Header>, header_2: Result<Header>) -> Result<(u64, Header)> {
        let valid_header = |header| match header {
            Ok(header) => Ok(Some(header)),
            Err(VhdxHeaderError::InvalidHeaderSign | VhdxHeaderError::InvalidChecksum(_)) => {
                Ok(None)
            }
            Err(error) => Err(error),
        };
        let header_1 = valid_header(header_1)?;
        let header_2 = valid_header(header_2)?;

        match (header_1, header_2) {
            (None, None) => Err(VhdxHeaderError::NoValidHeader),
            (Some(header_1), None) => Ok((HEADER_1_START, header_1)),
            (None, Some(header_2)) => Ok((HEADER_2_START, header_2)),
            (Some(header_1), Some(header_2)) => {
                if header_1.sequence_number >= header_2.sequence_number {
                    Ok((HEADER_1_START, header_1))
                } else {
                    Ok((HEADER_2_START, header_2))
                }
            }
        }
    }

    pub(super) fn update(&mut self, f: &AlignedFile) -> Result<()> {
        let mut header = self.header;
        let mut offset = self.header_offset;
        for _ in 0..2 {
            offset = if offset == HEADER_1_START {
                HEADER_2_START
            } else {
                HEADER_1_START
            };
            header = Header::update_header(f, &header, true, 0, offset)?;
        }
        self.header = header;
        self.header_offset = offset;
        Ok(())
    }

    pub(super) fn region_entry_count(&self) -> u32 {
        self.region_table_1.entry_count
    }

    /// Return the current header's log region as (offset, length).
    pub(super) fn log_region(&self) -> (u64, u32) {
        (self.header.log_offset, self.header.log_length)
    }

    /// A non-zero log GUID means a log is present and may need replay.
    pub(super) fn has_active_log(&self) -> bool {
        self.header.log_guid != 0 && self.header.log_length != 0
    }
}

/// Calculates the checksum of a buffer that itself contains its checksum
/// Therefore, before calculating, the existing checksum is retrieved and the
/// corresponding field is made zero. After the calculation, the existing checksum
/// is put back to the buffer.
fn calculate_checksum(buffer: &mut [u8], csum_offset: usize) -> u32 {
    let csum_range = csum_offset..csum_offset + size_of::<u32>();
    // Read the original checksum from the buffer
    let mut orig_csum = [0u8; size_of::<u32>()];
    orig_csum.copy_from_slice(&buffer[csum_range.clone()]);
    // Zero the checksum in the buffer
    buffer[csum_range.clone()].fill(0);
    // Calculate the checksum on the resulting buffer
    let mut crc = crc_any::CRC::crc32c();
    crc.digest(&buffer);
    let new_csum = crc.get_crc() as u32;

    // Put back the original checksum in the buffer
    buffer[csum_range].copy_from_slice(&orig_csum);

    new_csum
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::FileExt;

    use zerocopy::{FromBytes, IntoBytes};

    use super::{
        BAT_GUID, HEADER_1_START, HEADER_2_START, HEADER_SIGN, Header, MDR_GUID,
        REGION_TABLE_1_START, RegionInfo, RegionTableHeader, VhdxHeader, VhdxHeaderError,
        ranges_overlap,
    };
    use crate::aligned_file::AlignedFile;
    use crate::formats::vhdx::test_util::{create_dynamic_vhdx, region_entry, region_file};

    #[test]
    fn one_valid_header_is_enough() {
        for invalid in [HEADER_1_START, HEADER_2_START] {
            let tf = create_dynamic_vhdx(1, None);
            let file = AlignedFile::new(tf.into_file(), false);
            file.write_all_at(&[0; 4], invalid).unwrap();
            let header = VhdxHeader::new(&file).unwrap();
            assert_ne!(header.header_offset, invalid);
            file.write_all_at(&[0; 4], header.header_offset).unwrap();
            assert!(matches!(
                VhdxHeader::new(&file),
                Err(VhdxHeaderError::NoValidHeader)
            ));
        }
    }

    #[test]
    fn header_read_errors_are_propagated() {
        use std::io;

        let tf = create_dynamic_vhdx(1, None);
        let file = AlignedFile::new(tf.into_file(), false);
        let header = Header::new(&file, HEADER_1_START).unwrap();
        for failed in 0..2 {
            let mut headers = [Ok(header), Ok(header)];
            headers[failed] = Err(VhdxHeaderError::ReadHeader(io::Error::from_raw_os_error(
                libc::EIO,
            )));
            let [header_1, header_2] = headers;
            assert!(matches!(
                VhdxHeader::current_header(header_1, header_2),
                Err(VhdxHeaderError::ReadHeader(_))
            ));
        }
    }

    #[test]
    fn test_header_bytes_round_trip() {
        let header = Header {
            signature: HEADER_SIGN,
            checksum: 0x1122_3344,
            sequence_number: 0x0102_0304_0506_0708,
            file_write_guid: 0x0f0e_0d0c_0b0a_0908_0706_0504_0302_0100,
            data_write_guid: 0x1f1e_1d1c_1b1a_1918_1716_1514_1312_1110,
            log_guid: 0x2f2e_2d2c_2b2a_2928_2726_2524_2322_2120,
            log_version: 0xabcd,
            version: 0x0001,
            log_length: 0x0010_0000,
            log_offset: 0x0000_0100_0000_0000,
        };

        let bytes = header.as_bytes();
        assert_eq!(&bytes[0..4], &header.signature.to_le_bytes()[..]);
        assert_eq!(&bytes[8..16], &header.sequence_number.to_le_bytes()[..]);
        assert_eq!(&bytes[16..32], &header.file_write_guid.to_le_bytes()[..]);
        assert_eq!(&bytes[64..66], &header.log_version.to_le_bytes()[..]);
        assert_eq!(&bytes[72..80], &header.log_offset.to_le_bytes()[..]);

        let parsed = Header::read_from_bytes(bytes).unwrap();
        assert_eq!({ parsed.signature }, { header.signature });
        assert_eq!({ parsed.checksum }, { header.checksum });
        assert_eq!({ parsed.sequence_number }, { header.sequence_number });
        assert_eq!({ parsed.file_write_guid }, { header.file_write_guid });
        assert_eq!({ parsed.data_write_guid }, { header.data_write_guid });
        assert_eq!({ parsed.log_guid }, { header.log_guid });
        assert_eq!({ parsed.log_version }, { header.log_version });
        assert_eq!({ parsed.version }, { header.version });
        assert_eq!({ parsed.log_length }, { header.log_length });
        assert_eq!({ parsed.log_offset }, { header.log_offset });
    }

    #[test]
    fn test_ranges_overlap() {
        // (new [start,end), existing [s,e), expected overlap)
        let cases: &[(u64, u64, u64, u64, bool)] = &[
            // Genuine overlaps — all of these must be detected.
            (0, 10, 0, 10, true), // identical
            (2, 8, 0, 10, true),  // new fully inside existing
            (0, 20, 5, 10, true), // new fully contains existing
            (5, 15, 0, 10, true), // partial, new starts inside existing
            (0, 8, 5, 15, true),  // partial, new starts before existing
            // Non-overlapping — must not be flagged.
            (0, 5, 10, 20, false),   // disjoint, new before existing
            (30, 40, 10, 20, false), // disjoint, new after existing
            (0, 10, 10, 20, false),  // touching at the boundary (half-open)
            (0, 0, 0, 10, false),    // empty at the start
            (5, 5, 0, 10, false),    // empty inside
            (10, 10, 0, 10, false),  // empty at the end
        ];

        for &(a_start, a_end, b_start, b_end, expected) in cases {
            assert_eq!(
                ranges_overlap(a_start, a_end, b_start, b_end),
                expected,
                "[{a_start},{a_end}) vs [{b_start},{b_end})"
            );
            // Overlap is symmetric.
            assert_eq!(
                ranges_overlap(b_start, b_end, a_start, a_end),
                expected,
                "symmetry: [{b_start},{b_end}) vs [{a_start},{a_end})"
            );
        }
    }

    #[test]
    fn region_guids_are_unique() {
        const MIB: u64 = 1 << 20;
        let entries_at = REGION_TABLE_1_START + size_of::<RegionTableHeader>() as u64;
        let file = region_file(
            4 * MIB,
            &[
                region_entry(BAT_GUID, MIB, MIB as u32),
                region_entry(MDR_GUID, 2 * MIB, MIB as u32),
                region_entry([1; 16], MIB, 0),
                region_entry([2; 16], MIB, 0),
            ],
        );
        RegionInfo::new(&file, REGION_TABLE_1_START, 4).unwrap();

        file.write_all_at(&region_entry([1; 16], 3 * MIB, 0), entries_at + 96)
            .unwrap();
        assert!(matches!(
            RegionInfo::new(&file, REGION_TABLE_1_START, 4),
            Err(VhdxHeaderError::DuplicateRegionEntry)
        ));

        file.write_all_at(&region_entry([2; 16], MIB, MIB as u32), entries_at + 96)
            .unwrap();
        assert!(matches!(
            RegionInfo::new(&file, REGION_TABLE_1_START, 4),
            Err(VhdxHeaderError::RegionOverlap)
        ));
    }

    #[test]
    fn test_region_info_rejects_overlapping_regions() {
        // BAT region [1 MiB, 3 MiB) and metadata region [2 MiB, 4 MiB) overlap
        // on [2 MiB, 3 MiB); per [MS-VHDX] all region objects must be
        // non-overlapping, so this image must be rejected.
        const MIB: u64 = 1024 * 1024;
        let region_start = REGION_TABLE_1_START;
        let entries_at = region_start + size_of::<RegionTableHeader>() as u64;

        let af = region_file(
            entries_at + 64 * 1024,
            &[
                region_entry(BAT_GUID, MIB, (2 * MIB) as u32),
                region_entry(MDR_GUID, 2 * MIB, (2 * MIB) as u32),
            ],
        );
        let res = RegionInfo::new(&af, region_start, 2);
        assert!(
            matches!(res, Err(VhdxHeaderError::RegionOverlap)),
            "expected RegionOverlap for an overlapping region table"
        );
    }

    #[test]
    fn test_region_info_rejects_overflowing_region() {
        // A region whose file offset plus length wraps past u64::MAX must be
        // rejected rather than silently producing a small end offset that
        // could mask a genuine overlap.
        let region_start = REGION_TABLE_1_START;
        let entries_at = region_start + size_of::<RegionTableHeader>() as u64;

        let af = region_file(
            entries_at + 64 * 1024,
            &[region_entry(BAT_GUID, u64::MAX, 0x1000)],
        );
        let res = RegionInfo::new(&af, region_start, 1);
        assert!(
            matches!(res, Err(VhdxHeaderError::RegionEntryOverflow(..))),
            "expected RegionEntryOverflow for a wrapping region entry"
        );
    }
}
