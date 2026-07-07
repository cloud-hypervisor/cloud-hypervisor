// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::btree_map::BTreeMap;
use std::os::unix::fs::FileExt;
use std::{io, result};

use byteorder::{ByteOrder, LittleEndian};
use remain::sorted;
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

#[sorted]
#[derive(Error, Debug)]
pub enum VhdxHeaderError {
    #[error("Failed to calculate checksum")]
    CalculateChecksum,
    #[error("BAT entry is not unique")]
    DuplicateBATEntry,
    #[error("Metadata region entry is not unique")]
    DuplicateMDREntry,
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
    #[error("Cannot read checksum")]
    ReadChecksum,
    #[error("Failed to read File Type Identifier {0}")]
    ReadFileTypeIdentifier(#[source] io::Error),
    #[error("Failed to read headers {0}")]
    ReadHeader(#[source] io::Error),
    #[error("Failed to read metadata {0}")]
    ReadMetadata(#[source] io::Error),
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
        let _signature = LittleEndian::read_u64(&buf);
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

        let mut new_header = Header {
            signature: current_header.signature,
            checksum: 0,
            sequence_number: current_header.sequence_number + 1,
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
    a_start < b_end && b_start < a_end
}

pub(super) struct RegionInfo {
    pub bat_entry: RegionTableEntry,
    pub mdr_entry: RegionTableEntry,
    pub region_entries: BTreeMap<u64, u64>,
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

            for (region_ent_start, region_ent_end) in region_entries.iter() {
                if ranges_overlap(start, end, *region_ent_start, *region_ent_end) {
                    return Err(VhdxHeaderError::RegionOverlap);
                }
            }

            region_entries.insert(start, end);

            if entry.guid == BAT_GUID {
                if bat_entry.is_none() {
                    bat_entry = Some(entry);
                    continue;
                }
                return Err(VhdxHeaderError::DuplicateBATEntry);
            }

            if entry.guid == MDR_GUID {
                if mdr_entry.is_none() {
                    mdr_entry = Some(entry);
                    continue;
                }
                return Err(VhdxHeaderError::DuplicateMDREntry);
            }

            if (entry.required & REGION_ENTRY_REQUIRED) == 1 {
                // This implementation doesn't recognize this field.
                // Therefore, according to the spec, we are throwing an error.
                return Err(VhdxHeaderError::UnrecognizedRegionEntry);
            }
        }

        if bat_entry.is_none() || mdr_entry.is_none() {
            region_entries.clear();
            return Err(VhdxHeaderError::RegionEntryCollectionFailed);
        }

        // It's safe to unwrap as we checked both entries have been filled.
        // Otherwise, an error is already returned.
        let bat_entry = bat_entry.unwrap();
        let mdr_entry = mdr_entry.unwrap();

        Ok(RegionInfo {
            bat_entry,
            mdr_entry,
            region_entries,
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

enum HeaderNo {
    First,
    Second,
}

/// Contains the information from the header of a VHDx file
#[derive(Clone, Debug)]
pub(super) struct VhdxHeader {
    _file_type_identifier: FileTypeIdentifier,
    header_1: Header,
    header_2: Header,
    region_table_1: RegionTableHeader,
    _region_table_2: RegionTableHeader,
}

impl VhdxHeader {
    /// Creates a VhdxHeader from a reference to a file
    pub(super) fn new(f: &AlignedFile) -> Result<VhdxHeader> {
        Ok(VhdxHeader {
            _file_type_identifier: FileTypeIdentifier::new(f)?,
            header_1: Header::new(f, HEADER_1_START)?,
            header_2: Header::new(f, HEADER_2_START)?,
            region_table_1: RegionTableHeader::new(f, REGION_TABLE_1_START)?,
            _region_table_2: RegionTableHeader::new(f, REGION_TABLE_2_START)?,
        })
    }

    /// Identify the current header and return both headers along with an
    /// integer indicating the current header.
    fn current_header(
        header_1: Result<Header>,
        header_2: Result<Header>,
    ) -> Result<(HeaderNo, Header)> {
        let header_1 = header_1.ok();
        let header_2 = header_2.ok();

        match (header_1, header_2) {
            (None, None) => Err(VhdxHeaderError::NoValidHeader),
            (Some(header_1), None) => Ok((HeaderNo::First, header_1)),
            (None, Some(header_2)) => Ok((HeaderNo::Second, header_2)),
            (Some(header_1), Some(header_2)) => {
                if header_1.sequence_number >= header_2.sequence_number {
                    Ok((HeaderNo::First, header_1))
                } else {
                    Ok((HeaderNo::Second, header_2))
                }
            }
        }
    }

    /// This takes two headers and update the noncurrent header with the
    /// current one. Returns both headers as a tuple sequenced the way it was
    /// received from the parameter list.
    fn update_header(
        f: &AlignedFile,
        header_1: Result<Header>,
        header_2: Result<Header>,
        guid: u128,
    ) -> Result<(Header, Header)> {
        let (header_no, current_header) = VhdxHeader::current_header(header_1, header_2)?;

        match header_no {
            HeaderNo::First => {
                let other_header =
                    Header::update_header(f, &current_header, true, guid, HEADER_2_START)?;
                Ok((current_header, other_header))
            }
            HeaderNo::Second => {
                let other_header =
                    Header::update_header(f, &current_header, true, guid, HEADER_1_START)?;
                Ok((other_header, current_header))
            }
        }
    }

    // Update the provided headers according to the spec
    fn update_headers(
        f: &AlignedFile,
        header_1: Result<Header>,
        header_2: Result<Header>,
        guid: u128,
    ) -> Result<(Header, Header)> {
        // According to the spec, update twice
        let (header_1, header_2) = VhdxHeader::update_header(f, header_1, header_2, guid)?;
        VhdxHeader::update_header(f, Ok(header_1), Ok(header_2), guid)
    }

    pub(super) fn update(&mut self, f: &AlignedFile) -> Result<()> {
        let headers = VhdxHeader::update_headers(f, Ok(self.header_1), Ok(self.header_2), 0)?;
        self.header_1 = headers.0;
        self.header_2 = headers.1;
        Ok(())
    }

    pub(super) fn region_entry_count(&self) -> u32 {
        self.region_table_1.entry_count
    }
}

/// Calculates the checksum of a buffer that itself contains its checksum
/// Therefore, before calculating, the existing checksum is retrieved and the
/// corresponding field is made zero. After the calculation, the existing checksum
/// is put back to the buffer.
fn calculate_checksum(buffer: &mut [u8], csum_offset: usize) -> u32 {
    // Read the original checksum from the buffer
    let orig_csum = LittleEndian::read_u32(&buffer[csum_offset..csum_offset + 4]);
    // Zero the checksum in the buffer
    LittleEndian::write_u32(&mut buffer[csum_offset..csum_offset + 4], 0);
    // Calculate the checksum on the resulting buffer
    let mut crc = crc_any::CRC::crc32c();
    crc.digest(&buffer);
    let new_csum = crc.get_crc() as u32;

    // Put back the original checksum in the buffer
    LittleEndian::write_u32(&mut buffer[csum_offset..csum_offset + 4], orig_csum);

    new_csum
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::FileExt;

    use vmm_sys_util::tempfile::TempFile;
    use zerocopy::{FromBytes, IntoBytes};

    use super::{
        BAT_GUID, HEADER_SIGN, Header, MDR_GUID, REGION_TABLE_1_START, RegionInfo,
        RegionTableHeader, VhdxHeaderError, ranges_overlap,
    };
    use crate::aligned_file::AlignedFile;

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

    /// Builds the 32-byte on-disk region table entry for `guid` describing
    /// the region `[file_offset, file_offset + length)`.
    fn region_entry(guid: [u8; 16], file_offset: u64, length: u32) -> [u8; 32] {
        let mut e = [0u8; 32];
        e[0..16].copy_from_slice(&guid);
        e[16..24].copy_from_slice(&file_offset.to_le_bytes());
        e[24..28].copy_from_slice(&length.to_le_bytes());
        // `required` (e[28..32]) left zero.
        e
    }

    #[test]
    fn test_region_info_rejects_overlapping_regions() {
        // BAT region [1 MiB, 3 MiB) and metadata region [2 MiB, 4 MiB) overlap
        // on [2 MiB, 3 MiB); per [MS-VHDX] all region objects must be
        // non-overlapping, so this image must be rejected.
        const MIB: u64 = 1024 * 1024;
        let region_start = REGION_TABLE_1_START;
        let entries_at = region_start + size_of::<RegionTableHeader>() as u64;

        let temp = TempFile::new().unwrap();
        let f = temp.into_file();
        f.set_len(entries_at + 64 * 1024).unwrap();
        f.write_all_at(&region_entry(BAT_GUID, MIB, (2 * MIB) as u32), entries_at)
            .unwrap();
        f.write_all_at(
            &region_entry(MDR_GUID, 2 * MIB, (2 * MIB) as u32),
            entries_at + 32,
        )
        .unwrap();

        let af = AlignedFile::new(f, false);
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

        let temp = TempFile::new().unwrap();
        let f = temp.into_file();
        f.set_len(entries_at + 64 * 1024).unwrap();
        f.write_all_at(&region_entry(BAT_GUID, u64::MAX, 0x1000), entries_at)
            .unwrap();

        let af = AlignedFile::new(f, false);
        let res = RegionInfo::new(&af, region_start, 1);
        assert!(
            matches!(res, Err(VhdxHeaderError::RegionEntryOverflow(..))),
            "expected RegionEntryOverflow for a wrapping region entry"
        );
    }
}
