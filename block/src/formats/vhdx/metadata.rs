// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::os::unix::fs::FileExt;
use std::{io, result};

use thiserror::Error;
use zerocopy::FromBytes;

use super::header::{RegionTableEntry, ranges_overlap};
use crate::aligned_file::AlignedFile;

const METADATA_SIGN: u64 = 0x6174_6164_6174_656D;
const METADATA_ENTRY_SIZE: usize = 32;
const METADATA_MAX_ENTRIES: u16 = 2047;
// The size including the table header and entries
const METADATA_TABLE_MAX_SIZE: usize = METADATA_ENTRY_SIZE * (METADATA_MAX_ENTRIES as usize + 1);

const METADATA_FLAGS_IS_VIRTUAL_DISK: u32 = 0x02;
const METADATA_FLAGS_IS_REQUIRED: u32 = 0x04;

pub(super) const BLOCK_SIZE_MIN: u32 = 1 << 20; // 1 MiB
const BLOCK_SIZE_MAX: u32 = 256 << 20; // 256 MiB
const MAX_SECTORS_PER_BLOCK: u64 = 1 << 23;
const VIRTUAL_DISK_SIZE_MAX: u64 = 64 << 40; // 64 TiB

const BLOCK_HAS_PARENT: u32 = 0x02; // Has a parent or a backing file

// GUID for known metadata items
const METADATA_FILE_PARAMETER: [u8; 16] = [
    0x37, 0x67, 0xa1, 0xca, 0x36, 0xfa, 0x43, 0x4d, 0xb3, 0xb6, 0x33, 0xf0, 0xaa, 0x44, 0xe7, 0x6b,
];
const METADATA_VIRTUAL_DISK_SIZE: [u8; 16] = [
    0x24, 0x42, 0xa5, 0x2f, 0x1b, 0xcd, 0x76, 0x48, 0xb2, 0x11, 0x5d, 0xbe, 0xd8, 0x3b, 0xf4, 0xb8,
];
const METADATA_VIRTUAL_DISK_ID: [u8; 16] = [
    0xab, 0x12, 0xca, 0xbe, 0xe6, 0xb2, 0x23, 0x45, 0x93, 0xef, 0xc3, 0x09, 0xe0, 0x00, 0xc7, 0x46,
];
const METADATA_LOGICAL_SECTOR_SIZE: [u8; 16] = [
    0x1d, 0xbf, 0x41, 0x81, 0x6f, 0xa9, 0x09, 0x47, 0xba, 0x47, 0xf2, 0x33, 0xa8, 0xfa, 0xab, 0x5f,
];
const METADATA_PHYSICAL_SECTOR_SIZE: [u8; 16] = [
    0xc7, 0x48, 0xa3, 0xcd, 0x5d, 0x44, 0x71, 0x44, 0x9c, 0xc9, 0xe9, 0x88, 0x52, 0x51, 0xc5, 0x56,
];
const METADATA_PARENT_LOCATOR: [u8; 16] = [
    0x2d, 0x5f, 0xd3, 0xa8, 0x0b, 0xb3, 0x4d, 0x45, 0xab, 0xf7, 0xd3, 0xd8, 0x48, 0x34, 0xab, 0x0c,
];

const METADATA_FILE_PARAMETER_PRESENT: u16 = 0x01;
const METADATA_VIRTUAL_DISK_SIZE_PRESENT: u16 = 0x02;
const METADATA_VIRTUAL_DISK_ID_PRESENT: u16 = 0x04;
const METADATA_LOGICAL_SECTOR_SIZE_PRESENT: u16 = 0x08;
const METADATA_PHYSICAL_SECTOR_SIZE_PRESENT: u16 = 0x10;
const METADATA_PARENT_LOCATOR_PRESENT: u16 = 0x20;

const METADATA_ALL_PRESENT: u16 = METADATA_FILE_PARAMETER_PRESENT
    | METADATA_VIRTUAL_DISK_SIZE_PRESENT
    | METADATA_VIRTUAL_DISK_ID_PRESENT
    | METADATA_LOGICAL_SECTOR_SIZE_PRESENT
    | METADATA_PHYSICAL_SECTOR_SIZE_PRESENT;

const METADATA_LENGTH_MAX: u32 = 1 << 20; // 1 MiB

#[derive(Error, Debug)]
pub enum VhdxMetadataError {
    #[error("Duplicate metadata item")]
    DuplicateMetadataItem,
    #[error("Invalid block size count")]
    InvalidBlockSize,
    #[error("Invalid disk size {0}")]
    InvalidDiskSize(u64),
    #[error("Invalid metadata entry count")]
    InvalidEntryCount,
    #[error("Invalid logical sector size")]
    InvalidLogicalSectorSize,
    #[error("Invalid metadata ID")]
    InvalidMetadataItem,
    #[error("Invalid metadata length")]
    InvalidMetadataLength,
    #[error("Metadata sign doesn't match")]
    InvalidMetadataSign,
    #[error("Invalid physical sector size")]
    InvalidPhysicalSectorSize,
    #[error("Invalid value")]
    InvalidValue,
    #[error("Not all required metadata found")]
    MissingMetadata,
    #[error("Overlapping metadata items")]
    OverlappingMetadata,
    #[error("Failed to read metadata headers {0}")]
    ReadMetadata(#[source] io::Error),
    #[error("Reserved region has non-zero value")]
    ReservedIsNonZero,
    #[error("Differencing images are not supported")]
    UnsupportedDifferencing,
    #[error("This implementation doesn't support this metadata flag")]
    UnsupportedFlag,
}

pub(super) type Result<T> = result::Result<T, VhdxMetadataError>;

#[derive(Default, Clone, Debug)]
pub(super) struct DiskSpec {
    pub disk_id: u128,
    pub image_size: u64,
    pub block_size: u32,
    pub sectors_per_block: u32,
    pub virtual_disk_size: u64,
    pub logical_sector_size: u32,
    pub physical_sector_size: u32,
    pub chunk_ratio: u64,
    pub total_sectors: u64,
}

impl DiskSpec {
    /// Parse all metadata from the provided file and store info in DiskSpec
    /// structure.
    pub(super) fn new(f: &AlignedFile, metadata_region: &RegionTableEntry) -> Result<DiskSpec> {
        if metadata_region.length < METADATA_TABLE_MAX_SIZE as u32 {
            return Err(VhdxMetadataError::InvalidMetadataLength);
        }
        let mut disk_spec = DiskSpec::default();
        let mut metadata_presence: u16 = 0;
        let mut item_ranges = Vec::new();
        let mut offset = 0;
        let metadata = f
            .file()
            .metadata()
            .map_err(VhdxMetadataError::ReadMetadata)?;
        disk_spec.image_size = metadata.len();

        let mut buffer = [0u8; METADATA_TABLE_MAX_SIZE];
        f.read_exact_at(&mut buffer, metadata_region.file_offset)
            .map_err(VhdxMetadataError::ReadMetadata)?;

        let metadata_header =
            MetadataTableHeader::new(&buffer[0..size_of::<MetadataTableHeader>()])?;

        offset += size_of::<MetadataTableHeader>();
        for _ in 0..metadata_header.entry_count {
            let metadata_entry =
                MetadataTableEntry::new(&buffer[offset..offset + size_of::<MetadataTableEntry>()])?;

            let entry_start = u64::from(metadata_entry.offset);
            let entry_end = entry_start + u64::from(metadata_entry.length);
            if entry_end > metadata_region.length as u64 {
                return Err(VhdxMetadataError::InvalidMetadataLength);
            }
            if item_ranges
                .iter()
                .any(|&(start, end)| ranges_overlap(entry_start, entry_end, start, end))
            {
                return Err(VhdxMetadataError::OverlappingMetadata);
            }
            item_ranges.push((entry_start, entry_end));

            let presence = if metadata_entry.item_id == METADATA_FILE_PARAMETER {
                let item = metadata_entry.read_item::<8>(f, metadata_region.file_offset)?;
                disk_spec.block_size = u32::from_le_bytes(item[0..4].try_into().unwrap());

                // MUST be at least 1 MiB and not greater than 256 MiB
                if disk_spec.block_size < BLOCK_SIZE_MIN || disk_spec.block_size > BLOCK_SIZE_MAX {
                    return Err(VhdxMetadataError::InvalidBlockSize);
                }

                // MUST be power of 2
                if !disk_spec.block_size.is_power_of_two() {
                    return Err(VhdxMetadataError::InvalidBlockSize);
                }

                let bits = u32::from_le_bytes(item[4..8].try_into().unwrap());
                if bits & !0x03 != 0 {
                    return Err(VhdxMetadataError::ReservedIsNonZero);
                }
                if bits & BLOCK_HAS_PARENT != 0 {
                    return Err(VhdxMetadataError::UnsupportedDifferencing);
                }

                METADATA_FILE_PARAMETER_PRESENT
            } else if metadata_entry.item_id == METADATA_VIRTUAL_DISK_SIZE {
                let item = metadata_entry.read_item::<8>(f, metadata_region.file_offset)?;
                disk_spec.virtual_disk_size = u64::from_le_bytes(item);

                METADATA_VIRTUAL_DISK_SIZE_PRESENT
            } else if metadata_entry.item_id == METADATA_VIRTUAL_DISK_ID {
                let item = metadata_entry.read_item::<16>(f, metadata_region.file_offset)?;
                disk_spec.disk_id = u128::from_le_bytes(item);

                METADATA_VIRTUAL_DISK_ID_PRESENT
            } else if metadata_entry.item_id == METADATA_LOGICAL_SECTOR_SIZE {
                let item = metadata_entry.read_item::<4>(f, metadata_region.file_offset)?;
                disk_spec.logical_sector_size = u32::from_le_bytes(item);
                if disk_spec.logical_sector_size != 512 {
                    return Err(VhdxMetadataError::InvalidLogicalSectorSize);
                }

                METADATA_LOGICAL_SECTOR_SIZE_PRESENT
            } else if metadata_entry.item_id == METADATA_PHYSICAL_SECTOR_SIZE {
                let item = metadata_entry.read_item::<4>(f, metadata_region.file_offset)?;
                disk_spec.physical_sector_size = u32::from_le_bytes(item);
                if !(disk_spec.physical_sector_size == 512
                    || disk_spec.physical_sector_size == 4096)
                {
                    return Err(VhdxMetadataError::InvalidPhysicalSectorSize);
                }

                METADATA_PHYSICAL_SECTOR_SIZE_PRESENT
            } else if metadata_entry.item_id == METADATA_PARENT_LOCATOR {
                METADATA_PARENT_LOCATOR_PRESENT
            } else {
                return Err(VhdxMetadataError::InvalidMetadataItem);
            };

            let expected_flags = if matches!(
                presence,
                METADATA_FILE_PARAMETER_PRESENT | METADATA_PARENT_LOCATOR_PRESENT
            ) {
                METADATA_FLAGS_IS_REQUIRED
            } else {
                METADATA_FLAGS_IS_REQUIRED | METADATA_FLAGS_IS_VIRTUAL_DISK
            };
            if metadata_entry.flag_bits != expected_flags {
                return Err(VhdxMetadataError::UnsupportedFlag);
            }
            if metadata_presence & presence != 0 {
                return Err(VhdxMetadataError::DuplicateMetadataItem);
            }
            metadata_presence |= presence;
            offset += size_of::<MetadataTableEntry>();
        }

        // Check if all required metadata are present
        if metadata_presence != METADATA_ALL_PRESENT {
            return Err(VhdxMetadataError::MissingMetadata);
        }
        if disk_spec.virtual_disk_size == 0 || disk_spec.virtual_disk_size > VIRTUAL_DISK_SIZE_MAX {
            return Err(VhdxMetadataError::InvalidDiskSize(
                disk_spec.virtual_disk_size,
            ));
        }
        // Check if the virtual disk size is a multiple of the logical sector
        // size.
        if disk_spec.virtual_disk_size % disk_spec.logical_sector_size as u64 != 0 {
            return Err(VhdxMetadataError::InvalidBlockSize);
        }

        disk_spec.sectors_per_block =
            DiskSpec::sectors_per_block(disk_spec.block_size, disk_spec.logical_sector_size)?;

        disk_spec.chunk_ratio =
            DiskSpec::chunk_ratio(disk_spec.block_size, disk_spec.logical_sector_size)?;

        disk_spec.total_sectors =
            disk_spec.virtual_disk_size / disk_spec.logical_sector_size as u64;

        Ok(disk_spec)
    }

    /// Calculates the number of sectors per block
    fn sectors_per_block(block_size: u32, logical_sector_size: u32) -> Result<u32> {
        let sectors_per_block = block_size / logical_sector_size;

        if !sectors_per_block.is_power_of_two() {
            return Err(VhdxMetadataError::InvalidValue);
        }

        Ok(sectors_per_block)
    }

    /// Calculate the chunk ratio
    fn chunk_ratio(block_size: u32, logical_sector_size: u32) -> Result<u64> {
        let chunk_ratio = (MAX_SECTORS_PER_BLOCK * logical_sector_size as u64) / block_size as u64;

        if !chunk_ratio.is_power_of_two() {
            return Err(VhdxMetadataError::InvalidValue);
        }

        Ok(chunk_ratio)
    }
}

#[repr(C, packed)]
#[derive(Default, Debug, Clone, Copy, FromBytes)]
struct MetadataTableHeader {
    signature: u64,
    reserved: u16,
    entry_count: u16,
    reserved2: [u8; 20],
}

impl MetadataTableHeader {
    pub(crate) fn new(buffer: &[u8]) -> Result<MetadataTableHeader> {
        let metadata_table_header = MetadataTableHeader::read_from_bytes(buffer).unwrap();

        if metadata_table_header.signature != METADATA_SIGN {
            return Err(VhdxMetadataError::InvalidMetadataSign);
        }

        if metadata_table_header.entry_count > METADATA_MAX_ENTRIES {
            return Err(VhdxMetadataError::InvalidEntryCount);
        }

        if metadata_table_header.reserved != 0 || metadata_table_header.reserved2 != [0; 20] {
            return Err(VhdxMetadataError::ReservedIsNonZero);
        }

        Ok(metadata_table_header)
    }
}

#[repr(C, packed)]
#[derive(Default, Debug, Clone, Copy, FromBytes)]
pub(super) struct MetadataTableEntry {
    item_id: [u8; 16],
    offset: u32,
    length: u32,
    flag_bits: u32,
    reserved: u32,
}

impl MetadataTableEntry {
    fn read_item<const N: usize>(&self, f: &AlignedFile, region_offset: u64) -> Result<[u8; N]> {
        if self.length as usize != N {
            return Err(VhdxMetadataError::InvalidMetadataLength);
        }
        let offset = region_offset
            .checked_add(self.offset as u64)
            .ok_or(VhdxMetadataError::InvalidMetadataLength)?;
        let mut item = [0u8; N];
        f.read_exact_at(&mut item, offset)
            .map_err(VhdxMetadataError::ReadMetadata)?;
        Ok(item)
    }

    /// Parse one metadata entry from the buffer
    fn new(buffer: &[u8]) -> Result<MetadataTableEntry> {
        let metadata_table_entry = MetadataTableEntry::read_from_bytes(buffer).unwrap();

        if metadata_table_entry.length > METADATA_LENGTH_MAX {
            return Err(VhdxMetadataError::InvalidMetadataLength);
        }

        if (metadata_table_entry.length == 0 && metadata_table_entry.offset != 0)
            || (metadata_table_entry.length != 0
                && metadata_table_entry.offset < METADATA_TABLE_MAX_SIZE as u32)
        {
            return Err(VhdxMetadataError::InvalidMetadataLength);
        }

        if metadata_table_entry.reserved != 0 {
            return Err(VhdxMetadataError::ReservedIsNonZero);
        }

        Ok(metadata_table_entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::vhdx::header::{REGION_TABLE_1_START, RegionInfo, VhdxHeader};
    use crate::formats::vhdx::test_util::create_dynamic_vhdx;

    fn metadata_region() -> (AlignedFile, RegionTableEntry) {
        let file = AlignedFile::new(create_dynamic_vhdx(1, None).into_file(), false);
        let header = VhdxHeader::new(&file).unwrap();
        let regions =
            RegionInfo::new(&file, REGION_TABLE_1_START, header.region_entry_count()).unwrap();
        (file, regions.mdr_entry)
    }

    fn metadata_item(file: &AlignedFile, region: &RegionTableEntry, guid: [u8; 16]) -> (u64, u64) {
        let mut table = [0; METADATA_TABLE_MAX_SIZE];
        file.read_exact_at(&mut table, region.file_offset).unwrap();
        let header = MetadataTableHeader::new(&table[..32]).unwrap();
        for (index, bytes) in table[32..]
            .as_chunks::<METADATA_ENTRY_SIZE>()
            .0
            .iter()
            .take(header.entry_count as usize)
            .enumerate()
        {
            let entry = MetadataTableEntry::read_from_bytes(bytes).unwrap();
            if entry.item_id == guid {
                return (
                    region.file_offset + ((index + 1) * METADATA_ENTRY_SIZE) as u64,
                    region.file_offset + u64::from(entry.offset),
                );
            }
        }
        panic!("Missing metadata item {guid:x?}");
    }

    #[test]
    fn known_metadata_lengths_are_checked() {
        let (file, region) = metadata_region();
        for (guid, length) in [
            (METADATA_FILE_PARAMETER, 8u32),
            (METADATA_VIRTUAL_DISK_SIZE, 8),
            (METADATA_VIRTUAL_DISK_ID, 16),
            (METADATA_LOGICAL_SECTOR_SIZE, 4),
            (METADATA_PHYSICAL_SECTOR_SIZE, 4),
        ] {
            let (entry_offset, _) = metadata_item(&file, &region, guid);
            let length_offset = entry_offset + 20;
            for invalid in [1, length - 1, length + 1] {
                file.write_all_at(&invalid.to_le_bytes(), length_offset)
                    .unwrap();
                DiskSpec::new(&file, &region).unwrap_err();
            }
            file.write_all_at(&length.to_le_bytes(), length_offset)
                .unwrap();
        }
        DiskSpec::new(&file, &region).unwrap();
    }

    #[test]
    fn metadata_item_locations_are_checked() {
        let (file, region) = metadata_region();
        let mut short_region = region;
        short_region.length = METADATA_TABLE_MAX_SIZE as u32 - 1;
        assert!(matches!(
            DiskSpec::new(&file, &short_region),
            Err(VhdxMetadataError::InvalidMetadataLength)
        ));

        let (entry_offset, _) = metadata_item(&file, &region, METADATA_VIRTUAL_DISK_SIZE);
        let offset_field = entry_offset + 16;
        for offset in [
            0,
            METADATA_TABLE_MAX_SIZE as u32 - 1,
            region.length - 4,
            u32::MAX,
        ] {
            file.write_all_at(&offset.to_le_bytes(), offset_field)
                .unwrap();
            assert!(matches!(
                DiskSpec::new(&file, &region),
                Err(VhdxMetadataError::InvalidMetadataLength)
            ));
        }

        for offset in [region.length - 9, region.length - 8] {
            file.write_all_at(&offset.to_le_bytes(), offset_field)
                .unwrap();
            file.write_all_at(
                &(1u64 << 20).to_le_bytes(),
                region.file_offset + u64::from(offset),
            )
            .unwrap();
            DiskSpec::new(&file, &region).unwrap();
        }
    }

    #[test]
    fn overlapping_metadata_items_are_rejected() {
        let (file, region) = metadata_region();
        let (_, logical_offset) = metadata_item(&file, &region, METADATA_LOGICAL_SECTOR_SIZE);
        let (physical_entry, _) = metadata_item(&file, &region, METADATA_PHYSICAL_SECTOR_SIZE);
        file.write_all_at(
            &((logical_offset - region.file_offset) as u32).to_le_bytes(),
            physical_entry + 16,
        )
        .unwrap();
        assert!(matches!(
            DiskSpec::new(&file, &region),
            Err(VhdxMetadataError::OverlappingMetadata)
        ));
    }

    #[test]
    fn duplicate_metadata_items_are_rejected() {
        let (file, region) = metadata_region();
        let (entry_offset, _) = metadata_item(&file, &region, METADATA_VIRTUAL_DISK_SIZE);
        let mut entry = [0u8; 32];
        file.read_exact_at(&mut entry, entry_offset).unwrap();
        let item_offset = region.length - 8;
        entry[16..20].copy_from_slice(&item_offset.to_le_bytes());
        file.write_all_at(
            &(2u64 << 20).to_le_bytes(),
            region.file_offset + u64::from(item_offset),
        )
        .unwrap();
        let mut count = [0; 2];
        file.read_exact_at(&mut count, region.file_offset + 10)
            .unwrap();
        let count = u16::from_le_bytes(count);
        file.write_all_at(&entry, region.file_offset + 32 + u64::from(count) * 32)
            .unwrap();
        file.write_all_at(&(count + 1).to_le_bytes(), region.file_offset + 10)
            .unwrap();
        assert!(matches!(
            DiskSpec::new(&file, &region),
            Err(VhdxMetadataError::DuplicateMetadataItem)
        ));
    }

    #[test]
    fn known_metadata_flags_are_checked() {
        let (file, region) = metadata_region();
        for (guid, flags) in [
            (METADATA_FILE_PARAMETER, 4u32),
            (METADATA_VIRTUAL_DISK_SIZE, 6),
            (METADATA_VIRTUAL_DISK_ID, 6),
            (METADATA_LOGICAL_SECTOR_SIZE, 6),
            (METADATA_PHYSICAL_SECTOR_SIZE, 6),
        ] {
            let (entry_offset, _) = metadata_item(&file, &region, guid);
            let flags_offset = entry_offset + 24;
            for bit in [1, 2, 4, 8, 1 << 31] {
                file.write_all_at(&(flags ^ bit).to_le_bytes(), flags_offset)
                    .unwrap();
                assert!(matches!(
                    DiskSpec::new(&file, &region),
                    Err(VhdxMetadataError::UnsupportedFlag)
                ));
            }
            file.write_all_at(&flags.to_le_bytes(), flags_offset)
                .unwrap();
        }
        DiskSpec::new(&file, &region).unwrap();
    }

    #[test]
    fn virtual_disk_size_is_checked() {
        let (file, region) = metadata_region();
        let (_, item_offset) = metadata_item(&file, &region, METADATA_VIRTUAL_DISK_SIZE);
        for size in [0, VIRTUAL_DISK_SIZE_MAX + 512, u64::MAX] {
            file.write_all_at(&size.to_le_bytes(), item_offset).unwrap();
            assert!(matches!(
                DiskSpec::new(&file, &region),
                Err(VhdxMetadataError::InvalidDiskSize(_))
            ));
        }
        file.write_all_at(&VIRTUAL_DISK_SIZE_MAX.to_le_bytes(), item_offset)
            .unwrap();
        assert_eq!(
            DiskSpec::new(&file, &region).unwrap().virtual_disk_size,
            VIRTUAL_DISK_SIZE_MAX
        );
    }

    #[test]
    fn differencing_images_are_rejected_before_bat_validation() {
        use crate::error::BlockErrorKind;
        use crate::formats::vhdx::VhdxDisk;

        let (file, region) = metadata_region();
        let (_, item_offset) = metadata_item(&file, &region, METADATA_FILE_PARAMETER);
        file.write_all_at(&BLOCK_HAS_PARENT.to_le_bytes(), item_offset + 4)
            .unwrap();
        let header = VhdxHeader::new(&file).unwrap();
        let regions =
            RegionInfo::new(&file, REGION_TABLE_1_START, header.region_entry_count()).unwrap();
        for state in [0u64, 7] {
            file.write_all_at(&state.to_le_bytes(), regions.bat_entry.file_offset)
                .unwrap();
            let error = VhdxDisk::new(file.file().try_clone().unwrap(), false).unwrap_err();
            assert_eq!(error.kind(), BlockErrorKind::UnsupportedFeature);
        }
    }

    #[test]
    fn reserved_metadata_fields_are_checked() {
        let (file, region) = metadata_region();
        for offset in [12, 31] {
            file.write_all_at(&[1], region.file_offset + offset)
                .unwrap();
            assert!(matches!(
                DiskSpec::new(&file, &region),
                Err(VhdxMetadataError::ReservedIsNonZero)
            ));
            file.write_all_at(&[0], region.file_offset + offset)
                .unwrap();
        }

        let (_, item_offset) = metadata_item(&file, &region, METADATA_FILE_PARAMETER);
        let flags_offset = item_offset + 4;
        for bits in [4u32, 1 << 31] {
            file.write_all_at(&bits.to_le_bytes(), flags_offset)
                .unwrap();
            assert!(matches!(
                DiskSpec::new(&file, &region),
                Err(VhdxMetadataError::ReservedIsNonZero)
            ));
        }
        file.write_all_at(&1u32.to_le_bytes(), flags_offset)
            .unwrap();
        DiskSpec::new(&file, &region).unwrap();
    }
}
