// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::os::unix::fs::FileExt;
use std::{io, result};

use byteorder::{ByteOrder, LittleEndian};
use remain::sorted;
use thiserror::Error;
use zerocopy::FromBytes;

use super::header::RegionTableEntry;
use crate::aligned_file::AlignedFile;

const METADATA_SIGN: u64 = 0x6174_6164_6174_656D;
const METADATA_ENTRY_SIZE: usize = 32;
const METADATA_MAX_ENTRIES: u16 = 2047;
// The size including the table header and entries
const METADATA_TABLE_MAX_SIZE: usize = METADATA_ENTRY_SIZE * (METADATA_MAX_ENTRIES as usize + 1);

const METADATA_FLAGS_IS_REQUIRED: u32 = 0x04;

pub(super) const BLOCK_SIZE_MIN: u32 = 1 << 20; // 1 MiB
const BLOCK_SIZE_MAX: u32 = 256 << 20; // 256 MiB
const MAX_SECTORS_PER_BLOCK: u64 = 1 << 23;

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

#[sorted]
#[derive(Error, Debug)]
pub enum VhdxMetadataError {
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
    #[error("Failed to read metadata headers {0}")]
    ReadMetadata(#[source] io::Error),
    #[error("Reserved region has non-zero value")]
    ReservedIsNonZero,
    #[error("This implementation doesn't support this metadata flag")]
    UnsupportedFlag,
}

pub(super) type Result<T> = result::Result<T, VhdxMetadataError>;

#[derive(Default, Clone, Debug)]
pub(super) struct DiskSpec {
    pub disk_id: u128,
    pub image_size: u64,
    pub block_size: u32,
    pub has_parent: bool,
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
        let mut disk_spec = DiskSpec::default();
        let mut metadata_presence: u16 = 0;
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

            let item_offset = metadata_region.file_offset + metadata_entry.offset as u64;

            if metadata_entry.item_id == METADATA_FILE_PARAMETER {
                let mut item = [0u8; 2 * size_of::<u32>()];
                f.read_exact_at(&mut item, item_offset)
                    .map_err(VhdxMetadataError::ReadMetadata)?;
                disk_spec.block_size = LittleEndian::read_u32(&item[0..4]);

                // MUST be at least 1 MiB and not greater than 256 MiB
                if disk_spec.block_size < BLOCK_SIZE_MIN || disk_spec.block_size > BLOCK_SIZE_MAX {
                    return Err(VhdxMetadataError::InvalidBlockSize);
                }

                // MUST be power of 2
                if !disk_spec.block_size.is_power_of_two() {
                    return Err(VhdxMetadataError::InvalidBlockSize);
                }

                let bits = LittleEndian::read_u32(&item[4..8]);
                disk_spec.has_parent = bits & BLOCK_HAS_PARENT != 0;

                metadata_presence |= METADATA_FILE_PARAMETER_PRESENT;
            } else if metadata_entry.item_id == METADATA_VIRTUAL_DISK_SIZE {
                let mut item = [0u8; size_of::<u64>()];
                f.read_exact_at(&mut item, item_offset)
                    .map_err(VhdxMetadataError::ReadMetadata)?;
                disk_spec.virtual_disk_size = LittleEndian::read_u64(&item);

                metadata_presence |= METADATA_VIRTUAL_DISK_SIZE_PRESENT;
            } else if metadata_entry.item_id == METADATA_VIRTUAL_DISK_ID {
                let mut item = [0u8; size_of::<u128>()];
                f.read_exact_at(&mut item, item_offset)
                    .map_err(VhdxMetadataError::ReadMetadata)?;
                disk_spec.disk_id = LittleEndian::read_u128(&item);

                metadata_presence |= METADATA_VIRTUAL_DISK_ID_PRESENT;
            } else if metadata_entry.item_id == METADATA_LOGICAL_SECTOR_SIZE {
                let mut item = [0u8; size_of::<u32>()];
                f.read_exact_at(&mut item, item_offset)
                    .map_err(VhdxMetadataError::ReadMetadata)?;
                disk_spec.logical_sector_size = LittleEndian::read_u32(&item);
                if !(disk_spec.logical_sector_size == 512 || disk_spec.logical_sector_size == 4096)
                {
                    return Err(VhdxMetadataError::InvalidLogicalSectorSize);
                }

                metadata_presence |= METADATA_LOGICAL_SECTOR_SIZE_PRESENT;
            } else if metadata_entry.item_id == METADATA_PHYSICAL_SECTOR_SIZE {
                let mut item = [0u8; size_of::<u32>()];
                f.read_exact_at(&mut item, item_offset)
                    .map_err(VhdxMetadataError::ReadMetadata)?;
                disk_spec.physical_sector_size = LittleEndian::read_u32(&item);
                if !(disk_spec.physical_sector_size == 512
                    || disk_spec.physical_sector_size == 4096)
                {
                    return Err(VhdxMetadataError::InvalidPhysicalSectorSize);
                }

                metadata_presence |= METADATA_PHYSICAL_SECTOR_SIZE_PRESENT;
            } else if metadata_entry.item_id == METADATA_PARENT_LOCATOR {
                metadata_presence |= METADATA_PARENT_LOCATOR_PRESENT;
            } else {
                return Err(VhdxMetadataError::InvalidMetadataItem);
            }

            if (metadata_entry.flag_bits & METADATA_FLAGS_IS_REQUIRED) == 0 {
                return Err(VhdxMetadataError::UnsupportedFlag);
            }
            offset += size_of::<MetadataTableEntry>();
        }

        // Check if all required metadata are present
        if metadata_presence != METADATA_ALL_PRESENT {
            return Err(VhdxMetadataError::MissingMetadata);
        }
        // Make sure virtual disk size is not zero
        if (metadata_presence & METADATA_VIRTUAL_DISK_SIZE_PRESENT != 0)
            && disk_spec.virtual_disk_size == 0
        {
            return Err(VhdxMetadataError::InvalidDiskSize(
                disk_spec.virtual_disk_size,
            ));
        }
        // Check if the virtual disk size is a multiple of the logical sector
        // size.
        if ((metadata_presence & METADATA_LOGICAL_SECTOR_SIZE_PRESENT) != 0)
            && (disk_spec.virtual_disk_size % disk_spec.logical_sector_size as u64 != 0)
        {
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
    _reserved2: [u8; 20],
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

        if metadata_table_header.reserved != 0 {
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
    /// Parse one metadata entry from the buffer
    fn new(buffer: &[u8]) -> Result<MetadataTableEntry> {
        let metadata_table_entry = MetadataTableEntry::read_from_bytes(buffer).unwrap();

        if metadata_table_entry.length > METADATA_LENGTH_MAX {
            return Err(VhdxMetadataError::InvalidMetadataLength);
        }

        if metadata_table_entry.length == 0 && metadata_table_entry.offset != 0 {
            return Err(VhdxMetadataError::InvalidMetadataLength);
        }

        if metadata_table_entry.reserved != 0 {
            return Err(VhdxMetadataError::ReservedIsNonZero);
        }

        Ok(metadata_table_entry)
    }
}
