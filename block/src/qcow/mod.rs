// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

mod decoder;
mod qcow_raw_file;
mod raw_file;
mod refcount;
mod vec_cache;

use std::cmp::{max, min};
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
use std::fs::{OpenOptions, read_link};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::mem::size_of;
use std::os::fd::{AsRawFd, RawFd};
use std::str::{self, FromStr};

use bitflags::bitflags;
use libc::{EINVAL, EIO, ENOSPC};
use log::{error, warn};
use remain::sorted;
use thiserror::Error;
use vmm_sys_util::file_traits::{FileSetLen, FileSync};
use vmm_sys_util::seek_hole::SeekHole;
use vmm_sys_util::write_zeroes::{PunchHole, WriteZeroesAt};

use crate::BlockBackend;
use crate::qcow::decoder::{Decoder, ZlibDecoder, ZstdDecoder};
use crate::qcow::qcow_raw_file::{BeUint, QcowRawFile};
pub use crate::qcow::raw_file::RawFile;
use crate::qcow::refcount::RefCount;
use crate::qcow::vec_cache::{CacheMap, Cacheable, VecCache};

/// Nesting depth limit for disk formats that can open other disk files.
const MAX_NESTING_DEPTH: u32 = 10;

#[sorted]
#[derive(Debug, Error)]
pub enum Error {
    #[error("Backing file io error")]
    BackingFileIo(#[source] io::Error),
    #[error("Backing file open error")]
    BackingFileOpen(#[source] Box<Error>),
    #[error("Backing file name is too long: {0} bytes over")]
    BackingFileTooLong(usize),
    #[error("Image is marked corrupt and cannot be opened for writing")]
    CorruptImage,
    #[error("Failed to evict cache")]
    EvictingCache(#[source] io::Error),
    #[error("File larger than max of {MAX_QCOW_FILE_SIZE}: {0}")]
    FileTooBig(u64),
    #[error("Failed to get file size")]
    GettingFileSize(#[source] io::Error),
    #[error("Failed to get refcount")]
    GettingRefcount(#[source] refcount::Error),
    #[error("Failed to parse filename")]
    InvalidBackingFileName(#[source] str::Utf8Error),
    #[error("Invalid cluster index")]
    InvalidClusterIndex,
    #[error("Invalid cluster size")]
    InvalidClusterSize,
    #[error("Invalid index")]
    InvalidIndex,
    #[error("Invalid L1 table offset")]
    InvalidL1TableOffset,
    #[error("Invalid L1 table size: {0}")]
    InvalidL1TableSize(u32),
    #[error("Invalid magic")]
    InvalidMagic,
    #[error("Invalid offset: {0}")]
    InvalidOffset(u64),
    #[error("Invalid refcount table offset")]
    InvalidRefcountTableOffset,
    #[error("Invalid refcount table size: {0}")]
    InvalidRefcountTableSize(u64),
    #[error("Maximum disk nesting depth exceeded")]
    MaxNestingDepthExceeded,
    #[error("No free clusters")]
    NoFreeClusters,
    #[error("No refcount clusters")]
    NoRefcountClusters,
    #[error("Not enough space for refcounts")]
    NotEnoughSpaceForRefcounts,
    #[error("Failed to open file {0}")]
    OpeningFile(#[source] io::Error),
    #[error("Failed to read data")]
    ReadingData(#[source] io::Error),
    #[error("Failed to read header")]
    ReadingHeader(#[source] io::Error),
    #[error("Failed to read pointers")]
    ReadingPointers(#[source] io::Error),
    #[error("Failed to read ref count block")]
    ReadingRefCountBlock(#[source] refcount::Error),
    #[error("Failed to read ref counts")]
    ReadingRefCounts(#[source] io::Error),
    #[error("Failed to rebuild ref counts")]
    RebuildingRefCounts(#[source] io::Error),
    #[error("Refcount overflow")]
    RefcountOverflow(#[source] refcount::Error),
    #[error("Refcount table offset past file end")]
    RefcountTableOffEnd,
    #[error("Too many clusters specified for refcount")]
    RefcountTableTooLarge,
    #[error("Failed to seek file")]
    SeekingFile(#[source] io::Error),
    #[error("Failed to set file size")]
    SettingFileSize(#[source] io::Error),
    #[error("Failed to set refcount refcount")]
    SettingRefcountRefcount(#[source] io::Error),
    #[error("Size too small for number of clusters")]
    SizeTooSmallForNumberOfClusters,
    #[error("L1 entry table too large: {0}")]
    TooManyL1Entries(u64),
    #[error("Ref count table too large: {0}")]
    TooManyRefcounts(u64),
    #[error("Unsupported backing file format: {0}")]
    UnsupportedBackingFileFormat(String),
    #[error("Unsupported compression type")]
    UnsupportedCompressionType,
    #[error("Unsupported qcow2 feature(s)")]
    UnsupportedFeature(#[source] MissingFeatureError),
    #[error("Unsupported refcount order")]
    UnsupportedRefcountOrder,
    #[error("Unsupported version: {0}")]
    UnsupportedVersion(u32),
    #[error("Failed to write data")]
    WritingData(#[source] io::Error),
    #[error("Failed to write header")]
    WritingHeader(#[source] io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ImageType {
    Raw,
    Qcow2,
}

impl Display for ImageType {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            ImageType::Raw => write!(f, "raw"),
            ImageType::Qcow2 => write!(f, "qcow2"),
        }
    }
}

impl FromStr for ImageType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "raw" => Ok(ImageType::Raw),
            "qcow2" => Ok(ImageType::Qcow2),
            _ => Err(Error::UnsupportedBackingFileFormat(s.to_string())),
        }
    }
}

#[derive(Clone, Debug)]
pub enum CompressionType {
    Zlib,
    Zstd,
}

#[derive(Debug, Clone)]
pub struct BackingFileConfig {
    pub path: String,
    // If this is None, we will autodetect it.
    pub format: Option<ImageType>,
}

// Maximum data size supported.
const MAX_QCOW_FILE_SIZE: u64 = 0x01 << 44; // 16 TB.

// QCOW magic constant that starts the header.
const QCOW_MAGIC: u32 = 0x5146_49fb;
// Default to a cluster size of 2^DEFAULT_CLUSTER_BITS
const DEFAULT_CLUSTER_BITS: u32 = 16;
// Limit clusters to reasonable sizes. Choose the same limits as qemu. Making the clusters smaller
// increases the amount of overhead for book keeping.
const MIN_CLUSTER_BITS: u32 = 9;
const MAX_CLUSTER_BITS: u32 = 21;
// The L1 and RefCount table are kept in RAM, only handle files that require less than 35M entries.
// This easily covers 1 TB files. When support for bigger files is needed the assumptions made to
// keep these tables in RAM needs to be thrown out.
const MAX_RAM_POINTER_TABLE_SIZE: u64 = 35_000_000;
// 16-bit refcounts.
const DEFAULT_REFCOUNT_ORDER: u32 = 4;

const V2_BARE_HEADER_SIZE: u32 = 72;
const V3_BARE_HEADER_SIZE: u32 = 104;

// bits 0-8 and 56-63 are reserved.
const L1_TABLE_OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;
const L2_TABLE_OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;
// Flags
const ZERO_FLAG: u64 = 1 << 0;
const COMPRESSED_FLAG: u64 = 1 << 62;
const COMPRESSED_SECTOR_SIZE: u64 = 512;
const CLUSTER_USED_FLAG: u64 = 1 << 63;
const COMPATIBLE_FEATURES_LAZY_REFCOUNTS: u64 = 1;

// Compression types as defined in https://www.qemu.org/docs/master/interop/qcow2.html
const COMPRESSION_TYPE_ZLIB: u64 = 0; // zlib/deflate <https://www.ietf.org/rfc/rfc1951.txt>
const COMPRESSION_TYPE_ZSTD: u64 = 1; // zstd <http://github.com/facebook/zstd>

// Header extension types
const HEADER_EXT_END: u32 = 0x00000000;
// Backing file format name (raw, qcow2)
const HEADER_EXT_BACKING_FORMAT: u32 = 0xe2792aca;
// Feature name table
const HEADER_EXT_FEATURE_NAME_TABLE: u32 = 0x6803f857;

// Feature name table entry type incompatible
const FEAT_TYPE_INCOMPATIBLE: u8 = 0;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct IncompatFeatures: u64 {
        const DIRTY = 1 << 0;
        const CORRUPT = 1 << 1;
        const DATA_FILE = 1 << 2;
        const COMPRESSION = 1 << 3;
        const EXTENDED_L2 = 1 << 4;
    }
}

impl IncompatFeatures {
    /// Features supported by this implementation.
    const SUPPORTED: IncompatFeatures = IncompatFeatures::DIRTY
        .union(IncompatFeatures::CORRUPT)
        .union(IncompatFeatures::COMPRESSION);

    /// Get the fallback name for a known feature bit.
    fn flag_name(bit: u8) -> Option<&'static str> {
        Some(match Self::from_bits_truncate(1u64 << bit) {
            Self::DIRTY => "dirty bit",
            Self::CORRUPT => "corrupt bit",
            Self::DATA_FILE => "external data file",
            Self::EXTENDED_L2 => "extended L2 entries",
            _ => return None,
        })
    }
}

/// Error type for unsupported incompatible features.
#[derive(Debug, Clone, Error)]
pub struct MissingFeatureError {
    /// Unsupported feature bits.
    features: IncompatFeatures,
    /// Feature name table from the qcow2 image.
    feature_names: Vec<(u8, String)>,
}

impl MissingFeatureError {
    fn new(features: IncompatFeatures, feature_names: Vec<(u8, String)>) -> Self {
        Self {
            features,
            feature_names,
        }
    }
}

impl Display for MissingFeatureError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let names: Vec<String> = (0u8..64)
            .filter(|&bit| self.features.bits() & (1u64 << bit) != 0)
            .map(|bit| {
                // First try the image's feature name table
                self.feature_names
                    .iter()
                    .find(|(b, _)| *b == bit)
                    .map(|(_, name)| name.clone())
                    // Then try hardcoded fallback names
                    .or_else(|| IncompatFeatures::flag_name(bit).map(|s| s.to_string()))
                    // Finally, use generic description
                    .unwrap_or_else(|| format!("unknown feature bit {bit}"))
            })
            .collect();
        write!(f, "Missing features: {}", names.join(", "))
    }
}

// The format supports a "header extension area", that crosvm does not use.
const QCOW_EMPTY_HEADER_EXTENSION_SIZE: u32 = 8;

// Defined by the specification
const MAX_BACKING_FILE_SIZE: u32 = 1023;

fn l2_entry_is_empty(l2_entry: u64) -> bool {
    l2_entry == 0
}

// Check bit 0 - only valid for standard clusters.
fn l2_entry_is_zero(l2_entry: u64) -> bool {
    l2_entry & ZERO_FLAG != 0
}

fn l2_entry_is_compressed(l2_entry: u64) -> bool {
    l2_entry & COMPRESSED_FLAG != 0
}

// Get file offset and size of compressed cluster data
fn l2_entry_compressed_cluster_layout(l2_entry: u64, cluster_bits: u32) -> (u64, usize) {
    let compressed_size_shift = 62 - (cluster_bits - 8);
    let compressed_size_mask = (1 << (cluster_bits - 8)) - 1;
    let compressed_cluster_addr = l2_entry & ((1 << compressed_size_shift) - 1);
    let nsectors = (l2_entry >> compressed_size_shift & compressed_size_mask) + 1;
    let compressed_cluster_size = ((nsectors * COMPRESSED_SECTOR_SIZE)
        - (compressed_cluster_addr & (COMPRESSED_SECTOR_SIZE - 1)))
        as usize;
    (compressed_cluster_addr, compressed_cluster_size)
}

// Get file offset of standard (non-compressed) cluster
fn l2_entry_std_cluster_addr(l2_entry: u64) -> u64 {
    l2_entry & L2_TABLE_OFFSET_MASK
}

// Make L2 entry for standard (non-compressed) cluster
fn l2_entry_make_std(cluster_addr: u64) -> u64 {
    (cluster_addr & L2_TABLE_OFFSET_MASK) | CLUSTER_USED_FLAG
}

// Make L1 entry with optional flags
fn l1_entry_make(cluster_addr: u64, refcount_is_one: bool) -> u64 {
    (cluster_addr & L1_TABLE_OFFSET_MASK) | (refcount_is_one as u64 * CLUSTER_USED_FLAG)
}

/// Contains the information from the header of a qcow file.
#[derive(Clone, Debug)]
pub struct QcowHeader {
    pub magic: u32,
    pub version: u32,

    pub backing_file_offset: u64,
    pub backing_file_size: u32,

    pub cluster_bits: u32,
    pub size: u64,
    pub crypt_method: u32,

    pub l1_size: u32,
    pub l1_table_offset: u64,

    pub refcount_table_offset: u64,
    pub refcount_table_clusters: u32,

    pub nb_snapshots: u32,
    pub snapshots_offset: u64,

    // v3 entries
    pub incompatible_features: u64,
    pub compatible_features: u64,
    pub autoclear_features: u64,
    pub refcount_order: u32,
    pub header_size: u32,
    pub compression_type: CompressionType,

    // Post-header entries
    pub backing_file: Option<BackingFileConfig>,
}

impl QcowHeader {
    /// Read header extensions, optionally collecting feature names for error reporting.
    fn read_header_extensions(
        f: &mut RawFile,
        header: &mut QcowHeader,
        mut feature_table: Option<&mut Vec<(u8, String)>>,
    ) -> Result<()> {
        // Extensions start directly after the header
        f.seek(SeekFrom::Start(header.header_size as u64))
            .map_err(Error::ReadingHeader)?;

        loop {
            let ext_type = u32::read_be(f).map_err(Error::ReadingHeader)?;
            if ext_type == HEADER_EXT_END {
                break;
            }

            let ext_length = u32::read_be(f).map_err(Error::ReadingHeader)?;

            match ext_type {
                HEADER_EXT_BACKING_FORMAT => {
                    let mut format_bytes = vec![0u8; ext_length as usize];
                    f.read_exact(&mut format_bytes)
                        .map_err(Error::ReadingHeader)?;
                    let format_str = String::from_utf8(format_bytes)
                        .map_err(|err| Error::InvalidBackingFileName(err.utf8_error()))?;
                    if let Some(backing_file) = &mut header.backing_file {
                        backing_file.format = Some(format_str.parse()?);
                    }
                }
                HEADER_EXT_FEATURE_NAME_TABLE if feature_table.is_some() => {
                    const FEATURE_NAME_ENTRY_SIZE: usize = 1 + 1 + 46; // type + bit + name
                    let mut data = vec![0u8; ext_length as usize];
                    f.read_exact(&mut data).map_err(Error::ReadingHeader)?;
                    let table = feature_table.as_mut().unwrap();
                    for entry in data.chunks_exact(FEATURE_NAME_ENTRY_SIZE) {
                        if entry[0] == FEAT_TYPE_INCOMPATIBLE {
                            let bit_number = entry[1];
                            let name_bytes = &entry[2..];
                            let name_len = name_bytes.iter().position(|&b| b == 0).unwrap_or(46);
                            let name = String::from_utf8_lossy(&name_bytes[..name_len]).to_string();
                            table.push((bit_number, name));
                        }
                    }
                }
                _ => {
                    // Skip unknown extension
                    f.seek(SeekFrom::Current(ext_length as i64))
                        .map_err(Error::ReadingHeader)?;
                }
            }

            // Skip to the next 8 byte boundary
            let padding = (8 - (ext_length % 8)) % 8;
            f.seek(SeekFrom::Current(padding as i64))
                .map_err(Error::ReadingHeader)?;
        }

        Ok(())
    }

    /// Creates a QcowHeader from a reference to a file.
    pub fn new(f: &mut RawFile) -> Result<QcowHeader> {
        f.rewind().map_err(Error::ReadingHeader)?;
        let magic = u32::read_be(f).map_err(Error::ReadingHeader)?;
        if magic != QCOW_MAGIC {
            return Err(Error::InvalidMagic);
        }

        // Reads the next u32 from the file.
        fn read_u32_be(f: &mut RawFile) -> Result<u32> {
            u32::read_be(f).map_err(Error::ReadingHeader)
        }

        // Reads the next u64 from the file.
        fn read_u64_be(f: &mut RawFile) -> Result<u64> {
            u64::read_be(f).map_err(Error::ReadingHeader)
        }

        let version = read_u32_be(f)?;

        let mut header = QcowHeader {
            magic,
            version,
            backing_file_offset: read_u64_be(f)?,
            backing_file_size: read_u32_be(f)?,
            cluster_bits: read_u32_be(f)?,
            size: read_u64_be(f)?,
            crypt_method: read_u32_be(f)?,
            l1_size: read_u32_be(f)?,
            l1_table_offset: read_u64_be(f)?,
            refcount_table_offset: read_u64_be(f)?,
            refcount_table_clusters: read_u32_be(f)?,
            nb_snapshots: read_u32_be(f)?,
            snapshots_offset: read_u64_be(f)?,
            incompatible_features: if version == 2 { 0 } else { read_u64_be(f)? },
            compatible_features: if version == 2 { 0 } else { read_u64_be(f)? },
            autoclear_features: if version == 2 { 0 } else { read_u64_be(f)? },
            refcount_order: if version == 2 {
                DEFAULT_REFCOUNT_ORDER
            } else {
                read_u32_be(f)?
            },
            header_size: if version == 2 {
                V2_BARE_HEADER_SIZE
            } else {
                read_u32_be(f)?
            },
            compression_type: CompressionType::Zlib,
            backing_file: None,
        };
        if version == 3 && header.header_size > V3_BARE_HEADER_SIZE {
            let raw_compression_type = read_u64_be(f)? >> (64 - 8);
            header.compression_type = if raw_compression_type == COMPRESSION_TYPE_ZLIB {
                Ok(CompressionType::Zlib)
            } else if raw_compression_type == COMPRESSION_TYPE_ZSTD {
                Ok(CompressionType::Zstd)
            } else {
                Err(Error::UnsupportedCompressionType)
            }?;
        }
        if header.backing_file_size > MAX_BACKING_FILE_SIZE {
            return Err(Error::BackingFileTooLong(header.backing_file_size as usize));
        }
        if header.backing_file_offset != 0 {
            f.seek(SeekFrom::Start(header.backing_file_offset))
                .map_err(Error::ReadingHeader)?;
            let mut backing_file_name_bytes = vec![0u8; header.backing_file_size as usize];
            f.read_exact(&mut backing_file_name_bytes)
                .map_err(Error::ReadingHeader)?;
            let path = String::from_utf8(backing_file_name_bytes)
                .map_err(|err| Error::InvalidBackingFileName(err.utf8_error()))?;
            header.backing_file = Some(BackingFileConfig { path, format: None });
        }

        if version == 3 {
            // Check for unsupported incompatible features first
            let features = IncompatFeatures::from_bits_retain(header.incompatible_features);
            let unsupported = features - IncompatFeatures::SUPPORTED;
            if !unsupported.is_empty() {
                // Read extensions only to get feature names for error reporting
                let mut feature_table = Vec::new();
                if header.header_size > V3_BARE_HEADER_SIZE {
                    let _ = Self::read_header_extensions(f, &mut header, Some(&mut feature_table));
                }
                return Err(Error::UnsupportedFeature(MissingFeatureError::new(
                    unsupported,
                    feature_table,
                )));
            }

            // Features OK, now read extensions normally
            if header.header_size > V3_BARE_HEADER_SIZE {
                Self::read_header_extensions(f, &mut header, None)?;
            }
        }

        Ok(header)
    }

    pub fn get_decoder(&self) -> Box<dyn Decoder> {
        match self.compression_type {
            CompressionType::Zlib => Box::new(ZlibDecoder {}),
            CompressionType::Zstd => Box::new(ZstdDecoder {}),
        }
    }

    pub fn create_for_size_and_path(
        version: u32,
        size: u64,
        backing_file: Option<&str>,
    ) -> Result<QcowHeader> {
        let header_size = if version == 2 {
            V2_BARE_HEADER_SIZE
        } else {
            V3_BARE_HEADER_SIZE + QCOW_EMPTY_HEADER_EXTENSION_SIZE
        };
        let cluster_bits: u32 = DEFAULT_CLUSTER_BITS;
        let cluster_size: u32 = 0x01 << cluster_bits;
        let max_length: usize = (cluster_size - header_size) as usize;
        if let Some(path) = backing_file
            && path.len() > max_length
        {
            return Err(Error::BackingFileTooLong(path.len() - max_length));
        }

        // L2 blocks are always one cluster long. They contain cluster_size/sizeof(u64) addresses.
        let entries_per_cluster: u32 = cluster_size / size_of::<u64>() as u32;
        let num_clusters: u32 = div_round_up_u64(size, u64::from(cluster_size)) as u32;
        let num_l2_clusters: u32 = div_round_up_u32(num_clusters, entries_per_cluster);
        let l1_clusters: u32 = div_round_up_u32(num_l2_clusters, entries_per_cluster);
        let header_clusters = div_round_up_u32(size_of::<QcowHeader>() as u32, cluster_size);
        Ok(QcowHeader {
            magic: QCOW_MAGIC,
            version,
            backing_file_offset: backing_file.map_or(0, |_| {
                header_size
                    + if version == 3 {
                        QCOW_EMPTY_HEADER_EXTENSION_SIZE
                    } else {
                        0
                    }
            }) as u64,
            backing_file_size: backing_file.map_or(0, |x| x.len()) as u32,
            cluster_bits: DEFAULT_CLUSTER_BITS,
            size,
            crypt_method: 0,
            l1_size: num_l2_clusters,
            l1_table_offset: u64::from(cluster_size),
            // The refcount table is after l1 + header.
            refcount_table_offset: u64::from(cluster_size * (l1_clusters + 1)),
            refcount_table_clusters: {
                // Pre-allocate enough clusters for the entire refcount table as it must be
                // continuous in the file. Allocate enough space to refcount all clusters, including
                // the refcount clusters.
                let max_refcount_clusters = max_refcount_clusters(
                    DEFAULT_REFCOUNT_ORDER,
                    cluster_size,
                    num_clusters + l1_clusters + num_l2_clusters + header_clusters,
                ) as u32;
                // The refcount table needs to store the offset of each refcount cluster.
                div_round_up_u32(
                    max_refcount_clusters * size_of::<u64>() as u32,
                    cluster_size,
                )
            },
            nb_snapshots: 0,
            snapshots_offset: 0,
            incompatible_features: 0,
            compatible_features: 0,
            autoclear_features: 0,
            refcount_order: DEFAULT_REFCOUNT_ORDER,
            header_size,
            compression_type: CompressionType::Zlib,
            backing_file: backing_file.map(|path| BackingFileConfig {
                path: String::from(path),
                format: None,
            }),
        })
    }

    /// Write the header to `file`.
    pub fn write_to<F: Write + Seek>(&self, file: &mut F) -> Result<()> {
        // Writes the next u32 to the file.
        fn write_u32_be<F: Write>(f: &mut F, value: u32) -> Result<()> {
            u32::write_be(f, value).map_err(Error::WritingHeader)
        }

        // Writes the next u64 to the file.
        fn write_u64_be<F: Write>(f: &mut F, value: u64) -> Result<()> {
            u64::write_be(f, value).map_err(Error::WritingHeader)
        }

        write_u32_be(file, self.magic)?;
        write_u32_be(file, self.version)?;
        write_u64_be(file, self.backing_file_offset)?;
        write_u32_be(file, self.backing_file_size)?;
        write_u32_be(file, self.cluster_bits)?;
        write_u64_be(file, self.size)?;
        write_u32_be(file, self.crypt_method)?;
        write_u32_be(file, self.l1_size)?;
        write_u64_be(file, self.l1_table_offset)?;
        write_u64_be(file, self.refcount_table_offset)?;
        write_u32_be(file, self.refcount_table_clusters)?;
        write_u32_be(file, self.nb_snapshots)?;
        write_u64_be(file, self.snapshots_offset)?;

        if self.version == 3 {
            write_u64_be(file, self.incompatible_features)?;
            write_u64_be(file, self.compatible_features)?;
            write_u64_be(file, self.autoclear_features)?;
            write_u32_be(file, self.refcount_order)?;
            write_u32_be(file, self.header_size)?;

            if self.header_size > V3_BARE_HEADER_SIZE {
                write_u64_be(file, 0)?; // no compression
            }

            write_u32_be(file, 0)?; // header extension type: end of header extension area
            write_u32_be(file, 0)?; // length of header extension data: 0
        }

        if let Some(backing_file_path) = self.backing_file.as_ref().map(|bf| &bf.path) {
            if self.backing_file_offset > 0 {
                file.seek(SeekFrom::Start(self.backing_file_offset))
                    .map_err(Error::WritingHeader)?;
            }
            write!(file, "{backing_file_path}").map_err(Error::WritingHeader)?;
        }

        // Set the file length by seeking and writing a zero to the last byte. This avoids needing
        // a `File` instead of anything that implements seek as the `file` argument.
        // Zeros out the l1 and refcount table clusters.
        let cluster_size = 0x01u64 << self.cluster_bits;
        let refcount_blocks_size = u64::from(self.refcount_table_clusters) * cluster_size;
        file.seek(SeekFrom::Start(
            self.refcount_table_offset + refcount_blocks_size - 2,
        ))
        .map_err(Error::WritingHeader)?;
        file.write(&[0u8]).map_err(Error::WritingHeader)?;

        Ok(())
    }

    /// Write only the incompatible_features field to the file at its fixed offset.
    fn write_incompatible_features<F: Seek + Write>(&self, file: &mut F) -> Result<()> {
        if self.version != 3 {
            return Ok(());
        }
        file.seek(SeekFrom::Start(V2_BARE_HEADER_SIZE as u64))
            .map_err(Error::WritingHeader)?;
        u64::write_be(file, self.incompatible_features).map_err(Error::WritingHeader)?;
        Ok(())
    }

    /// Set or clear the dirty bit for QCOW2 v3 images.
    ///
    /// When `dirty` is true, sets the bit to indicate the image is in use.
    /// When `dirty` is false, clears the bit to indicate a clean shutdown.
    pub fn set_dirty_bit<F: Seek + Write + FileSync>(
        &mut self,
        file: &mut F,
        dirty: bool,
    ) -> Result<()> {
        if self.version == 3 {
            if dirty {
                self.incompatible_features |= IncompatFeatures::DIRTY.bits();
            } else {
                self.incompatible_features &= !IncompatFeatures::DIRTY.bits();
            }
            self.write_incompatible_features(file)?;
            file.fsync().map_err(Error::WritingHeader)?;
        }
        Ok(())
    }

    /// Set the corrupt bit for QCOW2 v3 images.
    ///
    /// This marks the image as corrupted. Once set, the image can only be
    /// opened read-only until repaired.
    pub fn set_corrupt_bit<F: Seek + Write + FileSync>(&mut self, file: &mut F) -> Result<()> {
        if self.version == 3 {
            self.incompatible_features |= IncompatFeatures::CORRUPT.bits();
            self.write_incompatible_features(file)?;
            file.fsync().map_err(Error::WritingHeader)?;
        }
        Ok(())
    }

    pub fn is_corrupt(&self) -> bool {
        IncompatFeatures::from_bits_truncate(self.incompatible_features)
            .contains(IncompatFeatures::CORRUPT)
    }
}

fn max_refcount_clusters(refcount_order: u32, cluster_size: u32, num_clusters: u32) -> u64 {
    // Use u64 as the product of the u32 inputs can overflow.
    let refcount_bits = 0x01u64 << u64::from(refcount_order);
    let cluster_bits = u64::from(cluster_size) * 8;
    let for_data = div_round_up_u64(u64::from(num_clusters) * refcount_bits, cluster_bits);
    let for_refcounts = div_round_up_u64(for_data * refcount_bits, cluster_bits);
    for_data + for_refcounts
}

trait BackingFileOps: Send + Seek + Read {
    fn read_at(&mut self, address: u64, buf: &mut [u8]) -> std::io::Result<()> {
        self.seek(SeekFrom::Start(address))?;
        self.read_exact(buf)
    }
    fn clone_box(&self) -> Box<dyn BackingFileOps>;
}

impl BackingFileOps for QcowFile {
    fn clone_box(&self) -> Box<dyn BackingFileOps> {
        Box::new(self.clone())
    }
}

impl BackingFileOps for RawFile {
    fn clone_box(&self) -> Box<dyn BackingFileOps> {
        Box::new(self.clone())
    }
}

/// Backing file wrapper
struct BackingFile {
    inner: Box<dyn BackingFileOps>,
}

impl BackingFile {
    fn new(
        backing_file_config: Option<&BackingFileConfig>,
        direct_io: bool,
        max_nesting_depth: u32,
    ) -> Result<Option<Self>> {
        let Some(config) = backing_file_config else {
            return Ok(None);
        };

        // Check nesting depth - applies to any backing file
        if max_nesting_depth == 0 {
            return Err(Error::MaxNestingDepthExceeded);
        }

        let backing_raw_file = OpenOptions::new()
            .read(true)
            .open(&config.path)
            .map_err(Error::BackingFileIo)?;

        let mut raw_file = RawFile::new(backing_raw_file, direct_io);

        // Determine backing file format from header extension or auto-detect
        let backing_format = match config.format {
            Some(format) => format,
            None => detect_image_type(&mut raw_file)?,
        };

        let inner: Box<dyn BackingFileOps> = match backing_format {
            ImageType::Raw => Box::new(raw_file),
            ImageType::Qcow2 => {
                let backing_qcow =
                    QcowFile::from_with_nesting_depth(raw_file, max_nesting_depth - 1)
                        .map_err(|e| Error::BackingFileOpen(Box::new(e)))?;
                Box::new(backing_qcow)
            }
        };

        Ok(Some(Self { inner }))
    }

    #[inline]
    fn read_at(&mut self, address: u64, buf: &mut [u8]) -> std::io::Result<()> {
        self.inner.read_at(address, buf)
    }
}

impl Clone for BackingFile {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone_box(),
        }
    }
}

impl Debug for BackingFile {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("BackingFile").finish()
    }
}

/// Represents a qcow2 file. This is a sparse file format maintained by the qemu project.
/// Full documentation of the format can be found in the qemu repository.
///
/// # Example
///
/// ```
/// # use block::qcow::{self, QcowFile, RawFile};
/// # use std::io::{Read, Seek, SeekFrom};
/// # fn test(file: std::fs::File) -> std::io::Result<()> {
///     let mut raw_img = RawFile::new(file, false);
///     let mut q = QcowFile::from(raw_img).expect("Can't open qcow file");
///     let mut buf = [0u8; 12];
///     q.seek(SeekFrom::Start(10 as u64))?;
///     q.read(&mut buf[..])?;
/// #   Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct QcowFile {
    raw_file: QcowRawFile,
    header: QcowHeader,
    l1_table: VecCache<u64>,
    l2_entries: u64,
    l2_cache: CacheMap<VecCache<u64>>,
    refcounts: RefCount,
    current_offset: u64,
    unref_clusters: Vec<u64>, // List of freshly unreferenced clusters.
    // List of unreferenced clusters available to be used. unref clusters become available once the
    // removal of references to them have been synced to disk.
    avail_clusters: Vec<u64>,
    backing_file: Option<BackingFile>,
}

impl QcowFile {
    /// Creates a QcowFile from `file`. File must be a valid qcow2 image.
    ///
    /// Additionally, max nesting depth of this qcow2 image will be set to default value 10.
    pub fn from(file: RawFile) -> Result<QcowFile> {
        Self::from_with_nesting_depth(file, MAX_NESTING_DEPTH)
    }

    /// Creates a QcowFile from `file` and with a max nesting depth. File must be a valid qcow2
    /// image.
    pub fn from_with_nesting_depth(mut file: RawFile, max_nesting_depth: u32) -> Result<QcowFile> {
        let header = QcowHeader::new(&mut file)?;

        // Only v2 and v3 files are supported.
        if header.version != 2 && header.version != 3 {
            return Err(Error::UnsupportedVersion(header.version));
        }

        // Make sure that the L1 table fits in RAM.
        if u64::from(header.l1_size) > MAX_RAM_POINTER_TABLE_SIZE {
            return Err(Error::InvalidL1TableSize(header.l1_size));
        }

        let cluster_bits: u32 = header.cluster_bits;
        if !(MIN_CLUSTER_BITS..=MAX_CLUSTER_BITS).contains(&cluster_bits) {
            return Err(Error::InvalidClusterSize);
        }
        let cluster_size = 0x01u64 << cluster_bits;

        // Limit the total size of the disk.
        if header.size > MAX_QCOW_FILE_SIZE {
            return Err(Error::FileTooBig(header.size));
        }

        let direct_io = file.is_direct();

        let backing_file =
            BackingFile::new(header.backing_file.as_ref(), direct_io, max_nesting_depth)?;

        // Validate refcount order to be 0..6
        let refcount_bits: u64 = 0x01u64
            .checked_shl(header.refcount_order)
            .ok_or(Error::UnsupportedRefcountOrder)?;
        if refcount_bits > 64 {
            return Err(Error::UnsupportedRefcountOrder);
        }

        // Need at least one refcount cluster
        if header.refcount_table_clusters == 0 {
            return Err(Error::NoRefcountClusters);
        }
        offset_is_cluster_boundary(header.l1_table_offset, header.cluster_bits)?;
        offset_is_cluster_boundary(header.snapshots_offset, header.cluster_bits)?;
        // refcount table must be a cluster boundary, and within the file's virtual or actual size.
        offset_is_cluster_boundary(header.refcount_table_offset, header.cluster_bits)?;
        let file_size = file.metadata().map_err(Error::GettingFileSize)?.len();
        if header.refcount_table_offset > max(file_size, header.size) {
            return Err(Error::RefcountTableOffEnd);
        }

        // The first cluster should always have a non-zero refcount, so if it is 0,
        // this is an old file with broken refcounts, which requires a rebuild.
        let mut refcount_rebuild_required = true;
        file.seek(SeekFrom::Start(header.refcount_table_offset))
            .map_err(Error::SeekingFile)?;
        let first_refblock_addr = u64::read_be(&mut file).map_err(Error::ReadingHeader)?;
        if first_refblock_addr != 0 {
            file.seek(SeekFrom::Start(first_refblock_addr))
                .map_err(Error::SeekingFile)?;
            let first_cluster_refcount = u16::read_be(&mut file).map_err(Error::ReadingHeader)?;
            if first_cluster_refcount != 0 {
                refcount_rebuild_required = false;
            }
        }

        if (header.compatible_features & COMPATIBLE_FEATURES_LAZY_REFCOUNTS) != 0 {
            refcount_rebuild_required = true;
        }

        let mut raw_file = QcowRawFile::from(file, cluster_size, refcount_bits)
            .ok_or(Error::InvalidClusterSize)?;
        let is_writable = raw_file.file().is_writable();

        if header.is_corrupt() {
            if is_writable {
                return Err(Error::CorruptImage);
            }
            let path = read_link(format!("/proc/self/fd/{}", raw_file.file().as_raw_fd()))
                .map_or_else(|_| "<unknown>".to_string(), |p| p.display().to_string());
            warn!("QCOW2 image is marked corrupt, opening read-only: {path}");
        }

        // Image already has dirty bit set. Refcounts may be invalid.
        if IncompatFeatures::from_bits_truncate(header.incompatible_features)
            .contains(IncompatFeatures::DIRTY)
        {
            log::warn!("QCOW2 image not cleanly closed, rebuilding refcounts");
            refcount_rebuild_required = true;
        }

        // Skip refcount rebuilding for readonly files.
        if refcount_rebuild_required && is_writable {
            QcowFile::rebuild_refcounts(&mut raw_file, header.clone())?;
        }

        let entries_per_cluster = cluster_size / size_of::<u64>() as u64;
        let num_clusters = div_round_up_u64(header.size, cluster_size);
        let num_l2_clusters = div_round_up_u64(num_clusters, entries_per_cluster);
        let l1_clusters = div_round_up_u64(num_l2_clusters, entries_per_cluster);
        let header_clusters = div_round_up_u64(size_of::<QcowHeader>() as u64, cluster_size);
        if num_l2_clusters > MAX_RAM_POINTER_TABLE_SIZE {
            return Err(Error::TooManyL1Entries(num_l2_clusters));
        }
        let l1_table = VecCache::from_vec(
            raw_file
                .read_pointer_table(
                    header.l1_table_offset,
                    num_l2_clusters,
                    Some(L1_TABLE_OFFSET_MASK),
                )
                .map_err(Error::ReadingHeader)?,
        );

        let num_clusters = div_round_up_u64(header.size, cluster_size);
        let refcount_clusters = max_refcount_clusters(
            header.refcount_order,
            cluster_size as u32,
            (num_clusters + l1_clusters + num_l2_clusters + header_clusters) as u32,
        );
        // Check that the given header doesn't have a suspiciously sized refcount table.
        if u64::from(header.refcount_table_clusters) > 2 * refcount_clusters {
            return Err(Error::RefcountTableTooLarge);
        }
        if l1_clusters + refcount_clusters > MAX_RAM_POINTER_TABLE_SIZE {
            return Err(Error::TooManyRefcounts(refcount_clusters));
        }
        let refcount_block_entries = cluster_size * 8 / refcount_bits;
        let refcounts = RefCount::new(
            &mut raw_file,
            header.refcount_table_offset,
            refcount_clusters,
            refcount_block_entries,
            cluster_size,
            refcount_bits,
        )
        .map_err(Error::ReadingRefCounts)?;

        let l2_entries = cluster_size / size_of::<u64>() as u64;

        let mut qcow = QcowFile {
            raw_file,
            header,
            l1_table,
            l2_entries,
            l2_cache: CacheMap::new(100),
            refcounts,
            current_offset: 0,
            unref_clusters: Vec::new(),
            avail_clusters: Vec::new(),
            backing_file,
        };

        // Check that the L1 and refcount tables fit in a 64bit address space.
        qcow.header
            .l1_table_offset
            .checked_add(qcow.l1_address_offset(qcow.virtual_size()))
            .ok_or(Error::InvalidL1TableOffset)?;
        qcow.header
            .refcount_table_offset
            .checked_add(u64::from(qcow.header.refcount_table_clusters) * cluster_size)
            .ok_or(Error::InvalidRefcountTableOffset)?;

        qcow.find_avail_clusters()?;

        if !IncompatFeatures::from_bits_truncate(qcow.header.incompatible_features)
            .contains(IncompatFeatures::DIRTY)
            && is_writable
        {
            qcow.header.set_dirty_bit(qcow.raw_file.file_mut(), true)?;
        }

        Ok(qcow)
    }

    /// Creates a new QcowFile at the given path.
    pub fn new(file: RawFile, version: u32, virtual_size: u64) -> Result<QcowFile> {
        let header = QcowHeader::create_for_size_and_path(version, virtual_size, None)?;
        QcowFile::new_from_header(file, &header)
    }

    /// Creates a new QcowFile at the given path with a backing file.
    pub fn new_from_backing(
        file: RawFile,
        version: u32,
        backing_file_size: u64,
        backing_config: &BackingFileConfig,
    ) -> Result<QcowFile> {
        let mut header = QcowHeader::create_for_size_and_path(
            version,
            backing_file_size,
            Some(&backing_config.path),
        )?;
        if let Some(backing_file) = &mut header.backing_file {
            backing_file.format = backing_config.format;
        }
        QcowFile::new_from_header(file, &header)
        // backing_file is loaded by new_from_header -> Self::from() based on the header
    }

    fn new_from_header(mut file: RawFile, header: &QcowHeader) -> Result<QcowFile> {
        file.rewind().map_err(Error::SeekingFile)?;
        header.write_to(&mut file)?;

        let mut qcow = Self::from(file)?;

        // Set the refcount for each refcount table cluster.
        let cluster_size = 0x01u64 << qcow.header.cluster_bits;
        let refcount_table_base = qcow.header.refcount_table_offset;
        let end_cluster_addr =
            refcount_table_base + u64::from(qcow.header.refcount_table_clusters) * cluster_size;

        let mut cluster_addr = 0;
        while cluster_addr < end_cluster_addr {
            let mut unref_clusters = qcow
                .set_cluster_refcount(cluster_addr, 1)
                .map_err(Error::SettingRefcountRefcount)?;
            qcow.unref_clusters.append(&mut unref_clusters);
            cluster_addr += cluster_size;
        }

        Ok(qcow)
    }

    pub fn set_backing_file(&mut self, backing: Option<Box<Self>>) {
        self.backing_file = backing.map(|b| BackingFile {
            inner: Box::new(*b),
        });
    }

    /// Returns the `QcowHeader` for this file.
    pub fn header(&self) -> &QcowHeader {
        &self.header
    }

    /// Returns the L1 lookup table for this file. This is only useful for debugging.
    pub fn l1_table(&self) -> &[u64] {
        self.l1_table.get_values()
    }

    /// Returns an L2_table of cluster addresses, only used for debugging.
    pub fn l2_table(&mut self, l1_index: usize) -> Result<Option<&[u64]>> {
        let l2_addr_disk = *self.l1_table.get(l1_index).ok_or(Error::InvalidIndex)?;

        if l2_addr_disk == 0 {
            // Reading from an unallocated cluster will return zeros.
            return Ok(None);
        }

        if !self.l2_cache.contains_key(l1_index) {
            // Not in the cache.
            let table = VecCache::from_vec(
                Self::read_l2_cluster(&mut self.raw_file, l2_addr_disk)
                    .map_err(Error::ReadingPointers)?,
            );
            let l1_table = &self.l1_table;
            let raw_file = &mut self.raw_file;
            self.l2_cache
                .insert(l1_index, table, |index, evicted| {
                    raw_file.write_pointer_table_direct(l1_table[index], evicted.iter())
                })
                .map_err(Error::EvictingCache)?;
        }

        // The index must exist as it was just inserted if it didn't already.
        Ok(Some(self.l2_cache.get(l1_index).unwrap().get_values()))
    }

    /// Returns the refcount table for this file. This is only useful for debugging.
    pub fn ref_table(&self) -> &[u64] {
        self.refcounts.ref_table()
    }

    /// Returns the `index`th refcount block from the file.
    pub fn refcount_block(&mut self, index: usize) -> Result<Option<&[u64]>> {
        self.refcounts
            .refcount_block(&mut self.raw_file, index)
            .map_err(Error::ReadingRefCountBlock)
    }

    /// Returns the first cluster in the file with a 0 refcount. Used for testing.
    pub fn first_zero_refcount(&mut self) -> Result<Option<u64>> {
        let file_size = self
            .raw_file
            .file_mut()
            .metadata()
            .map_err(Error::GettingFileSize)?
            .len();
        let cluster_size = 0x01u64 << self.header.cluster_bits;

        let mut cluster_addr = 0;
        while cluster_addr < file_size {
            let cluster_refcount = self
                .refcounts
                .get_cluster_refcount(&mut self.raw_file, cluster_addr)
                .map_err(Error::GettingRefcount)?;
            if cluster_refcount == 0 {
                return Ok(Some(cluster_addr));
            }
            cluster_addr += cluster_size;
        }
        Ok(None)
    }

    fn find_avail_clusters(&mut self) -> Result<()> {
        let cluster_size = self.raw_file.cluster_size();

        let file_size = self
            .raw_file
            .file_mut()
            .metadata()
            .map_err(Error::GettingFileSize)?
            .len();

        for i in (0..file_size).step_by(cluster_size as usize) {
            let refcount = self
                .refcounts
                .get_cluster_refcount(&mut self.raw_file, i)
                .map_err(Error::GettingRefcount)?;
            if refcount == 0 {
                self.avail_clusters.push(i);
            }
        }

        Ok(())
    }

    /// Rebuild the reference count tables.
    fn rebuild_refcounts(raw_file: &mut QcowRawFile, header: QcowHeader) -> Result<()> {
        fn add_ref(
            refcounts: &mut [u64],
            cluster_size: u64,
            cluster_address: u64,
            max_refcount: u64,
            refcount_bits: u64,
        ) -> Result<()> {
            let idx = (cluster_address / cluster_size) as usize;
            if idx >= refcounts.len() {
                return Err(Error::InvalidClusterIndex);
            }
            if refcounts[idx] >= max_refcount {
                return Err(Error::RefcountOverflow(refcount::Error::RefcountOverflow {
                    value: refcounts[idx] + 1,
                    max: max_refcount,
                    refcount_bits,
                }));
            }
            refcounts[idx] += 1;
            Ok(())
        }

        // Add a reference to the first cluster (header plus extensions).
        fn set_header_refcount(
            refcounts: &mut [u64],
            cluster_size: u64,
            max_refcount: u64,
            refcount_bits: u64,
        ) -> Result<()> {
            add_ref(refcounts, cluster_size, 0, max_refcount, refcount_bits)
        }

        // Add references to the L1 table clusters.
        fn set_l1_refcounts(
            refcounts: &mut [u64],
            header: &QcowHeader,
            cluster_size: u64,
            max_refcount: u64,
            refcount_bits: u64,
        ) -> Result<()> {
            let entries_per_cluster = cluster_size / size_of::<u64>() as u64;
            let l1_clusters = div_round_up_u64(u64::from(header.l1_size), entries_per_cluster);
            let l1_table_offset = header.l1_table_offset;
            for i in 0..l1_clusters {
                add_ref(
                    refcounts,
                    cluster_size,
                    l1_table_offset + i * cluster_size,
                    max_refcount,
                    refcount_bits,
                )?;
            }
            Ok(())
        }

        // Traverse the L1 and L2 tables to find all reachable data clusters.
        fn set_data_refcounts(
            refcounts: &mut [u64],
            header: &QcowHeader,
            cluster_size: u64,
            raw_file: &mut QcowRawFile,
            max_refcount: u64,
            refcount_bits: u64,
        ) -> Result<()> {
            let l1_table = raw_file
                .read_pointer_table(
                    header.l1_table_offset,
                    u64::from(header.l1_size),
                    Some(L1_TABLE_OFFSET_MASK),
                )
                .map_err(Error::ReadingPointers)?;
            for l1_index in 0..header.l1_size as usize {
                let l2_addr_disk = *l1_table.get(l1_index).ok_or(Error::InvalidIndex)?;
                if l2_addr_disk != 0 {
                    // Add a reference to the L2 table cluster itself.
                    add_ref(
                        refcounts,
                        cluster_size,
                        l2_addr_disk,
                        max_refcount,
                        refcount_bits,
                    )?;

                    // Read the L2 table and find all referenced data clusters.
                    let l2_table = raw_file
                        .read_pointer_table(
                            l2_addr_disk,
                            cluster_size / size_of::<u64>() as u64,
                            Some(L2_TABLE_OFFSET_MASK),
                        )
                        .map_err(Error::ReadingPointers)?;
                    for data_cluster_addr in l2_table {
                        if data_cluster_addr != 0 {
                            add_ref(
                                refcounts,
                                cluster_size,
                                data_cluster_addr,
                                max_refcount,
                                refcount_bits,
                            )?;
                        }
                    }
                }
            }

            Ok(())
        }

        // Add references to the top-level refcount table clusters.
        fn set_refcount_table_refcounts(
            refcounts: &mut [u64],
            header: &QcowHeader,
            cluster_size: u64,
            max_refcount: u64,
            refcount_bits: u64,
        ) -> Result<()> {
            let refcount_table_offset = header.refcount_table_offset;
            for i in 0..u64::from(header.refcount_table_clusters) {
                add_ref(
                    refcounts,
                    cluster_size,
                    refcount_table_offset + i * cluster_size,
                    max_refcount,
                    refcount_bits,
                )?;
            }
            Ok(())
        }

        // Allocate clusters for refblocks.
        // This needs to be done last so that we have the correct refcounts for all other
        // clusters.
        fn alloc_refblocks(
            refcounts: &mut [u64],
            cluster_size: u64,
            refblock_clusters: u64,
            max_refcount: u64,
            refcount_bits: u64,
        ) -> Result<Vec<u64>> {
            let mut ref_table = vec![0; refblock_clusters as usize];
            let mut first_free_cluster: u64 = 0;
            for refblock_addr in &mut ref_table {
                loop {
                    if first_free_cluster >= refcounts.len() as u64 {
                        return Err(Error::NotEnoughSpaceForRefcounts);
                    }
                    if refcounts[first_free_cluster as usize] == 0 {
                        break;
                    }
                    first_free_cluster += 1;
                }

                *refblock_addr = first_free_cluster * cluster_size;
                add_ref(
                    refcounts,
                    cluster_size,
                    *refblock_addr,
                    max_refcount,
                    refcount_bits,
                )?;

                first_free_cluster += 1;
            }

            Ok(ref_table)
        }

        // Write the updated reference count blocks and reftable.
        fn write_refblocks(
            refcounts: &[u64],
            mut header: QcowHeader,
            ref_table: &[u64],
            raw_file: &mut QcowRawFile,
            refcount_block_entries: u64,
        ) -> Result<()> {
            // Rewrite the header with lazy refcounts enabled while we are rebuilding the tables.
            header.compatible_features |= COMPATIBLE_FEATURES_LAZY_REFCOUNTS;
            raw_file.file_mut().rewind().map_err(Error::SeekingFile)?;
            header.write_to(raw_file.file_mut())?;

            for (i, refblock_addr) in ref_table.iter().enumerate() {
                // Write a block of refcounts to the location indicated by refblock_addr.
                let refblock_start = i * (refcount_block_entries as usize);
                let refblock_end = min(
                    refcounts.len(),
                    refblock_start + refcount_block_entries as usize,
                );
                let refblock = &refcounts[refblock_start..refblock_end];
                raw_file
                    .write_refcount_block(*refblock_addr, refblock)
                    .map_err(Error::WritingHeader)?;

                // If this is the last (partial) cluster, pad it out to a full refblock cluster.
                if refblock.len() < refcount_block_entries as usize {
                    let refblock_padding =
                        vec![0u64; refcount_block_entries as usize - refblock.len()];
                    let byte_offset =
                        refblock.len() as u64 * raw_file.cluster_size() / refcount_block_entries;
                    raw_file
                        .write_refcount_block(*refblock_addr + byte_offset, &refblock_padding)
                        .map_err(Error::WritingHeader)?;
                }
            }

            // Rewrite the top-level refcount table.
            raw_file
                .write_pointer_table_direct(header.refcount_table_offset, ref_table.iter())
                .map_err(Error::WritingHeader)?;

            // Rewrite the header again, now with lazy refcounts disabled.
            header.compatible_features &= !COMPATIBLE_FEATURES_LAZY_REFCOUNTS;
            raw_file.file_mut().rewind().map_err(Error::SeekingFile)?;
            header.write_to(raw_file.file_mut())?;

            Ok(())
        }

        let cluster_size = raw_file.cluster_size();

        let file_size = raw_file
            .file_mut()
            .metadata()
            .map_err(Error::GettingFileSize)?
            .len();

        let refcount_bits = 1u64 << header.refcount_order;
        let max_refcount = if refcount_bits == 64 {
            u64::MAX
        } else {
            (1u64 << refcount_bits) - 1
        };
        let refcount_block_entries = cluster_size * 8 / refcount_bits;
        let pointers_per_cluster = cluster_size / size_of::<u64>() as u64;
        let data_clusters = div_round_up_u64(header.size, cluster_size);
        let l2_clusters = div_round_up_u64(data_clusters, pointers_per_cluster);
        let l1_clusters = div_round_up_u64(l2_clusters, pointers_per_cluster);
        let header_clusters = div_round_up_u64(size_of::<QcowHeader>() as u64, cluster_size);
        let max_clusters = data_clusters + l2_clusters + l1_clusters + header_clusters;
        let mut max_valid_cluster_index = max_clusters;
        let refblock_clusters = div_round_up_u64(max_valid_cluster_index, refcount_block_entries);
        let reftable_clusters = div_round_up_u64(refblock_clusters, pointers_per_cluster);
        // Account for refblocks and the ref table size needed to address them.
        let refblocks_for_refs = div_round_up_u64(
            refblock_clusters + reftable_clusters,
            refcount_block_entries,
        );
        let reftable_clusters_for_refs =
            div_round_up_u64(refblocks_for_refs, refcount_block_entries);
        max_valid_cluster_index += refblock_clusters + reftable_clusters;
        max_valid_cluster_index += refblocks_for_refs + reftable_clusters_for_refs;

        if max_valid_cluster_index > MAX_RAM_POINTER_TABLE_SIZE {
            return Err(Error::InvalidRefcountTableSize(max_valid_cluster_index));
        }

        let max_valid_cluster_offset = max_valid_cluster_index * cluster_size;
        if max_valid_cluster_offset < file_size - cluster_size {
            return Err(Error::InvalidRefcountTableSize(max_valid_cluster_offset));
        }

        let mut refcounts = vec![0; max_valid_cluster_index as usize];

        // Find all references clusters and rebuild refcounts.
        set_header_refcount(&mut refcounts, cluster_size, max_refcount, refcount_bits)?;
        set_l1_refcounts(
            &mut refcounts,
            &header,
            cluster_size,
            max_refcount,
            refcount_bits,
        )?;
        set_data_refcounts(
            &mut refcounts,
            &header,
            cluster_size,
            raw_file,
            max_refcount,
            refcount_bits,
        )?;
        set_refcount_table_refcounts(
            &mut refcounts,
            &header,
            cluster_size,
            max_refcount,
            refcount_bits,
        )?;

        // Allocate clusters to store the new reference count blocks.
        let ref_table = alloc_refblocks(
            &mut refcounts,
            cluster_size,
            refblock_clusters,
            max_refcount,
            refcount_bits,
        )?;

        // Write updated reference counts and point the reftable at them.
        write_refblocks(
            &refcounts,
            header,
            &ref_table,
            raw_file,
            refcount_block_entries,
        )
    }

    // Limits the range so that it doesn't exceed the virtual size of the file.
    fn limit_range_file(&self, address: u64, count: usize) -> usize {
        if address.checked_add(count as u64).is_none() || address > self.virtual_size() {
            return 0;
        }
        min(count as u64, self.virtual_size() - address) as usize
    }

    // Limits the range so that it doesn't overflow the end of a cluster.
    fn limit_range_cluster(&self, address: u64, count: usize) -> usize {
        let offset: u64 = self.raw_file.cluster_offset(address);
        let limit = self.raw_file.cluster_size() - offset;
        min(count as u64, limit) as usize
    }

    // Gets the maximum virtual size of this image.
    fn virtual_size(&self) -> u64 {
        self.header.size
    }

    // Gets the offset of `address` in the L1 table.
    fn l1_address_offset(&self, address: u64) -> u64 {
        let l1_index = self.l1_table_index(address);
        l1_index * size_of::<u64>() as u64
    }

    // Gets the offset of `address` in the L1 table.
    fn l1_table_index(&self, address: u64) -> u64 {
        (address / self.raw_file.cluster_size()) / self.l2_entries
    }

    // Gets the offset of `address` in the L2 table.
    fn l2_table_index(&self, address: u64) -> u64 {
        (address / self.raw_file.cluster_size()) % self.l2_entries
    }

    /// Attempts to set the corrupt bit, logging failures without propagating them.
    ///
    /// This is "best effort" because the write may fail due to various reasons like
    /// disk full, readonly storage, etc. This method is called just before returning
    /// EIO to the caller. The error is not propagated because the original corruption
    /// error is more important to return to the call site than a secondary I/O
    /// failure from marking the image.
    fn set_corrupt_bit_best_effort(&mut self) {
        if let Err(e) = self.header.set_corrupt_bit(self.raw_file.file_mut()) {
            warn!("Failed to persist corrupt bit: {e}");
        }
    }

    // Decompress the cluster, return EIO on failure
    fn decompress_l2_cluster(&mut self, l2_entry: u64) -> std::io::Result<Vec<u8>> {
        let (compressed_cluster_addr, compressed_cluster_size) =
            l2_entry_compressed_cluster_layout(l2_entry, self.header.cluster_bits);
        // Read compressed cluster from raw file
        self.raw_file
            .file_mut()
            .seek(SeekFrom::Start(compressed_cluster_addr))?;
        let mut compressed_cluster = vec![0; compressed_cluster_size];
        self.raw_file
            .file_mut()
            .read_exact(&mut compressed_cluster)?;
        let decoder = self.header.get_decoder();
        // Decompress
        let cluster_size = self.raw_file.cluster_size() as usize;
        let mut decompressed_cluster = vec![0; cluster_size];
        let decompressed_size = decoder
            .decode(&compressed_cluster, &mut decompressed_cluster)
            .map_err(|_| {
                self.set_corrupt_bit_best_effort();
                io::Error::from_raw_os_error(EIO)
            })?;
        if decompressed_size as u64 != self.raw_file.cluster_size() {
            self.set_corrupt_bit_best_effort();
            return Err(std::io::Error::from_raw_os_error(EIO));
        }
        Ok(decompressed_cluster)
    }

    fn file_read(
        &mut self,
        address: u64,
        count: usize,
        buf: &mut [u8],
    ) -> std::io::Result<Option<()>> {
        let err_inval = std::io::Error::from_raw_os_error(EINVAL);
        if address >= self.virtual_size() {
            return Err(err_inval);
        }

        let l1_index = self.l1_table_index(address) as usize;
        let l2_addr_disk = *self
            .l1_table
            .get(l1_index)
            .ok_or_else(|| std::io::Error::from_raw_os_error(EINVAL))?;

        if l2_addr_disk == 0 {
            // Reading from an unallocated cluster will return zeros.
            return Ok(None);
        }

        let l2_index = self.l2_table_index(address) as usize;

        self.cache_l2_cluster(l1_index, l2_addr_disk, false)?;

        let l2_entry = self.l2_cache.get(l1_index).unwrap()[l2_index];
        if l2_entry_is_empty(l2_entry) {
            // Reading from an unallocated cluster will return zeros.
            return Ok(None);
        } else if l2_entry_is_compressed(l2_entry) {
            // Compressed cluster.
            // Read it, decompress, then return slice from decompressed data.
            let mut decompressed_cluster = self.decompress_l2_cluster(l2_entry)?;
            decompressed_cluster.resize(self.raw_file.cluster_size() as usize, 0);
            let start = self.raw_file.cluster_offset(address) as usize;
            let end = start.checked_add(count);
            if end.is_none() || end.unwrap() > decompressed_cluster.len() {
                return Err(err_inval);
            }
            buf[..count].copy_from_slice(&decompressed_cluster[start..end.unwrap()]);
        } else if l2_entry_is_zero(l2_entry) {
            // Cluster with zero flag reads as zeros without accessing disk.
            return Ok(None);
        } else {
            let cluster_addr = l2_entry_std_cluster_addr(l2_entry);
            if cluster_addr & (self.raw_file.cluster_size() - 1) != 0 {
                self.set_corrupt_bit_best_effort();
                return Err(io::Error::from_raw_os_error(EIO));
            }
            let start = cluster_addr + self.raw_file.cluster_offset(address);
            let raw_file = self.raw_file.file_mut();
            raw_file.seek(SeekFrom::Start(start))?;
            raw_file.read_exact(buf)?;
        }
        Ok(Some(()))
    }

    // Gets the offset of the given guest address in the host file. If L1, L2, or data clusters need
    // to be allocated, they will be.
    fn file_offset_write(&mut self, address: u64) -> std::io::Result<u64> {
        if address >= self.virtual_size() {
            return Err(std::io::Error::from_raw_os_error(EINVAL));
        }

        let l1_index = self.l1_table_index(address) as usize;
        let l2_addr_disk = *self
            .l1_table
            .get(l1_index)
            .ok_or_else(|| std::io::Error::from_raw_os_error(EINVAL))?;
        let l2_index = self.l2_table_index(address) as usize;

        let mut set_refcounts = Vec::new();

        if let Some(new_addr) = self.cache_l2_cluster(l1_index, l2_addr_disk, true)? {
            // The cluster refcount starts at one meaning it is used but doesn't need COW.
            set_refcounts.push((new_addr, 1));
        }

        let l2_entry = self.l2_cache.get(l1_index).unwrap()[l2_index];
        let cluster_addr = if l2_entry_is_compressed(l2_entry) {
            // Writing to compressed cluster.

            let (compressed_cluster_addr, compressed_cluster_size) =
                l2_entry_compressed_cluster_layout(l2_entry, self.header.cluster_bits);

            // Allocate new cluster, decompress into new cluster, then use
            // offset of new cluster.
            let decompressed_cluster = self.decompress_l2_cluster(l2_entry)?;
            let cluster_addr = self.append_data_cluster(None)?;
            self.update_cluster_addr(l1_index, l2_index, cluster_addr, &mut set_refcounts)?;
            self.raw_file
                .file_mut()
                .seek(SeekFrom::Start(cluster_addr))?;
            let nwritten = self.raw_file.file_mut().write(&decompressed_cluster)?;
            if nwritten != decompressed_cluster.len() {
                self.set_corrupt_bit_best_effort();
                return Err(std::io::Error::from_raw_os_error(EIO));
            }

            // Decrement refcount for each cluster spanned by the old compressed data
            let compressed_clusters_end = self.raw_file.cluster_address(
                compressed_cluster_addr             // Start of compressed data
                + compressed_cluster_size as u64    // Add size to get end address
                + self.raw_file.cluster_size()
                    - 1, // Catch possibly partially used last cluster
            );
            let mut addr = self.raw_file.cluster_address(compressed_cluster_addr);
            while addr < compressed_clusters_end {
                let refcount = self
                    .refcounts
                    .get_cluster_refcount(&mut self.raw_file, addr)
                    .map_err(|e| {
                        if matches!(e, refcount::Error::RefblockUnaligned(_)) {
                            self.set_corrupt_bit_best_effort();
                        }
                        io::Error::other(Error::GettingRefcount(e))
                    })?;
                if refcount > 0 {
                    self.set_cluster_refcount_track_freed(addr, refcount - 1)?;
                }
                addr += self.raw_file.cluster_size();
            }

            cluster_addr
        } else if l2_entry_is_empty(l2_entry) {
            let initial_data = if let Some(backing) = self.backing_file.as_mut() {
                let cluster_size = self.raw_file.cluster_size();
                let cluster_begin = address - (address % cluster_size);
                let mut cluster_data = vec![0u8; cluster_size as usize];
                backing.read_at(cluster_begin, &mut cluster_data)?;
                Some(cluster_data)
            } else {
                None
            };
            // Need to allocate a data cluster
            let cluster_addr = self.append_data_cluster(initial_data)?;
            self.update_cluster_addr(l1_index, l2_index, cluster_addr, &mut set_refcounts)?;
            cluster_addr
        } else {
            let cluster_addr = l2_entry_std_cluster_addr(l2_entry);
            if cluster_addr & (self.raw_file.cluster_size() - 1) != 0 {
                self.set_corrupt_bit_best_effort();
                return Err(io::Error::from_raw_os_error(EIO));
            }
            cluster_addr
        };

        for (addr, count) in set_refcounts {
            self.set_cluster_refcount_track_freed(addr, count)?;
        }

        Ok(cluster_addr + self.raw_file.cluster_offset(address))
    }

    // Updates the l1 and l2 tables to point to the new `cluster_addr`.
    fn update_cluster_addr(
        &mut self,
        l1_index: usize,
        l2_index: usize,
        cluster_addr: u64,
        set_refcounts: &mut Vec<(u64, u64)>,
    ) -> io::Result<()> {
        if !self.l2_cache.get(l1_index).unwrap().dirty() {
            // Free the previously used cluster if one exists. Modified tables are always
            // witten to new clusters so the L1 table can be committed to disk after they
            // are and L1 never points at an invalid table.
            // The index must be valid from when it was inserted.
            let addr = self.l1_table[l1_index];
            if addr != 0 {
                self.unref_clusters.push(addr);
                set_refcounts.push((addr, 0));
            }

            // Allocate a new cluster to store the L2 table and update the L1 table to point
            // to the new table. The cluster will be written when the cache is flushed, no
            // need to copy the data now.
            let new_addr: u64 = self.get_new_cluster(None)?;
            // The cluster refcount starts at one indicating it is used but doesn't need
            // COW.
            set_refcounts.push((new_addr, 1));
            self.l1_table[l1_index] = new_addr;
        }
        // 'unwrap' is OK because it was just added.
        self.l2_cache.get_mut(l1_index).unwrap()[l2_index] = l2_entry_make_std(cluster_addr);
        Ok(())
    }

    // Allocate a new cluster and return its offset within the raw file.
    fn get_new_cluster(&mut self, initial_data: Option<Vec<u8>>) -> std::io::Result<u64> {
        // First use a pre allocated cluster if one is available.
        if let Some(free_cluster) = self.avail_clusters.pop() {
            if free_cluster == 0 {
                self.set_corrupt_bit_best_effort();
                return Err(io::Error::from_raw_os_error(EIO));
            }
            if let Some(initial_data) = initial_data {
                self.raw_file.write_cluster(free_cluster, &initial_data)?;
            } else {
                self.raw_file.zero_cluster(free_cluster)?;
            }
            return Ok(free_cluster);
        }

        let max_valid_cluster_offset = self.refcounts.max_valid_cluster_offset();
        if let Some(new_cluster) = self.raw_file.add_cluster_end(max_valid_cluster_offset)? {
            if new_cluster == 0 {
                self.set_corrupt_bit_best_effort();
                return Err(io::Error::from_raw_os_error(EIO));
            }
            if let Some(initial_data) = initial_data {
                self.raw_file.write_cluster(new_cluster, &initial_data)?;
            }
            Ok(new_cluster)
        } else {
            error!("No free clusters in get_new_cluster()");
            Err(std::io::Error::from_raw_os_error(ENOSPC))
        }
    }

    // Allocate and initialize a new data cluster. Returns the offset of the
    // cluster into the file on success.
    fn append_data_cluster(&mut self, initial_data: Option<Vec<u8>>) -> std::io::Result<u64> {
        let new_addr: u64 = self.get_new_cluster(initial_data)?;
        // The cluster refcount starts at one indicating it is used but doesn't need COW.
        self.set_cluster_refcount_track_freed(new_addr, 1)?;
        Ok(new_addr)
    }

    // Returns true if the cluster containing `address` is already allocated.
    fn cluster_allocated(&mut self, address: u64) -> std::io::Result<bool> {
        if address >= self.virtual_size() {
            return Err(std::io::Error::from_raw_os_error(EINVAL));
        }

        let l1_index = self.l1_table_index(address) as usize;
        let l2_addr_disk = *self
            .l1_table
            .get(l1_index)
            .ok_or_else(|| std::io::Error::from_raw_os_error(EINVAL))?;
        let l2_index = self.l2_table_index(address) as usize;

        if l2_addr_disk == 0 {
            // The whole L2 table for this address is not allocated yet,
            // so the cluster must also be unallocated.
            return Ok(false);
        }

        self.cache_l2_cluster(l1_index, l2_addr_disk, false)?;

        let cluster_addr = self.l2_cache.get(l1_index).unwrap()[l2_index];
        // If cluster_addr != 0, the cluster is allocated.
        Ok(cluster_addr != 0)
    }

    // Find the first guest address greater than or equal to `address` whose allocation state
    // matches `allocated`.
    fn find_allocated_cluster(
        &mut self,
        address: u64,
        allocated: bool,
    ) -> std::io::Result<Option<u64>> {
        let size = self.virtual_size();
        if address >= size {
            return Ok(None);
        }

        // If offset is already within a hole, return it.
        if self.cluster_allocated(address)? == allocated {
            return Ok(Some(address));
        }

        // Skip to the next cluster boundary.
        let cluster_size = self.raw_file.cluster_size();
        let mut cluster_addr = (address / cluster_size + 1) * cluster_size;

        // Search for clusters with the desired allocation state.
        while cluster_addr < size {
            if self.cluster_allocated(cluster_addr)? == allocated {
                return Ok(Some(cluster_addr));
            }
            cluster_addr += cluster_size;
        }

        Ok(None)
    }

    // Deallocate the storage for the cluster starting at `address`.
    // Any future reads of this cluster will return all zeroes.
    fn deallocate_cluster(&mut self, address: u64) -> std::io::Result<()> {
        if address >= self.virtual_size() {
            return Err(std::io::Error::from_raw_os_error(EINVAL));
        }

        let l1_index = self.l1_table_index(address) as usize;
        let l2_addr_disk = *self
            .l1_table
            .get(l1_index)
            .ok_or_else(|| std::io::Error::from_raw_os_error(EINVAL))?;
        let l2_index = self.l2_table_index(address) as usize;

        if l2_addr_disk == 0 {
            // The whole L2 table for this address is not allocated yet,
            // so the cluster must also be unallocated.
            return Ok(());
        }

        self.cache_l2_cluster(l1_index, l2_addr_disk, false)?;

        let cluster_addr = self.l2_cache.get(l1_index).unwrap()[l2_index];
        if cluster_addr == 0 {
            // This cluster is already unallocated; nothing to do.
            return Ok(());
        }

        // Decrement the refcount.
        let refcount = self
            .refcounts
            .get_cluster_refcount(&mut self.raw_file, cluster_addr)
            .map_err(|e| {
                if matches!(e, refcount::Error::RefblockUnaligned(_)) {
                    self.set_corrupt_bit_best_effort();
                }
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to get cluster refcount: {e}"),
                )
            })?;
        if refcount == 0 {
            return Err(std::io::Error::from_raw_os_error(EINVAL));
        }

        let new_refcount = refcount - 1;
        self.set_cluster_refcount_track_freed(cluster_addr, new_refcount)?;

        // Rewrite the L2 entry to remove the cluster mapping.
        // unwrap is safe as we just checked/inserted this entry.
        self.l2_cache.get_mut(l1_index).unwrap()[l2_index] = 0;

        if new_refcount == 0 {
            let cluster_size = self.raw_file.cluster_size();
            // This cluster is no longer in use; deallocate the storage.
            // The underlying FS may not support FALLOC_FL_PUNCH_HOLE,
            // so don't treat an error as fatal.  Future reads will return zeros anyways.
            let _ = self
                .raw_file
                .file_mut()
                .punch_hole(cluster_addr, cluster_size);
            self.unref_clusters.push(cluster_addr);
        }
        Ok(())
    }

    // Deallocate the storage for `length` bytes starting at `address`.
    // Any future reads of this range will return all zeroes.
    fn deallocate_bytes(&mut self, address: u64, length: usize) -> std::io::Result<()> {
        let write_count: usize = self.limit_range_file(address, length);

        let mut nwritten: usize = 0;
        while nwritten < write_count {
            let curr_addr = address + nwritten as u64;
            let count = self.limit_range_cluster(curr_addr, write_count - nwritten);

            if count == self.raw_file.cluster_size() as usize {
                // Full cluster - deallocate the storage.
                self.deallocate_cluster(curr_addr)?;
            } else {
                // Partial cluster - zero out the relevant bytes if it was allocated.
                // Any space in unallocated clusters can be left alone, since
                // unallocated clusters already read back as zeroes.
                let offset = self.file_offset_write(curr_addr)?;
                // Partial cluster - zero it out.
                self.raw_file.file_mut().write_zeroes_at(offset, count)?;
            }

            nwritten += count;
        }
        Ok(())
    }

    // Reads an L2 cluster from the disk, returning an error if the file can't be read or if any
    // cluster is compressed.
    fn read_l2_cluster(raw_file: &mut QcowRawFile, cluster_addr: u64) -> std::io::Result<Vec<u64>> {
        let l2_table = raw_file.read_pointer_cluster(cluster_addr, None)?;
        Ok(l2_table)
    }

    // Put an L2 cluster to the cache with evicting less-used cluster
    // The new cluster may be allocated if necessary
    // (may_alloc argument is true and l2_addr_disk == 0)
    fn cache_l2_cluster(
        &mut self,
        l1_index: usize,
        l2_addr_disk: u64,
        may_alloc: bool,
    ) -> std::io::Result<Option<u64>> {
        let mut new_cluster: Option<u64> = None;
        if !self.l2_cache.contains_key(l1_index) {
            // Not in the cache.
            let l2_table = if may_alloc && l2_addr_disk == 0 {
                // Allocate a new cluster to store the L2 table and update the L1 table to point
                // to the new table.
                let new_addr: u64 = self.get_new_cluster(None)?;
                new_cluster = Some(new_addr);
                self.l1_table[l1_index] = new_addr;
                VecCache::new(self.l2_entries as usize)
            } else {
                let cluster_size = self.raw_file.cluster_size();
                if l2_addr_disk & (cluster_size - 1) != 0 {
                    self.set_corrupt_bit_best_effort();
                    return Err(io::Error::from_raw_os_error(EIO));
                }
                VecCache::from_vec(Self::read_l2_cluster(&mut self.raw_file, l2_addr_disk)?)
            };
            let l1_table = &self.l1_table;
            let raw_file = &mut self.raw_file;
            self.l2_cache.insert(l1_index, l2_table, |index, evicted| {
                raw_file.write_pointer_table_direct(l1_table[index], evicted.iter())
            })?;
        }
        Ok(new_cluster)
    }

    // Set the refcount for a cluster and add any unreferenced clusters to the unref list.
    fn set_cluster_refcount_track_freed(
        &mut self,
        address: u64,
        refcount: u64,
    ) -> std::io::Result<()> {
        let mut newly_unref = self.set_cluster_refcount(address, refcount)?;
        self.unref_clusters.append(&mut newly_unref);
        Ok(())
    }

    // Set the refcount for a cluster with the given address.
    // Returns a list of any refblocks that can be reused, this happens when a refblock is moved,
    // the old location can be reused.
    fn set_cluster_refcount(&mut self, address: u64, refcount: u64) -> std::io::Result<Vec<u64>> {
        let mut added_clusters = Vec::new();
        let mut unref_clusters = Vec::new();
        let mut refcount_set = false;
        let mut new_cluster = None;

        while !refcount_set {
            match self.refcounts.set_cluster_refcount(
                &mut self.raw_file,
                address,
                refcount,
                new_cluster.take(),
            ) {
                Ok(None) => {
                    refcount_set = true;
                }
                Ok(Some(freed_cluster)) => {
                    // Recursively set the freed refcount block's refcount to 0
                    let mut freed = self.set_cluster_refcount(freed_cluster, 0)?;
                    unref_clusters.append(&mut freed);
                    refcount_set = true;
                }
                Err(refcount::Error::EvictingRefCounts(e)) => {
                    return Err(e);
                }
                Err(refcount::Error::InvalidIndex) => {
                    self.set_corrupt_bit_best_effort();
                    return Err(std::io::Error::from_raw_os_error(EINVAL));
                }
                Err(refcount::Error::NeedCluster(addr)) => {
                    // Read the address and call set_cluster_refcount again.
                    new_cluster = Some((
                        addr,
                        VecCache::from_vec(self.raw_file.read_refcount_block(addr)?),
                    ));
                }
                Err(refcount::Error::NeedNewCluster) => {
                    // Allocate the cluster and call set_cluster_refcount again.
                    let addr = self.get_new_cluster(None)?;
                    added_clusters.push(addr);
                    new_cluster = Some((
                        addr,
                        VecCache::new(self.refcounts.refcounts_per_block() as usize),
                    ));
                }
                Err(refcount::Error::ReadingRefCounts(e)) => {
                    return Err(e);
                }
                Err(refcount::Error::RefcountOverflow { .. }) => {
                    return Err(std::io::Error::from_raw_os_error(EINVAL));
                }
                Err(refcount::Error::RefblockUnaligned(_)) => {
                    self.set_corrupt_bit_best_effort();
                    return Err(io::Error::from_raw_os_error(EIO));
                }
            }
        }

        for addr in added_clusters {
            self.set_cluster_refcount(addr, 1)?;
        }
        Ok(unref_clusters)
    }

    fn sync_caches(&mut self) -> std::io::Result<()> {
        // Write out all dirty L2 tables.
        for (l1_index, l2_table) in self.l2_cache.iter_mut().filter(|(_k, v)| v.dirty()) {
            // The index must be valid from when we inserted it.
            let addr = self.l1_table[*l1_index];
            if addr != 0 {
                self.raw_file
                    .write_pointer_table_direct(addr, l2_table.iter())?;
            } else {
                self.set_corrupt_bit_best_effort();
                return Err(std::io::Error::from_raw_os_error(EINVAL));
            }
            l2_table.mark_clean();
        }
        // Write the modified refcount blocks.
        self.refcounts.flush_blocks(&mut self.raw_file)?;
        // Make sure metadata(file len) and all data clusters are written.
        self.raw_file.file_mut().sync_all()?;

        // Push L1 table and refcount table last as all the clusters they point to are now
        // guaranteed to be valid.
        let mut sync_required = if self.l1_table.dirty() {
            // Write L1 table with OFLAG_COPIED bits
            let refcounts = &mut self.refcounts;
            self.raw_file.write_pointer_table(
                self.header.l1_table_offset,
                self.l1_table.iter(),
                |raw_file, l2_addr| {
                    if l2_addr == 0 {
                        Ok(0)
                    } else {
                        let refcount = refcounts
                            .get_cluster_refcount(raw_file, l2_addr)
                            .map_err(|e| std::io::Error::other(Error::GettingRefcount(e)))?;
                        Ok(l1_entry_make(l2_addr, refcount == 1))
                    }
                },
            )?;
            self.l1_table.mark_clean();
            true
        } else {
            false
        };
        sync_required |= self.refcounts.flush_table(&mut self.raw_file)?;
        if sync_required {
            self.raw_file.file_mut().sync_data()?;
        }

        Ok(())
    }
}

impl AsRawFd for QcowFile {
    fn as_raw_fd(&self) -> RawFd {
        self.raw_file.as_raw_fd()
    }
}

impl Drop for QcowFile {
    fn drop(&mut self) {
        let _ = self.sync_caches();
        if self.raw_file.file().is_writable() {
            let _ = self.header.set_dirty_bit(self.raw_file.file_mut(), false);
        }
    }
}

impl Read for QcowFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let address: u64 = self.current_offset;
        let read_count: usize = self.limit_range_file(address, buf.len());

        let mut nread: usize = 0;
        while nread < read_count {
            let curr_addr = address + nread as u64;
            let count = self.limit_range_cluster(curr_addr, read_count - nread);

            if (self.file_read(curr_addr, count, &mut buf[nread..(nread + count)])?).is_some() {
                // Data is successfully read from the cluster
            } else if let Some(backing) = self.backing_file.as_mut() {
                backing.read_at(curr_addr, &mut buf[nread..(nread + count)])?;
            } else {
                // Previously unwritten region, return zeros
                for b in &mut buf[nread..(nread + count)] {
                    *b = 0;
                }
            }

            nread += count;
        }
        self.current_offset += read_count as u64;
        Ok(read_count)
    }
}

impl Seek for QcowFile {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_offset: Option<u64> = match pos {
            SeekFrom::Start(off) => Some(off),
            SeekFrom::End(off) => {
                if off < 0 {
                    0i64.checked_sub(off)
                        .and_then(|increment| self.virtual_size().checked_sub(increment as u64))
                } else {
                    self.virtual_size().checked_add(off as u64)
                }
            }
            SeekFrom::Current(off) => {
                if off < 0 {
                    0i64.checked_sub(off)
                        .and_then(|increment| self.current_offset.checked_sub(increment as u64))
                } else {
                    self.current_offset.checked_add(off as u64)
                }
            }
        };

        if let Some(o) = new_offset
            && o <= self.virtual_size()
        {
            self.current_offset = o;
            return Ok(o);
        }
        Err(std::io::Error::from_raw_os_error(EINVAL))
    }
}

impl Write for QcowFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let address: u64 = self.current_offset;
        let write_count: usize = self.limit_range_file(address, buf.len());

        let mut nwritten: usize = 0;
        while nwritten < write_count {
            let curr_addr = address + nwritten as u64;
            let offset = self.file_offset_write(curr_addr)?;
            let count = self.limit_range_cluster(curr_addr, write_count - nwritten);

            self.raw_file.file_mut().seek(SeekFrom::Start(offset))?;
            let count = self
                .raw_file
                .file_mut()
                .write(&buf[nwritten..(nwritten + count)])?;

            nwritten += count;
        }
        self.current_offset += write_count as u64;
        Ok(write_count)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.sync_caches()?;
        self.avail_clusters.append(&mut self.unref_clusters);
        Ok(())
    }
}

impl FileSync for QcowFile {
    fn fsync(&mut self) -> std::io::Result<()> {
        self.flush()
    }
}

impl FileSetLen for QcowFile {
    fn set_len(&self, _len: u64) -> std::io::Result<()> {
        Err(std::io::Error::other(
            "set_len() not supported for QcowFile",
        ))
    }
}

impl PunchHole for QcowFile {
    fn punch_hole(&mut self, offset: u64, length: u64) -> std::io::Result<()> {
        let mut remaining = length;
        let mut offset = offset;
        while remaining > 0 {
            let chunk_length = min(remaining, usize::MAX as u64) as usize;
            self.deallocate_bytes(offset, chunk_length)?;
            remaining -= chunk_length as u64;
            offset += chunk_length as u64;
        }
        Ok(())
    }
}

impl WriteZeroesAt for QcowFile {
    fn write_zeroes_at(&mut self, offset: u64, length: usize) -> io::Result<usize> {
        self.punch_hole(offset, length as u64)?;
        Ok(length)
    }
}

impl SeekHole for QcowFile {
    fn seek_hole(&mut self, offset: u64) -> io::Result<Option<u64>> {
        match self.find_allocated_cluster(offset, false) {
            Err(e) => Err(e),
            Ok(None) => {
                if offset < self.virtual_size() {
                    Ok(Some(self.seek(SeekFrom::End(0))?))
                } else {
                    Ok(None)
                }
            }
            Ok(Some(o)) => {
                self.seek(SeekFrom::Start(o))?;
                Ok(Some(o))
            }
        }
    }

    fn seek_data(&mut self, offset: u64) -> io::Result<Option<u64>> {
        match self.find_allocated_cluster(offset, true) {
            Err(e) => Err(e),
            Ok(None) => Ok(None),
            Ok(Some(o)) => {
                self.seek(SeekFrom::Start(o))?;
                Ok(Some(o))
            }
        }
    }
}

impl BlockBackend for QcowFile {
    fn logical_size(&self) -> std::result::Result<u64, crate::Error> {
        Ok(self.virtual_size())
    }

    fn physical_size(&self) -> std::result::Result<u64, crate::Error> {
        self.raw_file
            .physical_size()
            .map_err(crate::Error::GetFileMetadata)
    }
}

// Returns an Error if the given offset doesn't align to a cluster boundary.
fn offset_is_cluster_boundary(offset: u64, cluster_bits: u32) -> Result<()> {
    if offset & ((0x01 << cluster_bits) - 1) != 0 {
        return Err(Error::InvalidOffset(offset));
    }
    Ok(())
}

// Ceiling of the division of `dividend`/`divisor`.
fn div_round_up_u64(dividend: u64, divisor: u64) -> u64 {
    dividend / divisor + u64::from(!dividend.is_multiple_of(divisor))
}

// Ceiling of the division of `dividend`/`divisor`.
fn div_round_up_u32(dividend: u32, divisor: u32) -> u32 {
    dividend / divisor + u32::from(!dividend.is_multiple_of(divisor))
}

fn convert_copy<R, W>(reader: &mut R, writer: &mut W, offset: u64, size: u64) -> Result<()>
where
    R: Read + Seek,
    W: Write + Seek,
{
    const CHUNK_SIZE: usize = 65536;
    let mut buf = [0; CHUNK_SIZE];
    let mut read_count = 0;
    reader
        .seek(SeekFrom::Start(offset))
        .map_err(Error::SeekingFile)?;
    writer
        .seek(SeekFrom::Start(offset))
        .map_err(Error::SeekingFile)?;
    loop {
        let this_count = min(CHUNK_SIZE as u64, size - read_count) as usize;
        let nread = reader
            .read(&mut buf[..this_count])
            .map_err(Error::ReadingData)?;
        writer.write(&buf[..nread]).map_err(Error::WritingData)?;
        read_count += nread as u64;
        if nread == 0 || read_count == size {
            break;
        }
    }

    Ok(())
}

fn convert_reader_writer<R, W>(reader: &mut R, writer: &mut W, size: u64) -> Result<()>
where
    R: Read + Seek + SeekHole,
    W: Write + Seek,
{
    let mut offset = 0;
    while offset < size {
        // Find the next range of data.
        let next_data = match reader.seek_data(offset).map_err(Error::SeekingFile)? {
            Some(o) => o,
            None => {
                // No more data in the file.
                break;
            }
        };
        let next_hole = match reader.seek_hole(next_data).map_err(Error::SeekingFile)? {
            Some(o) => o,
            None => {
                // This should not happen - there should always be at least one hole
                // after any data.
                return Err(Error::SeekingFile(io::Error::from_raw_os_error(EINVAL)));
            }
        };
        let count = next_hole - next_data;
        convert_copy(reader, writer, next_data, count)?;
        offset = next_hole;
    }

    Ok(())
}

fn convert_reader<R>(reader: &mut R, dst_file: RawFile, dst_type: ImageType) -> Result<()>
where
    R: Read + Seek + SeekHole,
{
    let src_size = reader.seek(SeekFrom::End(0)).map_err(Error::SeekingFile)?;
    reader.rewind().map_err(Error::SeekingFile)?;

    // Ensure the destination file is empty before writing to it.
    dst_file.set_len(0).map_err(Error::SettingFileSize)?;

    match dst_type {
        ImageType::Qcow2 => {
            let mut dst_writer = QcowFile::new(dst_file, 3, src_size)?;
            convert_reader_writer(reader, &mut dst_writer, src_size)
        }
        ImageType::Raw => {
            let mut dst_writer = dst_file;
            // Set the length of the destination file to convert it into a sparse file
            // of the desired size.
            dst_writer
                .set_len(src_size)
                .map_err(Error::SettingFileSize)?;
            convert_reader_writer(reader, &mut dst_writer, src_size)
        }
    }
}

/// Copy the contents of a disk image in `src_file` into `dst_file`.
/// The type of `src_file` is automatically detected, and the output file type is
/// determined by `dst_type`.
pub fn convert(
    mut src_file: RawFile,
    dst_file: RawFile,
    dst_type: ImageType,
    src_max_nesting_depth: u32,
) -> Result<()> {
    let src_type = detect_image_type(&mut src_file)?;
    match src_type {
        ImageType::Qcow2 => {
            let mut src_reader =
                QcowFile::from_with_nesting_depth(src_file, src_max_nesting_depth)?;
            convert_reader(&mut src_reader, dst_file, dst_type)
        }
        ImageType::Raw => {
            // src_file is a raw file.
            let mut src_reader = src_file;
            convert_reader(&mut src_reader, dst_file, dst_type)
        }
    }
}

/// Detect the type of an image file by checking for a valid qcow2 header.
pub fn detect_image_type(file: &mut RawFile) -> Result<ImageType> {
    let orig_seek = file.stream_position().map_err(Error::SeekingFile)?;
    file.rewind().map_err(Error::SeekingFile)?;
    let magic = u32::read_be(file).map_err(Error::ReadingHeader)?;
    let image_type = if magic == QCOW_MAGIC {
        ImageType::Qcow2
    } else {
        ImageType::Raw
    };
    file.seek(SeekFrom::Start(orig_seek))
        .map_err(Error::SeekingFile)?;
    Ok(image_type)
}

#[cfg(test)]
mod unit_tests {
    use std::fs::File;
    use std::path::Path;

    use vmm_sys_util::tempdir::TempDir;
    use vmm_sys_util::tempfile::TempFile;
    use vmm_sys_util::write_zeroes::WriteZeroes;

    use super::*;

    fn valid_header_v3() -> Vec<u8> {
        vec![
            0x51u8, 0x46, 0x49, 0xfb, // magic
            0x00, 0x00, 0x00, 0x03, // version
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // backing file offset
            0x00, 0x00, 0x00, 0x00, // backing file size
            0x00, 0x00, 0x00, 0x10, // cluster_bits
            0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, // size
            0x00, 0x00, 0x00, 0x00, // crypt method
            0x00, 0x00, 0x01, 0x00, // L1 size
            0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, // L1 table offset
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, // refcount table offset
            0x00, 0x00, 0x00, 0x03, // refcount table clusters
            0x00, 0x00, 0x00, 0x00, // nb snapshots
            0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, // snapshots offset
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // incompatible_features
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // compatible_features
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // autoclear_features
            0x00, 0x00, 0x00, 0x04, // refcount_order
            0x00, 0x00, 0x00, 0x68, // header_length
        ]
    }

    fn valid_header_v2() -> Vec<u8> {
        vec![
            0x51u8, 0x46, 0x49, 0xfb, // magic
            0x00, 0x00, 0x00, 0x02, // version
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // backing file offset
            0x00, 0x00, 0x00, 0x00, // backing file size
            0x00, 0x00, 0x00, 0x10, // cluster_bits
            0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, // size
            0x00, 0x00, 0x00, 0x00, // crypt method
            0x00, 0x00, 0x01, 0x00, // L1 size
            0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, // L1 table offset
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, // refcount table offset
            0x00, 0x00, 0x00, 0x03, // refcount table clusters
            0x00, 0x00, 0x00, 0x00, // nb snapshots
            0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, // snapshots offset
        ]
    }

    // Test case found by clusterfuzz to allocate excessive memory.
    fn test_huge_header() -> Vec<u8> {
        vec![
            0x51, 0x46, 0x49, 0xfb, // magic
            0x00, 0x00, 0x00, 0x03, // version
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // backing file offset
            0x00, 0x00, 0x00, 0x00, // backing file size
            0x00, 0x00, 0x00, 0x09, // cluster_bits
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, // size
            0x00, 0x00, 0x00, 0x00, // crypt method
            0x00, 0x00, 0x01, 0x00, // L1 size
            0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, // L1 table offset
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, // refcount table offset
            0x00, 0x00, 0x00, 0x03, // refcount table clusters
            0x00, 0x00, 0x00, 0x00, // nb snapshots
            0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, // snapshots offset
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // incompatible_features
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // compatible_features
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // autoclear_features
            0x00, 0x00, 0x00, 0x04, // refcount_order
            0x00, 0x00, 0x00, 0x68, // header_length
        ]
    }

    fn basic_file(header: &[u8]) -> RawFile {
        let mut disk_file: RawFile = RawFile::new(TempFile::new().unwrap().into_file(), false);
        disk_file.write_all(header).unwrap();
        disk_file.set_len(0x1_0000_0000).unwrap();
        disk_file.rewind().unwrap();
        disk_file
    }

    fn with_basic_file<F>(header: &[u8], mut testfn: F)
    where
        F: FnMut(RawFile),
    {
        testfn(basic_file(header)); // File closed when the function exits.
    }

    fn with_default_file<F>(file_size: u64, direct: bool, mut testfn: F)
    where
        F: FnMut(QcowFile),
    {
        let tmp: RawFile = RawFile::new(TempFile::new().unwrap().into_file(), direct);
        let qcow_file = QcowFile::new(tmp, 3, file_size).unwrap();

        testfn(qcow_file); // File closed when the function exits.
    }

    #[test]
    fn write_read_start_backing_v2() {
        let disk_file = basic_file(&valid_header_v2());
        let mut backing = QcowFile::from(disk_file).unwrap();
        backing
            .write_all(b"test first bytes")
            .expect("Failed to write test string.");
        let mut buf = [0u8; 4];
        let wrapping_disk_file = basic_file(&valid_header_v2());
        let mut wrapping = QcowFile::from(wrapping_disk_file).unwrap();
        wrapping.set_backing_file(Some(Box::new(backing)));
        wrapping.seek(SeekFrom::Start(0)).expect("Failed to seek.");
        wrapping.read_exact(&mut buf).expect("Failed to read.");
        assert_eq!(&buf, b"test");
    }

    #[test]
    fn write_read_start_backing_v3() {
        let disk_file = basic_file(&valid_header_v3());
        let mut backing = QcowFile::from(disk_file).unwrap();
        backing
            .write_all(b"test first bytes")
            .expect("Failed to write test string.");
        let mut buf = [0u8; 4];
        let wrapping_disk_file = basic_file(&valid_header_v3());
        let mut wrapping = QcowFile::from(wrapping_disk_file).unwrap();
        wrapping.set_backing_file(Some(Box::new(backing)));
        wrapping.seek(SeekFrom::Start(0)).expect("Failed to seek.");
        wrapping.read_exact(&mut buf).expect("Failed to read.");
        assert_eq!(&buf, b"test");
    }

    #[test]
    fn default_header_v2() {
        let header = QcowHeader::create_for_size_and_path(2, 0x10_0000, None);
        let mut disk_file: RawFile = RawFile::new(TempFile::new().unwrap().into_file(), false);
        header
            .expect("Failed to create header.")
            .write_to(&mut disk_file)
            .expect("Failed to write header to temporary file.");
        disk_file.rewind().unwrap();
        QcowFile::from(disk_file).expect("Failed to create Qcow from default Header");
    }

    #[test]
    fn default_header_v3() {
        let header = QcowHeader::create_for_size_and_path(3, 0x10_0000, None);
        let mut disk_file: RawFile = RawFile::new(TempFile::new().unwrap().into_file(), false);
        header
            .expect("Failed to create header.")
            .write_to(&mut disk_file)
            .expect("Failed to write header to temporary file.");
        disk_file.rewind().unwrap();
        QcowFile::from(disk_file).expect("Failed to create Qcow from default Header");
    }

    #[test]
    fn header_read() {
        with_basic_file(&valid_header_v2(), |mut disk_file: RawFile| {
            let header = QcowHeader::new(&mut disk_file).expect("Failed to create Header.");
            assert_eq!(header.version, 2);
            assert_eq!(header.refcount_order, DEFAULT_REFCOUNT_ORDER);
            assert_eq!(header.header_size, V2_BARE_HEADER_SIZE);
        });
        with_basic_file(&valid_header_v3(), |mut disk_file: RawFile| {
            let header = QcowHeader::new(&mut disk_file).expect("Failed to create Header.");
            assert_eq!(header.version, 3);
            assert_eq!(header.refcount_order, DEFAULT_REFCOUNT_ORDER);
            assert_eq!(header.header_size, V3_BARE_HEADER_SIZE);
        });
    }

    #[test]
    fn header_v2_with_backing() {
        let header = QcowHeader::create_for_size_and_path(2, 0x10_0000, Some("/my/path/to/a/file"))
            .expect("Failed to create header.");
        let mut disk_file: RawFile = RawFile::new(TempFile::new().unwrap().into_file(), false);
        header
            .write_to(&mut disk_file)
            .expect("Failed to write header to shm.");
        disk_file.rewind().unwrap();
        let read_header = QcowHeader::new(&mut disk_file).expect("Failed to create header.");
        assert_eq!(
            header.backing_file.as_ref().map(|bf| bf.path.clone()),
            Some(String::from("/my/path/to/a/file"))
        );
        assert_eq!(
            read_header.backing_file.as_ref().map(|bf| &bf.path),
            header.backing_file.as_ref().map(|bf| &bf.path)
        );
    }

    #[test]
    fn header_v3_with_backing() {
        let header = QcowHeader::create_for_size_and_path(3, 0x10_0000, Some("/my/path/to/a/file"))
            .expect("Failed to create header.");
        let mut disk_file: RawFile = RawFile::new(TempFile::new().unwrap().into_file(), false);
        header
            .write_to(&mut disk_file)
            .expect("Failed to write header to shm.");
        disk_file.rewind().unwrap();
        let read_header = QcowHeader::new(&mut disk_file).expect("Failed to create header.");
        assert_eq!(
            header.backing_file.as_ref().map(|bf| bf.path.clone()),
            Some(String::from("/my/path/to/a/file"))
        );
        assert_eq!(
            read_header.backing_file.as_ref().map(|bf| &bf.path),
            header.backing_file.as_ref().map(|bf| &bf.path)
        );
    }

    /// Helper to create a test file with header extensions
    fn create_header_with_extension(ext_type: u32, ext_data: &[u8]) -> (RawFile, QcowHeader) {
        let header = QcowHeader::create_for_size_and_path(3, 0x10_0000, None)
            .expect("Failed to create header.");

        let mut disk_file: RawFile = RawFile::new(TempFile::new().unwrap().into_file(), false);
        header.write_to(&mut disk_file).unwrap();

        // Write extension
        disk_file
            .seek(SeekFrom::Start(header.header_size as u64))
            .unwrap();
        u32::write_be(&mut disk_file, ext_type).unwrap();
        u32::write_be(&mut disk_file, ext_data.len() as u32).unwrap();
        disk_file.write_all(ext_data).unwrap();

        // Add padding to 8-byte boundary
        let padding = (8 - (ext_data.len() % 8)) % 8;
        if padding > 0 {
            disk_file.write_all(&vec![0u8; padding]).unwrap();
        }

        u32::write_be(&mut disk_file, HEADER_EXT_END).unwrap();

        disk_file.rewind().unwrap();

        (disk_file, header)
    }

    #[test]
    fn read_header_extensions_unknown_extension() {
        let (mut disk_file, mut header) = create_header_with_extension(
            0x12345678, // unknown type
            "test".as_bytes(),
        );

        // Extension parsing needs a backing file to set format on
        header.backing_file = Some(BackingFileConfig {
            path: "/test/backing".to_string(),
            format: None,
        });

        QcowHeader::read_header_extensions(&mut disk_file, &mut header, None).unwrap();
        assert_eq!(header.backing_file.as_ref().and_then(|bf| bf.format), None);
    }

    #[test]
    fn read_header_extensions_raw_format() {
        let (mut disk_file, mut header) =
            create_header_with_extension(HEADER_EXT_BACKING_FORMAT, "raw".as_bytes());

        header.backing_file = Some(BackingFileConfig {
            path: "/test/backing".to_string(),
            format: None,
        });

        QcowHeader::read_header_extensions(&mut disk_file, &mut header, None).unwrap();
        assert_eq!(
            header.backing_file.as_ref().and_then(|bf| bf.format),
            Some(ImageType::Raw)
        );
    }

    #[test]
    fn read_header_extensions_qcow2_format() {
        let (mut disk_file, mut header) =
            create_header_with_extension(HEADER_EXT_BACKING_FORMAT, "qcow2".as_bytes());

        header.backing_file = Some(BackingFileConfig {
            path: "/test/backing".to_string(),
            format: None,
        });

        QcowHeader::read_header_extensions(&mut disk_file, &mut header, None).unwrap();
        assert_eq!(
            header.backing_file.as_ref().and_then(|bf| bf.format),
            Some(ImageType::Qcow2)
        );
    }

    #[test]
    fn read_header_extensions_invalid_format() {
        let (mut disk_file, mut header) =
            create_header_with_extension(HEADER_EXT_BACKING_FORMAT, "vmdk".as_bytes());

        header.backing_file = Some(BackingFileConfig {
            path: "/test/backing".to_string(),
            format: None,
        });

        let result = QcowHeader::read_header_extensions(&mut disk_file, &mut header, None);
        assert!(matches!(
            result.unwrap_err(),
            Error::UnsupportedBackingFileFormat(_)
        ));
    }

    #[test]
    fn read_header_extensions_invalid_utf8() {
        let (mut disk_file, mut header) = create_header_with_extension(
            HEADER_EXT_BACKING_FORMAT,
            &[0xFF, 0xFE, 0xFD], // invalid UTF-8
        );

        let result = QcowHeader::read_header_extensions(&mut disk_file, &mut header, None);
        // Should fail with InvalidBackingFileName error
        assert!(matches!(
            result.unwrap_err(),
            Error::InvalidBackingFileName(_)
        ));
    }

    #[test]
    fn no_backing_file() {
        // `backing_file` is `None`
        let header = QcowHeader::create_for_size_and_path(3, 0x10_0000, None)
            .expect("Failed to create header.");
        let mut disk_file: RawFile = RawFile::new(TempFile::new().unwrap().into_file(), false);
        header
            .write_to(&mut disk_file)
            .expect("Failed to write header to shm.");
        disk_file.rewind().unwrap();
        // The maximum nesting depth is 0, which means backing file is not allowed.
        QcowFile::from_with_nesting_depth(disk_file, 0).unwrap();
    }

    #[test]
    fn disable_backing_file() {
        // `backing_file` is `Some`
        let header =
            QcowHeader::create_for_size_and_path(3, 0x10_0000, Some("/path/to/backing/file"))
                .expect("Failed to create header.");
        let mut disk_file: RawFile = RawFile::new(TempFile::new().unwrap().into_file(), false);
        header
            .write_to(&mut disk_file)
            .expect("Failed to write header to shm.");
        disk_file.rewind().unwrap();
        // The maximum nesting depth is 0, which means backing file is not allowed.
        let res = QcowFile::from_with_nesting_depth(disk_file, 0);
        assert!(matches!(res.unwrap_err(), Error::MaxNestingDepthExceeded));
    }

    /// Create a qcow2 file with itself as its backing file.
    ///
    /// Without configuration `max_nesting_depth`, this will cause infinite recursion when loading
    /// the file until stack overflow.
    fn new_self_referential_qcow(path: &Path) -> Result<()> {
        let header = QcowHeader::create_for_size_and_path(3, 0x10_0000, path.to_str())?;
        let mut disk_file = RawFile::new(
            File::create(path).expect("Failed to create image file."),
            false,
        );
        header.write_to(&mut disk_file)?;
        Ok(())
    }

    #[test]
    fn max_nesting_backing() {
        let test_dir = TempDir::new_with_prefix("/tmp/ch").unwrap();
        let img_path = test_dir.as_path().join("test.img");

        new_self_referential_qcow(img_path.as_path()).unwrap();

        let err = QcowFile::from_with_nesting_depth(
            RawFile::new(
                File::open(img_path.as_path()).expect("Failed to open qcow image file"),
                false,
            ),
            MAX_NESTING_DEPTH,
        )
        .expect_err("Opening qcow file with itself as backing file should fail.");

        // This type of error is complex. For comparing easily, we can check if it contains the
        // type name after formatting.
        assert!(format!("{err:?}").contains(&format!("{:?}", Error::MaxNestingDepthExceeded)));
        // This should recursively call the function ten times before throwing an error, and the
        // error `BackingFileOpen` should also be repeated ten times.
        assert_eq!(
            format!("{err:?}")
                .matches("BackingFileOpen")
                .collect::<Vec<_>>()
                .len() as u32,
            MAX_NESTING_DEPTH,
        );
    }

    #[test]
    fn invalid_magic() {
        let invalid_header = vec![0x51u8, 0x46, 0x4a, 0xfb];
        with_basic_file(&invalid_header, |mut disk_file: RawFile| {
            QcowHeader::new(&mut disk_file).expect_err("Invalid header worked.");
        });
    }

    #[test]
    fn invalid_refcount_order() {
        let mut header = valid_header_v3();
        header[99] = 7;
        with_basic_file(&header, |disk_file: RawFile| {
            QcowFile::from(disk_file).expect_err("Invalid refcount order worked.");
        });
    }

    /// Test all valid refcount orders (0-6) can be opened.
    #[test]
    fn refcount_all_orders() {
        for order in 0..=6u8 {
            let mut header = valid_header_v3();
            header[99] = order;
            with_basic_file(&header, |disk_file: RawFile| {
                QcowFile::from(disk_file).expect("refcount order should work");
            });
        }
    }

    /// Test write/read roundtrip for all refcount orders.
    #[test]
    fn refcount_all_orders_write_read() {
        for order in 0..=6u8 {
            let mut header = valid_header_v3();
            header[99] = order;
            with_basic_file(&header, |disk_file: RawFile| {
                let mut q = QcowFile::from(disk_file).unwrap();
                let test_data = b"test data for refcount";

                // Write and read back
                q.write_all(test_data).unwrap();
                q.rewind().unwrap();
                let mut buf = vec![0u8; test_data.len()];
                q.read_exact(&mut buf).unwrap();
                assert_eq!(&buf, test_data);

                // Write to another cluster
                q.seek(SeekFrom::Start(0x10000)).unwrap();
                q.write_all(test_data).unwrap();
                q.seek(SeekFrom::Start(0x10000)).unwrap();
                q.read_exact(&mut buf).unwrap();
                assert_eq!(&buf, test_data);
            });
        }
    }

    /// Test overwrite and multi-cluster allocation for all refcount orders.
    #[test]
    fn refcount_all_orders_overwrite() {
        for order in 0..=6u8 {
            let mut header = valid_header_v3();
            header[99] = order;
            with_basic_file(&header, |disk_file: RawFile| {
                let mut q = QcowFile::from(disk_file).unwrap();

                // Write then overwrite
                q.write_all(b"initial data here!!!").unwrap();
                q.rewind().unwrap();
                let new_data = b"overwritten data!!!!";
                q.write_all(new_data).unwrap();
                q.rewind().unwrap();
                let mut buf = vec![0u8; new_data.len()];
                q.read_exact(&mut buf).unwrap();
                assert_eq!(&buf, new_data);

                // Allocate multiple clusters
                let cluster_size = 0x10000u64;
                for i in 1..4u64 {
                    q.seek(SeekFrom::Start(i * cluster_size)).unwrap();
                    q.write_all(b"cluster data").unwrap();
                }
                for i in 1..4u64 {
                    let mut cluster_buf = vec![0u8; 12];
                    q.seek(SeekFrom::Start(i * cluster_size)).unwrap();
                    q.read_exact(&mut cluster_buf).unwrap();
                    assert_eq!(&cluster_buf, b"cluster data");
                }
            });
        }
    }

    /// Test L2 cache eviction for all refcount orders.
    #[test]
    fn refcount_all_orders_l2_eviction() {
        for order in 0..=6u8 {
            let mut header = valid_header_v3();
            header[99] = order;
            with_basic_file(&header, |disk_file: RawFile| {
                let mut q = QcowFile::from(disk_file).unwrap();

                // L2 cache has 100 entries. Write to >100 regions to force eviction.
                let cluster_size = 0x10000u64;
                let l2_coverage = cluster_size * (cluster_size / 8);

                for i in 0..110u64 {
                    q.seek(SeekFrom::Start(i * l2_coverage)).unwrap();
                    q.write_all(b"eviction test").unwrap();
                }

                // Verify evicted regions can be re-read
                for i in [0u64, 1, 50, 100, 109] {
                    let mut buf = vec![0u8; 13];
                    q.seek(SeekFrom::Start(i * l2_coverage)).unwrap();
                    q.read_exact(&mut buf).unwrap();
                    assert_eq!(&buf, b"eviction test");
                }
            });
        }
    }

    /// Test sub-byte refcount read/write roundtrip with max values.
    #[test]
    fn refcount_subbyte_max_values() {
        for (bits, max_val) in [(1u64, 1u64), (2, 3), (4, 15)] {
            let file = vmm_sys_util::tempfile::TempFile::new().unwrap().into_file();
            let cluster_size = 0x10000u64;
            file.set_len(cluster_size * 2).unwrap();
            let raw = RawFile::new(file, false);
            let mut qcow_raw = QcowRawFile::from(raw, cluster_size, bits).unwrap();

            let entries = (cluster_size * 8 / bits) as usize;
            let mut table: Vec<u64> = (0..entries as u64).map(|i| i % (max_val + 1)).collect();
            table[0] = max_val;
            table[entries - 1] = max_val;

            qcow_raw.write_refcount_block(cluster_size, &table).unwrap();
            let read_table = qcow_raw.read_refcount_block(cluster_size).unwrap();

            assert_eq!(read_table.len(), entries);
            for (i, (&written, &read)) in table.iter().zip(read_table.iter()).enumerate() {
                assert_eq!(read, written & max_val, "{bits}-bit entry {i} mismatch");
            }
        }
    }

    /// Test byte-aligned refcounts with max values.
    #[test]
    fn refcount_byte_aligned_large_values() {
        for (bits, test_val) in [
            (8u64, 0xFFu64),
            (16, 0xFFFFu64),
            (32, 0xFFFF_FFFFu64),
            (64, u64::MAX),
        ] {
            let file = vmm_sys_util::tempfile::TempFile::new().unwrap().into_file();
            let cluster_size = 0x10000u64;
            file.set_len(cluster_size * 2).unwrap();
            let raw = RawFile::new(file, false);
            let mut qcow_raw = QcowRawFile::from(raw, cluster_size, bits).unwrap();

            let entries = (cluster_size * 8 / bits) as usize;
            let mut table: Vec<u64> = vec![0; entries];
            table[0] = test_val;
            table[1] = 1;
            table[entries - 1] = test_val;

            qcow_raw.write_refcount_block(cluster_size, &table).unwrap();
            let read_table = qcow_raw.read_refcount_block(cluster_size).unwrap();

            assert_eq!(read_table[0], test_val);
            assert_eq!(read_table[1], 1);
            assert_eq!(read_table[entries - 1], test_val);
        }
    }

    /// Test RefcountOverflow error when exceeding max refcount value.
    #[test]
    fn refcount_overflow_returns_error() {
        use super::refcount::Error as RefcountError;

        for (refcount_bits, max_val) in [(1u64, 1u64), (2, 3), (4, 15)] {
            let file = vmm_sys_util::tempfile::TempFile::new().unwrap().into_file();
            let cluster_size = 0x10000u64;
            let refcount_block_entries = cluster_size * 8 / refcount_bits;
            file.set_len(cluster_size * 3).unwrap();

            let raw = RawFile::new(file, false);
            let mut qcow_raw = QcowRawFile::from(raw, cluster_size, refcount_bits).unwrap();

            // Set up refcount table pointing to refcount block
            let refcount_table_offset = cluster_size;
            qcow_raw
                .file_mut()
                .seek(SeekFrom::Start(refcount_table_offset))
                .unwrap();
            qcow_raw
                .file_mut()
                .write_all(&(cluster_size * 2).to_be_bytes())
                .unwrap();

            let zeros = vec![0u64; refcount_block_entries as usize];
            qcow_raw
                .write_refcount_block(cluster_size * 2, &zeros)
                .unwrap();

            let mut refcount = RefCount::new(
                &mut qcow_raw,
                refcount_table_offset,
                1,
                refcount_block_entries,
                cluster_size,
                refcount_bits,
            )
            .unwrap();

            // Overflow should fail
            let result = refcount.set_cluster_refcount(&mut qcow_raw, 0, max_val + 1, None);
            assert!(
                matches!(result, Err(RefcountError::RefcountOverflow { .. })),
                "{refcount_bits}-bit: expected overflow error"
            );

            // Max value should not overflow
            let result = refcount.set_cluster_refcount(&mut qcow_raw, 0, max_val, None);
            assert!(
                !matches!(result, Err(RefcountError::RefcountOverflow { .. })),
                "{refcount_bits}-bit: max value should not overflow"
            );
        }
    }

    #[test]
    fn invalid_cluster_bits() {
        let mut header = valid_header_v3();
        header[23] = 3;
        with_basic_file(&header, |disk_file: RawFile| {
            QcowFile::from(disk_file).expect_err("Failed to create file.");
        });
    }

    #[test]
    fn test_header_huge_file() {
        let header = test_huge_header();
        with_basic_file(&header, |disk_file: RawFile| {
            QcowFile::from(disk_file).expect_err("Failed to create file.");
        });
    }

    #[test]
    fn test_header_crazy_file_size_rejected() {
        let mut header = valid_header_v3();
        header[24..32].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1e]);
        with_basic_file(&header, |disk_file: RawFile| {
            QcowFile::from(disk_file).expect_err("Failed to create file.");
        });
    }

    #[test]
    fn test_huge_l1_table() {
        let mut header = valid_header_v3();
        header[36] = 0x12;
        with_basic_file(&header, |disk_file: RawFile| {
            QcowFile::from(disk_file).expect_err("Failed to create file.");
        });
    }

    #[test]
    fn test_header_1_tb_file_min_cluster() {
        let mut header = test_huge_header();
        header[24] = 0;
        header[26] = 1;
        header[31] = 0;
        // 1 TB with the min cluster size makes the arrays too big, it should fail.
        with_basic_file(&header, |disk_file: RawFile| {
            QcowFile::from(disk_file).expect_err("Failed to create file.");
        });
    }

    #[test]
    fn test_l2_entry_zero_flag() {
        let empty_entry: u64 = 0;
        let standard_entry: u64 = 0x1000;
        let zero_flag_entry: u64 = 0x1000 | ZERO_FLAG;
        let compressed_entry: u64 = COMPRESSED_FLAG;

        assert!(l2_entry_is_empty(empty_entry));
        assert!(!l2_entry_is_empty(standard_entry));

        assert!(!l2_entry_is_compressed(standard_entry));
        assert!(l2_entry_is_compressed(compressed_entry));

        assert!(!l2_entry_is_zero(standard_entry));
        assert!(l2_entry_is_zero(zero_flag_entry));

        // Note: l2_entry_is_zero() only checks bit 0, so compressed entries
        // must be checked first as the code does in file_read.
    }

    #[test]
    fn test_header_1_tb_file() {
        let mut header = test_huge_header();
        // reset to 1 TB size.
        header[24] = 0;
        header[26] = 1;
        header[31] = 0;
        // set cluster_bits
        header[23] = 16;
        with_basic_file(&header, |disk_file: RawFile| {
            let mut qcow = QcowFile::from(disk_file).expect("Failed to create file.");
            qcow.seek(SeekFrom::Start(0x100_0000_0000 - 8))
                .expect("Failed to seek.");
            let value = 0x0000_0040_3f00_ffffu64;
            qcow.write_all(&value.to_le_bytes())
                .expect("failed to write data");
        });
    }

    #[test]
    fn test_header_huge_num_refcounts() {
        let mut header = valid_header_v3();
        header[56..60].copy_from_slice(&[0x02, 0x00, 0xe8, 0xff]);
        with_basic_file(&header, |disk_file: RawFile| {
            QcowFile::from(disk_file).expect_err("Created disk with crazy refcount clusters");
        });
    }

    #[test]
    fn test_header_huge_refcount_offset() {
        let mut header = valid_header_v3();
        header[48..56].copy_from_slice(&[0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x02, 0x00]);
        with_basic_file(&header, |disk_file: RawFile| {
            QcowFile::from(disk_file).expect_err("Created disk with crazy refcount offset");
        });
    }

    #[test]
    fn write_read_start() {
        with_basic_file(&valid_header_v3(), |disk_file: RawFile| {
            let mut q = QcowFile::from(disk_file).unwrap();
            q.write_all(b"test first bytes")
                .expect("Failed to write test string.");
            let mut buf = [0u8; 4];
            q.rewind().expect("Failed to seek.");
            q.read_exact(&mut buf).expect("Failed to read.");
            assert_eq!(&buf, b"test");
        });
    }

    #[test]
    fn write_read_start_backing_overlap() {
        let disk_file = basic_file(&valid_header_v3());
        let mut backing = QcowFile::from(disk_file).unwrap();
        backing
            .write_all(b"test first bytes")
            .expect("Failed to write test string.");
        let wrapping_disk_file = basic_file(&valid_header_v3());
        let mut wrapping = QcowFile::from(wrapping_disk_file).unwrap();
        wrapping.set_backing_file(Some(Box::new(backing)));
        wrapping.seek(SeekFrom::Start(0)).expect("Failed to seek.");
        wrapping
            .write_all(b"TEST")
            .expect("Failed to write second test string.");
        let mut buf = [0u8; 10];
        wrapping.seek(SeekFrom::Start(0)).expect("Failed to seek.");
        wrapping.read_exact(&mut buf).expect("Failed to read.");
        assert_eq!(&buf, b"TEST first");
    }

    #[test]
    fn offset_write_read() {
        with_basic_file(&valid_header_v3(), |disk_file: RawFile| {
            let mut q = QcowFile::from(disk_file).unwrap();
            let b = [0x55u8; 0x1000];
            q.seek(SeekFrom::Start(0xfff2000)).expect("Failed to seek.");
            q.write_all(&b).expect("Failed to write test string.");
            let mut buf = [0u8; 4];
            q.seek(SeekFrom::Start(0xfff2000)).expect("Failed to seek.");
            q.read_exact(&mut buf).expect("Failed to read.");
            assert_eq!(buf[0], 0x55);
        });
    }

    #[test]
    fn write_zeroes_read() {
        with_basic_file(&valid_header_v3(), |disk_file: RawFile| {
            let mut q = QcowFile::from(disk_file).unwrap();
            // Write some test data.
            let b = [0x55u8; 0x1000];
            q.seek(SeekFrom::Start(0xfff2000)).expect("Failed to seek.");
            q.write_all(&b).expect("Failed to write test string.");
            // Overwrite the test data with zeroes.
            q.seek(SeekFrom::Start(0xfff2000)).expect("Failed to seek.");
            let nwritten = q.write_zeroes(0x200).expect("Failed to write zeroes.");
            assert_eq!(nwritten, 0x200);
            // Verify that the correct part of the data was zeroed out.
            let mut buf = [0u8; 0x1000];
            q.seek(SeekFrom::Start(0xfff2000)).expect("Failed to seek.");
            q.read_exact(&mut buf).expect("Failed to read.");
            assert_eq!(buf[0], 0);
            assert_eq!(buf[0x1FF], 0);
            assert_eq!(buf[0x200], 0x55);
            assert_eq!(buf[0xFFF], 0x55);
        });
    }

    #[test]
    fn write_zeroes_full_cluster() {
        // Choose a size that is larger than a cluster.
        // valid_header uses cluster_bits = 12, which corresponds to a cluster size of 4096.
        const CHUNK_SIZE: usize = 4096 * 2 + 512;
        with_basic_file(&valid_header_v3(), |disk_file: RawFile| {
            let mut q = QcowFile::from(disk_file).unwrap();
            // Write some test data.
            let b = [0x55u8; CHUNK_SIZE];
            q.rewind().expect("Failed to seek.");
            q.write_all(&b).expect("Failed to write test string.");
            // Overwrite the full cluster with zeroes.
            q.rewind().expect("Failed to seek.");
            let nwritten = q.write_zeroes(CHUNK_SIZE).expect("Failed to write zeroes.");
            assert_eq!(nwritten, CHUNK_SIZE);
            // Verify that the data was zeroed out.
            let mut buf = [0u8; CHUNK_SIZE];
            q.rewind().expect("Failed to seek.");
            q.read_exact(&mut buf).expect("Failed to read.");
            assert_eq!(buf[0], 0);
            assert_eq!(buf[CHUNK_SIZE - 1], 0);
        });
    }

    #[test]
    fn test_header() {
        with_basic_file(&valid_header_v2(), |disk_file: RawFile| {
            let q = QcowFile::from(disk_file).unwrap();
            assert_eq!(q.virtual_size(), 0x20_0000_0000);
        });
        with_basic_file(&valid_header_v3(), |disk_file: RawFile| {
            let q = QcowFile::from(disk_file).unwrap();
            assert_eq!(q.virtual_size(), 0x20_0000_0000);
        });
    }

    #[test]
    fn read_small_buffer() {
        with_basic_file(&valid_header_v3(), |disk_file: RawFile| {
            let mut q = QcowFile::from(disk_file).unwrap();
            let mut b = [5u8; 16];
            q.seek(SeekFrom::Start(1000)).expect("Failed to seek.");
            q.read_exact(&mut b).expect("Failed to read.");
            assert_eq!(0, b[0]);
            assert_eq!(0, b[15]);
        });
    }

    #[test]
    fn replay_ext4() {
        with_basic_file(&valid_header_v3(), |disk_file: RawFile| {
            let mut q = QcowFile::from(disk_file).unwrap();
            const BUF_SIZE: usize = 0x1000;
            let mut b = [0u8; BUF_SIZE];

            struct Transfer {
                pub write: bool,
                pub addr: u64,
            }

            // Write transactions from mkfs.ext4.
            let xfers: Vec<Transfer> = vec![
                Transfer {
                    write: false,
                    addr: 0xfff0000,
                },
                Transfer {
                    write: false,
                    addr: 0xfffe000,
                },
                Transfer {
                    write: false,
                    addr: 0x0,
                },
                Transfer {
                    write: false,
                    addr: 0x1000,
                },
                Transfer {
                    write: false,
                    addr: 0xffff000,
                },
                Transfer {
                    write: false,
                    addr: 0xffdf000,
                },
                Transfer {
                    write: false,
                    addr: 0xfff8000,
                },
                Transfer {
                    write: false,
                    addr: 0xffe0000,
                },
                Transfer {
                    write: false,
                    addr: 0xffce000,
                },
                Transfer {
                    write: false,
                    addr: 0xffb6000,
                },
                Transfer {
                    write: false,
                    addr: 0xffab000,
                },
                Transfer {
                    write: false,
                    addr: 0xffa4000,
                },
                Transfer {
                    write: false,
                    addr: 0xff8e000,
                },
                Transfer {
                    write: false,
                    addr: 0xff86000,
                },
                Transfer {
                    write: false,
                    addr: 0xff84000,
                },
                Transfer {
                    write: false,
                    addr: 0xff89000,
                },
                Transfer {
                    write: false,
                    addr: 0xfe7e000,
                },
                Transfer {
                    write: false,
                    addr: 0x100000,
                },
                Transfer {
                    write: false,
                    addr: 0x3000,
                },
                Transfer {
                    write: false,
                    addr: 0x7000,
                },
                Transfer {
                    write: false,
                    addr: 0xf000,
                },
                Transfer {
                    write: false,
                    addr: 0x2000,
                },
                Transfer {
                    write: false,
                    addr: 0x4000,
                },
                Transfer {
                    write: false,
                    addr: 0x5000,
                },
                Transfer {
                    write: false,
                    addr: 0x6000,
                },
                Transfer {
                    write: false,
                    addr: 0x8000,
                },
                Transfer {
                    write: false,
                    addr: 0x9000,
                },
                Transfer {
                    write: false,
                    addr: 0xa000,
                },
                Transfer {
                    write: false,
                    addr: 0xb000,
                },
                Transfer {
                    write: false,
                    addr: 0xc000,
                },
                Transfer {
                    write: false,
                    addr: 0xd000,
                },
                Transfer {
                    write: false,
                    addr: 0xe000,
                },
                Transfer {
                    write: false,
                    addr: 0x10000,
                },
                Transfer {
                    write: false,
                    addr: 0x11000,
                },
                Transfer {
                    write: false,
                    addr: 0x12000,
                },
                Transfer {
                    write: false,
                    addr: 0x13000,
                },
                Transfer {
                    write: false,
                    addr: 0x14000,
                },
                Transfer {
                    write: false,
                    addr: 0x15000,
                },
                Transfer {
                    write: false,
                    addr: 0x16000,
                },
                Transfer {
                    write: false,
                    addr: 0x17000,
                },
                Transfer {
                    write: false,
                    addr: 0x18000,
                },
                Transfer {
                    write: false,
                    addr: 0x19000,
                },
                Transfer {
                    write: false,
                    addr: 0x1a000,
                },
                Transfer {
                    write: false,
                    addr: 0x1b000,
                },
                Transfer {
                    write: false,
                    addr: 0x1c000,
                },
                Transfer {
                    write: false,
                    addr: 0x1d000,
                },
                Transfer {
                    write: false,
                    addr: 0x1e000,
                },
                Transfer {
                    write: false,
                    addr: 0x1f000,
                },
                Transfer {
                    write: false,
                    addr: 0x21000,
                },
                Transfer {
                    write: false,
                    addr: 0x22000,
                },
                Transfer {
                    write: false,
                    addr: 0x24000,
                },
                Transfer {
                    write: false,
                    addr: 0x40000,
                },
                Transfer {
                    write: false,
                    addr: 0x0,
                },
                Transfer {
                    write: false,
                    addr: 0x3000,
                },
                Transfer {
                    write: false,
                    addr: 0x7000,
                },
                Transfer {
                    write: false,
                    addr: 0x0,
                },
                Transfer {
                    write: false,
                    addr: 0x1000,
                },
                Transfer {
                    write: false,
                    addr: 0x2000,
                },
                Transfer {
                    write: false,
                    addr: 0x3000,
                },
                Transfer {
                    write: false,
                    addr: 0x0,
                },
                Transfer {
                    write: false,
                    addr: 0x449000,
                },
                Transfer {
                    write: false,
                    addr: 0x48000,
                },
                Transfer {
                    write: false,
                    addr: 0x48000,
                },
                Transfer {
                    write: false,
                    addr: 0x448000,
                },
                Transfer {
                    write: false,
                    addr: 0x44a000,
                },
                Transfer {
                    write: false,
                    addr: 0x48000,
                },
                Transfer {
                    write: false,
                    addr: 0x48000,
                },
                Transfer {
                    write: true,
                    addr: 0x0,
                },
                Transfer {
                    write: true,
                    addr: 0x448000,
                },
                Transfer {
                    write: true,
                    addr: 0x449000,
                },
                Transfer {
                    write: true,
                    addr: 0x44a000,
                },
                Transfer {
                    write: true,
                    addr: 0xfff0000,
                },
                Transfer {
                    write: true,
                    addr: 0xfff1000,
                },
                Transfer {
                    write: true,
                    addr: 0xfff2000,
                },
                Transfer {
                    write: true,
                    addr: 0xfff3000,
                },
                Transfer {
                    write: true,
                    addr: 0xfff4000,
                },
                Transfer {
                    write: true,
                    addr: 0xfff5000,
                },
                Transfer {
                    write: true,
                    addr: 0xfff6000,
                },
                Transfer {
                    write: true,
                    addr: 0xfff7000,
                },
                Transfer {
                    write: true,
                    addr: 0xfff8000,
                },
                Transfer {
                    write: true,
                    addr: 0xfff9000,
                },
                Transfer {
                    write: true,
                    addr: 0xfffa000,
                },
                Transfer {
                    write: true,
                    addr: 0xfffb000,
                },
                Transfer {
                    write: true,
                    addr: 0xfffc000,
                },
                Transfer {
                    write: true,
                    addr: 0xfffd000,
                },
                Transfer {
                    write: true,
                    addr: 0xfffe000,
                },
                Transfer {
                    write: true,
                    addr: 0xffff000,
                },
            ];

            for xfer in &xfers {
                q.seek(SeekFrom::Start(xfer.addr)).expect("Failed to seek.");
                if xfer.write {
                    q.write_all(&b).expect("Failed to write.");
                } else {
                    let read_count: usize = q.read(&mut b).expect("Failed to read.");
                    assert_eq!(read_count, BUF_SIZE);
                }
            }
        });
    }

    #[test]
    fn combo_write_read() {
        combo_write_read_common(false);
    }

    #[test]
    fn combo_write_read_direct() {
        combo_write_read_common(true);
    }

    fn combo_write_read_common(direct: bool) {
        with_default_file(1024 * 1024 * 1024 * 256, direct, |mut qcow_file| {
            const NUM_BLOCKS: usize = 555;
            const BLOCK_SIZE: usize = 0x1_0000;
            const OFFSET: usize = 0x1_0000_0020;
            let data = [0x55u8; BLOCK_SIZE];
            let mut readback = [0u8; BLOCK_SIZE];
            for i in 0..NUM_BLOCKS {
                let seek_offset = OFFSET + i * BLOCK_SIZE;
                qcow_file
                    .seek(SeekFrom::Start(seek_offset as u64))
                    .expect("Failed to seek.");
                let nwritten = qcow_file.write(&data).expect("Failed to write test data.");
                assert_eq!(nwritten, BLOCK_SIZE);
                // Read back the data to check it was written correctly.
                qcow_file
                    .seek(SeekFrom::Start(seek_offset as u64))
                    .expect("Failed to seek.");
                let nread = qcow_file.read(&mut readback).expect("Failed to read.");
                assert_eq!(nread, BLOCK_SIZE);
                for (orig, read) in data.iter().zip(readback.iter()) {
                    assert_eq!(orig, read);
                }
            }
            // Check that address 0 is still zeros.
            qcow_file.rewind().expect("Failed to seek.");
            let nread = qcow_file.read(&mut readback).expect("Failed to read.");
            assert_eq!(nread, BLOCK_SIZE);
            for read in readback.iter() {
                assert_eq!(*read, 0);
            }
            // Check the data again after the writes have happened.
            for i in 0..NUM_BLOCKS {
                let seek_offset = OFFSET + i * BLOCK_SIZE;
                qcow_file
                    .seek(SeekFrom::Start(seek_offset as u64))
                    .expect("Failed to seek.");
                let nread = qcow_file.read(&mut readback).expect("Failed to read.");
                assert_eq!(nread, BLOCK_SIZE);
                for (orig, read) in data.iter().zip(readback.iter()) {
                    assert_eq!(orig, read);
                }
            }
        });
    }

    fn seek_cur(file: &mut QcowFile) -> u64 {
        file.stream_position().unwrap()
    }

    #[test]
    fn seek_data() {
        seek_data_common(false);
    }

    #[test]
    fn seek_data_direct() {
        seek_data_common(true);
    }

    fn seek_data_common(direct: bool) {
        with_default_file(0x30000, direct, |mut file| {
            // seek_data at or after the end of the file should return None
            assert_eq!(file.seek_data(0x10000).unwrap(), None);
            assert_eq!(seek_cur(&mut file), 0);
            assert_eq!(file.seek_data(0x10001).unwrap(), None);
            assert_eq!(seek_cur(&mut file), 0);

            // Write some data to [0x10000, 0x20000)
            let b = [0x55u8; 0x10000];
            file.seek(SeekFrom::Start(0x10000)).unwrap();
            file.write_all(&b).unwrap();
            assert_eq!(file.seek_data(0).unwrap(), Some(0x10000));
            assert_eq!(seek_cur(&mut file), 0x10000);

            // seek_data within data should return the same offset
            assert_eq!(file.seek_data(0x10000).unwrap(), Some(0x10000));
            assert_eq!(seek_cur(&mut file), 0x10000);
            assert_eq!(file.seek_data(0x10001).unwrap(), Some(0x10001));
            assert_eq!(seek_cur(&mut file), 0x10001);
            assert_eq!(file.seek_data(0x1FFFF).unwrap(), Some(0x1FFFF));
            assert_eq!(seek_cur(&mut file), 0x1FFFF);

            assert_eq!(file.seek_data(0).unwrap(), Some(0x10000));
            assert_eq!(seek_cur(&mut file), 0x10000);
            assert_eq!(file.seek_data(0x1FFFF).unwrap(), Some(0x1FFFF));
            assert_eq!(seek_cur(&mut file), 0x1FFFF);
            assert_eq!(file.seek_data(0x20000).unwrap(), None);
            assert_eq!(seek_cur(&mut file), 0x1FFFF);
        });
    }

    #[test]
    fn seek_hole() {
        seek_hole_common(false);
    }

    #[test]
    fn seek_hole_direct() {
        seek_hole_common(true);
    }

    fn seek_hole_common(direct: bool) {
        with_default_file(0x30000, direct, |mut file| {
            // File consisting entirely of a hole
            assert_eq!(file.seek_hole(0).unwrap(), Some(0));
            assert_eq!(seek_cur(&mut file), 0);
            assert_eq!(file.seek_hole(0xFFFF).unwrap(), Some(0xFFFF));
            assert_eq!(seek_cur(&mut file), 0xFFFF);

            // seek_hole at or after the end of the file should return None
            file.rewind().unwrap();
            assert_eq!(file.seek_hole(0x30000).unwrap(), None);
            assert_eq!(seek_cur(&mut file), 0);
            assert_eq!(file.seek_hole(0x30001).unwrap(), None);
            assert_eq!(seek_cur(&mut file), 0);

            // Write some data to [0x10000, 0x20000)
            let b = [0x55u8; 0x10000];
            file.seek(SeekFrom::Start(0x10000)).unwrap();
            file.write_all(&b).unwrap();

            // seek_hole within a hole should return the same offset
            assert_eq!(file.seek_hole(0).unwrap(), Some(0));
            assert_eq!(seek_cur(&mut file), 0);
            assert_eq!(file.seek_hole(0xFFFF).unwrap(), Some(0xFFFF));
            assert_eq!(seek_cur(&mut file), 0xFFFF);

            // seek_hole within data should return the next hole
            file.rewind().unwrap();
            assert_eq!(file.seek_hole(0x10000).unwrap(), Some(0x20000));
            assert_eq!(seek_cur(&mut file), 0x20000);
            file.rewind().unwrap();
            assert_eq!(file.seek_hole(0x10001).unwrap(), Some(0x20000));
            assert_eq!(seek_cur(&mut file), 0x20000);
            file.rewind().unwrap();
            assert_eq!(file.seek_hole(0x1FFFF).unwrap(), Some(0x20000));
            assert_eq!(seek_cur(&mut file), 0x20000);
            file.rewind().unwrap();
            assert_eq!(file.seek_hole(0xFFFF).unwrap(), Some(0xFFFF));
            assert_eq!(seek_cur(&mut file), 0xFFFF);
            file.rewind().unwrap();
            assert_eq!(file.seek_hole(0x10000).unwrap(), Some(0x20000));
            assert_eq!(seek_cur(&mut file), 0x20000);
            file.rewind().unwrap();
            assert_eq!(file.seek_hole(0x1FFFF).unwrap(), Some(0x20000));
            assert_eq!(seek_cur(&mut file), 0x20000);
            file.rewind().unwrap();
            assert_eq!(file.seek_hole(0x20000).unwrap(), Some(0x20000));
            assert_eq!(seek_cur(&mut file), 0x20000);
            file.rewind().unwrap();
            assert_eq!(file.seek_hole(0x20001).unwrap(), Some(0x20001));
            assert_eq!(seek_cur(&mut file), 0x20001);

            // seek_hole at EOF should return None
            file.rewind().unwrap();
            assert_eq!(file.seek_hole(0x30000).unwrap(), None);
            assert_eq!(seek_cur(&mut file), 0);

            // Write some data to [0x20000, 0x30000)
            file.seek(SeekFrom::Start(0x20000)).unwrap();
            file.write_all(&b).unwrap();

            // seek_hole within [0x20000, 0x30000) should now find the hole at EOF
            assert_eq!(file.seek_hole(0x20000).unwrap(), Some(0x30000));
            assert_eq!(seek_cur(&mut file), 0x30000);
            file.rewind().unwrap();
            assert_eq!(file.seek_hole(0x20001).unwrap(), Some(0x30000));
            assert_eq!(seek_cur(&mut file), 0x30000);
            file.rewind().unwrap();
            assert_eq!(file.seek_hole(0x30000).unwrap(), None);
            assert_eq!(seek_cur(&mut file), 0);
        });
    }

    #[test]
    fn rebuild_refcounts() {
        with_basic_file(&valid_header_v3(), |mut disk_file: RawFile| {
            let header = QcowHeader::new(&mut disk_file).expect("Failed to create Header.");
            let cluster_size = 65536;
            let refcount_bits = 1u64 << header.refcount_order;
            let mut raw_file = QcowRawFile::from(disk_file, cluster_size, refcount_bits)
                .expect("Failed to create QcowRawFile.");
            QcowFile::rebuild_refcounts(&mut raw_file, header)
                .expect("Failed to rebuild recounts.");
        });
    }

    // Helper to create a v3 header with specific incompatible feature bits set
    fn header_v3_with_incompat_features(features: u64) -> Vec<u8> {
        let mut header = valid_header_v3();
        // incompatible_features is at offset 72, big-endian u64
        header[72..80].copy_from_slice(&features.to_be_bytes());
        header
    }

    #[test]
    fn accept_incompat_dirty_bit() {
        let header = header_v3_with_incompat_features(1 << 0);
        with_basic_file(&header, |disk_file: RawFile| {
            let result = QcowFile::from(disk_file);
            assert!(
                result.is_ok(),
                "Expected dirty bit to be accepted, got: {result:?}"
            );
        });
    }

    #[test]
    fn reject_corrupt_bit_for_writable_open() {
        // Bit 1: corrupt - image metadata is corrupted
        let header = header_v3_with_incompat_features(1 << 1);
        with_basic_file(&header, |disk_file: RawFile| {
            let result = QcowFile::from(disk_file);
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(
                matches!(err, Error::CorruptImage),
                "Expected CorruptImage error, got: {err:?}"
            );
        });
    }

    #[test]
    fn reject_unsupported_incompat_external_data_bit() {
        // Bit 2: external data file
        let header = header_v3_with_incompat_features(1 << 2);
        with_basic_file(&header, |disk_file: RawFile| {
            let result = QcowFile::from(disk_file);
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(
                matches!(err, Error::UnsupportedFeature(ref v) if v.to_string().contains("external")),
                "Expected UnsupportedFeature error mentioning external, got: {err:?}"
            );
        });
    }

    #[test]
    fn reject_unsupported_incompat_extended_l2_bit() {
        // Bit 4: extended L2 entries
        let header = header_v3_with_incompat_features(1 << 4);
        with_basic_file(&header, |disk_file: RawFile| {
            let result = QcowFile::from(disk_file);
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(
                matches!(err, Error::UnsupportedFeature(ref v) if v.to_string().contains("extended")),
                "Expected UnsupportedFeature error mentioning extended, got: {err:?}"
            );
        });
    }

    #[test]
    fn reject_multiple_unsupported_incompat_bits() {
        // Multiple unsupported bits: external data (2) + extended L2 (4)
        let header = header_v3_with_incompat_features((1 << 2) | (1 << 4));
        with_basic_file(&header, |disk_file: RawFile| {
            let result = QcowFile::from(disk_file);
            assert!(result.is_err());
            assert!(matches!(result.unwrap_err(), Error::UnsupportedFeature(_)));
        });
    }

    #[test]
    fn reject_unknown_incompat_bit() {
        // Unknown bit 5 (not defined in spec)
        let header = header_v3_with_incompat_features(1 << 5);
        with_basic_file(&header, |disk_file: RawFile| {
            let result = QcowFile::from(disk_file);
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(
                matches!(err, Error::UnsupportedFeature(ref v) if v.to_string().contains("unknown")),
                "Expected UnsupportedFeature error mentioning unknown, got: {err:?}"
            );
        });
    }

    #[test]
    fn dirty_bit_set_on_open_cleared_on_close_v3() {
        // Test that the dirty bit is set when a v3 image is opened and cleared when it's closed
        let header = valid_header_v3();
        with_basic_file(&header, |mut disk_file: RawFile| {
            // Verify dirty bit is not set initially
            disk_file
                .seek(SeekFrom::Start(V2_BARE_HEADER_SIZE as u64))
                .unwrap();
            let features_before = u64::read_be(&mut disk_file).unwrap();
            assert_eq!(
                features_before & IncompatFeatures::DIRTY.bits(),
                0,
                "Dirty bit should not be set initially"
            );

            // Open the file - this should set the dirty bit
            disk_file.rewind().unwrap();
            {
                let qcow = QcowFile::from(disk_file.try_clone().unwrap()).unwrap();

                // Verify dirty bit is set while file is open
                disk_file
                    .seek(SeekFrom::Start(V2_BARE_HEADER_SIZE as u64))
                    .unwrap();
                let features_during = u64::read_be(&mut disk_file).unwrap();
                assert_ne!(
                    features_during & IncompatFeatures::DIRTY.bits(),
                    0,
                    "Dirty bit should be set while file is open"
                );

                drop(qcow); // Close the file
            }

            // Verify dirty bit is cleared after close
            disk_file
                .seek(SeekFrom::Start(V2_BARE_HEADER_SIZE as u64))
                .unwrap();
            let features_after = u64::read_be(&mut disk_file).unwrap();
            assert_eq!(
                features_after & IncompatFeatures::DIRTY.bits(),
                0,
                "Dirty bit should be cleared after close"
            );
        });
    }

    #[test]
    fn dirty_bit_not_used_for_v2() {
        // Test that v2 images don't use the dirty bit (no incompatible_features field)
        let header = valid_header_v2();
        with_basic_file(&header, |mut disk_file: RawFile| {
            // Open and close v2 file - should work without touching offset 72
            disk_file.rewind().unwrap();
            let qcow = QcowFile::from(disk_file.try_clone().unwrap()).unwrap();
            assert_eq!(qcow.header.version, 2, "Should be a v2 file");
            drop(qcow);
        });
    }

    #[test]
    fn dirty_bit_not_set_for_readonly_v3() {
        // Test that read-only v3 files don't set the dirty bit (e.g., backing files)
        let header = valid_header_v3();

        // Create a temp file with a valid v3 qcow header
        let temp_file = TempFile::new().unwrap();
        let temp_path = temp_file.as_path().to_owned();
        {
            let mut file = temp_file.as_file().try_clone().unwrap();
            file.write_all(&header).unwrap();
            file.set_len(0x1_0000_0000).unwrap();
        }

        // Open the file read-only
        let readonly_file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(&temp_path)
            .unwrap();
        let raw_file = RawFile::new(readonly_file, false);

        // Verify the file is detected as read-only
        assert!(
            !raw_file.is_writable(),
            "File should be detected as read-only"
        );

        // Open as QcowFile - should not set dirty bit for read-only files
        let qcow = QcowFile::from(raw_file).unwrap();
        assert!(
            !qcow.raw_file.file().is_writable(),
            "File should be read-only"
        );

        // Verify dirty bit was not written to disk
        let verify_file = OpenOptions::new().read(true).open(&temp_path).unwrap();
        let mut verify_raw = RawFile::new(verify_file, false);
        verify_raw
            .seek(SeekFrom::Start(V2_BARE_HEADER_SIZE as u64))
            .unwrap();
        let features = u64::read_be(&mut verify_raw).unwrap();
        assert_eq!(
            features & IncompatFeatures::DIRTY.bits(),
            0,
            "Dirty bit should not be written for read-only files"
        );
    }

    #[test]
    fn corrupt_image_rejected_for_write() {
        // Test that a corrupt image cannot be opened for writing
        let header = header_v3_with_incompat_features(IncompatFeatures::CORRUPT.bits());
        with_basic_file(&header, |disk_file: RawFile| {
            assert!(disk_file.is_writable(), "File should be writable");

            let result = QcowFile::from(disk_file);
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(
                matches!(err, Error::CorruptImage),
                "Expected CorruptImage error, got: {err:?}"
            );
        });
    }

    #[test]
    fn corrupt_image_allowed_readonly() {
        // Test that a corrupt image can be opened read-only
        let header = header_v3_with_incompat_features(IncompatFeatures::CORRUPT.bits());

        // Create a temp file with the corrupt header
        let temp_file = TempFile::new().unwrap();
        let temp_path = temp_file.as_path().to_owned();
        {
            let mut file = temp_file.as_file().try_clone().unwrap();
            file.write_all(&header).unwrap();
            file.set_len(0x1_0000_0000).unwrap();
        }

        let readonly_file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(&temp_path)
            .unwrap();
        let raw_file = RawFile::new(readonly_file, false);
        assert!(!raw_file.is_writable(), "File should be read-only");

        let result = QcowFile::from(raw_file);
        assert!(
            result.is_ok(),
            "Corrupt image should be openable read-only, got: {:?}",
            result.err()
        );

        let qcow = result.unwrap();
        assert!(qcow.header.is_corrupt(), "Corrupt bit should be set");
    }

    #[test]
    fn set_corrupt_bit() {
        // Test that set_corrupt_bit correctly sets the corrupt bit
        let header = valid_header_v3();
        with_basic_file(&header, |mut disk_file: RawFile| {
            let mut qcow = QcowFile::from(disk_file.try_clone().unwrap()).unwrap();

            assert!(!qcow.header.is_corrupt(), "Should not be corrupt initially");

            qcow.header
                .set_corrupt_bit(qcow.raw_file.file_mut())
                .unwrap();

            // Verify in memory
            assert!(qcow.header.is_corrupt(), "Should be corrupt after set");

            // Verify on disk
            disk_file
                .seek(SeekFrom::Start(V2_BARE_HEADER_SIZE as u64))
                .unwrap();
            let features = u64::read_be(&mut disk_file).unwrap();
            assert!(
                IncompatFeatures::from_bits_retain(features).contains(IncompatFeatures::CORRUPT),
                "Corrupt bit should be set on disk"
            );
        });
    }

    #[test]
    fn corrupt_bit_persists_with_dirty() {
        // Test that both corrupt and dirty bits can coexist
        let header = header_v3_with_incompat_features(
            IncompatFeatures::CORRUPT.bits() | IncompatFeatures::DIRTY.bits(),
        );

        let temp_file = TempFile::new().unwrap();
        let temp_path = temp_file.as_path().to_owned();
        {
            let mut file = temp_file.as_file().try_clone().unwrap();
            file.write_all(&header).unwrap();
            file.set_len(0x1_0000_0000).unwrap();
        }

        // Writable would be rejected due to corrupt bit
        let readonly_file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(&temp_path)
            .unwrap();
        let raw_file = RawFile::new(readonly_file, false);

        let qcow = QcowFile::from(raw_file).unwrap();

        let features = IncompatFeatures::from_bits_truncate(qcow.header.incompatible_features);
        assert!(
            features.contains(IncompatFeatures::CORRUPT),
            "Corrupt bit should be set"
        );
        assert!(
            features.contains(IncompatFeatures::DIRTY),
            "Dirty bit should also be set"
        );
    }
}
