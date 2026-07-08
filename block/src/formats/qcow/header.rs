// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

//! QCOW2 header parsing, validation, and creation.

use std::fmt::{Display, Formatter, Result as FmtResult};
use std::os::unix::fs::FileExt;
use std::str::FromStr;

use bitflags::bitflags;
use vmm_sys_util::file_traits::FileSync;
use zerocopy::big_endian::{U32 as BeU32, U64 as BeU64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use super::decoder::{Decoder, ZlibDecoder, ZstdDecoder};
use super::parser::{Error, Result};
use super::util::{div_round_up_u32, div_round_up_u64};
use crate::aligned_file::AlignedFile;
use crate::error::{BlockError, BlockErrorKind, BlockResult};

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
pub(super) const MAX_QCOW_FILE_SIZE: u64 = 0x01 << 44; // 16 TB.

// QCOW magic constant that starts the header.
pub(super) const QCOW_MAGIC: u32 = 0x5146_49fb;
// Default to a cluster size of 2^DEFAULT_CLUSTER_BITS
pub(super) const DEFAULT_CLUSTER_BITS: u32 = 16;
// Limit clusters to reasonable sizes. Choose the same limits as qemu. Making the clusters smaller
// increases the amount of overhead for book keeping.
pub(super) const MIN_CLUSTER_BITS: u32 = 9;
pub(super) const MAX_CLUSTER_BITS: u32 = 21;
// The L1 and RefCount table are kept in RAM, only handle files that require less than 35M entries.
// This easily covers 1 TB files. When support for bigger files is needed the assumptions made to
// keep these tables in RAM needs to be thrown out.
pub(super) const MAX_RAM_POINTER_TABLE_SIZE: u64 = 35_000_000;
// 16-bit refcounts.
pub(super) const DEFAULT_REFCOUNT_ORDER: u32 = 4;

pub(super) const V2_BARE_HEADER_SIZE: u32 = 72;
pub(super) const V3_BARE_HEADER_SIZE: u32 = 104;
pub(super) const AUTOCLEAR_FEATURES_OFFSET: u64 = 88;

pub(super) const COMPATIBLE_FEATURES_LAZY_REFCOUNTS: u64 = 1;

// Compression types as defined in https://www.qemu.org/docs/master/interop/qcow2.html
const COMPRESSION_TYPE_ZLIB: u64 = 0; // zlib/deflate <https://www.ietf.org/rfc/rfc1951.txt>
const COMPRESSION_TYPE_ZSTD: u64 = 1; // zstd <http://github.com/facebook/zstd>

// Header extension types
pub(super) const HEADER_EXT_END: u32 = 0x00000000;
// Backing file format name (raw, qcow2)
pub(super) const HEADER_EXT_BACKING_FORMAT: u32 = 0xe2792aca;
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
    pub(super) const SUPPORTED: IncompatFeatures = IncompatFeatures::DIRTY
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
#[derive(Debug, Clone, thiserror::Error)]
pub struct MissingFeatureError {
    /// Unsupported feature bits.
    features: IncompatFeatures,
    /// Feature name table from the qcow2 image.
    feature_names: Vec<(u8, String)>,
}

impl MissingFeatureError {
    pub(super) fn new(features: IncompatFeatures, feature_names: Vec<(u8, String)>) -> Self {
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

/// On-disk layout of the bare qcow2 header shared by v2 and v3 (72 bytes).
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable)]
struct RawHeaderV2 {
    magic: BeU32,
    version: BeU32,
    backing_file_offset: BeU64,
    backing_file_size: BeU32,
    cluster_bits: BeU32,
    size: BeU64,
    crypt_method: BeU32,
    l1_size: BeU32,
    l1_table_offset: BeU64,
    refcount_table_offset: BeU64,
    refcount_table_clusters: BeU32,
    nb_snapshots: BeU32,
    snapshots_offset: BeU64,
}

impl RawHeaderV2 {
    fn from_header(header: &QcowHeader) -> Self {
        Self {
            magic: BeU32::new(header.magic),
            version: BeU32::new(header.version),
            backing_file_offset: BeU64::new(header.backing_file_offset),
            backing_file_size: BeU32::new(header.backing_file_size),
            cluster_bits: BeU32::new(header.cluster_bits),
            size: BeU64::new(header.size),
            crypt_method: BeU32::new(header.crypt_method),
            l1_size: BeU32::new(header.l1_size),
            l1_table_offset: BeU64::new(header.l1_table_offset),
            refcount_table_offset: BeU64::new(header.refcount_table_offset),
            refcount_table_clusters: BeU32::new(header.refcount_table_clusters),
            nb_snapshots: BeU32::new(header.nb_snapshots),
            snapshots_offset: BeU64::new(header.snapshots_offset),
        }
    }
}

/// On-disk layout of the fields v3 adds after the bare header (32 bytes).
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable)]
struct RawHeaderV3Tail {
    incompatible_features: BeU64,
    compatible_features: BeU64,
    autoclear_features: BeU64,
    refcount_order: BeU32,
    header_size: BeU32,
}

impl RawHeaderV3Tail {
    fn from_header(header: &QcowHeader) -> Self {
        Self {
            incompatible_features: BeU64::new(header.incompatible_features),
            compatible_features: BeU64::new(header.compatible_features),
            autoclear_features: BeU64::new(header.autoclear_features),
            refcount_order: BeU32::new(header.refcount_order),
            header_size: BeU32::new(header.header_size),
        }
    }
}

#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable)]
struct ExtensionHeader {
    extension_type: BeU32,
    length: BeU32,
}

impl ExtensionHeader {
    fn end() -> Self {
        Self {
            extension_type: BeU32::new(HEADER_EXT_END),
            length: BeU32::ZERO,
        }
    }
}

impl QcowHeader {
    /// Read header extensions, optionally collecting feature names for error reporting.
    pub(super) fn read_header_extensions(
        f: &AlignedFile,
        header: &mut QcowHeader,
        mut feature_table: Option<&mut Vec<(u8, String)>>,
    ) -> Result<()> {
        // Extensions start directly after the header.
        let mut offset = header.header_size as u64;

        loop {
            let mut field = [0u8; size_of::<ExtensionHeader>()];
            f.read_exact_at(&mut field, offset)
                .map_err(Error::ReadingHeader)?;
            offset += field.len() as u64;

            let extension =
                ExtensionHeader::read_from_bytes(&field).expect("buffer covers extension header");
            let ext_type = extension.extension_type.get();
            if ext_type == HEADER_EXT_END {
                break;
            }

            let ext_length = extension.length.get();

            match ext_type {
                HEADER_EXT_BACKING_FORMAT => {
                    let mut format_bytes = vec![0u8; ext_length as usize];
                    f.read_exact_at(&mut format_bytes, offset)
                        .map_err(Error::ReadingHeader)?;
                    offset += format_bytes.len() as u64;
                    let format_str = String::from_utf8(format_bytes)
                        .map_err(|err| Error::InvalidBackingFileName(err.utf8_error()))?;
                    if let Some(backing_file) = &mut header.backing_file {
                        backing_file.format = Some(format_str.parse()?);
                    }
                }
                HEADER_EXT_FEATURE_NAME_TABLE if feature_table.is_some() => {
                    const FEATURE_NAME_ENTRY_SIZE: usize = 1 + 1 + 46; // type + bit + name
                    let mut data = vec![0u8; ext_length as usize];
                    f.read_exact_at(&mut data, offset)
                        .map_err(Error::ReadingHeader)?;
                    offset += data.len() as u64;
                    let table = feature_table.as_mut().unwrap();
                    for entry in data.as_chunks::<FEATURE_NAME_ENTRY_SIZE>().0 {
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
                    offset += ext_length as u64;
                }
            }

            // Skip to the next 8 byte boundary
            let padding = (8 - (ext_length % 8)) % 8;
            offset += padding as u64;
        }

        Ok(())
    }

    /// Creates a QcowHeader from a reference to a file.
    pub fn new(f: &AlignedFile) -> Result<QcowHeader> {
        // The bare header fits in V3_BARE_HEADER_SIZE plus the optional
        // compression field. Read it once, then decode each region as a typed
        // view whose layout matches the on-disk header.
        let mut buf = [0u8; V3_BARE_HEADER_SIZE as usize + size_of::<u64>()];
        f.read_exact_at(&mut buf, 0).map_err(Error::ReadingHeader)?;

        // `buf` is always larger than the views, and the views are unaligned,
        // so the casts cannot fail.
        let (v2, tail) = RawHeaderV2::ref_from_prefix(&buf).expect("buffer covers the v2 header");

        let magic = v2.magic.get();
        if magic != QCOW_MAGIC {
            return Err(Error::InvalidMagic);
        }
        let version = v2.version.get();

        let mut header = QcowHeader {
            magic,
            version,
            backing_file_offset: v2.backing_file_offset.get(),
            backing_file_size: v2.backing_file_size.get(),
            cluster_bits: v2.cluster_bits.get(),
            size: v2.size.get(),
            crypt_method: v2.crypt_method.get(),
            l1_size: v2.l1_size.get(),
            l1_table_offset: v2.l1_table_offset.get(),
            refcount_table_offset: v2.refcount_table_offset.get(),
            refcount_table_clusters: v2.refcount_table_clusters.get(),
            nb_snapshots: v2.nb_snapshots.get(),
            snapshots_offset: v2.snapshots_offset.get(),
            incompatible_features: 0,
            compatible_features: 0,
            autoclear_features: 0,
            refcount_order: DEFAULT_REFCOUNT_ORDER,
            header_size: V2_BARE_HEADER_SIZE,
            compression_type: CompressionType::Zlib,
            backing_file: None,
        };

        if version != 2 {
            let (v3, rest) =
                RawHeaderV3Tail::ref_from_prefix(tail).expect("buffer covers the v3 header");
            header.incompatible_features = v3.incompatible_features.get();
            header.compatible_features = v3.compatible_features.get();
            header.autoclear_features = v3.autoclear_features.get();
            header.refcount_order = v3.refcount_order.get();
            header.header_size = v3.header_size.get();

            if version == 3 && header.header_size > V3_BARE_HEADER_SIZE {
                let (compression, _) =
                    BeU64::ref_from_prefix(rest).expect("buffer covers the compression field");
                let raw_compression_type = compression.get() >> (64 - 8);
                header.compression_type = if raw_compression_type == COMPRESSION_TYPE_ZLIB {
                    Ok(CompressionType::Zlib)
                } else if raw_compression_type == COMPRESSION_TYPE_ZSTD {
                    Ok(CompressionType::Zstd)
                } else {
                    Err(Error::UnsupportedCompressionType)
                }?;
            }
        }
        if header.backing_file_size > MAX_BACKING_FILE_SIZE {
            return Err(Error::BackingFileTooLong(header.backing_file_size as usize));
        }
        if header.backing_file_offset == 0 && header.backing_file_size != 0 {
            return Err(Error::BackingFileSizeWithoutOffset(
                header.backing_file_size,
            ));
        }
        if header.backing_file_offset != 0 && header.backing_file_size == 0 {
            return Err(Error::BackingFileOffsetWithoutSize(
                header.backing_file_offset,
            ));
        }
        if header.backing_file_offset != 0 {
            let cluster_size = 1u64
                .checked_shl(header.cluster_bits)
                .ok_or(Error::InvalidClusterSize)?;
            if header.backing_file_offset < u64::from(header.header_size) {
                return Err(Error::BackingFileOverlapsHeader(
                    header.backing_file_offset,
                    header.backing_file_size,
                    header.header_size,
                ));
            }
            if header.backing_file_offset >= cluster_size
                || header.backing_file_offset + u64::from(header.backing_file_size) > cluster_size
            {
                return Err(Error::BackingFileOutsideFirstCluster(
                    header.backing_file_offset,
                    header.backing_file_size,
                    cluster_size,
                ));
            }
            let mut backing_file_name_bytes = vec![0u8; header.backing_file_size as usize];
            f.read_exact_at(&mut backing_file_name_bytes, header.backing_file_offset)
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

    /// Write the header to `f`.
    pub fn write_to(&self, f: &AlignedFile) -> Result<()> {
        // Build the header in memory, then write it in one positional write.
        let mut buf = Vec::new();
        let v2 = RawHeaderV2::from_header(self);
        buf.extend_from_slice(v2.as_bytes());

        if self.version == 3 {
            let v3 = RawHeaderV3Tail::from_header(self);
            buf.extend_from_slice(v3.as_bytes());

            if self.header_size > V3_BARE_HEADER_SIZE {
                let compression_type = match &self.compression_type {
                    CompressionType::Zlib => COMPRESSION_TYPE_ZLIB,
                    CompressionType::Zstd => COMPRESSION_TYPE_ZSTD,
                };
                let compression_type = BeU64::new(compression_type << (64 - 8));
                buf.extend_from_slice(compression_type.as_bytes());
            }

            let end_extension = ExtensionHeader::end();
            buf.extend_from_slice(end_extension.as_bytes());
        }

        f.write_all_at(&buf, 0).map_err(Error::WritingHeader)?;

        if let Some(backing_file_path) = self.backing_file.as_ref().map(|bf| &bf.path) {
            let offset = if self.backing_file_offset > 0 {
                self.backing_file_offset
            } else {
                buf.len() as u64
            };
            f.write_all_at(backing_file_path.as_bytes(), offset)
                .map_err(Error::WritingHeader)?;
        }

        // Set the file length by writing a zero to the last byte. This also
        // zeros the l1 and refcount table clusters.
        let cluster_size = 0x01u64 << self.cluster_bits;
        let refcount_blocks_size = u64::from(self.refcount_table_clusters) * cluster_size;
        f.write_all_at(
            &[0u8],
            self.refcount_table_offset + refcount_blocks_size - 2,
        )
        .map_err(Error::WritingHeader)?;

        Ok(())
    }

    /// Write only the incompatible_features field to the file at its fixed offset.
    fn write_incompatible_features(&self, file: &AlignedFile) -> BlockResult<()> {
        if self.version != 3 {
            return Ok(());
        }
        file.write_all_at(
            &self.incompatible_features.to_be_bytes(),
            V2_BARE_HEADER_SIZE as u64,
        )
        .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::WritingHeader(e)))?;
        Ok(())
    }

    /// Set or clear the dirty bit for QCOW2 v3 images.
    ///
    /// When `dirty` is true, sets the bit to indicate the image is in use.
    /// When `dirty` is false, clears the bit to indicate a clean shutdown.
    pub fn set_dirty_bit(&mut self, file: &mut AlignedFile, dirty: bool) -> BlockResult<()> {
        if self.version == 3 {
            if dirty {
                self.incompatible_features |= IncompatFeatures::DIRTY.bits();
            } else {
                self.incompatible_features &= !IncompatFeatures::DIRTY.bits();
            }
            self.write_incompatible_features(file)?;
            file.fsync()
                .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::SyncingHeader(e)))?;
        }
        Ok(())
    }

    /// Set the corrupt bit for QCOW2 v3 images.
    ///
    /// This marks the image as corrupted. Once set, the image can only be
    /// opened read-only until repaired.
    pub fn set_corrupt_bit(&mut self, file: &mut AlignedFile) -> BlockResult<()> {
        if self.version == 3 {
            self.incompatible_features |= IncompatFeatures::CORRUPT.bits();
            self.write_incompatible_features(file)?;
            file.fsync()
                .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::SyncingHeader(e)))?;
        }
        Ok(())
    }

    pub fn is_corrupt(&self) -> bool {
        IncompatFeatures::from_bits_truncate(self.incompatible_features)
            .contains(IncompatFeatures::CORRUPT)
    }

    /// Clear all autoclear feature bits for QCOW2 v3 images.
    ///
    /// These bits indicate features that can be safely disabled when modified
    /// by software that doesn't understand them.
    pub fn clear_autoclear_features(&mut self, file: &mut AlignedFile) -> Result<()> {
        if self.version == 3 && self.autoclear_features != 0 {
            self.autoclear_features = 0;
            file.write_all_at(&0u64.to_be_bytes(), AUTOCLEAR_FEATURES_OFFSET)
                .map_err(Error::WritingHeader)?;
            file.fsync().map_err(Error::SyncingHeader)?;
        }
        Ok(())
    }
}

pub(super) fn max_refcount_clusters(
    refcount_order: u32,
    cluster_size: u32,
    num_clusters: u32,
) -> u64 {
    // Use u64 as the product of the u32 inputs can overflow.
    let refcount_bits = 0x01u64 << u64::from(refcount_order);
    let cluster_bits = u64::from(cluster_size) * 8;
    let for_data = div_round_up_u64(u64::from(num_clusters) * refcount_bits, cluster_bits);
    let for_refcounts = div_round_up_u64(for_data * refcount_bits, cluster_bits);
    for_data + for_refcounts
}

/// Returns an Error if the given offset doesn't align to a cluster boundary.
pub(super) fn offset_is_cluster_boundary(offset: u64, cluster_bits: u32) -> Result<()> {
    if offset & ((0x01 << cluster_bits) - 1) != 0 {
        return Err(Error::InvalidOffset(offset));
    }
    Ok(())
}
