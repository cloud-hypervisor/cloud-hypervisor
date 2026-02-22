// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

//! QCOW2 header parsing, validation, and creation.

use std::fmt::{Display, Formatter, Result as FmtResult};
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem::size_of;
use std::str::FromStr;

use bitflags::bitflags;
use vmm_sys_util::file_traits::FileSync;

use super::decoder::{Decoder, ZlibDecoder, ZstdDecoder};
use super::qcow_raw_file::BeUint;
use super::raw_file::RawFile;
use super::{Error, Result, div_round_up_u32, div_round_up_u64};

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

impl QcowHeader {
    /// Read header extensions, optionally collecting feature names for error reporting.
    pub(super) fn read_header_extensions(
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
            file.fsync().map_err(Error::SyncingHeader)?;
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
            file.fsync().map_err(Error::SyncingHeader)?;
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
    pub fn clear_autoclear_features<F: Seek + Write + FileSync>(
        &mut self,
        file: &mut F,
    ) -> Result<()> {
        if self.version == 3 && self.autoclear_features != 0 {
            self.autoclear_features = 0;
            file.seek(SeekFrom::Start(AUTOCLEAR_FEATURES_OFFSET))
                .map_err(Error::WritingHeader)?;
            u64::write_be(file, 0).map_err(Error::WritingHeader)?;
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
