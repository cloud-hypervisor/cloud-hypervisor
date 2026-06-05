// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

pub(crate) mod backing;
pub(crate) mod decoder;
mod header;
pub(crate) mod metadata;
pub(crate) mod qcow_raw_file;
mod raw_file;
mod refcount;
mod util;
mod vec_cache;

use std::cmp::{max, min};
use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::fs::{OpenOptions, read_link};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::mem::size_of;
use std::os::fd::{AsRawFd, RawFd};
use std::path::Path;
use std::str;

#[cfg(test)]
use header::{
    AUTOCLEAR_FEATURES_OFFSET, DEFAULT_REFCOUNT_ORDER, HEADER_EXT_BACKING_FORMAT, HEADER_EXT_END,
    V2_BARE_HEADER_SIZE, V3_BARE_HEADER_SIZE,
};
pub use header::{
    BackingFileConfig, CompressionType, ImageType, IncompatFeatures, MissingFeatureError,
    QcowHeader,
};
use header::{
    COMPATIBLE_FEATURES_LAZY_REFCOUNTS, MAX_CLUSTER_BITS, MAX_QCOW_FILE_SIZE,
    MAX_RAM_POINTER_TABLE_SIZE, MIN_CLUSTER_BITS, QCOW_MAGIC, max_refcount_clusters,
    offset_is_cluster_boundary,
};
use libc::{EINVAL, EIO, ENOSPC};
use log::{error, warn};
use metadata::ClusterReadMapping;
use qcow_raw_file::{BeUint, QcowRawFile};
pub use raw_file::RawFile;
use refcount::RefCount;
use remain::sorted;
use thiserror::Error;
pub(crate) use util::MAX_NESTING_DEPTH;
use util::{
    L1_TABLE_OFFSET_MASK, L2_TABLE_OFFSET_MASK, div_round_up_u32, div_round_up_u64, l1_entry_make,
    l2_entry_compressed_cluster_layout, l2_entry_is_compressed, l2_entry_is_empty,
    l2_entry_is_zero, l2_entry_make_std, l2_entry_make_zero, l2_entry_make_zero_plain,
    l2_entry_std_cluster_addr,
};
use vec_cache::{CacheMap, Cacheable, VecCache};
use vmm_sys_util::file_traits::{FileSetLen, FileSync};
use vmm_sys_util::seek_hole::SeekHole;
use vmm_sys_util::write_zeroes::{PunchHole, WriteZeroesAt};

use super::common::decompress_cluster;
use crate::BlockBackend;
use crate::error::{BlockError, BlockErrorKind, BlockResult};

#[sorted]
#[derive(Debug, Error)]
pub enum Error {
    #[error("Backing file I/O error: {0}")]
    BackingFileIo(String /* path */, #[source] io::Error),
    #[error("Backing file offset {0:#x} with zero size")]
    BackingFileOffsetWithoutSize(u64),
    #[error("Backing file open error: {0}")]
    BackingFileOpen(String /* path */, #[source] Box<Error>),
    #[error(
        "Backing file name at offset {0:#x} length {1:#x} lies outside first cluster of {2:#x}"
    )]
    BackingFileOutsideFirstCluster(u64, u32, u64),
    #[error("Backing file name at offset {0:#x} length {1:#x} overlaps header of size {2:#x}")]
    BackingFileOverlapsHeader(u64, u32, u32),
    #[error("Backing file size {0:#x} with zero offset")]
    BackingFileSizeWithoutOffset(u32),
    #[error("Backing file support is disabled")]
    BackingFilesDisabled,
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
    #[error("Failed to resize")]
    ResizeIo(#[source] io::Error),
    #[error("Resize not supported with backing file")]
    ResizeWithBackingFile,
    #[error("Failed to seek file")]
    SeekingFile(#[source] io::Error),
    #[error("Failed to set file size")]
    SettingFileSize(#[source] io::Error),
    #[error("Failed to set refcount refcount")]
    SettingRefcountRefcount(#[source] io::Error),
    #[error("Shrinking QCOW images is not supported")]
    ShrinkNotSupported,
    #[error("Size too small for number of clusters")]
    SizeTooSmallForNumberOfClusters,
    #[error("Failed to sync header")]
    SyncingHeader(#[source] io::Error),
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

/// Concrete backing file variants.
pub(crate) enum BackingKind {
    /// Raw backing file.
    Raw(RawFile),
    /// QCOW2 backing parsed into metadata and raw file.
    Qcow {
        inner: Box<metadata::QcowState>,
        backing: Option<Box<BackingFile>>,
    },
    /// Full QcowFile used as backing, only in tests.
    #[cfg(test)]
    QcowFile(Box<QcowFile>),
}
/// Backing file wrapper
pub(crate) struct BackingFile {
    kind: BackingKind,
    virtual_size: u64,
}

impl BackingFile {
    fn new(
        backing_file_config: Option<&BackingFileConfig>,
        direct_io: bool,
        max_nesting_depth: u32,
        sparse: bool,
    ) -> BlockResult<Option<Self>> {
        let Some(config) = backing_file_config else {
            return Ok(None);
        };

        // Check nesting depth - applies to any backing file
        if max_nesting_depth == 0 {
            return Err(BlockError::new(
                BlockErrorKind::Overflow,
                Error::MaxNestingDepthExceeded,
            ));
        }

        let backing_raw_file = OpenOptions::new()
            .read(true)
            .open(&config.path)
            .map_err(|e| {
                BlockError::new(
                    BlockErrorKind::Io,
                    Error::BackingFileIo(config.path.clone(), e),
                )
            })?;

        let mut raw_file = RawFile::new(backing_raw_file, direct_io);

        // Determine backing file format from header extension or auto-detect
        let backing_format = match config.format {
            Some(format) => format,
            None => detect_image_type(&mut raw_file)?,
        };

        let (kind, virtual_size) = match backing_format {
            ImageType::Raw => {
                let size = raw_file.seek(SeekFrom::End(0)).map_err(|e| {
                    BlockError::new(
                        BlockErrorKind::Io,
                        Error::BackingFileIo(config.path.clone(), e),
                    )
                })?;
                raw_file.rewind().map_err(|e| {
                    BlockError::new(
                        BlockErrorKind::Io,
                        Error::BackingFileIo(config.path.clone(), e),
                    )
                })?;
                (BackingKind::Raw(raw_file), size)
            }
            ImageType::Qcow2 => {
                let (inner, nested_backing, _sparse) =
                    parse_qcow(raw_file, max_nesting_depth - 1, sparse).map_err(|e| {
                        let kind = e.kind();
                        let source = e
                            .into_source()
                            .and_then(|s| s.downcast::<Error>().ok())
                            .map(|qcow_err| Error::BackingFileOpen(config.path.clone(), qcow_err));
                        match source {
                            Some(err) => BlockError::new(kind, err),
                            None => BlockError::from_kind(kind),
                        }
                    })?;
                let size = inner.header.size;
                (
                    BackingKind::Qcow {
                        inner: Box::new(inner),
                        backing: nested_backing.map(Box::new),
                    },
                    size,
                )
            }
        };

        Ok(Some(Self { kind, virtual_size }))
    }

    /// Consume and return the kind and virtual size.
    pub(crate) fn into_kind(self) -> (BackingKind, u64) {
        (self.kind, self.virtual_size)
    }

    /// Read from backing file, returning zeros for any portion beyond backing file size.
    #[inline]
    pub(crate) fn read_at(&mut self, address: u64, buf: &mut [u8]) -> std::io::Result<()> {
        if address >= self.virtual_size {
            buf.fill(0);
            return Ok(());
        }

        let available = (self.virtual_size - address) as usize;
        let (target, overflow) = if available >= buf.len() {
            (buf, &mut [][..])
        } else {
            buf.split_at_mut(available)
        };
        Self::read_at_inner(&mut self.kind, address, target)?;
        overflow.fill(0);
        Ok(())
    }

    fn read_at_inner(kind: &mut BackingKind, address: u64, buf: &mut [u8]) -> std::io::Result<()> {
        match kind {
            BackingKind::Raw(file) => {
                file.seek(SeekFrom::Start(address))?;
                file.read_exact(buf)
            }
            #[cfg(test)]
            BackingKind::QcowFile(qcow) => {
                qcow.seek(SeekFrom::Start(address))?;
                qcow.read_exact(buf)
            }
            BackingKind::Qcow { inner, backing } => {
                let has_backing = backing.is_some();
                let cluster_size = inner.raw_file.cluster_size();
                let mut pos = 0usize;
                while pos < buf.len() {
                    let curr_addr = address + pos as u64;
                    let intra = inner.raw_file.cluster_offset(curr_addr) as usize;
                    let count = min(buf.len() - pos, cluster_size as usize - intra);
                    let mapping = inner.map_cluster_read(curr_addr, count, has_backing)?;
                    match mapping {
                        ClusterReadMapping::Zero { length } => {
                            buf[pos..pos + length as usize].fill(0);
                        }
                        ClusterReadMapping::Allocated {
                            offset: host_off,
                            length,
                        } => {
                            inner.raw_file.file_mut().seek(SeekFrom::Start(host_off))?;
                            inner
                                .raw_file
                                .file_mut()
                                .read_exact(&mut buf[pos..pos + length as usize])?;
                        }
                        ClusterReadMapping::Compressed {
                            host_offset,
                            compressed_size,
                            cluster_offset,
                            length,
                        } => {
                            let mut compressed = vec![0u8; compressed_size];
                            inner
                                .raw_file
                                .file_mut()
                                .seek(SeekFrom::Start(host_offset))?;
                            inner.raw_file.file_mut().read_exact(&mut compressed)?;
                            let decompressed = decompress_cluster(
                                &compressed,
                                cluster_size as usize,
                                &*inner.header.get_decoder(),
                            )?;
                            buf[pos..pos + length].copy_from_slice(
                                &decompressed[cluster_offset..cluster_offset + length],
                            );
                        }
                        ClusterReadMapping::Backing {
                            offset: backing_off,
                            length,
                        } => {
                            if let Some(bf) = backing.as_mut() {
                                bf.read_at(backing_off, &mut buf[pos..pos + length as usize])?;
                            } else {
                                buf[pos..pos + length as usize].fill(0);
                            }
                        }
                    }
                    pos += count;
                }
                Ok(())
            }
        }
    }
}

impl Debug for BackingFile {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("BackingFile").finish()
    }
}

/// Parses and validates a QCOW2 image file, returning the metadata, backing
/// file and sparse flag.
///
/// Used by [`QcowFile`] and [`QcowDisk`] constructors.
pub(crate) fn parse_qcow(
    mut file: RawFile,
    max_nesting_depth: u32,
    sparse: bool,
) -> BlockResult<(metadata::QcowState, Option<BackingFile>, bool)> {
    let mut header = QcowHeader::new(&mut file).map_err(|e| {
        let kind = match &e {
            Error::InvalidMagic
            | Error::BackingFileTooLong(_)
            | Error::InvalidBackingFileName(_) => BlockErrorKind::InvalidFormat,
            Error::UnsupportedFeature(_) | Error::UnsupportedCompressionType => {
                BlockErrorKind::UnsupportedFeature
            }
            _ => BlockErrorKind::Io,
        };
        BlockError::new(kind, e)
    })?;

    // Only v2 and v3 files are supported.
    if header.version != 2 && header.version != 3 {
        return Err(BlockError::new(
            BlockErrorKind::UnsupportedFeature,
            Error::UnsupportedVersion(header.version),
        ));
    }

    // Make sure that the L1 table fits in RAM.
    if u64::from(header.l1_size) > MAX_RAM_POINTER_TABLE_SIZE {
        return Err(BlockError::new(
            BlockErrorKind::InvalidFormat,
            Error::InvalidL1TableSize(header.l1_size),
        ));
    }

    let cluster_bits: u32 = header.cluster_bits;
    if !(MIN_CLUSTER_BITS..=MAX_CLUSTER_BITS).contains(&cluster_bits) {
        return Err(BlockError::new(
            BlockErrorKind::InvalidFormat,
            Error::InvalidClusterSize,
        ));
    }
    let cluster_size = 0x01u64 << cluster_bits;

    // Limit the total size of the disk.
    if header.size > MAX_QCOW_FILE_SIZE {
        return Err(BlockError::new(
            BlockErrorKind::InvalidFormat,
            Error::FileTooBig(header.size),
        ));
    }

    let direct_io = file.is_direct();
    // QCOW2 relative backing paths are resolved from the image that stores
    // them. Resolve only the config passed to BackingFile::new(), leaving the
    // header copy unchanged so the original backing filename is preserved.
    let backing_file_config = header.backing_file.as_ref().map(|config| {
        let mut config = config.clone();
        if !Path::new(&config.path).is_absolute()
            && let Ok(disk_path) = read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
            && disk_path.exists()
            && let Some(parent) = disk_path.parent()
        {
            config.path = parent.join(&config.path).to_string_lossy().into_owned();
        }
        config
    });

    let backing_file = BackingFile::new(
        backing_file_config.as_ref(),
        direct_io,
        max_nesting_depth,
        sparse,
    )?;

    // Validate refcount order to be 0..6
    let refcount_bits: u64 = 0x01u64.checked_shl(header.refcount_order).ok_or_else(|| {
        BlockError::new(
            BlockErrorKind::UnsupportedFeature,
            Error::UnsupportedRefcountOrder,
        )
    })?;
    if refcount_bits > 64 {
        return Err(BlockError::new(
            BlockErrorKind::UnsupportedFeature,
            Error::UnsupportedRefcountOrder,
        ));
    }

    // Need at least one refcount cluster
    if header.refcount_table_clusters == 0 {
        return Err(BlockError::new(
            BlockErrorKind::InvalidFormat,
            Error::NoRefcountClusters,
        ));
    }
    offset_is_cluster_boundary(header.l1_table_offset, header.cluster_bits)
        .map_err(|e| BlockError::new(BlockErrorKind::CorruptImage, e))?;
    offset_is_cluster_boundary(header.snapshots_offset, header.cluster_bits)
        .map_err(|e| BlockError::new(BlockErrorKind::CorruptImage, e))?;
    // refcount table must be a cluster boundary, and within the file's virtual or actual size.
    offset_is_cluster_boundary(header.refcount_table_offset, header.cluster_bits)
        .map_err(|e| BlockError::new(BlockErrorKind::CorruptImage, e))?;
    let file_size = file
        .metadata()
        .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::GettingFileSize(e)))?
        .len();
    if header.refcount_table_offset > max(file_size, header.size) {
        return Err(BlockError::new(
            BlockErrorKind::CorruptImage,
            Error::RefcountTableOffEnd,
        ));
    }

    // The first cluster should always have a non-zero refcount, so if it is 0,
    // this is an old file with broken refcounts, which requires a rebuild.
    let mut refcount_rebuild_required = true;
    file.seek(SeekFrom::Start(header.refcount_table_offset))
        .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::SeekingFile(e)))?;
    let first_refblock_addr = u64::read_be(&mut file)
        .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::ReadingHeader(e)))?;
    if first_refblock_addr != 0 {
        file.seek(SeekFrom::Start(first_refblock_addr))
            .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::SeekingFile(e)))?;
        let first_cluster_refcount = u16::read_be(&mut file)
            .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::ReadingHeader(e)))?;
        if first_cluster_refcount != 0 {
            refcount_rebuild_required = false;
        }
    }

    if (header.compatible_features & COMPATIBLE_FEATURES_LAZY_REFCOUNTS) != 0 {
        refcount_rebuild_required = true;
    }

    let mut raw_file = QcowRawFile::from(file, cluster_size, refcount_bits)
        .ok_or_else(|| BlockError::new(BlockErrorKind::InvalidFormat, Error::InvalidClusterSize))?;
    let is_writable = raw_file.file().is_writable();

    if header.is_corrupt() {
        if is_writable {
            return Err(BlockError::new(
                BlockErrorKind::CorruptImage,
                Error::CorruptImage,
            ));
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
        return Err(BlockError::new(
            BlockErrorKind::CorruptImage,
            Error::TooManyL1Entries(num_l2_clusters),
        ));
    }
    let l1_table = VecCache::from_vec(
        raw_file
            .read_pointer_table(
                header.l1_table_offset,
                num_l2_clusters,
                Some(L1_TABLE_OFFSET_MASK),
            )
            .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::ReadingHeader(e)))?,
    );

    let num_clusters = div_round_up_u64(header.size, cluster_size);
    let refcount_clusters = max_refcount_clusters(
        header.refcount_order,
        cluster_size as u32,
        (num_clusters + l1_clusters + num_l2_clusters + header_clusters) as u32,
    );
    // Check that the given header doesn't have a suspiciously sized refcount table.
    if u64::from(header.refcount_table_clusters) > 2 * refcount_clusters {
        return Err(BlockError::new(
            BlockErrorKind::CorruptImage,
            Error::RefcountTableTooLarge,
        ));
    }
    if l1_clusters + refcount_clusters > MAX_RAM_POINTER_TABLE_SIZE {
        return Err(BlockError::new(
            BlockErrorKind::InvalidFormat,
            Error::TooManyRefcounts(refcount_clusters),
        ));
    }
    let refcount_block_entries = cluster_size * 8 / refcount_bits;
    let mut refcounts = RefCount::new(
        &mut raw_file,
        header.refcount_table_offset,
        refcount_clusters,
        refcount_block_entries,
        cluster_size,
        refcount_bits,
    )
    .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::ReadingRefCounts(e)))?;

    let l2_entries = cluster_size / size_of::<u64>() as u64;

    // Check that the L1 and refcount tables fit in a 64bit address space.
    let l1_index = (header.size / cluster_size) / l2_entries;
    header
        .l1_table_offset
        .checked_add(l1_index * size_of::<u64>() as u64)
        .ok_or_else(|| {
            BlockError::new(BlockErrorKind::CorruptImage, Error::InvalidL1TableOffset)
        })?;
    header
        .refcount_table_offset
        .checked_add(u64::from(header.refcount_table_clusters) * cluster_size)
        .ok_or_else(|| {
            BlockError::new(
                BlockErrorKind::CorruptImage,
                Error::InvalidRefcountTableOffset,
            )
        })?;

    // Find available (refcount == 0) clusters for the free list.
    let file_size = raw_file
        .file_mut()
        .metadata()
        .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::GettingFileSize(e)))?
        .len();
    let mut avail_clusters = Vec::new();
    for i in (0..file_size).step_by(cluster_size as usize) {
        let refcount = refcounts
            .get_cluster_refcount(&mut raw_file, i)
            .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::GettingRefcount(e)))?;
        if refcount == 0 {
            avail_clusters.push(i);
        }
    }

    if is_writable {
        if !IncompatFeatures::from_bits_truncate(header.incompatible_features)
            .contains(IncompatFeatures::DIRTY)
        {
            header
                .set_dirty_bit(raw_file.file_mut(), true)
                .map_err(|e| {
                    BlockError::new(
                        BlockErrorKind::Io,
                        Error::WritingHeader(io::Error::other(e)),
                    )
                })?;
        }

        header
            .clear_autoclear_features(raw_file.file_mut())
            .map_err(|e| BlockError::new(BlockErrorKind::Io, e))?;
    }

    let inner = metadata::QcowState {
        raw_file,
        header,
        l1_table,
        l2_entries,
        l2_cache: CacheMap::new(100),
        refcounts,
        avail_clusters,
        unref_clusters: Vec::new(),
    };

    Ok((inner, backing_file, sparse))
}

/// Represents a qcow2 file. This is a sparse file format maintained by the qemu project.
/// Full documentation of the format can be found in the qemu repository.
///
/// # Example
///
/// ```
/// # use block::formats::qcow::internal::{QcowFile, RawFile};
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
#[derive(Debug)]
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
    sparse: bool,
}

impl QcowFile {
    /// Creates a QcowFile from `file`. File must be a valid qcow2 image.
    ///
    /// Additionally, max nesting depth of this qcow2 image will be set to default value 10.
    pub fn from(file: RawFile) -> BlockResult<QcowFile> {
        Self::from_with_nesting_depth(file, MAX_NESTING_DEPTH, true)
    }

    /// Creates a QcowFile from `file` and with a max nesting depth. File must be a valid qcow2
    /// image.
    pub fn from_with_nesting_depth(
        file: RawFile,
        max_nesting_depth: u32,
        sparse: bool,
    ) -> BlockResult<QcowFile> {
        let (inner, backing_file, sparse) = parse_qcow(file, max_nesting_depth, sparse)?;
        let metadata::QcowState {
            raw_file,
            header,
            l1_table,
            l2_entries,
            l2_cache,
            refcounts,
            avail_clusters,
            unref_clusters,
        } = inner;
        Ok(QcowFile {
            raw_file,
            header,
            l1_table,
            l2_entries,
            l2_cache,
            refcounts,
            current_offset: 0,
            unref_clusters,
            avail_clusters,
            backing_file,
            sparse,
        })
    }

    /// Creates a new QcowFile at the given path.
    pub fn new(
        file: RawFile,
        version: u32,
        virtual_size: u64,
        sparse: bool,
    ) -> BlockResult<QcowFile> {
        let header =
            QcowHeader::create_for_size_and_path(version, virtual_size, None).map_err(|e| {
                let kind = match &e {
                    Error::BackingFileTooLong(_) => BlockErrorKind::InvalidFormat,
                    _ => BlockErrorKind::Io,
                };
                BlockError::new(kind, e)
            })?;
        QcowFile::new_from_header(file, &header, sparse)
    }

    /// Creates a new QcowFile at the given path with a backing file.
    pub fn new_from_backing(
        file: RawFile,
        version: u32,
        backing_file_size: u64,
        backing_config: &BackingFileConfig,
        sparse: bool,
    ) -> BlockResult<QcowFile> {
        let mut header = QcowHeader::create_for_size_and_path(
            version,
            backing_file_size,
            Some(&backing_config.path),
        )
        .map_err(|e| {
            let kind = match &e {
                Error::BackingFileTooLong(_) => BlockErrorKind::InvalidFormat,
                _ => BlockErrorKind::Io,
            };
            BlockError::new(kind, e)
        })?;
        if let Some(backing_file) = &mut header.backing_file {
            backing_file.format = backing_config.format;
        }
        QcowFile::new_from_header(file, &header, sparse)
        // backing_file is loaded by new_from_header -> Self::from() based on the header
    }

    fn new_from_header(
        mut file: RawFile,
        header: &QcowHeader,
        sparse: bool,
    ) -> BlockResult<QcowFile> {
        file.rewind()
            .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::SeekingFile(e)))?;
        header
            .write_to(&mut file)
            .map_err(|e| BlockError::new(BlockErrorKind::Io, e))?;

        let mut qcow = Self::from_with_nesting_depth(file, MAX_NESTING_DEPTH, sparse)?;

        // Set the refcount for each refcount table cluster.
        let cluster_size = 0x01u64 << qcow.header.cluster_bits;
        let refcount_table_base = qcow.header.refcount_table_offset;
        let end_cluster_addr =
            refcount_table_base + u64::from(qcow.header.refcount_table_clusters) * cluster_size;

        let mut cluster_addr = 0;
        while cluster_addr < end_cluster_addr {
            let mut unref_clusters = qcow.set_cluster_refcount(cluster_addr, 1).map_err(|e| {
                BlockError::new(BlockErrorKind::Io, Error::SettingRefcountRefcount(e))
            })?;
            qcow.unref_clusters.append(&mut unref_clusters);
            cluster_addr += cluster_size;
        }

        Ok(qcow)
    }

    #[cfg(test)]
    pub fn set_backing_file(&mut self, backing: Option<Box<Self>>) {
        self.backing_file = backing.map(|b| {
            let virtual_size = b.virtual_size();
            BackingFile {
                kind: BackingKind::QcowFile(b),
                virtual_size,
            }
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
    pub fn l2_table(&mut self, l1_index: usize) -> BlockResult<Option<&[u64]>> {
        let l2_addr_disk = *self
            .l1_table
            .get(l1_index)
            .ok_or_else(|| BlockError::new(BlockErrorKind::OutOfBounds, Error::InvalidIndex))?;

        if l2_addr_disk == 0 {
            // Reading from an unallocated cluster will return zeros.
            return Ok(None);
        }

        if !self.l2_cache.contains_key(l1_index) {
            // Not in the cache.
            let table = VecCache::from_vec(
                Self::read_l2_cluster(&mut self.raw_file, l2_addr_disk)
                    .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::ReadingPointers(e)))?,
            );
            let l1_table = &self.l1_table;
            let raw_file = &mut self.raw_file;
            self.l2_cache
                .insert(l1_index, table, |index, evicted| {
                    raw_file.write_pointer_table_direct(l1_table[index], evicted.iter())
                })
                .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::EvictingCache(e)))?;
        }

        // The index must exist as it was just inserted if it didn't already.
        Ok(Some(self.l2_cache.get(l1_index).unwrap().get_values()))
    }

    /// Returns the refcount table for this file. This is only useful for debugging.
    pub fn ref_table(&self) -> &[u64] {
        self.refcounts.ref_table()
    }

    /// Returns the `index`th refcount block from the file.
    pub fn refcount_block(&mut self, index: usize) -> BlockResult<Option<&[u64]>> {
        self.refcounts
            .refcount_block(&mut self.raw_file, index)
            .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::ReadingRefCountBlock(e)))
    }

    /// Returns the first cluster in the file with a 0 refcount. Used for testing.
    pub fn first_zero_refcount(&mut self) -> BlockResult<Option<u64>> {
        let file_size = self
            .raw_file
            .file_mut()
            .metadata()
            .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::GettingFileSize(e)))?
            .len();
        let cluster_size = 0x01u64 << self.header.cluster_bits;

        let mut cluster_addr = 0;
        while cluster_addr < file_size {
            let cluster_refcount = self
                .refcounts
                .get_cluster_refcount(&mut self.raw_file, cluster_addr)
                .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::GettingRefcount(e)))?;
            if cluster_refcount == 0 {
                return Ok(Some(cluster_addr));
            }
            cluster_addr += cluster_size;
        }
        Ok(None)
    }

    /// Resize the virtual size of the QCOW2 image.
    ///
    /// This supports growing the image, including growing the L1 table
    /// if needed. Shrinking is not supported, as it could lead to data
    /// loss. Not supported when a backing file is present in that case
    /// an error is returned.
    pub fn resize(&mut self, new_size: u64) -> BlockResult<()> {
        let current_size = self.virtual_size();

        if new_size == current_size {
            return Ok(());
        }

        if new_size < current_size {
            return Err(BlockError::new(
                BlockErrorKind::UnsupportedFeature,
                Error::ShrinkNotSupported,
            ));
        }

        if self.backing_file.is_some() {
            return Err(BlockError::new(
                BlockErrorKind::UnsupportedFeature,
                Error::ResizeWithBackingFile,
            ));
        }

        // Grow the L1 table if needed
        let cluster_size = self.raw_file.cluster_size();
        let entries_per_cluster = cluster_size / size_of::<u64>() as u64;
        let new_clusters = div_round_up_u64(new_size, cluster_size);
        let needed_l1_entries = div_round_up_u64(new_clusters, entries_per_cluster) as u32;

        if needed_l1_entries > self.header.l1_size {
            self.grow_l1_table(needed_l1_entries)?;
        }

        self.header.size = new_size;

        self.raw_file
            .file_mut()
            .rewind()
            .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::SeekingFile(e)))?;
        self.header
            .write_to(self.raw_file.file_mut())
            .map_err(|e| match e {
                Error::WritingHeader(io_err) => {
                    BlockError::new(BlockErrorKind::Io, Error::ResizeIo(io_err))
                }
                other => BlockError::new(BlockErrorKind::Io, other),
            })?;

        self.raw_file
            .file_mut()
            .sync_all()
            .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::SyncingHeader(e)))?;

        Ok(())
    }

    /// Grow the L1 table to accommodate at least `new_l1_size` entries.
    ///
    /// This allocates a new L1 table at file end (guaranteeing contiguity),
    /// copies existing entries, updates refcounts, and atomically switches
    /// to the new table.
    fn grow_l1_table(&mut self, new_l1_size: u32) -> BlockResult<()> {
        let old_l1_size = self.header.l1_size;
        let old_l1_offset = self.header.l1_table_offset;
        let cluster_size = self.raw_file.cluster_size();

        let new_l1_bytes = new_l1_size as u64 * size_of::<u64>() as u64;
        let new_l1_clusters = div_round_up_u64(new_l1_bytes, cluster_size);

        // Allocate contiguous clusters at file end for new L1 table
        let file_size = self
            .raw_file
            .file_mut()
            .seek(SeekFrom::End(0))
            .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::ResizeIo(e)))?;
        let new_l1_offset = self.raw_file.cluster_address(file_size + cluster_size - 1);

        // Extend file to fit all L1 clusters
        let new_file_end = new_l1_offset + new_l1_clusters * cluster_size;
        self.raw_file
            .file_mut()
            .set_len(new_file_end)
            .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::SettingFileSize(e)))?;

        // Set refcounts for the contiguous range
        for i in 0..new_l1_clusters {
            self.set_cluster_refcount(new_l1_offset + i * cluster_size, 1)
                .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::ResizeIo(e)))?;
        }

        let mut new_l1_data = vec![0u64; new_l1_size as usize];
        let old_entries = self.l1_table.get_values();
        new_l1_data[..old_entries.len()].copy_from_slice(old_entries);

        for (i, l2_addr) in new_l1_data.iter_mut().enumerate() {
            if *l2_addr != 0 && i < old_entries.len() {
                let refcount = self
                    .refcounts
                    .get_cluster_refcount(&mut self.raw_file, *l2_addr)
                    .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::GettingRefcount(e)))?;
                *l2_addr = l1_entry_make(*l2_addr, refcount == 1);
            }
        }

        // Write the new L1 table to the file.
        self.raw_file
            .write_pointer_table_direct(new_l1_offset, new_l1_data.iter())
            .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::ResizeIo(e)))?;

        self.raw_file
            .file_mut()
            .sync_all()
            .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::SyncingHeader(e)))?;

        self.header.l1_size = new_l1_size;
        self.header.l1_table_offset = new_l1_offset;

        self.raw_file
            .file_mut()
            .rewind()
            .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::SeekingFile(e)))?;
        self.header
            .write_to(self.raw_file.file_mut())
            .map_err(|e| BlockError::new(BlockErrorKind::Io, e))?;

        self.raw_file
            .file_mut()
            .sync_all()
            .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::SyncingHeader(e)))?;

        // Free old L1 table clusters
        let old_l1_bytes = old_l1_size as u64 * size_of::<u64>() as u64;
        let old_l1_clusters = div_round_up_u64(old_l1_bytes, cluster_size);
        for i in 0..old_l1_clusters {
            let cluster_addr = old_l1_offset + i * cluster_size;
            let _ = self.set_cluster_refcount(cluster_addr, 0);
        }

        // Update L1 table cache
        self.l1_table.extend(new_l1_size as usize);

        Ok(())
    }

    /// Rebuild the reference count tables.
    fn rebuild_refcounts(raw_file: &mut QcowRawFile, header: QcowHeader) -> BlockResult<()> {
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
            .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::GettingFileSize(e)))?
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
            return Err(BlockError::new(
                BlockErrorKind::CorruptImage,
                Error::InvalidRefcountTableSize(max_valid_cluster_index),
            ));
        }

        let max_valid_cluster_offset = max_valid_cluster_index * cluster_size;
        if max_valid_cluster_offset < file_size - cluster_size {
            return Err(BlockError::new(
                BlockErrorKind::CorruptImage,
                Error::InvalidRefcountTableSize(max_valid_cluster_offset),
            ));
        }

        let mut refcounts = vec![0; max_valid_cluster_index as usize];

        // Find all references clusters and rebuild refcounts.
        set_header_refcount(&mut refcounts, cluster_size, max_refcount, refcount_bits)
            .map_err(|e| BlockError::new(BlockErrorKind::Io, e))?;
        set_l1_refcounts(
            &mut refcounts,
            &header,
            cluster_size,
            max_refcount,
            refcount_bits,
        )
        .map_err(|e| BlockError::new(BlockErrorKind::Io, e))?;
        set_data_refcounts(
            &mut refcounts,
            &header,
            cluster_size,
            raw_file,
            max_refcount,
            refcount_bits,
        )
        .map_err(|e| BlockError::new(BlockErrorKind::Io, e))?;
        set_refcount_table_refcounts(
            &mut refcounts,
            &header,
            cluster_size,
            max_refcount,
            refcount_bits,
        )
        .map_err(|e| BlockError::new(BlockErrorKind::Io, e))?;

        // Allocate clusters to store the new reference count blocks.
        let ref_table = alloc_refblocks(
            &mut refcounts,
            cluster_size,
            refblock_clusters,
            max_refcount,
            refcount_bits,
        )
        .map_err(|e| BlockError::new(BlockErrorKind::Io, e))?;

        // Write updated reference counts and point the reftable at them.
        write_refblocks(
            &refcounts,
            header,
            &ref_table,
            raw_file,
            refcount_block_entries,
        )
        .map_err(|e| BlockError::new(BlockErrorKind::Io, e))
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
            buf[..count].fill(0);
            return Ok(Some(()));
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
            self.deallocate_compressed_cluster(l2_entry)?;

            cluster_addr
        } else if l2_entry_is_empty(l2_entry) || l2_entry_is_zero(l2_entry) {
            let cluster_addr = if l2_entry_is_zero(l2_entry) {
                self.append_zeroed_data_cluster()?
            } else {
                let initial_data = if let Some(backing) = self.backing_file.as_mut() {
                    let cluster_size = self.raw_file.cluster_size();
                    let cluster_begin = address - (address % cluster_size);
                    let mut cluster_data = vec![0u8; cluster_size as usize];
                    backing.read_at(cluster_begin, &mut cluster_data)?;
                    Some(cluster_data)
                } else {
                    None
                };
                self.append_data_cluster(initial_data)?
            };
            // Need to allocate a data cluster
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

    // Allocate and initialize a zeroed data cluster without building a cluster-sized buffer.
    fn append_zeroed_data_cluster(&mut self) -> std::io::Result<u64> {
        let new_addr: u64 = self.get_new_cluster(None)?;
        let cluster_size = self.raw_file.cluster_size() as usize;
        self.raw_file
            .file_mut()
            .write_zeroes_at(new_addr, cluster_size)?;
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
            // Empty overlay metadata means "consult backing" when a backing
            // file exists; otherwise it is a hole in this image.
            return Ok(self.backing_file.is_some());
        }

        self.cache_l2_cluster(l1_index, l2_addr_disk, false)?;

        let l2_entry = self.l2_cache.get(l1_index).unwrap()[l2_index];
        if l2_entry_is_empty(l2_entry) {
            // Empty cluster with backing has existing data to seek in the backing file.
            Ok(self.backing_file.is_some())
        } else if l2_entry_is_compressed(l2_entry) {
            Ok(true)
        } else if l2_entry_is_zero(l2_entry) {
            // Zero flagged cluster is a logical hole. It reads as zeros with no data to seek.
            Ok(false)
        } else {
            Ok(true)
        }
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

    // Deallocate compressed cluster and all related clusters spanned by compressed data.
    fn deallocate_compressed_cluster(&mut self, l2_entry: u64) -> std::io::Result<()> {
        let (compressed_cluster_addr, compressed_cluster_size) =
            l2_entry_compressed_cluster_layout(l2_entry, self.header.cluster_bits);

        // Calculate the end of the compressed data region
        let compressed_clusters_end = self.raw_file.cluster_address(
            compressed_cluster_addr             // Start of compressed data
            + compressed_cluster_size as u64    // Add size to get end address
            + self.raw_file.cluster_size()
                - 1, // Catch possibly partially used last cluster
        );

        // Decrement refcount for each cluster spanned by the compressed data
        let mut addr = self.raw_file.cluster_address(compressed_cluster_addr);
        while addr < compressed_clusters_end {
            let refcount = self
                .refcounts
                .get_cluster_refcount(&mut self.raw_file, addr)
                .map_err(|e| {
                    if matches!(e, refcount::Error::RefblockUnaligned(_)) {
                        self.set_corrupt_bit_best_effort();
                    }
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("failed to get cluster refcount: {e}"),
                    )
                })?;
            if refcount > 0 {
                self.set_cluster_refcount_track_freed(addr, refcount - 1)?;
            }
            addr += self.raw_file.cluster_size();
        }

        Ok(())
    }

    // Deallocate the storage for the cluster starting at `address`.
    // If `zero_marker` is true, preserve WRITE_ZEROES semantics with a logical-zero
    // entry instead of allowing backing data to reappear through an empty entry.
    fn deallocate_cluster(&mut self, address: u64, zero_marker: bool) -> std::io::Result<()> {
        if address >= self.virtual_size() {
            return Err(std::io::Error::from_raw_os_error(EINVAL));
        }

        let l1_index = self.l1_table_index(address) as usize;
        let l2_addr_disk = *self
            .l1_table
            .get(l1_index)
            .ok_or_else(|| std::io::Error::from_raw_os_error(EINVAL))?;
        let l2_index = self.l2_table_index(address) as usize;
        let write_zero_marker = zero_marker && self.backing_file.is_some();
        let dealloc_entry = if write_zero_marker {
            l2_entry_make_zero_plain()
        } else {
            0
        };

        if l2_addr_disk == 0 {
            // With a backing file, an empty L2 entry means "consult backing".
            // WRITE_ZEROES needs a logical-zero marker instead.
            if write_zero_marker {
                if let Some(new_addr) = self.cache_l2_cluster(l1_index, l2_addr_disk, true)? {
                    self.set_cluster_refcount_track_freed(new_addr, 1)?;
                }
                self.l2_cache.get_mut(l1_index).unwrap()[l2_index] = dealloc_entry;
            }
            return Ok(());
        }

        self.cache_l2_cluster(l1_index, l2_addr_disk, false)?;

        let l2_entry = self.l2_cache.get(l1_index).unwrap()[l2_index];
        if l2_entry_is_empty(l2_entry) {
            // With a backing file, empty means "consult backing"; preserve
            // WRITE_ZEROES semantics with an explicit zero marker.
            if write_zero_marker {
                self.l2_cache.get_mut(l1_index).unwrap()[l2_index] = dealloc_entry;
            }
            return Ok(());
        }
        // Compressed clusters cannot use the zero flag optimization, thus fully deallocate instead.
        // Their layout may also use bit 0, so classify them before zero-flagged standard entries.
        if l2_entry_is_compressed(l2_entry) {
            self.deallocate_compressed_cluster(l2_entry)?;
            self.l2_cache.get_mut(l1_index).unwrap()[l2_index] = dealloc_entry;
            return Ok(());
        }
        if l2_entry_is_zero(l2_entry) {
            return Ok(());
        }

        let cluster_addr = l2_entry_std_cluster_addr(l2_entry);

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

        if self.sparse {
            // Fully deallocate to reclaim storage space.
            let new_refcount = refcount - 1;
            self.set_cluster_refcount_track_freed(cluster_addr, new_refcount)?;

            // Rewrite the L2 entry to remove the cluster mapping (full deallocation).
            self.l2_cache.get_mut(l1_index).unwrap()[l2_index] = dealloc_entry;

            if new_refcount == 0 {
                let cluster_size = self.raw_file.cluster_size();
                // This cluster is no longer in use; deallocate the storage.
                // The underlying FS may not support FALLOC_FL_PUNCH_HOLE,
                // so don't treat an error as fatal. Future reads will return zeros anyways.
                let _ = self
                    .raw_file
                    .file_mut()
                    .punch_hole(cluster_addr, cluster_size);
                self.unref_clusters.push(cluster_addr);
            }
        } else {
            // Zero flag optimization - mark cluster as reading zeros without deallocating.
            // Only safe if refcount == 1 (no other references to this cluster).
            if refcount == 1 {
                // Single reference - safe to use zero flag optimization
                self.l2_cache.get_mut(l1_index).unwrap()[l2_index] =
                    l2_entry_make_zero(cluster_addr);
            } else {
                // Multiple references - must decrement refcount and unmap this entry.
                // Cannot use zero flag because other L2 entries still need the real data.
                self.set_cluster_refcount_track_freed(cluster_addr, refcount - 1)?;
                self.l2_cache.get_mut(l1_index).unwrap()[l2_index] = dealloc_entry;
            }
        }
        Ok(())
    }

    fn deallocate_bytes(&mut self, address: u64, length: usize) -> std::io::Result<()> {
        self.deallocate_bytes_impl(address, length, false)
    }

    // Apply WRITE_ZEROES semantics for `length` bytes starting at `address`.
    fn write_zeroes_bytes(&mut self, address: u64, length: usize) -> std::io::Result<()> {
        self.deallocate_bytes_impl(address, length, true)
    }

    fn deallocate_bytes_impl(
        &mut self,
        address: u64,
        length: usize,
        zero_marker: bool,
    ) -> std::io::Result<()> {
        let write_count: usize = self.limit_range_file(address, length);

        let mut nwritten: usize = 0;
        while nwritten < write_count {
            let curr_addr = address + nwritten as u64;
            let count = self.limit_range_cluster(curr_addr, write_count - nwritten);

            if count == self.raw_file.cluster_size() as usize {
                // Full cluster - deallocate the storage.
                self.deallocate_cluster(curr_addr, zero_marker)?;
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
                buf[nread..(nread + count)].fill(0);
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
        self.write_zeroes_bytes(offset, length)?;
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

fn convert_copy<R, W>(reader: &mut R, writer: &mut W, offset: u64, size: u64) -> BlockResult<()>
where
    R: Read + Seek,
    W: Write + Seek,
{
    const CHUNK_SIZE: usize = 65536;
    let mut buf = [0; CHUNK_SIZE];
    let mut read_count = 0;
    reader
        .seek(SeekFrom::Start(offset))
        .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::SeekingFile(e)))?;
    writer
        .seek(SeekFrom::Start(offset))
        .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::SeekingFile(e)))?;
    loop {
        let this_count = min(CHUNK_SIZE as u64, size - read_count) as usize;
        let nread = reader
            .read(&mut buf[..this_count])
            .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::ReadingData(e)))?;
        writer
            .write(&buf[..nread])
            .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::WritingData(e)))?;
        read_count += nread as u64;
        if nread == 0 || read_count == size {
            break;
        }
    }

    Ok(())
}

fn convert_reader_writer<R, W>(reader: &mut R, writer: &mut W, size: u64) -> BlockResult<()>
where
    R: Read + Seek + SeekHole,
    W: Write + Seek,
{
    let mut offset = 0;
    while offset < size {
        // Find the next range of data.
        let next_data = match reader
            .seek_data(offset)
            .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::SeekingFile(e)))?
        {
            Some(o) => o,
            None => {
                // No more data in the file.
                break;
            }
        };
        let next_hole = match reader
            .seek_hole(next_data)
            .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::SeekingFile(e)))?
        {
            Some(o) => o,
            None => {
                // This should not happen - there should always be at least one hole
                // after any data.
                return Err(BlockError::new(
                    BlockErrorKind::Io,
                    Error::SeekingFile(io::Error::from_raw_os_error(EINVAL)),
                ));
            }
        };
        let count = next_hole - next_data;
        convert_copy(reader, writer, next_data, count)?;
        offset = next_hole;
    }

    Ok(())
}

fn convert_reader<R>(reader: &mut R, dst_file: RawFile, dst_type: ImageType) -> BlockResult<()>
where
    R: Read + Seek + SeekHole,
{
    let src_size = reader
        .seek(SeekFrom::End(0))
        .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::SeekingFile(e)))?;
    reader
        .rewind()
        .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::SeekingFile(e)))?;

    // Ensure the destination file is empty before writing to it.
    dst_file
        .set_len(0)
        .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::SettingFileSize(e)))?;

    match dst_type {
        ImageType::Qcow2 => {
            let mut dst_writer = QcowFile::new(dst_file, 3, src_size, true)
                .map_err(|e| BlockError::new(BlockErrorKind::Io, e))?;
            convert_reader_writer(reader, &mut dst_writer, src_size)
        }
        ImageType::Raw => {
            let mut dst_writer = dst_file;
            // Set the length of the destination file to convert it into a sparse file
            // of the desired size.
            dst_writer
                .set_len(src_size)
                .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::SettingFileSize(e)))?;
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
) -> BlockResult<()> {
    let src_type = detect_image_type(&mut src_file)?;
    match src_type {
        ImageType::Qcow2 => {
            let mut src_reader =
                QcowFile::from_with_nesting_depth(src_file, src_max_nesting_depth, true)
                    .map_err(|e| BlockError::new(BlockErrorKind::Io, e))?;
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
pub fn detect_image_type(file: &mut RawFile) -> BlockResult<ImageType> {
    let orig_seek = file
        .stream_position()
        .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::SeekingFile(e)))?;
    file.rewind()
        .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::SeekingFile(e)))?;
    let magic = u32::read_be(file)
        .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::ReadingHeader(e)))?;
    let image_type = if magic == QCOW_MAGIC {
        ImageType::Qcow2
    } else {
        ImageType::Raw
    };
    file.seek(SeekFrom::Start(orig_seek))
        .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::SeekingFile(e)))?;
    Ok(image_type)
}

#[cfg(test)]
mod unit_tests {
    use std::error::Error as StdError;
    use std::fs::{File, OpenOptions};
    use std::io::{Seek, SeekFrom, Write};
    use std::os::unix::fs::FileExt;
    use std::path::Path;

    use vmm_sys_util::tempdir::TempDir;
    use vmm_sys_util::tempfile::TempFile;

    use super::header::DEFAULT_CLUSTER_BITS;
    use super::util::ZERO_FLAG;
    use super::*;
    use crate::formats::qcow::{QcowDisk, QcowTempDisk};

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

    fn tempfile_with_header(header: &[u8]) -> TempFile {
        let temp = TempFile::new().unwrap();
        let mut file = temp.as_file().try_clone().unwrap();
        file.write_all(header).unwrap();
        file.set_len(0x1_0000_0000).unwrap();
        file.sync_all().unwrap();
        temp
    }

    fn try_open_header(header: &[u8]) -> BlockResult<QcowDisk> {
        let temp = tempfile_with_header(header);
        let file = temp.into_file();
        QcowDisk::new(file, false, false, true, false)
    }

    fn try_open_qcow_header(header: &QcowHeader, backing_files: bool) -> BlockResult<QcowDisk> {
        let temp = TempFile::new().unwrap();
        let mut raw = RawFile::new(temp.as_file().try_clone().unwrap(), false);
        header.write_to(&mut raw).expect("write header");
        drop(raw);
        let file = temp.into_file();
        QcowDisk::new(file, false, backing_files, true, false)
    }

    #[test]
    fn default_header_v2() {
        let header = QcowHeader::create_for_size_and_path(2, 0x10_0000, None)
            .expect("Failed to create header.");
        try_open_qcow_header(&header, false)
            .expect("Failed to create QcowDisk from default header");
    }

    #[test]
    fn default_header_v3() {
        let header = QcowHeader::create_for_size_and_path(3, 0x10_0000, None)
            .expect("Failed to create header.");
        try_open_qcow_header(&header, false)
            .expect("Failed to create QcowDisk from default header");
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

    /// Write a header to a fresh file with backing_file_offset and
    /// backing_file_size patched. Panics on setup failures, returns
    /// the parse result of the patched header.
    fn read_header_with_patched_backing(offset: u64, size: u32) -> Result<QcowHeader> {
        let mut header = QcowHeader::create_for_size_and_path(3, 0x10_0000, None)
            .expect("Failed to create header.");
        header.backing_file_offset = offset;
        header.backing_file_size = size;
        let mut disk_file: RawFile = RawFile::new(
            TempFile::new()
                .expect("Failed to create temp file.")
                .into_file(),
            false,
        );
        header
            .write_to(&mut disk_file)
            .expect("Failed to write header.");
        disk_file.rewind().expect("Failed to rewind disk file.");
        QcowHeader::new(&mut disk_file)
    }

    #[test]
    fn backing_file_offset_at_cluster_boundary() {
        let cluster_size = 1u64 << DEFAULT_CLUSTER_BITS;
        let err = read_header_with_patched_backing(cluster_size, 1).unwrap_err();
        assert!(matches!(
            err,
            Error::BackingFileOutsideFirstCluster(_, _, _)
        ));
    }

    #[test]
    fn backing_file_offset_past_cluster() {
        let cluster_size = 1u64 << DEFAULT_CLUSTER_BITS;
        let err = read_header_with_patched_backing(cluster_size + 4096, 16).unwrap_err();
        assert!(matches!(
            err,
            Error::BackingFileOutsideFirstCluster(_, _, _)
        ));
    }

    #[test]
    fn backing_file_end_past_cluster() {
        let cluster_size = 1u64 << DEFAULT_CLUSTER_BITS;
        let err = read_header_with_patched_backing(cluster_size - 4, 16).unwrap_err();
        assert!(matches!(
            err,
            Error::BackingFileOutsideFirstCluster(_, _, _)
        ));
    }

    #[test]
    fn backing_file_offset_inside_header() {
        let err = read_header_with_patched_backing(64, 16).unwrap_err();
        assert!(matches!(err, Error::BackingFileOverlapsHeader(_, _, _)));
    }

    #[test]
    fn backing_file_size_without_offset() {
        let err = read_header_with_patched_backing(0, 16).unwrap_err();
        assert!(matches!(err, Error::BackingFileSizeWithoutOffset(16)));
    }

    #[test]
    fn backing_file_offset_without_size() {
        let err = read_header_with_patched_backing(1024, 0).unwrap_err();
        assert!(matches!(err, Error::BackingFileOffsetWithoutSize(1024)));
    }

    #[test]
    fn backing_file_fits_at_cluster_end() {
        let cluster_size = 1u64 << DEFAULT_CLUSTER_BITS;
        let header =
            read_header_with_patched_backing(cluster_size - 16, 16).expect("Header should parse.");
        assert_eq!(header.backing_file_offset, cluster_size - 16);
        assert_eq!(header.backing_file_size, 16);
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
        // No backing file declared; opening with backing_files=false should succeed.
        let header = QcowHeader::create_for_size_and_path(3, 0x10_0000, None)
            .expect("Failed to create header.");
        try_open_qcow_header(&header, false).unwrap();
    }

    #[test]
    fn disable_backing_file() {
        // Backing file is declared but backing_files=false disables it. QcowDisk
        // maps Overflow -> UnsupportedFeature when backing files are disabled.
        let header =
            QcowHeader::create_for_size_and_path(3, 0x10_0000, Some("/path/to/backing/file"))
                .expect("Failed to create header.");
        let err = try_open_qcow_header(&header, false).unwrap_err();
        assert!(matches!(err.kind(), BlockErrorKind::UnsupportedFeature));
        let source = StdError::source(&err).unwrap();
        let qcow_err = source.downcast_ref::<Error>().unwrap();
        assert!(matches!(qcow_err, Error::MaxNestingDepthExceeded));
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

        let err = QcowDisk::new(
            File::open(img_path.as_path()).expect("Failed to open qcow image file"),
            false,
            true,
            true,
            false,
        )
        .expect_err("Opening qcow file with itself as backing file should fail.");

        // This type of error is complex. For comparing easily, we can check if it contains the
        // type name after formatting.
        assert!(format!("{err:?}").contains(&format!("{:?}", Error::MaxNestingDepthExceeded)));
        // This should recursively call the function MAX_NESTING_DEPTH times before throwing the
        // error, so `BackingFileOpen` should appear that many times.
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
        try_open_header(&invalid_header).expect_err("Invalid header worked.");
    }

    #[test]
    fn invalid_refcount_order() {
        let mut header = valid_header_v3();
        header[99] = 7;
        try_open_header(&header).expect_err("Invalid refcount order worked.");
    }

    #[test]
    fn invalid_cluster_bits() {
        let mut header = valid_header_v3();
        header[23] = 3;
        try_open_header(&header).expect_err("Failed to create file.");
    }

    #[test]
    fn test_header_huge_file() {
        let header = test_huge_header();
        try_open_header(&header).expect_err("Failed to create file.");
    }

    #[test]
    fn test_header_crazy_file_size_rejected() {
        let mut header = valid_header_v3();
        header[24..32].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1e]);
        try_open_header(&header).expect_err("Failed to create file.");
    }

    #[test]
    fn test_huge_l1_table() {
        let mut header = valid_header_v3();
        header[36] = 0x12;
        try_open_header(&header).expect_err("Failed to create file.");
    }

    #[test]
    fn test_header_1_tb_file_min_cluster() {
        let mut header = test_huge_header();
        header[24] = 0;
        header[26] = 1;
        header[31] = 0;
        // 1 TB with the min cluster size makes the arrays too big, it should fail.
        try_open_header(&header).expect_err("Failed to create file.");
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
        let disk = try_open_header(&header).expect("Failed to create file.");
        // Write a sentinel value near the end of the virtual disk.
        let value = 0x0000_0040_3f00_ffffu64;
        disk.write_all_at(0x100_0000_0000 - 8, &value.to_le_bytes());
    }

    #[test]
    fn test_header_huge_num_refcounts() {
        let mut header = valid_header_v3();
        header[56..60].copy_from_slice(&[0x02, 0x00, 0xe8, 0xff]);
        try_open_header(&header).expect_err("Created disk with crazy refcount clusters");
    }

    #[test]
    fn test_header_huge_refcount_offset() {
        let mut header = valid_header_v3();
        header[48..56].copy_from_slice(&[0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x02, 0x00]);
        try_open_header(&header).expect_err("Created disk with crazy refcount offset");
    }

    #[test]
    fn test_l2_entry_zero_flag() {
        let empty_entry: u64 = 0;
        let standard_entry: u64 = 0x1000;
        let zero_flag_entry: u64 = 0x1000 | ZERO_FLAG;
        let compressed_entry: u64 = util::COMPRESSED_FLAG;
        let compressed_entry_with_low_bit: u64 = util::COMPRESSED_FLAG | ZERO_FLAG;

        assert!(util::l2_entry_is_empty(empty_entry));
        assert!(!util::l2_entry_is_empty(standard_entry));

        assert!(!util::l2_entry_is_compressed(standard_entry));
        assert!(util::l2_entry_is_compressed(compressed_entry));
        assert!(util::l2_entry_is_compressed(compressed_entry_with_low_bit));

        assert!(!util::l2_entry_is_zero(standard_entry));
        assert!(util::l2_entry_is_zero(zero_flag_entry));
        assert!(util::l2_entry_is_zero(compressed_entry_with_low_bit));

        // Note: l2_entry_is_zero() only checks bit 0, so compressed entries
        // must be checked before interpreting bit 0 as a zero flag.
    }

    #[test]
    fn rebuild_refcounts() {
        // A v3 header where the first refblock pointer is zero forces the
        // refcount rebuild path inside parse_qcow.
        let header = valid_header_v3();
        let disk = try_open_header(&header).expect("Failed to open and rebuild refcounts");
        // After rebuild the first cluster (header) must have refcount > 0.
        let refcount = disk.metadata().cluster_refcount(0).unwrap();
        assert!(refcount > 0, "header cluster refcount should be set");
    }

    /// Test all valid refcount orders (0-6) can be opened.
    #[test]
    fn refcount_all_orders() {
        for order in 0..=6u8 {
            let mut header = valid_header_v3();
            header[99] = order;
            try_open_header(&header).expect("refcount order should work");
        }
    }

    /// Test write/read roundtrip for all refcount orders.
    #[test]
    fn refcount_all_orders_write_read() {
        for order in 0..=6u8 {
            let mut header = valid_header_v3();
            header[99] = order;
            let disk = try_open_header(&header).unwrap();
            let test_data = b"test data for refcount";

            disk.write_all_at(0, test_data);
            assert_eq!(&disk.read_all_at(0, test_data.len()), test_data);

            // Write to another cluster
            disk.write_all_at(0x10000, test_data);
            assert_eq!(&disk.read_all_at(0x10000, test_data.len()), test_data);
        }
    }

    /// Test overwrite and multi-cluster allocation for all refcount orders.
    #[test]
    fn refcount_all_orders_overwrite() {
        for order in 0..=6u8 {
            let mut header = valid_header_v3();
            header[99] = order;
            let disk = try_open_header(&header).unwrap();

            // Write then overwrite at offset 0.
            disk.write_all_at(0, b"initial data here!!!");
            let new_data = b"overwritten data!!!!";
            disk.write_all_at(0, new_data);
            assert_eq!(&disk.read_all_at(0, new_data.len()), new_data);

            // Allocate multiple clusters
            let cluster_size = 0x10000u64;
            for i in 1..4u64 {
                disk.write_all_at(i * cluster_size, b"cluster data");
            }
            for i in 1..4u64 {
                assert_eq!(&disk.read_all_at(i * cluster_size, 12), b"cluster data");
            }
        }
    }

    /// Test L2 cache eviction for all refcount orders.
    #[test]
    fn refcount_all_orders_l2_eviction() {
        for order in 0..=6u8 {
            let mut header = valid_header_v3();
            header[99] = order;
            let disk = try_open_header(&header).unwrap();

            // L2 cache has 100 entries. Write to >100 regions to force eviction.
            let cluster_size = 0x10000u64;
            let l2_coverage = cluster_size * (cluster_size / 8);

            for i in 0..110u64 {
                disk.write_all_at(i * l2_coverage, b"eviction test");
            }

            // Verify evicted regions can be re-read
            for i in [0u64, 1, 50, 100, 109] {
                assert_eq!(&disk.read_all_at(i * l2_coverage, 13), b"eviction test");
            }
        }
    }

    /// Test sub-byte refcount read/write roundtrip with max values.
    #[test]
    fn refcount_subbyte_max_values() {
        for (bits, max_val) in [(1u64, 1u64), (2, 3), (4, 15)] {
            let file = TempFile::new().unwrap().into_file();
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
            let file = TempFile::new().unwrap().into_file();
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
            let file = TempFile::new().unwrap().into_file();
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

    // Helper to create a v3 header with specific incompatible feature bits set
    fn header_v3_with_incompat_features(features: u64) -> Vec<u8> {
        let mut header = valid_header_v3();
        // incompatible_features is at offset 72, big-endian u64
        header[72..80].copy_from_slice(&features.to_be_bytes());
        header
    }

    // Helper to create a v3 header with specific autoclear feature bits set
    fn header_v3_with_autoclear_features(features: u64) -> Vec<u8> {
        let mut header = valid_header_v3();
        let offset = AUTOCLEAR_FEATURES_OFFSET as usize;
        header[offset..offset + 8].copy_from_slice(&features.to_be_bytes());
        header
    }

    #[test]
    fn accept_incompat_dirty_bit() {
        let header = header_v3_with_incompat_features(1 << 0);
        let result = try_open_header(&header);
        assert!(
            result.is_ok(),
            "Expected dirty bit to be accepted, got: {result:?}"
        );
    }

    #[test]
    fn reject_corrupt_bit_for_writable_open() {
        // Bit 1: corrupt - image metadata is corrupted
        let header = header_v3_with_incompat_features(1 << 1);
        let err = try_open_header(&header).unwrap_err();
        assert!(
            matches!(err.kind(), BlockErrorKind::CorruptImage),
            "Expected CorruptImage error, got: {err:?}"
        );
    }

    #[test]
    fn reject_unsupported_incompat_external_data_bit() {
        // Bit 2: external data file
        let header = header_v3_with_incompat_features(1 << 2);
        let err = try_open_header(&header).unwrap_err();
        assert!(matches!(err.kind(), BlockErrorKind::UnsupportedFeature));
        let source = StdError::source(&err).unwrap();
        let qcow_err = source.downcast_ref::<Error>().unwrap();
        assert!(
            matches!(qcow_err, Error::UnsupportedFeature(v) if v.to_string().contains("external")),
            "Expected UnsupportedFeature error mentioning external, got: {err:?}"
        );
    }

    #[test]
    fn reject_unsupported_incompat_extended_l2_bit() {
        // Bit 4: extended L2 entries
        let header = header_v3_with_incompat_features(1 << 4);
        let err = try_open_header(&header).unwrap_err();
        assert!(matches!(err.kind(), BlockErrorKind::UnsupportedFeature));
        let source = StdError::source(&err).unwrap();
        let qcow_err = source.downcast_ref::<Error>().unwrap();
        assert!(
            matches!(qcow_err, Error::UnsupportedFeature(v) if v.to_string().contains("extended")),
            "Expected UnsupportedFeature error mentioning extended, got: {err:?}"
        );
    }

    #[test]
    fn reject_multiple_unsupported_incompat_bits() {
        // Multiple unsupported bits: external data (2) + extended L2 (4)
        let header = header_v3_with_incompat_features((1 << 2) | (1 << 4));
        let err = try_open_header(&header).unwrap_err();
        assert!(matches!(err.kind(), BlockErrorKind::UnsupportedFeature));
    }

    #[test]
    fn reject_unknown_incompat_bit() {
        // Unknown bit 5 (not defined in spec)
        let header = header_v3_with_incompat_features(1 << 5);
        let err = try_open_header(&header).unwrap_err();
        assert!(matches!(err.kind(), BlockErrorKind::UnsupportedFeature));
        let source = StdError::source(&err).unwrap();
        let qcow_err = source.downcast_ref::<Error>().unwrap();
        assert!(
            matches!(qcow_err, Error::UnsupportedFeature(v) if v.to_string().contains("unknown")),
            "Expected UnsupportedFeature error mentioning unknown, got: {err:?}"
        );
    }

    /// Reads the incompatible_features u64 at its v3 offset from a file.
    fn read_incompat_features(path: &Path) -> u64 {
        let file = OpenOptions::new().read(true).open(path).unwrap();
        let mut buf = [0u8; 8];
        file.read_exact_at(&mut buf, V2_BARE_HEADER_SIZE as u64)
            .unwrap();
        u64::from_be_bytes(buf)
    }

    /// Reads the autoclear_features u64 at its v3 offset from a file.
    fn read_autoclear_features(path: &Path) -> u64 {
        let file = OpenOptions::new().read(true).open(path).unwrap();
        let mut buf = [0u8; 8];
        file.read_exact_at(&mut buf, AUTOCLEAR_FEATURES_OFFSET)
            .unwrap();
        u64::from_be_bytes(buf)
    }

    #[test]
    fn dirty_bit_set_on_open_cleared_on_close_v3() {
        // Test that the dirty bit is set when a v3 image is opened and cleared when it's closed
        let temp = tempfile_with_header(&valid_header_v3());
        let path = temp.as_path().to_owned();

        assert_eq!(
            read_incompat_features(&path) & IncompatFeatures::DIRTY.bits(),
            0,
            "Dirty bit should not be set initially"
        );

        let file = temp.as_file().try_clone().unwrap();
        let disk = QcowDisk::new(file, false, false, true, false).unwrap();

        assert_ne!(
            read_incompat_features(&path) & IncompatFeatures::DIRTY.bits(),
            0,
            "Dirty bit should be set while file is open"
        );

        drop(disk);

        assert_eq!(
            read_incompat_features(&path) & IncompatFeatures::DIRTY.bits(),
            0,
            "Dirty bit should be cleared after close"
        );
    }

    #[test]
    fn dirty_bit_not_used_for_v2() {
        // Test that v2 images don't use the dirty bit (no incompatible_features field)
        let temp = tempfile_with_header(&valid_header_v2());
        let disk = QcowDisk::new(temp.into_file(), false, false, true, false).unwrap();
        assert_eq!(disk.metadata().header().version, 2);
    }

    #[test]
    fn dirty_bit_not_set_for_readonly_v3() {
        // Test that read-only v3 files don't set the dirty bit (e.g., backing files)
        let temp = tempfile_with_header(&valid_header_v3());
        let temp_path = temp.as_path().to_owned();

        let readonly_file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(&temp_path)
            .unwrap();

        // Opening as a QcowDisk should not set the dirty bit for read-only files.
        let _disk = QcowDisk::new(readonly_file, false, false, true, false).unwrap();

        assert_eq!(
            read_incompat_features(&temp_path) & IncompatFeatures::DIRTY.bits(),
            0,
            "Dirty bit should not be written for read-only files"
        );
    }

    #[test]
    fn autoclear_features_cleared_on_open() {
        let temp = tempfile_with_header(&header_v3_with_autoclear_features(0xFFFF_FFFF_FFFF_FFFF));
        let path = temp.as_path().to_owned();

        assert_eq!(
            read_autoclear_features(&path),
            0xFFFF_FFFF_FFFF_FFFF,
            "Autoclear features should be set initially"
        );

        let file = temp.as_file().try_clone().unwrap();
        {
            let _disk = QcowDisk::new(file, false, false, true, false).unwrap();
        }

        assert_eq!(
            read_autoclear_features(&path),
            0,
            "Autoclear features should be cleared after open for write"
        );
    }

    #[test]
    fn autoclear_features_not_cleared_for_readonly() {
        let temp = tempfile_with_header(&header_v3_with_autoclear_features(0xFFFF_FFFF_FFFF_FFFF));
        let path = temp.as_path().to_owned();

        let readonly_file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(&path)
            .unwrap();
        let _disk = QcowDisk::new(readonly_file, false, false, true, false).unwrap();
        drop(_disk);

        assert_eq!(
            read_autoclear_features(&path),
            0xFFFF_FFFF_FFFF_FFFF,
            "Autoclear features should NOT be cleared for read-only files"
        );
    }

    #[test]
    fn autoclear_features_v2_ignored() {
        let temp = tempfile_with_header(&valid_header_v2());
        let disk = QcowDisk::new(temp.into_file(), false, false, true, false).unwrap();
        let header = disk.metadata().header();
        assert_eq!(header.version, 2);
        assert_eq!(header.autoclear_features, 0);
    }

    #[test]
    fn corrupt_image_rejected_for_write() {
        // Test that a corrupt image cannot be opened for writing
        let header = header_v3_with_incompat_features(IncompatFeatures::CORRUPT.bits());
        let err = try_open_header(&header).unwrap_err();
        assert!(
            matches!(err.kind(), BlockErrorKind::CorruptImage),
            "Expected CorruptImage error, got: {err:?}"
        );
    }

    #[test]
    fn corrupt_image_allowed_readonly() {
        // Test that a corrupt image can be opened read-only
        let header = header_v3_with_incompat_features(IncompatFeatures::CORRUPT.bits());
        let temp = tempfile_with_header(&header);

        let readonly_file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(temp.as_path())
            .unwrap();

        let disk = QcowDisk::new(readonly_file, false, false, true, false)
            .expect("Corrupt image should be openable read-only");

        assert!(
            disk.metadata().header().is_corrupt(),
            "Corrupt bit should be set"
        );
    }

    #[test]
    fn resize_grow_within_l1() {
        use crate::disk_file::{DiskSize, Resizable};

        let temp = QcowTempDisk::new(0x10_0000, None, false, true, false).unwrap();
        let mut disk = QcowDisk::new(
            temp.as_file().try_clone().unwrap(),
            false,
            false,
            true,
            false,
        )
        .unwrap();

        let original_size = disk.logical_size().unwrap();
        assert_eq!(original_size, 0x10_0000);

        disk.resize(original_size)
            .expect("Resize to same size should succeed");
        assert_eq!(disk.logical_size().unwrap(), original_size);
    }

    #[test]
    fn resize_grow_with_l1_growth() {
        use crate::disk_file::{DiskSize, Resizable};

        let initial_size = 1024 * 1024; // 1 MB
        let new_size = 600 * 1024 * 1024; // 600 MB

        let temp = QcowTempDisk::new(initial_size, None, false, true, false).unwrap();
        let mut disk = QcowDisk::new(
            temp.as_file().try_clone().unwrap(),
            false,
            false,
            true,
            false,
        )
        .unwrap();

        let original_l1_size = disk.metadata().header().l1_size;
        assert_eq!(disk.logical_size().unwrap(), initial_size);

        let test_data = b"Hello, QCOW resize test!";
        disk.write_all_at(0, test_data);

        disk.resize(new_size).expect("Resize should succeed");
        assert_eq!(disk.logical_size().unwrap(), new_size);

        let new_l1_size = disk.metadata().header().l1_size;
        assert!(new_l1_size > original_l1_size);

        // Verify original data is still intact
        assert_eq!(&disk.read_all_at(0, test_data.len()), test_data);

        let new_offset = new_size - 0x10000; // 64KB before end
        let new_data = b"Data at new end!";
        disk.write_all_at(new_offset, new_data);
        assert_eq!(&disk.read_all_at(new_offset, new_data.len()), new_data);
    }

    #[test]
    fn resize_shrink_fails() {
        use crate::async_io::DiskFileError;
        use crate::disk_file::{DiskSize, Resizable};

        let temp = QcowTempDisk::new(0x10_0000, None, false, true, false).unwrap();
        let mut disk = QcowDisk::new(
            temp.as_file().try_clone().unwrap(),
            false,
            false,
            true,
            false,
        )
        .unwrap();

        let original_size = disk.logical_size().unwrap();
        let smaller_size = original_size / 2;

        let err = disk.resize(smaller_size).unwrap_err();
        let inner = err
            .source_ref()
            .and_then(|s| s.downcast_ref::<DiskFileError>())
            .expect("expected DiskFileError source");
        assert!(
            matches!(inner, DiskFileError::ResizeError(io_err) if io_err.to_string().contains("shrinking")),
            "expected ResizeError describing shrink, got {inner:?}",
        );
        assert_eq!(disk.logical_size().unwrap(), original_size);
    }

    #[test]
    fn resize_with_backing_file_fails() {
        use crate::disk_file::{DiskSize, Resizable};

        let backing_size = 1024 * 1024;
        let backing = QcowTempDisk::new(backing_size, None, false, true, false).unwrap();
        let backing_path = backing.path().to_str().unwrap().to_string();

        let backing_config = BackingFileConfig {
            path: backing_path,
            format: Some(ImageType::Qcow2),
        };
        let overlay = QcowTempDisk::new(backing_size, Some(&backing_config), false, true, false)
            .unwrap()
            .into_tempfile();

        let mut disk = QcowDisk::new(
            overlay.as_file().try_clone().unwrap(),
            false,
            true,
            true,
            false,
        )
        .unwrap();

        assert_eq!(disk.logical_size().unwrap(), backing_size);

        let err = disk.resize(backing_size * 2).unwrap_err();
        assert!(matches!(err.kind(), BlockErrorKind::UnsupportedFeature));
        assert_eq!(disk.logical_size().unwrap(), backing_size);
    }
}
