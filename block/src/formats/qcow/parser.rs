// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::cmp::{max, min};
use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::fs::{OpenOptions, read_link};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::{io, result, str};

use log::warn;
use remain::sorted;
use thiserror::Error;

pub use super::header::{
    BackingFileConfig, CompressionType, ImageType, IncompatFeatures, MissingFeatureError,
    QcowHeader,
};
use super::header::{
    COMPATIBLE_FEATURES_LAZY_REFCOUNTS, MAX_CLUSTER_BITS, MAX_QCOW_FILE_SIZE,
    MAX_RAM_POINTER_TABLE_SIZE, MIN_CLUSTER_BITS, QCOW_MAGIC, max_refcount_clusters,
    offset_is_cluster_boundary,
};
use super::qcow_raw_file::QcowRawFile;
use super::refcount::RefCount;
pub(crate) use super::util::MAX_NESTING_DEPTH;
use super::util::{L1_TABLE_OFFSET_MASK, L2_TABLE_OFFSET_MASK, div_round_up_u64};
use super::vec_cache::{CacheMap, VecCache};
use super::{metadata, refcount};
use crate::aligned_file::AlignedFile;
use crate::error::{BlockError, BlockErrorKind, BlockResult};
use crate::query_device_size;

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

pub(super) type Result<T> = result::Result<T, Error>;

/// Concrete backing file variants.
pub(crate) enum BackingKind {
    /// Raw backing file.
    Raw(AlignedFile),
    /// QCOW2 backing parsed into metadata and raw file.
    Qcow {
        inner: Box<metadata::QcowState>,
        backing: Option<Box<BackingFile>>,
    },
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

        let mut raw_file = AlignedFile::new(backing_raw_file, direct_io);

        // Determine backing file format from header extension or auto-detect
        let backing_format = match config.format {
            Some(format) => format,
            None => detect_image_type(&mut raw_file)?,
        };

        let (kind, virtual_size) = match backing_format {
            ImageType::Raw => {
                let size = query_device_size(raw_file.file())
                    .map_err(|e| {
                        BlockError::new(
                            BlockErrorKind::Io,
                            Error::BackingFileIo(config.path.clone(), e),
                        )
                    })?
                    .0;
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
}

impl Debug for BackingFile {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("BackingFile").finish()
    }
}

/// Parses and validates a QCOW2 image file, returning the metadata, backing
/// file and sparse flag.
///
/// Used by [`crate::formats::qcow::QcowDisk`] when opening an image.
pub(crate) fn parse_qcow(
    file: AlignedFile,
    max_nesting_depth: u32,
    sparse: bool,
) -> BlockResult<(metadata::QcowState, Option<BackingFile>, bool)> {
    let mut header = QcowHeader::new(&file).map_err(|e| {
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
    let mut first_refblock_bytes = [0u8; 8];
    file.read_exact_at(&mut first_refblock_bytes, header.refcount_table_offset)
        .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::ReadingHeader(e)))?;
    let first_refblock_addr = u64::from_be_bytes(first_refblock_bytes);
    if first_refblock_addr != 0 {
        let mut refcount_bytes = [0u8; 2];
        file.read_exact_at(&mut refcount_bytes, first_refblock_addr)
            .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::ReadingHeader(e)))?;
        let first_cluster_refcount = u16::from_be_bytes(refcount_bytes);
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
        rebuild_refcounts(&mut raw_file, header.clone())?;
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
                let refblock_padding = vec![0u64; refcount_block_entries as usize - refblock.len()];
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
    let reftable_clusters_for_refs = div_round_up_u64(refblocks_for_refs, refcount_block_entries);
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

/// Detect the type of an image file by checking for a valid qcow2 header.
pub(super) fn detect_image_type(file: &mut AlignedFile) -> BlockResult<ImageType> {
    let mut magic_bytes = [0u8; 4];
    file.read_exact_at(&mut magic_bytes, 0)
        .map_err(|e| BlockError::new(BlockErrorKind::Io, Error::ReadingHeader(e)))?;
    let magic = u32::from_be_bytes(magic_bytes);
    let image_type = if magic == QCOW_MAGIC {
        ImageType::Qcow2
    } else {
        ImageType::Raw
    };
    Ok(image_type)
}
#[cfg(test)]
mod unit_tests {
    use std::error::Error as StdError;
    use std::fs::{File, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::FileExt;
    use std::path::Path;

    use vmm_sys_util::tempdir::TempDir;
    use vmm_sys_util::tempfile::TempFile;

    use super::super::header::{
        AUTOCLEAR_FEATURES_OFFSET, DEFAULT_CLUSTER_BITS, DEFAULT_REFCOUNT_ORDER,
        HEADER_EXT_BACKING_FORMAT, HEADER_EXT_END, V2_BARE_HEADER_SIZE, V3_BARE_HEADER_SIZE,
    };
    use super::super::util::{self, ZERO_FLAG};
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

    fn basic_file(header: &[u8]) -> AlignedFile {
        let disk_file: AlignedFile = AlignedFile::new(TempFile::new().unwrap().into_file(), false);
        disk_file.write_all_at(header, 0).unwrap();
        disk_file.set_len(0x1_0000_0000).unwrap();
        disk_file
    }

    fn with_basic_file<F>(header: &[u8], mut testfn: F)
    where
        F: FnMut(AlignedFile),
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
        let raw = AlignedFile::new(temp.as_file().try_clone().unwrap(), false);
        header.write_to(&raw).expect("write header");
        drop(raw);
        let file = temp.into_file();
        QcowDisk::new(file, false, backing_files, true, false)
    }

    #[test]
    fn detect_image_type_recognizes_qcow2_magic() {
        let mut file = basic_file(&valid_header_v3());
        assert_eq!(detect_image_type(&mut file).unwrap(), ImageType::Qcow2);
    }

    #[test]
    fn detect_image_type_treats_other_magic_as_raw() {
        let mut file = basic_file(&[0u8; 16]);
        assert_eq!(detect_image_type(&mut file).unwrap(), ImageType::Raw);
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
        with_basic_file(&valid_header_v2(), |disk_file: AlignedFile| {
            let header = QcowHeader::new(&disk_file).expect("Failed to create Header.");
            assert_eq!(header.version, 2);
            assert_eq!(header.refcount_order, DEFAULT_REFCOUNT_ORDER);
            assert_eq!(header.header_size, V2_BARE_HEADER_SIZE);
        });
        with_basic_file(&valid_header_v3(), |disk_file: AlignedFile| {
            let header = QcowHeader::new(&disk_file).expect("Failed to create Header.");
            assert_eq!(header.version, 3);
            assert_eq!(header.refcount_order, DEFAULT_REFCOUNT_ORDER);
            assert_eq!(header.header_size, V3_BARE_HEADER_SIZE);
        });
    }

    #[test]
    fn header_write_matches_qcow2_layout() {
        for expected in [valid_header_v2(), valid_header_v3()] {
            let header = QcowHeader::new(&basic_file(&expected)).expect("Failed to read header.");
            let disk_file: AlignedFile =
                AlignedFile::new(TempFile::new().unwrap().into_file(), false);

            header
                .write_to(&disk_file)
                .expect("Failed to write header.");

            let mut actual = vec![0; expected.len()];
            disk_file.read_exact_at(&mut actual, 0).unwrap();
            assert_eq!(actual, expected);
        }

        let mut expected = valid_header_v3();
        expected[72..80].copy_from_slice(&IncompatFeatures::COMPRESSION.bits().to_be_bytes());
        expected[100..104].copy_from_slice(&(V3_BARE_HEADER_SIZE + 8).to_be_bytes());
        expected.extend_from_slice(&(1u64 << (64 - 8)).to_be_bytes());
        expected.extend_from_slice(&HEADER_EXT_END.to_be_bytes());
        expected.extend_from_slice(&0u32.to_be_bytes());

        let header = QcowHeader::new(&basic_file(&expected)).expect("Failed to read zstd header.");
        let disk_file: AlignedFile = AlignedFile::new(TempFile::new().unwrap().into_file(), false);
        header
            .write_to(&disk_file)
            .expect("Failed to write header.");

        let mut actual = vec![0; expected.len()];
        disk_file.read_exact_at(&mut actual, 0).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn header_v2_with_backing() {
        let header = QcowHeader::create_for_size_and_path(2, 0x10_0000, Some("/my/path/to/a/file"))
            .expect("Failed to create header.");
        let disk_file: AlignedFile = AlignedFile::new(TempFile::new().unwrap().into_file(), false);
        header
            .write_to(&disk_file)
            .expect("Failed to write header to shm.");
        let read_header = QcowHeader::new(&disk_file).expect("Failed to create header.");
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
        let disk_file: AlignedFile = AlignedFile::new(TempFile::new().unwrap().into_file(), false);
        header
            .write_to(&disk_file)
            .expect("Failed to write header to shm.");
        let read_header = QcowHeader::new(&disk_file).expect("Failed to create header.");
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
        let disk_file: AlignedFile = AlignedFile::new(
            TempFile::new()
                .expect("Failed to create temp file.")
                .into_file(),
            false,
        );
        header
            .write_to(&disk_file)
            .expect("Failed to write header.");
        QcowHeader::new(&disk_file)
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
    fn create_header_with_extension(ext_type: u32, ext_data: &[u8]) -> (AlignedFile, QcowHeader) {
        let header = QcowHeader::create_for_size_and_path(3, 0x10_0000, None)
            .expect("Failed to create header.");

        let disk_file: AlignedFile = AlignedFile::new(TempFile::new().unwrap().into_file(), false);
        header.write_to(&disk_file).unwrap();

        // Build the extension area and write it positionally after the header.
        let mut ext = Vec::new();
        ext.extend_from_slice(&ext_type.to_be_bytes());
        ext.extend_from_slice(&(ext_data.len() as u32).to_be_bytes());
        ext.extend_from_slice(ext_data);
        // Pad to the next 8 byte boundary.
        let padding = (8 - (ext_data.len() % 8)) % 8;
        ext.resize(ext.len() + padding, 0);
        ext.extend_from_slice(&HEADER_EXT_END.to_be_bytes());
        disk_file
            .write_all_at(&ext, header.header_size as u64)
            .unwrap();

        (disk_file, header)
    }

    #[test]
    fn read_header_extensions_unknown_extension() {
        let (disk_file, mut header) = create_header_with_extension(
            0x12345678, // unknown type
            "test".as_bytes(),
        );

        // Extension parsing needs a backing file to set format on
        header.backing_file = Some(BackingFileConfig {
            path: "/test/backing".to_string(),
            format: None,
        });

        QcowHeader::read_header_extensions(&disk_file, &mut header, None).unwrap();
        assert_eq!(header.backing_file.as_ref().and_then(|bf| bf.format), None);
    }

    #[test]
    fn read_header_extensions_raw_format() {
        let (disk_file, mut header) =
            create_header_with_extension(HEADER_EXT_BACKING_FORMAT, "raw".as_bytes());

        header.backing_file = Some(BackingFileConfig {
            path: "/test/backing".to_string(),
            format: None,
        });

        QcowHeader::read_header_extensions(&disk_file, &mut header, None).unwrap();
        assert_eq!(
            header.backing_file.as_ref().and_then(|bf| bf.format),
            Some(ImageType::Raw)
        );
    }

    #[test]
    fn read_header_extensions_qcow2_format() {
        let (disk_file, mut header) =
            create_header_with_extension(HEADER_EXT_BACKING_FORMAT, "qcow2".as_bytes());

        header.backing_file = Some(BackingFileConfig {
            path: "/test/backing".to_string(),
            format: None,
        });

        QcowHeader::read_header_extensions(&disk_file, &mut header, None).unwrap();
        assert_eq!(
            header.backing_file.as_ref().and_then(|bf| bf.format),
            Some(ImageType::Qcow2)
        );
    }

    #[test]
    fn read_header_extensions_invalid_format() {
        let (disk_file, mut header) =
            create_header_with_extension(HEADER_EXT_BACKING_FORMAT, "vmdk".as_bytes());

        header.backing_file = Some(BackingFileConfig {
            path: "/test/backing".to_string(),
            format: None,
        });

        let result = QcowHeader::read_header_extensions(&disk_file, &mut header, None);
        assert!(matches!(
            result.unwrap_err(),
            Error::UnsupportedBackingFileFormat(_)
        ));
    }

    #[test]
    fn read_header_extensions_invalid_utf8() {
        let (disk_file, mut header) = create_header_with_extension(
            HEADER_EXT_BACKING_FORMAT,
            &[0xFF, 0xFE, 0xFD], // invalid UTF-8
        );

        let result = QcowHeader::read_header_extensions(&disk_file, &mut header, None);
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
        let disk_file = AlignedFile::new(
            File::create(path).expect("Failed to create image file."),
            false,
        );
        header.write_to(&disk_file)?;
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
            let raw = AlignedFile::new(file, false);
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
            let raw = AlignedFile::new(file, false);
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

            let raw = AlignedFile::new(file, false);
            let mut qcow_raw = QcowRawFile::from(raw, cluster_size, refcount_bits).unwrap();

            // Set up refcount table pointing to refcount block
            let refcount_table_offset = cluster_size;
            qcow_raw
                .file_mut()
                .write_all_at(&(cluster_size * 2).to_be_bytes(), refcount_table_offset)
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
