// Copyright © 2021 Intel Corporation
//
// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

//! Thread safe backing file readers for QCOW2 images.

use std::fs::File;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::FileExt;
use std::sync::Arc;

use super::decoder::Decoder;
use super::metadata::{BackingRead, ClusterReadMapping, QcowMetadata};
use super::parser::{BackingFile, BackingKind, Error as QcowError};
use crate::error::{BlockError, BlockErrorKind, BlockResult, ErrorOp};
use crate::formats::qcow::common::decompress_cluster;

/// Raw backing file using position-independent reads on a duplicated fd.
pub(crate) struct RawBacking {
    pub(crate) file: File,
    pub(crate) virtual_size: u64,
}

// SAFETY: The only I/O operation is read_at which is position independent
// and safe for concurrent use from multiple threads.
unsafe impl Sync for RawBacking {}

impl BackingRead for RawBacking {
    fn read_at(&self, address: u64, buf: &mut [u8]) -> io::Result<()> {
        if address >= self.virtual_size {
            buf.fill(0);
            return Ok(());
        }
        let available = (self.virtual_size - address) as usize;
        if available >= buf.len() {
            self.file.read_exact_at(buf, address)
        } else {
            self.file.read_exact_at(&mut buf[..available], address)?;
            buf[available..].fill(0);
            Ok(())
        }
    }
}

/// QCOW2 image used as a backing file for another QCOW2 image.
///
/// Resolves guest offsets through the QCOW2 cluster mapping (L1/L2
/// tables, refcounts) before reading the underlying data. Read only
/// because backing files never receive writes. Nested backing chains
/// are handled recursively via the optional `backing_file` field.
pub(crate) struct Qcow2Backing {
    pub(crate) metadata: Arc<QcowMetadata>,
    pub(crate) data_file: File,
    pub(crate) backing_file: Option<Arc<dyn BackingRead>>,
    pub(crate) cluster_size: u64,
    pub(crate) decoder: Arc<dyn Decoder>,
}

// SAFETY: All reads go through QcowMetadata which uses RwLock
// and read_exact_at which is position independent and thread safe.
unsafe impl Sync for Qcow2Backing {}

impl BackingRead for Qcow2Backing {
    fn read_at(&self, address: u64, buf: &mut [u8]) -> io::Result<()> {
        let virtual_size = self.metadata.virtual_size();
        if address >= virtual_size {
            buf.fill(0);
            return Ok(());
        }
        let available = (virtual_size - address) as usize;
        if available < buf.len() {
            self.read_clusters(address, &mut buf[..available])?;
            buf[available..].fill(0);
            return Ok(());
        }
        self.read_clusters(address, buf)
    }
}

impl Qcow2Backing {
    fn read_clusters(&self, address: u64, buf: &mut [u8]) -> io::Result<()> {
        let total_len = buf.len();
        let has_backing = self.backing_file.is_some();

        let mappings = self
            .metadata
            .map_clusters_for_read(address, total_len, has_backing)?;

        let mut buf_offset = 0usize;
        for mapping in mappings {
            match mapping {
                ClusterReadMapping::Zero { length } => {
                    buf[buf_offset..buf_offset + length as usize].fill(0);
                    buf_offset += length as usize;
                }
                ClusterReadMapping::Allocated {
                    offset: host_offset,
                    length,
                } => {
                    self.data_file.read_exact_at(
                        &mut buf[buf_offset..buf_offset + length as usize],
                        host_offset,
                    )?;
                    buf_offset += length as usize;
                }
                ClusterReadMapping::Compressed {
                    host_offset,
                    compressed_size,
                    cluster_offset,
                    length,
                } => {
                    let mut compressed = vec![0u8; compressed_size];
                    self.data_file.read_exact_at(&mut compressed, host_offset)?;
                    let decompressed = decompress_cluster(
                        &compressed,
                        self.cluster_size as usize,
                        &*self.decoder,
                    )?;
                    buf[buf_offset..buf_offset + length]
                        .copy_from_slice(&decompressed[cluster_offset..cluster_offset + length]);
                    buf_offset += length;
                }
                ClusterReadMapping::Backing {
                    offset: backing_offset,
                    length,
                } => {
                    self.backing_file.as_ref().unwrap().read_at(
                        backing_offset,
                        &mut buf[buf_offset..buf_offset + length as usize],
                    )?;
                    buf_offset += length as usize;
                }
            }
        }
        Ok(())
    }
}

impl Drop for Qcow2Backing {
    fn drop(&mut self) {
        self.metadata.shutdown();
    }
}

/// Construct a thread safe backing file reader.
pub(super) fn shared_backing_from(bf: BackingFile) -> BlockResult<Arc<dyn BackingRead>> {
    let (kind, virtual_size) = bf.into_kind();

    let dup_fd = |fd: BorrowedFd<'_>| -> BlockResult<OwnedFd> {
        fd.try_clone_to_owned().map_err(|e| {
            BlockError::new(
                BlockErrorKind::Io,
                QcowError::BackingFileIo(String::new(), e),
            )
            .with_op(ErrorOp::DupBackingFd)
        })
    };

    match kind {
        BackingKind::Raw(raw_file) => {
            let file = File::from(dup_fd(raw_file.as_fd())?);
            Ok(Arc::new(RawBacking { file, virtual_size }))
        }
        BackingKind::Qcow { inner, backing } => {
            let data_file = File::from(dup_fd(inner.raw_file.as_fd())?);
            let metadata = Arc::new(QcowMetadata::new(*inner));
            Ok(Arc::new(Qcow2Backing {
                cluster_size: metadata.cluster_size(),
                decoder: metadata.decoder(),
                metadata,
                data_file,
                backing_file: backing.map(|bf| shared_backing_from(*bf)).transpose()?,
            }))
        }
    }
}
