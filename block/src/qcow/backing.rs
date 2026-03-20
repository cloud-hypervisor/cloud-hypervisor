// Copyright © 2021 Intel Corporation
//
// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

//! Thread safe backing file readers for QCOW2 images.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;

use crate::qcow::metadata::{BackingRead, ClusterReadMapping, QcowMetadata};
use crate::qcow_common::pread_exact;

/// Raw backing file using pread64 on a duplicated fd.
pub(crate) struct RawBacking {
    pub(crate) fd: OwnedFd,
    pub(crate) virtual_size: u64,
}

// SAFETY: The only I/O operation is pread64 which is position independent
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
            pread_exact(self.fd.as_raw_fd(), buf, address)
        } else {
            pread_exact(self.fd.as_raw_fd(), &mut buf[..available], address)?;
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
pub(crate) struct Qcow2MetadataBacking {
    pub(crate) metadata: Arc<QcowMetadata>,
    pub(crate) data_fd: OwnedFd,
    pub(crate) backing_file: Option<Arc<dyn BackingRead>>,
}

// SAFETY: All reads go through QcowMetadata which uses RwLock
// and pread64 which is position independent and thread safe.
unsafe impl Sync for Qcow2MetadataBacking {}

impl BackingRead for Qcow2MetadataBacking {
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

impl Qcow2MetadataBacking {
    /// Resolve cluster mappings via metadata then read allocated clusters
    /// with pread64.
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
                    pread_exact(
                        self.data_fd.as_raw_fd(),
                        &mut buf[buf_offset..buf_offset + length as usize],
                        host_offset,
                    )?;
                    buf_offset += length as usize;
                }
                ClusterReadMapping::Compressed { data } => {
                    let len = data.len();
                    buf[buf_offset..buf_offset + len].copy_from_slice(&data);
                    buf_offset += len;
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

impl Drop for Qcow2MetadataBacking {
    fn drop(&mut self) {
        self.metadata.shutdown();
    }
}
