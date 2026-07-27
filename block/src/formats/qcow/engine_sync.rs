// Copyright © 2021 Intel Corporation
//
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::cmp::min;
use std::io;
use std::os::unix::fs::FileExt;
use std::sync::Arc;

use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::write_zeroes::{PunchHole, WriteZeroesAt};

use super::common::decompress_cluster;
use super::decoder::Decoder;
use super::metadata::{
    BackingRead, ClusterReadMapping, ClusterWriteMapping, DeallocAction, QcowMetadata,
};
use super::qcow_raw_file::QcowRawFile;
use crate::async_io::{
    AsyncIo, AsyncIoCompletion, AsyncIoError, AsyncIoOperation, AsyncIoResult, SyncCompletionQueue,
};

pub(super) struct QcowSync {
    metadata: Arc<QcowMetadata>,
    data_file: QcowRawFile,
    /// See the backing_file field on QcowDisk.
    backing_file: Option<Arc<dyn BackingRead>>,
    sparse: bool,
    cluster_size: u64,
    decoder: Arc<dyn Decoder>,
    completions: SyncCompletionQueue,
}

impl QcowSync {
    pub(crate) fn new(
        metadata: Arc<QcowMetadata>,
        data_file: QcowRawFile,
        backing_file: Option<Arc<dyn BackingRead>>,
        sparse: bool,
    ) -> Self {
        QcowSync {
            cluster_size: metadata.cluster_size(),
            decoder: metadata.decoder(),
            metadata,
            data_file,
            backing_file,
            sparse,
            completions: SyncCompletionQueue::new(),
        }
    }

    fn apply_dealloc_action(&mut self, action: &DeallocAction) -> io::Result<()> {
        match action {
            DeallocAction::PunchHole {
                host_offset,
                length,
            } => {
                self.data_file
                    .file_mut()
                    .punch_hole(*host_offset, *length)?;
                self.metadata.complete_punch_hole(*host_offset);
                Ok(())
            }
            DeallocAction::WriteZeroes {
                host_offset,
                length,
            } => self
                .data_file
                .file_mut()
                .write_zeroes_at(*host_offset, *length)
                .map(|_| ()),
        }
    }

    fn read_operation(&mut self, op: &mut AsyncIoOperation) -> AsyncIoResult<usize> {
        let address = op.offset() as u64;
        let total_len = op.total_len();

        let has_backing = self.backing_file.is_some();
        let mappings = self
            .metadata
            .map_clusters_for_read(address, total_len, has_backing)
            .map_err(AsyncIoError::ReadVectored)?;

        let mut buf_offset = 0usize;
        for mapping in mappings {
            match mapping {
                ClusterReadMapping::Zero { length } => {
                    op.fill_zeroes_at(buf_offset, length as usize)
                        .map_err(AsyncIoError::ReadVectored)?;
                    buf_offset += length as usize;
                }
                ClusterReadMapping::Allocated {
                    offset: host_offset,
                    length,
                } => {
                    let len = length as usize;
                    let mut buf = vec![0u8; len];
                    self.data_file
                        .file()
                        .read_exact_at(&mut buf, host_offset)
                        .map_err(AsyncIoError::ReadVectored)?;
                    op.write_bytes_at(buf_offset, &buf)
                        .map_err(AsyncIoError::ReadVectored)?;
                    buf_offset += len;
                }
                ClusterReadMapping::Compressed {
                    host_offset,
                    compressed_size,
                    cluster_offset,
                    length,
                } => {
                    let mut compressed = vec![0u8; compressed_size];
                    self.data_file
                        .file()
                        .read_exact_at(&mut compressed, host_offset)
                        .map_err(AsyncIoError::ReadVectored)?;
                    let decompressed =
                        decompress_cluster(&compressed, self.cluster_size as usize, &*self.decoder)
                            .map_err(AsyncIoError::ReadVectored)?;
                    op.write_bytes_at(
                        buf_offset,
                        &decompressed[cluster_offset..cluster_offset + length],
                    )
                    .map_err(AsyncIoError::ReadVectored)?;
                    buf_offset += length;
                }
                ClusterReadMapping::Backing {
                    offset: backing_offset,
                    length,
                } => {
                    let mut buf = vec![0u8; length as usize];
                    self.backing_file
                        .as_ref()
                        .unwrap()
                        .read_at(backing_offset, &mut buf)
                        .map_err(AsyncIoError::ReadVectored)?;
                    op.write_bytes_at(buf_offset, &buf)
                        .map_err(AsyncIoError::ReadVectored)?;
                    buf_offset += length as usize;
                }
            }
        }

        Ok(total_len)
    }

    fn write_operation(&mut self, op: &AsyncIoOperation) -> AsyncIoResult<usize> {
        let address = op.offset() as u64;
        let total_len = op.total_len();
        let mut buf_offset = 0usize;

        while buf_offset < total_len {
            let curr_addr = address + buf_offset as u64;
            let intra_offset = curr_addr & (self.cluster_size - 1);
            let remaining_in_cluster = (self.cluster_size - intra_offset) as usize;
            let count = min(total_len - buf_offset, remaining_in_cluster);

            // Read backing data for COW if this is a partial cluster
            // write to an unallocated cluster with a backing file.
            let backing_data = if let Some(backing) = self
                .backing_file
                .as_ref()
                .filter(|_| intra_offset != 0 || count < self.cluster_size as usize)
            {
                let cluster_begin = curr_addr - intra_offset;
                let mut data = vec![0u8; self.cluster_size as usize];
                backing
                    .read_at(cluster_begin, &mut data)
                    .map_err(AsyncIoError::WriteVectored)?;
                Some(data)
            } else {
                None
            };

            let mapping = self
                .metadata
                .map_cluster_for_write(curr_addr, backing_data)
                .map_err(AsyncIoError::WriteVectored)?;

            match mapping {
                ClusterWriteMapping::Allocated {
                    offset: host_offset,
                } => {
                    let mut buf = vec![0u8; count];
                    op.read_bytes_at(buf_offset, &mut buf)
                        .map_err(AsyncIoError::WriteVectored)?;
                    self.data_file
                        .file()
                        .write_all_at(&buf, host_offset)
                        .map_err(AsyncIoError::WriteVectored)?;
                }
            }
            buf_offset += count;
        }

        Ok(total_len)
    }
}

impl AsyncIo for QcowSync {
    fn notifier(&self) -> &EventFd {
        self.completions.notifier()
    }

    fn submit_data_operation(&mut self, mut op: AsyncIoOperation) -> AsyncIoResult<()> {
        let is_read = op.is_read();
        let total_len = if is_read {
            self.read_operation(&mut op)?
        } else {
            self.write_operation(&op)?
        };
        self.completions
            .complete(AsyncIoCompletion::from_operation(op, total_len as i32));
        Ok(())
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        self.metadata.flush().map_err(AsyncIoError::Fsync)?;
        if let Some(user_data) = user_data {
            self.completions
                .complete(AsyncIoCompletion::new(user_data, 0, None));
        }
        Ok(())
    }

    fn next_completed_request(&mut self) -> Option<AsyncIoCompletion> {
        self.completions.next_completed()
    }

    fn punch_hole(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        let result = self
            .metadata
            .deallocate_bytes(
                offset,
                length as usize,
                self.sparse,
                false,
                self.backing_file.as_deref(),
            )
            .and_then(|actions| {
                let mut first_error = None;
                for action in &actions {
                    if let Err(e) = self.apply_dealloc_action(action) {
                        first_error.get_or_insert(e);
                    }
                }
                first_error.map_or(Ok(()), Err)
            })
            .map_err(AsyncIoError::PunchHole);

        match result {
            Ok(()) => {
                self.completions
                    .complete(AsyncIoCompletion::new(user_data, 0, None));
                Ok(())
            }
            Err(e) => {
                let errno = if let AsyncIoError::PunchHole(ref io_err) = e {
                    -io_err.raw_os_error().unwrap_or(libc::EIO)
                } else {
                    -libc::EIO
                };
                self.completions
                    .complete(AsyncIoCompletion::new(user_data, errno, None));
                Ok(())
            }
        }
    }

    fn write_zeroes(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        let result = self
            .metadata
            .deallocate_bytes(
                offset,
                length as usize,
                self.sparse,
                true,
                self.backing_file.as_deref(),
            )
            .and_then(|actions| {
                let mut first_error = None;
                for action in &actions {
                    if let Err(e) = self.apply_dealloc_action(action) {
                        first_error.get_or_insert(e);
                    }
                }
                first_error.map_or(Ok(()), Err)
            })
            .map_err(AsyncIoError::WriteZeroes);

        match result {
            Ok(()) => {
                self.completions
                    .complete(AsyncIoCompletion::new(user_data, 0, None));
                Ok(())
            }
            Err(e) => {
                let errno = if let AsyncIoError::WriteZeroes(ref io_err) = e {
                    -io_err.raw_os_error().unwrap_or(libc::EIO)
                } else {
                    -libc::EIO
                };
                self.completions
                    .complete(AsyncIoCompletion::new(user_data, errno, None));
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod unit_tests {
    use std::fs::{File, OpenOptions, create_dir};
    use std::io::Write;
    use std::os::unix::fs::FileExt;
    use std::path::Path;
    use std::sync::Arc;
    use std::{env, thread};

    use vmm_sys_util::tempdir::TempDir;
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::aligned_file::AlignedFile;
    use crate::async_io::{AsyncIoCompletion, OwnedIoBuffer};
    use crate::disk_file::{AsyncDiskFile, DiskSize, MetadataSync, Resizable};
    use crate::error::BlockErrorKind;
    use crate::formats::qcow;
    use crate::formats::qcow::common::unit_tests::compress_allocated_clusters;
    use crate::formats::qcow::{
        BackingFileConfig, Error as QcowError, ImageType, QcowDisk, QcowHeader, QcowTempDisk,
    };

    const TEST_L1_L2_ADDR_MASK: u64 = 0x00ff_ffff_ffff_fe00;
    const TEST_HEADER_L1_TABLE_OFFSET: u64 = 40;
    const TEST_CLUSTER_USED_FLAG: u64 = 1 << 63;
    const TEST_COMPRESSED_FLAG: u64 = 1 << 62;
    const TEST_ZERO_FLAG: u64 = 1;
    const TEST_OUT_OF_BOUNDS_CLUSTER: u64 = 0x0000_0001_4000_0000;

    fn read_be_u64_at(file: &mut File, offset: u64) -> u64 {
        let mut bytes = [0u8; 8];
        file.read_exact_at(&mut bytes, offset).unwrap();
        u64::from_be_bytes(bytes)
    }

    fn write_be_u64_at(file: &mut File, offset: u64, value: u64) {
        file.write_all_at(&value.to_be_bytes(), offset).unwrap();
    }

    fn first_l2_entry_offset(file: &mut File) -> u64 {
        let l1_table_offset = read_be_u64_at(file, TEST_HEADER_L1_TABLE_OFFSET);
        let l1_entry = read_be_u64_at(file, l1_table_offset);
        let l2_table_addr = l1_entry & TEST_L1_L2_ADDR_MASK;
        assert_ne!(l2_table_addr, 0);
        l2_table_addr
    }

    fn set_low_bit_on_first_compressed_l2_entry(file: &mut File) {
        let l2_entry_offset = first_l2_entry_offset(file);
        let l2_entry = read_be_u64_at(file, l2_entry_offset);
        assert_ne!(l2_entry & TEST_COMPRESSED_FLAG, 0);
        write_be_u64_at(file, l2_entry_offset, l2_entry | TEST_ZERO_FLAG);
        file.sync_all().unwrap();
    }

    fn set_first_l2_entry(file: &mut File, l2_entry: u64) {
        let l2_entry_offset = first_l2_entry_offset(file);
        write_be_u64_at(file, l2_entry_offset, l2_entry);
        file.sync_all().unwrap();
    }

    fn first_l2_entry(file: &mut File) -> u64 {
        let l2_entry_offset = first_l2_entry_offset(file);
        read_be_u64_at(file, l2_entry_offset)
    }

    fn qcow_header_is_corrupt(file: &File) -> bool {
        let raw = AlignedFile::new(file.try_clone().unwrap(), false);
        QcowHeader::new(&raw).unwrap().is_corrupt()
    }

    fn create_disk_with_data(
        file_size: u64,
        data: &[u8],
        offset: u64,
        sparse: bool,
        direct_io: bool,
    ) -> (TempFile, QcowDisk) {
        let temp_file = if data.is_empty() {
            QcowTempDisk::new(file_size, None, false, sparse, false)
                .unwrap()
                .into_tempfile()
        } else {
            let tmp_disk = QcowTempDisk::new(file_size, None, false, sparse, false).unwrap();
            tmp_disk.disk().write_all_at(offset, data);
            tmp_disk.into_tempfile()
        };
        let disk = QcowDisk::new(
            temp_file.as_file().try_clone().unwrap(),
            direct_io,
            false,
            sparse,
            false,
        )
        .unwrap();
        (temp_file, disk)
    }

    fn create_overlay_disk_with_raw_backing_pattern(
        file_size: u64,
        value: u8,
        direct_io: bool,
    ) -> (TempFile, TempFile, QcowDisk) {
        let backing_temp = TempFile::new().unwrap();
        let backing_data = vec![value; file_size as usize];
        backing_temp.as_file().write_all(&backing_data).unwrap();
        backing_temp.as_file().sync_all().unwrap();
        let backing_path = backing_temp.as_path().to_str().unwrap().to_string();

        let backing_config = BackingFileConfig {
            path: backing_path,
            format: Some(ImageType::Raw),
        };
        let overlay_temp = QcowTempDisk::new(file_size, Some(&backing_config), false, true, false)
            .unwrap()
            .into_tempfile();

        let disk = QcowDisk::new(
            overlay_temp.as_file().try_clone().unwrap(),
            direct_io,
            true,
            true,
            false,
        )
        .unwrap();

        (backing_temp, overlay_temp, disk)
    }

    fn completion_tuple(completion: &AsyncIoCompletion) -> (u64, i32) {
        (completion.user_data, completion.result)
    }

    fn next_completion(async_io: &mut dyn AsyncIo) -> (u64, i32) {
        completion_tuple(&async_io.next_completed_request().unwrap())
    }

    fn async_read(disk: &QcowDisk, offset: u64, len: usize) -> Vec<u8> {
        let mut async_io = disk.create_async_io(1).unwrap();
        async_io
            .read_to_vec(
                offset as libc::off_t,
                OwnedIoBuffer::from_vec(vec![0xFF; len]),
                1,
            )
            .unwrap();
        let mut completion = async_io.next_completed_request().unwrap();
        let (user_data, result) = completion_tuple(&completion);
        assert_eq!(user_data, 1);
        assert_eq!(result as usize, len, "read should return requested length");
        match completion.buffer.take() {
            Some(buffer) => buffer.as_slice().to_vec(),
            other => panic!("unexpected read completion: {other:?}"),
        }
    }

    fn async_write(disk: &QcowDisk, offset: u64, data: &[u8]) {
        let mut async_io = disk.create_async_io(1).unwrap();
        async_io
            .write_from_vec(
                offset as libc::off_t,
                OwnedIoBuffer::from_vec(data.to_vec()),
                1,
            )
            .unwrap();
        let (user_data, result) = next_completion(async_io.as_mut());
        assert_eq!(user_data, 1);
        assert_eq!(result as usize, data.len());
    }

    fn async_fsync(disk: &QcowDisk) {
        let mut async_io = disk.create_async_io(1).unwrap();
        async_io.fsync(Some(7)).unwrap();
        let (user_data, _result) = next_completion(async_io.as_mut());
        assert_eq!(user_data, 7);
    }

    // Freed relocation clusters must be reused so committed blocks track
    // live data.
    #[test]
    fn relocated_metadata_clusters_are_reused() {
        use std::os::unix::fs::MetadataExt;
        const CL: u64 = 65536;
        let virtual_size = 512 * 1024 * 1024; // one L2 table
        let (temp, disk) = create_disk_with_data(virtual_size, &[], 0, false, false);
        let n: u64 = 400;

        for i in 0..n {
            let pattern = vec![(i as u8).wrapping_add(1); CL as usize];
            async_write(&disk, i * CL, &pattern);
            async_fsync(&disk);
        }

        temp.as_file().sync_all().unwrap();
        let committed = (temp.as_file().metadata().unwrap().blocks() * 512) / CL;
        // Before the fix committed grew to ~2 * n.
        assert!(
            committed <= n + 64,
            "committed {committed} clusters far exceeds {n} live data clusters; \
             relocated metadata clusters are being stranded instead of reused",
        );

        for i in 0..n {
            let got = async_read(&disk, i * CL, CL as usize);
            assert_eq!(
                got,
                vec![(i as u8).wrapping_add(1); CL as usize],
                "cluster {i} data mismatch",
            );
        }
    }

    // Every refcount==0 cluster in the file must be on the runtime free list.
    // The bug left relocated refcount-block clusters free on disk yet absent
    // from the list, so the allocator never reused them.
    #[test]
    fn freed_clusters_are_tracked_in_free_list() {
        const CL: u64 = 65536;
        let virtual_size = 512 * 1024 * 1024;
        let (temp, disk) = create_disk_with_data(virtual_size, &[], 0, false, false);
        let n: u64 = 400;

        for i in 0..n {
            let pattern = vec![(i as u8).wrapping_add(1); CL as usize];
            async_write(&disk, i * CL, &pattern);
            async_fsync(&disk);
        }

        let file_clusters = temp.as_file().metadata().unwrap().len() / CL;
        let mut free_on_disk = 0u64;
        for c in 0..file_clusters {
            if disk.metadata().cluster_refcount(c * CL).unwrap() == 0 {
                free_on_disk += 1;
            }
        }
        let tracked = disk.metadata().free_list_len() as u64;
        assert_eq!(
            free_on_disk, tracked,
            "{free_on_disk} free clusters on disk but {tracked} tracked; \
             relocated clusters are stranded off the free list",
        );
    }

    // Reopening rebuilds the free list from the on-disk refcounts. With the
    // clusters tracked at runtime, a reopen must not discover a pile of them.
    #[test]
    fn reopen_discovers_no_stranded_clusters() {
        const CL: u64 = 65536;
        let virtual_size = 512 * 1024 * 1024;
        let (temp, disk) = create_disk_with_data(virtual_size, &[], 0, false, false);
        let n: u64 = 400;

        for i in 0..n {
            let pattern = vec![(i as u8).wrapping_add(1); CL as usize];
            async_write(&disk, i * CL, &pattern);
            async_fsync(&disk);
        }
        let tracked_before = disk.metadata().free_list_len();

        drop(disk);
        temp.as_file().sync_all().unwrap();
        let disk = QcowDisk::new(
            temp.as_file().try_clone().unwrap(),
            false,
            false,
            false,
            false,
        )
        .unwrap();
        let tracked_after = disk.metadata().free_list_len();

        assert!(
            tracked_after <= tracked_before + 8,
            "reopen recovered {} clusters the allocator had stranded",
            tracked_after.saturating_sub(tracked_before),
        );
    }

    // sync_metadata must make completed writes visible to a fresh reader of
    // the file while the writing disk stays open. Device pause relies on
    // this so snapshot copies and migration reopen a self-consistent image
    // without a guest-initiated flush.
    #[test]
    fn write_visible_after_sync_metadata_and_reopen() {
        const CL: u64 = 65536;
        let virtual_size = 512 * 1024 * 1024;
        let (temp, disk) = create_disk_with_data(virtual_size, &[], 0, false, false);
        let pattern = vec![0xA5u8; CL as usize];
        async_write(&disk, 0, &pattern);

        let reopen = || {
            QcowDisk::new(
                temp.as_file().try_clone().unwrap(),
                false,
                false,
                false,
                false,
            )
            .unwrap()
        };

        // Without the flush the L2 mapping exists only in the writer's
        // in-memory cache: a fresh reader sees the cluster unallocated.
        let stale = reopen();
        assert_eq!(
            async_read(&stale, 0, CL as usize),
            vec![0u8; CL as usize],
            "write leaked to disk without a metadata flush; test is vacuous",
        );

        disk.sync_metadata().unwrap();
        let fresh = reopen();
        assert_eq!(
            async_read(&fresh, 0, CL as usize),
            pattern,
            "write not visible after sync_metadata and reopen",
        );
    }

    #[test]
    fn test_qcow_sync_rejects_out_of_bounds_allocated_l2_entry_on_read() {
        let data = vec![0x5a; 4096];
        let (temp_file, disk) = create_disk_with_data(100 * 1024 * 1024, &data, 0, true, false);
        let mut file = temp_file.as_file().try_clone().unwrap();

        set_first_l2_entry(
            &mut file,
            TEST_CLUSTER_USED_FLAG | TEST_OUT_OF_BOUNDS_CLUSTER,
        );

        let mut async_io = disk.create_async_io(1).unwrap();
        let err = async_io
            .read_to_vec(0, OwnedIoBuffer::from_vec(vec![0u8; 512]), 1)
            .expect_err("out-of-bounds allocated L2 entry must fail");

        match err {
            AsyncIoError::ReadVectored(e) => assert_eq!(e.raw_os_error(), Some(libc::EIO)),
            other => panic!("unexpected error: {other:?}"),
        }
        assert!(
            qcow_header_is_corrupt(&file),
            "out-of-bounds allocated L2 entry should set the corrupt bit"
        );
    }

    #[test]
    fn test_qcow_sync_rejects_out_of_bounds_allocated_l2_entry_on_write() {
        let data = vec![0x5a; 4096];
        let (temp_file, disk) = create_disk_with_data(100 * 1024 * 1024, &data, 0, true, false);
        let mut file = temp_file.as_file().try_clone().unwrap();

        set_first_l2_entry(
            &mut file,
            TEST_CLUSTER_USED_FLAG | TEST_OUT_OF_BOUNDS_CLUSTER,
        );

        let mut async_io = disk.create_async_io(1).unwrap();
        let overwrite = vec![0x11u8; 512];
        let err = async_io
            .write_from_vec(0, OwnedIoBuffer::from_vec(overwrite), 1)
            .expect_err("out-of-bounds allocated L2 entry must fail");

        match err {
            AsyncIoError::WriteVectored(e) => assert_eq!(e.raw_os_error(), Some(libc::EIO)),
            other => panic!("unexpected error: {other:?}"),
        }
        assert!(
            qcow_header_is_corrupt(&file),
            "out-of-bounds allocated L2 entry should set the corrupt bit"
        );
    }

    #[test]
    fn test_qcow_async_punch_hole_completion() {
        let data = vec![0xDD; 128 * 1024];
        let offset = 0u64;
        let (_temp, disk) = create_disk_with_data(100 * 1024 * 1024, &data, offset, true, false);

        let mut async_io = disk.create_async_io(1).unwrap();
        async_io.punch_hole(offset, data.len() as u64, 100).unwrap();
        let (user_data, result) = next_completion(async_io.as_mut());
        assert_eq!(user_data, 100);
        assert_eq!(result, 0, "punch_hole should succeed");
        drop(async_io);

        let read_buf = async_read(&disk, offset, data.len());
        assert!(
            read_buf.iter().all(|&b| b == 0),
            "Punched hole should read as zeros"
        );
    }

    #[test]
    fn test_qcow_async_write_zeroes_completion() {
        let data = vec![0xEE; 256 * 1024];
        let offset = 64 * 1024u64;
        let (_temp, disk) = create_disk_with_data(100 * 1024 * 1024, &data, offset, true, false);

        let mut async_io = disk.create_async_io(1).unwrap();
        async_io
            .write_zeroes(offset, data.len() as u64, 200)
            .unwrap();
        let (user_data, result) = next_completion(async_io.as_mut());
        assert_eq!(user_data, 200);
        assert_eq!(result, 0, "write_zeroes should succeed");
        drop(async_io);

        let read_buf = async_read(&disk, offset, data.len());
        assert!(
            read_buf.iter().all(|&b| b == 0),
            "Zeroed region should read as zeros"
        );
    }

    #[test]
    fn test_write_zeroes_compressed_entry_checks_compressed_before_zero_bit() {
        let cluster_size = 1u64 << 16;
        let data = vec![0xEE; cluster_size as usize];
        let (temp, disk) = create_disk_with_data(100 * 1024 * 1024, &data, 0, true, false);
        drop(disk);

        compress_allocated_clusters(&mut temp.as_file().try_clone().unwrap());
        set_low_bit_on_first_compressed_l2_entry(&mut temp.as_file().try_clone().unwrap());

        let disk = QcowDisk::new(
            temp.as_file().try_clone().unwrap(),
            false,
            false,
            true,
            false,
        )
        .unwrap();
        let mut async_io = disk.create_async_io(1).unwrap();
        async_io.write_zeroes(0, cluster_size, 200).unwrap();
        let (user_data, result) = next_completion(async_io.as_mut());
        assert_eq!(user_data, 200);
        assert_eq!(result, 0);

        async_io.fsync(Some(201)).unwrap();
        let (user_data, result) = next_completion(async_io.as_mut());
        assert_eq!(user_data, 201);
        assert_eq!(result, 0);
        drop(async_io);
        drop(disk);

        let l2_entry = first_l2_entry(&mut temp.as_file().try_clone().unwrap());
        assert_eq!(l2_entry, 0);
    }

    #[test]
    fn test_qcow_async_multiple_operations() {
        let data = vec![0xFF; 64 * 1024];
        let (_temp, _) = create_disk_with_data(100 * 1024 * 1024, &[], 0, true, false);

        // Populate four 64 KiB regions at 128 KiB strides so the subsequent
        // punch_hole calls have allocated clusters to operate on.
        {
            let disk = QcowDisk::new(
                _temp.as_file().try_clone().unwrap(),
                false,
                false,
                true,
                false,
            )
            .unwrap();
            for i in 0..4u64 {
                disk.write_all_at(i * 128 * 1024, &data);
            }
        }

        let disk = QcowDisk::new(
            _temp.as_file().try_clone().unwrap(),
            false,
            false,
            true,
            false,
        )
        .unwrap();

        let mut async_io = disk.create_async_io(1).unwrap();

        async_io.punch_hole(0, 64 * 1024, 1).unwrap();
        async_io.punch_hole(128 * 1024, 64 * 1024, 2).unwrap();
        async_io.punch_hole(256 * 1024, 64 * 1024, 3).unwrap();

        let (ud, res) = next_completion(async_io.as_mut());
        assert_eq!(ud, 1);
        assert_eq!(res, 0);
        let (ud, res) = next_completion(async_io.as_mut());
        assert_eq!(ud, 2);
        assert_eq!(res, 0);
        let (ud, res) = next_completion(async_io.as_mut());
        assert_eq!(ud, 3);
        assert_eq!(res, 0);
        assert!(async_io.next_completed_request().is_none());
    }

    #[test]
    fn test_qcow_punch_hole_then_read() {
        // Verify that after punch_hole, a second async_io sees zeros.
        let data = vec![0xAB; 128 * 1024];
        let offset = 0u64;
        let (_temp, disk) = create_disk_with_data(100 * 1024 * 1024, &data, offset, true, false);

        let mut async_io1 = disk.create_async_io(1).unwrap();
        async_io1
            .punch_hole(offset, data.len() as u64, 100)
            .unwrap();
        let (user_data, result) = next_completion(async_io1.as_mut());
        assert_eq!(user_data, 100);
        assert_eq!(result, 0);
        drop(async_io1);

        // Read via second async_io, should see zeros
        let read_buf = async_read(&disk, offset, data.len());
        assert!(
            read_buf.iter().all(|&b| b == 0),
            "After punch_hole, read should return zeros"
        );
    }

    #[test]
    fn test_qcow_disk_sync_punch_hole_with_create_async_io() {
        // Simulates the real usage pattern of write data, punch hole, then read back.
        let data = vec![0xCD; 64 * 1024]; // one cluster
        let offset = 1024 * 1024u64; // 1MB offset
        let (_temp, disk) = create_disk_with_data(100 * 1024 * 1024, &data, offset, true, false);

        // Punch hole to simulate DISCARD
        let mut async_io1 = disk.create_async_io(1).unwrap();
        async_io1.punch_hole(offset, data.len() as u64, 1).unwrap();
        let (user_data, result) = next_completion(async_io1.as_mut());
        assert_eq!(user_data, 1);
        assert_eq!(result, 0, "punch_hole should succeed");
        drop(async_io1);

        // Read from the same location to verify
        let read_buf = async_read(&disk, offset, data.len());
        assert!(
            read_buf.iter().all(|&b| b == 0),
            "After punch_hole via create_async_io, read should return zeros"
        );
    }

    fn test_qcow_async_read_write_roundtrip_impl(direct_io: bool) {
        let (_temp, disk) = create_disk_with_data(100 * 1024 * 1024, &[], 0, true, direct_io);

        let data = vec![0x42u8; 64 * 1024];
        let offset = 0u64;

        async_write(&disk, offset, &data);

        let mut async_io = disk.create_async_io(1).unwrap();
        async_io.fsync(Some(10)).unwrap();
        let (ud, res) = next_completion(async_io.as_mut());
        assert_eq!(ud, 10);
        assert_eq!(res, 0);
        drop(async_io);

        let read_buf = async_read(&disk, offset, data.len());
        assert_eq!(read_buf, data, "Read-back should match written data");
    }

    #[test]
    fn test_qcow_async_read_write_roundtrip() {
        test_qcow_async_read_write_roundtrip_impl(false);
    }

    #[test]
    fn test_qcow_async_read_write_roundtrip_direct_io() {
        test_qcow_async_read_write_roundtrip_impl(true);
    }

    fn test_qcow_async_read_unallocated_impl(direct_io: bool) {
        // Reading from an unallocated region should return zeros.
        let (_temp, disk) = create_disk_with_data(100 * 1024 * 1024, &[], 0, true, direct_io);
        let read_buf = async_read(&disk, 0, 64 * 1024);
        assert!(
            read_buf.iter().all(|&b| b == 0),
            "Unallocated region should read as zeros"
        );
    }

    #[test]
    fn test_qcow_async_read_unallocated() {
        test_qcow_async_read_unallocated_impl(false);
    }

    #[test]
    fn test_qcow_async_read_unallocated_direct_io() {
        test_qcow_async_read_unallocated_impl(true);
    }

    fn test_qcow_async_cross_cluster_read_write_impl(direct_io: bool) {
        let (_temp, disk) = create_disk_with_data(100 * 1024 * 1024, &[], 0, true, direct_io);

        // Default cluster size is 64KB. Write 96KB starting at 32KB to cross the boundary.
        let data: Vec<u8> = (0..96 * 1024).map(|i| (i % 251) as u8).collect();
        let offset = 32 * 1024u64;

        async_write(&disk, offset, &data);

        let mut async_io = disk.create_async_io(1).unwrap();
        async_io.fsync(Some(99)).unwrap();
        drop(async_io);

        let read_buf = async_read(&disk, offset, data.len());
        assert_eq!(
            read_buf, data,
            "Cross cluster read should match written data"
        );
    }

    #[test]
    fn test_qcow_async_cross_cluster_read_write() {
        test_qcow_async_cross_cluster_read_write_impl(false);
    }

    #[test]
    fn test_qcow_async_cross_cluster_read_write_direct_io() {
        test_qcow_async_cross_cluster_read_write_impl(true);
    }

    fn test_backing_file_read_impl(direct_io: bool) {
        let backing_temp = TempFile::new().unwrap();
        let cluster_size = 1u64 << 16;
        let file_size = cluster_size * 4;
        let pattern: Vec<u8> = (0..file_size as usize).map(|i| (i % 251) as u8).collect();
        backing_temp.as_file().write_all(&pattern).unwrap();
        backing_temp.as_file().sync_all().unwrap();
        let backing_path = backing_temp.as_path().to_str().unwrap().to_string();

        let backing_config = BackingFileConfig {
            path: backing_path,
            format: Some(ImageType::Raw),
        };
        let overlay_temp = QcowTempDisk::new(file_size, Some(&backing_config), false, true, false)
            .unwrap()
            .into_tempfile();

        let file = overlay_temp.as_file().try_clone().unwrap();
        let disk = QcowDisk::new(file, direct_io, true, true, false).unwrap();

        // Read first cluster - should come from backing file
        let buf = async_read(&disk, 0, cluster_size as usize);
        assert_eq!(
            &buf[..],
            &pattern[..cluster_size as usize],
            "First cluster should match backing file data"
        );

        let buf = async_read(&disk, cluster_size, cluster_size as usize);
        assert_eq!(
            &buf[..],
            &pattern[cluster_size as usize..2 * cluster_size as usize],
            "Second cluster should match backing file data"
        );

        // Read a partial range spanning cluster boundary
        let mid = cluster_size - 512;
        let len = 1024usize;
        let buf = async_read(&disk, mid, len);
        assert_eq!(
            &buf[..],
            &pattern[mid as usize..mid as usize + len],
            "Cross cluster read from backing should match"
        );

        let buf = async_read(&disk, 0, file_size as usize);
        assert_eq!(
            &buf[..],
            &pattern[..],
            "Full file read from backing should match"
        );
    }

    #[test]
    fn test_backing_file_read() {
        test_backing_file_read_impl(false);
    }

    #[test]
    fn test_backing_file_read_direct_io() {
        test_backing_file_read_impl(true);
    }

    fn create_raw_backing(path: &Path, pattern: &[u8]) {
        let mut backing_file = File::create(path).unwrap();
        backing_file.write_all(pattern).unwrap();
        backing_file.sync_all().unwrap();
    }

    fn create_qcow2_overlay(overlay_path: &Path, backing_path: &str, file_size: u64) {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(overlay_path)
            .unwrap();
        let backing_config = BackingFileConfig {
            path: backing_path.to_string(),
            format: Some(ImageType::Raw),
        };
        qcow::create_image(&file, file_size, Some(&backing_config)).unwrap();
    }

    fn create_qcow2_overlay_header(overlay_path: &Path, backing_path: &str, file_size: u64) {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(overlay_path)
            .unwrap();
        let header =
            QcowHeader::create_for_size_and_path(3, file_size, Some(backing_path)).unwrap();
        let raw = AlignedFile::new(file, false);
        header.write_to(&raw).unwrap();
        raw.sync_all().unwrap();
    }

    #[test]
    fn test_relative_backing_file_read() {
        let test_dir = TempDir::new_with_prefix("/tmp/ch").unwrap();
        let cwd = env::current_dir().unwrap();
        assert_ne!(cwd.as_path(), test_dir.as_path());

        let backing_path = test_dir.as_path().join("backing.raw");
        let overlay_path = test_dir.as_path().join("overlay.qcow2");
        let cluster_size = 1u64 << 16;
        let file_size = cluster_size * 2;
        let pattern: Vec<u8> = (0..file_size as usize).map(|i| (i % 251) as u8).collect();

        create_raw_backing(&backing_path, &pattern);
        create_qcow2_overlay(&overlay_path, "backing.raw", file_size);

        let disk =
            QcowDisk::new(File::open(&overlay_path).unwrap(), false, true, true, false).unwrap();

        let buf = async_read(&disk, 0, cluster_size as usize);
        assert_eq!(
            &buf[..],
            &pattern[..cluster_size as usize],
            "Relative backing file should resolve from the overlay image directory"
        );
    }

    #[test]
    fn test_missing_relative_backing_file_error_uses_resolved_path() {
        let test_dir = TempDir::new_with_prefix("/tmp/ch").unwrap();
        let overlay_path = test_dir.as_path().join("overlay.qcow2");
        let cluster_size = 1u64 << 16;
        let file_size = cluster_size * 2;

        create_qcow2_overlay_header(&overlay_path, "missing.raw", file_size);

        let err = QcowDisk::new(File::open(&overlay_path).unwrap(), false, true, true, false)
            .unwrap_err();
        assert!(matches!(err.kind(), BlockErrorKind::Io));

        let expected_path = test_dir
            .as_path()
            .join("missing.raw")
            .to_string_lossy()
            .into_owned();
        match err.downcast_ref::<QcowError>() {
            Some(QcowError::BackingFileIo(path, _)) => {
                assert_eq!(path.as_str(), expected_path.as_str());
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn test_relative_backing_file_with_parent_components() {
        let test_dir = TempDir::new_with_prefix("/tmp/ch").unwrap();
        let overlay_dir = test_dir.as_path().join("overlay");
        let sibling_dir = test_dir.as_path().join("sibling");
        create_dir(&overlay_dir).unwrap();
        create_dir(&sibling_dir).unwrap();

        let backing_path = sibling_dir.join("backing.raw");
        let overlay_path = overlay_dir.join("overlay.qcow2");
        let cluster_size = 1u64 << 16;
        let file_size = cluster_size * 2;
        let pattern: Vec<u8> = (0..file_size as usize).map(|i| (i % 251) as u8).collect();

        create_raw_backing(&backing_path, &pattern);
        create_qcow2_overlay(&overlay_path, "../sibling/backing.raw", file_size);

        let disk =
            QcowDisk::new(File::open(&overlay_path).unwrap(), false, true, true, false).unwrap();

        let buf = async_read(&disk, 0, cluster_size as usize);
        assert_eq!(
            &buf[..],
            &pattern[..cluster_size as usize],
            "Relative backing file with parent components should resolve from the overlay image directory"
        );
    }

    #[test]
    fn test_absolute_backing_file_path_read() {
        let test_dir = TempDir::new_with_prefix("/tmp/ch").unwrap();
        let backing_path = test_dir.as_path().join("backing.raw");
        let overlay_path = test_dir.as_path().join("overlay.qcow2");
        let cluster_size = 1u64 << 16;
        let file_size = cluster_size * 2;
        let pattern: Vec<u8> = (0..file_size as usize).map(|i| (i % 251) as u8).collect();

        create_raw_backing(&backing_path, &pattern);
        create_qcow2_overlay(&overlay_path, backing_path.to_str().unwrap(), file_size);

        let disk =
            QcowDisk::new(File::open(&overlay_path).unwrap(), false, true, true, false).unwrap();

        let buf = async_read(&disk, 0, cluster_size as usize);
        assert_eq!(
            &buf[..],
            &pattern[..cluster_size as usize],
            "Absolute backing file path should be used as is"
        );
    }

    #[test]
    fn test_relative_backing_file_falls_back_for_fd_without_filesystem_path() {
        let overlay_temp = TempFile::new().unwrap();
        let cluster_size = 1u64 << 16;
        let file_size = cluster_size * 2;

        {
            let file = overlay_temp.as_file().try_clone().unwrap();
            let header =
                QcowHeader::create_for_size_and_path(3, file_size, Some("missing.raw")).unwrap();
            let raw = AlignedFile::new(file, false);
            header.write_to(&raw).unwrap();
            raw.sync_all().unwrap();
        }

        let overlay_file = overlay_temp.into_file();
        let err = QcowDisk::new(overlay_file, false, true, true, false).unwrap_err();
        assert!(matches!(err.kind(), BlockErrorKind::Io));

        match err.downcast_ref::<QcowError>() {
            Some(QcowError::BackingFileIo(path, _)) => assert_eq!(path, "missing.raw"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    fn test_write_zeroes_unallocated_overlay_with_backing_must_read_zero_impl(direct_io: bool) {
        let cluster_size = 1u64 << 16;
        let file_size = cluster_size * 4;
        let offset = cluster_size;
        let (_backing_temp, _overlay_temp, disk) =
            create_overlay_disk_with_raw_backing_pattern(file_size, 0xAB, direct_io);

        let mut async_io = disk.create_async_io(1).unwrap();
        async_io.write_zeroes(offset, cluster_size, 42).unwrap();
        let (user_data, result) = next_completion(async_io.as_mut());
        assert_eq!(user_data, 42);
        assert_eq!(result, 0);
        drop(async_io);

        let buf = async_read(&disk, offset, cluster_size as usize);
        assert!(
            buf.iter().all(|&b| b == 0),
            "zeroed unallocated overlay cluster exposed backing data"
        );
    }

    #[test]
    fn test_write_zeroes_unallocated_overlay_with_backing_must_read_zero() {
        test_write_zeroes_unallocated_overlay_with_backing_must_read_zero_impl(false);
    }

    #[test]
    fn test_write_zeroes_unallocated_overlay_with_backing_must_read_zero_direct_io() {
        test_write_zeroes_unallocated_overlay_with_backing_must_read_zero_impl(true);
    }

    fn test_partial_write_after_write_zeroes_must_not_reintroduce_backing_data_impl(
        direct_io: bool,
    ) {
        let cluster_size = 1u64 << 16;
        let file_size = cluster_size * 4;
        let offset = cluster_size;
        let patch_offset = 0x4000usize;
        let patch_len = 0x1000usize;
        let (_backing_temp, _overlay_temp, disk) =
            create_overlay_disk_with_raw_backing_pattern(file_size, 0xAB, direct_io);

        let mut async_io = disk.create_async_io(1).unwrap();
        async_io.write_zeroes(offset, cluster_size, 42).unwrap();
        let (_user_data, result) = next_completion(async_io.as_mut());
        assert_eq!(result, 0);
        drop(async_io);

        let patch = [0x99u8; 0x1000];
        async_write(&disk, offset + patch_offset as u64, &patch[..patch_len]);

        let buf = async_read(&disk, offset, cluster_size as usize);
        assert!(buf[..patch_offset].iter().all(|&b| b == 0));
        assert!(
            buf[patch_offset..patch_offset + patch_len]
                .iter()
                .all(|&b| b == 0x99)
        );
        assert!(buf[patch_offset + patch_len..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_partial_write_after_write_zeroes_must_not_reintroduce_backing_data() {
        test_partial_write_after_write_zeroes_must_not_reintroduce_backing_data_impl(false);
    }

    #[test]
    fn test_partial_write_after_write_zeroes_must_not_reintroduce_backing_data_direct_io() {
        test_partial_write_after_write_zeroes_must_not_reintroduce_backing_data_impl(true);
    }

    fn test_backing_file_read_qcow2_backing_impl(direct_io: bool) {
        let cluster_size = 1u64 << 16;
        let file_size = cluster_size * 4;
        let pattern: Vec<u8> = (0..file_size as usize).map(|i| (i % 251) as u8).collect();
        let backing = QcowTempDisk::new(file_size, None, false, true, false).unwrap();
        backing.disk().write_all_at(0, &pattern);
        let backing_temp = backing.into_tempfile();
        let backing_path = backing_temp.as_path().to_str().unwrap().to_string();

        let backing_config = BackingFileConfig {
            path: backing_path,
            format: Some(ImageType::Qcow2),
        };
        let overlay_temp = QcowTempDisk::new(file_size, Some(&backing_config), false, true, false)
            .unwrap()
            .into_tempfile();

        let file = overlay_temp.as_file().try_clone().unwrap();
        let disk = QcowDisk::new(file, direct_io, true, true, false).unwrap();

        // Read first cluster - should come from QCOW2 backing
        let buf = async_read(&disk, 0, cluster_size as usize);
        assert_eq!(
            &buf[..],
            &pattern[..cluster_size as usize],
            "First cluster from QCOW2 backing should match"
        );

        let buf = async_read(&disk, 0, file_size as usize);
        assert_eq!(
            &buf[..],
            &pattern[..],
            "Full file from QCOW2 backing should match"
        );

        // Write to first cluster, then verify second cluster still reads from backing
        let new_data = vec![0xAB; cluster_size as usize];
        async_write(&disk, 0, &new_data);
        {
            let mut async_io = disk.create_async_io(1).unwrap();
            async_io.fsync(Some(99)).unwrap();
        }

        let buf = async_read(&disk, 0, cluster_size as usize);
        assert_eq!(
            &buf[..],
            &new_data[..],
            "Written cluster should be new data"
        );

        let buf = async_read(&disk, cluster_size, cluster_size as usize);
        assert_eq!(
            &buf[..],
            &pattern[cluster_size as usize..2 * cluster_size as usize],
            "Unwritten cluster should still come from backing"
        );
    }

    #[test]
    fn test_backing_file_read_qcow2_backing() {
        test_backing_file_read_qcow2_backing_impl(false);
    }

    #[test]
    fn test_backing_file_read_qcow2_backing_direct_io() {
        test_backing_file_read_qcow2_backing_impl(true);
    }

    fn test_multi_queue_concurrent_reads_impl(direct_io: bool) {
        // Verify that multiple queues (threads) can read simultaneously.
        // This exercises the RwLock + pread64 design: concurrent L2 cache hits
        // proceed in parallel and data reads are position independent.
        let cluster_size = 1u64 << 16;
        let file_size = cluster_size * 16;
        let pattern: Vec<u8> = (0..file_size as usize).map(|i| (i % 251) as u8).collect();
        let (_temp, disk) = create_disk_with_data(file_size, &pattern, 0, true, direct_io);
        let disk = Arc::new(disk);

        let threads: Vec<_> = (0..8)
            .map(|t| {
                let disk = Arc::clone(&disk);
                let pattern = pattern.clone();
                thread::spawn(move || {
                    for i in 0..16u64 {
                        // Each thread reads clusters in a different order
                        let cluster_idx = (i + t * 2) % 16;
                        let offset = cluster_idx * cluster_size;
                        let buf = async_read(&disk, offset, cluster_size as usize);
                        assert_eq!(
                            &buf[..],
                            &pattern[offset as usize..(offset + cluster_size) as usize],
                            "Thread {t} cluster {cluster_idx} mismatch"
                        );
                    }
                })
            })
            .collect();

        for t in threads {
            t.join().unwrap();
        }
    }

    #[test]
    fn test_multi_queue_concurrent_reads() {
        test_multi_queue_concurrent_reads_impl(false);
    }

    #[test]
    fn test_multi_queue_concurrent_reads_direct_io() {
        test_multi_queue_concurrent_reads_impl(true);
    }

    fn test_multi_queue_concurrent_reads_qcow2_backing_impl(direct_io: bool) {
        // Same as above but reads go through a Qcow2Backing,
        // exercising concurrent metadata resolution + pread64 in the backing.
        let cluster_size = 1u64 << 16;
        let file_size = cluster_size * 16;
        let pattern: Vec<u8> = (0..file_size as usize).map(|i| (i % 251) as u8).collect();
        let backing = QcowTempDisk::new(file_size, None, false, true, false).unwrap();
        backing.disk().write_all_at(0, &pattern);
        let backing_temp = backing.into_tempfile();
        let backing_path = backing_temp.as_path().to_str().unwrap().to_string();

        let backing_config = BackingFileConfig {
            path: backing_path,
            format: Some(ImageType::Qcow2),
        };
        let overlay_temp = QcowTempDisk::new(file_size, Some(&backing_config), false, true, false)
            .unwrap()
            .into_tempfile();

        let file = overlay_temp.as_file().try_clone().unwrap();
        let disk = Arc::new(QcowDisk::new(file, direct_io, true, true, false).unwrap());

        let threads: Vec<_> = (0..8)
            .map(|t| {
                let disk = Arc::clone(&disk);
                let pattern = pattern.clone();
                thread::spawn(move || {
                    for i in 0..16u64 {
                        let cluster_idx = (i + t * 2) % 16;
                        let offset = cluster_idx * cluster_size;
                        let buf = async_read(&disk, offset, cluster_size as usize);
                        assert_eq!(
                            &buf[..],
                            &pattern[offset as usize..(offset + cluster_size) as usize],
                            "Thread {t} cluster {cluster_idx} mismatch (qcow2 backing)"
                        );
                    }
                })
            })
            .collect();

        for t in threads {
            t.join().unwrap();
        }
    }

    #[test]
    fn test_multi_queue_concurrent_reads_qcow2_backing() {
        test_multi_queue_concurrent_reads_qcow2_backing_impl(false);
    }

    #[test]
    fn test_multi_queue_concurrent_reads_qcow2_backing_direct_io() {
        test_multi_queue_concurrent_reads_qcow2_backing_impl(true);
    }

    fn test_three_layer_backing_chain_impl(direct_io: bool) {
        // raw base -> qcow2 mid -> qcow2 overlay
        // Tests recursive shared_backing_from() with nested backing.
        let cluster_size = 1u64 << 16;
        let file_size = cluster_size * 4;
        let base_pattern: Vec<u8> = (0..file_size as usize).map(|i| (i % 251) as u8).collect();

        // Layer 0: raw base
        let base_temp = TempFile::new().unwrap();
        base_temp.as_file().write_all(&base_pattern).unwrap();
        base_temp.as_file().sync_all().unwrap();
        let base_path = base_temp.as_path().to_str().unwrap().to_string();

        // Layer 1: qcow2 mid pointing at raw base, write to cluster 0 only
        let mid_pattern = vec![0xBBu8; cluster_size as usize];
        let mid = QcowTempDisk::new(
            file_size,
            Some(&BackingFileConfig {
                path: base_path,
                format: Some(ImageType::Raw),
            }),
            false,
            true,
            false,
        )
        .unwrap();
        mid.disk().write_all_at(0, &mid_pattern);
        let mid_temp = mid.into_tempfile();
        let mid_path = mid_temp.as_path().to_str().unwrap().to_string();

        // Layer 2: qcow2 overlay pointing at qcow2 mid, write to cluster 1 only
        let overlay_pattern = vec![0xCCu8; cluster_size as usize];
        let overlay = QcowTempDisk::new(
            file_size,
            Some(&BackingFileConfig {
                path: mid_path,
                format: Some(ImageType::Qcow2),
            }),
            false,
            true,
            false,
        )
        .unwrap();
        overlay.disk().write_all_at(cluster_size, &overlay_pattern);
        let overlay_temp = overlay.into_tempfile();

        let file = overlay_temp.as_file().try_clone().unwrap();
        let disk = QcowDisk::new(file, direct_io, true, true, false).unwrap();

        // Cluster 0: mid wrote 0xBB
        let buf = async_read(&disk, 0, cluster_size as usize);
        assert!(
            buf.iter().all(|&b| b == 0xBB),
            "Cluster 0 should come from mid layer"
        );

        // Cluster 1: overlay wrote 0xCC
        let buf = async_read(&disk, cluster_size, cluster_size as usize);
        assert!(
            buf.iter().all(|&b| b == 0xCC),
            "Cluster 1 should come from overlay"
        );

        // Cluster 2: falls through mid (unwritten) to raw base
        let buf = async_read(&disk, cluster_size * 2, cluster_size as usize);
        let expected_start = (cluster_size * 2) as usize;
        assert_eq!(
            &buf[..],
            &base_pattern[expected_start..expected_start + cluster_size as usize],
            "Cluster 2 should come from raw base"
        );

        // Cluster 3: also falls through to raw base
        let buf = async_read(&disk, cluster_size * 3, cluster_size as usize);
        let expected_start = (cluster_size * 3) as usize;
        assert_eq!(
            &buf[..],
            &base_pattern[expected_start..expected_start + cluster_size as usize],
            "Cluster 3 should come from raw base"
        );
    }

    #[test]
    fn test_three_layer_backing_chain() {
        test_three_layer_backing_chain_impl(false);
    }

    #[test]
    fn test_three_layer_backing_chain_direct_io() {
        test_three_layer_backing_chain_impl(true);
    }

    fn test_backing_cow_preserves_all_unwritten_clusters_impl(direct_io: bool) {
        // Write to specific clusters in the overlay, verify all others still
        // read from the qcow2 backing correctly.
        let cluster_size = 1u64 << 16;
        let num_clusters = 8u64;
        let file_size = cluster_size * num_clusters;
        let pattern: Vec<u8> = (0..file_size as usize).map(|i| (i % 251) as u8).collect();

        let backing = QcowTempDisk::new(file_size, None, false, true, false).unwrap();
        backing.disk().write_all_at(0, &pattern);
        let backing_temp = backing.into_tempfile();
        let backing_path = backing_temp.as_path().to_str().unwrap().to_string();

        let backing_config = BackingFileConfig {
            path: backing_path,
            format: Some(ImageType::Qcow2),
        };
        let overlay_temp = QcowTempDisk::new(file_size, Some(&backing_config), false, true, false)
            .unwrap()
            .into_tempfile();

        let file = overlay_temp.as_file().try_clone().unwrap();
        let disk = QcowDisk::new(file, direct_io, true, true, false).unwrap();

        let written = vec![0xFFu8; cluster_size as usize];
        for &idx in &[0u64, 3, 7] {
            async_write(&disk, idx * cluster_size, &written);
        }
        {
            let mut async_io = disk.create_async_io(1).unwrap();
            async_io.fsync(Some(99)).unwrap();
        }

        for &idx in &[0u64, 3, 7] {
            let buf = async_read(&disk, idx * cluster_size, cluster_size as usize);
            assert!(
                buf.iter().all(|&b| b == 0xFF),
                "Cluster {idx} should be written data"
            );
        }

        // Verify unwritten clusters read from backing
        for idx in 0..num_clusters {
            if idx == 0 || idx == 3 || idx == 7 {
                continue;
            }
            let offset = idx * cluster_size;
            let buf = async_read(&disk, offset, cluster_size as usize);
            assert_eq!(
                &buf[..],
                &pattern[offset as usize..(offset + cluster_size) as usize],
                "Cluster {idx} should come from backing"
            );
        }
    }

    #[test]
    fn test_backing_cow_preserves_all_unwritten_clusters() {
        test_backing_cow_preserves_all_unwritten_clusters_impl(false);
    }

    #[test]
    fn test_backing_cow_preserves_all_unwritten_clusters_direct_io() {
        test_backing_cow_preserves_all_unwritten_clusters_impl(true);
    }

    fn test_qcow2_backing_read_beyond_virtual_size_impl(direct_io: bool) {
        // Read starting past the backing file virtual_size should return zeros.
        let cluster_size = 1u64 << 16;
        let backing_size = cluster_size * 2;
        let overlay_size = cluster_size * 4; // overlay is larger than backing

        let backing = QcowTempDisk::new(backing_size, None, false, true, false).unwrap();
        backing
            .disk()
            .write_all_at(0, &vec![0xAA; backing_size as usize]);
        let backing_temp = backing.into_tempfile();
        let backing_path = backing_temp.as_path().to_str().unwrap().to_string();

        let backing_config = BackingFileConfig {
            path: backing_path,
            format: Some(ImageType::Qcow2),
        };
        let overlay_temp =
            QcowTempDisk::new(overlay_size, Some(&backing_config), false, true, false)
                .unwrap()
                .into_tempfile();

        let file = overlay_temp.as_file().try_clone().unwrap();
        let disk = QcowDisk::new(file, direct_io, true, true, false).unwrap();

        // Read cluster 2 (past backing virtual_size) - should be zeros
        let buf = async_read(&disk, backing_size, cluster_size as usize);
        assert!(
            buf.iter().all(|&b| b == 0),
            "Read beyond backing virtual_size should return zeros"
        );
    }

    #[test]
    fn test_qcow2_backing_read_beyond_virtual_size() {
        test_qcow2_backing_read_beyond_virtual_size_impl(false);
    }

    #[test]
    fn test_qcow2_backing_read_beyond_virtual_size_direct_io() {
        test_qcow2_backing_read_beyond_virtual_size_impl(true);
    }

    fn test_qcow2_backing_read_spanning_virtual_size_impl(direct_io: bool) {
        // Read that starts within backing bounds but extends past virtual_size.
        // First part should have backing data, remainder should be zeros.
        let cluster_size = 1u64 << 16;
        let backing_size = cluster_size * 2;
        let overlay_size = cluster_size * 4;

        let backing_data = vec![0xBBu8; backing_size as usize];
        let backing = QcowTempDisk::new(backing_size, None, false, true, false).unwrap();
        backing.disk().write_all_at(0, &backing_data);
        let backing_temp = backing.into_tempfile();
        let backing_path = backing_temp.as_path().to_str().unwrap().to_string();

        let backing_config = BackingFileConfig {
            path: backing_path,
            format: Some(ImageType::Qcow2),
        };
        let overlay_temp =
            QcowTempDisk::new(overlay_size, Some(&backing_config), false, true, false)
                .unwrap()
                .into_tempfile();

        let file = overlay_temp.as_file().try_clone().unwrap();
        let disk = QcowDisk::new(file, direct_io, true, true, false).unwrap();

        // Read 2 clusters starting at cluster 1 (spans backing boundary)
        let read_len = cluster_size as usize * 2;
        let buf = async_read(&disk, cluster_size, read_len);

        // First cluster should be backing data
        assert!(
            buf[..cluster_size as usize].iter().all(|&b| b == 0xBB),
            "First half should come from backing"
        );

        // Second cluster is past backing virtual_size - zeros
        assert!(
            buf[cluster_size as usize..].iter().all(|&b| b == 0),
            "Second half should be zeros (past backing virtual_size)"
        );
    }

    #[test]
    fn test_qcow2_backing_read_spanning_virtual_size() {
        test_qcow2_backing_read_spanning_virtual_size_impl(false);
    }

    #[test]
    fn test_qcow2_backing_read_spanning_virtual_size_direct_io() {
        test_qcow2_backing_read_spanning_virtual_size_impl(true);
    }

    fn test_raw_backing_read_beyond_virtual_size_impl(direct_io: bool) {
        // Read past raw backing file virtual_size should return zeros.
        let cluster_size = 1u64 << 16;
        let backing_size = cluster_size * 2;
        let overlay_size = cluster_size * 4;

        let backing_temp = TempFile::new().unwrap();
        let backing_data = vec![0xDD; backing_size as usize];
        backing_temp.as_file().write_all(&backing_data).unwrap();
        backing_temp.as_file().sync_all().unwrap();
        let backing_path = backing_temp.as_path().to_str().unwrap().to_string();

        let backing_config = BackingFileConfig {
            path: backing_path,
            format: Some(ImageType::Raw),
        };
        let overlay_temp =
            QcowTempDisk::new(overlay_size, Some(&backing_config), false, true, false)
                .unwrap()
                .into_tempfile();

        let file = overlay_temp.as_file().try_clone().unwrap();
        let disk = QcowDisk::new(file, direct_io, true, true, false).unwrap();

        // Read cluster 2 (past backing size) - should be zeros
        let buf = async_read(&disk, backing_size, cluster_size as usize);
        assert!(
            buf.iter().all(|&b| b == 0),
            "Read beyond raw backing virtual_size should return zeros"
        );

        // Read spanning boundary: cluster 1 has data, cluster 2 zeros
        let read_len = cluster_size as usize * 2;
        let buf = async_read(&disk, cluster_size, read_len);
        assert!(
            buf[..cluster_size as usize].iter().all(|&b| b == 0xDD),
            "First half should come from raw backing"
        );
        assert!(
            buf[cluster_size as usize..].iter().all(|&b| b == 0),
            "Second half should be zeros (past raw backing size)"
        );
    }

    #[test]
    fn test_raw_backing_read_beyond_virtual_size() {
        test_raw_backing_read_beyond_virtual_size_impl(false);
    }

    #[test]
    fn test_raw_backing_read_beyond_virtual_size_direct_io() {
        test_raw_backing_read_beyond_virtual_size_impl(true);
    }

    fn test_qcow2_backing_cross_cluster_read_impl(direct_io: bool) {
        // Read spanning a cluster boundary through qcow2 backing.
        // Exercises the read_clusters loop in Qcow2Backing.
        let cluster_size = 1u64 << 16;
        let file_size = cluster_size * 4;
        let pattern: Vec<u8> = (0..file_size as usize).map(|i| (i % 251) as u8).collect();

        let backing = QcowTempDisk::new(file_size, None, false, true, false).unwrap();
        backing.disk().write_all_at(0, &pattern);
        let backing_temp = backing.into_tempfile();
        let backing_path = backing_temp.as_path().to_str().unwrap().to_string();

        let backing_config = BackingFileConfig {
            path: backing_path,
            format: Some(ImageType::Qcow2),
        };
        let overlay_temp = QcowTempDisk::new(file_size, Some(&backing_config), false, true, false)
            .unwrap()
            .into_tempfile();

        let file = overlay_temp.as_file().try_clone().unwrap();
        let disk = QcowDisk::new(file, direct_io, true, true, false).unwrap();

        // Read spanning clusters 1-2 boundary: 512 bytes before + 512 after
        let mid = cluster_size - 512;
        let len = 1024usize;
        let buf = async_read(&disk, mid, len);
        assert_eq!(
            &buf[..],
            &pattern[mid as usize..mid as usize + len],
            "Cross cluster read through qcow2 backing should match"
        );

        // Read spanning clusters 0-1-2 (3 clusters worth)
        let start = cluster_size / 2;
        let len = cluster_size as usize * 2;
        let buf = async_read(&disk, start, len);
        assert_eq!(
            &buf[..],
            &pattern[start as usize..start as usize + len],
            "Multi cluster read through qcow2 backing should match"
        );
    }

    #[test]
    fn test_qcow2_backing_cross_cluster_read() {
        test_qcow2_backing_cross_cluster_read_impl(false);
    }

    #[test]
    fn test_qcow2_backing_cross_cluster_read_direct_io() {
        test_qcow2_backing_cross_cluster_read_impl(true);
    }

    fn test_punch_hole_with_backing_fallthrough_impl(direct_io: bool) {
        // Write to overlay, then punch hole. After punch, the cluster should
        // fall through to backing data (not zeros).
        let cluster_size = 1u64 << 16;
        let file_size = cluster_size * 4;
        let pattern: Vec<u8> = (0..file_size as usize).map(|i| (i % 251) as u8).collect();

        let backing_temp = TempFile::new().unwrap();
        backing_temp.as_file().write_all(&pattern).unwrap();
        backing_temp.as_file().sync_all().unwrap();
        let backing_path = backing_temp.as_path().to_str().unwrap().to_string();

        let backing_config = BackingFileConfig {
            path: backing_path,
            format: Some(ImageType::Raw),
        };
        let overlay_temp = QcowTempDisk::new(file_size, Some(&backing_config), false, true, false)
            .unwrap()
            .into_tempfile();

        let file = overlay_temp.as_file().try_clone().unwrap();
        let disk = QcowDisk::new(file, direct_io, true, true, false).unwrap();

        let written = vec![0xFFu8; cluster_size as usize];
        async_write(&disk, 0, &written);
        {
            let mut async_io = disk.create_async_io(1).unwrap();
            async_io.fsync(Some(99)).unwrap();
        }

        let buf = async_read(&disk, 0, cluster_size as usize);
        assert!(buf.iter().all(|&b| b == 0xFF), "Should read written data");

        // Punch hole on cluster 0 - should deallocate and fall through to backing
        {
            let mut async_io = disk.create_async_io(1).unwrap();
            async_io.punch_hole(0, cluster_size, 42).unwrap();
            let (ud, res) = next_completion(async_io.as_mut());
            assert_eq!(ud, 42);
            assert_eq!(res, 0);
        }

        // Now read should return backing data, not zeros
        let buf = async_read(&disk, 0, cluster_size as usize);
        assert_eq!(
            &buf[..],
            &pattern[..cluster_size as usize],
            "After punch_hole with backing, should read backing data"
        );

        // Cluster 1 should still be backing data throughout
        let buf = async_read(&disk, cluster_size, cluster_size as usize);
        assert_eq!(
            &buf[..],
            &pattern[cluster_size as usize..2 * cluster_size as usize],
            "Untouched cluster should read from backing"
        );
    }

    #[test]
    fn test_punch_hole_with_backing_fallthrough() {
        test_punch_hole_with_backing_fallthrough_impl(false);
    }

    #[test]
    fn test_punch_hole_with_backing_fallthrough_direct_io() {
        test_punch_hole_with_backing_fallthrough_impl(true);
    }

    fn test_rewrite_allocated_cluster_impl(direct_io: bool) {
        // Write to a cluster, then overwrite it. The second write should hit
        // the already allocated path in map_write (no new cluster allocation).
        let (_temp, disk) = create_disk_with_data(100 * 1024 * 1024, &[], 0, true, direct_io);
        let cluster_size = 1u64 << 16;

        let data1 = vec![0xAAu8; cluster_size as usize];
        async_write(&disk, 0, &data1);
        {
            let mut aio = disk.create_async_io(1).unwrap();
            aio.fsync(Some(1)).unwrap();
        }
        let buf = async_read(&disk, 0, cluster_size as usize);
        assert!(buf.iter().all(|&b| b == 0xAA), "First write should stick");

        let data2 = vec![0xBBu8; cluster_size as usize];
        async_write(&disk, 0, &data2);
        {
            let mut aio = disk.create_async_io(1).unwrap();
            aio.fsync(Some(2)).unwrap();
        }
        let buf = async_read(&disk, 0, cluster_size as usize);
        assert!(
            buf.iter().all(|&b| b == 0xBB),
            "Overwrite should replace data"
        );
    }

    #[test]
    fn test_rewrite_allocated_cluster() {
        test_rewrite_allocated_cluster_impl(false);
    }

    #[test]
    fn test_rewrite_allocated_cluster_direct_io() {
        test_rewrite_allocated_cluster_impl(true);
    }

    fn test_partial_cluster_write_with_backing_cow_impl(direct_io: bool) {
        // Partial cluster write to an overlay with a backing file triggers COW.
        // The unwritten part of the cluster must be copied from backing.
        let cluster_size = 1u64 << 16;
        let file_size = cluster_size * 4;
        let pattern: Vec<u8> = (0..file_size as usize).map(|i| (i % 251) as u8).collect();

        let backing_temp = TempFile::new().unwrap();
        backing_temp.as_file().write_all(&pattern).unwrap();
        backing_temp.as_file().sync_all().unwrap();
        let backing_path = backing_temp.as_path().to_str().unwrap().to_string();

        let backing_config = BackingFileConfig {
            path: backing_path,
            format: Some(ImageType::Raw),
        };
        let overlay_temp = QcowTempDisk::new(file_size, Some(&backing_config), false, true, false)
            .unwrap()
            .into_tempfile();

        let file = overlay_temp.as_file().try_clone().unwrap();
        let disk = QcowDisk::new(file, direct_io, true, true, false).unwrap();

        // Write 4KB at offset 4KB within cluster 0 (partial cluster)
        let write_offset = 4096u64;
        let write_len = 4096usize;
        let write_data = vec![0xEEu8; write_len];
        async_write(&disk, write_offset, &write_data);
        {
            let mut aio = disk.create_async_io(1).unwrap();
            aio.fsync(Some(1)).unwrap();
        }

        let buf = async_read(&disk, 0, cluster_size as usize);

        // Before the write: should be COW'd from backing
        assert_eq!(
            &buf[..write_offset as usize],
            &pattern[..write_offset as usize],
            "Pre write region should be COW from backing"
        );

        assert_eq!(
            &buf[write_offset as usize..write_offset as usize + write_len],
            &write_data[..],
            "Written region should be new data"
        );

        // After the write: should be COW'd from backing
        let after_offset = write_offset as usize + write_len;
        assert_eq!(
            &buf[after_offset..cluster_size as usize],
            &pattern[after_offset..cluster_size as usize],
            "Post write region should be COW from backing"
        );
    }

    #[test]
    fn test_partial_cluster_write_with_backing_cow() {
        test_partial_cluster_write_with_backing_cow_impl(false);
    }

    #[test]
    fn test_partial_cluster_write_with_backing_cow_direct_io() {
        test_partial_cluster_write_with_backing_cow_impl(true);
    }

    #[test]
    fn test_partial_cluster_deallocate() {
        // Punch hole on a partial cluster range. The deallocate_bytes path
        // should produce WriteZeroes actions for partial clusters.
        let cluster_size = 1u64 << 16;
        let file_size = cluster_size * 4;

        let data: Vec<u8> = (0..2 * cluster_size as usize)
            .map(|i| (i % 251) as u8)
            .collect();
        let (_temp, disk) = create_disk_with_data(file_size, &data, 0, true, false);

        // Punch a partial range: last 4KB of cluster 0 + first 4KB of cluster 1
        let punch_offset = cluster_size - 4096;
        let punch_len = 8192u64;
        {
            let mut aio = disk.create_async_io(1).unwrap();
            aio.punch_hole(punch_offset, punch_len, 10).unwrap();
            let (ud, res) = next_completion(aio.as_mut());
            assert_eq!(ud, 10);
            assert_eq!(res, 0);
        }

        let buf = async_read(&disk, 0, 2 * cluster_size as usize);

        // Before punch: unchanged
        assert_eq!(
            &buf[..punch_offset as usize],
            &data[..punch_offset as usize],
            "Data before punch should be unchanged"
        );

        // Punched region: zeros
        assert!(
            buf[punch_offset as usize..(punch_offset + punch_len) as usize]
                .iter()
                .all(|&b| b == 0),
            "Punched region should be zeros"
        );

        // After punch: unchanged
        let after = (punch_offset + punch_len) as usize;
        assert_eq!(
            &buf[after..2 * cluster_size as usize],
            &data[after..2 * cluster_size as usize],
            "Data after punch should be unchanged"
        );
    }

    #[test]
    fn test_partial_zero_action_failure_is_reported() {
        const CLUSTER_SIZE: u64 = 1 << 16;
        let data = vec![0xa5; CLUSTER_SIZE as usize];
        let (temp, disk) = create_disk_with_data(4 * CLUSTER_SIZE, &data, 0, true, false);
        drop(disk);

        let raw = AlignedFile::new(temp.as_file().try_clone().unwrap(), false);
        let (inner, backing, sparse) = super::super::parser::parse_qcow(raw, 0, true).unwrap();
        assert!(backing.is_none());
        let refcount_bits = 1u64 << inner.header.refcount_order;
        let metadata = Arc::new(QcowMetadata::new(inner));

        // Metadata remains writable, but use a read-only per-queue data fd so
        // the partial-cluster WriteZeroes action deterministically fails.
        let read_only = File::open(temp.as_path()).unwrap();
        let data_file = QcowRawFile::from(
            AlignedFile::new(read_only, false),
            CLUSTER_SIZE,
            refcount_bits,
        )
        .unwrap();
        let mut aio = QcowSync::new(Arc::clone(&metadata), data_file, None, sparse);

        aio.write_zeroes(4096, 4096, 901).unwrap();
        let (user_data, result) = next_completion(&mut aio);
        assert_eq!(user_data, 901);
        assert!(result < 0, "host WriteZeroes failure must reach the guest");

        drop(aio);
        metadata.shutdown();
        drop(metadata);

        let reopened = QcowDisk::new(
            temp.as_file().try_clone().unwrap(),
            false,
            false,
            true,
            false,
        )
        .unwrap();
        assert_eq!(async_read(&reopened, 0, data.len()), data);
    }

    #[test]
    fn test_failed_punch_is_reported_and_cluster_stays_reserved() {
        const CLUSTER_SIZE: u64 = 1 << 16;
        const L2_ENTRIES: u64 = CLUSTER_SIZE / 8;
        const L1_SPAN: u64 = CLUSTER_SIZE * L2_ENTRIES;

        let data = vec![0x3c; CLUSTER_SIZE as usize];
        let (temp, disk) = create_disk_with_data(L1_SPAN + 2 * CLUSTER_SIZE, &data, 0, true, false);
        drop(disk);

        let raw = AlignedFile::new(temp.as_file().try_clone().unwrap(), false);
        let (inner, backing, sparse) = super::super::parser::parse_qcow(raw, 0, true).unwrap();
        assert!(backing.is_none());
        let refcount_bits = 1u64 << inner.header.refcount_order;
        let writable_data_file = inner.raw_file.clone();
        let metadata = Arc::new(QcowMetadata::new(inner));
        let old_host_offset = match &metadata
            .map_clusters_for_read(0, CLUSTER_SIZE as usize, false)
            .unwrap()[0]
        {
            ClusterReadMapping::Allocated { offset, .. } => *offset,
            other => panic!("expected allocated mapping, got {other:?}"),
        };

        // A read-only per-queue fd makes the host punch fail after the
        // metadata deallocation has already completed.
        let read_only = File::open(temp.as_path()).unwrap();
        let read_only_data_file = QcowRawFile::from(
            AlignedFile::new(read_only, false),
            CLUSTER_SIZE,
            refcount_bits,
        )
        .unwrap();
        let mut failing_aio =
            QcowSync::new(Arc::clone(&metadata), read_only_data_file, None, sparse);
        failing_aio.punch_hole(0, CLUSTER_SIZE, 902).unwrap();
        let (user_data, result) = next_completion(&mut failing_aio);
        assert_eq!(user_data, 902);
        assert!(result < 0, "host PunchHole failure must reach the guest");
        drop(failing_aio);

        // A FLUSH cannot make the failed-punch cluster reusable.
        metadata.flush().unwrap();
        let mut writer = QcowSync::new(Arc::clone(&metadata), writable_data_file, None, sparse);
        writer
            .write_from_vec(
                L1_SPAN as libc::off_t,
                OwnedIoBuffer::from_vec(vec![0x7e; CLUSTER_SIZE as usize]),
                903,
            )
            .unwrap();
        assert_eq!(
            completion_tuple(&writer.next_completed_request().unwrap()),
            (903, CLUSTER_SIZE as i32)
        );
        writer.fsync(None).unwrap();

        let mut inspect = temp.as_file().try_clone().unwrap();
        let l1_table_offset = read_be_u64_at(&mut inspect, TEST_HEADER_L1_TABLE_OFFSET);
        let new_l2 = read_be_u64_at(&mut inspect, l1_table_offset + 8) & TEST_L1_L2_ADDR_MASK;
        assert_ne!(new_l2, old_host_offset);
    }

    #[test]
    fn test_resize_grow() {
        let cluster_size = 1u64 << 16;
        let initial_size = cluster_size * 4;
        let data = vec![0xAA; cluster_size as usize];
        let (_temp, mut disk) = create_disk_with_data(initial_size, &data, 0, true, false);

        assert_eq!(disk.logical_size().unwrap(), initial_size);

        let new_size = cluster_size * 8;
        disk.resize(new_size).unwrap();
        assert_eq!(disk.logical_size().unwrap(), new_size);

        // Original data intact
        let buf = async_read(&disk, 0, cluster_size as usize);
        assert!(
            buf.iter().all(|&b| b == 0xAA),
            "Original data should survive resize"
        );

        // New region reads as zeros
        let buf = async_read(&disk, initial_size, cluster_size as usize);
        assert!(
            buf.iter().all(|&b| b == 0),
            "Newly grown region should read as zeros"
        );

        // Can write to newly grown region
        let new_data = vec![0xBB; cluster_size as usize];
        async_write(&disk, initial_size, &new_data);
        {
            let mut aio = disk.create_async_io(1).unwrap();
            aio.fsync(Some(1)).unwrap();
        }
        let buf = async_read(&disk, initial_size, cluster_size as usize);
        assert!(
            buf.iter().all(|&b| b == 0xBB),
            "Write to grown region should work"
        );
    }

    #[test]
    fn test_resize_with_backing_file_rejected() {
        let backing_temp = TempFile::new().unwrap();
        let cluster_size = 1u64 << 16;
        let file_size = cluster_size * 4;
        backing_temp
            .as_file()
            .write_all(&vec![0u8; file_size as usize])
            .unwrap();
        backing_temp.as_file().sync_all().unwrap();
        let backing_path = backing_temp.as_path().to_str().unwrap().to_string();

        let backing_config = BackingFileConfig {
            path: backing_path,
            format: Some(ImageType::Raw),
        };
        let overlay_temp = QcowTempDisk::new(file_size, Some(&backing_config), false, true, false)
            .unwrap()
            .into_tempfile();

        let file = overlay_temp.as_file().try_clone().unwrap();
        let mut disk = QcowDisk::new(file, false, true, true, false).unwrap();

        assert_eq!(disk.logical_size().unwrap(), file_size);
        let result = disk.resize(file_size * 2);
        assert!(result.is_err(), "resize with backing file should fail");
        assert_eq!(
            disk.logical_size().unwrap(),
            file_size,
            "size should be unchanged after failed resize"
        );
    }

    fn test_multi_iovec_read_write_impl(direct_io: bool) {
        // Exercise scatter/gather with multiple iovecs per operation.
        let (_temp, disk) = create_disk_with_data(100 * 1024 * 1024, &[], 0, true, direct_io);

        // Write: 3 iovecs with distinct patterns
        let a = vec![0xAAu8; 16 * 1024];
        let b = vec![0xBBu8; 32 * 1024];
        let c = vec![0xCCu8; 16 * 1024];
        let total = a.len() + b.len() + c.len();
        let mut write_buf = Vec::with_capacity(total);
        write_buf.extend_from_slice(&a);
        write_buf.extend_from_slice(&b);
        write_buf.extend_from_slice(&c);

        let mut aio = disk.create_async_io(1).unwrap();
        aio.write_from_vec(0, OwnedIoBuffer::from_vec(write_buf), 1)
            .unwrap();
        let (ud, res) = next_completion(aio.as_mut());
        assert_eq!(ud, 1);
        assert_eq!(res as usize, total);
        aio.fsync(Some(2)).unwrap();
        drop(aio);

        let mut aio = disk.create_async_io(1).unwrap();
        aio.read_to_vec(0, OwnedIoBuffer::from_vec(vec![0; total]), 10)
            .unwrap();
        let mut completion = aio.next_completed_request().unwrap();
        let (ud, res) = completion_tuple(&completion);
        assert_eq!(ud, 10);
        assert_eq!(res as usize, total);
        drop(aio);

        let got = match completion.buffer.take() {
            Some(buffer) => buffer.as_slice().to_vec(),
            other => panic!("unexpected read completion: {other:?}"),
        };

        // Build expected from the write buffers
        let mut expected = Vec::with_capacity(total);
        expected.extend_from_slice(&a);
        expected.extend_from_slice(&b);
        expected.extend_from_slice(&c);

        assert_eq!(got, expected, "Multi iovec read should match written data");
    }

    #[test]
    fn test_multi_iovec_read_write() {
        test_multi_iovec_read_write_impl(false);
    }

    #[test]
    fn test_multi_iovec_read_write_direct_io() {
        test_multi_iovec_read_write_impl(true);
    }

    #[test]
    fn test_compressed_read() {
        let cluster_size = 65536usize;
        let data: Vec<u8> = (0..=255).cycle().take(cluster_size).collect();
        let (temp, disk) = create_disk_with_data(100 * 1024 * 1024, &data, 0, false, false);
        drop(disk);

        compress_allocated_clusters(&mut temp.as_file().try_clone().unwrap());

        let disk = QcowDisk::new(
            temp.as_file().try_clone().unwrap(),
            false,
            false,
            false,
            false,
        )
        .unwrap();

        let buf = async_read(&disk, 0, cluster_size);
        assert_eq!(buf, data);
    }

    // Regression test for a valid cross-queue schedule where a guest FLUSH
    // and a new allocation run while a returned PunchHole side effect is
    // still pending.
    #[test]
    fn stale_punch_cannot_reuse_or_destroy_new_l2() {
        const CLUSTER_SIZE: u64 = 1 << 16;
        const L2_ENTRIES: u64 = CLUSTER_SIZE / 8;
        const L1_SPAN: u64 = CLUSTER_SIZE * L2_ENTRIES;

        let temp = TempFile::new().unwrap();
        let file = temp.as_file().try_clone().unwrap();
        let virtual_size = L1_SPAN + 2 * CLUSTER_SIZE;
        qcow::create_image(&file, virtual_size, None).unwrap();

        // Seed one allocated data cluster below L1[0].
        {
            let disk = QcowDisk::new(file.try_clone().unwrap(), false, false, true, false).unwrap();
            async_write(&disk, 0, &vec![0x11; CLUSTER_SIZE as usize]);
            async_fsync(&disk);
        }

        let raw = AlignedFile::new(file.try_clone().unwrap(), false);
        let (inner, backing, sparse) = super::super::parser::parse_qcow(raw, 0, true).unwrap();
        assert!(backing.is_none());
        let data_file = inner.raw_file.clone();
        let metadata = Arc::new(QcowMetadata::new(inner));
        let mut aio = QcowSync::new(Arc::clone(&metadata), data_file, None, sparse);

        // Queue A: update metadata, retain the old host side effect.
        let actions = metadata
            .deallocate_bytes(0, CLUSTER_SIZE as usize, true, false, None)
            .unwrap();
        assert_eq!(actions.len(), 1);
        let stale_punch_offset = match actions[0] {
            DeallocAction::PunchHole {
                host_offset,
                length,
            } => {
                assert_eq!(length, CLUSTER_SIZE);
                host_offset
            }
            _ => panic!("expected one full-cluster PunchHole"),
        };

        // Queue B: guest FLUSH must not publish the pending-punch cluster.
        metadata.flush().unwrap();

        // Queue C: allocate a new L2 and commit it. The pending-punch
        // cluster must not be selected.
        let new_guest_offset = L1_SPAN;
        aio.write_from_vec(
            new_guest_offset as libc::off_t,
            OwnedIoBuffer::from_vec(vec![0x5a; CLUSTER_SIZE as usize]),
            77,
        )
        .unwrap();
        let completion = aio.next_completed_request().unwrap();
        assert_eq!(completion_tuple(&completion), (77, CLUSTER_SIZE as i32));
        aio.fsync(None).unwrap();

        let mut inspect = file.try_clone().unwrap();
        let l1_table_offset = read_be_u64_at(&mut inspect, TEST_HEADER_L1_TABLE_OFFSET);
        let committed_l2 = read_be_u64_at(&mut inspect, l1_table_offset + 8) & TEST_L1_L2_ADDR_MASK;
        assert_ne!(committed_l2, stale_punch_offset);

        // Queue A resumes. Completing the old action must not touch the new
        // L2, and only now may the old data cluster enter unref_clusters.
        aio.apply_dealloc_action(&actions[0]).unwrap();
        metadata.flush().unwrap();
        metadata.shutdown();
        drop(aio);
        drop(metadata);

        let reopened = QcowDisk::new(file.try_clone().unwrap(), false, false, true, false).unwrap();
        let read_back = async_read(&reopened, new_guest_offset, CLUSTER_SIZE as usize);
        assert!(read_back.iter().all(|&byte| byte == 0x5a));
    }
}
