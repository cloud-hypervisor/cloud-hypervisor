// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::cmp::min;
use std::collections::VecDeque;
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd};
use std::sync::Arc;
use std::{fmt, io};

use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::write_zeroes::{PunchHole, WriteZeroesAt};

use crate::async_io::{AsyncIo, AsyncIoError, AsyncIoResult, BorrowedDiskFd, DiskFileError};
use crate::disk_file;
use crate::error::{BlockError, BlockErrorKind, BlockResult, ErrorOp};
use crate::qcow::backing::shared_backing_from;
use crate::qcow::decoder::Decoder;
use crate::qcow::metadata::{
    BackingRead, ClusterReadMapping, ClusterWriteMapping, DeallocAction, QcowMetadata,
};
use crate::qcow::qcow_raw_file::QcowRawFile;
use crate::qcow::{MAX_NESTING_DEPTH, RawFile, parse_qcow};
use crate::qcow_common::{
    AlignedBuf, aligned_pread, aligned_pwrite, decompress_cluster, gather_from_iovecs,
    gather_from_iovecs_into, pread_alloc, pread_exact, pwrite_all, scatter_to_iovecs,
    zero_fill_iovecs,
};

pub struct QcowDiskSync {
    metadata: Arc<QcowMetadata>,
    /// Shared across queues, resolved once at construction.
    backing_file: Option<Arc<dyn BackingRead>>,
    sparse: bool,
    data_raw_file: QcowRawFile,
}

impl fmt::Debug for QcowDiskSync {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QcowDiskSync")
            .field("sparse", &self.sparse)
            .field("has_backing", &self.backing_file.is_some())
            .finish_non_exhaustive()
    }
}

impl QcowDiskSync {
    pub fn new(
        file: File,
        direct_io: bool,
        backing_files: bool,
        sparse: bool,
    ) -> BlockResult<Self> {
        let max_nesting_depth = if backing_files { MAX_NESTING_DEPTH } else { 0 };
        let (inner, backing_file, sparse) =
            parse_qcow(RawFile::new(file, direct_io), max_nesting_depth, sparse).map_err(|e| {
                let e = if !backing_files && matches!(e.kind(), BlockErrorKind::Overflow) {
                    e.with_kind(BlockErrorKind::UnsupportedFeature)
                } else {
                    e
                };
                e.with_op(ErrorOp::Open)
            })?;
        let data_raw_file = inner.raw_file.clone();
        Ok(QcowDiskSync {
            metadata: Arc::new(QcowMetadata::new(inner)),
            backing_file: backing_file.map(shared_backing_from).transpose()?,
            sparse,
            data_raw_file,
        })
    }
}

impl Drop for QcowDiskSync {
    fn drop(&mut self) {
        self.metadata.shutdown();
    }
}

impl disk_file::DiskSize for QcowDiskSync {
    fn logical_size(&self) -> BlockResult<u64> {
        Ok(self.metadata.virtual_size())
    }
}

impl disk_file::PhysicalSize for QcowDiskSync {
    fn physical_size(&self) -> BlockResult<u64> {
        Ok(self.data_raw_file.physical_size()?)
    }
}

impl disk_file::DiskFd for QcowDiskSync {
    fn fd(&self) -> BorrowedDiskFd<'_> {
        BorrowedDiskFd::new(self.data_raw_file.as_fd().as_raw_fd())
    }
}

impl disk_file::Geometry for QcowDiskSync {}

impl disk_file::SparseCapable for QcowDiskSync {
    fn supports_sparse_operations(&self) -> bool {
        true
    }

    fn supports_zero_flag(&self) -> bool {
        true
    }
}

impl disk_file::Resizable for QcowDiskSync {
    fn resize(&mut self, size: u64) -> BlockResult<()> {
        if self.backing_file.is_some() {
            return Err(BlockError::new(
                BlockErrorKind::UnsupportedFeature,
                DiskFileError::ResizeError(io::Error::other(
                    "resize not supported with backing file",
                )),
            )
            .with_op(ErrorOp::Resize));
        }
        self.metadata.resize(size).map_err(|e| {
            BlockError::new(BlockErrorKind::Io, DiskFileError::ResizeError(e))
                .with_op(ErrorOp::Resize)
        })
    }
}

impl disk_file::DiskFile for QcowDiskSync {}

impl disk_file::AsyncDiskFile for QcowDiskSync {
    fn try_clone(&self) -> BlockResult<Box<dyn disk_file::AsyncDiskFile>> {
        Ok(Box::new(QcowDiskSync {
            metadata: Arc::clone(&self.metadata),
            backing_file: self.backing_file.as_ref().map(Arc::clone),
            sparse: self.sparse,
            data_raw_file: self.data_raw_file.clone(),
        }))
    }

    // ring_depth is unused - this sync backend performs blocking I/O
    // instead of submitting to an async ring.
    fn create_async_io(&self, _ring_depth: u32) -> BlockResult<Box<dyn AsyncIo>> {
        Ok(Box::new(QcowSync::new(
            Arc::clone(&self.metadata),
            self.data_raw_file.clone(),
            self.backing_file.as_ref().map(Arc::clone),
            self.sparse,
        )))
    }
}

pub struct QcowSync {
    metadata: Arc<QcowMetadata>,
    data_file: QcowRawFile,
    /// See the backing_file field on QcowDiskSync.
    backing_file: Option<Arc<dyn BackingRead>>,
    sparse: bool,
    /// O_DIRECT alignment requirement (0 = no alignment needed).
    alignment: usize,
    cluster_size: u64,
    decoder: Arc<dyn Decoder>,
    eventfd: EventFd,
    completion_list: VecDeque<(u64, i32)>,
}

impl QcowSync {
    pub(crate) fn new(
        metadata: Arc<QcowMetadata>,
        data_file: QcowRawFile,
        backing_file: Option<Arc<dyn BackingRead>>,
        sparse: bool,
    ) -> Self {
        let alignment = data_file.file().alignment();
        QcowSync {
            cluster_size: metadata.cluster_size(),
            decoder: metadata.decoder(),
            metadata,
            data_file,
            backing_file,
            sparse,
            alignment,
            eventfd: EventFd::new(libc::EFD_NONBLOCK)
                .expect("Failed creating EventFd for QcowSync"),
            completion_list: VecDeque::new(),
        }
    }
}

impl AsyncIo for QcowSync {
    fn notifier(&self) -> &EventFd {
        &self.eventfd
    }

    fn read_vectored(
        &mut self,
        offset: libc::off_t,
        iovecs: &[libc::iovec],
        user_data: u64,
    ) -> AsyncIoResult<()> {
        let address = offset as u64;
        let total_len: usize = iovecs.iter().map(|v| v.iov_len).sum();

        let has_backing = self.backing_file.is_some();
        let mappings = self
            .metadata
            .map_clusters_for_read(address, total_len, has_backing)
            .map_err(AsyncIoError::ReadVectored)?;

        let mut buf_offset = 0usize;
        for mapping in mappings {
            match mapping {
                ClusterReadMapping::Zero { length } => {
                    // SAFETY: iovecs point to valid guest memory buffers
                    unsafe { zero_fill_iovecs(iovecs, buf_offset, length as usize) };
                    buf_offset += length as usize;
                }
                ClusterReadMapping::Allocated {
                    offset: host_offset,
                    length,
                } => {
                    let len = length as usize;
                    if self.alignment > 0 {
                        // O_DIRECT, aligned buffer avoids bounce copy.
                        let mut abuf = AlignedBuf::new(len, self.alignment)
                            .map_err(AsyncIoError::ReadVectored)?;
                        aligned_pread(
                            self.data_file.as_raw_fd(),
                            abuf.as_mut_slice(len),
                            host_offset,
                            self.alignment,
                        )
                        .map_err(AsyncIoError::ReadVectored)?;
                        // SAFETY: iovecs point to valid guest memory buffers
                        unsafe { scatter_to_iovecs(iovecs, buf_offset, abuf.as_slice(len)) };
                    } else {
                        // No O_DIRECT, plain buffer is fine.
                        let mut buf = vec![0u8; len];
                        pread_exact(self.data_file.as_raw_fd(), &mut buf, host_offset)
                            .map_err(AsyncIoError::ReadVectored)?;
                        // SAFETY: iovecs point to valid guest memory buffers
                        unsafe { scatter_to_iovecs(iovecs, buf_offset, &buf) };
                    }
                    buf_offset += len;
                }
                ClusterReadMapping::Compressed {
                    host_offset,
                    compressed_size,
                    cluster_offset,
                    length,
                } => {
                    let compressed =
                        pread_alloc(self.data_file.as_raw_fd(), host_offset, compressed_size)
                            .map_err(AsyncIoError::ReadVectored)?;
                    let decompressed =
                        decompress_cluster(&compressed, self.cluster_size as usize, &*self.decoder)
                            .map_err(AsyncIoError::ReadVectored)?;
                    // SAFETY: iovecs point to valid guest memory buffers
                    unsafe {
                        scatter_to_iovecs(
                            iovecs,
                            buf_offset,
                            &decompressed[cluster_offset..cluster_offset + length],
                        );
                    }
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
                    // SAFETY: iovecs point to valid guest memory buffers
                    unsafe { scatter_to_iovecs(iovecs, buf_offset, &buf) };
                    buf_offset += length as usize;
                }
            }
        }

        self.completion_list
            .push_back((user_data, total_len as i32));
        self.eventfd.write(1).unwrap();
        Ok(())
    }

    fn write_vectored(
        &mut self,
        offset: libc::off_t,
        iovecs: &[libc::iovec],
        user_data: u64,
    ) -> AsyncIoResult<()> {
        let address = offset as u64;
        let total_len: usize = iovecs.iter().map(|v| v.iov_len).sum();
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
                    if self.alignment > 0 {
                        // O_DIRECT, gather directly into aligned buffer.
                        let mut abuf = AlignedBuf::new(count, self.alignment)
                            .map_err(AsyncIoError::WriteVectored)?;
                        // SAFETY: iovecs point to valid guest memory buffers
                        unsafe {
                            gather_from_iovecs_into(iovecs, buf_offset, abuf.as_mut_slice(count));
                        }
                        aligned_pwrite(
                            self.data_file.as_raw_fd(),
                            abuf.as_slice(count),
                            host_offset,
                            self.alignment,
                        )
                        .map_err(AsyncIoError::WriteVectored)?;
                    } else {
                        // No O_DIRECT, plain buffer is fine.
                        // SAFETY: iovecs point to valid guest memory buffers
                        let buf = unsafe { gather_from_iovecs(iovecs, buf_offset, count) };
                        pwrite_all(self.data_file.as_raw_fd(), &buf, host_offset)
                            .map_err(AsyncIoError::WriteVectored)?;
                    }
                }
            }
            buf_offset += count;
        }

        self.completion_list
            .push_back((user_data, total_len as i32));
        self.eventfd.write(1).unwrap();
        Ok(())
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        self.metadata.flush().map_err(AsyncIoError::Fsync)?;
        if let Some(user_data) = user_data {
            self.completion_list.push_back((user_data, 0));
            self.eventfd.write(1).unwrap();
        }
        Ok(())
    }

    fn next_completed_request(&mut self) -> Option<(u64, i32)> {
        self.completion_list.pop_front()
    }

    fn punch_hole(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        let virtual_size = self.metadata.virtual_size();
        let cluster_size = self.cluster_size;

        let result = self
            .metadata
            .deallocate_bytes(
                offset,
                length as usize,
                self.sparse,
                virtual_size,
                cluster_size,
                self.backing_file.as_deref(),
            )
            .map_err(AsyncIoError::PunchHole);

        match result {
            Ok(actions) => {
                for action in actions {
                    match action {
                        DeallocAction::PunchHole {
                            host_offset,
                            length,
                        } => {
                            let _ = self.data_file.file_mut().punch_hole(host_offset, length);
                        }
                        DeallocAction::WriteZeroes {
                            host_offset,
                            length,
                        } => {
                            let _ = self
                                .data_file
                                .file_mut()
                                .write_zeroes_at(host_offset, length);
                        }
                    }
                }
                self.completion_list.push_back((user_data, 0));
                self.eventfd.write(1).unwrap();
                Ok(())
            }
            Err(e) => {
                let errno = if let AsyncIoError::PunchHole(ref io_err) = e {
                    -io_err.raw_os_error().unwrap_or(libc::EIO)
                } else {
                    -libc::EIO
                };
                self.completion_list.push_back((user_data, errno));
                self.eventfd.write(1).unwrap();
                Ok(())
            }
        }
    }

    fn write_zeroes(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        // For QCOW2 write_zeroes uses cluster deallocation, same as punch_hole.
        // Unallocated clusters inherently read as zero in the QCOW2 format.
        self.punch_hole(offset, length, user_data)
    }
}

#[cfg(test)]
mod unit_tests {
    use std::io::{Seek, SeekFrom, Write};
    use std::os::fd::RawFd;
    use std::thread;

    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::disk_file::{AsyncDiskFile, DiskSize, Resizable};
    use crate::qcow::{BackingFileConfig, ImageType, QcowFile, RawFile};
    use crate::qcow_common::unit_tests::compress_allocated_clusters;

    fn create_disk_with_data(
        file_size: u64,
        data: &[u8],
        offset: u64,
        sparse: bool,
        direct_io: bool,
    ) -> (TempFile, QcowDiskSync) {
        let temp_file = TempFile::new().unwrap();
        {
            let raw_file = RawFile::new(temp_file.as_file().try_clone().unwrap(), false);
            let mut qcow_file = QcowFile::new(raw_file, 3, file_size, sparse).unwrap();
            qcow_file.seek(SeekFrom::Start(offset)).unwrap();
            qcow_file.write_all(data).unwrap();
            qcow_file.flush().unwrap();
        }
        let disk = QcowDiskSync::new(
            temp_file.as_file().try_clone().unwrap(),
            direct_io,
            false,
            sparse,
        )
        .unwrap();
        (temp_file, disk)
    }

    fn async_read(disk: &QcowDiskSync, offset: u64, len: usize) -> Vec<u8> {
        let mut async_io = disk.create_async_io(1).unwrap();
        let mut buf = vec![0xFFu8; len];
        let iovec = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        async_io
            .read_vectored(offset as libc::off_t, &[iovec], 1)
            .unwrap();
        let (user_data, result) = async_io.next_completed_request().unwrap();
        assert_eq!(user_data, 1);
        assert_eq!(result as usize, len, "read should return requested length");
        buf
    }

    fn async_write(disk: &QcowDiskSync, offset: u64, data: &[u8]) {
        let mut async_io = disk.create_async_io(1).unwrap();
        let iovec = libc::iovec {
            iov_base: data.as_ptr() as *mut libc::c_void,
            iov_len: data.len(),
        };
        async_io
            .write_vectored(offset as libc::off_t, &[iovec], 1)
            .unwrap();
        let (user_data, result) = async_io.next_completed_request().unwrap();
        assert_eq!(user_data, 1);
        assert_eq!(result as usize, data.len());
    }

    #[test]
    fn test_qcow_async_punch_hole_completion() {
        let data = vec![0xDD; 128 * 1024];
        let offset = 0u64;
        let (_temp, disk) = create_disk_with_data(100 * 1024 * 1024, &data, offset, true, false);

        let mut async_io = disk.create_async_io(1).unwrap();
        async_io.punch_hole(offset, data.len() as u64, 100).unwrap();
        let (user_data, result) = async_io.next_completed_request().unwrap();
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
        let (user_data, result) = async_io.next_completed_request().unwrap();
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
    fn test_qcow_async_multiple_operations() {
        let data = vec![0xFF; 64 * 1024];
        let (_temp, _) = create_disk_with_data(100 * 1024 * 1024, &[], 0, true, false);

        // Write data at multiple offsets via QcowFile first, then punch
        {
            let temp_file = _temp.as_file().try_clone().unwrap();
            let raw_file = RawFile::new(temp_file, false);
            let mut qcow_file = QcowFile::from(raw_file).unwrap();
            for i in 0..4u64 {
                let off = i * 128 * 1024;
                qcow_file.seek(SeekFrom::Start(off)).unwrap();
                qcow_file.write_all(&data).unwrap();
            }
            qcow_file.flush().unwrap();
        }

        let disk =
            QcowDiskSync::new(_temp.as_file().try_clone().unwrap(), false, false, true).unwrap();

        let mut async_io = disk.create_async_io(1).unwrap();

        async_io.punch_hole(0, 64 * 1024, 1).unwrap();
        async_io.punch_hole(128 * 1024, 64 * 1024, 2).unwrap();
        async_io.punch_hole(256 * 1024, 64 * 1024, 3).unwrap();

        let (ud, res) = async_io.next_completed_request().unwrap();
        assert_eq!(ud, 1);
        assert_eq!(res, 0);
        let (ud, res) = async_io.next_completed_request().unwrap();
        assert_eq!(ud, 2);
        assert_eq!(res, 0);
        let (ud, res) = async_io.next_completed_request().unwrap();
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
        let (user_data, result) = async_io1.next_completed_request().unwrap();
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
        let (user_data, result) = async_io1.next_completed_request().unwrap();
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
        let (ud, res) = async_io.next_completed_request().unwrap();
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

        let overlay_temp = TempFile::new().unwrap();
        {
            let raw = RawFile::new(overlay_temp.as_file().try_clone().unwrap(), false);
            let backing_config = BackingFileConfig {
                path: backing_path,
                format: Some(ImageType::Raw),
            };
            let _overlay =
                QcowFile::new_from_backing(raw, 3, file_size, &backing_config, true).unwrap();
        }

        let file = overlay_temp.as_file().try_clone().unwrap();
        let disk = QcowDiskSync::new(file, direct_io, true, true).unwrap();

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

    fn test_backing_file_read_qcow2_backing_impl(direct_io: bool) {
        let backing_temp = TempFile::new().unwrap();
        let cluster_size = 1u64 << 16;
        let file_size = cluster_size * 4;
        let pattern: Vec<u8> = (0..file_size as usize).map(|i| (i % 251) as u8).collect();
        {
            let raw = RawFile::new(backing_temp.as_file().try_clone().unwrap(), false);
            let mut qcow = QcowFile::new(raw, 3, file_size, true).unwrap();
            qcow.seek(SeekFrom::Start(0)).unwrap();
            qcow.write_all(&pattern).unwrap();
            qcow.flush().unwrap();
        }
        let backing_path = backing_temp.as_path().to_str().unwrap().to_string();

        let overlay_temp = TempFile::new().unwrap();
        {
            let raw = RawFile::new(overlay_temp.as_file().try_clone().unwrap(), false);
            let backing_config = BackingFileConfig {
                path: backing_path,
                format: Some(ImageType::Qcow2),
            };
            let _overlay =
                QcowFile::new_from_backing(raw, 3, file_size, &backing_config, true).unwrap();
        }

        let file = overlay_temp.as_file().try_clone().unwrap();
        let disk = QcowDiskSync::new(file, direct_io, true, true).unwrap();

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
        let backing_temp = TempFile::new().unwrap();
        let cluster_size = 1u64 << 16;
        let file_size = cluster_size * 16;
        let pattern: Vec<u8> = (0..file_size as usize).map(|i| (i % 251) as u8).collect();
        {
            let raw = RawFile::new(backing_temp.as_file().try_clone().unwrap(), false);
            let mut qcow = QcowFile::new(raw, 3, file_size, true).unwrap();
            qcow.seek(SeekFrom::Start(0)).unwrap();
            qcow.write_all(&pattern).unwrap();
            qcow.flush().unwrap();
        }
        let backing_path = backing_temp.as_path().to_str().unwrap().to_string();

        let overlay_temp = TempFile::new().unwrap();
        {
            let raw = RawFile::new(overlay_temp.as_file().try_clone().unwrap(), false);
            let backing_config = BackingFileConfig {
                path: backing_path,
                format: Some(ImageType::Qcow2),
            };
            let _overlay =
                QcowFile::new_from_backing(raw, 3, file_size, &backing_config, true).unwrap();
        }

        let file = overlay_temp.as_file().try_clone().unwrap();
        let disk = Arc::new(QcowDiskSync::new(file, direct_io, true, true).unwrap());

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
        let mid_temp = TempFile::new().unwrap();
        let mid_pattern = vec![0xBBu8; cluster_size as usize];
        {
            let raw = RawFile::new(mid_temp.as_file().try_clone().unwrap(), false);
            let backing_config = BackingFileConfig {
                path: base_path,
                format: Some(ImageType::Raw),
            };
            let mut mid =
                QcowFile::new_from_backing(raw, 3, file_size, &backing_config, true).unwrap();
            mid.seek(SeekFrom::Start(0)).unwrap();
            mid.write_all(&mid_pattern).unwrap();
            mid.flush().unwrap();
        }
        let mid_path = mid_temp.as_path().to_str().unwrap().to_string();

        // Layer 2: qcow2 overlay pointing at qcow2 mid, write to cluster 1 only
        let overlay_temp = TempFile::new().unwrap();
        let overlay_pattern = vec![0xCCu8; cluster_size as usize];
        {
            let raw = RawFile::new(overlay_temp.as_file().try_clone().unwrap(), false);
            let backing_config = BackingFileConfig {
                path: mid_path,
                format: Some(ImageType::Qcow2),
            };
            let mut overlay =
                QcowFile::new_from_backing(raw, 3, file_size, &backing_config, true).unwrap();
            overlay.seek(SeekFrom::Start(cluster_size)).unwrap();
            overlay.write_all(&overlay_pattern).unwrap();
            overlay.flush().unwrap();
        }

        let file = overlay_temp.as_file().try_clone().unwrap();
        let disk = QcowDiskSync::new(file, direct_io, true, true).unwrap();

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

        let backing_temp = TempFile::new().unwrap();
        {
            let raw = RawFile::new(backing_temp.as_file().try_clone().unwrap(), false);
            let mut qcow = QcowFile::new(raw, 3, file_size, true).unwrap();
            qcow.seek(SeekFrom::Start(0)).unwrap();
            qcow.write_all(&pattern).unwrap();
            qcow.flush().unwrap();
        }
        let backing_path = backing_temp.as_path().to_str().unwrap().to_string();

        let overlay_temp = TempFile::new().unwrap();
        {
            let raw = RawFile::new(overlay_temp.as_file().try_clone().unwrap(), false);
            let backing_config = BackingFileConfig {
                path: backing_path,
                format: Some(ImageType::Qcow2),
            };
            let _overlay =
                QcowFile::new_from_backing(raw, 3, file_size, &backing_config, true).unwrap();
        }

        let file = overlay_temp.as_file().try_clone().unwrap();
        let disk = QcowDiskSync::new(file, direct_io, true, true).unwrap();

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

        let backing_temp = TempFile::new().unwrap();
        {
            let raw = RawFile::new(backing_temp.as_file().try_clone().unwrap(), false);
            let mut qcow = QcowFile::new(raw, 3, backing_size, true).unwrap();
            qcow.seek(SeekFrom::Start(0)).unwrap();
            qcow.write_all(&vec![0xAA; backing_size as usize]).unwrap();
            qcow.flush().unwrap();
        }
        let backing_path = backing_temp.as_path().to_str().unwrap().to_string();

        let overlay_temp = TempFile::new().unwrap();
        {
            let raw = RawFile::new(overlay_temp.as_file().try_clone().unwrap(), false);
            let backing_config = BackingFileConfig {
                path: backing_path,
                format: Some(ImageType::Qcow2),
            };
            let _overlay =
                QcowFile::new_from_backing(raw, 3, overlay_size, &backing_config, true).unwrap();
        }

        let file = overlay_temp.as_file().try_clone().unwrap();
        let disk = QcowDiskSync::new(file, direct_io, true, true).unwrap();

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

        let backing_temp = TempFile::new().unwrap();
        let backing_data = vec![0xBBu8; backing_size as usize];
        {
            let raw = RawFile::new(backing_temp.as_file().try_clone().unwrap(), false);
            let mut qcow = QcowFile::new(raw, 3, backing_size, true).unwrap();
            qcow.seek(SeekFrom::Start(0)).unwrap();
            qcow.write_all(&backing_data).unwrap();
            qcow.flush().unwrap();
        }
        let backing_path = backing_temp.as_path().to_str().unwrap().to_string();

        let overlay_temp = TempFile::new().unwrap();
        {
            let raw = RawFile::new(overlay_temp.as_file().try_clone().unwrap(), false);
            let backing_config = BackingFileConfig {
                path: backing_path,
                format: Some(ImageType::Qcow2),
            };
            let _overlay =
                QcowFile::new_from_backing(raw, 3, overlay_size, &backing_config, true).unwrap();
        }

        let file = overlay_temp.as_file().try_clone().unwrap();
        let disk = QcowDiskSync::new(file, direct_io, true, true).unwrap();

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

        let overlay_temp = TempFile::new().unwrap();
        {
            let raw = RawFile::new(overlay_temp.as_file().try_clone().unwrap(), false);
            let backing_config = BackingFileConfig {
                path: backing_path,
                format: Some(ImageType::Raw),
            };
            let _overlay =
                QcowFile::new_from_backing(raw, 3, overlay_size, &backing_config, true).unwrap();
        }

        let file = overlay_temp.as_file().try_clone().unwrap();
        let disk = QcowDiskSync::new(file, direct_io, true, true).unwrap();

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

        let backing_temp = TempFile::new().unwrap();
        {
            let raw = RawFile::new(backing_temp.as_file().try_clone().unwrap(), false);
            let mut qcow = QcowFile::new(raw, 3, file_size, true).unwrap();
            qcow.seek(SeekFrom::Start(0)).unwrap();
            qcow.write_all(&pattern).unwrap();
            qcow.flush().unwrap();
        }
        let backing_path = backing_temp.as_path().to_str().unwrap().to_string();

        let overlay_temp = TempFile::new().unwrap();
        {
            let raw = RawFile::new(overlay_temp.as_file().try_clone().unwrap(), false);
            let backing_config = BackingFileConfig {
                path: backing_path,
                format: Some(ImageType::Qcow2),
            };
            let _overlay =
                QcowFile::new_from_backing(raw, 3, file_size, &backing_config, true).unwrap();
        }

        let file = overlay_temp.as_file().try_clone().unwrap();
        let disk = QcowDiskSync::new(file, direct_io, true, true).unwrap();

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

        let overlay_temp = TempFile::new().unwrap();
        {
            let raw = RawFile::new(overlay_temp.as_file().try_clone().unwrap(), false);
            let backing_config = BackingFileConfig {
                path: backing_path,
                format: Some(ImageType::Raw),
            };
            let _overlay =
                QcowFile::new_from_backing(raw, 3, file_size, &backing_config, true).unwrap();
        }

        let file = overlay_temp.as_file().try_clone().unwrap();
        let disk = QcowDiskSync::new(file, direct_io, true, true).unwrap();

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
            let (ud, res) = async_io.next_completed_request().unwrap();
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

        let overlay_temp = TempFile::new().unwrap();
        {
            let raw = RawFile::new(overlay_temp.as_file().try_clone().unwrap(), false);
            let backing_config = BackingFileConfig {
                path: backing_path,
                format: Some(ImageType::Raw),
            };
            let _overlay =
                QcowFile::new_from_backing(raw, 3, file_size, &backing_config, true).unwrap();
        }

        let file = overlay_temp.as_file().try_clone().unwrap();
        let disk = QcowDiskSync::new(file, direct_io, true, true).unwrap();

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
            let (ud, res) = aio.next_completed_request().unwrap();
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

        let overlay_temp = TempFile::new().unwrap();
        {
            let raw = RawFile::new(overlay_temp.as_file().try_clone().unwrap(), false);
            let backing_config = BackingFileConfig {
                path: backing_path,
                format: Some(ImageType::Raw),
            };
            let _overlay =
                QcowFile::new_from_backing(raw, 3, file_size, &backing_config, true).unwrap();
        }

        let file = overlay_temp.as_file().try_clone().unwrap();
        let mut disk = QcowDiskSync::new(file, false, true, true).unwrap();

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
        let iovecs_w = [
            libc::iovec {
                iov_base: a.as_ptr() as *mut libc::c_void,
                iov_len: a.len(),
            },
            libc::iovec {
                iov_base: b.as_ptr() as *mut libc::c_void,
                iov_len: b.len(),
            },
            libc::iovec {
                iov_base: c.as_ptr() as *mut libc::c_void,
                iov_len: c.len(),
            },
        ];
        let total = a.len() + b.len() + c.len();

        let mut aio = disk.create_async_io(1).unwrap();
        aio.write_vectored(0, &iovecs_w, 1).unwrap();
        let (ud, res) = aio.next_completed_request().unwrap();
        assert_eq!(ud, 1);
        assert_eq!(res as usize, total);
        aio.fsync(Some(2)).unwrap();
        drop(aio);

        // Read back into 3 iovecs of different sizes
        let mut r1 = vec![0u8; 8 * 1024];
        let mut r2 = vec![0u8; 48 * 1024];
        let mut r3 = vec![0u8; 8 * 1024];
        let iovecs_r = [
            libc::iovec {
                iov_base: r1.as_mut_ptr() as *mut libc::c_void,
                iov_len: r1.len(),
            },
            libc::iovec {
                iov_base: r2.as_mut_ptr() as *mut libc::c_void,
                iov_len: r2.len(),
            },
            libc::iovec {
                iov_base: r3.as_mut_ptr() as *mut libc::c_void,
                iov_len: r3.len(),
            },
        ];

        let mut aio = disk.create_async_io(1).unwrap();
        aio.read_vectored(0, &iovecs_r, 10).unwrap();
        let (ud, res) = aio.next_completed_request().unwrap();
        assert_eq!(ud, 10);
        assert_eq!(res as usize, total);
        drop(aio);

        // Reassemble the read buffers into a flat vec
        let mut got = Vec::with_capacity(total);
        got.extend_from_slice(&r1);
        got.extend_from_slice(&r2);
        got.extend_from_slice(&r3);

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

    // -- Low level aligned I/O function tests --
    //
    // Test aligned_pread and aligned_pwrite directly with controlled
    // alignment values on a plain temp file.

    /// Create a temp file filled with a repeating pattern of the given size.
    /// Returns the TempFile (must be kept alive) and the raw fd.
    fn create_pattern_file(size: usize) -> (TempFile, RawFd) {
        let tf = TempFile::new().unwrap();
        let pattern: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        tf.as_file().write_all(&pattern).unwrap();
        tf.as_file().sync_all().unwrap();
        let fd = tf.as_file().as_raw_fd();
        (tf, fd)
    }

    #[test]
    fn test_aligned_pread_pass_through() {
        // When buffer address, length, and offset are all aligned,
        // aligned_pread should take the fast path (no bounce buffer).
        let size = 4096usize;
        let (_tf, fd) = create_pattern_file(size);
        let alignment = 512;

        // Use AlignedBuf to guarantee buffer address alignment.
        let mut abuf = AlignedBuf::new(size, alignment).unwrap();
        aligned_pread(fd, abuf.as_mut_slice(size), 0, alignment).unwrap();

        let expected: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        assert_eq!(abuf.as_slice(size), &expected[..]);
    }

    #[test]
    fn test_aligned_pread_bounce_unaligned_buffer() {
        // Force a misaligned buffer so aligned_pread must take the
        // bounce path. A plain vec![0u8; 4096] is often page-aligned
        // by the allocator, which would skip the bounce entirely.
        let size = 4096usize;
        let (_tf, fd) = create_pattern_file(size);
        let alignment = 512;

        let mut backing = vec![0u8; size + 1];
        let buf = &mut backing[1..size + 1];
        aligned_pread(fd, buf, 0, alignment).unwrap();

        let expected: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        assert_eq!(buf, &expected[..]);
    }

    #[test]
    fn test_aligned_pread_unaligned_offset() {
        // Read at an offset that is not a multiple of alignment.
        // aligned_pread should round down the offset, read an aligned
        // region, then copy the correct slice into the caller buffer.
        let file_size = 8192usize;
        let (_tf, fd) = create_pattern_file(file_size);
        let alignment = 512;

        let offset = 100u64;
        let len = 200usize;
        let mut buf = vec![0u8; len];
        aligned_pread(fd, &mut buf, offset, alignment).unwrap();

        let expected: Vec<u8> = (offset as usize..offset as usize + len)
            .map(|i| (i % 251) as u8)
            .collect();
        assert_eq!(buf, expected);
    }

    #[test]
    fn test_aligned_pwrite_pass_through() {
        // When buffer address, length, and offset are all aligned,
        // aligned_pwrite should take the fast path.
        let size = 4096usize;
        let (_tf, fd) = create_pattern_file(size);
        let alignment = 512;

        let data: Vec<u8> = (0..size).map(|i| ((i + 1) % 251) as u8).collect();
        let mut abuf = AlignedBuf::new(size, alignment).unwrap();
        abuf.as_mut_slice(size).copy_from_slice(&data);
        aligned_pwrite(fd, abuf.as_slice(size), 0, alignment).unwrap();

        let mut readback = vec![0u8; size];
        pread_exact(fd, &mut readback, 0).unwrap();
        assert_eq!(readback, data);
    }

    #[test]
    fn test_aligned_pwrite_bounce_unaligned_buffer() {
        // Force a misaligned buffer so aligned_pwrite must take the
        // bounce path. A plain vec![0u8; 4096] is often page-aligned
        // by the allocator, which would skip the bounce entirely.
        let size = 4096usize;
        let (_tf, fd) = create_pattern_file(size);
        let alignment = 512;

        let backing: Vec<u8> = (0..size + 1).map(|i| ((i + 1) % 251) as u8).collect();
        let data = &backing[1..size + 1];
        aligned_pwrite(fd, data, 0, alignment).unwrap();

        let mut readback = vec![0u8; size];
        pread_exact(fd, &mut readback, 0).unwrap();
        assert_eq!(readback, data);
    }

    #[test]
    fn test_aligned_pwrite_unaligned_offset() {
        // Write at an offset that is not a multiple of alignment.
        // aligned_pwrite should do read-modify-write and preserve
        // surrounding data.
        let file_size = 8192usize;
        let (_tf, fd) = create_pattern_file(file_size);
        let alignment = 512;

        let offset = 100u64;
        let len = 200usize;
        let data: Vec<u8> = (0..len).map(|i| ((i + 1) % 239) as u8).collect();
        aligned_pwrite(fd, &data, offset, alignment).unwrap();

        // Read entire file and verify the written region plus untouched areas.
        let mut whole = vec![0u8; file_size];
        pread_exact(fd, &mut whole, 0).unwrap();

        // Before the write region: original pattern.
        let before: Vec<u8> = (0..offset as usize).map(|i| (i % 251) as u8).collect();
        assert_eq!(&whole[..offset as usize], &before[..]);

        // The written region.
        assert_eq!(&whole[offset as usize..offset as usize + len], &data[..]);

        // After the write region: original pattern.
        let after_start = offset as usize + len;
        let after: Vec<u8> = (after_start..file_size).map(|i| (i % 251) as u8).collect();
        assert_eq!(&whole[after_start..], &after[..]);
    }

    #[test]
    fn test_aligned_pread_pwrite_4096_alignment() {
        // Exercise aligned I/O with 4096 byte alignment.
        let file_size = 16384usize;
        let (_tf, fd) = create_pattern_file(file_size);
        let alignment = 4096;

        // Write 4096 bytes at offset 4096 via unaligned Vec<u8>.
        let offset = 4096u64;
        let len = 4096usize;
        let data: Vec<u8> = (0..len).map(|i| ((i + 1) % 239) as u8).collect();
        aligned_pwrite(fd, &data, offset, alignment).unwrap();

        // Read back the written region via unaligned Vec<u8>.
        let mut buf = vec![0u8; len];
        aligned_pread(fd, &mut buf, offset, alignment).unwrap();
        assert_eq!(buf, data);

        // Verify untouched regions.
        let mut whole = vec![0u8; file_size];
        pread_exact(fd, &mut whole, 0).unwrap();
        let before: Vec<u8> = (0..offset as usize).map(|i| (i % 251) as u8).collect();
        assert_eq!(&whole[..offset as usize], &before[..]);
        let after_start = offset as usize + len;
        let after: Vec<u8> = (after_start..file_size).map(|i| (i % 251) as u8).collect();
        assert_eq!(&whole[after_start..], &after[..]);
    }

    #[test]
    fn test_aligned_buf_allocation_and_access() {
        for alignment in [512, 4096] {
            let size = 1024usize;
            let mut abuf = AlignedBuf::new(size, alignment).unwrap();
            let aligned_size = size.next_multiple_of(alignment);

            assert!(
                (abuf.ptr() as usize).is_multiple_of(alignment),
                "ptr not aligned to {alignment}"
            );
            assert!(abuf.as_slice(aligned_size).iter().all(|&b| b == 0));

            let pattern: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            abuf.as_mut_slice(size).copy_from_slice(&pattern);
            assert_eq!(abuf.as_slice(size), &pattern[..]);
        }
    }

    #[test]
    fn test_aligned_buf_size_rounds_up() {
        let abuf = AlignedBuf::new(1, 512).unwrap();
        assert_eq!(abuf.layout().size(), 512);

        let abuf = AlignedBuf::new(513, 512).unwrap();
        assert_eq!(abuf.layout().size(), 1024);
    }

    #[test]
    fn test_compressed_read() {
        let cluster_size = 65536usize;
        let data: Vec<u8> = (0..=255).cycle().take(cluster_size).collect();
        let (temp, disk) = create_disk_with_data(100 * 1024 * 1024, &data, 0, false, false);
        drop(disk);

        compress_allocated_clusters(&mut temp.as_file().try_clone().unwrap());

        let disk =
            QcowDiskSync::new(temp.as_file().try_clone().unwrap(), false, false, false).unwrap();

        let buf = async_read(&disk, 0, cluster_size);
        assert_eq!(buf, data);
    }
}
