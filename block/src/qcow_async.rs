// Copyright © 2021 Intel Corporation
//
// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

//! QCOW2 async disk backend.

use std::cmp::{max, min};
use std::io;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::write_zeroes::{PunchHole, WriteZeroesAt};

use crate::async_io::{
    AsyncIo, AsyncIoCompletion, AsyncIoError, AsyncIoOperation, AsyncIoResult, UringDataIo,
};
use crate::qcow::decoder::Decoder;
use crate::qcow::metadata::{
    BackingRead, ClusterReadMapping, ClusterWriteMapping, DeallocAction, QcowMetadata,
};
use crate::qcow::qcow_raw_file::QcowRawFile;
use crate::qcow_common::{
    AlignedBuf, aligned_pread, aligned_pwrite, decompress_cluster, gather_from_iovecs_into,
    pread_alloc, pread_exact, pwrite_all, scatter_to_iovecs, zero_fill_iovecs,
};
use crate::{BatchRequest, RequestType, SECTOR_SIZE};

/// Per queue QCOW2 I/O worker using io_uring.
///
/// Reads against fully allocated single mapping clusters are submitted
/// to io_uring for true asynchronous completion. All other cluster
/// types (zero, compressed, backing) and multi mapping reads fall back
/// to synchronous I/O with synthetic completions.
///
/// Writes are synchronous because metadata allocation must complete
/// before the host offset is known.
pub struct QcowAsync {
    metadata: Arc<QcowMetadata>,
    data_file: QcowRawFile,
    backing_file: Option<Arc<dyn BackingRead>>,
    sparse: bool,
    /// O_DIRECT alignment requirement (0 = no alignment needed).
    alignment: usize,
    /// I/O alignment for the AsyncIo trait (at least SECTOR_SIZE).
    io_alignment: u64,
    cluster_size: u64,
    decoder: Arc<dyn Decoder>,
    data_io: UringDataIo,
}

impl QcowAsync {
    pub(crate) fn new(
        metadata: Arc<QcowMetadata>,
        data_file: QcowRawFile,
        backing_file: Option<Arc<dyn BackingRead>>,
        sparse: bool,
        ring_depth: u32,
    ) -> io::Result<Self> {
        let alignment = data_file.file().alignment();
        let io_alignment = max(alignment as u64, SECTOR_SIZE);

        Ok(QcowAsync {
            cluster_size: metadata.cluster_size(),
            decoder: metadata.decoder(),
            metadata,
            data_file,
            backing_file,
            sparse,
            alignment,
            io_alignment,
            data_io: UringDataIo::new(ring_depth)?,
        })
    }

    fn apply_dealloc_action(&mut self, action: &DeallocAction) {
        match action {
            DeallocAction::PunchHole {
                host_offset,
                length,
            } => {
                let _ = self.data_file.file_mut().punch_hole(*host_offset, *length);
            }
            DeallocAction::WriteZeroes {
                host_offset,
                length,
            } => {
                let _ = self
                    .data_file
                    .file_mut()
                    .write_zeroes_at(*host_offset, *length);
            }
        }
    }

    fn async_error_result(error: &AsyncIoError) -> i32 {
        let io_error = match error {
            AsyncIoError::ReadVectored(e)
            | AsyncIoError::WriteVectored(e)
            | AsyncIoError::SubmitBatchRequests(e)
            | AsyncIoError::Fsync(e)
            | AsyncIoError::PunchHole(e)
            | AsyncIoError::WriteZeroes(e) => e,
        };
        -io_error.raw_os_error().unwrap_or(libc::EIO)
    }

    fn inject_operation_completion(&mut self, op: AsyncIoOperation, result: i32) {
        self.data_io
            .inject_completion(AsyncIoCompletion::from_operation(op, result));
    }

    fn prepare_read_operation(
        &mut self,
        mut op: AsyncIoOperation,
    ) -> Result<Option<AsyncIoOperation>, Box<(AsyncIoOperation, AsyncIoError)>> {
        let total_len = op.total_len();
        let host_offset = match Self::resolve_read(
            &self.metadata,
            &self.data_file,
            &self.backing_file,
            op.offset() as u64,
            op.iovecs(),
            total_len,
            self.alignment,
            self.cluster_size,
            &*self.decoder,
        ) {
            Ok(host_offset) => host_offset,
            Err(e) => return Err(Box::new((op, e))),
        };

        if let Some(host_offset) = host_offset {
            op.set_offset(host_offset as libc::off_t);
            Ok(Some(op))
        } else {
            self.inject_operation_completion(op, total_len as i32);
            Ok(None)
        }
    }

    fn complete_write_operation_sync(
        &mut self,
        op: AsyncIoOperation,
    ) -> Result<(), Box<(AsyncIoOperation, AsyncIoError)>> {
        // TODO Make writes async.
        // Writes are synchronous. Async writes require a multi step
        // state machine for COW (backing read, cluster allocation, data
        // write, L2 commit) with per request buffer lifetime tracking
        // and write ordering.
        let total_len = op.total_len();
        if let Err(e) = Self::cow_write_sync(
            op.offset() as u64,
            op.iovecs(),
            &self.metadata,
            &self.data_file,
            &self.backing_file,
            self.alignment,
            self.cluster_size,
        ) {
            return Err(Box::new((op, e)));
        }

        self.inject_operation_completion(op, total_len as i32);
        Ok(())
    }
}

impl AsyncIo for QcowAsync {
    fn notifier(&self) -> &EventFd {
        self.data_io.notifier()
    }

    fn read_vectored(
        &mut self,
        offset: libc::off_t,
        iovecs: &[libc::iovec],
        user_data: u64,
    ) -> AsyncIoResult<()> {
        let total_len: usize = iovecs.iter().map(|v| v.iov_len).sum();

        if let Some(host_offset) = Self::resolve_read(
            &self.metadata,
            &self.data_file,
            &self.backing_file,
            offset as u64,
            iovecs,
            total_len,
            self.alignment,
            self.cluster_size,
            &*self.decoder,
        )? {
            // SAFETY: this legacy trait method's caller must keep the
            // borrowed iovecs and writable buffers valid until completion.
            unsafe {
                self.data_io.submit_borrowed_operation(
                    self.data_file.as_raw_fd(),
                    host_offset as libc::off_t,
                    true,
                    iovecs,
                    user_data,
                )
            }
            .map_err(AsyncIoError::ReadVectored)?;
        } else {
            self.data_io.inject_completion(AsyncIoCompletion::new(
                user_data,
                total_len as i32,
                None,
            ));
        }
        Ok(())
    }

    fn write_vectored(
        &mut self,
        offset: libc::off_t,
        iovecs: &[libc::iovec],
        user_data: u64,
    ) -> AsyncIoResult<()> {
        Self::cow_write_sync(
            offset as u64,
            iovecs,
            &self.metadata,
            &self.data_file,
            &self.backing_file,
            self.alignment,
            self.cluster_size,
        )?;

        let total_len: usize = iovecs.iter().map(|v| v.iov_len).sum();
        self.data_io
            .inject_completion(AsyncIoCompletion::new(user_data, total_len as i32, None));
        Ok(())
    }

    fn submit_data_operation(&mut self, op: AsyncIoOperation) -> AsyncIoResult<()> {
        if op.is_read() {
            match self.prepare_read_operation(op) {
                Ok(Some(op)) => {
                    self.data_io
                        .submit_operation(self.data_file.as_raw_fd(), op)
                        .map_err(AsyncIoError::ReadVectored)?;
                }
                Ok(None) => {}
                Err(e) => return Err(e.1),
            }
            Ok(())
        } else {
            self.complete_write_operation_sync(op).map_err(|e| e.1)
        }
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        self.metadata.flush().map_err(AsyncIoError::Fsync)?;
        if let Some(user_data) = user_data {
            self.data_io
                .inject_completion(AsyncIoCompletion::new(user_data, 0, None));
        }
        Ok(())
    }

    fn next_completion(&mut self) -> Option<AsyncIoCompletion> {
        self.data_io.next_completion()
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
            .map_err(AsyncIoError::PunchHole);

        match result {
            Ok(actions) => {
                for action in &actions {
                    self.apply_dealloc_action(action);
                }
                self.data_io
                    .inject_completion(AsyncIoCompletion::new(user_data, 0, None));
                Ok(())
            }
            Err(e) => {
                let errno = if let AsyncIoError::PunchHole(ref io_err) = e {
                    -io_err.raw_os_error().unwrap_or(libc::EIO)
                } else {
                    -libc::EIO
                };
                self.data_io
                    .inject_completion(AsyncIoCompletion::new(user_data, errno, None));
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
            .map_err(AsyncIoError::WriteZeroes);

        match result {
            Ok(actions) => {
                for action in &actions {
                    self.apply_dealloc_action(action);
                }
                self.data_io
                    .inject_completion(AsyncIoCompletion::new(user_data, 0, None));
                Ok(())
            }
            Err(e) => {
                let errno = if let AsyncIoError::WriteZeroes(ref io_err) = e {
                    -io_err.raw_os_error().unwrap_or(libc::EIO)
                } else {
                    -libc::EIO
                };
                self.data_io
                    .inject_completion(AsyncIoCompletion::new(user_data, errno, None));
                Ok(())
            }
        }
    }

    fn batch_requests_enabled(&self) -> bool {
        true
    }

    fn alignment(&self) -> u64 {
        self.io_alignment
    }

    fn submit_batch_requests(&mut self, batch_request: &[BatchRequest]) -> AsyncIoResult<()> {
        let mut async_reads = Vec::new();

        for req in batch_request {
            match req.request_type {
                RequestType::In => {
                    let total_len: usize = req.iovecs.iter().map(|v| v.iov_len).sum();

                    if let Some(host_offset) = Self::resolve_read(
                        &self.metadata,
                        &self.data_file,
                        &self.backing_file,
                        req.offset as u64,
                        &req.iovecs,
                        total_len,
                        self.alignment,
                        self.cluster_size,
                        &*self.decoder,
                    )? {
                        async_reads.push((
                            host_offset as libc::off_t,
                            true,
                            req.iovecs.as_slice(),
                            req.user_data,
                        ));
                    } else {
                        self.data_io.inject_completion(AsyncIoCompletion::new(
                            req.user_data,
                            total_len as i32,
                            None,
                        ));
                    }
                }
                RequestType::Out => {
                    let total_len: usize = req.iovecs.iter().map(|v| v.iov_len).sum();
                    Self::cow_write_sync(
                        req.offset as u64,
                        &req.iovecs,
                        &self.metadata,
                        &self.data_file,
                        &self.backing_file,
                        self.alignment,
                        self.cluster_size,
                    )?;
                    self.data_io.inject_completion(AsyncIoCompletion::new(
                        req.user_data,
                        total_len as i32,
                        None,
                    ));
                }
                _ => unreachable!("Unexpected batch request type: {:?}", req.request_type),
            }
        }

        if !async_reads.is_empty() {
            // SAFETY: this legacy trait method's caller must keep every
            // borrowed iovec array and buffer valid until its completion.
            unsafe {
                self.data_io
                    .submit_borrowed_batch(self.data_file.as_raw_fd(), &async_reads)
            }
            .map_err(AsyncIoError::SubmitBatchRequests)?;
        }

        Ok(())
    }

    fn submit_batch_operations(
        &mut self,
        batch_request: Vec<AsyncIoOperation>,
    ) -> AsyncIoResult<()> {
        let mut async_reads = Vec::new();

        for op in batch_request {
            if op.is_read() {
                match self.prepare_read_operation(op) {
                    Ok(Some(op)) => async_reads.push(op),
                    Ok(None) => {}
                    Err(boxed) => {
                        let (op, e) = *boxed;
                        // The operation was not submitted to the kernel. Accept
                        // it at the qcow layer and surface the failure through
                        // the common completion path so batch acceptance remains
                        // all-or-none for the virtqueue.
                        let result = Self::async_error_result(&e);
                        self.inject_operation_completion(op, result);
                    }
                }
            } else if let Err(boxed) = self.complete_write_operation_sync(op) {
                let (op, e) = *boxed;
                let result = Self::async_error_result(&e);
                self.inject_operation_completion(op, result);
            }
        }

        if !async_reads.is_empty() {
            self.data_io
                .submit_batch(self.data_file.as_raw_fd(), async_reads)
                .map_err(AsyncIoError::SubmitBatchRequests)?;
        }

        Ok(())
    }
}

impl QcowAsync {
    /// Resolves read mappings for a guest read request.
    ///
    /// Returns `Some(host_offset)` if the entire read falls within a single
    /// allocated cluster (fast path). Otherwise handles the read
    /// synchronously via `scatter_read_sync` and returns `None`.
    #[allow(clippy::too_many_arguments)]
    fn resolve_read(
        metadata: &QcowMetadata,
        data_file: &QcowRawFile,
        backing_file: &Option<Arc<dyn BackingRead>>,
        address: u64,
        iovecs: &[libc::iovec],
        total_len: usize,
        alignment: usize,
        cluster_size: u64,
        decoder: &dyn Decoder,
    ) -> AsyncIoResult<Option<u64>> {
        let has_backing = backing_file.is_some();
        let mappings = metadata
            .map_clusters_for_read(address, total_len, has_backing)
            .map_err(AsyncIoError::ReadVectored)?;

        // The fast path returns a host offset so the caller can submit a
        // single io_uring readv with the original iovecs.  This only works
        // without O_DIRECT because it requires I/O
        // size and file offset to be multiples of the device sector size.
        // Guest requests can be smaller (e.g. 512 byte UEFI reads on a
        // 4096 byte sector device), so O_DIRECT reads fall through to the
        // alignment aware synchronous path instead.
        if alignment == 0
            && mappings.len() == 1
            && let ClusterReadMapping::Allocated {
                offset: host_offset,
                length,
            } = &mappings[0]
            && *length as usize == total_len
        {
            return Ok(Some(*host_offset));
        }

        Self::scatter_read_sync(
            mappings,
            iovecs,
            data_file,
            backing_file,
            alignment,
            cluster_size,
            decoder,
        )?;
        Ok(None)
    }

    /// Scatter-read cluster mappings synchronously into iovec buffers.
    fn scatter_read_sync(
        mappings: Vec<ClusterReadMapping>,
        iovecs: &[libc::iovec],
        data_file: &QcowRawFile,
        backing_file: &Option<Arc<dyn BackingRead>>,
        alignment: usize,
        cluster_size: u64,
        decoder: &dyn Decoder,
    ) -> AsyncIoResult<()> {
        let mut buf_offset = 0usize;
        for mapping in mappings {
            match mapping {
                ClusterReadMapping::Zero { length } => {
                    // SAFETY: iovecs point to valid guest memory buffers.
                    unsafe {
                        zero_fill_iovecs(iovecs, buf_offset, length as usize);
                    }
                    buf_offset += length as usize;
                }
                ClusterReadMapping::Allocated {
                    offset: host_offset,
                    length,
                } => {
                    let len = length as usize;
                    if alignment > 0 {
                        let mut abuf =
                            AlignedBuf::new(len, alignment).map_err(AsyncIoError::ReadVectored)?;
                        aligned_pread(
                            data_file.as_raw_fd(),
                            abuf.as_mut_slice(len),
                            host_offset,
                            alignment,
                        )
                        .map_err(AsyncIoError::ReadVectored)?;
                        // SAFETY: iovecs point to valid guest memory buffers.
                        unsafe { scatter_to_iovecs(iovecs, buf_offset, abuf.as_slice(len)) };
                    } else {
                        let mut buf = vec![0u8; len];
                        pread_exact(data_file.as_raw_fd(), &mut buf, host_offset)
                            .map_err(AsyncIoError::ReadVectored)?;
                        // SAFETY: iovecs point to valid guest memory buffers.
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
                        pread_alloc(data_file.as_raw_fd(), host_offset, compressed_size)
                            .map_err(AsyncIoError::ReadVectored)?;
                    let decompressed =
                        decompress_cluster(&compressed, cluster_size as usize, decoder)
                            .map_err(AsyncIoError::ReadVectored)?;
                    // SAFETY: iovecs point to valid guest memory buffers.
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
                    backing_file
                        .as_ref()
                        .unwrap()
                        .read_at(backing_offset, &mut buf)
                        .map_err(AsyncIoError::ReadVectored)?;
                    // SAFETY: iovecs point to valid guest memory buffers.
                    unsafe { scatter_to_iovecs(iovecs, buf_offset, &buf) };
                    buf_offset += length as usize;
                }
            }
        }
        Ok(())
    }

    /// Write iovec data cluster-by-cluster with COW from backing file.
    fn cow_write_sync(
        address: u64,
        iovecs: &[libc::iovec],
        metadata: &QcowMetadata,
        data_file: &QcowRawFile,
        backing_file: &Option<Arc<dyn BackingRead>>,
        alignment: usize,
        cluster_size: u64,
    ) -> AsyncIoResult<()> {
        let total_len: usize = iovecs.iter().map(|v| v.iov_len).sum();
        let mut buf_offset = 0usize;

        while buf_offset < total_len {
            let curr_addr = address + buf_offset as u64;
            let intra_offset = curr_addr & (cluster_size - 1);
            let remaining_in_cluster = (cluster_size - intra_offset) as usize;
            let count = min(total_len - buf_offset, remaining_in_cluster);

            let backing_data = if let Some(backing) = backing_file
                .as_ref()
                .filter(|_| intra_offset != 0 || count < cluster_size as usize)
            {
                let cluster_begin = curr_addr - intra_offset;
                let mut data = vec![0u8; cluster_size as usize];
                backing
                    .read_at(cluster_begin, &mut data)
                    .map_err(AsyncIoError::WriteVectored)?;
                Some(data)
            } else {
                None
            };

            let mapping = metadata
                .map_cluster_for_write(curr_addr, backing_data)
                .map_err(AsyncIoError::WriteVectored)?;

            match mapping {
                ClusterWriteMapping::Allocated {
                    offset: host_offset,
                } => {
                    if alignment > 0 {
                        // O_DIRECT, gather directly into aligned buffer.
                        let mut abuf = AlignedBuf::new(count, alignment)
                            .map_err(AsyncIoError::WriteVectored)?;
                        // SAFETY: iovecs point to valid guest memory buffers
                        unsafe {
                            gather_from_iovecs_into(iovecs, buf_offset, abuf.as_mut_slice(count));
                        }
                        aligned_pwrite(
                            data_file.as_raw_fd(),
                            abuf.as_slice(count),
                            host_offset,
                            alignment,
                        )
                        .map_err(AsyncIoError::WriteVectored)?;
                    } else {
                        // No O_DIRECT, plain buffer is fine.
                        let mut buf = vec![0u8; count];
                        // SAFETY: iovecs point to valid guest memory buffers.
                        unsafe {
                            gather_from_iovecs_into(iovecs, buf_offset, &mut buf);
                        }
                        pwrite_all(data_file.as_raw_fd(), &buf, host_offset)
                            .map_err(AsyncIoError::WriteVectored)?;
                    }
                }
            }
            buf_offset += count;
        }
        Ok(())
    }
}

#[cfg(test)]
mod unit_tests {
    use std::io::{Seek, SeekFrom, Write};
    use std::sync::Arc;
    use std::thread;

    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::SECTOR_SIZE;
    use crate::async_io::{AsyncIoCompletion, AsyncIoOperation, OwnedIoBuffer};
    use crate::disk_file::AsyncDiskFile;
    use crate::qcow::{BackingFileConfig, ImageType, QcowFile, RawFile};
    use crate::qcow_common::unit_tests::compress_allocated_clusters;
    use crate::qcow_disk::QcowDisk;

    fn create_disk_with_data(
        file_size: u64,
        data: &[u8],
        offset: u64,
        sparse: bool,
    ) -> (TempFile, QcowDisk) {
        let temp_file = TempFile::new().unwrap();
        {
            let raw_file = RawFile::new(temp_file.as_file().try_clone().unwrap(), false);
            let mut qcow_file = QcowFile::new(raw_file, 3, file_size, sparse).unwrap();
            qcow_file.seek(SeekFrom::Start(offset)).unwrap();
            qcow_file.write_all(data).unwrap();
            qcow_file.flush().unwrap();
        }
        let disk = QcowDisk::new(
            temp_file.as_file().try_clone().unwrap(),
            false,
            false,
            sparse,
            true,
        )
        .unwrap();
        (temp_file, disk)
    }

    fn create_overlay_disk_with_raw_backing_pattern(
        file_size: u64,
        value: u8,
    ) -> (TempFile, TempFile, QcowDisk) {
        let backing_temp = TempFile::new().unwrap();
        let backing_data = vec![value; file_size as usize];
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
            QcowFile::new_from_backing(raw, 3, file_size, &backing_config, true).unwrap();
        }

        let disk = QcowDisk::new(
            overlay_temp.as_file().try_clone().unwrap(),
            false,
            true,
            true,
            true,
        )
        .unwrap();

        (backing_temp, overlay_temp, disk)
    }

    fn wait_for_completion(async_io: &mut dyn AsyncIo) -> AsyncIoCompletion {
        loop {
            if let Some(c) = async_io.next_completion() {
                return c;
            }
            // Block until the eventfd is signaled (io_uring or synthetic).
            let fd = async_io.notifier().as_raw_fd();
            let mut val = 0u64;
            // SAFETY: reading 8 bytes from a valid eventfd.
            unsafe {
                libc::read(fd, (&raw mut val).cast(), 8);
            }
        }
    }

    fn completion_tuple(completion: &AsyncIoCompletion) -> (u64, i32) {
        (completion.user_data, completion.result)
    }

    fn async_write(disk: &QcowDisk, offset: u64, data: &[u8]) {
        let mut async_io = disk.create_async_io(1).unwrap();
        async_io
            .write_from_vec(
                offset as libc::off_t,
                OwnedIoBuffer::from_vec(data.to_vec()),
                2,
            )
            .unwrap();
        let completion = wait_for_completion(async_io.as_mut());
        let (user_data, result) = completion_tuple(&completion);
        assert_eq!(user_data, 2);
        assert_eq!(
            result as usize,
            data.len(),
            "write should return requested length"
        );
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
        let mut completion = wait_for_completion(async_io.as_mut());
        let (user_data, result) = completion_tuple(&completion);
        assert_eq!(user_data, 1);
        assert_eq!(result as usize, len, "read should return requested length");
        match completion.buffer.take() {
            Some(buffer) => buffer.as_slice().to_vec(),
            other => panic!("unexpected read completion: {other:?}"),
        }
    }

    #[test]
    fn test_qcow_async_punch_hole_completion() {
        let data = vec![0xDD; 128 * 1024];
        let offset = 0u64;
        let (_temp, disk) = create_disk_with_data(100 * 1024 * 1024, &data, offset, true);

        let mut async_io = disk.create_async_io(1).unwrap();
        async_io.punch_hole(offset, data.len() as u64, 100).unwrap();
        let completion = async_io.next_completion().unwrap();
        let (user_data, result) = completion_tuple(&completion);
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
        let data = vec![0xAA; 128 * 1024];
        let offset = 0u64;
        let (_temp, disk) = create_disk_with_data(100 * 1024 * 1024, &data, offset, true);

        let mut async_io = disk.create_async_io(1).unwrap();
        async_io
            .write_zeroes(offset, data.len() as u64, 200)
            .unwrap();
        let completion = async_io.next_completion().unwrap();
        let (user_data, result) = completion_tuple(&completion);
        assert_eq!(user_data, 200);
        assert_eq!(result, 0, "write_zeroes should succeed");
        drop(async_io);

        let read_buf = async_read(&disk, offset, data.len());
        assert!(
            read_buf.iter().all(|&b| b == 0),
            "Write zeroes region should read as zeros"
        );
    }

    #[test]
    fn test_qcow_async_write_zeroes_unallocated_overlay_with_backing_must_read_zero() {
        let cluster_size = 1u64 << 16;
        let file_size = cluster_size * 4;
        let offset = cluster_size;
        let (_backing_temp, _overlay_temp, disk) =
            create_overlay_disk_with_raw_backing_pattern(file_size, 0xAB);

        let mut async_io = disk.create_async_io(1).unwrap();
        async_io.write_zeroes(offset, cluster_size, 201).unwrap();
        let completion = wait_for_completion(async_io.as_mut());
        let (user_data, result) = completion_tuple(&completion);
        assert_eq!(user_data, 201);
        assert_eq!(result, 0, "write_zeroes should succeed");
        drop(async_io);

        let read_buf = async_read(&disk, offset, cluster_size as usize);
        assert!(
            read_buf.iter().all(|&b| b == 0),
            "zeroed unallocated overlay cluster exposed backing data"
        );
    }

    #[test]
    fn test_qcow_async_write_read_roundtrip() {
        let file_size = 100 * 1024 * 1024;
        let temp_file = TempFile::new().unwrap();
        {
            let raw_file = RawFile::new(temp_file.as_file().try_clone().unwrap(), false);
            QcowFile::new(raw_file, 3, file_size, true).unwrap();
        }
        let disk = QcowDisk::new(
            temp_file.as_file().try_clone().unwrap(),
            false,
            false,
            true,
            true,
        )
        .unwrap();

        let pattern: Vec<u8> = (0..128 * 1024).map(|i| (i % 251) as u8).collect();
        let offset = 64 * 1024;

        async_write(&disk, offset, &pattern);
        let read_buf = async_read(&disk, offset, pattern.len());
        assert_eq!(read_buf, pattern, "read should match written data");
    }

    #[test]
    fn test_qcow_async_read_spanning_cluster_boundary() {
        let cluster_size: u64 = 65536;
        let file_size = 100 * 1024 * 1024;

        // Write distinct patterns into two adjacent clusters.
        let pattern_a = vec![0xAA; cluster_size as usize];
        let pattern_b = vec![0xBB; cluster_size as usize];
        let (_temp, disk) = create_disk_with_data(file_size, &pattern_a, 0, true);
        async_write(&disk, cluster_size, &pattern_b);

        // Read across the boundary: last 4K of cluster 0 + first 4K of cluster 1.
        let read_offset = cluster_size - 4096;
        let read_len = 8192;
        let buf = async_read(&disk, read_offset, read_len);

        assert!(
            buf[..4096].iter().all(|&b| b == 0xAA),
            "first half should come from cluster 0"
        );
        assert!(
            buf[4096..].iter().all(|&b| b == 0xBB),
            "second half should come from cluster 1"
        );
    }

    #[test]
    fn test_qcow_async_batch_mixed_requests() {
        let file_size = 100 * 1024 * 1024;
        let temp_file = TempFile::new().unwrap();
        {
            let raw_file = RawFile::new(temp_file.as_file().try_clone().unwrap(), false);
            QcowFile::new(raw_file, 3, file_size, true).unwrap();
        }
        let disk = QcowDisk::new(
            temp_file.as_file().try_clone().unwrap(),
            false,
            false,
            true,
            true,
        )
        .unwrap();

        let mut async_io = disk.create_async_io(8).unwrap();

        // Prepare write data for two regions.
        let write_a = vec![0xAA; 4096];
        let write_b = vec![0xBB; 4096];
        let offset_a: u64 = 0;
        let offset_b: u64 = 65536;

        let batch = vec![
            AsyncIoOperation::write_from_vec(
                offset_a as libc::off_t,
                OwnedIoBuffer::from_vec(write_a.clone()),
                10,
            ),
            AsyncIoOperation::write_from_vec(
                offset_b as libc::off_t,
                OwnedIoBuffer::from_vec(write_b.clone()),
                20,
            ),
        ];

        async_io.submit_batch_operations(batch).unwrap();

        let mut completions = [
            completion_tuple(&wait_for_completion(async_io.as_mut())),
            completion_tuple(&wait_for_completion(async_io.as_mut())),
        ];
        completions.sort_by_key(|c| c.0);
        assert_eq!(completions[0], (10, 4096));
        assert_eq!(completions[1], (20, 4096));
        drop(async_io);

        // Batch read both regions back.
        let mut async_io = disk.create_async_io(8).unwrap();
        let read_batch = vec![
            AsyncIoOperation::read_to_vec(
                offset_a as libc::off_t,
                OwnedIoBuffer::from_vec(vec![0; 4096]),
                30,
            ),
            AsyncIoOperation::read_to_vec(
                offset_b as libc::off_t,
                OwnedIoBuffer::from_vec(vec![0; 4096]),
                40,
            ),
        ];

        async_io.submit_batch_operations(read_batch).unwrap();

        let mut completion_a = wait_for_completion(async_io.as_mut());
        let mut completion_b = wait_for_completion(async_io.as_mut());
        if completion_a.user_data > completion_b.user_data {
            std::mem::swap(&mut completion_a, &mut completion_b);
        }
        assert_eq!(completion_tuple(&completion_a), (30, 4096));
        assert_eq!(completion_tuple(&completion_b), (40, 4096));

        let read_a = match completion_a.buffer.take() {
            Some(buffer) => buffer.as_slice().to_vec(),
            other => panic!("unexpected read completion A: {other:?}"),
        };
        let read_b = match completion_b.buffer.take() {
            Some(buffer) => buffer.as_slice().to_vec(),
            other => panic!("unexpected read completion B: {other:?}"),
        };
        assert_eq!(read_a, write_a, "batch read A should match written data");
        assert_eq!(read_b, write_b, "batch read B should match written data");
    }

    #[test]
    fn test_qcow_async_read_unallocated() {
        let file_size = 100 * 1024 * 1024;
        let temp_file = TempFile::new().unwrap();
        {
            let raw_file = RawFile::new(temp_file.as_file().try_clone().unwrap(), false);
            QcowFile::new(raw_file, 3, file_size, true).unwrap();
        }
        let disk = QcowDisk::new(
            temp_file.as_file().try_clone().unwrap(),
            false,
            false,
            true,
            true,
        )
        .unwrap();

        let buf = async_read(&disk, 0, 128 * 1024);
        assert!(
            buf.iter().all(|&b| b == 0),
            "unallocated region should read as zeroes"
        );
    }

    #[test]
    fn test_qcow_async_sub_cluster_write() {
        let cluster_size = 65536usize;
        let file_size = 100 * 1024 * 1024;
        let temp_file = TempFile::new().unwrap();
        {
            let raw_file = RawFile::new(temp_file.as_file().try_clone().unwrap(), false);
            QcowFile::new(raw_file, 3, file_size, true).unwrap();
        }
        let disk = QcowDisk::new(
            temp_file.as_file().try_clone().unwrap(),
            false,
            false,
            true,
            true,
        )
        .unwrap();

        // Write 4K into the middle of a cluster.
        let write_offset = 4096u64;
        let write_len = 4096;
        let pattern = vec![0xCC; write_len];
        async_write(&disk, write_offset, &pattern);

        // Read the entire cluster back.
        let buf = async_read(&disk, 0, cluster_size);

        assert!(
            buf[..write_offset as usize].iter().all(|&b| b == 0),
            "bytes before the write should be zero"
        );
        assert_eq!(
            &buf[write_offset as usize..write_offset as usize + write_len],
            &pattern[..],
            "written region should match"
        );
        assert!(
            buf[write_offset as usize + write_len..]
                .iter()
                .all(|&b| b == 0),
            "bytes after the write should be zero"
        );
    }

    #[test]
    fn test_qcow_async_write_after_punch_hole() {
        let data = vec![0xAA; 64 * 1024];
        let offset = 0u64;
        let (_temp, disk) = create_disk_with_data(100 * 1024 * 1024, &data, offset, true);

        let buf = async_read(&disk, offset, data.len());
        assert!(buf.iter().all(|&b| b == 0xAA));

        let mut async_io = disk.create_async_io(1).unwrap();
        async_io.punch_hole(offset, data.len() as u64, 10).unwrap();
        let result = wait_for_completion(async_io.as_mut()).result;
        assert_eq!(result, 0);
        drop(async_io);

        let buf = async_read(&disk, offset, data.len());
        assert!(
            buf.iter().all(|&b| b == 0),
            "should be zero after punch hole"
        );

        let new_data = vec![0xBB; 64 * 1024];
        async_write(&disk, offset, &new_data);

        let buf = async_read(&disk, offset, new_data.len());
        assert_eq!(buf, new_data, "should read new data after rewrite");
    }

    #[test]
    fn test_qcow_async_large_sequential_io() {
        let cluster_size = 64 * 1024;
        let num_clusters = 8;
        let total_len = cluster_size * num_clusters;
        let offset = 0u64;

        let mut data = vec![0u8; total_len];
        for (i, chunk) in data.chunks_mut(cluster_size).enumerate() {
            chunk.fill((i + 1) as u8);
        }

        let (_temp, disk) = create_disk_with_data(100 * 1024 * 1024, &data, offset, true);

        let buf = async_read(&disk, offset, total_len);
        assert_eq!(buf.len(), total_len);
        for (i, chunk) in buf.chunks(cluster_size).enumerate() {
            assert!(
                chunk.iter().all(|&b| b == (i + 1) as u8),
                "cluster {i} mismatch"
            );
        }
    }

    #[test]
    fn test_qcow_async_alignment_without_direct_io() {
        let file_size = 100 * 1024 * 1024;
        let temp_file = TempFile::new().unwrap();
        {
            let raw_file = RawFile::new(temp_file.as_file().try_clone().unwrap(), false);
            QcowFile::new(raw_file, 3, file_size, true).unwrap();
        }
        let disk = QcowDisk::new(
            temp_file.as_file().try_clone().unwrap(),
            false,
            false,
            true,
            true,
        )
        .unwrap();
        let async_io = disk.create_async_io(1).unwrap();
        assert_eq!(async_io.alignment(), SECTOR_SIZE);
    }

    /// Returns None if O_DIRECT is not supported (e.g. tmpfs).
    fn try_create_direct_io_disk(temp_file: &TempFile, file_size: u64) -> Option<QcowDisk> {
        {
            let raw_file = RawFile::new(temp_file.as_file().try_clone().unwrap(), false);
            QcowFile::new(raw_file, 3, file_size, true).unwrap();
        }
        QcowDisk::new(
            temp_file.as_file().try_clone().unwrap(),
            true,
            false,
            true,
            true,
        )
        .ok()
    }

    #[test]
    fn test_qcow_async_alignment_with_direct_io() {
        let temp_file = TempFile::new().unwrap();
        let disk = match try_create_direct_io_disk(&temp_file, 100 * 1024 * 1024) {
            Some(d) => d,
            None => {
                eprintln!("skipping: O_DIRECT not supported on this filesystem");
                return;
            }
        };
        let async_io = disk.create_async_io(1).unwrap();
        assert!(async_io.alignment() >= SECTOR_SIZE);
    }

    #[test]
    fn test_qcow_async_sub_sector_read_with_direct_io() {
        let temp_file = TempFile::new().unwrap();
        let disk = match try_create_direct_io_disk(&temp_file, 100 * 1024 * 1024) {
            Some(d) => d,
            None => {
                eprintln!("skipping: O_DIRECT not supported on this filesystem");
                return;
            }
        };

        let pattern = vec![0xAB; 65536];
        async_write(&disk, 0, &pattern);

        let buf = async_read(&disk, 0, 512);
        assert!(
            buf.iter().all(|&b| b == 0xAB),
            "sub-sector O_DIRECT read should return written data"
        );
    }

    #[test]
    fn test_qcow_async_direct_io_write_read_roundtrip() {
        let temp_file = TempFile::new().unwrap();
        let disk = match try_create_direct_io_disk(&temp_file, 100 * 1024 * 1024) {
            Some(d) => d,
            None => {
                eprintln!("skipping: O_DIRECT not supported on this filesystem");
                return;
            }
        };

        let pattern: Vec<u8> = (0..128 * 1024).map(|i| (i % 251) as u8).collect();
        async_write(&disk, 0, &pattern);

        let buf = async_read(&disk, 0, pattern.len());
        assert_eq!(buf, pattern, "O_DIRECT roundtrip should match");
    }

    #[test]
    fn test_compressed_read_multi_queue() {
        let cluster_size = 65536usize;
        let data: Vec<u8> = (0..=255).cycle().take(cluster_size).collect();
        let (temp, disk) = create_disk_with_data(100 * 1024 * 1024, &data, 0, false);
        drop(disk);

        compress_allocated_clusters(&mut temp.as_file().try_clone().unwrap());

        let disk = Arc::new(
            QcowDisk::new(
                temp.as_file().try_clone().unwrap(),
                false,
                false,
                false,
                true,
            )
            .unwrap(),
        );

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let disk = Arc::clone(&disk);
                let expected = data.clone();
                thread::spawn(move || {
                    let mut async_io = disk.create_async_io(1).unwrap();
                    async_io
                        .read_to_vec(0, OwnedIoBuffer::from_vec(vec![0xFF; cluster_size]), 1)
                        .unwrap();
                    let mut completion = wait_for_completion(async_io.as_mut());
                    let result = completion.result;
                    assert_eq!(result as usize, cluster_size);
                    let buf = match completion.buffer.take() {
                        Some(buffer) => buffer.as_slice().to_vec(),
                        other => panic!("unexpected read completion: {other:?}"),
                    };
                    assert_eq!(buf, expected);
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
    }
}
