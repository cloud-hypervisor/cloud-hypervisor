// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::cmp::min;
use std::collections::VecDeque;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::{io, ptr, slice};

use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::write_zeroes::{PunchHole, WriteZeroesAt};

use crate::async_io::{
    AsyncIo, AsyncIoError, AsyncIoResult, BorrowedDiskFd, DiskFile, DiskFileError, DiskFileResult,
};
use crate::qcow::metadata::{
    BackingRead, ClusterReadMapping, ClusterWriteMapping, DeallocAction, QcowMetadata,
};
use crate::qcow::qcow_raw_file::QcowRawFile;
use crate::qcow::{
    BackingFile, BackingKind, Error as QcowError, MAX_NESTING_DEPTH, RawFile, Result as QcowResult,
    parse_qcow,
};

/// Raw backing file using pread64 on a duplicated fd.
struct RawBacking {
    fd: OwnedFd,
    virtual_size: u64,
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

/// QCOW2 backing file with RwLock metadata and pread64 data reads.
///
/// Read only because backing files never receive writes. Nested backing
/// files are handled recursively.
struct Qcow2MetadataBacking {
    metadata: Arc<QcowMetadata>,
    data_fd: OwnedFd,
    backing_file: Option<Arc<dyn BackingRead>>,
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

/// Construct a thread safe backing file reader.
fn shared_backing_from(bf: BackingFile) -> Arc<dyn BackingRead> {
    let (kind, virtual_size) = bf.into_kind();
    match kind {
        BackingKind::Raw(raw_file) => {
            // SAFETY: raw_file holds a valid open fd.
            let dup_fd = unsafe { libc::dup(raw_file.as_raw_fd()) };
            assert!(dup_fd >= 0, "dup() backing file fd");
            // SAFETY: dup_fd is a freshly duplicated valid fd.
            let fd = unsafe { OwnedFd::from_raw_fd(dup_fd) };
            Arc::new(RawBacking { fd, virtual_size })
        }
        BackingKind::Qcow { inner, backing } => {
            // SAFETY: inner.raw_file holds a valid open fd.
            let dup_fd = unsafe { libc::dup(inner.raw_file.as_raw_fd()) };
            assert!(dup_fd >= 0, "dup() backing qcow data fd");
            // SAFETY: dup_fd is a freshly duplicated valid fd.
            let data_fd = unsafe { OwnedFd::from_raw_fd(dup_fd) };
            Arc::new(Qcow2MetadataBacking {
                metadata: Arc::new(QcowMetadata::new(*inner)),
                data_fd,
                backing_file: backing.map(|bf| shared_backing_from(*bf)),
            })
        }
        #[cfg(test)]
        BackingKind::QcowFile(_) => {
            unreachable!("QcowFile variant is only used by set_backing_file() in tests")
        }
    }
}

pub struct QcowDiskSync {
    metadata: Arc<QcowMetadata>,
    /// Shared across queues, resolved once at construction.
    backing_file: Option<Arc<dyn BackingRead>>,
    sparse: bool,
    data_raw_file: QcowRawFile,
}

impl QcowDiskSync {
    pub fn new(file: File, direct_io: bool, backing_files: bool, sparse: bool) -> QcowResult<Self> {
        let max_nesting_depth = if backing_files { MAX_NESTING_DEPTH } else { 0 };
        let (inner, backing_file, sparse) =
            parse_qcow(RawFile::new(file, direct_io), max_nesting_depth, sparse).map_err(|e| {
                match e {
                    QcowError::MaxNestingDepthExceeded if !backing_files => {
                        QcowError::BackingFilesDisabled
                    }
                    other => other,
                }
            })?;
        let data_raw_file = inner.raw_file.clone();
        Ok(QcowDiskSync {
            metadata: Arc::new(QcowMetadata::new(inner)),
            backing_file: backing_file.map(shared_backing_from),
            sparse,
            data_raw_file,
        })
    }
}

impl DiskFile for QcowDiskSync {
    fn logical_size(&mut self) -> DiskFileResult<u64> {
        Ok(self.metadata.virtual_size())
    }

    fn physical_size(&mut self) -> DiskFileResult<u64> {
        self.data_raw_file
            .physical_size()
            .map_err(DiskFileError::Size)
    }

    fn new_async_io(&self, _ring_depth: u32) -> DiskFileResult<Box<dyn AsyncIo>> {
        Ok(Box::new(QcowSync::new(
            Arc::clone(&self.metadata),
            self.data_raw_file.clone(),
            self.backing_file.as_ref().map(Arc::clone),
            self.sparse,
        )) as Box<dyn AsyncIo>)
    }

    fn resize(&mut self, size: u64) -> DiskFileResult<()> {
        if self.backing_file.is_some() {
            return Err(DiskFileError::ResizeError(io::Error::other(
                "resize not supported with backing file",
            )));
        }
        self.metadata
            .resize(size)
            .map_err(DiskFileError::ResizeError)
    }

    fn supports_sparse_operations(&self) -> bool {
        true
    }

    fn supports_zero_flag(&self) -> bool {
        true
    }

    fn fd(&mut self) -> BorrowedDiskFd<'_> {
        BorrowedDiskFd::new(self.data_raw_file.as_raw_fd())
    }
}

impl Drop for QcowDiskSync {
    fn drop(&mut self) {
        self.metadata.shutdown();
    }
}

pub struct QcowSync {
    metadata: Arc<QcowMetadata>,
    data_file: QcowRawFile,
    /// See the backing_file field on QcowDiskSync.
    backing_file: Option<Arc<dyn BackingRead>>,
    sparse: bool,
    eventfd: EventFd,
    completion_list: VecDeque<(u64, i32)>,
}

impl QcowSync {
    fn new(
        metadata: Arc<QcowMetadata>,
        data_file: QcowRawFile,
        backing_file: Option<Arc<dyn BackingRead>>,
        sparse: bool,
    ) -> Self {
        QcowSync {
            metadata,
            data_file,
            backing_file,
            sparse,
            eventfd: EventFd::new(libc::EFD_NONBLOCK)
                .expect("Failed creating EventFd for QcowSync"),
            completion_list: VecDeque::new(),
        }
    }
}

// -- Position independent I/O helpers --
//
// Duplicated file descriptors share the kernel file description and thus the
// file position. Using seek then read from multiple queues races on that
// shared position. pread64 and pwrite64 are atomic and never touch the position.

/// Read exactly the requested bytes at offset, looping on short reads.
fn pread_exact(fd: RawFd, buf: &mut [u8], offset: u64) -> io::Result<()> {
    let mut total = 0usize;
    while total < buf.len() {
        // SAFETY: buf and fd are valid for the lifetime of the call.
        let ret = unsafe {
            libc::pread64(
                fd,
                buf[total..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - total,
                (offset + total as u64) as libc::off_t,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        if ret == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        total += ret as usize;
    }
    Ok(())
}

/// Write all bytes to fd at offset, looping on short writes.
fn pwrite_all(fd: RawFd, buf: &[u8], offset: u64) -> io::Result<()> {
    let mut total = 0usize;
    while total < buf.len() {
        // SAFETY: buf and fd are valid for the lifetime of the call.
        let ret = unsafe {
            libc::pwrite64(
                fd,
                buf[total..].as_ptr() as *const libc::c_void,
                buf.len() - total,
                (offset + total as u64) as libc::off_t,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        if ret == 0 {
            return Err(io::Error::other("pwrite64 wrote 0 bytes"));
        }
        total += ret as usize;
    }
    Ok(())
}

// -- iovec helper functions --
//
// Operate on the iovec array as a flat byte stream.

/// Copy data into iovecs starting at the given byte offset.
///
/// # Safety
/// Caller must ensure iovecs point to valid, writable memory of sufficient size.
unsafe fn scatter_to_iovecs(iovecs: &[libc::iovec], start: usize, data: &[u8]) {
    let mut remaining = data;
    let mut pos = 0usize;
    for iov in iovecs {
        let iov_end = pos + iov.iov_len;
        if iov_end <= start || remaining.is_empty() {
            pos = iov_end;
            continue;
        }
        let iov_start = start.saturating_sub(pos);
        let available = iov.iov_len - iov_start;
        let count = min(available, remaining.len());
        // SAFETY: iov_base is valid for iov_len bytes per caller contract.
        unsafe {
            let dst = (iov.iov_base as *mut u8).add(iov_start);
            ptr::copy_nonoverlapping(remaining.as_ptr(), dst, count);
        }
        remaining = &remaining[count..];
        if remaining.is_empty() {
            break;
        }
        pos = iov_end;
    }
}

/// Zero fill iovecs starting at the given byte offset for the given length.
///
/// # Safety
/// Caller must ensure iovecs point to valid, writable memory of sufficient size.
unsafe fn zero_fill_iovecs(iovecs: &[libc::iovec], start: usize, len: usize) {
    let mut remaining = len;
    let mut pos = 0usize;
    for iov in iovecs {
        let iov_end = pos + iov.iov_len;
        if iov_end <= start || remaining == 0 {
            pos = iov_end;
            continue;
        }
        let iov_start = start.saturating_sub(pos);
        let available = iov.iov_len - iov_start;
        let count = min(available, remaining);
        // SAFETY: iov_base is valid for iov_len bytes per caller contract.
        unsafe {
            let dst = (iov.iov_base as *mut u8).add(iov_start);
            ptr::write_bytes(dst, 0, count);
        }
        remaining -= count;
        if remaining == 0 {
            break;
        }
        pos = iov_end;
    }
}

/// Gather bytes from iovecs starting at the given byte offset into a Vec.
///
/// # Safety
/// Caller must ensure iovecs point to valid, readable memory of sufficient size.
unsafe fn gather_from_iovecs(iovecs: &[libc::iovec], start: usize, len: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(len);
    let mut remaining = len;
    let mut pos = 0usize;
    for iov in iovecs {
        let iov_end = pos + iov.iov_len;
        if iov_end <= start || remaining == 0 {
            pos = iov_end;
            continue;
        }
        let iov_start = start.saturating_sub(pos);
        let available = iov.iov_len - iov_start;
        let count = min(available, remaining);
        // SAFETY: iov_base is valid for iov_len bytes per caller contract.
        unsafe {
            let src = (iov.iov_base as *const u8).add(iov_start);
            result.extend_from_slice(slice::from_raw_parts(src, count));
        }
        remaining -= count;
        if remaining == 0 {
            break;
        }
        pos = iov_end;
    }
    result
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
                    let mut buf = vec![0u8; length as usize];
                    pread_exact(self.data_file.as_raw_fd(), &mut buf, host_offset)
                        .map_err(AsyncIoError::ReadVectored)?;
                    // SAFETY: iovecs point to valid guest memory buffers
                    unsafe { scatter_to_iovecs(iovecs, buf_offset, &buf) };
                    buf_offset += length as usize;
                }
                ClusterReadMapping::Compressed { data } => {
                    let len = data.len();
                    // SAFETY: iovecs point to valid guest memory buffers
                    unsafe { scatter_to_iovecs(iovecs, buf_offset, &data) };
                    buf_offset += len;
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
            let cluster_size = self.metadata.cluster_size();
            let intra_offset = self.metadata.cluster_offset(curr_addr);
            let remaining_in_cluster = (cluster_size - intra_offset) as usize;
            let count = min(total_len - buf_offset, remaining_in_cluster);

            // Read backing data for COW if this is a partial cluster
            // write to an unallocated cluster with a backing file.
            let backing_data = if let Some(backing) = self
                .backing_file
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

            let mapping = self
                .metadata
                .map_cluster_for_write(curr_addr, backing_data)
                .map_err(AsyncIoError::WriteVectored)?;

            match mapping {
                ClusterWriteMapping::Allocated {
                    offset: host_offset,
                } => {
                    // SAFETY: iovecs point to valid guest memory buffers
                    let buf = unsafe { gather_from_iovecs(iovecs, buf_offset, count) };
                    pwrite_all(self.data_file.as_raw_fd(), &buf, host_offset)
                        .map_err(AsyncIoError::WriteVectored)?;
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
        let cluster_size = self.metadata.cluster_size();

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

    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::async_io::DiskFile;
    use crate::qcow::{QcowFile, RawFile};

    fn create_disk_with_data(
        file_size: u64,
        data: &[u8],
        offset: u64,
        sparse: bool,
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
            false,
            false,
            sparse,
        )
        .unwrap();
        (temp_file, disk)
    }

    fn async_read(disk: &QcowDiskSync, offset: u64, len: usize) -> Vec<u8> {
        let mut async_io = disk.new_async_io(1).unwrap();
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
        let mut async_io = disk.new_async_io(1).unwrap();
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
        let (_temp, disk) = create_disk_with_data(100 * 1024 * 1024, &data, offset, true);

        let mut async_io = disk.new_async_io(1).unwrap();
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
        let (_temp, disk) = create_disk_with_data(100 * 1024 * 1024, &data, offset, true);

        let mut async_io = disk.new_async_io(1).unwrap();
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
        let (_temp, _) = create_disk_with_data(100 * 1024 * 1024, &[], 0, true);

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

        let mut async_io = disk.new_async_io(1).unwrap();

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
        let (_temp, disk) = create_disk_with_data(100 * 1024 * 1024, &data, offset, true);

        let mut async_io1 = disk.new_async_io(1).unwrap();
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
    fn test_qcow_disk_sync_punch_hole_with_new_async_io() {
        // Simulates the real usage pattern of write data, punch hole, then read back.
        let data = vec![0xCD; 64 * 1024]; // one cluster
        let offset = 1024 * 1024u64; // 1MB offset
        let (_temp, disk) = create_disk_with_data(100 * 1024 * 1024, &data, offset, true);

        // Punch hole to simulate DISCARD
        let mut async_io1 = disk.new_async_io(1).unwrap();
        async_io1.punch_hole(offset, data.len() as u64, 1).unwrap();
        let (user_data, result) = async_io1.next_completed_request().unwrap();
        assert_eq!(user_data, 1);
        assert_eq!(result, 0, "punch_hole should succeed");
        drop(async_io1);

        // Read from the same location to verify
        let read_buf = async_read(&disk, offset, data.len());
        assert!(
            read_buf.iter().all(|&b| b == 0),
            "After punch_hole via new_async_io, read should return zeros"
        );
    }

    #[test]
    fn test_qcow_async_read_write_roundtrip() {
        let (_temp, disk) = create_disk_with_data(100 * 1024 * 1024, &[], 0, true);

        let data = vec![0x42u8; 64 * 1024];
        let offset = 0u64;

        async_write(&disk, offset, &data);

        let mut async_io = disk.new_async_io(1).unwrap();
        async_io.fsync(Some(10)).unwrap();
        let (ud, res) = async_io.next_completed_request().unwrap();
        assert_eq!(ud, 10);
        assert_eq!(res, 0);
        drop(async_io);

        let read_buf = async_read(&disk, offset, data.len());
        assert_eq!(read_buf, data, "Read-back should match written data");
    }

    #[test]
    fn test_qcow_async_read_unallocated() {
        // Reading from an unallocated region should return zeros.
        let (_temp, disk) = create_disk_with_data(100 * 1024 * 1024, &[], 0, true);
        let read_buf = async_read(&disk, 0, 64 * 1024);
        assert!(
            read_buf.iter().all(|&b| b == 0),
            "Unallocated region should read as zeros"
        );
    }

    #[test]
    fn test_qcow_async_cross_cluster_read_write() {
        let (_temp, disk) = create_disk_with_data(100 * 1024 * 1024, &[], 0, true);

        // Default cluster size is 64KB. Write 96KB starting at 32KB to cross the boundary.
        let data: Vec<u8> = (0..96 * 1024).map(|i| (i % 251) as u8).collect();
        let offset = 32 * 1024u64;

        async_write(&disk, offset, &data);

        let mut async_io = disk.new_async_io(1).unwrap();
        async_io.fsync(Some(99)).unwrap();
        drop(async_io);

        let read_buf = async_read(&disk, offset, data.len());
        assert_eq!(
            read_buf, data,
            "Cross-cluster read should match written data"
        );
    }
}
