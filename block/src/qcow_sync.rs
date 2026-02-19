// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};

use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::write_zeroes::PunchHole;

use crate::async_io::{
    AsyncIo, AsyncIoError, AsyncIoResult, BorrowedDiskFd, DiskFile, DiskFileError, DiskFileResult,
};
use crate::qcow::{Error as QcowError, MAX_NESTING_DEPTH, QcowFile, RawFile, Result as QcowResult};
use crate::{AsyncAdaptor, BlockBackend};

pub struct QcowDiskSync {
    // FIXME: The Mutex serializes all QCOW2 I/O operations across queues, which
    // is necessary for correctness but eliminates any parallelism benefit from
    // multiqueue. QcowFile has internal mutable state (L2 cache, refcounts, file
    // position) that is not safe to share across threads via Clone.
    //
    // A proper fix would require restructuring QcowFile to separate metadata
    // operations (which need synchronization) from data I/O (which could be
    // parallelized with per queue file descriptors). See #7560 for details.
    qcow_file: Arc<Mutex<QcowFile>>,
}

impl QcowDiskSync {
    pub fn new(file: File, direct_io: bool, backing_files: bool, sparse: bool) -> QcowResult<Self> {
        let max_nesting_depth = if backing_files { MAX_NESTING_DEPTH } else { 0 };
        let qcow_file = QcowFile::from_with_nesting_depth(
            RawFile::new(file, direct_io),
            max_nesting_depth,
            sparse,
        )
        .map_err(|e| match e {
            QcowError::MaxNestingDepthExceeded if !backing_files => QcowError::BackingFilesDisabled,
            other => other,
        })?;
        Ok(QcowDiskSync {
            qcow_file: Arc::new(Mutex::new(qcow_file)),
        })
    }
}

impl DiskFile for QcowDiskSync {
    fn logical_size(&mut self) -> DiskFileResult<u64> {
        self.qcow_file
            .lock()
            .unwrap()
            .seek(SeekFrom::End(0))
            .map_err(DiskFileError::Size)
    }

    fn physical_size(&mut self) -> DiskFileResult<u64> {
        self.qcow_file.lock().unwrap().physical_size().map_err(|e| {
            let io_inner = match e {
                crate::Error::GetFileMetadata(e) => e,
                _ => unreachable!(),
            };
            DiskFileError::Size(io_inner)
        })
    }

    fn new_async_io(&self, _ring_depth: u32) -> DiskFileResult<Box<dyn AsyncIo>> {
        Ok(Box::new(QcowSync::new(Arc::clone(&self.qcow_file))) as Box<dyn AsyncIo>)
    }

    fn resize(&mut self, size: u64) -> DiskFileResult<()> {
        self.qcow_file
            .lock()
            .unwrap()
            .resize(size)
            .map_err(|e| DiskFileError::ResizeError(io::Error::other(e)))
    }

    fn supports_sparse_operations(&self) -> bool {
        true
    }

    fn supports_zero_flag(&self) -> bool {
        true
    }

    fn fd(&mut self) -> BorrowedDiskFd<'_> {
        BorrowedDiskFd::new(self.qcow_file.lock().unwrap().as_raw_fd())
    }
}

pub struct QcowSync {
    qcow_file: Arc<Mutex<QcowFile>>,
    eventfd: EventFd,
    completion_list: VecDeque<(u64, i32)>,
}

impl QcowSync {
    pub fn new(qcow_file: Arc<Mutex<QcowFile>>) -> Self {
        QcowSync {
            qcow_file,
            eventfd: EventFd::new(libc::EFD_NONBLOCK)
                .expect("Failed creating EventFd for QcowSync"),
            completion_list: VecDeque::new(),
        }
    }
}

impl AsyncAdaptor for QcowFile {}

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
        self.qcow_file.lock().unwrap().read_vectored_sync(
            offset,
            iovecs,
            user_data,
            &self.eventfd,
            &mut self.completion_list,
        )
    }

    fn write_vectored(
        &mut self,
        offset: libc::off_t,
        iovecs: &[libc::iovec],
        user_data: u64,
    ) -> AsyncIoResult<()> {
        self.qcow_file.lock().unwrap().write_vectored_sync(
            offset,
            iovecs,
            user_data,
            &self.eventfd,
            &mut self.completion_list,
        )
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        self.qcow_file.lock().unwrap().fsync_sync(
            user_data,
            &self.eventfd,
            &mut self.completion_list,
        )
    }

    fn next_completed_request(&mut self) -> Option<(u64, i32)> {
        self.completion_list.pop_front()
    }

    fn punch_hole(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        // For QCOW2, punch_hole calls deallocate_cluster
        let result = self
            .qcow_file
            .lock()
            .unwrap()
            .punch_hole(offset, length)
            .map(|_| 0i32)
            .map_err(AsyncIoError::PunchHole);

        match result {
            Ok(res) => {
                self.completion_list.push_back((user_data, res));
                self.eventfd.write(1).unwrap();
                Ok(())
            }
            Err(e) => {
                // CRITICAL: Always signal completion even on error to avoid hangs
                let errno = if let AsyncIoError::PunchHole(io_err) = &e {
                    let err = io_err.raw_os_error().unwrap_or(libc::EIO);
                    -err
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
        // For QCOW2, write_zeroes is implemented by deallocating clusters via punch_hole.
        // This is more efficient than writing actual zeros and reduces disk usage.
        // Unallocated clusters inherently read as zero in the QCOW2 format.
        let result = self
            .qcow_file
            .lock()
            .unwrap()
            .punch_hole(offset, length)
            .map(|_| 0i32)
            .map_err(AsyncIoError::WriteZeroes);

        match result {
            Ok(res) => {
                self.completion_list.push_back((user_data, res));
                self.eventfd.write(1).unwrap();
                Ok(())
            }
            Err(e) => {
                // Always signal completion even on error to avoid hangs
                let errno = if let AsyncIoError::WriteZeroes(io_err) = &e {
                    let err = io_err.raw_os_error().unwrap_or(libc::EIO);
                    -err
                } else {
                    -libc::EIO
                };
                self.completion_list.push_back((user_data, errno));
                self.eventfd.write(1).unwrap();
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod unit_tests {
    use std::io::{Read, Seek, SeekFrom, Write};

    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::qcow::{QcowFile, RawFile};

    #[test]
    fn test_qcow_async_punch_hole_completion() {
        // Create a QCOW2 image with valid header
        let temp_file = TempFile::new().unwrap();
        let raw_file = RawFile::new(temp_file.into_file(), false);
        let file_size = 1024 * 1024 * 100; // 100MB
        let mut qcow_file = QcowFile::new(raw_file, 3, file_size, true).unwrap();

        // Write some data
        let data = vec![0xDD; 128 * 1024]; // 128KB
        let offset = 0;
        qcow_file.seek(SeekFrom::Start(offset)).unwrap();
        qcow_file.write_all(&data).unwrap();
        qcow_file.flush().unwrap();

        // Create async wrapper
        let qcow_file = Arc::new(Mutex::new(qcow_file));
        let mut async_qcow = QcowSync::new(qcow_file.clone());

        // Punch hole
        async_qcow
            .punch_hole(offset, data.len() as u64, 100)
            .unwrap();

        // Verify completion event was generated
        let (user_data, result) = async_qcow.next_completed_request().unwrap();
        assert_eq!(user_data, 100);
        assert_eq!(result, 0, "punch_hole should succeed");

        // Verify data reads as zeros
        let mut read_buf = vec![0; data.len()];
        qcow_file
            .lock()
            .unwrap()
            .seek(SeekFrom::Start(offset))
            .unwrap();
        qcow_file.lock().unwrap().read_exact(&mut read_buf).unwrap();
        assert!(
            read_buf.iter().all(|&b| b == 0),
            "Punched hole should read as zeros"
        );
    }

    #[test]
    fn test_qcow_async_write_zeroes_completion() {
        // Create a QCOW2 image with valid header
        let temp_file = TempFile::new().unwrap();
        let raw_file = RawFile::new(temp_file.into_file(), false);
        let file_size = 1024 * 1024 * 100; // 100MB
        let mut qcow_file = QcowFile::new(raw_file, 3, file_size, true).unwrap();

        // Write some data
        let data = vec![0xEE; 256 * 1024]; // 256KB
        let offset = 64 * 1024; // Start at 64KB offset
        qcow_file.seek(SeekFrom::Start(offset)).unwrap();
        qcow_file.write_all(&data).unwrap();
        qcow_file.flush().unwrap();

        // Create async wrapper
        let qcow_file = Arc::new(Mutex::new(qcow_file));
        let mut async_qcow = QcowSync::new(qcow_file.clone());

        // Write zeros
        async_qcow
            .write_zeroes(offset, data.len() as u64, 200)
            .unwrap();

        // Verify completion event was generated
        let (user_data, result) = async_qcow.next_completed_request().unwrap();
        assert_eq!(user_data, 200);
        assert_eq!(result, 0, "write_zeroes should succeed");

        // Verify data reads as zeros
        let mut read_buf = vec![0; data.len()];
        qcow_file
            .lock()
            .unwrap()
            .seek(SeekFrom::Start(offset))
            .unwrap();
        qcow_file.lock().unwrap().read_exact(&mut read_buf).unwrap();
        assert!(
            read_buf.iter().all(|&b| b == 0),
            "Zeroed region should read as zeros"
        );
    }

    #[test]
    fn test_qcow_async_multiple_operations() {
        // Create a QCOW2 image with valid header
        let temp_file = TempFile::new().unwrap();
        let raw_file = RawFile::new(temp_file.into_file(), false);
        let file_size = 1024 * 1024 * 100; // 100MB
        let mut qcow_file = QcowFile::new(raw_file, 3, file_size, true).unwrap();

        // Write data at multiple offsets
        let data = vec![0xFF; 64 * 1024]; // 64KB chunks
        for i in 0..4 {
            let offset = i * 128 * 1024; // 128KB spacing
            qcow_file.seek(SeekFrom::Start(offset)).unwrap();
            qcow_file.write_all(&data).unwrap();
        }
        qcow_file.flush().unwrap();

        // Create async wrapper
        let qcow_file = Arc::new(Mutex::new(qcow_file));
        let mut async_qcow = QcowSync::new(qcow_file.clone());

        // Queue multiple punch_hole operations
        async_qcow.punch_hole(0, 64 * 1024, 1).unwrap();
        async_qcow.punch_hole(128 * 1024, 64 * 1024, 2).unwrap();
        async_qcow.punch_hole(256 * 1024, 64 * 1024, 3).unwrap();

        // Verify all completions
        let (user_data, result) = async_qcow.next_completed_request().unwrap();
        assert_eq!(user_data, 1);
        assert_eq!(result, 0);

        let (user_data, result) = async_qcow.next_completed_request().unwrap();
        assert_eq!(user_data, 2);
        assert_eq!(result, 0);

        let (user_data, result) = async_qcow.next_completed_request().unwrap();
        assert_eq!(user_data, 3);
        assert_eq!(result, 0);

        // Verify no more completions
        assert!(async_qcow.next_completed_request().is_none());
    }

    #[test]
    fn test_qcow_punch_hole_with_shared_instance() {
        // This test verifies that with Arc<Mutex<>>, multiple async I/O operations
        // share the same QcowFile instance and see each other's changes.

        // Create a QCOW2 image
        let temp_file = TempFile::new().unwrap();
        let raw_file = RawFile::new(temp_file.into_file(), false);
        let file_size = 1024 * 1024 * 100; // 100MB
        let mut qcow_file = QcowFile::new(raw_file, 3, file_size, true).unwrap();

        // Write some data at offset 0
        let data = vec![0xAB; 128 * 1024]; // 128KB of 0xAB pattern
        let offset = 0;
        qcow_file.seek(SeekFrom::Start(offset)).unwrap();
        qcow_file.write_all(&data).unwrap();
        qcow_file.flush().unwrap();

        let qcow_shared = Arc::new(Mutex::new(qcow_file));

        // First async I/O: punch hole
        let mut async_qcow1 = QcowSync::new(qcow_shared.clone());
        async_qcow1
            .punch_hole(offset, data.len() as u64, 100)
            .unwrap();

        // Verify punch_hole completed
        let (user_data, result) = async_qcow1.next_completed_request().unwrap();
        assert_eq!(user_data, 100);
        assert_eq!(result, 0, "punch_hole should succeed");

        // Second async I/O: read from same shared instance
        // This should see the deallocated cluster because they share the same QcowFile
        let mut read_buf = vec![0xFF; data.len()];
        qcow_shared
            .lock()
            .unwrap()
            .seek(SeekFrom::Start(offset))
            .unwrap();
        qcow_shared
            .lock()
            .unwrap()
            .read_exact(&mut read_buf)
            .unwrap();

        // The read should return zeros because the cluster was deallocated
        assert!(
            read_buf.iter().all(|&b| b == 0),
            "After punch_hole, shared QcowFile instance should read zeros from deallocated cluster"
        );
    }

    #[test]
    fn test_qcow_disk_sync_punch_hole_with_new_async_io() {
        // This test simulates the EXACT real usage pattern: QcowDiskSync.new_async_io()
        // creates a new QcowSync with a cloned QcowFile for each I/O operation.

        use std::io::Write;

        use crate::async_io::DiskFile;

        // Create a QCOW2 image
        let temp_file = TempFile::new().unwrap();
        let file_size = 1024 * 1024 * 100; // 100MB

        {
            let raw_file = RawFile::new(temp_file.as_file().try_clone().unwrap(), false);
            let mut qcow_file = QcowFile::new(raw_file, 3, file_size, true).unwrap();

            // Write data at offset 1MB - use single cluster (64KB) to simplify test
            let data = vec![0xCD; 64 * 1024]; // 64KB (one cluster)
            let offset = 1024 * 1024u64;
            qcow_file.seek(SeekFrom::Start(offset)).unwrap();
            qcow_file.write_all(&data).unwrap();
            qcow_file.flush().unwrap();
        }

        // Open with QcowDiskSync (like real code does)
        let disk =
            QcowDiskSync::new(temp_file.as_file().try_clone().unwrap(), false, true, true).unwrap();

        // First async I/O: punch hole (simulates DISCARD command)
        let mut async_io1 = disk.new_async_io(1).unwrap();
        let offset = 1024 * 1024u64;
        let length = 64 * 1024u64; // Single cluster
        async_io1.punch_hole(offset, length, 1).unwrap();
        let (user_data, result) = async_io1.next_completed_request().unwrap();
        assert_eq!(user_data, 1);
        assert_eq!(result, 0, "punch_hole should succeed");
        drop(async_io1);

        // Second async I/O: read from the same location (simulates READ command)
        let mut async_io2 = disk.new_async_io(1).unwrap();
        let mut read_buf = vec![0xFF; length as usize];
        let iovec = libc::iovec {
            iov_base: read_buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: read_buf.len(),
        };

        // These assertions are critical to prevent compiler optimization bugs
        // that can reorder operations. Without them, the test can fail even
        // though the QCOW2 implementation is correct.
        assert_eq!(iovec.iov_base as *const u8, read_buf.as_ptr());
        assert_eq!(iovec.iov_len, read_buf.len());

        async_io2
            .read_vectored(offset as libc::off_t, &[iovec], 2)
            .unwrap();

        let (user_data, result) = async_io2.next_completed_request().unwrap();
        assert_eq!(user_data, 2);
        assert_eq!(
            result as usize, length as usize,
            "read should complete successfully"
        );

        // Verify the data is all zeros
        assert!(
            read_buf.iter().all(|&b| b == 0),
            "After punch_hole via new_async_io, read should return zeros"
        );
    }
}
