// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0

//! Fixed VHD disk image format.
//!
//! Provides [`VhdDisk`], the `DiskFile` wrapper for fixed size VHD
//! images.

mod engine_sync;
#[cfg(feature = "io_uring")]
mod engine_uring;
mod fixed;
mod footer;

use std::fs::File;
use std::io;
use std::os::unix::io::AsRawFd;

pub use footer::is_fixed_vhd;
use log::warn;

use self::engine_sync::FixedVhdSync;
#[cfg(feature = "io_uring")]
use self::engine_uring::FixedVhdAsync;
use self::fixed::FixedVhd;
use crate::async_io::{AsyncIo, BorrowedDiskFd, DiskFileError};
use crate::disk_file::DiskSize;
use crate::error::{BlockError, BlockErrorKind, BlockResult, ErrorOp};
use crate::{AlignedFile, DiskTopology, Error, disk_file};

#[derive(Debug)]
pub struct VhdDisk {
    inner: FixedVhd,
    use_io_uring: bool,
    direct: bool,
}

impl VhdDisk {
    pub fn new(file: File, use_io_uring: bool, direct: bool) -> BlockResult<Self> {
        #[cfg(not(feature = "io_uring"))]
        if use_io_uring {
            return Err(BlockError::new(
                BlockErrorKind::UnsupportedFeature,
                DiskFileError::NewAsyncIo(io::Error::other(
                    "io_uring requested but feature is not enabled",
                )),
            ));
        }

        Ok(Self {
            inner: FixedVhd::new(file).map_err(|e| BlockError::from(e).with_op(ErrorOp::Open))?,
            use_io_uring,
            direct,
        })
    }
}

impl disk_file::DiskSize for VhdDisk {
    fn logical_size(&self) -> BlockResult<u64> {
        self.inner
            .logical_size()
            .map_err(|e| BlockError::new(BlockErrorKind::Io, e))
    }
}

impl disk_file::PhysicalSize for VhdDisk {
    fn physical_size(&self) -> BlockResult<u64> {
        self.inner.physical_size().map_err(|e| match e {
            Error::GetFileMetadata(io) => {
                BlockError::new(BlockErrorKind::Io, Error::GetFileMetadata(io))
            }
            _ => unreachable!("unexpected error from FixedVhd::physical_size(): {e}"),
        })
    }
}

impl disk_file::DiskFd for VhdDisk {
    fn fd(&self) -> BorrowedDiskFd<'_> {
        BorrowedDiskFd::new(self.inner.as_raw_fd())
    }
}

impl disk_file::Geometry for VhdDisk {
    fn topology(&self) -> DiskTopology {
        DiskTopology::probe(self.inner.file()).unwrap_or_else(|_| {
            warn!("Unable to get device topology. Using default topology");
            DiskTopology::default()
        })
    }
}

impl disk_file::SparseCapable for VhdDisk {}

impl disk_file::Resizable for VhdDisk {
    fn resize(&mut self, _size: u64) -> BlockResult<()> {
        Err(BlockError::new(
            BlockErrorKind::UnsupportedFeature,
            DiskFileError::ResizeError(io::Error::other("resize not supported for fixed VHD")),
        )
        .with_op(ErrorOp::Resize))
    }
}

impl disk_file::DiskFile for VhdDisk {}

impl disk_file::AsyncDiskFile for VhdDisk {
    fn try_clone(&self) -> BlockResult<Box<dyn disk_file::AsyncDiskFile>> {
        Ok(Box::new(VhdDisk {
            inner: self.inner.clone(),
            use_io_uring: self.use_io_uring,
            direct: self.direct,
        }))
    }

    fn create_async_io(&self, ring_depth: u32) -> BlockResult<Box<dyn AsyncIo>> {
        let size = self.logical_size()?;
        let file = self.inner.file().try_clone().map_err(|e| {
            BlockError::new(BlockErrorKind::Io, DiskFileError::NewAsyncIo(e)).with_op(ErrorOp::Open)
        })?;
        let raw_file = AlignedFile::new(file, self.direct);

        if self.use_io_uring {
            #[cfg(feature = "io_uring")]
            {
                return Ok(Box::new(FixedVhdAsync::new(raw_file, ring_depth, size)?));
            }

            #[cfg(not(feature = "io_uring"))]
            unreachable!("use_io_uring is set but io_uring feature is not enabled");
        }

        let _ = ring_depth;
        Ok(Box::new(FixedVhdSync::new(raw_file, size)))
    }
}

#[cfg(test)]
mod unit_tests {
    use std::fs::File;
    use std::io::{Seek, SeekFrom, Write};

    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::async_io::{AsyncIo, AsyncIoError, AsyncIoOperation, OwnedIoBuffer};
    use crate::disk_file::{AsyncDiskFile, DiskSize, PhysicalSize, Resizable};

    /// Minimal fixed VHD footer (disk type = 2, current_size = 0x11223344).
    fn fixed_vhd_footer() -> &'static [u8] {
        &[
            0x63, 0x6f, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x78, // cookie
            0x00, 0x00, 0x00, 0x02, // features
            0x00, 0x01, 0x00, 0x00, // file format version
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // data offset
            0x27, 0xa6, 0xa6, 0x5d, // time stamp
            0x71, 0x65, 0x6d, 0x75, // creator application
            0x00, 0x05, 0x00, 0x03, // creator version
            0x57, 0x69, 0x32, 0x6b, // creator host os
            0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, // original size
            0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, // current size
            0x11, 0xe0, 0x10, 0x3f, // disk geometry
            0x00, 0x00, 0x00, 0x02, // disk type
            0x00, 0x00, 0x00, 0x00, // checksum
            0x98, 0x7b, 0xb1, 0xcd, 0x84, 0x14, 0x41, 0xfc, // unique id
            0xa4, 0xab, 0xd0, 0x69, 0x45, 0x2b, 0xf2, 0x23, 0x00, // saved state
        ]
    }

    fn make_vhd_file() -> File {
        let mut file: File = TempFile::new().unwrap().into_file();
        let data_size: u64 = 0x1122_3344;
        file.set_len(data_size + 0x200).unwrap();
        file.seek(SeekFrom::Start(data_size)).unwrap();
        file.write_all(fixed_vhd_footer()).unwrap();
        file
    }

    #[test]
    fn new_sync_returns_correct_size() {
        let file = make_vhd_file();
        let disk = VhdDisk::new(file, false, false).unwrap();
        assert_eq!(disk.logical_size().unwrap(), 0x1122_3344);
    }

    fn assert_async_io_from_dyn(disk: &dyn AsyncDiskFile, expect_batch: bool) {
        let io: Box<dyn AsyncIo> = disk.create_async_io(128).unwrap();
        assert_eq!(io.batch_requests_enabled(), expect_batch);
    }

    fn assert_async_io(disk: &VhdDisk, expect_batch: bool) {
        assert_async_io_from_dyn(disk, expect_batch);
    }

    #[test]
    fn sync_backend_disables_batch_requests() {
        let file = make_vhd_file();
        let disk = VhdDisk::new(file, false, false).unwrap();
        assert_async_io(&disk, false);
    }

    #[cfg(feature = "io_uring")]
    #[test]
    fn io_uring_backend_enables_batch_requests() {
        let file = make_vhd_file();
        let disk = VhdDisk::new(file, true, false).unwrap();
        assert_async_io(&disk, true);
    }

    #[test]
    fn sync_rejects_read_straddling_logical_size() {
        let file = TempFile::new().unwrap().into_file();
        file.set_len(0x2000).unwrap();
        let mut sync_io =
            FixedVhdSync::new(AlignedFile::new(file.try_clone().unwrap(), false), 0x1000);
        let op = AsyncIoOperation::read_to_vec(0x800, OwnedIoBuffer::from_vec(vec![0; 0x900]), 1);

        assert!(matches!(
            sync_io.submit_data_operation(op),
            Err(AsyncIoError::ReadVectored(_))
        ));
    }

    #[test]
    fn sync_rejects_write_straddling_logical_size() {
        let file = TempFile::new().unwrap().into_file();
        file.set_len(0x2000).unwrap();
        let mut sync_io =
            FixedVhdSync::new(AlignedFile::new(file.try_clone().unwrap(), false), 0x1000);
        let op =
            AsyncIoOperation::write_from_vec(0x800, OwnedIoBuffer::from_vec(vec![0; 0x900]), 1);

        assert!(matches!(
            sync_io.submit_data_operation(op),
            Err(AsyncIoError::WriteVectored(_))
        ));
    }

    #[test]
    fn sync_accepts_operation_exactly_filling_logical_size() {
        let file = TempFile::new().unwrap().into_file();
        file.set_len(0x2000).unwrap();
        let mut sync_io =
            FixedVhdSync::new(AlignedFile::new(file.try_clone().unwrap(), false), 0x1000);
        // end == size: boundary must be accepted
        let op = AsyncIoOperation::read_to_vec(0, OwnedIoBuffer::from_vec(vec![0; 0x1000]), 1);
        sync_io.submit_data_operation(op).unwrap();
    }

    #[test]
    fn sync_accepts_operation_at_last_byte() {
        let file = TempFile::new().unwrap().into_file();
        file.set_len(0x2000).unwrap();
        let mut sync_io =
            FixedVhdSync::new(AlignedFile::new(file.try_clone().unwrap(), false), 0x1000);
        // end = 0xFFF + 1 = 0x1000 == size: boundary must be accepted
        let op = AsyncIoOperation::read_to_vec(0xFFF, OwnedIoBuffer::from_vec(vec![0; 1]), 1);
        sync_io.submit_data_operation(op).unwrap();
    }

    #[cfg(feature = "io_uring")]
    #[test]
    fn io_uring_batch_rejects_request_straddling_logical_size() {
        let file = TempFile::new().unwrap().into_file();
        file.set_len(0x2000).unwrap();
        let mut async_io = FixedVhdAsync::new(
            AlignedFile::new(file.try_clone().unwrap(), false),
            8,
            0x1000,
        )
        .unwrap();
        let op = AsyncIoOperation::read_to_vec(0x800, OwnedIoBuffer::from_vec(vec![0; 0x900]), 1);

        assert!(matches!(
            async_io.submit_batch_requests(vec![op]),
            Err(AsyncIoError::ReadVectored(_))
        ));
    }

    #[cfg(feature = "io_uring")]
    #[test]
    fn io_uring_rejects_single_op_straddling_logical_size() {
        let file = TempFile::new().unwrap().into_file();
        file.set_len(0x2000).unwrap();
        let mut async_io = FixedVhdAsync::new(
            AlignedFile::new(file.try_clone().unwrap(), false),
            8,
            0x1000,
        )
        .unwrap();
        let op = AsyncIoOperation::read_to_vec(0x800, OwnedIoBuffer::from_vec(vec![0; 0x900]), 1);

        assert!(matches!(
            async_io.submit_data_operation(op),
            Err(AsyncIoError::ReadVectored(_))
        ));
    }

    #[test]
    fn try_clone_preserves_sync_dispatch() {
        let file = make_vhd_file();
        let disk = VhdDisk::new(file, false, false).unwrap();
        let cloned = disk.try_clone().unwrap();
        assert_async_io_from_dyn(cloned.as_ref(), false);
    }

    #[cfg(feature = "io_uring")]
    #[test]
    fn try_clone_preserves_io_uring_dispatch() {
        let file = make_vhd_file();
        let disk = VhdDisk::new(file, true, false).unwrap();
        let cloned = disk.try_clone().unwrap();
        assert_async_io_from_dyn(cloned.as_ref(), true);
    }

    #[test]
    fn resize_returns_error() {
        let file = make_vhd_file();
        let mut disk = VhdDisk::new(file, false, false).unwrap();
        assert!(disk.resize(0x2000_0000).is_err());
    }

    #[test]
    fn physical_size_includes_footer() {
        let file = make_vhd_file();
        let disk = VhdDisk::new(file, false, false).unwrap();
        // Data region (0x1122_3344) + VHD footer (0x200).
        assert_eq!(disk.physical_size().unwrap(), 0x1122_3344 + 0x200);
    }
}
