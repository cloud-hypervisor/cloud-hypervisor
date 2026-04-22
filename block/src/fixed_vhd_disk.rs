// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io;
use std::os::unix::io::AsRawFd;

use crate::async_io::{AsyncIo, BorrowedDiskFd, DiskFileError};
use crate::disk_file::DiskSize;
use crate::error::{BlockError, BlockErrorKind, BlockResult, ErrorOp};
use crate::fixed_vhd::FixedVhd;
#[cfg(feature = "io_uring")]
use crate::fixed_vhd_async::FixedVhdAsync;
use crate::fixed_vhd_sync::FixedVhdSync;
use crate::{BlockBackend, Error, disk_file};

#[derive(Debug)]
pub struct FixedVhdDisk {
    inner: FixedVhd,
    use_io_uring: bool,
}

impl FixedVhdDisk {
    pub fn new(file: File, use_io_uring: bool) -> BlockResult<Self> {
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
        })
    }
}

impl disk_file::DiskSize for FixedVhdDisk {
    fn logical_size(&self) -> BlockResult<u64> {
        self.inner
            .logical_size()
            .map_err(|e| BlockError::new(BlockErrorKind::Io, e))
    }
}

impl disk_file::PhysicalSize for FixedVhdDisk {
    fn physical_size(&self) -> BlockResult<u64> {
        self.inner.physical_size().map_err(|e| match e {
            Error::GetFileMetadata(io) => {
                BlockError::new(BlockErrorKind::Io, Error::GetFileMetadata(io))
            }
            _ => unreachable!("unexpected error from FixedVhd::physical_size(): {e}"),
        })
    }
}

impl disk_file::DiskFd for FixedVhdDisk {
    fn fd(&self) -> BorrowedDiskFd<'_> {
        BorrowedDiskFd::new(self.inner.as_raw_fd())
    }
}

impl disk_file::Geometry for FixedVhdDisk {}

impl disk_file::SparseCapable for FixedVhdDisk {}

impl disk_file::Resizable for FixedVhdDisk {
    fn resize(&mut self, _size: u64) -> BlockResult<()> {
        Err(BlockError::new(
            BlockErrorKind::UnsupportedFeature,
            DiskFileError::ResizeError(io::Error::other("resize not supported for fixed VHD")),
        )
        .with_op(ErrorOp::Resize))
    }
}

impl disk_file::DiskFile for FixedVhdDisk {}

impl disk_file::AsyncDiskFile for FixedVhdDisk {
    fn try_clone(&self) -> BlockResult<Box<dyn disk_file::AsyncDiskFile>> {
        Ok(Box::new(FixedVhdDisk {
            inner: self.inner.clone(),
            use_io_uring: self.use_io_uring,
        }))
    }

    fn create_async_io(&self, ring_depth: u32) -> BlockResult<Box<dyn AsyncIo>> {
        let size = self.logical_size()?;

        if self.use_io_uring {
            #[cfg(feature = "io_uring")]
            {
                return Ok(Box::new(FixedVhdAsync::new(
                    self.inner.as_raw_fd(),
                    ring_depth,
                    size,
                )?));
            }

            #[cfg(not(feature = "io_uring"))]
            unreachable!("use_io_uring is set but io_uring feature is not enabled");
        }

        let _ = ring_depth;
        Ok(Box::new(
            FixedVhdSync::new(self.inner.as_raw_fd(), size).map_err(|e| {
                BlockError::new(BlockErrorKind::Io, DiskFileError::NewAsyncIo(e))
                    .with_op(ErrorOp::Open)
            })?,
        ))
    }
}

#[cfg(test)]
mod unit_tests {
    use std::fs::File;
    use std::io::{Seek, SeekFrom, Write};

    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::async_io::AsyncIo;
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
        let disk = FixedVhdDisk::new(file, false).unwrap();
        assert_eq!(disk.logical_size().unwrap(), 0x1122_3344);
    }

    fn assert_async_io_from_dyn(disk: &dyn AsyncDiskFile, expect_batch: bool) {
        let io: Box<dyn AsyncIo> = disk.create_async_io(128).unwrap();
        assert_eq!(io.batch_requests_enabled(), expect_batch);
    }

    fn assert_async_io(disk: &FixedVhdDisk, expect_batch: bool) {
        assert_async_io_from_dyn(disk, expect_batch);
    }

    #[test]
    fn sync_backend_disables_batch_requests() {
        let file = make_vhd_file();
        let disk = FixedVhdDisk::new(file, false).unwrap();
        assert_async_io(&disk, false);
    }

    #[cfg(feature = "io_uring")]
    #[test]
    fn io_uring_backend_enables_batch_requests() {
        let file = make_vhd_file();
        let disk = FixedVhdDisk::new(file, true).unwrap();
        assert_async_io(&disk, true);
    }

    #[test]
    fn try_clone_preserves_sync_dispatch() {
        let file = make_vhd_file();
        let disk = FixedVhdDisk::new(file, false).unwrap();
        let cloned = disk.try_clone().unwrap();
        assert_async_io_from_dyn(cloned.as_ref(), false);
    }

    #[cfg(feature = "io_uring")]
    #[test]
    fn try_clone_preserves_io_uring_dispatch() {
        let file = make_vhd_file();
        let disk = FixedVhdDisk::new(file, true).unwrap();
        let cloned = disk.try_clone().unwrap();
        assert_async_io_from_dyn(cloned.as_ref(), true);
    }

    #[test]
    fn resize_returns_error() {
        let file = make_vhd_file();
        let mut disk = FixedVhdDisk::new(file, false).unwrap();
        assert!(disk.resize(0x2000_0000).is_err());
    }

    #[test]
    fn physical_size_includes_footer() {
        let file = make_vhd_file();
        let disk = FixedVhdDisk::new(file, false).unwrap();
        // Data region (0x1122_3344) + VHD footer (0x200).
        assert_eq!(disk.physical_size().unwrap(), 0x1122_3344 + 0x200);
    }
}
