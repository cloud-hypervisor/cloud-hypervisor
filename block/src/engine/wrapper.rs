// Copyright © 2021 Intel Corporation
// Copyright © 2026 Demi Marie Obenour
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::fs::File;
use std::io;
use std::marker::PhantomData;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::FileTypeExt as _;

use log::warn;

use crate::async_io::{AsyncIo, AsyncIoError, AsyncIoResult, BorrowedDiskFd, DiskFileError};
use crate::engine::{Completion, CreatableEngine, IoBuf, Tracker};
use crate::error::{BlockError, BlockErrorKind, BlockResult};
use crate::request::SECTOR_SIZE;
use crate::{DiskTopology, disk_file, probe_sparse_support, query_device_size};

pub struct RawFileDisk<T: super::AsyncIoEngine> {
    file: File,
    phantom: PhantomData<fn() -> T>,
}
impl<T: super::AsyncIoEngine> std::fmt::Debug for RawFileDisk<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawFileDisk")
            .field("file", &self.file)
            .finish()
    }
}

impl<T: super::AsyncIoEngine> RawFileDisk<T> {
    pub fn new(file: File) -> Self {
        Self {
            file,
            phantom: PhantomData,
        }
    }
}

impl<T: super::AsyncIoEngine> disk_file::DiskSize for RawFileDisk<T> {
    fn logical_size(&self) -> BlockResult<u64> {
        query_device_size(&self.file)
            .map(|(logical_size, _)| logical_size)
            .map_err(|e| BlockError::new(BlockErrorKind::Io, DiskFileError::Size(e)))
    }
}

impl<T: super::AsyncIoEngine> disk_file::PhysicalSize for RawFileDisk<T> {
    fn physical_size(&self) -> BlockResult<u64> {
        query_device_size(&self.file)
            .map(|(_, physical_size)| physical_size)
            .map_err(|e| BlockError::new(BlockErrorKind::Io, DiskFileError::Size(e)))
    }
}

impl<T: super::AsyncIoEngine> disk_file::DiskFd for RawFileDisk<T> {
    fn fd(&self) -> BorrowedDiskFd<'_> {
        BorrowedDiskFd::new(self.file.as_raw_fd())
    }
}

impl<T: super::AsyncIoEngine> disk_file::Geometry for RawFileDisk<T> {
    fn topology(&self) -> DiskTopology {
        DiskTopology::probe(&self.file).unwrap_or_else(|_| {
            warn!("Unable to get device topology. Using default topology");
            DiskTopology::default()
        })
    }
}

impl<T: super::AsyncIoEngine> disk_file::SparseCapable for RawFileDisk<T> {
    fn supports_sparse_operations(&self) -> bool {
        probe_sparse_support(&self.file)
    }
}

impl<T: super::AsyncIoEngine> disk_file::Resizable for RawFileDisk<T> {
    fn resize(&mut self, size: u64) -> BlockResult<()> {
        let fd_metadata = self
            .file
            .metadata()
            .map_err(|e| BlockError::new(BlockErrorKind::Io, DiskFileError::ResizeError(e)))?;

        if fd_metadata.file_type().is_block_device() {
            // Block devices cannot be resized via ftruncate - they are resized
            // externally (LVM, losetup -c, etc.). Verify the size matches.
            let (actual_size, _) = query_device_size(&self.file)
                .map_err(|e| BlockError::new(BlockErrorKind::Io, DiskFileError::ResizeError(e)))?;
            if actual_size != size {
                return Err(BlockError::new(
                    BlockErrorKind::Io,
                    DiskFileError::ResizeError(io::Error::other(format!(
                        "Block device size {actual_size} does not match requested size {size}"
                    ))),
                ));
            }
            Ok(())
        } else {
            self.file
                .set_len(size)
                .map_err(|e| BlockError::new(BlockErrorKind::Io, DiskFileError::ResizeError(e)))
        }
    }
}

impl<T: super::AsyncIoEngine> disk_file::DiskFile for RawFileDisk<T> {}

impl<T: super::CreatableEngine + 'static> disk_file::AsyncDiskFile for RawFileDisk<T> {
    fn try_clone(&self) -> BlockResult<Box<dyn disk_file::AsyncDiskFile>> {
        let file = self
            .file
            .try_clone()
            .map_err(|e| BlockError::new(BlockErrorKind::Io, DiskFileError::Clone(e)))?;
        Ok(Box::new(Self {
            file,
            phantom: PhantomData,
        }))
    }

    fn new_async_io(&self, ring_depth: u32) -> BlockResult<Box<dyn AsyncIo>> {
        let file = self
            .file
            .try_clone()
            .map_err(|e| BlockError::new(BlockErrorKind::Io, DiskFileError::Clone(e)))?;
        let raw =
            Wrapper {
                fd: file.into(),
                tracker: Tracker::new(T::create(ring_depth).map_err(|e| {
                    BlockError::new(BlockErrorKind::Io, DiskFileError::NewAsyncIo(e))
                })?),
                alignment: DiskTopology::probe(&self.file)
                    .map_or(SECTOR_SIZE, |t| t.logical_block_size),
            };
        Ok(Box::new(raw) as Box<dyn AsyncIo>)
    }
}

pub struct Wrapper<T: super::AsyncIoEngine> {
    fd: OwnedFd,
    tracker: Tracker<T>,
    alignment: u64,
}

impl<T: CreatableEngine + 'static> Wrapper<T> {
    pub fn new(file: File, ring_depth: u32) -> std::io::Result<Self> {
        let alignment = DiskTopology::probe(&file).map_or(SECTOR_SIZE, |t| t.logical_block_size);
        Ok(Wrapper {
            fd: file.into(),
            tracker: Tracker::new(T::create(ring_depth)?),
            alignment,
        })
    }
}

impl<T: super::AsyncIoEngine> AsyncIo for Wrapper<T> {
    fn notifier(&self) -> &vmm_sys_util::eventfd::EventFd {
        self.tracker.notifier()
    }

    fn read_vectored(
        &mut self,
        offset: libc::off_t,
        iobuf: IoBuf,
        user_data: u64,
    ) -> AsyncIoResult<()> {
        self.tracker.read_vectored(
            BorrowedDiskFd::new(self.fd.as_raw_fd()),
            offset,
            iobuf,
            user_data,
        )
    }

    fn write_vectored(
        &mut self,
        offset: libc::off_t,
        iobuf: IoBuf,
        user_data: u64,
    ) -> AsyncIoResult<()> {
        self.tracker.write_vectored(
            BorrowedDiskFd::new(self.fd.as_raw_fd()),
            offset,
            iobuf,
            user_data,
        )
    }

    fn punch_hole(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        self.tracker.punch_hole(
            BorrowedDiskFd::new(self.fd.as_raw_fd()),
            offset,
            length,
            user_data,
        )
    }

    fn write_zeroes(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        self.tracker.write_zeroes(
            BorrowedDiskFd::new(self.fd.as_raw_fd()),
            offset,
            length,
            user_data,
        )
    }

    fn next_completed_request(&mut self) -> Option<Completion> {
        self.tracker.next_completed_request()
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        if let Some(user_data) = user_data {
            self.tracker
                .fsync(BorrowedDiskFd::new(self.fd.as_raw_fd()), user_data)
        } else {
            // SAFETY: libc call with valid FD
            match unsafe { libc::fsync(self.fd.as_raw_fd()) } {
                -1 => Err(AsyncIoError::Fsync(std::io::Error::last_os_error())),
                0 => Ok(()),
                _ => panic!("bad value from kernel"),
            }
        }
    }

    fn alignment(&self) -> u64 {
        self.alignment
    }

    fn batch_requests_enabled(&self) -> bool {
        self.tracker.batch_requests_enabled()
    }

    fn submit_batch_requests(
        &mut self,
        batch_request: Vec<crate::BatchRequest>,
    ) -> AsyncIoResult<()> {
        self.tracker
            .submit_batch_requests(BorrowedDiskFd::new(self.fd.as_raw_fd()), batch_request)
    }
}
