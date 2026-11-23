// Copyright © 2021 Intel Corporation
//
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0

//! VHDX disk format support.
//!
//! Provides [`VhdxDisk`], the `DiskFile` wrapper for dynamic VHDX
//! images.

mod bat;
mod dynamic;
mod engine_sync;
mod header;
mod metadata;
#[cfg(test)]
mod test_util;

use std::fs::File;
use std::io::Error as IoError;
use std::os::fd::AsRawFd;
use std::sync::{Arc, RwLock};

pub use dynamic::VhdxError;

use self::dynamic::Vhdx;
use self::engine_sync::VhdxSync;
use crate::async_io::{AsyncIo, BorrowedDiskFd, DiskFileError};
use crate::error::{BlockError, BlockErrorKind, BlockResult, ErrorOp};
use crate::{Error, disk_file};

#[derive(Debug)]
pub struct VhdxDisk {
    // Reads take the read lock; writes take the write lock because
    // `write_all_at` mutates the BAT and header.
    vhdx_file: Arc<RwLock<Vhdx>>,
}

impl VhdxDisk {
    pub fn new(f: File, direct_io: bool) -> BlockResult<Self> {
        Ok(VhdxDisk {
            vhdx_file: Arc::new(RwLock::new(Vhdx::new(f, direct_io).map_err(|e| {
                let kind = match &e {
                    VhdxError::ParseVhdxHeader(_)
                    | VhdxError::ParseVhdxMetadata(_)
                    | VhdxError::ParseVhdxRegionEntry(_)
                    | VhdxError::UnsupportedLogReplay => BlockErrorKind::InvalidFormat,
                    VhdxError::ReadBatEntry(_) => BlockErrorKind::CorruptImage,
                };
                BlockError::new(kind, e).with_op(ErrorOp::Open)
            })?)),
        })
    }
}

impl disk_file::DiskSize for VhdxDisk {
    fn logical_size(&self) -> BlockResult<u64> {
        Ok(self.vhdx_file.read().unwrap().virtual_disk_size())
    }
}

impl disk_file::PhysicalSize for VhdxDisk {
    fn physical_size(&self) -> BlockResult<u64> {
        self.vhdx_file
            .read()
            .unwrap()
            .physical_size()
            .map_err(|e| match e {
                Error::GetFileMetadata(io) => {
                    BlockError::new(BlockErrorKind::Io, Error::GetFileMetadata(io))
                }
                _ => unreachable!("unexpected error from Vhdx::physical_size(): {e}"),
            })
    }
}

impl disk_file::DiskFd for VhdxDisk {
    fn fd(&self) -> BorrowedDiskFd<'_> {
        BorrowedDiskFd::new(self.vhdx_file.read().unwrap().as_raw_fd())
    }
}

impl disk_file::Geometry for VhdxDisk {}

impl disk_file::SparseCapable for VhdxDisk {}

impl disk_file::Resizable for VhdxDisk {
    fn resize(&mut self, _size: u64) -> BlockResult<()> {
        Err(BlockError::new(
            BlockErrorKind::UnsupportedFeature,
            DiskFileError::ResizeError(IoError::other("resize not supported for VHDX")),
        )
        .with_op(ErrorOp::Resize))
    }
}

impl disk_file::MetadataSync for VhdxDisk {}

impl disk_file::DiskFile for VhdxDisk {}

impl disk_file::AsyncDiskFile for VhdxDisk {
    fn try_clone(&self) -> BlockResult<Box<dyn disk_file::AsyncDiskFile>> {
        Ok(Box::new(VhdxDisk {
            vhdx_file: Arc::clone(&self.vhdx_file),
        }))
    }

    fn create_async_io(&self, _ring_depth: u32) -> BlockResult<Box<dyn AsyncIo>> {
        let size = self.vhdx_file.read().unwrap().virtual_disk_size();
        Ok(Box::new(VhdxSync::new(Arc::clone(&self.vhdx_file), size)))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Arc;

    use virtio_bindings::virtio_blk::{VIRTIO_BLK_T_FLUSH, VIRTIO_BLK_T_OUT};
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};
    use vmm_sys_util::tempfile::TempFile;

    use crate::ImageType;
    use crate::factory::{DiskOpenOptions, open_disk};
    use crate::test_util::shared::QemuImgCommand;
    use crate::test_util::{execute_virtio_blk_request, read_disk_data, require_direct_io};

    fn assert_data_round_trip(direct: bool) {
        const BLOCK_SIZE: usize = 1 << 20;
        const WRITE_SIZE: usize = 4096;
        const DISK_SIZE: usize = 2 * BLOCK_SIZE;
        const DATA_ADDRESS: GuestAddress = GuestAddress(0x10000);

        let mut expected = vec![0; DISK_SIZE];
        for (offset, byte) in expected[..WRITE_SIZE].iter_mut().enumerate() {
            *byte = (offset % 251) as u8;
        }
        let raw = TempFile::new().unwrap();
        fs::write(raw.as_path(), &expected).unwrap();
        let image = TempFile::new().unwrap();
        let image_path = image.as_path().to_str().unwrap();
        QemuImgCommand::new()
            .convert("raw", "vhdx", "subformat=dynamic,block_size=1M")
            .args(&[raw.as_path().to_str().unwrap(), image_path])
            .run("Failed to create dynamic VHDX fixture");

        let options = DiskOpenOptions {
            path: image.as_path(),
            readonly: false,
            direct,
            sparse: false,
            backing_files: false,
            disable_io_uring: true,
            disable_aio: true,
        };
        let mem = Arc::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), DISK_SIZE + 0x20000)]).unwrap(),
        );
        {
            let disk = open_disk(&options, ImageType::Vhdx).unwrap();
            assert_eq!(disk.logical_size().unwrap(), DISK_SIZE as u64);
            let mut io = disk.create_async_io(16).unwrap();
            assert_eq!(
                read_disk_data(io.as_mut(), &mem, DATA_ADDRESS, DISK_SIZE),
                expected
            );

            for (offset, address, byte, token) in [
                (0, DATA_ADDRESS, 0xa0, 2),
                (
                    BLOCK_SIZE + WRITE_SIZE,
                    GuestAddress(DATA_ADDRESS.0 + 1),
                    0xb1,
                    3,
                ),
            ] {
                let data = &mut expected[offset..offset + WRITE_SIZE];
                data.fill(byte);
                mem.write_slice(data, address).unwrap();
                execute_virtio_blk_request(
                    io.as_mut(),
                    &mem,
                    VIRTIO_BLK_T_OUT,
                    offset as u64,
                    (address, WRITE_SIZE),
                    DISK_SIZE as u64,
                    token,
                );
            }
            execute_virtio_blk_request(
                io.as_mut(),
                &mem,
                VIRTIO_BLK_T_FLUSH,
                0,
                (DATA_ADDRESS, 0),
                DISK_SIZE as u64,
                4,
            );
        }
        {
            let disk = open_disk(&options, ImageType::Vhdx).unwrap();
            let mut io = disk.create_async_io(16).unwrap();
            assert_eq!(
                read_disk_data(
                    io.as_mut(),
                    &mem,
                    GuestAddress(DATA_ADDRESS.0 + 1),
                    DISK_SIZE
                ),
                expected
            );
        }

        QemuImgCommand::new()
            .check(image_path)
            .run("Dynamic VHDX fixture failed its consistency check");
        let round_trip = TempFile::new().unwrap();
        QemuImgCommand::new()
            .convert("vhdx", "raw", "")
            .args(&[image_path, round_trip.as_path().to_str().unwrap()])
            .run("Failed to read dynamic VHDX fixture with qemu-img");
        assert_eq!(fs::read(round_trip.as_path()).unwrap(), expected);
    }

    #[test]
    fn sync_data_round_trip() {
        assert_data_round_trip(false);
    }

    #[test]
    fn sync_direct_io_data_round_trip() {
        require_direct_io!();
        assert_data_round_trip(true);
    }
}
