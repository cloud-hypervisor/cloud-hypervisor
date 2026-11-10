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

impl disk_file::MetadataSync for VhdDisk {}

impl disk_file::DiskFile for VhdDisk {}

impl disk_file::AsyncDiskFile for VhdDisk {
    fn try_clone(&self) -> BlockResult<Box<dyn disk_file::AsyncDiskFile>> {
        let inner = self.inner.try_clone().map_err(|e| {
            BlockError::new(BlockErrorKind::Io, DiskFileError::Clone(e))
                .with_op(ErrorOp::DupBackingFd)
        })?;

        Ok(Box::new(VhdDisk {
            inner,
            use_io_uring: self.use_io_uring,
            direct: self.direct,
        }))
    }

    fn create_async_io(&self, ring_depth: u32) -> BlockResult<Box<dyn AsyncIo>> {
        let size = self.logical_size()?;
        let file = self.inner.file().try_clone().map_err(|e| {
            BlockError::new(BlockErrorKind::Io, DiskFileError::NewAsyncIo(e)).with_op(ErrorOp::Open)
        })?;

        if self.use_io_uring {
            #[cfg(feature = "io_uring")]
            {
                return Ok(Box::new(FixedVhdAsync::new(
                    file,
                    self.direct,
                    ring_depth,
                    size,
                )?));
            }

            #[cfg(not(feature = "io_uring"))]
            unreachable!("use_io_uring is set but io_uring feature is not enabled");
        }

        let _ = ring_depth;
        Ok(Box::new(FixedVhdSync::new(
            AlignedFile::new(file, self.direct),
            size,
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::io::{Seek, SeekFrom, Write};
    use std::os::unix::fs::FileExt;
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    use virtio_bindings::virtio_blk::{VIRTIO_BLK_T_FLUSH, VIRTIO_BLK_T_IN, VIRTIO_BLK_T_OUT};
    use virtio_bindings::virtio_ring::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};
    use virtio_queue::QueueT;
    use vm_memory::{Bytes, GuestAddress, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};
    use vm_virtio::queue::testing::VirtQueue;
    use vmm_sys_util::tempfile::TempFile;

    use super::footer::{VHD_FOOTER_LEN, checksummed_footer};
    use super::*;
    use crate::async_io::{
        AsyncIo, AsyncIoCompletion, AsyncIoError, AsyncIoOperation, OwnedIoBuffer,
    };
    use crate::disk_file::{AsyncDiskFile, DiskSize, PhysicalSize, Resizable};
    use crate::factory::{DiskOpenOptions, open_disk};
    use crate::test_util::require_direct_io;
    use crate::test_util::shared::QemuImgCommand;
    use crate::{ImageType, Request, SECTOR_SIZE};

    const VHD_REQUEST_DATA: GuestAddress = GuestAddress(0x10000);

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
        file.write_all(&checksummed_footer(fixed_vhd_footer()))
            .unwrap();
        file
    }

    fn wait_for_vhd_completion(io: &mut dyn AsyncIo) -> AsyncIoCompletion {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(completion) = io.next_completed_request() {
                return completion;
            }
            assert!(
                Instant::now() < deadline,
                "Timed out waiting for VHD completion"
            );
            thread::yield_now();
        }
    }

    fn execute_vhd_request(
        io: &mut dyn AsyncIo,
        mem: &Arc<GuestMemoryMmap<()>>,
        request_type: u32,
        offset: u64,
        (data_address, len): (GuestAddress, usize),
        disk_size: u64,
        user_data: u64,
    ) {
        assert!(offset.is_multiple_of(SECTOR_SIZE));
        mem.write_obj(request_type.to_le(), GuestAddress(0x8000))
            .unwrap();
        mem.write_obj((offset / SECTOR_SIZE).to_le(), GuestAddress(0x8008))
            .unwrap();
        let guest_queue = VirtQueue::new(GuestAddress(0x1000), mem.as_ref(), 4);
        guest_queue.dtable[0].set(
            0x8000,
            16,
            VRING_DESC_F_NEXT as u16,
            if request_type == VIRTIO_BLK_T_FLUSH {
                2
            } else {
                1
            },
        );
        let data_flags = if request_type == VIRTIO_BLK_T_IN {
            VRING_DESC_F_NEXT | VRING_DESC_F_WRITE
        } else {
            VRING_DESC_F_NEXT
        };
        guest_queue.dtable[1].set(
            data_address.0,
            len.try_into().unwrap(),
            data_flags as u16,
            2,
        );
        guest_queue.dtable[2].set(0x9000, 1, VRING_DESC_F_WRITE as u16, 0);
        guest_queue.avail.ring[0].set(0);
        guest_queue.avail.idx.set(1);

        let mem_atomic = GuestMemoryAtomic::new(mem.as_ref().clone());
        let mut queue = guest_queue.create_queue();
        let mut chain = queue.pop_descriptor_chain(mem_atomic.memory()).unwrap();
        let (request, status_addr) = Request::parse(&mut chain, None);
        assert_eq!(status_addr, Some(GuestAddress(0x9000)));
        let mut request = request.unwrap();
        let result = request
            .execute_async(Arc::clone(mem), disk_size / SECTOR_SIZE, io, &[], user_data)
            .unwrap();
        assert!(result.async_complete);
        if let Some(operation) = result.batch_request {
            io.submit_batch_requests(vec![operation]).unwrap();
        }
        let mut completion = wait_for_vhd_completion(io);
        assert_eq!(completion.user_data, user_data);
        assert_eq!(completion.result, len as i32);
        request
            .complete_async(mem.as_ref(), &mut completion)
            .unwrap();
    }

    fn read_vhd_data(
        io: &mut dyn AsyncIo,
        mem: &Arc<GuestMemoryMmap<()>>,
        data_address: GuestAddress,
        len: usize,
    ) -> Vec<u8> {
        let mut data = vec![0x5a; len];
        mem.write_slice(&data, data_address).unwrap();
        execute_vhd_request(
            io,
            mem,
            VIRTIO_BLK_T_IN,
            0,
            (data_address, len),
            len as u64,
            1,
        );
        mem.read_slice(&mut data, data_address).unwrap();
        data
    }

    fn assert_qemu_img_data_round_trip(use_io_uring: bool, direct: bool) {
        let data_size = 4 * 17 * 512 * 64;
        let mut data: Vec<u8> = (0..data_size).map(|offset| (offset % 251) as u8).collect();
        let raw_file = TempFile::new().unwrap();
        fs::write(raw_file.as_path(), &data).unwrap();
        let vhd_file = TempFile::new().unwrap();
        QemuImgCommand::new()
            .convert("raw", "vpc", "subformat=fixed")
            .args(&[
                raw_file.as_path().to_str().unwrap(),
                vhd_file.as_path().to_str().unwrap(),
            ])
            .run("Failed to create fixed VHD fixture");

        let footer = fs::read(vhd_file.as_path()).unwrap()[data_size..].to_vec();
        assert_eq!(footer.len() as u64, VHD_FOOTER_LEN);
        let options = DiskOpenOptions {
            path: vhd_file.as_path(),
            readonly: false,
            direct,
            sparse: false,
            backing_files: false,
            disable_io_uring: !use_io_uring,
            disable_aio: true,
        };
        let error = open_disk(&options, ImageType::Qcow2)
            .map(|_| ())
            .expect_err("A fixed VHD must not open as QCOW2");
        assert_eq!(
            error.kind(),
            BlockErrorKind::ImageTypeMismatch {
                specified: ImageType::Qcow2,
            }
        );
        let disk = open_disk(&options, ImageType::FixedVhd).unwrap();
        assert_eq!(disk.logical_size().unwrap(), data_size as u64);
        assert_eq!(
            disk.physical_size().unwrap(),
            data_size as u64 + VHD_FOOTER_LEN
        );
        let mut io = disk.create_async_io(16).unwrap();
        assert_eq!(io.batch_requests_enabled(), use_io_uring);
        let mem = Arc::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), data_size + 0x20000)]).unwrap(),
        );
        assert_eq!(
            read_vhd_data(io.as_mut(), &mem, VHD_REQUEST_DATA, data_size),
            data
        );

        let write_size = 4096;
        for (index, offset) in [0, data_size / 2, data_size - write_size]
            .into_iter()
            .enumerate()
        {
            let value = 0xa0 + index as u8;
            let data_address = GuestAddress(VHD_REQUEST_DATA.0 + index as u64 % 2);
            mem.write_slice(&vec![value; write_size], data_address)
                .unwrap();
            let user_data = index as u64 + 2;
            execute_vhd_request(
                io.as_mut(),
                &mem,
                VIRTIO_BLK_T_OUT,
                offset as u64,
                (data_address, write_size),
                data_size as u64,
                user_data,
            );
            data[offset..offset + write_size].fill(value);
        }

        execute_vhd_request(
            io.as_mut(),
            &mem,
            VIRTIO_BLK_T_FLUSH,
            0,
            (VHD_REQUEST_DATA, 0),
            data_size as u64,
            5,
        );
        assert_eq!(
            read_vhd_data(
                io.as_mut(),
                &mem,
                GuestAddress(VHD_REQUEST_DATA.0 + 1),
                data_size
            ),
            data
        );
        drop(io);
        drop(disk);

        let disk = open_disk(&options, ImageType::FixedVhd).unwrap();
        assert_eq!(disk.logical_size().unwrap(), data_size as u64);
        let mut io = disk.create_async_io(16).unwrap();
        assert_eq!(io.batch_requests_enabled(), use_io_uring);
        assert_eq!(
            read_vhd_data(io.as_mut(), &mem, VHD_REQUEST_DATA, data_size),
            data
        );
        drop(io);
        drop(disk);
        assert_eq!(&fs::read(vhd_file.as_path()).unwrap()[data_size..], footer);

        let round_trip_file = TempFile::new().unwrap();
        QemuImgCommand::new()
            .convert("vpc", "raw", "")
            .args(&[
                vhd_file.as_path().to_str().unwrap(),
                round_trip_file.as_path().to_str().unwrap(),
            ])
            .run("Failed to read fixed VHD fixture with qemu-img");
        assert_eq!(fs::read(round_trip_file.as_path()).unwrap(), data);

        let mut invalid_footer = footer;
        invalid_footer[64] ^= 1;
        vhd_file
            .as_file()
            .write_all_at(&invalid_footer, data_size as u64)
            .unwrap();
        let error = open_disk(&options, ImageType::FixedVhd)
            .map(|_| ())
            .expect_err("A fixed VHD with a damaged checksum must be rejected");
        assert_eq!(
            error.kind(),
            BlockErrorKind::ImageTypeMismatch {
                specified: ImageType::FixedVhd,
            }
        );
    }

    #[test]
    fn sync_data_round_trip() {
        assert_qemu_img_data_round_trip(false, false);
    }

    #[test]
    fn sync_direct_io_data_round_trip() {
        require_direct_io!();
        assert_qemu_img_data_round_trip(false, true);
    }

    #[cfg(feature = "io_uring")]
    #[test]
    fn io_uring_data_round_trip() {
        assert_qemu_img_data_round_trip(true, false);
    }

    #[cfg(feature = "io_uring")]
    #[test]
    fn io_uring_direct_io_data_round_trip() {
        require_direct_io!();
        assert_qemu_img_data_round_trip(true, true);
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
        let mut async_io = FixedVhdAsync::new(file.try_clone().unwrap(), false, 8, 0x1000).unwrap();
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
        let mut async_io = FixedVhdAsync::new(file.try_clone().unwrap(), false, 8, 0x1000).unwrap();
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
    fn new_rejects_footer_claiming_more_than_the_file_holds() {
        let mut file: File = TempFile::new().unwrap().into_file();
        let data_size: u64 = 0x1000;
        file.set_len(data_size + 0x200).unwrap();
        file.seek(SeekFrom::Start(data_size)).unwrap();

        let mut footer = fixed_vhd_footer().to_vec();
        // current_size, at offset 48, claims a terabyte.
        footer[48..56].copy_from_slice(&(1u64 << 40).to_be_bytes());
        file.write_all(&footer).unwrap();

        let err = VhdDisk::new(file, false, false)
            .expect_err("a footer larger than the file must be rejected");
        assert_eq!(err.kind(), BlockErrorKind::Io);
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
