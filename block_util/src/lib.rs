// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

#[macro_use]
extern crate log;

pub mod async_io;
pub mod fixed_vhd_async;
pub mod fixed_vhd_sync;
pub mod qcow_sync;
pub mod raw_async;
pub mod raw_sync;
pub mod vhd;

use crate::async_io::{AsyncIo, AsyncIoError, AsyncIoResult, DiskFileError, DiskFileResult};
#[cfg(feature = "io_uring")]
use io_uring::{opcode, IoUring, Probe};
use std::cmp;
use std::convert::TryInto;
use std::fs::File;
use std::io::{self, IoSlice, IoSliceMut, Read, Seek, SeekFrom, Write};
use std::os::linux::fs::MetadataExt;
#[cfg(feature = "io_uring")]
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::result;
use std::sync::{Arc, Mutex};
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;
use virtio_bindings::bindings::virtio_blk::*;
use vm_memory::{
    bitmap::AtomicBitmap, bitmap::Bitmap, ByteValued, Bytes, GuestAddress, GuestMemory,
    GuestMemoryError,
};
use vm_virtio::DescriptorChain;
use vmm_sys_util::eventfd::EventFd;

type GuestMemoryMmap = vm_memory::GuestMemoryMmap<AtomicBitmap>;

const SECTOR_SHIFT: u8 = 9;
pub const SECTOR_SIZE: u64 = 0x01 << SECTOR_SHIFT;

#[derive(Debug)]
pub enum Error {
    /// Guest gave us bad memory addresses.
    GuestMemory(GuestMemoryError),
    /// Guest gave us offsets that would have overflowed a usize.
    CheckedOffset(GuestAddress, usize),
    /// Guest gave us a write only descriptor that protocol says to read from.
    UnexpectedWriteOnlyDescriptor,
    /// Guest gave us a read only descriptor that protocol says to write to.
    UnexpectedReadOnlyDescriptor,
    /// Guest gave us too few descriptors in a descriptor chain.
    DescriptorChainTooShort,
    /// Guest gave us a descriptor that was too short to use.
    DescriptorLengthTooSmall,
    /// Getting a block's metadata fails for any reason.
    GetFileMetadata,
    /// The requested operation would cause a seek beyond disk end.
    InvalidOffset,
    /// The requested operation does not support multiple descriptors.
    TooManyDescriptors,
}

fn build_device_id(disk_path: &Path) -> result::Result<String, Error> {
    let blk_metadata = match disk_path.metadata() {
        Err(_) => return Err(Error::GetFileMetadata),
        Ok(m) => m,
    };
    // This is how kvmtool does it.
    let device_id = format!(
        "{}{}{}",
        blk_metadata.st_dev(),
        blk_metadata.st_rdev(),
        blk_metadata.st_ino()
    );
    Ok(device_id)
}

pub fn build_disk_image_id(disk_path: &Path) -> Vec<u8> {
    let mut default_disk_image_id = vec![0; VIRTIO_BLK_ID_BYTES as usize];
    match build_device_id(disk_path) {
        Err(_) => {
            warn!("Could not generate device id. We'll use a default.");
        }
        Ok(m) => {
            // The kernel only knows to read a maximum of VIRTIO_BLK_ID_BYTES.
            // This will also zero out any leftover bytes.
            let disk_id = m.as_bytes();
            let bytes_to_copy = cmp::min(disk_id.len(), VIRTIO_BLK_ID_BYTES as usize);
            default_disk_image_id[..bytes_to_copy].clone_from_slice(&disk_id[..bytes_to_copy])
        }
    }
    default_disk_image_id
}

#[derive(Debug)]
pub enum ExecuteError {
    BadRequest(Error),
    Flush(io::Error),
    Read(GuestMemoryError),
    Seek(io::Error),
    Write(GuestMemoryError),
    Unsupported(u32),
    SubmitIoUring(io::Error),
    GetHostAddress(GuestMemoryError),
    AsyncRead(AsyncIoError),
    AsyncWrite(AsyncIoError),
    AsyncFlush(AsyncIoError),
}

impl ExecuteError {
    pub fn status(&self) -> u32 {
        match *self {
            ExecuteError::BadRequest(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::Flush(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::Read(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::Seek(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::Write(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::Unsupported(_) => VIRTIO_BLK_S_UNSUPP,
            ExecuteError::SubmitIoUring(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::GetHostAddress(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::AsyncRead(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::AsyncWrite(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::AsyncFlush(_) => VIRTIO_BLK_S_IOERR,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RequestType {
    In,
    Out,
    Flush,
    GetDeviceId,
    Unsupported(u32),
}

pub fn request_type(
    mem: &GuestMemoryMmap,
    desc_addr: GuestAddress,
) -> result::Result<RequestType, Error> {
    let type_ = mem.read_obj(desc_addr).map_err(Error::GuestMemory)?;
    match type_ {
        VIRTIO_BLK_T_IN => Ok(RequestType::In),
        VIRTIO_BLK_T_OUT => Ok(RequestType::Out),
        VIRTIO_BLK_T_FLUSH => Ok(RequestType::Flush),
        VIRTIO_BLK_T_GET_ID => Ok(RequestType::GetDeviceId),
        t => Ok(RequestType::Unsupported(t)),
    }
}

fn sector(mem: &GuestMemoryMmap, desc_addr: GuestAddress) -> result::Result<u64, Error> {
    const SECTOR_OFFSET: usize = 8;
    let addr = match mem.checked_offset(desc_addr, SECTOR_OFFSET) {
        Some(v) => v,
        None => return Err(Error::CheckedOffset(desc_addr, SECTOR_OFFSET)),
    };

    mem.read_obj(addr).map_err(Error::GuestMemory)
}

#[derive(Debug)]
pub struct Request {
    pub request_type: RequestType,
    pub sector: u64,
    pub data_descriptors: Vec<(GuestAddress, u32)>,
    pub status_addr: GuestAddress,
    pub writeback: bool,
}

impl Request {
    pub fn parse(
        avail_desc: &DescriptorChain,
        mem: &GuestMemoryMmap,
    ) -> result::Result<Request, Error> {
        // The head contains the request type which MUST be readable.
        if avail_desc.is_write_only() {
            return Err(Error::UnexpectedWriteOnlyDescriptor);
        }

        let mut req = Request {
            request_type: request_type(mem, avail_desc.addr)?,
            sector: sector(mem, avail_desc.addr)?,
            data_descriptors: Vec::new(),
            status_addr: GuestAddress(0),
            writeback: true,
        };

        let status_desc;
        let mut desc = avail_desc
            .next_descriptor()
            .ok_or(Error::DescriptorChainTooShort)
            .map_err(|e| {
                error!("Only head descriptor present: request = {:?}", req);
                e
            })?;

        if !desc.has_next() {
            status_desc = desc;
            // Only flush requests are allowed to skip the data descriptor.
            if req.request_type != RequestType::Flush {
                error!("Need a data descriptor: request = {:?}", req);
                return Err(Error::DescriptorChainTooShort);
            }
        } else {
            while desc.has_next() {
                if desc.is_write_only() && req.request_type == RequestType::Out {
                    return Err(Error::UnexpectedWriteOnlyDescriptor);
                }
                if !desc.is_write_only() && req.request_type == RequestType::In {
                    return Err(Error::UnexpectedReadOnlyDescriptor);
                }
                if !desc.is_write_only() && req.request_type == RequestType::GetDeviceId {
                    return Err(Error::UnexpectedReadOnlyDescriptor);
                }
                req.data_descriptors.push((desc.addr, desc.len));
                desc = desc
                    .next_descriptor()
                    .ok_or(Error::DescriptorChainTooShort)
                    .map_err(|e| {
                        error!("DescriptorChain corrupted: request = {:?}", req);
                        e
                    })?;
            }
            status_desc = desc;
        }

        // The status MUST always be writable.
        if !status_desc.is_write_only() {
            return Err(Error::UnexpectedReadOnlyDescriptor);
        }

        if status_desc.len < 1 {
            return Err(Error::DescriptorLengthTooSmall);
        }

        req.status_addr = status_desc.addr;

        Ok(req)
    }

    #[allow(clippy::ptr_arg)]
    pub fn execute<T: Seek + Read + Write>(
        &self,
        disk: &mut T,
        disk_nsectors: u64,
        mem: &GuestMemoryMmap,
        disk_id: &Vec<u8>,
    ) -> result::Result<u32, ExecuteError> {
        disk.seek(SeekFrom::Start(self.sector << SECTOR_SHIFT))
            .map_err(ExecuteError::Seek)?;
        let mut len = 0;
        for (data_addr, data_len) in &self.data_descriptors {
            let mut top: u64 = u64::from(*data_len) / SECTOR_SIZE;
            if u64::from(*data_len) % SECTOR_SIZE != 0 {
                top += 1;
            }
            top = top
                .checked_add(self.sector)
                .ok_or(ExecuteError::BadRequest(Error::InvalidOffset))?;
            if top > disk_nsectors {
                return Err(ExecuteError::BadRequest(Error::InvalidOffset));
            }

            match self.request_type {
                RequestType::In => {
                    mem.read_exact_from(*data_addr, disk, *data_len as usize)
                        .map_err(ExecuteError::Read)?;
                    len += data_len;
                }
                RequestType::Out => {
                    mem.write_all_to(*data_addr, disk, *data_len as usize)
                        .map_err(ExecuteError::Write)?;
                    if !self.writeback {
                        disk.flush().map_err(ExecuteError::Flush)?;
                    }
                }
                RequestType::Flush => disk.flush().map_err(ExecuteError::Flush)?,
                RequestType::GetDeviceId => {
                    if (*data_len as usize) < disk_id.len() {
                        return Err(ExecuteError::BadRequest(Error::InvalidOffset));
                    }
                    mem.write_slice(disk_id.as_slice(), *data_addr)
                        .map_err(ExecuteError::Write)?;
                }
                RequestType::Unsupported(t) => return Err(ExecuteError::Unsupported(t)),
            };
        }
        Ok(len)
    }

    pub fn execute_async(
        &self,
        mem: &GuestMemoryMmap,
        disk_nsectors: u64,
        disk_image: &mut dyn AsyncIo,
        disk_id: &[u8],
        user_data: u64,
    ) -> result::Result<bool, ExecuteError> {
        let sector = self.sector;
        let request_type = self.request_type;
        let offset = (sector << SECTOR_SHIFT) as libc::off_t;

        let mut iovecs = Vec::new();
        for (data_addr, data_len) in &self.data_descriptors {
            let mut top: u64 = u64::from(*data_len) / SECTOR_SIZE;
            if u64::from(*data_len) % SECTOR_SIZE != 0 {
                top += 1;
            }
            top = top
                .checked_add(sector)
                .ok_or(ExecuteError::BadRequest(Error::InvalidOffset))?;
            if top > disk_nsectors {
                return Err(ExecuteError::BadRequest(Error::InvalidOffset));
            }

            let buf = mem
                .get_slice(*data_addr, *data_len as usize)
                .map_err(ExecuteError::GetHostAddress)?
                .as_ptr();
            let iovec = libc::iovec {
                iov_base: buf as *mut libc::c_void,
                iov_len: *data_len as libc::size_t,
            };
            iovecs.push(iovec);
        }

        // Queue operations expected to be submitted.
        match request_type {
            RequestType::In => {
                for (data_addr, data_len) in &self.data_descriptors {
                    mem.get_slice(*data_addr, *data_len as usize)
                        .map_err(ExecuteError::GetHostAddress)?
                        .bitmap()
                        .mark_dirty(0, *data_len as usize);
                }
                disk_image
                    .read_vectored(offset, iovecs, user_data)
                    .map_err(ExecuteError::AsyncRead)?;
            }
            RequestType::Out => {
                disk_image
                    .write_vectored(offset, iovecs, user_data)
                    .map_err(ExecuteError::AsyncWrite)?;
            }
            RequestType::Flush => {
                disk_image
                    .fsync(Some(user_data))
                    .map_err(ExecuteError::AsyncFlush)?;
            }
            RequestType::GetDeviceId => {
                let (data_addr, data_len) = if self.data_descriptors.len() == 1 {
                    (self.data_descriptors[0].0, self.data_descriptors[0].1)
                } else {
                    return Err(ExecuteError::BadRequest(Error::TooManyDescriptors));
                };
                if (data_len as usize) < disk_id.len() {
                    return Err(ExecuteError::BadRequest(Error::InvalidOffset));
                }
                mem.write_slice(disk_id, data_addr)
                    .map_err(ExecuteError::Write)?;
                return Ok(false);
            }
            RequestType::Unsupported(t) => return Err(ExecuteError::Unsupported(t)),
        }

        Ok(true)
    }

    pub fn set_writeback(&mut self, writeback: bool) {
        self.writeback = writeback
    }
}

#[derive(Copy, Clone, Debug, Default, Versionize)]
#[repr(C, packed)]
pub struct VirtioBlockConfig {
    pub capacity: u64,
    pub size_max: u32,
    pub seg_max: u32,
    pub geometry: VirtioBlockGeometry,
    pub blk_size: u32,
    pub physical_block_exp: u8,
    pub alignment_offset: u8,
    pub min_io_size: u16,
    pub opt_io_size: u32,
    pub writeback: u8,
    pub unused: u8,
    pub num_queues: u16,
    pub max_discard_sectors: u32,
    pub max_discard_seg: u32,
    pub discard_sector_alignment: u32,
    pub max_write_zeroes_sectors: u32,
    pub max_write_zeroes_seg: u32,
    pub write_zeroes_may_unmap: u8,
    pub unused1: [u8; 3],
}
unsafe impl ByteValued for VirtioBlockConfig {}

#[derive(Copy, Clone, Debug, Default, Versionize)]
#[repr(C, packed)]
pub struct VirtioBlockGeometry {
    pub cylinders: u16,
    pub heads: u8,
    pub sectors: u8,
}
unsafe impl ByteValued for VirtioBlockGeometry {}

/// Check if io_uring for block device can be used on the current system, as
/// it correctly supports the expected io_uring features.
#[cfg(feature = "io_uring")]
pub fn block_io_uring_is_supported() -> bool {
    let error_msg = "io_uring not supported:";

    // Check we can create an io_uring instance, which effectively verifies
    // that io_uring_setup() syscall is supported.
    let io_uring = match IoUring::new(1) {
        Ok(io_uring) => io_uring,
        Err(e) => {
            info!("{} failed to create io_uring instance: {}", error_msg, e);
            return false;
        }
    };

    let submitter = io_uring.submitter();

    let event_fd = match EventFd::new(libc::EFD_NONBLOCK) {
        Ok(fd) => fd,
        Err(e) => {
            info!("{} failed to create eventfd: {}", error_msg, e);
            return false;
        }
    };

    // Check we can register an eventfd as this is going to be needed while
    // using io_uring with the virtio block device. This also validates that
    // io_uring_register() syscall is supported.
    match submitter.register_eventfd(event_fd.as_raw_fd()) {
        Ok(_) => {}
        Err(e) => {
            info!("{} failed to register eventfd: {}", error_msg, e);
            return false;
        }
    }

    let mut probe = Probe::new();

    // Check we can register a probe to validate supported operations.
    match submitter.register_probe(&mut probe) {
        Ok(_) => {}
        Err(e) => {
            info!("{} failed to register a probe: {}", error_msg, e);
            return false;
        }
    }

    // Check IORING_OP_FSYNC is supported
    if !probe.is_supported(opcode::Fsync::CODE) {
        info!("{} IORING_OP_FSYNC operation not supported", error_msg);
        return false;
    }

    // Check IORING_OP_READ is supported
    if !probe.is_supported(opcode::Read::CODE) {
        info!("{} IORING_OP_READ operation not supported", error_msg);
        return false;
    }

    // Check IORING_OP_WRITE is supported
    if !probe.is_supported(opcode::Write::CODE) {
        info!("{} IORING_OP_WRITE operation not supported", error_msg);
        return false;
    }

    true
}

#[cfg(not(feature = "io_uring"))]
pub fn block_io_uring_is_supported() -> bool {
    false
}

pub fn disk_size(file: &mut dyn Seek, semaphore: &mut Arc<Mutex<()>>) -> DiskFileResult<u64> {
    // Take the semaphore to ensure other threads are not interacting with
    // the underlying file.
    let _lock = semaphore.lock().unwrap();

    Ok(file.seek(SeekFrom::End(0)).map_err(DiskFileError::Size)? as u64)
}

pub trait ReadSeekFile: Read + Seek {}
impl<F: Read + Seek> ReadSeekFile for F {}

pub fn read_vectored_sync(
    offset: libc::off_t,
    iovecs: Vec<libc::iovec>,
    user_data: u64,
    file: &mut dyn ReadSeekFile,
    eventfd: &EventFd,
    completion_list: &mut Vec<(u64, i32)>,
    semaphore: &mut Arc<Mutex<()>>,
) -> AsyncIoResult<()> {
    // Convert libc::iovec into IoSliceMut
    let mut slices = Vec::new();
    for iovec in iovecs.iter() {
        slices.push(IoSliceMut::new(unsafe { std::mem::transmute(*iovec) }));
    }

    let result = {
        // Take the semaphore to ensure other threads are not interacting
        // with the underlying file.
        let _lock = semaphore.lock().unwrap();

        // Move the cursor to the right offset
        file.seek(SeekFrom::Start(offset as u64))
            .map_err(AsyncIoError::ReadVectored)?;

        // Read vectored
        file.read_vectored(slices.as_mut_slice())
            .map_err(AsyncIoError::ReadVectored)?
    };

    completion_list.push((user_data, result as i32));
    eventfd.write(1).unwrap();

    Ok(())
}

pub trait WriteSeekFile: Write + Seek {}
impl<F: Write + Seek> WriteSeekFile for F {}

pub fn write_vectored_sync(
    offset: libc::off_t,
    iovecs: Vec<libc::iovec>,
    user_data: u64,
    file: &mut dyn WriteSeekFile,
    eventfd: &EventFd,
    completion_list: &mut Vec<(u64, i32)>,
    semaphore: &mut Arc<Mutex<()>>,
) -> AsyncIoResult<()> {
    // Convert libc::iovec into IoSlice
    let mut slices = Vec::new();
    for iovec in iovecs.iter() {
        slices.push(IoSlice::new(unsafe { std::mem::transmute(*iovec) }));
    }

    let result = {
        // Take the semaphore to ensure other threads are not interacting
        // with the underlying file.
        let _lock = semaphore.lock().unwrap();

        // Move the cursor to the right offset
        file.seek(SeekFrom::Start(offset as u64))
            .map_err(AsyncIoError::WriteVectored)?;

        // Write vectored
        file.write_vectored(slices.as_slice())
            .map_err(AsyncIoError::WriteVectored)?
    };

    completion_list.push((user_data, result as i32));
    eventfd.write(1).unwrap();

    Ok(())
}

pub fn fsync_sync(
    user_data: Option<u64>,
    file: &mut dyn Write,
    eventfd: &EventFd,
    completion_list: &mut Vec<(u64, i32)>,
    semaphore: &mut Arc<Mutex<()>>,
) -> AsyncIoResult<()> {
    let result: i32 = {
        // Take the semaphore to ensure other threads are not interacting
        // with the underlying file.
        let _lock = semaphore.lock().unwrap();

        // Flush
        file.flush().map_err(AsyncIoError::Fsync)?;

        0
    };

    if let Some(user_data) = user_data {
        completion_list.push((user_data, result));
        eventfd.write(1).unwrap();
    }

    Ok(())
}

pub enum ImageType {
    FixedVhd,
    Qcow2,
    Raw,
}

const QCOW_MAGIC: u32 = 0x5146_49fb;

/// Determine image type through file parsing.
pub fn detect_image_type(f: &mut File) -> std::io::Result<ImageType> {
    // We must create a buffer aligned on 512 bytes with a size being a
    // multiple of 512 bytes as the file might be opened with O_DIRECT flag.
    #[repr(align(512))]
    struct Sector {
        data: [u8; 512],
    }
    let mut s = Sector { data: [0; 512] };

    f.read_exact(&mut s.data)?;

    // Check 4 first bytes to get the header value and determine the image type
    let image_type = if u32::from_be_bytes(s.data[0..4].try_into().unwrap()) == QCOW_MAGIC {
        ImageType::Qcow2
    } else if vhd::is_fixed_vhd(f)? {
        ImageType::FixedVhd
    } else {
        ImageType::Raw
    };

    Ok(image_type)
}
