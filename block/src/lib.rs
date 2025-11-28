// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

pub mod async_io;
pub mod fcntl;
pub mod fixed_vhd;
#[cfg(feature = "io_uring")]
/// Enabled with the `"io_uring"` feature
pub mod fixed_vhd_async;
pub mod fixed_vhd_sync;
pub mod qcow;
pub mod qcow_sync;
#[cfg(feature = "io_uring")]
/// Async primitives based on `io-uring`
///
/// Enabled with the `"io_uring"` feature
pub mod raw_async;
pub mod raw_async_aio;
pub mod raw_sync;
pub mod vhd;
pub mod vhdx;
pub mod vhdx_sync;

use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::collections::VecDeque;
use std::fmt::Debug;
use std::fs::File;
use std::io::{self, IoSlice, IoSliceMut, Read, Seek, SeekFrom, Write};
use std::os::fd::RawFd;
use std::os::linux::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::time::Instant;
use std::{cmp, mem, result};

#[cfg(feature = "io_uring")]
use io_uring::{IoUring, Probe, opcode};
use libc::{S_IFBLK, S_IFMT, ioctl};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use thiserror::Error;
use virtio_bindings::virtio_blk::*;
use virtio_queue::DescriptorChain;
use vm_memory::bitmap::Bitmap;
use vm_memory::{
    Address, ByteValued, Bytes, GuestAddress, GuestMemory, GuestMemoryError, GuestMemoryLoadGuard,
};
use vm_virtio::{AccessPlatform, Translatable};
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::{aio, ioctl_io_nr};

use crate::async_io::{AsyncIo, AsyncIoError, AsyncIoResult};
use crate::vhdx::VhdxError;

const SECTOR_SHIFT: u8 = 9;
pub const SECTOR_SIZE: u64 = 0x01 << SECTOR_SHIFT;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Guest gave us bad memory addresses")]
    GuestMemory(#[source] GuestMemoryError),
    #[error("Guest gave us offsets that would have overflowed a usize")]
    CheckedOffset(GuestAddress, usize /* sector offset */),
    #[error("Guest gave us a write only descriptor that protocol says to read from")]
    UnexpectedWriteOnlyDescriptor,
    #[error("Guest gave us a read only descriptor that protocol says to write to")]
    UnexpectedReadOnlyDescriptor,
    #[error("Guest gave us too few descriptors in a descriptor chain")]
    DescriptorChainTooShort,
    #[error("Guest gave us a descriptor that was too short to use")]
    DescriptorLengthTooSmall,
    #[error("Failed to detect image type")]
    DetectImageType(#[source] std::io::Error),
    #[error("Failure in fixed vhd")]
    FixedVhdError(#[source] std::io::Error),
    #[error("Getting a block's metadata fails for any reason")]
    GetFileMetadata,
    #[error("The requested operation would cause a seek beyond disk end")]
    InvalidOffset,
    #[error("Failure in qcow")]
    QcowError(#[source] qcow::Error),
    #[error("Failure in raw file")]
    RawFileError(#[source] std::io::Error),
    #[error("The requested operation does not support multiple descriptors")]
    TooManyDescriptors,
    #[error("Failure in vhdx")]
    VhdxError(#[source] VhdxError),
    #[error("Invalid file access")]
    InvalidAccess,
    #[error("Failed to punch hole: {0}")]
    PunchHole(AsyncIoError),
    #[error("Failed to write zeroes: {0}")]
    WriteZeroes(AsyncIoError),
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

pub fn build_serial(disk_path: &Path) -> Vec<u8> {
    let mut default_serial = vec![0; VIRTIO_BLK_ID_BYTES as usize];
    match build_device_id(disk_path) {
        Err(_) => {
            warn!("Could not generate device id. We'll use a default.");
        }
        Ok(m) => {
            // The kernel only knows to read a maximum of VIRTIO_BLK_ID_BYTES.
            // This will also zero out any leftover bytes.
            let disk_id = m.as_bytes();
            let bytes_to_copy = cmp::min(disk_id.len(), VIRTIO_BLK_ID_BYTES as usize);
            default_serial[..bytes_to_copy].clone_from_slice(&disk_id[..bytes_to_copy]);
        }
    }
    default_serial
}

#[derive(Error, Debug)]
pub enum ExecuteError {
    #[error("Bad request")]
    BadRequest(#[source] Error),
    #[error("Failed to flush")]
    Flush(#[source] io::Error),
    #[error("Failed to read")]
    Read(#[source] GuestMemoryError),
    #[error("Failed to read_exact")]
    ReadExact(#[source] io::Error),
    #[error("Can't execute an operation other than `read` on a read-only device")]
    ReadOnly,
    #[error("Failed to seek")]
    Seek(#[source] io::Error),
    #[error("Failed to write")]
    Write(#[source] GuestMemoryError),
    #[error("Failed to write_all")]
    WriteAll(#[source] io::Error),
    #[error("Unsupported request: {0}")]
    Unsupported(u32),
    #[error("Failed to submit io uring")]
    SubmitIoUring(#[source] io::Error),
    #[error("Failed to get guest address")]
    GetHostAddress(#[source] GuestMemoryError),
    #[error("Failed to async read")]
    AsyncRead(#[source] AsyncIoError),
    #[error("Failed to async write")]
    AsyncWrite(#[source] AsyncIoError),
    #[error("failed to async flush")]
    AsyncFlush(#[source] AsyncIoError),
    #[error("Failed allocating a temporary buffer")]
    TemporaryBufferAllocation(#[source] io::Error),
    #[error("Failed to handle discard or write zeroes: {0}")]
    DiscardWriteZeroes(Error),
}

impl ExecuteError {
    pub fn status(&self) -> u8 {
        let status = match *self {
            ExecuteError::BadRequest(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::Flush(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::Read(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::ReadExact(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::ReadOnly => VIRTIO_BLK_S_IOERR,
            ExecuteError::Seek(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::Write(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::WriteAll(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::Unsupported(_) => VIRTIO_BLK_S_UNSUPP,
            ExecuteError::SubmitIoUring(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::GetHostAddress(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::AsyncRead(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::AsyncWrite(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::AsyncFlush(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::TemporaryBufferAllocation(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::DiscardWriteZeroes(_) => VIRTIO_BLK_S_IOERR,
        };
        status as u8
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestType {
    In,
    Out,
    Flush,
    GetDeviceId,
    Discard,
    WriteZeroes,
    Unsupported(u32),
}

pub fn request_type<B: Bitmap + 'static>(
    mem: &vm_memory::GuestMemoryMmap<B>,
    desc_addr: GuestAddress,
) -> result::Result<RequestType, Error> {
    let type_ = mem.read_obj(desc_addr).map_err(Error::GuestMemory)?;
    match type_ {
        VIRTIO_BLK_T_IN => Ok(RequestType::In),
        VIRTIO_BLK_T_OUT => Ok(RequestType::Out),
        VIRTIO_BLK_T_FLUSH => Ok(RequestType::Flush),
        VIRTIO_BLK_T_GET_ID => Ok(RequestType::GetDeviceId),
        VIRTIO_BLK_T_DISCARD => Ok(RequestType::Discard),
        VIRTIO_BLK_T_WRITE_ZEROES => Ok(RequestType::WriteZeroes),
        t => Ok(RequestType::Unsupported(t)),
    }
}

fn sector<B: Bitmap + 'static>(
    mem: &vm_memory::GuestMemoryMmap<B>,
    desc_addr: GuestAddress,
) -> result::Result<u64, Error> {
    const SECTOR_OFFSET: usize = 8;
    let addr = match mem.checked_offset(desc_addr, SECTOR_OFFSET) {
        Some(v) => v,
        None => return Err(Error::CheckedOffset(desc_addr, SECTOR_OFFSET)),
    };

    mem.read_obj(addr).map_err(Error::GuestMemory)
}

const DEFAULT_DESCRIPTOR_VEC_SIZE: usize = 32;

#[derive(Debug)]
pub struct AlignedOperation {
    origin_ptr: u64,
    aligned_ptr: u64,
    size: usize,
    layout: Layout,
}

/// One or more `DiscardWriteZeroes` structs are used to describe the data for
/// discard or write zeroes command.
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
struct DiscardWriteZeroes {
    sector: u64,
    num_sectors: u32,
    flags: u32,
}

impl DiscardWriteZeroes {
    // Size of DiscardWriteZeroes struct.
    const LEN: u64 = mem::size_of::<DiscardWriteZeroes>() as u64;
}

// SAFETY: Safe because DiscardWriteZeroes contains only plain data.
unsafe impl ByteValued for DiscardWriteZeroes {}

pub struct BatchRequest {
    pub offset: libc::off_t,
    pub iovecs: SmallVec<[libc::iovec; DEFAULT_DESCRIPTOR_VEC_SIZE]>,
    pub user_data: u64,
    pub request_type: RequestType,
}

pub struct ExecuteAsync {
    // `true` if the execution will complete asynchronously
    pub async_complete: bool,
    // request need to be batched for submission if any
    pub batch_request: Option<BatchRequest>,
}

#[derive(Debug)]
pub struct Request {
    pub request_type: RequestType,
    pub sector: u64,
    pub data_descriptors: SmallVec<[(GuestAddress, u32); DEFAULT_DESCRIPTOR_VEC_SIZE]>,
    pub status_addr: GuestAddress,
    pub writeback: bool,
    pub aligned_operations: SmallVec<[AlignedOperation; DEFAULT_DESCRIPTOR_VEC_SIZE]>,
    pub start: Instant,
}

impl Request {
    pub fn parse<B: Bitmap + 'static>(
        desc_chain: &mut DescriptorChain<GuestMemoryLoadGuard<vm_memory::GuestMemoryMmap<B>>>,
        access_platform: Option<&dyn AccessPlatform>,
    ) -> result::Result<Request, Error> {
        let hdr_desc = desc_chain
            .next()
            .ok_or(Error::DescriptorChainTooShort)
            .inspect_err(|_| {
                error!("Missing head descriptor");
            })?;

        // The head contains the request type which MUST be readable.
        if hdr_desc.is_write_only() {
            return Err(Error::UnexpectedWriteOnlyDescriptor);
        }

        let hdr_desc_addr = hdr_desc
            .addr()
            .translate_gva(access_platform, hdr_desc.len() as usize);

        let mut req = Request {
            request_type: request_type(desc_chain.memory(), hdr_desc_addr)?,
            sector: sector(desc_chain.memory(), hdr_desc_addr)?,
            data_descriptors: SmallVec::with_capacity(DEFAULT_DESCRIPTOR_VEC_SIZE),
            status_addr: GuestAddress(0),
            writeback: true,
            aligned_operations: SmallVec::with_capacity(DEFAULT_DESCRIPTOR_VEC_SIZE),
            start: Instant::now(),
        };

        let status_desc;
        let mut desc = desc_chain
            .next()
            .ok_or(Error::DescriptorChainTooShort)
            .inspect_err(|_| {
                error!("Only head descriptor present: request = {req:?}");
            })?;

        if desc.has_next() {
            req.data_descriptors.reserve_exact(1);
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

                req.data_descriptors.push((
                    desc.addr()
                        .translate_gva(access_platform, desc.len() as usize),
                    desc.len(),
                ));
                desc = desc_chain
                    .next()
                    .ok_or(Error::DescriptorChainTooShort)
                    .inspect_err(|_| {
                        error!("DescriptorChain corrupted: request = {req:?}");
                    })?;
            }
            status_desc = desc;
        } else {
            status_desc = desc;
            // Only flush requests are allowed to skip the data descriptor.
            if req.request_type != RequestType::Flush {
                error!("Need a data descriptor: request = {req:?}");
                return Err(Error::DescriptorChainTooShort);
            }
        }

        // The status MUST always be writable.
        if !status_desc.is_write_only() {
            return Err(Error::UnexpectedReadOnlyDescriptor);
        }

        if status_desc.len() < 1 {
            return Err(Error::DescriptorLengthTooSmall);
        }

        req.status_addr = status_desc
            .addr()
            .translate_gva(access_platform, status_desc.len() as usize);

        Ok(req)
    }

    pub fn execute<T: Seek + Read + Write, B: Bitmap + 'static>(
        &self,
        disk: &mut T,
        disk_nsectors: u64,
        mem: &vm_memory::GuestMemoryMmap<B>,
        serial: &[u8],
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
                    let mut buf = vec![0u8; *data_len as usize];
                    disk.read_exact(&mut buf).map_err(ExecuteError::ReadExact)?;
                    mem.read_exact_volatile_from(
                        *data_addr,
                        &mut buf.as_slice(),
                        *data_len as usize,
                    )
                    .map_err(ExecuteError::Read)?;
                    len += data_len;
                }
                RequestType::Out => {
                    let mut buf: Vec<u8> = Vec::new();
                    mem.write_all_volatile_to(*data_addr, &mut buf, *data_len as usize)
                        .map_err(ExecuteError::Write)?;
                    disk.write_all(&buf).map_err(ExecuteError::WriteAll)?;
                    if !self.writeback {
                        disk.flush().map_err(ExecuteError::Flush)?;
                    }
                }
                RequestType::Flush => disk.flush().map_err(ExecuteError::Flush)?,
                RequestType::GetDeviceId => {
                    if (*data_len as usize) < serial.len() {
                        return Err(ExecuteError::BadRequest(Error::InvalidOffset));
                    }
                    mem.write_slice(serial, *data_addr)
                        .map_err(ExecuteError::Write)?;
                }
                RequestType::Discard => {
                    return Err(ExecuteError::Unsupported(VIRTIO_BLK_T_DISCARD));
                }
                RequestType::WriteZeroes => {
                    return Err(ExecuteError::Unsupported(VIRTIO_BLK_T_WRITE_ZEROES));
                }
                RequestType::Unsupported(t) => return Err(ExecuteError::Unsupported(t)),
            }
        }
        Ok(len)
    }

    pub fn execute_async<B: Bitmap + 'static>(
        &mut self,
        mem: &vm_memory::GuestMemoryMmap<B>,
        disk_nsectors: u64,
        disk_image: &mut dyn AsyncIo,
        serial: &[u8],
        user_data: u64,
        write_zeroes_unmap: bool,
    ) -> result::Result<ExecuteAsync, ExecuteError> {
        let sector = self.sector;
        let request_type = self.request_type;
        let offset = (sector << SECTOR_SHIFT) as libc::off_t;

        let mut iovecs: SmallVec<[libc::iovec; DEFAULT_DESCRIPTOR_VEC_SIZE]> =
            SmallVec::with_capacity(self.data_descriptors.len());
        for &(data_addr, data_len) in &self.data_descriptors {
            let _: u32 = data_len; // compiler-checked documentation
            const _: () = assert!(
                core::mem::size_of::<u32>() <= core::mem::size_of::<usize>(),
                "unsupported platform"
            );
            if data_len == 0 {
                continue;
            }
            let mut top: u64 = u64::from(data_len) / SECTOR_SIZE;
            if u64::from(data_len) % SECTOR_SIZE != 0 {
                top += 1;
            }
            let data_len = data_len as usize;
            top = top
                .checked_add(sector)
                .ok_or(ExecuteError::BadRequest(Error::InvalidOffset))?;
            if top > disk_nsectors {
                return Err(ExecuteError::BadRequest(Error::InvalidOffset));
            }

            let origin_ptr = mem
                .get_slice(data_addr, data_len)
                .map_err(ExecuteError::GetHostAddress)?;
            assert!(origin_ptr.len() >= data_len);
            let origin_ptr = origin_ptr.ptr_guard();

            // Verify the buffer alignment.
            // In case it's not properly aligned, an intermediate buffer is
            // created with the correct alignment, and a copy from/to the
            // origin buffer is performed, depending on the type of operation.
            let iov_base = if (origin_ptr.as_ptr() as u64).is_multiple_of(SECTOR_SIZE) {
                origin_ptr.as_ptr() as *mut libc::c_void
            } else {
                let layout = Layout::from_size_align(data_len, SECTOR_SIZE as usize).unwrap();
                // SAFETY: layout has non-zero size
                let aligned_ptr = unsafe { alloc_zeroed(layout) };
                if aligned_ptr.is_null() {
                    return Err(ExecuteError::TemporaryBufferAllocation(
                        io::Error::last_os_error(),
                    ));
                }

                // We need to perform the copy beforehand in case we're writing
                // data out.
                if request_type == RequestType::Out {
                    // SAFETY: destination buffer has been allocated with
                    // the proper size.
                    unsafe { std::ptr::copy(origin_ptr.as_ptr(), aligned_ptr, data_len) };
                }

                // Store both origin and aligned pointers for complete_async()
                // to process them.
                self.aligned_operations.push(AlignedOperation {
                    origin_ptr: origin_ptr.as_ptr() as u64,
                    aligned_ptr: aligned_ptr as u64,
                    size: data_len,
                    layout,
                });

                aligned_ptr as *mut libc::c_void
            };

            let iovec = libc::iovec {
                iov_base,
                iov_len: data_len as libc::size_t,
            };
            iovecs.push(iovec);
        }

        let mut ret = ExecuteAsync {
            async_complete: true,
            batch_request: None,
        };
        // Queue operations expected to be submitted.
        match request_type {
            RequestType::In => {
                for (data_addr, data_len) in &self.data_descriptors {
                    mem.get_slice(*data_addr, *data_len as usize)
                        .map_err(ExecuteError::GetHostAddress)?
                        .bitmap()
                        .mark_dirty(0, *data_len as usize);
                }
                if disk_image.batch_requests_enabled() {
                    ret.batch_request = Some(BatchRequest {
                        offset,
                        iovecs,
                        user_data,
                        request_type,
                    });
                } else {
                    disk_image
                        .read_vectored(offset, &iovecs, user_data)
                        .map_err(ExecuteError::AsyncRead)?;
                }
            }
            RequestType::Out => {
                if disk_image.batch_requests_enabled() {
                    ret.batch_request = Some(BatchRequest {
                        offset,
                        iovecs,
                        user_data,
                        request_type,
                    });
                } else {
                    disk_image
                        .write_vectored(offset, &iovecs, user_data)
                        .map_err(ExecuteError::AsyncWrite)?;
                }
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
                if (data_len as usize) < serial.len() {
                    return Err(ExecuteError::BadRequest(Error::InvalidOffset));
                }
                mem.write_slice(serial, data_addr)
                    .map_err(ExecuteError::Write)?;
                ret.async_complete = false;
                return Ok(ret);
            }
            RequestType::Discard | RequestType::WriteZeroes => {
                for (data_addr, data_len) in &self.data_descriptors {
                    let data_len = *data_len as u64;
                    // We support for now only data descriptors with the `len` field = multiple of
                    // the size of `virtio_blk_discard_write_zeroes` segment. The specification,
                    // however, requires that only `total_len` be such multiple (a segment can be
                    // divided between several descriptors). Once we switch to a more general
                    // approach regarding how we store and parse the device buffers, we'll fix this
                    // too.
                    if !data_len.is_multiple_of(DiscardWriteZeroes::LEN) {
                        return Err(ExecuteError::BadRequest(Error::InvalidOffset));
                    }
                    let mut available_bytes = data_len;
                    let mut crt_addr = *data_addr;

                    while available_bytes >= DiscardWriteZeroes::LEN {
                        let segment: DiscardWriteZeroes = mem
                            .read_obj(crt_addr)
                            .map_err(|e| ExecuteError::BadRequest(Error::GuestMemory(e)))?;

                        // For Discard, unmap bit (the least significant bit from segment flags)
                        // MUST be 0, for Write Zeroes it can be either 0 or 1.
                        // The other bits are reserved and MUST not be set (for both request types).
                        // If any of these conditions are not met, status must be set to
                        // VIRTIO_BLK_S_UNSUPP.
                        // Verify two invalid request case:
                        //1. Discard request: any unknown flag is set or unmap flag is set.
                        //2. Write zeroes request: any unknown flag is set.
                        if request_type == RequestType::Discard && segment.flags != 0 {
                            return Err(ExecuteError::Unsupported(VIRTIO_BLK_T_DISCARD));
                        } else if request_type == RequestType::WriteZeroes
                            && segment.flags & !1 != 0
                        {
                            return Err(ExecuteError::Unsupported(VIRTIO_BLK_T_WRITE_ZEROES));
                        }

                        Self::handle_discard_write_zeroes_sync(
                            &segment,
                            request_type,
                            disk_nsectors,
                            write_zeroes_unmap,
                            disk_image,
                            user_data,
                        )
                        .map_err(ExecuteError::DiscardWriteZeroes)?;
                        // Using `unchecked_add` here, since the overflow is not possible at this
                        // point (it is checked when parsing the request) and `read_obj` fails if
                        // the memory access is invalid.
                        crt_addr = crt_addr.unchecked_add(DiscardWriteZeroes::LEN);
                        available_bytes -= DiscardWriteZeroes::LEN;
                    }
                }
            }
            RequestType::Unsupported(t) => return Err(ExecuteError::Unsupported(t)),
        }

        Ok(ret)
    }

    fn handle_discard_write_zeroes_sync(
        segment: &DiscardWriteZeroes,
        request_type: RequestType,
        disk_nsectors: u64,
        write_zeroes_unmap: bool,
        disk_image: &mut dyn AsyncIo,
        user_data: u64,
    ) -> Result<(), Error> {
        let sector = segment.sector;
        let num_sectors = segment.num_sectors;
        let _flags = segment.flags;

        let offset = sector
            .checked_shl(u32::from(SECTOR_SHIFT))
            .ok_or(Error::InvalidAccess)?;
        let length = u64::from(num_sectors)
            .checked_shl(u32::from(SECTOR_SHIFT))
            .ok_or(Error::InvalidAccess)?;

        let mut sectors_count = num_sectors as u64;
        sectors_count = sectors_count
            .checked_add(sector)
            .ok_or(Error::InvalidAccess)?;
        if sectors_count > disk_nsectors {
            return Err(Error::InvalidAccess);
        }

        // Unmap has two different cases:
        // - request type is Discard
        // - request type is Write Zeroes and unmap bit is set
        if request_type == RequestType::Discard {
            // Since Discard is just a hint and some filesystems may not implement
            // FALLOC_FL_PUNCH_HOLE, ignore punch_hole() errors.
            disk_image
                .punch_hole(offset, length, user_data)
                .map_err(Error::PunchHole)?;
        } else {
            // If unmap is set, try at first to punch a hole, if it fails, fall back to just
            // writing zeroes.
            // After a write zeroes command is completed, reads of the specified ranges of sectors
            // MUST return zeroes, independent of unmap value.
            if !write_zeroes_unmap || disk_image.punch_hole(offset, length, user_data).is_err() {
                disk_image
                    .write_all_zeroes_at(offset, length as usize, user_data)
                    .map_err(Error::WriteZeroes)?;
            }
        }
        Ok(())
    }

    pub fn complete_async(&mut self) -> result::Result<(), Error> {
        for aligned_operation in self.aligned_operations.drain(..) {
            // We need to perform the copy after the data has been read inside
            // the aligned buffer in case we're reading data in.
            if self.request_type == RequestType::In {
                // SAFETY: origin buffer has been allocated with the
                // proper size.
                unsafe {
                    std::ptr::copy(
                        aligned_operation.aligned_ptr as *const u8,
                        aligned_operation.origin_ptr as *mut u8,
                        aligned_operation.size,
                    );
                };
            }

            // Free the temporary aligned buffer.
            // SAFETY: aligned_ptr was allocated by alloc_zeroed with the same
            // layout
            unsafe {
                dealloc(
                    aligned_operation.aligned_ptr as *mut u8,
                    aligned_operation.layout,
                );
            };
        }

        Ok(())
    }

    pub fn set_writeback(&mut self, writeback: bool) {
        self.writeback = writeback;
    }
}

#[derive(Copy, Clone, Debug, Default, Serialize, Deserialize)]
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
#[derive(Copy, Clone, Debug, Default, Serialize, Deserialize)]
#[repr(C, packed)]
pub struct VirtioBlockGeometry {
    pub cylinders: u16,
    pub heads: u8,
    pub sectors: u8,
}

// SAFETY: data structure only contain a series of integers
unsafe impl ByteValued for VirtioBlockConfig {}
// SAFETY: data structure only contain a series of integers
unsafe impl ByteValued for VirtioBlockGeometry {}

/// Check if aio can be used on the current system.
pub fn block_aio_is_supported() -> bool {
    aio::IoContext::new(1).is_ok()
}

/// Check if io_uring for block device can be used on the current system, as
/// it correctly supports the expected io_uring features.
pub fn block_io_uring_is_supported() -> bool {
    #[cfg(not(feature = "io_uring"))]
    {
        info!("io_uring is disabled by crate features");
        false
    }

    #[cfg(feature = "io_uring")]
    {
        let error_msg = "io_uring not supported:";

        // Check we can create an io_uring instance, which effectively verifies
        // that io_uring_setup() syscall is supported.
        let io_uring = match IoUring::new(1) {
            Ok(io_uring) => io_uring,
            Err(e) => {
                info!("{error_msg} failed to create io_uring instance: {e}");
                return false;
            }
        };

        let submitter = io_uring.submitter();

        let mut probe = Probe::new();

        // Check we can register a probe to validate supported operations.
        match submitter.register_probe(&mut probe) {
            Ok(_) => {}
            Err(e) => {
                info!("{error_msg} failed to register a probe: {e}");
                return false;
            }
        }

        // Check IORING_OP_FSYNC is supported
        if !probe.is_supported(opcode::Fsync::CODE) {
            info!("{error_msg} IORING_OP_FSYNC operation not supported");
            return false;
        }

        // Check IORING_OP_READV is supported
        if !probe.is_supported(opcode::Readv::CODE) {
            info!("{error_msg} IORING_OP_READV operation not supported");
            return false;
        }

        // Check IORING_OP_WRITEV is supported
        if !probe.is_supported(opcode::Writev::CODE) {
            info!("{error_msg} IORING_OP_WRITEV operation not supported");
            return false;
        }

        true
    }
}

pub trait AsyncAdaptor {
    fn read_vectored_sync(
        &mut self,
        offset: libc::off_t,
        iovecs: &[libc::iovec],
        user_data: u64,
        eventfd: &EventFd,
        completion_list: &mut VecDeque<(u64, i32)>,
    ) -> AsyncIoResult<()>
    where
        Self: Read + Seek,
    {
        // Convert libc::iovec into IoSliceMut
        let mut slices: SmallVec<[IoSliceMut; DEFAULT_DESCRIPTOR_VEC_SIZE]> =
            SmallVec::with_capacity(iovecs.len());
        for iovec in iovecs.iter() {
            // SAFETY: on Linux IoSliceMut wraps around libc::iovec
            slices.push(IoSliceMut::new(unsafe {
                std::mem::transmute::<libc::iovec, &mut [u8]>(*iovec)
            }));
        }

        let result = {
            // Move the cursor to the right offset
            self.seek(SeekFrom::Start(offset as u64))
                .map_err(AsyncIoError::ReadVectored)?;

            let mut r = 0;
            for b in slices.iter_mut() {
                r += self.read(b).map_err(AsyncIoError::ReadVectored)?;
            }
            r
        };

        completion_list.push_back((user_data, result as i32));
        eventfd.write(1).unwrap();

        Ok(())
    }

    fn write_vectored_sync(
        &mut self,
        offset: libc::off_t,
        iovecs: &[libc::iovec],
        user_data: u64,
        eventfd: &EventFd,
        completion_list: &mut VecDeque<(u64, i32)>,
    ) -> AsyncIoResult<()>
    where
        Self: Write + Seek,
    {
        // Convert libc::iovec into IoSlice
        let mut slices: SmallVec<[IoSlice; DEFAULT_DESCRIPTOR_VEC_SIZE]> =
            SmallVec::with_capacity(iovecs.len());
        for iovec in iovecs.iter() {
            // SAFETY: on Linux IoSlice wraps around libc::iovec
            slices.push(IoSlice::new(unsafe {
                std::mem::transmute::<libc::iovec, &mut [u8]>(*iovec)
            }));
        }

        let result = {
            // Move the cursor to the right offset
            self.seek(SeekFrom::Start(offset as u64))
                .map_err(AsyncIoError::WriteVectored)?;

            let mut r = 0;
            for b in slices.iter() {
                r += self.write(b).map_err(AsyncIoError::WriteVectored)?;
            }
            r
        };

        completion_list.push_back((user_data, result as i32));
        eventfd.write(1).unwrap();

        Ok(())
    }

    fn fsync_sync(
        &mut self,
        user_data: Option<u64>,
        eventfd: &EventFd,
        completion_list: &mut VecDeque<(u64, i32)>,
    ) -> AsyncIoResult<()>
    where
        Self: Write,
    {
        let result: i32 = {
            // Flush
            self.flush().map_err(AsyncIoError::Fsync)?;

            0
        };

        if let Some(user_data) = user_data {
            completion_list.push_back((user_data, result));
            eventfd.write(1).unwrap();
        }

        Ok(())
    }
}

pub enum ImageType {
    FixedVhd,
    Qcow2,
    Raw,
    Vhdx,
}

const QCOW_MAGIC: u32 = 0x5146_49fb;
const VHDX_SIGN: u64 = 0x656C_6966_7864_6876;

/// Read a block into memory aligned by the source block size (needed for O_DIRECT)
pub fn read_aligned_block_size(f: &mut File) -> std::io::Result<Vec<u8>> {
    let blocksize = DiskTopology::probe(f)?.logical_block_size as usize;
    // SAFETY: We are allocating memory that is naturally aligned (size = alignment) and we meet
    // requirements for safety from Vec::from_raw_parts() as we are using the global allocator
    // and transferring ownership of the memory.
    let mut data = unsafe {
        Vec::from_raw_parts(
            alloc_zeroed(Layout::from_size_align_unchecked(blocksize, blocksize)),
            blocksize,
            blocksize,
        )
    };
    f.read_exact(&mut data)?;
    Ok(data)
}

/// Determine image type through file parsing.
pub fn detect_image_type(f: &mut File) -> std::io::Result<ImageType> {
    let block = read_aligned_block_size(f)?;

    // Check 4 first bytes to get the header value and determine the image type
    let image_type = if u32::from_be_bytes(block[0..4].try_into().unwrap()) == QCOW_MAGIC {
        ImageType::Qcow2
    } else if vhd::is_fixed_vhd(f)? {
        ImageType::FixedVhd
    } else if u64::from_le_bytes(block[0..8].try_into().unwrap()) == VHDX_SIGN {
        ImageType::Vhdx
    } else {
        ImageType::Raw
    };

    Ok(image_type)
}

pub trait BlockBackend: Read + Write + Seek + Send + Debug {
    fn size(&self) -> Result<u64, Error>;
}

#[derive(Debug)]
pub struct DiskTopology {
    pub logical_block_size: u64,
    pub physical_block_size: u64,
    pub minimum_io_size: u64,
    pub optimal_io_size: u64,
}

impl Default for DiskTopology {
    fn default() -> Self {
        Self {
            logical_block_size: 512,
            physical_block_size: 512,
            minimum_io_size: 512,
            optimal_io_size: 0,
        }
    }
}

ioctl_io_nr!(BLKSSZGET, 0x12, 104);
ioctl_io_nr!(BLKDISCARD, 0x12, 119);
ioctl_io_nr!(BLKIOMIN, 0x12, 120);
ioctl_io_nr!(BLKIOOPT, 0x12, 121);
ioctl_io_nr!(BLKPBSZGET, 0x12, 123);
ioctl_io_nr!(BLKZEROOUT, 0x12, 127);

ioctl_io_nr!(BLOCK_URING_CMD_DISCARD, 0x12, 0);

#[derive(Copy, Clone)]
enum BlockSize {
    LogicalBlock,
    PhysicalBlock,
    MinimumIo,
    OptimalIo,
}

impl DiskTopology {
    fn is_block_device(f: RawFd) -> std::io::Result<bool> {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: FFI call with a valid fd and buffer
        let ret = unsafe { libc::fstat(f, stat.as_mut_ptr()) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }

        // SAFETY: stat is valid at this point
        let is_block = unsafe { (*stat.as_ptr()).st_mode & S_IFMT == S_IFBLK };
        Ok(is_block)
    }

    // libc::ioctl() takes different types on different architectures
    fn query_block_size(f: &File, block_size_type: BlockSize) -> std::io::Result<u64> {
        let mut block_size = 0;
        // SAFETY: FFI call with correct arguments
        let ret = unsafe {
            ioctl(
                f.as_raw_fd(),
                match block_size_type {
                    BlockSize::LogicalBlock => BLKSSZGET(),
                    BlockSize::PhysicalBlock => BLKPBSZGET(),
                    BlockSize::MinimumIo => BLKIOMIN(),
                    BlockSize::OptimalIo => BLKIOOPT(),
                } as _,
                &mut block_size,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(block_size)
    }

    pub fn probe(f: &File) -> std::io::Result<Self> {
        if !Self::is_block_device(f.as_raw_fd())? {
            return Ok(DiskTopology::default());
        }

        Ok(DiskTopology {
            logical_block_size: Self::query_block_size(f, BlockSize::LogicalBlock)?,
            physical_block_size: Self::query_block_size(f, BlockSize::PhysicalBlock)?,
            minimum_io_size: Self::query_block_size(f, BlockSize::MinimumIo)?,
            optimal_io_size: Self::query_block_size(f, BlockSize::OptimalIo)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use epoll::Event;
    use std::os::fd::FromRawFd;
    use std::panic;
    use std::process::Command;
    use std::sync::Arc;
    use virtio_bindings::bindings::virtio_ring::VRING_DESC_F_WRITE;
    use virtio_queue::desc::RawDescriptor;
    use virtio_queue::desc::split::Descriptor;
    use virtio_queue::mock::MockSplitQueue;
    use virtio_queue::{Queue, QueueT};
    use vm_memory::bitmap::AtomicBitmap;
    use vm_memory::{GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::async_io::DiskFile;
    #[cfg(feature = "io_uring")]
    use crate::raw_async::RawFileDisk;
    use crate::raw_sync::RawFileDiskSync;

    const COMPLETION_EVENT: u16 = 17;

    #[derive(Copy, Clone, Debug, Default)]
    #[repr(C)]
    struct RequestHeader {
        request_type: u32,
        _reserved: u32,
        sector: u64,
    }

    // SAFETY: data structure only contain a series of integers
    unsafe impl ByteValued for RequestHeader {}

    struct DummyBlKDev {
        loop_device: String,
    }

    impl DummyBlKDev {
        pub fn new(path: &str) -> Self {
            let output = Command::new("losetup")
                .arg("--find")
                .arg("--show")
                .arg(path)
                .output()
                .unwrap();

            assert!(output.status.success());

            let loop_device = String::from_utf8_lossy(&output.stdout).trim().to_string();
            Self { loop_device }
        }

        pub fn open(&self) -> File {
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(self.loop_device.as_str()).unwrap()
        }
    }
    impl Drop for DummyBlKDev {
        fn drop(&mut self) {
            let _ = Command::new("losetup")
                .arg("-d")
                .arg(self.loop_device.as_str())
                .output();
        }
    }

    fn read_data_vec(
        disk_image_async: &mut dyn AsyncIo,
        user_data: u64,
        offset: u64,
        len: usize,
    ) -> Vec<u8> {
        let mut data_vec = vec![0u8; len];
        let iovec = vec![libc::iovec {
            iov_base: data_vec.as_mut_ptr() as *mut libc::c_void,
            iov_len: len as libc::size_t,
        }];
        disk_image_async
            .read_vectored(offset as libc::off_t, &iovec, user_data)
            .unwrap();
        data_vec
    }

    fn wait_evt(
        epoll_file: &File,
        timeout: i32,
        events: &mut [Event],
        disk_image_async: &dyn AsyncIo,
    ) {
        loop {
            let evt_num = match epoll::wait(epoll_file.as_raw_fd(), timeout, &mut events[..]) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => panic!("epoll_wait failed: {e}"),
            };

            for event in events.iter().take(evt_num) {
                assert_eq!(event.data as u16, COMPLETION_EVENT);
                disk_image_async.notifier().read().unwrap();
            }
            break;
        }
    }

    #[test]
    fn test_parse_request() {
        let mem: GuestMemoryMmap<AtomicBitmap> =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000_0000)]).unwrap();
        let vq = MockSplitQueue::new(&mem, 128);

        {
            let v = [
                // A device-writable request header descriptor.
                RawDescriptor::from(Descriptor::new(
                    0x10_0000,
                    0x100,
                    VRING_DESC_F_WRITE as u16,
                    0,
                )),
                RawDescriptor::from(Descriptor::new(
                    0x20_0000,
                    0x100,
                    VRING_DESC_F_WRITE as u16,
                    0,
                )),
                RawDescriptor::from(Descriptor::new(
                    0x30_0000,
                    0x100,
                    VRING_DESC_F_WRITE as u16,
                    0,
                )),
            ];
            vq.build_desc_chain(&v).unwrap();
            let mut queue: Queue = vq.create_queue().unwrap();
            let req_header = RequestHeader {
                request_type: VIRTIO_BLK_T_IN,
                _reserved: 0,
                sector: 2,
            };
            mem.write_obj::<RequestHeader>(req_header, GuestAddress(0x10_0000))
                .unwrap();
            let mem_atomic: GuestMemoryAtomic<GuestMemoryMmap<AtomicBitmap>> =
                GuestMemoryAtomic::from(Arc::new(mem.clone()));
            let mut chain = queue.pop_descriptor_chain(mem_atomic.memory()).unwrap();
            // Request header descriptor should be device-readable.
            Request::parse(&mut chain, None).unwrap_err();
        }

        // Valid descriptor chain for FLUSH.
        {
            let v = [
                RawDescriptor::from(Descriptor::new(0x10_0000, 0x100, 0, 0)),
                RawDescriptor::from(Descriptor::new(
                    0x40_0000,
                    0x100,
                    VRING_DESC_F_WRITE as u16,
                    0,
                )),
            ];
            vq.build_desc_chain(&v).unwrap();
            let mut queue: Queue = vq.create_queue().unwrap();
            let req_header = RequestHeader {
                request_type: VIRTIO_BLK_T_FLUSH,
                _reserved: 0,
                sector: 0,
            };
            mem.write_obj::<RequestHeader>(req_header, GuestAddress(0x10_0000))
                .unwrap();

            let mem_atomic: GuestMemoryAtomic<GuestMemoryMmap<AtomicBitmap>> =
                GuestMemoryAtomic::from(Arc::new(mem));
            let mut chain = queue.pop_descriptor_chain(mem_atomic.memory()).unwrap();
            Request::parse(&mut chain, None).unwrap();
        }
    }

    #[cfg(feature = "io_uring")]
    #[test]
    fn test_raw_io_uring_discard_wr_zeroes_request() {
        _test_discard_wr_zeroes_request(false, true);
    }

    #[test]
    fn test_raw_sync_discard_wr_zeroes_request() {
        _test_discard_wr_zeroes_request(false, false);
    }

    #[cfg(feature = "io_uring")]
    #[test]
    fn test_blk_dev_raw_io_uring_discard_wr_zeroes_request() {
        _test_discard_wr_zeroes_request(true, true);
    }

    #[test]
    fn test_blk_dev_raw_sync_discard_wr_zeroes_request() {
        _test_discard_wr_zeroes_request(true, false);
    }

    fn _test_discard_wr_zeroes_request(is_block_dev: bool, raw_async_flag: bool) {
        const NON_ZERO_VALUE: u8 = 0x55;
        let disk_size = 0x1000u64;
        let disk_nsectors = disk_size / SECTOR_SIZE; // 8
        // 0x000-0x200: 0
        // 0x200-0x400: 1
        // 0x400-0x600: 2
        // 0x600-0x800: 3
        // 0x800-0xA00: 4
        // 0xA00-0xC00: 5
        // 0xC00-0xE00: 6
        // 0xE00-0x1000: 7

        let mut _loop_device = None;
        let f = if is_block_dev {
            let path = "/tmp/test_discard_dev.raw";
            let file = File::create(path).unwrap();
            file.set_len(disk_size).unwrap();
            let device = DummyBlKDev::new(path);
            let f = device.open();
            _loop_device = Some(device);
            f
        } else {
            let f = TempFile::new().unwrap().into_file();
            f.set_len(disk_size).unwrap();
            f
        };

        let mut disk_image = if raw_async_flag {
            #[cfg(not(feature = "io_uring"))]
            unreachable!("Checked in if statement above");
            #[cfg(feature = "io_uring")]
            {
                Box::new(RawFileDisk::new(f)) as Box<dyn DiskFile>
            }
        } else {
            Box::new(RawFileDiskSync::new(f)) as Box<dyn DiskFile>
        };
        let mut disk_image_async = disk_image.new_async_io(128).unwrap();
        let disk_image_id_str = String::from("test image");
        let disk_image_id = disk_image_id_str.as_bytes();

        // Create the epoll file descriptor
        let epoll_fd = epoll::create(true).unwrap();
        // Use 'File' to enforce closing on 'epoll_fd'
        // SAFETY: epoll_fd is a valid fd
        let epoll_file = unsafe { File::from_raw_fd(epoll_fd) };
        epoll::ctl(
            epoll_file.as_raw_fd(),
            epoll::ControlOptions::EPOLL_CTL_ADD,
            disk_image_async.notifier().as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, COMPLETION_EVENT.into()),
        )
        .unwrap();
        let mut events = [epoll::Event::new(epoll::Events::empty(), 0); 1];
        let timeout = 5;

        let mem: GuestMemoryMmap<AtomicBitmap> =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000_0000)]).unwrap();
        let vq = MockSplitQueue::new(&mem, 128);
        let v = [
            RawDescriptor::from(Descriptor::new(0x10_0000, 0x100, 0, 0)),
            // 0x100:0 0x200: NON_ZERO_VALUE 0x100: 0
            RawDescriptor::from(Descriptor::new(0x100, 0x400, 0, 0)),
            // 0x80: NON_ZERO_VALUE 0x120: 0
            RawDescriptor::from(Descriptor::new(0x800, 0x200, 0, 0)),
            RawDescriptor::from(Descriptor::new(
                0x40_0000,
                0x100,
                VRING_DESC_F_WRITE as u16,
                0,
            )),
        ];
        vq.build_desc_chain(&v).unwrap();
        let mut queue: Queue = vq.create_queue().unwrap();

        mem.write_slice(&[NON_ZERO_VALUE; 0x200], GuestAddress(0x200))
            .unwrap();
        mem.write_slice(&[NON_ZERO_VALUE; 0x100], GuestAddress(0x880))
            .unwrap();
        let req_header = RequestHeader {
            request_type: VIRTIO_BLK_T_OUT,
            _reserved: 0,
            sector: 1,
        };
        mem.write_obj::<RequestHeader>(req_header, GuestAddress(0x10_0000))
            .unwrap();

        {
            let mem_atomic: GuestMemoryAtomic<GuestMemoryMmap<AtomicBitmap>> =
                GuestMemoryAtomic::from(Arc::new(mem.clone()));
            let mut chain = queue.pop_descriptor_chain(mem_atomic.memory()).unwrap();
            let mut request = Request::parse(&mut chain, None).unwrap();

            // We will write in file at sector 1 (offset 0x200) 0x400 bytes from 0x100 guest memory
            // address and 0x200 bytes from 0x800 address. 0 bytes should've been written in memory.
            if let Ok(ExecuteAsync {
                async_complete: true,
                batch_request,
            }) = request.execute_async(
                chain.memory(),
                disk_nsectors,
                disk_image_async.as_mut(),
                disk_image_id,
                chain.head_index() as u64,
                false,
            ) {
                let mut batch_requests = Vec::new();
                if let Some(batch_request) = batch_request {
                    match batch_request.request_type {
                        RequestType::In | RequestType::Out => batch_requests.push(batch_request),
                        _ => {
                            unreachable!(
                                "Unexpected batch request type: {:?}",
                                request.request_type
                            )
                        }
                    }
                    disk_image_async
                        .submit_batch_requests(&batch_requests)
                        .unwrap();
                }
            }
            wait_evt(&epoll_file, timeout, &mut events, disk_image_async.as_ref());
            // file data now:
            // 0x000-0x300: 0
            // 0x300-0x500: NON_ZERO_VALUE
            // 0x500-0x680: 0
            // 0x680-0x780: NON_ZERO_VALUE
            // 0x780-0x800: 0
        }

        // Let's write some more bytes to the file.
        mem.write_slice(&[NON_ZERO_VALUE + 1; 0x600], GuestAddress(0x3100))
            .unwrap();

        // Write at offset 0x600 in file, 800 bytes: the first 100 bytes = 0, the next 600 bytes =
        // = NON_ZERO_VALUE + 1 and the last 100 bytes = 0; and then at offset 0x600 + 0x800 =
        // = 0xE00, which is the last sector, 200 bytes = NON_ZERO_VALUE.
        let v = [
            RawDescriptor::from(Descriptor::new(0x10_0000, 0x100, 0, 0)),
            // 0x100:0 0x600: NON_ZERO_VALUE+1 0x100: 0
            RawDescriptor::from(Descriptor::new(0x3000, 0x800, 0, 0)),
            // 0x200: NON_ZERO_VALUE
            RawDescriptor::from(Descriptor::new(0x200, 0x200, 0, 0)),
            RawDescriptor::from(Descriptor::new(
                0x40_0000,
                0x100,
                VRING_DESC_F_WRITE as u16,
                0,
            )),
        ];
        vq.build_desc_chain(&v).unwrap();
        let mut queue: Queue = vq.create_queue().unwrap();

        let req_header = RequestHeader {
            request_type: VIRTIO_BLK_T_OUT,
            _reserved: 0,
            sector: 3,
        };
        mem.write_obj::<RequestHeader>(req_header, GuestAddress(0x10_0000))
            .unwrap();

        {
            let mem_atomic: GuestMemoryAtomic<GuestMemoryMmap<AtomicBitmap>> =
                GuestMemoryAtomic::from(Arc::new(mem.clone()));
            let mut chain = queue.pop_descriptor_chain(mem_atomic.memory()).unwrap();
            let mut request = Request::parse(&mut chain, None).unwrap();

            // We will write in file at sector 1 (offset 0x200) 0x400 bytes from 0x100 guest memory
            // address and 0x200 bytes from 0x800 address. 0 bytes should've been written in memory.
            if let Ok(ExecuteAsync {
                async_complete: true,
                batch_request,
            }) = request.execute_async(
                chain.memory(),
                disk_nsectors,
                disk_image_async.as_mut(),
                disk_image_id,
                chain.head_index() as u64,
                false,
            ) {
                let mut batch_requests = Vec::new();
                if let Some(batch_request) = batch_request {
                    match batch_request.request_type {
                        RequestType::In | RequestType::Out => batch_requests.push(batch_request),
                        _ => {
                            unreachable!(
                                "Unexpected batch request type: {:?}",
                                request.request_type
                            )
                        }
                    }
                    disk_image_async
                        .submit_batch_requests(&batch_requests)
                        .unwrap();
                }
            }
            wait_evt(&epoll_file, timeout, &mut events, disk_image_async.as_ref());
            // file data now:
            // 0x000-0x300: 0
            // 0x300-0x500: NON_ZERO_VALUE
            // 0x500-0x700: 0
            // 0x700-0xD00: NON_ZERO_VALUE + 1
            // 0xD00-0xE00: 0
            // 0xE00-0x1000: NON_ZERO_VALUE
        }

        // Test write zeroes request.
        // Write zeroes at offset 0x400 in file, 2 sectors = 0x400 bytes.
        let wr_zeroes_1 = DiscardWriteZeroes {
            sector: 2,
            num_sectors: 2,
            flags: 0,
        };
        mem.write_obj::<DiscardWriteZeroes>(wr_zeroes_1, GuestAddress(0x1000))
            .unwrap();
        // Write zeroes at offset 0xA00 in file, 1 sector = 0x200 bytes.
        let wr_zeroes_2 = DiscardWriteZeroes {
            sector: 5,
            num_sectors: 1,
            flags: 0,
        };
        mem.write_obj::<DiscardWriteZeroes>(wr_zeroes_2, GuestAddress(0x4000))
            .unwrap();

        let v = [
            RawDescriptor::from(Descriptor::new(0x10_0000, 0x100, 0, 0)),
            RawDescriptor::from(Descriptor::new(
                0x1000,
                DiscardWriteZeroes::LEN as u32,
                0,
                0,
            )),
            RawDescriptor::from(Descriptor::new(
                0x4000,
                DiscardWriteZeroes::LEN as u32,
                0,
                0,
            )),
            RawDescriptor::from(Descriptor::new(
                0x40_0000,
                0x100,
                VRING_DESC_F_WRITE as u16,
                0,
            )),
        ];
        vq.build_desc_chain(&v).unwrap();
        let mut queue: Queue = vq.create_queue().unwrap();

        let req_header = RequestHeader {
            request_type: VIRTIO_BLK_T_WRITE_ZEROES,
            _reserved: 0,
            sector: 2,
        };
        mem.write_obj::<RequestHeader>(req_header, GuestAddress(0x10_0000))
            .unwrap();

        {
            let mem_atomic: GuestMemoryAtomic<GuestMemoryMmap<AtomicBitmap>> =
                GuestMemoryAtomic::from(Arc::new(mem.clone()));
            let mut chain = queue.pop_descriptor_chain(mem_atomic.memory()).unwrap();
            let mut request = Request::parse(&mut chain, None).unwrap();

            // 0 bytes should've been written in memory.
            request
                .execute_async(
                    chain.memory(),
                    disk_nsectors,
                    disk_image_async.as_mut(),
                    disk_image_id,
                    chain.head_index() as u64,
                    false,
                )
                .unwrap();
            wait_evt(&epoll_file, timeout, &mut events, disk_image_async.as_ref());

            // expected file data:
            // 0x000-0x300: 0
            // 0x300-0x400: NON_ZERO_VALUE
            // 0x400-0x800: 0
            // 0x800-0xA00: NON_ZERO_VALUE + 1
            // 0xA00-0xC00: 0
            // 0xC00-0xD00: NON_ZERO_VALUE + 1
            // 0xD00-0xE00: 0
            // 0xE00-0x1000: NON_ZERO_VALUE
            let data_vec = read_data_vec(
                disk_image_async.as_mut(),
                chain.head_index() as u64,
                0x0,
                0x300,
            );
            wait_evt(&epoll_file, timeout, &mut events, disk_image_async.as_ref());
            assert_eq!(data_vec, vec![0x0; 0x300]);

            let data_vec = read_data_vec(
                disk_image_async.as_mut(),
                chain.head_index() as u64,
                0x300,
                0x100,
            );
            wait_evt(&epoll_file, timeout, &mut events, disk_image_async.as_ref());
            assert_eq!(data_vec, vec![NON_ZERO_VALUE; 0x100]);

            let data_vec = read_data_vec(
                disk_image_async.as_mut(),
                chain.head_index() as u64,
                0x400,
                0x400,
            );
            wait_evt(&epoll_file, timeout, &mut events, disk_image_async.as_ref());
            assert_eq!(data_vec, vec![0x0; 0x400]);

            let data_vec = read_data_vec(
                disk_image_async.as_mut(),
                chain.head_index() as u64,
                0x800,
                0x200,
            );
            wait_evt(&epoll_file, timeout, &mut events, disk_image_async.as_ref());
            assert_eq!(data_vec, vec![NON_ZERO_VALUE + 1; 0x200]);

            let data_vec = read_data_vec(
                disk_image_async.as_mut(),
                chain.head_index() as u64,
                0xA00,
                0x200,
            );
            wait_evt(&epoll_file, timeout, &mut events, disk_image_async.as_ref());
            assert_eq!(data_vec, vec![0; 0x200]);

            let data_vec = read_data_vec(
                disk_image_async.as_mut(),
                chain.head_index() as u64,
                0xC00,
                0x100,
            );
            wait_evt(&epoll_file, timeout, &mut events, disk_image_async.as_ref());
            assert_eq!(data_vec, vec![NON_ZERO_VALUE + 1; 0x100]);

            let data_vec = read_data_vec(
                disk_image_async.as_mut(),
                chain.head_index() as u64,
                0xD00,
                0x100,
            );
            assert_eq!(data_vec, vec![0; 0x100]);

            let data_vec = read_data_vec(
                disk_image_async.as_mut(),
                chain.head_index() as u64,
                0xE00,
                0x100,
            );
            wait_evt(&epoll_file, timeout, &mut events, disk_image_async.as_ref());
            assert_eq!(data_vec, vec![NON_ZERO_VALUE; 0x100]);
        }

        // Test discard request.
        let discard_req = DiscardWriteZeroes {
            sector: 7,
            num_sectors: 1,
            flags: 0,
        };
        mem.write_obj::<DiscardWriteZeroes>(discard_req, GuestAddress(0x1000))
            .unwrap();

        let v = [
            RawDescriptor::from(Descriptor::new(0x10_0000, 0x100, 0, 0)),
            RawDescriptor::from(Descriptor::new(
                0x1000,
                DiscardWriteZeroes::LEN as u32,
                0,
                0,
            )),
            RawDescriptor::from(Descriptor::new(
                0x40_0000,
                0x100,
                VRING_DESC_F_WRITE as u16,
                0,
            )),
        ];
        vq.build_desc_chain(&v).unwrap();
        let mut queue: Queue = vq.create_queue().unwrap();

        let req_header = RequestHeader {
            request_type: VIRTIO_BLK_T_DISCARD,
            _reserved: 0,
            sector: 7,
        };
        mem.write_obj::<RequestHeader>(req_header, GuestAddress(0x10_0000))
            .unwrap();

        {
            let mem_atomic: GuestMemoryAtomic<GuestMemoryMmap<AtomicBitmap>> =
                GuestMemoryAtomic::from(Arc::new(mem.clone()));
            let mut chain = queue.pop_descriptor_chain(mem_atomic.memory()).unwrap();
            let mut request = Request::parse(&mut chain, None).unwrap();

            request
                .execute_async(
                    chain.memory(),
                    disk_nsectors,
                    disk_image_async.as_mut(),
                    disk_image_id,
                    chain.head_index() as u64,
                    false,
                )
                .unwrap();
            wait_evt(&epoll_file, timeout, &mut events, disk_image_async.as_ref());

            let data_vec = read_data_vec(
                disk_image_async.as_mut(),
                chain.head_index() as u64,
                0xE00,
                0x200,
            );
            wait_evt(&epoll_file, timeout, &mut events, disk_image_async.as_ref());
            assert_eq!(data_vec, vec![0x0; 0x200]);
            // Even though we punched a hole at the end of the file, the file size should remain the
            // same since FALLOC_FL_PUNCH_HOLE is used with FALLOC_FL_KEEP_SIZE.
            assert_eq!(disk_image.size().unwrap(), 0x1000);
        }

        // Test that write zeroes request with unmap bit set is okay.
        let wr_zeroes_req = DiscardWriteZeroes {
            sector: 4,
            num_sectors: 1,
            flags: 0x0001,
        };
        mem.write_obj::<DiscardWriteZeroes>(wr_zeroes_req, GuestAddress(0x1000))
            .unwrap();

        let v = [
            RawDescriptor::from(Descriptor::new(0x10_0000, 0x100, 0, 0)),
            RawDescriptor::from(Descriptor::new(
                0x1000,
                DiscardWriteZeroes::LEN as u32,
                0,
                0,
            )),
            RawDescriptor::from(Descriptor::new(
                0x40_0000,
                0x100,
                VRING_DESC_F_WRITE as u16,
                0,
            )),
        ];
        vq.build_desc_chain(&v).unwrap();
        let mut queue: Queue = vq.create_queue().unwrap();

        let req_header = RequestHeader {
            request_type: VIRTIO_BLK_T_WRITE_ZEROES,
            _reserved: 0,
            sector: 7,
        };
        mem.write_obj::<RequestHeader>(req_header, GuestAddress(0x10_0000))
            .unwrap();

        {
            let mem_atomic: GuestMemoryAtomic<GuestMemoryMmap<AtomicBitmap>> =
                GuestMemoryAtomic::from(Arc::new(mem.clone()));
            let mut chain = queue.pop_descriptor_chain(mem_atomic.memory()).unwrap();
            let mut request = Request::parse(&mut chain, None).unwrap();

            let data_vec = read_data_vec(
                disk_image_async.as_mut(),
                chain.head_index() as u64,
                0x800,
                0x200,
            );
            wait_evt(&epoll_file, timeout, &mut events, disk_image_async.as_ref());
            // Data is != 0 before the write zeroes request.
            assert_eq!(data_vec, vec![NON_ZERO_VALUE + 1; 0x200]);

            // Let's write some data in the file right before and after the fourth sector to confirm
            // that those regions won't be zeroed out.
            // After the fourth sector:
            let mut v = vec![NON_ZERO_VALUE + 2; 0x200];
            disk_image_async
                .write_vectored(
                    0xA00 as libc::off_t,
                    &[libc::iovec {
                        iov_base: v.as_mut_ptr() as *mut libc::c_void,
                        iov_len: v.len() as libc::size_t,
                    }],
                    chain.head_index() as u64,
                )
                .unwrap();
            // Before the fourth sector:
            disk_image_async
                .write_vectored(
                    0x600 as libc::off_t,
                    &[libc::iovec {
                        iov_base: v.as_mut_ptr() as *mut libc::c_void,
                        iov_len: v.len() as libc::size_t,
                    }],
                    chain.head_index() as u64,
                )
                .unwrap();

            // 0 bytes should've been written in memory.
            request
                .execute_async(
                    chain.memory(),
                    disk_nsectors,
                    disk_image_async.as_mut(),
                    disk_image_id,
                    chain.head_index() as u64,
                    false,
                )
                .unwrap();
            wait_evt(&epoll_file, timeout, &mut events, disk_image_async.as_ref());

            let data = read_data_vec(
                disk_image_async.as_mut(),
                chain.head_index() as u64,
                0x600,
                0x200,
            );
            wait_evt(&epoll_file, timeout, &mut events, disk_image_async.as_ref());
            assert_eq!(data, vec![NON_ZERO_VALUE + 2; 0x200]);

            let data = read_data_vec(
                disk_image_async.as_mut(),
                chain.head_index() as u64,
                0x800,
                0x200,
            );
            wait_evt(&epoll_file, timeout, &mut events, disk_image_async.as_ref());
            assert_eq!(data, vec![0; 0x200]);

            let data = read_data_vec(
                disk_image_async.as_mut(),
                chain.head_index() as u64,
                0xA00,
                0x200,
            );
            wait_evt(&epoll_file, timeout, &mut events, disk_image_async.as_ref());
            assert_eq!(data, vec![NON_ZERO_VALUE + 2; 0x200]);
        }
    }
}
