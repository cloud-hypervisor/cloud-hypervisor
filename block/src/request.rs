// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem;
use std::time::Instant;

use libc::iovec;
use log::{error, warn};
use smallvec::SmallVec;
use virtio_bindings::virtio_blk::{
    VIRTIO_BLK_T_DISCARD, VIRTIO_BLK_T_WRITE_ZEROES, VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP,
    virtio_blk_discard_write_zeroes,
};
use virtio_queue::DescriptorChain;
use vm_memory::bitmap::Bitmap;
use vm_memory::{
    Address as _, Bytes as _, GuestAddress, GuestMemory as _, GuestMemoryError,
    GuestMemoryLoadGuard, GuestRegionCollection, GuestRegionMmap,
};
use vm_virtio::{AccessPlatform, Translatable as _};

use crate::async_io::AsyncIo;
use crate::{Error, ExecuteError, request_type, sector};

const SECTOR_SHIFT: u8 = 9;
pub const SECTOR_SIZE: u64 = 0x01 << SECTOR_SHIFT;

/// Maximum number of segments per DISCARD or WRITE_ZEROES request.
pub const MAX_DISCARD_WRITE_ZEROES_SEG: u32 = 1;
/// Size and field offsets within `struct virtio_blk_discard_write_zeroes`.
const DISCARD_WZ_SEG_SIZE: u32 = mem::size_of::<virtio_blk_discard_write_zeroes>() as u32;
const DISCARD_WZ_MAX_PAYLOAD: u32 = DISCARD_WZ_SEG_SIZE * MAX_DISCARD_WRITE_ZEROES_SEG;
const DISCARD_WZ_SECTOR_OFFSET: u64 =
    mem::offset_of!(virtio_blk_discard_write_zeroes, sector) as u64;
const DISCARD_WZ_NUM_SECTORS_OFFSET: u64 =
    mem::offset_of!(virtio_blk_discard_write_zeroes, num_sectors) as u64;
const DISCARD_WZ_FLAGS_OFFSET: u64 = mem::offset_of!(virtio_blk_discard_write_zeroes, flags) as u64;
#[derive(Debug)]
pub struct AlignedOperation {
    origin_ptr: u64,
    aligned_ptr: u64,
    size: usize,
    layout: Layout,
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

pub const DEFAULT_DESCRIPTOR_VEC_SIZE: usize = 32;

/// A vector of pointers to guest memory, along with a reference to the
/// snapshot of the memory keeping them alove.
pub struct GuestIovecs {
    // DO NOT USE SMALLVEC HERE!!!!!!
    //
    // The io_uring code submits *pointers to arrays of iovec* to the kernel.
    // Therefore, the pointers *must remain stable*.  This means they must be
    // behind an indirection, rather than being stored inline in the HashMap.
    // SmallVec stores the iovecs inline, so pointers to them become invalid
    // when the iovec resizes.
    //
    // See https://github.com/tokio-rs/io-uring/issues/391#issuecomment-4241517187
    // for the diagnosis.  This took two days to find.
    iovecs: Vec<libc::iovec>,
    // This only serves to keep the memory backing the pointers alive.
    #[allow(dead_code)]
    desc_chain: DescChain,
}

impl GuestIovecs {
    /// Returns a reference to an iovec.
    ///
    /// The pointer this reference refers to is guaranteed to be behind
    /// an indirection.  In other words, the iovecs will not move even if
    /// this object is moved.  It is not safe to use the reference after
    /// that, but it can be converted to a pointer first.
    pub fn iovecs(&self) -> &[libc::iovec] {
        &self.iovecs
    }
}

// SAFETY: The DescChain keeps the iovec pointers valid.
unsafe impl Send for GuestIovecs {}

#[derive(Clone)]
pub struct HostIovecs {
    // This only keeps the pointers alive.
    #[allow(dead_code)]
    data: Vec<Vec<u8>>,
    iovecs: Vec<iovec>,
}

impl HostIovecs {
    pub fn new(mut data: Vec<Vec<u8>>) -> Self {
        Self {
            iovecs: data
                .iter_mut()
                .map(|v| iovec {
                    iov_base: v.as_mut_ptr().cast(),
                    iov_len: v.len(),
                })
                .collect(),
            data,
        }
    }
}

// SAFETY: we own the pointers in the iovec
unsafe impl Send for HostIovecs {}

/// I/O buffer.
pub enum IoBuf {
    /// Data from the guest
    Guest(GuestIovecs),
    /// Data from the host
    Host(HostIovecs),
}

impl IoBuf {
    pub fn len(&self) -> usize {
        let iovecs = self.iovecs();
        let mut out = 0usize;
        for iovec in iovecs {
            out = out.checked_add(iovec.iov_len).unwrap();
        }
        out
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl HostIovecs {
    pub fn get_vecs(self) -> Vec<Vec<u8>> {
        self.data
    }
}

impl From<HostIovecs> for IoBuf {
    fn from(host: HostIovecs) -> Self {
        Self::Host(host)
    }
}

impl From<Vec<u8>> for IoBuf {
    fn from(host: Vec<u8>) -> Self {
        Self::Host(HostIovecs::new(vec![host]))
    }
}

// SAFETY: we own the pointers in the iovec
unsafe impl Send for IoBuf {}

impl From<GuestIovecs> for IoBuf {
    fn from(guest: GuestIovecs) -> Self {
        Self::Guest(guest)
    }
}

impl IoBuf {
    /// Returns a reference to the iovecs.
    ///
    /// The pointer this reference refers to is guaranteed to be behind
    /// an indirection.  In other words, the iovecs will not move even if
    /// this object is moved.  It is not safe to use the reference after
    /// that, but it can be converted to a pointer first.
    pub fn iovecs(&self) -> &[iovec] {
        match self {
            Self::Guest(guest) => guest.iovecs(),
            Self::Host(host) => &host.iovecs,
        }
    }
}

pub struct BatchRequest {
    pub offset: libc::off_t,
    pub user_data: u64,
    pub iobuf: IoBuf,
    pub request_type: RequestType,
}

pub struct ExecuteAsync {
    // `true` if the execution will complete asynchronously
    pub async_complete: bool,
    // request need to be batched for submission if any
    pub batch_request: Option<BatchRequest>,
}

type BackingBitmap = vm_memory::bitmap::AtomicBitmap;

type DescChain = DescriptorChain<
    GuestMemoryLoadGuard<
        vm_memory::GuestRegionCollection<vm_memory::GuestRegionMmap<BackingBitmap>>,
    >,
>;

pub struct Request {
    pub request_type: RequestType,
    pub sector: u64,
    pub data_descriptors: SmallVec<[(GuestAddress, u32); DEFAULT_DESCRIPTOR_VEC_SIZE]>,
    pub status_addr: GuestAddress,
    pub writeback: bool,
    aligned_operations: SmallVec<[AlignedOperation; DEFAULT_DESCRIPTOR_VEC_SIZE]>,
    pub start: Instant,
    desc_chain: DescChain,
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("request_type", &self.request_type)
            .field("sector", &self.sector)
            .field("data_descriptors", &self.data_descriptors)
            .field("status_addr", &self.status_addr)
            .field("writeback", &self.writeback)
            .field("aligned_operations", &self.aligned_operations)
            .field("start", &self.start)
            .field("desc_chain", &self.desc_chain)
            .finish()
    }
}

impl Request {
    pub fn memory(&self) -> &GuestRegionCollection<GuestRegionMmap<BackingBitmap>> {
        self.desc_chain.memory()
    }

    pub fn parse(
        mut desc_chain: DescChain,
        access_platform: Option<&dyn AccessPlatform>,
    ) -> Result<Self, Error> {
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
            .translate_gva(access_platform, hdr_desc.len() as usize)
            .map_err(|e| Error::GuestMemory(GuestMemoryError::IOError(e)))?;

        let mut req = Request {
            request_type: request_type(desc_chain.memory(), hdr_desc_addr)?,
            sector: sector(desc_chain.memory(), hdr_desc_addr)?,
            data_descriptors: SmallVec::with_capacity(DEFAULT_DESCRIPTOR_VEC_SIZE),
            status_addr: GuestAddress(0),
            writeback: true,
            aligned_operations: SmallVec::with_capacity(DEFAULT_DESCRIPTOR_VEC_SIZE),
            start: Instant::now(),
            desc_chain,
        };

        let status_desc;
        let mut desc = req
            .desc_chain
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
                if desc.is_write_only() && req.request_type == RequestType::Discard {
                    return Err(Error::UnexpectedWriteOnlyDescriptor);
                }
                if desc.is_write_only() && req.request_type == RequestType::WriteZeroes {
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
                        .translate_gva(access_platform, desc.len() as usize)
                        .map_err(|e| Error::GuestMemory(GuestMemoryError::IOError(e)))?,
                    desc.len(),
                ));
                desc = req
                    .desc_chain
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
            .translate_gva(access_platform, status_desc.len() as usize)
            .map_err(|e| Error::GuestMemory(GuestMemoryError::IOError(e)))?;

        Ok(req)
    }

    pub fn execute<T: Seek + Read + Write>(
        &self,
        disk: &mut T,
        disk_nsectors: u64,
        serial: &[u8],
    ) -> Result<u32, ExecuteError> {
        disk.seek(SeekFrom::Start(self.sector << SECTOR_SHIFT))
            .map_err(ExecuteError::Seek)?;
        let mut len = 0;
        let mem = self.desc_chain.memory();
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

    pub fn execute_async(
        &mut self,
        disk_nsectors: u64,
        disk_image: &mut dyn AsyncIo,
        serial: &[u8],
        disable_sector0_writes: bool,
    ) -> Result<ExecuteAsync, ExecuteError> {
        let sector = self.sector;
        let offset = (sector << SECTOR_SHIFT) as libc::off_t;
        let alignment = disk_image.alignment();
        let user_data = self.desc_chain.head_index() as u64;
        let desc_chain = self.desc_chain.clone();

        let mut iovecs = Vec::<iovec>::with_capacity(self.data_descriptors.len());
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

            let origin_ptr = self
                .desc_chain
                .memory()
                .get_slice(data_addr, data_len)
                .map_err(ExecuteError::GetHostAddress)?;
            assert!(origin_ptr.len() >= data_len);
            let origin_ptr = origin_ptr.ptr_guard();

            // O_DIRECT requires buffer addresses to be aligned to the
            // backend device's logical block size. In case it's not properly
            // aligned, an intermediate buffer is created with the correct
            // alignment, and a copy from/to the origin buffer is performed,
            // depending on the type of operation.
            let iov_base = if (origin_ptr.as_ptr() as u64).is_multiple_of(alignment) {
                origin_ptr.as_ptr() as *mut libc::c_void
            } else {
                let layout = Layout::from_size_align(data_len, alignment as usize).unwrap();
                // SAFETY: layout has non-zero size
                let aligned_ptr = unsafe { alloc_zeroed(layout) };
                if aligned_ptr.is_null() {
                    return Err(ExecuteError::TemporaryBufferAllocation(
                        std::io::Error::last_os_error(),
                    ));
                }

                // We need to perform the copy beforehand in case we're writing
                // data out.
                if self.request_type == RequestType::Out {
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
        let request_type = self.request_type;
        let mem = self.desc_chain.memory();
        // Queue operations expected to be submitted.
        match self.request_type {
            RequestType::In => {
                for (data_addr, data_len) in &self.data_descriptors {
                    mem.get_slice(*data_addr, *data_len as usize)
                        .map_err(ExecuteError::GetHostAddress)?
                        .bitmap()
                        .mark_dirty(0, *data_len as usize);
                }
                let batch_request = BatchRequest {
                    offset,
                    request_type,
                    user_data,
                    iobuf: IoBuf::Guest(GuestIovecs { iovecs, desc_chain }),
                };
                if disk_image.batch_requests_enabled() {
                    ret.batch_request = Some(batch_request);
                } else {
                    disk_image
                        .read_vectored(
                            batch_request.offset,
                            batch_request.iobuf,
                            batch_request.user_data,
                        )
                        .map_err(ExecuteError::AsyncRead)?;
                }
            }
            RequestType::Out => {
                let batch_request = BatchRequest {
                    request_type,
                    offset,
                    user_data,
                    iobuf: IoBuf::Guest(GuestIovecs { iovecs, desc_chain }),
                };
                if disk_image.batch_requests_enabled() {
                    ret.batch_request = Some(batch_request);
                } else {
                    disk_image
                        .write_vectored(
                            batch_request.offset,
                            batch_request.iobuf,
                            batch_request.user_data,
                        )
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
            RequestType::Discard => {
                let (data_addr, data_len) = if self.data_descriptors.len() == 1 {
                    (self.data_descriptors[0].0, self.data_descriptors[0].1)
                } else {
                    return Err(ExecuteError::BadRequest(Error::TooManyDescriptors));
                };

                if data_len < DISCARD_WZ_SEG_SIZE {
                    return Err(ExecuteError::BadRequest(Error::DescriptorLengthTooSmall));
                }
                if data_len > DISCARD_WZ_MAX_PAYLOAD {
                    return Err(ExecuteError::BadRequest(Error::TooManySegments(
                        data_len.div_ceil(DISCARD_WZ_SEG_SIZE),
                    )));
                }

                let mut discard_sector = [0u8; 8];
                let mut discard_num_sectors = [0u8; 4];
                let mut discard_flags = [0u8; 4];

                let sector_addr = data_addr.checked_add(DISCARD_WZ_SECTOR_OFFSET).unwrap();
                mem.read_slice(&mut discard_sector, sector_addr)
                    .map_err(ExecuteError::Read)?;

                let num_sectors_addr = data_addr
                    .checked_add(DISCARD_WZ_NUM_SECTORS_OFFSET)
                    .unwrap();
                mem.read_slice(&mut discard_num_sectors, num_sectors_addr)
                    .map_err(ExecuteError::Read)?;

                let flags_addr = data_addr.checked_add(DISCARD_WZ_FLAGS_OFFSET).unwrap();
                mem.read_slice(&mut discard_flags, flags_addr)
                    .map_err(ExecuteError::Read)?;

                let discard_flags = u32::from_le_bytes(discard_flags);
                // Per virtio spec v1.2 reject discard if any flag is set, including unmap.
                if discard_flags != 0 {
                    warn!("Unsupported flags {discard_flags:#x} in discard request");
                    return Err(ExecuteError::UnsupportedFlags {
                        request_type: VIRTIO_BLK_T_DISCARD,
                        flags: discard_flags,
                    });
                }

                let discard_sector = u64::from_le_bytes(discard_sector);

                if discard_sector == 0 && disable_sector0_writes {
                    return Err(ExecuteError::BadRequest(Error::InvalidOffset));
                }

                let discard_num_sectors = u32::from_le_bytes(discard_num_sectors);

                let top = discard_sector
                    .checked_add(discard_num_sectors as u64)
                    .ok_or(ExecuteError::BadRequest(Error::InvalidOffset))?;
                if top > disk_nsectors {
                    return Err(ExecuteError::BadRequest(Error::InvalidOffset));
                }

                let discard_offset = discard_sector * SECTOR_SIZE;
                let discard_length = (discard_num_sectors as u64) * SECTOR_SIZE;

                disk_image
                    .punch_hole(discard_offset, discard_length, user_data)
                    .map_err(ExecuteError::AsyncPunchHole)?;
            }
            RequestType::WriteZeroes => {
                let (data_addr, data_len) = if self.data_descriptors.len() == 1 {
                    (self.data_descriptors[0].0, self.data_descriptors[0].1)
                } else {
                    return Err(ExecuteError::BadRequest(Error::TooManyDescriptors));
                };

                if data_len < DISCARD_WZ_SEG_SIZE {
                    return Err(ExecuteError::BadRequest(Error::DescriptorLengthTooSmall));
                }
                if data_len > DISCARD_WZ_MAX_PAYLOAD {
                    return Err(ExecuteError::BadRequest(Error::TooManySegments(
                        data_len.div_ceil(DISCARD_WZ_SEG_SIZE),
                    )));
                }

                let mut wz_sector = [0u8; 8];
                let mut wz_num_sectors = [0u8; 4];
                let mut wz_flags = [0u8; 4];

                let sector_addr = data_addr.checked_add(DISCARD_WZ_SECTOR_OFFSET).unwrap();
                mem.read_slice(&mut wz_sector, sector_addr)
                    .map_err(ExecuteError::Read)?;

                let num_sectors_addr = data_addr
                    .checked_add(DISCARD_WZ_NUM_SECTORS_OFFSET)
                    .unwrap();
                mem.read_slice(&mut wz_num_sectors, num_sectors_addr)
                    .map_err(ExecuteError::Read)?;

                let flags_addr = data_addr.checked_add(DISCARD_WZ_FLAGS_OFFSET).unwrap();
                mem.read_slice(&mut wz_flags, flags_addr)
                    .map_err(ExecuteError::Read)?;

                let wz_sector = u64::from_le_bytes(wz_sector);
                let wz_num_sectors = u32::from_le_bytes(wz_num_sectors);

                let wz_flags = u32::from_le_bytes(wz_flags);
                // Per virtio spec v1.2 reject write zeroes if any unknown flag is set.
                if (wz_flags & !VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP) != 0 {
                    warn!("Unsupported flags {wz_flags:#x} in write zeroes request");
                    return Err(ExecuteError::UnsupportedFlags {
                        request_type: VIRTIO_BLK_T_WRITE_ZEROES,
                        flags: wz_flags,
                    });
                }

                let wz_offset = wz_sector * SECTOR_SIZE;
                if wz_offset == 0 && disable_sector0_writes {
                    return Err(ExecuteError::BadRequest(Error::InvalidOffset));
                }

                let top = wz_sector
                    .checked_add(wz_num_sectors as u64)
                    .ok_or(ExecuteError::BadRequest(Error::InvalidOffset))?;
                if top > disk_nsectors {
                    return Err(ExecuteError::BadRequest(Error::InvalidOffset));
                }

                let wz_length = (wz_num_sectors as u64) * SECTOR_SIZE;

                if wz_flags & VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP != 0 {
                    disk_image
                        .punch_hole(wz_offset, wz_length, user_data)
                        .map_err(ExecuteError::AsyncPunchHole)?;
                } else {
                    disk_image
                        .write_zeroes(wz_offset, wz_length, user_data)
                        .map_err(ExecuteError::AsyncWriteZeroes)?;
                }
            }
            RequestType::Unsupported(t) => return Err(ExecuteError::Unsupported(t)),
        }

        Ok(ret)
    }

    pub fn complete_async(&mut self) -> Result<(), Error> {
        for aligned_operation in self.aligned_operations.drain(..) {
            // We need to perform the copy after the data has been read inside
            // the aligned buffer in case we're reading data in.
            if self.request_type == RequestType::In {
                // SAFETY: origin buffer has been allocated with the
                // proper size. It is still alive because we hold
                // the descriptor chain, which means that the backing
                // memory is still present.
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
