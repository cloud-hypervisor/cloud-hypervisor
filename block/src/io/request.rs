// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2020 Intel Corporation
//
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::mem;
use std::os::unix::fs::FileExt;
use std::sync::Arc;
use std::time::Instant;

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
    GuestMemoryLoadGuard,
};
use vm_virtio::AccessPlatform;
use vm_virtio::checked_descriptor::DescriptorChainExt;
use vmm_sys_util::file_traits::FileSync;

use crate::async_io::{
    AsyncIo, AsyncIoCompletion, AsyncIoOperation, GuestMemoryTarget, OwnedIoBuffer,
};
use crate::{Error, ExecuteError, request_type, sector};

const SECTOR_SHIFT: u8 = 9;
pub const SECTOR_SIZE: u64 = 0x01 << SECTOR_SHIFT;

/// Maximum number of segments per DISCARD or WRITE_ZEROES request.
pub const MAX_DISCARD_WRITE_ZEROES_SEG: u32 = 1;
/// Size and field offsets within `struct virtio_blk_discard_write_zeroes`.
const DISCARD_WZ_SEG_SIZE: u32 = size_of::<virtio_blk_discard_write_zeroes>() as u32;
const DISCARD_WZ_MAX_PAYLOAD: u32 = DISCARD_WZ_SEG_SIZE * MAX_DISCARD_WRITE_ZEROES_SEG;
const DISCARD_WZ_SECTOR_OFFSET: u64 =
    mem::offset_of!(virtio_blk_discard_write_zeroes, sector) as u64;
const DISCARD_WZ_NUM_SECTORS_OFFSET: u64 =
    mem::offset_of!(virtio_blk_discard_write_zeroes, num_sectors) as u64;
const DISCARD_WZ_FLAGS_OFFSET: u64 = mem::offset_of!(virtio_blk_discard_write_zeroes, flags) as u64;

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

pub struct ExecuteAsync {
    // `true` if the execution will complete asynchronously
    pub async_complete: bool,
    // request need to be batched for submission if any
    pub batch_request: Option<AsyncIoOperation>,
}

#[derive(Debug)]
pub struct Request {
    request_type: RequestType,
    sector: u64,
    data_descriptors: SmallVec<[(GuestAddress, u32); DEFAULT_DESCRIPTOR_VEC_SIZE]>,
    status_addr: GuestAddress,
    pub writeback: bool,
    start: Instant,
}

impl Request {
    pub fn parse<B: Bitmap + 'static>(
        desc_chain: &mut DescriptorChain<GuestMemoryLoadGuard<vm_memory::GuestMemoryMmap<B>>>,
        access_platform: Option<&dyn AccessPlatform>,
    ) -> Result<Request, Error> {
        let hdr_desc = desc_chain
            .next_checked(access_platform)
            .map_err(|addr| Error::GuestMemory(GuestMemoryError::InvalidGuestAddress(addr)))?
            .ok_or_else(|| {
                error!("Missing head descriptor");
                Error::DescriptorChainTooShort
            })?;

        // The head contains the request type which MUST be readable.
        if hdr_desc.is_write_only() {
            return Err(Error::UnexpectedWriteOnlyDescriptor);
        }

        let hdr_desc_addr = hdr_desc.addr();

        let mut req = Request {
            request_type: request_type(desc_chain.memory(), hdr_desc_addr)?,
            sector: sector(desc_chain.memory(), hdr_desc_addr)?,
            data_descriptors: SmallVec::with_capacity(DEFAULT_DESCRIPTOR_VEC_SIZE),
            status_addr: GuestAddress(0),
            writeback: true,
            start: Instant::now(),
        };

        let status_desc;
        let mut desc = desc_chain
            .next_checked(access_platform)
            .map_err(|addr| Error::GuestMemory(GuestMemoryError::InvalidGuestAddress(addr)))?
            .ok_or_else(|| {
                error!("Only head descriptor present: request = {req:?}");
                Error::DescriptorChainTooShort
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

                req.data_descriptors.push((desc.addr(), desc.len()));
                desc = desc_chain
                    .next_checked(access_platform)
                    .map_err(|addr| {
                        Error::GuestMemory(GuestMemoryError::InvalidGuestAddress(addr))
                    })?
                    .ok_or_else(|| {
                        error!("DescriptorChain corrupted: request = {req:?}");
                        Error::DescriptorChainTooShort
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

        if status_desc.is_empty() {
            return Err(Error::DescriptorLengthTooSmall);
        }

        req.status_addr = status_desc.addr();

        Ok(req)
    }

    pub fn execute<T: FileExt + FileSync, B: Bitmap + 'static>(
        &self,
        disk: &mut T,
        disk_nsectors: u64,
        mem: &vm_memory::GuestMemoryMmap<B>,
        serial: &[u8],
    ) -> Result<u32, ExecuteError> {
        self.check_data_bounds(disk_nsectors)?;

        let mut offset = self.sector << SECTOR_SHIFT;
        let mut len = 0;
        for (data_addr, data_len) in &self.data_descriptors {
            match self.request_type {
                RequestType::In => {
                    let mut buf = vec![0u8; *data_len as usize];
                    disk.read_exact_at(&mut buf, offset)
                        .map_err(ExecuteError::ReadExact)?;
                    mem.read_exact_volatile_from(
                        *data_addr,
                        &mut buf.as_slice(),
                        *data_len as usize,
                    )
                    .map_err(ExecuteError::Read)?;
                    offset += u64::from(*data_len);
                    len += data_len;
                }
                RequestType::Out => {
                    let mut buf: Vec<u8> = Vec::new();
                    mem.write_all_volatile_to(*data_addr, &mut buf, *data_len as usize)
                        .map_err(ExecuteError::Write)?;
                    disk.write_all_at(&buf, offset)
                        .map_err(ExecuteError::WriteAll)?;
                    if !self.writeback {
                        disk.fsync().map_err(ExecuteError::Flush)?;
                    }
                    offset += u64::from(*data_len);
                }
                RequestType::Flush => disk.fsync().map_err(ExecuteError::Flush)?,
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

    pub fn execute_async<B: Bitmap + Send + Sync + 'static>(
        &mut self,
        mem: Arc<vm_memory::GuestMemoryMmap<B>>,
        disk_nsectors: u64,
        disk_image: &mut dyn AsyncIo,
        serial: &[u8],
        disable_sector0_writes: bool,
        user_data: u64,
    ) -> Result<ExecuteAsync, ExecuteError> {
        let sector = self.sector;
        let request_type = self.request_type;
        let offset = (sector << SECTOR_SHIFT) as libc::off_t;
        let alignment = disk_image.alignment();

        self.check_data_bounds(disk_nsectors)?;

        let mut ret = ExecuteAsync {
            async_complete: true,
            batch_request: None,
        };
        // Queue operations expected to be submitted.
        match request_type {
            RequestType::In => {
                self.mark_read_dirty(&mem)?;
                let op = self.build_data_operation(mem, offset, alignment, user_data)?;
                if disk_image.batch_requests_enabled() {
                    ret.batch_request = Some(op);
                } else {
                    match op {
                        AsyncIoOperation::ReadToMemory {
                            offset,
                            target,
                            user_data,
                        } => disk_image
                            .read_to_memory(offset, target, user_data)
                            .map_err(ExecuteError::AsyncRead)?,
                        AsyncIoOperation::ReadToVec {
                            offset,
                            buffer,
                            user_data,
                        } => disk_image
                            .read_to_vec(offset, buffer, user_data)
                            .map_err(ExecuteError::AsyncRead)?,
                        _ => unreachable!("unexpected read operation"),
                    }
                }
            }
            RequestType::Out => {
                let op = self.build_data_operation(mem, offset, alignment, user_data)?;
                if disk_image.batch_requests_enabled() {
                    ret.batch_request = Some(op);
                } else {
                    match op {
                        AsyncIoOperation::WriteFromMemory {
                            offset,
                            target,
                            user_data,
                        } => disk_image
                            .write_from_memory(offset, target, user_data)
                            .map_err(ExecuteError::AsyncWrite)?,
                        AsyncIoOperation::WriteFromVec {
                            offset,
                            buffer,
                            user_data,
                        } => disk_image
                            .write_from_vec(offset, buffer, user_data)
                            .map_err(ExecuteError::AsyncWrite)?,
                        _ => unreachable!("unexpected write operation"),
                    }
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

                let top = wz_sector
                    .checked_add(wz_num_sectors as u64)
                    .ok_or(ExecuteError::BadRequest(Error::InvalidOffset))?;
                if top > disk_nsectors {
                    return Err(ExecuteError::BadRequest(Error::InvalidOffset));
                }

                let wz_offset = wz_sector * SECTOR_SIZE;
                if wz_offset == 0 && disable_sector0_writes {
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

    // Builds a read or write operation for IO to or from `mem`.
    fn build_data_operation<B: Bitmap + Send + Sync + 'static>(
        &self,
        mem: Arc<vm_memory::GuestMemoryMmap<B>>,
        offset: libc::off_t,
        alignment: u64,
        user_data: u64,
    ) -> Result<AsyncIoOperation, ExecuteError> {
        if self.guest_memory_is_aligned(&mem, alignment)? {
            let target = GuestMemoryTarget::new(mem, &self.data_descriptors)
                .map_err(ExecuteError::GetHostAddress)?;
            return Ok(match self.request_type {
                RequestType::In => AsyncIoOperation::read_to_memory(offset, target, user_data),
                RequestType::Out => AsyncIoOperation::write_from_memory(offset, target, user_data),
                _ => unreachable!("unexpected data operation type"),
            });
        }

        // The guest-memory buffers are unaligned, so use an aligned bounce buffer.
        let mut buffer = OwnedIoBuffer::new(self.data_len(), alignment as usize)
            .map_err(ExecuteError::TemporaryBufferAllocation)?;

        if self.request_type == RequestType::Out {
            self.copy_guest_to_buffer(&mem, buffer.as_mut_slice())?;
        }

        Ok(match self.request_type {
            RequestType::In => AsyncIoOperation::read_to_vec(offset, buffer, user_data),
            RequestType::Out => AsyncIoOperation::write_from_vec(offset, buffer, user_data),
            _ => unreachable!("unexpected data operation type"),
        })
    }

    // Checks whether `self.data_descriptors` are aligned to `alignment`.
    fn guest_memory_is_aligned<B: Bitmap + 'static>(
        &self,
        mem: &vm_memory::GuestMemoryMmap<B>,
        alignment: u64,
    ) -> Result<bool, ExecuteError> {
        if alignment <= 1 {
            return Ok(true);
        }

        for &(data_addr, data_len) in &self.data_descriptors {
            let _: u32 = data_len;
            const _: () = assert!(
                size_of::<u32>() <= size_of::<usize>(),
                "unsupported platform"
            );
            if data_len == 0 {
                continue;
            }
            let data_len = data_len as usize;
            let origin_ptr = mem
                .get_slice(data_addr, data_len)
                .map_err(ExecuteError::GetHostAddress)?;
            let origin_ptr = origin_ptr.ptr_guard_mut();
            if !(origin_ptr.as_ptr() as u64).is_multiple_of(alignment)
                || !(origin_ptr.len() as u64).is_multiple_of(alignment)
            {
                return Ok(false);
            }
        }

        Ok(true)
    }

    // Returns the sum of the lengths of `self.data_descriptors`.
    fn data_len(&self) -> usize {
        self.data_descriptors
            .iter()
            .map(|(_, len)| *len as usize)
            .sum()
    }

    // Marks guest-memory read destinations dirty before submitting async IO.
    fn mark_read_dirty<B: Bitmap + 'static>(
        &self,
        mem: &vm_memory::GuestMemoryMmap<B>,
    ) -> Result<(), ExecuteError> {
        for (data_addr, data_len) in &self.data_descriptors {
            mem.get_slice(*data_addr, *data_len as usize)
                .map_err(ExecuteError::GetHostAddress)?
                .bitmap()
                .mark_dirty(0, *data_len as usize);
        }
        Ok(())
    }

    // Copies guest descriptor contents into a contiguous host buffer.
    fn copy_guest_to_buffer<B: Bitmap + 'static>(
        &self,
        mem: &vm_memory::GuestMemoryMmap<B>,
        buffer: &mut [u8],
    ) -> Result<(), ExecuteError> {
        let mut offset = 0usize;
        for (data_addr, data_len) in &self.data_descriptors {
            let data_len = *data_len as usize;
            mem.read_slice(&mut buffer[offset..offset + data_len], *data_addr)
                .map_err(ExecuteError::Read)?;
            offset += data_len;
        }
        Ok(())
    }

    // Copies a host completion buffer back into guest descriptors.
    fn copy_buffer_to_guest<B: Bitmap + 'static>(
        &self,
        mem: &vm_memory::GuestMemoryMmap<B>,
        buffer: &[u8],
    ) -> Result<(), Error> {
        let mut buffer_offset = 0usize;
        for (data_addr, data_len) in &self.data_descriptors {
            if buffer_offset >= buffer.len() {
                break;
            }
            let data_len = (*data_len as usize).min(buffer.len() - buffer_offset);
            mem.write_slice(&buffer[buffer_offset..buffer_offset + data_len], *data_addr)
                .map_err(Error::GuestMemory)?;
            buffer_offset += data_len;
        }
        Ok(())
    }

    pub fn complete_async<B: Bitmap + 'static>(
        &mut self,
        mem: &vm_memory::GuestMemoryMmap<B>,
        completion: &mut AsyncIoCompletion,
    ) -> Result<(), Error> {
        if self.request_type == RequestType::In
            && completion.result > 0
            && let Some(buffer) = completion.buffer.take()
        {
            let len = (completion.result as usize).min(buffer.as_slice().len());
            self.copy_buffer_to_guest(mem, &buffer.as_slice()[..len])?;
        }

        Ok(())
    }

    #[inline]
    pub fn data_descriptors(
        &self,
    ) -> &SmallVec<[(GuestAddress, u32); DEFAULT_DESCRIPTOR_VEC_SIZE]> {
        &self.data_descriptors
    }

    #[inline]
    pub fn status_addr(&self) -> GuestAddress {
        self.status_addr
    }

    #[inline]
    pub fn start(&self) -> Instant {
        self.start
    }

    #[inline]
    pub fn sector(&self) -> u64 {
        self.sector
    }

    #[inline]
    pub fn request_type(&self) -> RequestType {
        self.request_type
    }

    /// For In and Out requests, checks that the descriptors collectively fit in a backing disk of
    /// the given size. Returns `Ok(())` if they fit, or `ExecuteError::BadRequest` otherwise.
    fn check_data_bounds(&self, disk_nsectors: u64) -> Result<(), ExecuteError> {
        if !matches!(self.request_type, RequestType::In | RequestType::Out) {
            return Ok(());
        }
        let mut total_bytes: u64 = 0;
        for (_, data_len) in &self.data_descriptors {
            total_bytes = total_bytes
                .checked_add(u64::from(*data_len))
                .ok_or(ExecuteError::BadRequest(Error::InvalidOffset))?;
        }
        if total_bytes == 0 {
            return Ok(());
        }
        let total_sectors = total_bytes.div_ceil(SECTOR_SIZE);
        let end_sector = self
            .sector
            .checked_add(total_sectors)
            .ok_or(ExecuteError::BadRequest(Error::InvalidOffset))?;
        if end_sector > disk_nsectors {
            return Err(ExecuteError::BadRequest(Error::InvalidOffset));
        }
        Ok(())
    }
}

#[cfg(test)]
mod unit_tests {
    use std::sync::Arc;

    use vm_memory::GuestMemoryMmap;
    use vmm_sys_util::eventfd::EventFd;

    use super::*;
    use crate::async_io::{AsyncIo, AsyncIoCompletion, AsyncIoOperation, AsyncIoResult};

    struct PanicAsyncIo(EventFd);

    impl AsyncIo for PanicAsyncIo {
        fn notifier(&self) -> &EventFd {
            &self.0
        }
        fn submit_data_operation(&mut self, _: AsyncIoOperation) -> AsyncIoResult<()> {
            unreachable!()
        }
        fn fsync(&mut self, _: Option<u64>) -> AsyncIoResult<()> {
            unreachable!()
        }
        fn punch_hole(&mut self, _: u64, _: u64, _: u64) -> AsyncIoResult<()> {
            unreachable!()
        }
        fn write_zeroes(&mut self, _: u64, _: u64, _: u64) -> AsyncIoResult<()> {
            unreachable!()
        }
        fn next_completed_request(&mut self) -> Option<AsyncIoCompletion> {
            None
        }
    }

    #[test]
    fn write_zeroes_rejects_sector_arithmetic_overflow() {
        let mem = Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 4096)]).unwrap());
        mem.write_slice(&(u64::MAX - 100).to_le_bytes(), GuestAddress(0))
            .unwrap();
        mem.write_slice(&1000u32.to_le_bytes(), GuestAddress(8))
            .unwrap();

        let mut request = Request {
            request_type: RequestType::WriteZeroes,
            sector: 0,
            data_descriptors: SmallVec::from_slice(&[(GuestAddress(0), DISCARD_WZ_SEG_SIZE)]),
            status_addr: GuestAddress(0),
            writeback: true,
            start: Instant::now(),
        };
        let mut disk = PanicAsyncIo(EventFd::new(0).unwrap());

        let Err(ExecuteError::BadRequest(Error::InvalidOffset)) =
            request.execute_async(mem, 1024, &mut disk, &[], false, 0)
        else {
            panic!("expected BadRequest(InvalidOffset)");
        };
    }
}
