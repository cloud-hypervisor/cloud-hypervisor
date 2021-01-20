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
#[macro_use]
extern crate serde_derive;

pub mod async_io;

#[cfg(feature = "io_uring")]
use io_uring::Probe;
use io_uring::{opcode, squeue, IoUring};
use serde::ser::{Serialize, SerializeStruct, Serializer};
use std::cmp;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::linux::fs::MetadataExt;
#[cfg(feature = "io_uring")]
use std::os::unix::io::AsRawFd;
use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::result;
use virtio_bindings::bindings::virtio_blk::*;
use vm_memory::{ByteValued, Bytes, GuestAddress, GuestMemory, GuestMemoryError, GuestMemoryMmap};
use vm_virtio::DescriptorChain;
#[cfg(feature = "io_uring")]
use vmm_sys_util::eventfd::EventFd;

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

fn build_device_id(disk_path: &PathBuf) -> result::Result<String, Error> {
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

pub fn build_disk_image_id(disk_path: &PathBuf) -> Vec<u8> {
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
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RequestType {
    In,
    Out,
    Flush,
    GetDeviceID,
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
        VIRTIO_BLK_T_GET_ID => Ok(RequestType::GetDeviceID),
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
            request_type: request_type(&mem, avail_desc.addr)?,
            sector: sector(&mem, avail_desc.addr)?,
            data_descriptors: Vec::new(),
            status_addr: GuestAddress(0),
            writeback: true,
        };

        let status_desc;
        let mut desc = avail_desc
            .next_descriptor()
            .ok_or(Error::DescriptorChainTooShort)?;

        if !desc.has_next() {
            status_desc = desc;
            // Only flush requests are allowed to skip the data descriptor.
            if req.request_type != RequestType::Flush {
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
                if !desc.is_write_only() && req.request_type == RequestType::GetDeviceID {
                    return Err(Error::UnexpectedReadOnlyDescriptor);
                }
                req.data_descriptors.push((desc.addr, desc.len));
                desc = desc
                    .next_descriptor()
                    .ok_or(Error::DescriptorChainTooShort)?;
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
                RequestType::GetDeviceID => {
                    if (*data_len as usize) < disk_id.len() {
                        return Err(ExecuteError::BadRequest(Error::InvalidOffset));
                    }
                    mem.write_slice(&disk_id.as_slice(), *data_addr)
                        .map_err(ExecuteError::Write)?;
                }
                RequestType::Unsupported(t) => return Err(ExecuteError::Unsupported(t)),
            };
        }
        Ok(len)
    }

    pub fn execute_io_uring(
        &self,
        mem: &GuestMemoryMmap,
        io_uring: &mut IoUring,
        disk_nsectors: u64,
        disk_image_fd: RawFd,
        disk_id: &[u8],
        user_data: u64,
    ) -> result::Result<bool, ExecuteError> {
        let sector = self.sector;
        let request_type = self.request_type;
        let offset = (sector << SECTOR_SHIFT) as libc::off_t;

        let (submitter, sq, _) = io_uring.split();
        let mut avail_sq = sq.available();

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
                // Safe because we know the file descriptor is valid and we
                // relied on vm-memory to provide the buffer address.
                let _ = unsafe {
                    avail_sq.push(
                        opcode::Readv::new(
                            opcode::types::Fd(disk_image_fd),
                            iovecs.as_ptr(),
                            iovecs.len() as u32,
                        )
                        .offset(offset)
                        .build()
                        .flags(squeue::Flags::ASYNC)
                        .user_data(user_data),
                    )
                };
            }
            RequestType::Out => {
                // Safe because we know the file descriptor is valid and we
                // relied on vm-memory to provide the buffer address.
                let _ = unsafe {
                    avail_sq.push(
                        opcode::Writev::new(
                            opcode::types::Fd(disk_image_fd),
                            iovecs.as_ptr(),
                            iovecs.len() as u32,
                        )
                        .offset(offset)
                        .build()
                        .flags(squeue::Flags::ASYNC)
                        .user_data(user_data),
                    )
                };
            }
            RequestType::Flush => {
                // Safe because we know the file descriptor is valid.
                let _ = unsafe {
                    avail_sq.push(
                        opcode::Fsync::new(opcode::types::Fd(disk_image_fd))
                            .build()
                            .flags(squeue::Flags::ASYNC)
                            .user_data(user_data),
                    )
                };
            }
            RequestType::GetDeviceID => {
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

        // Update the submission queue and submit new operations to the
        // io_uring instance.
        avail_sq.sync();
        submitter.submit().map_err(ExecuteError::SubmitIoUring)?;

        Ok(true)
    }

    pub fn set_writeback(&mut self, writeback: bool) {
        self.writeback = writeback
    }
}

#[derive(Copy, Clone, Debug, Default, Deserialize)]
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

// We must explicitly implement Serialize since the structure is packed and
// it's unsafe to borrow from a packed structure. And by default, if we derive
// Serialize from serde, it will borrow the values from the structure.
// That's why this implementation copies each field separately before it
// serializes the entire structure field by field.
impl Serialize for VirtioBlockConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let capacity = self.capacity;
        let size_max = self.size_max;
        let seg_max = self.seg_max;
        let geometry = self.geometry;
        let blk_size = self.blk_size;
        let physical_block_exp = self.physical_block_exp;
        let alignment_offset = self.alignment_offset;
        let min_io_size = self.min_io_size;
        let opt_io_size = self.opt_io_size;
        let writeback = self.writeback;
        let unused = self.unused;
        let num_queues = self.num_queues;
        let max_discard_sectors = self.max_discard_sectors;
        let max_discard_seg = self.max_discard_seg;
        let discard_sector_alignment = self.discard_sector_alignment;
        let max_write_zeroes_sectors = self.max_write_zeroes_sectors;
        let max_write_zeroes_seg = self.max_write_zeroes_seg;
        let write_zeroes_may_unmap = self.write_zeroes_may_unmap;
        let unused1 = self.unused1;

        let mut virtio_block_config = serializer.serialize_struct("VirtioBlockConfig", 60)?;
        virtio_block_config.serialize_field("capacity", &capacity)?;
        virtio_block_config.serialize_field("size_max", &size_max)?;
        virtio_block_config.serialize_field("seg_max", &seg_max)?;
        virtio_block_config.serialize_field("geometry", &geometry)?;
        virtio_block_config.serialize_field("blk_size", &blk_size)?;
        virtio_block_config.serialize_field("physical_block_exp", &physical_block_exp)?;
        virtio_block_config.serialize_field("alignment_offset", &alignment_offset)?;
        virtio_block_config.serialize_field("min_io_size", &min_io_size)?;
        virtio_block_config.serialize_field("opt_io_size", &opt_io_size)?;
        virtio_block_config.serialize_field("writeback", &writeback)?;
        virtio_block_config.serialize_field("unused", &unused)?;
        virtio_block_config.serialize_field("num_queues", &num_queues)?;
        virtio_block_config.serialize_field("max_discard_sectors", &max_discard_sectors)?;
        virtio_block_config.serialize_field("max_discard_seg", &max_discard_seg)?;
        virtio_block_config
            .serialize_field("discard_sector_alignment", &discard_sector_alignment)?;
        virtio_block_config
            .serialize_field("max_write_zeroes_sectors", &max_write_zeroes_sectors)?;
        virtio_block_config.serialize_field("max_write_zeroes_seg", &max_write_zeroes_seg)?;
        virtio_block_config.serialize_field("write_zeroes_may_unmap", &write_zeroes_may_unmap)?;
        virtio_block_config.serialize_field("unused1", &unused1)?;
        virtio_block_config.end()
    }
}

unsafe impl ByteValued for VirtioBlockConfig {}

#[derive(Copy, Clone, Debug, Default, Deserialize)]
#[repr(C, packed)]
pub struct VirtioBlockGeometry {
    pub cylinders: u16,
    pub heads: u8,
    pub sectors: u8,
}

// We must explicitly implement Serialize since the structure is packed and
// it's unsafe to borrow from a packed structure. And by default, if we derive
// Serialize from serde, it will borrow the values from the structure.
// That's why this implementation copies each field separately before it
// serializes the entire structure field by field.
impl Serialize for VirtioBlockGeometry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let cylinders = self.cylinders;
        let heads = self.heads;
        let sectors = self.sectors;

        let mut virtio_block_geometry = serializer.serialize_struct("VirtioBlockGeometry", 4)?;
        virtio_block_geometry.serialize_field("cylinders", &cylinders)?;
        virtio_block_geometry.serialize_field("heads", &heads)?;
        virtio_block_geometry.serialize_field("sectors", &sectors)?;
        virtio_block_geometry.end()
    }
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
