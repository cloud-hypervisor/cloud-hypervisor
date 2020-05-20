// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use super::Error as DeviceError;
use super::{
    ActivateError, ActivateResult, DescriptorChain, DeviceEventT, Queue, VirtioDevice,
    VirtioDeviceType, VirtioInterruptType,
};
use crate::VirtioInterrupt;
use anyhow::anyhow;
use epoll;
use libc::{c_void, EFD_NONBLOCK};
use serde::ser::{Serialize, SerializeStruct, Serializer};
use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::cmp;
use std::convert::TryInto;
use std::fs::{File, Metadata};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::num::Wrapping;
use std::ops::DerefMut;
use std::os::linux::fs::MetadataExt;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::PathBuf;
use std::result;
use std::slice;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use virtio_bindings::bindings::virtio_blk::*;
use virtio_bindings::bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use vm_memory::{
    ByteValued, Bytes, GuestAddress, GuestAddressSpace, GuestMemory, GuestMemoryAtomic,
    GuestMemoryError, GuestMemoryMmap,
};
use vm_migration::{
    Migratable, MigratableError, Pausable, Snapshot, SnapshotDataSection, Snapshottable,
    Transportable,
};
use vmm_sys_util::{eventfd::EventFd, seek_hole::SeekHole, write_zeroes::PunchHole};

const SECTOR_SHIFT: u8 = 9;
pub const SECTOR_SIZE: u64 = (0x01 as u64) << SECTOR_SHIFT;

// New descriptors are pending on the virtio queue.
const QUEUE_AVAIL_EVENT: DeviceEventT = 0;
// The device has been dropped.
pub const KILL_EVENT: DeviceEventT = 1;
// Number of DeviceEventT events supported by this implementation.
pub const BLOCK_EVENTS_COUNT: usize = 2;
// The device should be paused.
const PAUSE_EVENT: DeviceEventT = 3;

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
}

#[derive(Debug)]
pub enum ExecuteError {
    BadRequest(Error),
    Flush(io::Error),
    Read(GuestMemoryError),
    Seek(io::Error),
    Write(GuestMemoryError),
    Unsupported(u32),
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
        }
    }
}

pub trait DiskFile: Read + Seek + Write + Clone {}
impl<D: Read + Seek + Write + Clone> DiskFile for D {}

#[derive(Debug)]
pub struct RawFile {
    file: File,
    alignment: usize,
    position: u64,
}

const BLK_ALIGNMENTS: [usize; 2] = [512, 4096];

fn is_valid_alignment(fd: RawFd, alignment: usize) -> bool {
    let layout = Layout::from_size_align(alignment, alignment).unwrap();
    let ptr = unsafe { alloc_zeroed(layout) };

    let ret = unsafe {
        ::libc::pread(
            fd,
            ptr as *mut c_void,
            alignment,
            alignment.try_into().unwrap(),
        )
    };

    unsafe { dealloc(ptr, layout) };

    ret >= 0
}

impl RawFile {
    pub fn new(file: File, direct_io: bool) -> Self {
        // Assume no alignment restrictions if we aren't using O_DIRECT.
        let mut alignment = 0;
        if direct_io {
            for align in &BLK_ALIGNMENTS {
                if is_valid_alignment(file.as_raw_fd(), *align) {
                    alignment = *align;
                    break;
                }
            }
        }
        RawFile {
            file,
            alignment: alignment.try_into().unwrap(),
            position: 0,
        }
    }

    fn round_up(&self, offset: u64) -> u64 {
        let align: u64 = self.alignment.try_into().unwrap();
        ((offset / (align + 1)) + 1) * align
    }

    fn round_down(&self, offset: u64) -> u64 {
        let align: u64 = self.alignment.try_into().unwrap();
        (offset / align) * align
    }

    fn is_aligned(&self, buf: &[u8]) -> bool {
        if self.alignment == 0 {
            return true;
        }

        let align64: u64 = self.alignment.try_into().unwrap();

        (self.position % align64 == 0)
            && ((buf.as_ptr() as usize) % self.alignment == 0)
            && (buf.len() % self.alignment == 0)
    }

    pub fn set_len(&self, size: u64) -> std::io::Result<()> {
        self.file.set_len(size)
    }

    pub fn metadata(&self) -> std::io::Result<Metadata> {
        self.file.metadata()
    }

    pub fn try_clone(&self) -> std::io::Result<RawFile> {
        Ok(RawFile {
            file: self.file.try_clone().expect("RawFile cloning failed"),
            alignment: self.alignment,
            position: self.position,
        })
    }

    pub fn sync_all(&self) -> std::io::Result<()> {
        self.file.sync_all()
    }

    pub fn sync_data(&self) -> std::io::Result<()> {
        self.file.sync_data()
    }
}

impl Read for RawFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.is_aligned(buf) {
            match self.file.read(buf) {
                Ok(r) => {
                    self.position = self.position.checked_add(r.try_into().unwrap()).unwrap();
                    Ok(r)
                }
                Err(e) => Err(e),
            }
        } else {
            let rounded_pos: u64 = self.round_down(self.position);
            let file_offset: usize = self
                .position
                .checked_sub(rounded_pos)
                .unwrap()
                .try_into()
                .unwrap();
            let buf_len: usize = buf.len();
            let rounded_len: usize = self
                .round_up(
                    file_offset
                        .checked_add(buf_len)
                        .unwrap()
                        .try_into()
                        .unwrap(),
                )
                .try_into()
                .unwrap();

            let layout = Layout::from_size_align(rounded_len, self.alignment).unwrap();
            let tmp_ptr = unsafe { alloc_zeroed(layout) };
            let tmp_buf = unsafe { slice::from_raw_parts_mut(tmp_ptr, rounded_len) };

            // This can eventually replaced with read_at once its interface
            // has been stabilized.
            let ret = unsafe {
                ::libc::pread64(
                    self.file.as_raw_fd(),
                    tmp_buf.as_mut_ptr() as *mut c_void,
                    tmp_buf.len(),
                    rounded_pos.try_into().unwrap(),
                )
            };
            if ret < 0 {
                unsafe { dealloc(tmp_ptr, layout) };
                return Err(io::Error::last_os_error());
            }

            let read: usize = ret.try_into().unwrap();
            if read < file_offset {
                unsafe { dealloc(tmp_ptr, layout) };
                return Ok(0);
            }

            let mut to_copy = read - file_offset;
            if to_copy > buf_len {
                to_copy = buf_len;
            }

            buf.copy_from_slice(&tmp_buf[file_offset..(file_offset + buf_len)]);
            unsafe { dealloc(tmp_ptr, layout) };

            self.seek(SeekFrom::Current(to_copy.try_into().unwrap()))
                .unwrap();
            Ok(to_copy.try_into().unwrap())
        }
    }
}

impl Write for RawFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.is_aligned(buf) {
            match self.file.write(buf) {
                Ok(r) => {
                    self.position = self.position.checked_add(r.try_into().unwrap()).unwrap();
                    Ok(r)
                }
                Err(e) => Err(e),
            }
        } else {
            let rounded_pos: u64 = self.round_down(self.position);
            let file_offset: usize = self
                .position
                .checked_sub(rounded_pos)
                .unwrap()
                .try_into()
                .unwrap();
            let buf_len: usize = buf.len();
            let rounded_len: usize = self
                .round_up(
                    file_offset
                        .checked_add(buf_len)
                        .unwrap()
                        .try_into()
                        .unwrap(),
                )
                .try_into()
                .unwrap();

            let layout = Layout::from_size_align(rounded_len, self.alignment).unwrap();
            let tmp_ptr = unsafe { alloc_zeroed(layout) };
            let tmp_buf = unsafe { slice::from_raw_parts_mut(tmp_ptr, rounded_len) };

            // This can eventually replaced with read_at once its interface
            // has been stabilized.
            let ret = unsafe {
                ::libc::pread64(
                    self.file.as_raw_fd(),
                    tmp_buf.as_mut_ptr() as *mut c_void,
                    tmp_buf.len(),
                    rounded_pos.try_into().unwrap(),
                )
            };
            if ret < 0 {
                unsafe { dealloc(tmp_ptr, layout) };
                return Err(io::Error::last_os_error());
            };

            tmp_buf[file_offset..(file_offset + buf_len)].copy_from_slice(buf);

            // This can eventually replaced with write_at once its interface
            // has been stabilized.
            let ret = unsafe {
                ::libc::pwrite64(
                    self.file.as_raw_fd(),
                    tmp_buf.as_ptr() as *const c_void,
                    tmp_buf.len(),
                    rounded_pos.try_into().unwrap(),
                )
            };

            unsafe { dealloc(tmp_ptr, layout) };

            if ret < 0 {
                return Err(io::Error::last_os_error());
            }

            let written: usize = ret.try_into().unwrap();
            if written < file_offset {
                Ok(0)
            } else {
                let mut to_seek = written - file_offset;
                if to_seek > buf_len {
                    to_seek = buf_len;
                }

                self.seek(SeekFrom::Current(to_seek.try_into().unwrap()))
                    .unwrap();
                Ok(to_seek.try_into().unwrap())
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.sync_all()
    }
}

impl Seek for RawFile {
    fn seek(&mut self, newpos: SeekFrom) -> std::io::Result<u64> {
        match self.file.seek(newpos) {
            Ok(pos) => {
                self.position = pos;
                Ok(pos)
            }
            Err(e) => Err(e),
        }
    }
}

impl PunchHole for RawFile {
    fn punch_hole(&mut self, offset: u64, length: u64) -> std::io::Result<()> {
        self.file.punch_hole(offset, length)
    }
}

impl SeekHole for RawFile {
    fn seek_hole(&mut self, offset: u64) -> std::io::Result<Option<u64>> {
        match self.file.seek_hole(offset) {
            Ok(pos) => {
                if let Some(p) = pos {
                    self.position = p;
                }
                Ok(pos)
            }
            Err(e) => Err(e),
        }
    }

    fn seek_data(&mut self, offset: u64) -> std::io::Result<Option<u64>> {
        match self.file.seek_data(offset) {
            Ok(pos) => {
                if let Some(p) = pos {
                    self.position = p;
                }
                Ok(pos)
            }
            Err(e) => Err(e),
        }
    }
}

impl Clone for RawFile {
    fn clone(&self) -> Self {
        RawFile {
            file: self.file.try_clone().expect("RawFile cloning failed"),
            alignment: self.alignment,
            position: self.position,
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

pub struct Request {
    request_type: RequestType,
    sector: u64,
    data_addr: GuestAddress,
    data_len: u32,
    pub status_addr: GuestAddress,
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
            data_addr: GuestAddress(0),
            data_len: 0,
            status_addr: GuestAddress(0),
        };

        let data_desc;
        let status_desc;
        let desc = avail_desc
            .next_descriptor()
            .ok_or(Error::DescriptorChainTooShort)?;

        if !desc.has_next() {
            status_desc = desc;
            // Only flush requests are allowed to skip the data descriptor.
            if req.request_type != RequestType::Flush {
                return Err(Error::DescriptorChainTooShort);
            }
        } else {
            data_desc = desc;
            status_desc = data_desc
                .next_descriptor()
                .ok_or(Error::DescriptorChainTooShort)?;

            if data_desc.is_write_only() && req.request_type == RequestType::Out {
                return Err(Error::UnexpectedWriteOnlyDescriptor);
            }
            if !data_desc.is_write_only() && req.request_type == RequestType::In {
                return Err(Error::UnexpectedReadOnlyDescriptor);
            }
            if !data_desc.is_write_only() && req.request_type == RequestType::GetDeviceID {
                return Err(Error::UnexpectedReadOnlyDescriptor);
            }

            req.data_addr = data_desc.addr;
            req.data_len = data_desc.len;
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
        let mut top: u64 = u64::from(self.data_len) / SECTOR_SIZE;
        if u64::from(self.data_len) % SECTOR_SIZE != 0 {
            top += 1;
        }
        top = top
            .checked_add(self.sector)
            .ok_or(ExecuteError::BadRequest(Error::InvalidOffset))?;
        if top > disk_nsectors {
            return Err(ExecuteError::BadRequest(Error::InvalidOffset));
        }

        disk.seek(SeekFrom::Start(self.sector << SECTOR_SHIFT))
            .map_err(ExecuteError::Seek)?;

        match self.request_type {
            RequestType::In => {
                mem.read_exact_from(self.data_addr, disk, self.data_len as usize)
                    .map_err(ExecuteError::Read)?;
                return Ok(self.data_len);
            }
            RequestType::Out => {
                mem.write_all_to(self.data_addr, disk, self.data_len as usize)
                    .map_err(ExecuteError::Write)?;
            }
            RequestType::Flush => match disk.flush() {
                Ok(_) => {
                    return Ok(0);
                }
                Err(e) => return Err(ExecuteError::Flush(e)),
            },
            RequestType::GetDeviceID => {
                if (self.data_len as usize) < disk_id.len() {
                    return Err(ExecuteError::BadRequest(Error::InvalidOffset));
                }
                mem.write_slice(&disk_id.as_slice(), self.data_addr)
                    .map_err(ExecuteError::Write)?;
            }
            RequestType::Unsupported(t) => return Err(ExecuteError::Unsupported(t)),
        };
        Ok(0)
    }
}

struct BlockEpollHandler<T: DiskFile> {
    queue: Queue,
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
    disk_image: Arc<Mutex<T>>,
    disk_nsectors: u64,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    disk_image_id: Vec<u8>,
    kill_evt: EventFd,
    pause_evt: EventFd,
    event_idx: bool,
    signalled_used: Option<Wrapping<u16>>,
}

impl<T: DiskFile> BlockEpollHandler<T> {
    fn process_queue(&mut self) -> bool {
        let queue = &mut self.queue;

        let mut used_desc_heads = Vec::new();
        let mut used_count = 0;
        let mem = self.mem.memory();
        for avail_desc in queue.iter(&mem) {
            let len;
            match Request::parse(&avail_desc, &mem) {
                Ok(request) => {
                    let mut disk_image_locked = self.disk_image.lock().unwrap();
                    let mut disk_image = disk_image_locked.deref_mut();
                    let status = match request.execute(
                        &mut disk_image,
                        self.disk_nsectors,
                        &mem,
                        &self.disk_image_id,
                    ) {
                        Ok(l) => {
                            len = l;
                            VIRTIO_BLK_S_OK
                        }
                        Err(e) => {
                            error!("Failed to execute request: {:?}", e);
                            len = 1; // We need at least 1 byte for the status.
                            e.status()
                        }
                    };
                    // We use unwrap because the request parsing process already checked that the
                    // status_addr was valid.
                    mem.write_obj(status, request.status_addr).unwrap();
                }
                Err(e) => {
                    error!("Failed to parse available descriptor chain: {:?}", e);
                    len = 0;
                }
            }
            used_desc_heads.push((avail_desc.index, len));
            used_count += 1;
        }

        for &(desc_index, len) in used_desc_heads.iter() {
            queue.add_used(&mem, desc_index, len);
        }
        used_count > 0
    }

    fn signal_used_queue(&self) -> result::Result<(), DeviceError> {
        self.interrupt_cb
            .trigger(&VirtioInterruptType::Queue, Some(&self.queue))
            .map_err(|e| {
                error!("Failed to signal used queue: {:?}", e);
                DeviceError::FailedSignalingUsedQueue(e)
            })
    }

    #[allow(dead_code)]
    fn update_disk_image(
        &mut self,
        mut disk_image: T,
        disk_path: &PathBuf,
    ) -> result::Result<(), DeviceError> {
        self.disk_nsectors = disk_image
            .seek(SeekFrom::End(0))
            .map_err(DeviceError::IoError)?
            / SECTOR_SIZE;
        self.disk_image_id = build_disk_image_id(disk_path);
        self.disk_image = Arc::new(Mutex::new(disk_image));
        Ok(())
    }

    fn needs_notification(&mut self, mem: &GuestMemoryMmap, used_idx: Wrapping<u16>) -> bool {
        if !self.event_idx {
            return true;
        }

        let mut notify = true;

        if let Some(old_idx) = self.signalled_used {
            if let Some(used_event) = self.queue.get_used_event(&mem) {
                if (used_idx - used_event - Wrapping(1u16)) >= (used_idx - old_idx) {
                    notify = false;
                }
            }
        }

        self.signalled_used = Some(used_idx);
        notify
    }

    fn run(
        &mut self,
        queue_evt: EventFd,
        paused: Arc<AtomicBool>,
    ) -> result::Result<(), DeviceError> {
        // Create the epoll file descriptor
        let epoll_fd = epoll::create(true).map_err(DeviceError::EpollCreateFd)?;
        // Use 'File' to enforce closing on 'epoll_fd'
        let epoll_file = unsafe { File::from_raw_fd(epoll_fd) };

        // Add events
        epoll::ctl(
            epoll_file.as_raw_fd(),
            epoll::ControlOptions::EPOLL_CTL_ADD,
            queue_evt.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, u64::from(QUEUE_AVAIL_EVENT)),
        )
        .map_err(DeviceError::EpollCtl)?;
        epoll::ctl(
            epoll_file.as_raw_fd(),
            epoll::ControlOptions::EPOLL_CTL_ADD,
            self.kill_evt.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, u64::from(KILL_EVENT)),
        )
        .map_err(DeviceError::EpollCtl)?;
        epoll::ctl(
            epoll_file.as_raw_fd(),
            epoll::ControlOptions::EPOLL_CTL_ADD,
            self.pause_evt.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, u64::from(PAUSE_EVENT)),
        )
        .map_err(DeviceError::EpollCtl)?;

        const EPOLL_EVENTS_LEN: usize = 100;
        let mut events = vec![epoll::Event::new(epoll::Events::empty(), 0); EPOLL_EVENTS_LEN];

        'epoll: loop {
            let num_events = match epoll::wait(epoll_file.as_raw_fd(), -1, &mut events[..]) {
                Ok(res) => res,
                Err(e) => {
                    if e.kind() == io::ErrorKind::Interrupted {
                        // It's well defined from the epoll_wait() syscall
                        // documentation that the epoll loop can be interrupted
                        // before any of the requested events occurred or the
                        // timeout expired. In both those cases, epoll_wait()
                        // returns an error of type EINTR, but this should not
                        // be considered as a regular error. Instead it is more
                        // appropriate to retry, by calling into epoll_wait().
                        continue;
                    }
                    return Err(DeviceError::EpollWait(e));
                }
            };

            for event in events.iter().take(num_events) {
                let ev_type = event.data as u16;

                match ev_type {
                    QUEUE_AVAIL_EVENT => {
                        if let Err(e) = queue_evt.read() {
                            error!("Failed to get queue event: {:?}", e);
                            break 'epoll;
                        } else if self.event_idx {
                            // vm-virtio's Queue implementation only checks avail_index
                            // once, so to properly support EVENT_IDX we need to keep
                            // calling process_queue() until it stops finding new
                            // requests on the queue.
                            loop {
                                if self.process_queue() {
                                    self.queue.update_avail_event(&self.mem.memory());

                                    if self.needs_notification(
                                        &self.mem.memory(),
                                        self.queue.next_used,
                                    ) {
                                        if let Err(e) = self.signal_used_queue() {
                                            error!("Failed to signal used queue: {:?}", e);
                                            break 'epoll;
                                        }
                                    }
                                } else {
                                    break;
                                }
                            }
                        } else if self.process_queue() {
                            if let Err(e) = self.signal_used_queue() {
                                error!("Failed to signal used queue: {:?}", e);
                                break 'epoll;
                            }
                        }
                    }
                    KILL_EVENT => {
                        debug!("KILL_EVENT received, stopping epoll loop");
                        break 'epoll;
                    }
                    PAUSE_EVENT => {
                        // Drain pause event
                        let _ = self.pause_evt.read();
                        debug!("PAUSE_EVENT received, pausing virtio-block epoll loop");
                        // We loop here to handle spurious park() returns.
                        // Until we have not resumed, the paused boolean will
                        // be true.
                        while paused.load(Ordering::SeqCst) {
                            thread::park();
                        }
                    }
                    _ => {
                        error!("Unknown event for virtio-block");
                    }
                }
            }
        }

        Ok(())
    }
}

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
    pub wce: u8,
    unused: u8,
    pub num_queues: u16,
    pub max_discard_sectors: u32,
    pub max_discard_seg: u32,
    pub discard_sector_alignment: u32,
    pub max_write_zeroes_sectors: u32,
    pub max_write_zeroes_seg: u32,
    pub write_zeroes_may_unmap: u8,
    unused1: [u8; 3],
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
        let wce = self.wce;
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
        virtio_block_config.serialize_field("wce", &wce)?;
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

/// Virtio device for exposing block level read/write operations on a host file.
pub struct Block<T: DiskFile> {
    id: String,
    kill_evt: Option<EventFd>,
    disk_image: Arc<Mutex<T>>,
    disk_path: PathBuf,
    disk_nsectors: u64,
    avail_features: u64,
    acked_features: u64,
    config: VirtioBlockConfig,
    queue_evts: Option<Vec<EventFd>>,
    interrupt_cb: Option<Arc<dyn VirtioInterrupt>>,
    epoll_threads: Option<Vec<thread::JoinHandle<result::Result<(), DeviceError>>>>,
    pause_evt: Option<EventFd>,
    paused: Arc<AtomicBool>,
    queue_size: Vec<u16>,
}

#[derive(Serialize, Deserialize)]
pub struct BlockState {
    pub disk_path: PathBuf,
    pub disk_nsectors: u64,
    pub avail_features: u64,
    pub acked_features: u64,
    pub config: VirtioBlockConfig,
}

impl<T: DiskFile> Block<T> {
    /// Create a new virtio block device that operates on the given file.
    ///
    /// The given file must be seekable and sizable.
    pub fn new(
        id: String,
        mut disk_image: T,
        disk_path: PathBuf,
        is_disk_read_only: bool,
        iommu: bool,
        num_queues: usize,
        queue_size: u16,
    ) -> io::Result<Block<T>> {
        let disk_size = disk_image.seek(SeekFrom::End(0))? as u64;
        if disk_size % SECTOR_SIZE != 0 {
            warn!(
                "Disk size {} is not a multiple of sector size {}; \
                 the remainder will not be visible to the guest.",
                disk_size, SECTOR_SIZE
            );
        }

        let mut avail_features = (1u64 << VIRTIO_F_VERSION_1)
            | (1u64 << VIRTIO_BLK_F_FLUSH)
            | (1u64 << VIRTIO_RING_F_EVENT_IDX);

        if iommu {
            avail_features |= 1u64 << VIRTIO_F_IOMMU_PLATFORM;
        }

        if is_disk_read_only {
            avail_features |= 1u64 << VIRTIO_BLK_F_RO;
        }

        let disk_nsectors = disk_size / SECTOR_SIZE;
        let mut config = VirtioBlockConfig {
            capacity: disk_nsectors,
            ..Default::default()
        };

        if num_queues > 1 {
            avail_features |= 1u64 << VIRTIO_BLK_F_MQ;
            config.num_queues = num_queues as u16;
        }

        Ok(Block {
            id,
            kill_evt: None,
            disk_image: Arc::new(Mutex::new(disk_image)),
            disk_path,
            disk_nsectors,
            avail_features,
            acked_features: 0u64,
            config,
            queue_evts: None,
            interrupt_cb: None,
            epoll_threads: None,
            pause_evt: None,
            paused: Arc::new(AtomicBool::new(false)),
            queue_size: vec![queue_size; num_queues],
        })
    }

    fn state(&self) -> BlockState {
        BlockState {
            disk_path: self.disk_path.clone(),
            disk_nsectors: self.disk_nsectors,
            avail_features: self.avail_features,
            acked_features: self.acked_features,
            config: self.config,
        }
    }

    fn set_state(&mut self, state: &BlockState) -> io::Result<()> {
        self.disk_path = state.disk_path.clone();
        self.disk_nsectors = state.disk_nsectors;
        self.avail_features = state.avail_features;
        self.acked_features = state.acked_features;
        self.config = state.config;

        Ok(())
    }
}

impl<T: DiskFile> Drop for Block<T> {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
    }
}

impl<T: 'static + DiskFile + Send> VirtioDevice for Block<T> {
    fn device_type(&self) -> u32 {
        VirtioDeviceType::TYPE_BLOCK as u32
    }

    fn queue_max_sizes(&self) -> &[u16] {
        self.queue_size.as_slice()
    }

    fn features(&self) -> u64 {
        self.avail_features
    }

    fn ack_features(&mut self, value: u64) {
        let mut v = value;
        // Check if the guest is ACK'ing a feature that we didn't claim to have.
        let unrequested_features = v & !self.avail_features;
        if unrequested_features != 0 {
            warn!("Received acknowledge request for unknown feature.");

            // Don't count these features as acked.
            v &= !unrequested_features;
        }
        self.acked_features |= v;
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_slice = self.config.as_slice();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&config_slice[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let config_slice = self.config.as_mut_slice();
        let data_len = data.len() as u64;
        let config_len = config_slice.len() as u64;
        if offset + data_len > config_len {
            error!("Failed to write config space");
            return;
        }
        let (_, right) = config_slice.split_at_mut(offset as usize);
        right.copy_from_slice(&data[..]);
    }

    fn activate(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        interrupt_cb: Arc<dyn VirtioInterrupt>,
        mut queues: Vec<Queue>,
        mut queue_evts: Vec<EventFd>,
    ) -> ActivateResult {
        if queues.len() != self.queue_size.len() || queue_evts.len() != self.queue_size.len() {
            error!(
                "Cannot perform activate. Expected {} queue(s), got {}",
                self.queue_size.len(),
                queues.len()
            );
            return Err(ActivateError::BadActivate);
        }

        let (self_kill_evt, kill_evt) = EventFd::new(EFD_NONBLOCK)
            .and_then(|e| Ok((e.try_clone()?, e)))
            .map_err(|e| {
                error!("failed creating kill EventFd pair: {}", e);
                ActivateError::BadActivate
            })?;

        self.kill_evt = Some(self_kill_evt);

        let (self_pause_evt, pause_evt) = EventFd::new(EFD_NONBLOCK)
            .and_then(|e| Ok((e.try_clone()?, e)))
            .map_err(|e| {
                error!("failed creating pause EventFd pair: {}", e);
                ActivateError::BadActivate
            })?;
        self.pause_evt = Some(self_pause_evt);

        let disk_image_id = build_disk_image_id(&self.disk_path);

        let mut tmp_queue_evts: Vec<EventFd> = Vec::new();
        for queue_evt in queue_evts.iter() {
            // Save the queue EventFD as we need to return it on reset
            // but clone it to pass into the thread.
            tmp_queue_evts.push(queue_evt.try_clone().map_err(|e| {
                error!("failed to clone queue EventFd: {}", e);
                ActivateError::BadActivate
            })?);
        }
        self.queue_evts = Some(tmp_queue_evts);

        let mut tmp_queue_evts: Vec<EventFd> = Vec::new();
        for queue_evt in queue_evts.iter() {
            // Save the queue EventFD as we need to return it on reset
            // but clone it to pass into the thread.
            tmp_queue_evts.push(queue_evt.try_clone().map_err(|e| {
                error!("failed to clone queue EventFd: {}", e);
                ActivateError::BadActivate
            })?);
        }
        self.queue_evts = Some(tmp_queue_evts);

        let event_idx = self.acked_features & 1u64 << VIRTIO_RING_F_EVENT_IDX
            == 1u64 << VIRTIO_RING_F_EVENT_IDX;

        let mut epoll_threads = Vec::new();
        for _ in 0..self.queue_size.len() {
            let mut handler = BlockEpollHandler {
                queue: queues.remove(0),
                mem: mem.clone(),
                disk_image: self.disk_image.clone(),
                disk_nsectors: self.disk_nsectors,
                interrupt_cb: interrupt_cb.clone(),
                disk_image_id: disk_image_id.clone(),
                kill_evt: kill_evt.try_clone().unwrap(),
                pause_evt: pause_evt.try_clone().unwrap(),
                event_idx,
                signalled_used: None,
            };

            let queue_evt = queue_evts.remove(0);
            let paused = self.paused.clone();
            thread::Builder::new()
                .name("virtio_blk".to_string())
                .spawn(move || handler.run(queue_evt, paused))
                .map(|thread| epoll_threads.push(thread))
                .map_err(|e| {
                    error!("failed to clone the virtio-blk epoll thread: {}", e);
                    ActivateError::BadActivate
                })?;
        }

        // Save the interrupt EventFD as we need to return it on reset
        // but clone it to pass into the thread.
        self.interrupt_cb = Some(interrupt_cb);

        self.epoll_threads = Some(epoll_threads);

        Ok(())
    }

    fn reset(&mut self) -> Option<(Arc<dyn VirtioInterrupt>, Vec<EventFd>)> {
        // We first must resume the virtio thread if it was paused.
        if self.pause_evt.take().is_some() {
            self.resume().ok()?;
        }

        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }

        // Return the interrupt and queue EventFDs
        Some((
            self.interrupt_cb.take().unwrap(),
            self.queue_evts.take().unwrap(),
        ))
    }
}

virtio_pausable!(Block, T: 'static + DiskFile + Send);
impl<T: 'static + DiskFile + Send> Snapshottable for Block<T> {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&self) -> std::result::Result<Snapshot, MigratableError> {
        let snapshot =
            serde_json::to_vec(&self.state()).map_err(|e| MigratableError::Snapshot(e.into()))?;

        let mut block_snapshot = Snapshot::new(self.id.as_str());
        block_snapshot.add_data_section(SnapshotDataSection {
            id: format!("{}-section", self.id),
            snapshot,
        });

        Ok(block_snapshot)
    }

    fn restore(&mut self, snapshot: Snapshot) -> std::result::Result<(), MigratableError> {
        if let Some(block_section) = snapshot.snapshot_data.get(&format!("{}-section", self.id)) {
            let block_state = match serde_json::from_slice(&block_section.snapshot) {
                Ok(state) => state,
                Err(error) => {
                    return Err(MigratableError::Restore(anyhow!(
                        "Could not deserialize BLOCK {}",
                        error
                    )))
                }
            };

            return self.set_state(&block_state).map_err(|e| {
                MigratableError::Restore(anyhow!("Could not restore BLOCK state {:?}", e))
            });
        }

        Err(MigratableError::Restore(anyhow!(
            "Could not find BLOCK snapshot section"
        )))
    }
}
impl<T: 'static + DiskFile + Send> Transportable for Block<T> {}
impl<T: 'static + DiskFile + Send> Migratable for Block<T> {}
