// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

pub mod disk_file;
pub mod error;
pub mod factory;
#[path = "io/mod.rs"]
mod io_impl;
pub use io_impl::{async_io, fcntl, request};
pub(crate) mod aligned_buffer;
pub mod aligned_file;
pub mod formats;
mod sparse;
use std::fmt::{self, Debug};
use std::fs::{File, OpenOptions};
use std::os::linux::fs::MetadataExt;
use std::os::unix::fs::{FileExt, FileTypeExt};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;
use std::str::FromStr;
use std::{cmp, io, mem, result};

pub use aligned_file::AlignedFile;
use formats::qcow;
#[cfg(feature = "io_uring")]
use io_uring::{IoUring, Probe, opcode};
use libc::{
    FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE, FALLOC_FL_ZERO_RANGE, S_IFBLK, S_IFMT, ioctl,
};
use log::{debug, info, warn};
pub use request::{ExecuteAsync, MAX_DISCARD_WRITE_ZEROES_SEG, Request, RequestType};
use serde::{Deserialize, Serialize};
pub use sparse::{BLKDISCARD, BLKZEROOUT};
use thiserror::Error;
use virtio_bindings::virtio_blk::*;
use vm_memory::bitmap::Bitmap;
use vm_memory::{ByteValued, Bytes, GuestAddress, GuestMemory, GuestMemoryError};
use vmm_sys_util::{aio, ioctl_io_nr, ioctl_ior_nr};

use crate::async_io::AsyncIoError;
use crate::error::{BlockError, BlockErrorKind, BlockResult, ErrorOp};
use crate::formats::vhdx::VhdxError;
use crate::request::SECTOR_SIZE;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Guest gave us bad memory addresses")]
    GuestMemory(#[source] GuestMemoryError),
    #[error("Guest address {0:?} with sector offset {1} would overflow a usize")]
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
    DetectImageType(#[source] io::Error),
    #[error("Failure in fixed vhd")]
    FixedVhdError(#[source] io::Error),
    #[error("Getting a block's metadata failed")]
    GetFileMetadata(#[source] io::Error),
    #[error("The requested operation would cause a seek beyond disk end")]
    InvalidOffset,
    #[error("Failure in qcow")]
    QcowError(#[source] qcow::Error),
    #[error("The requested operation does not support multiple descriptors")]
    TooManyDescriptors,
    #[error("Request contains too many segments ({0}, max {MAX_DISCARD_WRITE_ZEROES_SEG})")]
    TooManySegments(u32),
    #[error("Failure in vhdx")]
    VhdxError(#[source] VhdxError),
}

fn build_device_id(disk_path: &Path) -> result::Result<String, Error> {
    let blk_metadata = match disk_path.metadata() {
        Err(e) => return Err(Error::GetFileMetadata(e)),
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
    #[error("Can't execute an operation other than `read` or `get_id` on a read-only device")]
    ReadOnly,
    #[error("Failed to write")]
    Write(#[source] GuestMemoryError),
    #[error("Failed to write_all")]
    WriteAll(#[source] io::Error),
    #[error("Unsupported request: {0}")]
    Unsupported(u32),
    #[error("Unsupported flags {flags:#x} for request type {request_type}")]
    UnsupportedFlags { request_type: u32, flags: u32 },
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
    #[error("Failed to async punch hole")]
    AsyncPunchHole(#[source] AsyncIoError),
    #[error("Failed to async write zeroes")]
    AsyncWriteZeroes(#[source] AsyncIoError),
    #[error("Failed allocating a temporary buffer")]
    TemporaryBufferAllocation(#[source] io::Error),
}

impl ExecuteError {
    pub fn status(&self) -> u8 {
        let status = match *self {
            ExecuteError::BadRequest(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::Flush(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::Read(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::ReadExact(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::ReadOnly => VIRTIO_BLK_S_IOERR,
            ExecuteError::Write(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::WriteAll(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::Unsupported(_) => VIRTIO_BLK_S_UNSUPP,
            ExecuteError::UnsupportedFlags { .. } => VIRTIO_BLK_S_UNSUPP,
            ExecuteError::SubmitIoUring(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::GetHostAddress(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::AsyncRead(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::AsyncWrite(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::AsyncFlush(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::AsyncPunchHole(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::AsyncWriteZeroes(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::TemporaryBufferAllocation(_) => VIRTIO_BLK_S_IOERR,
        };
        status as u8
    }
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

/// Returns `true` iff `fd` refers to a block device.
///
/// Returns `false` if the `fstat()` probe itself fails. Callers that need to
/// distinguish "not a block device" from "couldn't tell" should fall back to
/// regular-file behaviour, which is what every current caller already does.
pub(crate) fn is_block_device(fd: RawFd) -> bool {
    // SAFETY: `libc::stat` is POD; zero-initialization is a valid bit pattern
    // and `fstat` overwrites every field it cares about on success.
    let mut stat: libc::stat = unsafe { mem::zeroed() };
    // SAFETY: FFI call with a valid fd and a valid out-pointer.
    let ret = unsafe { libc::fstat(fd, &mut stat) };
    ret == 0 && stat.st_mode & S_IFMT == S_IFBLK
}

/// Returns the kernel reported direct I/O alignment for `fd`, or `None`
/// when `fd` was not opened with O_DIRECT.
///
/// When O_DIRECT is set, uses `statx(STATX_DIOALIGN)` (Linux >= 6.1) to obtain
/// the exact memory and offset alignment the kernel requires for direct I/O on
/// this specific fd. Unlike `fstatvfs().f_bsize`, which only returns the
/// filesystem's preferred I/O block size, `STATX_DIOALIGN` reports the true per
/// fd direct I/O constraint accounting for the filesystem, underlying block
/// device, and any stacking such as loop or device mapper. Falls back to
/// [`SECTOR_SIZE`] when the kernel does not report a value.
pub(crate) fn probe_direct_alignment(fd: RawFd) -> Option<u64> {
    // SAFETY: fcntl(F_GETFL) is always safe on a valid fd.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || (flags & libc::O_DIRECT) == 0 {
        return None;
    }

    // The libc crate does not expose statx / STATX_DIOALIGN on all targets,
    // for example musl, so define the constant and a minimal repr(C) struct
    // locally and invoke the syscall directly.
    const STATX_DIOALIGN: u32 = 0x2000;

    // Minimal statx layout, only the needed fields, everything else is
    // padding.
    #[repr(C)]
    struct Statx {
        stx_mask: u32,
        _pad: [u8; 148],
        stx_dio_mem_align: u32,
        stx_dio_offset_align: u32,
        _pad2: [u8; 96],
    }

    let mut stx = mem::MaybeUninit::<Statx>::zeroed();
    // SAFETY: FFI syscall with valid fd and correctly sized buffer.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_statx,
            fd,
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            STATX_DIOALIGN,
            stx.as_mut_ptr(),
        )
    };
    if ret == 0 {
        // SAFETY: statx succeeded, the struct is fully initialized.
        let stx = unsafe { stx.assume_init() };
        if stx.stx_mask & STATX_DIOALIGN != 0 && stx.stx_dio_mem_align > 0 {
            return Some(cmp::max(stx.stx_dio_mem_align, stx.stx_dio_offset_align) as u64);
        }
    }

    debug!("O_DIRECT alignment query failed, falling back to default {SECTOR_SIZE}");
    Some(SECTOR_SIZE)
}

/// Probe whether the file/device supports punch hole and zero range
pub fn probe_sparse_support(file: &File) -> bool {
    let fd = file.as_raw_fd();

    if is_block_device(fd) {
        probe_block_device_sparse_support(fd)
    } else {
        probe_file_sparse_support(fd)
    }
}

/// Probe sparse support for a regular file using fallocate().
fn probe_file_sparse_support(fd: libc::c_int) -> bool {
    // SAFETY: FFI call with valid fd
    let file_size = unsafe { libc::lseek(fd, 0, libc::SEEK_END) };
    if file_size < 0 {
        let err = io::Error::last_os_error();
        warn!("Failed to get file size for sparse probe: {err}");
        return false;
    }

    // SAFETY: FFI call with valid fd, probing past EOF is safe with KEEP_SIZE
    let punch_hole =
        unsafe { libc::fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, file_size, 1) }
            == 0;

    if !punch_hole {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EOPNOTSUPP) {
            debug!("File does not support FALLOC_FL_PUNCH_HOLE: {err}");
        } else {
            debug!("PUNCH_HOLE probe returned unexpected error: {err}");
        }
    }

    // SAFETY: FFI call with valid fd, probing past EOF is safe with KEEP_SIZE
    let zero_range =
        unsafe { libc::fallocate(fd, FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE, file_size, 1) }
            == 0;

    if !zero_range {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EOPNOTSUPP) {
            debug!("File does not support FALLOC_FL_ZERO_RANGE: {err}");
        }
    }

    let supported = punch_hole || zero_range;
    info!(
        "Probed file sparse support: punch_hole={punch_hole}, zero_range={zero_range} => {supported}"
    );
    supported
}

/// Probe sparse support for a block device.
///
/// Block devices always report sparse support. `BLKZEROOUT` is guaranteed to
/// succeed as the kernel provides a software fallback writing explicit zeros
/// when the hardware lacks a native write zeroes command. `BLKDISCARD` may fail
/// at runtime with `EOPNOTSUPP` on devices without trim or discard support, but
/// Linux guests handle this gracefully by ceasing discard requests.
///
/// There is no non destructive read only ioctl to query block device discard
/// or write zeroes capabilities.
fn probe_block_device_sparse_support(_fd: libc::c_int) -> bool {
    info!("Block device: assuming sparse support");
    true
}

/// Preallocate disk space for a disk image file.
///
/// Uses `fallocate()` to allocate all disk space upfront, ensuring storage
/// availability and reducing fragmentation. Allocating all blocks upfront is
/// more likely to place them contiguously than allocating on demand during
/// random writes.
pub fn preallocate_disk<P: AsRef<Path>>(file: &File, path: P) {
    let size = match file.metadata() {
        Ok(m) => m.len(),
        Err(e) => {
            warn!("Failed to get metadata for {:?}: {}", path.as_ref(), e);
            return;
        }
    };

    if size == 0 {
        return;
    }

    // SAFETY: FFI call with valid file descriptor and size
    let ret = unsafe { libc::fallocate(file.as_raw_fd(), 0, 0, size as libc::off_t) };

    if ret != 0 {
        warn!(
            "Failed to preallocate disk space for {:?}: {}",
            path.as_ref(),
            io::Error::last_os_error()
        );
    } else {
        debug!(
            "Preallocated {size} bytes for disk image {:?}",
            path.as_ref()
        );
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ImageType {
    FixedVhd,
    Qcow2,
    Raw,
    Vhdx,
    #[default]
    Unknown,
}

impl fmt::Display for ImageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImageType::FixedVhd => write!(f, "vhd"),
            ImageType::Qcow2 => write!(f, "qcow2"),
            ImageType::Raw => write!(f, "raw"),
            ImageType::Vhdx => write!(f, "vhdx"),
            ImageType::Unknown => write!(f, "unknown"),
        }
    }
}

pub enum ImageTypeParseError {
    InvalidValue(String),
}

impl FromStr for ImageType {
    type Err = ImageTypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "vhd" => Ok(ImageType::FixedVhd),
            "qcow2" => Ok(ImageType::Qcow2),
            "raw" => Ok(ImageType::Raw),
            "vhdx" => Ok(ImageType::Vhdx),
            _ => Err(ImageTypeParseError::InvalidValue(s.to_string())),
        }
    }
}

const QCOW_MAGIC: u32 = 0x5146_49fb;
const VHDX_SIGN: u64 = 0x656C_6966_7864_6876;

/// Open a disk image file, returning a [`BlockError`] with path context
/// on failure.
pub fn open_disk_image(path: &Path, options: &OpenOptions) -> BlockResult<File> {
    options.open(path).map_err(|e| {
        BlockError::new(BlockErrorKind::Io, e)
            .with_op(ErrorOp::Open)
            .with_path(path)
    })
}

/// Determine image type through file parsing.
pub fn detect_image_type(f: &mut File) -> BlockResult<ImageType> {
    let aligned = AlignedFile::new(f.try_clone()?, true);
    let mut block = vec![0u8; aligned.alignment()];
    aligned
        .read_exact_at(&mut block, 0)
        .map_err(|e| BlockError::new(BlockErrorKind::Io, e).with_op(ErrorOp::DetectImageType))?;

    // Check 4 first bytes to get the header value and determine the image type
    let image_type = if u32::from_be_bytes(block[0..4].try_into().unwrap()) == QCOW_MAGIC {
        ImageType::Qcow2
    } else if formats::vhd::is_fixed_vhd(f)
        .map_err(|e| BlockError::new(BlockErrorKind::Io, e).with_op(ErrorOp::DetectImageType))?
    {
        ImageType::FixedVhd
    } else if u64::from_le_bytes(block[0..8].try_into().unwrap()) == VHDX_SIGN {
        ImageType::Vhdx
    } else {
        ImageType::Raw
    };

    Ok(image_type)
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
ioctl_io_nr!(BLKPBSZGET, 0x12, 123);
ioctl_io_nr!(BLKIOMIN, 0x12, 120);
ioctl_io_nr!(BLKIOOPT, 0x12, 121);
ioctl_ior_nr!(BLKGETSIZE64, 0x12, 114, u64);

/// Returns `(logical_size, physical_size)` in bytes for regular files and block devices.
///
/// For regular files, logical size is `st_size` and physical size is
/// `st_blocks * 512` (actual host allocation). For block devices both
/// values equal the `BLKGETSIZE64` result.
pub fn query_device_size(file: &File) -> io::Result<(u64, u64)> {
    let m = file.metadata()?;
    if m.is_file() {
        // st_blocks is always in 512-byte units on Linux
        Ok((m.len(), m.st_blocks() * 512))
    } else if m.file_type().is_block_device() {
        let mut size: u64 = 0;
        // SAFETY: BLKGETSIZE64 reads the device size into a u64 pointer.
        let ret = unsafe { libc::ioctl(file.as_raw_fd(), BLKGETSIZE64() as _, &mut size) };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((size, size))
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "disk image must be a regular file or block device, is: {:?}",
                m.file_type()
            ),
        ))
    }
}

#[derive(Copy, Clone)]
enum BlockSize {
    LogicalBlock,
    PhysicalBlock,
    MinimumIo,
    OptimalIo,
}

impl DiskTopology {
    // libc::ioctl() takes different types on different architectures
    fn query_block_size(f: &File, block_size_type: BlockSize) -> io::Result<u64> {
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
            return Err(io::Error::last_os_error());
        }

        Ok(block_size)
    }

    pub fn probe(f: &File) -> io::Result<Self> {
        if !is_block_device(f.as_raw_fd()) {
            // For regular files opened with O_DIRECT, the logical block size
            // must reflect the filesystem DIO alignment so the guest issues
            // correctly sized I/O.
            if let Some(alignment) = probe_direct_alignment(f.as_raw_fd()) {
                return Ok(DiskTopology {
                    logical_block_size: alignment,
                    physical_block_size: alignment,
                    minimum_io_size: alignment,
                    optimal_io_size: 0,
                });
            }
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
mod unit_tests {
    use std::alloc::{Layout, alloc_zeroed, dealloc};
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::{mem, ptr, slice};

    use vmm_sys_util::tempfile::TempFile;

    use super::*;

    #[test]
    fn test_probe_regular_file_returns_valid_alignment() {
        let temp_file = TempFile::new().unwrap();
        let mut f = temp_file.into_file();
        f.write_all(&[0u8; 4096]).unwrap();
        f.sync_all().unwrap();

        let topo = DiskTopology::probe(&f).unwrap();

        assert_eq!(
            topo.logical_block_size, SECTOR_SIZE,
            "probe() should return {SECTOR_SIZE} for regular files without O_DIRECT, got {}",
            topo.logical_block_size
        );
    }

    #[test]
    fn test_probe_regular_file_with_direct_returns_dio_alignment() {
        let temp_file = TempFile::new().unwrap();
        let path = temp_file.as_path().to_owned();
        {
            let f = temp_file.as_file();
            f.set_len(1 << 20).unwrap(); // 1 MiB
            f.sync_all().unwrap();
        }

        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_DIRECT)
            .open(&path)
            .unwrap();
        let topo = DiskTopology::probe(&f).unwrap();

        assert!(
            topo.logical_block_size.is_power_of_two(),
            "logical_block_size {} is not a power of two",
            topo.logical_block_size
        );
        assert!(
            topo.logical_block_size >= SECTOR_SIZE,
            "logical_block_size {} is less than SECTOR_SIZE ({SECTOR_SIZE})",
            topo.logical_block_size
        );

        let alignment = topo.logical_block_size as usize;
        let layout = Layout::from_size_align(4096, alignment);
        assert!(
            layout.is_ok(),
            "Layout::from_size_align(4096, {alignment}) failed: {:?}",
            layout.err()
        );
    }

    #[test]
    fn test_dio_write_read_with_probed_alignment() {
        let temp_file = TempFile::new().unwrap();
        let path = temp_file.as_path().to_owned();
        {
            let f = temp_file.as_file();
            f.set_len(1 << 20).unwrap(); // 1 MiB
            f.sync_all().unwrap();
        }

        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_DIRECT)
            .open(&path)
            .unwrap();
        let topo = DiskTopology::probe(&f).unwrap();
        let alignment = topo.logical_block_size as usize;

        let layout = Layout::from_size_align(alignment, alignment).unwrap();
        // SAFETY: layout is valid (non-zero, power-of-two alignment).
        let buf = unsafe { alloc_zeroed(layout) };
        assert!(!buf.is_null());

        // SAFETY: buf is valid for `alignment` bytes.
        unsafe { ptr::write_bytes(buf, 0xAB, alignment) };

        // SAFETY: buf is aligned and sized for O_DIRECT; fd is valid.
        let written = unsafe { libc::pwrite(f.as_raw_fd(), buf.cast(), alignment, 0) };
        assert_eq!(
            written as usize,
            alignment,
            "O_DIRECT pwrite failed: {}",
            io::Error::last_os_error()
        );

        // SAFETY: buf is valid for `alignment` bytes.
        unsafe { ptr::write_bytes(buf, 0x00, alignment) };
        // SAFETY: buf is aligned and sized for O_DIRECT; fd is valid.
        let read = unsafe { libc::pread(f.as_raw_fd(), buf.cast(), alignment, 0) };
        assert_eq!(
            read as usize,
            alignment,
            "O_DIRECT pread failed: {}",
            io::Error::last_os_error()
        );

        // SAFETY: buf is valid for `alignment` bytes after successful pread.
        let slice = unsafe { slice::from_raw_parts(buf, alignment) };
        assert!(
            slice.iter().all(|&b| b == 0xAB),
            "Data mismatch after O_DIRECT roundtrip"
        );

        // SAFETY: buf was allocated with this layout via alloc_zeroed.
        unsafe { dealloc(buf, layout) };
    }

    #[test]
    fn test_query_device_size_regular_file() {
        let temp_file = TempFile::new().unwrap();
        let mut f = temp_file.into_file();
        // 5 sectors + 13 extra bytes - not page aligned, not sectoraligned
        f.write_all(&[0xAB; 5 * 512 + 13]).unwrap();
        f.sync_all().unwrap();

        let (logical, physical) = query_device_size(&f).unwrap();
        assert_eq!(logical, 5 * 512 + 13);
        assert!(physical > 0);
    }

    // A mode-0 fallocate() is not eagerly accounted in st_blocks on every
    // filesystem: zfs reserves the range but accounts blocks lazily at
    // transaction-group commit, and FUSE-based filesystems such as virtiofs
    // report preallocated files as sparse. Identify those by filesystem type
    // so a skipped physical-size check always names a proven platform
    // limitation instead of being inferred from the value under test.
    fn fs_defers_fallocate_block_accounting(f: &File) -> bool {
        // SAFETY: a zeroed statfs is a valid output buffer for fstatfs and it
        // is only read after the call succeeds.
        let mut sfs: libc::statfs = unsafe { mem::zeroed() };
        // SAFETY: the fd is valid and sfs outlives the call.
        let ret = unsafe { libc::fstatfs(f.as_raw_fd(), &mut sfs) };
        assert_eq!(ret, 0, "fstatfs failed: {}", io::Error::last_os_error());
        // ZFS_SUPER_MAGIC and FUSE_SUPER_MAGIC (statfs(2)), as untyped
        // literals because the width and signedness of f_type differ
        // between libc targets.
        matches!(sfs.f_type, 0x2fc1_2fc1 | 0x6573_5546)
    }

    #[test]
    fn test_query_device_size_sparse_file_punch_hole() {
        let temp_file = TempFile::new().unwrap();
        let f = temp_file.as_file();
        // Allocate 1 MiB
        let size: i64 = 1 << 20;
        f.set_len(size as u64).unwrap();
        // SAFETY: fd is valid, range is within file size.
        let ret = unsafe {
            libc::fallocate(
                f.as_raw_fd(),
                0, // allocate
                0,
                size,
            )
        };
        if ret != 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EOPNOTSUPP) {
                eprintln!("Skipping test: fallocate() is not supported: {err}");
                return;
            }
            panic!("fallocate failed: {err}");
        }
        f.sync_all().unwrap();

        let (log_before, phys_before) = query_device_size(f).unwrap();
        assert_eq!(log_before, size as u64);
        if fs_defers_fallocate_block_accounting(f) {
            eprintln!(
                "Skipping physical size checks: the filesystem defers \
                 fallocate() block accounting"
            );
            return;
        }
        assert_eq!(phys_before, size as u64);

        // Punch a hole in the middle 512 KiB
        // SAFETY: fd is valid, range is within file size.
        let ret = unsafe {
            libc::fallocate(
                f.as_raw_fd(),
                libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                size / 4,
                size / 2,
            )
        };
        if ret != 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EOPNOTSUPP) {
                eprintln!(
                    "Skipping punch-hole checks: FALLOC_FL_PUNCH_HOLE is not supported: {err}"
                );
                return;
            }
            panic!("punch hole failed: {err}");
        }
        f.sync_all().unwrap();

        let (logical, physical) = query_device_size(f).unwrap();
        assert_eq!(logical, size as u64, "logical size must not change");
        assert!(
            physical < logical,
            "physical ({physical}) should be less than logical ({logical}) after punch hole"
        );
    }

    #[test]
    fn test_query_device_size_rejects_char_device() {
        let f = File::open("/dev/zero").unwrap();
        let err = query_device_size(&f).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
