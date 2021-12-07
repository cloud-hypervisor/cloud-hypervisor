// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use libc::{ioctl, S_IFBLK, S_IFMT};
use std::convert::TryInto;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use thiserror::Error;
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::{ioctl_expr, ioctl_io_nr, ioctl_ioc_nr};

#[derive(Error, Debug)]
pub enum DiskFileError {
    /// Failed getting disk file size.
    #[error("Failed getting disk file size: {0}")]
    Size(#[source] std::io::Error),
    /// Failed creating a new AsyncIo.
    #[error("Failed creating a new AsyncIo: {0}")]
    NewAsyncIo(#[source] std::io::Error),
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

impl DiskTopology {
    // libc::ioctl() takes different types on different architectures
    #[allow(clippy::useless_conversion)]
    pub fn probe(f: &mut File) -> std::io::Result<Self> {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        let ret = unsafe { libc::fstat(f.as_raw_fd(), stat.as_mut_ptr()) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }

        let is_block = unsafe { (*stat.as_ptr()).st_mode & S_IFMT == S_IFBLK };
        if !is_block {
            return Ok(DiskTopology::default());
        }

        let mut logical_block_size = 0;
        let mut physical_block_size = 0;
        let mut minimum_io_size = 0;
        let mut optimal_io_size = 0;

        let ret = unsafe {
            ioctl(
                f.as_raw_fd(),
                BLKSSZGET().try_into().unwrap(),
                &mut logical_block_size,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        };

        let ret = unsafe {
            ioctl(
                f.as_raw_fd(),
                BLKPBSZGET().try_into().unwrap(),
                &mut physical_block_size,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        };

        let ret = unsafe {
            ioctl(
                f.as_raw_fd(),
                BLKIOMIN().try_into().unwrap(),
                &mut minimum_io_size,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        };

        let ret = unsafe {
            ioctl(
                f.as_raw_fd(),
                BLKIOOPT().try_into().unwrap(),
                &mut optimal_io_size,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        };

        Ok(DiskTopology {
            logical_block_size,
            physical_block_size,
            minimum_io_size,
            optimal_io_size,
        })
    }
}

pub type DiskFileResult<T> = std::result::Result<T, DiskFileError>;

pub trait DiskFile: Send + Sync {
    fn size(&mut self) -> DiskFileResult<u64>;
    fn new_async_io(&self, ring_depth: u32) -> DiskFileResult<Box<dyn AsyncIo>>;
    fn topology(&mut self) -> DiskTopology {
        DiskTopology::default()
    }
}

#[derive(Error, Debug)]
pub enum AsyncIoError {
    /// Failed vectored reading from file.
    #[error("Failed vectored reading from file: {0}")]
    ReadVectored(#[source] std::io::Error),
    /// Failed vectored writing to file.
    #[error("Failed vectored writing to file: {0}")]
    WriteVectored(#[source] std::io::Error),
    /// Failed synchronizing file.
    #[error("Failed synchronizing file: {0}")]
    Fsync(#[source] std::io::Error),
}

pub type AsyncIoResult<T> = std::result::Result<T, AsyncIoError>;

pub trait AsyncIo: Send + Sync {
    fn notifier(&self) -> &EventFd;
    fn read_vectored(
        &mut self,
        offset: libc::off_t,
        iovecs: Vec<libc::iovec>,
        user_data: u64,
    ) -> AsyncIoResult<()>;
    fn write_vectored(
        &mut self,
        offset: libc::off_t,
        iovecs: Vec<libc::iovec>,
        user_data: u64,
    ) -> AsyncIoResult<()>;
    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()>;
    fn complete(&mut self) -> Vec<(u64, i32)>;
}
