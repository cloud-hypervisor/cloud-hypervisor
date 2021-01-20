// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use thiserror::Error;
use vmm_sys_util::eventfd::EventFd;

#[derive(Error, Debug)]
pub enum DiskFileError {
    /// Failed getting disk file size.
    #[error("Failed getting disk file size: {0}")]
    Size(#[source] std::io::Error),
    /// Failed creating a new AsyncIo.
    #[error("Failed creating a new AsyncIo: {0}")]
    NewAsyncIo(#[source] std::io::Error),
}

pub type DiskFileResult<T> = std::result::Result<T, DiskFileError>;

pub trait DiskFile: Send + Sync {
    fn size(&mut self) -> DiskFileResult<u64>;
    fn new_async_io(&self, ring_depth: u32) -> DiskFileResult<Box<dyn AsyncIo>>;
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
