// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use crate::async_io::{
    AsyncIo, AsyncIoError, AsyncIoResult, DiskFile, DiskFileError, DiskFileResult,
};
use qcow::RawFile;
use std::fs::File;
use std::io::{IoSlice, IoSliceMut, Read, Seek, SeekFrom, Write};
use std::sync::{Arc, Mutex};
use vmm_sys_util::eventfd::EventFd;

pub struct RawFileDiskSync {
    raw_file: RawFile,
    semaphore: Arc<Mutex<()>>,
}

impl RawFileDiskSync {
    pub fn new(file: File, direct_io: bool) -> Self {
        RawFileDiskSync {
            raw_file: RawFile::new(file, direct_io),
            semaphore: Arc::new(Mutex::new(())),
        }
    }
}

impl DiskFile for RawFileDiskSync {
    fn size(&mut self) -> DiskFileResult<u64> {
        // Take the semaphore to ensure other threads are not interacting with
        // the underlying file.
        let _lock = self.semaphore.lock().unwrap();

        Ok(self
            .raw_file
            .seek(SeekFrom::End(0))
            .map_err(DiskFileError::Size)? as u64)
    }

    fn new_async_io(&self, _ring_depth: u32) -> DiskFileResult<Box<dyn AsyncIo>> {
        Ok(Box::new(RawFileSync::new(
            self.raw_file.clone(),
            self.semaphore.clone(),
        )) as Box<dyn AsyncIo>)
    }
}

pub struct RawFileSync {
    raw_file: RawFile,
    eventfd: EventFd,
    completion_list: Vec<(u64, i32)>,
    semaphore: Arc<Mutex<()>>,
}

impl RawFileSync {
    pub fn new(raw_file: RawFile, semaphore: Arc<Mutex<()>>) -> Self {
        RawFileSync {
            raw_file,
            eventfd: EventFd::new(libc::EFD_NONBLOCK).expect("Failed creating EventFd for RawFile"),
            completion_list: Vec::new(),
            semaphore,
        }
    }
}

impl AsyncIo for RawFileSync {
    fn notifier(&self) -> &EventFd {
        &self.eventfd
    }

    fn read_vectored(
        &mut self,
        offset: libc::off_t,
        iovecs: Vec<libc::iovec>,
        user_data: u64,
    ) -> AsyncIoResult<()> {
        // Convert libc::iovec into IoSliceMut
        let mut slices = Vec::new();
        for iovec in iovecs.iter() {
            slices.push(IoSliceMut::new(unsafe { std::mem::transmute(*iovec) }));
        }

        let result = {
            // Take the semaphore to ensure other threads are not interacting
            // with the underlying file.
            let _lock = self.semaphore.lock().unwrap();

            // Move the cursor to the right offset
            self.raw_file
                .seek(SeekFrom::Start(offset as u64))
                .map_err(AsyncIoError::ReadVectored)?;

            // Read vectored
            self.raw_file
                .read_vectored(slices.as_mut_slice())
                .map_err(AsyncIoError::ReadVectored)?
        };

        self.completion_list.push((user_data, result as i32));
        self.eventfd.write(1).unwrap();

        Ok(())
    }

    fn write_vectored(
        &mut self,
        offset: libc::off_t,
        iovecs: Vec<libc::iovec>,
        user_data: u64,
    ) -> AsyncIoResult<()> {
        // Convert libc::iovec into IoSlice
        let mut slices = Vec::new();
        for iovec in iovecs.iter() {
            slices.push(IoSlice::new(unsafe { std::mem::transmute(*iovec) }));
        }

        let result = {
            // Take the semaphore to ensure other threads are not interacting
            // with the underlying file.
            let _lock = self.semaphore.lock().unwrap();

            // Move the cursor to the right offset
            self.raw_file
                .seek(SeekFrom::Start(offset as u64))
                .map_err(AsyncIoError::WriteVectored)?;

            // Write vectored
            self.raw_file
                .write_vectored(slices.as_slice())
                .map_err(AsyncIoError::WriteVectored)?
        };

        self.completion_list.push((user_data, result as i32));
        self.eventfd.write(1).unwrap();

        Ok(())
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        let result: i32 = {
            // Take the semaphore to ensure other threads are not interacting
            // with the underlying file.
            let _lock = self.semaphore.lock().unwrap();

            // Flush
            self.raw_file.flush().map_err(AsyncIoError::Fsync)?;

            0
        };

        if let Some(user_data) = user_data {
            self.completion_list.push((user_data, result));
            self.eventfd.write(1).unwrap();
        }

        Ok(())
    }

    fn complete(&mut self) -> Vec<(u64, i32)> {
        self.completion_list.drain(..).collect()
    }
}
