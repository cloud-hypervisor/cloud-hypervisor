// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::fs::{File, Metadata};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::io::{AsRawFd, RawFd};

use vmm_sys_util::file_traits::FileSync;
use vmm_sys_util::seek_hole::SeekHole;
use vmm_sys_util::write_zeroes::{PunchHole, WriteZeroesAt};

use crate::aligned::rmw::{pread_aligned, pwrite_aligned};
use crate::{BlockBackend, probe_direct_alignment, query_device_size};

#[derive(Debug)]
pub struct RawFile {
    file: File,
    alignment: usize,
    position: u64,
    direct_io: bool,
}

impl RawFile {
    pub fn new(file: File, direct_io: bool) -> Self {
        let alignment = probe_direct_alignment(file.as_raw_fd()).map_or(0, |a| a as usize);
        RawFile {
            file,
            alignment,
            position: 0,
            direct_io,
        }
    }

    fn is_aligned(&self, buf: &[u8]) -> bool {
        if self.alignment == 0 {
            return true;
        }

        let align64: u64 = self.alignment.try_into().unwrap();

        self.position.is_multiple_of(align64)
            && (buf.as_ptr() as usize).is_multiple_of(self.alignment)
            && buf.len().is_multiple_of(self.alignment)
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
            direct_io: self.direct_io,
        })
    }

    pub fn sync_all(&self) -> std::io::Result<()> {
        self.file.sync_all()
    }

    pub fn sync_data(&self) -> std::io::Result<()> {
        self.file.sync_data()
    }

    pub fn is_direct(&self) -> bool {
        self.direct_io
    }

    pub fn alignment(&self) -> usize {
        self.alignment
    }

    /// Returns true if the file was opened with write access.
    pub fn is_writable(&self) -> bool {
        // SAFETY: fcntl with F_GETFL is safe and doesn't modify the file descriptor
        let flags = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return false;
        }
        let access_mode = flags & libc::O_ACCMODE;
        access_mode == libc::O_WRONLY || access_mode == libc::O_RDWR
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
            pread_aligned(
                self.file.as_raw_fd(),
                buf,
                self.position,
                self.alignment as u64,
            )?;
            let n = buf.len();
            self.seek(SeekFrom::Current(n as i64)).unwrap();
            Ok(n)
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
            pwrite_aligned(
                self.file.as_raw_fd(),
                buf,
                self.position,
                self.alignment as u64,
            )?;
            let n = buf.len();
            self.seek(SeekFrom::Current(n as i64)).unwrap();
            Ok(n)
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

impl WriteZeroesAt for RawFile {
    fn write_zeroes_at(&mut self, offset: u64, length: usize) -> std::io::Result<usize> {
        self.file.write_zeroes_at(offset, length)
    }
}

impl PunchHole for RawFile {
    fn punch_hole(&mut self, offset: u64, length: u64) -> std::io::Result<()> {
        self.file.punch_hole(offset, length)
    }
}

impl FileSync for RawFile {
    fn fsync(&mut self) -> std::io::Result<()> {
        self.file.fsync()
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

impl BlockBackend for RawFile {
    fn logical_size(&self) -> std::result::Result<u64, crate::Error> {
        Ok(query_device_size(&self.file)
            .map_err(crate::Error::RawFileError)?
            .0)
    }

    fn physical_size(&self) -> std::result::Result<u64, crate::Error> {
        Ok(query_device_size(&self.file)
            .map_err(crate::Error::RawFileError)?
            .1)
    }
}

impl Clone for RawFile {
    fn clone(&self) -> Self {
        RawFile {
            file: self.file.try_clone().expect("RawFile cloning failed"),
            alignment: self.alignment,
            position: self.position,
            direct_io: self.direct_io,
        }
    }
}

impl AsRawFd for RawFile {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl AsFd for RawFile {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}
