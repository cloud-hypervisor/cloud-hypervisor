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
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::FileExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::result;

use vmm_sys_util::file_traits::FileSync;
use vmm_sys_util::seek_hole::SeekHole;
use vmm_sys_util::write_zeroes::{PunchHole, WriteZeroesAt};

use crate::aligned_file::AlignedFile;
use crate::{BlockBackend, query_device_size};

#[derive(Debug)]
pub struct RawFile {
    aligned: AlignedFile,
    position: u64,
    direct_io: bool,
}

impl RawFile {
    pub fn new(file: File, direct_io: bool) -> Self {
        RawFile {
            aligned: AlignedFile::new(file, direct_io),
            position: 0,
            direct_io,
        }
    }

    pub fn set_len(&self, size: u64) -> io::Result<()> {
        self.aligned.file().set_len(size)
    }

    pub fn metadata(&self) -> io::Result<Metadata> {
        self.aligned.file().metadata()
    }

    pub fn try_clone(&self) -> io::Result<RawFile> {
        Ok(RawFile {
            aligned: self.aligned.try_clone()?,
            position: self.position,
            direct_io: self.direct_io,
        })
    }

    pub fn sync_all(&self) -> io::Result<()> {
        self.aligned.file().sync_all()
    }

    pub fn sync_data(&self) -> io::Result<()> {
        self.aligned.file().sync_data()
    }

    pub fn is_direct(&self) -> bool {
        self.direct_io
    }

    pub fn alignment(&self) -> usize {
        self.aligned.alignment()
    }

    /// Returns true if the file was opened with write access.
    pub fn is_writable(&self) -> bool {
        // SAFETY: fcntl with F_GETFL is safe and doesn't modify the file descriptor
        let flags = unsafe { libc::fcntl(self.aligned.file().as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return false;
        }
        let access_mode = flags & libc::O_ACCMODE;
        access_mode == libc::O_WRONLY || access_mode == libc::O_RDWR
    }
}

impl Read for RawFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.aligned.read_at(buf, self.position)?;
        self.position += n as u64;
        Ok(n)
    }
}

impl Write for RawFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.aligned.write_at(buf, self.position)?;
        self.position += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.aligned.file().sync_all()
    }
}

impl Seek for RawFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let newpos = match pos {
            SeekFrom::Start(o) => o,
            SeekFrom::Current(d) => self
                .position
                .checked_add_signed(d)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid seek"))?,
            SeekFrom::End(d) => self
                .aligned
                .file()
                .metadata()?
                .len()
                .checked_add_signed(d)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid seek"))?,
        };
        self.position = newpos;
        Ok(newpos)
    }
}

impl WriteZeroesAt for RawFile {
    fn write_zeroes_at(&mut self, offset: u64, length: usize) -> io::Result<usize> {
        self.aligned.file_mut().write_zeroes_at(offset, length)
    }
}

impl PunchHole for RawFile {
    fn punch_hole(&mut self, offset: u64, length: u64) -> io::Result<()> {
        self.aligned.file_mut().punch_hole(offset, length)
    }
}

impl FileSync for RawFile {
    fn fsync(&mut self) -> io::Result<()> {
        self.aligned.file_mut().fsync()
    }
}

impl SeekHole for RawFile {
    fn seek_hole(&mut self, offset: u64) -> io::Result<Option<u64>> {
        match self.aligned.file_mut().seek_hole(offset) {
            Ok(pos) => {
                if let Some(p) = pos {
                    self.position = p;
                }
                Ok(pos)
            }
            Err(e) => Err(e),
        }
    }

    fn seek_data(&mut self, offset: u64) -> io::Result<Option<u64>> {
        match self.aligned.file_mut().seek_data(offset) {
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
    fn logical_size(&self) -> result::Result<u64, crate::Error> {
        Ok(query_device_size(self.aligned.file())
            .map_err(crate::Error::RawFileError)?
            .0)
    }

    fn physical_size(&self) -> result::Result<u64, crate::Error> {
        Ok(query_device_size(self.aligned.file())
            .map_err(crate::Error::RawFileError)?
            .1)
    }
}

impl Clone for RawFile {
    fn clone(&self) -> Self {
        RawFile {
            aligned: self.aligned.try_clone().expect("RawFile cloning failed"),
            position: self.position,
            direct_io: self.direct_io,
        }
    }
}

impl AsRawFd for RawFile {
    fn as_raw_fd(&self) -> RawFd {
        self.aligned.file().as_raw_fd()
    }
}

impl AsFd for RawFile {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.aligned.file().as_fd()
    }
}

impl FileExt for RawFile {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        self.aligned.read_at(buf, offset)
    }

    fn write_at(&self, buf: &[u8], offset: u64) -> io::Result<usize> {
        self.aligned.write_at(buf, offset)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::FileExt;

    use vmm_sys_util::tempfile::TempFile;

    use super::*;

    const TEST_ALIGNMENT: usize = 512;

    fn create_pattern_file(size: usize) -> TempFile {
        let tf = TempFile::new().unwrap();
        let pattern: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        tf.as_file().write_all(&pattern).unwrap();
        tf.as_file().sync_all().unwrap();
        tf
    }

    fn raw_with_alignment(file: File) -> RawFile {
        // A tempfile is not O_DIRECT, but its aligned probe read still
        // succeeds, so RawFile::new selects the smallest candidate (512).
        let raw = RawFile::new(file, true);
        assert_eq!(raw.alignment(), TEST_ALIGNMENT);
        raw
    }

    #[test]
    fn test_unaligned_read_returns_short_read_at_eof() {
        let file_size = 100usize;
        let tf = create_pattern_file(file_size);
        let mut raw = raw_with_alignment(tf.as_file().try_clone().unwrap());
        raw.seek(SeekFrom::Start(10)).unwrap();

        let mut buf = vec![0u8; 200];
        let bytes_read = raw.read(&mut buf).unwrap();

        let expected: Vec<u8> = (10..file_size).map(|i| (i % 251) as u8).collect();
        assert_eq!(bytes_read, expected.len());
        assert_eq!(&buf[..bytes_read], &expected[..]);
        assert_eq!(raw.position, file_size as u64);
    }

    #[test]
    fn test_unaligned_read_beyond_eof_returns_zero() {
        let tf = create_pattern_file(100);
        let mut raw = raw_with_alignment(tf.as_file().try_clone().unwrap());
        raw.seek(SeekFrom::Start(200)).unwrap();

        let mut buf = vec![0u8; 16];
        let bytes_read = raw.read(&mut buf).unwrap();

        assert_eq!(bytes_read, 0);
        assert_eq!(raw.position, 200);
    }

    #[test]
    fn test_unaligned_write_extends_at_eof() {
        let file_size = 100usize;
        let tf = create_pattern_file(file_size);
        let mut raw = raw_with_alignment(tf.as_file().try_clone().unwrap());
        raw.seek(SeekFrom::Start(file_size as u64)).unwrap();

        let data = b"xyz";
        let bytes_written = raw.write(data).unwrap();

        assert_eq!(bytes_written, data.len());
        assert_eq!(raw.position, (file_size + data.len()) as u64);

        let mut readback = vec![0u8; file_size + data.len()];
        tf.as_file().read_exact_at(&mut readback, 0).unwrap();
        let expected_prefix: Vec<u8> = (0..file_size).map(|i| (i % 251) as u8).collect();
        assert_eq!(&readback[..file_size], &expected_prefix[..]);
        assert_eq!(&readback[file_size..], data);
    }

    #[test]
    fn test_empty_unaligned_io_is_noop() {
        let tf = create_pattern_file(100);
        let mut raw = raw_with_alignment(tf.as_file().try_clone().unwrap());
        raw.seek(SeekFrom::Start(1)).unwrap();

        let mut read_buf = [];
        assert_eq!(raw.read(&mut read_buf).unwrap(), 0);
        assert_eq!(raw.write(&[]).unwrap(), 0);
        assert_eq!(raw.position, 1);
    }
}
