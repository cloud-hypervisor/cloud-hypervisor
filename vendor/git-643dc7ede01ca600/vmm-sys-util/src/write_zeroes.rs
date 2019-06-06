// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: BSD-3-Clause

use std::cmp::min;
use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};

use crate::fallocate;
use crate::FallocateMode;

/// A trait for deallocating space in a file.
pub trait PunchHole {
    /// Replace a range of bytes with a hole.
    fn punch_hole(&mut self, offset: u64, length: u64) -> io::Result<()>;
}

impl PunchHole for File {
    fn punch_hole(&mut self, offset: u64, length: u64) -> io::Result<()> {
        fallocate(self, FallocateMode::PunchHole, true, offset, length as u64)
            .map_err(|e| io::Error::from_raw_os_error(e.errno()))
    }
}

/// A trait for writing zeroes to a stream.
pub trait WriteZeroes {
    /// Write `length` bytes of zeroes to the stream, returning how many bytes were written.
    fn write_zeroes(&mut self, length: usize) -> io::Result<usize>;
}

impl<T: PunchHole + Seek + Write> WriteZeroes for T {
    fn write_zeroes(&mut self, length: usize) -> io::Result<usize> {
        // Try to punch a hole first.
        let offset = self.seek(SeekFrom::Current(0))?;
        if let Ok(()) = self.punch_hole(offset, length as u64) {
            // Advance the seek cursor as if we had done a real write().
            self.seek(SeekFrom::Current(length as i64))?;
            return Ok(length);
        }

        // fall back to write()

        // punch_hole() failed; fall back to writing a buffer of zeroes
        // until we have written up to length.
        let buf_size = min(length, 0x10000);
        let buf = vec![0u8; buf_size];
        let mut nwritten: usize = 0;
        while nwritten < length {
            let remaining = length - nwritten;
            let write_size = min(remaining, buf_size);
            nwritten += self.write(&buf[0..write_size])?;
        }
        Ok(length)
    }
}

#[cfg(test)]
#[allow(clippy::unused_io_amount)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::io::{Read, Seek, SeekFrom};
    use std::path::PathBuf;

    use crate::TempDir;

    #[test]
    fn simple_test() {
        let tempdir = TempDir::new("/tmp/write_zeroes_test").unwrap();
        let mut path = PathBuf::from(tempdir.as_path().unwrap());
        path.push("file");
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .unwrap();
        f.set_len(16384).unwrap();

        // Write buffer of non-zero bytes to offset 1234
        let orig_data = [0x55u8; 5678];
        f.seek(SeekFrom::Start(1234)).unwrap();
        f.write(&orig_data).unwrap();

        // Read back the data plus some overlap on each side
        let mut readback = [0u8; 16384];
        f.seek(SeekFrom::Start(0)).unwrap();
        f.read(&mut readback).unwrap();
        // Bytes before the write should still be 0
        for read in readback[0..1234].iter() {
            assert_eq!(*read, 0);
        }
        // Bytes that were just written should be 0x55
        for read in readback[1234..(1234 + 5678)].iter() {
            assert_eq!(*read, 0x55);
        }
        // Bytes after the written area should still be 0
        for read in readback[(1234 + 5678)..].iter() {
            assert_eq!(*read, 0);
        }

        // Overwrite some of the data with zeroes
        f.seek(SeekFrom::Start(2345)).unwrap();
        f.write_zeroes(4321).expect("write_zeroes failed");
        // Verify seek position after write_zeroes()
        assert_eq!(f.seek(SeekFrom::Current(0)).unwrap(), 2345 + 4321);

        // Read back the data and verify that it is now zero
        f.seek(SeekFrom::Start(0)).unwrap();
        f.read(&mut readback).unwrap();
        // Bytes before the write should still be 0
        for read in readback[0..1234].iter() {
            assert_eq!(*read, 0);
        }
        // Original data should still exist before the write_zeroes region
        for read in readback[1234..2345].iter() {
            assert_eq!(*read, 0x55);
        }
        // The write_zeroes region should now be zero
        for read in readback[2345..(2345 + 4321)].iter() {
            assert_eq!(*read, 0);
        }
        // Original data should still exist after the write_zeroes region
        for read in readback[(2345 + 4321)..(1234 + 5678)].iter() {
            assert_eq!(*read, 0x55);
        }
        // The rest of the file should still be 0
        for read in readback[(1234 + 5678)..].iter() {
            assert_eq!(*read, 0);
        }
    }

    #[test]
    fn large_write_zeroes() {
        let tempdir = TempDir::new("/tmp/write_zeroes_test").unwrap();
        let mut path = PathBuf::from(tempdir.as_path().unwrap());
        path.push("file");
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .unwrap();
        f.set_len(16384).unwrap();

        // Write buffer of non-zero bytes
        let orig_data = [0x55u8; 0x20000];
        f.seek(SeekFrom::Start(0)).unwrap();
        f.write(&orig_data).unwrap();

        // Overwrite some of the data with zeroes
        f.seek(SeekFrom::Start(0)).unwrap();
        f.write_zeroes(0x10001).expect("write_zeroes failed");
        // Verify seek position after write_zeroes()
        assert_eq!(f.seek(SeekFrom::Current(0)).unwrap(), 0x10001);

        // Read back the data and verify that it is now zero
        let mut readback = [0u8; 0x20000];
        f.seek(SeekFrom::Start(0)).unwrap();
        f.read(&mut readback).unwrap();
        // The write_zeroes region should now be zero
        for read in readback[0..0x10001].iter() {
            assert_eq!(*read, 0);
        }
        // Original data should still exist after the write_zeroes region
        for read in readback[0x10001..0x20000].iter() {
            assert_eq!(*read, 0x55);
        }
    }
}
