// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::{File, Metadata};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::FileExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::result;

use vmm_sys_util::file_traits::FileSync;
use vmm_sys_util::seek_hole::SeekHole;
use vmm_sys_util::write_zeroes::{PunchHole, WriteZeroesAt};

use crate::aligned_buffer::AlignedBuffer;
use crate::{BlockBackend, SECTOR_SIZE, probe_direct_alignment, query_device_size};

/// True when `buf_ptr`/`len`/`offset` already satisfy `alignment`
/// (`alignment == 0` means no O_DIRECT, so everything is "aligned").
fn is_aligned(alignment: usize, buf_ptr: usize, len: usize, offset: u64) -> bool {
    alignment == 0
        || (buf_ptr.is_multiple_of(alignment)
            && len.is_multiple_of(alignment)
            && offset.is_multiple_of(alignment as u64))
}

/// A `File` that transparently satisfies O_DIRECT alignment requirements.
///
/// `alignment == 0` means no O_DIRECT (all I/O passes straight through).
/// For unaligned requests under O_DIRECT, I/O is bounced through an
/// `AlignedBuffer` (read-modify-write for writes).
#[derive(Debug)]
pub struct AlignedFile {
    file: File,
    alignment: usize,
    position: u64,
}

impl AlignedFile {
    /// Wrap `file`, querying the O_DIRECT block alignment when `direct_io`.
    pub fn new(file: File, direct_io: bool) -> Self {
        let alignment = if direct_io {
            probe_direct_alignment(file.as_raw_fd()).unwrap_or(SECTOR_SIZE) as usize
        } else {
            0
        };
        AlignedFile {
            file,
            alignment,
            position: 0,
        }
    }

    pub fn alignment(&self) -> usize {
        self.alignment
    }

    pub fn file(&self) -> &File {
        &self.file
    }

    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(AlignedFile {
            file: self.file.try_clone()?,
            alignment: self.alignment,
            position: self.position,
        })
    }

    pub fn set_len(&self, size: u64) -> io::Result<()> {
        self.file.set_len(size)
    }

    pub fn metadata(&self) -> io::Result<Metadata> {
        self.file.metadata()
    }

    pub fn sync_all(&self) -> io::Result<()> {
        self.file.sync_all()
    }

    pub fn sync_data(&self) -> io::Result<()> {
        self.file.sync_data()
    }

    pub fn is_direct(&self) -> bool {
        self.alignment != 0
    }

    pub fn is_writable(&self) -> bool {
        // SAFETY: fcntl with F_GETFL is safe and doesn't modify the file descriptor
        let flags = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return false;
        }
        let access_mode = flags & libc::O_ACCMODE;
        access_mode == libc::O_WRONLY || access_mode == libc::O_RDWR
    }

    /// Wrap `file` with an explicit alignment, bypassing the probe. Used by
    /// tests to force the bounce/RMW path without a real O_DIRECT fd.
    #[cfg(test)]
    pub fn with_alignment(file: File, alignment: usize) -> Self {
        AlignedFile {
            file,
            alignment,
            position: 0,
        }
    }
}

impl FileExt for AlignedFile {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if is_aligned(self.alignment, buf.as_ptr() as usize, buf.len(), offset) {
            return self.file.read_at(buf, offset);
        }
        let mut abuf = AlignedBuffer::new(offset, buf.len(), self.alignment)?;
        let n = abuf.read_from(&self.file)?;
        buf[..n].copy_from_slice(&abuf.as_slice()[..n]);
        Ok(n)
    }

    fn write_at(&self, buf: &[u8], offset: u64) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if is_aligned(self.alignment, buf.as_ptr() as usize, buf.len(), offset) {
            return self.file.write_at(buf, offset);
        }
        let mut abuf = AlignedBuffer::new(offset, buf.len(), self.alignment)?;
        abuf.read_from(&self.file)?; // RMW: preserve head/tail padding
        abuf.as_mut_slice().copy_from_slice(buf);
        abuf.write_to(&self.file)?;
        Ok(buf.len())
    }
}

impl Read for AlignedFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.read_at(buf, self.position)?;
        self.position += n as u64;
        Ok(n)
    }
}

impl Write for AlignedFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.write_at(buf, self.position)?;
        self.position += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.sync_all()
    }
}

impl Seek for AlignedFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let newpos = match pos {
            SeekFrom::Start(o) => o,
            SeekFrom::Current(d) => self
                .position
                .checked_add_signed(d)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid seek"))?,
            SeekFrom::End(d) => query_device_size(&self.file)?
                .0
                .checked_add_signed(d)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid seek"))?,
        };
        self.position = newpos;
        Ok(newpos)
    }
}

impl WriteZeroesAt for AlignedFile {
    fn write_zeroes_at(&mut self, offset: u64, length: usize) -> io::Result<usize> {
        self.file.write_zeroes_at(offset, length)
    }
}

impl PunchHole for AlignedFile {
    fn punch_hole(&mut self, offset: u64, length: u64) -> io::Result<()> {
        self.file.punch_hole(offset, length)
    }
}

impl FileSync for AlignedFile {
    fn fsync(&mut self) -> io::Result<()> {
        self.file.fsync()
    }
}

impl SeekHole for AlignedFile {
    fn seek_hole(&mut self, offset: u64) -> io::Result<Option<u64>> {
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

    fn seek_data(&mut self, offset: u64) -> io::Result<Option<u64>> {
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

impl BlockBackend for AlignedFile {
    fn logical_size(&self) -> result::Result<u64, crate::Error> {
        Ok(query_device_size(&self.file)
            .map_err(crate::Error::RawFileError)?
            .0)
    }

    fn physical_size(&self) -> result::Result<u64, crate::Error> {
        Ok(query_device_size(&self.file)
            .map_err(crate::Error::RawFileError)?
            .1)
    }
}

impl Clone for AlignedFile {
    fn clone(&self) -> Self {
        self.try_clone().expect("AlignedFile cloning failed")
    }
}

impl AsRawFd for AlignedFile {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl AsFd for AlignedFile {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::FileExt;

    use vmm_sys_util::tempfile::TempFile;

    use super::*;

    fn pattern_file(size: usize) -> TempFile {
        let tf = TempFile::new().unwrap();
        let p: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        tf.as_file().write_all(&p).unwrap();
        tf.as_file().sync_all().unwrap();
        tf
    }

    fn forced(file: File, alignment: usize) -> AlignedFile {
        AlignedFile {
            file,
            alignment,
            position: 0,
        }
    }

    #[test]
    fn new_probes_alignment_and_accessors() {
        let tf = pattern_file(8192);
        // Not O_DIRECT, so new() falls back to SECTOR_SIZE (512).
        let mut af = AlignedFile::new(tf.as_file().try_clone().unwrap(), true);
        assert_eq!(af.alignment(), 512);
        let _ = af.file();
        let _ = af.file_mut();
        let _ = af.try_clone().unwrap();

        let plain = AlignedFile::new(tf.as_file().try_clone().unwrap(), false);
        assert_eq!(plain.alignment(), 0);
    }

    #[test]
    fn read_unaligned_offset_matches_contents() {
        let tf = pattern_file(8192);
        let af = forced(tf.as_file().try_clone().unwrap(), 512);
        let mut buf = vec![0u8; 200];
        assert_eq!(af.read_at(&mut buf, 100).unwrap(), 200);
        let want: Vec<u8> = (100..300).map(|i| (i % 251) as u8).collect();
        assert_eq!(buf, want);
    }

    #[test]
    fn read_unaligned_short_at_eof() {
        let tf = pattern_file(100);
        let af = forced(tf.as_file().try_clone().unwrap(), 512);
        let mut buf = vec![0u8; 200];
        assert_eq!(af.read_at(&mut buf, 10).unwrap(), 90);
    }

    #[test]
    fn write_unaligned_offset_is_rmw() {
        let tf = pattern_file(8192);
        let af = forced(tf.as_file().try_clone().unwrap(), 512);
        let data: Vec<u8> = (0..200).map(|i| ((i + 1) % 239) as u8).collect();
        assert_eq!(af.write_at(&data, 100).unwrap(), 200);

        let mut whole = vec![0u8; 8192];
        tf.as_file().read_exact_at(&mut whole, 0).unwrap();
        let before: Vec<u8> = (0..100).map(|i| (i % 251) as u8).collect();
        assert_eq!(&whole[..100], &before[..]);
        assert_eq!(&whole[100..300], &data[..]);
        let after: Vec<u8> = (300..8192).map(|i| (i % 251) as u8).collect();
        assert_eq!(&whole[300..], &after[..]);
    }

    #[test]
    fn aligned_passthrough_roundtrip() {
        let tf = pattern_file(4096);
        let af = forced(tf.as_file().try_clone().unwrap(), 512);
        let mut buf = vec![0u8; 512];
        assert_eq!(af.read_at(&mut buf, 512).unwrap(), 512);
        let want: Vec<u8> = (512..1024).map(|i| (i % 251) as u8).collect();
        assert_eq!(buf, want);
    }

    #[test]
    fn no_alignment_is_plain_passthrough() {
        let tf = pattern_file(100);
        let af = forced(tf.as_file().try_clone().unwrap(), 0);
        let mut buf = vec![0u8; 50];
        assert_eq!(af.read_at(&mut buf, 10).unwrap(), 50);
    }

    #[test]
    fn test_unaligned_read_returns_short_read_at_eof() {
        let file_size = 100usize;
        let tf = pattern_file(file_size);
        let mut af = forced(tf.as_file().try_clone().unwrap(), 512);
        af.seek(SeekFrom::Start(10)).unwrap();

        let mut buf = vec![0u8; 200];
        let bytes_read = af.read(&mut buf).unwrap();

        let expected: Vec<u8> = (10..file_size).map(|i| (i % 251) as u8).collect();
        assert_eq!(bytes_read, expected.len());
        assert_eq!(&buf[..bytes_read], &expected[..]);
        assert_eq!(af.position, file_size as u64);
    }

    #[test]
    fn test_unaligned_read_beyond_eof_returns_zero() {
        let tf = pattern_file(100);
        let mut af = forced(tf.as_file().try_clone().unwrap(), 512);
        af.seek(SeekFrom::Start(200)).unwrap();

        let mut buf = vec![0u8; 16];
        let bytes_read = af.read(&mut buf).unwrap();

        assert_eq!(bytes_read, 0);
        assert_eq!(af.position, 200);
    }

    #[test]
    fn test_unaligned_write_extends_at_eof() {
        let file_size = 100usize;
        let tf = pattern_file(file_size);
        let mut af = forced(tf.as_file().try_clone().unwrap(), 512);
        af.seek(SeekFrom::Start(file_size as u64)).unwrap();

        let data = b"xyz";
        let bytes_written = af.write(data).unwrap();

        assert_eq!(bytes_written, data.len());
        assert_eq!(af.position, (file_size + data.len()) as u64);

        let mut readback = vec![0u8; file_size + data.len()];
        tf.as_file().read_exact_at(&mut readback, 0).unwrap();
        let expected_prefix: Vec<u8> = (0..file_size).map(|i| (i % 251) as u8).collect();
        assert_eq!(&readback[..file_size], &expected_prefix[..]);
        assert_eq!(&readback[file_size..], data);
    }

    #[test]
    fn test_empty_unaligned_io_is_noop() {
        let tf = pattern_file(100);
        let mut af = forced(tf.as_file().try_clone().unwrap(), 512);
        af.seek(SeekFrom::Start(1)).unwrap();

        let mut read_buf = [];
        assert_eq!(af.read(&mut read_buf).unwrap(), 0);
        assert_eq!(af.write(&[]).unwrap(), 0);
        assert_eq!(af.position, 1);
    }
}
