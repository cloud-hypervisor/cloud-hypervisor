// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::os::unix::io::AsRawFd;

use crate::aligned_buffer::AlignedBuffer;
use crate::{SECTOR_SIZE, probe_direct_alignment};

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
pub(crate) struct AlignedFile {
    file: File,
    alignment: usize,
}

impl AlignedFile {
    /// Wrap `file`, querying the O_DIRECT block alignment when `direct_io`.
    pub fn new(file: File, direct_io: bool) -> Self {
        let alignment = if direct_io {
            probe_direct_alignment(file.as_raw_fd()).unwrap_or(SECTOR_SIZE) as usize
        } else {
            0
        };
        AlignedFile { file, alignment }
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
        })
    }

    /// Wrap `file` with an explicit alignment, bypassing the probe. Used by
    /// tests to force the bounce/RMW path without a real O_DIRECT fd.
    #[cfg(test)]
    pub fn with_alignment(file: File, alignment: usize) -> Self {
        AlignedFile { file, alignment }
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

#[cfg(test)]
mod tests {
    use std::io::Write;
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
        AlignedFile { file, alignment }
    }

    #[test]
    fn new_probes_alignment_and_accessors() {
        let tf = pattern_file(8192);
        // A tempfile is not O_DIRECT, so probe_direct_alignment reports
        // None and new() falls back to SECTOR_SIZE (512).
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
}
