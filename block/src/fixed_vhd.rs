// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::io::{AsRawFd, RawFd};

use crate::vhd::VhdFooter;
use crate::BlockBackend;

#[derive(Debug)]
pub struct FixedVhd {
    file: File,
    size: u64,
    position: u64,
}

impl FixedVhd {
    pub fn new(mut file: File) -> std::io::Result<Self> {
        let footer = VhdFooter::new(&mut file)?;

        Ok(Self {
            file,
            size: footer.current_size(),
            position: 0,
        })
    }
}

impl AsRawFd for FixedVhd {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl Read for FixedVhd {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.file.read(buf) {
            Ok(r) => {
                self.position = self.position.checked_add(r.try_into().unwrap()).unwrap();
                Ok(r)
            }
            Err(e) => Err(e),
        }
    }
}

impl Write for FixedVhd {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.file.write(buf) {
            Ok(r) => {
                self.position = self.position.checked_add(r.try_into().unwrap()).unwrap();
                Ok(r)
            }
            Err(e) => Err(e),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.sync_all()
    }
}

impl Seek for FixedVhd {
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

impl BlockBackend for FixedVhd {
    fn size(&self) -> std::result::Result<u64, crate::Error> {
        Ok(self.size)
    }
}

impl Clone for FixedVhd {
    fn clone(&self) -> Self {
        Self {
            file: self.file.try_clone().expect("FixedVhd cloning failed"),
            size: self.size,
            position: self.position,
        }
    }
}
