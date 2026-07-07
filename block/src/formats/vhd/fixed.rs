// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};

use super::footer::VhdFooter;

#[derive(Debug)]
pub(super) struct FixedVhd {
    file: File,
    size: u64,
}

impl FixedVhd {
    pub(super) fn new(mut file: File) -> io::Result<Self> {
        let footer = VhdFooter::new(&mut file)?;

        Ok(Self {
            file,
            size: footer.current_size(),
        })
    }

    pub(crate) fn file(&self) -> &File {
        &self.file
    }
}

impl AsRawFd for FixedVhd {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl FixedVhd {
    pub(crate) fn logical_size(&self) -> Result<u64, crate::Error> {
        Ok(self.size)
    }

    /// Returns the physical size of the underlying file.
    pub(crate) fn physical_size(&self) -> Result<u64, crate::Error> {
        self.file
            .metadata()
            .map(|m| m.len())
            .map_err(crate::Error::GetFileMetadata)
    }
}

impl Clone for FixedVhd {
    fn clone(&self) -> Self {
        Self {
            file: self.file.try_clone().expect("FixedVhd cloning failed"),
            size: self.size,
        }
    }
}
