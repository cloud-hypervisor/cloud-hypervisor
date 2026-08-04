// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};

use super::footer::{VHD_FOOTER_LEN, VhdFooter};

#[derive(Debug)]
pub(super) struct FixedVhd {
    file: File,
    size: u64,
}

impl FixedVhd {
    pub(super) fn new(mut file: File) -> io::Result<Self> {
        let footer = VhdFooter::new(&mut file)?;
        footer.validate_fixed()?;
        let size = footer.current_size();

        // A fixed VHD is the data followed by a 512 byte footer. The size
        // the footer states cannot exceed what the file can hold.
        let data_len = file.metadata()?.len().saturating_sub(VHD_FOOTER_LEN);
        if size > data_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Fixed VHD footer declares {size} bytes, more than the {data_len} bytes the file holds"
                ),
            ));
        }

        Ok(Self { file, size })
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

    pub(super) fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            file: self.file.try_clone()?,
            size: self.size,
        })
    }
}
