// Copyright © 2021 Intel Corporation
//
// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

//! Thread safe backing file readers for QCOW2 images.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};

use crate::qcow::metadata::BackingRead;
use crate::qcow_common::pread_exact;

/// Raw backing file using pread64 on a duplicated fd.
pub struct RawBacking {
    pub fd: OwnedFd,
    pub virtual_size: u64,
}

// SAFETY: The only I/O operation is pread64 which is position independent
// and safe for concurrent use from multiple threads.
unsafe impl Sync for RawBacking {}

impl BackingRead for RawBacking {
    fn read_at(&self, address: u64, buf: &mut [u8]) -> io::Result<()> {
        if address >= self.virtual_size {
            buf.fill(0);
            return Ok(());
        }
        let available = (self.virtual_size - address) as usize;
        if available >= buf.len() {
            pread_exact(self.fd.as_raw_fd(), buf, address)
        } else {
            pread_exact(self.fd.as_raw_fd(), &mut buf[..available], address)?;
            buf[available..].fill(0);
            Ok(())
        }
    }
}
