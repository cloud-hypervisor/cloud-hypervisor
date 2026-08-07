// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Shared helpers for block unit tests.

use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;

use vmm_sys_util::tempfile::TempFile;

use crate::aligned_buffer::AlignedBuffer;

/// Returns whether the filesystem supports O_DIRECT reads.
pub(crate) fn direct_io_supported() -> bool {
    let Ok(tmp) = TempFile::new() else {
        return false;
    };
    if tmp.as_file().set_len(1 << 20).is_err() {
        return false;
    }
    let Ok(file) = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECT)
        .open(tmp.as_path())
    else {
        return false;
    };
    let Ok(mut buf) = AlignedBuffer::new(0, 4096, 4096) else {
        return false;
    };
    buf.read_from(&file).is_ok()
}

/// Skips the current test when the filesystem does not support O_DIRECT.
macro_rules! require_direct_io {
    () => {
        if !$crate::test_util::direct_io_supported() {
            eprintln!("skipping: O_DIRECT not supported on this filesystem");
            return;
        }
    };
}

pub(crate) use require_direct_io;
