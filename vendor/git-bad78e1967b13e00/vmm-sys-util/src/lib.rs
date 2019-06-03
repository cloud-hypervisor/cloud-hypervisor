// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate libc;

mod tempdir;

#[macro_use]
pub mod ioctl;

pub mod errno;
pub mod eventfd;
pub mod file_traits;
pub mod seek_hole;
pub mod signal;
pub mod terminal;
pub mod timerfd;
pub mod write_zeroes;

#[macro_use]
pub mod syslog;

pub mod poll;

pub use crate::tempdir::*;
pub use errno::*;
pub use eventfd::*;
pub use poll::*;

use std::os::unix::io::AsRawFd;

pub use crate::file_traits::{FileSetLen, FileSync};
pub use crate::seek_hole::SeekHole;
pub use crate::write_zeroes::{PunchHole, WriteZeroes};

pub enum FallocateMode {
    PunchHole,
    ZeroRange,
}

/// Safe wrapper for `fallocate()`.
pub fn fallocate(
    file: &dyn AsRawFd,
    mode: FallocateMode,
    keep_size: bool,
    offset: u64,
    len: u64,
) -> Result<()> {
    let offset = if offset > libc::off64_t::max_value() as u64 {
        return Err(Error::new(libc::EINVAL));
    } else {
        offset as libc::off64_t
    };

    let len = if len > libc::off64_t::max_value() as u64 {
        return Err(Error::new(libc::EINVAL));
    } else {
        len as libc::off64_t
    };

    let mut mode = match mode {
        FallocateMode::PunchHole => libc::FALLOC_FL_PUNCH_HOLE,
        FallocateMode::ZeroRange => libc::FALLOC_FL_ZERO_RANGE,
    };

    if keep_size {
        mode |= libc::FALLOC_FL_KEEP_SIZE;
    }

    // Safe since we pass in a valid fd and fallocate mode, validate offset and len,
    // and check the return value.
    let ret = unsafe { libc::fallocate64(file.as_raw_fd(), mode, offset, len) };
    if ret < 0 {
        errno_result()
    } else {
        Ok(())
    }
}
