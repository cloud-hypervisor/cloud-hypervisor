// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! A default Unix implementation of the GuestMemory trait by mmap()-ing guest's memory into
//! the current process.
//!
//! The main structs to access guest's memory are:
//! - [MmapRegion](struct.MmapRegion.html): mmap a continuous region of guest's memory into the
//! current process
//! - [GuestRegionMmap](struct.GuestRegionMmap.html): tracks a mapping of memory in the current
//! process and the corresponding base address. It relays guest memory access requests to the
//! underline [MmapRegion](struct.MmapRegion.html) object.
//! - [GuestMemoryMmap](struct.GuestMemoryMmap.html): provides methods to access a collection of
//! GuestRegionMmap objects.

use libc;
use std::io;
use std::ptr::null_mut;

use mmap::AsSlice;
use volatile_memory::{self, compute_offset, VolatileMemory, VolatileSlice};

use std::os::unix::io::AsRawFd;

/// A backend driver to access guest's physical memory by mmapping guest's memory into the current
/// process.
/// For a combination of 32-bit hypervisor and 64-bit virtual machine, only partial of guest's
/// physical memory may be mapped into current process due to limited process virtual address
/// space size.
#[derive(Debug)]
pub struct MmapRegion {
    addr: *mut u8,
    size: usize,
}

// Send and Sync aren't automatically inherited for the raw address pointer.
// Accessing that pointer is only done through the stateless interface which
// allows the object to be shared by multiple threads without a decrease in
// safety.
unsafe impl Send for MmapRegion {}
unsafe impl Sync for MmapRegion {}

impl MmapRegion {
    /// Creates an anonymous shared mapping of `size` bytes.
    ///
    /// # Arguments
    /// * `size` - Size of memory region in bytes.
    pub fn new(size: usize) -> io::Result<Self> {
        // This is safe because we are creating an anonymous mapping in a place not already used by
        // any other area in this process.
        let addr = unsafe {
            libc::mmap(
                null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        if addr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            addr: addr as *mut u8,
            size,
        })
    }

    /// Maps the `size` bytes starting at `offset` bytes of the given `fd`.
    ///
    /// # Arguments
    /// * `fd` - File descriptor to mmap from.
    /// * `size` - Size of memory region in bytes.
    /// * `offset` - Offset in bytes from the beginning of `fd` to start the mmap.
    pub fn from_fd(fd: &AsRawFd, size: usize, offset: libc::off_t) -> io::Result<Self> {
        // This is safe because we are creating a mapping in a place not already used by any other
        // area in this process.
        let addr = unsafe {
            libc::mmap(
                null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                offset,
            )
        };
        if addr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            addr: addr as *mut u8,
            size,
        })
    }

    /// Returns a pointer to the beginning of the memory region.  Should only be
    /// used for passing this region to ioctls for setting guest memory.
    pub fn as_ptr(&self) -> *mut u8 {
        self.addr
    }
}

impl AsSlice for MmapRegion {
    // Returns the region as a slice
    // used to do crap
    unsafe fn as_slice(&self) -> &[u8] {
        // This is safe because we mapped the area at addr ourselves, so this slice will not
        // overflow. However, it is possible to alias.
        std::slice::from_raw_parts(self.addr, self.size)
    }

    // safe because it's expected interior mutability
    #[allow(clippy::mut_from_ref)]
    unsafe fn as_mut_slice(&self) -> &mut [u8] {
        // This is safe because we mapped the area at addr ourselves, so this slice will not
        // overflow. However, it is possible to alias.
        std::slice::from_raw_parts_mut(self.addr, self.size)
    }
}

impl VolatileMemory for MmapRegion {
    fn len(&self) -> usize {
        self.size
    }

    fn get_slice(&self, offset: usize, count: usize) -> volatile_memory::Result<VolatileSlice> {
        let end = compute_offset(offset, count)?;
        if end > self.size {
            return Err(volatile_memory::Error::OutOfBounds { addr: end });
        }

        // Safe because we checked that offset + count was within our range and we only ever hand
        // out volatile accessors.
        Ok(unsafe { VolatileSlice::new((self.addr as usize + offset) as *mut _, count) })
    }
}

impl Drop for MmapRegion {
    fn drop(&mut self) {
        // This is safe because we mmap the area at addr ourselves, and nobody
        // else is holding a reference to it.
        unsafe {
            libc::munmap(self.addr as *mut libc::c_void, self.size);
        }
    }
}

#[cfg(test)]
mod tests {
    use mmap_unix::MmapRegion;
    use std::os::unix::io::FromRawFd;

    #[test]
    fn map_invalid_fd() {
        let fd = unsafe { std::fs::File::from_raw_fd(-1) };
        let e = MmapRegion::from_fd(&fd, 1024, 0).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::EBADF));
    }
}
