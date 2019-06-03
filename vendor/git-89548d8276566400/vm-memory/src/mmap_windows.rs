// Copyright (C) 2019 CrowdStrike, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//

//! A default Windows implementation of the GuestMemory trait using VirtualAlloc() and MapViewOfFile().
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

use libc::{c_void, size_t};
use std;
use std::os::windows::io::{AsRawHandle, RawHandle};
use std::ptr::null;

#[allow(non_snake_case)]
#[link(name = "kernel32")]
extern "stdcall" {
    pub fn VirtualAlloc(
        lpAddress: *mut c_void,
        dwSize: size_t,
        flAllocationType: u32,
        flProtect: u32,
    ) -> *mut c_void;

    pub fn VirtualFree(lpAddress: *mut c_void, dwSize: size_t, dwFreeType: u32) -> u32;

    pub fn CreateFileMappingA(
        hFile: RawHandle,                       // HANDLE
        lpFileMappingAttributes: *const c_void, // LPSECURITY_ATTRIBUTES
        flProtect: u32,                         // DWORD
        dwMaximumSizeHigh: u32,                 // DWORD
        dwMaximumSizeLow: u32,                  // DWORD
        lpName: *const u8,                      // LPCSTR
    ) -> RawHandle; // HANDLE

    pub fn MapViewOfFile(
        hFileMappingObject: RawHandle,
        dwDesiredAccess: u32,
        dwFileOffsetHigh: u32,
        dwFileOffsetLow: u32,
        dwNumberOfBytesToMap: size_t,
    ) -> *mut c_void;

    pub fn CloseHandle(hObject: RawHandle) -> u32; // BOOL
}

const MM_HIGHEST_VAD_ADDRESS: u64 = 0x000007FFFFFDFFFF;

const MEM_COMMIT: u32 = 0x00001000;
const MEM_RELEASE: u32 = 0x00008000;
const FILE_MAP_ALL_ACCESS: u32 = 0xf001f;
const PAGE_READWRITE: u32 = 0x04;

pub const MAP_FAILED: *mut c_void = 0 as *mut c_void;
pub const INVALID_HANDLE_VALUE: RawHandle = (-1isize) as RawHandle;
#[allow(dead_code)]
pub const ERROR_INVALID_PARAMETER: i32 = 87;

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
        if (size == 0) || (size > MM_HIGHEST_VAD_ADDRESS as usize) {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        // This is safe because we are creating an anonymous mapping in a place not already used by
        // any other area in this process.
        let addr = unsafe { VirtualAlloc(0 as *mut c_void, size, MEM_COMMIT, PAGE_READWRITE) };
        if addr == MAP_FAILED {
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
    /// * `file` - Raw handle to a file to map into the address space.
    /// * `size` - Size of memory region in bytes.
    /// * `offset` - Offset in bytes from the beginning of `file` to start the mapping.
    pub fn from_fd(file: &AsRawHandle, size: usize, offset: libc::off_t) -> io::Result<Self> {
        let handle = file.as_raw_handle();
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }

        let mapping = unsafe {
            CreateFileMappingA(
                handle,
                null(),
                PAGE_READWRITE,
                (size >> 32) as u32,
                size as u32,
                null(),
            )
        };
        if mapping == 0 as RawHandle {
            return Err(io::Error::last_os_error());
        }

        // This is safe because we are creating a mapping in a place not already used by any other
        // area in this process.
        let addr = unsafe {
            MapViewOfFile(
                mapping,
                FILE_MAP_ALL_ACCESS,
                (offset as u64 >> 32) as u32,
                offset as u32,
                size,
            )
        };

        unsafe {
            CloseHandle(mapping);
        }

        if addr == null_mut() {
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
            VirtualFree(self.addr as *mut libc::c_void, self.size, MEM_RELEASE);
        }
    }
}

#[cfg(test)]
mod tests {
    use mmap_windows::{MmapRegion, INVALID_HANDLE_VALUE};
    use std::os::windows::io::FromRawHandle;

    #[test]
    fn map_invalid_handle() {
        let fd = unsafe { std::fs::File::from_raw_handle(INVALID_HANDLE_VALUE) };
        let e = MmapRegion::from_fd(&fd, 1024, 0).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::EBADF));
    }
}
