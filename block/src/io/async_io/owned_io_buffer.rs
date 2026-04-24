// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::{fmt, io};

// Storage owned by an async I/O request for host-memory buffers.
//
// `Vec` is used when ordinary vector storage is sufficient. `Aligned` is used
// when the backend requires an alignment that a normal `Vec` cannot
// guarantee.
enum OwnedIoBufferStorage {
    // Buffer backed by a standard `Vec<u8>`.
    Vec(Vec<u8>),
    // Buffer backed by an explicitly aligned allocation.
    Aligned {
        // Pointer returned by `alloc_zeroed` for `layout`.
        ptr: *mut u8,
        // Layout used to allocate and deallocate `ptr`.
        layout: Layout,
        // Logical buffer length exposed to I/O.
        len: usize,
    },
}

// SAFETY: OwnedIoBufferStorage owns its allocation exclusively. Moving it to
// another thread transfers that ownership.
unsafe impl Send for OwnedIoBufferStorage {}

impl OwnedIoBufferStorage {
    fn new(len: usize, alignment: usize) -> io::Result<Self> {
        if alignment <= 1 {
            return Ok(Self::Vec(vec![0; len]));
        }

        let alloc_len = len.max(1).next_multiple_of(alignment);
        let layout = Layout::from_size_align(alloc_len, alignment)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        // SAFETY: layout has non-zero size because alloc_len is at least 1.
        let ptr = unsafe { alloc_zeroed(layout) };
        if ptr.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "alloc_zeroed returned null",
            ));
        }

        Ok(Self::Aligned { ptr, layout, len })
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        match self {
            Self::Vec(buf) => buf.as_mut_ptr(),
            Self::Aligned { ptr, .. } => *ptr,
        }
    }

    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Vec(buf) => buf.as_slice(),
            Self::Aligned { ptr, len, .. } => {
                // SAFETY: alloc_zeroed initialized `len` bytes at `ptr` and the
                // allocation is owned by Self.
                unsafe { std::slice::from_raw_parts(*ptr, *len) }
            }
        }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        match self {
            Self::Vec(buf) => buf.as_mut_slice(),
            Self::Aligned { ptr, len, .. } => {
                // SAFETY: alloc_zeroed initialized `len` bytes at `ptr`,
                // &mut self ensures unique access, and the allocation is
                // owned by Self.
                unsafe { std::slice::from_raw_parts_mut(*ptr, *len) }
            }
        }
    }
}

impl Drop for OwnedIoBufferStorage {
    fn drop(&mut self) {
        if let Self::Aligned { ptr, layout, .. } = self {
            // SAFETY: ptr was allocated by alloc_zeroed with this layout and is
            // solely owned by Self.
            unsafe { dealloc(*ptr, *layout) };
        }
    }
}

impl fmt::Debug for OwnedIoBufferStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vec(buf) => f.debug_tuple("Vec").field(&buf.len()).finish(),
            Self::Aligned { len, layout, .. } => f
                .debug_struct("Aligned")
                .field("len", len)
                .field("layout", layout)
                .finish(),
        }
    }
}

/// Owns host-memory buffer storage and the iovec array that points into it.
///
/// The retained iovec is valid for as long as this value is alive.
/// When used for Async I/O this struct must remain valid for the duration of the op.
#[derive(Debug)]
pub struct OwnedIoBuffer {
    storage: OwnedIoBufferStorage,
    iovecs: Vec<libc::iovec>,
}

// SAFETY: OwnedIoBuffer owns the storage referenced by its single iovec, and moving the buffer
// keeps the allocation address stable.
unsafe impl Send for OwnedIoBuffer {}

impl OwnedIoBuffer {
    /// Creates a zeroed buffer with the requested logical length and alignment.
    ///
    /// An alignment of 0 or 1 uses ordinary `Vec` storage. Larger alignments use an explicitly
    /// aligned allocation whose allocated size may be rounded up while the exposed slice length
    /// remains `len`.
    pub fn new(len: usize, alignment: usize) -> io::Result<Self> {
        let mut storage = OwnedIoBufferStorage::new(len, alignment)?;
        let iovec = libc::iovec {
            iov_base: storage.as_mut_ptr().cast(),
            iov_len: len,
        };
        Ok(Self {
            storage,
            iovecs: vec![iovec],
        })
    }

    /// Creates an owned I/O buffer from an existing `Vec<u8>`.
    ///
    /// The generated iovec covers the full vector length and remains valid
    /// until the OwnedIoBuffer is dropped.
    pub fn from_vec(mut buf: Vec<u8>) -> Self {
        let iovec = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        Self {
            storage: OwnedIoBufferStorage::Vec(buf),
            iovecs: vec![iovec],
        }
    }

    /// Returns the logical buffer contents.
    pub fn as_slice(&self) -> &[u8] {
        self.storage.as_slice()
    }

    /// Returns the logical buffer contents mutably.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.storage.as_mut_slice()
    }

    /// Returns the retained iovec array for kernel submission.
    ///
    /// The iovec pointers remain valid while this buffer is alive.
    pub fn iovecs(&self) -> &[libc::iovec] {
        &self.iovecs
    }

    /// Returns the total number of bytes described by the retained iovecs.
    pub fn total_len(&self) -> usize {
        self.iovecs.iter().map(|iov| iov.iov_len).sum()
    }
}
