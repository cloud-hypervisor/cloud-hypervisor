// Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::io;

use vm_memory::GuestAddress;

/// Owns an aligned bounce buffer used when a guest descriptor's host VA
/// does not meet the disk backend's alignment requirement.
#[derive(Debug)]
pub struct AlignedOperation {
    data_addr: GuestAddress,
    aligned_ptr: *mut u8,
    size: usize,
    layout: Layout,
}

impl AlignedOperation {
    /// Allocate a zero-initialized buffer of `size` bytes aligned to
    /// `alignment`. Returns `InvalidInput` if `size` is zero;
    /// `alignment` must be a power of two and not exceed `isize::MAX`
    /// after rounding up.
    pub fn new(data_addr: GuestAddress, size: usize, alignment: usize) -> io::Result<Self> {
        if size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "AlignedOperation requires a non-zero size",
            ));
        }
        let layout = Layout::from_size_align(size, alignment)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        // SAFETY: size is non-zero (checked above) and Layout::from_size_align
        // rejects alignments that are not a power of two or that overflow.
        let aligned_ptr = unsafe { alloc_zeroed(layout) };
        if aligned_ptr.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            data_addr,
            aligned_ptr,
            size,
            layout,
        })
    }

    /// Gets the raw pointer to the aligned buffer.
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.aligned_ptr
    }

    /// Returns the aligned buffer as a slice.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: `new` allocates `size` bytes via alloc_zeroed (so they
        // are initialized) and AlignedOperation owns the buffer
        // exclusively.
        unsafe { std::slice::from_raw_parts(self.aligned_ptr, self.size) }
    }

    /// Returns the aligned buffer as a mutable slice.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: same invariant as as_bytes; &mut self rules out other
        // simultaneous borrows.
        unsafe { std::slice::from_raw_parts_mut(self.aligned_ptr, self.size) }
    }

    /// Returns the guest address for this op.
    pub fn data_addr(&self) -> GuestAddress {
        self.data_addr
    }
}

impl Drop for AlignedOperation {
    fn drop(&mut self) {
        // SAFETY: `new` is the only constructor, and it stores a pointer
        // returned by `alloc_zeroed` paired with the exact `layout` used
        // for that allocation. Ownership has not escaped (the type is
        // neither `Clone` nor `Copy`).
        unsafe {
            dealloc(self.aligned_ptr, self.layout);
        }
    }
}

// SAFETY: AlignedOperation owns its heap allocation exclusively (no Clone/
// Copy, no shared aliases) and the allocation's lifetime is tied to the
// value's. Moving an AlignedOperation between threads transfers that
// ownership — the same rationale Box<T> uses for its Send impl.
unsafe impl Send for AlignedOperation {}
