// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::io;
use std::mem::size_of;
use std::os::unix::io::AsRawFd;
use std::ptr::null_mut;
use std::result;

use kvm_bindings::kvm_run;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use kvm_bindings::{kvm_cpuid2, kvm_cpuid_entry2};

/// Wrappers over KVM device ioctls.
pub mod device;
/// Wrappers over KVM system ioctls.
pub mod system;
/// Wrappers over KVM VCPU ioctls.
pub mod vcpu;
/// Wrappers over KVM Virtual Machine ioctls.
pub mod vm;

/// A specialized `Result` type for KVM ioctls.
///
/// This typedef is generally used to avoid writing out io::Error directly and
/// is otherwise a direct mapping to Result.
pub type Result<T> = result::Result<T, io::Error>;

// Returns a `Vec<T>` with a size in bytes at least as large as `size_in_bytes`.
fn vec_with_size_in_bytes<T: Default>(size_in_bytes: usize) -> Vec<T> {
    let rounded_size = (size_in_bytes + size_of::<T>() - 1) / size_of::<T>();
    let mut v = Vec::with_capacity(rounded_size);
    for _ in 0..rounded_size {
        v.push(T::default())
    }
    v
}

// The kvm API has many structs that resemble the following `Foo` structure:
//
// ```
// #[repr(C)]
// struct Foo {
//    some_data: u32
//    entries: __IncompleteArrayField<__u32>,
// }
// ```
//
// In order to allocate such a structure, `size_of::<Foo>()` would be too small because it would not
// include any space for `entries`. To make the allocation large enough while still being aligned
// for `Foo`, a `Vec<Foo>` is created. Only the first element of `Vec<Foo>` would actually be used
// as a `Foo`. The remaining memory in the `Vec<Foo>` is for `entries`, which must be contiguous
// with `Foo`. This function is used to make the `Vec<Foo>` with enough space for `count` entries.
fn vec_with_array_field<T: Default, F>(count: usize) -> Vec<T> {
    let element_space = count * size_of::<F>();
    let vec_size_bytes = size_of::<T>() + element_space;
    vec_with_size_in_bytes(vec_size_bytes)
}

/// Wrapper over the `kvm_cpuid2` structure.
///
/// The structure has a zero length array at the end, hidden behind bounds check.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub struct CpuId {
    // Wrapper over `kvm_cpuid2` from which we only use the first element.
    kvm_cpuid: Vec<kvm_cpuid2>,
    // Number of `kvm_cpuid_entry2` structs at the end of kvm_cpuid2.
    allocated_len: usize,
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl Clone for CpuId {
    fn clone(&self) -> Self {
        let mut kvm_cpuid = Vec::with_capacity(self.kvm_cpuid.len());
        for _ in 0..self.kvm_cpuid.len() {
            kvm_cpuid.push(kvm_cpuid2::default());
        }

        let num_bytes = self.kvm_cpuid.len() * size_of::<kvm_cpuid2>();

        let src_byte_slice =
            unsafe { std::slice::from_raw_parts(self.kvm_cpuid.as_ptr() as *const u8, num_bytes) };

        let dst_byte_slice =
            unsafe { std::slice::from_raw_parts_mut(kvm_cpuid.as_mut_ptr() as *mut u8, num_bytes) };

        dst_byte_slice.copy_from_slice(src_byte_slice);

        CpuId {
            kvm_cpuid,
            allocated_len: self.allocated_len,
        }
    }
}

#[cfg(test)]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl PartialEq for CpuId {
    fn eq(&self, other: &CpuId) -> bool {
        let entries: &[kvm_cpuid_entry2] =
            unsafe { self.kvm_cpuid[0].entries.as_slice(self.allocated_len) };
        let other_entries: &[kvm_cpuid_entry2] =
            unsafe { self.kvm_cpuid[0].entries.as_slice(other.allocated_len) };
        self.allocated_len == other.allocated_len && entries == other_entries
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl CpuId {
    /// Creates a new `CpuId` structure that contains at most `array_len` KVM CPUID entries.
    ///
    /// # Arguments
    ///
    /// * `array_len` - Maximum number of CPUID entries.
    ///
    /// # Example
    ///
    /// ```
    /// use kvm_ioctls::CpuId;
    /// let cpu_id = CpuId::new(32);
    /// ```
    pub fn new(array_len: usize) -> CpuId {
        let mut kvm_cpuid = vec_with_array_field::<kvm_cpuid2, kvm_cpuid_entry2>(array_len);
        kvm_cpuid[0].nent = array_len as u32;

        CpuId {
            kvm_cpuid,
            allocated_len: array_len,
        }
    }

    /// Creates a new `CpuId` structure based on a supplied vector of `kvm_cpuid_entry2`.
    ///
    /// # Arguments
    ///
    /// * `entries` - The vector of `kvm_cpuid_entry2` entries.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// extern crate kvm_bindings;
    ///
    /// use kvm_bindings::kvm_cpuid_entry2;
    /// use kvm_ioctls::CpuId;
    /// // Create a Cpuid to hold one entry.
    /// let mut cpuid = CpuId::new(1);
    /// let mut entries = cpuid.mut_entries_slice().to_vec();
    /// let new_entry = kvm_cpuid_entry2 {
    ///     function: 0x4,
    ///     index: 0,
    ///     flags: 1,
    ///     eax: 0b1100000,
    ///     ebx: 0,
    ///     ecx: 0,
    ///     edx: 0,
    ///     padding: [0, 0, 0],
    /// };
    /// entries.insert(0, new_entry);
    /// cpuid = CpuId::from_entries(&entries);
    /// ```
    ///
    pub fn from_entries(entries: &[kvm_cpuid_entry2]) -> CpuId {
        let mut kvm_cpuid = vec_with_array_field::<kvm_cpuid2, kvm_cpuid_entry2>(entries.len());
        kvm_cpuid[0].nent = entries.len() as u32;

        unsafe {
            kvm_cpuid[0]
                .entries
                .as_mut_slice(entries.len())
                .copy_from_slice(entries);
        }

        CpuId {
            kvm_cpuid,
            allocated_len: entries.len(),
        }
    }

    /// Returns the mutable entries slice so they can be modified before passing to the VCPU.
    ///
    /// # Example
    /// ```rust
    /// use kvm_ioctls::{CpuId, Kvm, MAX_KVM_CPUID_ENTRIES};
    /// let kvm = Kvm::new().unwrap();
    /// let mut cpuid = kvm.get_supported_cpuid(MAX_KVM_CPUID_ENTRIES).unwrap();
    /// let cpuid_entries = cpuid.mut_entries_slice();
    /// ```
    ///
    pub fn mut_entries_slice(&mut self) -> &mut [kvm_cpuid_entry2] {
        // Mapping the unsized array to a slice is unsafe because the length isn't known.  Using
        // the length we originally allocated with eliminates the possibility of overflow.
        if self.kvm_cpuid[0].nent as usize > self.allocated_len {
            self.kvm_cpuid[0].nent = self.allocated_len as u32;
        }
        let nent = self.kvm_cpuid[0].nent as usize;
        unsafe { self.kvm_cpuid[0].entries.as_mut_slice(nent) }
    }

    /// Get a  pointer so it can be passed to the kernel. Using this pointer is unsafe.
    ///
    pub fn as_ptr(&self) -> *const kvm_cpuid2 {
        &self.kvm_cpuid[0]
    }

    /// Get a mutable pointer so it can be passed to the kernel. Using this pointer is unsafe.
    ///
    pub fn as_mut_ptr(&mut self) -> *mut kvm_cpuid2 {
        &mut self.kvm_cpuid[0]
    }
}

/// Safe wrapper over the `kvm_run` struct.
///
/// The wrapper is needed for sending the pointer to `kvm_run` between
/// threads as raw pointers do not implement `Send` and `Sync`.
pub struct KvmRunWrapper {
    kvm_run_ptr: *mut u8,
}

// Send and Sync aren't automatically inherited for the raw address pointer.
// Accessing that pointer is only done through the stateless interface which
// allows the object to be shared by multiple threads without a decrease in
// safety.
unsafe impl Send for KvmRunWrapper {}
unsafe impl Sync for KvmRunWrapper {}

impl KvmRunWrapper {
    /// Maps the first `size` bytes of the given `fd`.
    ///
    /// # Arguments
    /// * `fd` - File descriptor to mmap from.
    /// * `size` - Size of memory region in bytes.
    pub fn mmap_from_fd(fd: &AsRawFd, size: usize) -> Result<KvmRunWrapper> {
        // This is safe because we are creating a mapping in a place not already used by any other
        // area in this process.
        let addr = unsafe {
            libc::mmap(
                null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if addr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        Ok(KvmRunWrapper {
            kvm_run_ptr: addr as *mut u8,
        })
    }

    /// Returns a mutable reference to `kvm_run`.
    ///
    #[allow(clippy::mut_from_ref)]
    pub fn as_mut_ref(&self) -> &mut kvm_run {
        // Safe because we know we mapped enough memory to hold the kvm_run struct because the
        // kernel told us how large it was.
        #[allow(clippy::cast_ptr_alignment)]
        unsafe {
            &mut *(self.kvm_run_ptr as *mut kvm_run)
        }
    }
}

#[cfg(test)]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod tests {
    use super::*;

    #[test]
    fn test_cpuid_from_entries() {
        let num_entries = 4;
        let mut cpuid = CpuId::new(num_entries);

        // add entry
        let mut entries = cpuid.mut_entries_slice().to_vec();
        let new_entry = kvm_cpuid_entry2 {
            function: 0x4,
            index: 0,
            flags: 1,
            eax: 0b1100000,
            ebx: 0,
            ecx: 0,
            edx: 0,
            padding: [0, 0, 0],
        };
        entries.insert(0, new_entry);
        cpuid = CpuId::from_entries(&entries);

        // check that the cpuid contains the new entry
        assert_eq!(cpuid.allocated_len, num_entries + 1);
        assert_eq!(cpuid.kvm_cpuid[0].nent, (num_entries + 1) as u32);
        assert_eq!(cpuid.mut_entries_slice().len(), num_entries + 1);
        assert_eq!(cpuid.mut_entries_slice()[0], new_entry);
    }
}
