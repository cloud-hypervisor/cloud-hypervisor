// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2020, Microsoft Corporation
//
// Copyright 2018-2019 CrowdStrike, Inc.
//
//

use vmm_sys_util::{generate_fam_struct_impl, fam::FamStruct, fam::FamStructWrapper};
use serde::{Deserialize, Serialize};

#[repr(C)]
#[derive(Default)]
pub struct __IncompleteArrayField<T>(::std::marker::PhantomData<T>, [T; 0]);
impl<T> __IncompleteArrayField<T> {
    #[inline]
    pub fn new() -> Self {
        __IncompleteArrayField(::std::marker::PhantomData, [])
    }

    #[inline]
    /// # Safety
    /// Safe Beacuse we know the size of the field.
    /// Caller needs to make sure lossless conversion
    pub unsafe fn as_ptr(&self) -> *const T {
        ::std::mem::transmute(self)
    }
    #[inline]
    /// # Safety
    /// Safe Beacuse we know the size of the field.
    /// Caller needs to make sure lossless conversion
    pub unsafe fn as_mut_ptr(&mut self) -> *mut T {
        ::std::mem::transmute(self)
    }
    #[inline]
    /// # Safety
    /// Safe Beacuse we know the size of the field.
    /// Caller needs to make sure lossless conversion
    pub unsafe fn as_slice(&self, len: usize) -> &[T] {
        ::std::slice::from_raw_parts(self.as_ptr(), len)
    }
    #[inline]
    /// # Safety
    /// Safe Beacuse we know the size of the field.
    /// Caller needs to make sure lossless conversion
    pub unsafe fn as_mut_slice(&mut self, len: usize) -> &mut [T] {
        ::std::slice::from_raw_parts_mut(self.as_mut_ptr(), len)
    }
}
impl<T> ::std::fmt::Debug for __IncompleteArrayField<T> {
    fn fmt(&self, fmt: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        fmt.write_str("__IncompleteArrayField")
    }
}
impl<T> ::std::clone::Clone for __IncompleteArrayField<T> {
    #[inline]
    fn clone(&self) -> Self {
        Self::new()
    }
}


#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct CpuIdEntry {
    pub function: u32,
    pub index: u32,
    pub flags: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub padding: [u32; 3usize],
}

#[repr(C)]
#[derive(Debug, Default)]
#[derive(Deserialize, Serialize)]
pub struct HypervisorCpuId {
    pub nent: u32,
    pub padding: u32,
    #[serde(skip)]
    pub entries: __IncompleteArrayField<CpuIdEntry>,
}

pub const CPUID_FLAG_VALID_INDEX: u32 = 0x1;
pub const HYPERVISOR_MAX_CPUID_ENTRIES: usize = 80;
pub type CpuId = FamStructWrapper<HypervisorCpuId>;


generate_fam_struct_impl!(
    HypervisorCpuId,
    CpuIdEntry,
    entries,
    u32,
    nent,
    HYPERVISOR_MAX_CPUID_ENTRIES
);