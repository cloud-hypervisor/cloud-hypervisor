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
use crate::arch::x86::SegmentRegisterOps;

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

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct StandardRegisters {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
#[derive(Deserialize, Serialize)]
pub struct SegmentRegister {
    /* segment register + descriptor */
    pub base: u64,
    pub limit: u32,
    pub selector: u16,
    pub type_: u8,   /* type, writeable etc: 4 */
    pub present: u8, /* if not present, exception generated: 1 */
    pub dpl: u8,     /* descriptor privilege level (ring): 2 */
    pub db: u8,      /* default/big (16 or 32 bit size offset): 1 */
    pub s: u8,       /* non-system segment */
    pub l: u8,       /* long (64 bit): 1 */
    pub g: u8,       /* granularity (bytes or 4096 byte pages): 1 */
    pub avl: u8,     /* available (free bit for software to use): 1 */
    pub unusable: u8,
    pub padding: u8,
}

impl SegmentRegisterOps for SegmentRegister {
    fn segment_type(&self) -> u8 {
        self.type_
    }
    fn set_segment_type(&mut self, val: u8) {
        self.type_ = val;
    }

    fn dpl(&self) -> u8 {
        self.dpl
    }

    fn set_dpl(&mut self, val: u8) {
        self.dpl = val;
    }

    fn present(&self) -> u8 {
        self.present
    }

    fn set_present(&mut self, val: u8) {
        self.present = val;
    }

    fn long(&self) -> u8 {
        self.l
    }

    fn set_long(&mut self, val: u8) {
        self.l = val;
    }

    fn avl(&self) -> u8 {
        self.avl
    }

    fn set_avl(&mut self, val: u8) {
        self.avl = val;
    }

    fn desc_type(&self) -> u8 {
        self.s
    }

    fn set_desc_type(&mut self, val: u8) {
        self.s = val;
    }

    fn granularity(&self) -> u8 {
        self.g
    }

    fn set_granularity(&mut self, val: u8) {
        self.g = val;
    }

    fn db(&self) -> u8 {
        self.db
    }

    fn set_db(&mut self, val: u8) {
        self.db = val;
    }
}