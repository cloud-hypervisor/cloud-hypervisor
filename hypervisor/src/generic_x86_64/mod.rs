// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2020, Microsoft Corporation
//
// Copyright 2018-2019 CrowdStrike, Inc.
//
//

use crate::arch::x86::{SegmentRegisterOps, msr_index, MTRR_ENABLE, MTRR_MEM_TYPE_WB};
use crate::{msr, msr_data};
use serde::{Deserialize, Serialize, Serializer, Deserializer};
use vmm_sys_util::{fam::FamStruct, fam::FamStructWrapper, generate_fam_struct_impl};
use crate::kvm;
#[cfg(feature = "mshv")]
use crate::mshv;

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
#[derive(Debug, Default, Copy, Clone, PartialEq, Deserialize, Serialize)]
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
#[derive(Debug, Default, Deserialize, Serialize)]
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
#[derive(Debug, Default, Copy, Clone, PartialEq, Deserialize, Serialize)]
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
#[derive(Debug, Default, Copy, Clone, Deserialize, Serialize)]
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

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct TableRegister {
    pub base: u64,
    pub limit: u16,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Deserialize, Serialize)]
pub struct SpecialRegisters {
    pub cs: SegmentRegister,
    pub ds: SegmentRegister,
    pub es: SegmentRegister,
    pub fs: SegmentRegister,
    pub gs: SegmentRegister,
    pub ss: SegmentRegister,
    pub tr: SegmentRegister,
    pub ldt: SegmentRegister,
    pub gdt: TableRegister,
    pub idt: TableRegister,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub efer: u64,
    pub apic_base: u64,
    pub interrupt_bitmap: [u64; 4usize],
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Deserialize, Serialize)]
pub struct FpuState {
    pub fpr: [[u8; 16usize]; 8usize],
    pub fcw: u16,
    pub fsw: u16,
    pub ftwx: u8,
    pub pad1: u8,
    pub last_opcode: u16,
    pub last_ip: u64,
    pub last_dp: u64,
    pub xmm: [[u8; 16usize]; 16usize],
    pub mxcsr: u32,
    pub pad2: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct LapicState {
    pub regs: [::std::os::raw::c_char; 1024usize],
}

impl Default for LapicState {
    fn default() -> Self {
        let mut s = ::std::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::std::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}

impl<'de> Deserialize<'de> for LapicState {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let regs: Vec<::std::os::raw::c_char> = Vec::deserialize(deserializer)?;
        let mut val = LapicState::default();
        // This panics if the source and destination have different lengths.
        val.regs.copy_from_slice(&regs[..]);
        Ok(val)
    }
}

impl Serialize for LapicState {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let regs = &self.regs[..];
        regs.serialize(serializer)
    }
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct MsrEntry {
    pub index: u32,
    pub reserved: u32,
    pub data: u64,
}

#[repr(C)]
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct HypervisorMsrs {
    pub nmsrs: u32,
    pub padding: u32,
    #[serde(skip)]
    pub entries: __IncompleteArrayField<MsrEntry>,
}

pub const HYPERVISOR_MAX_MSR_ENTRIES: usize = 256;
generate_fam_struct_impl!(HypervisorMsrs, MsrEntry, entries, u32, nmsrs, HYPERVISOR_MAX_MSR_ENTRIES);
pub type MsrEntries = FamStructWrapper<HypervisorMsrs>;

#[repr(C)]
#[derive(Debug, Default)]
pub struct HypervisorMsrList {
    pub nmsrs: u32,
    pub indices: __IncompleteArrayField<u32>,
}

generate_fam_struct_impl!(HypervisorMsrList, u32, indices, u32, nmsrs, HYPERVISOR_MAX_MSR_ENTRIES);
pub type MsrList = FamStructWrapper<HypervisorMsrList>;

pub fn boot_msr_entries() -> MsrEntries {
    match crate::get_hypervisor_type() {
        crate::HypervisorType::Kvm => {
            MsrEntries::from_entries(&[
                msr!(msr_index::MSR_IA32_SYSENTER_CS),
                msr!(msr_index::MSR_IA32_SYSENTER_ESP),
                msr!(msr_index::MSR_IA32_SYSENTER_EIP),
                msr!(msr_index::MSR_STAR),
                msr!(msr_index::MSR_CSTAR),
                msr!(msr_index::MSR_LSTAR),
                msr!(msr_index::MSR_KERNEL_GS_BASE),
                msr!(msr_index::MSR_SYSCALL_MASK),
                msr!(msr_index::MSR_IA32_TSC),
                msr_data!(
                    msr_index::MSR_IA32_MISC_ENABLE,
                    msr_index::MSR_IA32_MISC_ENABLE_FAST_STRING as u64
                ),
                msr_data!(msr_index::MSR_MTRRdefType, MTRR_ENABLE | MTRR_MEM_TYPE_WB),
            ])
            .unwrap()
        },

        crate::HypervisorType::Mshv => {
            MsrEntries::from_entries(&[
                msr!(msr_index::MSR_IA32_SYSENTER_CS),
                msr!(msr_index::MSR_IA32_SYSENTER_ESP),
                msr!(msr_index::MSR_IA32_SYSENTER_EIP),
                msr!(msr_index::MSR_STAR),
                msr!(msr_index::MSR_CSTAR),
                msr!(msr_index::MSR_LSTAR),
                msr!(msr_index::MSR_KERNEL_GS_BASE),
                msr!(msr_index::MSR_SYSCALL_MASK),
                msr!(msr_index::MSR_IA32_TSC),
                msr_data!(msr_index::MSR_MTRRdefType, MTRR_ENABLE | MTRR_MEM_TYPE_WB),
            ])
            .unwrap()
        }
    }
    
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum _Xsave{
    Kvm(kvm_bindings::kvm_xsave),
    Mshv(mshv_bindings::XSave),
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct Xsave {
    xsave: _Xsave,
}

impl Xsave {
    pub fn xsave(&self) -> _Xsave {
        self.xsave.clone()
    }

    pub fn set_xsave(&mut self, new_xsave: _Xsave) -> () {
        self.xsave = new_xsave;
    }
    /// Need to implement these functions instead of From trait, because xsave is a private field, 
    /// and cannot be accessed outside here
    pub fn from_kvm(new_xsave: kvm_bindings::kvm_xsave) -> Self {
        Xsave{
            xsave: _Xsave::Kvm(new_xsave),
        }
    }

    pub fn from_mshv(new_xsave: mshv_bindings::XSave) -> Self {
        Xsave{
            xsave: _Xsave::Mshv(new_xsave),
        }
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum _VcpuEvents {
    Kvm(kvm_bindings::kvm_vcpu_events),
    Mshv(mshv_bindings::VcpuEvents),
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct VcpuEvents {
    events: _VcpuEvents,
}

impl VcpuEvents {
    pub fn events(&self) -> _VcpuEvents {
        self.events
    }

    pub fn set_vcpu_events(&mut self, new_events: _VcpuEvents) -> () {
        self.events = new_events;
    }

    pub fn from_kvm(new_events: kvm_bindings::kvm_vcpu_events) -> Self {
        VcpuEvents{
            events: _VcpuEvents::Kvm(new_events),
        }
    }

    pub fn from_mshv(new_events: mshv_bindings::VcpuEvents) -> Self {
        VcpuEvents{
            events: _VcpuEvents::Mshv(new_events),
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct MpState {
    pub mp_state: u32,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct SuspendRegisters {
    pub explicit_register: u64,
    pub intercept_register: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum _CpuState {
    Kvm(kvm::x86_64::VcpuKvmState),
    #[cfg(feature = "mshv")]
    Mshv(mshv::x86_64::VcpuMshvState,)
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CpuState {
    state: _CpuState,
}

impl CpuState {
    pub fn state(&self) -> _CpuState {
        self.state.clone()
    }

    pub fn set_state(&mut self, new_state: _CpuState) -> () {
        self.state = new_state;
    }

    pub fn from_kvm(new_state: kvm::x86_64::VcpuKvmState) -> Self {
        CpuState{
            state: _CpuState::Kvm(new_state),
        }
    }
    #[cfg(feature = "mshv")]
    pub fn from_mshv(new_state: mshv::x86_64::VcpuMshvState) -> Self {
        CpuState{
            state: _CpuState::Mshv(new_state),
        }
    }
}