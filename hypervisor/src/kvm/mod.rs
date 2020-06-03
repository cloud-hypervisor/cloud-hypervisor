// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2020, Microsoft  Corporation
//
// Copyright 2018-2019 CrowdStrike, Inc.
//
//

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "x86_64")]
pub use x86_64::{CpuId, ExtendedControlRegisters, LapicState, MsrEntries, Xsave};

///
/// Export generically-named wrappers of kvm-bindings for Unix-based platforms
///
pub use {
    kvm_bindings::kvm_fpu as FpuState, kvm_bindings::kvm_mp_state as MpState,
    kvm_bindings::kvm_regs as StandardRegisters, kvm_bindings::kvm_sregs as SpecialRegisters,
    kvm_bindings::kvm_vcpu_events as VcpuEvents, kvm_ioctls::VcpuExit,
};
