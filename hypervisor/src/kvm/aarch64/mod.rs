// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2020, Microsoft  Corporation
//

///
/// Export generically-named wrappers of kvm-bindings for Unix-based platforms
///
use crate::kvm::{KvmError, KvmResult};
pub use kvm_bindings::kvm_vcpu_init as VcpuInit;
use serde_derive::{Deserialize, Serialize};
pub use {kvm_ioctls::Cap, kvm_ioctls::Kvm};

pub fn check_required_kvm_extensions(kvm: &Kvm) -> KvmResult<()> {
    if !kvm.check_extension(Cap::SignalMsi) {
        return Err(KvmError::CapabilityMissing(Cap::SignalMsi));
    }
    Ok(())
}

#[derive(Clone, Serialize, Deserialize)]
pub struct VcpuKvmState {}
