// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

extern crate kvm_ioctls;

use kvm_ioctls::*;

pub mod vm;

use self::vm::{Result, Vm, VmConfig};

struct Vmm {
    kvm: Kvm,
}

impl Vmm {
    fn new() -> Result<Self> {
        let kvm = Kvm::new().expect("new KVM instance creation failed");
        Ok(Vmm { kvm })
    }
}

pub fn boot_kernel(config: VmConfig) -> Result<()> {
    let vmm = Vmm::new()?;
    let mut vm = Vm::new(&vmm.kvm, config)?;

    let entry = vm.load_kernel()?;
    vm.start(entry)?;

    Ok(())
}
