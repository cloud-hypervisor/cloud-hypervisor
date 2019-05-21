// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

extern crate kvm_ioctls;
#[macro_use]
extern crate log;

use kvm_ioctls::*;
use std::fmt::{self, Display};
use std::result;

pub mod vm;

use self::vm::{Vm, VmConfig};

/// Errors associated with VM management
#[derive(Debug)]
pub enum Error {
    /// Cannot create a new VM.
    VmNew(vm::Error),

    /// Cannot start a VM.
    VmStart(vm::Error),

    /// Cannot load a kernel.
    LoadKernel(vm::Error),
}
pub type Result<T> = result::Result<T, Error>;

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            VmNew(e) => write!(f, "Can not create a new virtual machine: {:?}", e),
            VmStart(e) => write!(f, "Can not start a new virtual machine: {:?}", e),
            LoadKernel(e) => write!(f, "Can not load a guest kernel: {:?}", e),
        }
    }
}

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
    let mut vm = Vm::new(&vmm.kvm, config).map_err(Error::VmNew)?;

    let entry = vm.load_kernel().map_err(Error::LoadKernel)?;
    vm.start(entry).map_err(Error::VmStart)?;

    Ok(())
}
