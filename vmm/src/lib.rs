// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

extern crate kvm_ioctls;
#[macro_use]
extern crate log;

use kvm_ioctls::*;
use std::fmt::{self, Display};
use std::{result, thread};

pub mod config;
pub mod device_manager;
pub mod vm;

use self::config::{VmConfig, VmmConfig};
use self::vm::{ExitBehaviour, Vm};

/// Errors associated with VM management
#[derive(Debug)]
pub enum Error {
    /// Cannot start API server socket
    ApiServerStart,

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
            ApiServerStart => write!(f, "Can not start the API server"),
            VmNew(e) => write!(f, "Can not create a new virtual machine: {:?}", e),
            VmStart(e) => write!(f, "Can not start a new virtual machine: {:?}", e),
            LoadKernel(e) => write!(f, "Can not load a guest kernel: {:?}", e),
        }
    }
}

pub struct Vmm {
    kvm: Kvm,
}

impl Vmm {
    pub fn new() -> Result<Self> {
        let kvm = Kvm::new().expect("new KVM instance creation failed");
        Ok(Vmm { kvm })
    }

    pub fn run(&self, vmm_config: VmmConfig, vm_config: VmConfig) -> Result<()> {
        let socket_path = vmm_config.api_server.socket_path.to_string();

        // First we spawn the API server
        let api_thread = thread::spawn(move || {
            panic!("API server at {} UNSUPPORTED", &socket_path);
        });

        // If we have a valid VM configuration, we need to verify that it
        // has been explicitly set by the user.
        if vm_config.user_defined && vm_config.valid() {
            loop {
                let mut vm = Vm::new(&self.kvm, &vm_config).map_err(Error::VmNew)?;

                let entry = vm.load_kernel().map_err(Error::LoadKernel)?;

                if vm.start(entry).map_err(Error::VmStart)? == ExitBehaviour::Shutdown {
                    break;
                }

                #[cfg(not(feature = "acpi"))]
                break;
            }
        }

        api_thread.join().map_err(|_| Error::ApiServerStart)?;

        Ok(())
    }
}
