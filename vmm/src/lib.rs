// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

#[macro_use]
extern crate log;

use std::fmt::{self, Display};
use std::result;

pub mod config;
pub mod device_manager;
pub mod vm;

use self::config::VmConfig;
use self::vm::{ExitBehaviour, Vm};

/// Errors associated with VM management
#[derive(Debug)]
pub enum Error {
    /// Cannot create a new VM.
    VmNew(vm::Error),

    /// Cannot start a VM.
    VmStart(vm::Error),
}
pub type Result<T> = result::Result<T, Error>;

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            VmNew(e) => write!(f, "Can not create a new virtual machine: {:?}", e),
            VmStart(e) => write!(f, "Can not start a new virtual machine: {:?}", e),
        }
    }
}

pub fn start_vm_loop(config: VmConfig) -> Result<()> {
    loop {
        let mut vm = Vm::new(&config).map_err(Error::VmNew)?;

        if vm.start().map_err(Error::VmStart)? == ExitBehaviour::Shutdown {
            break;
        }

        #[cfg(not(feature = "acpi"))]
        break;
    }

    Ok(())
}
