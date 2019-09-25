// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

#[macro_use]
extern crate log;
extern crate vmm_sys_util;

use libc::EFD_NONBLOCK;
use std::fmt::{self, Display};
use std::io;
use std::result;
use std::sync::Arc;
use vmm_sys_util::eventfd::EventFd;

pub mod api;
pub mod config;
pub mod device_manager;
pub mod vm;

use self::config::VmConfig;
use self::vm::{ExitBehaviour, Vm};

/// Errors associated with VM management
#[derive(Debug)]
pub enum Error {
    /// Cannot create EventFd.
    EventFd(io::Error),

    /// Cannot create a new VM.
    VmNew(vm::Error),

    /// Cannot start a VM.
    VmStart(vm::Error),

    /// Cannot stop a VM.
    VmStop(vm::Error),
}
pub type Result<T> = result::Result<T, Error>;

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            EventFd(e) => write!(f, "Can not create EventFd: {:?}", e),
            VmNew(e) => write!(f, "Can not create a new virtual machine: {:?}", e),
            VmStart(e) => write!(f, "Can not start a new virtual machine: {:?}", e),
            VmStop(e) => write!(f, "Can not stop a virtual machine: {:?}", e),
        }
    }
}

pub fn start_vm_loop(config: Arc<VmConfig>) -> Result<()> {
    let exit_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::EventFd)?;
    let reset_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::EventFd)?;

    loop {
        let mut vm = Vm::new(
            config.clone(),
            exit_evt.try_clone().unwrap(),
            reset_evt.try_clone().unwrap(),
        )
        .map_err(Error::VmNew)?;

        if vm.start().map_err(Error::VmStart)? == ExitBehaviour::Shutdown {
            vm.stop().map_err(Error::VmStop)?;
            break;
        }

        vm.stop().map_err(Error::VmStop)?;

        #[cfg(not(feature = "acpi"))]
        break;
    }

    Ok(())
}
