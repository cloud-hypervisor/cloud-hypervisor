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
use std::os::unix::io::{AsRawFd, RawFd};
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

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EpollDispatch {
    Exit,
    Reset,
    Stdin,
    Api,
}

pub struct EpollContext {
    raw_fd: RawFd,
    dispatch_table: Vec<Option<EpollDispatch>>,
}

impl EpollContext {
    pub fn new() -> result::Result<EpollContext, io::Error> {
        let raw_fd = epoll::create(true)?;

        // Initial capacity needs to be large enough to hold:
        // * 1 exit event
        // * 1 reset event
        // * 1 stdin event
        // * 1 API event
        let mut dispatch_table = Vec::with_capacity(5);
        dispatch_table.push(None);

        Ok(EpollContext {
            raw_fd,
            dispatch_table,
        })
    }

    pub fn add_stdin(&mut self) -> result::Result<(), io::Error> {
        let dispatch_index = self.dispatch_table.len() as u64;
        epoll::ctl(
            self.raw_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            libc::STDIN_FILENO,
            epoll::Event::new(epoll::Events::EPOLLIN, dispatch_index),
        )?;

        self.dispatch_table.push(Some(EpollDispatch::Stdin));

        Ok(())
    }

    fn add_event<T>(&mut self, fd: &T, token: EpollDispatch) -> result::Result<(), io::Error>
    where
        T: AsRawFd,
    {
        let dispatch_index = self.dispatch_table.len() as u64;
        epoll::ctl(
            self.raw_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            fd.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, dispatch_index),
        )?;
        self.dispatch_table.push(Some(token));

        Ok(())
    }
}

impl AsRawFd for EpollContext {
    fn as_raw_fd(&self) -> RawFd {
        self.raw_fd
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
