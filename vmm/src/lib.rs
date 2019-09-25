// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

#[macro_use]
extern crate log;
extern crate vmm_sys_util;

use crate::api::{ApiError, ApiRequest, ApiResponse, ApiResponsePayload};
use crate::vm::{Error as VmError, ExitBehaviour, Vm};
use libc::EFD_NONBLOCK;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::mpsc::{channel, Receiver, RecvError, SendError, Sender};
use std::sync::Arc;
use std::{result, thread};
use vmm_sys_util::eventfd::EventFd;

pub mod api;
pub mod config;
pub mod device_manager;
pub mod vm;

use self::config::VmConfig;
//use self::vm::{ExitBehaviour, Vm};

/// Errors associated with VMM management
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Error {
    /// API request receive error
    ApiRequestRecv(RecvError),

    /// API response receive error
    ApiResponseRecv(RecvError),

    /// API request send error
    ApiRequestSend(SendError<ApiRequest>),

    /// API response send error
    ApiResponseSend(SendError<ApiResponse>),

    /// Cannot create a VM from the API
    ApiVmCreate(ApiError),

    /// Cannot start a VM from the API
    ApiVmStart(ApiError),

    /// Cannot clone EventFd.
    EventFdClone(io::Error),

    /// Cannot create EventFd.
    EventFdCreate(io::Error),

    /// Cannot read from EventFd.
    EventFdRead(io::Error),

    /// Cannot write to EventFd.
    EventFdWrite(io::Error),

    /// Cannot create epoll context.
    Epoll(io::Error),

    /// Cannot handle the VM STDIN stream
    Stdin(VmError),

    /// Cannot create a VM
    VmCreate(VmError),

    /// Cannot start a VM
    VmStart(VmError),

    /// Cannot stop a VM
    VmStop(VmError),
}
pub type Result<T> = result::Result<T, Error>;

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

pub struct Vmm {
    epoll: EpollContext,
    exit_evt: EventFd,
    reset_evt: EventFd,
    api_evt: EventFd,
    vm: Option<Vm>,
}

impl Vmm {
    fn new(api_evt: EventFd) -> Result<Self> {
        let mut epoll = EpollContext::new().map_err(Error::Epoll)?;
        let exit_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::EventFdCreate)?;
        let reset_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::EventFdCreate)?;

        if unsafe { libc::isatty(libc::STDIN_FILENO as i32) } != 0 {
            epoll.add_stdin().map_err(Error::Epoll)?;
        }

        epoll
            .add_event(&exit_evt, EpollDispatch::Exit)
            .map_err(Error::Epoll)?;

        epoll
            .add_event(&reset_evt, EpollDispatch::Reset)
            .map_err(Error::Epoll)?;

        epoll
            .add_event(&api_evt, EpollDispatch::Api)
            .map_err(Error::Epoll)?;

        Ok(Vmm {
            epoll,
            exit_evt,
            reset_evt,
            api_evt,
            vm: None,
        })
    }

    fn control_loop(&mut self, api_receiver: Arc<Receiver<ApiRequest>>) -> Result<ExitBehaviour> {
        const EPOLL_EVENTS_LEN: usize = 100;

        let mut events = vec![epoll::Event::new(epoll::Events::empty(), 0); EPOLL_EVENTS_LEN];
        let epoll_fd = self.epoll.as_raw_fd();

        let exit_behaviour;

        'outer: loop {
            let num_events = match epoll::wait(epoll_fd, -1, &mut events[..]) {
                Ok(res) => res,
                Err(e) => {
                    if e.kind() == io::ErrorKind::Interrupted {
                        // It's well defined from the epoll_wait() syscall
                        // documentation that the epoll loop can be interrupted
                        // before any of the requested events occurred or the
                        // timeout expired. In both those cases, epoll_wait()
                        // returns an error of type EINTR, but this should not
                        // be considered as a regular error. Instead it is more
                        // appropriate to retry, by calling into epoll_wait().
                        continue;
                    }
                    return Err(Error::Epoll(e));
                }
            };

            for event in events.iter().take(num_events) {
                let dispatch_idx = event.data as usize;

                if let Some(dispatch_type) = self.epoll.dispatch_table[dispatch_idx] {
                    match dispatch_type {
                        EpollDispatch::Exit => {
                            // Consume the event.
                            self.exit_evt.read().map_err(Error::EventFdRead)?;
                            exit_behaviour = ExitBehaviour::Shutdown;

                            break 'outer;
                        }
                        EpollDispatch::Reset => {
                            // Consume the event.
                            self.reset_evt.read().map_err(Error::EventFdRead)?;
                            exit_behaviour = ExitBehaviour::Reset;

                            break 'outer;
                        }
                        EpollDispatch::Stdin => {
                            if let Some(ref vm) = self.vm {
                                vm.handle_stdin().map_err(Error::Stdin)?;
                            }
                        }
                        EpollDispatch::Api => {
                            // Consume the event.
                            self.api_evt.read().map_err(Error::EventFdRead)?;

                            // Read from the API receiver channel
                            let api_request = api_receiver.recv().map_err(Error::ApiRequestRecv)?;

                            match api_request {
                                ApiRequest::VmCreate(config, sender) => {
                                    let exit_evt =
                                        self.exit_evt.try_clone().map_err(Error::EventFdClone)?;
                                    let reset_evt =
                                        self.reset_evt.try_clone().map_err(Error::EventFdClone)?;
                                    let response = match Vm::new(config, exit_evt, reset_evt) {
                                        Ok(vm) => {
                                            self.vm = Some(vm);
                                            Ok(ApiResponsePayload::Empty)
                                        }
                                        Err(e) => Err(ApiError::VmCreate(e)),
                                    };

                                    sender.send(response).map_err(Error::ApiResponseSend)?;
                                }
                                ApiRequest::VmStart(sender) => {
                                    if let Some(ref mut vm) = self.vm {
                                        let response = match vm.start() {
                                            Ok(_) => Ok(ApiResponsePayload::Empty),
                                            Err(e) => Err(ApiError::VmStart(e)),
                                        };

                                        sender.send(response).map_err(Error::ApiResponseSend)?;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(exit_behaviour)
    }
}

pub fn start_vm_loop(config: Arc<VmConfig>) -> Result<()> {
    let exit_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::EventFdCreate)?;
    let reset_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::EventFdCreate)?;

    loop {
        let mut vm = Vm::new(
            config.clone(),
            exit_evt.try_clone().unwrap(),
            reset_evt.try_clone().unwrap(),
        )
        .expect("Could not create VM");

        if vm.start().expect("Could not start VM") == ExitBehaviour::Shutdown {
            vm.stop().expect("Could not stop VM");
            break;
        }

        vm.stop().expect("Could not stop VM");

        #[cfg(not(feature = "acpi"))]
        break;
    }

    Ok(())
}
