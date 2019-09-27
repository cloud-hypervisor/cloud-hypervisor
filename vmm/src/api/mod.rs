// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! The internal VMM API for Cloud Hypervisor.
//!
//! This API is a synchronous, [mpsc](https://doc.rust-lang.org/std/sync/mpsc/)
//! based IPC for sending commands to the VMM thread, from other
//! Cloud Hypervisor threads. The IPC follows a command-response protocol, i.e.
//! each command will receive a response back.
//!
//! The main Cloud Hypervisor thread creates an API event file descriptor
//! to notify the VMM thread about pending API commands, together with an
//! API mpsc channel. The former is the IPC control plane, the latter is the
//! IPC data plane.
//! In order to use the IPC, a Cloud Hypervisor thread needs to have a clone
//! of both the API event file descriptor and the channel Sender. Then it must
//! go through the following steps:
//!
//! 1. The thread creates an mpsc channel for receiving the command response.
//! 2. The thread sends an ApiRequest to the Sender endpoint. The ApiRequest
//!    contains the response channel Sender, for the VMM API server to be able
//!    to send the response back.
//! 3. The thread writes to the API event file descriptor to notify the VMM
//!    API server about a pending command.
//! 4. The thread reads the response back from the VMM API server, from the
//!    response channel Receiver.
//! 5. The thread handles the response and forwards potential errors.

extern crate micro_http;
extern crate vmm_sys_util;

pub use self::http::start_http_thread;

pub mod http;

use crate::config::VmConfig;
use crate::vm::Error as VmError;
use crate::{Error, Result};
use std::sync::mpsc::{channel, Sender};
use std::sync::Arc;
use vmm_sys_util::eventfd::EventFd;

/// API errors are sent back from the VMM API server through the ApiResponse.
#[derive(Debug)]
pub enum ApiError {
    /// The VM could not be created.
    VmCreate(VmError),

    /// The VM could not boot.
    VmBoot(VmError),

    /// The VM could not shutdown.
    VmShutdown(VmError),

    /// The VM could not reboot.
    VmReboot,
}

pub enum ApiResponsePayload {
    /// No data is sent on the channel.
    Empty,
}

/// This is the response sent by the VMM API server through the mpsc channel.
pub type ApiResponse = std::result::Result<ApiResponsePayload, ApiError>;

#[allow(clippy::large_enum_variant)]
pub enum ApiRequest {
    /// Create the virtual machine. This request payload is a VM configuration
    /// (VmConfig).
    /// If the VMM API server could not create the VM, it will send a VmCreate
    /// error back.
    VmCreate(Arc<VmConfig>, Sender<ApiResponse>),

    /// Boot the previously created virtual machine.
    /// If the VM was not previously created, the VMM API server will send a
    /// VmBoot error back.
    VmBoot(Sender<ApiResponse>),

    /// Shut the previously booted virtual machine down.
    /// If the VM was not previously booted or created, the VMM API server
    /// will send a VmShutdown error back.
    VmShutdown(Sender<ApiResponse>),

    /// Reboot the previously booted virtual machine.
    /// If the VM was not previously booted or created, the VMM API server
    /// will send a VmReboot error back.
    VmReboot(Sender<ApiResponse>),
}

pub fn vm_create(
    api_evt: EventFd,
    api_sender: Sender<ApiRequest>,
    config: Arc<VmConfig>,
) -> Result<()> {
    let (response_sender, response_receiver) = channel();

    // Send the VM creation request.
    api_sender
        .send(ApiRequest::VmCreate(config, response_sender))
        .map_err(Error::ApiRequestSend)?;
    api_evt.write(1).map_err(Error::EventFdWrite)?;

    response_receiver
        .recv()
        .map_err(Error::ApiResponseRecv)?
        .map_err(Error::ApiVmCreate)?;

    Ok(())
}

/// Represents a VM related action.
/// This is mostly used to factorize code between VM routines
/// that only differ by the IPC command they send.
pub enum VmAction {
    /// Boot a VM
    Boot,

    /// Shut a VM down
    Shutdown,

    /// Reboot a VM
    Reboot,
}

fn vm_action(api_evt: EventFd, api_sender: Sender<ApiRequest>, action: VmAction) -> Result<()> {
    let (response_sender, response_receiver) = channel();

    let request = match action {
        VmAction::Boot => ApiRequest::VmBoot(response_sender),
        VmAction::Shutdown => ApiRequest::VmShutdown(response_sender),
        VmAction::Reboot => ApiRequest::VmReboot(response_sender),
    };

    // Send the VM request.
    api_sender.send(request).map_err(Error::ApiRequestSend)?;
    api_evt.write(1).map_err(Error::EventFdWrite)?;

    match action {
        VmAction::Boot => {
            response_receiver
                .recv()
                .map_err(Error::ApiResponseRecv)?
                .map_err(Error::ApiVmBoot)?;
        }

        VmAction::Shutdown => {
            response_receiver
                .recv()
                .map_err(Error::ApiResponseRecv)?
                .map_err(Error::ApiVmShutdown)?;
        }

        VmAction::Reboot => {
            response_receiver
                .recv()
                .map_err(Error::ApiResponseRecv)?
                .map_err(Error::ApiVmReboot)?;
        }
    }

    Ok(())
}

pub fn vm_boot(api_evt: EventFd, api_sender: Sender<ApiRequest>) -> Result<()> {
    vm_action(api_evt, api_sender, VmAction::Boot)
}

pub fn vm_shutdown(api_evt: EventFd, api_sender: Sender<ApiRequest>) -> Result<()> {
    vm_action(api_evt, api_sender, VmAction::Shutdown)
}

pub fn vm_reboot(api_evt: EventFd, api_sender: Sender<ApiRequest>) -> Result<()> {
    vm_action(api_evt, api_sender, VmAction::Reboot)
}
