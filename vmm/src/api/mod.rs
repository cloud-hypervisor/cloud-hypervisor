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
pub mod http_endpoint;

use crate::config::VmConfig;
use crate::vm::{Error as VmError, VmState};
use std::io;
use std::sync::mpsc::{channel, RecvError, SendError, Sender};
use std::sync::Arc;
use vmm_sys_util::eventfd::EventFd;
use vm_migration::state::MigrationRequest;

/// API errors are sent back from the VMM API server through the ApiResponse.
#[derive(Debug)]
pub enum ApiError {
    /// Cannot write to EventFd.
    EventFdWrite(io::Error),

    /// API request send error
    RequestSend(SendError<ApiRequest>),

    /// Wrong reponse payload type
    ResponsePayloadType,

    /// API response receive error
    ResponseRecv(RecvError),

    /// The VM could not boot.
    VmBoot(VmError),

    /// The VM is already created.
    VmAlreadyCreated,

    /// The VM could not be created.
    VmCreate(VmError),

    /// The VM could not be deleted.
    VmDelete(VmError),

    /// The VM info is not available.
    VmInfo(VmError),

    /// The VM config is missing.
    VmMissingConfig,

    /// The VM could not be paused.
    VmPause(VmError),

    /// The VM could not resume.
    VmResume(VmError),

    /// The VM is not booted.
    VmNotBooted,

    /// The VM is not created.
    VmNotCreated,

    /// The VM could not shutdown.
    VmShutdown(VmError),

    /// The VM could not reboot.
    VmReboot(VmError),

    /// The VMM could not shutdown.
    VmmShutdown(VmError),
}
pub type ApiResult<T> = std::result::Result<T, ApiError>;

#[derive(Clone, Deserialize, Serialize)]
pub struct VmInfo {
    pub config: Arc<VmConfig>,
    pub state: VmState,
}

pub enum ApiResponsePayload {
    /// No data is sent on the channel.
    Empty,

    /// Virtual machine information
    VmInfo(VmInfo),
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

    /// Delete the previously created virtual machine.
    /// If the VM was not previously created, the VMM API server will send a
    /// VmDelete error back.
    /// If the VM is booted, we shut it down first.
    VmDelete(Sender<ApiResponse>),

    /// Request the VM information.
    VmInfo(Sender<ApiResponse>),

    /// Pause a VM.
    VmPause(Sender<ApiResponse>),

    /// Resume a VM.
    VmResume(Sender<ApiResponse>),

    /// Shut the previously booted virtual machine down.
    /// If the VM was not previously booted or created, the VMM API server
    /// will send a VmShutdown error back.
    VmShutdown(Sender<ApiResponse>),

    /// Reboot the previously booted virtual machine.
    /// If the VM was not previously booted or created, the VMM API server
    /// will send a VmReboot error back.
    VmReboot(Sender<ApiResponse>),

    /// Shut the VMM down.
    /// This will shutdown and delete the current VM, if any, and then exit the
    /// VMM process.
    VmmShutdown(Sender<ApiResponse>),

    /// Register migration component.
    /// This will register migration component sender to migrate state array,
    /// then migration thread can send request to component to get/load states.
    MigrationRegister(String, Sender<MigrationRequest>),
}

pub fn vm_create(
    api_evt: EventFd,
    api_sender: Sender<ApiRequest>,
    config: Arc<VmConfig>,
) -> ApiResult<()> {
    let (response_sender, response_receiver) = channel();

    // Send the VM creation request.
    api_sender
        .send(ApiRequest::VmCreate(config, response_sender))
        .map_err(ApiError::RequestSend)?;
    api_evt.write(1).map_err(ApiError::EventFdWrite)?;

    response_receiver.recv().map_err(ApiError::ResponseRecv)??;

    Ok(())
}

/// Represents a VM related action.
/// This is mostly used to factorize code between VM routines
/// that only differ by the IPC command they send.
pub enum VmAction {
    /// Boot a VM
    Boot,

    /// Delete a VM
    Delete,

    /// Shut a VM down
    Shutdown,

    /// Reboot a VM
    Reboot,

    /// Pause a VM
    Pause,

    /// Resume a VM
    Resume,
}

fn vm_action(api_evt: EventFd, api_sender: Sender<ApiRequest>, action: VmAction) -> ApiResult<()> {
    let (response_sender, response_receiver) = channel();

    let request = match action {
        VmAction::Boot => ApiRequest::VmBoot(response_sender),
        VmAction::Delete => ApiRequest::VmDelete(response_sender),
        VmAction::Shutdown => ApiRequest::VmShutdown(response_sender),
        VmAction::Reboot => ApiRequest::VmReboot(response_sender),
        VmAction::Pause => ApiRequest::VmPause(response_sender),
        VmAction::Resume => ApiRequest::VmResume(response_sender),
    };

    // Send the VM request.
    api_sender.send(request).map_err(ApiError::RequestSend)?;
    api_evt.write(1).map_err(ApiError::EventFdWrite)?;

    response_receiver.recv().map_err(ApiError::ResponseRecv)??;

    Ok(())
}

pub fn vm_boot(api_evt: EventFd, api_sender: Sender<ApiRequest>) -> ApiResult<()> {
    vm_action(api_evt, api_sender, VmAction::Boot)
}

pub fn vm_delete(api_evt: EventFd, api_sender: Sender<ApiRequest>) -> ApiResult<()> {
    vm_action(api_evt, api_sender, VmAction::Delete)
}

pub fn vm_shutdown(api_evt: EventFd, api_sender: Sender<ApiRequest>) -> ApiResult<()> {
    vm_action(api_evt, api_sender, VmAction::Shutdown)
}

pub fn vm_reboot(api_evt: EventFd, api_sender: Sender<ApiRequest>) -> ApiResult<()> {
    vm_action(api_evt, api_sender, VmAction::Reboot)
}

pub fn vm_pause(api_evt: EventFd, api_sender: Sender<ApiRequest>) -> ApiResult<()> {
    vm_action(api_evt, api_sender, VmAction::Pause)
}

pub fn vm_resume(api_evt: EventFd, api_sender: Sender<ApiRequest>) -> ApiResult<()> {
    vm_action(api_evt, api_sender, VmAction::Resume)
}

pub fn vm_info(api_evt: EventFd, api_sender: Sender<ApiRequest>) -> ApiResult<VmInfo> {
    let (response_sender, response_receiver) = channel();

    // Send the VM request.
    api_sender
        .send(ApiRequest::VmInfo(response_sender))
        .map_err(ApiError::RequestSend)?;
    api_evt.write(1).map_err(ApiError::EventFdWrite)?;

    let vm_info = response_receiver.recv().map_err(ApiError::ResponseRecv)??;

    match vm_info {
        ApiResponsePayload::VmInfo(info) => Ok(info),
        _ => Err(ApiError::ResponsePayloadType),
    }
}

pub fn vmm_shutdown(api_evt: EventFd, api_sender: Sender<ApiRequest>) -> ApiResult<()> {
    let (response_sender, response_receiver) = channel();

    // Send the VMM shutdown request.
    api_sender
        .send(ApiRequest::VmmShutdown(response_sender))
        .map_err(ApiError::RequestSend)?;
    api_evt.write(1).map_err(ApiError::EventFdWrite)?;

    response_receiver.recv().map_err(ApiError::ResponseRecv)??;

    Ok(())
}
