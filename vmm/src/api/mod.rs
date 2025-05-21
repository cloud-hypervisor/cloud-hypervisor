// Copyright © 2019 Intel Corporation
// Copyright 2024 Alyssa Ross <hi@alyssa.is>
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
//!    encapsulates the response channel Sender, for the VMM API server to be
//!    able to send the response back.
//! 3. The thread writes to the API event file descriptor to notify the VMM
//!    API server about a pending command.
//! 4. The thread reads the response back from the VMM API server, from the
//!    response channel Receiver.
//! 5. The thread handles the response and forwards potential errors.

#[cfg(feature = "dbus_api")]
pub mod dbus;
pub mod http;

use std::io;
use std::sync::mpsc::{channel, RecvError, SendError, Sender};

use micro_http::Body;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use vm_migration::MigratableError;
use vmm_sys_util::eventfd::EventFd;

#[cfg(feature = "dbus_api")]
pub use self::dbus::start_dbus_thread;
pub use self::http::{start_http_fd_thread, start_http_path_thread};
use crate::config::RestoreConfig;
use crate::device_tree::DeviceTree;
use crate::vm::{Error as VmError, VmState};
use crate::vm_config::{
    DeviceConfig, DiskConfig, FsConfig, NetConfig, PmemConfig, UserDeviceConfig, VdpaConfig,
    VmConfig, VsockConfig,
};
use crate::Error as VmmError;

/// API errors are sent back from the VMM API server through the ApiResponse.
#[derive(Error, Debug)]
pub enum ApiError {
    /// Cannot write to EventFd.
    #[error("Cannot write to EventFd: {0}")]
    EventFdWrite(#[source] io::Error),

    /// API request send error
    #[error("API request send error: {0}")]
    RequestSend(#[source] SendError<ApiRequest>),

    /// Wrong response payload type
    #[error("Wrong response payload type")]
    ResponsePayloadType,

    /// API response receive error
    #[error("API response receive error: {0}")]
    ResponseRecv(#[source] RecvError),

    /// The VM could not boot.
    #[error("The VM could not boot: {0}")]
    VmBoot(#[source] VmError),

    /// The VM could not be created.
    #[error("The VM could not be created: {0}")]
    VmCreate(#[source] VmError),

    /// The VM could not be deleted.
    #[error("The VM could not be deleted: {0}")]
    VmDelete(#[source] VmError),

    /// The VM info is not available.
    #[error("The VM info is not available: {0}")]
    VmInfo(#[source] VmError),

    /// The VM could not be paused.
    #[error("The VM could not be paused: {0}")]
    VmPause(#[source] VmError),

    /// The VM could not resume.
    #[error("The VM could not resume: {0}")]
    VmResume(#[source] VmError),

    /// The VM is not booted.
    #[error("The VM is not booted")]
    VmNotBooted,

    /// The VM is not created.
    #[error("The VM is not created")]
    VmNotCreated,

    /// The VM could not shutdown.
    #[error("The VM could not shutdown: {0}")]
    VmShutdown(#[source] VmError),

    /// The VM could not reboot.
    #[error("The VM could not reboot: {0}")]
    VmReboot(#[source] VmError),

    /// The VM could not be snapshotted.
    #[error("The VM could not be snapshotted: {0}")]
    VmSnapshot(#[source] VmError),

    /// The VM could not restored.
    #[error("The VM could not restored: {0}")]
    VmRestore(#[source] VmError),

    /// The VM could not be coredumped.
    #[error("The VM could not be coredumped: {0}")]
    VmCoredump(#[source] VmError),

    /// The VMM could not shutdown.
    #[error("The VMM could not shutdown: {0}")]
    VmmShutdown(#[source] VmError),

    /// The VM could not be resized
    #[error("The VM could not be resized: {0}")]
    VmResize(#[source] VmError),

    /// The memory zone could not be resized.
    #[error("The memory zone could not be resized: {0}")]
    VmResizeZone(#[source] VmError),

    /// The device could not be added to the VM.
    #[error("The device could not be added to the VM: {0}")]
    VmAddDevice(#[source] VmError),

    /// The user device could not be added to the VM.
    #[error("The user device could not be added to the VM: {0}")]
    VmAddUserDevice(#[source] VmError),

    /// The device could not be removed from the VM.
    #[error("The device could not be removed from the VM: {0}")]
    VmRemoveDevice(#[source] VmError),

    /// Cannot create seccomp filter
    #[error("Cannot create seccomp filter: {0}")]
    CreateSeccompFilter(#[source] seccompiler::Error),

    /// Cannot apply seccomp filter
    #[error("Cannot apply seccomp filter: {0}")]
    ApplySeccompFilter(#[source] seccompiler::Error),

    /// The disk could not be added to the VM.
    #[error("The disk could not be added to the VM: {0}")]
    VmAddDisk(#[source] VmError),

    /// The fs could not be added to the VM.
    #[error("The fs could not be added to the VM: {0}")]
    VmAddFs(#[source] VmError),

    /// The pmem device could not be added to the VM.
    #[error("The pmem device could not be added to the VM: {0}")]
    VmAddPmem(#[source] VmError),

    /// The network device could not be added to the VM.
    #[error("The network device could not be added to the VM: {0}")]
    VmAddNet(#[source] VmError),

    /// The vDPA device could not be added to the VM.
    #[error("The vDPA device could not be added to the VM: {0}")]
    VmAddVdpa(#[source] VmError),

    /// The vsock device could not be added to the VM.
    #[error("The vsock device could not be added to the VM: {0}")]
    VmAddVsock(#[source] VmError),

    /// Error starting migration receiver
    #[error("Error starting migration receiver: {0}")]
    VmReceiveMigration(#[source] MigratableError),

    /// Error starting migration sender
    #[error("Error starting migration sender: {0}")]
    VmSendMigration(#[source] MigratableError),

    /// Error triggering power button
    #[error("Error triggering power button: {0}")]
    VmPowerButton(#[source] VmError),

    /// Error triggering NMI
    #[error("Error triggering NMI: {0}")]
    VmNmi(#[source] VmError),
}
pub type ApiResult<T> = Result<T, ApiError>;

#[derive(Clone, Deserialize, Serialize)]
pub struct VmInfoResponse {
    pub config: Box<VmConfig>,
    pub state: VmState,
    pub memory_actual_size: u64,
    pub device_tree: Option<DeviceTree>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct VmmPingResponse {
    pub build_version: String,
    pub version: String,
    pub pid: i64,
    pub features: Vec<String>,
}

#[derive(Clone, Deserialize, Serialize, Default, Debug)]
pub struct VmResizeData {
    pub desired_vcpus: Option<u8>,
    pub desired_ram: Option<u64>,
    pub desired_balloon: Option<u64>,
}

#[derive(Clone, Deserialize, Serialize, Default, Debug)]
pub struct VmResizeZoneData {
    pub id: String,
    pub desired_ram: u64,
}

#[derive(Clone, Deserialize, Serialize, Default, Debug)]
pub struct VmRemoveDeviceData {
    pub id: String,
}

#[derive(Clone, Deserialize, Serialize, Default, Debug)]
pub struct VmSnapshotConfig {
    /// The snapshot destination URL
    pub destination_url: String,
}

#[derive(Clone, Deserialize, Serialize, Default, Debug)]
pub struct VmCoredumpData {
    /// The coredump destination file
    pub destination_url: String,
}

#[derive(Clone, Deserialize, Serialize, Default, Debug)]
pub struct VmReceiveMigrationData {
    /// URL for the reception of migration state
    pub receiver_url: String,
}

#[derive(Clone, Deserialize, Serialize, Default, Debug)]
pub struct VmSendMigrationData {
    /// URL to migrate the VM to
    pub destination_url: String,
    /// Send memory across socket without copying
    #[serde(default)]
    pub local: bool,
}

pub enum ApiResponsePayload {
    /// No data is sent on the channel.
    Empty,

    /// Virtual machine information
    VmInfo(VmInfoResponse),

    /// Vmm ping response
    VmmPing(VmmPingResponse),

    /// Vm action response
    VmAction(Option<Vec<u8>>),
}

/// This is the response sent by the VMM API server through the mpsc channel.
pub type ApiResponse = Result<ApiResponsePayload, ApiError>;

pub trait RequestHandler {
    fn vm_create(&mut self, config: Box<VmConfig>) -> Result<(), VmError>;

    fn vm_boot(&mut self) -> Result<(), VmError>;

    fn vm_pause(&mut self) -> Result<(), VmError>;

    fn vm_resume(&mut self) -> Result<(), VmError>;

    fn vm_snapshot(&mut self, destination_url: &str) -> Result<(), VmError>;

    fn vm_restore(&mut self, restore_cfg: RestoreConfig) -> Result<(), VmError>;

    #[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
    fn vm_coredump(&mut self, destination_url: &str) -> Result<(), VmError>;

    fn vm_shutdown(&mut self) -> Result<(), VmError>;

    fn vm_reboot(&mut self) -> Result<(), VmError>;

    fn vm_info(&self) -> Result<VmInfoResponse, VmError>;

    fn vmm_ping(&self) -> VmmPingResponse;

    fn vm_delete(&mut self) -> Result<(), VmError>;

    fn vmm_shutdown(&mut self) -> Result<(), VmError>;

    fn vm_resize(
        &mut self,
        desired_vcpus: Option<u8>,
        desired_ram: Option<u64>,
        desired_balloon: Option<u64>,
    ) -> Result<(), VmError>;

    fn vm_resize_zone(&mut self, id: String, desired_ram: u64) -> Result<(), VmError>;

    fn vm_add_device(&mut self, device_cfg: DeviceConfig) -> Result<Option<Vec<u8>>, VmError>;

    fn vm_add_user_device(
        &mut self,
        device_cfg: UserDeviceConfig,
    ) -> Result<Option<Vec<u8>>, VmError>;

    fn vm_remove_device(&mut self, id: String) -> Result<(), VmError>;

    fn vm_add_disk(&mut self, disk_cfg: DiskConfig) -> Result<Option<Vec<u8>>, VmError>;

    fn vm_add_fs(&mut self, fs_cfg: FsConfig) -> Result<Option<Vec<u8>>, VmError>;

    fn vm_add_pmem(&mut self, pmem_cfg: PmemConfig) -> Result<Option<Vec<u8>>, VmError>;

    fn vm_add_net(&mut self, net_cfg: NetConfig) -> Result<Option<Vec<u8>>, VmError>;

    fn vm_add_vdpa(&mut self, vdpa_cfg: VdpaConfig) -> Result<Option<Vec<u8>>, VmError>;

    fn vm_add_vsock(&mut self, vsock_cfg: VsockConfig) -> Result<Option<Vec<u8>>, VmError>;

    fn vm_counters(&mut self) -> Result<Option<Vec<u8>>, VmError>;

    fn vm_power_button(&mut self) -> Result<(), VmError>;

    fn vm_receive_migration(
        &mut self,
        receive_data_migration: VmReceiveMigrationData,
    ) -> Result<(), MigratableError>;

    fn vm_send_migration(
        &mut self,
        send_data_migration: VmSendMigrationData,
    ) -> Result<(), MigratableError>;

    fn vm_nmi(&mut self) -> Result<(), VmError>;
}

/// It would be nice if we could pass around an object like this:
///
/// ```
/// # use vmm::api::ApiAction;
/// struct ApiRequest<Action: ApiAction + 'static> {
///     action: &'static Action,
///     body: Action::RequestBody,
/// }
/// ```
///
/// Unfortunately, it's not possible to use such a type in a trait object,
/// so as a workaround, we instead encapsulate that data in a closure, and have
/// the event loop call that closure to process a request.
pub type ApiRequest =
    Box<dyn FnOnce(&mut dyn RequestHandler) -> Result<bool, VmmError> + Send + 'static>;

fn get_response<Action: ApiAction>(
    action: &Action,
    api_evt: EventFd,
    api_sender: Sender<ApiRequest>,
    data: Action::RequestBody,
) -> ApiResult<ApiResponsePayload> {
    let (response_sender, response_receiver) = channel();

    let request = action.request(data, response_sender);

    // Send the VM request.
    api_sender.send(request).map_err(ApiError::RequestSend)?;
    api_evt.write(1).map_err(ApiError::EventFdWrite)?;

    response_receiver.recv().map_err(ApiError::ResponseRecv)?
}

fn get_response_body<Action: ApiAction<ResponseBody = Option<Body>>>(
    action: &Action,
    api_evt: EventFd,
    api_sender: Sender<ApiRequest>,
    data: Action::RequestBody,
) -> ApiResult<Option<Body>> {
    let body = match get_response(action, api_evt, api_sender, data)? {
        ApiResponsePayload::VmAction(response) => response.map(Body::new),
        ApiResponsePayload::Empty => None,
        _ => return Err(ApiError::ResponsePayloadType),
    };

    Ok(body)
}

pub trait ApiAction: Send + Sync {
    type RequestBody: Send + Sync + Sized;
    type ResponseBody: Send + Sized;

    fn request(&self, body: Self::RequestBody, response_sender: Sender<ApiResponse>) -> ApiRequest;

    fn send(
        &self,
        api_evt: EventFd,
        api_sender: Sender<ApiRequest>,
        data: Self::RequestBody,
    ) -> ApiResult<Self::ResponseBody>;
}

pub struct VmAddDevice;

impl ApiAction for VmAddDevice {
    type RequestBody = DeviceConfig;
    type ResponseBody = Option<Body>;

    fn request(
        &self,
        config: Self::RequestBody,
        response_sender: Sender<ApiResponse>,
    ) -> ApiRequest {
        Box::new(move |vmm| {
            info!("API request event: VmAddDevice {:?}", config);

            let response = vmm
                .vm_add_device(config)
                .map_err(ApiError::VmAddDevice)
                .map(ApiResponsePayload::VmAction);

            response_sender
                .send(response)
                .map_err(VmmError::ApiResponseSend)?;

            Ok(false)
        })
    }

    fn send(
        &self,
        api_evt: EventFd,
        api_sender: Sender<ApiRequest>,
        data: Self::RequestBody,
    ) -> ApiResult<Self::ResponseBody> {
        get_response_body(self, api_evt, api_sender, data)
    }
}

pub struct AddDisk;

impl ApiAction for AddDisk {
    type RequestBody = DiskConfig;
    type ResponseBody = Option<Body>;

    fn request(
        &self,
        config: Self::RequestBody,
        response_sender: Sender<ApiResponse>,
    ) -> ApiRequest {
        Box::new(move |vmm| {
            info!("API request event: AddDisk {:?}", config);

            let response = vmm
                .vm_add_disk(config)
                .map_err(ApiError::VmAddDisk)
                .map(ApiResponsePayload::VmAction);

            response_sender
                .send(response)
                .map_err(VmmError::ApiResponseSend)?;

            Ok(false)
        })
    }

    fn send(
        &self,
        api_evt: EventFd,
        api_sender: Sender<ApiRequest>,
        data: Self::RequestBody,
    ) -> ApiResult<Self::ResponseBody> {
        get_response_body(self, api_evt, api_sender, data)
    }
}

pub struct VmAddFs;

impl ApiAction for VmAddFs {
    type RequestBody = FsConfig;
    type ResponseBody = Option<Body>;

    fn request(
        &self,
        config: Self::RequestBody,
        response_sender: Sender<ApiResponse>,
    ) -> ApiRequest {
        Box::new(move |vmm| {
            info!("API request event: VmAddFs {:?}", config);

            let response = vmm
                .vm_add_fs(config)
                .map_err(ApiError::VmAddFs)
                .map(ApiResponsePayload::VmAction);

            response_sender
                .send(response)
                .map_err(VmmError::ApiResponseSend)?;

            Ok(false)
        })
    }

    fn send(
        &self,
        api_evt: EventFd,
        api_sender: Sender<ApiRequest>,
        data: Self::RequestBody,
    ) -> ApiResult<Self::ResponseBody> {
        get_response_body(self, api_evt, api_sender, data)
    }
}

pub struct VmAddPmem;

impl ApiAction for VmAddPmem {
    type RequestBody = PmemConfig;
    type ResponseBody = Option<Body>;

    fn request(
        &self,
        config: Self::RequestBody,
        response_sender: Sender<ApiResponse>,
    ) -> ApiRequest {
        Box::new(move |vmm| {
            info!("API request event: VmAddPmem {:?}", config);

            let response = vmm
                .vm_add_pmem(config)
                .map_err(ApiError::VmAddPmem)
                .map(ApiResponsePayload::VmAction);

            response_sender
                .send(response)
                .map_err(VmmError::ApiResponseSend)?;

            Ok(false)
        })
    }

    fn send(
        &self,
        api_evt: EventFd,
        api_sender: Sender<ApiRequest>,
        data: Self::RequestBody,
    ) -> ApiResult<Self::ResponseBody> {
        get_response_body(self, api_evt, api_sender, data)
    }
}

pub struct VmAddNet;

impl ApiAction for VmAddNet {
    type RequestBody = NetConfig;
    type ResponseBody = Option<Body>;

    fn request(
        &self,
        config: Self::RequestBody,
        response_sender: Sender<ApiResponse>,
    ) -> ApiRequest {
        Box::new(move |vmm| {
            info!("API request event: VmAddNet {:?}", config);

            let response = vmm
                .vm_add_net(config)
                .map_err(ApiError::VmAddNet)
                .map(ApiResponsePayload::VmAction);

            response_sender
                .send(response)
                .map_err(VmmError::ApiResponseSend)?;

            Ok(false)
        })
    }

    fn send(
        &self,
        api_evt: EventFd,
        api_sender: Sender<ApiRequest>,
        data: Self::RequestBody,
    ) -> ApiResult<Self::ResponseBody> {
        get_response_body(self, api_evt, api_sender, data)
    }
}

pub struct VmAddVdpa;

impl ApiAction for VmAddVdpa {
    type RequestBody = VdpaConfig;
    type ResponseBody = Option<Body>;

    fn request(
        &self,
        config: Self::RequestBody,
        response_sender: Sender<ApiResponse>,
    ) -> ApiRequest {
        Box::new(move |vmm| {
            info!("API request event: VmAddVdpa {:?}", config);

            let response = vmm
                .vm_add_vdpa(config)
                .map_err(ApiError::VmAddVdpa)
                .map(ApiResponsePayload::VmAction);

            response_sender
                .send(response)
                .map_err(VmmError::ApiResponseSend)?;

            Ok(false)
        })
    }

    fn send(
        &self,
        api_evt: EventFd,
        api_sender: Sender<ApiRequest>,
        data: Self::RequestBody,
    ) -> ApiResult<Self::ResponseBody> {
        get_response_body(self, api_evt, api_sender, data)
    }
}

pub struct VmAddVsock;

impl ApiAction for VmAddVsock {
    type RequestBody = VsockConfig;
    type ResponseBody = Option<Body>;

    fn request(
        &self,
        config: Self::RequestBody,
        response_sender: Sender<ApiResponse>,
    ) -> ApiRequest {
        Box::new(move |vmm| {
            info!("API request event: VmAddVsock {:?}", config);

            let response = vmm
                .vm_add_vsock(config)
                .map_err(ApiError::VmAddVsock)
                .map(ApiResponsePayload::VmAction);

            response_sender
                .send(response)
                .map_err(VmmError::ApiResponseSend)?;

            Ok(false)
        })
    }

    fn send(
        &self,
        api_evt: EventFd,
        api_sender: Sender<ApiRequest>,
        data: Self::RequestBody,
    ) -> ApiResult<Self::ResponseBody> {
        get_response_body(self, api_evt, api_sender, data)
    }
}

pub struct VmAddUserDevice;

impl ApiAction for VmAddUserDevice {
    type RequestBody = UserDeviceConfig;
    type ResponseBody = Option<Body>;

    fn request(
        &self,
        config: Self::RequestBody,
        response_sender: Sender<ApiResponse>,
    ) -> ApiRequest {
        Box::new(move |vmm| {
            info!("API request event: VmAddUserDevice {:?}", config);

            let response = vmm
                .vm_add_user_device(config)
                .map_err(ApiError::VmAddUserDevice)
                .map(ApiResponsePayload::VmAction);

            response_sender
                .send(response)
                .map_err(VmmError::ApiResponseSend)?;

            Ok(false)
        })
    }

    fn send(
        &self,
        api_evt: EventFd,
        api_sender: Sender<ApiRequest>,
        data: Self::RequestBody,
    ) -> ApiResult<Self::ResponseBody> {
        get_response_body(self, api_evt, api_sender, data)
    }
}

pub struct VmBoot;

impl ApiAction for VmBoot {
    type RequestBody = ();
    type ResponseBody = Option<Body>;

    fn request(&self, _: Self::RequestBody, response_sender: Sender<ApiResponse>) -> ApiRequest {
        Box::new(move |vmm| {
            info!("API request event: VmBoot");

            let response = vmm
                .vm_boot()
                .map_err(ApiError::VmBoot)
                .map(|_| ApiResponsePayload::Empty);

            response_sender
                .send(response)
                .map_err(VmmError::ApiResponseSend)?;

            Ok(false)
        })
    }

    fn send(
        &self,
        api_evt: EventFd,
        api_sender: Sender<ApiRequest>,
        data: Self::RequestBody,
    ) -> ApiResult<Self::ResponseBody> {
        get_response_body(self, api_evt, api_sender, data)
    }
}

#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
pub struct VmCoredump;

#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
impl ApiAction for VmCoredump {
    type RequestBody = VmCoredumpData;
    type ResponseBody = Option<Body>;

    fn request(
        &self,
        coredump_data: Self::RequestBody,
        response_sender: Sender<ApiResponse>,
    ) -> ApiRequest {
        Box::new(move |vmm| {
            info!("API request event: VmCoredump {:?}", coredump_data);

            let response = vmm
                .vm_coredump(&coredump_data.destination_url)
                .map_err(ApiError::VmCoredump)
                .map(|_| ApiResponsePayload::Empty);

            response_sender
                .send(response)
                .map_err(VmmError::ApiResponseSend)?;

            Ok(false)
        })
    }

    fn send(
        &self,
        api_evt: EventFd,
        api_sender: Sender<ApiRequest>,
        data: Self::RequestBody,
    ) -> ApiResult<Self::ResponseBody> {
        get_response_body(self, api_evt, api_sender, data)
    }
}

pub struct VmCounters;

impl ApiAction for VmCounters {
    type RequestBody = ();
    type ResponseBody = Option<Body>;

    fn request(&self, _: Self::RequestBody, response_sender: Sender<ApiResponse>) -> ApiRequest {
        Box::new(move |vmm| {
            info!("API request event: VmCounters");

            let response = vmm
                .vm_counters()
                .map_err(ApiError::VmInfo)
                .map(ApiResponsePayload::VmAction);

            response_sender
                .send(response)
                .map_err(VmmError::ApiResponseSend)?;

            Ok(false)
        })
    }

    fn send(
        &self,
        api_evt: EventFd,
        api_sender: Sender<ApiRequest>,
        data: Self::RequestBody,
    ) -> ApiResult<Self::ResponseBody> {
        get_response_body(self, api_evt, api_sender, data)
    }
}

pub struct VmCreate;

impl ApiAction for VmCreate {
    type RequestBody = Box<VmConfig>;
    type ResponseBody = ();

    fn request(
        &self,
        config: Self::RequestBody,
        response_sender: Sender<ApiResponse>,
    ) -> ApiRequest {
        Box::new(move |vmm| {
            info!("API request event: VmCreate {:?}", config);

            let response = vmm
                .vm_create(config)
                .map_err(ApiError::VmCreate)
                .map(|_| ApiResponsePayload::Empty);

            response_sender
                .send(response)
                .map_err(VmmError::ApiResponseSend)?;

            Ok(false)
        })
    }

    fn send(
        &self,
        api_evt: EventFd,
        api_sender: Sender<ApiRequest>,
        data: Self::RequestBody,
    ) -> ApiResult<()> {
        get_response(self, api_evt, api_sender, data)?;

        Ok(())
    }
}

pub struct VmDelete;

impl ApiAction for VmDelete {
    type RequestBody = ();
    type ResponseBody = Option<Body>;

    fn request(&self, _: Self::RequestBody, response_sender: Sender<ApiResponse>) -> ApiRequest {
        Box::new(move |vmm| {
            info!("API request event: VmDelete");

            let response = vmm
                .vm_delete()
                .map_err(ApiError::VmDelete)
                .map(|_| ApiResponsePayload::Empty);

            response_sender
                .send(response)
                .map_err(VmmError::ApiResponseSend)?;

            Ok(false)
        })
    }

    fn send(
        &self,
        api_evt: EventFd,
        api_sender: Sender<ApiRequest>,
        data: Self::RequestBody,
    ) -> ApiResult<Self::ResponseBody> {
        get_response_body(self, api_evt, api_sender, data)
    }
}

pub struct VmInfo;

impl ApiAction for VmInfo {
    type RequestBody = ();
    type ResponseBody = VmInfoResponse;

    fn request(&self, _: Self::RequestBody, response_sender: Sender<ApiResponse>) -> ApiRequest {
        Box::new(move |vmm| {
            info!("API request event: VmInfo");

            let response = vmm
                .vm_info()
                .map_err(ApiError::VmInfo)
                .map(ApiResponsePayload::VmInfo);

            response_sender
                .send(response)
                .map_err(VmmError::ApiResponseSend)?;

            Ok(false)
        })
    }

    fn send(
        &self,
        api_evt: EventFd,
        api_sender: Sender<ApiRequest>,
        data: (),
    ) -> ApiResult<VmInfoResponse> {
        let vm_info = get_response(self, api_evt, api_sender, data)?;

        match vm_info {
            ApiResponsePayload::VmInfo(info) => Ok(info),
            _ => Err(ApiError::ResponsePayloadType),
        }
    }
}

pub struct VmPause;

impl ApiAction for VmPause {
    type RequestBody = ();
    type ResponseBody = Option<Body>;

    fn request(&self, _: Self::RequestBody, response_sender: Sender<ApiResponse>) -> ApiRequest {
        Box::new(move |vmm| {
            info!("API request event: VmPause");

            let response = vmm
                .vm_pause()
                .map_err(ApiError::VmPause)
                .map(|_| ApiResponsePayload::Empty);

            response_sender
                .send(response)
                .map_err(VmmError::ApiResponseSend)?;

            Ok(false)
        })
    }

    fn send(
        &self,
        api_evt: EventFd,
        api_sender: Sender<ApiRequest>,
        data: Self::RequestBody,
    ) -> ApiResult<Self::ResponseBody> {
        get_response_body(self, api_evt, api_sender, data)
    }
}

pub struct VmPowerButton;

impl ApiAction for VmPowerButton {
    type RequestBody = ();
    type ResponseBody = Option<Body>;

    fn request(&self, _: Self::RequestBody, response_sender: Sender<ApiResponse>) -> ApiRequest {
        Box::new(move |vmm| {
            info!("API request event: VmPowerButton");

            let response = vmm
                .vm_power_button()
                .map_err(ApiError::VmPowerButton)
                .map(|_| ApiResponsePayload::Empty);

            response_sender
                .send(response)
                .map_err(VmmError::ApiResponseSend)?;

            Ok(false)
        })
    }

    fn send(
        &self,
        api_evt: EventFd,
        api_sender: Sender<ApiRequest>,
        data: Self::RequestBody,
    ) -> ApiResult<Self::ResponseBody> {
        get_response_body(self, api_evt, api_sender, data)
    }
}

pub struct VmReboot;

impl ApiAction for VmReboot {
    type RequestBody = ();
    type ResponseBody = Option<Body>;

    fn request(&self, _: Self::RequestBody, response_sender: Sender<ApiResponse>) -> ApiRequest {
        Box::new(move |vmm| {
            info!("API request event: VmReboot");

            let response = vmm
                .vm_reboot()
                .map_err(ApiError::VmReboot)
                .map(|_| ApiResponsePayload::Empty);

            response_sender
                .send(response)
                .map_err(VmmError::ApiResponseSend)?;

            Ok(false)
        })
    }

    fn send(
        &self,
        api_evt: EventFd,
        api_sender: Sender<ApiRequest>,
        data: Self::RequestBody,
    ) -> ApiResult<Self::ResponseBody> {
        get_response_body(self, api_evt, api_sender, data)
    }
}

pub struct VmReceiveMigration;

impl ApiAction for VmReceiveMigration {
    type RequestBody = VmReceiveMigrationData;
    type ResponseBody = Option<Body>;

    fn request(&self, data: Self::RequestBody, response_sender: Sender<ApiResponse>) -> ApiRequest {
        Box::new(move |vmm| {
            info!("API request event: VmReceiveMigration {:?}", data);

            let response = vmm
                .vm_receive_migration(data)
                .map_err(ApiError::VmReceiveMigration)
                .map(|_| ApiResponsePayload::Empty);

            response_sender
                .send(response)
                .map_err(VmmError::ApiResponseSend)?;

            Ok(false)
        })
    }

    fn send(
        &self,
        api_evt: EventFd,
        api_sender: Sender<ApiRequest>,
        data: Self::RequestBody,
    ) -> ApiResult<Self::ResponseBody> {
        get_response_body(self, api_evt, api_sender, data)
    }
}

pub struct VmRemoveDevice;

impl ApiAction for VmRemoveDevice {
    type RequestBody = VmRemoveDeviceData;
    type ResponseBody = Option<Body>;

    fn request(
        &self,
        remove_device_data: Self::RequestBody,
        response_sender: Sender<ApiResponse>,
    ) -> ApiRequest {
        Box::new(move |vmm| {
            info!("API request event: VmRemoveDevice {:?}", remove_device_data);

            let response = vmm
                .vm_remove_device(remove_device_data.id)
                .map_err(ApiError::VmRemoveDevice)
                .map(|_| ApiResponsePayload::Empty);

            response_sender
                .send(response)
                .map_err(VmmError::ApiResponseSend)?;

            Ok(false)
        })
    }

    fn send(
        &self,
        api_evt: EventFd,
        api_sender: Sender<ApiRequest>,
        data: Self::RequestBody,
    ) -> ApiResult<Self::ResponseBody> {
        get_response_body(self, api_evt, api_sender, data)
    }
}

pub struct VmResize;

impl ApiAction for VmResize {
    type RequestBody = VmResizeData;
    type ResponseBody = Option<Body>;

    fn request(
        &self,
        resize_data: Self::RequestBody,
        response_sender: Sender<ApiResponse>,
    ) -> ApiRequest {
        Box::new(move |vmm| {
            info!("API request event: VmResize {:?}", resize_data);

            let response = vmm
                .vm_resize(
                    resize_data.desired_vcpus,
                    resize_data.desired_ram,
                    resize_data.desired_balloon,
                )
                .map_err(ApiError::VmResize)
                .map(|_| ApiResponsePayload::Empty);

            response_sender
                .send(response)
                .map_err(VmmError::ApiResponseSend)?;

            Ok(false)
        })
    }

    fn send(
        &self,
        api_evt: EventFd,
        api_sender: Sender<ApiRequest>,
        data: Self::RequestBody,
    ) -> ApiResult<Self::ResponseBody> {
        get_response_body(self, api_evt, api_sender, data)
    }
}

pub struct VmResizeZone;

impl ApiAction for VmResizeZone {
    type RequestBody = VmResizeZoneData;
    type ResponseBody = Option<Body>;

    fn request(
        &self,
        resize_zone_data: Self::RequestBody,
        response_sender: Sender<ApiResponse>,
    ) -> ApiRequest {
        Box::new(move |vmm| {
            info!("API request event: VmResizeZone {:?}", resize_zone_data);

            let response = vmm
                .vm_resize_zone(resize_zone_data.id, resize_zone_data.desired_ram)
                .map_err(ApiError::VmResizeZone)
                .map(|_| ApiResponsePayload::Empty);

            response_sender
                .send(response)
                .map_err(VmmError::ApiResponseSend)?;

            Ok(false)
        })
    }

    fn send(
        &self,
        api_evt: EventFd,
        api_sender: Sender<ApiRequest>,
        data: Self::RequestBody,
    ) -> ApiResult<Self::ResponseBody> {
        get_response_body(self, api_evt, api_sender, data)
    }
}

pub struct VmRestore;

impl ApiAction for VmRestore {
    type RequestBody = RestoreConfig;
    type ResponseBody = Option<Body>;

    fn request(
        &self,
        config: Self::RequestBody,
        response_sender: Sender<ApiResponse>,
    ) -> ApiRequest {
        Box::new(move |vmm| {
            info!("API request event: VmRestore {:?}", config);

            let response = vmm
                .vm_restore(config)
                .map_err(ApiError::VmRestore)
                .map(|_| ApiResponsePayload::Empty);

            response_sender
                .send(response)
                .map_err(VmmError::ApiResponseSend)?;

            Ok(false)
        })
    }

    fn send(
        &self,
        api_evt: EventFd,
        api_sender: Sender<ApiRequest>,
        data: Self::RequestBody,
    ) -> ApiResult<Self::ResponseBody> {
        get_response_body(self, api_evt, api_sender, data)
    }
}

pub struct VmResume;

impl ApiAction for VmResume {
    type RequestBody = ();
    type ResponseBody = Option<Body>;

    fn request(&self, _: Self::RequestBody, response_sender: Sender<ApiResponse>) -> ApiRequest {
        Box::new(move |vmm| {
            info!("API request event: VmResume");

            let response = vmm
                .vm_resume()
                .map_err(ApiError::VmResume)
                .map(|_| ApiResponsePayload::Empty);

            response_sender
                .send(response)
                .map_err(VmmError::ApiResponseSend)?;

            Ok(false)
        })
    }

    fn send(
        &self,
        api_evt: EventFd,
        api_sender: Sender<ApiRequest>,
        data: Self::RequestBody,
    ) -> ApiResult<Self::ResponseBody> {
        get_response_body(self, api_evt, api_sender, data)
    }
}

pub struct VmSendMigration;

impl ApiAction for VmSendMigration {
    type RequestBody = VmSendMigrationData;
    type ResponseBody = Option<Body>;

    fn request(&self, data: Self::RequestBody, response_sender: Sender<ApiResponse>) -> ApiRequest {
        Box::new(move |vmm| {
            info!("API request event: VmSendMigration {:?}", data);

            let response = vmm
                .vm_send_migration(data)
                .map_err(ApiError::VmSendMigration)
                .map(|_| ApiResponsePayload::Empty);

            response_sender
                .send(response)
                .map_err(VmmError::ApiResponseSend)?;

            Ok(false)
        })
    }

    fn send(
        &self,
        api_evt: EventFd,
        api_sender: Sender<ApiRequest>,
        data: Self::RequestBody,
    ) -> ApiResult<Self::ResponseBody> {
        get_response_body(self, api_evt, api_sender, data)
    }
}

pub struct VmShutdown;

impl ApiAction for VmShutdown {
    type RequestBody = ();
    type ResponseBody = Option<Body>;

    fn request(
        &self,
        config: Self::RequestBody,
        response_sender: Sender<ApiResponse>,
    ) -> ApiRequest {
        Box::new(move |vmm| {
            info!("API request event: VmShutdown {:?}", config);

            let response = vmm
                .vm_shutdown()
                .map_err(ApiError::VmShutdown)
                .map(|_| ApiResponsePayload::Empty);

            response_sender
                .send(response)
                .map_err(VmmError::ApiResponseSend)?;

            Ok(false)
        })
    }

    fn send(
        &self,
        api_evt: EventFd,
        api_sender: Sender<ApiRequest>,
        data: Self::RequestBody,
    ) -> ApiResult<Self::ResponseBody> {
        get_response_body(self, api_evt, api_sender, data)
    }
}

pub struct VmSnapshot;

impl ApiAction for VmSnapshot {
    type RequestBody = VmSnapshotConfig;
    type ResponseBody = Option<Body>;

    fn request(
        &self,
        config: Self::RequestBody,
        response_sender: Sender<ApiResponse>,
    ) -> ApiRequest {
        Box::new(move |vmm| {
            info!("API request event: VmSnapshot {:?}", config);

            let response = vmm
                .vm_snapshot(&config.destination_url)
                .map_err(ApiError::VmSnapshot)
                .map(|_| ApiResponsePayload::Empty);

            response_sender
                .send(response)
                .map_err(VmmError::ApiResponseSend)?;

            Ok(false)
        })
    }

    fn send(
        &self,
        api_evt: EventFd,
        api_sender: Sender<ApiRequest>,
        data: Self::RequestBody,
    ) -> ApiResult<Self::ResponseBody> {
        get_response_body(self, api_evt, api_sender, data)
    }
}

pub struct VmmPing;

impl ApiAction for VmmPing {
    type RequestBody = ();
    type ResponseBody = VmmPingResponse;

    fn request(&self, _: Self::RequestBody, response_sender: Sender<ApiResponse>) -> ApiRequest {
        Box::new(move |vmm| {
            info!("API request event: VmmPing");

            let response = ApiResponsePayload::VmmPing(vmm.vmm_ping());

            response_sender
                .send(Ok(response))
                .map_err(VmmError::ApiResponseSend)?;

            Ok(false)
        })
    }

    fn send(
        &self,
        api_evt: EventFd,
        api_sender: Sender<ApiRequest>,
        data: (),
    ) -> ApiResult<VmmPingResponse> {
        let vmm_pong = get_response(self, api_evt, api_sender, data)?;

        match vmm_pong {
            ApiResponsePayload::VmmPing(pong) => Ok(pong),
            _ => Err(ApiError::ResponsePayloadType),
        }
    }
}

pub struct VmmShutdown;

impl ApiAction for VmmShutdown {
    type RequestBody = ();
    type ResponseBody = ();

    fn request(&self, _: Self::RequestBody, response_sender: Sender<ApiResponse>) -> ApiRequest {
        Box::new(move |vmm| {
            info!("API request event: VmmShutdown");

            let response = vmm
                .vmm_shutdown()
                .map_err(ApiError::VmmShutdown)
                .map(|_| ApiResponsePayload::Empty);

            response_sender
                .send(response)
                .map_err(VmmError::ApiResponseSend)?;

            Ok(true)
        })
    }

    fn send(&self, api_evt: EventFd, api_sender: Sender<ApiRequest>, data: ()) -> ApiResult<()> {
        get_response(self, api_evt, api_sender, data)?;

        Ok(())
    }
}

pub struct VmNmi;

impl ApiAction for VmNmi {
    type RequestBody = ();
    type ResponseBody = Option<Body>;

    fn request(&self, _: Self::RequestBody, response_sender: Sender<ApiResponse>) -> ApiRequest {
        Box::new(move |vmm| {
            info!("API request event: VmNmi");

            let response = vmm
                .vm_nmi()
                .map_err(ApiError::VmNmi)
                .map(|_| ApiResponsePayload::Empty);

            response_sender
                .send(response)
                .map_err(VmmError::ApiResponseSend)?;

            Ok(false)
        })
    }

    fn send(
        &self,
        api_evt: EventFd,
        api_sender: Sender<ApiRequest>,
        data: Self::RequestBody,
    ) -> ApiResult<Self::ResponseBody> {
        get_response_body(self, api_evt, api_sender, data)
    }
}
