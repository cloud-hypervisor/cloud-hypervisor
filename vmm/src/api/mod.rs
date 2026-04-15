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
use std::num::{NonZeroU32, NonZeroU64};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::mpsc::{RecvError, SendError, Sender, channel};
use std::time::Duration;

use log::info;
use micro_http::Body;
use option_parser::{OptionParser, OptionParserError, Toggle};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use vm_migration::MigratableError;
use vmm_sys_util::eventfd::EventFd;

#[cfg(feature = "dbus_api")]
pub use self::dbus::start_dbus_thread;
pub use self::http::{start_http_fd_thread, start_http_path_thread};
use crate::Error as VmmError;
use crate::config::RestoreConfig;
use crate::device_tree::DeviceTree;
use crate::migration_transport::{MAX_MIGRATION_CONNECTIONS, tcp_address_to_server_name};
use crate::vm::{Error as VmError, VmState};
use crate::vm_config::{
    DeviceConfig, DiskConfig, FsConfig, GenericVhostUserConfig, NetConfig, PmemConfig,
    UserDeviceConfig, VdpaConfig, VmConfig, VsockConfig,
};

/// API errors are sent back from the VMM API server through the ApiResponse.
#[derive(Error, Debug)]
pub enum ApiError {
    /// Cannot write to EventFd.
    #[error("Cannot write to EventFd")]
    EventFdWrite(#[source] io::Error),

    /// API request send error
    #[error("API request send error")]
    RequestSend(#[source] SendError<ApiRequest>),

    /// Wrong response payload type
    #[error("Wrong response payload type")]
    ResponsePayloadType,

    /// API response receive error
    #[error("API response receive error")]
    ResponseRecv(#[source] RecvError),

    /// The VM could not boot.
    #[error("The VM could not boot")]
    VmBoot(#[source] VmError),

    /// The VM could not be created.
    #[error("The VM could not be created")]
    VmCreate(#[source] VmError),

    /// The VM could not be deleted.
    #[error("The VM could not be deleted")]
    VmDelete(#[source] VmError),

    /// The VM info is not available.
    #[error("The VM info is not available")]
    VmInfo(#[source] VmError),

    /// The VM could not be paused.
    #[error("The VM could not be paused")]
    VmPause(#[source] VmError),

    /// The VM could not resume.
    #[error("The VM could not resume")]
    VmResume(#[source] VmError),

    /// The VM is not booted.
    #[error("The VM is not booted")]
    VmNotBooted,

    /// The VM is not created.
    #[error("The VM is not created")]
    VmNotCreated,

    /// The VM could not shutdown.
    #[error("The VM could not shutdown")]
    VmShutdown(#[source] VmError),

    /// The VM could not reboot.
    #[error("The VM could not reboot")]
    VmReboot(#[source] VmError),

    /// The VM could not be snapshotted.
    #[error("The VM could not be snapshotted")]
    VmSnapshot(#[source] VmError),

    /// The VM could not be restored.
    #[error("The VM could not be restored")]
    VmRestore(#[source] VmError),

    /// The VM could not be coredumped.
    #[error("The VM could not be coredumped")]
    VmCoredump(#[source] VmError),

    /// The VMM could not shutdown.
    #[error("The VMM could not shutdown")]
    VmmShutdown(#[source] VmError),

    /// The VM could not be resized
    #[error("The VM could not be resized")]
    VmResize(#[source] VmError),

    /// The disk could not be resized.
    #[error("The disk could not be resized")]
    VmResizeDisk(#[source] VmError),

    /// The memory zone could not be resized.
    #[error("The memory zone could not be resized")]
    VmResizeZone(#[source] VmError),

    /// The device could not be added to the VM.
    #[error("The device could not be added to the VM")]
    VmAddDevice(#[source] VmError),

    /// The user device could not be added to the VM.
    #[error("The user device could not be added to the VM")]
    VmAddUserDevice(#[source] VmError),

    /// The device could not be removed from the VM.
    #[error("The device could not be removed from the VM")]
    VmRemoveDevice(#[source] VmError),

    /// Cannot create seccomp filter
    #[error("Cannot create seccomp filter")]
    CreateSeccompFilter(#[source] seccompiler::Error),

    /// Cannot apply seccomp filter
    #[error("Cannot apply seccomp filter")]
    ApplySeccompFilter(#[source] seccompiler::Error),

    /// The disk could not be added to the VM.
    #[error("The disk could not be added to the VM")]
    VmAddDisk(#[source] VmError),

    /// The fs could not be added to the VM.
    #[error("The fs could not be added to the VM")]
    VmAddFs(#[source] VmError),

    /// The generic vhost-user device could not be added to the VM.
    #[error("The generic vhost-user device could not be added to the VM")]
    VmAddGenericVhostUser(#[source] VmError),

    /// The pmem device could not be added to the VM.
    #[error("The pmem device could not be added to the VM")]
    VmAddPmem(#[source] VmError),

    /// The network device could not be added to the VM.
    #[error("The network device could not be added to the VM")]
    VmAddNet(#[source] VmError),

    /// The vDPA device could not be added to the VM.
    #[error("The vDPA device could not be added to the VM")]
    VmAddVdpa(#[source] VmError),

    /// The vsock device could not be added to the VM.
    #[error("The vsock device could not be added to the VM")]
    VmAddVsock(#[source] VmError),

    /// Error starting migration receiver
    #[error("Error starting migration receiver")]
    VmReceiveMigration(#[source] MigratableError),

    /// Error starting migration sender
    #[error("Error starting migration sender")]
    VmSendMigration(#[source] MigratableError),

    /// Error triggering power button
    #[error("Error triggering power button")]
    VmPowerButton(#[source] VmError),

    /// Error triggering NMI
    #[error("Error triggering NMI")]
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
    pub desired_vcpus: Option<u32>,
    pub desired_ram: Option<u64>,
    pub desired_balloon: Option<u64>,
}

#[derive(Clone, Deserialize, Serialize, Default, Debug)]
pub struct VmResizeDiskData {
    pub id: String,
    pub desired_size: u64,
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

#[derive(Copy, Clone, Default, Deserialize, Serialize, Debug, PartialEq, Eq)]
/// The migration timeout strategy.
///
/// This strategy describes the behavior of the migration when the target
/// downtime can't be reached in the given timeout.
pub enum TimeoutStrategy {
    #[default]
    /// Cancel the migration and keep the VM running on the source.
    Cancel,
    /// Ignore the timeout and migrate anyway.
    Ignore,
}

impl FromStr for TimeoutStrategy {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "cancel" => Ok(TimeoutStrategy::Cancel),
            "ignore" => Ok(TimeoutStrategy::Ignore),
            _ => Err(format!("Invalid timeout strategy: {s}")),
        }
    }
}

#[derive(Debug, Error)]
pub enum VmSendMigrationConfigError {
    #[error("Error parsing send migration parameters")]
    ParseError(#[source] OptionParserError),

    #[error("Error validating send migration parameters")]
    ValidationError(String),
}

/// Configuration for an outgoing migration.
#[derive(Clone, Deserialize, Serialize, Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct VmSendMigrationData {
    /// Migration destination, e.g. `tcp:<host>:<port>` or `unix:/path/to/socket`.
    pub destination_url: String,
    /// Send memory across socket without copying
    #[serde(default)]
    pub local: bool,
    /// The maximum downtime the migration aims for.
    ///
    /// Usually, on the order of a few hundred milliseconds.
    #[serde(default = "VmSendMigrationData::default_downtime_ms")]
    downtime_ms: NonZeroU64,
    /// The timeout for the migration, i.e., the maximum duration.
    #[serde(default = "VmSendMigrationData::default_timeout_s")]
    timeout_s: NonZeroU64,
    /// The timeout strategy for the migration.
    #[serde(default)]
    pub timeout_strategy: TimeoutStrategy,

    /// The number of parallel TCP connections for migration.
    ///
    /// Must be between 1 and `MAX_MIGRATION_CONNECTIONS` inclusive.
    #[serde(default = "VmSendMigrationData::default_connections")]
    pub connections: NonZeroU32,
    /// Path to the directory containing the TLS root CA certificate (ca-cert.pem), the TLS client certificate (client-cert.pem), and TLS client key (client-key.pem).
    #[serde(default)]
    pub tls_dir: Option<PathBuf>,
}

impl VmSendMigrationData {
    pub const SYNTAX: &'static str = "VM send migration parameters \
        \"destination_url=<url>[,local=on|off,\
        downtime_ms=<milliseconds>,timeout_s=<seconds>,\
        timeout_strategy=cancel|ignore,connections=<amount>,\
        tls_dir=<path>]\"";

    // Same as QEMU.
    pub const DEFAULT_DOWNTIME: Duration = Duration::from_millis(300);
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60 * 60 /* one hour */);

    fn default_downtime_ms() -> NonZeroU64 {
        let ms_u64 = u64::try_from(Self::DEFAULT_DOWNTIME.as_millis()).unwrap();
        NonZeroU64::new(ms_u64).unwrap()
    }

    fn default_timeout_s() -> NonZeroU64 {
        NonZeroU64::new(Self::DEFAULT_TIMEOUT.as_secs()).unwrap()
    }

    // Use a single connection as default for backward compatibility.
    fn default_connections() -> NonZeroU32 {
        NonZeroU32::new(1).unwrap()
    }

    pub fn parse(migration: &str) -> Result<Self, VmSendMigrationConfigError> {
        let mut parser = OptionParser::new();
        parser
            .add("destination_url")
            .add("local")
            .add("downtime_ms")
            .add("timeout_s")
            .add("timeout_strategy")
            .add("connections")
            .add("tls_dir");
        parser
            .parse(migration)
            .map_err(VmSendMigrationConfigError::ParseError)?;

        let destination_url = parser.get("destination_url").ok_or_else(|| {
            VmSendMigrationConfigError::ParseError(OptionParserError::InvalidSyntax(
                "destination_url is required".to_string(),
            ))
        })?;
        let local = parser
            .convert::<Toggle>("local")
            .map_err(VmSendMigrationConfigError::ParseError)?
            .unwrap_or(Toggle(false))
            .0;
        let downtime_ms = match parser
            .convert::<u64>("downtime_ms")
            .map_err(VmSendMigrationConfigError::ParseError)?
        {
            Some(v) => NonZeroU64::new(v).ok_or_else(|| {
                VmSendMigrationConfigError::ParseError(OptionParserError::InvalidValue(
                    "downtime_ms must be non-zero".to_string(),
                ))
            })?,
            None => Self::default_downtime_ms(),
        };
        let timeout_s = match parser
            .convert::<u64>("timeout_s")
            .map_err(VmSendMigrationConfigError::ParseError)?
        {
            Some(v) => NonZeroU64::new(v).ok_or_else(|| {
                VmSendMigrationConfigError::ParseError(OptionParserError::InvalidValue(
                    "timeout_s must be non-zero".to_string(),
                ))
            })?,
            None => Self::default_timeout_s(),
        };
        let timeout_strategy = parser
            .convert("timeout_strategy")
            .map_err(VmSendMigrationConfigError::ParseError)?
            .unwrap_or_default();
        let connections = match parser
            .convert::<u32>("connections")
            .map_err(VmSendMigrationConfigError::ParseError)?
        {
            Some(v) => NonZeroU32::new(v).ok_or_else(|| {
                VmSendMigrationConfigError::ParseError(OptionParserError::InvalidValue(
                    "connections must be non-zero".to_string(),
                ))
            })?,
            None => Self::default_connections(),
        };
        let tls_dir = parser
            .convert::<String>("tls_dir")
            .map_err(VmSendMigrationConfigError::ParseError)?
            .map(|path| PathBuf::from(&path));

        let data = Self {
            destination_url,
            local,
            downtime_ms,
            timeout_s,
            timeout_strategy,
            connections,
            tls_dir,
        };

        data.validate()?;

        Ok(data)
    }

    pub fn downtime(&self) -> Duration {
        Duration::from_millis(self.downtime_ms.get())
    }

    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_s.get())
    }

    pub fn validate(&self) -> Result<(), VmSendMigrationConfigError> {
        if let Some(addr) = self.destination_url.strip_prefix("tcp:") {
            tcp_address_to_server_name(addr).map_err(|e| {
                VmSendMigrationConfigError::ValidationError(format!(
                    "destination_url must use tcp:<host>:<port> or unix:<path>: {e}."
                ))
            })?;
        } else if self
            .destination_url
            .strip_prefix("unix:")
            .is_some_and(|path| !path.is_empty())
        {
            if self.connections.get() > 1 {
                return Err(VmSendMigrationConfigError::ValidationError(
                    "UNIX sockets and connections option cannot be used at the same time."
                        .to_string(),
                ));
            }
            if self.tls_dir.is_some() {
                return Err(VmSendMigrationConfigError::ValidationError(
                    "UNIX sockets and TLS encryption cannot be used at the same time.".to_string(),
                ));
            }
        } else {
            return Err(VmSendMigrationConfigError::ValidationError(
                "destination_url must use tcp:<host>:<port> or unix:<path>.".to_string(),
            ));
        }

        if self.connections.get() > MAX_MIGRATION_CONNECTIONS {
            return Err(VmSendMigrationConfigError::ValidationError(format!(
                "connections must not exceed {MAX_MIGRATION_CONNECTIONS}."
            )));
        }

        if self.local {
            if !self.destination_url.starts_with("unix:") {
                return Err(VmSendMigrationConfigError::ValidationError(
                    "local option is only supported with UNIX sockets.".to_string(),
                ));
            }

            if self.connections.get() > 1 {
                return Err(VmSendMigrationConfigError::ValidationError(
                    "local option and connections option cannot be used at the same time."
                        .to_string(),
                ));
            }
        }

        Ok(())
    }
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
        desired_vcpus: Option<u32>,
        desired_ram: Option<u64>,
        desired_balloon: Option<u64>,
    ) -> Result<(), VmError>;

    fn vm_resize_zone(&mut self, id: String, desired_ram: u64) -> Result<(), VmError>;

    fn vm_resize_disk(&mut self, id: String, desired_size: u64) -> Result<(), VmError>;

    fn vm_add_device(&mut self, device_cfg: DeviceConfig) -> Result<Option<Vec<u8>>, VmError>;

    fn vm_add_user_device(
        &mut self,
        device_cfg: UserDeviceConfig,
    ) -> Result<Option<Vec<u8>>, VmError>;

    fn vm_remove_device(&mut self, id: String) -> Result<(), VmError>;

    fn vm_add_disk(&mut self, disk_cfg: DiskConfig) -> Result<Option<Vec<u8>>, VmError>;

    fn vm_add_fs(&mut self, fs_cfg: FsConfig) -> Result<Option<Vec<u8>>, VmError>;

    fn vm_add_generic_vhost_user(
        &mut self,
        fs_cfg: GenericVhostUserConfig,
    ) -> Result<Option<Vec<u8>>, VmError>;

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

#[allow(clippy::needless_pass_by_value)]
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
            info!("API request event: VmAddDevice {config:?}");

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
            info!("API request event: AddDisk {config:?}");

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
            info!("API request event: VmAddFs {config:?}");

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

pub struct VmAddGenericVhostUser;

impl ApiAction for VmAddGenericVhostUser {
    type RequestBody = GenericVhostUserConfig;
    type ResponseBody = Option<Body>;

    fn request(
        &self,
        config: Self::RequestBody,
        response_sender: Sender<ApiResponse>,
    ) -> ApiRequest {
        Box::new(move |vmm| {
            info!("API request event: VmAddGenericVhostUser {config:?}");

            let response = vmm
                .vm_add_generic_vhost_user(config)
                .map_err(ApiError::VmAddGenericVhostUser)
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
            info!("API request event: VmAddPmem {config:?}");

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
            info!("API request event: VmAddNet {config:?}");

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
            info!("API request event: VmAddVdpa {config:?}");

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
            info!("API request event: VmAddVsock {config:?}");

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
            info!("API request event: VmAddUserDevice {config:?}");

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
            info!("API request event: VmCoredump {coredump_data:?}");

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
            info!("API request event: VmCreate {config:?}");

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
            info!("API request event: VmReceiveMigration {data:?}");

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
            info!("API request event: VmRemoveDevice {remove_device_data:?}");

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
            info!("API request event: VmResize {resize_data:?}");

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

pub struct VmResizeDisk;

impl ApiAction for VmResizeDisk {
    type RequestBody = VmResizeDiskData;
    type ResponseBody = Option<Body>;

    fn request(
        &self,
        resize_disk_data: Self::RequestBody,
        response_sender: Sender<ApiResponse>,
    ) -> ApiRequest {
        Box::new(move |vmm| {
            let response = vmm
                .vm_resize_disk(resize_disk_data.id, resize_disk_data.desired_size)
                .map_err(ApiError::VmResizeDisk)
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
            info!("API request event: VmResizeZone {resize_zone_data:?}");

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
            info!("API request event: VmRestore {config:?}");

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
            info!("API request event: VmSendMigration {data:?}");

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
            info!("API request event: VmShutdown {config:?}");

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
            info!("API request event: VmSnapshot {config:?}");

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

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_vm_send_migration_data_parse() {
        // Fully specified
        let data = VmSendMigrationData::parse(
            "destination_url=unix:/tmp/migrate.sock,local=on,downtime_ms=200,timeout_s=3600,timeout_strategy=cancel"
        ).expect("valid migration string should parse");
        assert_eq!(data.destination_url, "unix:/tmp/migrate.sock");
        assert!(data.local);
        assert_eq!(data.downtime_ms.get(), 200);
        assert_eq!(data.timeout_s.get(), 3600);
        assert_eq!(data.timeout_strategy, TimeoutStrategy::Cancel);
        assert_eq!(data.connections.get(), 1);

        // Defaults applied when optional fields are omitted
        let data = VmSendMigrationData::parse("destination_url=tcp:192.168.1.1:8080")
            .expect("minimal migration string should parse");
        assert_eq!(data.destination_url, "tcp:192.168.1.1:8080");
        assert!(!data.local);
        assert_eq!(data.downtime_ms, VmSendMigrationData::default_downtime_ms());
        assert_eq!(data.timeout_s, VmSendMigrationData::default_timeout_s());
        assert_eq!(data.timeout_strategy, TimeoutStrategy::default());
        assert_eq!(data.connections, VmSendMigrationData::default_connections());

        let data = VmSendMigrationData::parse("destination_url=tcp:[2001:db8::1]:8080")
            .expect("IPv6 migration string should parse");
        assert_eq!(data.destination_url, "tcp:[2001:db8::1]:8080");

        let data = VmSendMigrationData::parse("destination_url=tcp:destination.example:8080")
            .expect("hostname migration string should parse");
        assert_eq!(data.destination_url, "tcp:destination.example:8080");

        // Missing destination_url is an error
        VmSendMigrationData::parse("local=on,downtime_ms=200").unwrap_err();

        // Zero downtime_ms is rejected
        let _data =
            VmSendMigrationData::parse("destination_url=tcp:192.168.1.1:8080,downtime_ms=0")
                .expect_err("zero downtime_ms should be rejected");

        // Zero timeout_s is rejected
        let _data = VmSendMigrationData::parse("destination_url=unix:/tmp/sock,timeout_s=0")
            .expect_err("zero timeout_s should be rejected");

        // Zero connections is rejected
        let _data =
            VmSendMigrationData::parse("destination_url=tcp:192.168.1.1:8080,connections=0")
                .expect_err("zero connections should be rejected");

        // Excessive numbers of parallel connections are rejected
        let _data =
            VmSendMigrationData::parse("destination_url=tcp:192.168.1.1:8080,connections=129")
                .expect_err("too many connections should be rejected");

        // Unknown option is an error
        VmSendMigrationData::parse("destination_url=unix:/tmp/sock,unknown_field=foo").unwrap_err();

        // Invalid toggle value is an error
        VmSendMigrationData::parse("destination_url=unix:/tmp/sock,local=yes").unwrap_err();

        // Timeout strategy
        let _data = VmSendMigrationData::parse(
            "destination_url=tcp:192.168.1.1:8080,timeout_strategy=invalid",
        )
        .expect_err("invalid timeout strategy should be rejected");

        // Invalid destination URL scheme is rejected
        VmSendMigrationData::parse("destination_url=file:///tmp/migration").unwrap_err();
        VmSendMigrationData::parse("destination_url=tcp:192.168.1.1").unwrap_err();
        VmSendMigrationData::parse("destination_url=tcp:[2001:db8::1]").unwrap_err();

        // Local migration requires a UNIX socket destination
        VmSendMigrationData::parse("destination_url=tcp:192.168.1.1:8080,local=yes").unwrap_err();

        // Local migration cannot use multiple connections
        VmSendMigrationData::parse("destination_url=unix:/tmp/sock,local=yes,connections=2")
            .unwrap_err();

        // Happy path with some defaults
        let data =
            VmSendMigrationData::parse("destination_url=tcp:192.168.1.1:8080,downtime_ms=150")
                .unwrap();
        assert_eq!(
            data,
            VmSendMigrationData {
                destination_url: "tcp:192.168.1.1:8080".to_string(),
                local: false,
                downtime_ms: NonZeroU64::new(150).unwrap(),
                timeout_s: VmSendMigrationData::default_timeout_s(),
                timeout_strategy: Default::default(),
                connections: VmSendMigrationData::default_connections(),
                tls_dir: None,
            }
        );

        // Happy path, fully specified
        let tls_dir = std::env::temp_dir();
        let data =
            VmSendMigrationData::parse(&format!("destination_url=tcp:192.168.1.1:8080,downtime_ms=150,timeout_s=900,timeout_strategy=ignore,connections=4,tls_dir={}", tls_dir.display()))
                .unwrap();
        assert_eq!(
            data,
            VmSendMigrationData {
                destination_url: "tcp:192.168.1.1:8080".to_string(),
                local: false,
                downtime_ms: NonZeroU64::new(150).unwrap(),
                timeout_s: NonZeroU64::new(900).unwrap(),
                timeout_strategy: TimeoutStrategy::Ignore,
                connections: NonZeroU32::new(4).unwrap(),
                tls_dir: Some(tls_dir),
            }
        );
    }
}
