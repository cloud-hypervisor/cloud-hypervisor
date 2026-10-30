// Copyright © 2019 Intel Corporation
// Copyright 2024 Alyssa Ross <hi@alyssa.is>
//
// SPDX-License-Identifier: Apache-2.0
//

//! # HTTP Endpoints of the Cloud Hypervisor API
//!
//! ## Special Handling for Devices Backed by Network File Descriptors (FDs) (e.g., virtio-net)
//!
//! Some of the HTTP handlers here implement special logic for devices
//! **backed by network FDs** to enable live-migration, state save/resume
//! (restore), and similar VM lifecycle events.
//!
//! The utilized mechanism requires that the control software (e.g., libvirt)
//! connects to Cloud Hypervisor by using a UNIX domain socket and that it
//! passes file descriptors (FDs) via _ancillary_ messages - specifically using
//! the `SCM_RIGHTS` mechanism described in [`cmsg(3)`]. These ancillary
//! messages must accompany the primary payload (HTTP JSON REST API in this
//! case). The Linux kernel handles these messages by `dup()`ing the referenced
//! FDs from the sender process into the receiving process, thereby ensuring
//! they are valid and usable in the target context.
//!
//! Once these valid file descriptors are received here, we integrate the actual
//! FDs into the VM's configuration, allowing the device to function correctly
//! with its backing network resources.
//!
//! We can receive these FDs as we use a [special HTTP library] that is aware
//! of the described mechanism.
//!
//! Please have a look into the [`fds_helper`] module for the technical
//! implementation.
//!
//! [`cmsg(3)`]: https://man7.org/linux/man-pages/man3/cmsg.3.html
//! [special HTTP library]: https://github.com/firecracker-microvm/micro-http

use std::fs::File;
use std::result;
use std::sync::mpsc::Sender;

use log::error;
use micro_http::{Body, Method, Request, Response, StatusCode, Version};
use vmm_sys_util::eventfd::EventFd;

use crate::api;
#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
use crate::api::VmCoredump;
use crate::api::http::http_endpoint::fds_helper::{attach_fds_to_cfg, attach_fds_to_cfgs};
use crate::api::http::{EndpointHandler, HttpError, error_response};
use crate::api::{
    AddDisk, ApiAction, ApiError, ApiRequest, DeviceConfig, NetConfig, VmAddDevice, VmAddFs,
    VmAddGenericVhostUser, VmAddNet, VmAddPmem, VmAddUserDevice, VmAddVdpa, VmAddVsock, VmBoot,
    VmCancelMigration, VmConfig, VmCounters, VmDelete, VmNmi, VmPause, VmPowerButton, VmReboot,
    VmReceiveMigration, VmReceiveMigrationData, VmRemoveDevice, VmResize, VmResizeDisk,
    VmResizeZone, VmRestore, VmResume, VmSendMigration, VmShutdown, VmSnapshot,
};
use crate::config::RestoreConfig;
use crate::cpu::Error as CpuError;
use crate::vm::Error as VmError;
use crate::vm_config::ExternalFd;

/// Helper module for attaching externally opened FDs to config objects.
///
/// # Difference between [`ConfigWithFDs`] and [`ConfigWithVariableFDs`]
///
/// The base trait [`ConfigWithFDs`] type must be implemented by all config
/// types that want to take ownership of externally provided FDs.
///
/// In the case of restore operations, e.g., after a live-migration, config
/// objects will know the amount of FDs they need. In this case, they must
/// also implement [`ConfigWithVariableFDs`]. In other scenarios, such as
/// hot device attach, the base type is sufficient and the type will take
/// over all available FDs.
///
/// In any case, the management software (e.g., libvirt) is responsible for
/// providing the exact amount of FDs.
mod fds_helper {
    use std::fs::File;

    use log::{debug, error, warn};

    use crate::api::http::HttpError;

    /// Abstraction over configuration types received via the HTTP API that
    /// have associated externally opened FDs.
    pub(super) trait ConfigWithFDs {
        /// Returns the ID of the device.
        ///
        /// Used for logging.
        fn id(&self) -> Option<&str>;

        /// Whether this config contains FD slots that need replacement.
        fn has_fds(&self) -> bool;

        /// Assigns the provided file descriptors (`fds`) to this configuration
        /// object.
        ///
        /// After calling this method, the configuration will behave as if it
        /// had originally been created with these FDs. Next, the configuration
        /// can be used to properly configure the corresponding device.
        ///
        /// # Arguments
        /// - `fds`: Either a non-empty Vector with corresponding FDs or `None`
        ///   indicating that no valid FDs were supplied.
        fn set_fds(&mut self, fds: Option<Vec<File>>);
    }

    /// Extension of [`ConfigWithFDs`] for config objects that know how many
    /// FDs they want (e.g., a restore configuration that is aware of the
    /// previous state).
    pub(super) trait ConfigWithVariableFDs: ConfigWithFDs {
        /// Returns how many FDs this type wants to have from the pool of
        /// available FDs.
        fn expected_num_fds(&self) -> usize;
    }

    mod config_with_fds_impls {
        use std::fs::File;

        use super::{ConfigWithFDs, ConfigWithVariableFDs};
        use crate::config::{RestoredNetConfig, RestoredVfioConfig};
        use crate::vm_config::{DeviceConfig, ExternalFd, NetConfig};

        impl ConfigWithFDs for NetConfig {
            fn id(&self) -> Option<&str> {
                self.pci_common.id.as_deref()
            }

            fn has_fds(&self) -> bool {
                self.fds.is_some()
            }

            fn set_fds(&mut self, fds: Option<Vec<File>>) {
                self.fds = fds.map(|files| files.into_iter().map(ExternalFd::from).collect());
            }
        }

        impl ConfigWithFDs for DeviceConfig {
            fn id(&self) -> Option<&str> {
                self.pci_common.id.as_deref()
            }

            fn has_fds(&self) -> bool {
                self.fd.is_some()
            }

            fn set_fds(&mut self, fds: Option<Vec<File>>) {
                // The VmAddDevice PutHandler enforces `fds.len() <= 1`
                // before calling into this trait, so `pop()` yields the
                // single FD when present.
                self.fd = fds
                    .and_then(|mut v| v.pop())
                    .map(ExternalFd::from)
                    .unwrap_or_default();
            }
        }

        impl ConfigWithFDs for RestoredNetConfig {
            fn id(&self) -> Option<&str> {
                Some(self.id.as_str())
            }

            fn has_fds(&self) -> bool {
                self.fds.is_some()
            }

            fn set_fds(&mut self, fds: Option<Vec<File>>) {
                self.fds = fds.map(|files| files.into_iter().map(ExternalFd::from).collect());
            }
        }

        impl ConfigWithVariableFDs for RestoredNetConfig {
            fn expected_num_fds(&self) -> usize {
                self.num_fds
            }
        }

        impl ConfigWithFDs for RestoredVfioConfig {
            fn id(&self) -> Option<&str> {
                Some(self.id.as_str())
            }

            fn has_fds(&self) -> bool {
                self.fd.is_some()
            }

            fn set_fds(&mut self, fds: Option<Vec<File>>) {
                self.fd = fds
                    .and_then(|mut v| v.pop())
                    .map(ExternalFd::from)
                    .unwrap_or_default();
            }
        }

        impl ConfigWithVariableFDs for RestoredVfioConfig {
            fn expected_num_fds(&self) -> usize {
                1
            }
        }
    }

    fn attach_fds_to_cfg_inner<T: ConfigWithFDs>(
        fds: &mut Vec<File>,
        fds_amount: usize,
        cfg: &mut T,
    ) {
        if cfg.has_fds() {
            // Only descriptors received through SCM_RIGHTS can be owned here.
            warn!(
                "FDs were present in HTTP request body for device {:?} but will be ignored",
                cfg.id()
            );

            // Reset old value in any case; if there are FDs, they are invalid.
            cfg.set_fds(None);
        }

        if fds_amount > 0 {
            let new_fds = fds.drain(..fds_amount).collect::<Vec<_>>();
            debug!(
                "Attaching network FDs received via UNIX domain socket to device: id={:?}, fds={new_fds:?}",
                cfg.id()
            );
            cfg.set_fds(Some(new_fds));
        }
    }

    /// Applies FDs to configs for their corresponding devices, as part of the special
    /// handling for devices backed by externally provided FDs.
    ///
    /// The FDs (via `files`) must be provided in the exact order matching the
    /// config struct they belong to.
    ///
    /// See [module description] for more info.
    ///
    /// # Arguments
    /// - `device_fds`: Ordered list of all FDs from the request.
    /// - `cfgs`: List of network configurations where each network can have up to `n` FDs.
    ///
    /// [module description]: self
    pub(super) fn attach_fds_to_cfgs<T: ConfigWithVariableFDs>(
        device_fds: Vec<File>,
        cfgs: &mut [&mut T],
    ) -> Result<(), HttpError> {
        let expected_fds: usize = cfgs.iter().map(|cfg| cfg.expected_num_fds()).sum();

        if device_fds.len() != expected_fds {
            error!(
                "Number of expected FDs: {}, received: {}",
                expected_fds,
                device_fds.len()
            );
            return Err(HttpError::BadRequest);
        }

        let mut fds = device_fds;

        // For each config: We drain the FDs vector by the amount of FDs the config expects.
        for cfg in cfgs {
            attach_fds_to_cfg_inner(&mut fds, cfg.expected_num_fds(), *cfg);
        }

        // We checked that `fds.len() == expected_fds`; so if we panic here, we
        // have a hard programming error
        assert!(fds.is_empty());

        Ok(())
    }

    /// Applies FDs to the config for the corresponding device, as part of the special
    /// handling for devices backed by externally provided FDs.
    ///
    /// See [module description] for more info.
    ///
    /// # Arguments
    /// - `device_fds`: Ordered list of all FDs from the request.
    /// - `cfg`: The config object that wants to take ownership of all available FDs.
    ///
    /// [module description]: self
    pub(super) fn attach_fds_to_cfg<T: ConfigWithFDs>(
        device_fds: Vec<File>,
        cfg: &mut T,
    ) -> Result<(), HttpError> {
        let mut fds = device_fds;

        let len = fds.len();
        attach_fds_to_cfg_inner(&mut fds, len, cfg);

        Ok(())
    }
}

// /api/v1/vm.create handler
pub struct VmCreate {}

impl EndpointHandler for VmCreate {
    fn handle_request(
        &self,
        req: &Request,
        api_notifier: EventFd,
        api_sender: Sender<ApiRequest>,
    ) -> Response {
        match req.method() {
            Method::Put => {
                match &req.body {
                    Some(body) => {
                        // Deserialize into a VmConfig
                        let mut vm_config: Box<VmConfig> = match serde_json::from_slice(body.raw())
                            .map_err(HttpError::SerdeJsonDeserialize)
                        {
                            Ok(config) => config,
                            Err(e) => return error_response(e),
                        };

                        if let Some(ref mut nets) = vm_config.net {
                            let mut cfgs = nets.iter_mut().collect::<Vec<&mut _>>();
                            let cfgs = cfgs.as_mut_slice();

                            // For the VmCreate call, we do not accept FDs from the socket currently.
                            // This call sets all FDs to null while doing the same logging as
                            // similar code paths.
                            for cfg in cfgs {
                                if let Err(e) =
                                    attach_fds_to_cfg(vec![], *cfg).map_err(error_response)
                                {
                                    return e;
                                }
                            }
                        }

                        if let Some(ref mut devices) = vm_config.devices {
                            // For the VmCreate call, we do not accept FDs from the socket currently.
                            // This call sets all FDs to null while doing the same logging as
                            // similar code paths.
                            for cfg in devices.iter_mut() {
                                if let Err(e) =
                                    attach_fds_to_cfg(vec![], cfg).map_err(error_response)
                                {
                                    return e;
                                }
                            }
                        }

                        match api::VmCreate
                            .send(api_notifier, api_sender, vm_config)
                            .map_err(HttpError::ApiError)
                        {
                            Ok(_) => Response::new(Version::Http11, StatusCode::NoContent),
                            Err(e) => error_response(e),
                        }
                    }

                    None => Response::new(Version::Http11, StatusCode::BadRequest),
                }
            }

            _ => error_response(HttpError::BadRequest),
        }
    }
}

pub trait GetHandler {
    fn handle_request(
        &'static self,
        _api_notifier: EventFd,
        _api_sender: Sender<ApiRequest>,
    ) -> result::Result<Option<Body>, HttpError> {
        Err(HttpError::BadRequest)
    }
}

pub trait PutHandler {
    fn handle_request(
        &'static self,
        _api_notifier: EventFd,
        _api_sender: Sender<ApiRequest>,
        _body: &Option<Body>,
        _files: Vec<File>,
    ) -> result::Result<Option<Body>, HttpError> {
        Err(HttpError::BadRequest)
    }
}

pub trait HttpVmAction: GetHandler + PutHandler + Sync {}

impl<T: GetHandler + PutHandler + Sync> HttpVmAction for T {}

macro_rules! vm_action_get_handler {
    ($action:ty) => {
        impl GetHandler for $action {
            fn handle_request(
                &'static self,
                api_notifier: EventFd,
                api_sender: Sender<ApiRequest>,
            ) -> std::result::Result<Option<Body>, HttpError> {
                self.send(api_notifier, api_sender, ())
                    .map_err(HttpError::ApiError)
            }
        }

        impl PutHandler for $action {}
    };
}

macro_rules! vm_action_put_handler {
    ($action:ty) => {
        impl PutHandler for $action {
            fn handle_request(
                &'static self,
                api_notifier: EventFd,
                api_sender: Sender<ApiRequest>,
                body: &Option<Body>,
                _files: Vec<File>,
            ) -> std::result::Result<Option<Body>, HttpError> {
                if body.is_some() {
                    Err(HttpError::BadRequest)
                } else {
                    self.send(api_notifier, api_sender, ())
                        .map_err(HttpError::ApiError)
                }
            }
        }

        impl GetHandler for $action {}
    };
}

macro_rules! vm_action_put_handler_body {
    ($action:ty) => {
        impl PutHandler for $action {
            fn handle_request(
                &'static self,
                api_notifier: EventFd,
                api_sender: Sender<ApiRequest>,
                body: &Option<Body>,
                _files: Vec<File>,
            ) -> std::result::Result<Option<Body>, HttpError> {
                if let Some(body) = body {
                    self.send(
                        api_notifier,
                        api_sender,
                        serde_json::from_slice(body.raw())?,
                    )
                    .map_err(HttpError::ApiError)
                } else {
                    Err(HttpError::BadRequest)
                }
            }
        }

        impl GetHandler for $action {}
    };
}

vm_action_get_handler!(VmCounters);

vm_action_put_handler!(VmBoot);
vm_action_put_handler!(VmDelete);
vm_action_put_handler!(VmShutdown);
vm_action_put_handler!(VmReboot);
vm_action_put_handler!(VmPause);
vm_action_put_handler!(VmResume);
vm_action_put_handler!(VmPowerButton);
vm_action_put_handler!(VmNmi);
vm_action_put_handler!(VmCancelMigration);

vm_action_put_handler_body!(AddDisk);
vm_action_put_handler_body!(VmAddFs);
vm_action_put_handler_body!(VmAddGenericVhostUser);
vm_action_put_handler_body!(VmAddPmem);
vm_action_put_handler_body!(VmAddVdpa);
vm_action_put_handler_body!(VmAddVsock);
vm_action_put_handler_body!(VmAddUserDevice);
vm_action_put_handler_body!(VmRemoveDevice);
vm_action_put_handler_body!(VmResizeDisk);
vm_action_put_handler_body!(VmResizeZone);
vm_action_put_handler_body!(VmSnapshot);
vm_action_put_handler_body!(VmSendMigration);

#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
vm_action_put_handler_body!(VmCoredump);

// Special handling for VFIO devices backed by an externally-opened cdev FD.
// See module description for more info.
impl PutHandler for VmAddDevice {
    fn handle_request(
        &'static self,
        api_notifier: EventFd,
        api_sender: Sender<ApiRequest>,
        body: &Option<Body>,
        files: Vec<File>,
    ) -> Result<Option<Body>, HttpError> {
        if let Some(body) = body {
            // A DeviceConfig is backed by at most one FD.
            if files.len() > 1 {
                return Err(HttpError::BadRequest);
            }
            let mut device_cfg: DeviceConfig = serde_json::from_slice(body.raw())?;
            attach_fds_to_cfg(files, &mut device_cfg)?;

            self.send(api_notifier, api_sender, device_cfg)
                .map_err(HttpError::ApiError)
        } else {
            Err(HttpError::BadRequest)
        }
    }
}

impl GetHandler for VmAddDevice {}

// Special handling for virtio-net devices backed by network FDs.
// See module description for more info.
impl PutHandler for VmAddNet {
    fn handle_request(
        &'static self,
        api_notifier: EventFd,
        api_sender: Sender<ApiRequest>,
        body: &Option<Body>,
        files: Vec<File>,
    ) -> result::Result<Option<Body>, HttpError> {
        if let Some(body) = body {
            let mut net_cfg: NetConfig = serde_json::from_slice(body.raw())?;
            attach_fds_to_cfg(files, &mut net_cfg)?;

            self.send(api_notifier, api_sender, net_cfg)
                .map_err(HttpError::ApiError)
        } else {
            Err(HttpError::BadRequest)
        }
    }
}

impl GetHandler for VmAddNet {}

impl PutHandler for VmResize {
    fn handle_request(
        &'static self,
        api_notifier: EventFd,
        api_sender: Sender<ApiRequest>,
        body: &Option<Body>,
        _files: Vec<File>,
    ) -> result::Result<Option<Body>, HttpError> {
        if let Some(body) = body {
            self.send(
                api_notifier,
                api_sender,
                serde_json::from_slice(body.raw())?,
            )
            .map_err(|e| match e {
                ApiError::VmResize(VmError::CpuManager(CpuError::VcpuPendingRemovedVcpu)) => {
                    HttpError::TooManyRequests
                }
                _ => HttpError::ApiError(e),
            })
        } else {
            Err(HttpError::BadRequest)
        }
    }
}

impl GetHandler for VmResize {}

// Special handling for virtio-net devices backed by network FDs.
// See module description for more info.
impl PutHandler for VmRestore {
    fn handle_request(
        &'static self,
        api_notifier: EventFd,
        api_sender: Sender<ApiRequest>,
        body: &Option<Body>,
        files: Vec<File>,
    ) -> result::Result<Option<Body>, HttpError> {
        if let Some(body) = body {
            let mut restore_cfg: RestoreConfig = serde_json::from_slice(body.raw())?;

            let net_total: usize = restore_cfg
                .net_fds
                .iter()
                .flatten()
                .map(|c| c.num_fds)
                .sum();
            let vfio_total = restore_cfg.vfio_fds.as_ref().map_or(0, |c| c.len());
            let iommufd_total = usize::from(restore_cfg.vfio_fds.is_some());
            let expected = net_total + vfio_total + iommufd_total;
            if files.len() != expected {
                error!(
                    "Expected {expected} FDs in VmRestore request, received {}",
                    files.len()
                );
                return Err(HttpError::BadRequest);
            }

            // Split in the order net_fds, then vfio_fds, then the iommufd FD.
            let mut files = files;
            if let Some(cfgs) = restore_cfg.net_fds.as_mut() {
                let net_files: Vec<File> = files.drain(..net_total).collect();
                let mut cfgs = cfgs.iter_mut().collect::<Vec<&mut _>>();
                attach_fds_to_cfgs(net_files, cfgs.as_mut_slice())?;
            }
            if let Some(cfgs) = restore_cfg.vfio_fds.as_mut() {
                let vfio_files: Vec<File> = files.drain(..vfio_total).collect();
                let mut cfgs = cfgs.iter_mut().collect::<Vec<&mut _>>();
                attach_fds_to_cfgs(vfio_files, cfgs.as_mut_slice())?;
            }
            if restore_cfg.vfio_fds.is_some() {
                restore_cfg.iommufd_fd = ExternalFd::from(files.remove(0));
            }

            self.send(api_notifier, api_sender, restore_cfg)
                .map_err(HttpError::ApiError)
        } else {
            Err(HttpError::BadRequest)
        }
    }
}

impl GetHandler for VmRestore {}

// Custom handler so the SCM_RIGHTS file pool can be split the same way
// VmRestore does, cdev FDs for the vfio_fds entries then the iommufd FD.
impl PutHandler for VmReceiveMigration {
    fn handle_request(
        &'static self,
        api_notifier: EventFd,
        api_sender: Sender<ApiRequest>,
        body: &Option<Body>,
        files: Vec<File>,
    ) -> result::Result<Option<Body>, HttpError> {
        if let Some(body) = body {
            let mut data: VmReceiveMigrationData = serde_json::from_slice(body.raw())?;

            let vfio_total = data.vfio_fds.as_ref().map_or(0, |c| c.len());
            let expected = if data.vfio_fds.is_some() {
                vfio_total + 1
            } else {
                0
            };
            if files.len() != expected {
                error!(
                    "Expected {expected} FDs in VmReceiveMigration request, received {}",
                    files.len()
                );
                return Err(HttpError::BadRequest);
            }

            // Split in the order vfio_fds, then the iommufd FD.
            let mut files = files;
            if let Some(cfgs) = data.vfio_fds.as_mut() {
                let vfio_files: Vec<File> = files.drain(..vfio_total).collect();
                let mut cfgs = cfgs.iter_mut().collect::<Vec<&mut _>>();
                attach_fds_to_cfgs(vfio_files, cfgs.as_mut_slice())?;
            }
            if data.vfio_fds.is_some() {
                data.iommufd_fd = ExternalFd::from(files.remove(0));
            }

            self.send(api_notifier, api_sender, data)
                .map_err(HttpError::ApiError)
        } else {
            Err(HttpError::BadRequest)
        }
    }
}

impl GetHandler for VmReceiveMigration {}

// Common handler for boot, shutdown and reboot
pub struct VmActionHandler {
    action: &'static dyn HttpVmAction,
}

impl VmActionHandler {
    pub fn new(action: &'static dyn HttpVmAction) -> Self {
        VmActionHandler { action }
    }
}

impl EndpointHandler for VmActionHandler {
    fn put_handler(
        &self,
        api_notifier: EventFd,
        api_sender: Sender<ApiRequest>,
        body: &Option<Body>,
        files: Vec<File>,
    ) -> result::Result<Option<Body>, HttpError> {
        PutHandler::handle_request(self.action, api_notifier, api_sender, body, files)
    }

    fn get_handler(
        &self,
        api_notifier: EventFd,
        api_sender: Sender<ApiRequest>,
        _body: &Option<Body>,
    ) -> result::Result<Option<Body>, HttpError> {
        GetHandler::handle_request(self.action, api_notifier, api_sender)
    }
}

// /api/v1/vm.info handler
pub struct VmInfo {}

impl EndpointHandler for VmInfo {
    fn handle_request(
        &self,
        req: &Request,
        api_notifier: EventFd,
        api_sender: Sender<ApiRequest>,
    ) -> Response {
        match req.method() {
            Method::Get => match api::VmInfo
                .send(api_notifier, api_sender, ())
                .map_err(HttpError::ApiError)
            {
                Ok(info) => {
                    let mut response = Response::new(Version::Http11, StatusCode::OK);
                    let info_serialized = serde_json::to_string(&info).unwrap();

                    response.set_body(Body::new(info_serialized));
                    response
                }
                Err(e) => error_response(e),
            },
            _ => error_response(HttpError::BadRequest),
        }
    }
}

// /api/v1/vm.balloon-stats handler
pub struct VmBalloonStats {}

impl EndpointHandler for VmBalloonStats {
    fn handle_request(
        &self,
        req: &Request,
        api_notifier: EventFd,
        api_sender: Sender<ApiRequest>,
    ) -> Response {
        match req.method() {
            Method::Get => match api::VmBalloonStats
                .send(api_notifier, api_sender, ())
                .map_err(HttpError::ApiError)
            {
                Ok(stats) => {
                    let mut response = Response::new(Version::Http11, StatusCode::OK);
                    response.set_body(Body::new(serde_json::to_string(&stats).unwrap()));
                    response
                }
                Err(e) => error_response(e),
            },
            _ => error_response(HttpError::BadRequest),
        }
    }
}

// /api/v1/vmm.info handler
pub struct VmmPing {}

impl EndpointHandler for VmmPing {
    fn handle_request(
        &self,
        req: &Request,
        api_notifier: EventFd,
        api_sender: Sender<ApiRequest>,
    ) -> Response {
        match req.method() {
            Method::Get => match api::VmmPing
                .send(api_notifier, api_sender, ())
                .map_err(HttpError::ApiError)
            {
                Ok(pong) => {
                    let mut response = Response::new(Version::Http11, StatusCode::OK);
                    let info_serialized = serde_json::to_string(&pong).unwrap();

                    response.set_body(Body::new(info_serialized));
                    response
                }
                Err(e) => error_response(e),
            },

            _ => error_response(HttpError::BadRequest),
        }
    }
}

// /api/v1/vmm.shutdown handler
pub struct VmmShutdown {}

impl EndpointHandler for VmmShutdown {
    fn handle_request(
        &self,
        req: &Request,
        api_notifier: EventFd,
        api_sender: Sender<ApiRequest>,
    ) -> Response {
        match req.method() {
            Method::Put => {
                match api::VmmShutdown
                    .send(api_notifier, api_sender, ())
                    .map_err(HttpError::ApiError)
                {
                    Ok(_) => Response::new(Version::Http11, StatusCode::OK),
                    Err(e) => error_response(e),
                }
            }
            _ => error_response(HttpError::BadRequest),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;

    use super::*;
    use crate::config::RestoredNetConfig;
    use crate::tests::test_fd;

    #[test]
    fn test_fds_provided_via_http_api_are_reset() {
        let mut config: NetConfig = serde_json::from_str(r#"{"fds":[1,2,3]}"#).unwrap();
        attach_fds_to_cfg(vec![], &mut config).unwrap();
        assert!(config.fds.is_none());
    }

    #[test]
    fn test_new_device_cfg_takes_all_fds() {
        let files: Vec<_> = (0..3).map(|_| test_fd()).collect();
        let fds: Vec<_> = files.iter().map(AsRawFd::as_raw_fd).collect();
        let mut config: NetConfig = serde_json::from_str("{}").unwrap();
        attach_fds_to_cfg(files, &mut config).unwrap();
        let actual: Vec<_> = config
            .fds
            .unwrap()
            .iter()
            .map(|fd| fd.as_ref().unwrap().as_raw_fd())
            .collect();
        assert_eq!(actual, fds);
    }

    #[test]
    fn test_restore_cfgs_take_only_their_fds() {
        let files: Vec<_> = (0..6).map(|_| test_fd()).collect();
        let fds: Vec<_> = files.iter().map(AsRawFd::as_raw_fd).collect();
        let mut configs: Vec<_> = [3, 1, 0, 2]
            .into_iter()
            .map(|num_fds| RestoredNetConfig {
                num_fds,
                ..Default::default()
            })
            .collect();
        attach_fds_to_cfgs(files, &mut configs.iter_mut().collect::<Vec<_>>()).unwrap();
        let expected = [Some(&fds[..3]), Some(&fds[3..4]), None, Some(&fds[4..])];
        for (config, expected) in configs.iter().zip(expected) {
            let actual: Option<Vec<_>> = config.fds.as_ref().map(|fds| {
                fds.iter()
                    .map(|fd| fd.as_ref().unwrap().as_raw_fd())
                    .collect()
            });
            assert_eq!(actual.as_deref(), expected);
        }
    }
}
