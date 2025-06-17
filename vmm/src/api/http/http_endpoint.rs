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
//! [`cmsg(3)`]: https://man7.org/linux/man-pages/man3/cmsg.3.html
//! [special HTTP library]: https://github.com/firecracker-microvm/micro-http

use std::fs::File;
use std::os::unix::io::IntoRawFd;
use std::sync::mpsc::Sender;

use micro_http::{Body, Method, Request, Response, StatusCode, Version};
use vmm_sys_util::eventfd::EventFd;

#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
use crate::api::VmCoredump;
use crate::api::http::{EndpointHandler, HttpError, error_response};
use crate::api::{
    AddDisk, ApiAction, ApiError, ApiRequest, NetConfig, VmAddDevice, VmAddFs, VmAddNet, VmAddPmem,
    VmAddUserDevice, VmAddVdpa, VmAddVsock, VmBoot, VmConfig, VmCounters, VmDelete, VmNmi, VmPause,
    VmPowerButton, VmReboot, VmReceiveMigration, VmRemoveDevice, VmResize, VmResizeZone, VmRestore,
    VmResume, VmSendMigration, VmShutdown, VmSnapshot,
};
use crate::config::RestoreConfig;
use crate::cpu::Error as CpuError;
use crate::vm::Error as VmError;

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
                            Err(e) => return error_response(e, StatusCode::BadRequest),
                        };

                        if let Some(ref mut nets) = vm_config.net {
                            if nets.iter().any(|net| net.fds.is_some()) {
                                warn!("Ignoring FDs sent via the HTTP request body");
                            }
                            for net in nets {
                                net.fds = None;
                            }
                        }

                        match crate::api::VmCreate
                            .send(api_notifier, api_sender, vm_config)
                            .map_err(HttpError::ApiError)
                        {
                            Ok(_) => Response::new(Version::Http11, StatusCode::NoContent),
                            Err(e) => error_response(e, StatusCode::InternalServerError),
                        }
                    }

                    None => Response::new(Version::Http11, StatusCode::BadRequest),
                }
            }

            _ => error_response(HttpError::BadRequest, StatusCode::BadRequest),
        }
    }
}

pub trait GetHandler {
    fn handle_request(
        &'static self,
        _api_notifier: EventFd,
        _api_sender: Sender<ApiRequest>,
    ) -> std::result::Result<Option<Body>, HttpError> {
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
    ) -> std::result::Result<Option<Body>, HttpError> {
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

vm_action_put_handler_body!(VmAddDevice);
vm_action_put_handler_body!(AddDisk);
vm_action_put_handler_body!(VmAddFs);
vm_action_put_handler_body!(VmAddPmem);
vm_action_put_handler_body!(VmAddVdpa);
vm_action_put_handler_body!(VmAddVsock);
vm_action_put_handler_body!(VmAddUserDevice);
vm_action_put_handler_body!(VmRemoveDevice);
vm_action_put_handler_body!(VmResizeZone);
vm_action_put_handler_body!(VmSnapshot);
vm_action_put_handler_body!(VmReceiveMigration);
vm_action_put_handler_body!(VmSendMigration);

#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
vm_action_put_handler_body!(VmCoredump);

// Special handling for virtio-net devices backed by network FDs.
// See module description for more info.
impl PutHandler for VmAddNet {
    fn handle_request(
        &'static self,
        api_notifier: EventFd,
        api_sender: Sender<ApiRequest>,
        body: &Option<Body>,
        mut files: Vec<File>,
    ) -> std::result::Result<Option<Body>, HttpError> {
        if let Some(body) = body {
            let mut net_cfg: NetConfig = serde_json::from_slice(body.raw())?;
            if net_cfg.fds.is_some() {
                warn!("Ignoring FDs sent via the HTTP request body");
                net_cfg.fds = None;
            }
            if !files.is_empty() {
                let fds = files.drain(..).map(|f| f.into_raw_fd()).collect();
                net_cfg.fds = Some(fds);
            }
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
    ) -> std::result::Result<Option<Body>, HttpError> {
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
        mut files: Vec<File>,
    ) -> std::result::Result<Option<Body>, HttpError> {
        if let Some(body) = body {
            let mut restore_cfg: RestoreConfig = serde_json::from_slice(body.raw())?;

            let mut fds = Vec::new();
            if !files.is_empty() {
                fds = files.drain(..).map(|f| f.into_raw_fd()).collect();
            }
            let expected_fds = match restore_cfg.net_fds {
                Some(ref net_fds) => net_fds.iter().map(|net| net.num_fds).sum(),
                None => 0,
            };
            if fds.len() != expected_fds {
                error!(
                    "Number of FDs expected: {}, but received: {}",
                    expected_fds,
                    fds.len()
                );
                return Err(HttpError::BadRequest);
            }
            if let Some(ref mut nets) = restore_cfg.net_fds {
                warn!("Ignoring FDs sent via the HTTP request body");
                let mut start_idx = 0;
                for restored_net in nets.iter_mut() {
                    let end_idx = start_idx + restored_net.num_fds;
                    restored_net.fds = Some(fds[start_idx..end_idx].to_vec());
                    start_idx = end_idx;
                }
            }

            self.send(api_notifier, api_sender, restore_cfg)
                .map_err(HttpError::ApiError)
        } else {
            Err(HttpError::BadRequest)
        }
    }
}

impl GetHandler for VmRestore {}

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
    ) -> std::result::Result<Option<Body>, HttpError> {
        PutHandler::handle_request(self.action, api_notifier, api_sender, body, files)
    }

    fn get_handler(
        &self,
        api_notifier: EventFd,
        api_sender: Sender<ApiRequest>,
        _body: &Option<Body>,
    ) -> std::result::Result<Option<Body>, HttpError> {
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
            Method::Get => match crate::api::VmInfo
                .send(api_notifier, api_sender, ())
                .map_err(HttpError::ApiError)
            {
                Ok(info) => {
                    let mut response = Response::new(Version::Http11, StatusCode::OK);
                    let info_serialized = serde_json::to_string(&info).unwrap();

                    response.set_body(Body::new(info_serialized));
                    response
                }
                Err(e) => error_response(e, StatusCode::InternalServerError),
            },
            _ => error_response(HttpError::BadRequest, StatusCode::BadRequest),
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
            Method::Get => match crate::api::VmmPing
                .send(api_notifier, api_sender, ())
                .map_err(HttpError::ApiError)
            {
                Ok(pong) => {
                    let mut response = Response::new(Version::Http11, StatusCode::OK);
                    let info_serialized = serde_json::to_string(&pong).unwrap();

                    response.set_body(Body::new(info_serialized));
                    response
                }
                Err(e) => error_response(e, StatusCode::InternalServerError),
            },

            _ => error_response(HttpError::BadRequest, StatusCode::BadRequest),
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
                match crate::api::VmmShutdown
                    .send(api_notifier, api_sender, ())
                    .map_err(HttpError::ApiError)
                {
                    Ok(_) => Response::new(Version::Http11, StatusCode::OK),
                    Err(e) => error_response(e, StatusCode::InternalServerError),
                }
            }
            _ => error_response(HttpError::BadRequest, StatusCode::BadRequest),
        }
    }
}
