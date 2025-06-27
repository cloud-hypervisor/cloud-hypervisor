// Copyright © 2019 Intel Corporation
// Copyright 2024 Alyssa Ross <hi@alyssa.is>
//
// SPDX-License-Identifier: Apache-2.0
//

//! # HTTP Endpoints of the Cloud Hypervisor API
//!
//! ## Special Handling for virtio-net Devices Backed by Network File Descriptors (FDs)
//!
//! Some of the HTTP handlers here implement special logic for virtio-net
//! devices **backed by network FDs** to enable live-migration, state save/
//! resume (restore), and similar VM lifecycle events.
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
//! FDs into the VM's configuration, allowing the virtio-net device to
//! function correctly with its backing network resources.
//!
//! We can receive these FDs as we use a **special** HTTP library that is aware
//! of the just described mechanism.
//!
//! [`cmsg(3)`]: https://man7.org/linux/man-pages/man3/cmsg.3.html

use std::fs::File;
use std::os::unix::io::IntoRawFd;
use std::sync::mpsc::Sender;

use micro_http::{Body, Method, Request, Response, StatusCode, Version};
use vmm_sys_util::eventfd::EventFd;

use crate::api::http::{error_response, EndpointHandler, HttpError};
#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
use crate::api::VmCoredump;
use crate::api::{
    AddDisk, ApiAction, ApiError, ApiRequest, NetConfig, VmAddDevice, VmAddFs, VmAddNet, VmAddPmem,
    VmAddUserDevice, VmAddVdpa, VmAddVsock, VmBoot, VmConfig, VmCounters, VmDelete, VmNmi, VmPause,
    VmPowerButton, VmReboot, VmReceiveMigration, VmReceiveMigrationData, VmRemoveDevice, VmResize,
    VmResizeZone, VmRestore, VmResume, VmSendMigration, VmShutdown, VmSnapshot,
};
use crate::config::{RestoreConfig, RestoredNetConfig};
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
                            let mut cfgs = nets.iter_mut().collect::<Vec<&mut _>>();
                            let cfgs = cfgs.as_mut_slice();

                            // For the VmCreate call, we do not accept FDs from the socket currently.
                            // This call sets all FDs to null while doing the same logging as
                            // similar code paths.
                            let res = apply_new_fds_to_cfg::<NetConfig>(
                                vec![],
                                cfgs,
                                &|cfg| cfg.id.as_deref(),
                                &|_| 0,
                                &|cfg| cfg.fds.as_deref(),
                                &|cfg, value| {
                                    assert!(value.is_none());
                                    cfg.fds = None
                                },
                            )
                            .map_err(|e| error_response(e, StatusCode::InternalServerError));

                            if let Err(e) = res {
                                return e;
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
vm_action_put_handler_body!(VmSendMigration);

#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
vm_action_put_handler_body!(VmCoredump);

/// Applies FDs to the network config of a given device, as part of the special
/// handling for virtio-net devices backed by network FDs.
///
/// See [module description] for more info.
///
/// [module description]: self
fn apply_new_fds_to_cfg<T>(
    // List of new files (well, actually FDs) that back up a virtio-net device.
    files: Vec<File>,
    // List of network configurations where each network can have `n` FDs.
    network_cfgs: &mut [&mut T],
    // Callback to return the ID.
    network_cfg_extract_id: &impl Fn(&T) -> Option<&str>,
    // Callback to extract the amount of expected FDs.
    network_cfg_extract_num_fds_fn: &impl Fn(&T) -> usize,
    // Callback to extract the FDs that are part of the type (transmitted via
    // the HTTP body)
    network_cfg_extract_fds_fn: &impl Fn(&T) -> Option<&[i32]>,
    // Callback to set any FDs in the type to the new value. The new value
    // is either `Some` with a non-empty Vector or `None`.
    network_cfg_replace_fds: &impl Fn(&mut T, Option<Vec<i32>>),
) -> Result<(), HttpError> {
    let expected_fds: usize = network_cfgs
        .iter()
        .map(|cfg| network_cfg_extract_num_fds_fn(cfg))
        .sum();

    let mut fds = files
        .into_iter()
        .map(|f| f.into_raw_fd())
        .collect::<Vec<i32>>();

    if fds.len() != expected_fds {
        error!(
            "Number of FDs expected: {}, but received: {}",
            expected_fds,
            fds.len()
        );
        return Err(HttpError::BadRequest);
    }

    for network_cfg in network_cfgs {
        let has_fds_from_http_body = network_cfg_extract_fds_fn(network_cfg).is_some();
        if has_fds_from_http_body {
            // Only FDs transmitted via an SCM_RIGHTS UNIX Domain Socket message
            // are valid. Any provided over the HTTP API are set to `-1` in our
            // specialized serializer callbacks.
            warn!(
                "FD numbers were present in HTTP request body for virtio-net device {:?} but will be ignored",
                network_cfg_extract_id(network_cfg)
            );

            // Reset old value in any case; if there are FDs, they are invalid.
            network_cfg_replace_fds(*network_cfg, None);
        }

        let n = network_cfg_extract_num_fds_fn(network_cfg);
        if n > 0 {
            let new_fds = fds.drain(..n).collect::<Vec<_>>();
            log::debug!("Applying network FDs received via UNIX domain socket to virtio-net device: id={:?}, fds={new_fds:?}", network_cfg_extract_id(network_cfg));
            network_cfg_replace_fds(*network_cfg, Some(new_fds));
        }
    }

    // We checked that `fds.len() != expected_fds`; so if we panic here, we have a hard
    // programming bug
    assert!(fds.is_empty());

    Ok(())
}

impl PutHandler for VmAddNet {
    fn handle_request(
        &'static self,
        api_notifier: EventFd,
        api_sender: Sender<ApiRequest>,
        body: &Option<Body>,
        files: Vec<File>,
    ) -> std::result::Result<Option<Body>, HttpError> {
        if let Some(body) = body {
            let mut net_cfg: NetConfig = serde_json::from_slice(body.raw())?;

            let mut net_cfgs = [&mut net_cfg];
            let num_fds = files.len();
            apply_new_fds_to_cfg::<NetConfig>(
                files,
                &mut net_cfgs,
                &|cfg| cfg.id.as_deref(),
                // We only have one single network here, so it wants all available FDs.
                &|_| num_fds,
                &|cfg| cfg.fds.as_deref(),
                &|cfg, value| {
                    cfg.fds = value;
                },
            )?;

            self.send(api_notifier, api_sender, net_cfg)
                .map_err(HttpError::ApiError)
        } else {
            Err(HttpError::BadRequest)
        }
    }
}

impl GetHandler for VmAddNet {}

// Special Handling for virtio-net Devices Backed by Network File Descriptors
//
// See above.
impl PutHandler for VmReceiveMigration {
    fn handle_request(
        &'static self,
        api_notifier: EventFd,
        api_sender: Sender<ApiRequest>,
        body: &Option<Body>,
        files: Vec<File>,
    ) -> std::result::Result<Option<Body>, HttpError> {
        if let Some(body) = body {
            let mut net_cfg: VmReceiveMigrationData = serde_json::from_slice(body.raw())?;
            if let Some(cfgs) = &mut net_cfg.net_fds {
                let mut cfgs = cfgs.iter_mut().collect::<Vec<&mut _>>();
                let cfgs = cfgs.as_mut_slice();
                apply_new_fds_to_cfg::<RestoredNetConfig>(
                    files,
                    cfgs,
                    &|cfg| Some(&cfg.id),
                    &|cfg| cfg.num_fds,
                    &|cfg| cfg.fds.as_deref(),
                    &|cfg, value| {
                        cfg.fds = value;
                    },
                )?;
            }

            self.send(api_notifier, api_sender, net_cfg)
                .map_err(HttpError::ApiError)
        } else {
            Err(HttpError::BadRequest)
        }
    }
}

impl GetHandler for VmReceiveMigration {}

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
        files: Vec<File>,
    ) -> std::result::Result<Option<Body>, HttpError> {
        if let Some(body) = body {
            let mut restore_cfg: RestoreConfig = serde_json::from_slice(body.raw())?;

            if let Some(cfgs) = restore_cfg.net_fds.as_mut() {
                let mut cfgs = cfgs.iter_mut().collect::<Vec<&mut _>>();
                let cfgs = cfgs.as_mut_slice();
                apply_new_fds_to_cfg::<RestoredNetConfig>(
                    files,
                    cfgs,
                    &|cfg| Some(&cfg.id),
                    &|cfg| cfg.num_fds,
                    &|cfg| cfg.fds.as_deref(),
                    &|cfg, value| {
                        cfg.fds = value;
                    },
                )?;
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
