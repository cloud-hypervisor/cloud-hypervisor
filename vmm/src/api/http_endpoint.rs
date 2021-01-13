// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::api::http::{error_response, EndpointHandler, HttpError};
use crate::api::{
    vm_add_device, vm_add_disk, vm_add_fs, vm_add_net, vm_add_pmem, vm_add_vsock, vm_boot,
    vm_counters, vm_create, vm_delete, vm_info, vm_pause, vm_power_button, vm_reboot,
    vm_receive_migration, vm_remove_device, vm_resize, vm_resize_zone, vm_restore, vm_resume,
    vm_send_migration, vm_shutdown, vm_snapshot, vmm_ping, vmm_shutdown, ApiRequest, VmAction,
    VmConfig,
};
use micro_http::{Body, Method, Request, Response, StatusCode, Version};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use vmm_sys_util::eventfd::EventFd;

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
                        let vm_config: VmConfig = match serde_json::from_slice(body.raw())
                            .map_err(HttpError::SerdeJsonDeserialize)
                        {
                            Ok(config) => config,
                            Err(e) => return error_response(e, StatusCode::BadRequest),
                        };

                        // Call vm_create()
                        match vm_create(api_notifier, api_sender, Arc::new(Mutex::new(vm_config)))
                            .map_err(HttpError::VmCreate)
                        {
                            Ok(_) => Response::new(Version::Http11, StatusCode::NoContent),
                            Err(e) => error_response(e, StatusCode::InternalServerError),
                        }
                    }

                    None => Response::new(Version::Http11, StatusCode::BadRequest),
                }
            }

            _ => Response::new(Version::Http11, StatusCode::BadRequest),
        }
    }
}

// Common handler for boot, shutdown and reboot
pub struct VmActionHandler {
    action: VmAction,
}

impl VmActionHandler {
    pub fn new(action: VmAction) -> Self {
        VmActionHandler { action }
    }
}

impl EndpointHandler for VmActionHandler {
    fn put_handler(
        &self,
        api_notifier: EventFd,
        api_sender: Sender<ApiRequest>,
        body: &Option<Body>,
    ) -> std::result::Result<Option<Body>, HttpError> {
        use VmAction::*;
        if let Some(body) = body {
            match self.action {
                AddDevice(_) => vm_add_device(
                    api_notifier,
                    api_sender,
                    Arc::new(serde_json::from_slice(body.raw())?),
                )
                .map_err(HttpError::VmAddDevice),

                AddDisk(_) => vm_add_disk(
                    api_notifier,
                    api_sender,
                    Arc::new(serde_json::from_slice(body.raw())?),
                )
                .map_err(HttpError::VmAddDisk),

                AddFs(_) => vm_add_fs(
                    api_notifier,
                    api_sender,
                    Arc::new(serde_json::from_slice(body.raw())?),
                )
                .map_err(HttpError::VmAddFs),

                AddPmem(_) => vm_add_pmem(
                    api_notifier,
                    api_sender,
                    Arc::new(serde_json::from_slice(body.raw())?),
                )
                .map_err(HttpError::VmAddPmem),

                AddNet(_) => vm_add_net(
                    api_notifier,
                    api_sender,
                    Arc::new(serde_json::from_slice(body.raw())?),
                )
                .map_err(HttpError::VmAddNet),

                AddVsock(_) => vm_add_vsock(
                    api_notifier,
                    api_sender,
                    Arc::new(serde_json::from_slice(body.raw())?),
                )
                .map_err(HttpError::VmAddVsock),

                RemoveDevice(_) => vm_remove_device(
                    api_notifier,
                    api_sender,
                    Arc::new(serde_json::from_slice(body.raw())?),
                )
                .map_err(HttpError::VmRemoveDevice),

                Resize(_) => vm_resize(
                    api_notifier,
                    api_sender,
                    Arc::new(serde_json::from_slice(body.raw())?),
                )
                .map_err(HttpError::VmResize),

                ResizeZone(_) => vm_resize_zone(
                    api_notifier,
                    api_sender,
                    Arc::new(serde_json::from_slice(body.raw())?),
                )
                .map_err(HttpError::VmResizeZone),

                Restore(_) => vm_restore(
                    api_notifier,
                    api_sender,
                    Arc::new(serde_json::from_slice(body.raw())?),
                )
                .map_err(HttpError::VmRestore),

                Snapshot(_) => vm_snapshot(
                    api_notifier,
                    api_sender,
                    Arc::new(serde_json::from_slice(body.raw())?),
                )
                .map_err(HttpError::VmSnapshot),

                ReceiveMigration(_) => vm_receive_migration(
                    api_notifier,
                    api_sender,
                    Arc::new(serde_json::from_slice(body.raw())?),
                )
                .map_err(HttpError::VmReceiveMigration),

                SendMigration(_) => vm_send_migration(
                    api_notifier,
                    api_sender,
                    Arc::new(serde_json::from_slice(body.raw())?),
                )
                .map_err(HttpError::VmSendMigration),

                _ => Err(HttpError::BadRequest),
            }
        } else {
            match self.action {
                Boot => vm_boot(api_notifier, api_sender).map_err(HttpError::VmBoot),
                Delete => vm_delete(api_notifier, api_sender).map_err(HttpError::VmDelete),
                Shutdown => vm_shutdown(api_notifier, api_sender).map_err(HttpError::VmShutdown),
                Reboot => vm_reboot(api_notifier, api_sender).map_err(HttpError::VmReboot),
                Pause => vm_pause(api_notifier, api_sender).map_err(HttpError::VmPause),
                Resume => vm_resume(api_notifier, api_sender).map_err(HttpError::VmResume),
                PowerButton => {
                    vm_power_button(api_notifier, api_sender).map_err(HttpError::VmPowerButton)
                }
                _ => Err(HttpError::BadRequest),
            }
        }
    }

    fn get_handler(
        &self,
        api_notifier: EventFd,
        api_sender: Sender<ApiRequest>,
        _body: &Option<Body>,
    ) -> std::result::Result<Option<Body>, HttpError> {
        use VmAction::*;
        match self.action {
            Counters => vm_counters(api_notifier, api_sender).map_err(HttpError::VmCounters),
            _ => Err(HttpError::BadRequest),
        }
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
            Method::Get => match vm_info(api_notifier, api_sender).map_err(HttpError::VmInfo) {
                Ok(info) => {
                    let mut response = Response::new(Version::Http11, StatusCode::OK);
                    let info_serialized = serde_json::to_string(&info).unwrap();

                    response.set_body(Body::new(info_serialized));
                    response
                }
                Err(e) => error_response(e, StatusCode::InternalServerError),
            },
            _ => Response::new(Version::Http11, StatusCode::BadRequest),
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
            Method::Get => match vmm_ping(api_notifier, api_sender).map_err(HttpError::VmmPing) {
                Ok(pong) => {
                    let mut response = Response::new(Version::Http11, StatusCode::OK);
                    let info_serialized = serde_json::to_string(&pong).unwrap();

                    response.set_body(Body::new(info_serialized));
                    response
                }
                Err(e) => error_response(e, StatusCode::InternalServerError),
            },
            _ => Response::new(Version::Http11, StatusCode::BadRequest),
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
                match vmm_shutdown(api_notifier, api_sender).map_err(HttpError::VmmShutdown) {
                    Ok(_) => Response::new(Version::Http11, StatusCode::OK),
                    Err(e) => error_response(e, StatusCode::InternalServerError),
                }
            }
            _ => Response::new(Version::Http11, StatusCode::BadRequest),
        }
    }
}
