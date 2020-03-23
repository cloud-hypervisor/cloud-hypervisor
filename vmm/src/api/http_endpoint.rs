// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::api::http::EndpointHandler;
use crate::api::{
    vm_add_device, vm_add_disk, vm_add_pmem, vm_boot, vm_create, vm_delete, vm_info, vm_pause,
    vm_reboot, vm_remove_device, vm_resize, vm_resume, vm_shutdown, vmm_ping, vmm_shutdown,
    ApiError, ApiRequest, ApiResult, DeviceConfig, DiskConfig, PmemConfig, VmAction, VmConfig,
    VmRemoveDeviceData, VmResizeData,
};
use micro_http::{Body, Method, Request, Response, StatusCode, Version};
use serde_json::Error as SerdeError;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use vmm_sys_util::eventfd::EventFd;

/// Errors associated with VMM management
#[derive(Debug)]
pub enum HttpError {
    /// API request receive error
    SerdeJsonDeserialize(SerdeError),

    /// Could not create a VM
    VmCreate(ApiError),

    /// Could not boot a VM
    VmBoot(ApiError),

    /// Could not get the VM information
    VmInfo(ApiError),

    /// Could not pause the VM
    VmPause(ApiError),

    /// Could not pause the VM
    VmResume(ApiError),

    /// Could not shut a VM down
    VmShutdown(ApiError),

    /// Could not reboot a VM
    VmReboot(ApiError),

    /// Could not act on a VM
    VmAction(ApiError),

    /// Could not resize a VM
    VmResize(ApiError),

    /// Could not add a device to a VM
    VmAddDevice(ApiError),

    /// Could not remove a device from a VM
    VmRemoveDevice(ApiError),

    /// Could not shut the VMM down
    VmmShutdown(ApiError),

    /// Could not handle VMM ping
    VmmPing(ApiError),

    /// Could not add a disk to a VM
    VmAddDisk(ApiError),

    /// Could not add a pmem device to a VM
    VmAddPmem(ApiError),
}

fn error_response(error: HttpError, status: StatusCode) -> Response {
    let mut response = Response::new(Version::Http11, status);
    response.set_body(Body::new(format!("{:?}", error)));

    response
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
    action_fn: VmActionFn,
}

type VmActionFn = Box<dyn Fn(EventFd, Sender<ApiRequest>) -> ApiResult<()> + Send + Sync>;

impl VmActionHandler {
    pub fn new(action: VmAction) -> Self {
        let action_fn = Box::new(match action {
            VmAction::Boot => vm_boot,
            VmAction::Delete => vm_delete,
            VmAction::Shutdown => vm_shutdown,
            VmAction::Reboot => vm_reboot,
            VmAction::Pause => vm_pause,
            VmAction::Resume => vm_resume,
        });

        VmActionHandler { action_fn }
    }
}

impl EndpointHandler for VmActionHandler {
    fn handle_request(
        &self,
        req: &Request,
        api_notifier: EventFd,
        api_sender: Sender<ApiRequest>,
    ) -> Response {
        match req.method() {
            Method::Put => {
                match (self.action_fn)(api_notifier, api_sender).map_err(|e| match e {
                    ApiError::VmBoot(_) => HttpError::VmBoot(e),
                    ApiError::VmShutdown(_) => HttpError::VmShutdown(e),
                    ApiError::VmReboot(_) => HttpError::VmReboot(e),
                    ApiError::VmPause(_) => HttpError::VmPause(e),
                    ApiError::VmResume(_) => HttpError::VmResume(e),
                    _ => HttpError::VmAction(e),
                }) {
                    Ok(_) => Response::new(Version::Http11, StatusCode::NoContent),
                    Err(e) => error_response(e, StatusCode::InternalServerError),
                }
            }
            _ => Response::new(Version::Http11, StatusCode::BadRequest),
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

// /api/v1/vm.resize handler
pub struct VmResize {}

impl EndpointHandler for VmResize {
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
                        let vm_resize_data: VmResizeData = match serde_json::from_slice(body.raw())
                            .map_err(HttpError::SerdeJsonDeserialize)
                        {
                            Ok(config) => config,
                            Err(e) => return error_response(e, StatusCode::BadRequest),
                        };

                        // Call vm_resize()
                        match vm_resize(api_notifier, api_sender, Arc::new(vm_resize_data))
                            .map_err(HttpError::VmResize)
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

// /api/v1/vm.add-device handler
pub struct VmAddDevice {}

impl EndpointHandler for VmAddDevice {
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
                        // Deserialize into a DeviceConfig
                        let vm_add_device_data: DeviceConfig =
                            match serde_json::from_slice(body.raw())
                                .map_err(HttpError::SerdeJsonDeserialize)
                            {
                                Ok(config) => config,
                                Err(e) => return error_response(e, StatusCode::BadRequest),
                            };

                        // Call vm_add_device()
                        match vm_add_device(api_notifier, api_sender, Arc::new(vm_add_device_data))
                            .map_err(HttpError::VmAddDevice)
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

// /api/v1/vm.remove-device handler
pub struct VmRemoveDevice {}

impl EndpointHandler for VmRemoveDevice {
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
                        // Deserialize into a VmRemoveDeviceData
                        let vm_remove_device_data: VmRemoveDeviceData =
                            match serde_json::from_slice(body.raw())
                                .map_err(HttpError::SerdeJsonDeserialize)
                            {
                                Ok(config) => config,
                                Err(e) => return error_response(e, StatusCode::BadRequest),
                            };

                        // Call vm_remove_device()
                        match vm_remove_device(
                            api_notifier,
                            api_sender,
                            Arc::new(vm_remove_device_data),
                        )
                        .map_err(HttpError::VmRemoveDevice)
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

// /api/v1/vm.add-disk handler
pub struct VmAddDisk {}

impl EndpointHandler for VmAddDisk {
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
                        // Deserialize into a DiskConfig
                        let vm_add_disk_data: DiskConfig = match serde_json::from_slice(body.raw())
                            .map_err(HttpError::SerdeJsonDeserialize)
                        {
                            Ok(config) => config,
                            Err(e) => return error_response(e, StatusCode::BadRequest),
                        };

                        // Call vm_add_device()
                        match vm_add_disk(api_notifier, api_sender, Arc::new(vm_add_disk_data))
                            .map_err(HttpError::VmAddDisk)
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

// /api/v1/vm.add-pmem handler
pub struct VmAddPmem {}

impl EndpointHandler for VmAddPmem {
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
                        // Deserialize into a PmemConfig
                        let vm_add_pmem_data: PmemConfig = match serde_json::from_slice(body.raw())
                            .map_err(HttpError::SerdeJsonDeserialize)
                        {
                            Ok(config) => config,
                            Err(e) => return error_response(e, StatusCode::BadRequest),
                        };

                        match vm_add_pmem(api_notifier, api_sender, Arc::new(vm_add_pmem_data))
                            .map_err(HttpError::VmAddPmem)
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
