// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::api::http::{error_response, EndpointHandler, HttpError};
use crate::api::{
    vm_add_device, vm_add_disk, vm_add_fs, vm_add_net, vm_add_pmem, vm_add_vsock, vm_boot,
    vm_create, vm_delete, vm_info, vm_pause, vm_reboot, vm_remove_device, vm_resize, vm_restore,
    vm_resume, vm_shutdown, vm_snapshot, vmm_ping, vmm_shutdown, ApiRequest, DeviceConfig,
    DiskConfig, FsConfig, NetConfig, PmemConfig, RestoreConfig, VmAction, VmConfig,
    VmRemoveDeviceData, VmResizeData, VmSnapshotConfig, VsockConfig,
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
    fn handle_request(
        &self,
        req: &Request,
        api_notifier: EventFd,
        api_sender: Sender<ApiRequest>,
    ) -> Response {
        match req.method() {
            Method::Put => {
                use VmAction::*;
                match match self.action {
                    Boot => vm_boot(api_notifier, api_sender).map_err(HttpError::VmBoot),
                    Delete => vm_delete(api_notifier, api_sender).map_err(HttpError::VmDelete),
                    Shutdown => {
                        vm_shutdown(api_notifier, api_sender).map_err(HttpError::VmShutdown)
                    }
                    Reboot => vm_reboot(api_notifier, api_sender).map_err(HttpError::VmReboot),
                    Pause => vm_pause(api_notifier, api_sender).map_err(HttpError::VmPause),
                    Resume => vm_resume(api_notifier, api_sender).map_err(HttpError::VmResume),
                    _ => Err(HttpError::BadRequest)
                } {
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

// /api/v1/vm.snapshot handler
pub struct VmSnapshot {}

impl EndpointHandler for VmSnapshot {
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
                        // Deserialize into a VmSnapshotConfig
                        let vm_snapshot_data: VmSnapshotConfig =
                            match serde_json::from_slice(body.raw())
                                .map_err(HttpError::SerdeJsonDeserialize)
                            {
                                Ok(data) => data,
                                Err(e) => return error_response(e, StatusCode::BadRequest),
                            };

                        // Call vm_snapshot()
                        match vm_snapshot(api_notifier, api_sender, Arc::new(vm_snapshot_data))
                            .map_err(HttpError::VmSnapshot)
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

// /api/v1/vm.restore handler
pub struct VmRestore {}

impl EndpointHandler for VmRestore {
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
                        // Deserialize into a RestoreConfig
                        let vm_restore_data: RestoreConfig =
                            match serde_json::from_slice(body.raw())
                                .map_err(HttpError::SerdeJsonDeserialize)
                            {
                                Ok(data) => data,
                                Err(e) => return error_response(e, StatusCode::BadRequest),
                            };

                        // Call vm_restore()
                        match vm_restore(api_notifier, api_sender, Arc::new(vm_restore_data))
                            .map_err(HttpError::VmRestore)
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

// /api/v1/vm.add-fs handler
pub struct VmAddFs {}

impl EndpointHandler for VmAddFs {
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
                        // Deserialize into a FsConfig
                        let vm_add_fs_data: FsConfig = match serde_json::from_slice(body.raw())
                            .map_err(HttpError::SerdeJsonDeserialize)
                        {
                            Ok(config) => config,
                            Err(e) => return error_response(e, StatusCode::BadRequest),
                        };

                        // Call vm_add_fs()
                        match vm_add_fs(api_notifier, api_sender, Arc::new(vm_add_fs_data))
                            .map_err(HttpError::VmAddFs)
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

// /api/v1/vm.add-net handler
pub struct VmAddNet {}

impl EndpointHandler for VmAddNet {
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
                        // Deserialize into a NetConfig
                        let vm_add_net_data: NetConfig = match serde_json::from_slice(body.raw())
                            .map_err(HttpError::SerdeJsonDeserialize)
                        {
                            Ok(config) => config,
                            Err(e) => return error_response(e, StatusCode::BadRequest),
                        };

                        match vm_add_net(api_notifier, api_sender, Arc::new(vm_add_net_data))
                            .map_err(HttpError::VmAddNet)
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

// /api/v1/vm.add-vsock handler
pub struct VmAddVsock {}

impl EndpointHandler for VmAddVsock {
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
                        // Deserialize into a VsockConfig
                        let vm_add_vsock_data: VsockConfig =
                            match serde_json::from_slice(body.raw())
                                .map_err(HttpError::SerdeJsonDeserialize)
                            {
                                Ok(config) => config,
                                Err(e) => return error_response(e, StatusCode::BadRequest),
                            };

                        match vm_add_vsock(api_notifier, api_sender, Arc::new(vm_add_vsock_data))
                            .map_err(HttpError::VmAddVsock)
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
