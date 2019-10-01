// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::api::http::EndpointHandler;
use crate::api::VmConfig;
use crate::api::{vm_boot, vm_create, vm_info, vm_reboot, vm_shutdown, ApiRequest, VmAction};
use crate::{Error, Result};
use micro_http::{Body, Method, Request, Response, StatusCode, Version};
use serde_json::Error as SerdeError;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use vmm_sys_util::eventfd::EventFd;

/// Errors associated with VMM management
#[derive(Debug)]
pub enum HttpError {
    /// API request receive error
    SerdeJsonDeserialize(SerdeError),

    /// Could not create a VM
    VmCreate(Error),

    /// Could not boot a VM
    VmBoot(Error),

    /// Could not get the VM information
    VmInfo(Error),

    /// Could not shut a VM down
    VmShutdown(Error),

    /// Could not reboot a VM
    VmReboot(Error),

    /// Could not act on a VM
    VmAction(Error),
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
                        match vm_create(api_notifier, api_sender, Arc::new(vm_config))
                            .map_err(HttpError::VmCreate)
                        {
                            Ok(_) => Response::new(Version::Http11, StatusCode::OK),
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

type VmActionFn = Box<dyn Fn(EventFd, Sender<ApiRequest>) -> Result<()> + Send + Sync>;

impl VmActionHandler {
    pub fn new(action: VmAction) -> Self {
        let action_fn = Box::new(match action {
            VmAction::Boot => vm_boot,
            VmAction::Shutdown => vm_shutdown,
            VmAction::Reboot => vm_reboot,
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
                    Error::ApiVmBoot(_) => HttpError::VmBoot(e),
                    Error::ApiVmShutdown(_) => HttpError::VmShutdown(e),
                    Error::ApiVmReboot(_) => HttpError::VmReboot(e),
                    _ => HttpError::VmAction(e),
                }) {
                    Ok(_) => Response::new(Version::Http11, StatusCode::OK),
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
