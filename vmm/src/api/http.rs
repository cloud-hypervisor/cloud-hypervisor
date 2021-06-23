// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::api::http_endpoint::{VmActionHandler, VmCreate, VmInfo, VmmPing, VmmShutdown};
use crate::api::{ApiError, ApiRequest, VmAction};
use crate::seccomp_filters::{get_seccomp_filter, Thread};
use crate::{Error, Result};
use micro_http::{Body, HttpServer, MediaType, Method, Request, Response, StatusCode, Version};
use seccomp::{SeccompAction, SeccompFilter};
use serde_json::Error as SerdeError;
use std::collections::HashMap;
use std::os::unix::io::{IntoRawFd, RawFd};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread;
use vmm_sys_util::eventfd::EventFd;

/// Errors associated with VMM management
#[derive(Debug)]
pub enum HttpError {
    /// API request receive error
    SerdeJsonDeserialize(SerdeError),

    /// Attempt to access unsupported HTTP method
    BadRequest,

    /// Undefined endpoints
    NotFound,

    /// Internal Server Error
    InternalServerError,

    /// Could not create a VM
    VmCreate(ApiError),

    /// Could not boot a VM
    VmBoot(ApiError),

    /// Could not delete a VM
    VmDelete(ApiError),

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

    /// Could not snapshot a VM
    VmSnapshot(ApiError),

    /// Could not restore a VM
    VmRestore(ApiError),

    /// Could not act on a VM
    VmAction(ApiError),

    /// Could not resize a VM
    VmResize(ApiError),

    /// Could not resize a memory zone
    VmResizeZone(ApiError),

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

    /// Could not add a fs to a VM
    VmAddFs(ApiError),

    /// Could not add a pmem device to a VM
    VmAddPmem(ApiError),

    /// Could not add a network device to a VM
    VmAddNet(ApiError),

    /// Could not add a vsock device to a VM
    VmAddVsock(ApiError),

    /// Could not get counters from VM
    VmCounters(ApiError),

    /// Error setting up migration received
    VmReceiveMigration(ApiError),

    /// Error setting up migration sender
    VmSendMigration(ApiError),

    /// Error activating power button
    VmPowerButton(ApiError),
}

impl From<serde_json::Error> for HttpError {
    fn from(e: serde_json::Error) -> Self {
        HttpError::SerdeJsonDeserialize(e)
    }
}

const HTTP_ROOT: &str = "/api/v1";

pub fn error_response(error: HttpError, status: StatusCode) -> Response {
    let mut response = Response::new(Version::Http11, status);
    response.set_body(Body::new(format!("{:?}", error)));

    response
}

/// An HTTP endpoint handler interface
pub trait EndpointHandler: Sync + Send {
    /// Handles an HTTP request.
    /// After parsing the request, the handler could decide to send an
    /// associated API request down to the VMM API server to e.g. create
    /// or start a VM. The request will block waiting for an answer from the
    /// API server and translate that into an HTTP response.
    fn handle_request(
        &self,
        req: &Request,
        api_notifier: EventFd,
        api_sender: Sender<ApiRequest>,
    ) -> Response {
        let res = match req.method() {
            Method::Put => self.put_handler(api_notifier, api_sender, &req.body),
            Method::Get => self.get_handler(api_notifier, api_sender, &req.body),
            _ => return Response::new(Version::Http11, StatusCode::BadRequest),
        };

        match res {
            Ok(response_body) => {
                if let Some(body) = response_body {
                    let mut response = Response::new(Version::Http11, StatusCode::OK);
                    response.set_body(body);
                    response
                } else {
                    Response::new(Version::Http11, StatusCode::NoContent)
                }
            }
            Err(e @ HttpError::BadRequest) => error_response(e, StatusCode::BadRequest),
            Err(e @ HttpError::SerdeJsonDeserialize(_)) => {
                error_response(e, StatusCode::BadRequest)
            }
            Err(e) => error_response(e, StatusCode::InternalServerError),
        }
    }

    fn put_handler(
        &self,
        _api_notifier: EventFd,
        _api_sender: Sender<ApiRequest>,
        _body: &Option<Body>,
    ) -> std::result::Result<Option<Body>, HttpError> {
        Err(HttpError::BadRequest)
    }

    fn get_handler(
        &self,
        _api_notifier: EventFd,
        _api_sender: Sender<ApiRequest>,
        _body: &Option<Body>,
    ) -> std::result::Result<Option<Body>, HttpError> {
        Err(HttpError::BadRequest)
    }
}

/// An HTTP routes structure.
pub struct HttpRoutes {
    /// routes is a hash table mapping endpoint URIs to their endpoint handlers.
    pub routes: HashMap<String, Box<dyn EndpointHandler + Sync + Send>>,
}

macro_rules! endpoint {
    ($path:expr) => {
        format!("{}{}", HTTP_ROOT, $path)
    };
}

lazy_static! {
    /// HTTP_ROUTES contain all the cloud-hypervisor HTTP routes.
    pub static ref HTTP_ROUTES: HttpRoutes = {
        let mut r = HttpRoutes {
            routes: HashMap::new(),
        };

        r.routes.insert(endpoint!("/vm.add-device"), Box::new(VmActionHandler::new(VmAction::AddDevice(Arc::default()))));
        r.routes.insert(endpoint!("/vm.add-disk"), Box::new(VmActionHandler::new(VmAction::AddDisk(Arc::default()))));
        r.routes.insert(endpoint!("/vm.add-fs"), Box::new(VmActionHandler::new(VmAction::AddFs(Arc::default()))));
        r.routes.insert(endpoint!("/vm.add-net"), Box::new(VmActionHandler::new(VmAction::AddNet(Arc::default()))));
        r.routes.insert(endpoint!("/vm.add-pmem"), Box::new(VmActionHandler::new(VmAction::AddPmem(Arc::default()))));
        r.routes.insert(endpoint!("/vm.add-vsock"), Box::new(VmActionHandler::new(VmAction::AddVsock(Arc::default()))));
        r.routes.insert(endpoint!("/vm.boot"), Box::new(VmActionHandler::new(VmAction::Boot)));
        r.routes.insert(endpoint!("/vm.counters"), Box::new(VmActionHandler::new(VmAction::Counters)));
        r.routes.insert(endpoint!("/vm.create"), Box::new(VmCreate {}));
        r.routes.insert(endpoint!("/vm.delete"), Box::new(VmActionHandler::new(VmAction::Delete)));
        r.routes.insert(endpoint!("/vm.info"), Box::new(VmInfo {}));
        r.routes.insert(endpoint!("/vm.pause"), Box::new(VmActionHandler::new(VmAction::Pause)));
        r.routes.insert(endpoint!("/vm.power-button"), Box::new(VmActionHandler::new(VmAction::PowerButton)));
        r.routes.insert(endpoint!("/vm.reboot"), Box::new(VmActionHandler::new(VmAction::Reboot)));
        r.routes.insert(endpoint!("/vm.receive-migration"), Box::new(VmActionHandler::new(VmAction::ReceiveMigration(Arc::default()))));
        r.routes.insert(endpoint!("/vm.remove-device"), Box::new(VmActionHandler::new(VmAction::RemoveDevice(Arc::default()))));
        r.routes.insert(endpoint!("/vm.resize"), Box::new(VmActionHandler::new(VmAction::Resize(Arc::default()))));
        r.routes.insert(endpoint!("/vm.resize-zone"), Box::new(VmActionHandler::new(VmAction::ResizeZone(Arc::default()))));
        r.routes.insert(endpoint!("/vm.restore"), Box::new(VmActionHandler::new(VmAction::Restore(Arc::default()))));
        r.routes.insert(endpoint!("/vm.resume"), Box::new(VmActionHandler::new(VmAction::Resume)));
        r.routes.insert(endpoint!("/vm.send-migration"), Box::new(VmActionHandler::new(VmAction::SendMigration(Arc::default()))));
        r.routes.insert(endpoint!("/vm.shutdown"), Box::new(VmActionHandler::new(VmAction::Shutdown)));
        r.routes.insert(endpoint!("/vm.snapshot"), Box::new(VmActionHandler::new(VmAction::Snapshot(Arc::default()))));
        r.routes.insert(endpoint!("/vmm.ping"), Box::new(VmmPing {}));
        r.routes.insert(endpoint!("/vmm.shutdown"), Box::new(VmmShutdown {}));

        r
    };
}

fn handle_http_request(
    request: &Request,
    api_notifier: &EventFd,
    api_sender: &Sender<ApiRequest>,
) -> Response {
    let path = request.uri().get_abs_path().to_string();
    let mut response = match HTTP_ROUTES.routes.get(&path) {
        Some(route) => match api_notifier.try_clone() {
            Ok(notifier) => route.handle_request(request, notifier, api_sender.clone()),
            Err(_) => error_response(
                HttpError::InternalServerError,
                StatusCode::InternalServerError,
            ),
        },
        None => error_response(HttpError::NotFound, StatusCode::NotFound),
    };

    response.set_server("Cloud Hypervisor API");
    response.set_content_type(MediaType::ApplicationJson);
    response
}

fn start_http_thread(
    mut server: HttpServer,
    api_notifier: EventFd,
    api_sender: Sender<ApiRequest>,
    seccomp_action: &SeccompAction,
) -> Result<thread::JoinHandle<Result<()>>> {
    // Retrieve seccomp filter for API thread
    let api_seccomp_filter =
        get_seccomp_filter(seccomp_action, Thread::Api).map_err(Error::CreateSeccompFilter)?;

    thread::Builder::new()
        .name("http-server".to_string())
        .spawn(move || {
            // Apply seccomp filter for API thread.
            SeccompFilter::apply(api_seccomp_filter).map_err(Error::ApplySeccompFilter)?;

            server.start_server().unwrap();
            loop {
                match server.requests() {
                    Ok(request_vec) => {
                        for server_request in request_vec {
                            server
                                .respond(server_request.process(|request| {
                                    handle_http_request(request, &api_notifier, &api_sender)
                                }))
                                .or_else(|e| {
                                    error!("HTTP server error on response: {}", e);
                                    Ok(())
                                })?;
                        }
                    }
                    Err(e) => {
                        error!(
                            "HTTP server error on retrieving incoming request. Error: {}",
                            e
                        );
                    }
                }
            }
        })
        .map_err(Error::HttpThreadSpawn)
}

pub fn start_http_path_thread(
    path: &str,
    api_notifier: EventFd,
    api_sender: Sender<ApiRequest>,
    seccomp_action: &SeccompAction,
) -> Result<thread::JoinHandle<Result<()>>> {
    std::fs::remove_file(path).unwrap_or_default();
    let socket_path = PathBuf::from(path);
    let socket_fd = UnixListener::bind(socket_path).map_err(Error::CreateApiServerSocket)?;
    let server =
        HttpServer::new_from_fd(socket_fd.into_raw_fd()).map_err(Error::CreateApiServer)?;
    start_http_thread(server, api_notifier, api_sender, seccomp_action)
}

pub fn start_http_fd_thread(
    fd: RawFd,
    api_notifier: EventFd,
    api_sender: Sender<ApiRequest>,
    seccomp_action: &SeccompAction,
) -> Result<thread::JoinHandle<Result<()>>> {
    let server = HttpServer::new_from_fd(fd).map_err(Error::CreateApiServer)?;
    start_http_thread(server, api_notifier, api_sender, seccomp_action)
}
