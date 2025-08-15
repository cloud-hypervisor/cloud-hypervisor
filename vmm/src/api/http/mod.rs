// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::BTreeMap;
use std::error::Error;
use std::fs::File;
use std::os::unix::io::{IntoRawFd, RawFd};
use std::os::unix::net::UnixListener;
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::LazyLock;
use std::sync::mpsc::Sender;
use std::thread;

use hypervisor::HypervisorType;
use micro_http::{
    Body, HttpServer, MediaType, Method, Request, Response, ServerError, StatusCode, Version,
};
use seccompiler::{SeccompAction, apply_filter};
use serde_json::Error as SerdeError;
use thiserror::Error;
use vmm_sys_util::eventfd::EventFd;

use self::http_endpoint::{VmActionHandler, VmCreate, VmInfo, VmmPing, VmmShutdown};
#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
use crate::api::VmCoredump;
use crate::api::{
    AddDisk, ApiError, ApiRequest, VmAddDevice, VmAddFs, VmAddNet, VmAddPmem, VmAddUserDevice,
    VmAddVdpa, VmAddVsock, VmBoot, VmCounters, VmDelete, VmNmi, VmPause, VmPowerButton, VmReboot,
    VmReceiveMigration, VmRemoveDevice, VmResize, VmResizeZone, VmRestore, VmResume,
    VmSendMigration, VmShutdown, VmSnapshot,
};
use crate::landlock::Landlock;
use crate::seccomp_filters::{Thread, get_seccomp_filter};
use crate::{Error as VmmError, Result};

pub mod http_endpoint;

pub type HttpApiHandle = (thread::JoinHandle<Result<()>>, EventFd);

/// Errors associated with VMM management
#[derive(Error, Debug)]
pub enum HttpError {
    /// API request receive error
    #[error("Failed to deserialize JSON")]
    SerdeJsonDeserialize(#[from] SerdeError),

    /// Attempt to access unsupported HTTP method
    #[error("Bad Request")]
    BadRequest,

    /// Undefined endpoints
    #[error("Not Found")]
    NotFound,

    /// Too many requests
    #[error("Too Many Requests")]
    TooManyRequests,

    /// Internal Server Error
    #[error("Internal Server Error")]
    InternalServerError,

    /// Error from internal API
    #[error("Error from API")]
    ApiError(#[source] ApiError),
}

const HTTP_ROOT: &str = "/api/v1";

/// Creates the error response's JSON body meant to be sent back to an API client.
///
/// The error message contained in the response is supposed to be user-facing,
/// thus insightful and helpful while balancing technical accuracy and
/// simplicity.
pub fn error_response(error: HttpError, status: StatusCode) -> Response {
    let mut response = Response::new(Version::Http11, status);

    let error: &dyn Error = &error;
    // Write the Display::display() output all errors (from top to root).
    let error_messages = std::iter::successors(Some(error), |sub_error| {
        // Dereference necessary to mitigate rustc compiler bug.
        // See <https://github.com/rust-lang/rust/issues/141673>
        (*sub_error).source()
    })
    .map(|error| format!("{error}"))
    .collect::<Vec<_>>();

    // TODO: Move `api` module from `vmm` to dedicated crate and use a common type definition
    let json = serde_json::to_string(&error_messages).unwrap();

    let body = Body::new(json);
    response.set_body(body);

    response
}

/// An HTTP endpoint handler interface
pub trait EndpointHandler {
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
        // Cloning the files here is very important as it dup() the file
        // descriptors, leaving open the one that was received. This way,
        // rebooting the VM will work since the VM will be created from the
        // original file descriptors.
        let files = req.files.iter().map(|f| f.try_clone().unwrap()).collect();
        let res = match req.method() {
            Method::Put => self.put_handler(api_notifier, api_sender, &req.body, files),
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
            Err(e @ HttpError::TooManyRequests) => error_response(e, StatusCode::TooManyRequests),
            Err(e) => error_response(e, StatusCode::InternalServerError),
        }
    }

    fn put_handler(
        &self,
        _api_notifier: EventFd,
        _api_sender: Sender<ApiRequest>,
        _body: &Option<Body>,
        _files: Vec<File>,
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
    pub routes: BTreeMap<String, Box<dyn EndpointHandler + Sync + Send>>,
}

macro_rules! endpoint {
    ($path:expr) => {
        format!("{}{}", HTTP_ROOT, $path)
    };
}

/// HTTP_ROUTES contain all the cloud-hypervisor HTTP routes.
pub static HTTP_ROUTES: LazyLock<HttpRoutes> = LazyLock::new(|| {
    let mut r = HttpRoutes {
        routes: BTreeMap::new(),
    };

    r.routes.insert(
        endpoint!("/vm.add-device"),
        Box::new(VmActionHandler::new(&VmAddDevice)),
    );
    r.routes.insert(
        endpoint!("/vm.add-user-device"),
        Box::new(VmActionHandler::new(&VmAddUserDevice)),
    );
    r.routes.insert(
        endpoint!("/vm.add-disk"),
        Box::new(VmActionHandler::new(&AddDisk)),
    );
    r.routes.insert(
        endpoint!("/vm.add-fs"),
        Box::new(VmActionHandler::new(&VmAddFs)),
    );
    r.routes.insert(
        endpoint!("/vm.add-net"),
        Box::new(VmActionHandler::new(&VmAddNet)),
    );
    r.routes.insert(
        endpoint!("/vm.add-pmem"),
        Box::new(VmActionHandler::new(&VmAddPmem)),
    );
    r.routes.insert(
        endpoint!("/vm.add-vdpa"),
        Box::new(VmActionHandler::new(&VmAddVdpa)),
    );
    r.routes.insert(
        endpoint!("/vm.add-vsock"),
        Box::new(VmActionHandler::new(&VmAddVsock)),
    );
    r.routes.insert(
        endpoint!("/vm.boot"),
        Box::new(VmActionHandler::new(&VmBoot)),
    );
    r.routes.insert(
        endpoint!("/vm.counters"),
        Box::new(VmActionHandler::new(&VmCounters)),
    );
    r.routes
        .insert(endpoint!("/vm.create"), Box::new(VmCreate {}));
    r.routes.insert(
        endpoint!("/vm.delete"),
        Box::new(VmActionHandler::new(&VmDelete)),
    );
    r.routes.insert(endpoint!("/vm.info"), Box::new(VmInfo {}));
    r.routes.insert(
        endpoint!("/vm.pause"),
        Box::new(VmActionHandler::new(&VmPause)),
    );
    r.routes.insert(
        endpoint!("/vm.power-button"),
        Box::new(VmActionHandler::new(&VmPowerButton)),
    );
    r.routes.insert(
        endpoint!("/vm.reboot"),
        Box::new(VmActionHandler::new(&VmReboot)),
    );
    r.routes.insert(
        endpoint!("/vm.receive-migration"),
        Box::new(VmActionHandler::new(&VmReceiveMigration)),
    );
    r.routes.insert(
        endpoint!("/vm.remove-device"),
        Box::new(VmActionHandler::new(&VmRemoveDevice)),
    );
    r.routes.insert(
        endpoint!("/vm.resize"),
        Box::new(VmActionHandler::new(&VmResize)),
    );
    r.routes.insert(
        endpoint!("/vm.resize-zone"),
        Box::new(VmActionHandler::new(&VmResizeZone)),
    );
    r.routes.insert(
        endpoint!("/vm.restore"),
        Box::new(VmActionHandler::new(&VmRestore)),
    );
    r.routes.insert(
        endpoint!("/vm.resume"),
        Box::new(VmActionHandler::new(&VmResume)),
    );
    r.routes.insert(
        endpoint!("/vm.send-migration"),
        Box::new(VmActionHandler::new(&VmSendMigration)),
    );
    r.routes.insert(
        endpoint!("/vm.shutdown"),
        Box::new(VmActionHandler::new(&VmShutdown)),
    );
    r.routes.insert(
        endpoint!("/vm.snapshot"),
        Box::new(VmActionHandler::new(&VmSnapshot)),
    );
    #[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
    r.routes.insert(
        endpoint!("/vm.coredump"),
        Box::new(VmActionHandler::new(&VmCoredump)),
    );
    r.routes
        .insert(endpoint!("/vmm.ping"), Box::new(VmmPing {}));
    r.routes
        .insert(endpoint!("/vmm.shutdown"), Box::new(VmmShutdown {}));
    r.routes
        .insert(endpoint!("/vm.nmi"), Box::new(VmActionHandler::new(&VmNmi)));

    r
});

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
    exit_evt: EventFd,
    hypervisor_type: HypervisorType,
    landlock_enable: bool,
) -> Result<HttpApiHandle> {
    // Retrieve seccomp filter for API thread
    let api_seccomp_filter = get_seccomp_filter(seccomp_action, Thread::HttpApi, hypervisor_type)
        .map_err(VmmError::CreateSeccompFilter)?;

    let api_shutdown_fd = EventFd::new(libc::EFD_NONBLOCK).map_err(VmmError::EventFdCreate)?;
    let api_shutdown_fd_clone = api_shutdown_fd.try_clone().unwrap();

    server
        .add_kill_switch(api_shutdown_fd_clone)
        .map_err(VmmError::CreateApiServer)?;

    let thread = thread::Builder::new()
        .name("http-server".to_string())
        .spawn(move || {
            // Apply seccomp filter for API thread.
            if !api_seccomp_filter.is_empty() {
                apply_filter(&api_seccomp_filter)
                    .map_err(VmmError::ApplySeccompFilter)
                    .map_err(|e| {
                        error!("Error applying seccomp filter: {:?}", e);
                        exit_evt.write(1).ok();
                        e
                    })?;
            }

            if landlock_enable {
                Landlock::new()
                    .map_err(VmmError::CreateLandlock)?
                    .restrict_self()
                    .map_err(VmmError::ApplyLandlock)
                    .map_err(|e| {
                        error!("Error applying landlock to http-server thread: {:?}", e);
                        exit_evt.write(1).ok();
                        e
                    })?;
            }

            std::panic::catch_unwind(AssertUnwindSafe(move || {
                server.start_server().unwrap();
                loop {
                    match server.requests() {
                        Ok(request_vec) => {
                            for server_request in request_vec {
                                if let Err(e) = server.respond(server_request.process(|request| {
                                    handle_http_request(request, &api_notifier, &api_sender)
                                })) {
                                    error!("HTTP server error on response: {}", e);
                                }
                            }
                        }
                        Err(ServerError::ShutdownEvent) => {
                            server.flush_outgoing_writes();
                            return;
                        }
                        Err(e) => {
                            error!(
                                "HTTP server error on retrieving incoming request. Error: {}",
                                e
                            );
                        }
                    }
                }
            }))
            .map_err(|_| {
                error!("http-server thread panicked");
                exit_evt.write(1).ok()
            })
            .ok();

            Ok(())
        })
        .map_err(VmmError::HttpThreadSpawn)?;

    Ok((thread, api_shutdown_fd))
}

pub fn start_http_path_thread(
    path: &str,
    api_notifier: EventFd,
    api_sender: Sender<ApiRequest>,
    seccomp_action: &SeccompAction,
    exit_evt: EventFd,
    hypervisor_type: HypervisorType,
    landlock_enable: bool,
) -> Result<HttpApiHandle> {
    let socket_path = PathBuf::from(path);
    let socket_fd = UnixListener::bind(socket_path).map_err(VmmError::CreateApiServerSocket)?;
    // SAFETY: Valid FD just opened
    let server = unsafe { HttpServer::new_from_fd(socket_fd.into_raw_fd()) }
        .map_err(VmmError::CreateApiServer)?;

    start_http_thread(
        server,
        api_notifier,
        api_sender,
        seccomp_action,
        exit_evt,
        hypervisor_type,
        landlock_enable,
    )
}

pub fn start_http_fd_thread(
    fd: RawFd,
    api_notifier: EventFd,
    api_sender: Sender<ApiRequest>,
    seccomp_action: &SeccompAction,
    exit_evt: EventFd,
    hypervisor_type: HypervisorType,
    landlock_enable: bool,
) -> Result<HttpApiHandle> {
    // SAFETY: Valid FD
    let server = unsafe { HttpServer::new_from_fd(fd) }.map_err(VmmError::CreateApiServer)?;
    start_http_thread(
        server,
        api_notifier,
        api_sender,
        seccomp_action,
        exit_evt,
        hypervisor_type,
        landlock_enable,
    )
}

pub fn http_api_graceful_shutdown(http_handle: HttpApiHandle) -> Result<()> {
    let (api_thread, api_shutdown_fd) = http_handle;

    api_shutdown_fd.write(1).unwrap();
    api_thread.join().map_err(VmmError::ThreadCleanup)?
}
