// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::api::http_endpoint::{
    VmActionHandler, VmAddDevice, VmAddDisk, VmCreate, VmInfo, VmRemoveDevice, VmResize, VmmPing,
    VmmShutdown,
};
use crate::api::{ApiRequest, VmAction};
use crate::seccomp_filters::{get_seccomp_filter, Thread};
use crate::{Error, Result};
use micro_http::{HttpServer, MediaType, Request, Response, StatusCode, Version};
use seccomp::{SeccompFilter, SeccompLevel};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::thread;
use vmm_sys_util::eventfd::EventFd;

const HTTP_ROOT: &str = "/api/v1";

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
    ) -> Response;
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

        r.routes.insert(endpoint!("/vm.create"), Box::new(VmCreate {}));
        r.routes.insert(endpoint!("/vm.boot"), Box::new(VmActionHandler::new(VmAction::Boot)));
        r.routes.insert(endpoint!("/vm.delete"), Box::new(VmActionHandler::new(VmAction::Delete)));
        r.routes.insert(endpoint!("/vm.info"), Box::new(VmInfo {}));
        r.routes.insert(endpoint!("/vm.pause"), Box::new(VmActionHandler::new(VmAction::Pause)));
        r.routes.insert(endpoint!("/vm.resume"), Box::new(VmActionHandler::new(VmAction::Resume)));
        r.routes.insert(endpoint!("/vm.shutdown"), Box::new(VmActionHandler::new(VmAction::Shutdown)));
        r.routes.insert(endpoint!("/vm.reboot"), Box::new(VmActionHandler::new(VmAction::Reboot)));
        r.routes.insert(endpoint!("/vmm.shutdown"), Box::new(VmmShutdown {}));
        r.routes.insert(endpoint!("/vmm.ping"), Box::new(VmmPing {}));
        r.routes.insert(endpoint!("/vm.resize"), Box::new(VmResize {}));
        r.routes.insert(endpoint!("/vm.add-device"), Box::new(VmAddDevice {}));
        r.routes.insert(endpoint!("/vm.remove-device"), Box::new(VmRemoveDevice {}));
        r.routes.insert(endpoint!("/vm.add-disk"), Box::new(VmAddDisk {}));

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
            Ok(notifier) => route.handle_request(&request, notifier, api_sender.clone()),
            Err(_) => Response::new(Version::Http11, StatusCode::InternalServerError),
        },
        None => Response::new(Version::Http11, StatusCode::NotFound),
    };

    response.set_server("Cloud Hypervisor API");
    response.set_content_type(MediaType::ApplicationJson);
    response
}

pub fn start_http_thread(
    path: &str,
    api_notifier: EventFd,
    api_sender: Sender<ApiRequest>,
    seccomp_level: &SeccompLevel,
) -> Result<thread::JoinHandle<Result<()>>> {
    std::fs::remove_file(path).unwrap_or_default();
    let socket_path = PathBuf::from(path);

    // Retrieve seccomp filter for API thread
    let api_seccomp_filter =
        get_seccomp_filter(seccomp_level, Thread::Api).map_err(Error::CreateSeccompFilter)?;

    thread::Builder::new()
        .name("http-server".to_string())
        .spawn(move || {
            // Apply seccomp filter for API thread.
            SeccompFilter::apply(api_seccomp_filter).map_err(Error::ApplySeccompFilter)?;

            let mut server = HttpServer::new(socket_path).unwrap();
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
