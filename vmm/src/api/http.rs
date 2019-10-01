// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

extern crate threadpool;

use crate::api::http_endpoint::{VmActionHandler, VmCreate, VmInfo};
use crate::api::{ApiRequest, VmAction};
use crate::{Error, Result};
use micro_http::{HttpConnection, Request, Response, StatusCode, Version};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::sync::mpsc::Sender;
use std::thread;
use threadpool::ThreadPool;
use vmm_sys_util::eventfd::EventFd;

const HTTP_ROOT: &str = "/api/v1";
const NUM_THREADS: usize = 4;

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
        r.routes.insert(endpoint!("/vm.shutdown"), Box::new(VmActionHandler::new(VmAction::Shutdown)));
        r.routes.insert(endpoint!("/vm.reboot"), Box::new(VmActionHandler::new(VmAction::Reboot)));

        r
    };
}

fn http_serve<T: Read + Write>(
    http_connection: &mut HttpConnection<T>,
    api_notifier: EventFd,
    api_sender: Sender<ApiRequest>,
) {
    if http_connection.try_read().is_err() {
        http_connection.enqueue_response(Response::new(
            Version::Http11,
            StatusCode::InternalServerError,
        ));

        return;
    }

    while let Some(request) = http_connection.pop_parsed_request() {
        let sender = api_sender.clone();
        let path = request.uri().get_abs_path().to_string();
        let response = match HTTP_ROUTES.routes.get(&path) {
            Some(route) => match api_notifier.try_clone() {
                Ok(notifier) => route.handle_request(&request, notifier, sender),
                Err(_) => Response::new(Version::Http11, StatusCode::InternalServerError),
            },
            None => Response::new(Version::Http11, StatusCode::NotFound),
        };

        http_connection.enqueue_response(response);
    }
}

pub fn start_http_thread(
    path: &str,
    api_notifier: EventFd,
    api_sender: Sender<ApiRequest>,
) -> Result<thread::JoinHandle<Result<()>>> {
    let listener = UnixListener::bind(path).map_err(Error::Bind)?;
    let pool = ThreadPool::new(NUM_THREADS);

    thread::Builder::new()
        .name("http-server".to_string())
        .spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(s) => {
                        let sender = api_sender.clone();
                        let notifier = api_notifier.try_clone().map_err(Error::EventFdClone)?;

                        pool.execute(move || {
                            let mut http_connection = HttpConnection::new(s);

                            http_serve(&mut http_connection, notifier, sender);

                            // It's ok to panic from a threadpool managed thread,
                            // it won't make parent threads crash.
                            http_connection.try_write().unwrap();
                        });
                    }

                    Err(_) => continue,
                }
            }

            pool.join();

            Ok(())
        })
        .map_err(Error::HttpThreadSpawn)
}
