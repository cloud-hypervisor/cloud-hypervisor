// Copyright 2019 Intel Corporation. All Rights Reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

#[macro_use(crate_version, crate_authors)]
extern crate clap;
extern crate log;
extern crate vhost_rs;
extern crate vhost_user_backend;
extern crate vm_virtio;

use clap::{App, Arg};
use epoll;
use libc::EFD_NONBLOCK;
use log::*;
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, RwLock};
use std::{convert, error, fmt, io, process};

use vhost_rs::vhost_user::message::*;
use vhost_user_backend::{VhostUserBackend, VhostUserDaemon, Vring};
use vhost_user_fs::descriptor_utils::{Reader, Writer};
use vhost_user_fs::filesystem::FileSystem;
use vhost_user_fs::passthrough::{self, PassthroughFs};
use vhost_user_fs::server::Server;
use vhost_user_fs::Error as VhostUserFsError;
use virtio_bindings::bindings::virtio_net::*;
use vm_memory::GuestMemoryMmap;
use vmm_sys_util::eventfd::EventFd;

const QUEUE_SIZE: usize = 1024;
const NUM_QUEUES: usize = 2;

// The guest queued an available buffer for the high priority queue.
const HIPRIO_QUEUE_EVENT: u16 = 0;
// The guest queued an available buffer for the request queue.
const REQ_QUEUE_EVENT: u16 = 1;
// The device has been dropped.
const KILL_EVENT: u16 = 2;

type Result<T> = std::result::Result<T, Error>;
type VhostUserBackendResult<T> = std::result::Result<T, std::io::Error>;

#[derive(Debug)]
enum Error {
    /// Failed to create kill eventfd.
    CreateKillEventFd(io::Error),
    /// Failed to handle event other than input event.
    HandleEventNotEpollIn,
    /// Failed to handle unknown event.
    HandleEventUnknownEvent,
    /// No memory configured.
    NoMemoryConfigured,
    /// Processing queue failed.
    ProcessQueue(VhostUserFsError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "vhost_user_fs_error: {:?}", self)
    }
}

impl error::Error for Error {}

impl convert::From<Error> for io::Error {
    fn from(e: Error) -> Self {
        io::Error::new(io::ErrorKind::Other, e)
    }
}

struct VhostUserFsBackend<F: FileSystem + Send + Sync + 'static> {
    mem: Option<GuestMemoryMmap>,
    kill_evt: EventFd,
    server: Arc<Server<F>>,
}

impl<F: FileSystem + Send + Sync + 'static> Clone for VhostUserFsBackend<F> {
    fn clone(&self) -> Self {
        VhostUserFsBackend {
            mem: self.mem.clone(),
            kill_evt: self.kill_evt.try_clone().unwrap(),
            server: self.server.clone(),
        }
    }
}

impl<F: FileSystem + Send + Sync + 'static> VhostUserFsBackend<F> {
    fn new(fs: F) -> Result<Self> {
        Ok(VhostUserFsBackend {
            mem: None,
            kill_evt: EventFd::new(EFD_NONBLOCK).map_err(Error::CreateKillEventFd)?,
            server: Arc::new(Server::new(fs)),
        })
    }

    fn process_queue(&mut self, vring: &mut Vring) -> Result<()> {
        let mem = self.mem.as_ref().ok_or(Error::NoMemoryConfigured)?;

        let mut used_desc_heads = [(0, 0); QUEUE_SIZE];
        let mut used_count = 0;
        while let Some(avail_desc) = vring.mut_queue().iter(&mem).next() {
            let head_index = avail_desc.index;
            let reader = Reader::new(mem, avail_desc.clone()).unwrap();
            let writer = Writer::new(mem, avail_desc.clone()).unwrap();

            let total = self
                .server
                .handle_message(reader, writer)
                .map_err(Error::ProcessQueue)?;

            used_desc_heads[used_count] = (head_index, total);
            used_count += 1;
        }

        if used_count > 0 {
            for &(desc_index, _) in &used_desc_heads[..used_count] {
                vring.mut_queue().add_used(&mem, desc_index, 0);
            }
            vring.signal_used_queue().unwrap();
        }

        Ok(())
    }
}

impl<F: FileSystem + Send + Sync + 'static> VhostUserBackend for VhostUserFsBackend<F> {
    fn num_queues(&self) -> usize {
        NUM_QUEUES
    }

    fn max_queue_size(&self) -> usize {
        QUEUE_SIZE
    }

    fn features(&self) -> u64 {
        1 << VIRTIO_F_VERSION_1 | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::all()
    }

    fn update_memory(&mut self, mem: GuestMemoryMmap) -> VhostUserBackendResult<()> {
        self.mem = Some(mem);
        Ok(())
    }

    fn handle_event(
        &mut self,
        device_event: u16,
        evset: epoll::Events,
        vrings: &[Arc<RwLock<Vring>>],
    ) -> VhostUserBackendResult<bool> {
        if evset != epoll::Events::EPOLLIN {
            return Err(Error::HandleEventNotEpollIn.into());
        }

        match device_event {
            HIPRIO_QUEUE_EVENT => {
                debug!("HIPRIO_QUEUE_EVENT");
            }
            REQ_QUEUE_EVENT => {
                debug!("REQ_QUEUE_EVENT");
                let mut vring = vrings[1].write().unwrap();
                self.process_queue(&mut vring)?;
            }
            KILL_EVENT => {
                debug!("KILL_EVENT");
                self.kill_evt.read().unwrap();
                return Ok(true);
            }
            _ => return Err(Error::HandleEventUnknownEvent.into()),
        }

        Ok(false)
    }
}

fn main() {
    let cmd_arguments = App::new("vhost-user-fs backend")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Launch a vhost-user-fs backend.")
        .arg(
            Arg::with_name("shared-dir")
                .long("shared-dir")
                .help("Shared directory path")
                .takes_value(true)
                .min_values(1),
        )
        .arg(
            Arg::with_name("sock")
                .long("sock")
                .help("vhost-user socket path")
                .takes_value(true)
                .min_values(1),
        )
        .get_matches();

    // Retrieve arguments
    let shared_dir = cmd_arguments
        .value_of("shared-dir")
        .expect("Failed to retrieve shared directory path");
    let sock = cmd_arguments
        .value_of("sock")
        .expect("Failed to retrieve vhost-user socket path");

    // Convert into appropriate types
    let sock = String::from(sock);

    let fs_cfg = passthrough::Config {
        root_dir: shared_dir.to_string(),
        ..Default::default()
    };
    let fs = PassthroughFs::new(fs_cfg).unwrap();
    let fs_backend = Arc::new(RwLock::new(VhostUserFsBackend::new(fs).unwrap()));

    let mut daemon = VhostUserDaemon::new(
        String::from("vhost-user-fs-backend"),
        sock,
        fs_backend.clone(),
    )
    .unwrap();

    let vring_worker = daemon.get_vring_worker();

    if let Err(e) = vring_worker.register_listener(
        fs_backend.read().unwrap().kill_evt.as_raw_fd(),
        epoll::Events::EPOLLIN,
        u64::from(KILL_EVENT),
    ) {
        error!("Failed to register listener for kill event: {:?}", e);
        process::exit(1);
    }

    if let Err(e) = daemon.start() {
        error!("Failed to start daemon: {:?}", e);
        process::exit(1);
    }

    if let Err(e) = daemon.wait() {
        error!("Waiting for daemon failed: {:?}", e);
    }

    let kill_evt = &fs_backend.read().unwrap().kill_evt;
    if let Err(e) = kill_evt.write(1) {
        error!("Error shutting down worker thread: {:?}", e)
    }
}
