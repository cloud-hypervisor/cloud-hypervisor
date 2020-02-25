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
use std::num::Wrapping;
use std::sync::{Arc, Mutex};
use std::{convert, error, fmt, io, process};

use vhost_rs::vhost_user::message::*;
use vhost_rs::vhost_user::SlaveFsCacheReq;
use vhost_user_backend::{VhostUserBackend, VhostUserDaemon, Vring};
use vhost_user_fs::descriptor_utils::Error as VufDescriptorError;
use vhost_user_fs::descriptor_utils::{Reader, Writer};
use vhost_user_fs::filesystem::FileSystem;
use vhost_user_fs::passthrough::{self, PassthroughFs};
use vhost_user_fs::server::Server;
use vhost_user_fs::Error as VhostUserFsError;
use virtio_bindings::bindings::virtio_net::*;
use virtio_bindings::bindings::virtio_ring::{
    VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC,
};
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
    /// Creating a queue reader failed.
    QueueReader(VufDescriptorError),
    /// Creating a queue writer failed.
    QueueWriter(VufDescriptorError),
    /// Signaling queue failed.
    SignalQueue(io::Error),
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
    // handle request from slave to master
    vu_req: Option<SlaveFsCacheReq>,
    event_idx: bool,
}

impl<F: FileSystem + Send + Sync + 'static> Clone for VhostUserFsBackend<F> {
    fn clone(&self) -> Self {
        VhostUserFsBackend {
            mem: self.mem.clone(),
            kill_evt: self.kill_evt.try_clone().unwrap(),
            server: self.server.clone(),
            vu_req: self.vu_req.clone(),
            event_idx: self.event_idx,
        }
    }
}

impl<F: FileSystem + Send + Sync + 'static> VhostUserFsBackend<F> {
    fn new(fs: F) -> Result<Self> {
        Ok(VhostUserFsBackend {
            mem: None,
            kill_evt: EventFd::new(EFD_NONBLOCK).map_err(Error::CreateKillEventFd)?,
            server: Arc::new(Server::new(fs)),
            vu_req: None,
            event_idx: false,
        })
    }

    fn process_queue(&mut self, vring: &mut Vring) -> Result<bool> {
        let mut used_any = false;
        let mem = self.mem.as_ref().ok_or(Error::NoMemoryConfigured)?;

        while let Some(avail_desc) = vring.mut_queue().iter(&mem).next() {
            let head_index = avail_desc.index;
            let reader = Reader::new(mem, avail_desc.clone()).map_err(Error::QueueReader)?;
            let writer = Writer::new(mem, avail_desc.clone()).map_err(Error::QueueWriter)?;

            self.server
                .handle_message(reader, writer, self.vu_req.as_mut())
                .map_err(Error::ProcessQueue)?;
            if self.event_idx {
                if let Some(used_idx) = vring.mut_queue().add_used(mem, head_index, 0) {
                    let used_event = vring.mut_queue().get_used_event(mem);
                    if vring.needs_notification(Wrapping(used_idx), used_event) {
                        vring.signal_used_queue().map_err(Error::SignalQueue)?;
                    }
                    used_any = true;
                }
            } else {
                vring.mut_queue().add_used(mem, head_index, 0);
                vring.signal_used_queue().map_err(Error::SignalQueue)?;
                used_any = true;
            }
            vring.signal_used_queue().map_err(Error::SignalQueue)?;
        }

        Ok(used_any)
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
        1 << VIRTIO_F_VERSION_1
            | 1 << VIRTIO_RING_F_INDIRECT_DESC
            | 1 << VIRTIO_RING_F_EVENT_IDX
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::MQ | VhostUserProtocolFeatures::SLAVE_REQ
    }

    fn set_event_idx(&mut self, enabled: bool) {
        self.event_idx = enabled;
    }

    fn update_memory(&mut self, mem: GuestMemoryMmap) -> VhostUserBackendResult<()> {
        self.mem = Some(mem);
        Ok(())
    }

    fn handle_event(
        &mut self,
        device_event: u16,
        evset: epoll::Events,
        vrings: &[Arc<Mutex<Vring>>],
    ) -> VhostUserBackendResult<bool> {
        if evset != epoll::Events::EPOLLIN {
            return Err(Error::HandleEventNotEpollIn.into());
        }

        let mut vring = match device_event {
            HIPRIO_QUEUE_EVENT => {
                debug!("HIPRIO_QUEUE_EVENT");
                vrings[0].lock().unwrap()
            }
            REQ_QUEUE_EVENT => {
                debug!("QUEUE_EVENT");
                vrings[1].lock().unwrap()
            }
            _ => return Err(Error::HandleEventUnknownEvent.into()),
        };

        if self.event_idx {
            // vm-virtio's Queue implementation only checks avail_index
            // once, so to properly support EVENT_IDX we need to keep
            // calling process_queue() until it stops finding new
            // requests on the queue.
            loop {
                vring
                    .mut_queue()
                    .update_avail_event(self.mem.as_ref().ok_or(Error::NoMemoryConfigured)?);
                if !self.process_queue(&mut vring)? {
                    break;
                }
            }
        } else {
            // Without EVENT_IDX, a single call is enough.
            self.process_queue(&mut vring)?;
        }

        Ok(false)
    }

    fn exit_event(&self) -> Option<(EventFd, Option<u16>)> {
        Some((self.kill_evt.try_clone().unwrap(), Some(KILL_EVENT)))
    }

    fn set_slave_req_fd(&mut self, vu_req: SlaveFsCacheReq) {
        self.vu_req = Some(vu_req);
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
    let fs_backend = Arc::new(Mutex::new(VhostUserFsBackend::new(fs).unwrap()));

    let mut daemon = VhostUserDaemon::new(
        String::from("vhost-user-fs-backend"),
        sock,
        fs_backend.clone(),
    )
    .unwrap();

    if let Err(e) = daemon.start() {
        error!("Failed to start daemon: {:?}", e);
        process::exit(1);
    }

    if let Err(e) = daemon.wait() {
        error!("Waiting for daemon failed: {:?}", e);
    }

    let kill_evt = &fs_backend.lock().unwrap().kill_evt;
    if let Err(e) = kill_evt.write(1) {
        error!("Error shutting down worker thread: {:?}", e)
    }
}
