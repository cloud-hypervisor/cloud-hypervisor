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
use futures::executor::{ThreadPool, ThreadPoolBuilder};
use libc::EFD_NONBLOCK;
use log::*;
use std::num::Wrapping;
use std::os::unix::io::RawFd;
use std::sync::{Arc, RwLock};
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
use vm_memory::{GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};
use vm_virtio::net_util::{register_listener, unregister_listener};
use vm_virtio::queue::DescriptorChain;
use vmm_sys_util::eventfd::EventFd;

const QUEUE_SIZE: usize = 1024;
const NUM_QUEUES: usize = 2;
const THREAD_POOL_SIZE: usize = 64;

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
    /// Failed to create EventFd.
    EpollCreateFd(io::Error),
    /// Failed to create kill eventfd.
    CreateKillEventFd(io::Error),
    /// Failed to create thread pool.
    CreateThreadPool(io::Error),
    /// Failed register listener for vring.
    FailedRegisterListener,
    /// Failed unregister listener for vring.
    FailedUnRegisterListener,
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
    mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    kill_evt: EventFd,
    server: Arc<Server<F>>,
    // handle request from slave to master
    vu_req: Option<SlaveFsCacheReq>,
    event_idx: bool,
    pool: ThreadPool,
    epoll_fd: RawFd,
}

impl<F: FileSystem + Send + Sync + 'static> Clone for VhostUserFsBackend<F> {
    fn clone(&self) -> Self {
        VhostUserFsBackend {
            mem: self.mem.clone(),
            kill_evt: self.kill_evt.try_clone().unwrap(),
            server: self.server.clone(),
            vu_req: self.vu_req.clone(),
            event_idx: self.event_idx,
            pool: self.pool.clone(),
            epoll_fd: self.epoll_fd,
        }
    }
}

impl<F: FileSystem + Send + Sync + 'static> VhostUserFsBackend<F> {
    fn new(fs: F, thread_pool_size: usize) -> Result<Self> {
        Ok(VhostUserFsBackend {
            mem: None,
            kill_evt: EventFd::new(EFD_NONBLOCK).map_err(Error::CreateKillEventFd)?,
            server: Arc::new(Server::new(fs)),
            vu_req: None,
            event_idx: false,
            pool: ThreadPoolBuilder::new()
                .pool_size(thread_pool_size)
                .create()
                .map_err(Error::CreateThreadPool)?,
            epoll_fd: epoll::create(true).map_err(Error::EpollCreateFd)?,
        })
    }

    fn process_queue(&mut self, vring_lock: Arc<RwLock<Vring>>) -> Result<bool> {
        let mut used_any = false;
        let (atomic_mem, mem) = match &self.mem {
            Some(m) => (m, m.memory()),
            None => return Err(Error::NoMemoryConfigured),
        };
        let mut vring = vring_lock.write().unwrap();

        while let Some(avail_desc) = vring.mut_queue().iter(&mem).next() {
            used_any = true;

            // Prepare a set of objects that can be moved to the worker thread.
            let desc_head = avail_desc.get_head();
            let atomic_mem = atomic_mem.clone();
            let server = self.server.clone();
            let mut vu_req = self.vu_req.clone();
            let event_idx = self.event_idx;
            let vring_lock = vring_lock.clone();

            self.pool.spawn_ok(async move {
                let mem = atomic_mem.memory();
                let desc = DescriptorChain::new_from_head(&mem, desc_head).unwrap();
                let head_index = desc.index;

                let reader = Reader::new(&mem, desc.clone())
                    .map_err(Error::QueueReader)
                    .unwrap();
                let writer = Writer::new(&mem, desc.clone())
                    .map_err(Error::QueueWriter)
                    .unwrap();

                server
                    .handle_message(reader, writer, vu_req.as_mut())
                    .map_err(Error::ProcessQueue)
                    .unwrap();

                let mut vring = vring_lock.write().unwrap();

                if event_idx {
                    if let Some(used_idx) = vring.mut_queue().add_used(&mem, head_index, 0) {
                        if vring.needs_notification(&mem, Wrapping(used_idx)) {
                            vring.signal_used_queue().unwrap();
                        }
                    }
                } else {
                    vring.mut_queue().add_used(&mem, head_index, 0);
                    vring.signal_used_queue().unwrap();
                }
            });
        }

        Ok(used_any)
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

        let mem = match &self.mem {
            Some(m) => m.memory(),
            None => return Err(Error::NoMemoryConfigured.into()),
        };

        let vring_lock = match device_event {
            HIPRIO_QUEUE_EVENT => {
                debug!("HIPRIO_QUEUE_EVENT");
                vrings[0].clone()
            }
            REQ_QUEUE_EVENT => {
                debug!("QUEUE_EVENT");
                vrings[1].clone()
            }
            _ => return Err(Error::HandleEventUnknownEvent.into()),
        };

        if self.event_idx {
            // vm-virtio's Queue implementation only checks avail_index
            // once, so to properly support EVENT_IDX we need to keep
            // calling process_queue() until it stops finding new
            // requests on the queue.
            loop {
                {
                    let mut vring = vring_lock.write().unwrap();
                    vring.mut_queue().update_avail_event(&mem);
                }
                if !self.process_queue(vring_lock.clone())? {
                    break;
                }
            }
        } else {
            // Without EVENT_IDX, a single call is enough.
            self.process_queue(vring_lock)?;
        }

        Ok(false)
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
        self.mem = Some(GuestMemoryAtomic::new(mem));
        Ok(())
    }

    fn set_slave_req_fd(&mut self, vu_req: SlaveFsCacheReq) {
        self.vu_req = Some(vu_req);
    }

    fn register_listener(&mut self, fd: RawFd, index: u64) -> VhostUserBackendResult<()> {
        register_listener(self.epoll_fd, fd, epoll::Events::EPOLLIN, index)
            .map_err(|_| Error::FailedRegisterListener)?;
        Ok(())
    }

    fn unregister_listener(&mut self, fd: RawFd, index: u64) -> VhostUserBackendResult<()> {
        unregister_listener(self.epoll_fd, fd, epoll::Events::EPOLLIN, index)
            .map_err(|_| Error::FailedUnRegisterListener)?;
        Ok(())
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
        .arg(
            Arg::with_name("thread-pool-size")
                .long("thread-pool-size")
                .help("thread pool size (default 64)")
                .takes_value(true)
                .min_values(1),
        )
        .arg(
            Arg::with_name("disable-xattr")
                .long("disable-xattr")
                .help("Disable support for extended attributes"),
        )
        .get_matches();

    // Retrieve arguments
    let shared_dir = cmd_arguments
        .value_of("shared-dir")
        .expect("Failed to retrieve shared directory path");
    let sock = cmd_arguments
        .value_of("sock")
        .expect("Failed to retrieve vhost-user socket path");
    let thread_pool_size: usize = match cmd_arguments.value_of("thread-pool-size") {
        Some(size) => size.parse().expect("Invalid argument for thread-pool-size"),
        None => THREAD_POOL_SIZE,
    };
    let xattr: bool = !cmd_arguments.is_present("disable-xattr");

    // Convert into appropriate types
    let sock = String::from(sock);

    let fs_cfg = passthrough::Config {
        root_dir: shared_dir.to_string(),
        xattr,
        ..Default::default()
    };
    let fs = PassthroughFs::new(fs_cfg).unwrap();
    let fs_backend = Arc::new(RwLock::new(
        VhostUserFsBackend::new(fs, thread_pool_size).unwrap(),
    ));

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

    let kill_evt = &fs_backend.read().unwrap().kill_evt;
    if let Err(e) = kill_evt.write(1) {
        error!("Error shutting down worker thread: {:?}", e)
    }
}
