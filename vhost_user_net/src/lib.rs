// Copyright 2019 Intel Corporation. All Rights Reserved.
//
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

extern crate log;
extern crate net_util;
extern crate vhost_rs;
extern crate vhost_user_backend;

use libc::{self, EFD_NONBLOCK};
use log::*;
use net_util::{
    open_tap, MacAddr, NetCounters, NetQueuePair, OpenTapError, RxVirtio, Tap, TxVirtio,
};
use option_parser::{OptionParser, OptionParserError};
use std::fmt;
use std::io::{self};
use std::net::Ipv4Addr;
use std::os::unix::io::AsRawFd;
use std::process;
use std::sync::{Arc, Mutex, RwLock};
use std::vec::Vec;
use vhost_rs::vhost_user::message::*;
use vhost_rs::vhost_user::{Error as VhostUserError, Listener};
use vhost_user_backend::{VhostUserBackend, VhostUserDaemon, Vring, VringWorker};
use virtio_bindings::bindings::virtio_net::*;
use virtio_bindings::bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};
use vmm_sys_util::eventfd::EventFd;

pub type VhostUserResult<T> = std::result::Result<T, VhostUserError>;
pub type Result<T> = std::result::Result<T, Error>;
pub type VhostUserBackendResult<T> = std::result::Result<T, std::io::Error>;

#[derive(Debug)]
pub enum Error {
    /// Failed to activate device.
    BadActivate,
    /// Failed to create kill eventfd
    CreateKillEventFd(io::Error),
    /// Failed to add event.
    EpollCtl(io::Error),
    /// Fail to wait event.
    EpollWait(io::Error),
    /// Failed to create EventFd.
    EpollCreateFd,
    /// Failed to read Tap.
    FailedReadTap,
    /// Failed to parse configuration string
    FailedConfigParse(OptionParserError),
    /// Failed to signal used queue.
    FailedSignalingUsedQueue(io::Error),
    /// Failed to handle event other than input event.
    HandleEventNotEpollIn,
    /// Failed to handle unknown event.
    HandleEventUnknownEvent,
    /// Invalid vring address.
    InvalidVringAddr,
    /// No vring call fd to notify.
    NoVringCallFdNotify,
    /// No memory configured.
    NoMemoryConfigured,
    /// Open tap device failed.
    OpenTap(OpenTapError),
    /// No socket provided
    SocketParameterMissing,
    /// Underlying QueuePair error
    NetQueuePair(net_util::NetQueuePairError),
}

pub const SYNTAX: &str = "vhost-user-net backend parameters \
\"ip=<ip_addr>,mask=<net_mask>,socket=<socket_path>,\
num_queues=<number_of_queues>,queue_size=<size_of_each_queue>,tap=<if_name>\"";

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "vhost_user_net_error: {:?}", self)
    }
}

impl std::error::Error for Error {}

impl std::convert::From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        std::io::Error::new(io::ErrorKind::Other, e)
    }
}

struct VhostUserNetThread {
    net: NetQueuePair,
    vring_worker: Option<Arc<VringWorker>>,
    kill_evt: EventFd,
}

impl VhostUserNetThread {
    /// Create a new virtio network device with the given TAP interface.
    fn new(tap: Tap) -> Result<Self> {
        Ok(VhostUserNetThread {
            vring_worker: None,
            kill_evt: EventFd::new(EFD_NONBLOCK).map_err(Error::CreateKillEventFd)?,
            net: NetQueuePair {
                mem: None,
                tap,
                rx: RxVirtio::new(),
                tx: TxVirtio::new(),
                rx_tap_listening: false,
                epoll_fd: None,
                counters: NetCounters::default(),
                tap_event_id: 2,
            },
        })
    }

    pub fn set_vring_worker(&mut self, vring_worker: Option<Arc<VringWorker>>) {
        self.net.epoll_fd = Some(vring_worker.as_ref().unwrap().as_raw_fd());
        self.vring_worker = vring_worker;
    }
}

pub struct VhostUserNetBackend {
    threads: Vec<Mutex<VhostUserNetThread>>,
    num_queues: usize,
    queue_size: u16,
    queues_per_thread: Vec<u64>,
}

impl VhostUserNetBackend {
    fn new(
        ip_addr: Ipv4Addr,
        host_mac: MacAddr,
        netmask: Ipv4Addr,
        num_queues: usize,
        queue_size: u16,
        ifname: Option<&str>,
    ) -> Result<Self> {
        let mut taps = open_tap(
            ifname,
            Some(ip_addr),
            Some(netmask),
            &mut Some(host_mac),
            num_queues / 2,
            None,
        )
        .map_err(Error::OpenTap)?;

        let mut queues_per_thread = Vec::new();
        let mut threads = Vec::new();
        for (i, tap) in taps.drain(..).enumerate() {
            let thread = Mutex::new(VhostUserNetThread::new(tap)?);
            threads.push(thread);
            queues_per_thread.push(0b11 << (i * 2));
        }

        Ok(VhostUserNetBackend {
            threads,
            num_queues,
            queue_size,
            queues_per_thread,
        })
    }
}

impl VhostUserBackend for VhostUserNetBackend {
    fn num_queues(&self) -> usize {
        self.num_queues
    }

    fn max_queue_size(&self) -> usize {
        self.queue_size as usize
    }

    fn features(&self) -> u64 {
        1 << VIRTIO_NET_F_GUEST_CSUM
            | 1 << VIRTIO_NET_F_CSUM
            | 1 << VIRTIO_NET_F_GUEST_TSO4
            | 1 << VIRTIO_NET_F_GUEST_UFO
            | 1 << VIRTIO_NET_F_HOST_TSO4
            | 1 << VIRTIO_NET_F_HOST_UFO
            | 1 << VIRTIO_F_VERSION_1
            | 1 << VIRTIO_RING_F_EVENT_IDX
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::MQ | VhostUserProtocolFeatures::REPLY_ACK
    }

    fn set_event_idx(&mut self, _enabled: bool) {}

    fn update_memory(&mut self, mem: GuestMemoryMmap) -> VhostUserBackendResult<()> {
        for thread in self.threads.iter() {
            thread.lock().unwrap().net.mem = Some(GuestMemoryAtomic::new(mem.clone()));
        }
        Ok(())
    }

    fn handle_event(
        &self,
        device_event: u16,
        evset: epoll::Events,
        vrings: &[Arc<RwLock<Vring>>],
        thread_id: usize,
    ) -> VhostUserBackendResult<bool> {
        if evset != epoll::Events::EPOLLIN {
            return Err(Error::HandleEventNotEpollIn.into());
        }

        let mut thread = self.threads[thread_id].lock().unwrap();
        match device_event {
            0 => {
                let mut vring = vrings[0].write().unwrap();
                if thread
                    .net
                    .resume_rx(&mut vring.mut_queue())
                    .map_err(Error::NetQueuePair)?
                {
                    vring
                        .signal_used_queue()
                        .map_err(Error::FailedSignalingUsedQueue)?
                }
            }
            1 => {
                let mut vring = vrings[1].write().unwrap();
                if thread
                    .net
                    .process_tx(&mut vring.mut_queue())
                    .map_err(Error::NetQueuePair)?
                {
                    vring
                        .signal_used_queue()
                        .map_err(Error::FailedSignalingUsedQueue)?
                }
            }
            2 => {
                let mut vring = vrings[0].write().unwrap();
                if thread
                    .net
                    .process_rx_tap(&mut vring.mut_queue())
                    .map_err(Error::NetQueuePair)?
                {
                    vring
                        .signal_used_queue()
                        .map_err(Error::FailedSignalingUsedQueue)?
                }
            }
            _ => return Err(Error::HandleEventUnknownEvent.into()),
        }

        Ok(false)
    }

    fn exit_event(&self, thread_index: usize) -> Option<(EventFd, Option<u16>)> {
        // The exit event is placed after the queues and the tap event, which
        // is event index 3.
        Some((
            self.threads[thread_index]
                .lock()
                .unwrap()
                .kill_evt
                .try_clone()
                .unwrap(),
            Some(3),
        ))
    }

    fn queues_per_thread(&self) -> Vec<u64> {
        self.queues_per_thread.clone()
    }
}

pub struct VhostUserNetBackendConfig {
    pub ip: Ipv4Addr,
    pub host_mac: MacAddr,
    pub mask: Ipv4Addr,
    pub socket: String,
    pub num_queues: usize,
    pub queue_size: u16,
    pub tap: Option<String>,
}

impl VhostUserNetBackendConfig {
    pub fn parse(backend: &str) -> Result<Self> {
        let mut parser = OptionParser::new();

        parser
            .add("tap")
            .add("ip")
            .add("host_mac")
            .add("mask")
            .add("queue_size")
            .add("num_queues")
            .add("socket");

        parser.parse(backend).map_err(Error::FailedConfigParse)?;

        let tap = parser.get("tap");
        let ip = parser
            .convert("ip")
            .map_err(Error::FailedConfigParse)?
            .unwrap_or_else(|| Ipv4Addr::new(192, 168, 100, 1));
        let host_mac = parser
            .convert("host_mac")
            .map_err(Error::FailedConfigParse)?
            .unwrap_or_else(MacAddr::local_random);
        let mask = parser
            .convert("mask")
            .map_err(Error::FailedConfigParse)?
            .unwrap_or_else(|| Ipv4Addr::new(255, 255, 255, 0));
        let queue_size = parser
            .convert("queue_size")
            .map_err(Error::FailedConfigParse)?
            .unwrap_or(256);
        let num_queues = parser
            .convert("num_queues")
            .map_err(Error::FailedConfigParse)?
            .unwrap_or(2);
        let socket = parser.get("socket").ok_or(Error::SocketParameterMissing)?;

        Ok(VhostUserNetBackendConfig {
            ip,
            host_mac,
            mask,
            socket,
            num_queues,
            queue_size,
            tap,
        })
    }
}

pub fn start_net_backend(backend_command: &str) {
    let backend_config = match VhostUserNetBackendConfig::parse(backend_command) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Failed parsing parameters {:?}", e);
            process::exit(1);
        }
    };

    let tap = if let Some(tap) = backend_config.tap.as_ref() {
        Some(tap.as_str())
    } else {
        None
    };

    let net_backend = Arc::new(RwLock::new(
        VhostUserNetBackend::new(
            backend_config.ip,
            backend_config.host_mac,
            backend_config.mask,
            backend_config.num_queues,
            backend_config.queue_size,
            tap,
        )
        .unwrap(),
    ));

    let listener = Listener::new(&backend_config.socket, true).unwrap();

    let mut net_daemon =
        VhostUserDaemon::new("vhost-user-net-backend".to_string(), net_backend.clone()).unwrap();

    let mut vring_workers = net_daemon.get_vring_workers();

    if vring_workers.len() != net_backend.read().unwrap().threads.len() {
        error!("Number of vring workers must be identical to the number of backend threads");
        process::exit(1);
    }

    for thread in net_backend.read().unwrap().threads.iter() {
        thread
            .lock()
            .unwrap()
            .set_vring_worker(Some(vring_workers.remove(0)));
    }

    if let Err(e) = net_daemon.start(listener) {
        error!(
            "failed to start daemon for vhost-user-net with error: {:?}",
            e
        );
        process::exit(1);
    }

    if let Err(e) = net_daemon.wait() {
        error!("Error from the main thread: {:?}", e);
    }

    for thread in net_backend.read().unwrap().threads.iter() {
        if let Err(e) = thread.lock().unwrap().kill_evt.write(1) {
            error!("Error shutting down worker thread: {:?}", e)
        }
    }
}
