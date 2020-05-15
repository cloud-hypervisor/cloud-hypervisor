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
extern crate vm_virtio;
extern crate vmm;

use epoll;
use libc::{self, EAGAIN, EFD_NONBLOCK};
use log::*;
use net_util::{MacAddr, Tap};
use std::fmt;
use std::io::Read;
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
use vm_memory::GuestMemoryMmap;
use vm_virtio::net_util::{open_tap, RxVirtio, TxVirtio};
use vm_virtio::Queue;
use vmm::config::{OptionParser, OptionParserError};
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
    FailedSignalingUsedQueue,
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
    OpenTap(vm_virtio::net_util::Error),
    /// No socket provided
    SocketParameterMissing,
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
    mem: Option<GuestMemoryMmap>,
    vring_worker: Option<Arc<VringWorker>>,
    kill_evt: EventFd,
    tap: Tap,
    rx: RxVirtio,
    tx: TxVirtio,
    rx_tap_listening: bool,
}

impl VhostUserNetThread {
    /// Create a new virtio network device with the given TAP interface.
    fn new(tap: Tap) -> Result<Self> {
        Ok(VhostUserNetThread {
            mem: None,
            vring_worker: None,
            kill_evt: EventFd::new(EFD_NONBLOCK).map_err(Error::CreateKillEventFd)?,
            tap,
            rx: RxVirtio::new(),
            tx: TxVirtio::new(),
            rx_tap_listening: false,
        })
    }

    // Copies a single frame from `self.rx.frame_buf` into the guest. Returns true
    // if a buffer was used, and false if the frame must be deferred until a buffer
    // is made available by the driver.
    fn rx_single_frame(&mut self, mut queue: &mut Queue) -> Result<bool> {
        let mem = self.mem.as_ref().ok_or(Error::NoMemoryConfigured)?;

        let next_desc = queue.iter(&mem).next();

        if next_desc.is_none() {
            // Queue has no available descriptors
            if self.rx_tap_listening {
                self.vring_worker
                    .as_ref()
                    .unwrap()
                    .unregister_listener(self.tap.as_raw_fd(), epoll::Events::EPOLLIN, 2)
                    .unwrap();
                self.rx_tap_listening = false;
            }
            return Ok(false);
        }

        let write_complete = self.rx.process_desc_chain(&mem, next_desc, &mut queue);

        Ok(write_complete)
    }

    fn process_rx(&mut self, vring: &mut Vring) -> Result<()> {
        // Read as many frames as possible.
        loop {
            match self.read_tap() {
                Ok(count) => {
                    self.rx.bytes_read = count;
                    if !self.rx_single_frame(&mut vring.mut_queue())? {
                        self.rx.deferred_frame = true;
                        break;
                    }
                }
                Err(e) => {
                    // The tap device is non-blocking, so any error aside from EAGAIN is
                    // unexpected.
                    match e.raw_os_error() {
                        Some(err) if err == EAGAIN => (),
                        _ => {
                            error!("Failed to read tap: {:?}", e);
                            return Err(Error::FailedReadTap);
                        }
                    };
                    break;
                }
            }
        }
        if self.rx.deferred_irqs {
            self.rx.deferred_irqs = false;
            vring.signal_used_queue().unwrap();
            Ok(())
        } else {
            Ok(())
        }
    }

    fn resume_rx(&mut self, vring: &mut Vring) -> Result<()> {
        if self.rx.deferred_frame {
            if self.rx_single_frame(&mut vring.mut_queue())? {
                self.rx.deferred_frame = false;
                // process_rx() was interrupted possibly before consuming all
                // packets in the tap; try continuing now.
                self.process_rx(vring)
            } else if self.rx.deferred_irqs {
                self.rx.deferred_irqs = false;
                vring.signal_used_queue().unwrap();
                Ok(())
            } else {
                Ok(())
            }
        } else {
            Ok(())
        }
    }

    fn process_tx(&mut self, mut queue: &mut Queue) -> Result<()> {
        let mem = self.mem.as_ref().ok_or(Error::NoMemoryConfigured)?;

        self.tx.process_desc_chain(&mem, &mut self.tap, &mut queue);

        Ok(())
    }

    fn read_tap(&mut self) -> io::Result<usize> {
        self.tap.read(&mut self.rx.frame_buf)
    }

    pub fn set_vring_worker(&mut self, vring_worker: Option<Arc<VringWorker>>) {
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
            Some(host_mac),
            num_queues / 2,
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
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::all()
    }

    fn set_event_idx(&mut self, _enabled: bool) {}

    fn update_memory(&mut self, mem: GuestMemoryMmap) -> VhostUserBackendResult<()> {
        for thread in self.threads.iter() {
            thread.lock().unwrap().mem = Some(mem.clone());
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
                thread.resume_rx(&mut vrings[0].write().unwrap())?;

                if !thread.rx_tap_listening {
                    thread.vring_worker.as_ref().unwrap().register_listener(
                        thread.tap.as_raw_fd(),
                        epoll::Events::EPOLLIN,
                        2,
                    )?;
                    thread.rx_tap_listening = true;
                }
            }
            1 => {
                thread.process_tx(&mut vrings[1].write().unwrap().mut_queue())?;
            }
            2 => {
                let mut vring = vrings[0].write().unwrap();
                if thread.rx.deferred_frame
                // Process a deferred frame first if available. Don't read from tap again
                // until we manage to receive this deferred frame.
                {
                    if thread.rx_single_frame(&mut vring.mut_queue())? {
                        thread.rx.deferred_frame = false;
                        thread.process_rx(&mut vring)?;
                    } else if thread.rx.deferred_irqs {
                        thread.rx.deferred_irqs = false;
                        vring.signal_used_queue()?;
                    }
                } else {
                    thread.process_rx(&mut vring)?;
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
