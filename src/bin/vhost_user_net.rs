// Copyright 2019 Intel Corporation. All Rights Reserved.
//
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

#[macro_use(crate_version, crate_authors)]
extern crate clap;
extern crate log;
extern crate net_util;
extern crate vhost_rs;
extern crate vhost_user_backend;
extern crate vm_virtio;

use clap::{App, Arg};
use epoll;
use libc::{self, EAGAIN, EFD_NONBLOCK};
use log::*;
use net_util::Tap;
use std::fmt;
use std::io::Read;
use std::io::{self};
use std::net::Ipv4Addr;
use std::os::unix::io::AsRawFd;
use std::process;
use std::sync::{Arc, RwLock};
use std::vec::Vec;
use vhost_rs::vhost_user::message::*;
use vhost_rs::vhost_user::Error as VhostUserError;
use vhost_user_backend::{VhostUserBackend, VhostUserDaemon, Vring, VringWorker};
use virtio_bindings::bindings::virtio_net::*;
use vm_memory::GuestMemoryMmap;
use vm_virtio::net_util::{
    open_tap, RxVirtio, TxVirtio, KILL_EVENT, RX_QUEUE_EVENT, RX_TAP_EVENT, TX_QUEUE_EVENT,
};
use vm_virtio::Queue;
use vmm_sys_util::eventfd::EventFd;

const QUEUE_SIZE: usize = 1024;
const NUM_QUEUES: usize = 2;

pub type VhostUserResult<T> = std::result::Result<T, VhostUserError>;
pub type Result<T> = std::result::Result<T, Error>;
pub type VhostUserBackendResult<T> = std::result::Result<T, std::io::Error>;

#[derive(Debug)]
pub enum Error {
    /// Failed to activate device.
    BadActivate,
    /// Failed to create kill eventfd
    CreateKillEventFd,
    /// Failed to add event.
    EpollCtl(io::Error),
    /// Fail to wait event.
    EpollWait(io::Error),
    /// Failed to create EventFd.
    EpollCreateFd,
    /// Failed to read Tap.
    FailedReadTap,
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
    /// Failed to parse sock parameter.
    ParseSockParam,
    /// Failed to parse ip parameter.
    ParseIpParam,
    /// Failed to parse mask parameter.
    ParseMaskParam,
    /// Open tap device failed.
    OpenTap(vm_virtio::net_util::Error),
}

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

struct VhostUserNetBackend {
    mem: Option<GuestMemoryMmap>,
    vring_worker: Option<Arc<VringWorker>>,
    kill_evt: EventFd,
    tap: Tap,
    rx: RxVirtio,
    tx: TxVirtio,
    rx_tap_listening: bool,
}

impl std::clone::Clone for VhostUserNetBackend {
    fn clone(&self) -> Self {
        VhostUserNetBackend {
            mem: self.mem.clone(),
            vring_worker: self.vring_worker.clone(),
            kill_evt: self.kill_evt.try_clone().unwrap(),
            tap: self.tap.clone(),
            rx: self.rx.clone(),
            tx: self.tx.clone(),
            rx_tap_listening: self.rx_tap_listening,
        }
    }
}

impl VhostUserNetBackend {
    /// Create a new virtio network device with the given TAP interface.
    pub fn new_with_tap(tap: Tap) -> Result<Self> {
        let rx = RxVirtio::new();
        let tx = TxVirtio::new();

        Ok(VhostUserNetBackend {
            mem: None,
            vring_worker: None,
            kill_evt: EventFd::new(EFD_NONBLOCK).map_err(|_| Error::CreateKillEventFd)?,
            tap,
            rx,
            tx,
            rx_tap_listening: false,
        })
    }

    /// Create a new virtio network device with the given IP address and
    /// netmask.
    pub fn new(ip_addr: Ipv4Addr, netmask: Ipv4Addr) -> Result<Self> {
        let tap = open_tap(ip_addr, netmask).map_err(Error::OpenTap)?;

        Self::new_with_tap(tap)
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
                    .unregister_listener(
                        self.tap.as_raw_fd(),
                        epoll::Events::EPOLLIN,
                        u64::from(RX_TAP_EVENT),
                    )
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
}

impl VhostUserBackend for VhostUserNetBackend {
    fn num_queues(&self) -> usize {
        NUM_QUEUES
    }

    fn max_queue_size(&self) -> usize {
        QUEUE_SIZE
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
            RX_QUEUE_EVENT => {
                let mut vring = vrings[0].write().unwrap();
                self.resume_rx(&mut vring)?;

                if !self.rx_tap_listening {
                    self.vring_worker.as_ref().unwrap().register_listener(
                        self.tap.as_raw_fd(),
                        epoll::Events::EPOLLIN,
                        u64::from(RX_TAP_EVENT),
                    )?;
                    self.rx_tap_listening = true;
                }
            }
            TX_QUEUE_EVENT => {
                let mut vring = vrings[1].write().unwrap();
                self.process_tx(&mut vring.mut_queue())?;
            }
            RX_TAP_EVENT => {
                let mut vring = vrings[0].write().unwrap();
                if self.rx.deferred_frame
                // Process a deferred frame first if available. Don't read from tap again
                // until we manage to receive this deferred frame.
                {
                    if self.rx_single_frame(&mut vring.mut_queue())? {
                        self.rx.deferred_frame = false;
                        self.process_rx(&mut vring)?;
                    } else if self.rx.deferred_irqs {
                        self.rx.deferred_irqs = false;
                        vring.signal_used_queue()?;
                    }
                } else {
                    self.process_rx(&mut vring)?;
                }
            }
            KILL_EVENT => {
                self.kill_evt.read().unwrap();
                return Ok(true);
            }
            _ => return Err(Error::HandleEventUnknownEvent.into()),
        }

        Ok(false)
    }
}

pub struct VhostUserNetBackendConfig<'a> {
    pub ip: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub sock: &'a str,
}

impl<'a> VhostUserNetBackendConfig<'a> {
    pub fn parse(backend: &'a str) -> Result<Self> {
        let params_list: Vec<&str> = backend.split(',').collect();

        let mut ip_str: &str = "";
        let mut mask_str: &str = "";
        let mut sock: &str = "";

        for param in params_list.iter() {
            if param.starts_with("ip=") {
                ip_str = &param[3..];
            } else if param.starts_with("mask=") {
                mask_str = &param[5..];
            } else if param.starts_with("sock=") {
                sock = &param[5..];
            }
        }

        let mut ip: Ipv4Addr = Ipv4Addr::new(192, 168, 100, 1);
        let mut mask: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);

        if sock.is_empty() {
            return Err(Error::ParseSockParam);
        }
        if !ip_str.is_empty() {
            ip = ip_str.parse().map_err(|_| Error::ParseIpParam)?;
        }
        if !mask_str.is_empty() {
            mask = mask_str.parse().map_err(|_| Error::ParseMaskParam)?;
        }

        Ok(VhostUserNetBackendConfig { ip, mask, sock })
    }
}

fn main() {
    let cmd_arguments = App::new("vhost-user-net backend")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Launch a vhost-user-net backend.")
        .arg(
            Arg::with_name("backend")
                .long("backend")
                .help(
                    "Backend parameters \"ip=<ip_addr>,\
                     mask=<net_mask>,sock=<socket_path>\"",
                )
                .takes_value(true)
                .min_values(1),
        )
        .get_matches();

    let vhost_user_net_backend = cmd_arguments.value_of("backend").unwrap();

    let backend_config = match VhostUserNetBackendConfig::parse(vhost_user_net_backend) {
        Ok(config) => config,
        Err(e) => {
            println!("Failed parsing parameters {:?}", e);
            process::exit(1);
        }
    };

    let net_backend = Arc::new(RwLock::new(
        VhostUserNetBackend::new(backend_config.ip, backend_config.mask).unwrap(),
    ));
    let name = "vhost-user-net-backend";
    let mut net_daemon = VhostUserDaemon::new(
        name.to_string(),
        backend_config.sock.to_string(),
        net_backend.clone(),
    )
    .unwrap();
    let vring_worker = net_daemon.get_vring_worker();

    if let Err(e) = vring_worker.register_listener(
        net_backend.read().unwrap().kill_evt.as_raw_fd(),
        epoll::Events::EPOLLIN,
        u64::from(KILL_EVENT),
    ) {
        println!("failed to register listener for kill event: {:?}", e);
        process::exit(1);
    }

    net_backend.write().unwrap().vring_worker = Some(vring_worker);

    if let Err(e) = net_daemon.start() {
        println!(
            "failed to start daemon for vhost-user-net with error: {:?}",
            e
        );
        process::exit(1);
    }

    net_daemon.wait().unwrap();
}
