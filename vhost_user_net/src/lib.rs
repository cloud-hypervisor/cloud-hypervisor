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

use epoll;
use libc::{self, EAGAIN, EFD_NONBLOCK};
use log::*;
use net_util::Tap;
use std::convert::TryFrom;
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
use vm_virtio::net_util::{open_tap, RxVirtio, TxVirtio};
use vm_virtio::Queue;
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
    ParseIpParam(std::net::AddrParseError),
    /// Failed to parse mask parameter.
    ParseMaskParam(std::net::AddrParseError),
    /// Failed to parse queue number.
    ParseQueueNumParam(std::num::ParseIntError),
    /// Failed to parse queue size.
    ParseQueueSizeParam(std::num::ParseIntError),
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

pub struct VhostUserNetBackend {
    mem: Option<GuestMemoryMmap>,
    vring_worker: Option<Arc<VringWorker>>,
    kill_evt: EventFd,
    taps: Vec<(Tap, usize)>,
    rxs: Vec<RxVirtio>,
    txs: Vec<TxVirtio>,
    rx_tap_listenings: Vec<bool>,
    num_queues: usize,
    queue_size: u16,
}

impl VhostUserNetBackend {
    /// Create a new virtio network device with the given TAP interface.
    pub fn new_with_tap(taps: Vec<Tap>, num_queues: usize, queue_size: u16) -> Result<Self> {
        let mut taps_v: Vec<(Tap, usize)> = Vec::new();
        for (i, tap) in taps.iter().enumerate() {
            taps_v.push((tap.clone(), num_queues + i));
        }

        let mut rxs: Vec<RxVirtio> = Vec::new();
        let mut txs: Vec<TxVirtio> = Vec::new();
        let mut rx_tap_listenings: Vec<bool> = Vec::new();

        for _ in 0..taps.len() {
            let rx = RxVirtio::new();
            rxs.push(rx);
            let tx = TxVirtio::new();
            txs.push(tx);
            rx_tap_listenings.push(false);
        }

        Ok(VhostUserNetBackend {
            mem: None,
            vring_worker: None,
            kill_evt: EventFd::new(EFD_NONBLOCK).map_err(Error::CreateKillEventFd)?,
            taps: taps_v,
            rxs,
            txs,
            rx_tap_listenings,
            num_queues,
            queue_size,
        })
    }

    /// Create a new virtio network device with the given IP address and
    /// netmask.
    pub fn new(
        ip_addr: Ipv4Addr,
        netmask: Ipv4Addr,
        num_queues: usize,
        queue_size: u16,
    ) -> Result<Self> {
        let taps =
            open_tap(None, Some(ip_addr), Some(netmask), num_queues / 2).map_err(Error::OpenTap)?;

        Self::new_with_tap(taps, num_queues, queue_size)
    }

    // Copies a single frame from `self.rx.frame_buf` into the guest. Returns true
    // if a buffer was used, and false if the frame must be deferred until a buffer
    // is made available by the driver.
    fn rx_single_frame(&mut self, mut queue: &mut Queue, index: usize) -> Result<bool> {
        let mem = self.mem.as_ref().ok_or(Error::NoMemoryConfigured)?;

        let next_desc = queue.iter(&mem).next();

        if next_desc.is_none() {
            // Queue has no available descriptors
            if self.rx_tap_listenings[index] {
                self.vring_worker
                    .as_ref()
                    .unwrap()
                    .unregister_listener(
                        self.taps[index].0.as_raw_fd(),
                        epoll::Events::EPOLLIN,
                        u64::try_from(self.taps[index].1).unwrap(),
                    )
                    .unwrap();
                self.rx_tap_listenings[index] = false;
            }
            return Ok(false);
        }

        let write_complete = self.rxs[index].process_desc_chain(&mem, next_desc, &mut queue);

        Ok(write_complete)
    }

    fn process_rx(&mut self, vring: &mut Vring, index: usize) -> Result<()> {
        // Read as many frames as possible.
        loop {
            match self.read_tap(index) {
                Ok(count) => {
                    self.rxs[index].bytes_read = count;
                    if !self.rx_single_frame(&mut vring.mut_queue(), index)? {
                        self.rxs[index].deferred_frame = true;
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
        if self.rxs[index].deferred_irqs {
            self.rxs[index].deferred_irqs = false;
            vring.signal_used_queue().unwrap();
            Ok(())
        } else {
            Ok(())
        }
    }

    fn resume_rx(&mut self, vring: &mut Vring, index: usize) -> Result<()> {
        if self.rxs[index].deferred_frame {
            if self.rx_single_frame(&mut vring.mut_queue(), index)? {
                self.rxs[index].deferred_frame = false;
                // process_rx() was interrupted possibly before consuming all
                // packets in the tap; try continuing now.
                self.process_rx(vring, index)
            } else if self.rxs[index].deferred_irqs {
                self.rxs[index].deferred_irqs = false;
                vring.signal_used_queue().unwrap();
                Ok(())
            } else {
                Ok(())
            }
        } else {
            Ok(())
        }
    }

    fn process_tx(&mut self, mut queue: &mut Queue, index: usize) -> Result<()> {
        let mem = self.mem.as_ref().ok_or(Error::NoMemoryConfigured)?;

        self.txs[index].process_desc_chain(&mem, &mut self.taps[index].0, &mut queue);

        Ok(())
    }

    fn read_tap(&mut self, index: usize) -> io::Result<usize> {
        self.taps[index].0.read(&mut self.rxs[index].frame_buf)
    }

    pub fn set_vring_worker(&mut self, vring_worker: Option<Arc<VringWorker>>) {
        self.vring_worker = vring_worker;
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

        let tap_start_index = self.num_queues as u16;
        let tap_end_index = (self.num_queues + self.num_queues / 2 - 1) as u16;

        match device_event {
            x if ((x < self.num_queues as u16) && (x % 2 == 0)) => {
                let index = (x / 2) as usize;
                let mut vring = vrings[x as usize].write().unwrap();
                self.resume_rx(&mut vring, index)?;

                if !self.rx_tap_listenings[index] {
                    self.vring_worker.as_ref().unwrap().register_listener(
                        self.taps[index].0.as_raw_fd(),
                        epoll::Events::EPOLLIN,
                        u64::try_from(self.taps[index].1).unwrap(),
                    )?;
                    self.rx_tap_listenings[index] = true;
                }
            }
            x if ((x < self.num_queues as u16) && (x % 2 != 0)) => {
                let index = ((x - 1) / 2) as usize;
                let mut vring = vrings[x as usize].write().unwrap();
                self.process_tx(&mut vring.mut_queue(), index)?;
            }
            x if x >= tap_start_index && x <= tap_end_index => {
                let index = x as usize - self.num_queues;
                let mut vring = vrings[2 * index].write().unwrap();
                if self.rxs[index].deferred_frame
                // Process a deferred frame first if available. Don't read from tap again
                // until we manage to receive this deferred frame.
                {
                    if self.rx_single_frame(&mut vring.mut_queue(), index)? {
                        self.rxs[index].deferred_frame = false;
                        self.process_rx(&mut vring, index)?;
                    } else if self.rxs[index].deferred_irqs {
                        self.rxs[index].deferred_irqs = false;
                        vring.signal_used_queue()?;
                    }
                } else {
                    self.process_rx(&mut vring, index)?;
                }
            }
            _ => return Err(Error::HandleEventUnknownEvent.into()),
        }

        Ok(false)
    }

    fn exit_event(&self) -> Option<(EventFd, Option<u16>)> {
        let tap_end_index = (self.num_queues + self.num_queues / 2 - 1) as u16;
        let kill_index = tap_end_index + 1;
        Some((self.kill_evt.try_clone().unwrap(), Some(kill_index)))
    }
}

pub struct VhostUserNetBackendConfig<'a> {
    pub ip: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub sock: &'a str,
    pub num_queues: usize,
    pub queue_size: u16,
}

impl<'a> VhostUserNetBackendConfig<'a> {
    pub fn parse(backend: &'a str) -> Result<Self> {
        let params_list: Vec<&str> = backend.split(',').collect();

        let mut ip_str: &str = "";
        let mut mask_str: &str = "";
        let mut sock: &str = "";
        let mut num_queues_str: &str = "";
        let mut queue_size_str: &str = "";

        for param in params_list.iter() {
            if param.starts_with("ip=") {
                ip_str = &param[3..];
            } else if param.starts_with("mask=") {
                mask_str = &param[5..];
            } else if param.starts_with("sock=") {
                sock = &param[5..];
            } else if param.starts_with("num_queues=") {
                num_queues_str = &param[11..];
            } else if param.starts_with("queue_size=") {
                queue_size_str = &param[11..];
            }
        }

        let mut ip: Ipv4Addr = Ipv4Addr::new(192, 168, 100, 1);
        let mut mask: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);
        let mut num_queues: usize = 2;
        let mut queue_size: u16 = 256;

        if sock.is_empty() {
            return Err(Error::ParseSockParam);
        }
        if !ip_str.is_empty() {
            ip = ip_str.parse().map_err(Error::ParseIpParam)?;
        }
        if !mask_str.is_empty() {
            mask = mask_str.parse().map_err(Error::ParseMaskParam)?;
        }
        if !num_queues_str.is_empty() {
            num_queues = num_queues_str.parse().map_err(Error::ParseQueueNumParam)?;
        }
        if !queue_size_str.is_empty() {
            queue_size = queue_size_str.parse().map_err(Error::ParseQueueSizeParam)?;
        }

        Ok(VhostUserNetBackendConfig {
            ip,
            mask,
            sock,
            num_queues,
            queue_size,
        })
    }
}

pub fn start_net_backend(backend_command: &str) {
    let backend_config = match VhostUserNetBackendConfig::parse(backend_command) {
        Ok(config) => config,
        Err(e) => {
            println!("Failed parsing parameters {:?}", e);
            process::exit(1);
        }
    };

    let net_backend = Arc::new(RwLock::new(
        VhostUserNetBackend::new(
            backend_config.ip,
            backend_config.mask,
            backend_config.num_queues,
            backend_config.queue_size,
        )
        .unwrap(),
    ));

    let mut net_daemon = VhostUserDaemon::new(
        "vhost-user-net-backend".to_string(),
        backend_config.sock.to_string(),
        net_backend.clone(),
    )
    .unwrap();

    let vring_worker = net_daemon.get_vring_worker();

    net_backend
        .write()
        .unwrap()
        .set_vring_worker(Some(vring_worker));

    if let Err(e) = net_daemon.start() {
        println!(
            "failed to start daemon for vhost-user-net with error: {:?}",
            e
        );
        process::exit(1);
    }

    if let Err(e) = net_daemon.wait() {
        error!("Error from the main thread: {:?}", e);
    }

    let kill_evt = &net_backend.write().unwrap().kill_evt;
    if let Err(e) = kill_evt.write(1) {
        error!("Error shutting down worker thread: {:?}", e)
    }
}
