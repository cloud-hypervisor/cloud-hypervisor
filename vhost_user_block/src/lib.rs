// Copyright 2019 Red Hat, Inc. All Rights Reserved.
//
// Portions Copyright 2019 Intel Corporation. All Rights Reserved.
//
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

extern crate log;
extern crate vhost_rs;
extern crate vhost_user_backend;
extern crate vm_virtio;

use epoll;
use libc::EFD_NONBLOCK;
use log::*;
use qcow::{self, ImageType, QcowFile};
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Read;
use std::io::{Seek, SeekFrom, Write};
use std::mem;
use std::num::Wrapping;
use std::ops::DerefMut;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::process;
use std::slice;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;
use std::vec::Vec;
use std::{convert, error, fmt, io};
use vhost_rs::vhost_user::message::*;
use vhost_user_backend::{VhostUserBackend, VhostUserDaemon, Vring};
use virtio_bindings::bindings::virtio_blk::*;
use virtio_bindings::bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use vm_memory::{Bytes, GuestMemoryError, GuestMemoryMmap};
use vm_virtio::block::{build_disk_image_id, Request};
use vm_virtio::net_util::{register_listener, unregister_listener};
use vmm_sys_util::eventfd::EventFd;

const QUEUE_SIZE: usize = 1024;
const SECTOR_SHIFT: u8 = 9;
const SECTOR_SIZE: u64 = (0x01 as u64) << SECTOR_SHIFT;
const BLK_SIZE: u32 = 512;
// Current (2020) enterprise SSDs have a latency lower than 30us.
// Polling for 50us should be enough to cover for the device latency
// and the overhead of the emulation layer.
const POLL_QUEUE_US: u128 = 50;

trait DiskFile: Read + Seek + Write + Send + Sync {}
impl<D: Read + Seek + Write + Send + Sync> DiskFile for D {}

pub type Result<T> = std::result::Result<T, Error>;
pub type VhostUserBackendResult<T> = std::result::Result<T, std::io::Error>;

#[derive(Debug)]
pub enum Error {
    /// Failed to create EventFd.
    EpollCreateFd(io::Error),
    /// Failed to detect image type.
    DetectImageType,
    /// Failed register listener for vring.
    FailedRegisterListener,
    /// Failed unregister listener for vring.
    FailedUnRegisterListener,
    /// Bad memory address.
    GuestMemory(GuestMemoryError),
    /// Can't open image file.
    OpenImage,
    /// Failed to parse direct parameter.
    ParseDirectParam,
    /// Failed to parse image parameter.
    ParseImageParam,
    /// Failed to parse sock parameter.
    ParseSockParam,
    /// Failed to parse readonly parameter.
    ParseReadOnlyParam,
    /// Failed parsing fs number of queues parameter.
    ParseBlkNumQueuesParam(std::num::ParseIntError),
    /// Failed to parse the poll_queue parameter.
    ParsePollQueueParam,
    /// Failed to create kill eventfd
    CreateKillEventFd(io::Error),
    /// Failed to handle unknown event.
    HandleEventUnknownEvent,
    /// Failed to read kick EventFd.
    HandleEventReadKick,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "vhost_user_block_error: {:?}", self)
    }
}

impl error::Error for Error {}

impl convert::From<Error> for io::Error {
    fn from(e: Error) -> Self {
        io::Error::new(io::ErrorKind::Other, e)
    }
}

pub struct VhostUserBlkBackend {
    mem: Option<GuestMemoryMmap>,
    disk_image: Arc<Mutex<dyn DiskFile>>,
    disk_image_id: Vec<u8>,
    disk_nsectors: u64,
    config: virtio_blk_config,
    rdonly: bool,
    poll_queue: bool,
    event_idx: bool,
    kill_evt: EventFd,
    epoll_fd: RawFd,
}

impl VhostUserBlkBackend {
    pub fn new(
        image_path: String,
        num_queues: usize,
        rdonly: bool,
        direct: bool,
        poll_queue: bool,
    ) -> Result<Self> {
        let mut options = OpenOptions::new();
        options.read(true);
        options.write(!rdonly);
        if direct {
            options.custom_flags(libc::O_DIRECT);
        }
        let image: File = options.open(&image_path).unwrap();
        let mut raw_img: vm_virtio::RawFile = vm_virtio::RawFile::new(image, direct);

        let image_id = build_disk_image_id(&PathBuf::from(&image_path));
        let image_type = qcow::detect_image_type(&mut raw_img).unwrap();
        let image = match image_type {
            ImageType::Raw => Arc::new(Mutex::new(raw_img)) as Arc<Mutex<dyn DiskFile>>,
            ImageType::Qcow2 => {
                Arc::new(Mutex::new(QcowFile::from(raw_img).unwrap())) as Arc<Mutex<dyn DiskFile>>
            }
        };

        let nsectors = (image.lock().unwrap().seek(SeekFrom::End(0)).unwrap() as u64) / SECTOR_SIZE;
        let mut config = virtio_blk_config::default();

        config.capacity = nsectors;
        config.blk_size = BLK_SIZE;
        config.size_max = 65535;
        config.seg_max = 128 - 2;
        config.min_io_size = 1;
        config.opt_io_size = 1;
        config.num_queues = num_queues as u16;
        config.wce = 1;

        Ok(VhostUserBlkBackend {
            mem: None,
            disk_image: image,
            disk_image_id: image_id,
            disk_nsectors: nsectors,
            config,
            rdonly,
            poll_queue,
            event_idx: false,
            kill_evt: EventFd::new(EFD_NONBLOCK).map_err(Error::CreateKillEventFd)?,
            epoll_fd: epoll::create(true).map_err(Error::EpollCreateFd)?,
        })
    }
}

impl VhostUserBackend for VhostUserBlkBackend {
    fn num_queues(&self) -> usize {
        self.config.num_queues as usize
    }

    fn max_queue_size(&self) -> usize {
        QUEUE_SIZE
    }

    fn features(&self) -> u64 {
        let mut avail_features = 1 << VIRTIO_BLK_F_MQ
            | 1 << VIRTIO_BLK_F_CONFIG_WCE
            | 1 << VIRTIO_RING_F_EVENT_IDX
            | 1 << VIRTIO_F_VERSION_1
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

        if self.rdonly {
            avail_features |= 1 << VIRTIO_BLK_F_RO;
        }
        avail_features
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::CONFIG
    }

    fn set_event_idx(&mut self, enabled: bool) {
        self.event_idx = enabled;
    }

    fn update_memory(&mut self, mem: GuestMemoryMmap) -> VhostUserBackendResult<()> {
        self.mem = Some(mem);
        Ok(())
    }

    fn get_config(&self, _offset: u32, _size: u32) -> Vec<u8> {
        // self.config is a statically allocated virtio_blk_config
        let buf = unsafe {
            slice::from_raw_parts(
                &self.config as *const virtio_blk_config as *const _,
                mem::size_of::<virtio_blk_config>(),
            )
        };

        buf.to_vec()
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

struct BlockEpollHandler {
    mem: Option<GuestMemoryMmap>,
    disk_image: Arc<Mutex<dyn DiskFile>>,
    disk_image_id: Vec<u8>,
    disk_nsectors: u64,
    poll_queue: bool,
    event_idx: bool,
    epoll_fd: RawFd,
    num_queues: u16,
}

impl BlockEpollHandler {
    pub fn process_queue(&mut self, vring: &mut Vring) -> bool {
        let mut used_any = false;
        let mem = match self.mem.as_ref() {
            Some(m) => m,
            None => return false,
        };

        while let Some(head) = vring.mut_queue().iter(mem).next() {
            debug!("got an element in the queue");
            let len;
            match Request::parse(&head, mem) {
                Ok(request) => {
                    debug!("element is a valid request");
                    // TODO: Remove the Mutex lock which prevents parallelismm.
                    let mut disk_image_locked = self.disk_image.lock().unwrap();
                    let mut disk_image = disk_image_locked.deref_mut();
                    let status = match request.execute(
                        &mut disk_image,
                        self.disk_nsectors,
                        mem,
                        &self.disk_image_id,
                    ) {
                        Ok(l) => {
                            len = l;
                            VIRTIO_BLK_S_OK
                        }
                        Err(e) => {
                            len = 1;
                            e.status()
                        }
                    };
                    mem.write_obj(status, request.status_addr).unwrap();
                }
                Err(err) => {
                    error!("failed to parse available descriptor chain: {:?}", err);
                    len = 0;
                }
            }

            if self.event_idx {
                if let Some(used_idx) = vring.mut_queue().add_used(mem, head.index, len) {
                    if vring.needs_notification(&mem, Wrapping(used_idx)) {
                        debug!("signalling queue");
                        vring.signal_used_queue().unwrap();
                    } else {
                        debug!("omitting signal (event_idx)");
                    }
                    used_any = true;
                }
            } else {
                debug!("signalling queue");
                vring.mut_queue().add_used(mem, head.index, len);
                vring.signal_used_queue().unwrap();
                used_any = true;
            }
        }

        used_any
    }

    fn handle_event(&mut self, vrings: Vec<Arc<RwLock<Vring>>>) -> VhostUserBackendResult<()> {
        let mut events =
            vec![epoll::Event::new(epoll::Events::empty(), 0); self.num_queues as usize];

        'epoll: loop {
            let num_events = match epoll::wait(self.epoll_fd, -1, &mut events[..]) {
                Ok(res) => res,
                Err(e) => {
                    if e.kind() == io::ErrorKind::Interrupted {
                        // It's well defined from the epoll_wait() syscall
                        // documentation that the epoll loop can be interrupted
                        // before any of the requested events occurred or the
                        // timeout expired. In both those cases, epoll_wait()
                        // returns an error of type EINTR, but this should not
                        // be considered as a regular error. Instead it is more
                        // appropriate to retry, by calling into epoll_wait().
                        continue;
                    }
                    return Err(e);
                }
            };

            for event in events.iter().take(num_events) {
                let device_event = event.data as u16;

                match device_event {
                    q if q < self.num_queues => {
                        if let Some(kick) = &vrings[q as usize].read().unwrap().get_kick() {
                            kick.read().map_err(|_| Error::HandleEventReadKick)?;
                        }
                        if !vrings[q as usize].read().unwrap().get_enabled() {
                            continue;
                        }

                        let mut vring = vrings[q as usize].write().unwrap();

                        if self.poll_queue {
                            // Actively poll the queue until POLL_QUEUE_US has passed
                            // without seeing a new request.
                            let mut now = Instant::now();
                            loop {
                                if self.process_queue(&mut vring) {
                                    now = Instant::now();
                                } else if now.elapsed().as_micros() > POLL_QUEUE_US {
                                    break;
                                }
                            }
                        }

                        if self.event_idx {
                            // vm-virtio's Queue implementation only checks avail_index
                            // once, so to properly support EVENT_IDX we need to keep
                            // calling process_queue() until it stops finding new
                            // requests on the queue.
                            loop {
                                vring
                                    .mut_queue()
                                    .update_avail_event(self.mem.as_ref().unwrap());
                                if !self.process_queue(&mut vring) {
                                    break;
                                }
                            }
                        } else {
                            // Without EVENT_IDX, a single call is enough.
                            self.process_queue(&mut vring);
                        }
                    }
                    _ => return Err(Error::HandleEventUnknownEvent.into()),
                }
            }
        }
        Ok(())
    }
}

pub struct VhostUserBlkBackendConfig<'a> {
    pub image: &'a str,
    pub sock: &'a str,
    pub num_queues: usize,
    pub readonly: bool,
    pub direct: bool,
    pub poll_queue: bool,
}

impl<'a> VhostUserBlkBackendConfig<'a> {
    pub fn parse(backend: &'a str) -> Result<Self> {
        let params_list: Vec<&str> = backend.split(',').collect();

        let mut image: &str = "";
        let mut sock: &str = "";
        let mut num_queues_str: &str = "";
        let mut readonly: bool = false;
        let mut direct: bool = false;
        let mut poll_queue: bool = true;

        for param in params_list.iter() {
            if param.starts_with("image=") {
                image = &param[6..];
            } else if param.starts_with("sock=") {
                sock = &param[5..];
            } else if param.starts_with("num_queues=") {
                num_queues_str = &param[11..];
            } else if param.starts_with("readonly=") {
                readonly = match param[9..].parse::<bool>() {
                    Ok(b) => b,
                    Err(_) => return Err(Error::ParseReadOnlyParam),
                }
            } else if param.starts_with("direct=") {
                direct = match param[7..].parse::<bool>() {
                    Ok(b) => b,
                    Err(_) => return Err(Error::ParseDirectParam),
                }
            } else if param.starts_with("poll_queue=") {
                poll_queue = match param[11..].parse::<bool>() {
                    Ok(b) => b,
                    Err(_) => return Err(Error::ParsePollQueueParam),
                }
            }
        }

        let mut num_queues: usize = 1;
        if image.is_empty() {
            return Err(Error::ParseImageParam);
        }
        if sock.is_empty() {
            return Err(Error::ParseSockParam);
        }
        if !num_queues_str.is_empty() {
            num_queues = num_queues_str
                .parse()
                .map_err(Error::ParseBlkNumQueuesParam)?;
        }
        Ok(VhostUserBlkBackendConfig {
            image,
            sock,
            num_queues,
            readonly,
            direct,
            poll_queue,
        })
    }
}

pub fn start_block_backend(backend_command: &str) {
    let backend_config = match VhostUserBlkBackendConfig::parse(backend_command) {
        Ok(config) => config,
        Err(e) => {
            println!("Failed parsing parameters {:?}", e);
            process::exit(1);
        }
    };

    let blk_backend = Arc::new(RwLock::new(
        VhostUserBlkBackend::new(
            backend_config.image.to_string(),
            backend_config.num_queues,
            backend_config.readonly,
            backend_config.direct,
            backend_config.poll_queue,
        )
        .unwrap(),
    ));

    debug!("blk_backend is created!\n");

    let name = "vhost-user-blk-backend";
    let mut blk_daemon = VhostUserDaemon::new(
        name.to_string(),
        backend_config.sock.to_string(),
        blk_backend.clone(),
    )
    .unwrap();
    debug!("blk_daemon is created!\n");

    if let Err(e) = blk_daemon.start() {
        error!(
            "Failed to start daemon for vhost-user-block with error: {:?}\n",
            e
        );
        process::exit(1);
    }

    if let Err(e) = blk_daemon.wait() {
        error!("Error from the main thread: {:?}", e);
    }

    let kill_evt = &blk_backend.write().unwrap().kill_evt;
    if let Err(e) = kill_evt.write(1) {
        error!("Error shutting down worker thread: {:?}", e)
    }
}
