// Copyright 2019 Red Hat, Inc. All Rights Reserved.
//
// Portions Copyright 2019 Intel Corporation. All Rights Reserved.
//
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use block_util::{build_disk_image_id, Request, VirtioBlockConfig};
use libc::EFD_NONBLOCK;
use log::*;
use option_parser::{OptionParser, OptionParserError, Toggle};
use qcow::{self, ImageType, QcowFile};
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Read;
use std::io::{Seek, SeekFrom, Write};
use std::num::Wrapping;
use std::ops::DerefMut;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process;
use std::result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;
use std::vec::Vec;
use std::{convert, error, fmt, io};
use vhost::vhost_user::message::*;
use vhost::vhost_user::Listener;
use vhost_user_backend::{GuestMemoryMmap, VhostUserBackend, VhostUserDaemon, Vring};
use virtio_bindings::bindings::virtio_blk::*;
use virtio_bindings::bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use vm_memory::ByteValued;
use vm_memory::Bytes;
use vmm_sys_util::eventfd::EventFd;

const SECTOR_SHIFT: u8 = 9;
const SECTOR_SIZE: u64 = 0x01 << SECTOR_SHIFT;
const BLK_SIZE: u32 = 512;
// Current (2020) enterprise SSDs have a latency lower than 30us.
// Polling for 50us should be enough to cover for the device latency
// and the overhead of the emulation layer.
const POLL_QUEUE_US: u128 = 50;

trait DiskFile: Read + Seek + Write + Send + Sync {}
impl<D: Read + Seek + Write + Send + Sync> DiskFile for D {}

type Result<T> = std::result::Result<T, Error>;
type VhostUserBackendResult<T> = std::result::Result<T, std::io::Error>;

#[derive(Debug)]
enum Error {
    /// Failed to create kill eventfd
    CreateKillEventFd(io::Error),
    /// Failed to parse configuration string
    FailedConfigParse(OptionParserError),
    /// Failed to handle event other than input event.
    HandleEventNotEpollIn,
    /// Failed to handle unknown event.
    HandleEventUnknownEvent,
    /// No path provided
    PathParameterMissing,
    /// No socket provided
    SocketParameterMissing,
}

pub const SYNTAX: &str = "vhost-user-block backend parameters \
 \"path=<image_path>,socket=<socket_path>,num_queues=<number_of_queues>,\
 queue_size=<size_of_each_queue>,readonly=true|false,direct=true|false,\
 poll_queue=true|false\"";

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

struct VhostUserBlkThread {
    mem: Option<GuestMemoryMmap>,
    disk_image: Arc<Mutex<dyn DiskFile>>,
    disk_image_id: Vec<u8>,
    disk_nsectors: u64,
    event_idx: bool,
    kill_evt: EventFd,
    writeback: Arc<AtomicBool>,
}

impl VhostUserBlkThread {
    fn new(
        disk_image: Arc<Mutex<dyn DiskFile>>,
        disk_image_id: Vec<u8>,
        disk_nsectors: u64,
        writeback: Arc<AtomicBool>,
    ) -> Result<Self> {
        Ok(VhostUserBlkThread {
            mem: None,
            disk_image,
            disk_image_id,
            disk_nsectors,
            event_idx: false,
            kill_evt: EventFd::new(EFD_NONBLOCK).map_err(Error::CreateKillEventFd)?,
            writeback,
        })
    }

    fn process_queue(&mut self, vring: &mut Vring) -> bool {
        let mut used_any = false;
        let mem = match self.mem.as_ref() {
            Some(m) => m,
            None => return false,
        };

        while let Some(head) = vring.mut_queue().iter(mem).next() {
            debug!("got an element in the queue");
            let len;
            match Request::parse(&head, mem) {
                Ok(mut request) => {
                    debug!("element is a valid request");
                    request.set_writeback(self.writeback.load(Ordering::Acquire));
                    let status = match request.execute(
                        &mut self.disk_image.lock().unwrap().deref_mut(),
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
                let queue = vring.mut_queue();
                if let Some(used_idx) = queue.add_used(mem, head.index, len) {
                    if queue.needs_notification(mem, Wrapping(used_idx)) {
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
}

struct VhostUserBlkBackend {
    threads: Vec<Mutex<VhostUserBlkThread>>,
    config: VirtioBlockConfig,
    rdonly: bool,
    poll_queue: bool,
    queues_per_thread: Vec<u64>,
    queue_size: usize,
    acked_features: u64,
    writeback: Arc<AtomicBool>,
}

impl VhostUserBlkBackend {
    fn new(
        image_path: String,
        num_queues: usize,
        rdonly: bool,
        direct: bool,
        poll_queue: bool,
        queue_size: usize,
    ) -> Result<Self> {
        let mut options = OpenOptions::new();
        options.read(true);
        options.write(!rdonly);
        if direct {
            options.custom_flags(libc::O_DIRECT);
        }
        let image: File = options.open(&image_path).unwrap();
        let mut raw_img: qcow::RawFile = qcow::RawFile::new(image, direct);

        let image_id = build_disk_image_id(&PathBuf::from(&image_path));
        let image_type = qcow::detect_image_type(&mut raw_img).unwrap();
        let image = match image_type {
            ImageType::Raw => Arc::new(Mutex::new(raw_img)) as Arc<Mutex<dyn DiskFile>>,
            ImageType::Qcow2 => {
                Arc::new(Mutex::new(QcowFile::from(raw_img).unwrap())) as Arc<Mutex<dyn DiskFile>>
            }
        };

        let nsectors = (image.lock().unwrap().seek(SeekFrom::End(0)).unwrap() as u64) / SECTOR_SIZE;
        let config = VirtioBlockConfig {
            capacity: nsectors,
            blk_size: BLK_SIZE,
            size_max: 65535,
            seg_max: 128 - 2,
            min_io_size: 1,
            opt_io_size: 1,
            num_queues: num_queues as u16,
            writeback: 1,
            ..Default::default()
        };

        let mut queues_per_thread = Vec::new();
        let mut threads = Vec::new();
        let writeback = Arc::new(AtomicBool::new(true));
        for i in 0..num_queues {
            let thread = Mutex::new(VhostUserBlkThread::new(
                image.clone(),
                image_id.clone(),
                nsectors,
                writeback.clone(),
            )?);
            threads.push(thread);
            queues_per_thread.push(0b1 << i);
        }

        Ok(VhostUserBlkBackend {
            threads,
            config,
            rdonly,
            poll_queue,
            queues_per_thread,
            queue_size,
            acked_features: 0,
            writeback,
        })
    }

    fn update_writeback(&mut self) {
        // Use writeback from config if VIRTIO_BLK_F_CONFIG_WCE
        let writeback =
            if self.acked_features & 1 << VIRTIO_BLK_F_CONFIG_WCE == 1 << VIRTIO_BLK_F_CONFIG_WCE {
                self.config.writeback == 1
            } else {
                // Else check if VIRTIO_BLK_F_FLUSH negotiated
                self.acked_features & 1 << VIRTIO_BLK_F_FLUSH == 1 << VIRTIO_BLK_F_FLUSH
            };

        info!(
            "Changing cache mode to {}",
            if writeback {
                "writeback"
            } else {
                "writethrough"
            }
        );
        self.writeback.store(writeback, Ordering::Release);
    }
}

impl VhostUserBackend for VhostUserBlkBackend {
    fn num_queues(&self) -> usize {
        self.config.num_queues as usize
    }

    fn max_queue_size(&self) -> usize {
        self.queue_size as usize
    }

    fn features(&self) -> u64 {
        let mut avail_features = 1 << VIRTIO_BLK_F_SEG_MAX
            | 1 << VIRTIO_BLK_F_BLK_SIZE
            | 1 << VIRTIO_BLK_F_FLUSH
            | 1 << VIRTIO_BLK_F_TOPOLOGY
            | 1 << VIRTIO_BLK_F_MQ
            | 1 << VIRTIO_BLK_F_CONFIG_WCE
            | 1 << VIRTIO_RING_F_EVENT_IDX
            | 1 << VIRTIO_F_VERSION_1
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

        if self.rdonly {
            avail_features |= 1 << VIRTIO_BLK_F_RO;
        }
        avail_features
    }

    fn acked_features(&mut self, features: u64) {
        self.acked_features = features;
        self.update_writeback();
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::CONFIG
            | VhostUserProtocolFeatures::MQ
            | VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS
    }

    fn set_event_idx(&mut self, enabled: bool) {
        for thread in self.threads.iter() {
            thread.lock().unwrap().event_idx = enabled;
        }
    }

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

        debug!("event received: {:?}", device_event);

        let mut thread = self.threads[thread_id].lock().unwrap();
        match device_event {
            0 => {
                let mut vring = vrings[0].write().unwrap();

                if self.poll_queue {
                    // Actively poll the queue until POLL_QUEUE_US has passed
                    // without seeing a new request.
                    let mut now = Instant::now();
                    loop {
                        if thread.process_queue(&mut vring) {
                            now = Instant::now();
                        } else if now.elapsed().as_micros() > POLL_QUEUE_US {
                            break;
                        }
                    }
                }

                if thread.event_idx {
                    // vm-virtio's Queue implementation only checks avail_index
                    // once, so to properly support EVENT_IDX we need to keep
                    // calling process_queue() until it stops finding new
                    // requests on the queue.
                    loop {
                        vring
                            .mut_queue()
                            .update_avail_event(thread.mem.as_ref().unwrap());
                        if !thread.process_queue(&mut vring) {
                            break;
                        }
                    }
                } else {
                    // Without EVENT_IDX, a single call is enough.
                    thread.process_queue(&mut vring);
                }

                Ok(false)
            }
            _ => Err(Error::HandleEventUnknownEvent.into()),
        }
    }

    fn get_config(&self, _offset: u32, _size: u32) -> Vec<u8> {
        self.config.as_slice().to_vec()
    }

    fn set_config(&mut self, offset: u32, data: &[u8]) -> result::Result<(), io::Error> {
        let config_slice = self.config.as_mut_slice();
        let data_len = data.len() as u32;
        let config_len = config_slice.len() as u32;
        if offset + data_len > config_len {
            error!("Failed to write config space");
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        let (_, right) = config_slice.split_at_mut(offset as usize);
        right.copy_from_slice(data);
        self.update_writeback();
        Ok(())
    }

    fn exit_event(&self, thread_index: usize) -> Option<(EventFd, Option<u16>)> {
        // The exit event is placed after the queue, which is event index 1.
        Some((
            self.threads[thread_index]
                .lock()
                .unwrap()
                .kill_evt
                .try_clone()
                .unwrap(),
            Some(1),
        ))
    }

    fn queues_per_thread(&self) -> Vec<u64> {
        self.queues_per_thread.clone()
    }
}

struct VhostUserBlkBackendConfig {
    path: String,
    socket: String,
    num_queues: usize,
    queue_size: usize,
    readonly: bool,
    direct: bool,
    poll_queue: bool,
}

impl VhostUserBlkBackendConfig {
    fn parse(backend: &str) -> Result<Self> {
        let mut parser = OptionParser::new();
        parser
            .add("path")
            .add("readonly")
            .add("direct")
            .add("num_queues")
            .add("queue_size")
            .add("socket")
            .add("poll_queue");
        parser.parse(backend).map_err(Error::FailedConfigParse)?;

        let path = parser.get("path").ok_or(Error::PathParameterMissing)?;
        let readonly = parser
            .convert::<Toggle>("readonly")
            .map_err(Error::FailedConfigParse)?
            .unwrap_or(Toggle(false))
            .0;
        let direct = parser
            .convert::<Toggle>("direct")
            .map_err(Error::FailedConfigParse)?
            .unwrap_or(Toggle(false))
            .0;
        let num_queues = parser
            .convert("num_queues")
            .map_err(Error::FailedConfigParse)?
            .unwrap_or(1);
        let socket = parser.get("socket").ok_or(Error::SocketParameterMissing)?;
        let poll_queue = parser
            .convert::<Toggle>("poll_queue")
            .map_err(Error::FailedConfigParse)?
            .unwrap_or(Toggle(true))
            .0;
        let queue_size = parser
            .convert("queue_size")
            .map_err(Error::FailedConfigParse)?
            .unwrap_or(1024);

        Ok(VhostUserBlkBackendConfig {
            path,
            socket,
            num_queues,
            queue_size,
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
            backend_config.path,
            backend_config.num_queues,
            backend_config.readonly,
            backend_config.direct,
            backend_config.poll_queue,
            backend_config.queue_size,
        )
        .unwrap(),
    ));

    debug!("blk_backend is created!\n");

    let listener = Listener::new(&backend_config.socket, true).unwrap();

    let name = "vhost-user-blk-backend";
    let mut blk_daemon = VhostUserDaemon::new(name.to_string(), blk_backend.clone()).unwrap();

    debug!("blk_daemon is created!\n");

    if let Err(e) = blk_daemon.start_server(listener) {
        error!(
            "Failed to start daemon for vhost-user-block with error: {:?}\n",
            e
        );
        process::exit(1);
    }

    if let Err(e) = blk_daemon.wait() {
        error!("Error from the main thread: {:?}", e);
    }

    for thread in blk_backend.read().unwrap().threads.iter() {
        if let Err(e) = thread.lock().unwrap().kill_evt.write(1) {
            error!("Error shutting down worker thread: {:?}", e)
        }
    }
}
