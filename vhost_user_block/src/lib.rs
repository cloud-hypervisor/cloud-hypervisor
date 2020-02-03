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
use log::*;
use qcow::{self, ImageType, QcowFile};
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Read;
use std::io::{Seek, SeekFrom, Write};
use std::mem;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process;
use std::slice;
use std::sync::{Arc, RwLock};
use std::vec::Vec;
use vhost_rs::vhost_user::message::*;
use vhost_user_backend::{VhostUserBackend, VhostUserDaemon, Vring, VringWorker};
use virtio_bindings::bindings::virtio_blk::*;
use vm_memory::{Bytes, GuestMemoryError, GuestMemoryMmap};
use vm_virtio::block::{build_disk_image_id, Request};

const QUEUE_SIZE: usize = 1024;
const SECTOR_SHIFT: u8 = 9;
const SECTOR_SIZE: u64 = (0x01 as u64) << SECTOR_SHIFT;
const BLK_SIZE: u32 = 512;

trait DiskFile: Read + Seek + Write + Send + Sync {}
impl<D: Read + Seek + Write + Send + Sync> DiskFile for D {}

pub type Result<T> = std::result::Result<T, Error>;
pub type VhostUserBackendResult<T> = std::result::Result<T, std::io::Error>;

#[derive(Debug)]
pub enum Error {
    /// Failed to detect image type.
    DetectImageType,
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
}

pub struct VhostUserBlkBackend {
    mem: Option<GuestMemoryMmap>,
    vring_worker: Option<Arc<VringWorker>>,
    disk_image: Box<dyn DiskFile>,
    disk_image_id: Vec<u8>,
    disk_nsectors: u64,
    config: virtio_blk_config,
    rdonly: bool,
}

impl VhostUserBlkBackend {
    pub fn new(image_path: String, num_queues: usize, rdonly: bool, direct: bool) -> Result<Self> {
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
        let mut image = match image_type {
            ImageType::Raw => Box::new(raw_img) as Box<dyn DiskFile>,
            ImageType::Qcow2 => Box::new(QcowFile::from(raw_img).unwrap()) as Box<dyn DiskFile>,
        };

        let nsectors = (image.seek(SeekFrom::End(0)).unwrap() as u64) / SECTOR_SIZE;
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
            vring_worker: None,
            disk_image: image,
            disk_image_id: image_id,
            disk_nsectors: nsectors,
            config,
            rdonly,
        })
    }

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
                    let status = match request.execute(
                        &mut self.disk_image,
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
            vring.mut_queue().add_used(mem, head.index, len);
            used_any = true;
        }

        used_any
    }

    pub fn set_vring_worker(&mut self, vring_worker: Option<Arc<VringWorker>>) {
        self.vring_worker = vring_worker;
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
            warn!("invalid events operation");
            return Ok(false);
        }

        debug!("event received: {:?}", device_event);

        let mut vring = vrings[device_event as usize].write().unwrap();
        if self.process_queue(&mut vring) {
            debug!("signalling queue");
            vring.signal_used_queue().unwrap();
        }

        Ok(false)
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
}

pub struct VhostUserBlkBackendConfig<'a> {
    pub image: &'a str,
    pub sock: &'a str,
    pub num_queues: usize,
    pub readonly: bool,
    pub direct: bool,
}

impl<'a> VhostUserBlkBackendConfig<'a> {
    pub fn parse(backend: &'a str) -> Result<Self> {
        let params_list: Vec<&str> = backend.split(',').collect();

        let mut image: &str = "";
        let mut sock: &str = "";
        let mut num_queues_str: &str = "";
        let mut readonly: bool = false;
        let mut direct: bool = false;

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

    let vring_worker = blk_daemon.get_vring_worker();

    blk_backend
        .write()
        .unwrap()
        .set_vring_worker(Some(vring_worker));

    if let Err(e) = blk_daemon.start() {
        println!(
            "failed to start daemon for vhost-user-blk with error: {:?}\n",
            e
        );
        process::exit(1);
    }

    blk_daemon.wait().unwrap();
}
