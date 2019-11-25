// Copyright 2019 Red Hat, Inc. All Rights Reserved.
//
// Portions Copyright 2019 Intel Corporation. All Rights Reserved.
//
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
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
use log::*;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Read;
use std::io::{Seek, SeekFrom, Write};
use std::mem;
use std::path::PathBuf;
use std::process;
use std::slice;
use std::sync::{Arc, RwLock};
use std::vec::Vec;

use qcow::{self, ImageType, QcowFile};

use vhost_rs::vhost_user::message::*;
use vhost_user_backend::{VhostUserBackend, VhostUserDaemon, Vring, VringWorker};

use virtio_bindings::bindings::virtio_blk::*;
use vm_memory::{Bytes, GuestMemoryError, GuestMemoryMmap};
use vm_virtio::block::{build_disk_image_id, Request};

const QUEUE_SIZE: usize = 1024;
const NUM_QUEUES: usize = 1;
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
    /// Failed to parse image parameter.
    ParseImageParam,
    /// Failed to parse sock parameter.
    ParseSockParam,
    /// Failed to parse iommu parameter.
    ParseDeviceIommu,
    /// Failed to parse readonly parameter.
    ParseVuBlkReadOnlyParam(std::str::ParseBoolError),
}

struct VhostUserBlkBackend {
    mem: Option<GuestMemoryMmap>,
    vring_worker: Option<Arc<VringWorker>>,
    disk_image: Box<dyn DiskFile>,
    disk_image_id: Vec<u8>,
    disk_nsectors: u64,
    config: virtio_blk_config,
    iommu: bool,
    rdonly: bool,
}

impl VhostUserBlkBackend {
    pub fn new(image_path: String, iommu: bool, rdonly: bool) -> Result<Self> {
        let raw_img: File = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&image_path)
            .unwrap();

        let image_id = build_disk_image_id(&PathBuf::from(&image_path));
        let image_type = qcow::detect_image_type(&raw_img).unwrap();
        let mut image = match image_type {
            ImageType::Raw => Box::new(vm_virtio::RawFile::new(raw_img)) as Box<dyn DiskFile>,
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
        config.num_queues = 1;

        Ok(VhostUserBlkBackend {
            mem: None,
            vring_worker: None,
            disk_image: image,
            disk_image_id: image_id,
            disk_nsectors: nsectors,
            config,
            iommu,
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
}

impl VhostUserBackend for VhostUserBlkBackend {
    fn num_queues(&self) -> usize {
        NUM_QUEUES
    }

    fn max_queue_size(&self) -> usize {
        QUEUE_SIZE
    }

    fn features(&self) -> u64 {
        let mut avail_features = 1 << VIRTIO_BLK_F_MQ
            | 1 << VIRTIO_F_VERSION_1
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

        if self.iommu {
            avail_features |= 1 << VIRTIO_F_IOMMU_PLATFORM;
        }

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

        let mut vring = vrings[0].write().unwrap();
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

fn parse_iommu(iommu: &str) -> Result<bool> {
    if !iommu.is_empty() {
        let res = match iommu {
            "on" => true,
            "off" => false,
            _ => return Err(Error::ParseDeviceIommu),
        };

        Ok(res)
    } else {
        Ok(false)
    }
}

pub struct VhostUserBlkBackendConfig<'a> {
    pub image: &'a str,
    pub sock: &'a str,
    pub iommu: bool,
    pub readonly: bool,
}

impl<'a> VhostUserBlkBackendConfig<'a> {
    pub fn parse(backend: &'a str) -> Result<Self> {
        let params_list: Vec<&str> = backend.split(',').collect();

        let mut image: &str = "";
        let mut sock: &str = "";
        let mut iommu: bool = false;
        let mut readonly_str: &str = "";

        for param in params_list.iter() {
            if param.starts_with("image=") {
                image = &param[6..];
            } else if param.starts_with("sock=") {
                sock = &param[5..];
            } else if param.starts_with("iommu=") {
                iommu = parse_iommu(&param[6..])?;
            } else if param.starts_with("readonly=") {
                readonly_str = &param[9..];
            }
        }

        let mut readonly: bool = false;

        if image.is_empty() {
            return Err(Error::ParseImageParam);
        }
        if sock.is_empty() {
            return Err(Error::ParseSockParam);
        }
        if !readonly_str.is_empty() {
            readonly = readonly_str
                .parse()
                .map_err(Error::ParseVuBlkReadOnlyParam)?;
        }

        Ok(VhostUserBlkBackendConfig {
            image,
            sock,
            iommu,
            readonly,
        })
    }
}

fn main() {
    let cmd_arguments = App::new("vhost-user-blk backend")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Launch a vhost-user-blk backend.")
        .arg(
            Arg::with_name("backend")
                .long("backend")
                .help(
                    "Backend parameters \"image=<image_path>,\
                     sock=<socket_path>, iommu=on|off,\
                     readonly=true|false\"",
                )
                .takes_value(true)
                .min_values(1),
        )
        .get_matches();

    let vhost_user_blk_backend = cmd_arguments.value_of("backend").unwrap();

    let backend_config = match VhostUserBlkBackendConfig::parse(vhost_user_blk_backend) {
        Ok(config) => config,
        Err(e) => {
            println!("Failed parsing parameters {:?}", e);
            process::exit(1);
        }
    };

    let blk_backend = Arc::new(RwLock::new(
        VhostUserBlkBackend::new(
            backend_config.image.to_string(),
            backend_config.iommu,
            backend_config.readonly,
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

    blk_backend.write().unwrap().vring_worker = Some(vring_worker);

    if let Err(e) = blk_daemon.start() {
        println!(
            "failed to start daemon for vhost-user-blk with error: {:?}\n",
            e
        );
        process::exit(1);
    }

    blk_daemon.wait().unwrap();
}
