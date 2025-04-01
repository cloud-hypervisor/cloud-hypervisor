// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::seccomp_filters::Thread;
use crate::thread_helper::spawn_virtio_thread;
use crate::Error as DeviceError;
use crate::VirtioInterruptType;
use crate::{
    ActivateError, ActivateResult, EpollHelper, EpollHelperError, EpollHelperHandler,
    UserspaceMapping, VirtioCommon, VirtioDevice, VirtioDeviceType, VirtioInterrupt,
    VirtioSharedMemoryList, EPOLL_HELPER_EVENT_LAST, VIRTIO_F_IOMMU_PLATFORM, VIRTIO_F_VERSION_1,
};
use crate::{GuestMemoryMmap, MmapRegion};
use anyhow::anyhow;
use seccompiler::SeccompAction;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io;
use std::io::Error as IOError;
use std::os::unix::io::{AsRawFd, RawFd};
use std::result;
use std::str::FromStr;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Barrier};
use std::time::Duration;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::io::{BufRead, BufReader, Read};
use std::ops::Deref;
use std::sync::Mutex;
use rlimit::Resource;
use virtio_queue::{Queue, QueueT};
use fuse_backend_rs::abi::virtio_fs::RemovemappingOne;
use fuse_backend_rs::api::server::Server;
use fuse_backend_rs::api::{Vfs, VfsIndex, VfsOptions};
use fuse_backend_rs::transport::{FsCacheReqHandler, Reader, VirtioFsWriter, Writer};
use fuse_backend_rs::transport::Error as FuseTransportError;
use fuse_backend_rs::passthrough::{CachePolicy, Config as PassthroughConfig, PassthroughFs};
use fuse_backend_rs::Error as FuseServerError;
use nydus_api::config::ConfigV2;
use nydus_rafs::blobfs::{BlobFs, Config as BlobfsConfig};
use nydus_rafs::{fs::Rafs, RafsIoRead};
use vm_memory::{ByteValued, GuestAddressSpace, GuestMemoryAtomic};
use vm_migration::{
    Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable,
};
use vmm_sys_util::eventfd::EventFd;
use caps::{CapSet, Capability};
use threadpool::ThreadPool;
use serde_with::serde_as;
use serde_with::Bytes;

const NUM_QUEUE_OFFSET: usize = 1;

pub const VIRTIO_FS_NAME: &str = "virtio-fs";

pub type Result<T> = result::Result<T, Error>;

// Attr and entry timeout values
const CACHE_ALWAYS_TIMEOUT: u64 = 86_400; // 1 day
const CACHE_AUTO_TIMEOUT: u64 = 1;
const CACHE_NONE_TIMEOUT: u64 = 0;

// VirtioFs backend fs type
pub const PASSTHROUGHFS: &str = "passthroughfs";
pub const BLOBFS: &str = "blobfs";
pub const RAFS: &str = "rafs";

/// Error for virtio fs device.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid Virtio descriptor chain.
    #[error("invalid descriptorchain: {0}")]
    InvalidDescriptorChain(FuseTransportError),
    /// Processing queue failed.
    #[error("process queue failed: {0}")]
    ProcessQueue(FuseServerError),
    #[error("invalid data.")]
    InvalidData,
    /// Failed to attach/detach a backend fs.
    #[error("attach/detach a backend filesystem failed:: {0}")]
    BackendFs(String),
    /// Error from IO error.
    #[error("io error: {0}")]
    IOError(#[from] IOError),
    /// Invalid input parameter or status.
    #[error("invalid input parameter or status.")]
    InvalidInput,
}

#[derive(Serialize, Deserialize)]
pub struct State {
    pub avail_features: u64,
    pub acked_features: u64,
    pub config: VirtioFsConfig,
}

pub const VIRTIO_FS_TAG_LEN: usize = 36;
#[serde_as]
#[derive(Copy, Clone, Serialize, Deserialize)]
#[repr(C, packed)]
pub struct VirtioFsConfig {
    #[serde_as(as = "Bytes")]
    pub tag: [u8; VIRTIO_FS_TAG_LEN],
    pub num_request_queues: u32,
}

impl Default for VirtioFsConfig {
    fn default() -> Self {
        VirtioFsConfig {
            tag: [0; 36],
            num_request_queues: 0,
        }
    }
}

/// CacheHandler handles DAX window mmap/unmap operations
#[derive(Clone)]
pub struct CacheHandler {
    /// the size of memory region allocated for virtiofs
    pub cache_size: u64,

    /// the address of mmap region corresponding to the memory region
    pub mmap_cache_addr: u64,

    /// the device ID
    pub id: String,
}

impl CacheHandler {
    /// Make sure request is within cache range
    fn is_req_valid(&self, offset: u64, len: u64) -> bool {
        // TODO: do we need to validate alignment here?
        match offset.checked_add(len) {
            Some(n) => n <= self.cache_size,
            None => false,
        }
    }
}

impl FsCacheReqHandler for CacheHandler {
    // Do not close fd in here. The fd is automatically closed in the setupmapping
    // of passthrough_fs when destructing
    fn map(
        &mut self,
        foffset: u64,
        moffset: u64,
        len: u64,
        flags: u64,
        fd: RawFd,
    ) -> result::Result<(), io::Error> {
        debug!("fs_slave_map");

        // Ignore if the length is 0.
        if len == 0 {
            return Ok(());
        }

        if !self.is_req_valid(moffset, len) {
            error!(
                "{}: CacheHandler::map(): Wrong offset or length, offset=0x{:x} len=0x{:x} cache_size=0x{:x}",
                self.id, moffset, len, self.cache_size
            );
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }

        let addr = self.mmap_cache_addr + moffset;
        // TODO:
        // In terms of security, DAX does not easily handle all kinds of write
        // scenarios, especially append write. Therefore, to prevent guest users
        // from using the DAX to write files maliciously, we do not support guest
        // write permission configuration. If DAX needs to support write, we can
        // add write permissions by Control path.
        let ret = unsafe {
            libc::mmap(
                addr as *mut libc::c_void,
                len as usize,
                flags as i32,
                libc::MAP_SHARED | libc::MAP_FIXED,
                fd.as_raw_fd(),
                foffset as libc::off_t,
            )
        };
        if ret == libc::MAP_FAILED {
            error!("{}: CacheHandler::map() failed: {}", VIRTIO_FS_NAME, io::Error::last_os_error());
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    fn unmap(&mut self, requests: Vec<RemovemappingOne>) -> std::result::Result<(), io::Error> {
        debug!("fs_slave_unmap");

        for req in requests {
            let mut offset = req.moffset;
            let mut len = req.len;

            // Ignore if the length is 0.
            if len == 0 {
                continue;
            }

            debug!(
                "{}: do unmap(): offset=0x{:x} len=0x{:x} cache_size=0x{:x}",
                self.id, offset, len, self.cache_size
            );

            // Need to handle a special case where the slave ask for the unmapping
            // of the entire mapping.
            if len == 0xffff_ffff_ffff_ffff {
                len = self.cache_size;
                offset = 0;
            }

            if !self.is_req_valid(offset, len) {
                error!(
                    "{}: CacheHandler::unmap(): Wrong offset or length, offset=0x{:x} len=0x{:x} cache_size=0x{:x}",
                    self.id, offset, len, self.cache_size
                );
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }

            let addr = self.mmap_cache_addr + offset;
            // Use mmap + PROT_NONE can reserve host userspace address while unmap memory.
            // In this way, guest will not be able to access the memory, and dragonball
            // also can reserve the HVA.
            let ret = unsafe {
                libc::mmap(
                    addr as *mut libc::c_void,
                    len as usize,
                    libc::PROT_NONE,
                    libc::MAP_ANONYMOUS | libc::MAP_PRIVATE | libc::MAP_FIXED,
                    -1,
                    0,
                )
            };
            if ret == libc::MAP_FAILED {
                error!("{}: CacheHandler::unmap() failed, {}", self.id, io::Error::last_os_error());
                return Err(io::Error::last_os_error());
            }
        }

        Ok(())
    }
}

pub struct FsEpollHandler {
    pub queue_index: u16,
    pub queue_evt: EventFd,
    pub queue: Arc<Mutex<Queue>>,
    pub thread_pool: Option<ThreadPool>,
    pub mem: GuestMemoryAtomic<GuestMemoryMmap>,
    pub interrupt_cb: Arc<dyn VirtioInterrupt>,
    pub kill_evt: EventFd,
    pub pause_evt: EventFd,
    pub server: Arc<Server<Arc<Vfs>>>,
    pub cache_handler: Option<CacheHandler>,
}

// New descriptors are pending on the virtio queue.
const QUEUE_AVAIL_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;

impl FsEpollHandler {
    fn run(
        &mut self,
        paused: Arc<AtomicBool>,
        paused_sync: Arc<Barrier>,
    ) -> result::Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;

        helper.add_event(self.queue_evt.as_raw_fd(), QUEUE_AVAIL_EVENT)?;
        helper.run(paused, paused_sync, self)?;

        Ok(())
    }

    fn signal_used_queue(&self) -> result::Result<(), DeviceError> {
        self.interrupt_cb
            .trigger(VirtioInterruptType::Queue(self.queue_index))
            .map_err(|e| {
                error!("Failed to signal used queue: {:?}", e);
                DeviceError::FailedSignalingUsedQueue(e)
            })
    }

    fn return_descriptor(queue: &mut Queue, mem: &GuestMemoryMmap, head_index: u16, len: usize) {
        let used_len: u32 = match len.try_into() {
            Ok(l) => l,
            Err(_) => panic!("Invalid used length, can't return used descritors to the ring"),
        };

        if queue.add_used(mem, head_index, used_len).is_err() {
            warn!("Couldn't return used descriptors to the ring");
        }
    }

    fn process_queue(&mut self) -> Result<bool> {
        let mut cache_handler = self.cache_handler.clone();
        let mut used_descs = false;
        let queue_index = self.queue_index;
    
        while let Some(desc_chain) = {
            let mut queue_lock = self.queue.lock().unwrap();
            queue_lock.pop_descriptor_chain(self.mem.memory())
        } {
            let head_index = desc_chain.head_index();
    
            if let Some(pool) = &self.thread_pool {
                let mut cache_handler_clone = cache_handler.clone();
                let server_clone = self.server.clone();

                let queue_clone = self.queue.clone();
                let interrupt_cb_clone = self.interrupt_cb.clone();
    
                pool.execute(move || {
                    let reader = Reader::from_descriptor_chain(desc_chain.memory(), desc_chain.clone())
                        .expect("Failed to create reader");
                    let writer = Writer::VirtioFs(
                        VirtioFsWriter::new(desc_chain.memory(), desc_chain.clone())
                            .expect("Failed to create writer")
                    );

                    let len = server_clone
                        .handle_message(
                            reader,
                            writer,
                            cache_handler_clone
                                .as_mut()
                                .map(|x| x as &mut dyn FsCacheReqHandler),
                            None,
                        )
                        .expect("Failed to handle message");

                    let mut queue_lock = queue_clone.lock().unwrap();
                    Self::return_descriptor(&mut queue_lock, desc_chain.memory(), head_index, len);
                    interrupt_cb_clone
                        .trigger(VirtioInterruptType::Queue(queue_index))
                        .map_err(|e| {
                            error!("Failed to signal used queue: {:?}", e);
                            DeviceError::FailedSignalingUsedQueue(e)
                        }).unwrap();
                });
            } else {
                let reader = Reader::from_descriptor_chain(desc_chain.memory(), desc_chain.clone())
                    .map_err(Error::InvalidDescriptorChain)
                    .unwrap();
                let writer = Writer::VirtioFs(
                    VirtioFsWriter::new(desc_chain.memory(), desc_chain.clone())
                        .map_err(Error::InvalidDescriptorChain)
                        .unwrap(),
                );

                let len = self.server
                    .handle_message(
                        reader,
                        writer,
                        cache_handler
                            .as_mut()
                            .map(|x| x as &mut dyn FsCacheReqHandler),
                        None,
                    )
                    .map_err(Error::ProcessQueue)
                    .unwrap();

                let mut queue_lock = self.queue.lock().unwrap();
                Self::return_descriptor(&mut queue_lock, desc_chain.memory(), head_index, len);
                used_descs = true;
            }
        }
    
        Ok(used_descs)
    }

    fn handle_event_impl(&mut self) -> result::Result<(), EpollHelperError> {
        let needs_notification = self.process_queue().map_err(|e| {
            EpollHelperError::HandleEvent(anyhow!("Failed to process queue (submit): {:?}", e))
        })?;

        if needs_notification {
            self.signal_used_queue().map_err(|e| {
                EpollHelperError::HandleEvent(anyhow!("Failed to signal used queue: {:?}", e))
            })?
        };

        Ok(())
    }
}

impl EpollHelperHandler for FsEpollHandler {
    fn handle_event(
        &mut self,
        _helper: &mut EpollHelper,
        event: &epoll::Event,
    ) -> result::Result<(), EpollHelperError> {
        let ev_type = event.data as u16;
        match ev_type {
            QUEUE_AVAIL_EVENT => {
                self.queue_evt.read().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!("Failed to get queue event: {:?}", e))
                })?;
                self.handle_event_impl()?
            }
            _ => {
                return Err(EpollHelperError::HandleEvent(anyhow!(
                    "Unexpected event: {}",
                    ev_type
                )));
            }
        }
        Ok(())
    }
}

#[allow(dead_code)]
pub struct BackendFsInfo {
    pub(crate) index: VfsIndex,
    pub(crate) fstype: String,
    // (source, config), only suitable for Rafs
    pub(crate) src_cfg: Option<(String, String)>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct BackendFsConfig {
    #[serde(default)]
    pub thread_pool_size: usize,
    #[serde(default)]
    pub cache: u8,
    #[serde(default)]
    pub writeback_cache: bool,
    #[serde(default)]
    pub no_open: bool,
    #[serde(default)]
    pub killpriv_v2: bool,
    #[serde(default)]
    pub no_readdir: bool,
    #[serde(default)]
    pub xattr: bool,
    #[serde(default)]
    pub drop_sys_resource: bool,
}

// SAFETY: only a series of integers
unsafe impl ByteValued for VirtioFsConfig {}

pub struct VirtioFs {
    common: VirtioCommon,
    id: String,
    config: VirtioFsConfig,
    seccomp_action: SeccompAction,
    exit_evt: EventFd,
    backendfs_config: BackendFsConfig,
    fs: Arc<Vfs>,
    backend_fs: HashMap<String, BackendFsInfo>,
    // Hold ownership of the memory that is allocated for the device
    // which will be automatically dropped when the device is dropped
    cache: Option<(VirtioSharedMemoryList, MmapRegion)>,
}

impl VirtioFs {
    /// Create a new virtio-fs device.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        tag: &str,
        req_num_queues: usize,
        queue_size: u16,
        seccomp_action: SeccompAction,
        exit_evt: EventFd,
        iommu: bool,
        state: Option<State>,
        backendfs_config: &BackendFsConfig,
        cache: Option<(VirtioSharedMemoryList, MmapRegion)>,
    ) -> io::Result<VirtioFs> {
        // Calculate the actual number of queues needed.
        let num_queues = NUM_QUEUE_OFFSET + req_num_queues;

        let (avail_features, acked_features, config, paused) = if let Some(state) = state {
            info!("Restoring virtio-fs {}", id);
            (
                state.avail_features,
                state.acked_features,
                state.config,
                true,
            )
        } else {
            // Filling device and vring features VMM supports.
            let mut avail_features: u64 = 1 << VIRTIO_F_VERSION_1;
            if iommu {
                avail_features |= 1 << VIRTIO_F_IOMMU_PLATFORM;
            }

            // Create virtio-fs device configuration.
            let mut config = VirtioFsConfig::default();
            let tag_bytes_vec = tag.to_string().into_bytes();
            config.tag[..tag_bytes_vec.len()].copy_from_slice(tag_bytes_vec.as_slice());
            config.num_request_queues = req_num_queues as u32;

            (avail_features, 0, config, false)
        };

        // Set rlimit first, in case we dropped CAP_SYS_RESOURCE later and hit EPERM.
        if let Err(e) = set_default_rlimit_nofile() {
            warn!("{}: failed to set rlimit: {:?}", VIRTIO_FS_NAME, e);
        }

        if backendfs_config.drop_sys_resource && backendfs_config.writeback_cache {
            error!(
                "{}: writeback_cache is not compatible with drop_sys_resource",
                VIRTIO_FS_NAME
            );
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("invalid para"),
            ));
        }

        // Drop CAP_SYS_RESOURCE when creating VirtioFs device, not in activate(), as it's vcpu
        // thread that calls activate(), but we do I/O in vmm epoll thread, so drop cap here.
        if backendfs_config.drop_sys_resource {
            info!(
                "{}: Dropping CAP_SYS_RESOURCE, tid {:?}",
                VIRTIO_FS_NAME,
                nix::unistd::gettid()
            );
            if let Err(e) = caps::drop(None, CapSet::Effective, Capability::CAP_SYS_RESOURCE) {
                warn!(
                    "{}: failed to drop CAP_SYS_RESOURCE: {:?}",
                    VIRTIO_FS_NAME, e
                );
            }
        }

        let vfs_opts = VfsOptions {
            #[cfg(target_os = "linux")]
            no_writeback: !backendfs_config.writeback_cache,
            #[cfg(target_os = "linux")]
            no_open: backendfs_config.no_open,
            #[cfg(target_os = "linux")]
            killpriv_v2: backendfs_config.killpriv_v2,
            no_readdir: backendfs_config.no_readdir,
            ..VfsOptions::default()
        };

        Ok(VirtioFs {
            common: VirtioCommon {
                device_type: VirtioDeviceType::Fs as u32,
                avail_features,
                acked_features,
                queue_sizes: vec![queue_size; num_queues],
                paused_sync: Some(Arc::new(Barrier::new(2))),
                min_queues: 1,
                paused: Arc::new(AtomicBool::new(paused)),
                ..Default::default()
            },
            id,
            config,
            seccomp_action,
            exit_evt,
            backendfs_config: backendfs_config.clone(),
            backend_fs: HashMap::new(),
            fs: Arc::new(Vfs::new(vfs_opts)),
            cache,
        })
    }

    fn state(&self) -> State {
        State {
            avail_features: self.common.avail_features,
            acked_features: self.common.acked_features,
            config: self.config,
        }
    }

    fn get_timeout(&self) -> Duration {
        match self.backendfs_config.cache {
            2 => Duration::from_secs(CACHE_ALWAYS_TIMEOUT),
            0 => Duration::from_secs(CACHE_NONE_TIMEOUT),
            1 => Duration::from_secs(CACHE_AUTO_TIMEOUT),
            3_u8..=u8::MAX => Duration::from_secs(CACHE_NONE_TIMEOUT),
        }
    }

    fn get_cachepolicy(&self) -> CachePolicy {
        match self.backendfs_config.cache {
            2 => CachePolicy::Always,
            0 => CachePolicy::Never,
            1 => CachePolicy::Auto,
            3_u8..=u8::MAX => CachePolicy::Never,
        }
    }


    fn parse_blobfs_cfg(
        &self,
        source: &str,
        config: Option<String>,
        dax_threshold_size_kb: Option<u64>,
    ) -> Result<(String, String, Option<u64>)> {
        let (blob_cache_dir, blob_ondemand_cfg) = match config.as_ref() {
            Some(cfg) => {
                let conf = ConfigV2::from_str(cfg).map_err(|e| {
                    error!("failed to load rafs config {} error: {:?}", &cfg, e);
                    Error::InvalidData
                })?;

                // v6 doesn't support digest validation yet.
                if conf.rafs.ok_or(Error::InvalidData)?.validate {
                    error!("config.digest_validate needs to be false");
                    return Err(Error::InvalidData);
                }

                let work_dir = conf
                    .cache
                    .ok_or(Error::InvalidData)?
                    .file_cache
                    .ok_or(Error::InvalidData)?
                    .work_dir;

                let blob_ondemand_cfg = format!(
                    r#"
                    {{
                        "rafs_conf": {},
                        "bootstrap_path": "{}",
                        "blob_cache_dir": "{}"
                    }}"#,
                    cfg, source, &work_dir
                );

                (work_dir, blob_ondemand_cfg)
            }
            None => return Err(Error::BackendFs("no rafs config file".to_string())),
        };

        let dax_file_size = match dax_threshold_size_kb {
            Some(size) => Some(kb_to_bytes(size)?),
            None => None,
        };

        Ok((blob_cache_dir, blob_ondemand_cfg, dax_file_size))
    }

    pub fn manipulate_backend_fs(
        &mut self,
        source: Option<String>,
        fstype: Option<String>,
        mountpoint: &str,
        config: Option<String>,
        ops: &str,
        prefetch_list_path: Option<String>,
        dax_threshold_size_kb: Option<u64>,
    ) -> Result<()> {
        debug!(
            "source {:?}, fstype {:?}, mountpoint {:?}, config {:?}, ops {:?}, prefetch_list_path {:?}, dax_threshold_size_kb 0x{:x?}",
            source, fstype, mountpoint, config, ops, prefetch_list_path, dax_threshold_size_kb
        );
        match ops {
            "mount" => {
                if source.is_none() {
                    error!("{}: source is required for mount.", VIRTIO_FS_NAME);
                    return Err(Error::InvalidData);
                }
                // safe because is not None
                let source = source.unwrap();
                match fstype.as_deref() {
                    Some("Blobfs") | Some(BLOBFS) => {
                        self.mount_blobfs(source, mountpoint, config, dax_threshold_size_kb)
                    }
                    Some("PassthroughFs") | Some(PASSTHROUGHFS) => {
                        self.mount_passthroughfs(source, mountpoint, dax_threshold_size_kb)
                    }
                    Some("Rafs") | Some(RAFS) => {
                        self.mount_rafs(source, mountpoint, config, prefetch_list_path)
                    }
                    _ => {
                        error!("virtio-fs: type is not invalid.");
                        Err(Error::InvalidData)
                    }
                }
            }
            "umount" => {
                self.fs.umount(mountpoint).map_err(|e| {
                    error!("umount {:?}", e);
                    Error::InvalidData
                })?;
                self.backend_fs.remove(mountpoint);
                Ok(())
            }
            "update" => {
                info!("switch backend");
                self.update_rafs(source, mountpoint, config)
            }
            _ => {
                error!("invalid ops, mount failed.");
                Err(Error::InvalidData)
            }
        }
    }

    fn mount_blobfs(
        &mut self,
        source: String,
        mountpoint: &str,
        config: Option<String>,
        dax_threshold_size_kb: Option<u64>,
    ) -> Result<()> {
        debug!("virtio-fs blobfs");
        let timeout = self.get_timeout();
        let (blob_cache_dir, blob_ondemand_cfg, dax_file_size) =
            self.parse_blobfs_cfg(&source, config, dax_threshold_size_kb)?;

        let fs_cfg = BlobfsConfig {
            ps_config: PassthroughConfig {
                root_dir: blob_cache_dir,
                do_import: true,
                writeback: self.backendfs_config.writeback_cache,
                no_open: self.backendfs_config.no_open,
                xattr: self.backendfs_config.xattr,
                cache_policy: self.get_cachepolicy(),
                entry_timeout: timeout,
                attr_timeout: timeout,
                dax_file_size,
                ..Default::default()
            },
            blob_ondemand_cfg,
        };
        let blob_fs = BlobFs::new(fs_cfg).map_err(Error::IOError)?;
        blob_fs.import().map_err(Error::IOError)?;
        debug!("blobfs mounted");

        let fs = Box::new(blob_fs);
        match self.fs.mount(fs, mountpoint) {
            Ok(idx) => {
                self.backend_fs.insert(
                    mountpoint.to_string(),
                    BackendFsInfo {
                        index: idx,
                        fstype: BLOBFS.to_string(),
                        src_cfg: None,
                    },
                );
                Ok(())
            }
            Err(e) => {
                error!("blobfs mount {:?}", e);
                Err(Error::InvalidData)
            }
        }
    }

    fn mount_passthroughfs(
        &mut self,
        source: String,
        mountpoint: &str,
        dax_threshold_size_kb: Option<u64>,
    ) -> Result<()> {
        debug!("virtio-fs passthrough");
        let timeout = self.get_timeout();

        let dax_threshold_size = match dax_threshold_size_kb {
            Some(size) => Some(kb_to_bytes(size)?),
            None => None,
        };

        let fs_cfg = PassthroughConfig {
            root_dir: source,
            do_import: false,
            writeback: self.backendfs_config.writeback_cache,
            no_open: self.backendfs_config.no_open,
            no_readdir: self.backendfs_config.no_readdir,
            killpriv_v2: self.backendfs_config.killpriv_v2,
            xattr: self.backendfs_config.xattr,
            cache_policy: self.get_cachepolicy(),
            entry_timeout: timeout,
            attr_timeout: timeout,
            dax_file_size: dax_threshold_size,
            ..Default::default()
        };

        let passthrough_fs = PassthroughFs::<()>::new(fs_cfg).map_err(Error::IOError)?;
        passthrough_fs.import().map_err(Error::IOError)?;
        debug!("passthroughfs mounted");

        let fs = Box::new(passthrough_fs);
        match self.fs.mount(fs, mountpoint) {
            Ok(idx) => {
                self.backend_fs.insert(
                    mountpoint.to_string(),
                    BackendFsInfo {
                        index: idx,
                        fstype: PASSTHROUGHFS.to_string(),
                        src_cfg: None,
                    },
                );
                Ok(())
            }
            Err(e) => {
                error!("passthroughfs mount {:?}", e);
                Err(Error::InvalidData)
            }
        }
    }

    fn mount_rafs(
        &mut self,
        source: String,
        mountpoint: &str,
        config: Option<String>,
        prefetch_list_path: Option<String>,
    ) -> Result<()> {
        debug!("virtio-fs rafs");
        let file = Path::new(&source);
        let (mut rafs, rafs_cfg) = match config.as_ref() {
            Some(cfg) => {
                let rafs_conf: Arc<ConfigV2> = Arc::new(
                    ConfigV2::from_str(cfg).map_err(|e| Error::BackendFs(e.to_string()))?,
                );

                (
                    Rafs::new(&rafs_conf, mountpoint, file)
                        .map_err(|e| Error::BackendFs(format!("Rafs::new() failed: {e:?}")))?,
                    cfg.clone(),
                )
            }
            None => return Err(Error::BackendFs("no rafs config file".to_string())),
        };
        let prefetch_files = parse_prefetch_files(prefetch_list_path.clone());
        debug!(
            "{}: Import rafs with prefetch_files {:?}",
            VIRTIO_FS_NAME, prefetch_files
        );
        rafs.0
            .import(rafs.1, prefetch_files)
            .map_err(|e| Error::BackendFs(format!("Import rafs failed: {e:?}")))?;
        info!(
            "{}: Rafs imported with prefetch_list_path {:?}",
            VIRTIO_FS_NAME, prefetch_list_path
        );
        let fs = Box::new(rafs.0);
        match self.fs.mount(fs, mountpoint) {
            Ok(idx) => {
                self.backend_fs.insert(
                    mountpoint.to_string(),
                    BackendFsInfo {
                        index: idx,
                        fstype: RAFS.to_string(),
                        src_cfg: Some((source, rafs_cfg)),
                    },
                );
                Ok(())
            }
            Err(e) => {
                error!("Rafs mount failed: {:?}", e);
                Err(Error::InvalidData)
            }
        }
    }

    fn update_rafs(
        &mut self,
        source: Option<String>,
        mountpoint: &str,
        config: Option<String>,
    ) -> Result<()> {
        if config.is_none() {
            return Err(Error::BackendFs("no rafs config file".to_string()));
        }
        if source.is_none() {
            return Err(Error::BackendFs(format!(
                "rafs mounted at {mountpoint} doesn't have source configured"
            )));
        }
        // safe because config is not None.
        let config = config.unwrap();
        let source = source.unwrap();
        let rafs_conf: Arc<ConfigV2> =
            Arc::new(serde_json::from_str(&config).map_err(|e| Error::BackendFs(e.to_string()))?);
        // Update rafs config, update BackendFsInfo as well.
        let new_info = match self.backend_fs.get(mountpoint) {
            Some(orig_info) => BackendFsInfo {
                index: orig_info.index,
                fstype: orig_info.fstype.clone(),
                src_cfg: Some((source.to_string(), config)),
            },
            None => {
                return Err(Error::BackendFs(format!(
                    "rafs mount point {mountpoint} is not mounted"
                )));
            }
        };
        let rootfs = match self.fs.get_rootfs(mountpoint) {
            Ok(fs) => match fs {
                Some(f) => f,
                None => {
                    return Err(Error::BackendFs(format!(
                        "rafs get_rootfs() failed: mountpoint {mountpoint} not mounted"
                    )));
                }
            },
            Err(e) => {
                return Err(Error::BackendFs(format!(
                    "rafs get_rootfs() failed: {e:?}"
                )));
            }
        };
        let any_fs = rootfs.deref().as_any();
        if let Some(fs_swap) = any_fs.downcast_ref::<Rafs>() {
            let mut file = <dyn RafsIoRead>::from_file(&source)
                .map_err(|e| Error::BackendFs(format!("RafsIoRead failed: {e:?}")))?;

            fs_swap
                .update(&mut file, &rafs_conf)
                .map_err(|e| Error::BackendFs(format!("Update rafs failed: {e:?}")))?;
            self.backend_fs.insert(mountpoint.to_string(), new_info);
            Ok(())
        } else {
            Err(Error::BackendFs("no rafs is found".to_string()))
        }
    }

    pub fn get_tag(&mut self) -> String {
        String::from_utf8_lossy(&self.config.tag).into_owned().trim_end_matches('\0').to_string()
    }
}

impl Drop for VirtioFs {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.common.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
    }
}

fn parse_prefetch_files(prefetch_list_path: Option<String>) -> Option<Vec<PathBuf>> {
    let prefetch_files: Option<Vec<PathBuf>> = match prefetch_list_path {
        Some(p) => {
            match File::open(p.as_str()) {
                Ok(f) => {
                    let r = BufReader::new(f);
                    // All prefetch files should be absolute path
                    let v: Vec<PathBuf> = r
                        .lines()
                        .filter(|l| {
                            let lref = l.as_ref();
                            lref.is_ok() && lref.unwrap().starts_with('/')
                        })
                        .map(|l| PathBuf::from(l.unwrap().as_str()))
                        .collect();
                    if v.is_empty() {
                        None
                    } else {
                        Some(v)
                    }
                }
                Err(e) => {
                    // We could contineu without prefetch files, just print warning and return
                    warn!(
                        "{}: Open prefetch_file_path {} failed: {:?}",
                        VIRTIO_FS_NAME,
                        p.as_str(),
                        e
                    );
                    None
                }
            }
        }
        None => None,
    };
    prefetch_files
}

fn kb_to_bytes(kb: u64) -> Result<u64> {
    if (kb & 0xffc0_0000_0000_0000) != 0 {
        error!(
            "dax_threshold_size_kb * 1024 overflow. dax_threshold_size_kb is 0x{:x}.",
            kb
        );
        return Err(Error::InvalidData);
    }

    let bytes = kb << 10;
    Ok(bytes)
}

fn set_default_rlimit_nofile() -> Result<()> {
    // Our default RLIMIT_NOFILE target.
    let mut max_fds: u64 = 300_000;
    // leave at least this many fds free
    let reserved_fds: u64 = 16_384;

    // Reduce max_fds below the system-wide maximum, if necessary.
    // This ensures there are fds available for other processes so we
    // don't cause resource exhaustion.
    let mut file_max = String::new();
    let mut f = File::open("/proc/sys/fs/file-max").map_err(|e| {
        error!(
            "{}: failed to read /proc/sys/fs/file-max {:?}",
            VIRTIO_FS_NAME, e
        );
        Error::IOError(e)
    })?;
    f.read_to_string(&mut file_max)?;
    let file_max = file_max.trim().parse::<u64>().map_err(|e| {
        error!("{}: read fs.file-max sysctl wrong {:?}", VIRTIO_FS_NAME, e);
        Error::InvalidInput
    })?;
    if file_max < 2 * reserved_fds {
        error!(
            "{}: The fs.file-max sysctl ({}) is too low to allow a reasonable number of open files ({}).",
            VIRTIO_FS_NAME, file_max, 2 * reserved_fds
        );
        return Err(Error::InvalidInput);
    }

    max_fds = std::cmp::min(file_max - reserved_fds, max_fds);
    let rlimit_nofile = Resource::NOFILE
        .get()
        .map(|(curr, _)| if curr >= max_fds { 0 } else { max_fds })
        .map_err(|e| {
            error!("{}: failed to get rlimit {:?}", VIRTIO_FS_NAME, e);
            Error::IOError(e)
        })?;

    if rlimit_nofile == 0 {
        info!(
            "{}: original rlimit nofile is greater than max_fds({}), keep rlimit nofile setting",
            VIRTIO_FS_NAME, max_fds
        );
        Ok(())
    } else {
        info!(
            "{}: set rlimit {} (max_fds {})",
            VIRTIO_FS_NAME, rlimit_nofile, max_fds
        );

        Resource::NOFILE
            .set(rlimit_nofile, rlimit_nofile)
            .map_err(|e| {
                error!("{}: failed to set rlimit {:?}", VIRTIO_FS_NAME, e);
                Error::IOError(e)
            })
    }
}

impl VirtioDevice for VirtioFs {
    fn device_type(&self) -> u32 {
        self.common.device_type
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.common.queue_sizes
    }

    fn features(&self) -> u64 {
        self.common.avail_features
    }

    fn ack_features(&mut self, value: u64) {
        self.common.ack_features(value)
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        self.read_config_from_slice(self.config.as_slice(), offset, data);
    }

    fn activate(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        interrupt_cb: Arc<dyn VirtioInterrupt>,
        mut queues: Vec<(usize, Queue, EventFd)>,
    ) -> ActivateResult {
        self.common.activate(&queues, &interrupt_cb)?;
        // Test that unshare(CLONE_FS) works, it will be called for each thread.
        // It's an unprivileged system call but some Docker/Moby versions are
        // known to reject it via seccomp when CAP_SYS_ADMIN is not given.
        //
        // Note that the program is single-threaded here so this syscall has no
        // visible effect and is safe to make.
        let ret = unsafe { libc::unshare(libc::CLONE_FS) };
        if ret == -1 {
            return Err(ActivateError::ActivateVirtioFs(io::Error::last_os_error()));
        }

        let mut epoll_threads = Vec::new();
        for i in 0..queues.len() {
            let (_, queue, queue_evt) = queues.remove(0);
            let (kill_evt, pause_evt) = self.common.dup_eventfds();

            let cache_handler = if let Some(cache) = self.cache.as_ref() {
                let handler = CacheHandler {
                    cache_size: cache.0.len,
                    mmap_cache_addr: cache.0.host_addr,
                    id: self.id.clone(),
                };

                Some(handler)
            } else {
                None
            };
            let thread_pool = if self.backendfs_config.thread_pool_size > 0 {
                Some(ThreadPool::with_name(
                    "virtiofs-thread".to_string(),
                    self.backendfs_config.thread_pool_size as usize,
                ))
            } else {
                None
            };
            let mut handler = FsEpollHandler {
                queue_index: i as u16,
                queue_evt,
                queue: Arc::new(Mutex::new(queue)),
                thread_pool,
                mem: mem.clone(),
                interrupt_cb: interrupt_cb.clone(),
                kill_evt,
                pause_evt,
                server: Arc::new(Server::new(self.fs.clone())),
                cache_handler,
            };

            let paused = self.common.paused.clone();
            let paused_sync = self.common.paused_sync.clone();

            spawn_virtio_thread(
                &format!("{}_q{}", self.id.clone(), i),
                &self.seccomp_action,
                Thread::VirtioFs,
                &mut epoll_threads,
                &self.exit_evt,
                move || handler.run(paused, paused_sync.unwrap()),
            )?;
        }

        self.common.epoll_threads = Some(epoll_threads);
        event!("virtio-device", "activated", "id", &self.id);

        Ok(())
    }

    fn reset(&mut self) -> Option<Arc<dyn VirtioInterrupt>> {
        // We first must resume the virtio thread if it was paused.
        if self.common.pause_evt.take().is_some() {
            self.common.resume().ok()?;
        }

        if let Some(kill_evt) = self.common.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }

        event!("virtio-device", "reset", "id", &self.id);

        // Return the interrupt
        Some(self.common.interrupt_cb.take().unwrap())
    }

    fn get_shm_regions(&self) -> Option<VirtioSharedMemoryList> {
        self.cache.as_ref().map(|cache| cache.0.clone())
    }

    fn set_shm_regions(
        &mut self,
        shm_regions: VirtioSharedMemoryList,
    ) -> std::result::Result<(), crate::Error> {
        if let Some(cache) = self.cache.as_mut() {
            cache.0 = shm_regions;
            Ok(())
        } else {
            Err(crate::Error::SetShmRegionsNotSupported)
        }
    }

    fn userspace_mappings(&self) -> Vec<UserspaceMapping> {
        let mut mappings = Vec::new();
        if let Some(cache) = self.cache.as_ref() {
            mappings.push(UserspaceMapping {
                host_addr: cache.0.host_addr,
                mem_slot: cache.0.mem_slot,
                addr: cache.0.addr,
                len: cache.0.len,
                mergeable: false,
            })
        }

        mappings
    }
}

impl Pausable for VirtioFs {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        self.common.pause()
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        self.common.resume()
    }
}

impl Snapshottable for VirtioFs {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        Snapshot::new_from_state(&self.state())
    }
}
impl Transportable for VirtioFs {}
impl Migratable for VirtioFs {}


