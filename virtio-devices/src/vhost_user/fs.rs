// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::vu_common_ctrl::VhostUserHandle;
use super::{Error, Result, DEFAULT_VIRTIO_FEATURES};
use crate::seccomp_filters::{get_seccomp_filter, Thread};
use crate::vhost_user::{Inflight, VhostUserEpollHandler};
use crate::{
    ActivateError, ActivateResult, Queue, UserspaceMapping, VirtioCommon, VirtioDevice,
    VirtioDeviceType, VirtioInterrupt, VirtioSharedMemoryList,
};
use crate::{GuestMemoryMmap, GuestRegionMmap, MmapRegion};
use anyhow::anyhow;
use libc::{self, c_void, off64_t, pread64, pwrite64};
use seccomp::{SeccompAction, SeccompFilter};
use std::io;
use std::ops::Deref;
use std::os::unix::io::AsRawFd;
use std::result;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;
use vhost::vhost_user::message::{
    VhostUserFSSlaveMsg, VhostUserFSSlaveMsgFlags, VhostUserProtocolFeatures,
    VhostUserVirtioFeatures, VHOST_USER_FS_SLAVE_ENTRIES,
};
use vhost::vhost_user::{
    HandlerResult, MasterReqHandler, VhostUserMaster, VhostUserMasterReqHandler,
};
use vm_memory::{
    Address, ByteValued, GuestAddress, GuestAddressSpace, GuestMemory, GuestMemoryAtomic,
};
use vm_migration::{
    protocol::MemoryRangeTable, Migratable, MigratableError, Pausable, Snapshot, Snapshottable,
    Transportable, VersionMapped,
};
use vmm_sys_util::eventfd::EventFd;

const NUM_QUEUE_OFFSET: usize = 1;
const DEFAULT_QUEUE_NUMBER: usize = 2;

#[derive(Versionize)]
pub struct State {
    pub avail_features: u64,
    pub acked_features: u64,
    pub config: VirtioFsConfig,
    pub acked_protocol_features: u64,
    pub vu_num_queues: usize,
    pub slave_req_support: bool,
}

impl VersionMapped for State {}

struct SlaveReqHandler {
    cache_offset: GuestAddress,
    cache_size: u64,
    mmap_cache_addr: u64,
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
}

impl SlaveReqHandler {
    // Make sure request is within cache range
    fn is_req_valid(&self, offset: u64, len: u64) -> bool {
        let end = match offset.checked_add(len) {
            Some(n) => n,
            None => return false,
        };

        !(offset >= self.cache_size || end > self.cache_size)
    }
}

impl VhostUserMasterReqHandler for SlaveReqHandler {
    fn handle_config_change(&self) -> HandlerResult<u64> {
        debug!("handle_config_change");
        Ok(0)
    }

    fn fs_slave_map(&self, fs: &VhostUserFSSlaveMsg, fd: &dyn AsRawFd) -> HandlerResult<u64> {
        debug!("fs_slave_map");

        for i in 0..VHOST_USER_FS_SLAVE_ENTRIES {
            let offset = fs.cache_offset[i];
            let len = fs.len[i];

            // Ignore if the length is 0.
            if len == 0 {
                continue;
            }

            if !self.is_req_valid(offset, len) {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }

            let addr = self.mmap_cache_addr + offset;
            let flags = fs.flags[i];
            let ret = unsafe {
                libc::mmap(
                    addr as *mut libc::c_void,
                    len as usize,
                    flags.bits() as i32,
                    libc::MAP_SHARED | libc::MAP_FIXED,
                    fd.as_raw_fd(),
                    fs.fd_offset[i] as libc::off_t,
                )
            };
            if ret == libc::MAP_FAILED {
                return Err(io::Error::last_os_error());
            }

            let ret = unsafe { libc::close(fd.as_raw_fd()) };
            if ret == -1 {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(0)
    }

    fn fs_slave_unmap(&self, fs: &VhostUserFSSlaveMsg) -> HandlerResult<u64> {
        debug!("fs_slave_unmap");

        for i in 0..VHOST_USER_FS_SLAVE_ENTRIES {
            let offset = fs.cache_offset[i];
            let mut len = fs.len[i];

            // Ignore if the length is 0.
            if len == 0 {
                continue;
            }

            // Need to handle a special case where the slave ask for the unmapping
            // of the entire mapping.
            if len == 0xffff_ffff_ffff_ffff {
                len = self.cache_size;
            }

            if !self.is_req_valid(offset, len) {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }

            let addr = self.mmap_cache_addr + offset;
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
                return Err(io::Error::last_os_error());
            }
        }

        Ok(0)
    }

    fn fs_slave_sync(&self, fs: &VhostUserFSSlaveMsg) -> HandlerResult<u64> {
        debug!("fs_slave_sync");

        for i in 0..VHOST_USER_FS_SLAVE_ENTRIES {
            let offset = fs.cache_offset[i];
            let len = fs.len[i];

            // Ignore if the length is 0.
            if len == 0 {
                continue;
            }

            if !self.is_req_valid(offset, len) {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }

            let addr = self.mmap_cache_addr + offset;
            let ret =
                unsafe { libc::msync(addr as *mut libc::c_void, len as usize, libc::MS_SYNC) };
            if ret == -1 {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(0)
    }

    fn fs_slave_io(&self, fs: &VhostUserFSSlaveMsg, fd: &dyn AsRawFd) -> HandlerResult<u64> {
        debug!("fs_slave_io");

        let mut done: u64 = 0;
        for i in 0..VHOST_USER_FS_SLAVE_ENTRIES {
            // Ignore if the length is 0.
            if fs.len[i] == 0 {
                continue;
            }

            let mut foffset = fs.fd_offset[i];
            let mut len = fs.len[i] as usize;
            let gpa = fs.cache_offset[i];
            let cache_end = self.cache_offset.raw_value() + self.cache_size;
            let efault = libc::EFAULT;

            let mut ptr = if gpa >= self.cache_offset.raw_value() && gpa < cache_end {
                let offset = gpa
                    .checked_sub(self.cache_offset.raw_value())
                    .ok_or_else(|| io::Error::from_raw_os_error(efault))?;
                let end = gpa
                    .checked_add(fs.len[i])
                    .ok_or_else(|| io::Error::from_raw_os_error(efault))?;

                if end >= cache_end {
                    return Err(io::Error::from_raw_os_error(efault));
                }

                self.mmap_cache_addr + offset
            } else {
                self.mem
                    .memory()
                    .get_host_address(GuestAddress(gpa))
                    .map_err(|e| {
                        error!(
                            "Failed to find RAM region associated with guest physical address 0x{:x}: {:?}",
                            gpa, e
                        );
                        io::Error::from_raw_os_error(efault)
                    })? as u64
            };

            while len > 0 {
                let ret = if (fs.flags[i] & VhostUserFSSlaveMsgFlags::MAP_W)
                    == VhostUserFSSlaveMsgFlags::MAP_W
                {
                    debug!("write: foffset={}, len={}", foffset, len);
                    unsafe {
                        pwrite64(
                            fd.as_raw_fd(),
                            ptr as *const c_void,
                            len as usize,
                            foffset as off64_t,
                        )
                    }
                } else {
                    debug!("read: foffset={}, len={}", foffset, len);
                    unsafe {
                        pread64(
                            fd.as_raw_fd(),
                            ptr as *mut c_void,
                            len as usize,
                            foffset as off64_t,
                        )
                    }
                };

                if ret < 0 {
                    return Err(io::Error::last_os_error());
                }

                if ret == 0 {
                    // EOF
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "failed to access whole buffer",
                    ));
                }
                len -= ret as usize;
                foffset += ret as u64;
                ptr += ret as u64;
                done += ret as u64;
            }
        }

        let ret = unsafe { libc::close(fd.as_raw_fd()) };
        if ret == -1 {
            return Err(io::Error::last_os_error());
        }

        Ok(done)
    }
}

#[derive(Copy, Clone, Versionize)]
#[repr(C, packed)]
pub struct VirtioFsConfig {
    pub tag: [u8; 36],
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

unsafe impl ByteValued for VirtioFsConfig {}

pub struct Fs {
    common: VirtioCommon,
    id: String,
    vu: Option<Arc<Mutex<VhostUserHandle>>>,
    config: VirtioFsConfig,
    // Hold ownership of the memory that is allocated for the device
    // which will be automatically dropped when the device is dropped
    cache: Option<(VirtioSharedMemoryList, MmapRegion)>,
    slave_req_support: bool,
    seccomp_action: SeccompAction,
    guest_memory: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    acked_protocol_features: u64,
    socket_path: String,
    epoll_thread: Option<thread::JoinHandle<()>>,
    vu_num_queues: usize,
    migration_started: bool,
}

impl Fs {
    /// Create a new virtio-fs device.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        path: &str,
        tag: &str,
        req_num_queues: usize,
        queue_size: u16,
        cache: Option<(VirtioSharedMemoryList, MmapRegion)>,
        seccomp_action: SeccompAction,
        restoring: bool,
    ) -> Result<Fs> {
        let mut slave_req_support = false;

        // Calculate the actual number of queues needed.
        let num_queues = NUM_QUEUE_OFFSET + req_num_queues;

        if restoring {
            // We need 'queue_sizes' to report a number of queues that will be
            // enough to handle all the potential queues. VirtioPciDevice::new()
            // will create the actual queues based on this information.
            return Ok(Fs {
                id,
                common: VirtioCommon {
                    device_type: VirtioDeviceType::Fs as u32,
                    queue_sizes: vec![queue_size; num_queues],
                    paused_sync: Some(Arc::new(Barrier::new(2))),
                    min_queues: DEFAULT_QUEUE_NUMBER as u16,
                    ..Default::default()
                },
                vu: None,
                config: VirtioFsConfig::default(),
                cache,
                slave_req_support,
                seccomp_action,
                guest_memory: None,
                acked_protocol_features: 0,
                socket_path: path.to_string(),
                epoll_thread: None,
                vu_num_queues: num_queues,
                migration_started: false,
            });
        }

        // Connect to the vhost-user socket.
        let mut vu = VhostUserHandle::connect_vhost_user(false, path, num_queues as u64, false)?;

        // Filling device and vring features VMM supports.
        let avail_features = DEFAULT_VIRTIO_FEATURES;

        let mut avail_protocol_features = VhostUserProtocolFeatures::MQ
            | VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS
            | VhostUserProtocolFeatures::REPLY_ACK
            | VhostUserProtocolFeatures::INFLIGHT_SHMFD
            | VhostUserProtocolFeatures::LOG_SHMFD;
        let slave_protocol_features =
            VhostUserProtocolFeatures::SLAVE_REQ | VhostUserProtocolFeatures::SLAVE_SEND_FD;
        if cache.is_some() {
            avail_protocol_features |= slave_protocol_features;
        }

        let (acked_features, acked_protocol_features) =
            vu.negotiate_features_vhost_user(avail_features, avail_protocol_features)?;

        let backend_num_queues =
            if acked_protocol_features & VhostUserProtocolFeatures::MQ.bits() != 0 {
                vu.socket_handle()
                    .get_queue_num()
                    .map_err(Error::VhostUserGetQueueMaxNum)? as usize
            } else {
                DEFAULT_QUEUE_NUMBER
            };

        if num_queues > backend_num_queues {
            error!(
                "vhost-user-fs requested too many queues ({}) since the backend only supports {}\n",
                num_queues, backend_num_queues
            );
            return Err(Error::BadQueueNum);
        }

        if acked_protocol_features & slave_protocol_features.bits()
            == slave_protocol_features.bits()
        {
            slave_req_support = true;
        }

        // Create virtio-fs device configuration.
        let mut config = VirtioFsConfig::default();
        let tag_bytes_vec = tag.to_string().into_bytes();
        config.tag[..tag_bytes_vec.len()].copy_from_slice(tag_bytes_vec.as_slice());
        config.num_request_queues = req_num_queues as u32;

        Ok(Fs {
            common: VirtioCommon {
                device_type: VirtioDeviceType::Fs as u32,
                avail_features: acked_features,
                acked_features: 0,
                queue_sizes: vec![queue_size; num_queues],
                paused_sync: Some(Arc::new(Barrier::new(2))),
                min_queues: DEFAULT_QUEUE_NUMBER as u16,
                ..Default::default()
            },
            id,
            vu: Some(Arc::new(Mutex::new(vu))),
            config,
            cache,
            slave_req_support,
            seccomp_action,
            guest_memory: None,
            acked_protocol_features,
            socket_path: path.to_string(),
            epoll_thread: None,
            vu_num_queues: num_queues,
            migration_started: false,
        })
    }

    fn state(&self) -> State {
        State {
            avail_features: self.common.avail_features,
            acked_features: self.common.acked_features,
            config: self.config,
            acked_protocol_features: self.acked_protocol_features,
            vu_num_queues: self.vu_num_queues,
            slave_req_support: self.slave_req_support,
        }
    }

    fn set_state(&mut self, state: &State) {
        self.common.avail_features = state.avail_features;
        self.common.acked_features = state.acked_features;
        self.config = state.config;
        self.acked_protocol_features = state.acked_protocol_features;
        self.vu_num_queues = state.vu_num_queues;
        self.slave_req_support = state.slave_req_support;

        let mut vu = match VhostUserHandle::connect_vhost_user(
            false,
            &self.socket_path,
            self.vu_num_queues as u64,
            false,
        ) {
            Ok(r) => r,
            Err(e) => {
                error!("Failed connecting vhost-user backend: {:?}", e);
                return;
            }
        };

        if let Err(e) = vu.set_protocol_features_vhost_user(
            self.common.acked_features,
            self.acked_protocol_features,
        ) {
            error!("Failed setting up vhost-user backend: {:?}", e);
            return;
        }

        self.vu = Some(Arc::new(Mutex::new(vu)));
    }
}

impl Drop for Fs {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.common.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
    }
}

impl VirtioDevice for Fs {
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
        queues: Vec<Queue>,
        queue_evts: Vec<EventFd>,
    ) -> ActivateResult {
        self.common.activate(&queues, &queue_evts, &interrupt_cb)?;
        self.guest_memory = Some(mem.clone());

        // Initialize slave communication.
        let slave_req_handler = if self.slave_req_support {
            if let Some(cache) = self.cache.as_ref() {
                let vu_master_req_handler = Arc::new(SlaveReqHandler {
                    cache_offset: cache.0.addr,
                    cache_size: cache.0.len,
                    mmap_cache_addr: cache.0.host_addr,
                    mem: mem.clone(),
                });

                let mut req_handler =
                    MasterReqHandler::new(vu_master_req_handler).map_err(|e| {
                        ActivateError::VhostUserFsSetup(Error::MasterReqHandlerCreation(e))
                    })?;
                req_handler.set_reply_ack_flag(true);
                Some(req_handler)
            } else {
                None
            }
        } else {
            None
        };

        // The backend acknowledged features must contain the protocol feature
        // bit in case it was initially set but lost through the features
        // negotiation with the guest.
        let backend_acked_features = self.common.acked_features
            | (self.common.avail_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits());

        let mut inflight: Option<Inflight> =
            if self.acked_protocol_features & VhostUserProtocolFeatures::INFLIGHT_SHMFD.bits() != 0
            {
                Some(Inflight::default())
            } else {
                None
            };

        if self.vu.is_none() {
            error!("Missing vhost-user handle");
            return Err(ActivateError::BadActivate);
        }
        let vu = self.vu.as_ref().unwrap();
        vu.lock()
            .unwrap()
            .setup_vhost_user(
                &mem.memory(),
                queues.clone(),
                queue_evts.iter().map(|q| q.try_clone().unwrap()).collect(),
                &interrupt_cb,
                backend_acked_features,
                &slave_req_handler,
                inflight.as_mut(),
            )
            .map_err(ActivateError::VhostUserFsSetup)?;

        // Run a dedicated thread for handling potential reconnections with
        // the backend as well as requests initiated by the backend.
        let (kill_evt, pause_evt) = self.common.dup_eventfds();
        let mut handler: VhostUserEpollHandler<SlaveReqHandler> = VhostUserEpollHandler {
            vu: vu.clone(),
            mem,
            kill_evt,
            pause_evt,
            queues,
            queue_evts,
            virtio_interrupt: interrupt_cb,
            acked_features: backend_acked_features,
            acked_protocol_features: self.acked_protocol_features,
            socket_path: self.socket_path.clone(),
            server: false,
            slave_req_handler,
            inflight,
        };

        let paused = self.common.paused.clone();
        let paused_sync = self.common.paused_sync.clone();

        let virtio_vhost_fs_seccomp_filter =
            get_seccomp_filter(&self.seccomp_action, Thread::VirtioVhostFs)
                .map_err(ActivateError::CreateSeccompFilter)?;

        thread::Builder::new()
            .name(self.id.to_string())
            .spawn(move || {
                if let Err(e) = SeccompFilter::apply(virtio_vhost_fs_seccomp_filter) {
                    error!("Error applying seccomp filter: {:?}", e);
                } else if let Err(e) = handler.run(paused, paused_sync.unwrap()) {
                    error!("Error running vhost-user-fs worker: {:?}", e);
                }
            })
            .map(|thread| self.epoll_thread = Some(thread))
            .map_err(|e| {
                error!("failed to clone queue EventFd: {}", e);
                ActivateError::BadActivate
            })?;

        event!("virtio-device", "activated", "id", &self.id);
        Ok(())
    }

    fn reset(&mut self) -> Option<Arc<dyn VirtioInterrupt>> {
        // We first must resume the virtio thread if it was paused.
        if self.common.pause_evt.take().is_some() {
            self.common.resume().ok()?;
        }

        if let Some(vu) = &self.vu {
            if let Err(e) = vu
                .lock()
                .unwrap()
                .reset_vhost_user(self.common.queue_sizes.len())
            {
                error!("Failed to reset vhost-user daemon: {:?}", e);
                return None;
            }
        }

        if let Some(kill_evt) = self.common.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }

        event!("virtio-device", "reset", "id", &self.id);

        // Return the interrupt
        Some(self.common.interrupt_cb.take().unwrap())
    }

    fn shutdown(&mut self) {
        if let Some(vu) = &self.vu {
            let _ = unsafe { libc::close(vu.lock().unwrap().socket_handle().as_raw_fd()) };
        }
    }

    fn get_shm_regions(&self) -> Option<VirtioSharedMemoryList> {
        self.cache.as_ref().map(|cache| cache.0.clone())
    }

    fn set_shm_regions(
        &mut self,
        shm_regions: VirtioSharedMemoryList,
    ) -> std::result::Result<(), crate::Error> {
        if let Some(mut cache) = self.cache.as_mut() {
            cache.0 = shm_regions;
            Ok(())
        } else {
            Err(crate::Error::SetShmRegionsNotSupported)
        }
    }

    fn add_memory_region(
        &mut self,
        region: &Arc<GuestRegionMmap>,
    ) -> std::result::Result<(), crate::Error> {
        if let Some(vu) = &self.vu {
            if self.acked_protocol_features & VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS.bits()
                != 0
            {
                return vu
                    .lock()
                    .unwrap()
                    .add_memory_region(region)
                    .map_err(crate::Error::VhostUserAddMemoryRegion);
            } else if let Some(guest_memory) = &self.guest_memory {
                return vu
                    .lock()
                    .unwrap()
                    .update_mem_table(guest_memory.memory().deref())
                    .map_err(crate::Error::VhostUserUpdateMemory);
            }
        }
        Ok(())
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

impl Pausable for Fs {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        if let Some(vu) = &self.vu {
            vu.lock()
                .unwrap()
                .pause_vhost_user(self.vu_num_queues)
                .map_err(|e| {
                    MigratableError::Pause(anyhow!("Error pausing vhost-user-fs backend: {:?}", e))
                })?;
        }

        self.common.pause()
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        self.common.resume()?;

        if let Some(epoll_thread) = &self.epoll_thread {
            epoll_thread.thread().unpark();
        }

        if let Some(vu) = &self.vu {
            vu.lock()
                .unwrap()
                .resume_vhost_user(self.vu_num_queues)
                .map_err(|e| {
                    MigratableError::Resume(anyhow!(
                        "Error resuming vhost-user-fs backend: {:?}",
                        e
                    ))
                })
        } else {
            Ok(())
        }
    }
}

impl Snapshottable for Fs {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        let snapshot = Snapshot::new_from_versioned_state(&self.id(), &self.state())?;

        if self.migration_started {
            self.shutdown();
        }

        Ok(snapshot)
    }

    fn restore(&mut self, snapshot: Snapshot) -> std::result::Result<(), MigratableError> {
        self.set_state(&snapshot.to_versioned_state(&self.id)?);
        Ok(())
    }
}
impl Transportable for Fs {}

impl Migratable for Fs {
    fn start_dirty_log(&mut self) -> std::result::Result<(), MigratableError> {
        self.migration_started = true;
        if let Some(vu) = &self.vu {
            if let Some(guest_memory) = &self.guest_memory {
                let last_ram_addr = guest_memory.memory().last_addr().raw_value();
                vu.lock()
                    .unwrap()
                    .start_dirty_log(last_ram_addr)
                    .map_err(|e| {
                        MigratableError::StartDirtyLog(anyhow!(
                            "Error starting migration for vhost-user-fs backend: {:?}",
                            e
                        ))
                    })
            } else {
                Err(MigratableError::StartDirtyLog(anyhow!(
                    "Missing guest memory"
                )))
            }
        } else {
            Ok(())
        }
    }

    fn stop_dirty_log(&mut self) -> std::result::Result<(), MigratableError> {
        self.migration_started = false;
        if let Some(vu) = &self.vu {
            vu.lock().unwrap().stop_dirty_log().map_err(|e| {
                MigratableError::StopDirtyLog(anyhow!(
                    "Error stopping migration for vhost-user-fs backend: {:?}",
                    e
                ))
            })
        } else {
            Ok(())
        }
    }

    fn dirty_log(&mut self) -> std::result::Result<MemoryRangeTable, MigratableError> {
        if let Some(vu) = &self.vu {
            if let Some(guest_memory) = &self.guest_memory {
                let last_ram_addr = guest_memory.memory().last_addr().raw_value();
                vu.lock().unwrap().dirty_log(last_ram_addr).map_err(|e| {
                    MigratableError::DirtyLog(anyhow!(
                        "Error retrieving dirty ranges from vhost-user-fs backend: {:?}",
                        e
                    ))
                })
            } else {
                Err(MigratableError::DirtyLog(anyhow!("Missing guest memory")))
            }
        } else {
            Ok(MemoryRangeTable::default())
        }
    }

    fn complete_migration(&mut self) -> std::result::Result<(), MigratableError> {
        // Make sure the device thread is killed in order to prevent from
        // reconnections to the socket.
        if let Some(kill_evt) = self.common.kill_evt.take() {
            kill_evt.write(1).map_err(|e| {
                MigratableError::CompleteMigration(anyhow!(
                    "Error killing vhost-user-fs threads: {:?}",
                    e
                ))
            })?;
        }

        // Drop the vhost-user handler to avoid further calls to fail because
        // the connection with the backend has been closed.
        self.vu = None;

        Ok(())
    }
}
