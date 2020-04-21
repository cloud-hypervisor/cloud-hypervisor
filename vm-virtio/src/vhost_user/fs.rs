// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::vu_common_ctrl::{reset_vhost_user, setup_vhost_user, update_mem_table};
use super::Error as DeviceError;
use super::{Error, Result};
use crate::vhost_user::handler::{VhostUserEpollConfig, VhostUserEpollHandler};
use crate::{
    ActivateError, ActivateResult, Queue, UserspaceMapping, VirtioDevice, VirtioDeviceType,
    VirtioInterrupt, VirtioSharedMemoryList, VIRTIO_F_VERSION_1,
};
use libc::{self, c_void, off64_t, pread64, pwrite64, EFD_NONBLOCK};
use std::cmp;
use std::io;
use std::io::Write;
use std::os::unix::io::{AsRawFd, RawFd};
use std::result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use vhost_rs::vhost_user::message::{
    VhostUserFSSlaveMsg, VhostUserFSSlaveMsgFlags, VhostUserProtocolFeatures,
    VhostUserVirtioFeatures, VHOST_USER_FS_SLAVE_ENTRIES,
};
use vhost_rs::vhost_user::{
    HandlerResult, Master, MasterReqHandler, VhostUserMaster, VhostUserMasterReqHandler,
};
use vhost_rs::VhostBackend;
use vm_memory::{
    Address, ByteValued, GuestAddress, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap,
    MmapRegion,
};
use vm_migration::{Migratable, MigratableError, Pausable, Snapshottable, Transportable};
use vmm_sys_util::eventfd::EventFd;

const NUM_QUEUE_OFFSET: usize = 1;

struct SlaveReqHandler {
    cache_offset: GuestAddress,
    cache_size: u64,
    mmap_cache_addr: u64,
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
    fn handle_config_change(&mut self) -> HandlerResult<u64> {
        debug!("handle_config_change");
        Ok(0)
    }

    fn fs_slave_map(&mut self, fs: &VhostUserFSSlaveMsg, fd: RawFd) -> HandlerResult<u64> {
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
            let ret = unsafe {
                libc::mmap(
                    addr as *mut libc::c_void,
                    len as usize,
                    fs.flags[i].bits() as i32,
                    libc::MAP_SHARED | libc::MAP_FIXED,
                    fd,
                    fs.fd_offset[i] as libc::off_t,
                )
            };
            if ret == libc::MAP_FAILED {
                return Err(io::Error::last_os_error());
            }

            let ret = unsafe { libc::close(fd) };
            if ret == -1 {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(0)
    }

    fn fs_slave_unmap(&mut self, fs: &VhostUserFSSlaveMsg) -> HandlerResult<u64> {
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
                    0 as libc::off_t,
                )
            };
            if ret == libc::MAP_FAILED {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(0)
    }

    fn fs_slave_sync(&mut self, fs: &VhostUserFSSlaveMsg) -> HandlerResult<u64> {
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

    fn fs_slave_io(&mut self, fs: &VhostUserFSSlaveMsg, fd: RawFd) -> HandlerResult<u64> {
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

            let offset = gpa
                .checked_sub(self.cache_offset.raw_value())
                .ok_or_else(|| io::Error::from_raw_os_error(efault))?;
            let end = gpa
                .checked_add(fs.len[i])
                .ok_or_else(|| io::Error::from_raw_os_error(efault))?;

            if gpa < self.cache_offset.raw_value() || gpa >= cache_end || end >= cache_end {
                return Err(io::Error::from_raw_os_error(efault));
            }

            let mut ptr = self.mmap_cache_addr + offset;
            while len > 0 {
                let ret = if (fs.flags[i] & VhostUserFSSlaveMsgFlags::MAP_W)
                    == VhostUserFSSlaveMsgFlags::MAP_W
                {
                    debug!("write: foffset={}, len={}", foffset, len);
                    unsafe { pwrite64(fd, ptr as *const c_void, len as usize, foffset as off64_t) }
                } else {
                    debug!("read: foffset={}, len={}", foffset, len);
                    unsafe { pread64(fd, ptr as *mut c_void, len as usize, foffset as off64_t) }
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

        let ret = unsafe { libc::close(fd) };
        if ret == -1 {
            return Err(io::Error::last_os_error());
        }

        Ok(done)
    }
}

#[derive(Copy, Clone)]
#[repr(C, packed)]
struct VirtioFsConfig {
    tag: [u8; 36],
    num_request_queues: u32,
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
    vu: Master,
    queue_sizes: Vec<u16>,
    avail_features: u64,
    acked_features: u64,
    config: VirtioFsConfig,
    kill_evt: Option<EventFd>,
    pause_evt: Option<EventFd>,
    // Hold ownership of the memory that is allocated for the device
    // which will be automatically dropped when the device is dropped
    cache: Option<(VirtioSharedMemoryList, MmapRegion)>,
    slave_req_support: bool,
    queue_evts: Option<Vec<EventFd>>,
    interrupt_cb: Option<Arc<dyn VirtioInterrupt>>,
    epoll_threads: Option<Vec<thread::JoinHandle<result::Result<(), DeviceError>>>>,
    paused: Arc<AtomicBool>,
}

impl Fs {
    /// Create a new virtio-fs device.
    pub fn new(
        path: &str,
        tag: &str,
        req_num_queues: usize,
        queue_size: u16,
        cache: Option<(VirtioSharedMemoryList, MmapRegion)>,
    ) -> Result<Fs> {
        let mut slave_req_support = false;

        // Calculate the actual number of queues needed.
        let num_queues = NUM_QUEUE_OFFSET + req_num_queues;

        // Connect to the vhost-user socket.
        let mut master =
            Master::connect(path, num_queues as u64).map_err(Error::VhostUserCreateMaster)?;

        // Filling device and vring features VMM supports.
        let mut avail_features =
            1 << VIRTIO_F_VERSION_1 | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

        // Set vhost-user owner.
        master.set_owner().map_err(Error::VhostUserSetOwner)?;

        // Get features from backend, do negotiation to get a feature collection which
        // both VMM and backend support.
        let backend_features = master.get_features().map_err(Error::VhostUserGetFeatures)?;
        avail_features &= backend_features;
        // Set features back is required by the vhost crate mechanism, since the
        // later vhost call will check if features is filled in master before execution.
        master
            .set_features(avail_features)
            .map_err(Error::VhostUserSetFeatures)?;

        // Identify if protocol features are supported by the slave.
        let mut acked_features = 0;
        if avail_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() != 0 {
            acked_features |= VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

            let mut protocol_features = master
                .get_protocol_features()
                .map_err(Error::VhostUserGetProtocolFeatures)?;

            if cache.is_some() {
                protocol_features &= VhostUserProtocolFeatures::MQ
                    | VhostUserProtocolFeatures::REPLY_ACK
                    | VhostUserProtocolFeatures::SLAVE_REQ
                    | VhostUserProtocolFeatures::SLAVE_SEND_FD;
            } else {
                protocol_features &=
                    VhostUserProtocolFeatures::MQ | VhostUserProtocolFeatures::REPLY_ACK;
            }

            master
                .set_protocol_features(protocol_features)
                .map_err(Error::VhostUserSetProtocolFeatures)?;

            slave_req_support = true;
        }

        // Create virtio-fs device configuration.
        let mut config = VirtioFsConfig::default();
        let tag_bytes_vec = tag.to_string().into_bytes();
        config.tag[..tag_bytes_vec.len()].copy_from_slice(tag_bytes_vec.as_slice());
        config.num_request_queues = req_num_queues as u32;

        Ok(Fs {
            vu: master,
            queue_sizes: vec![queue_size; num_queues],
            avail_features,
            acked_features,
            config,
            kill_evt: None,
            pause_evt: None,
            cache,
            slave_req_support,
            queue_evts: None,
            interrupt_cb: None,
            epoll_threads: None,
            paused: Arc::new(AtomicBool::new(false)),
        })
    }
}

impl Drop for Fs {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
    }
}

impl VirtioDevice for Fs {
    fn device_type(&self) -> u32 {
        VirtioDeviceType::TYPE_FS as u32
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.queue_sizes.as_slice()
    }

    fn features(&self) -> u64 {
        self.avail_features
    }

    fn ack_features(&mut self, value: u64) {
        let mut v = value;
        // Check if the guest is ACK'ing a feature that we didn't claim to have.
        let unrequested_features = v & !self.avail_features;
        if unrequested_features != 0 {
            warn!("fs: virtio-fs got unknown feature ack: {:x}", v);

            // Don't count these features as acked.
            v &= !unrequested_features;
        }
        self.acked_features |= v;
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_slice = self.config.as_slice();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&config_slice[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let config_slice = self.config.as_mut_slice();
        let data_len = data.len() as u64;
        let config_len = config_slice.len() as u64;
        if offset + data_len > config_len {
            error!("Failed to write config space");
            return;
        }
        let (_, right) = config_slice.split_at_mut(offset as usize);
        right.copy_from_slice(&data[..]);
    }

    fn activate(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        interrupt_cb: Arc<dyn VirtioInterrupt>,
        queues: Vec<Queue>,
        queue_evts: Vec<EventFd>,
    ) -> ActivateResult {
        if queues.len() != self.queue_sizes.len() || queue_evts.len() != self.queue_sizes.len() {
            error!(
                "Cannot perform activate. Expected {} queue(s), got {}",
                self.queue_sizes.len(),
                queues.len()
            );
            return Err(ActivateError::BadActivate);
        }

        let (self_kill_evt, kill_evt) = EventFd::new(EFD_NONBLOCK)
            .and_then(|e| Ok((e.try_clone()?, e)))
            .map_err(|e| {
                error!("failed creating kill EventFd pair: {}", e);
                ActivateError::BadActivate
            })?;
        self.kill_evt = Some(self_kill_evt);

        let (self_pause_evt, pause_evt) = EventFd::new(EFD_NONBLOCK)
            .and_then(|e| Ok((e.try_clone()?, e)))
            .map_err(|e| {
                error!("failed creating pause EventFd pair: {}", e);
                ActivateError::BadActivate
            })?;
        self.pause_evt = Some(self_pause_evt);

        // Save the interrupt EventFD as we need to return it on reset
        // but clone it to pass into the thread.
        self.interrupt_cb = Some(interrupt_cb.clone());

        let mut tmp_queue_evts: Vec<EventFd> = Vec::new();
        for queue_evt in queue_evts.iter() {
            // Save the queue EventFD as we need to return it on reset
            // but clone it to pass into the thread.
            tmp_queue_evts.push(queue_evt.try_clone().map_err(|e| {
                error!("failed to clone queue EventFd: {}", e);
                ActivateError::BadActivate
            })?);
        }
        self.queue_evts = Some(tmp_queue_evts);

        let vu_call_evt_queue_list = setup_vhost_user(
            &mut self.vu,
            &mem.memory(),
            queues,
            queue_evts,
            &interrupt_cb,
            self.acked_features,
        )
        .map_err(ActivateError::VhostUserSetup)?;

        // Initialize slave communication.
        let slave_req_handler = if self.slave_req_support {
            if let Some(cache) = self.cache.as_ref() {
                let vu_master_req_handler = Arc::new(Mutex::new(SlaveReqHandler {
                    cache_offset: cache.0.addr,
                    cache_size: cache.0.len,
                    mmap_cache_addr: cache.0.host_addr,
                }));

                let req_handler = MasterReqHandler::new(vu_master_req_handler).map_err(|e| {
                    ActivateError::VhostUserSetup(Error::MasterReqHandlerCreation(e))
                })?;
                self.vu
                    .set_slave_request_fd(req_handler.get_tx_raw_fd())
                    .map_err(|e| {
                        ActivateError::VhostUserSetup(Error::VhostUserSetSlaveRequestFd(e))
                    })?;
                Some(req_handler)
            } else {
                None
            }
        } else {
            None
        };

        let mut handler = VhostUserEpollHandler::new(VhostUserEpollConfig {
            vu_interrupt_list: vu_call_evt_queue_list,
            interrupt_cb,
            kill_evt,
            pause_evt,
            slave_req_handler,
        });

        let paused = self.paused.clone();
        let mut epoll_threads = Vec::new();
        thread::Builder::new()
            .name("virtio_fs".to_string())
            .spawn(move || handler.run(paused))
            .map(|thread| epoll_threads.push(thread))
            .map_err(|e| {
                error!("failed to clone queue EventFd: {}", e);
                ActivateError::BadActivate
            })?;

        self.epoll_threads = Some(epoll_threads);

        Ok(())
    }

    fn reset(&mut self) -> Option<(Arc<dyn VirtioInterrupt>, Vec<EventFd>)> {
        // We first must resume the virtio thread if it was paused.
        if self.pause_evt.take().is_some() {
            self.resume().ok()?;
        }

        if let Err(e) = reset_vhost_user(&mut self.vu, self.queue_sizes.len()) {
            error!("Failed to reset vhost-user daemon: {:?}", e);
            return None;
        }

        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }

        // Return the interrupt and queue EventFDs
        Some((
            self.interrupt_cb.take().unwrap(),
            self.queue_evts.take().unwrap(),
        ))
    }

    fn shutdown(&mut self) {
        let _ = unsafe { libc::close(self.vu.as_raw_fd()) };
    }

    fn get_shm_regions(&self) -> Option<VirtioSharedMemoryList> {
        if let Some(cache) = self.cache.as_ref() {
            Some(cache.0.clone())
        } else {
            None
        }
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

    fn update_memory(&mut self, mem: &GuestMemoryMmap) -> std::result::Result<(), crate::Error> {
        update_mem_table(&mut self.vu, mem).map_err(crate::Error::VhostUserUpdateMemory)
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

virtio_pausable!(Fs);
impl Snapshottable for Fs {}
impl Transportable for Fs {}
impl Migratable for Fs {}
