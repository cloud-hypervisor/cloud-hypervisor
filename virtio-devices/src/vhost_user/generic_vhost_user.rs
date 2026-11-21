// Copyright 2019 Intel Corporation. All Rights Reserved.
// Copyright 2025 Demi Marie Obenour.
// SPDX-License-Identifier: Apache-2.0

use std::os::fd::BorrowedFd;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::{io, result};

use event_monitor::event;
use log::{error, info, warn};
use seccompiler::SeccompAction;
use vhost::vhost_user::message::{
    VhostUserConfigFlags, VhostUserMMap, VhostUserMMapFlags, VhostUserProtocolFeatures,
};
use vhost::vhost_user::{FrontendReqHandler, VhostUserFrontend, VhostUserFrontendReqHandler};
use vm_migration::protocol::MemoryRangeTable;
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
use vmm_sys_util::eventfd::EventFd;

use super::vu_common_ctrl::VhostUserHandle;
use super::{Error, Result};
use crate::device::ActivationContext;
use crate::seccomp_filters::Thread;
use crate::vhost_user::{PostcopyHandler, VhostUserCommon, VhostUserState};
use crate::{
    ActivateResult, VIRTIO_F_ACCESS_PLATFORM, VirtioCommon, VirtioDevice, VirtioInterrupt,
    VirtioInterruptType, VirtioSharedMemoryList,
};

pub type State = VhostUserState<()>;

struct BackendReqHandler {
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    shm_regions: Option<VirtioSharedMemoryList>,
}

impl VhostUserFrontendReqHandler for BackendReqHandler {
    fn handle_config_change(&self) -> io::Result<u64> {
        self.interrupt_cb
            .trigger(VirtioInterruptType::Config)
            .map_err(|e| {
                error!("Failed to signal config change: {e:?}");
                io::Error::other(e)
            })?;
        Ok(0)
    }

    fn shmem_map(&self, req: &VhostUserMMap, fd: &dyn AsRawFd) -> io::Result<u64> {
        let shm_list = self
            .shm_regions
            .as_ref()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
        let flags = VhostUserMMapFlags::from_bits(req.flags)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
        let raw_fd = fd.as_raw_fd();
        if raw_fd < 0 {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }
        // SAFETY: `VhostUserFrontendReqHandler::shmem_map` borrows an open
        // file descriptor from its caller for the duration of this call, and
        // `raw_fd` was verified non-negative above (`vhost` passes `&File` as
        // `&dyn AsRawFd`).
        let borrowed_fd = unsafe { BorrowedFd::borrow_raw(raw_fd) };
        shm_list.map_region(
            req.shmid,
            req.shm_offset,
            req.len,
            borrowed_fd,
            req.fd_offset,
            flags.contains(VhostUserMMapFlags::WRITABLE),
        )?;
        Ok(0)
    }

    fn shmem_unmap(&self, req: &VhostUserMMap) -> io::Result<u64> {
        let shm_list = self
            .shm_regions
            .as_ref()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
        shm_list.unmap_region(req.shmid, req.shm_offset, req.len)?;
        Ok(0)
    }
}

pub struct GenericVhostUser {
    vu_common: VhostUserCommon,
    id: String,
    // Hold ownership of the memory that is allocated for the device
    // which will be automatically dropped when the device is dropped
    cache: Option<VirtioSharedMemoryList>,
    seccomp_action: SeccompAction,
    exit_evt: EventFd,
    cfg_warning: AtomicBool,
}

impl GenericVhostUser {
    /// Create a new generic vhost-user device.
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        path: &str,
        request_queue_sizes: Vec<u16>,
        device_type: u32,
        seccomp_action: SeccompAction,
        exit_evt: EventFd,
        access_platform_enabled: bool,
        state: Option<State>,
        postcopy_handler: Option<Arc<dyn PostcopyHandler>>,
    ) -> Result<(GenericVhostUser, Vec<u64>)> {
        // Calculate the actual number of queues needed.
        let num_queues =
            u16::try_from(request_queue_sizes.len()).map_err(|_| Error::BadQueueNum)?;

        // Connect to the vhost-user socket.
        let mut vu =
            VhostUserHandle::connect_vhost_user(false, path, num_queues, false, &exit_evt, |_| {
                Ok(())
            })?;

        let (
            avail_features,
            acked_features,
            acked_protocol_features,
            vu_num_queues,
            paused,
            vring_bases,
            shmem_sizes,
        ) = if let Some(state) = state {
            info!("Restoring generic vhost-user {id}");
            vu.set_protocol_features_vhost_user(
                state.acked_protocol_features,
                postcopy_handler.is_some(),
            )?;

            vu.restore_state(&state)?;

            (
                state.avail_features,
                state.acked_features,
                state.acked_protocol_features,
                state.vu_num_queues,
                true,
                state.vring_bases,
                state.shmem_sizes,
            )
        } else {
            let avail_protocol_features = VhostUserProtocolFeatures::CONFIG
                | VhostUserProtocolFeatures::MQ
                | VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS
                | VhostUserProtocolFeatures::REPLY_ACK
                | VhostUserProtocolFeatures::INFLIGHT_SHMFD
                | VhostUserProtocolFeatures::LOG_SHMFD
                | VhostUserProtocolFeatures::DEVICE_STATE
                | VhostUserProtocolFeatures::BACKEND_REQ
                | VhostUserProtocolFeatures::SHMEM;

            let avail_features = super::DEFAULT_VIRTIO_FEATURES;

            let (acked_features, acked_protocol_features) = vu.negotiate_features_vhost_user(
                avail_features,
                avail_protocol_features,
                postcopy_handler.is_some(),
            )?;

            let backend_num_queues =
                if acked_protocol_features & VhostUserProtocolFeatures::MQ.bits() != 0 {
                    vu.socket_handle()
                        .get_queue_num()
                        .map_err(Error::VhostUserGetQueueMaxNum)?
                } else {
                    num_queues as u64
                };

            if num_queues as u64 > backend_num_queues {
                error!(
                    "generic vhost-user requested too many queues ({num_queues}) \
since the backend only supports {backend_num_queues}\n",
                );
                return Err(Error::BadQueueNum);
            }

            let has_shmem = acked_protocol_features & VhostUserProtocolFeatures::SHMEM.bits() != 0;
            let shmem_sizes = has_shmem
                .then(|| {
                    let cfg = vu
                        .socket_handle()
                        .get_shmem_config()
                        .map_err(Error::VhostUserGetShmemConfig)?;
                    let sizes = &cfg.memory_sizes;
                    if sizes.iter().filter(|&&size| size != 0).count() != cfg.nregions as usize {
                        return Err(Error::BadShmemRegionCount(cfg.nregions));
                    }
                    Ok(sizes.to_vec())
                })
                .transpose()?
                .unwrap_or_default();

            let mut avail_features = acked_features;
            if access_platform_enabled {
                avail_features |= 1u64 << VIRTIO_F_ACCESS_PLATFORM;
            }

            (
                avail_features,
                0,
                acked_protocol_features,
                num_queues,
                false,
                None,
                shmem_sizes,
            )
        };

        if let Some(postcopy_handler) = postcopy_handler {
            vu.start_postcopy(id.clone(), postcopy_handler)?;
        }

        let virtio_common = VirtioCommon {
            device_type,
            avail_features,
            acked_features,
            queue_sizes: request_queue_sizes,
            min_queues: 1,
            ..VirtioCommon::new(paused).map_err(Error::CreateEventFd)?
        };

        Ok((
            GenericVhostUser {
                vu_common: VhostUserCommon {
                    vu: Some(Arc::new(Mutex::new(vu))),
                    acked_protocol_features,
                    socket_path: path.to_string(),
                    vu_num_queues,
                    vring_bases,
                    ..VhostUserCommon::new(virtio_common)
                },
                id,
                cache: None,
                seccomp_action,
                exit_evt,
                cfg_warning: AtomicBool::new(false),
            },
            shmem_sizes,
        ))
    }

    fn state(&self) -> result::Result<State, MigratableError> {
        let mut state = self.vu_common.state(())?;
        if let Some(cache) = &self.cache {
            state.shmem_sizes = cache.region_list().iter().map(|r| r.len).collect();
        }
        Ok(state)
    }

    #[cold]
    #[inline(never)]
    fn warn_no_config_access(&self) {
        if self
            .cfg_warning
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            warn!(
                "Attempt to read config space, but backend does not support config \
space access. Reads will return 0xFF and writes will be ignored."
            );
        }
    }
}

impl Drop for GenericVhostUser {
    fn drop(&mut self) {
        self.vu_common.shutdown();
    }
}

impl VirtioDevice for GenericVhostUser {
    fn device_type(&self) -> u32 {
        self.vu_common.virtio_common.device_type
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.vu_common.virtio_common.queue_sizes
    }

    fn features(&self) -> u64 {
        self.vu_common.virtio_common.avail_features
    }

    fn ack_features(&mut self, value: u64) {
        self.vu_common.virtio_common.ack_features(value);
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        if (VhostUserProtocolFeatures::CONFIG.bits() & self.vu_common.acked_protocol_features) == 0
        {
            self.warn_no_config_access();

            data.fill(0xFF);
            return;
        }
        let Some(vu) = &self.vu_common.vu else {
            error!(
                "Missing vhost-user handle for socket {}",
                self.vu_common.socket_path
            );
            data.fill(0xFF);
            return;
        };
        if let Err(e) = vu
            .lock()
            .unwrap()
            .socket_handle()
            .get_config(
                offset.try_into().unwrap(),
                data.len().try_into().unwrap(),
                VhostUserConfigFlags::empty(),
                data,
            )
            .map(|(_, config)| data.copy_from_slice(&config))
        {
            error!("Failed getting generic vhost-user configuration: {e}");
            data.fill(0xFF);
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        if (VhostUserProtocolFeatures::CONFIG.bits() & self.vu_common.acked_protocol_features) == 0
        {
            self.warn_no_config_access();
            return;
        }
        let Some(vu) = &self.vu_common.vu else {
            error!(
                "Missing vhost-user handle for socket {}",
                self.vu_common.socket_path
            );
            return;
        };
        if let Err(e) = vu.lock().unwrap().socket_handle().set_config(
            offset.try_into().unwrap(),
            VhostUserConfigFlags::WRITABLE,
            data,
        ) {
            error!("Failed setting generic vhost-user configuration: {e}");
        }
    }

    fn activate(&mut self, context: ActivationContext) -> ActivateResult {
        let ActivationContext {
            mem,
            interrupt_cb,
            queues,
            device_status,
        } = context;
        self.vu_common
            .virtio_common
            .activate(&queues, Arc::clone(&interrupt_cb))?;

        let has_backend_req = self.vu_common.acked_protocol_features
            & VhostUserProtocolFeatures::BACKEND_REQ.bits()
            != 0;

        if let Some(cache) = &self.cache {
            cache.clear_mappings();
        }
        let backend_req_handler = has_backend_req
            .then(|| {
                let mut handler = FrontendReqHandler::new(Arc::new(BackendReqHandler {
                    interrupt_cb: Arc::clone(&interrupt_cb),
                    shm_regions: self.cache.clone(),
                }))
                .map_err(|e| {
                    crate::ActivateError::VhostUserSetup(Error::FrontendReqHandlerCreation(e))
                })?;

                if self.vu_common.acked_protocol_features
                    & VhostUserProtocolFeatures::REPLY_ACK.bits()
                    != 0
                {
                    handler.set_reply_ack_flag(true);
                }

                Ok(handler)
            })
            // Return inner Err early, keep Option of `Ok` value
            .transpose()?;

        // Run a dedicated thread for handling potential reconnections with
        // the backend.
        let (kill_evt, pause_evt) = self.vu_common.virtio_common.dup_eventfds()?;

        let mut handler = self.vu_common.activate(
            mem,
            &queues,
            Arc::clone(&interrupt_cb),
            self.vu_common.virtio_common.acked_features,
            backend_req_handler,
            kill_evt,
            pause_evt,
        )?;

        self.vu_common.spawn_worker(
            &self.id,
            &self.seccomp_action,
            Thread::VirtioGenericVhostUser,
            &self.exit_evt,
            Arc::clone(&device_status),
            Arc::clone(&interrupt_cb),
            move |pause_common| handler.run(pause_common),
        )?;

        event!("virtio-device", "activated", "id", &self.id);
        Ok(())
    }

    fn reset(&mut self) {
        self.vu_common.reset(&self.id);
        if let Some(cache) = &self.cache {
            cache.clear_mappings();
        }
    }

    fn shutdown(&mut self) {
        self.vu_common.shutdown();
    }

    fn get_shm_regions(&self) -> Option<VirtioSharedMemoryList> {
        self.cache.clone()
    }

    fn set_shm_regions(
        &mut self,
        shm_regions: VirtioSharedMemoryList,
    ) -> result::Result<(), crate::Error> {
        self.cache = Some(shm_regions);
        Ok(())
    }

    fn is_removable(&self) -> bool {
        true
    }
}

impl Pausable for GenericVhostUser {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        self.vu_common.pause()?;
        self.vu_common.virtio_common.pause()
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        self.vu_common.virtio_common.resume()?;
        self.vu_common.resume()
    }
}

impl Snapshottable for GenericVhostUser {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> result::Result<Snapshot, MigratableError> {
        self.vu_common.snapshot(&self.state()?)
    }
}
impl Transportable for GenericVhostUser {}

impl Migratable for GenericVhostUser {
    fn start_dirty_log(&mut self) -> result::Result<(), MigratableError> {
        self.vu_common.start_dirty_log()
    }

    fn stop_dirty_log(&mut self) -> result::Result<(), MigratableError> {
        self.vu_common.stop_dirty_log()
    }

    fn dirty_log(&mut self) -> result::Result<MemoryRangeTable, MigratableError> {
        self.vu_common.dirty_log()
    }

    fn notify_started_migration(&mut self) -> result::Result<(), MigratableError> {
        self.vu_common.notify_started_migration()
    }

    fn notify_failed_migration(&mut self) -> result::Result<(), MigratableError> {
        self.vu_common.notify_failed_migration()
    }

    fn notify_completed_migration(&mut self) -> result::Result<(), MigratableError> {
        self.vu_common.notify_completed_migration()
    }
}
