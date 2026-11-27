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

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Write;
    use std::os::unix::io::RawFd;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::thread;

    use hypervisor::Vm;
    use vhost::vhost_user::message::{FrontendReq, VhostUserHeaderFlag, VhostUserVirtioFeatures};
    use vm_allocator::page_size::get_page_size;
    use vm_memory::GuestAddress;
    use vm_virtio::VirtioDeviceType;
    use vmm_sys_util::tempdir::TempDir;

    use super::*;
    use crate::VirtioSharedMemory;
    use crate::device::tests::{MockVm, VmMemoryOp, new_test_slot_allocator};
    use crate::vhost_user::tests::{read_request, write_reply};
    use crate::vsock::tests::NoopVirtioInterrupt;

    struct RawFdWrapper(RawFd);
    impl AsRawFd for RawFdWrapper {
        fn as_raw_fd(&self) -> RawFd {
            self.0
        }
    }

    fn write_shmem_config_reply(stream: &mut UnixStream, nregions: u32, entries: &[(usize, u64)]) {
        let payload_len = 8 + 256 * 8;
        for field in [
            u32::from(FrontendReq::GET_SHMEM_CONFIG),
            VhostUserHeaderFlag::REPLY.bits() | 1,
            payload_len as u32,
        ] {
            stream.write_all(&field.to_ne_bytes()).unwrap();
        }
        let mut shmem_cfg = vec![0u8; payload_len];
        shmem_cfg[0..4].copy_from_slice(&nregions.to_ne_bytes());
        for &(idx, size) in entries {
            let off = 8 + idx * 8;
            shmem_cfg[off..off + 8].copy_from_slice(&size.to_ne_bytes());
        }
        stream.write_all(&shmem_cfg).unwrap();
    }

    fn make_mmap_req(
        shmid: u8,
        shm_offset: u64,
        fd_offset: u64,
        len: u64,
        flags: u64,
    ) -> VhostUserMMap {
        VhostUserMMap {
            shmid,
            padding: [0; 7],
            fd_offset,
            shm_offset,
            len,
            flags,
        }
    }

    fn create_test_file(size: u64) -> (TempDir, File) {
        let temp_dir = TempDir::new_with_prefix("/tmp/vhost-user-shmem-map-").unwrap();
        let file = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(temp_dir.as_path().join("blob"))
            .unwrap();
        file.set_len(size).unwrap();
        (temp_dir, file)
    }

    #[test]
    fn generic_vhost_user_invalid_shmem_region_count_returns_error() {
        let page = get_page_size();
        let protocol_features = VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        let shmem = VhostUserProtocolFeatures::SHMEM.bits();
        for bad_nregions in [0u32, 2u32, 257u32] {
            let temp_dir = TempDir::new_with_prefix("/tmp/vhost-user-shmem-invalid-").unwrap();
            let socket_path = temp_dir.as_path().join("backend.sock");
            let listener = UnixListener::bind(&socket_path).unwrap();
            let backend = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                assert!(read_request(&mut stream, FrontendReq::SET_OWNER).is_empty());
                assert!(read_request(&mut stream, FrontendReq::GET_FEATURES).is_empty());
                write_reply(&mut stream, FrontendReq::GET_FEATURES, protocol_features);
                assert!(read_request(&mut stream, FrontendReq::GET_PROTOCOL_FEATURES).is_empty());
                write_reply(&mut stream, FrontendReq::GET_PROTOCOL_FEATURES, shmem);
                assert_eq!(
                    read_request(&mut stream, FrontendReq::SET_PROTOCOL_FEATURES),
                    shmem.to_ne_bytes()
                );
                assert!(read_request(&mut stream, FrontendReq::GET_SHMEM_CONFIG).is_empty());
                // Only 1 non-zero region (at shmid 2), so 0, 2, and 257 are invalid.
                write_shmem_config_reply(&mut stream, bad_nregions, &[(2, page)]);
            });

            let err = GenericVhostUser::new(
                "test-shmem".to_string(),
                socket_path.to_str().unwrap(),
                vec![256],
                VirtioDeviceType::Gpu as u32,
                SeccompAction::Allow,
                EventFd::new(libc::EFD_NONBLOCK).unwrap(),
                false,
                None,
                None,
            )
            .err()
            .expect("expected BadShmemRegionCount error");
            assert!(
                matches!(err, Error::BadShmemRegionCount(n) if n == bad_nregions),
                "expected BadShmemRegionCount({bad_nregions}), got {err}"
            );
            backend.join().unwrap();
        }
    }

    #[test]
    fn generic_vhost_user_shmem_snapshot_restore() {
        let page = get_page_size();
        let protocol_features = VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        let shmem = VhostUserProtocolFeatures::SHMEM.bits();
        let temp_dir = TempDir::new_with_prefix("/tmp/vhost-user-shmem-snap-").unwrap();
        let socket_path = temp_dir.as_path().join("backend.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let backend = thread::spawn(move || {
            // Initial creation queries GET_SHMEM_CONFIG.
            let (mut stream, _) = listener.accept().unwrap();
            assert!(read_request(&mut stream, FrontendReq::SET_OWNER).is_empty());
            assert!(read_request(&mut stream, FrontendReq::GET_FEATURES).is_empty());
            write_reply(&mut stream, FrontendReq::GET_FEATURES, protocol_features);
            assert!(read_request(&mut stream, FrontendReq::GET_PROTOCOL_FEATURES).is_empty());
            write_reply(&mut stream, FrontendReq::GET_PROTOCOL_FEATURES, shmem);
            assert_eq!(
                read_request(&mut stream, FrontendReq::SET_PROTOCOL_FEATURES),
                shmem.to_ne_bytes()
            );
            assert!(read_request(&mut stream, FrontendReq::GET_SHMEM_CONFIG).is_empty());
            write_shmem_config_reply(&mut stream, 1, &[(2, page)]);
            drop(stream);

            // Restore connection must skip GET_SHMEM_CONFIG and reuse saved state.
            let (mut stream2, _) = listener.accept().unwrap();
            assert!(read_request(&mut stream2, FrontendReq::SET_OWNER).is_empty());
            assert!(read_request(&mut stream2, FrontendReq::GET_FEATURES).is_empty());
            write_reply(&mut stream2, FrontendReq::GET_FEATURES, protocol_features);
            assert!(read_request(&mut stream2, FrontendReq::GET_PROTOCOL_FEATURES).is_empty());
            write_reply(&mut stream2, FrontendReq::GET_PROTOCOL_FEATURES, shmem);
            assert_eq!(
                read_request(&mut stream2, FrontendReq::SET_PROTOCOL_FEATURES),
                shmem.to_ne_bytes()
            );
        });

        let (mut device, shmem_sizes) = GenericVhostUser::new(
            "test-shmem".to_string(),
            socket_path.to_str().unwrap(),
            vec![256],
            VirtioDeviceType::Gpu as u32,
            SeccompAction::Allow,
            EventFd::new(libc::EFD_NONBLOCK).unwrap(),
            false,
            None,
            None,
        )
        .unwrap();
        let mut expected_sizes = vec![0u64; 256];
        expected_sizes[2] = page;
        assert_eq!(shmem_sizes, expected_sizes);

        let vm = MockVm::new();
        let shm_list = VirtioSharedMemoryList::new(
            GuestAddress(0x1_0000_0000),
            page,
            expected_sizes
                .iter()
                .map(|&len| VirtioSharedMemory { offset: 0, len })
                .collect(),
            Arc::clone(&vm) as Arc<dyn Vm>,
            new_test_slot_allocator(),
        )
        .unwrap();
        device.set_shm_regions(shm_list).unwrap();

        let state: VhostUserState<()> = device.snapshot().unwrap().to_state().unwrap();
        assert_eq!(state.shmem_sizes, expected_sizes);
        drop(device);

        let (_restored_device, restored_sizes) = GenericVhostUser::new(
            "test-shmem".to_string(),
            socket_path.to_str().unwrap(),
            vec![256],
            VirtioDeviceType::Gpu as u32,
            SeccompAction::Allow,
            EventFd::new(libc::EFD_NONBLOCK).unwrap(),
            false,
            Some(state),
            None,
        )
        .unwrap();
        assert_eq!(restored_sizes, expected_sizes);
        backend.join().unwrap();
    }

    #[test]
    fn generic_vhost_user_shmem_map_unmap_and_overlap() {
        let page = get_page_size();
        let (temp_dir, file) = create_test_file(4 * page);
        let ro_file = File::open(temp_dir.as_path().join("blob")).unwrap();
        let vm = MockVm::new();
        let bar_base = 0x10 * page;
        // Sparse shmid layout: shmid 0 has 2 pages, shmid 1 is unused (0),
        // shmid 2 has 2 pages.
        let shm_list = VirtioSharedMemoryList::new(
            GuestAddress(bar_base),
            4 * page,
            vec![
                VirtioSharedMemory {
                    offset: 0,
                    len: 2 * page,
                },
                VirtioSharedMemory {
                    offset: 2 * page,
                    len: 0,
                },
                VirtioSharedMemory {
                    offset: 2 * page,
                    len: 2 * page,
                },
            ],
            Arc::clone(&vm) as Arc<dyn Vm>,
            new_test_slot_allocator(),
        )
        .unwrap();
        let handler = BackendReqHandler {
            interrupt_cb: Arc::new(NoopVirtioInterrupt {}),
            shm_regions: Some(shm_list.clone()),
        };

        let rw = VhostUserMMapFlags::WRITABLE.bits();
        let ro = 0u64;

        // Invalid requests fail without registering any slots.
        for bad_req in [
            make_mmap_req(0, 0, 0, 0, rw),           // zero length
            make_mmap_req(1, 0, 0, page, rw),        // zero-len shmid
            make_mmap_req(3, 0, 0, page, rw),        // out-of-range shmid
            make_mmap_req(0, page, 0, 2 * page, rw), // crosses region end
            make_mmap_req(0, 0, 0, page, 1 << 1),    // unknown flag bit
            make_mmap_req(0, 1, 0, page, rw),        // unaligned shm_offset
            make_mmap_req(0, 0, 1, page, rw),        // unaligned fd_offset
            make_mmap_req(0, 0, 0, page / 2, rw),    // unaligned length
            make_mmap_req(0, 0, u64::MAX, page, rw), // fd_offset overflow
        ] {
            assert_eq!(
                handler
                    .shmem_map(&bad_req, &file)
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::EINVAL)
            );
        }
        assert_eq!(
            handler
                .shmem_map(&make_mmap_req(0, 0, 0, page, rw), &RawFdWrapper(-1))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EBADF)
        );
        assert_eq!(shm_list.mapped_count(), 0);
        assert_eq!(vm.active_slot_count(), 0);

        // Map writable page at shmid=0 offset=0.
        let req1 = make_mmap_req(0, 0, 0, page, rw);
        assert_eq!(handler.shmem_map(&req1, &file).unwrap(), 0);
        assert_eq!(shm_list.mapped_count(), 1);
        assert_eq!(vm.active_slot_count(), 1);
        assert!(!vm.active_slots()[0].1.readonly);

        // Overlapping mapping on same shmid fails with EINVAL.
        let overlapping = make_mmap_req(0, 0, 0, 2 * page, rw);
        assert_eq!(
            handler
                .shmem_map(&overlapping, &file)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EINVAL)
        );

        // Map adjacent read-only page at shmid=0 offset=page using O_RDONLY fd.
        let req2_rw = make_mmap_req(0, page, page, page, rw);
        assert_eq!(
            handler
                .shmem_map(&req2_rw, &ro_file)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EACCES)
        );
        let req2 = make_mmap_req(0, page, page, page, ro);
        assert_eq!(handler.shmem_map(&req2, &ro_file).unwrap(), 0);
        assert_eq!(shm_list.mapped_count(), 2);

        // Map on distinct shmid=2 offset=0 -> GPA bar_base + 2*page.
        let req3 = make_mmap_req(2, 0, 2 * page, page, rw);
        assert_eq!(handler.shmem_map(&req3, &file).unwrap(), 0);
        assert_eq!(shm_list.mapped_count(), 3);
        let active = vm.active_slots();
        assert_eq!(active[0].1.gpa, bar_base);
        assert!(!active[0].1.readonly);
        assert_eq!(active[1].1.gpa, bar_base + page);
        assert!(active[1].1.readonly);
        assert_eq!(active[2].1.gpa, bar_base + 2 * page);
        assert!(!active[2].1.readonly);

        // Unmap mismatches fail with EINVAL and leave all 3 mappings active.
        assert_eq!(
            handler
                .shmem_unmap(&overlapping)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EINVAL)
        );
        assert_eq!(
            handler
                .shmem_unmap(&make_mmap_req(2, page, 0, page, 0))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EINVAL)
        );
        assert_eq!(shm_list.mapped_count(), 3);

        // Unmapping exact range removes the hypervisor slot and allows re-mapping.
        assert_eq!(handler.shmem_unmap(&req1).unwrap(), 0);
        assert_eq!(shm_list.mapped_count(), 2);
        assert_eq!(vm.active_slot_count(), 2);
        assert_eq!(handler.shmem_map(&req1, &file).unwrap(), 0);
        assert_eq!(shm_list.mapped_count(), 3);
        assert_eq!(vm.active_slot_count(), 3);

        // Dropping handler without shm_list still keeps device mappings alive,
        // and no-BAR handler rejects map/unmap with EINVAL.
        let no_bar = BackendReqHandler {
            interrupt_cb: Arc::new(NoopVirtioInterrupt {}),
            shm_regions: None,
        };
        assert_eq!(
            no_bar.shmem_map(&req1, &file).unwrap_err().raw_os_error(),
            Some(libc::EINVAL)
        );
        assert_eq!(
            no_bar.shmem_unmap(&req1).unwrap_err().raw_os_error(),
            Some(libc::EINVAL)
        );
    }

    #[test]
    fn generic_vhost_user_shmem_failed_register_and_reset() {
        let page = get_page_size();
        let (_dir, file) = create_test_file(2 * page);
        let protocol_features = VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        let shmem = VhostUserProtocolFeatures::SHMEM.bits();
        let sock_dir = TempDir::new_with_prefix("/tmp/vhost-user-shmem-reset-").unwrap();
        let socket_path = sock_dir.as_path().join("backend.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let backend = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            assert!(read_request(&mut stream, FrontendReq::SET_OWNER).is_empty());
            assert!(read_request(&mut stream, FrontendReq::GET_FEATURES).is_empty());
            write_reply(&mut stream, FrontendReq::GET_FEATURES, protocol_features);
            assert!(read_request(&mut stream, FrontendReq::GET_PROTOCOL_FEATURES).is_empty());
            write_reply(&mut stream, FrontendReq::GET_PROTOCOL_FEATURES, shmem);
            assert_eq!(
                read_request(&mut stream, FrontendReq::SET_PROTOCOL_FEATURES),
                shmem.to_ne_bytes()
            );
            assert!(read_request(&mut stream, FrontendReq::GET_SHMEM_CONFIG).is_empty());
            write_shmem_config_reply(&mut stream, 1, &[(0, 2 * page)]);
        });

        let (mut device, _sizes) = GenericVhostUser::new(
            "test-reset".to_string(),
            socket_path.to_str().unwrap(),
            vec![256],
            VirtioDeviceType::Gpu as u32,
            SeccompAction::Allow,
            EventFd::new(libc::EFD_NONBLOCK).unwrap(),
            false,
            None,
            None,
        )
        .unwrap();
        backend.join().unwrap();

        let vm = MockVm::new();
        let base = 0x20 * page;
        let shm_list = VirtioSharedMemoryList::new(
            GuestAddress(base),
            2 * page,
            vec![VirtioSharedMemory {
                offset: 0,
                len: 2 * page,
            }],
            Arc::clone(&vm) as Arc<dyn Vm>,
            new_test_slot_allocator(),
        )
        .unwrap();
        device.set_shm_regions(shm_list.clone()).unwrap();

        let handler = BackendReqHandler {
            interrupt_cb: Arc::new(NoopVirtioInterrupt {}),
            shm_regions: device.get_shm_regions(),
        };
        let req0 = make_mmap_req(0, 0, 0, page, VhostUserMMapFlags::WRITABLE.bits());
        assert_eq!(handler.shmem_map(&req0, &file).unwrap(), 0);
        assert_eq!(vm.active_slot_count(), 1);

        // Failed hypervisor registration must leave RangeMap and existing slot intact.
        vm.fail_next_create_at(base + page);
        let req1 = make_mmap_req(0, page, page, page, 0);
        let _ = handler.shmem_map(&req1, &file).unwrap_err();
        assert_eq!(shm_list.mapped_count(), 1);
        assert_eq!(vm.active_slot_count(), 1);

        // Next map at the same range succeeds and reuses the recycled slot.
        assert_eq!(handler.shmem_map(&req1, &file).unwrap(), 0);
        assert_eq!(shm_list.mapped_count(), 2);
        assert_eq!(vm.active_slot_count(), 2);

        // Relocating the BAR moves both slots and updates subsequent map base.
        let moved_base = base + page;
        let _ = vm.take_ops();
        shm_list.move_bar(GuestAddress(moved_base)).unwrap();
        let ops = vm.take_ops();
        assert!(ops.contains(&VmMemoryOp::Create {
            slot: 1,
            gpa: moved_base + page,
            size: page as usize,
            readonly: true,
        }));
        assert!(ops.contains(&VmMemoryOp::Create {
            slot: 0,
            gpa: moved_base,
            size: page as usize,
            readonly: false,
        }));

        // Unmapping and re-mapping after BAR relocation uses the moved base GPA.
        assert_eq!(handler.shmem_unmap(&req0).unwrap(), 0);
        let _ = vm.take_ops();
        assert_eq!(handler.shmem_map(&req0, &file).unwrap(), 0);
        assert_eq!(
            vm.take_ops(),
            vec![VmMemoryOp::Create {
                slot: 0,
                gpa: moved_base,
                size: page as usize,
                readonly: false,
            }]
        );

        // Device reset clears and unregisters every mapped GuestRegion.
        device.reset();
        assert_eq!(shm_list.mapped_count(), 0);
        assert_eq!(vm.active_slot_count(), 0);
    }
}
