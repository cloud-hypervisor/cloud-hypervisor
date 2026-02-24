// Copyright (c) 2020 Ant Financial
// Copyright (c) 2025 Demi Marie Obenour
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This implements a vhost-user device backend.  Documentation can be found at:
// https://stefanha.github.io/virtio/vhost-user-slave.html

use core::ffi;
use std::os::fd::{BorrowedFd, OwnedFd, RawFd};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex, MutexGuard};
use std::{io, result};

use anyhow::anyhow;
use event_monitor::event;
use libc::PROT_WRITE;
use log::{debug, error, info, trace, warn};
use seccompiler::SeccompAction;
use thiserror::Error;
use vhost::vhost_user::message::VhostUserMemoryRegion;
use vhost::vhost_user::{BackendListener, BackendReqHandler, VhostUserProtocolFeatures};
use virtio_queue::{Queue, QueueT};
use vm_memory::{ByteValued, GuestAddressSpace, GuestMemoryAtomic, Le32};
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
use vmm_sys_util::eventfd::EventFd;

use crate::seccomp_filters::Thread;
use crate::thread_helper::spawn_virtio_thread;
use crate::{
    ActivateResult, EPOLL_HELPER_EVENT_LAST, EpollHelper, EpollHelperError, EpollHelperHandler,
    GuestMemoryMmap, VIRTIO_F_VERSION_1, VirtioCommon, VirtioDevice, VirtioDeviceType,
    VirtioInterrupt, VirtioInterruptType,
};

#[allow(unused)]
/// Not a valid device backend type.
const VIRTIO_DEVICE_BACKEND_TYPE_INVALID: u32 = 0;

/// vhost-user device backend
const VIRTIO_DEVICE_BACKEND_TYPE_VHOST_USER: u32 = 1;

/// Backend is not yet ready.
const VIRTIO_DEVICE_BACKEND_STATUS_DOWN: u32 = 0;

/// Backend is ready.
const VIRTIO_DEVICE_BACKEND_STATUS_UP: u32 = 1;

/// Common virtio-device-backend configuration space fields.
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct VirtioDeviceBackendConfigCommon {
    /// The type of the device.  Must be 1 for a vhost-user device.
    pub device_type: Le32,
    /// The status of the device.  Always 0 at startup.  Set to 1 when ready.
    pub status: Le32,
    /// A UUID for the backend.
    pub uuid: [u8; 16],
}

// Le32 should be #[repr(transparent)] but isn't.  However,
// it has a single field, and that field is a u32.  Furthermore,
// it has exactly 2^32 valid values.  Therefore, there is no way
// that this can be represented as anything other than a u32 by the
// Pidgeonhole Principle.  Otherwise field access won't work.
const _: () = assert!(size_of::<Le32>() == size_of::<u32>());
const _: () = assert!(
    size_of::<VirtioDeviceBackendConfigCommon>() == size_of::<Le32>() * 2 + size_of::<[u8; 16]>()
);

/// Configuration space fields that are specific to vhost-user device backends.
#[derive(Copy, Clone)]
#[repr(transparent)]
pub struct VirtioDeviceBackendConfigVhostUser {
    /// The maximum number of vhost-user queues that are supported.
    pub max_queues: Le32,
}

const _: () = assert!(size_of::<VirtioDeviceBackendConfigVhostUser>() == size_of::<Le32>());

#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct VirtioDeviceBackendConfig {
    pub common: VirtioDeviceBackendConfigCommon,
    pub vhost_user: VirtioDeviceBackendConfigVhostUser,
}

const _: () = assert!(
    size_of::<VirtioDeviceBackendConfig>()
        == size_of::<VirtioDeviceBackendConfigCommon>()
            + size_of::<VirtioDeviceBackendConfigVhostUser>()
);

// SAFETY: The above static assertions check that the size
// is exactly the minimum needed to hold all possible values.
// Therefore, there cannot be any padding or invalid values.
unsafe impl ByteValued for VirtioDeviceBackendConfig {}

const QUEUE_SIZE: u16 = 128;
const NUM_QUEUES: usize = 2;

// Inflate virtio queue event.
const FRONT2BACK_QUEUE_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;
// Deflate virtio queue event.
const BACK2FRONT_QUEUE_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 2;
// vhost-user socket event
const VHOST_USER_SOCKET_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 3;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Guest gave us a write only descriptor that protocol says to read from")]
    UnexpectedWriteOnlyDescriptor,
    #[error("Guest sent us invalid request")]
    InvalidRequest,
    #[error("Failed to EventFd write.")]
    EventFdWriteFail(#[source] std::io::Error),
    #[error("Invalid queue index: {0}")]
    InvalidQueueIndex(usize),
    #[error("Fail tp signal")]
    FailedSignal(#[source] io::Error),
    #[error("Descriptor chain is too short")]
    DescriptorChainTooShort,
    #[error("Failed adding used index")]
    QueueAddUsed(#[source] virtio_queue::Error),
    #[error("Failed creating an iterator over the queue")]
    QueueIterator(#[source] virtio_queue::Error),
    #[error("Too large max queues")]
    TooLargeMaxQueues,
    #[error("Cannot accept connection")]
    Accept(#[source] vhost::vhost_user::Error),
}

impl From<vhost::vhost_user::Error> for Error {
    fn from(value: vhost::vhost_user::Error) -> Self {
        Error::Accept(value)
    }
}

type Region = Arc<vm_memory::GuestRegionMmap<vm_memory::bitmap::AtomicBitmap>>;

// The most complex part of this struct is the threading model.
// Implementations should use one thread per queue, rather than
// being single-threaded.
pub struct Backend {
    pub avail_features: VhostUserProtocolFeatures,
    pub active_features: AtomicU64,
    pub queues: u64,
    page_size_mask: u64,
    region: Region,
    pub current_offset: Mutex<usize>,
}

impl Backend {
    pub fn new(avail_features: VhostUserProtocolFeatures, queues: u64, region: Region) -> Self {
        // SAFETY: FFI call with valid parameters
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) };
        assert!(page_size.count_ones() == 1);
        Self {
            page_size_mask: u64::try_from(page_size).unwrap() - 1,
            queues,
            avail_features,
            active_features: AtomicU64::new(0),
            region,
            current_offset: Mutex::new(0),
        }
    }
}

/// A kind of ioeventfd that might need to be registered with the VMM.
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum IoEventKind {
    /// Register the doorbell call FD for the queue.
    /// The VM can signal this via an ioeventfd.
    DoorbellCall(u8),
    /// Register the doorbell error FD for the queue.
    /// The VM can signal this via an ioeventfd.
    DoorbellErr(u8),
    /// Register the IRQ notification FD for the queue.
    /// Signalling this triggers an MSI-X interrupt.
    VringKick(u8),
    /// Register the doorbell call FD for the queue.
    /// The VM can signal this via an ioeventfd.
    Log,
}

/// A controller for ioeventfds.
///
/// VMMs provide this to device implementations that
/// need to register and unregister ioeventfds at runtime.
pub trait IoeventfdController {
    fn register_eventfd(&self, kind: IoEventKind, eventfd: BorrowedFd) -> Result<(), io::Error>;
    fn unregister_eventfd(&self, kind: IoEventKind, eventfd: BorrowedFd) -> Result<(), io::Error>;
}

/// A controller for irqfds.
///
/// VMMs provide this to device implementations that need
impl vhost::vhost_user::VhostUserBackendReqHandler for Backend {
    fn set_owner(&self) -> vhost::vhost_user::Result<()> {
        debug!("Session start");
        Ok(())
    }

    fn reset_owner(&self) -> vhost::vhost_user::Result<()> {
        warn!("Frontend used deprecated RESET_OWNER, ignoring");
        Ok(())
    }

    fn reset_device(&self) -> vhost::vhost_user::Result<()> {
        Err(vhost::vhost_user::Error::InactiveOperation(
            VhostUserProtocolFeatures::DEVICE_STATE,
        ))
    }

    fn get_features(&self) -> vhost::vhost_user::Result<u64> {
        Ok(self.avail_features.bits())
    }

    fn set_features(&self, features: u64) -> vhost::vhost_user::Result<()> {
        if (!self.avail_features.bits() & features) == 0 {
            self.active_features.store(features, Ordering::Release);
            Ok(())
        } else {
            Err(vhost::vhost_user::Error::FeatureMismatch)
        }
    }

    fn set_mem_table(
        &self,
        ctx: &[VhostUserMemoryRegion],
        files: Vec<std::fs::File>,
    ) -> vhost::vhost_user::Result<()> {
        const _: () = assert!(
            u64::MAX as usize as u64 == u64::MAX,
            "32-bit platforms not supported"
        );
        const _: () = assert!(
            u64::MAX as libc::size_t as u64 == u64::MAX,
            "32-bit platforms not supported"
        );
        if ctx.len() != files.len() {
            return Err(vhost::vhost_user::Error::InvalidParam);
        }

        // Validate all the regions before doing any mappings.
        for &VhostUserMemoryRegion {
            guest_phys_addr,
            memory_size,
            mmap_offset,
            user_addr,
            ..
        } in ctx
        {
            // There must not be an overflow computing the end of the address
            // spaces.
            let (Some(_last_guest_phys_addr), Some(_last_user_addr), Some(last_byte_in_file)) = (
                memory_size.checked_add(guest_phys_addr),
                memory_size.checked_add(user_addr),
                memory_size.checked_add(mmap_offset),
            ) else {
                return Err(vhost::vhost_user::Error::InvalidParam);
            };

            // mmap64() takes the size as size_t and the offset
            // as off64_t.  Check that the size fits in size_t
            // and that the last byte of the file fits in off64_t.
            let (Ok(_memory_size), Ok(_another_size), Ok(_offset)) = (
                libc::size_t::try_from(memory_size),
                isize::try_from(memory_size),
                libc::off64_t::try_from(last_byte_in_file),
            ) else {
                return Err(vhost::vhost_user::Error::InvalidParam);
            };

            // The mmap offset and size must be multiples of the page size.
            if memory_size & self.page_size_mask != 0 || mmap_offset & self.page_size_mask != 0 {
                return Err(vhost::vhost_user::Error::InvalidParam);
            }

            // The user address and guest physical address do not
            // technically need to be multiples of the page size,
            // but it would be very strange for them not to be.
            if guest_phys_addr & self.page_size_mask != 0 || user_addr & self.page_size_mask != 0 {
                return Err(vhost::vhost_user::Error::InvalidParam);
            }
        }

        for (
            &VhostUserMemoryRegion {
                memory_size,
                mmap_offset,
                ..
            },
            file,
        ) in ctx.iter().zip(files.iter())
        {
            let addr = self.region.as_ptr() as *mut ffi::c_void;
            let region_size: usize = self.region.size();
            let mut current_offset_ref: MutexGuard<usize> = self.current_offset.lock().unwrap();
            let current_offset = *current_offset_ref;
            let memory_size = usize::try_from(memory_size).expect("checked in previous loop");
            isize::try_from(region_size).expect("region size {region_size} overflows isize");
            assert!(
                region_size >= current_offset,
                "current offset is {current_offset} but region size is {region_size}"
            );
            if region_size - current_offset < memory_size {
                return Err(vhost::vhost_user::Error::BackendInternalError);
            }

            // SAFETY: the address is checked to fit within the GuestRegionMmap
            let addr_to_map = unsafe { addr.add(memory_size) };
            // SAFETY: MAP_FIXED passed and the address is valid.
            let addr = unsafe {
                libc::mmap64(
                    addr_to_map,
                    memory_size,
                    libc::PROT_READ | PROT_WRITE,
                    libc::MAP_FIXED | libc::MAP_SHARED_VALIDATE,
                    file.as_raw_fd(),
                    mmap_offset.try_into().expect("checked in previous loop"),
                )
            };
            if addr == libc::MAP_FAILED {
                return Err(vhost::vhost_user::Error::BackendInternalError);
            }
            *current_offset_ref += memory_size;
        }
        Ok(())
    }

    fn set_vring_num(&self, _index: u32, _num: u32) -> vhost::vhost_user::Result<()> {
        todo!("setting vring number")
    }

    fn set_vring_addr(
        &self,
        _index: u32,
        _flags: vhost::vhost_user::message::VhostUserVringAddrFlags,
        _descriptor: u64,
        _used: u64,
        _available: u64,
        _log: u64,
    ) -> vhost::vhost_user::Result<()> {
        todo!("setting vring address")
    }

    fn set_vring_base(&self, _index: u32, _base: u32) -> vhost::vhost_user::Result<()> {
        todo!("setting vring base")
    }

    fn get_vring_base(
        &self,
        _index: u32,
    ) -> vhost::vhost_user::Result<vhost::vhost_user::message::VhostUserVringState> {
        todo!("getting vring base")
    }

    fn set_vring_kick(
        &self,
        _index: u8,
        _fd: Option<std::fs::File>,
    ) -> vhost::vhost_user::Result<()> {
        todo!()
    }

    fn set_vring_call(
        &self,
        _index: u8,
        _fd: Option<std::fs::File>,
    ) -> vhost::vhost_user::Result<()> {
        todo!("setting vring call fd")
    }

    fn set_vring_err(
        &self,
        _index: u8,
        _fd: Option<std::fs::File>,
    ) -> vhost::vhost_user::Result<()> {
        todo!("setting vring error fd")
    }

    fn get_protocol_features(
        &self,
    ) -> vhost::vhost_user::Result<vhost::vhost_user::VhostUserProtocolFeatures> {
        todo!("getting protocol features")
    }

    fn set_protocol_features(&self, _features: u64) -> vhost::vhost_user::Result<()> {
        todo!("setting protocol features")
    }

    fn get_queue_num(&self) -> vhost::vhost_user::Result<u64> {
        todo!("getting number of queues")
    }

    fn set_vring_enable(&self, _index: u32, _enable: bool) -> vhost::vhost_user::Result<()> {
        todo!("vring handling")
    }

    fn get_config(
        &self,
        _offset: u32,
        _size: u32,
        _flags: vhost::vhost_user::message::VhostUserConfigFlags,
    ) -> vhost::vhost_user::Result<Vec<u8>> {
        todo!("configuration space")
    }

    fn set_config(
        &self,
        _offset: u32,
        _buf: &[u8],
        _flags: vhost::vhost_user::message::VhostUserConfigFlags,
    ) -> vhost::vhost_user::Result<()> {
        Err(vhost::vhost_user::Error::InactiveOperation(
            VhostUserProtocolFeatures::CONFIG,
        ))
    }

    fn set_gpu_socket(
        &self,
        _gpu_backend: vhost::vhost_user::GpuBackend,
    ) -> vhost::vhost_user::Result<()> {
        Err(vhost::vhost_user::Error::InvalidOperation(
            "GPU display not supported",
        ))
    }

    fn get_shared_object(
        &self,
        _uuid: vhost::vhost_user::message::VhostUserSharedMsg,
    ) -> vhost::vhost_user::Result<std::fs::File> {
        Err(vhost::vhost_user::Error::InactiveOperation(
            VhostUserProtocolFeatures::SHARED_OBJECT,
        ))
    }

    fn get_inflight_fd(
        &self,
        _inflight: &vhost::vhost_user::message::VhostUserInflight,
    ) -> vhost::vhost_user::Result<(vhost::vhost_user::message::VhostUserInflight, std::fs::File)>
    {
        Err(vhost::vhost_user::Error::InactiveOperation(
            VhostUserProtocolFeatures::INFLIGHT_SHMFD,
        ))
    }

    fn set_inflight_fd(
        &self,
        _inflight: &vhost::vhost_user::message::VhostUserInflight,
        _file: std::fs::File,
    ) -> vhost::vhost_user::Result<()> {
        Err(vhost::vhost_user::Error::InactiveOperation(
            VhostUserProtocolFeatures::INFLIGHT_SHMFD,
        ))
    }

    fn get_max_mem_slots(&self) -> vhost::vhost_user::Result<u64> {
        Err(vhost::vhost_user::Error::InactiveOperation(
            VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS,
        ))
    }

    fn add_mem_region(
        &self,
        _region: &vhost::vhost_user::message::VhostUserSingleMemoryRegion,
        _fd: std::fs::File,
    ) -> vhost::vhost_user::Result<()> {
        Err(vhost::vhost_user::Error::InactiveOperation(
            VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS,
        ))
    }

    fn remove_mem_region(
        &self,
        _region: &vhost::vhost_user::message::VhostUserSingleMemoryRegion,
    ) -> vhost::vhost_user::Result<()> {
        Err(vhost::vhost_user::Error::InactiveOperation(
            VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS,
        ))
    }

    fn set_device_state_fd(
        &self,
        _direction: vhost::vhost_user::message::VhostTransferStateDirection,
        _phase: vhost::vhost_user::message::VhostTransferStatePhase,
        _fd: std::fs::File,
    ) -> vhost::vhost_user::Result<Option<std::fs::File>> {
        Err(vhost::vhost_user::Error::InactiveOperation(
            VhostUserProtocolFeatures::DEVICE_STATE,
        ))
    }

    fn check_device_state(&self) -> vhost::vhost_user::Result<()> {
        Err(vhost::vhost_user::Error::InactiveOperation(
            VhostUserProtocolFeatures::DEVICE_STATE,
        ))
    }

    fn set_log_base(
        &self,
        _log: &vhost::vhost_user::message::VhostUserLog,
        _file: std::fs::File,
    ) -> vhost::vhost_user::Result<()> {
        Err(vhost::vhost_user::Error::InactiveOperation(
            VhostUserProtocolFeatures::LOG_SHMFD,
        ))
    }
}

struct VdbEpollHandler {
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
    front2back_queue: Queue,
    back2front_queue: Queue,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    front2back_queue_evt: EventFd,
    back2front_queue_evt: EventFd,
    kill_evt: EventFd,
    pause_evt: EventFd,
    #[allow(dead_code)]
    backend: Arc<Backend>,
    connection: Option<BackendReqHandler<Backend>>,
}

impl VdbEpollHandler {
    fn signal(&self, int_type: VirtioInterruptType) -> result::Result<(), Error> {
        self.interrupt_cb.trigger(int_type).map_err(|e| {
            error!("Failed to signal used queue: {e:?}");
            Error::FailedSignal(e)
        })
    }

    #[allow(unused)]
    fn process_front2back_queue(&mut self) -> result::Result<(), Error> {
        let mut used_descs = false;
        while let Some(mut desc_chain) = self
            .front2back_queue
            .pop_descriptor_chain(self.mem.memory())
        {
            let desc = desc_chain.next().ok_or(Error::DescriptorChainTooShort)?;
            used_descs = true;
            todo!();
        }

        if used_descs {
            self.signal(VirtioInterruptType::Queue(0))
        } else {
            Ok(())
        }
    }

    fn process_back2front_queue(&mut self) -> result::Result<(), Error> {
        let mut _used_descs = false;
        while let Some(mut desc_chain) = self
            .back2front_queue
            .pop_descriptor_chain(self.mem.memory())
        {
            let _desc = desc_chain.next().ok_or(Error::DescriptorChainTooShort)?;
            _used_descs = true;
            todo!();
        }

        if _used_descs {
            self.signal(VirtioInterruptType::Queue(1))
        } else {
            Ok(())
        }
    }

    fn process_vhost_user_queue(&mut self) -> result::Result<(), Error> {
        self.connection
            .as_mut()
            .unwrap()
            .handle_request()
            .map_err(From::from)
    }

    fn run(
        &mut self,
        paused: &AtomicBool,
        paused_sync: &Barrier,
        mut listener: BackendListener<Backend>,
    ) -> result::Result<(), EpollHelperError> {
        let connection = listener
            .accept()
            .map_err(|t| EpollHelperError::IoError(std::io::Error::other(t)))?
            .expect("TODO: nonblocking socket");
        // TODO: retry if socket is nonblocking (via poll(2))
        // TODO: accept incoming connection (synchronously!)
        // TODO: handle incoming messages
        // TODO: send interrupts
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;
        helper.add_event(
            self.front2back_queue_evt.as_raw_fd(),
            FRONT2BACK_QUEUE_EVENT,
        )?;
        helper.add_event(
            self.back2front_queue_evt.as_raw_fd(),
            BACK2FRONT_QUEUE_EVENT,
        )?;
        helper.add_event(connection.as_raw_fd(), VHOST_USER_SOCKET_EVENT)?;
        self.connection = Some(connection);
        helper.run(paused, paused_sync, self)?;
        Ok(())
    }
}

impl EpollHelperHandler for VdbEpollHandler {
    fn handle_event(
        &mut self,
        _helper: &mut EpollHelper,
        event: &epoll::Event,
    ) -> result::Result<(), EpollHelperError> {
        let ev_type = event.data as u16;
        match ev_type {
            FRONT2BACK_QUEUE_EVENT => {
                self.front2back_queue_evt.read().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!(
                        "Failed to get front-to-back event: {e:?}"
                    ))
                })?;
                self.process_front2back_queue().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!(
                        "Failed to process front-to-back queue: {e:?}"
                    ))
                })?;
            }
            BACK2FRONT_QUEUE_EVENT => {
                self.back2front_queue_evt.read().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!(
                        "Failed to get back-to-front queue event: {e:?}"
                    ))
                })?;
                self.process_back2front_queue().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!(
                        "Failed to process back-to-front queue: {e:?}"
                    ))
                })?;
            }
            VHOST_USER_SOCKET_EVENT => {
                self.process_vhost_user_queue().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!(
                        "Failed to handle vhost-user message: {e:?}"
                    ))
                })?;
            }
            _ => {
                return Err(EpollHelperError::HandleEvent(anyhow!(
                    "Unknown event for virtio-vdb"
                )));
            }
        }

        Ok(())
    }
}

#[derive(Copy, Clone)]
#[repr(packed, C)]
pub struct VdbState {
    pub avail_features: u64,
    pub acked_features: u64,
    pub config: VirtioDeviceBackendConfig,
}

const _: () =
    assert!(size_of::<VdbState>() == size_of::<u64>() * 2 + size_of::<VirtioDeviceBackendConfig>());

// SAFETY: VdbState has no padding and all values are valid.
unsafe impl ByteValued for VdbState {}

// Virtio device backend
pub struct Vdb {
    common: VirtioCommon,
    id: String,
    config: VirtioDeviceBackendConfig,
    seccomp_action: SeccompAction,
    exit_evt: EventFd,
    interrupt_cb: Option<Arc<dyn VirtioInterrupt>>,
    max_queues: u8,
    backend: Arc<Backend>,
    listener: Option<BackendListener<Backend>>,
    msix_fds: [Option<OwnedFd>; MSIX_ARRAY_SIZE],
    statuses: [bool; MSIX_ARRAY_SIZE],
}

impl Vdb {
    // Create a new virtio-vdb.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        seccomp_action: SeccompAction,
        exit_evt: EventFd,
        state: Option<VdbState>,
        max_queues: u32,
        uuid: [u8; 16],
        backend: Backend,
        listener: BackendListener<Backend>,
    ) -> io::Result<Self> {
        if max_queues > 127 {
            warn!("Cannot support {max_queues} queues, limit is 127");
            return Err(io::Error::other(Error::TooLargeMaxQueues));
        }
        let queue_sizes = vec![QUEUE_SIZE; NUM_QUEUES];

        let (avail_features, acked_features, config, paused) = if let Some(state) = state {
            info!("Restoring virtio-balloon {id}");
            (
                state.avail_features,
                state.acked_features,
                state.config,
                true,
            )
        } else {
            let avail_features = 1u64 << VIRTIO_F_VERSION_1;

            (
                avail_features,
                0,
                VirtioDeviceBackendConfig {
                    common: VirtioDeviceBackendConfigCommon {
                        device_type: Le32::from(VIRTIO_DEVICE_BACKEND_TYPE_VHOST_USER),
                        status: Le32::from(VIRTIO_DEVICE_BACKEND_STATUS_DOWN),
                        uuid,
                    },
                    vhost_user: VirtioDeviceBackendConfigVhostUser {
                        max_queues: Le32::from(max_queues),
                    },
                },
                false,
            )
        };

        const _: () = assert!(size_of::<RawFd>() == size_of::<OwnedFd>());
        Ok(Vdb {
            common: VirtioCommon {
                device_type: VirtioDeviceType::Balloon as u32,
                avail_features,
                acked_features,
                paused_sync: Some(Arc::new(Barrier::new(2))),
                queue_sizes,
                min_queues: NUM_QUEUES as u16,
                paused: Arc::new(AtomicBool::new(paused)),
                ..Default::default()
            },
            id,
            config,
            seccomp_action,
            exit_evt,
            interrupt_cb: None,
            max_queues: max_queues as _,
            backend: Arc::new(backend),
            listener: Some(listener),
            statuses: [false; MSIX_ARRAY_SIZE],
            msix_fds: [const { None }; MSIX_ARRAY_SIZE],
        })
    }

    fn state(&self) -> VdbState {
        VdbState {
            avail_features: self.common.avail_features,
            acked_features: self.common.acked_features,
            config: self.config,
        }
    }

    #[cfg(fuzzing)]
    pub fn wait_for_epoll_threads(&mut self) {
        self.common.wait_for_epoll_threads();
    }
}

impl Drop for Vdb {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.common.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
        self.common.wait_for_epoll_threads();
    }
}

const MSIX_ARRAY_OFFSET: usize = 512;
const MSIX_ARRAY_SIZE: usize = 256;

impl VirtioDevice for Vdb {
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
        self.common.ack_features(value);
    }

    fn doorbells_max(&self) -> u8 {
        self.max_queues * 2 + 1
    }

    fn max_interrupts(&self) -> usize {
        usize::from(self.max_queues) + self.queue_max_sizes().len()
    }

    fn read_config(&self, _offset: u64, _data: &mut [u8]) {}

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        if offset == 4
            && let Ok(v) = data.try_into().map(u32::from_le_bytes)
        {
            match v {
                1 => self.config.common.status = Le32::from(VIRTIO_DEVICE_BACKEND_STATUS_UP),
                0 => self.config.common.status = Le32::from(VIRTIO_DEVICE_BACKEND_STATUS_DOWN),
                _ => warn!("Invalid value {v} for VDB device status"),
            }
            return;
        }
        if offset & 1 == 0
            && let Ok(offset) = usize::try_from(offset)
            && (MSIX_ARRAY_OFFSET..MSIX_ARRAY_SIZE * 2).contains(&offset)
            && let Ok(value) = data.try_into().map(u16::from_le_bytes)
        {
            let offset = (offset - MSIX_ARRAY_OFFSET) >> 1;
            let fd = &mut self.msix_fds[offset];
            let status = self.statuses[offset];
            trace!(
                "VDB driver wrote {value} to index {offset} in MSI-X activity array. Status: {}. FD {}.",
                if status { "enabled" } else { "disabled" },
                if fd.is_some() { "present" } else { "absent" }
            );
        }
    }

    fn activate(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        interrupt_cb: Arc<dyn VirtioInterrupt>,
        mut queues: Vec<(usize, Queue, EventFd)>,
    ) -> ActivateResult {
        self.common.activate(&queues, interrupt_cb.clone())?;
        let (kill_evt, pause_evt) = self.common.dup_eventfds();

        let (_, front2back_queue, front2back_queue_evt) = queues.remove(0);
        let (_, back2front_queue, back2front_queue_evt) = queues.remove(0);

        self.interrupt_cb = Some(interrupt_cb.clone());
        let mut handler = VdbEpollHandler {
            mem,
            back2front_queue,
            front2back_queue,
            interrupt_cb,
            front2back_queue_evt,
            back2front_queue_evt,
            kill_evt,
            pause_evt,
            backend: self.backend.clone(),
            connection: None,
        };

        let paused = self.common.paused.clone();
        let paused_sync = self.common.paused_sync.clone();
        let mut epoll_threads = Vec::new();
        let listener = self.listener.take().expect("double activate");

        spawn_virtio_thread(
            &self.id,
            &self.seccomp_action,
            Thread::VirtioVdb,
            &mut epoll_threads,
            &self.exit_evt,
            move || handler.run(&paused, paused_sync.as_ref().unwrap(), listener),
        )?;
        self.common.epoll_threads = Some(epoll_threads);

        event!("virtio-device", "activated", "id", &self.id);
        Ok(())
    }

    fn reset(&mut self) -> Option<Arc<dyn VirtioInterrupt>> {
        let result = self.common.reset();
        event!("virtio-device", "reset", "id", &self.id);
        result
    }
}

impl Pausable for Vdb {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        self.common.pause()
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        self.common.resume()
    }
}

impl Snapshottable for Vdb {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        Snapshot::new_from_state(&self.state().as_slice())
    }
}
impl Transportable for Vdb {}
impl Migratable for Vdb {}
