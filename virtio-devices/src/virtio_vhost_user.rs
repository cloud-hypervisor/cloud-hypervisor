// Copyright (c) 2020 Ant Financial
// Copyright (c) 2026 Demi Marie Obenour
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

use std::os::fd::{AsRawFd as _, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Barrier, Mutex};
use std::{io, result};

use anyhow::anyhow;
use event_monitor::event;
use hypervisor::IoEventAddress;
use log::{error, info, trace, warn};
use seccompiler::SeccompAction;
use vhost::vhost_user::Error;
use virtio_vhost_user::{
    BackendRequestQueuePair, FrontendRequestQueuePair, IoEventFds, Mapping, Region, Translate, VM,
    VirtioVhostUserQueuePair,
};
use vm_allocator::AddressAllocator;
use vm_memory::{ByteValued, GuestAddress, Le32};
use vm_virtio::AccessPlatform;
use vmm_sys_util::eventfd::EventFd;

use crate::seccomp_filters::Thread;
use crate::thread_helper::spawn_virtio_thread;
use crate::{
    ActivateResult, ActivationContext, EPOLL_HELPER_EVENT_LAST, EpollHelper, EpollHelperError,
    EpollHelperHandler, VIRTIO_F_VERSION_1, VirtioCommon, VirtioDevice, VirtioDeviceType,
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

const F2B_REQUEST_QUEUE_SPACE_AVAIL: u16 = EPOLL_HELPER_EVENT_LAST + 1 + Events::QueueIn as u16;
const B2F_REPLY_AVAILABLE: u16 = EPOLL_HELPER_EVENT_LAST + 1 + Events::QueueOut as u16;
const F2B_REQUEST_READABLE: u16 = EPOLL_HELPER_EVENT_LAST + 1 + Events::SocketIn as u16;
const B2F_REPLY_SENDABLE: u16 = EPOLL_HELPER_EVENT_LAST + 1 + Events::SocketOut as u16;

const F2B_REPLY_QUEUE_SPACE_AVAIL: u16 = F2B_REQUEST_QUEUE_SPACE_AVAIL + Events::Total as u16;
const B2F_REQUEST_AVAILABLE: u16 = B2F_REPLY_AVAILABLE + Events::Total as u16;
const F2B_REPLY_READABLE: u16 = F2B_REQUEST_READABLE + Events::Total as u16;
const B2F_REQUEST_SENDABLE: u16 = B2F_REPLY_SENDABLE + Events::Total as u16;

// The most complex part of this struct is the threading model.
// Implementations should use one thread per queue, rather than
// being single-threaded.
pub struct Backend {}

struct InternalAllocator(AddressAllocator);
impl virtio_vhost_user::Allocator for InternalAllocator {
    fn new(base: vm_memory::GuestAddress, size: u64) -> Self {
        Self(AddressAllocator::new(base, size).unwrap())
    }

    fn allocate(&mut self, size: u64) -> Option<vm_memory::GuestAddress> {
        self.0.allocate(None, size, None)
    }

    fn base(&self) -> vm_memory::GuestAddress {
        self.0.base()
    }
}

struct InternalVM {
    vm: Arc<dyn hypervisor::Vm>,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    backend_socket: Option<UnixStream>,
}

impl VM for InternalVM {
    fn register_ioevent(&mut self, fd: &EventFd, offset: u64) {
        self.vm
            .unregister_ioevent(fd, &IoEventAddress::Mmio(offset))
            .expect("TODO");
    }

    fn unregister_ioevent(&mut self, fd: EventFd, offset: u64) {
        self.vm
            .unregister_ioevent(&fd, &IoEventAddress::Mmio(offset))
            .expect("TODO");
    }

    fn register_vring_kick(&mut self, fd: Option<EventFd>, queue: u8) {
        self.interrupt_cb
            .set_notifier(u32::from(queue) + 4, fd, &*self.vm)
            .map_err(|e| {
                error!("Cannot set vring kick notifier: {e}");
                vhost::vhost_user::Error::BackendInternalError
            })
            .expect("TODO: handle error");
    }

    fn backend_request_socket(&mut self, socket: UnixStream) {
        self.backend_socket = Some(socket);
    }
}

fn register_socket(helper: &mut EpollHelper, socket: &UnixStream) -> Result<(), io::Error> {
    fn conv(e: EpollHelperError) -> Error {
        match e {
            EpollHelperError::Ctl(e) => Error::ReqHandlerError(e),
            _ => unreachable!(),
        }
    }
    helper
        .add_event(socket.as_raw_fd(), F2B_REPLY_READABLE)
        .map_err(conv)?;
    helper
        .add_event_custom(
            socket.as_raw_fd(),
            B2F_REQUEST_SENDABLE,
            epoll::Events::EPOLLOUT,
        )
        .map_err(conv)?;
    Ok(())
}

struct VdbEpollHandler {
    requests: FrontendRequestQueuePair<InternalAllocator, InternalVM>,
    replies: BackendRequestQueuePair,
    kill_evt: EventFd,
    pause_evt: EventFd,
    epoll_fd: Option<BorrowedFd<'static>>,
    access_platform: Option<Box<dyn AccessPlatform>>,
    needs_reset: bool,
}

#[repr(u16)]
enum Events {
    QueueIn = 0,
    QueueOut = 1,
    SocketIn = 2,
    SocketOut = 3,
    Total = 4,
}

fn register_epoll_events(
    helper: &mut EpollHelper,
    fds: &virtio_vhost_user::Fds,
    base: u16,
) -> Result<(), EpollHelperError> {
    helper.add_event(fds.queue_in.as_raw_fd(), base + Events::QueueIn as u16)?;
    helper.add_event(fds.queue_out.as_raw_fd(), base + Events::QueueOut as u16)?;
    if let Some(socket) = &fds.socket {
        helper.add_event(socket.as_raw_fd(), base + Events::SocketIn as u16)?;
        helper.add_event_custom(
            socket.as_raw_fd(),
            base + Events::SocketOut as u16,
            epoll::Events::EPOLLOUT,
        )?;
    }
    Ok(())
}

impl VdbEpollHandler {
    fn run(
        &mut self,
        paused: &AtomicBool,
        paused_sync: &Barrier,
    ) -> result::Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;

        register_epoll_events(
            &mut helper,
            &self.requests.fds(),
            F2B_REQUEST_QUEUE_SPACE_AVAIL,
        )?;
        register_epoll_events(
            &mut helper,
            &self.replies.fds(),
            F2B_REPLY_QUEUE_SPACE_AVAIL,
        )?;
        // SAFETY: The 'static lifetime on the returned FD is a lie. However,
        // we have a unique reference to self so nobody else can access the fd
        // through this reference. Furthermore, the FD will stay alive until
        // after self.fd is set to None, which happens even in the event of
        // a panic. So no code can observe the FD after it is dropped.
        self.epoll_fd = Some(unsafe { BorrowedFd::borrow_raw(helper.as_raw_fd()) });
        let p =
            std::panic::catch_unwind(AssertUnwindSafe(|| helper.run(paused, paused_sync, self)));
        self.epoll_fd = None;
        match p {
            Ok(good) => good,
            Err(panicked) => std::panic::resume_unwind(panicked),
        }
    }

    fn process_event(
        &mut self,
        ev_type: u16,
        helper: &mut EpollHelper,
    ) -> Result<(), EpollHelperError> {
        // Avoid Option::map here.  The compiler can't figure out the types
        // and produces confusing errors.
        let translate: Option<Translate> = match self.access_platform.as_deref() {
            None => None,
            Some(a) => Some(&mut |base, size| {
                a.translate_gva(base.0, size.try_into().unwrap())
                    .map(GuestAddress)
            }),
        };

        match match ev_type {
            // TODO: handle FD rearming, queue interrupts
            F2B_REQUEST_QUEUE_SPACE_AVAIL | F2B_REQUEST_READABLE => self
                .requests
                .process_requests(translate, 50)
                .map(|b| do_use(b.1, 0)),
            B2F_REPLY_AVAILABLE | B2F_REPLY_SENDABLE => self
                .requests
                .process_replies(translate, 50)
                .map(|b| do_use(b.1, 1)),
            F2B_REPLY_QUEUE_SPACE_AVAIL | F2B_REPLY_READABLE => self
                .replies
                .process_incoming(translate, 50)
                .map(|b| do_use(b.1, 2)),
            B2F_REQUEST_AVAILABLE | B2F_REQUEST_SENDABLE => self
                .replies
                .process_outgoing(translate, 50)
                .map(|b| do_use(b.1, 3)),

            _ => {
                return Err(EpollHelperError::HandleEvent(anyhow!(
                    "Unknown event for virtio-vdb"
                )));
            }
        } {
            Ok(None) => Ok(()),
            Ok(Some(queue)) => self
                .requests
                .vm_mut()
                .interrupt_cb
                .trigger(VirtioInterruptType::Queue(queue))
                .map_err(|e| {
                    error!("Error triggering interrupt: {e}");
                    EpollHelperError::HandleEvent(anyhow!(e))
                }),
            Err(e) => Err(EpollHelperError::HandleEvent(anyhow!(e))),
        }?;
        if let Some(socket) = self.requests.vm_mut().backend_socket.take() {
            register_socket(helper, &socket)
                .map_err(|e| EpollHelperError::HandleEvent(anyhow!(e)))?;
            self.replies
                .set_socket(socket)
                .map_err(|e| EpollHelperError::HandleEvent(anyhow!(e)))?;
        }
        Ok(())
    }
}

fn do_use(do_use: bool, other: u16) -> Option<u16> {
    if do_use { Some(other) } else { None }
}

impl EpollHelperHandler for VdbEpollHandler {
    fn handle_event(
        &mut self,
        helper: &mut EpollHelper,
        event: &epoll::Event,
    ) -> result::Result<(), EpollHelperError> {
        let ev_type = event.data as u16;
        if self.needs_reset {
            return Err(EpollHelperError::HandleEvent(anyhow!(
                "Needs reset, cannot handle events"
            )));
        }
        self.process_event(ev_type, helper)
            .inspect_err(|_| self.needs_reset = true)
    }
}

#[derive(Copy, Clone)]
#[repr(packed, C)]
pub struct VirtioVhostUserState {
    pub avail_features: u64,
    pub acked_features: u64,
    pub config: VirtioDeviceBackendConfig,
}

const _: () = assert!(
    size_of::<VirtioVhostUserState>()
        == size_of::<u64>() * 2 + size_of::<VirtioDeviceBackendConfig>()
);

// SAFETY: VdbState has no padding and all values are valid.
unsafe impl ByteValued for VirtioVhostUserState {}

// Virtio device backend
pub struct VirtioVhostUser {
    common: VirtioCommon,
    id: String,
    config: VirtioDeviceBackendConfig,
    seccomp_action: SeccompAction,
    exit_evt: EventFd,
    max_queues: u8,
    region: Region,
    listener: Option<UnixStream>,
    msix_fds: [Option<OwnedFd>; MSIX_ARRAY_SIZE],
    statuses: [bool; MSIX_ARRAY_SIZE],
    ioeventfds: Arc<Mutex<IoEventFds>>,
    vm: Option<Arc<dyn hypervisor::Vm>>,
    access_platform: Option<Box<dyn AccessPlatform>>,
}

impl VirtioVhostUser {
    // Create a new virtio-vdb.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        seccomp_action: SeccompAction,
        exit_evt: EventFd,
        state: Option<VirtioVhostUserState>,
        max_queues: u32,
        uuid: [u8; 16],
        listener: UnixStream,
        vm: Arc<dyn hypervisor::Vm>,
        region: Region,
        access_platform: Option<Box<dyn AccessPlatform>>,
    ) -> io::Result<Self> {
        if max_queues > 255 {
            warn!("Cannot support {max_queues} queues, limit is 255");
            todo!()
        }
        let queue_sizes = vec![QUEUE_SIZE; NUM_QUEUES];
        let num_fds = (max_queues * 2 + 1) as usize;
        let mut ioeventfds = Vec::with_capacity(num_fds);
        for _ in 0..num_fds {
            ioeventfds.push(None);
        }
        let ioeventfds = Arc::new(Mutex::new(IoEventFds {
            offset: 0,
            fds: ioeventfds,
        }));

        let (avail_features, acked_features, config, paused) = if let Some(state) = state {
            info!("Restoring virtio-vhost-user {id}");
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

        Ok(VirtioVhostUser {
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
            max_queues: max_queues as _,
            listener: Some(listener),
            statuses: [false; MSIX_ARRAY_SIZE],
            msix_fds: [const { None }; MSIX_ARRAY_SIZE],
            region,
            vm: Some(vm),
            ioeventfds,
            access_platform,
        })
    }

    #[cfg(fuzzing)]
    pub fn wait_for_epoll_threads(&mut self) {
        self.common.wait_for_epoll_threads();
    }
}

impl Drop for VirtioVhostUser {
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

impl VirtioDevice for VirtioVhostUser {
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

    fn doorbells_max(&self) -> u16 {
        u16::from(self.max_queues) * 2 + 1
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        self.read_config_from_slice(self.config.as_slice(), offset, data);
    }

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
        ActivationContext {
            mem,
            interrupt_cb,
            mut queues,
            device_status: _,
        }: crate::ActivationContext,
    ) -> ActivateResult {
        self.common.activate(&queues, interrupt_cb.clone())?;
        let (kill_evt, pause_evt) = self.common.dup_eventfds();

        let (_, frontend_request_queue, frontend_request_queue_evt) = queues.remove(0);
        let (_, frontend_reply_queue, frontend_reply_queue_evt) = queues.remove(0);
        let (_, backend_reply_queue, backend_reply_queue_evt) = queues.remove(0);
        let (_, backend_request_queue, backend_request_queue_evt) = queues.remove(0);
        let queue_pair = VirtioVhostUserQueuePair::new(
            frontend_request_queue,
            backend_reply_queue,
            frontend_request_queue_evt,
            backend_reply_queue_evt,
            Some(self.listener.take().expect("double activate")),
            mem.clone(),
        );
        let backend_request_queue_pair = VirtioVhostUserQueuePair::new(
            backend_request_queue,
            frontend_reply_queue,
            backend_request_queue_evt,
            frontend_reply_queue_evt,
            None,
            mem.clone(),
        );
        let mapping = Mapping::new(self.region.clone());
        let vm = InternalVM {
            vm: self.vm.take().expect("double activate"),
            interrupt_cb,
            backend_socket: None,
        };
        let mut handler = VdbEpollHandler {
            kill_evt,
            pause_evt,
            epoll_fd: None,
            requests: FrontendRequestQueuePair::new(
                queue_pair,
                mapping,
                self.ioeventfds.clone(),
                self.max_queues,
                vm,
            ),
            replies: BackendRequestQueuePair::new(backend_request_queue_pair),
            needs_reset: false,
            access_platform: self.access_platform.take(),
        };

        let paused = self.common.paused.clone();
        let paused_sync = self.common.paused_sync.clone();
        let mut epoll_threads = Vec::new();

        spawn_virtio_thread(
            &self.id,
            &self.seccomp_action,
            Thread::VirtioVhostUser,
            &mut epoll_threads,
            &self.exit_evt,
            move || handler.run(&paused, paused_sync.as_ref().unwrap()),
        )?;
        self.common.epoll_threads = Some(epoll_threads);

        event!("virtio-device", "activated", "id", &self.id);
        Ok(())
    }

    fn reset(&mut self) -> Option<Arc<dyn VirtioInterrupt>> {
        let result = self.common.reset();
        event!("virtio-device", "reset", "id", &self.id);
        if false { result } else { todo!("reset") }
    }
}
