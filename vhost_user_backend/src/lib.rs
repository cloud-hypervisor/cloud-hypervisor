// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::error;
use std::fs::File;
use std::io;
use std::num::Wrapping;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::result;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use vhost_rs::vhost_user::message::{
    VhostUserConfigFlags, VhostUserMemoryRegion, VhostUserProtocolFeatures,
    VhostUserVirtioFeatures, VhostUserVringAddrFlags, VhostUserVringState,
};
use vhost_rs::vhost_user::{
    Error as VhostUserError, Result as VhostUserResult, SlaveFsCacheReq, SlaveListener,
    VhostUserSlaveReqHandler,
};
use virtio_bindings::bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use vm_memory::guest_memory::FileOffset;
use vm_memory::{GuestAddress, GuestMemoryMmap};
use vm_virtio::Queue;
use vmm_sys_util::eventfd::EventFd;

#[derive(Debug)]
/// Errors related to vhost-user daemon.
pub enum Error {
    /// Failed to create a new vhost-user handler.
    NewVhostUserHandler(VhostUserHandlerError),
    /// Failed creating vhost-user slave listener.
    CreateSlaveListener(VhostUserError),
    /// Failed creating vhost-user slave handler.
    CreateSlaveReqHandler(VhostUserError),
    /// Failed starting daemon thread.
    StartDaemon(io::Error),
    /// Failed waiting for daemon thread.
    WaitDaemon(std::boxed::Box<dyn std::any::Any + std::marker::Send>),
    /// Failed handling a vhost-user request.
    HandleRequest(VhostUserError),
}

/// Result of vhost-user daemon operations.
pub type Result<T> = result::Result<T, Error>;

/// This trait must be implemented by the caller in order to provide backend
/// specific implementation.
pub trait VhostUserBackend: Send + Sync + 'static {
    /// Number of queues.
    fn num_queues(&self) -> usize;

    /// Depth of each queue.
    fn max_queue_size(&self) -> usize;

    /// Virtio features.
    fn features(&self) -> u64;

    /// Virtio protocol features.
    fn protocol_features(&self) -> VhostUserProtocolFeatures;

    /// Tell the backend if EVENT_IDX has been negotiated.
    fn set_event_idx(&mut self, enabled: bool);

    /// Update guest memory regions.
    fn update_memory(&mut self, mem: GuestMemoryMmap) -> result::Result<(), io::Error>;

    /// Get virtio device configuration.
    /// A default implementation is provided as we cannot expect all backends
    /// to implement this function.
    fn get_config(&self, _offset: u32, _size: u32) -> Vec<u8> {
        Vec::new()
    }

    /// Set virtio device configuration.
    /// A default implementation is provided as we cannot expect all backends
    /// to implement this function.
    fn set_config(&mut self, _offset: u32, _buf: &[u8]) -> result::Result<(), io::Error> {
        Ok(())
    }

    /// Set slave fd.
    /// A default implementation is provided as we cannot expect all backends
    /// to implement this function.
    fn set_slave_req_fd(&mut self, _vu_req: SlaveFsCacheReq) {}

    /// Register listener.
    /// Register listener for vring to the epoll_fd managed by backends. Then epoll thread could receive the vring events.
    fn register_listener(&mut self, _fd: RawFd, _index: u64) -> result::Result<(), io::Error> {
        Ok(())
    }

    /// Rnregister listener.
    /// Unregister listener for vring from the epoll_fd managed by backends.
    fn unregister_listener(&mut self, _fd: RawFd, _index: u64) -> result::Result<(), io::Error> {
        Ok(())
    }
}

/// This structure is the public API the backend is allowed to interact with
/// in order to run a fully functional vhost-user daemon.
pub struct VhostUserDaemon<S: VhostUserBackend> {
    name: String,
    sock_path: String,
    handler: Arc<Mutex<VhostUserHandler<S>>>,
    main_thread: Option<thread::JoinHandle<Result<()>>>,
}

impl<S: VhostUserBackend> VhostUserDaemon<S> {
    /// Create the daemon instance, providing the backend implementation of
    /// VhostUserBackend.
    /// Under the hood, this will start a dedicated thread responsible for
    /// listening onto registered event. Those events can be vring events or
    /// custom events from the backend, but they get to be registered later
    /// during the sequence.
    pub fn new(name: String, sock_path: String, backend: Arc<RwLock<S>>) -> Result<Self> {
        let handler = Arc::new(Mutex::new(
            VhostUserHandler::new(backend).map_err(Error::NewVhostUserHandler)?,
        ));

        Ok(VhostUserDaemon {
            name,
            sock_path,
            handler,
            main_thread: None,
        })
    }

    /// Connect to the vhost-user socket and run a dedicated thread handling
    /// all requests coming through this socket. This runs in an infinite loop
    /// that should be terminating once the other end of the socket (the VMM)
    /// disconnects.
    pub fn start(&mut self) -> Result<()> {
        let mut slave_listener =
            SlaveListener::new(self.sock_path.as_str(), true, self.handler.clone())
                .map_err(Error::CreateSlaveListener)?;
        let mut slave_handler = slave_listener
            .accept()
            .map_err(Error::CreateSlaveReqHandler)?
            .unwrap();
        let handle = thread::Builder::new()
            .name(self.name.clone())
            .spawn(move || loop {
                slave_handler
                    .handle_request()
                    .map_err(Error::HandleRequest)?;
            })
            .map_err(Error::StartDaemon)?;

        self.main_thread = Some(handle);

        Ok(())
    }

    /// Wait for the thread handling the vhost-user socket connection to
    /// terminate.
    pub fn wait(&mut self) -> Result<()> {
        if let Some(handle) = self.main_thread.take() {
            match handle.join().map_err(Error::WaitDaemon)? {
                Ok(()) => Ok(()),
                Err(Error::HandleRequest(VhostUserError::SocketBroken(_))) => Ok(()),
                Err(e) => Err(e),
            }
        } else {
            Ok(())
        }
    }
}

struct AddrMapping {
    vmm_addr: u64,
    size: u64,
    gpa_base: u64,
}

struct Memory {
    mappings: Vec<AddrMapping>,
}

pub struct Vring {
    queue: Queue,
    kick: Option<EventFd>,
    call: Option<EventFd>,
    err: Option<EventFd>,
    enabled: bool,
    event_idx: bool,
    signalled_used: Option<Wrapping<u16>>,
}

impl Vring {
    fn new(max_queue_size: u16) -> Self {
        Vring {
            queue: Queue::new(max_queue_size),
            kick: None,
            call: None,
            err: None,
            enabled: false,
            event_idx: false,
            signalled_used: None,
        }
    }

    pub fn mut_queue(&mut self) -> &mut Queue {
        &mut self.queue
    }

    pub fn set_event_idx(&mut self, enabled: bool) {
        /* Also reset the last signalled event */
        self.signalled_used = None;
        self.event_idx = enabled;
    }

    pub fn needs_notification(&mut self, mem: &GuestMemoryMmap, used_idx: Wrapping<u16>) -> bool {
        if !self.event_idx {
            return true;
        }

        let mut notify = true;

        if let Some(old_idx) = self.signalled_used {
            if let Some(used_event) = self.mut_queue().get_used_event(&mem) {
                if (used_idx - used_event - Wrapping(1u16)) >= (used_idx - old_idx) {
                    notify = false;
                }
            }
        }

        self.signalled_used = Some(used_idx);
        notify
    }

    pub fn signal_used_queue(&mut self) -> result::Result<(), io::Error> {
        if let Some(call) = self.call.as_ref() {
            call.write(1)
        } else {
            Ok(())
        }
    }

    pub fn get_kick(&self) -> Option<&EventFd> {
        self.kick.as_ref()
    }

    pub fn get_enabled(&self) -> bool {
        self.enabled
    }
}

#[derive(Debug)]
/// Errors related to vhost-user handler.
pub enum VhostUserHandlerError {
    /// Failed to create epoll file descriptor.
    EpollCreateFd(io::Error),
    /// Failed to spawn vring worker.
    SpawnVringWorker(io::Error),
    /// Could not find the mapping from memory regions.
    MissingMemoryMapping,
}

impl std::fmt::Display for VhostUserHandlerError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            VhostUserHandlerError::EpollCreateFd(e) => write!(f, "failed creating epoll fd: {}", e),
            VhostUserHandlerError::SpawnVringWorker(e) => {
                write!(f, "failed spawning the vring worker: {}", e)
            }
            VhostUserHandlerError::MissingMemoryMapping => write!(f, "Missing memory mapping"),
        }
    }
}

impl error::Error for VhostUserHandlerError {}

/// Result of vhost-user handler operations.
type VhostUserHandlerResult<T> = std::result::Result<T, VhostUserHandlerError>;

struct VhostUserHandler<S: VhostUserBackend> {
    backend: Arc<RwLock<S>>,
    owned: bool,
    features_acked: bool,
    acked_features: u64,
    acked_protocol_features: u64,
    num_queues: usize,
    max_queue_size: usize,
    memory: Option<Memory>,
    vrings: Vec<Arc<RwLock<Vring>>>,
}

impl<S: VhostUserBackend> VhostUserHandler<S> {
    fn new(backend: Arc<RwLock<S>>) -> VhostUserHandlerResult<Self> {
        let num_queues = backend.read().unwrap().num_queues();
        let max_queue_size = backend.read().unwrap().max_queue_size();

        let mut vrings: Vec<Arc<RwLock<Vring>>> = Vec::new();
        for _ in 0..num_queues {
            let vring = Arc::new(RwLock::new(Vring::new(max_queue_size as u16)));
            vrings.push(vring);
        }

        Ok(VhostUserHandler {
            backend,
            owned: false,
            features_acked: false,
            acked_features: 0,
            acked_protocol_features: 0,
            num_queues,
            max_queue_size,
            memory: None,
            vrings,
        })
    }

    fn vmm_va_to_gpa(&self, vmm_va: u64) -> VhostUserHandlerResult<u64> {
        if let Some(memory) = &self.memory {
            for mapping in memory.mappings.iter() {
                if vmm_va >= mapping.vmm_addr && vmm_va < mapping.vmm_addr + mapping.size {
                    return Ok(vmm_va - mapping.vmm_addr + mapping.gpa_base);
                }
            }
        }

        Err(VhostUserHandlerError::MissingMemoryMapping)
    }
}

impl<S: VhostUserBackend> VhostUserSlaveReqHandler for VhostUserHandler<S> {
    fn set_owner(&mut self) -> VhostUserResult<()> {
        if self.owned {
            return Err(VhostUserError::InvalidOperation);
        }
        self.owned = true;
        Ok(())
    }

    fn reset_owner(&mut self) -> VhostUserResult<()> {
        self.owned = false;
        self.features_acked = false;
        self.acked_features = 0;
        self.acked_protocol_features = 0;
        Ok(())
    }

    fn get_features(&mut self) -> VhostUserResult<u64> {
        Ok(self.backend.read().unwrap().features())
    }

    fn set_features(&mut self, features: u64) -> VhostUserResult<()> {
        if (features & !self.backend.read().unwrap().features()) != 0 {
            return Err(VhostUserError::InvalidParam);
        }

        self.acked_features = features;
        self.features_acked = true;

        // If VHOST_USER_F_PROTOCOL_FEATURES has not been negotiated,
        // the ring is initialized in an enabled state.
        // If VHOST_USER_F_PROTOCOL_FEATURES has been negotiated,
        // the ring is initialized in a disabled state. Client must not
        // pass data to/from the backend until ring is enabled by
        // VHOST_USER_SET_VRING_ENABLE with parameter 1, or after it has
        // been disabled by VHOST_USER_SET_VRING_ENABLE with parameter 0.
        let vring_enabled =
            self.acked_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() == 0;
        for vring in self.vrings.iter_mut() {
            vring.write().unwrap().enabled = vring_enabled;
        }

        Ok(())
    }

    fn get_protocol_features(&mut self) -> VhostUserResult<VhostUserProtocolFeatures> {
        Ok(self.backend.read().unwrap().protocol_features())
    }

    fn set_protocol_features(&mut self, features: u64) -> VhostUserResult<()> {
        // Note: slave that reported VHOST_USER_F_PROTOCOL_FEATURES must
        // support this message even before VHOST_USER_SET_FEATURES was
        // called.
        self.acked_protocol_features = features;
        Ok(())
    }

    fn set_mem_table(
        &mut self,
        ctx: &[VhostUserMemoryRegion],
        fds: &[RawFd],
    ) -> VhostUserResult<()> {
        // We need to create tuple of ranges from the list of VhostUserMemoryRegion
        // that we get from the caller.
        let mut regions: Vec<(GuestAddress, usize, Option<FileOffset>)> = Vec::new();
        let mut mappings: Vec<AddrMapping> = Vec::new();

        for (idx, region) in ctx.iter().enumerate() {
            let g_addr = GuestAddress(region.guest_phys_addr);
            let len = region.memory_size as usize;
            let file = unsafe { File::from_raw_fd(fds[idx]) };
            let f_off = FileOffset::new(file, region.mmap_offset);

            regions.push((g_addr, len, Some(f_off)));
            mappings.push(AddrMapping {
                vmm_addr: region.user_addr,
                size: region.memory_size,
                gpa_base: region.guest_phys_addr,
            });
        }

        let mem = GuestMemoryMmap::from_ranges_with_files(regions).map_err(|e| {
            VhostUserError::ReqHandlerError(io::Error::new(io::ErrorKind::Other, e))
        })?;
        self.backend
            .write()
            .unwrap()
            .update_memory(mem)
            .map_err(|e| {
                VhostUserError::ReqHandlerError(io::Error::new(io::ErrorKind::Other, e))
            })?;
        self.memory = Some(Memory { mappings });

        Ok(())
    }

    fn get_queue_num(&mut self) -> VhostUserResult<u64> {
        Ok(self.num_queues as u64)
    }

    fn set_vring_num(&mut self, index: u32, num: u32) -> VhostUserResult<()> {
        if index as usize >= self.num_queues || num == 0 || num as usize > self.max_queue_size {
            return Err(VhostUserError::InvalidParam);
        }
        self.vrings[index as usize].write().unwrap().queue.size = num as u16;
        Ok(())
    }

    fn set_vring_addr(
        &mut self,
        index: u32,
        _flags: VhostUserVringAddrFlags,
        descriptor: u64,
        used: u64,
        available: u64,
        _log: u64,
    ) -> VhostUserResult<()> {
        if index as usize >= self.num_queues {
            return Err(VhostUserError::InvalidParam);
        }

        if self.memory.is_some() {
            let desc_table = self.vmm_va_to_gpa(descriptor).map_err(|e| {
                VhostUserError::ReqHandlerError(io::Error::new(io::ErrorKind::Other, e))
            })?;
            let avail_ring = self.vmm_va_to_gpa(available).map_err(|e| {
                VhostUserError::ReqHandlerError(io::Error::new(io::ErrorKind::Other, e))
            })?;
            let used_ring = self.vmm_va_to_gpa(used).map_err(|e| {
                VhostUserError::ReqHandlerError(io::Error::new(io::ErrorKind::Other, e))
            })?;
            self.vrings[index as usize]
                .write()
                .unwrap()
                .queue
                .desc_table = GuestAddress(desc_table);
            self.vrings[index as usize]
                .write()
                .unwrap()
                .queue
                .avail_ring = GuestAddress(avail_ring);
            self.vrings[index as usize].write().unwrap().queue.used_ring = GuestAddress(used_ring);
            Ok(())
        } else {
            Err(VhostUserError::InvalidParam)
        }
    }

    fn set_vring_base(&mut self, index: u32, base: u32) -> VhostUserResult<()> {
        self.vrings[index as usize]
            .write()
            .unwrap()
            .queue
            .next_avail = Wrapping(base as u16);
        self.vrings[index as usize].write().unwrap().queue.next_used = Wrapping(base as u16);

        let event_idx: bool = (self.acked_features & (1 << VIRTIO_RING_F_EVENT_IDX)) != 0;
        self.vrings[index as usize]
            .write()
            .unwrap()
            .set_event_idx(event_idx);
        self.backend.write().unwrap().set_event_idx(event_idx);
        Ok(())
    }

    fn get_vring_base(&mut self, index: u32) -> VhostUserResult<VhostUserVringState> {
        if index as usize >= self.num_queues {
            return Err(VhostUserError::InvalidParam);
        }
        // Quote from vhost-user specification:
        // Client must start ring upon receiving a kick (that is, detecting
        // that file descriptor is readable) on the descriptor specified by
        // VHOST_USER_SET_VRING_KICK, and stop ring upon receiving
        // VHOST_USER_GET_VRING_BASE.
        self.vrings[index as usize].write().unwrap().queue.ready = false;
        if let Some(fd) = self.vrings[index as usize].read().unwrap().kick.as_ref() {
            self.backend
                .write()
                .unwrap()
                .unregister_listener(fd.as_raw_fd(), u64::from(index))
                .map_err(VhostUserError::ReqHandlerError)?;
        }

        let next_avail = self.vrings[index as usize]
            .read()
            .unwrap()
            .queue
            .next_avail
            .0 as u16;

        Ok(VhostUserVringState::new(index, u32::from(next_avail)))
    }

    fn set_vring_kick(&mut self, index: u8, fd: Option<RawFd>) -> VhostUserResult<()> {
        if index as usize >= self.num_queues {
            return Err(VhostUserError::InvalidParam);
        }

        if let Some(kick) = self.vrings[index as usize].write().unwrap().kick.take() {
            // Close file descriptor set by previous operations.
            let _ = unsafe { libc::close(kick.as_raw_fd()) };
        }
        self.vrings[index as usize].write().unwrap().kick =
            fd.map(|x| unsafe { EventFd::from_raw_fd(x) });

        // Quote from vhost-user specification:
        // Client must start ring upon receiving a kick (that is, detecting
        // that file descriptor is readable) on the descriptor specified by
        // VHOST_USER_SET_VRING_KICK, and stop ring upon receiving
        // VHOST_USER_GET_VRING_BASE.
        self.vrings[index as usize].write().unwrap().queue.ready = true;
        if let Some(fd) = self.vrings[index as usize].read().unwrap().kick.as_ref() {
            self.backend
                .write()
                .unwrap()
                .register_listener(fd.as_raw_fd(), u64::from(index))
                .map_err(VhostUserError::ReqHandlerError)?;
        }

        Ok(())
    }

    fn set_vring_call(&mut self, index: u8, fd: Option<RawFd>) -> VhostUserResult<()> {
        if index as usize >= self.num_queues {
            return Err(VhostUserError::InvalidParam);
        }

        if let Some(call) = self.vrings[index as usize].write().unwrap().call.take() {
            // Close file descriptor set by previous operations.
            let _ = unsafe { libc::close(call.as_raw_fd()) };
        }
        self.vrings[index as usize].write().unwrap().call =
            fd.map(|x| unsafe { EventFd::from_raw_fd(x) });

        Ok(())
    }

    fn set_vring_err(&mut self, index: u8, fd: Option<RawFd>) -> VhostUserResult<()> {
        if index as usize >= self.num_queues {
            return Err(VhostUserError::InvalidParam);
        }

        if let Some(err) = self.vrings[index as usize].write().unwrap().err.take() {
            // Close file descriptor set by previous operations.
            let _ = unsafe { libc::close(err.as_raw_fd()) };
        }
        self.vrings[index as usize].write().unwrap().err =
            fd.map(|x| unsafe { EventFd::from_raw_fd(x) });

        Ok(())
    }

    fn set_vring_enable(&mut self, index: u32, enable: bool) -> VhostUserResult<()> {
        // This request should be handled only when VHOST_USER_F_PROTOCOL_FEATURES
        // has been negotiated.
        if self.acked_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() == 0 {
            return Err(VhostUserError::InvalidOperation);
        } else if index as usize >= self.num_queues {
            return Err(VhostUserError::InvalidParam);
        }

        // Slave must not pass data to/from the backend until ring is
        // enabled by VHOST_USER_SET_VRING_ENABLE with parameter 1,
        // or after it has been disabled by VHOST_USER_SET_VRING_ENABLE
        // with parameter 0.
        self.vrings[index as usize].write().unwrap().enabled = enable;

        Ok(())
    }

    fn get_config(
        &mut self,
        offset: u32,
        size: u32,
        _flags: VhostUserConfigFlags,
    ) -> VhostUserResult<Vec<u8>> {
        Ok(self.backend.read().unwrap().get_config(offset, size))
    }

    fn set_config(
        &mut self,
        offset: u32,
        buf: &[u8],
        _flags: VhostUserConfigFlags,
    ) -> VhostUserResult<()> {
        self.backend
            .write()
            .unwrap()
            .set_config(offset, buf)
            .map_err(VhostUserError::ReqHandlerError)
    }

    fn set_slave_req_fd(&mut self, vu_req: SlaveFsCacheReq) {
        self.backend.write().unwrap().set_slave_req_fd(vu_req);
    }
}

impl<S: VhostUserBackend> Drop for VhostUserHandler<S> {
    fn drop(&mut self) {}
}
