// Copyright (c) 2020 Ant Financial
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

use crate::{
    seccomp_filters::Thread, thread_helper::spawn_virtio_thread, ActivateError, ActivateResult,
    EpollHelper, EpollHelperError, EpollHelperHandler, GuestMemoryMmap, VirtioCommon, VirtioDevice,
    VirtioDeviceType, VirtioInterrupt, VirtioInterruptType, EPOLL_HELPER_EVENT_LAST,
    VIRTIO_F_VERSION_1,
};
use libc::EFD_NONBLOCK;
use seccompiler::SeccompAction;
use std::io;
use std::mem::size_of;
use std::os::unix::io::AsRawFd;
use std::result;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc, Arc, Barrier, Mutex,
};
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;
use virtio_queue::Queue;
use vm_memory::{
    Address, ByteValued, Bytes, GuestAddress, GuestMemory, GuestMemoryAtomic, GuestMemoryError,
    GuestMemoryRegion,
};
use vm_migration::{
    Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable, VersionMapped,
};
use vmm_sys_util::eventfd::EventFd;

const QUEUE_SIZE: u16 = 128;
const REPORTING_QUEUE_SIZE: u16 = 32;
const MIN_NUM_QUEUES: usize = 2;

// Resize event.
const RESIZE_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;
// Inflate virtio queue event.
const INFLATE_QUEUE_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 2;
// Deflate virtio queue event.
const DEFLATE_QUEUE_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 3;
// Reporting virtio queue event.
const REPORTING_QUEUE_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 4;

// Size of a PFN in the balloon interface.
const VIRTIO_BALLOON_PFN_SHIFT: u64 = 12;

// Deflate balloon on OOM
const VIRTIO_BALLOON_F_DEFLATE_ON_OOM: u64 = 2;
// Enable an additional virtqueue to let the guest notify the host about free
// pages.
const VIRTIO_BALLOON_F_REPORTING: u64 = 5;

#[derive(Debug)]
pub enum Error {
    // Guest gave us bad memory addresses.
    GuestMemory(GuestMemoryError),
    // Guest gave us a write only descriptor that protocol says to read from.
    UnexpectedWriteOnlyDescriptor,
    // Guest sent us invalid request.
    InvalidRequest,
    // Fallocate fail.
    FallocateFail(std::io::Error),
    // Madvise fail.
    MadviseFail(std::io::Error),
    // Failed to EventFd write.
    EventFdWriteFail(std::io::Error),
    // Failed to EventFd try_clone.
    EventFdTryCloneFail(std::io::Error),
    // Failed to MpscRecv.
    MpscRecvFail(mpsc::RecvError),
    // Resize invalid argument
    ResizeInval(String),
    // Invalid queue index
    InvalidQueueIndex(usize),
    // Fail tp signal
    FailedSignal(io::Error),
    /// Descriptor chain is too short
    DescriptorChainTooShort,
    /// Failed adding used index
    QueueAddUsed(virtio_queue::Error),
    /// Failed creating an iterator over the queue
    QueueIterator(virtio_queue::Error),
}

// Got from include/uapi/linux/virtio_balloon.h
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Versionize)]
pub struct VirtioBalloonConfig {
    // Number of pages host wants Guest to give up.
    num_pages: u32,
    // Number of pages we've actually got in balloon.
    actual: u32,
}

const CONFIG_ACTUAL_OFFSET: u64 = 4;
const CONFIG_ACTUAL_SIZE: usize = 4;

// SAFETY: it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioBalloonConfig {}

struct VirtioBalloonResizeReceiver {
    size: Arc<AtomicU64>,
    tx: mpsc::Sender<Result<(), Error>>,
    evt: EventFd,
}

impl VirtioBalloonResizeReceiver {
    fn get_size(&self) -> u64 {
        self.size.load(Ordering::Acquire)
    }

    fn send(&self, r: Result<(), Error>) -> Result<(), mpsc::SendError<Result<(), Error>>> {
        self.tx.send(r)
    }
}

struct VirtioBalloonResize {
    size: Arc<AtomicU64>,
    tx: mpsc::Sender<Result<(), Error>>,
    rx: mpsc::Receiver<Result<(), Error>>,
    evt: EventFd,
}

impl VirtioBalloonResize {
    pub fn new(size: u64) -> io::Result<Self> {
        let (tx, rx) = mpsc::channel();

        Ok(Self {
            size: Arc::new(AtomicU64::new(size)),
            tx,
            rx,
            evt: EventFd::new(EFD_NONBLOCK)?,
        })
    }

    pub fn get_receiver(&self) -> Result<VirtioBalloonResizeReceiver, Error> {
        Ok(VirtioBalloonResizeReceiver {
            size: self.size.clone(),
            tx: self.tx.clone(),
            evt: self.evt.try_clone().map_err(Error::EventFdTryCloneFail)?,
        })
    }

    pub fn work(&self, size: u64) -> Result<(), Error> {
        self.size.store(size, Ordering::Release);
        self.evt.write(1).map_err(Error::EventFdWriteFail)?;
        self.rx.recv().map_err(Error::MpscRecvFail)?
    }
}

struct BalloonEpollHandler {
    config: Arc<Mutex<VirtioBalloonConfig>>,
    resize_receiver: VirtioBalloonResizeReceiver,
    queues: Vec<Queue<GuestMemoryAtomic<GuestMemoryMmap>>>,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    inflate_queue_evt: EventFd,
    deflate_queue_evt: EventFd,
    reporting_queue_evt: Option<EventFd>,
    kill_evt: EventFd,
    pause_evt: EventFd,
}

impl BalloonEpollHandler {
    fn signal(&self, int_type: VirtioInterruptType) -> result::Result<(), Error> {
        self.interrupt_cb.trigger(int_type).map_err(|e| {
            error!("Failed to signal used queue: {:?}", e);
            Error::FailedSignal(e)
        })
    }

    fn advise_memory_range(
        memory: &GuestMemoryMmap,
        range_base: GuestAddress,
        range_len: usize,
        advice: libc::c_int,
    ) -> result::Result<(), Error> {
        let hva = memory
            .get_host_address(range_base)
            .map_err(Error::GuestMemory)?;
        // Need unsafe to do syscall madvise
        let res =
            unsafe { libc::madvise(hva as *mut libc::c_void, range_len as libc::size_t, advice) };
        if res != 0 {
            return Err(Error::MadviseFail(io::Error::last_os_error()));
        }
        Ok(())
    }

    fn release_memory_range(
        memory: &GuestMemoryMmap,
        range_base: GuestAddress,
        range_len: usize,
    ) -> result::Result<(), Error> {
        let region = memory.find_region(range_base).ok_or(Error::GuestMemory(
            GuestMemoryError::InvalidGuestAddress(range_base),
        ))?;
        if let Some(f_off) = region.file_offset() {
            let offset = range_base.0 - region.start_addr().0;
            let res = unsafe {
                libc::fallocate64(
                    f_off.file().as_raw_fd(),
                    libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                    (offset as u64 + f_off.start()) as libc::off64_t,
                    range_len as libc::off64_t,
                )
            };

            if res != 0 {
                return Err(Error::FallocateFail(io::Error::last_os_error()));
            }
        }

        Self::advise_memory_range(memory, range_base, range_len, libc::MADV_DONTNEED)
    }

    fn notify_queue(
        &mut self,
        queue_index: usize,
        used_descs: Vec<(u16, u32)>,
    ) -> result::Result<(), Error> {
        for (desc_index, len) in used_descs.iter() {
            self.queues[queue_index]
                .add_used(*desc_index, *len)
                .map_err(Error::QueueAddUsed)?;
        }

        if !used_descs.is_empty() {
            self.signal(VirtioInterruptType::Queue(queue_index as u16))?;
        }

        Ok(())
    }

    fn process_queue(&mut self, queue_index: usize) -> result::Result<(), Error> {
        let mut used_descs = Vec::new();
        for mut desc_chain in self.queues[queue_index]
            .iter()
            .map_err(Error::QueueIterator)?
        {
            let desc = desc_chain.next().ok_or(Error::DescriptorChainTooShort)?;

            used_descs.push((desc_chain.head_index(), desc.len()));

            let data_chunk_size = size_of::<u32>();

            // The head contains the request type which MUST be readable.
            if desc.is_write_only() {
                error!("The head contains the request type is not right");
                return Err(Error::UnexpectedWriteOnlyDescriptor);
            }
            if desc.len() as usize % data_chunk_size != 0 {
                error!("the request size {} is not right", desc.len());
                return Err(Error::InvalidRequest);
            }

            let mut offset = 0u64;
            while offset < desc.len() as u64 {
                let addr = desc.addr().checked_add(offset).unwrap();
                let pfn: u32 = desc_chain
                    .memory()
                    .read_obj(addr)
                    .map_err(Error::GuestMemory)?;
                offset += data_chunk_size as u64;

                let range_base = GuestAddress((pfn as u64) << VIRTIO_BALLOON_PFN_SHIFT);
                let range_len = 1 << VIRTIO_BALLOON_PFN_SHIFT;

                match queue_index {
                    0 => {
                        Self::release_memory_range(desc_chain.memory(), range_base, range_len)?;
                    }
                    1 => {
                        Self::advise_memory_range(
                            desc_chain.memory(),
                            range_base,
                            range_len,
                            libc::MADV_WILLNEED,
                        )?;
                    }
                    _ => return Err(Error::InvalidQueueIndex(queue_index)),
                }
            }
        }

        self.notify_queue(queue_index, used_descs)
    }

    fn process_reporting_queue(&mut self, queue_index: usize) -> result::Result<(), Error> {
        let mut used_descs = Vec::new();

        for mut desc_chain in self.queues[queue_index]
            .iter()
            .map_err(Error::QueueIterator)?
        {
            let mut descs_len = 0;
            while let Some(desc) = desc_chain.next() {
                descs_len += desc.len();
                Self::release_memory_range(desc_chain.memory(), desc.addr(), desc.len() as usize)?;
            }

            used_descs.push((desc_chain.head_index(), descs_len));
        }

        self.notify_queue(queue_index, used_descs)
    }

    fn run(
        &mut self,
        paused: Arc<AtomicBool>,
        paused_sync: Arc<Barrier>,
    ) -> result::Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;
        helper.add_event(self.resize_receiver.evt.as_raw_fd(), RESIZE_EVENT)?;
        helper.add_event(self.inflate_queue_evt.as_raw_fd(), INFLATE_QUEUE_EVENT)?;
        helper.add_event(self.deflate_queue_evt.as_raw_fd(), DEFLATE_QUEUE_EVENT)?;
        if let Some(reporting_queue_evt) = self.reporting_queue_evt.as_ref() {
            helper.add_event(reporting_queue_evt.as_raw_fd(), REPORTING_QUEUE_EVENT)?;
        }
        helper.run(paused, paused_sync, self)?;

        Ok(())
    }
}

impl EpollHelperHandler for BalloonEpollHandler {
    fn handle_event(&mut self, _helper: &mut EpollHelper, event: &epoll::Event) -> bool {
        let ev_type = event.data as u16;
        match ev_type {
            RESIZE_EVENT => {
                if let Err(e) = self.resize_receiver.evt.read() {
                    error!("Failed to get resize event: {:?}", e);
                    return true;
                }
                let mut signal_error = false;
                let r = {
                    let mut config = self.config.lock().unwrap();
                    config.num_pages =
                        (self.resize_receiver.get_size() >> VIRTIO_BALLOON_PFN_SHIFT) as u32;
                    if let Err(e) = self.signal(VirtioInterruptType::Config) {
                        signal_error = true;
                        Err(e)
                    } else {
                        Ok(())
                    }
                };
                if let Err(e) = &r {
                    // This error will send back to resize caller.
                    error!("Handle resize event get error: {:?}", e);
                }
                if let Err(e) = self.resize_receiver.send(r) {
                    error!("Sending \"resize\" generated error: {:?}", e);
                    return true;
                }
                if signal_error {
                    return true;
                }
            }
            INFLATE_QUEUE_EVENT => {
                if let Err(e) = self.inflate_queue_evt.read() {
                    error!("Failed to get inflate queue event: {:?}", e);
                    return true;
                } else if let Err(e) = self.process_queue(0) {
                    error!("Failed to signal used inflate queue: {:?}", e);
                    return true;
                }
            }
            DEFLATE_QUEUE_EVENT => {
                if let Err(e) = self.deflate_queue_evt.read() {
                    error!("Failed to get deflate queue event: {:?}", e);
                    return true;
                } else if let Err(e) = self.process_queue(1) {
                    error!("Failed to signal used deflate queue: {:?}", e);
                    return true;
                }
            }
            REPORTING_QUEUE_EVENT => {
                if let Some(reporting_queue_evt) = self.reporting_queue_evt.as_ref() {
                    if let Err(e) = reporting_queue_evt.read() {
                        error!("Failed to get reporting queue event: {:?}", e);
                        return true;
                    } else if let Err(e) = self.process_reporting_queue(2) {
                        error!("Failed to signal used inflate queue: {:?}", e);
                        return true;
                    }
                } else {
                    error!("Invalid reporting queue event as no eventfd registered");
                    return true;
                }
            }
            _ => {
                error!("Unknown event for virtio-balloon");
                return true;
            }
        }

        false
    }
}

#[derive(Versionize)]
pub struct BalloonState {
    pub avail_features: u64,
    pub acked_features: u64,
    pub config: VirtioBalloonConfig,
}

impl VersionMapped for BalloonState {}

// Virtio device for exposing entropy to the guest OS through virtio.
pub struct Balloon {
    common: VirtioCommon,
    id: String,
    resize: VirtioBalloonResize,
    config: Arc<Mutex<VirtioBalloonConfig>>,
    seccomp_action: SeccompAction,
    exit_evt: EventFd,
}

impl Balloon {
    // Create a new virtio-balloon.
    pub fn new(
        id: String,
        size: u64,
        deflate_on_oom: bool,
        free_page_reporting: bool,
        seccomp_action: SeccompAction,
        exit_evt: EventFd,
    ) -> io::Result<Self> {
        let mut queue_sizes = vec![QUEUE_SIZE; MIN_NUM_QUEUES];
        let mut avail_features = 1u64 << VIRTIO_F_VERSION_1;
        if deflate_on_oom {
            avail_features |= 1u64 << VIRTIO_BALLOON_F_DEFLATE_ON_OOM;
        }
        if free_page_reporting {
            avail_features |= 1u64 << VIRTIO_BALLOON_F_REPORTING;
            queue_sizes.push(REPORTING_QUEUE_SIZE);
        }

        let config = VirtioBalloonConfig {
            num_pages: (size >> VIRTIO_BALLOON_PFN_SHIFT) as u32,
            ..Default::default()
        };

        Ok(Balloon {
            common: VirtioCommon {
                device_type: VirtioDeviceType::Balloon as u32,
                avail_features,
                paused_sync: Some(Arc::new(Barrier::new(2))),
                queue_sizes,
                min_queues: MIN_NUM_QUEUES as u16,
                ..Default::default()
            },
            id,
            resize: VirtioBalloonResize::new(size)?,
            config: Arc::new(Mutex::new(config)),
            seccomp_action,
            exit_evt,
        })
    }

    pub fn resize(&self, size: u64) -> Result<(), Error> {
        self.resize.work(size)
    }

    // Get the actual size of the virtio-balloon.
    pub fn get_actual(&self) -> u64 {
        (self.config.lock().unwrap().actual as u64) << VIRTIO_BALLOON_PFN_SHIFT
    }

    fn state(&self) -> BalloonState {
        BalloonState {
            avail_features: self.common.avail_features,
            acked_features: self.common.acked_features,
            config: *(self.config.lock().unwrap()),
        }
    }

    fn set_state(&mut self, state: &BalloonState) {
        self.common.avail_features = state.avail_features;
        self.common.acked_features = state.acked_features;
        *(self.config.lock().unwrap()) = state.config;
    }
}

impl Drop for Balloon {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.common.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
    }
}

impl VirtioDevice for Balloon {
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
        self.read_config_from_slice(self.config.lock().unwrap().as_slice(), offset, data);
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        // The "actual" field is the only mutable field
        if offset != CONFIG_ACTUAL_OFFSET || data.len() != CONFIG_ACTUAL_SIZE {
            error!(
                "Attempt to write to read-only field: offset {:x} length {}",
                offset,
                data.len()
            );
            return;
        }

        self.write_config_helper(self.config.lock().unwrap().as_mut_slice(), offset, data);
    }

    fn activate(
        &mut self,
        _mem: GuestMemoryAtomic<GuestMemoryMmap>,
        interrupt_cb: Arc<dyn VirtioInterrupt>,
        queues: Vec<Queue<GuestMemoryAtomic<GuestMemoryMmap>>>,
        mut queue_evts: Vec<EventFd>,
        _resample_evt: Option<EventFd>,
    ) -> ActivateResult {
        self.common.activate(&queues, &queue_evts, &interrupt_cb)?;
        let (kill_evt, pause_evt) = self.common.dup_eventfds();

        let inflate_queue_evt = queue_evts.remove(0);
        let deflate_queue_evt = queue_evts.remove(0);
        let reporting_queue_evt =
            if self.common.feature_acked(VIRTIO_BALLOON_F_REPORTING) && !queue_evts.is_empty() {
                Some(queue_evts.remove(0))
            } else {
                None
            };

        let mut handler = BalloonEpollHandler {
            config: self.config.clone(),
            resize_receiver: self.resize.get_receiver().map_err(|e| {
                error!("failed to clone resize EventFd: {:?}", e);
                ActivateError::BadActivate
            })?,
            queues,
            interrupt_cb,
            inflate_queue_evt,
            deflate_queue_evt,
            reporting_queue_evt,
            kill_evt,
            pause_evt,
        };

        let paused = self.common.paused.clone();
        let paused_sync = self.common.paused_sync.clone();
        let mut epoll_threads = Vec::new();

        spawn_virtio_thread(
            &self.id,
            &self.seccomp_action,
            Thread::VirtioBalloon,
            &mut epoll_threads,
            &self.exit_evt,
            move || {
                if let Err(e) = handler.run(paused, paused_sync.unwrap()) {
                    error!("Error running worker: {:?}", e);
                }
            },
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

impl Pausable for Balloon {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        self.common.pause()
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        self.common.resume()
    }
}

impl Snapshottable for Balloon {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        Snapshot::new_from_versioned_state(&self.id(), &self.state())
    }

    fn restore(&mut self, snapshot: Snapshot) -> std::result::Result<(), MigratableError> {
        self.set_state(&snapshot.to_versioned_state(&self.id)?);
        Ok(())
    }
}
impl Transportable for Balloon {}
impl Migratable for Balloon {}
