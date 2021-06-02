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

use super::{
    ActivateError, ActivateResult, EpollHelper, EpollHelperError, EpollHelperHandler, Queue,
    VirtioCommon, VirtioDevice, VirtioDeviceType, EPOLL_HELPER_EVENT_LAST, VIRTIO_F_VERSION_1,
};
use crate::seccomp_filters::{get_seccomp_filter, Thread};
use crate::GuestMemoryMmap;
use crate::{VirtioInterrupt, VirtioInterruptType};
use libc::EFD_NONBLOCK;
use seccomp::{SeccompAction, SeccompFilter};
use std::io;
use std::mem::size_of;
use std::os::unix::io::AsRawFd;
use std::result;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use vm_memory::GuestMemory;
use vm_memory::{
    Address, ByteValued, Bytes, GuestAddress, GuestAddressSpace, GuestMemoryAtomic,
    GuestMemoryError,
};
use vm_migration::{Migratable, MigratableError, Pausable, Snapshottable, Transportable};
use vmm_sys_util::eventfd::EventFd;

const QUEUE_SIZE: u16 = 128;
const NUM_QUEUES: usize = 2;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE; NUM_QUEUES];

// Get resize event.
const RESIZE_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;
// New descriptors are pending on the virtio queue.
const INFLATE_QUEUE_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 2;
// New descriptors are pending on the virtio queue.
const DEFLATE_QUEUE_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 3;

// Size of a PFN in the balloon interface.
const VIRTIO_BALLOON_PFN_SHIFT: u64 = 12;

#[derive(Debug)]
pub enum Error {
    // Guest gave us bad memory addresses.
    GuestMemory(GuestMemoryError),
    // Guest gave us a write only descriptor that protocol says to read from.
    UnexpectedWriteOnlyDescriptor,
    // Guest sent us invalid request.
    InvalidRequest,
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
    // process_queue got wrong ev_type
    ProcessQueueWrongEvType(u16),
    // Fail tp signal
    FailedSignal(io::Error),
}

// Got from include/uapi/linux/virtio_balloon.h
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct VirtioBalloonConfig {
    // Number of pages host wants Guest to give up.
    num_pages: u32,
    // Number of pages we've actually got in balloon.
    actual: u32,
}

const CONFIG_ACTUAL_OFFSET: u64 = 4;
const CONFIG_ACTUAL_SIZE: usize = 4;

// Safe because it only has data and has no implicit padding.
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
    pub fn new() -> io::Result<Self> {
        let (tx, rx) = mpsc::channel();

        Ok(Self {
            size: Arc::new(AtomicU64::new(0)),
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
    queues: Vec<Queue>,
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    inflate_queue_evt: EventFd,
    deflate_queue_evt: EventFd,
    kill_evt: EventFd,
    pause_evt: EventFd,
}

impl BalloonEpollHandler {
    fn signal(
        &self,
        int_type: &VirtioInterruptType,
        queue: Option<&Queue>,
    ) -> result::Result<(), Error> {
        self.interrupt_cb.trigger(int_type, queue).map_err(|e| {
            error!("Failed to signal used queue: {:?}", e);
            Error::FailedSignal(e)
        })
    }

    fn process_queue(&mut self, ev_type: u16) -> result::Result<(), Error> {
        let queue_index = match ev_type {
            INFLATE_QUEUE_EVENT => 0,
            DEFLATE_QUEUE_EVENT => 1,
            _ => return Err(Error::ProcessQueueWrongEvType(ev_type)),
        };

        let mut used_desc_heads = [0; QUEUE_SIZE as usize];
        let mut used_count = 0;
        let mem = self.mem.memory();
        for avail_desc in self.queues[queue_index].iter(&mem) {
            used_desc_heads[used_count] = avail_desc.index;
            used_count += 1;

            let data_chunk_size = size_of::<u32>();

            // The head contains the request type which MUST be readable.
            if avail_desc.is_write_only() {
                error!("The head contains the request type is not right");
                return Err(Error::UnexpectedWriteOnlyDescriptor);
            }
            if avail_desc.len as usize % data_chunk_size != 0 {
                error!("the request size {} is not right", avail_desc.len);
                return Err(Error::InvalidRequest);
            }

            let mut offset = 0u64;
            while offset < avail_desc.len as u64 {
                let addr = avail_desc.addr.checked_add(offset).unwrap();
                let pfn: u32 = mem.read_obj(addr).map_err(Error::GuestMemory)?;
                offset += data_chunk_size as u64;

                let gpa = (pfn as u64) << VIRTIO_BALLOON_PFN_SHIFT;
                if let Ok(hva) = mem.get_host_address(GuestAddress(gpa)) {
                    let advice = match ev_type {
                        INFLATE_QUEUE_EVENT => libc::MADV_DONTNEED,
                        DEFLATE_QUEUE_EVENT => libc::MADV_WILLNEED,
                        _ => return Err(Error::ProcessQueueWrongEvType(ev_type)),
                    };
                    // Need unsafe to do syscall madvise
                    let res = unsafe {
                        libc::madvise(
                            hva as *mut libc::c_void,
                            (1 << VIRTIO_BALLOON_PFN_SHIFT) as libc::size_t,
                            advice,
                        )
                    };
                    if res != 0 {
                        return Err(Error::MadviseFail(io::Error::last_os_error()));
                    }
                } else {
                    error!("Address 0x{:x} is not available", gpa);
                    return Err(Error::InvalidRequest);
                }
            }
        }

        for &desc_index in &used_desc_heads[..used_count] {
            self.queues[queue_index].add_used(&mem, desc_index, 0);
        }
        if used_count > 0 {
            self.signal(&VirtioInterruptType::Queue, Some(&self.queues[queue_index]))?;
        }

        Ok(())
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
                    if let Err(e) = self.signal(&VirtioInterruptType::Config, None) {
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
                } else if let Err(e) = self.process_queue(ev_type) {
                    error!("Failed to signal used inflate queue: {:?}", e);
                    return true;
                }
            }
            DEFLATE_QUEUE_EVENT => {
                if let Err(e) = self.deflate_queue_evt.read() {
                    error!("Failed to get deflate queue event: {:?}", e);
                    return true;
                } else if let Err(e) = self.process_queue(ev_type) {
                    error!("Failed to signal used deflate queue: {:?}", e);
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

// Virtio device for exposing entropy to the guest OS through virtio.
pub struct Balloon {
    common: VirtioCommon,
    id: String,
    resize: VirtioBalloonResize,
    config: Arc<Mutex<VirtioBalloonConfig>>,
    seccomp_action: SeccompAction,
}

impl Balloon {
    // Create a new virtio-balloon.
    pub fn new(id: String, size: u64, seccomp_action: SeccompAction) -> io::Result<Self> {
        let avail_features = 1u64 << VIRTIO_F_VERSION_1;

        let config = VirtioBalloonConfig {
            num_pages: (size >> VIRTIO_BALLOON_PFN_SHIFT) as u32,
            ..Default::default()
        };

        Ok(Balloon {
            common: VirtioCommon {
                device_type: VirtioDeviceType::Balloon as u32,
                avail_features,
                paused_sync: Some(Arc::new(Barrier::new(2))),
                queue_sizes: QUEUE_SIZES.to_vec(),
                min_queues: NUM_QUEUES as u16,
                ..Default::default()
            },
            id,
            resize: VirtioBalloonResize::new()?,
            config: Arc::new(Mutex::new(config)),
            seccomp_action,
        })
    }

    pub fn resize(&self, size: u64) -> Result<(), Error> {
        self.resize.work(size)
    }

    // Get the actual size of the virtio-balloon.
    pub fn get_actual(&self) -> u64 {
        (self.config.lock().unwrap().actual as u64) << VIRTIO_BALLOON_PFN_SHIFT
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
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        interrupt_cb: Arc<dyn VirtioInterrupt>,
        queues: Vec<Queue>,
        mut queue_evts: Vec<EventFd>,
    ) -> ActivateResult {
        self.common.activate(&queues, &queue_evts, &interrupt_cb)?;
        let (kill_evt, pause_evt) = self.common.dup_eventfds();

        let mut handler = BalloonEpollHandler {
            config: self.config.clone(),
            resize_receiver: self.resize.get_receiver().map_err(|e| {
                error!("failed to clone resize EventFd: {:?}", e);
                ActivateError::BadActivate
            })?,
            queues,
            mem,
            interrupt_cb,
            inflate_queue_evt: queue_evts.remove(0),
            deflate_queue_evt: queue_evts.remove(0),
            kill_evt,
            pause_evt,
        };

        let paused = self.common.paused.clone();
        let paused_sync = self.common.paused_sync.clone();
        let mut epoll_threads = Vec::new();
        let virtio_balloon_seccomp_filter =
            get_seccomp_filter(&self.seccomp_action, Thread::VirtioBalloon)
                .map_err(ActivateError::CreateSeccompFilter)?;
        thread::Builder::new()
            .name(self.id.clone())
            .spawn(move || {
                if let Err(e) = SeccompFilter::apply(virtio_balloon_seccomp_filter) {
                    error!("Error applying seccomp filter: {:?}", e);
                } else if let Err(e) = handler.run(paused, paused_sync.unwrap()) {
                    error!("Error running worker: {:?}", e);
                }
            })
            .map(|thread| epoll_threads.push(thread))
            .map_err(|e| {
                error!("failed to clone virtio-balloon epoll thread: {}", e);
                ActivateError::BadActivate
            })?;
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
}
impl Transportable for Balloon {}
impl Migratable for Balloon {}
