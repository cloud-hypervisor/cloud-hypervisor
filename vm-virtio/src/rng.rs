// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::Error as DeviceError;
use super::{
    ActivateError, ActivateResult, DeviceEventT, Queue, VirtioDevice, VirtioDeviceType,
    VIRTIO_F_IOMMU_PLATFORM, VIRTIO_F_VERSION_1,
};
use crate::{VirtioInterrupt, VirtioInterruptType};
use epoll;
use libc::EFD_NONBLOCK;
use std;
use std::fs::File;
use std::io;
use std::os::unix::io::AsRawFd;
use std::result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use vm_memory::{Bytes, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};
use vm_migration::{Migratable, MigratableError, Pausable, Snapshotable, Transportable};
use vmm_sys_util::eventfd::EventFd;

const QUEUE_SIZE: u16 = 256;
const NUM_QUEUES: usize = 1;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE];

// New descriptors are pending on the virtio queue.
const QUEUE_AVAIL_EVENT: DeviceEventT = 0;
// The device has been dropped.
const KILL_EVENT: DeviceEventT = 1;
// The device should be paused.
const PAUSE_EVENT: DeviceEventT = 2;

struct RngEpollHandler {
    queues: Vec<Queue>,
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
    random_file: File,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    queue_evt: EventFd,
    kill_evt: EventFd,
    pause_evt: EventFd,
}

impl RngEpollHandler {
    fn process_queue(&mut self) -> bool {
        let queue = &mut self.queues[0];

        let mut used_desc_heads = [(0, 0); QUEUE_SIZE as usize];
        let mut used_count = 0;
        let mem = self.mem.memory();
        for avail_desc in queue.iter(&mem) {
            let mut len = 0;

            // Drivers can only read from the random device.
            if avail_desc.is_write_only() {
                // Fill the read with data from the random device on the host.
                if mem
                    .read_from(
                        avail_desc.addr,
                        &mut self.random_file,
                        avail_desc.len as usize,
                    )
                    .is_ok()
                {
                    len = avail_desc.len;
                }
            }

            used_desc_heads[used_count] = (avail_desc.index, len);
            used_count += 1;
        }

        for &(desc_index, len) in &used_desc_heads[..used_count] {
            queue.add_used(&mem, desc_index, len);
        }
        used_count > 0
    }

    fn signal_used_queue(&self) -> result::Result<(), DeviceError> {
        self.interrupt_cb
            .trigger(&VirtioInterruptType::Queue, Some(&self.queues[0]))
            .map_err(|e| {
                error!("Failed to signal used queue: {:?}", e);
                DeviceError::FailedSignalingUsedQueue(e)
            })
    }

    fn run(&mut self, paused: Arc<AtomicBool>) -> result::Result<(), DeviceError> {
        // Create the epoll file descriptor
        let epoll_fd = epoll::create(true).map_err(DeviceError::EpollCreateFd)?;

        // Add events
        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            self.queue_evt.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, u64::from(QUEUE_AVAIL_EVENT)),
        )
        .map_err(DeviceError::EpollCtl)?;
        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            self.kill_evt.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, u64::from(KILL_EVENT)),
        )
        .map_err(DeviceError::EpollCtl)?;
        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            self.pause_evt.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, u64::from(PAUSE_EVENT)),
        )
        .map_err(DeviceError::EpollCtl)?;

        const EPOLL_EVENTS_LEN: usize = 100;
        let mut events = vec![epoll::Event::new(epoll::Events::empty(), 0); EPOLL_EVENTS_LEN];

        'epoll: loop {
            let num_events = match epoll::wait(epoll_fd, -1, &mut events[..]) {
                Ok(res) => res,
                Err(e) => {
                    if e.kind() == io::ErrorKind::Interrupted {
                        // It's well defined from the epoll_wait() syscall
                        // documentation that the epoll loop can be interrupted
                        // before any of the requested events occurred or the
                        // timeout expired. In both those cases, epoll_wait()
                        // returns an error of type EINTR, but this should not
                        // be considered as a regular error. Instead it is more
                        // appropriate to retry, by calling into epoll_wait().
                        continue;
                    }
                    return Err(DeviceError::EpollWait(e));
                }
            };

            for event in events.iter().take(num_events) {
                let ev_type = event.data as u16;

                match ev_type {
                    QUEUE_AVAIL_EVENT => {
                        if let Err(e) = self.queue_evt.read() {
                            error!("Failed to get queue event: {:?}", e);
                            break 'epoll;
                        } else if self.process_queue() {
                            if let Err(e) = self.signal_used_queue() {
                                error!("Failed to signal used queue: {:?}", e);
                                break 'epoll;
                            }
                        }
                    }
                    KILL_EVENT => {
                        debug!("KILL_EVENT received, stopping epoll loop");
                        break 'epoll;
                    }
                    PAUSE_EVENT => {
                        // Drain pause event
                        let _ = self.pause_evt.read();
                        debug!("PAUSE_EVENT received, pausing virtio-rng epoll loop");
                        // We loop here to handle spurious park() returns.
                        // Until we have not resumed, the paused boolean will
                        // be true.
                        while paused.load(Ordering::SeqCst) {
                            thread::park();
                        }
                    }
                    _ => {
                        error!("Unknown event for virtio-block");
                    }
                }
            }
        }

        Ok(())
    }
}

/// Virtio device for exposing entropy to the guest OS through virtio.
pub struct Rng {
    kill_evt: Option<EventFd>,
    pause_evt: Option<EventFd>,
    random_file: Option<File>,
    avail_features: u64,
    acked_features: u64,
    queue_evts: Option<Vec<EventFd>>,
    interrupt_cb: Option<Arc<dyn VirtioInterrupt>>,
    epoll_threads: Option<Vec<thread::JoinHandle<result::Result<(), DeviceError>>>>,
    paused: Arc<AtomicBool>,
}

impl Rng {
    /// Create a new virtio rng device that gets random data from /dev/urandom.
    pub fn new(path: &str, iommu: bool) -> io::Result<Rng> {
        let random_file = File::open(path)?;
        let mut avail_features = 1u64 << VIRTIO_F_VERSION_1;

        if iommu {
            avail_features |= 1u64 << VIRTIO_F_IOMMU_PLATFORM;
        }

        Ok(Rng {
            kill_evt: None,
            pause_evt: None,
            random_file: Some(random_file),
            avail_features,
            acked_features: 0u64,
            queue_evts: None,
            interrupt_cb: None,
            epoll_threads: None,
            paused: Arc::new(AtomicBool::new(false)),
        })
    }
}

impl Drop for Rng {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
    }
}

impl VirtioDevice for Rng {
    fn device_type(&self) -> u32 {
        VirtioDeviceType::TYPE_RNG as u32
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn features(&self) -> u64 {
        self.avail_features
    }

    fn ack_features(&mut self, value: u64) {
        let mut v = value;
        // Check if the guest is ACK'ing a feature that we didn't claim to have.
        let unrequested_features = v & !self.avail_features;
        if unrequested_features != 0 {
            warn!("Received acknowledge request for unknown feature.");

            // Don't count these features as acked.
            v &= !unrequested_features;
        }
        self.acked_features |= v;
    }

    fn read_config(&self, _offset: u64, _data: &mut [u8]) {
        warn!("No currently device specific configration defined");
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        warn!("No currently device specific configration defined");
    }

    fn activate(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        interrupt_cb: Arc<dyn VirtioInterrupt>,
        queues: Vec<Queue>,
        mut queue_evts: Vec<EventFd>,
    ) -> ActivateResult {
        if queues.len() != NUM_QUEUES || queue_evts.len() != NUM_QUEUES {
            error!(
                "Cannot perform activate. Expected {} queue(s), got {}",
                NUM_QUEUES,
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

        if let Some(file) = self.random_file.as_ref() {
            let random_file = file.try_clone().map_err(|e| {
                error!("failed cloning rng source: {}", e);
                ActivateError::BadActivate
            })?;
            let mut handler = RngEpollHandler {
                queues,
                mem,
                random_file,
                interrupt_cb,
                queue_evt: queue_evts.remove(0),
                kill_evt,
                pause_evt,
            };

            let paused = self.paused.clone();
            let mut epoll_threads = Vec::new();
            thread::Builder::new()
                .name("virtio_rng".to_string())
                .spawn(move || handler.run(paused))
                .map(|thread| epoll_threads.push(thread))
                .map_err(|e| {
                    error!("failed to clone the virtio-rng epoll thread: {}", e);
                    ActivateError::BadActivate
                })?;

            self.epoll_threads = Some(epoll_threads);

            return Ok(());
        }
        Err(ActivateError::BadActivate)
    }

    fn reset(&mut self) -> Option<(Arc<dyn VirtioInterrupt>, Vec<EventFd>)> {
        // We first must resume the virtio thread if it was paused.
        if self.pause_evt.take().is_some() {
            self.resume().ok()?;
        }

        // Then kill it.
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
}

virtio_pausable!(Rng);
impl Snapshotable for Rng {}
impl Transportable for Rng {}
impl Migratable for Rng {}
