// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use epoll;
use libc::EFD_NONBLOCK;
use std;
use std::fs::File;
use std::io;
use std::os::unix::io::AsRawFd;
use std::result;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

use super::Error as DeviceError;
use super::{
    ActivateError, ActivateResult, DeviceEventT, Queue, VirtioDevice, VirtioDeviceType,
    INTERRUPT_STATUS_USED_RING, VIRTIO_F_VERSION_1,
};

use vm_memory::{Bytes, GuestMemoryMmap};
use vmm_sys_util::EventFd;

const QUEUE_SIZE: u16 = 256;
const NUM_QUEUES: usize = 1;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE];

// New descriptors are pending on the virtio queue.
const QUEUE_AVAIL_EVENT: DeviceEventT = 0;
// The device has been dropped.
const KILL_EVENT: DeviceEventT = 1;

struct RngEpollHandler {
    queues: Vec<Queue>,
    mem: GuestMemoryMmap,
    random_file: File,
    interrupt_status: Arc<AtomicUsize>,
    interrupt_evt: Arc<Box<Fn(u16) + Send + Sync>>,
    queue_evt: EventFd,
    kill_evt: EventFd,
}

impl RngEpollHandler {
    fn process_queue(&mut self) -> bool {
        let queue = &mut self.queues[0];

        let mut used_desc_heads = [(0, 0); QUEUE_SIZE as usize];
        let mut used_count = 0;
        for avail_desc in queue.iter(&self.mem) {
            let mut len = 0;

            // Drivers can only read from the random device.
            if avail_desc.is_write_only() {
                // Fill the read with data from the random device on the host.
                if self
                    .mem
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
            queue.add_used(&self.mem, desc_index, len);
        }
        used_count > 0
    }

    fn signal_used_queue(&self) -> result::Result<(), DeviceError> {
        self.interrupt_status
            .fetch_or(INTERRUPT_STATUS_USED_RING as usize, Ordering::SeqCst);
        (self.interrupt_evt)(self.queues[0].msix_vector);
        Ok(())
    }

    fn run(&mut self) -> result::Result<(), DeviceError> {
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

        const EPOLL_EVENTS_LEN: usize = 100;
        let mut events = vec![epoll::Event::new(epoll::Events::empty(), 0); EPOLL_EVENTS_LEN];

        'epoll: loop {
            let num_events =
                epoll::wait(epoll_fd, -1, &mut events[..]).map_err(DeviceError::EpollWait)?;

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
    random_file: Option<File>,
    avail_features: u64,
    acked_features: u64,
}

impl Rng {
    /// Create a new virtio rng device that gets random data from /dev/urandom.
    pub fn new(path: &str) -> io::Result<Rng> {
        let random_file = File::open(path)?;
        let avail_features = 1u64 << VIRTIO_F_VERSION_1;

        Ok(Rng {
            kill_evt: None,
            random_file: Some(random_file),
            avail_features,
            acked_features: 0u64,
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

    fn features(&self, page: u32) -> u32 {
        match page {
            // Get the lower 32-bits of the features bitfield.
            0 => self.avail_features as u32,
            // Get the upper 32-bits of the features bitfield.
            1 => (self.avail_features >> 32) as u32,
            _ => {
                warn!("Received request for unknown features page.");
                0u32
            }
        }
    }

    fn ack_features(&mut self, page: u32, value: u32) {
        let mut v = match page {
            0 => u64::from(value),
            1 => u64::from(value) << 32,
            _ => {
                warn!("Cannot acknowledge unknown features page.");
                0u64
            }
        };

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
        mem: GuestMemoryMmap,
        interrupt_evt: Arc<Box<Fn(u16) + Send + Sync>>,
        status: Arc<AtomicUsize>,
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

        let (self_kill_evt, kill_evt) =
            match EventFd::new(EFD_NONBLOCK).and_then(|e| Ok((e.try_clone()?, e))) {
                Ok(v) => v,
                Err(e) => {
                    error!("failed creating kill EventFd pair: {}", e);
                    return Err(ActivateError::BadActivate);
                }
            };
        self.kill_evt = Some(self_kill_evt);

        if let Some(random_file) = self.random_file.take() {
            let mut handler = RngEpollHandler {
                queues,
                mem,
                random_file,
                interrupt_status: status,
                interrupt_evt,
                queue_evt: queue_evts.remove(0),
                kill_evt,
            };

            let worker_result = thread::Builder::new()
                .name("virtio_rng".to_string())
                .spawn(move || handler.run());

            if let Err(e) = worker_result {
                error!("failed to spawn virtio_rng worker: {}", e);
                return Err(ActivateError::BadActivate);;
            }

            return Ok(());
        }
        Err(ActivateError::BadActivate)
    }
}
