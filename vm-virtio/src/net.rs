// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use super::net_util::{
    build_net_config_space, open_tap, RxVirtio, TxVirtio, KILL_EVENT, NET_EVENTS_COUNT,
    PAUSE_EVENT, RX_QUEUE_EVENT, RX_TAP_EVENT, TX_QUEUE_EVENT,
};
use super::Error as DeviceError;
use super::{
    ActivateError, ActivateResult, Queue, VirtioDevice, VirtioDeviceType, VirtioInterruptType,
};
use crate::VirtioInterrupt;
use arc_swap::ArcSwap;
use epoll;
use libc::EAGAIN;
use libc::EFD_NONBLOCK;
use net_util::{MacAddr, Tap};
use std::cmp;
use std::io::Read;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::os::unix::io::{AsRawFd, RawFd};
use std::result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::vec::Vec;
use virtio_bindings::bindings::virtio_net::*;
use vm_device::{Migratable, MigratableError, Pausable, Snapshotable};
use vm_memory::GuestMemoryMmap;
use vmm_sys_util::eventfd::EventFd;

const QUEUE_SIZE: u16 = 256;
const NUM_QUEUES: usize = 2;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE; NUM_QUEUES];

#[derive(Debug)]
pub enum Error {
    /// Failed to open taps.
    OpenTap(super::net_util::Error),
}

pub type Result<T> = result::Result<T, Error>;

struct NetEpollHandler {
    mem: Arc<ArcSwap<GuestMemoryMmap>>,
    tap: Tap,
    rx: RxVirtio,
    tx: TxVirtio,
    interrupt_cb: Arc<VirtioInterrupt>,
    kill_evt: EventFd,
    pause_evt: EventFd,
    epoll_fd: RawFd,
    rx_tap_listening: bool,
}

impl NetEpollHandler {
    fn signal_used_queue(&self, queue: &Queue) -> result::Result<(), DeviceError> {
        (self.interrupt_cb)(&VirtioInterruptType::Queue, Some(queue)).map_err(|e| {
            error!("Failed to signal used queue: {:?}", e);
            DeviceError::FailedSignalingUsedQueue(e)
        })
    }

    // Copies a single frame from `self.rx.frame_buf` into the guest. Returns true
    // if a buffer was used, and false if the frame must be deferred until a buffer
    // is made available by the driver.
    fn rx_single_frame(&mut self, mut queue: &mut Queue) -> bool {
        let mem = self.mem.load();
        let next_desc = queue.iter(&mem).next();

        if next_desc.is_none() {
            // Queue has no available descriptors
            if self.rx_tap_listening {
                unregister_listener(
                    self.epoll_fd,
                    self.tap.as_raw_fd(),
                    epoll::Events::EPOLLIN,
                    u64::from(RX_TAP_EVENT),
                )
                .unwrap();
                self.rx_tap_listening = false;
            }
            return false;
        }

        self.rx.process_desc_chain(&mem, next_desc, &mut queue)
    }

    fn process_rx(&mut self, queue: &mut Queue) -> result::Result<(), DeviceError> {
        // Read as many frames as possible.
        loop {
            match self.read_tap() {
                Ok(count) => {
                    self.rx.bytes_read = count;
                    if !self.rx_single_frame(queue) {
                        self.rx.deferred_frame = true;
                        break;
                    }
                }
                Err(e) => {
                    // The tap device is non-blocking, so any error aside from EAGAIN is
                    // unexpected.
                    match e.raw_os_error() {
                        Some(err) if err == EAGAIN => (),
                        _ => {
                            error!("Failed to read tap: {:?}", e);
                            return Err(DeviceError::FailedReadTap);
                        }
                    };
                    break;
                }
            }
        }
        if self.rx.deferred_irqs {
            self.rx.deferred_irqs = false;
            self.signal_used_queue(queue)
        } else {
            Ok(())
        }
    }

    fn resume_rx(&mut self, queue: &mut Queue) -> result::Result<(), DeviceError> {
        if self.rx.deferred_frame {
            if self.rx_single_frame(queue) {
                self.rx.deferred_frame = false;
                // process_rx() was interrupted possibly before consuming all
                // packets in the tap; try continuing now.
                self.process_rx(queue)
            } else if self.rx.deferred_irqs {
                self.rx.deferred_irqs = false;
                self.signal_used_queue(queue)
            } else {
                Ok(())
            }
        } else {
            Ok(())
        }
    }

    fn process_tx(&mut self, mut queue: &mut Queue) -> result::Result<(), DeviceError> {
        let mem = self.mem.load();

        self.tx.process_desc_chain(&mem, &mut self.tap, &mut queue);

        Ok(())
    }

    fn read_tap(&mut self) -> io::Result<usize> {
        self.tap.read(&mut self.rx.frame_buf)
    }

    fn handle_rx_event(&mut self, mut queue: &mut Queue, queue_evt: &EventFd) {
        if let Err(e) = queue_evt.read() {
            error!("Failed to get rx queue event: {:?}", e);
        }

        self.resume_rx(&mut queue).unwrap();
        if !self.rx_tap_listening {
            register_listener(
                self.epoll_fd,
                self.tap.as_raw_fd(),
                epoll::Events::EPOLLIN,
                u64::from(RX_TAP_EVENT),
            )
            .unwrap();
            self.rx_tap_listening = true;
        }
    }

    fn handle_tx_event(&mut self, mut queue: &mut Queue, queue_evt: &EventFd) {
        if let Err(e) = queue_evt.read() {
            error!("Failed to get tx queue event: {:?}", e);
        }

        self.process_tx(&mut queue).unwrap();
    }

    fn handle_rx_tap_event(&mut self, mut queue: &mut Queue) {
        if self.rx.deferred_frame
        // Process a deferred frame first if available. Don't read from tap again
        // until we manage to receive this deferred frame.
        {
            if self.rx_single_frame(&mut queue) {
                self.rx.deferred_frame = false;
                self.process_rx(&mut queue).unwrap();
            } else if self.rx.deferred_irqs {
                self.rx.deferred_irqs = false;
                self.signal_used_queue(&queue).unwrap();
            }
        } else {
            self.process_rx(&mut queue).unwrap();
        }
    }

    fn run(
        &mut self,
        paused: Arc<AtomicBool>,
        mut queues: Vec<Queue>,
        queue_evts: Vec<EventFd>,
    ) -> result::Result<(), DeviceError> {
        // Create the epoll file descriptor
        self.epoll_fd = epoll::create(true).map_err(DeviceError::EpollCreateFd)?;
        // Add events
        // Add events
        epoll::ctl(
            self.epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            queue_evts[0].as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, u64::from(RX_QUEUE_EVENT)),
        )
        .map_err(DeviceError::EpollCtl)?;
        epoll::ctl(
            self.epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            queue_evts[1].as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, u64::from(TX_QUEUE_EVENT)),
        )
        .map_err(DeviceError::EpollCtl)?;
        epoll::ctl(
            self.epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            self.kill_evt.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, u64::from(KILL_EVENT)),
        )
        .map_err(DeviceError::EpollCtl)?;
        epoll::ctl(
            self.epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            self.pause_evt.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, u64::from(PAUSE_EVENT)),
        )
        .map_err(DeviceError::EpollCtl)?;

        let mut events = vec![epoll::Event::new(epoll::Events::empty(), 0); NET_EVENTS_COUNT];

        'epoll: loop {
            let num_events = match epoll::wait(self.epoll_fd, -1, &mut events[..]) {
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
                    RX_QUEUE_EVENT => {
                        self.handle_rx_event(&mut queues[0], &queue_evts[0]);
                    }
                    TX_QUEUE_EVENT => {
                        self.handle_tx_event(&mut queues[1], &queue_evts[1]);
                    }
                    RX_TAP_EVENT => {
                        self.handle_rx_tap_event(&mut queues[0]);
                    }
                    KILL_EVENT => {
                        debug!("KILL_EVENT received, stopping epoll loop");
                        break 'epoll;
                    }
                    PAUSE_EVENT => {
                        debug!("PAUSE_EVENT received, pausing virtio-net epoll loop");
                        // We loop here to handle spurious park() returns.
                        // Until we have not resumed, the paused boolean will
                        // be true.
                        while paused.load(Ordering::SeqCst) {
                            thread::park();
                        }
                    }
                    _ => {
                        error!("Unknown event for virtio-net");
                    }
                }
            }
        }
        Ok(())
    }
}

pub fn register_listener(
    epoll_fd: RawFd,
    fd: RawFd,
    ev_type: epoll::Events,
    data: u64,
) -> result::Result<(), io::Error> {
    epoll::ctl(
        epoll_fd,
        epoll::ControlOptions::EPOLL_CTL_ADD,
        fd,
        epoll::Event::new(ev_type, data),
    )
}

pub fn unregister_listener(
    epoll_fd: RawFd,
    fd: RawFd,
    ev_type: epoll::Events,
    data: u64,
) -> result::Result<(), io::Error> {
    epoll::ctl(
        epoll_fd,
        epoll::ControlOptions::EPOLL_CTL_DEL,
        fd,
        epoll::Event::new(ev_type, data),
    )
}

pub struct Net {
    kill_evt: Option<EventFd>,
    pause_evt: Option<EventFd>,
    tap: Option<Tap>,
    avail_features: u64,
    acked_features: u64,
    // The config space will only consist of the MAC address specified by the user,
    // or nothing, if no such address if provided.
    config_space: Vec<u8>,
    queue_evts: Option<Vec<EventFd>>,
    interrupt_cb: Option<Arc<VirtioInterrupt>>,
    epoll_thread: Option<thread::JoinHandle<result::Result<(), DeviceError>>>,
    paused: Arc<AtomicBool>,
}

impl Net {
    /// Create a new virtio network device with the given TAP interface.
    pub fn new_with_tap(tap: Tap, guest_mac: Option<MacAddr>, iommu: bool) -> Result<Self> {
        let mut avail_features = 1 << VIRTIO_NET_F_GUEST_CSUM
            | 1 << VIRTIO_NET_F_CSUM
            | 1 << VIRTIO_NET_F_GUEST_TSO4
            | 1 << VIRTIO_NET_F_GUEST_UFO
            | 1 << VIRTIO_NET_F_HOST_TSO4
            | 1 << VIRTIO_NET_F_HOST_UFO
            | 1 << VIRTIO_F_VERSION_1;

        if iommu {
            avail_features |= 1u64 << VIRTIO_F_IOMMU_PLATFORM;
        }

        let config_space;
        if let Some(mac) = guest_mac {
            config_space = build_net_config_space(mac, &mut avail_features);
        } else {
            config_space = Vec::new();
        }

        Ok(Net {
            kill_evt: None,
            pause_evt: None,
            tap: Some(tap),
            avail_features,
            acked_features: 0u64,
            config_space,
            queue_evts: None,
            interrupt_cb: None,
            epoll_thread: None,
            paused: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Create a new virtio network device with the given IP address and
    /// netmask.
    pub fn new(
        ip_addr: Ipv4Addr,
        netmask: Ipv4Addr,
        guest_mac: Option<MacAddr>,
        iommu: bool,
    ) -> Result<Self> {
        let tap = open_tap(ip_addr, netmask).map_err(Error::OpenTap)?;

        Self::new_with_tap(tap, guest_mac, iommu)
    }
}

impl Drop for Net {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
    }
}

impl VirtioDevice for Net {
    fn device_type(&self) -> u32 {
        VirtioDeviceType::TYPE_NET as u32
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
                warn!("Received request for unknown features page: {}", page);
                0u32
            }
        }
    }

    fn ack_features(&mut self, page: u32, value: u32) {
        let mut v = match page {
            0 => u64::from(value),
            1 => u64::from(value) << 32,
            _ => {
                warn!("Cannot acknowledge unknown features page: {}", page);
                0u64
            }
        };

        // Check if the guest is ACK'ing a feature that we didn't claim to have.
        let unrequested_features = v & !self.avail_features;
        if unrequested_features != 0 {
            warn!("Received acknowledge request for unknown feature: {:x}", v);
            // Don't count these features as acked.
            v &= !unrequested_features;
        }
        self.acked_features |= v;
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_len = self.config_space.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&self.config_space[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let data_len = data.len() as u64;
        let config_len = self.config_space.len() as u64;
        if offset + data_len > config_len {
            error!("Failed to write config space");
            return;
        }
        let (_, right) = self.config_space.split_at_mut(offset as usize);
        right.copy_from_slice(&data[..]);
    }

    fn activate(
        &mut self,
        mem: Arc<ArcSwap<GuestMemoryMmap>>,
        interrupt_cb: Arc<VirtioInterrupt>,
        mut queues: Vec<Queue>,
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

        if let Some(tap) = self.tap.clone() {
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

            let mut queues_v = Vec::new();
            let mut queue_evts_v = Vec::new();
            queues_v.push(queues.remove(0));
            queues_v.push(queues.remove(0));
            queue_evts_v.push(queue_evts.remove(0));
            queue_evts_v.push(queue_evts.remove(0));
            let mut handler = NetEpollHandler {
                mem,
                tap,
                rx: RxVirtio::new(),
                tx: TxVirtio::new(),
                interrupt_cb,
                kill_evt,
                pause_evt,
                epoll_fd: 0,
                rx_tap_listening: false,
            };

            let paused = self.paused.clone();
            thread::Builder::new()
                .name("virtio_net".to_string())
                .spawn(move || handler.run(paused, queues_v, queue_evts_v))
                .map(|thread| self.epoll_thread = Some(thread))
                .map_err(|e| {
                    error!("failed to clone the virtio-net epoll thread: {}", e);
                    ActivateError::BadActivate
                })?;

            return Ok(());
        }
        Err(ActivateError::BadActivate)
    }

    fn reset(&mut self) -> Option<(Arc<VirtioInterrupt>, Vec<EventFd>)> {
        // We first must resume the virtio thread if it was paused.
        if self.pause_evt.take().is_some() {
            self.resume().ok()?;
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
}

virtio_pausable!(Net);
impl Snapshotable for Net {}
impl Migratable for Net {}
