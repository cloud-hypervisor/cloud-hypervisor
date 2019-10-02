// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use epoll;
use libc::EAGAIN;
use libc::EFD_NONBLOCK;
use std::cmp;
use std::io::Read;
use std::io::{self, Write};
use std::mem;
use std::net::Ipv4Addr;
use std::os::unix::io::{AsRawFd, RawFd};
use std::result;
use std::sync::{Arc, RwLock};
use std::thread;
use std::vec::Vec;

use net_gen;

use super::Error as DeviceError;
use super::{
    ActivateError, ActivateResult, DeviceEventT, Queue, VirtioDevice, VirtioDeviceType,
    VirtioInterruptType,
};
use crate::VirtioInterrupt;
use net_util::{MacAddr, Tap, TapError, MAC_ADDR_LEN};
use virtio_bindings::bindings::virtio_net::*;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};
use vmm_sys_util::eventfd::EventFd;

/// The maximum buffer size when segmentation offload is enabled. This
/// includes the 12-byte virtio net header.
/// http://docs.oasis-open.org/virtio/virtio/v1.0/virtio-v1.0.html#x1-1740003
const MAX_BUFFER_SIZE: usize = 65562;
const QUEUE_SIZE: u16 = 256;
const NUM_QUEUES: usize = 2;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE; NUM_QUEUES];

// A frame is available for reading from the tap device to receive in the guest.
const RX_TAP_EVENT: DeviceEventT = 0;
// The guest has made a buffer available to receive a frame into.
const RX_QUEUE_EVENT: DeviceEventT = 1;
// The transmit queue has a frame that is ready to send from the guest.
const TX_QUEUE_EVENT: DeviceEventT = 2;
// The device has been dropped.
pub const KILL_EVENT: DeviceEventT = 3;
// Number of DeviceEventT events supported by this implementation.
pub const NET_EVENTS_COUNT: usize = 4;

#[derive(Debug)]
pub enum Error {
    /// Open tap device failed.
    TapOpen(TapError),
    /// Setting tap IP failed.
    TapSetIp(TapError),
    /// Setting tap netmask failed.
    TapSetNetmask(TapError),
    /// Setting tap interface offload flags failed.
    TapSetOffload(TapError),
    /// Setting vnet header size failed.
    TapSetVnetHdrSize(TapError),
    /// Enabling tap interface failed.
    TapEnable(TapError),
}

pub type Result<T> = result::Result<T, Error>;

struct TxVirtio {
    queue_evt: EventFd,
    queue: Queue,
    iovec: Vec<(GuestAddress, usize)>,
    frame_buf: [u8; MAX_BUFFER_SIZE],
}

impl TxVirtio {
    fn new(queue: Queue, queue_evt: EventFd) -> Self {
        let tx_queue_max_size = queue.get_max_size() as usize;
        TxVirtio {
            queue_evt,
            queue,
            iovec: Vec::with_capacity(tx_queue_max_size),
            frame_buf: [0u8; MAX_BUFFER_SIZE],
        }
    }
}

struct RxVirtio {
    queue_evt: EventFd,
    deferred_frame: bool,
    deferred_irqs: bool,
    queue: Queue,
    bytes_read: usize,
    frame_buf: [u8; MAX_BUFFER_SIZE],
}

impl RxVirtio {
    fn new(queue: Queue, queue_evt: EventFd) -> Self {
        RxVirtio {
            queue_evt,
            deferred_frame: false,
            deferred_irqs: false,
            queue,
            bytes_read: 0,
            frame_buf: [0u8; MAX_BUFFER_SIZE],
        }
    }
}

fn vnet_hdr_len() -> usize {
    mem::size_of::<virtio_net_hdr_v1>()
}

struct NetEpollHandler {
    mem: Arc<RwLock<GuestMemoryMmap>>,
    tap: Tap,
    rx: RxVirtio,
    tx: TxVirtio,
    interrupt_cb: Arc<VirtioInterrupt>,
    kill_evt: EventFd,
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
    fn rx_single_frame(&mut self) -> bool {
        let mem = self.mem.read().unwrap();
        let mut next_desc = self.rx.queue.iter(&mem).next();

        if next_desc.is_none() {
            // Queue has no available descriptors
            if self.rx_tap_listening {
                self.unregister_tap_rx_listener().unwrap();
                self.rx_tap_listening = false;
            }
            return false;
        }

        // We just checked that the head descriptor exists.
        let head_index = next_desc.as_ref().unwrap().index;
        let mut write_count = 0;

        // Copy from frame into buffer, which may span multiple descriptors.
        loop {
            match next_desc {
                Some(desc) => {
                    if !desc.is_write_only() {
                        break;
                    }
                    let limit = cmp::min(write_count + desc.len as usize, self.rx.bytes_read);
                    let source_slice = &self.rx.frame_buf[write_count..limit];
                    let write_result = mem.write_slice(source_slice, desc.addr);

                    match write_result {
                        Ok(_) => {
                            write_count = limit;
                        }
                        Err(e) => {
                            error!("Failed to write slice: {:?}", e);
                            break;
                        }
                    };

                    if write_count >= self.rx.bytes_read {
                        break;
                    }
                    next_desc = desc.next_descriptor();
                }
                None => {
                    warn!("Receiving buffer is too small to hold frame of current size");
                    break;
                }
            }
        }

        self.rx.queue.add_used(&mem, head_index, write_count as u32);

        // Mark that we have at least one pending packet and we need to interrupt the guest.
        self.rx.deferred_irqs = true;

        write_count >= self.rx.bytes_read
    }

    fn process_rx(&mut self) -> result::Result<(), DeviceError> {
        // Read as many frames as possible.
        loop {
            match self.read_tap() {
                Ok(count) => {
                    self.rx.bytes_read = count;
                    if !self.rx_single_frame() {
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
            self.signal_used_queue(&self.rx.queue)
        } else {
            Ok(())
        }
    }

    fn resume_rx(&mut self) -> result::Result<(), DeviceError> {
        if self.rx.deferred_frame {
            if self.rx_single_frame() {
                self.rx.deferred_frame = false;
                // process_rx() was interrupted possibly before consuming all
                // packets in the tap; try continuing now.
                self.process_rx()
            } else if self.rx.deferred_irqs {
                self.rx.deferred_irqs = false;
                self.signal_used_queue(&self.rx.queue)
            } else {
                Ok(())
            }
        } else {
            Ok(())
        }
    }

    fn process_tx(&mut self) -> result::Result<(), DeviceError> {
        let mem = self.mem.read().unwrap();
        while let Some(avail_desc) = self.tx.queue.iter(&mem).next() {
            let head_index = avail_desc.index;
            let mut read_count = 0;
            let mut next_desc = Some(avail_desc);

            self.tx.iovec.clear();
            while let Some(desc) = next_desc {
                if desc.is_write_only() {
                    break;
                }
                self.tx.iovec.push((desc.addr, desc.len as usize));
                read_count += desc.len as usize;
                next_desc = desc.next_descriptor();
            }

            read_count = 0;
            // Copy buffer from across multiple descriptors.
            // TODO(performance - Issue #420): change this to use `writev()` instead of `write()`
            // and get rid of the intermediate buffer.
            for (desc_addr, desc_len) in self.tx.iovec.drain(..) {
                let limit = cmp::min((read_count + desc_len) as usize, self.tx.frame_buf.len());

                let read_result = mem.read_slice(
                    &mut self.tx.frame_buf[read_count..limit as usize],
                    desc_addr,
                );
                match read_result {
                    Ok(_) => {
                        // Increment by number of bytes actually read
                        read_count += limit - read_count;
                    }
                    Err(e) => {
                        error!("Failed to read slice: {:?}", e);
                        break;
                    }
                }
            }

            let write_result = self.tap.write(&self.tx.frame_buf[..read_count as usize]);
            match write_result {
                Ok(_) => {}
                Err(e) => {
                    warn!("net: tx: error failed to write to tap: {}", e);
                }
            };

            self.tx.queue.add_used(&mem, head_index, 0);
        }

        Ok(())
    }

    fn read_tap(&mut self) -> io::Result<usize> {
        self.tap.read(&mut self.rx.frame_buf)
    }

    fn register_tap_rx_listener(&self) -> std::result::Result<(), std::io::Error> {
        epoll::ctl(
            self.epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            self.tap.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, u64::from(RX_TAP_EVENT)),
        )?;
        Ok(())
    }

    fn unregister_tap_rx_listener(&self) -> std::result::Result<(), std::io::Error> {
        epoll::ctl(
            self.epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_DEL,
            self.tap.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, u64::from(RX_TAP_EVENT)),
        )?;
        Ok(())
    }

    fn run(&mut self) -> result::Result<(), DeviceError> {
        // Create the epoll file descriptor
        self.epoll_fd = epoll::create(true).map_err(DeviceError::EpollCreateFd)?;
        // Add events
        epoll::ctl(
            self.epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            self.rx.queue_evt.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, u64::from(RX_QUEUE_EVENT)),
        )
        .map_err(DeviceError::EpollCtl)?;
        epoll::ctl(
            self.epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            self.tx.queue_evt.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, u64::from(TX_QUEUE_EVENT)),
        )
        .map_err(DeviceError::EpollCtl)?;
        self.register_tap_rx_listener()
            .map_err(DeviceError::EpollCtl)?;
        self.rx_tap_listening = true;
        epoll::ctl(
            self.epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            self.kill_evt.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, u64::from(KILL_EVENT)),
        )
        .map_err(DeviceError::EpollCtl)?;

        const EPOLL_EVENTS_LEN: usize = 100;
        let mut events = vec![epoll::Event::new(epoll::Events::empty(), 0); EPOLL_EVENTS_LEN];

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
                        debug!("RX_QUEUE_EVENT received");
                        if let Err(e) = self.rx.queue_evt.read() {
                            error!("Failed to get rx queue event: {:?}", e);
                            break 'epoll;
                        }

                        self.resume_rx().unwrap();
                        if !self.rx_tap_listening {
                            self.register_tap_rx_listener().unwrap();
                            self.rx_tap_listening = true;
                        }
                    }
                    TX_QUEUE_EVENT => {
                        debug!("TX_QUEUE_EVENT received");
                        if let Err(e) = self.tx.queue_evt.read() {
                            error!("Failed to get tx queue event: {:?}", e);
                            break 'epoll;
                        }

                        self.process_tx().unwrap();
                    }
                    RX_TAP_EVENT => {
                        debug!("RX_TAP_EVENT received");
                        if self.rx.deferred_frame
                        // Process a deferred frame first if available. Don't read from tap again
                        // until we manage to receive this deferred frame.
                        {
                            if self.rx_single_frame() {
                                self.rx.deferred_frame = false;
                                self.process_rx().unwrap();
                            } else if self.rx.deferred_irqs {
                                self.rx.deferred_irqs = false;
                                self.signal_used_queue(&self.rx.queue).unwrap();
                            }
                        } else {
                            self.process_rx().unwrap();
                        }
                    }
                    KILL_EVENT => {
                        debug!("KILL_EVENT received, stopping epoll loop");
                        break 'epoll;
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

pub struct Net {
    kill_evt: Option<EventFd>,
    tap: Option<Tap>,
    avail_features: u64,
    acked_features: u64,
    // The config space will only consist of the MAC address specified by the user,
    // or nothing, if no such address if provided.
    config_space: Vec<u8>,
    queue_evts: Option<Vec<EventFd>>,
    interrupt_cb: Option<Arc<VirtioInterrupt>>,
}

impl Net {
    /// Create a new virtio network device with the given TAP interface.
    pub fn new_with_tap(tap: Tap, guest_mac: Option<&MacAddr>) -> Result<Self> {
        // Set offload flags to match the virtio features below.
        tap.set_offload(
            net_gen::TUN_F_CSUM | net_gen::TUN_F_UFO | net_gen::TUN_F_TSO4 | net_gen::TUN_F_TSO6,
        )
        .map_err(Error::TapSetOffload)?;

        let vnet_hdr_size = vnet_hdr_len() as i32;
        tap.set_vnet_hdr_size(vnet_hdr_size)
            .map_err(Error::TapSetVnetHdrSize)?;

        let mut avail_features = 1 << VIRTIO_NET_F_GUEST_CSUM
            | 1 << VIRTIO_NET_F_CSUM
            | 1 << VIRTIO_NET_F_GUEST_TSO4
            | 1 << VIRTIO_NET_F_GUEST_UFO
            | 1 << VIRTIO_NET_F_HOST_TSO4
            | 1 << VIRTIO_NET_F_HOST_UFO
            | 1 << VIRTIO_F_VERSION_1;

        let mut config_space;
        if let Some(mac) = guest_mac {
            config_space = Vec::with_capacity(MAC_ADDR_LEN);
            // This is safe, because we know the capacity is large enough.
            unsafe { config_space.set_len(MAC_ADDR_LEN) }
            config_space[..].copy_from_slice(mac.get_bytes());
            // When this feature isn't available, the driver generates a random MAC address.
            // Otherwise, it should attempt to read the device MAC address from the config space.
            avail_features |= 1 << VIRTIO_NET_F_MAC;
        } else {
            config_space = Vec::new();
        }

        Ok(Net {
            kill_evt: None,
            tap: Some(tap),
            avail_features,
            acked_features: 0u64,
            config_space,
            queue_evts: None,
            interrupt_cb: None,
        })
    }

    /// Create a new virtio network device with the given IP address and
    /// netmask.
    pub fn new(ip_addr: Ipv4Addr, netmask: Ipv4Addr, guest_mac: Option<&MacAddr>) -> Result<Self> {
        let tap = Tap::new().map_err(Error::TapOpen)?;
        tap.set_ip_addr(ip_addr).map_err(Error::TapSetIp)?;
        tap.set_netmask(netmask).map_err(Error::TapSetNetmask)?;
        tap.enable().map_err(Error::TapEnable)?;

        Self::new_with_tap(tap, guest_mac)
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
        mem: Arc<RwLock<GuestMemoryMmap>>,
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

        let (self_kill_evt, kill_evt) =
            match EventFd::new(EFD_NONBLOCK).and_then(|e| Ok((e.try_clone()?, e))) {
                Ok(v) => v,
                Err(e) => {
                    error!("failed creating kill EventFd pair: {}", e);
                    return Err(ActivateError::BadActivate);
                }
            };
        self.kill_evt = Some(self_kill_evt);

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

            let rx_queue = queues.remove(0);
            let tx_queue = queues.remove(0);
            let rx_queue_evt = queue_evts.remove(0);
            let tx_queue_evt = queue_evts.remove(0);
            let mut handler = NetEpollHandler {
                mem,
                tap,
                rx: RxVirtio::new(rx_queue, rx_queue_evt),
                tx: TxVirtio::new(tx_queue, tx_queue_evt),
                interrupt_cb,
                kill_evt,
                epoll_fd: 0,
                rx_tap_listening: false,
            };

            let worker_result = thread::Builder::new()
                .name("virtio_net".to_string())
                .spawn(move || handler.run());

            if let Err(e) = worker_result {
                error!("failed to spawn virtio_blk worker: {}", e);
                return Err(ActivateError::BadActivate);
            }

            return Ok(());
        }
        Err(ActivateError::BadActivate)
    }

    fn reset(&mut self) -> Option<(Arc<VirtioInterrupt>, Vec<EventFd>)> {
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
