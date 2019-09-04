// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

/// This is the `VirtioDevice` implementation for our vsock device. It handles the virtio-level
/// device logic: feature negociation, device configuration, and device activation.
/// The run-time device logic (i.e. event-driven data handling) is implemented by
/// `super::epoll_handler::EpollHandler`.
///
/// We aim to conform to the VirtIO v1.1 spec:
/// https://docs.oasis-open.org/virtio/virtio/v1.1/virtio-v1.1.html
///
/// The vsock device has two input parameters: a CID to identify the device, and a `VsockBackend`
/// to use for offloading vsock traffic.
///
/// Upon its activation, the vsock device creates its `EpollHandler`, passes it the event-interested
/// file descriptors, and registers these descriptors with the VMM `EpollContext`. Going forward,
/// the `EpollHandler` will get notified whenever an event occurs on the just-registered FDs:
/// - an RX queue FD;
/// - a TX queue FD;
/// - an event queue FD; and
/// - a backend FD.
///
use epoll;
use libc::EFD_NONBLOCK;
use std;
use std::io;
use std::os::unix::io::AsRawFd;
use std::result;
use std::sync::{Arc, RwLock};
use std::thread;

use super::VsockBackend;
use crate::Error as DeviceError;
use crate::VirtioInterrupt;
use crate::{
    ActivateError, ActivateResult, DeviceEventT, Queue, VirtioDevice, VirtioDeviceType,
    VIRTIO_F_IN_ORDER, VIRTIO_F_VERSION_1,
};
use byteorder::{ByteOrder, LittleEndian};
use vm_memory::GuestMemoryMmap;
use vmm_sys_util::eventfd::EventFd;

const QUEUE_SIZE: u16 = 256;
const NUM_QUEUES: usize = 3;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE; NUM_QUEUES];

// New descriptors are pending on the rx queue.
const RX_QUEUE_EVENT: DeviceEventT = 0;
// New descriptors are pending on the tx queue.
const TX_QUEUE_EVENT: DeviceEventT = 1;
// New descriptors are pending on the event queue.
const EVT_QUEUE_EVENT: DeviceEventT = 2;
// The device has been dropped.
const KILL_EVENT: DeviceEventT = 3;

struct VsockEpollHandler {
    _cid: u64,
    _mem: Arc<RwLock<GuestMemoryMmap>>,
    _queues: Vec<Queue>,
    queue_evts: Vec<EventFd>,
    kill_evt: EventFd,
    _interrupt_cb: Arc<VirtioInterrupt>,
}

impl VsockEpollHandler {
    fn run(&mut self) -> result::Result<(), DeviceError> {
        // Create the epoll file descriptor
        let epoll_fd = epoll::create(true).map_err(DeviceError::EpollCreateFd)?;

        // Add events
        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            self.queue_evts[0].as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, u64::from(RX_QUEUE_EVENT)),
        )
        .map_err(DeviceError::EpollCtl)?;
        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            self.queue_evts[1].as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, u64::from(TX_QUEUE_EVENT)),
        )
        .map_err(DeviceError::EpollCtl)?;
        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            self.queue_evts[2].as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, u64::from(EVT_QUEUE_EVENT)),
        )
        .map_err(DeviceError::EpollCtl)?;
        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            self.kill_evt.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, u64::from(KILL_EVENT)),
        )
        .map_err(DeviceError::EpollCtl)?;

        let mut events = vec![epoll::Event::new(epoll::Events::empty(), 0); 4];

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
                    RX_QUEUE_EVENT => {
                        if let Err(e) = self.queue_evts[0].read() {
                            error!("Failed to get queue event: {:?}", e);
                            break 'epoll;
                        }

                        debug!("RX queue event received");
                    }
                    TX_QUEUE_EVENT => {
                        if let Err(e) = self.queue_evts[1].read() {
                            error!("Failed to get queue event: {:?}", e);
                            break 'epoll;
                        }

                        debug!("TX queue event received");
                    }
                    EVT_QUEUE_EVENT => {
                        if let Err(e) = self.queue_evts[2].read() {
                            error!("Failed to get queue event: {:?}", e);
                            break 'epoll;
                        }

                        debug!("EVT queue event received");
                    }
                    KILL_EVENT => {
                        debug!("KILL_EVENT received, stopping epoll loop");
                        break 'epoll;
                    }
                    _ => {
                        error!("Unknown event for virtio-vsock");
                    }
                }
            }
        }

        Ok(())
    }
}

/// Virtio device exposing virtual socket to the guest.
pub struct Vsock<B: VsockBackend> {
    cid: u64,
    _backend: Option<B>,
    kill_evt: Option<EventFd>,
    avail_features: u64,
    acked_features: u64,
}

impl<B> Vsock<B>
where
    B: VsockBackend,
{
    /// Create a new virtio-vsock device with the given VM CID and vsock
    /// backend.
    pub fn new(cid: u64, backend: B) -> io::Result<Vsock<B>> {
        let avail_features = 1u64 << VIRTIO_F_VERSION_1 | 1u64 << VIRTIO_F_IN_ORDER;

        Ok(Vsock {
            cid,
            _backend: Some(backend),
            kill_evt: None,
            avail_features,
            acked_features: 0u64,
        })
    }
}

impl<B> Drop for Vsock<B>
where
    B: VsockBackend,
{
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
    }
}

impl<B> VirtioDevice for Vsock<B>
where
    B: VsockBackend,
{
    fn device_type(&self) -> u32 {
        VirtioDeviceType::TYPE_VSOCK as u32
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

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        match offset {
            0 if data.len() == 8 => LittleEndian::write_u64(data, self.cid),
            0 if data.len() == 4 => LittleEndian::write_u32(data, (self.cid & 0xffff_ffff) as u32),
            4 if data.len() == 4 => {
                LittleEndian::write_u32(data, ((self.cid >> 32) & 0xffff_ffff) as u32)
            }
            _ => warn!(
                "vsock: virtio-vsock received invalid read request of {} bytes at offset {}",
                data.len(),
                offset
            ),
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        warn!(
            "vsock: guest driver attempted to write device config (offset={:x}, len={:x})",
            offset,
            data.len()
        );
    }

    fn activate(
        &mut self,
        mem: Arc<RwLock<GuestMemoryMmap>>,
        interrupt_cb: Arc<VirtioInterrupt>,
        queues: Vec<Queue>,
        queue_evts: Vec<EventFd>,
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

        let mut handler = VsockEpollHandler {
            _cid: self.cid,
            _mem: mem,
            _queues: queues,
            queue_evts,
            kill_evt,
            _interrupt_cb: interrupt_cb,
        };

        let worker_result = thread::Builder::new()
            .name("virtio_vsock".to_string())
            .spawn(move || handler.run());

        if let Err(e) = worker_result {
            error!("failed to spawn virtio_vsock worker: {}", e);
            return Err(ActivateError::BadActivate);;
        }

        Ok(())
    }
}
