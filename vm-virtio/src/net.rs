// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use super::net_util::{
    build_net_config_space, build_net_config_space_with_mq, open_tap, register_listener,
    unregister_listener, CtrlVirtio, NetCtrlEpollHandler, RxVirtio, TxVirtio, VirtioNetConfig,
    KILL_EVENT, NET_EVENTS_COUNT, PAUSE_EVENT, RX_QUEUE_EVENT, RX_TAP_EVENT, TX_QUEUE_EVENT,
};
use super::Error as DeviceError;
use super::{
    ActivateError, ActivateResult, Queue, VirtioDevice, VirtioDeviceType, VirtioInterruptType,
};
use crate::VirtioInterrupt;
use anyhow::anyhow;
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
use vm_memory::{ByteValued, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};
use vm_migration::{
    Migratable, MigratableError, Pausable, Snapshot, SnapshotDataSection, Snapshottable,
    Transportable,
};
use vmm_sys_util::eventfd::EventFd;

#[derive(Debug)]
pub enum Error {
    /// Failed to open taps.
    OpenTap(super::net_util::Error),
}

pub type Result<T> = result::Result<T, Error>;

struct NetEpollHandler {
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
    tap: Tap,
    rx: RxVirtio,
    tx: TxVirtio,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    kill_evt: EventFd,
    pause_evt: EventFd,
    epoll_fd: RawFd,
    rx_tap_listening: bool,
}

impl NetEpollHandler {
    fn signal_used_queue(&self, queue: &Queue) -> result::Result<(), DeviceError> {
        self.interrupt_cb
            .trigger(&VirtioInterruptType::Queue, Some(queue))
            .map_err(|e| {
                error!("Failed to signal used queue: {:?}", e);
                DeviceError::FailedSignalingUsedQueue(e)
            })
    }

    // Copies a single frame from `self.rx.frame_buf` into the guest. Returns true
    // if a buffer was used, and false if the frame must be deferred until a buffer
    // is made available by the driver.
    fn rx_single_frame(&mut self, mut queue: &mut Queue) -> bool {
        let mem = self.mem.memory();
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
        let mem = self.mem.memory();

        self.tx.process_desc_chain(&mem, &mut self.tap, &mut queue);
        self.signal_used_queue(queue)
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

        // If there are some already available descriptors on the RX queue,
        // then we can start the thread while listening onto the TAP.
        if queues[0].available_descriptors(&self.mem.memory()).unwrap() {
            epoll::ctl(
                self.epoll_fd,
                epoll::ControlOptions::EPOLL_CTL_ADD,
                self.tap.as_raw_fd(),
                epoll::Event::new(epoll::Events::EPOLLIN, u64::from(RX_TAP_EVENT)),
            )
            .map_err(DeviceError::EpollCtl)?;
            self.rx_tap_listening = true;
        }

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
                        // Drain pause event
                        let _ = self.pause_evt.read();
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

pub struct Net {
    id: String,
    kill_evt: Option<EventFd>,
    pause_evt: Option<EventFd>,
    taps: Option<Vec<Tap>>,
    avail_features: u64,
    acked_features: u64,
    config: VirtioNetConfig,
    queue_evts: Option<Vec<EventFd>>,
    interrupt_cb: Option<Arc<dyn VirtioInterrupt>>,
    epoll_threads: Option<Vec<thread::JoinHandle<result::Result<(), DeviceError>>>>,
    ctrl_queue_epoll_thread: Option<thread::JoinHandle<result::Result<(), DeviceError>>>,
    paused: Arc<AtomicBool>,
    queue_size: Vec<u16>,
}

#[derive(Serialize, Deserialize)]
pub struct NetState {
    pub avail_features: u64,
    pub acked_features: u64,
    pub config: VirtioNetConfig,
    pub queue_size: Vec<u16>,
}

impl Net {
    /// Create a new virtio network device with the given TAP interface.
    pub fn new_with_tap(
        id: String,
        taps: Vec<Tap>,
        guest_mac: Option<MacAddr>,
        iommu: bool,
        num_queues: usize,
        queue_size: u16,
    ) -> Result<Self> {
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

        avail_features |= 1 << VIRTIO_NET_F_CTRL_VQ;
        let queue_num = num_queues + 1;

        let mut config = VirtioNetConfig::default();
        if let Some(mac) = guest_mac {
            build_net_config_space(&mut config, mac, num_queues, &mut avail_features);
        } else {
            build_net_config_space_with_mq(&mut config, num_queues, &mut avail_features);
        }

        Ok(Net {
            id,
            kill_evt: None,
            pause_evt: None,
            taps: Some(taps),
            avail_features,
            acked_features: 0u64,
            config,
            queue_evts: None,
            interrupt_cb: None,
            epoll_threads: None,
            ctrl_queue_epoll_thread: None,
            paused: Arc::new(AtomicBool::new(false)),
            queue_size: vec![queue_size; queue_num],
        })
    }

    /// Create a new virtio network device with the given IP address and
    /// netmask.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        if_name: Option<&str>,
        ip_addr: Option<Ipv4Addr>,
        netmask: Option<Ipv4Addr>,
        guest_mac: Option<MacAddr>,
        host_mac: Option<MacAddr>,
        iommu: bool,
        num_queues: usize,
        queue_size: u16,
    ) -> Result<Self> {
        let taps = open_tap(if_name, ip_addr, netmask, host_mac, num_queues / 2)
            .map_err(Error::OpenTap)?;

        Self::new_with_tap(id, taps, guest_mac, iommu, num_queues, queue_size)
    }

    fn state(&self) -> NetState {
        NetState {
            avail_features: self.avail_features,
            acked_features: self.acked_features,
            config: self.config,
            queue_size: self.queue_size.clone(),
        }
    }

    fn set_state(&mut self, state: &NetState) -> Result<()> {
        self.avail_features = state.avail_features;
        self.acked_features = state.acked_features;
        self.config = state.config;
        self.queue_size = state.queue_size.clone();

        Ok(())
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
        &self.queue_size.as_slice()
    }

    fn features(&self) -> u64 {
        self.avail_features
    }

    fn ack_features(&mut self, value: u64) {
        let mut v = value;
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
        let config_slice = self.config.as_slice();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&config_slice[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let config_slice = self.config.as_mut_slice();
        let data_len = data.len() as u64;
        let config_len = config_slice.len() as u64;
        if offset + data_len > config_len {
            error!("Failed to write config space");
            return;
        }
        let (_, right) = config_slice.split_at_mut(offset as usize);
        right.copy_from_slice(&data[..]);
    }

    fn activate(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        interrupt_cb: Arc<dyn VirtioInterrupt>,
        mut queues: Vec<Queue>,
        mut queue_evts: Vec<EventFd>,
    ) -> ActivateResult {
        if queues.len() != self.queue_size.len() || queue_evts.len() != self.queue_size.len() {
            error!(
                "Cannot perform activate. Expected {} queue(s), got {}",
                self.queue_size.len(),
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

        if let Some(mut taps) = self.taps.clone() {
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

            let queue_num = queues.len();
            if (self.acked_features & 1 << VIRTIO_NET_F_CTRL_VQ) != 0 && queue_num % 2 != 0 {
                let cvq_queue = queues.remove(queue_num - 1);
                let cvq_queue_evt = queue_evts.remove(queue_num - 1);

                let mut ctrl_handler = NetCtrlEpollHandler {
                    mem: mem.clone(),
                    kill_evt: kill_evt.try_clone().unwrap(),
                    pause_evt: pause_evt.try_clone().unwrap(),
                    ctrl_q: CtrlVirtio::new(cvq_queue, cvq_queue_evt),
                    epoll_fd: 0,
                };

                let paused = self.paused.clone();
                thread::Builder::new()
                    .name("virtio_net".to_string())
                    .spawn(move || ctrl_handler.run_ctrl(paused))
                    .map(|thread| self.ctrl_queue_epoll_thread = Some(thread))
                    .map_err(|e| {
                        error!("failed to clone queue EventFd: {}", e);
                        ActivateError::BadActivate
                    })?;
            }

            let mut epoll_threads = Vec::new();
            for _ in 0..taps.len() {
                let rx = RxVirtio::new();
                let tx = TxVirtio::new();
                let rx_tap_listening = false;

                let mut queue_pair = Vec::new();
                queue_pair.push(queues.remove(0));
                queue_pair.push(queues.remove(0));

                let mut queue_evt_pair = Vec::new();
                queue_evt_pair.push(queue_evts.remove(0));
                queue_evt_pair.push(queue_evts.remove(0));

                let mut handler = NetEpollHandler {
                    mem: mem.clone(),
                    tap: taps.remove(0),
                    rx,
                    tx,
                    interrupt_cb: interrupt_cb.clone(),
                    kill_evt: kill_evt.try_clone().unwrap(),
                    pause_evt: pause_evt.try_clone().unwrap(),
                    epoll_fd: 0,
                    rx_tap_listening,
                };

                let paused = self.paused.clone();
                thread::Builder::new()
                    .name("virtio_net".to_string())
                    .spawn(move || handler.run(paused, queue_pair, queue_evt_pair))
                    .map(|thread| epoll_threads.push(thread))
                    .map_err(|e| {
                        error!("failed to clone queue EventFd: {}", e);
                        ActivateError::BadActivate
                    })?;
            }

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

virtio_ctrl_q_pausable!(Net);
impl Snapshottable for Net {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&self) -> std::result::Result<Snapshot, MigratableError> {
        let snapshot =
            serde_json::to_vec(&self.state()).map_err(|e| MigratableError::Snapshot(e.into()))?;

        let mut net_snapshot = Snapshot::new(self.id.as_str());
        net_snapshot.add_data_section(SnapshotDataSection {
            id: format!("{}-section", self.id),
            snapshot,
        });

        Ok(net_snapshot)
    }

    fn restore(&mut self, snapshot: Snapshot) -> std::result::Result<(), MigratableError> {
        if let Some(net_section) = snapshot.snapshot_data.get(&format!("{}-section", self.id)) {
            let net_state = match serde_json::from_slice(&net_section.snapshot) {
                Ok(state) => state,
                Err(error) => {
                    return Err(MigratableError::Restore(anyhow!(
                        "Could not deserialize NET {}",
                        error
                    )))
                }
            };

            return self.set_state(&net_state).map_err(|e| {
                MigratableError::Restore(anyhow!("Could not restore NET state {:?}", e))
            });
        }

        Err(MigratableError::Restore(anyhow!(
            "Could not find NET snapshot section"
        )))
    }
}
impl Transportable for Net {}
impl Migratable for Net {}
