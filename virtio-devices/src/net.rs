// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use super::net_util::{
    build_net_config_space, build_net_config_space_with_mq, CtrlVirtio, NetCtrlEpollHandler,
    VirtioNetConfig,
};
use super::Error as DeviceError;
use super::{
    ActivateError, ActivateResult, EpollHelper, EpollHelperError, EpollHelperHandler, Queue,
    VirtioCommon, VirtioDevice, VirtioDeviceType, VirtioInterruptType, EPOLL_HELPER_EVENT_LAST,
};
use crate::seccomp_filters::{get_seccomp_filter, Thread};
use crate::VirtioInterrupt;
use anyhow::anyhow;
use net_util::{
    open_tap, MacAddr, NetCounters, NetQueuePair, OpenTapError, RxVirtio, Tap, TapError, TxVirtio,
};
use seccomp::{SeccompAction, SeccompFilter};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::num::Wrapping;
use std::os::unix::io::{AsRawFd, RawFd};
use std::result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::vec::Vec;
use virtio_bindings::bindings::virtio_net::*;
use virtio_bindings::bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use vm_memory::{ByteValued, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};
use vm_migration::{
    Migratable, MigratableError, Pausable, Snapshot, SnapshotDataSection, Snapshottable,
    Transportable,
};
use vmm_sys_util::eventfd::EventFd;

// The guest has made a buffer available to receive a frame into.
pub const RX_QUEUE_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;
// The transmit queue has a frame that is ready to send from the guest.
pub const TX_QUEUE_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 2;
// A frame is available for reading from the tap device to receive in the guest.
pub const RX_TAP_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 3;

#[derive(Debug)]
pub enum Error {
    /// Failed to open taps.
    OpenTap(OpenTapError),

    // Using existing tap
    TapError(TapError),
}

pub type Result<T> = result::Result<T, Error>;

struct NetEpollHandler {
    net: NetQueuePair,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    kill_evt: EventFd,
    pause_evt: EventFd,
    queue_pair: Vec<Queue>,
    queue_evt_pair: Vec<EventFd>,
    // Always generate interrupts until the driver has signalled to the device.
    // This mitigates a problem with interrupts from tap events being "lost" upon
    // a restore as the vCPU thread isn't ready to handle the interrupt. This causes
    // issues when combined with VIRTIO_RING_F_EVENT_IDX interrupt suppression.
    driver_awake: bool,
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

    fn handle_rx_event(&mut self) -> result::Result<(), DeviceError> {
        let queue_evt = &self.queue_evt_pair[0];
        if let Err(e) = queue_evt.read() {
            error!("Failed to get rx queue event: {:?}", e);
        }

        if !self.net.rx_tap_listening {
            net_util::register_listener(
                self.net.epoll_fd.unwrap(),
                self.net.tap.as_raw_fd(),
                epoll::Events::EPOLLIN,
                u64::from(self.net.tap_event_id),
            )
            .map_err(DeviceError::IoError)?;
            self.net.rx_tap_listening = true;
        }

        Ok(())
    }

    fn handle_tx_event(&mut self) -> result::Result<(), DeviceError> {
        let queue_evt = &self.queue_evt_pair[1];
        if let Err(e) = queue_evt.read() {
            error!("Failed to get tx queue event: {:?}", e);
        }
        if self
            .net
            .process_tx(&mut self.queue_pair[1])
            .map_err(DeviceError::NetQueuePair)?
            || !self.driver_awake
        {
            self.signal_used_queue(&self.queue_pair[1])?;
            debug!("Signalling TX queue");
        } else {
            debug!("Not signalling TX queue");
        }
        Ok(())
    }

    fn handle_rx_tap_event(&mut self) -> result::Result<(), DeviceError> {
        if self
            .net
            .process_rx(&mut self.queue_pair[0])
            .map_err(DeviceError::NetQueuePair)?
            || !self.driver_awake
        {
            self.signal_used_queue(&self.queue_pair[0])?;
            debug!("Signalling RX queue");
        } else {
            debug!("Not signalling RX queue");
        }
        Ok(())
    }

    fn run(
        &mut self,
        paused: Arc<AtomicBool>,
        paused_sync: Arc<Barrier>,
    ) -> result::Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;
        helper.add_event(self.queue_evt_pair[0].as_raw_fd(), RX_QUEUE_EVENT)?;
        helper.add_event(self.queue_evt_pair[1].as_raw_fd(), TX_QUEUE_EVENT)?;

        // If there are some already available descriptors on the RX queue,
        // then we can start the thread while listening onto the TAP.
        if self.queue_pair[0]
            .available_descriptors(&self.net.mem.as_ref().unwrap().memory())
            .unwrap()
        {
            helper.add_event(self.net.tap.as_raw_fd(), RX_TAP_EVENT)?;
            self.net.rx_tap_listening = true;
            info!("Listener registered at start");
        }

        // The NetQueuePair needs the epoll fd.
        self.net.epoll_fd = Some(helper.as_raw_fd());

        helper.run(paused, paused_sync, self)?;

        Ok(())
    }
}

impl EpollHelperHandler for NetEpollHandler {
    fn handle_event(&mut self, _helper: &mut EpollHelper, event: &epoll::Event) -> bool {
        let ev_type = event.data as u16;
        match ev_type {
            RX_QUEUE_EVENT => {
                self.driver_awake = true;
                if let Err(e) = self.handle_rx_event() {
                    error!("Error processing RX queue: {:?}", e);
                    return true;
                }
            }
            TX_QUEUE_EVENT => {
                self.driver_awake = true;
                if let Err(e) = self.handle_tx_event() {
                    error!("Error processing TX queue: {:?}", e);
                    return true;
                }
            }
            RX_TAP_EVENT => {
                if let Err(e) = self.handle_rx_tap_event() {
                    error!("Error processing tap queue: {:?}", e);
                    return true;
                }
            }
            _ => {
                error!("Unknown event: {}", ev_type);
                return true;
            }
        }
        false
    }
}

pub struct Net {
    common: VirtioCommon,
    id: String,
    taps: Option<Vec<Tap>>,
    config: VirtioNetConfig,
    ctrl_queue_epoll_thread: Option<thread::JoinHandle<()>>,
    counters: NetCounters,
    seccomp_action: SeccompAction,
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
        seccomp_action: SeccompAction,
    ) -> Result<Self> {
        let mut avail_features = 1 << VIRTIO_NET_F_GUEST_CSUM
            | 1 << VIRTIO_NET_F_CSUM
            | 1 << VIRTIO_NET_F_GUEST_TSO4
            | 1 << VIRTIO_NET_F_GUEST_UFO
            | 1 << VIRTIO_NET_F_HOST_TSO4
            | 1 << VIRTIO_NET_F_HOST_UFO
            | 1 << VIRTIO_RING_F_EVENT_IDX
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
            common: VirtioCommon {
                device_type: VirtioDeviceType::TYPE_NET as u32,
                avail_features,
                queue_sizes: vec![queue_size; queue_num],
                paused_sync: Some(Arc::new(Barrier::new((num_queues / 2) + 1))),
                min_queues: 2,
                ..Default::default()
            },
            id,
            taps: Some(taps),
            config,
            ctrl_queue_epoll_thread: None,
            counters: NetCounters::default(),
            seccomp_action,
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
        host_mac: &mut Option<MacAddr>,
        iommu: bool,
        num_queues: usize,
        queue_size: u16,
        seccomp_action: SeccompAction,
    ) -> Result<Self> {
        let taps = open_tap(if_name, ip_addr, netmask, host_mac, num_queues / 2, None)
            .map_err(Error::OpenTap)?;

        Self::new_with_tap(
            id,
            taps,
            guest_mac,
            iommu,
            num_queues,
            queue_size,
            seccomp_action,
        )
    }

    pub fn from_tap_fds(
        id: String,
        fds: &[RawFd],
        guest_mac: Option<MacAddr>,
        iommu: bool,
        queue_size: u16,
        seccomp_action: SeccompAction,
    ) -> Result<Self> {
        let mut taps: Vec<Tap> = Vec::new();
        let num_queue_pairs = fds.len();

        for fd in fds.iter() {
            let tap = Tap::from_tap_fd(*fd, num_queue_pairs).map_err(Error::TapError)?;
            taps.push(tap);
        }

        Self::new_with_tap(
            id,
            taps,
            guest_mac,
            iommu,
            num_queue_pairs * 2,
            queue_size,
            seccomp_action,
        )
    }

    fn state(&self) -> NetState {
        NetState {
            avail_features: self.common.avail_features,
            acked_features: self.common.acked_features,
            config: self.config,
            queue_size: self.common.queue_sizes.clone(),
        }
    }

    fn set_state(&mut self, state: &NetState) {
        self.common.avail_features = state.avail_features;
        self.common.acked_features = state.acked_features;
        self.config = state.config;
        self.common.queue_sizes = state.queue_size.clone();
    }
}

impl Drop for Net {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.common.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
    }
}

impl VirtioDevice for Net {
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
        self.read_config_from_slice(self.config.as_slice(), offset, data);
    }

    fn activate(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        interrupt_cb: Arc<dyn VirtioInterrupt>,
        mut queues: Vec<Queue>,
        mut queue_evts: Vec<EventFd>,
    ) -> ActivateResult {
        if let Some(mut taps) = self.taps.clone() {
            self.common.activate(&queues, &queue_evts, &interrupt_cb)?;

            let queue_num = queues.len();
            if self.common.feature_acked(VIRTIO_NET_F_CTRL_VQ.into()) && queue_num % 2 != 0 {
                let cvq_queue = queues.remove(queue_num - 1);
                let cvq_queue_evt = queue_evts.remove(queue_num - 1);

                let kill_evt = self
                    .common
                    .kill_evt
                    .as_ref()
                    .unwrap()
                    .try_clone()
                    .map_err(|e| {
                        error!("failed to clone kill_evt eventfd: {}", e);
                        ActivateError::BadActivate
                    })?;
                let pause_evt = self
                    .common
                    .pause_evt
                    .as_ref()
                    .unwrap()
                    .try_clone()
                    .map_err(|e| {
                        error!("failed to clone pause_evt eventfd: {}", e);
                        ActivateError::BadActivate
                    })?;

                let mut ctrl_handler = NetCtrlEpollHandler {
                    mem: mem.clone(),
                    kill_evt,
                    pause_evt,
                    ctrl_q: CtrlVirtio::new(cvq_queue, cvq_queue_evt),
                    epoll_fd: 0,
                };

                let paused = self.common.paused.clone();
                // Let's update the barrier as we need 1 for each RX/TX pair +
                // 1 for the control queue + 1 for the main thread signalling
                // the pause.
                self.common.paused_sync = Some(Arc::new(Barrier::new(taps.len() + 2)));
                let paused_sync = self.common.paused_sync.clone();

                // Retrieve seccomp filter for virtio_net_ctl thread
                let virtio_net_ctl_seccomp_filter =
                    get_seccomp_filter(&self.seccomp_action, Thread::VirtioNetCtl)
                        .map_err(ActivateError::CreateSeccompFilter)?;
                thread::Builder::new()
                    .name(format!("{}_ctrl", self.id))
                    .spawn(move || {
                        if let Err(e) = SeccompFilter::apply(virtio_net_ctl_seccomp_filter) {
                            error!("Error applying seccomp filter: {:?}", e);
                        } else if let Err(e) = ctrl_handler.run_ctrl(paused, paused_sync.unwrap()) {
                            error!("Error running worker: {:?}", e);
                        }
                    })
                    .map(|thread| self.ctrl_queue_epoll_thread = Some(thread))
                    .map_err(|e| {
                        error!("failed to clone queue EventFd: {}", e);
                        ActivateError::BadActivate
                    })?;
            }

            let event_idx = self.common.feature_acked(VIRTIO_RING_F_EVENT_IDX.into());

            let mut epoll_threads = Vec::new();
            for i in 0..taps.len() {
                let rx = RxVirtio::new();
                let tx = TxVirtio::new();
                let rx_tap_listening = false;

                let mut queue_pair = Vec::new();
                queue_pair.push(queues.remove(0));
                queue_pair.push(queues.remove(0));
                queue_pair[0].set_event_idx(event_idx);
                queue_pair[1].set_event_idx(event_idx);

                let mut queue_evt_pair = Vec::new();
                queue_evt_pair.push(queue_evts.remove(0));
                queue_evt_pair.push(queue_evts.remove(0));

                let kill_evt = self
                    .common
                    .kill_evt
                    .as_ref()
                    .unwrap()
                    .try_clone()
                    .map_err(|e| {
                        error!("failed to clone kill_evt eventfd: {}", e);
                        ActivateError::BadActivate
                    })?;
                let pause_evt = self
                    .common
                    .pause_evt
                    .as_ref()
                    .unwrap()
                    .try_clone()
                    .map_err(|e| {
                        error!("failed to clone pause_evt eventfd: {}", e);
                        ActivateError::BadActivate
                    })?;

                let mut handler = NetEpollHandler {
                    net: NetQueuePair {
                        mem: Some(mem.clone()),
                        tap: taps.remove(0),
                        rx,
                        tx,
                        epoll_fd: None,
                        rx_tap_listening,
                        counters: self.counters.clone(),
                        tap_event_id: RX_TAP_EVENT,
                    },
                    queue_pair,
                    queue_evt_pair,
                    interrupt_cb: interrupt_cb.clone(),
                    kill_evt,
                    pause_evt,
                    driver_awake: false,
                };

                let paused = self.common.paused.clone();
                let paused_sync = self.common.paused_sync.clone();
                // Retrieve seccomp filter for virtio_net thread
                let virtio_net_seccomp_filter =
                    get_seccomp_filter(&self.seccomp_action, Thread::VirtioNet)
                        .map_err(ActivateError::CreateSeccompFilter)?;
                thread::Builder::new()
                    .name(format!("{}_qp{}", self.id.clone(), i))
                    .spawn(move || {
                        if let Err(e) = SeccompFilter::apply(virtio_net_seccomp_filter) {
                            error!("Error applying seccomp filter: {:?}", e);
                        } else if let Err(e) = handler.run(paused, paused_sync.unwrap()) {
                            error!("Error running worker: {:?}", e);
                        }
                    })
                    .map(|thread| epoll_threads.push(thread))
                    .map_err(|e| {
                        error!("failed to clone queue EventFd: {}", e);
                        ActivateError::BadActivate
                    })?;
            }

            self.common.epoll_threads = Some(epoll_threads);

            event!("virtio-device", "activated", "id", &self.id);
            return Ok(());
        }
        Err(ActivateError::BadActivate)
    }

    fn reset(&mut self) -> Option<Arc<dyn VirtioInterrupt>> {
        let result = self.common.reset();
        event!("virtio-device", "reset", "id", &self.id);
        result
    }

    fn counters(&self) -> Option<HashMap<&'static str, Wrapping<u64>>> {
        let mut counters = HashMap::new();

        counters.insert(
            "rx_bytes",
            Wrapping(self.counters.rx_bytes.load(Ordering::Acquire)),
        );
        counters.insert(
            "rx_frames",
            Wrapping(self.counters.rx_frames.load(Ordering::Acquire)),
        );
        counters.insert(
            "tx_bytes",
            Wrapping(self.counters.tx_bytes.load(Ordering::Acquire)),
        );
        counters.insert(
            "tx_frames",
            Wrapping(self.counters.tx_frames.load(Ordering::Acquire)),
        );

        Some(counters)
    }
}

impl Pausable for Net {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        self.common.pause()
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        self.common.resume()?;

        if let Some(ctrl_queue_epoll_thread) = &self.ctrl_queue_epoll_thread {
            ctrl_queue_epoll_thread.thread().unpark();
        }
        Ok(())
    }
}

impl Snapshottable for Net {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
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

            self.set_state(&net_state);
            return Ok(());
        }

        Err(MigratableError::Restore(anyhow!(
            "Could not find NET snapshot section"
        )))
    }
}
impl Transportable for Net {}
impl Migratable for Net {}
