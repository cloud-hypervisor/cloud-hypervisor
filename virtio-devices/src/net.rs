// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::HashMap;
use std::io::{self, Write};
use std::net::IpAddr;
use std::num::Wrapping;
use std::ops::Deref;
use std::os::unix::io::{AsRawFd, RawFd};
use std::result;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::time::Duration;

use anyhow::{Context, anyhow};
use event_monitor::event;
use log::{debug, error, info, warn};
#[cfg(not(fuzzing))]
use net_util::virtio_features_to_tap_offload;
use net_util::{
    CtrlQueue, MAC_ADDR_LEN, MacAddr, NetCounters, NetQueuePair, OpenTapError, RxVirtio, Tap,
    TapError, TxVirtio, VirtioNetConfig, build_net_config_space, build_net_config_space_with_mq,
    open_tap, vnet_hdr_len,
};
use seccompiler::SeccompAction;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use virtio_bindings::virtio_config::*;
use virtio_bindings::virtio_net::*;
use virtio_bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use virtio_queue::{Queue, QueueT};
use vm_memory::{ByteValued, GuestAddressSpace, GuestMemoryAtomic};
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
use vm_virtio::AccessPlatform;
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::timerfd::TimerFd;

use super::{
    ActivateError, ActivateResult, EPOLL_HELPER_EVENT_LAST, EpollHelper, EpollHelperError,
    EpollHelperHandler, Error as DeviceError, RateLimiterConfig, VirtioCommon, VirtioDevice,
    VirtioDeviceType, VirtioInterruptType,
};
use crate::device::ActivationContext;
use crate::seccomp_filters::Thread;
use crate::{GuestMemoryMmap, VirtioInterrupt};

/// Control queue
// Event available on the control queue.
const CTRL_QUEUE_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;
// Start post-migration or post-restore announcements.
const START_ANNOUNCEMENTS_EVENT: u16 = CTRL_QUEUE_EVENT + 1;
// Retry post-migration or post-restore announcements.
const RETRY_ANNOUNCEMENTS_EVENT: u16 = START_ANNOUNCEMENTS_EVENT + 1;

// Following the VIRTIO specification, the MTU should be at least 1280.
pub const MIN_MTU: u16 = 1280;

pub struct NetCtrlEpollHandler {
    pub mem: GuestMemoryAtomic<GuestMemoryMmap>,
    pub kill_evt: EventFd,
    pub pause_evt: EventFd,
    pub ctrl_q: CtrlQueue,
    pub queue_evt: EventFd,
    pub queue: Queue,
    pub access_platform: Option<Arc<dyn AccessPlatform>>,
    pub interrupt_cb: Arc<dyn VirtioInterrupt>,
    pub queue_index: u16,
    pub announce_evt: EventFd,
    pub announce_retry_timer: TimerFd,
    pub announcer: Announcer,
}

impl NetCtrlEpollHandler {
    fn signal_used_queue(&self, queue_index: u16) -> result::Result<(), DeviceError> {
        self.interrupt_cb
            .trigger(VirtioInterruptType::Queue(queue_index))
            .map_err(|e| {
                error!("Failed to signal used queue: {e:?}");
                DeviceError::FailedSignalingUsedQueue(e)
            })
    }

    pub fn run_ctrl(
        &mut self,
        paused: &AtomicBool,
        paused_sync: &Barrier,
    ) -> result::Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;
        helper.add_event(self.queue_evt.as_raw_fd(), CTRL_QUEUE_EVENT)?;
        helper.add_event(self.announce_evt.as_raw_fd(), START_ANNOUNCEMENTS_EVENT)?;
        helper.add_event(
            self.announce_retry_timer.as_raw_fd(),
            RETRY_ANNOUNCEMENTS_EVENT,
        )?;
        helper.run(paused, paused_sync, self)?;

        Ok(())
    }

    const ANNOUNCE_RETRY_INTERVAL: Duration = Duration::from_millis(200);

    fn arm_retry_timer(&mut self) -> result::Result<(), EpollHelperError> {
        self.announce_retry_timer
            .reset(
                Self::ANNOUNCE_RETRY_INTERVAL,
                Some(Self::ANNOUNCE_RETRY_INTERVAL),
            )
            .context("Failed to arm announcement retry timer")
            .map_err(EpollHelperError::HandleEvent)
    }

    fn disarm_retry_timer(&mut self) -> result::Result<(), EpollHelperError> {
        self.announce_retry_timer
            .clear()
            .context("Failed to disarm announcement retry timer")
            .map_err(EpollHelperError::HandleEvent)
    }
}

impl EpollHelperHandler for NetCtrlEpollHandler {
    fn handle_event(
        &mut self,
        _helper: &mut EpollHelper,
        event: &epoll::Event,
    ) -> result::Result<(), EpollHelperError> {
        let ev_type = event.data as u16;
        match ev_type {
            CTRL_QUEUE_EVENT => {
                let mem = self.mem.memory();
                self.queue_evt.read().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!(
                        "Failed to get control queue event: {e:?}"
                    ))
                })?;
                self.ctrl_q
                    .process(
                        mem.deref(),
                        &mut self.queue,
                        self.access_platform.as_deref(),
                    )
                    .map_err(|e| {
                        EpollHelperError::HandleEvent(anyhow!(
                            "Failed to process control queue: {e:?}"
                        ))
                    })?;
                match self.queue.needs_notification(mem.deref()) {
                    Ok(true) => {
                        self.signal_used_queue(self.queue_index).map_err(|e| {
                            EpollHelperError::HandleEvent(anyhow!(
                                "Error signalling that control queue was used: {e:?}"
                            ))
                        })?;
                    }
                    Ok(false) => {}
                    Err(e) => {
                        return Err(EpollHelperError::HandleEvent(anyhow!(
                            "Error getting notification state of control queue: {e}"
                        )));
                    }
                }
            }
            START_ANNOUNCEMENTS_EVENT => {
                self.announce_evt.read().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!(
                        "Failed to get start announcements event: {e:?}"
                    ))
                })?;

                self.announcer.initialize();
                match self.announcer.send_announce() {
                    AnnounceOutcome::Done => self.disarm_retry_timer()?,
                    AnnounceOutcome::Retry => self.arm_retry_timer()?,
                }
            }
            RETRY_ANNOUNCEMENTS_EVENT => {
                self.announce_retry_timer.wait().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!(
                        "Failed to get retry announcements event: {e:?}"
                    ))
                })?;

                match self.announcer.send_announce() {
                    AnnounceOutcome::Done => self.disarm_retry_timer()?,
                    AnnounceOutcome::Retry => {}
                }
            }
            _ => {
                return Err(EpollHelperError::HandleEvent(anyhow!(
                    "Unknown event for virtio-net control queue"
                )));
            }
        }

        Ok(())
    }
}

/// Rx/Tx queue pair
// The guest has made a buffer available to receive a frame into.
pub const RX_QUEUE_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;
// The transmit queue has a frame that is ready to send from the guest.
pub const TX_QUEUE_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 2;
// A frame is available for reading from the tap device to receive in the guest.
pub const RX_TAP_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 3;
// The TAP can be written to. Used after an EAGAIN error to retry TX.
pub const TX_TAP_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 4;
// New 'wake up' event from the rx rate limiter
pub const RX_RATE_LIMITER_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 5;
// New 'wake up' event from the tx rate limiter
pub const TX_RATE_LIMITER_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 6;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to open taps")]
    OpenTap(#[source] OpenTapError),
    #[error("Using existing tap")]
    TapError(#[source] TapError),
    #[error("Error calling dup() on tap fd")]
    DuplicateTapFd(#[source] io::Error),
    #[error("Error creating EventFd")]
    CreateEventFd(#[source] io::Error),
    #[error("Error cloning EventFd")]
    CloneEventFd(#[source] io::Error),
}

pub type Result<T> = result::Result<T, Error>;

struct NetEpollHandler {
    net: NetQueuePair,
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    kill_evt: EventFd,
    pause_evt: EventFd,
    queue_index_base: u16,
    queue_pair: (Queue, Queue),
    queue_evt_pair: (EventFd, EventFd),
}

impl NetEpollHandler {
    fn signal_used_queue(&self, queue_index: u16) -> result::Result<(), DeviceError> {
        self.interrupt_cb
            .trigger(VirtioInterruptType::Queue(queue_index))
            .map_err(|e| {
                error!("Failed to signal used queue: {e:?}");
                DeviceError::FailedSignalingUsedQueue(e)
            })
    }

    fn handle_rx_event(&mut self) -> result::Result<(), DeviceError> {
        let queue_evt = &self.queue_evt_pair.0;
        if let Err(e) = queue_evt.read() {
            error!("Failed to get rx queue event: {e:?}");
        }

        self.net.rx_desc_avail = true;

        let rate_limit_reached = self
            .net
            .rx_rate_limiter
            .as_ref()
            .is_some_and(|r| r.is_blocked());

        // Start to listen on RX_TAP_EVENT only when the rate limit is not reached
        if !self.net.rx_tap_listening && !rate_limit_reached {
            net_util::register_listener(
                self.net.epoll_fd.unwrap(),
                self.net.tap.as_raw_fd(),
                epoll::Events::EPOLLIN,
                u64::from(self.net.tap_rx_event_id),
            )
            .map_err(DeviceError::IoError)?;
            self.net.rx_tap_listening = true;
        }

        Ok(())
    }

    fn process_tx(&mut self) -> result::Result<(), DeviceError> {
        let res = self
            .net
            .process_tx(&self.mem.memory(), &mut self.queue_pair.1)
            .map_err(DeviceError::NetQueuePair)?;

        if res {
            self.signal_used_queue(self.queue_index_base + 1)?;
            debug!("Signalling TX queue");
        } else {
            debug!("Not signalling TX queue");
        }
        Ok(())
    }

    fn handle_tx_event(&mut self) -> result::Result<(), DeviceError> {
        let rate_limit_reached = self
            .net
            .tx_rate_limiter
            .as_ref()
            .is_some_and(|r| r.is_blocked());

        if !rate_limit_reached {
            self.process_tx()?;
        }

        Ok(())
    }

    fn handle_rx_tap_event(&mut self) -> result::Result<(), DeviceError> {
        let res = self
            .net
            .process_rx(&self.mem.memory(), &mut self.queue_pair.0)
            .map_err(DeviceError::NetQueuePair)?;

        if res {
            self.signal_used_queue(self.queue_index_base)?;
            debug!("Signalling RX queue");
        } else {
            debug!("Not signalling RX queue");
        }
        Ok(())
    }

    fn run(
        &mut self,
        paused: &AtomicBool,
        paused_sync: &Barrier,
    ) -> result::Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;
        helper.add_event(self.queue_evt_pair.0.as_raw_fd(), RX_QUEUE_EVENT)?;
        helper.add_event(self.queue_evt_pair.1.as_raw_fd(), TX_QUEUE_EVENT)?;
        if let Some(rate_limiter) = &self.net.rx_rate_limiter {
            helper.add_event(rate_limiter.as_raw_fd(), RX_RATE_LIMITER_EVENT)?;
        }
        if let Some(rate_limiter) = &self.net.tx_rate_limiter {
            helper.add_event(rate_limiter.as_raw_fd(), TX_RATE_LIMITER_EVENT)?;
        }

        let mem = self.mem.memory();
        // If there are some already available descriptors on the RX queue,
        // then we can start the thread while listening onto the TAP.
        if self
            .queue_pair
            .0
            .used_idx(mem.deref(), Ordering::Acquire)
            .map_err(EpollHelperError::QueueRingIndex)?
            < self
                .queue_pair
                .0
                .avail_idx(mem.deref(), Ordering::Acquire)
                .map_err(EpollHelperError::QueueRingIndex)?
        {
            helper.add_event(self.net.tap.as_raw_fd(), RX_TAP_EVENT)?;
            self.net.rx_tap_listening = true;
            debug!("Listener registered at start");
        }

        // The NetQueuePair needs the epoll fd.
        self.net.epoll_fd = Some(helper.as_raw_fd());

        helper.run(paused, paused_sync, self)?;

        Ok(())
    }
}

impl EpollHelperHandler for NetEpollHandler {
    fn handle_event(
        &mut self,
        _helper: &mut EpollHelper,
        event: &epoll::Event,
    ) -> result::Result<(), EpollHelperError> {
        let ev_type = event.data as u16;
        match ev_type {
            RX_QUEUE_EVENT => {
                self.handle_rx_event().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!("Error processing RX queue: {e:?}"))
                })?;
            }
            TX_QUEUE_EVENT => {
                let queue_evt = &self.queue_evt_pair.1;
                if let Err(e) = queue_evt.read() {
                    error!("Failed to get tx queue event: {e:?}");
                }
                self.handle_tx_event().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!("Error processing TX queue: {e:?}"))
                })?;
            }
            TX_TAP_EVENT => {
                self.handle_tx_event().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!(
                        "Error processing TX queue (TAP event): {e:?}"
                    ))
                })?;
            }
            RX_TAP_EVENT => {
                self.handle_rx_tap_event().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!("Error processing tap queue: {e:?}"))
                })?;
            }
            RX_RATE_LIMITER_EVENT => {
                if let Some(rate_limiter) = &mut self.net.rx_rate_limiter {
                    // Upon rate limiter event, call the rate limiter handler and register the
                    // TAP fd for further processing if some RX buffers are available
                    rate_limiter.event_handler().map_err(|e| {
                        EpollHelperError::HandleEvent(anyhow!(
                            "Error from 'rate_limiter.event_handler()': {e:?}"
                        ))
                    })?;

                    if !self.net.rx_tap_listening && self.net.rx_desc_avail {
                        net_util::register_listener(
                            self.net.epoll_fd.unwrap(),
                            self.net.tap.as_raw_fd(),
                            epoll::Events::EPOLLIN,
                            u64::from(self.net.tap_rx_event_id),
                        )
                        .map_err(|e| {
                            EpollHelperError::HandleEvent(anyhow!(
                                "Error register_listener with `RX_RATE_LIMITER_EVENT`: {e:?}"
                            ))
                        })?;

                        self.net.rx_tap_listening = true;
                    }
                } else {
                    return Err(EpollHelperError::HandleEvent(anyhow!(
                        "Unexpected RX_RATE_LIMITER_EVENT"
                    )));
                }
            }
            TX_RATE_LIMITER_EVENT => {
                if let Some(rate_limiter) = &mut self.net.tx_rate_limiter {
                    // Upon rate limiter event, call the rate limiter handler
                    // and restart processing the queue.
                    rate_limiter.event_handler().map_err(|e| {
                        EpollHelperError::HandleEvent(anyhow!(
                            "Error from 'rate_limiter.event_handler()': {e:?}"
                        ))
                    })?;
                    self.process_tx().map_err(|e| {
                        EpollHelperError::HandleEvent(anyhow!("Error processing TX queue: {e:?}"))
                    })?;
                } else {
                    return Err(EpollHelperError::HandleEvent(anyhow!(
                        "Unexpected TX_RATE_LIMITER_EVENT"
                    )));
                }
            }
            _ => {
                return Err(EpollHelperError::HandleEvent(anyhow!(
                    "Unexpected event: {ev_type}"
                )));
            }
        }
        Ok(())
    }
}

// Minimum length of an ethernet frame. This size omits the FCS/CRC (frame check
// sequence), which will be added by the hardware.
const ETH_FRAME_LEN: usize = 60;

/// Shared announcement bookkeeping for virtio-net backends.
pub struct AnnouncementState {
    pub(crate) pending: Arc<AtomicBool>,
    /// Generation counter used to invalidate active announcers before a
    /// reset or device teardown, so they stop sending notifications.
    pub(crate) generation: Arc<AtomicU64>,
    /// When signaled, the epoll thread will do the announcements.
    pub(crate) evt: EventFd,
}

impl AnnouncementState {
    pub fn new(pending: bool) -> io::Result<Self> {
        Ok(Self {
            pending: Arc::new(AtomicBool::new(pending)),
            generation: Arc::new(AtomicU64::new(0)),
            evt: EventFd::new(libc::EFD_NONBLOCK)?,
        })
    }

    pub fn invalidate(&self) {
        self.generation.fetch_add(1, Ordering::Release);
    }

    pub fn reset(&self) {
        self.generation.fetch_add(1, Ordering::Release);
        self.pending.store(false, Ordering::Release);
    }

    pub fn notify(&self, enabled: bool) {
        if enabled && self.pending.load(Ordering::Acquire) {
            self.generation.fetch_add(1, Ordering::Release);
            self.evt
                .write(1)
                .inspect_err(|e| warn!("Could not write to announce EventFd: {e:?}"))
                .ok();
        }
    }
}

pub struct Net {
    common: VirtioCommon,
    id: String,
    taps: Vec<Tap>,
    config: VirtioNetConfig,
    counters: NetCounters,
    seccomp_action: SeccompAction,
    rate_limiter_config: Option<RateLimiterConfig>,
    exit_evt: EventFd,
    device_status: Arc<AtomicU8>,
    announce: AnnouncementState,
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
    #[expect(clippy::too_many_arguments)]
    pub fn new_with_tap(
        id: String,
        taps: Vec<Tap>,
        guest_mac: Option<MacAddr>,
        access_platform_enabled: bool,
        num_queues: usize,
        queue_size: u16,
        seccomp_action: SeccompAction,
        rate_limiter_config: Option<RateLimiterConfig>,
        exit_evt: EventFd,
        state: Option<NetState>,
        offload_tso: bool,
        offload_ufo: bool,
        offload_csum: bool,
    ) -> Result<Self> {
        assert!(!taps.is_empty());

        // Skip advertising VIRTIO_NET_F_MTU and let the guest fall back to the Ethernet default if querying failed
        let mtu = match taps[0].mtu() {
            Ok(m) => Some(m as u16),
            Err(e) => {
                warn!("Failed to query tap MTU; not advertising VIRTIO_NET_F_MTU: {e}");
                None
            }
        };

        let (avail_features, acked_features, config, queue_sizes, paused, announce_pending) =
            if let Some(state) = state {
                info!("Restoring virtio-net {id}");
                // Always mark the announcement pending if the device was restored
                // so the device announces itself.
                (
                    state.avail_features,
                    state.acked_features,
                    state.config,
                    state.queue_size,
                    true,
                    true,
                )
            } else {
                let mut avail_features = (1 << VIRTIO_RING_F_EVENT_IDX) | (1 << VIRTIO_F_VERSION_1);

                if mtu.is_some() {
                    avail_features |= 1 << VIRTIO_NET_F_MTU;
                }

                if access_platform_enabled {
                    avail_features |= 1u64 << VIRTIO_F_ACCESS_PLATFORM;
                }

                // Configure TSO/UFO features when hardware checksum offload is enabled.
                if offload_csum {
                    avail_features |= (1 << VIRTIO_NET_F_CSUM)
                        | (1 << VIRTIO_NET_F_GUEST_CSUM)
                        | (1 << VIRTIO_NET_F_CTRL_GUEST_OFFLOADS);

                    if offload_tso {
                        avail_features |= (1 << VIRTIO_NET_F_HOST_ECN)
                            | (1 << VIRTIO_NET_F_HOST_TSO4)
                            | (1 << VIRTIO_NET_F_HOST_TSO6)
                            | (1 << VIRTIO_NET_F_GUEST_ECN)
                            | (1 << VIRTIO_NET_F_GUEST_TSO4)
                            | (1 << VIRTIO_NET_F_GUEST_TSO6);
                    }

                    if offload_ufo {
                        avail_features |=
                            (1 << VIRTIO_NET_F_HOST_UFO) | (1 << VIRTIO_NET_F_GUEST_UFO);
                    }
                }

                avail_features |= 1 << VIRTIO_NET_F_CTRL_VQ;
                avail_features |= 1 << VIRTIO_NET_F_STATUS;
                avail_features |= 1 << VIRTIO_NET_F_GUEST_ANNOUNCE;
                let queue_num = num_queues + 1;

                let mut config = VirtioNetConfig::default();
                if let Some(mac) = guest_mac {
                    build_net_config_space(&mut config, mac, num_queues, mtu, &mut avail_features);
                } else {
                    build_net_config_space_with_mq(
                        &mut config,
                        num_queues,
                        mtu,
                        &mut avail_features,
                    );
                }

                (
                    avail_features,
                    0,
                    config,
                    vec![queue_size; queue_num],
                    false,
                    false,
                )
            };

        Ok(Net {
            common: VirtioCommon {
                device_type: VirtioDeviceType::Net as u32,
                avail_features,
                acked_features,
                queue_sizes,
                paused_sync: Some(Arc::new(Barrier::new((num_queues / 2) + 1))),
                min_queues: 2,
                paused: Arc::new(AtomicBool::new(paused)),
                ..Default::default()
            },
            id,
            taps,
            config,
            counters: NetCounters::default(),
            seccomp_action,
            rate_limiter_config,
            exit_evt,
            device_status: Arc::new(AtomicU8::new(0)),
            announce: AnnouncementState::new(announce_pending).map_err(Error::CreateEventFd)?,
        })
    }

    /// Create a new virtio network device with the given IP address and
    /// netmask.
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        if_name: Option<&str>,
        ip_addr: Option<IpAddr>,
        netmask: Option<IpAddr>,
        guest_mac: Option<MacAddr>,
        host_mac: &mut Option<MacAddr>,
        mtu: Option<u16>,
        access_platform_enabled: bool,
        num_queues: usize,
        queue_size: u16,
        seccomp_action: SeccompAction,
        rate_limiter_config: Option<RateLimiterConfig>,
        exit_evt: EventFd,
        state: Option<NetState>,
        offload_tso: bool,
        offload_ufo: bool,
        offload_csum: bool,
    ) -> Result<Self> {
        let taps = open_tap(
            if_name,
            ip_addr,
            netmask,
            host_mac,
            mtu,
            num_queues / 2,
            None,
        )
        .map_err(Error::OpenTap)?;

        Self::new_with_tap(
            id,
            taps,
            guest_mac,
            access_platform_enabled,
            num_queues,
            queue_size,
            seccomp_action,
            rate_limiter_config,
            exit_evt,
            state,
            offload_tso,
            offload_ufo,
            offload_csum,
        )
    }

    #[expect(clippy::too_many_arguments)]
    pub fn from_tap_fds(
        id: String,
        fds: &[RawFd],
        guest_mac: Option<MacAddr>,
        mtu: Option<u16>,
        access_platform_enabled: bool,
        queue_size: u16,
        seccomp_action: SeccompAction,
        rate_limiter_config: Option<RateLimiterConfig>,
        exit_evt: EventFd,
        state: Option<NetState>,
        offload_tso: bool,
        offload_ufo: bool,
        offload_csum: bool,
    ) -> Result<Self> {
        let mut taps: Vec<Tap> = Vec::new();
        let num_queue_pairs = fds.len();

        for fd in fds.iter() {
            // Duplicate so that it can survive reboots
            // SAFETY: FFI call to dup. Trivially safe.
            let fd = unsafe { libc::dup(*fd) };
            if fd < 0 {
                return Err(Error::DuplicateTapFd(io::Error::last_os_error()));
            }
            let tap = Tap::from_tap_fd(fd, num_queue_pairs).map_err(Error::TapError)?;
            taps.push(tap);
        }

        assert!(!taps.is_empty());

        if let Some(mtu) = mtu {
            taps[0].set_mtu(mtu as i32).map_err(Error::TapError)?;
        }

        Self::new_with_tap(
            id,
            taps,
            guest_mac,
            access_platform_enabled,
            num_queue_pairs * 2,
            queue_size,
            seccomp_action,
            rate_limiter_config,
            exit_evt,
            state,
            offload_tso,
            offload_ufo,
            offload_csum,
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

    /// Compute the guest-visible virtio-net status field.
    fn guest_visible_status(&self) -> u16 {
        let mut status = 0;

        if self.common.feature_acked(VIRTIO_NET_F_STATUS.into()) {
            status |= VIRTIO_NET_S_LINK_UP as u16;

            if self
                .common
                .feature_acked(VIRTIO_NET_F_GUEST_ANNOUNCE.into())
                && self.announce.pending.load(Ordering::Acquire)
            {
                status |= VIRTIO_NET_S_ANNOUNCE as u16;
            }
        }

        status
    }

    // Builds a reverse ARP packet with this device's MAC address. Without a
    // negotiated VIRTIO_NET_F_MAC feature, valid construction paths may leave
    // config.mac as zeros, which must not be announced on the host network.
    fn build_rarp_announce(&self) -> Option<[u8; ETH_FRAME_LEN]> {
        if !self.common.feature_acked(VIRTIO_NET_F_MAC.into()) {
            return None;
        }

        const ETH_P_RARP: u16 = 0x8035; // Ethertype RARP
        const ARP_HTYPE_ETH: u16 = 0x1; // Hardware type Ethernet
        const ARP_PTYPE_IP: u16 = 0x0800; // Protocol type IPv4
        const ARP_OP_REQUEST_REV: u16 = 0x0003; // RARP Request opcode

        const IPV4_ADDR_LENGTH: usize = 4; // Size of an IPv4 address

        let mut buf = [0u8; ETH_FRAME_LEN];

        // Ethernet header
        buf[0..6].copy_from_slice(&[0xff; MAC_ADDR_LEN]); // This is a broadcast
        buf[6..12].copy_from_slice(&self.config.mac); // Src is this NIC
        buf[12..14].copy_from_slice(&ETH_P_RARP.to_be_bytes()); // This is a RARP packet

        // ARP Header
        buf[14..16].copy_from_slice(&ARP_HTYPE_ETH.to_be_bytes());
        buf[16..18].copy_from_slice(&ARP_PTYPE_IP.to_be_bytes());
        buf[18] = MAC_ADDR_LEN as u8; // Hardware address length (ethernet)
        buf[19] = IPV4_ADDR_LENGTH as u8; // Protocol address length (IPv4)
        // This is a "fake RARP" packet, we don't want to perform a real RARP lookup.
        // Thus the content of the next fields is largely irrelevant. Setting source
        // hardware address = target hardware address is fine according to RFC 903.
        buf[20..22].copy_from_slice(&ARP_OP_REQUEST_REV.to_be_bytes());
        buf[22..28].copy_from_slice(&self.config.mac); // Source hardware address
        buf[28..32].copy_from_slice(&[0x00; IPV4_ADDR_LENGTH]); // Source protocol address
        buf[32..38].copy_from_slice(&self.config.mac); // Target hardware address
        buf[38..42].copy_from_slice(&[0x00; IPV4_ADDR_LENGTH]); // Target protocol address

        Some(buf)
    }

    #[cfg(fuzzing)]
    pub fn wait_for_epoll_threads(&mut self) {
        self.common.wait_for_epoll_threads();
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
        self.common.ack_features(value);
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let mut config = self.config;
        config.status = self.guest_visible_status();
        self.read_config_from_slice(config.as_slice(), offset, data);
    }

    fn activate(&mut self, context: ActivationContext) -> ActivateResult {
        let ActivationContext {
            mem,
            interrupt_cb,
            mut queues,
            device_status,
        } = context;
        self.device_status = device_status;
        self.common.activate(&queues, interrupt_cb.clone())?;

        let num_queues = queues.len();
        let event_idx = self.common.feature_acked(VIRTIO_RING_F_EVENT_IDX.into());

        // Recompute the barrier size from the queues that are actually activated.
        let has_ctrl_queue =
            self.common.feature_acked(VIRTIO_NET_F_CTRL_VQ.into()) && !num_queues.is_multiple_of(2);
        let ctrl_threads = if has_ctrl_queue { 1 } else { 0 };
        let qp_threads = (num_queues - ctrl_threads) / 2;
        self.common.paused_sync = Some(Arc::new(Barrier::new(1 + qp_threads + ctrl_threads)));

        if has_ctrl_queue {
            let ctrl_queue_index = num_queues - 1;
            let (_, mut ctrl_queue, ctrl_queue_evt) = queues.remove(ctrl_queue_index);

            ctrl_queue.set_event_idx(event_idx);

            let (kill_evt, pause_evt) = self.common.dup_eventfds()?;

            let guest_announce_ops = VirtioNetGuestAnnounceOps::new(
                interrupt_cb.clone(),
                self.common
                    .feature_acked(VIRTIO_NET_F_GUEST_ANNOUNCE.into()),
                &self.announce,
            );

            let host_announce_ops = VirtioNetHostAnnounceOps::new(
                self.build_rarp_announce(),
                self.taps.clone().into_boxed_slice(),
            );

            let announcer = Announcer::new(
                &self.announce,
                vec![
                    Box::new(guest_announce_ops) as Box<dyn AnnounceOps>,
                    Box::new(host_announce_ops) as Box<dyn AnnounceOps>,
                ]
                .into_boxed_slice(),
            );

            let mut ctrl_handler = NetCtrlEpollHandler {
                mem: mem.clone(),
                kill_evt,
                pause_evt,
                ctrl_q: CtrlQueue::new(self.taps.clone(), self.announce.pending.clone()),
                queue: ctrl_queue,
                queue_evt: ctrl_queue_evt,
                access_platform: self.common.access_platform(),
                queue_index: ctrl_queue_index as u16,
                interrupt_cb: interrupt_cb.clone(),
                announce_evt: self
                    .announce
                    .evt
                    .try_clone()
                    .map_err(ActivateError::CloneEventFd)?,
                announce_retry_timer: TimerFd::new().map_err(ActivateError::CreateTimerFd)?,
                announcer,
            };

            let paused = self.common.paused.clone();
            let paused_sync = self.common.paused_sync.clone();

            self.common.spawn_worker(
                &format!("{}_ctrl", self.id),
                &self.seccomp_action,
                Thread::VirtioNetCtl,
                &self.exit_evt,
                self.device_status.clone(),
                interrupt_cb.clone(),
                move || ctrl_handler.run_ctrl(&paused, paused_sync.as_ref().unwrap()),
            )?;
        }

        let mut taps = self.taps.clone();
        for i in 0..queues.len() / 2 {
            let rx = RxVirtio::new();
            let tx = TxVirtio::new();
            let rx_tap_listening = false;

            let (_, queue_0, queue_evt_0) = queues.remove(0);
            let (_, queue_1, queue_evt_1) = queues.remove(0);
            let mut queue_pair = (queue_0, queue_1);
            queue_pair.0.set_event_idx(event_idx);
            queue_pair.1.set_event_idx(event_idx);

            let queue_evt_pair = (queue_evt_0, queue_evt_1);

            let (kill_evt, pause_evt) = self.common.dup_eventfds()?;

            let rx_rate_limiter: Option<rate_limiter::RateLimiter> = self
                .rate_limiter_config
                .map(RateLimiterConfig::try_into)
                .transpose()
                .map_err(ActivateError::CreateRateLimiter)?;

            let tx_rate_limiter: Option<rate_limiter::RateLimiter> = self
                .rate_limiter_config
                .map(RateLimiterConfig::try_into)
                .transpose()
                .map_err(ActivateError::CreateRateLimiter)?;

            let tap = taps.remove(0);
            #[cfg(not(fuzzing))]
            tap.set_offload(virtio_features_to_tap_offload(self.common.acked_features))
                .map_err(|e| {
                    error!("Error programming tap offload: {e:?}");
                    ActivateError::BadActivate
                })?;

            let mut handler = NetEpollHandler {
                net: NetQueuePair {
                    tap_for_write_epoll: tap.clone(),
                    tap,
                    rx,
                    tx,
                    epoll_fd: None,
                    rx_tap_listening,
                    tx_tap_listening: false,
                    counters: self.counters.clone(),
                    tap_rx_event_id: RX_TAP_EVENT,
                    tap_tx_event_id: TX_TAP_EVENT,
                    rx_desc_avail: false,
                    rx_rate_limiter,
                    tx_rate_limiter,
                    access_platform: self.common.access_platform(),
                },
                mem: mem.clone(),
                queue_index_base: (i * 2) as u16,
                queue_pair,
                queue_evt_pair,
                interrupt_cb: interrupt_cb.clone(),
                kill_evt,
                pause_evt,
            };

            let paused = self.common.paused.clone();
            let paused_sync = self.common.paused_sync.clone();

            self.common.spawn_worker(
                &format!("{}_qp{}", self.id.clone(), i),
                &self.seccomp_action,
                Thread::VirtioNet,
                &self.exit_evt,
                self.device_status.clone(),
                interrupt_cb.clone(),
                move || handler.run(&paused, paused_sync.as_ref().unwrap()),
            )?;
        }

        self.announce.notify(true);

        event!("virtio-device", "activated", "id", &self.id);
        Ok(())
    }

    fn reset(&mut self) {
        self.common.reset();
        self.announce.reset();
        event!("virtio-device", "reset", "id", &self.id);
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

    fn set_access_platform(&mut self, access_platform: Arc<dyn AccessPlatform>) {
        self.common.set_access_platform(access_platform);
    }

    fn access_platform(&self) -> Option<Arc<dyn AccessPlatform>> {
        self.common.access_platform()
    }
}

impl Pausable for Net {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        self.announce.invalidate();
        self.common.pause()
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        self.common.resume()?;
        self.announce.notify(true);
        Ok(())
    }
}

impl Snapshottable for Net {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> result::Result<Snapshot, MigratableError> {
        Snapshot::new_from_state(&self.state())
    }
}
impl Transportable for Net {}
impl Migratable for Net {
    fn start_migration(&mut self) -> result::Result<(), MigratableError> {
        self.announce.invalidate();
        Ok(())
    }
}

/// Whether announcements have to be retried. To avoid ambiguity when using a bool,
/// this enum clearly describes whether announcements are done, or have to be
/// retried.
#[derive(Clone)]
pub enum AnnounceOutcome {
    Retry,
    Done,
}

/// Backend-specific logic for driving announcements.
pub trait AnnounceOps: Send {
    /// Send an announcement and return whether this function has to be executed
    /// again.
    fn send_announce(&mut self) -> AnnounceOutcome;
}

pub struct Announcer {
    announce_generation: Arc<AtomicU64>,
    generation: u64,
    announcements_done: usize,
    announce_ops: Box<[Box<dyn AnnounceOps>]>,
}

impl Announcer {
    const MAX_ANNOUNCEMENTS: usize = 5;

    pub fn new(announce: &AnnouncementState, announce_ops: Box<[Box<dyn AnnounceOps>]>) -> Self {
        Self {
            announce_generation: announce.generation.clone(),
            generation: 0,
            announcements_done: 0,
            announce_ops,
        }
    }

    pub fn initialize(&mut self) {
        self.generation = self.announce_generation.load(Ordering::Acquire);
        self.announcements_done = 0;
    }

    /// Execute all announcers and return whether more announcements are necessary.
    pub fn send_announce(&mut self) -> AnnounceOutcome {
        if self.announce_generation.load(Ordering::Acquire) != self.generation
            || self.announcements_done >= Self::MAX_ANNOUNCEMENTS
        {
            return AnnounceOutcome::Done;
        }

        let announce_outcomes = self
            .announce_ops
            .iter_mut()
            .map(|ops| ops.send_announce())
            .collect::<Vec<AnnounceOutcome>>();

        self.announcements_done += 1;
        if self.announcements_done < Self::MAX_ANNOUNCEMENTS
            && announce_outcomes
                .iter()
                .any(|outcome| matches!(outcome, AnnounceOutcome::Retry))
        {
            return AnnounceOutcome::Retry;
        }

        AnnounceOutcome::Done
    }
}

pub(crate) struct VirtioNetGuestAnnounceOps {
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    guest_announce_negotiated: bool,
    announce_pending: Arc<AtomicBool>,
}

impl VirtioNetGuestAnnounceOps {
    pub fn new(
        interrupt_cb: Arc<dyn VirtioInterrupt>,
        guest_announce_negotiated: bool,
        announce: &AnnouncementState,
    ) -> Self {
        Self {
            interrupt_cb,
            guest_announce_negotiated,
            announce_pending: announce.pending.clone(),
        }
    }
}

impl AnnounceOps for VirtioNetGuestAnnounceOps {
    fn send_announce(&mut self) -> AnnounceOutcome {
        if !self.guest_announce_negotiated {
            self.announce_pending.store(false, Ordering::Release);
            return AnnounceOutcome::Done;
        }

        // If the guest hasn't ack'ed the announce, we trigger the interrupt.
        if self.announce_pending.load(Ordering::Acquire) {
            self.interrupt_cb
                .trigger(VirtioInterruptType::Config)
                .inspect_err(|e| {
                    warn!("Unable to send interrupt for virtio-net device: {e}");
                })
                .ok();

            // We have to check again whether the driver ack'ed the announcement.
            return AnnounceOutcome::Retry;
        }
        AnnounceOutcome::Done
    }
}

struct VirtioNetHostAnnounceOps {
    rarp_announce: Option<[u8; ETH_FRAME_LEN]>,
    taps: Box<[Tap]>,
}

impl VirtioNetHostAnnounceOps {
    pub fn new(rarp_announce: Option<[u8; ETH_FRAME_LEN]>, taps: Box<[Tap]>) -> Self {
        Self {
            rarp_announce,
            taps,
        }
    }
}

impl AnnounceOps for VirtioNetHostAnnounceOps {
    fn send_announce(&mut self) -> AnnounceOutcome {
        if let Some(rarp_announce) = self.rarp_announce {
            // The TAP fd expects the virtio-net header configured by
            // TUNSETVNETHDRSZ before the Ethernet frame.
            let mut buf = vec![0u8; vnet_hdr_len() + rarp_announce.len()];
            buf[vnet_hdr_len()..].copy_from_slice(&rarp_announce);

            for tap in &mut self.taps {
                if let Err(e) = tap.write(&buf) {
                    // The host-side RARP packets are best-effort. Thus, to keep things simple, we
                    // only log errors here instead of waiting for the TAP to become writable again.
                    error!("Host RARP write to TAP failed: {e}");
                }
            }

            return AnnounceOutcome::Retry;
        }

        AnnounceOutcome::Done
    }
}

#[cfg(test)]
mod unit_tests {
    use std::mem::{offset_of, size_of};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use seccompiler::SeccompAction;
    use virtio_bindings::virtio_net::{
        VIRTIO_NET_F_STATUS, VIRTIO_NET_S_ANNOUNCE, VIRTIO_NET_S_LINK_UP,
    };
    use vmm_sys_util::eventfd::EventFd;

    use super::*;

    fn test_net(
        acked_features: u64,
        interrupt_cb: Option<Arc<dyn VirtioInterrupt>>,
    ) -> Result<Net> {
        Ok(Net {
            common: VirtioCommon {
                acked_features,
                interrupt_cb,
                ..Default::default()
            },
            id: "test-net".to_string(),
            taps: Vec::new(),
            config: VirtioNetConfig::default(),
            counters: NetCounters::default(),
            seccomp_action: SeccompAction::Allow,
            rate_limiter_config: None,
            exit_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
            device_status: Arc::new(AtomicU8::new(0)),
            announce: AnnouncementState::new(false).map_err(Error::CreateEventFd)?,
        })
    }

    const STATUS_OFFSET: usize = offset_of!(VirtioNetConfig, status);
    fn read_status(device: &Net) -> u16 {
        let mut data = vec![0; size_of::<VirtioNetConfig>()];
        device.read_config(0, &mut data);

        u16::from_le_bytes(
            data[STATUS_OFFSET..STATUS_OFFSET + size_of::<u16>()]
                .try_into()
                .unwrap(),
        )
    }

    #[test]
    fn test_status_feature_reports_link_up() {
        // The current implementation should always report "link up" if
        // VIRTIO_NET_F_STATUS has been negotiated.
        let net = test_net(1 << VIRTIO_NET_F_STATUS, None).unwrap();

        assert_eq!(read_status(&net), VIRTIO_NET_S_LINK_UP as u16);
    }

    struct TestInterrupt {
        config_count: AtomicUsize,
    }

    impl TestInterrupt {
        fn new() -> Self {
            Self {
                config_count: AtomicUsize::new(0),
            }
        }
    }

    impl VirtioInterrupt for TestInterrupt {
        fn trigger(&self, int_type: VirtioInterruptType) -> result::Result<(), io::Error> {
            if matches!(int_type, VirtioInterruptType::Config) {
                self.config_count.fetch_add(1, Ordering::AcqRel);
            }
            Ok(())
        }

        fn set_notifier(
            &self,
            _int_type: u32,
            _notifier: Option<EventFd>,
            _vm: &dyn hypervisor::Vm,
        ) -> io::Result<()> {
            unimplemented!()
        }
    }

    fn test_announcer(dev: &Net) -> Result<Announcer> {
        let guest_announce_ops = VirtioNetGuestAnnounceOps::new(
            dev.common.interrupt_cb.clone().unwrap(),
            dev.common.feature_acked(VIRTIO_NET_F_GUEST_ANNOUNCE.into()),
            &dev.announce,
        );

        let host_announce_ops = VirtioNetHostAnnounceOps::new(
            dev.build_rarp_announce(),
            dev.taps.clone().into_boxed_slice(),
        );

        let announcer = Announcer::new(
            &dev.announce,
            vec![
                Box::new(guest_announce_ops) as Box<dyn AnnounceOps>,
                Box::new(host_announce_ops) as Box<dyn AnnounceOps>,
            ]
            .into_boxed_slice(),
        );

        Ok(announcer)
    }

    #[test]
    fn test_announcer_stop_retrying_on_generation_change() {
        let interrupt = Arc::new(TestInterrupt::new());
        let net = test_net(
            (1 << VIRTIO_NET_F_STATUS) | (1 << VIRTIO_NET_F_GUEST_ANNOUNCE),
            Some(interrupt.clone() as Arc<dyn VirtioInterrupt>),
        )
        .unwrap();
        let mut announcer = test_announcer(&net).unwrap();

        net.announce.pending.store(true, Ordering::Release);

        announcer.initialize();
        assert!(matches!(announcer.send_announce(), AnnounceOutcome::Retry));

        net.announce.generation.store(1, Ordering::Release);

        assert!(matches!(announcer.send_announce(), AnnounceOutcome::Done));
        assert!(net.announce.pending.load(Ordering::Acquire));
    }

    #[test]
    fn test_guest_ack_before_first_announce_run() {
        let interrupt = Arc::new(TestInterrupt::new());
        let net = test_net(
            (1 << VIRTIO_NET_F_STATUS) | (1 << VIRTIO_NET_F_GUEST_ANNOUNCE),
            Some(interrupt.clone() as Arc<dyn VirtioInterrupt>),
        )
        .unwrap();
        let mut announcer = test_announcer(&net).unwrap();

        // Here we check what happens if the guest ACK arrives before the epoll thread
        // does the first announcement.
        net.announce.pending.store(true, Ordering::Release);
        announcer.initialize();
        net.announce.pending.store(false, Ordering::Release);

        assert!(matches!(announcer.send_announce(), AnnounceOutcome::Done));
        assert!(!net.announce.pending.load(Ordering::Acquire));
        assert_eq!(read_status(&net) & VIRTIO_NET_S_ANNOUNCE as u16, 0);
        assert_eq!(interrupt.config_count.load(Ordering::Acquire), 0);
    }

    #[test]
    fn test_post_migration_without_feature_is_noop() {
        let interrupt = Arc::new(TestInterrupt::new());
        let net = test_net(0, Some(interrupt.clone() as Arc<dyn VirtioInterrupt>)).unwrap();
        let mut announcer = test_announcer(&net).unwrap();

        net.announce.pending.store(true, Ordering::Release);

        announcer.initialize();
        assert!(matches!(announcer.send_announce(), AnnounceOutcome::Done));

        assert!(!net.announce.pending.load(Ordering::Acquire));
        assert_eq!(read_status(&net) & VIRTIO_NET_S_ANNOUNCE as u16, 0);
        assert_eq!(interrupt.config_count.load(Ordering::Acquire), 0);
    }

    #[test]
    fn test_reset_clears_pending_announce() {
        let interrupt = Arc::new(TestInterrupt::new());
        let mut net = test_net(
            (1 << VIRTIO_NET_F_GUEST_ANNOUNCE) | (1 << VIRTIO_NET_F_STATUS),
            Some(interrupt.clone() as Arc<dyn VirtioInterrupt>),
        )
        .unwrap();
        let mut announcer = test_announcer(&net).unwrap();

        net.announce.pending.store(true, Ordering::Release);

        announcer.initialize();
        assert!(matches!(announcer.send_announce(), AnnounceOutcome::Retry));

        assert!(net.announce.pending.load(Ordering::Acquire));

        net.reset();

        assert!(!net.announce.pending.load(Ordering::Acquire));
        assert_eq!(read_status(&net) & VIRTIO_NET_S_ANNOUNCE as u16, 0);
    }

    fn assert_old_announcer_invalidated<F>(invalidate: F)
    where
        F: FnOnce(&mut Net),
    {
        let interrupt = Arc::new(TestInterrupt::new());
        let mut net = test_net(
            1 << VIRTIO_NET_F_GUEST_ANNOUNCE,
            Some(interrupt.clone() as Arc<dyn VirtioInterrupt>),
        )
        .unwrap();
        let mut announcer = test_announcer(&net).unwrap();

        net.announce.pending.store(true, Ordering::Release);

        announcer.initialize();
        assert!(matches!(announcer.send_announce(), AnnounceOutcome::Retry));
        assert_eq!(interrupt.config_count.load(Ordering::Acquire), 1);

        invalidate(&mut net);
        assert!(matches!(announcer.send_announce(), AnnounceOutcome::Done));

        assert_eq!(interrupt.config_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn test_reset_invalidates_old_announcer() {
        assert_old_announcer_invalidated(|net| {
            net.reset();
        });
    }

    #[test]
    fn test_pause_invalidates_old_announcer() {
        assert_old_announcer_invalidated(|net| {
            net.pause().unwrap();
        });
    }

    #[test]
    fn test_start_migration_invalidates_old_announcer() {
        assert_old_announcer_invalidated(|net| {
            net.start_migration().unwrap();
        });
    }

    struct RecordingAnnounceOps {
        val: Arc<AtomicUsize>,
        outcome: AnnounceOutcome,
    }

    impl AnnounceOps for RecordingAnnounceOps {
        fn send_announce(&mut self) -> AnnounceOutcome {
            self.val.fetch_add(1, Ordering::AcqRel);
            self.outcome.clone()
        }
    }

    fn recording_test_announcer(
        dev: &Net,
        first_outcome: AnnounceOutcome,
        second_outcome: AnnounceOutcome,
        val: Arc<AtomicUsize>,
    ) -> Result<Announcer> {
        let first_ops = RecordingAnnounceOps {
            val: val.clone(),
            outcome: first_outcome,
        };
        let second_ops = RecordingAnnounceOps {
            val,
            outcome: second_outcome,
        };

        Ok(Announcer::new(
            &dev.announce,
            vec![
                Box::new(first_ops) as Box<dyn AnnounceOps>,
                Box::new(second_ops) as Box<dyn AnnounceOps>,
            ]
            .into_boxed_slice(),
        ))
    }

    #[test]
    fn test_all_announcers_run_before_retry_decision() {
        let net = test_net(
            (1 << VIRTIO_NET_F_STATUS) | (1 << VIRTIO_NET_F_GUEST_ANNOUNCE),
            None,
        )
        .unwrap();

        let val = Arc::new(AtomicUsize::new(0));
        let mut announcer = recording_test_announcer(
            &net,
            AnnounceOutcome::Retry,
            AnnounceOutcome::Done,
            val.clone(),
        )
        .unwrap();

        announcer.initialize();
        assert!(matches!(announcer.send_announce(), AnnounceOutcome::Retry));
        assert_eq!(val.load(Ordering::Acquire), 2);
    }
}
