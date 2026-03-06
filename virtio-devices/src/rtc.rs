// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2026, Microsoft Corporation
//

use std::mem::size_of;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Barrier};
use std::{io, result};

use anyhow::anyhow;
use event_monitor::event;
use log::{error, info};
use seccompiler::SeccompAction;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use virtio_queue::{Queue, QueueT};
use vm_memory::{Address, ByteValued, Bytes, GuestAddressSpace, GuestMemoryAtomic};
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
use vm_virtio::{AccessPlatform, Translatable};
use vmm_sys_util::eventfd::EventFd;

use super::{
    ActivateResult, EPOLL_HELPER_EVENT_LAST, EpollHelper, EpollHelperError, EpollHelperHandler,
    Error as DeviceError, VIRTIO_F_ACCESS_PLATFORM, VIRTIO_F_VERSION_1, VirtioCommon, VirtioDevice,
    VirtioDeviceType,
};
use crate::seccomp_filters::Thread;
use crate::thread_helper::spawn_virtio_thread;
use crate::{GuestMemoryMmap, VirtioInterrupt, VirtioInterruptType};

const QUEUE_SIZE: u16 = 256;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE];

// New descriptors are pending on the virtio queue.
const QUEUE_AVAIL_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;

// Virtio RTC request message types
const VIRTIO_RTC_REQ_READ: u16 = 0x0001;
const VIRTIO_RTC_REQ_CFG: u16 = 0x1000;
const VIRTIO_RTC_REQ_CLOCK_CAP: u16 = 0x1001;
const VIRTIO_RTC_REQ_CROSS_CAP: u16 = 0x1002;

// Virtio RTC status codes
const VIRTIO_RTC_S_OK: u8 = 0;
const VIRTIO_RTC_S_EOPNOTSUPP: u8 = 2;
const VIRTIO_RTC_S_ENODEV: u8 = 3;
#[allow(unused)]
const VIRTIO_RTC_S_EINVAL: u8 = 4;
const VIRTIO_RTC_S_EIO: u8 = 5;

// Clock types
const VIRTIO_RTC_CLOCK_UTC_SMEARED: u8 = 3;
const VIRTIO_RTC_SMEAR_UNSPECIFIED: u8 = 0;

// Number of clocks exposed by this device
const NUM_CLOCKS: u16 = 1;

/// Request header: 8 bytes
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
struct VirtioRtcReqHead {
    msg_type: u16,
    reserved: [u8; 6],
}

// SAFETY: it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioRtcReqHead {}

/// Response header: 8 bytes
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
struct VirtioRtcRespHead {
    status: u8,
    reserved: [u8; 7],
}

// SAFETY: it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioRtcRespHead {}

/// Request body for READ and CLOCK_CAP (after head): 8 bytes
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
struct VirtioRtcReqClockBody {
    clock_id: u16,
    reserved: [u8; 6],
}

// SAFETY: it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioRtcReqClockBody {}

/// Request body for CROSS_CAP (after head): 8 bytes
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
struct VirtioRtcReqCrossCapBody {
    clock_id: u16,
    hw_counter: u8,
    reserved: [u8; 5],
}

// SAFETY: it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioRtcReqCrossCapBody {}

/// CFG response: head (8) + num_clocks (2) + reserved (6) = 16 bytes
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
struct VirtioRtcRespCfg {
    head: VirtioRtcRespHead,
    num_clocks: u16,
    reserved: [u8; 6],
}

// SAFETY: it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioRtcRespCfg {}

/// CLOCK_CAP response: head (8) + type (1) + leap_second_smearing (1) + flags (1) + reserved (5) = 16 bytes
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
struct VirtioRtcRespClockCap {
    head: VirtioRtcRespHead,
    type_: u8,
    leap_second_smearing: u8,
    flags: u8,
    reserved: [u8; 5],
}

// SAFETY: it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioRtcRespClockCap {}

/// READ response: head (8) + clock_reading (8) = 16 bytes
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
struct VirtioRtcRespRead {
    head: VirtioRtcRespHead,
    clock_reading: u64,
}

// SAFETY: it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioRtcRespRead {}

/// CROSS_CAP response: head (8) + flags (1) + reserved (7) = 16 bytes
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
struct VirtioRtcRespCrossCap {
    head: VirtioRtcRespHead,
    flags: u8,
    reserved: [u8; 7],
}

// SAFETY: it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioRtcRespCrossCap {}

/// Parsed request from guest.
enum VirtioRtcRequest {
    Cfg,
    ClockCap { clock_id: u16 },
    Read { clock_id: u16 },
    CrossCap { clock_id: u16, _hw_counter: u8 },
    Unknown,
}

/// Response to be written back to the guest.
enum VirtioRtcResponse {
    Cfg(VirtioRtcRespCfg),
    ClockCap(VirtioRtcRespClockCap),
    Read(VirtioRtcRespRead),
    CrossCap(VirtioRtcRespCrossCap),
    Error(VirtioRtcRespHead),
}

#[derive(Error, Debug)]
enum Error {
    #[error("Descriptor chain too short")]
    DescriptorChainTooShort,
    #[error("Invalid descriptor")]
    InvalidDescriptor,
    #[error("Failed to read request from guest memory")]
    GuestMemoryRead(#[source] vm_memory::guest_memory::Error),
    #[error("Failed to write to guest memory")]
    GuestMemoryWrite(#[source] vm_memory::guest_memory::Error),
    #[error("Failed adding used index")]
    QueueAddUsed(#[source] virtio_queue::Error),
}

struct RtcEpollHandler {
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
    queue: Queue,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    queue_evt: EventFd,
    kill_evt: EventFd,
    pause_evt: EventFd,
    access_platform: Option<Arc<dyn AccessPlatform>>,
}

impl RtcEpollHandler {
    fn process_queue(&mut self) -> Result<bool, Error> {
        let mut used_descs = false;

        while let Some(mut desc_chain) = self.queue.pop_descriptor_chain(self.mem.memory()) {
            let req_desc = desc_chain.next().ok_or(Error::DescriptorChainTooShort)?;
            let req_len = req_desc.len();

            // The request descriptor must be readable by the device.
            if req_desc.is_write_only() || req_len < size_of::<VirtioRtcReqHead>() as u32 {
                return Err(Error::InvalidDescriptor);
            }

            let req_addr = req_desc
                .addr()
                .translate_gva(self.access_platform.as_deref(), req_desc.len() as usize);

            // Read the request header
            let req_head: VirtioRtcReqHead = desc_chain
                .memory()
                .read_obj(req_addr)
                .map_err(Error::GuestMemoryRead)?;

            let body_addr = req_addr
                .checked_add(size_of::<VirtioRtcReqHead>() as u64)
                .ok_or(Error::InvalidDescriptor)?;

            // Parse the full request based on msg_type
            let request = match req_head.msg_type {
                VIRTIO_RTC_REQ_CFG => VirtioRtcRequest::Cfg,
                VIRTIO_RTC_REQ_CLOCK_CAP => {
                    if req_len
                        < (size_of::<VirtioRtcReqHead>() + size_of::<VirtioRtcReqClockBody>())
                            as u32
                    {
                        return Err(Error::InvalidDescriptor);
                    }

                    let body: VirtioRtcReqClockBody = desc_chain
                        .memory()
                        .read_obj(body_addr)
                        .map_err(Error::GuestMemoryRead)?;
                    VirtioRtcRequest::ClockCap {
                        clock_id: body.clock_id,
                    }
                }
                VIRTIO_RTC_REQ_READ => {
                    if req_len
                        < (size_of::<VirtioRtcReqHead>() + size_of::<VirtioRtcReqClockBody>())
                            as u32
                    {
                        return Err(Error::InvalidDescriptor);
                    }

                    let body: VirtioRtcReqClockBody = desc_chain
                        .memory()
                        .read_obj(body_addr)
                        .map_err(Error::GuestMemoryRead)?;
                    VirtioRtcRequest::Read {
                        clock_id: body.clock_id,
                    }
                }
                VIRTIO_RTC_REQ_CROSS_CAP => {
                    if req_len
                        < (size_of::<VirtioRtcReqHead>() + size_of::<VirtioRtcReqCrossCapBody>())
                            as u32
                    {
                        return Err(Error::InvalidDescriptor);
                    }

                    let body: VirtioRtcReqCrossCapBody = desc_chain
                        .memory()
                        .read_obj(body_addr)
                        .map_err(Error::GuestMemoryRead)?;
                    VirtioRtcRequest::CrossCap {
                        clock_id: body.clock_id,
                        _hw_counter: body.hw_counter,
                    }
                }
                _ => VirtioRtcRequest::Unknown,
            };

            let response = self.handle_request(&request);

            let resp_desc = desc_chain.next().ok_or(Error::DescriptorChainTooShort)?;

            // The response descriptor must be writable by the device.
            if !resp_desc.is_write_only() {
                return Err(Error::InvalidDescriptor);
            }

            let resp_addr = resp_desc
                .addr()
                .translate_gva(self.access_platform.as_deref(), resp_desc.len() as usize);

            let resp_len = match &response {
                VirtioRtcResponse::Cfg(_) => size_of::<VirtioRtcRespCfg>() as u32,
                VirtioRtcResponse::ClockCap(_) => size_of::<VirtioRtcRespClockCap>() as u32,
                VirtioRtcResponse::Read(_) => size_of::<VirtioRtcRespRead>() as u32,
                VirtioRtcResponse::CrossCap(_) => size_of::<VirtioRtcRespCrossCap>() as u32,
                VirtioRtcResponse::Error(_) => size_of::<VirtioRtcRespHead>() as u32,
            };

            if resp_desc.len() < resp_len {
                return Err(Error::InvalidDescriptor);
            }

            match &response {
                VirtioRtcResponse::Cfg(resp) => {
                    desc_chain
                        .memory()
                        .write_obj(*resp, resp_addr)
                        .map_err(Error::GuestMemoryWrite)?;
                }
                VirtioRtcResponse::ClockCap(resp) => {
                    desc_chain
                        .memory()
                        .write_obj(*resp, resp_addr)
                        .map_err(Error::GuestMemoryWrite)?;
                }
                VirtioRtcResponse::Read(resp) => {
                    desc_chain
                        .memory()
                        .write_obj(*resp, resp_addr)
                        .map_err(Error::GuestMemoryWrite)?;
                }
                VirtioRtcResponse::CrossCap(resp) => {
                    desc_chain
                        .memory()
                        .write_obj(*resp, resp_addr)
                        .map_err(Error::GuestMemoryWrite)?;
                }
                VirtioRtcResponse::Error(resp) => {
                    desc_chain
                        .memory()
                        .write_obj(*resp, resp_addr)
                        .map_err(Error::GuestMemoryWrite)?;
                }
            }

            self.queue
                .add_used(desc_chain.memory(), desc_chain.head_index(), resp_len)
                .map_err(Error::QueueAddUsed)?;

            used_descs = true;
        }

        Ok(used_descs)
    }

    fn handle_request(&self, req: &VirtioRtcRequest) -> VirtioRtcResponse {
        match req {
            VirtioRtcRequest::Cfg => VirtioRtcResponse::Cfg(VirtioRtcRespCfg {
                head: VirtioRtcRespHead {
                    status: VIRTIO_RTC_S_OK,
                    ..Default::default()
                },
                num_clocks: NUM_CLOCKS,
                ..Default::default()
            }),
            VirtioRtcRequest::ClockCap { clock_id } => match clock_id {
                0 => VirtioRtcResponse::ClockCap(VirtioRtcRespClockCap {
                    head: VirtioRtcRespHead {
                        status: VIRTIO_RTC_S_OK,
                        ..Default::default()
                    },
                    type_: VIRTIO_RTC_CLOCK_UTC_SMEARED,
                    leap_second_smearing: VIRTIO_RTC_SMEAR_UNSPECIFIED,
                    flags: 0, // alarm not supported
                    ..Default::default()
                }),
                _ => VirtioRtcResponse::ClockCap(VirtioRtcRespClockCap {
                    head: VirtioRtcRespHead {
                        status: VIRTIO_RTC_S_ENODEV,
                        ..Default::default()
                    },
                    ..Default::default()
                }),
            }
            VirtioRtcRequest::Read { clock_id } => match clock_id {
                0 => match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                    Ok(now) => VirtioRtcResponse::Read(VirtioRtcRespRead {
                        head: VirtioRtcRespHead {
                            status: VIRTIO_RTC_S_OK,
                            ..Default::default()
                        },
                        clock_reading: now.as_nanos() as u64,
                    }),
                    Err(_) => VirtioRtcResponse::Read(VirtioRtcRespRead {
                        head: VirtioRtcRespHead {
                            status: VIRTIO_RTC_S_EIO,
                            ..Default::default()
                        },
                        ..Default::default()
                    }),
                },
                _ => VirtioRtcResponse::Read(VirtioRtcRespRead {
                    head: VirtioRtcRespHead {
                        status: VIRTIO_RTC_S_ENODEV,
                        ..Default::default()
                    },
                    ..Default::default()
                }),
            }
            VirtioRtcRequest::CrossCap { clock_id, .. } => match clock_id {
                0 => VirtioRtcResponse::CrossCap(VirtioRtcRespCrossCap {
                    head: VirtioRtcRespHead {
                        status: VIRTIO_RTC_S_OK,
                        ..Default::default()
                    },
                    flags: 0, // no cross-timestamping support
                    ..Default::default()
                }),
                _ => VirtioRtcResponse::CrossCap(VirtioRtcRespCrossCap {
                    head: VirtioRtcRespHead {
                        status: VIRTIO_RTC_S_ENODEV,
                        ..Default::default()
                    },
                    ..Default::default()
                }),
            }
            VirtioRtcRequest::Unknown => VirtioRtcResponse::Error(VirtioRtcRespHead {
                status: VIRTIO_RTC_S_EOPNOTSUPP,
                ..Default::default()
            }),
        }
    }

    fn signal_used_queue(&self) -> result::Result<(), DeviceError> {
        self.interrupt_cb
            .trigger(VirtioInterruptType::Queue(0))
            .map_err(|e| {
                error!("Failed to signal used queue: {e:?}");
                DeviceError::FailedSignalingUsedQueue(e)
            })
    }

    fn run(
        &mut self,
        paused: &AtomicBool,
        paused_sync: &Barrier,
    ) -> result::Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;
        helper.add_event(self.queue_evt.as_raw_fd(), QUEUE_AVAIL_EVENT)?;
        helper.run(paused, paused_sync, self)?;

        Ok(())
    }
}

impl EpollHelperHandler for RtcEpollHandler {
    fn handle_event(
        &mut self,
        _helper: &mut EpollHelper,
        event: &epoll::Event,
    ) -> result::Result<(), EpollHelperError> {
        let ev_type = event.data as u16;
        match ev_type {
            QUEUE_AVAIL_EVENT => {
                self.queue_evt.read().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!("Failed to get queue event: {e:?}"))
                })?;
                let needs_notification = self.process_queue().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!("Failed to process queue : {e:?}"))
                })?;
                if needs_notification {
                    self.signal_used_queue().map_err(|e| {
                        EpollHelperError::HandleEvent(anyhow!("Failed to signal used queue: {e:?}"))
                    })?;
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

/// Virtio RTC device exposing high-resolution host clocks to the guest.
pub struct Rtc {
    common: VirtioCommon,
    id: String,
    seccomp_action: SeccompAction,
    exit_evt: EventFd,
}

#[derive(Deserialize, Serialize)]
pub struct RtcState {
    pub avail_features: u64,
    pub acked_features: u64,
}

impl Rtc {
    /// Create a new virtio RTC device.
    pub fn new(
        id: String,
        iommu: bool,
        seccomp_action: SeccompAction,
        exit_evt: EventFd,
        state: Option<RtcState>,
    ) -> io::Result<Rtc> {
        let (avail_features, acked_features, paused) = if let Some(state) = state {
            info!("Restoring virtio-rtc {id}");
            (state.avail_features, state.acked_features, true)
        } else {
            let mut avail_features = 1u64 << VIRTIO_F_VERSION_1;

            if iommu {
                avail_features |= 1u64 << VIRTIO_F_ACCESS_PLATFORM;
            }

            (avail_features, 0, false)
        };

        Ok(Rtc {
            common: VirtioCommon {
                device_type: VirtioDeviceType::Rtc as u32,
                queue_sizes: QUEUE_SIZES.to_vec(),
                paused_sync: Some(Arc::new(Barrier::new(2))),
                avail_features,
                acked_features,
                min_queues: 1,
                paused: Arc::new(AtomicBool::new(paused)),
                ..Default::default()
            },
            id,
            seccomp_action,
            exit_evt,
        })
    }

    fn state(&self) -> RtcState {
        RtcState {
            avail_features: self.common.avail_features,
            acked_features: self.common.acked_features,
        }
    }

    #[cfg(fuzzing)]
    pub fn wait_for_epoll_threads(&mut self) {
        self.common.wait_for_epoll_threads();
    }
}

impl Drop for Rtc {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.common.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
        self.common.wait_for_epoll_threads();
    }
}

impl VirtioDevice for Rtc {
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

    fn activate(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        interrupt_cb: Arc<dyn VirtioInterrupt>,
        mut queues: Vec<(usize, Queue, EventFd)>,
    ) -> ActivateResult {
        self.common.activate(&queues, interrupt_cb.clone())?;
        let (kill_evt, pause_evt) = self.common.dup_eventfds();

        let (_, queue, queue_evt) = queues.remove(0);

        let mut handler = RtcEpollHandler {
            mem,
            queue,
            interrupt_cb,
            queue_evt,
            kill_evt,
            pause_evt,
            access_platform: self.common.access_platform.clone(),
        };

        let paused = self.common.paused.clone();
        let paused_sync = self.common.paused_sync.clone();
        let mut epoll_threads = Vec::new();
        spawn_virtio_thread(
            &self.id,
            &self.seccomp_action,
            Thread::VirtioRtc,
            &mut epoll_threads,
            &self.exit_evt,
            move || handler.run(&paused, paused_sync.as_ref().unwrap()),
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

    fn set_access_platform(&mut self, access_platform: Arc<dyn AccessPlatform>) {
        self.common.set_access_platform(access_platform);
    }
}

impl Pausable for Rtc {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        self.common.pause()
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        self.common.resume()
    }
}

impl Snapshottable for Rtc {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        Snapshot::new_from_state(&self.state())
    }
}

impl Transportable for Rtc {}
impl Migratable for Rtc {}
