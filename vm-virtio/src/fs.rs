// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::Error as DeviceError;
use super::{ActivateError, ActivateResult, Queue, VirtioDevice, VirtioDeviceType};
use crate::{
    VirtioInterrupt, VirtioInterruptType, VirtioSharedMemoryList, VIRTIO_F_VERSION_1_BITMASK,
};
use epoll;
use libc::EFD_NONBLOCK;
use std::cmp;
use std::io;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::result;
use std::sync::Arc;
use std::thread;
use vhost_rs::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_rs::vhost_user::{Master, VhostUserMaster};
use vhost_rs::{VhostBackend, VhostUserMemoryRegionInfo, VringConfigData};
use vm_memory::{Address, Error as MmapError, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};
use vmm_sys_util::eventfd::EventFd;

const CONFIG_SPACE_TAG_SIZE: usize = 36;
const CONFIG_SPACE_NUM_QUEUES_SIZE: usize = 4;
const CONFIG_SPACE_SIZE: usize = CONFIG_SPACE_TAG_SIZE + CONFIG_SPACE_NUM_QUEUES_SIZE;
const NUM_QUEUE_OFFSET: usize = 1;

#[derive(Debug)]
pub enum Error {
    /// common

    /// Invalid descriptor table address.
    DescriptorTableAddress,
    /// Invalid used address.
    UsedAddress,
    /// Invalid available address.
    AvailAddress,

    /// vhost

    /// Creating kill eventfd failed.
    CreateKillEventFd(io::Error),
    /// Cloning kill eventfd failed.
    CloneKillEventFd(io::Error),
    /// Error while polling for events.
    PollError(io::Error),
    /// Failed to create irq eventfd.
    IrqEventCreate(io::Error),
    /// Failed to read vhost eventfd.
    VhostIrqRead(io::Error),

    /// vhost-user

    /// Connection to socket failed.
    VhostUserConnect(vhost_rs::Error),
    /// Get features failed.
    VhostUserGetFeatures(vhost_rs::Error),
    /// Get protocol features failed.
    VhostUserGetProtocolFeatures(vhost_rs::Error),
    /// Set owner failed.
    VhostUserSetOwner(vhost_rs::Error),
    /// Set features failed.
    VhostUserSetFeatures(vhost_rs::Error),
    /// Set protocol features failed.
    VhostUserSetProtocolFeatures(vhost_rs::Error),
    /// Set mem table failed.
    VhostUserSetMemTable(vhost_rs::Error),
    /// Set vring num failed.
    VhostUserSetVringNum(vhost_rs::Error),
    /// Set vring addr failed.
    VhostUserSetVringAddr(vhost_rs::Error),
    /// Set vring base failed.
    VhostUserSetVringBase(vhost_rs::Error),
    /// Set vring call failed.
    VhostUserSetVringCall(vhost_rs::Error),
    /// Set vring kick failed.
    VhostUserSetVringKick(vhost_rs::Error),

    /// Invalid features provided from vhost-user backend.
    InvalidFeatures,

    /// Missing file descriptor.
    FdMissing,

    /// Failure going through memory regions.
    MemoryRegions(MmapError),
}
type Result<T> = result::Result<T, Error>;

struct FsEpollHandler {
    vu_call_evt_queue_list: Vec<(EventFd, Queue)>,
    interrupt_cb: Arc<VirtioInterrupt>,
    kill_evt: EventFd,
}

impl FsEpollHandler {
    fn run(&mut self) -> result::Result<(), DeviceError> {
        // Create the epoll file descriptor
        let epoll_fd = epoll::create(true).map_err(DeviceError::EpollCreateFd)?;

        for (evt_index, vu_call_evt_queue) in self.vu_call_evt_queue_list.iter().enumerate() {
            // Add events
            epoll::ctl(
                epoll_fd,
                epoll::ControlOptions::EPOLL_CTL_ADD,
                vu_call_evt_queue.0.as_raw_fd(),
                epoll::Event::new(epoll::Events::EPOLLIN, evt_index as u64),
            )
            .map_err(DeviceError::EpollCtl)?;
        }

        let kill_evt_index = self.vu_call_evt_queue_list.len();
        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            self.kill_evt.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, kill_evt_index as u64),
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
                let ev_type = event.data as usize;

                match ev_type {
                    x if (x < kill_evt_index) => {
                        if let Err(e) = self.vu_call_evt_queue_list[x].0.read() {
                            error!("Failed to get queue event: {:?}", e);
                            break 'epoll;
                        } else if let Err(e) = (self.interrupt_cb)(
                            &VirtioInterruptType::Queue,
                            Some(&self.vu_call_evt_queue_list[x].1),
                        ) {
                            error!(
                                "Failed to signal used queue: {:?}",
                                DeviceError::FailedSignalingUsedQueue(e)
                            );
                            break 'epoll;
                        }
                    }
                    x if (x == kill_evt_index) => {
                        debug!("KILL_EVENT received, stopping epoll loop");
                        break 'epoll;
                    }
                    _ => {
                        error!("Unknown event for virtio-fs");
                    }
                }
            }
        }

        Ok(())
    }
}

pub struct Fs {
    vu: Master,
    queue_sizes: Vec<u16>,
    avail_features: u64,
    acked_features: u64,
    config_space: Vec<u8>,
    kill_evt: Option<EventFd>,
}

impl Fs {
    /// Create a new virtio-fs device.
    pub fn new(
        path: &str,
        tag: &str,
        req_num_queues: usize,
        queue_size: u16,
        _cache_addr: Option<(VirtioSharedMemoryList, u64)>,
    ) -> Result<Fs> {
        // Calculate the actual number of queues needed.
        let num_queues = NUM_QUEUE_OFFSET + req_num_queues;
        // Connect to the vhost-user socket.
        let mut master =
            Master::connect(path, num_queues as u64).map_err(Error::VhostUserConnect)?;
        // Retrieve available features only when connecting the first time.
        let mut avail_features = master.get_features().map_err(Error::VhostUserGetFeatures)?;
        // Let only ack features we expect, that is VIRTIO_F_VERSION_1.
        if (avail_features & VIRTIO_F_VERSION_1_BITMASK) != VIRTIO_F_VERSION_1_BITMASK {
            return Err(Error::InvalidFeatures);
        }
        avail_features =
            VIRTIO_F_VERSION_1_BITMASK | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        master
            .set_features(avail_features)
            .map_err(Error::VhostUserSetFeatures)?;
        // Identify if protocol features are supported by the slave.
        if (avail_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits())
            == VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
        {
            let mut protocol_features = master
                .get_protocol_features()
                .map_err(Error::VhostUserGetProtocolFeatures)?;
            protocol_features &= VhostUserProtocolFeatures::MQ;
            master
                .set_protocol_features(protocol_features)
                .map_err(Error::VhostUserSetProtocolFeatures)?;
        }
        // Create virtio device config space.
        // First by adding the tag.
        let mut config_space = tag.to_string().into_bytes();
        config_space.resize(CONFIG_SPACE_SIZE, 0);
        // And then by copying the number of queues.
        let num_queues_slice = (req_num_queues as u32).to_le_bytes();
        config_space[CONFIG_SPACE_TAG_SIZE..CONFIG_SPACE_SIZE].copy_from_slice(&num_queues_slice);

        Ok(Fs {
            vu: master,
            queue_sizes: vec![queue_size; num_queues],
            avail_features,
            acked_features: 0u64,
            config_space,
            kill_evt: None,
        })
    }

    fn setup_vu(
        &mut self,
        mem: &GuestMemoryMmap,
        queues: Vec<Queue>,
        queue_evts: Vec<EventFd>,
    ) -> Result<Vec<(EventFd, Queue)>> {
        // Set vhost-user owner.
        self.vu.set_owner().map_err(Error::VhostUserSetOwner)?;

        // Set backend features.
        self.vu
            .set_features(self.acked_features)
            .map_err(Error::VhostUserSetFeatures)?;

        let mut regions: Vec<VhostUserMemoryRegionInfo> = Vec::new();

        mem.with_regions_mut(|_, region| {
            let (mmap_handle, mmap_offset) = match region.file_offset() {
                Some(fo) => (fo.file().as_raw_fd(), fo.start()),
                None => return Err(MmapError::NoMemoryRegion),
            };

            let vu_mem_reg = VhostUserMemoryRegionInfo {
                guest_phys_addr: region.start_addr().raw_value(),
                memory_size: region.len() as u64,
                userspace_addr: region.as_ptr() as u64,
                mmap_offset,
                mmap_handle,
            };

            regions.push(vu_mem_reg);

            Ok(())
        })
        .map_err(Error::MemoryRegions)?;

        self.vu
            .set_mem_table(regions.as_slice())
            .map_err(Error::VhostUserSetMemTable)?;

        let mut result = Vec::new();
        for (queue_index, queue) in queues.into_iter().enumerate() {
            self.vu
                .set_vring_num(queue_index, queue.get_max_size())
                .map_err(Error::VhostUserSetVringNum)?;

            let vring_config = VringConfigData {
                queue_max_size: queue.get_max_size(),
                queue_size: queue.size,
                flags: 0u32,
                desc_table_addr: mem
                    .get_host_address(queue.desc_table)
                    .ok_or_else(|| Error::DescriptorTableAddress)?
                    as u64,
                used_ring_addr: mem
                    .get_host_address(queue.used_ring)
                    .ok_or_else(|| Error::UsedAddress)? as u64,
                avail_ring_addr: mem
                    .get_host_address(queue.avail_ring)
                    .ok_or_else(|| Error::AvailAddress)? as u64,
                log_addr: None,
            };

            self.vu
                .set_vring_addr(queue_index, &vring_config)
                .map_err(Error::VhostUserSetVringAddr)?;

            self.vu
                .set_vring_base(queue_index, 0u16)
                .map_err(Error::VhostUserSetVringBase)?;

            let vu_call_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::IrqEventCreate)?;

            self.vu
                .set_vring_call(queue_index, &vu_call_evt)
                .map_err(Error::VhostUserSetVringCall)?;

            result.push((vu_call_evt, queue));

            self.vu
                .set_vring_kick(queue_index, &queue_evts[queue_index])
                .map_err(Error::VhostUserSetVringKick)?;
        }

        Ok(result)
    }
}

impl Drop for Fs {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
    }
}

impl VirtioDevice for Fs {
    fn device_type(&self) -> u32 {
        VirtioDeviceType::TYPE_FS as u32
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.queue_sizes.as_slice()
    }

    fn features(&self, page: u32) -> u32 {
        match page {
            // Get the lower 32-bits of the features bitfield.
            0 => self.avail_features as u32,
            // Get the upper 32-bits of the features bitfield.
            1 => (self.avail_features >> 32) as u32,
            _ => {
                warn!("fs: Received request for unknown features page: {}", page);
                0u32
            }
        }
    }

    fn ack_features(&mut self, page: u32, value: u32) {
        let mut v = match page {
            0 => u64::from(value),
            1 => u64::from(value) << 32,
            _ => {
                warn!("fs: Cannot acknowledge unknown features page: {}", page);
                0u64
            }
        };

        // Check if the guest is ACK'ing a feature that we didn't claim to have.
        let unrequested_features = v & !self.avail_features;
        if unrequested_features != 0 {
            warn!("fs: virtio-fs got unknown feature ack: {:x}", v);

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
        mem: GuestMemoryMmap,
        interrupt_cb: Arc<VirtioInterrupt>,
        queues: Vec<Queue>,
        queue_evts: Vec<EventFd>,
    ) -> ActivateResult {
        if queues.len() != self.queue_sizes.len() || queue_evts.len() != self.queue_sizes.len() {
            error!(
                "Cannot perform activate. Expected {} queue(s), got {}",
                self.queue_sizes.len(),
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

        let vu_call_evt_queue_list = self
            .setup_vu(&mem, queues, queue_evts)
            .map_err(ActivateError::VhostUserSetup)?;

        let mut handler = FsEpollHandler {
            vu_call_evt_queue_list,
            interrupt_cb,
            kill_evt,
        };

        let worker_result = thread::Builder::new()
            .name("virtio_fs".to_string())
            .spawn(move || handler.run());

        if let Err(e) = worker_result {
            error!("failed to spawn virtio_blk worker: {}", e);
            return Err(ActivateError::BadActivate);
        }

        Ok(())
    }
}
