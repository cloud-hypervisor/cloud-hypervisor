// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::super::{Descriptor, Queue};
use super::{Error, Result};
use crate::vhost_user::Inflight;
use crate::{get_host_address_range, VirtioInterrupt, VirtioInterruptType};
use crate::{GuestMemoryMmap, GuestRegionMmap};
use std::convert::TryInto;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixListener;
use std::sync::Arc;
use std::thread::sleep;
use std::time::{Duration, Instant};
use std::vec::Vec;
use vhost::vhost_user::message::{
    VhostUserInflight, VhostUserProtocolFeatures, VhostUserVirtioFeatures,
};
use vhost::vhost_user::{Master, MasterReqHandler, VhostUserMaster, VhostUserMasterReqHandler};
use vhost::{VhostBackend, VhostUserMemoryRegionInfo, VringConfigData};
use vm_memory::{Address, Error as MmapError, GuestMemory, GuestMemoryRegion};
use vmm_sys_util::eventfd::EventFd;

#[derive(Debug, Clone)]
pub struct VhostUserConfig {
    pub socket: String,
    pub num_queues: usize,
    pub queue_size: u16,
}

pub fn update_mem_table(vu: &mut Master, mem: &GuestMemoryMmap) -> Result<()> {
    let mut regions: Vec<VhostUserMemoryRegionInfo> = Vec::new();
    for region in mem.iter() {
        let (mmap_handle, mmap_offset) = match region.file_offset() {
            Some(_file_offset) => (_file_offset.file().as_raw_fd(), _file_offset.start()),
            None => return Err(Error::VhostUserMemoryRegion(MmapError::NoMemoryRegion)),
        };

        let vhost_user_net_reg = VhostUserMemoryRegionInfo {
            guest_phys_addr: region.start_addr().raw_value(),
            memory_size: region.len() as u64,
            userspace_addr: region.as_ptr() as u64,
            mmap_offset,
            mmap_handle,
        };

        regions.push(vhost_user_net_reg);
    }

    vu.set_mem_table(regions.as_slice())
        .map_err(Error::VhostUserSetMemTable)?;

    Ok(())
}

pub fn add_memory_region(vu: &mut Master, region: &Arc<GuestRegionMmap>) -> Result<()> {
    let (mmap_handle, mmap_offset) = match region.file_offset() {
        Some(file_offset) => (file_offset.file().as_raw_fd(), file_offset.start()),
        None => return Err(Error::MissingRegionFd),
    };

    let region = VhostUserMemoryRegionInfo {
        guest_phys_addr: region.start_addr().raw_value(),
        memory_size: region.len() as u64,
        userspace_addr: region.as_ptr() as u64,
        mmap_offset,
        mmap_handle,
    };

    vu.add_mem_region(&region)
        .map_err(Error::VhostUserAddMemReg)
}

pub fn negotiate_features_vhost_user(
    vu: &mut Master,
    avail_features: u64,
    avail_protocol_features: VhostUserProtocolFeatures,
) -> Result<(u64, u64)> {
    // Set vhost-user owner.
    vu.set_owner().map_err(Error::VhostUserSetOwner)?;

    // Get features from backend, do negotiation to get a feature collection which
    // both VMM and backend support.
    let backend_features = vu.get_features().map_err(Error::VhostUserGetFeatures)?;
    let acked_features = avail_features & backend_features;

    let acked_protocol_features =
        if acked_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() != 0 {
            let backend_protocol_features = vu
                .get_protocol_features()
                .map_err(Error::VhostUserGetProtocolFeatures)?;

            let acked_protocol_features = avail_protocol_features & backend_protocol_features;

            vu.set_protocol_features(acked_protocol_features)
                .map_err(Error::VhostUserSetProtocolFeatures)?;

            acked_protocol_features.bits()
        } else {
            0
        };

    Ok((acked_features, acked_protocol_features))
}

#[allow(clippy::too_many_arguments)]
pub fn setup_vhost_user<S: VhostUserMasterReqHandler>(
    vu: &mut Master,
    mem: &GuestMemoryMmap,
    queues: Vec<Queue>,
    queue_evts: Vec<EventFd>,
    virtio_interrupt: &Arc<dyn VirtioInterrupt>,
    acked_features: u64,
    slave_req_handler: &Option<MasterReqHandler<S>>,
    inflight: Option<&mut Inflight>,
) -> Result<()> {
    vu.set_features(acked_features)
        .map_err(Error::VhostUserSetFeatures)?;

    // Let's first provide the memory table to the backend.
    update_mem_table(vu, mem)?;

    // Setup for inflight I/O tracking shared memory.
    if let Some(inflight) = inflight {
        if inflight.fd.is_none() {
            let inflight_req_info = VhostUserInflight {
                mmap_size: 0,
                mmap_offset: 0,
                num_queues: queues.len() as u16,
                queue_size: queues[0].actual_size(),
            };
            let (info, fd) = vu
                .get_inflight_fd(&inflight_req_info)
                .map_err(Error::VhostUserGetInflight)?;
            inflight.info = info;
            inflight.fd = Some(fd);
        }
        // Unwrapping the inflight fd is safe here since we know it can't be None.
        vu.set_inflight_fd(&inflight.info, inflight.fd.as_ref().unwrap().as_raw_fd())
            .map_err(Error::VhostUserSetInflight)?;
    }

    for (queue_index, queue) in queues.into_iter().enumerate() {
        let actual_size: usize = queue.actual_size().try_into().unwrap();

        vu.set_vring_num(queue_index, queue.actual_size())
            .map_err(Error::VhostUserSetVringNum)?;

        let config_data = VringConfigData {
            queue_max_size: queue.get_max_size(),
            queue_size: queue.actual_size(),
            flags: 0u32,
            desc_table_addr: get_host_address_range(
                mem,
                queue.desc_table,
                actual_size * std::mem::size_of::<Descriptor>(),
            )
            .ok_or(Error::DescriptorTableAddress)? as u64,
            // The used ring is {flags: u16; idx: u16; virtq_used_elem [{id: u16, len: u16}; actual_size]},
            // i.e. 4 + (4 + 4) * actual_size.
            used_ring_addr: get_host_address_range(mem, queue.used_ring, 4 + actual_size * 8)
                .ok_or(Error::UsedAddress)? as u64,
            // The used ring is {flags: u16; idx: u16; elem [u16; actual_size]},
            // i.e. 4 + (2) * actual_size.
            avail_ring_addr: get_host_address_range(mem, queue.avail_ring, 4 + actual_size * 2)
                .ok_or(Error::AvailAddress)? as u64,
            log_addr: None,
        };

        vu.set_vring_addr(queue_index, &config_data)
            .map_err(Error::VhostUserSetVringAddr)?;
        vu.set_vring_base(
            queue_index,
            queue
                .avail_index_from_memory(mem)
                .map_err(Error::GetAvailableIndex)?,
        )
        .map_err(Error::VhostUserSetVringBase)?;

        if let Some(eventfd) = virtio_interrupt.notifier(&VirtioInterruptType::Queue, Some(&queue))
        {
            vu.set_vring_call(queue_index, &eventfd)
                .map_err(Error::VhostUserSetVringCall)?;
        }

        vu.set_vring_kick(queue_index, &queue_evts[queue_index])
            .map_err(Error::VhostUserSetVringKick)?;

        vu.set_vring_enable(queue_index, true)
            .map_err(Error::VhostUserSetVringEnable)?;
    }

    if let Some(slave_req_handler) = slave_req_handler {
        vu.set_slave_request_fd(slave_req_handler.get_tx_raw_fd())
            .map_err(Error::VhostUserSetSlaveRequestFd)
    } else {
        Ok(())
    }
}

pub fn reset_vhost_user(vu: &mut Master, num_queues: usize) -> Result<()> {
    for queue_index in 0..num_queues {
        // Disable the vrings.
        vu.set_vring_enable(queue_index, false)
            .map_err(Error::VhostUserSetVringEnable)?;
    }

    // Reset the owner.
    vu.reset_owner().map_err(Error::VhostUserResetOwner)
}

#[allow(clippy::too_many_arguments)]
pub fn reinitialize_vhost_user<S: VhostUserMasterReqHandler>(
    vu: &mut Master,
    mem: &GuestMemoryMmap,
    queues: Vec<Queue>,
    queue_evts: Vec<EventFd>,
    virtio_interrupt: &Arc<dyn VirtioInterrupt>,
    acked_features: u64,
    acked_protocol_features: u64,
    slave_req_handler: &Option<MasterReqHandler<S>>,
    inflight: Option<&mut Inflight>,
) -> Result<()> {
    vu.set_owner().map_err(Error::VhostUserSetOwner)?;
    vu.get_features().map_err(Error::VhostUserGetFeatures)?;

    if acked_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() != 0 {
        if let Some(acked_protocol_features) =
            VhostUserProtocolFeatures::from_bits(acked_protocol_features)
        {
            vu.set_protocol_features(acked_protocol_features)
                .map_err(Error::VhostUserSetProtocolFeatures)?;
        }
    }

    setup_vhost_user(
        vu,
        mem,
        queues,
        queue_evts,
        virtio_interrupt,
        acked_features,
        slave_req_handler,
        inflight,
    )
}

pub fn connect_vhost_user(
    server: bool,
    socket_path: &str,
    num_queues: u64,
    unlink_socket: bool,
) -> Result<Master> {
    if server {
        if unlink_socket {
            std::fs::remove_file(socket_path).map_err(Error::RemoveSocketPath)?;
        }

        info!("Binding vhost-user listener...");
        let listener = UnixListener::bind(socket_path).map_err(Error::BindSocket)?;
        info!("Waiting for incoming vhost-user connection...");
        let (stream, _) = listener.accept().map_err(Error::AcceptConnection)?;

        Ok(Master::from_stream(stream, num_queues))
    } else {
        let now = Instant::now();

        // Retry connecting for a full minute
        let err = loop {
            let err = match Master::connect(socket_path, num_queues) {
                Ok(m) => return Ok(m),
                Err(e) => e,
            };
            sleep(Duration::from_millis(100));

            if now.elapsed().as_secs() >= 60 {
                break err;
            }
        };

        error!(
            "Failed connecting the backend after trying for 1 minute: {:?}",
            err
        );
        Err(Error::VhostUserConnect)
    }
}
