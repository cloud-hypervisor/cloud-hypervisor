// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use libc;
use libc::EFD_NONBLOCK;
use std::os::unix::io::AsRawFd;
use std::vec::Vec;

use vm_memory::{Address, Error as MmapError, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};
use vmm_sys_util::eventfd::EventFd;

use super::super::Queue;
use super::{Error, Result};
use vhost_rs::vhost_user::{Master, VhostUserMaster};
use vhost_rs::{VhostBackend, VhostUserMemoryRegionInfo, VringConfigData};

#[derive(Debug, Clone)]
pub struct VhostUserConfig {
    pub sock: String,
    pub num_queues: usize,
    pub queue_size: u16,
}

pub fn setup_vhost_user_vring(
    vu: &mut Master,
    mem: &GuestMemoryMmap,
    queues: Vec<Queue>,
    queue_evts: Vec<EventFd>,
) -> Result<Vec<(EventFd, Queue)>> {
    let mut regions: Vec<VhostUserMemoryRegionInfo> = Vec::new();
    mem.with_regions_mut(|_, region| {
        let (mmap_handle, mmap_offset) = match region.file_offset() {
            Some(_file_offset) => (_file_offset.file().as_raw_fd(), _file_offset.start()),
            None => return Err(MmapError::NoMemoryRegion),
        };

        let vhost_user_net_reg = VhostUserMemoryRegionInfo {
            guest_phys_addr: region.start_addr().raw_value(),
            memory_size: region.len() as u64,
            userspace_addr: region.as_ptr() as u64,
            mmap_offset,
            mmap_handle,
        };

        regions.push(vhost_user_net_reg);

        Ok(())
    })
    .map_err(Error::VhostUserMemoryRegion)?;

    vu.set_mem_table(regions.as_slice())
        .map_err(Error::VhostUserSetMemTable)?;

    let mut vu_interrupt_list = Vec::new();

    for (queue_index, queue) in queues.into_iter().enumerate() {
        vu.set_vring_num(queue_index, queue.actual_size())
            .map_err(Error::VhostUserSetVringNum)?;

        let config_data = VringConfigData {
            queue_max_size: queue.get_max_size(),
            queue_size: queue.actual_size(),
            flags: 0u32,
            desc_table_addr: mem
                .get_host_address(queue.desc_table)
                .ok_or_else(|| Error::DescriptorTableAddress)? as u64,
            used_ring_addr: mem
                .get_host_address(queue.used_ring)
                .ok_or_else(|| Error::UsedAddress)? as u64,
            avail_ring_addr: mem
                .get_host_address(queue.avail_ring)
                .ok_or_else(|| Error::AvailAddress)? as u64,
            log_addr: None,
        };

        vu.set_vring_addr(queue_index, &config_data)
            .map_err(Error::VhostUserSetVringAddr)?;
        vu.set_vring_base(queue_index, 0u16)
            .map_err(Error::VhostUserSetVringBase)?;

        let vhost_user_interrupt = EventFd::new(EFD_NONBLOCK).map_err(Error::VhostIrqCreate)?;
        vu.set_vring_call(queue_index, &vhost_user_interrupt)
            .map_err(Error::VhostUserSetVringCall)?;
        vu_interrupt_list.push((vhost_user_interrupt, queue));

        vu.set_vring_kick(queue_index, &queue_evts[queue_index])
            .map_err(Error::VhostUserSetVringKick)?;

        vu.set_vring_enable(queue_index, true)
            .map_err(Error::VhostUserSetVringEnable)?;
    }

    Ok(vu_interrupt_list)
}

pub fn setup_vhost_user(
    vu: &mut Master,
    mem: &GuestMemoryMmap,
    queues: Vec<Queue>,
    queue_evts: Vec<EventFd>,
    acked_features: u64,
) -> Result<Vec<(EventFd, Queue)>> {
    // Set features based on the acked features from the guest driver.
    vu.set_features(acked_features)
        .map_err(Error::VhostUserSetFeatures)?;

    setup_vhost_user_vring(vu, mem, queues, queue_evts)
}

pub fn reset_vhost_user(vu: &mut Master, num_queues: usize) -> Result<()> {
    for queue_index in 0..num_queues {
        // Disable the vrings.
        vu.set_vring_enable(queue_index, false)
            .map_err(Error::VhostUserSetVringEnable)?;

        // Stop the vrings.
        vu.get_vring_base(queue_index)
            .map_err(Error::VhostUserSetFeatures)?;
    }

    // Reset the owner.
    vu.reset_owner().map_err(Error::VhostUserResetOwner)
}
