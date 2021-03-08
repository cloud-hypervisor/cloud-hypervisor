// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::super::{Descriptor, Queue};
use super::{Error, Result};
use crate::{get_host_address_range, VirtioInterrupt, VirtioInterruptType};
use libc::EFD_NONBLOCK;
use std::convert::TryInto;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::vec::Vec;
use vhost::vhost_user::{Master, VhostUserMaster};
use vhost::{VhostBackend, VhostUserMemoryRegionInfo, VringConfigData};
use vm_memory::{Address, Error as MmapError, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};
use vmm_sys_util::eventfd::EventFd;

#[derive(Debug, Clone)]
pub struct VhostUserConfig {
    pub socket: String,
    pub num_queues: usize,
    pub queue_size: u16,
}

pub fn update_mem_table(vu: &mut Master, mem: &GuestMemoryMmap) -> Result<()> {
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

    Ok(())
}

pub fn setup_vhost_user_vring(
    vu: &mut Master,
    mem: &GuestMemoryMmap,
    queues: Vec<Queue>,
    queue_evts: Vec<EventFd>,
    virtio_interrupt: &Arc<dyn VirtioInterrupt>,
) -> Result<Vec<(Option<EventFd>, Queue)>> {
    // Let's first provide the memory table to the backend.
    update_mem_table(vu, mem)?;

    let mut vu_interrupt_list = Vec::new();

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
        vu.set_vring_base(queue_index, 0u16)
            .map_err(Error::VhostUserSetVringBase)?;

        if let Some(eventfd) = virtio_interrupt.notifier(&VirtioInterruptType::Queue, Some(&queue))
        {
            vu.set_vring_call(queue_index, &eventfd)
                .map_err(Error::VhostUserSetVringCall)?;
            vu_interrupt_list.push((None, queue));
        } else {
            let eventfd = EventFd::new(EFD_NONBLOCK).map_err(Error::VhostIrqCreate)?;
            vu.set_vring_call(queue_index, &eventfd)
                .map_err(Error::VhostUserSetVringCall)?;
            vu_interrupt_list.push((Some(eventfd), queue));
        }

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
    virtio_interrupt: &Arc<dyn VirtioInterrupt>,
    acked_features: u64,
) -> Result<Vec<(Option<EventFd>, Queue)>> {
    // Set features based on the acked features from the guest driver.
    vu.set_features(acked_features)
        .map_err(Error::VhostUserSetFeatures)?;

    setup_vhost_user_vring(vu, mem, queues, queue_evts, virtio_interrupt)
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
