// Copyright © 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{
    ActivateError, ActivateResult, GuestMemoryMmap, VirtioCommon, VirtioDevice, VirtioInterrupt,
    VirtioInterruptType, DEVICE_ACKNOWLEDGE, DEVICE_DRIVER, DEVICE_DRIVER_OK, DEVICE_FEATURES_OK,
    VIRTIO_F_IOMMU_PLATFORM,
};
use std::{
    io, result,
    sync::{atomic::Ordering, Arc, Mutex},
};
use thiserror::Error;
use vhost::{
    vdpa::{VhostVdpa, VhostVdpaIovaRange},
    vhost_kern::vdpa::VhostKernVdpa,
    vhost_kern::VhostKernFeatures,
    VhostBackend, VringConfigData,
};
use virtio_queue::Queue;
use vm_device::dma_mapping::ExternalDmaMapping;
use vm_memory::{GuestAddress, GuestAddressSpace, GuestMemory, GuestMemoryAtomic};
use vm_virtio::AccessPlatform;
use vmm_sys_util::eventfd::EventFd;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to create vhost-vdpa: {0}")]
    CreateVhostVdpa(vhost::Error),
    #[error("Failed to map DMA range: {0}")]
    DmaMap(vhost::Error),
    #[error("Failed to unmap DMA range: {0}")]
    DmaUnmap(vhost::Error),
    #[error("Failed to get address range")]
    GetAddressRange,
    #[error("Failed to get the available index from the virtio queue: {0}")]
    GetAvailableIndex(virtio_queue::Error),
    #[error("Get virtio device identifier: {0}")]
    GetDeviceId(vhost::Error),
    #[error("Failed to get backend specific features: {0}")]
    GetBackendFeatures(vhost::Error),
    #[error("Failed to get virtio features: {0}")]
    GetFeatures(vhost::Error),
    #[error("Failed to get the IOVA range: {0}")]
    GetIovaRange(vhost::Error),
    #[error("Failed to get queue size: {0}")]
    GetVringNum(vhost::Error),
    #[error("Invalid IOVA range: {0}-{1}")]
    InvalidIovaRange(u64, u64),
    #[error("Missing VIRTIO_F_ACCESS_PLATFORM feature")]
    MissingAccessPlatformVirtioFeature,
    #[error("Failed to reset owner: {0}")]
    ResetOwner(vhost::Error),
    #[error("Failed to set backend specific features: {0}")]
    SetBackendFeatures(vhost::Error),
    #[error("Failed to set eventfd notifying about a configuration change: {0}")]
    SetConfigCall(vhost::Error),
    #[error("Failed to set virtio features: {0}")]
    SetFeatures(vhost::Error),
    #[error("Failed to set memory table: {0}")]
    SetMemTable(vhost::Error),
    #[error("Failed to set owner: {0}")]
    SetOwner(vhost::Error),
    #[error("Failed to set virtio status: {0}")]
    SetStatus(vhost::Error),
    #[error("Failed to set vring address: {0}")]
    SetVringAddr(vhost::Error),
    #[error("Failed to set vring base: {0}")]
    SetVringBase(vhost::Error),
    #[error("Failed to set vring eventfd when buffer are used: {0}")]
    SetVringCall(vhost::Error),
    #[error("Failed to enable/disable vring: {0}")]
    SetVringEnable(vhost::Error),
    #[error("Failed to set vring eventfd when new descriptors are available: {0}")]
    SetVringKick(vhost::Error),
    #[error("Failed to set vring size: {0}")]
    SetVringNum(vhost::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct Vdpa {
    common: VirtioCommon,
    id: String,
    vhost: VhostKernVdpa<GuestMemoryAtomic<GuestMemoryMmap>>,
    iova_range: VhostVdpaIovaRange,
    enabled_num_queues: Option<usize>,
    backend_features: u64,
}

impl Vdpa {
    pub fn new(
        id: String,
        device_path: &str,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        num_queues: u16,
    ) -> Result<Self> {
        let mut vhost = VhostKernVdpa::new(device_path, mem).map_err(Error::CreateVhostVdpa)?;
        vhost.set_owner().map_err(Error::SetOwner)?;
        let device_type = vhost.get_device_id().map_err(Error::GetDeviceId)?;
        let queue_size = vhost.get_vring_num().map_err(Error::GetVringNum)?;
        let avail_features = vhost.get_features().map_err(Error::GetFeatures)?;
        let backend_features = vhost
            .get_backend_features()
            .map_err(Error::GetBackendFeatures)?;
        vhost.set_backend_features_acked(backend_features);

        // TODO: https://github.com/cloud-hypervisor/cloud-hypervisor/issues/3861
        // There's a bug in rust-vmm/vhost crate. Let's wait for next release
        // to fix it. Below is the correct code once the bug will be fixed:
        //
        // let iova_range = vhost.get_iova_range().map_err(Error::GetIovaRange)?;
        let iova_range = VhostVdpaIovaRange {
            first: 0,
            last: 0xffff_ffff_ffff_ffff,
        };

        if avail_features & (1u64 << VIRTIO_F_IOMMU_PLATFORM) == 0 {
            return Err(Error::MissingAccessPlatformVirtioFeature);
        }

        Ok(Vdpa {
            common: VirtioCommon {
                device_type,
                queue_sizes: vec![queue_size; num_queues as usize],
                avail_features,
                min_queues: num_queues,
                ..Default::default()
            },
            id,
            vhost,
            iova_range,
            enabled_num_queues: None,
            backend_features,
        })
    }

    fn enable_vrings(&mut self, num_queues: usize, enable: bool) -> Result<()> {
        for queue_index in 0..num_queues {
            self.vhost
                .set_vring_enable(queue_index, enable)
                .map_err(Error::SetVringEnable)?;
        }

        self.enabled_num_queues = if enable { Some(num_queues) } else { None };

        Ok(())
    }

    fn activate_vdpa(
        &mut self,
        _mem: &GuestMemoryMmap,
        virtio_interrupt: &Arc<dyn VirtioInterrupt>,
        queues: Vec<Queue<GuestMemoryAtomic<GuestMemoryMmap>>>,
        queue_evts: Vec<EventFd>,
    ) -> Result<()> {
        self.vhost
            .set_features(self.common.acked_features)
            .map_err(Error::SetFeatures)?;
        self.vhost
            .set_backend_features(self.backend_features)
            .map_err(Error::SetBackendFeatures)?;

        for (queue_index, queue) in queues.iter().enumerate() {
            let queue_max_size = queue.max_size();
            let queue_size = queue.state.size;
            self.vhost
                .set_vring_num(queue_index, queue_size)
                .map_err(Error::SetVringNum)?;

            let config_data = VringConfigData {
                queue_max_size,
                queue_size,
                flags: 0u32,
                desc_table_addr: queue.state.desc_table.0,
                used_ring_addr: queue.state.used_ring.0,
                avail_ring_addr: queue.state.avail_ring.0,
                log_addr: None,
            };

            self.vhost
                .set_vring_addr(queue_index, &config_data)
                .map_err(Error::SetVringAddr)?;
            self.vhost
                .set_vring_base(
                    queue_index,
                    queue
                        .avail_idx(Ordering::Acquire)
                        .map_err(Error::GetAvailableIndex)?
                        .0,
                )
                .map_err(Error::SetVringBase)?;

            if let Some(eventfd) =
                virtio_interrupt.notifier(VirtioInterruptType::Queue(queue_index as u16))
            {
                self.vhost
                    .set_vring_call(queue_index, &eventfd)
                    .map_err(Error::SetVringCall)?;
            }

            self.vhost
                .set_vring_kick(queue_index, &queue_evts[queue_index])
                .map_err(Error::SetVringKick)?;
        }

        // Setup the config eventfd if there is one
        if let Some(eventfd) = virtio_interrupt.notifier(VirtioInterruptType::Config) {
            self.vhost
                .set_config_call(&eventfd)
                .map_err(Error::SetConfigCall)?;
        }

        self.enable_vrings(queues.len(), true)?;

        self.vhost
            .set_status(
                (DEVICE_ACKNOWLEDGE | DEVICE_DRIVER | DEVICE_DRIVER_OK | DEVICE_FEATURES_OK) as u8,
            )
            .map_err(Error::SetStatus)
    }

    fn reset_vdpa(&mut self) -> Result<()> {
        if let Some(num_queues) = self.enabled_num_queues {
            self.enable_vrings(num_queues, false)?;
        }

        self.vhost.set_status(0).map_err(Error::SetStatus)
    }

    fn dma_map(&self, iova: u64, size: u64, host_vaddr: *const u8, readonly: bool) -> Result<()> {
        let iova_last = iova + size - 1;
        if iova < self.iova_range.first || iova_last > self.iova_range.last {
            return Err(Error::InvalidIovaRange(iova, iova_last));
        }

        self.vhost
            .dma_map(iova, size, host_vaddr, readonly)
            .map_err(Error::DmaMap)
    }

    fn dma_unmap(&self, iova: u64, size: u64) -> Result<()> {
        let iova_last = iova + size - 1;
        if iova < self.iova_range.first || iova_last > self.iova_range.last {
            return Err(Error::InvalidIovaRange(iova, iova_last));
        }

        self.vhost.dma_unmap(iova, size).map_err(Error::DmaUnmap)
    }
}

impl VirtioDevice for Vdpa {
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
        if let Err(e) = self.vhost.get_config(offset as u32, data) {
            error!("Failed reading virtio config: {}", e);
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        if let Err(e) = self.vhost.set_config(offset as u32, data) {
            error!("Failed writing virtio config: {}", e);
        }
    }

    fn activate(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        virtio_interrupt: Arc<dyn VirtioInterrupt>,
        queues: Vec<Queue<GuestMemoryAtomic<GuestMemoryMmap>>>,
        queue_evts: Vec<EventFd>,
        _resample_evt: Option<EventFd>,
    ) -> ActivateResult {
        self.activate_vdpa(&mem.memory(), &virtio_interrupt, queues, queue_evts)
            .map_err(ActivateError::ActivateVdpa)?;

        // Store the virtio interrupt handler as we need to return it on reset
        self.common.interrupt_cb = Some(virtio_interrupt);

        event!("vdpa", "activated", "id", &self.id);
        Ok(())
    }

    fn reset(&mut self) -> Option<Arc<dyn VirtioInterrupt>> {
        if let Err(e) = self.reset_vdpa() {
            error!("Failed to reset vhost-vdpa: {:?}", e);
            return None;
        }

        event!("vdpa", "reset", "id", &self.id);

        // Return the virtio interrupt handler
        self.common.interrupt_cb.take()
    }

    fn set_access_platform(&mut self, access_platform: Arc<dyn AccessPlatform>) {
        self.common.set_access_platform(access_platform)
    }
}

pub struct VdpaDmaMapping<M: GuestAddressSpace> {
    device: Arc<Mutex<Vdpa>>,
    memory: Arc<M>,
}

impl<M: GuestAddressSpace> VdpaDmaMapping<M> {
    pub fn new(device: Arc<Mutex<Vdpa>>, memory: Arc<M>) -> Self {
        Self { device, memory }
    }
}

impl<M: GuestAddressSpace + Sync + Send> ExternalDmaMapping for VdpaDmaMapping<M> {
    fn map(&self, iova: u64, gpa: u64, size: u64) -> result::Result<(), io::Error> {
        let mem = self.memory.memory();
        let guest_addr = GuestAddress(gpa);
        let user_addr = if mem.check_range(guest_addr, size as usize) {
            mem.get_host_address(guest_addr).unwrap() as *const u8
        } else {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "failed to convert guest address 0x{:x} into \
                     host user virtual address",
                    gpa
                ),
            ));
        };

        self.device
            .lock()
            .unwrap()
            .dma_map(iova, size, user_addr, false)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "failed to map memory for vDPA device, \
                         iova 0x{:x}, gpa 0x{:x}, size 0x{:x}: {:?}",
                        iova, gpa, size, e
                    ),
                )
            })
    }

    fn unmap(&self, iova: u64, size: u64) -> std::result::Result<(), std::io::Error> {
        self.device
            .lock()
            .unwrap()
            .dma_unmap(iova, size)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "failed to unmap memory for vDPA device, \
                     iova 0x{:x}, size 0x{:x}: {:?}",
                        iova, size, e
                    ),
                )
            })
    }
}
