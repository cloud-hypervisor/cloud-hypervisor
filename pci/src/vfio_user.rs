// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::any::Any;
use std::collections::BTreeMap;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::prelude::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::{Duration, Instant};
use std::{io, result, thread};

use hypervisor::HypervisorVmError;
use log::{error, info, warn};
use thiserror::Error;
use vfio_bindings::bindings::vfio::*;
use vfio_ioctls::VfioIrq;
use vfio_user::{Client, Error as VfioUserError, IrqInfo, Region};
use vm_allocator::{AddressAllocator, MemorySlotAllocator, SystemAllocator};
use vm_device::dma_mapping::ExternalDmaMapping;
use vm_device::interrupt::{InterruptManager, InterruptSourceGroup, MsiIrqGroupConfig};
use vm_device::{BusDevice, Resource};
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::{
    Address, GuestAddress, GuestAddressSpace, GuestMemoryBackend, GuestMemoryRegion,
    GuestRegionMmap,
};
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
use vmm_sys_util::errno;
use vmm_sys_util::eventfd::EventFd;

use crate::mmap::MmapRegion;
use crate::vfio::{
    UserMemoryRegion, VFIO_COMMON_ID, Vfio, VfioCommon, VfioCommonConfig, VfioError,
};
use crate::{
    BarReprogrammingParams, PciBarConfiguration, PciBdf, PciDevice, PciDeviceError, PciSubclass,
    VfioPciError,
};

const RECONNECT_RETRY_INTERVAL: Duration = Duration::from_millis(100);
const WAIT_REPORT_INTERVAL: Duration = Duration::from_secs(30);

fn is_transport_error(e: &VfioUserError) -> bool {
    matches!(
        e,
        VfioUserError::Connect(_)
            | VfioUserError::StreamWrite(_)
            | VfioUserError::StreamRead(_)
            | VfioUserError::SendWithFd(_)
            | VfioUserError::ReceiveWithFd(_)
    )
}

fn set_irq_eventfds(client: &mut Client, index: u32, fds: &[RawFd]) -> Result<(), VfioUserError> {
    // Batch into blocks of 16 fds as sendmsg() has a size limit
    for (i, chunk) in fds.chunks(16).enumerate() {
        client.set_irqs(
            index,
            VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER,
            (i * 16) as u32,
            chunk.len() as u32,
            chunk,
        )?;
    }

    Ok(())
}

fn fd_error(e: &io::Error) -> VfioUserError {
    VfioUserError::SendWithFd(errno::Error::new(e.raw_os_error().unwrap_or(libc::EIO)))
}

struct DmaMapping {
    offset: u64,
    size: u64,
    fd: OwnedFd,
}

/// A vfio-user connection that survives the backend going away: the state the
/// backend was given is replayed on a new connection to the same socket.
pub struct VfioUserClient {
    socket: PathBuf,
    client: Client,
    dma_mappings: BTreeMap<u64, DmaMapping>,
    irqs: BTreeMap<u32, Vec<EventFd>>,
    generation: u64,
    backend_incompatible: bool,
    reconnect_disabled: Arc<AtomicBool>,
}

impl VfioUserClient {
    pub fn new(socket: &Path) -> Result<Self, VfioUserError> {
        Ok(Self {
            socket: socket.to_path_buf(),
            client: Client::new(socket)?,
            dma_mappings: BTreeMap::new(),
            irqs: BTreeMap::new(),
            generation: 0,
            backend_incompatible: false,
            reconnect_disabled: Arc::new(AtomicBool::new(false)),
        })
    }

    fn region(&self, index: u32) -> Option<&Region> {
        self.client.region(index)
    }

    fn resettable(&self) -> bool {
        self.client.resettable()
    }

    fn call<T>(
        &mut self,
        mut op: impl FnMut(&mut Client) -> Result<T, VfioUserError>,
    ) -> Result<T, VfioUserError> {
        match op(&mut self.client) {
            Err(e)
                if is_transport_error(&e)
                    && !self.reconnect_disabled.load(Ordering::Relaxed)
                    && self.reconnect() =>
            {
                op(&mut self.client)
            }
            result => result,
        }
    }

    fn reconnect(&mut self) -> bool {
        let start = Instant::now();
        let mut last_report = start;
        let mut last_error = String::new();
        if !self.backend_incompatible {
            warn!(
                "vfio-user backend on socket {} disconnected, reconnecting",
                self.socket.display()
            );
        }

        // The access waits for the backend however long it takes: a guest NVMe
        // driver that reads zeros from the registers gives up on the controller.
        loop {
            if self.reconnect_disabled.load(Ordering::Relaxed) {
                return false;
            }

            match Client::new(&self.socket).and_then(|client| self.restore(client)) {
                Ok(()) => {
                    self.generation += 1;
                    self.backend_incompatible = false;
                    info!(
                        "vfio-user backend on socket {} reconnected after {:?}",
                        self.socket.display(),
                        start.elapsed()
                    );
                    return true;
                }
                Err(e) if !is_transport_error(&e) => {
                    if !self.backend_incompatible {
                        error!(
                            "vfio-user backend on socket {} cannot take over the device: {e}",
                            self.socket.display()
                        );
                    }
                    self.backend_incompatible = true;
                    return false;
                }
                Err(e) => {
                    let error = e.to_string();
                    if error != last_error {
                        info!(
                            "Reconnecting to vfio-user backend on socket {} failed: {error}",
                            self.socket.display()
                        );
                        last_error = error;
                    }
                }
            }

            if self.backend_incompatible {
                return false;
            }

            if last_report.elapsed() >= WAIT_REPORT_INTERVAL {
                info!(
                    "Still waiting for vfio-user backend on socket {} after {:?}",
                    self.socket.display(),
                    start.elapsed()
                );
                last_report = Instant::now();
            }

            thread::sleep(RECONNECT_RETRY_INTERVAL);
        }
    }

    fn restore(&mut self, mut client: Client) -> Result<(), VfioUserError> {
        for index in 0..VFIO_PCI_NUM_REGIONS {
            let same = match (self.client.region(index), client.region(index)) {
                (Some(old), Some(new)) => old.flags == new.flags && old.size == new.size,
                (None, None) => true,
                _ => false,
            };
            if !same {
                return Err(VfioUserError::InvalidInput);
            }
        }

        for (iova, mapping) in &self.dma_mappings {
            client.dma_map(mapping.offset, *iova, mapping.size, mapping.fd.as_raw_fd())?;
        }

        for (index, event_fds) in &self.irqs {
            let fds: Vec<RawFd> = event_fds.iter().map(|e| e.as_raw_fd()).collect();
            set_irq_eventfds(&mut client, *index, &fds)?;
        }

        self.client = client;
        Ok(())
    }

    fn reset(&mut self) -> Result<(), VfioUserError> {
        self.call(Client::reset)
    }

    fn region_read(
        &mut self,
        index: u32,
        offset: u64,
        data: &mut [u8],
    ) -> Result<(), VfioUserError> {
        self.call(|client| client.region_read(index, offset, data))
    }

    fn region_write(&mut self, index: u32, offset: u64, data: &[u8]) -> Result<(), VfioUserError> {
        self.call(|client| client.region_write(index, offset, data))
    }

    fn get_irq_info(&mut self, index: u32) -> Result<IrqInfo, VfioUserError> {
        self.call(|client| client.get_irq_info(index))
    }

    fn enable_irq(&mut self, index: u32, event_fds: &[&EventFd]) -> Result<(), VfioUserError> {
        let event_fds = event_fds
            .iter()
            .map(|e| e.try_clone())
            .collect::<io::Result<Vec<_>>>()
            .map_err(|e| fd_error(&e))?;
        let fds: Vec<RawFd> = event_fds.iter().map(|e| e.as_raw_fd()).collect();
        self.call(|client| set_irq_eventfds(client, index, &fds))?;
        self.irqs.insert(index, event_fds);
        Ok(())
    }

    fn disable_irq(&mut self, index: u32) -> Result<(), VfioUserError> {
        self.irqs.remove(&index);
        self.call(|client| {
            client.set_irqs(
                index,
                VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_TRIGGER,
                0,
                0,
                &[],
            )
        })
    }

    fn unmask_irq(&mut self, index: u32) -> Result<(), VfioUserError> {
        self.call(|client| {
            client.set_irqs(
                index,
                VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_UNMASK,
                0,
                1,
                &[],
            )
        })
    }

    fn dma_map(
        &mut self,
        offset: u64,
        iova: u64,
        size: u64,
        fd: RawFd,
    ) -> Result<(), VfioUserError> {
        // SAFETY: the caller's fd stays open for the duration of this call
        let owned = unsafe { BorrowedFd::borrow_raw(fd) }
            .try_clone_to_owned()
            .map_err(|e| fd_error(&e))?;
        self.call(|client| client.dma_map(offset, iova, size, fd))?;
        self.dma_mappings.insert(
            iova,
            DmaMapping {
                offset,
                size,
                fd: owned,
            },
        );
        Ok(())
    }

    fn dma_unmap(&mut self, iova: u64, size: u64) -> Result<(), VfioUserError> {
        self.dma_mappings.remove(&iova);
        self.call(|client| client.dma_unmap(iova, size))
    }

    /// Lets another thread stop an ongoing reconnect: the flag is not
    /// behind the lock the waiting access holds.
    pub fn reconnect_disabled(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.reconnect_disabled)
    }

    fn shutdown(&self) -> Result<(), VfioUserError> {
        self.client.shutdown()
    }
}

pub struct VfioUserPciDevice {
    id: String,
    vm: Arc<dyn hypervisor::Vm>,
    client: Arc<Mutex<VfioUserClient>>,
    common: VfioCommon,
    memory_slot_allocator: MemorySlotAllocator,
    mapped_generation: u64,
}

#[derive(Error, Debug)]
pub enum VfioUserPciDeviceError {
    #[error("Client error")]
    Client(#[source] VfioUserError),
    #[error("Failed to map VFIO PCI region into guest")]
    MapRegionGuest(#[source] HypervisorVmError),
    #[error(
        "Sparse mmap area [0x{offset:x}, +0x{size:x}) outside the 0x{region_size:x} byte region"
    )]
    SparseAreaOutsideRegion {
        offset: u64,
        size: u64,
        region_size: u64,
    },
    #[error("Failed to DMA map")]
    DmaMap(#[source] VfioUserError),
    #[error("Failed to DMA unmap")]
    DmaUnmap(#[source] VfioUserError),
    #[error("Failed to create VfioCommon")]
    CreateVfioCommon(#[source] VfioPciError),
    #[error("Other OS error")]
    Other(#[source] io::Error),
}

#[derive(Copy, Clone)]
enum PciVfioUserSubclass {
    VfioUserSubclass = 0xff,
}

impl PciSubclass for PciVfioUserSubclass {
    fn get_register_value(&self) -> u8 {
        *self as u8
    }
}

impl VfioUserPciDevice {
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        vm: Arc<dyn hypervisor::Vm>,
        client: Arc<Mutex<VfioUserClient>>,
        msi_interrupt_manager: Arc<dyn InterruptManager<GroupConfig = MsiIrqGroupConfig>>,
        legacy_interrupt_group: Option<Arc<dyn InterruptSourceGroup>>,
        bdf: PciBdf,
        memory_slot_allocator: MemorySlotAllocator,
        snapshot: Option<&Snapshot>,
    ) -> Result<Self, VfioUserPciDeviceError> {
        let resettable = client.lock().unwrap().resettable();
        if resettable {
            client
                .lock()
                .unwrap()
                .reset()
                .map_err(VfioUserPciDeviceError::Client)?;
        }

        let vfio_wrapper = VfioUserClientWrapper {
            client: Arc::clone(&client),
        };

        let common = VfioCommon::new(
            msi_interrupt_manager,
            legacy_interrupt_group,
            Arc::new(vfio_wrapper) as Arc<dyn Vfio>,
            &PciVfioUserSubclass::VfioUserSubclass,
            bdf,
            vm_migration::snapshot_from_id(snapshot, VFIO_COMMON_ID),
            VfioCommonConfig::default(),
        )
        .map_err(VfioUserPciDeviceError::CreateVfioCommon)?;

        Ok(Self {
            id,
            vm,
            client,
            common,
            memory_slot_allocator,
            mapped_generation: 0,
        })
    }

    /// Map all of the MMIO regions.
    pub fn map_mmio_regions(&mut self) -> Result<(), VfioUserPciDeviceError> {
        self.mapped_generation = self.client.lock().unwrap().generation;
        for mmio_region in &mut self.common.mmio_regions {
            let region_flags = self
                .client
                .lock()
                .unwrap()
                .region(mmio_region.index)
                .unwrap()
                .flags;
            let file_offset = self
                .client
                .lock()
                .unwrap()
                .region(mmio_region.index)
                .unwrap()
                .file_offset
                .clone();

            let sparse_areas = self
                .client
                .lock()
                .unwrap()
                .region(mmio_region.index)
                .unwrap()
                .sparse_areas
                .clone();

            if region_flags & VFIO_REGION_INFO_FLAG_MMAP != 0 {
                let mut prot = 0;
                if region_flags & VFIO_REGION_INFO_FLAG_READ != 0 {
                    prot |= libc::PROT_READ;
                }
                if region_flags & VFIO_REGION_INFO_FLAG_WRITE != 0 {
                    prot |= libc::PROT_WRITE;
                }

                let mmaps = if sparse_areas.is_empty() {
                    vec![vfio_region_sparse_mmap_area {
                        offset: 0,
                        size: mmio_region.length,
                    }]
                } else {
                    sparse_areas
                };

                let file_offset = file_offset.as_ref().unwrap();

                for s in mmaps.iter() {
                    // The area layout comes from the untrusted backend. Never
                    // mmap or create a memory slot outside the BAR window.
                    if s.offset
                        .checked_add(s.size)
                        .is_none_or(|end| end > mmio_region.length)
                    {
                        return Err(VfioUserPciDeviceError::SparseAreaOutsideRegion {
                            offset: s.offset,
                            size: s.size,
                            region_size: mmio_region.length,
                        });
                    }

                    let mapping = match MmapRegion::mmap(
                        s.size,
                        prot,
                        file_offset.file().as_fd(),
                        file_offset.start(),
                        s.offset,
                    ) {
                        Ok(mapping) => Arc::new(mapping),
                        Err(e) => {
                            error!(
                                "Could not mmap sparse area (offset = 0x{:x}, size = 0x{:x}): {}",
                                s.offset, s.size, e
                            );
                            return Err(VfioUserPciDeviceError::Other(e));
                        }
                    };

                    let user_memory_region = UserMemoryRegion {
                        slot: self.memory_slot_allocator.next_memory_slot(),
                        start: mmio_region.start.0 + s.offset,
                        mapping,
                    };

                    // SAFETY: validity of len and host_addr guaranteed by hypervisor::mmap::MmapRegion
                    unsafe {
                        self.vm.create_user_memory_region(
                            user_memory_region.slot,
                            user_memory_region.start,
                            user_memory_region.mapping.len(),
                            user_memory_region.mapping.addr(),
                            false,
                            false,
                            hypervisor::MemoryVisibility::Shared,
                        )
                    }
                    .map_err(VfioUserPciDeviceError::MapRegionGuest)?;

                    mmio_region.user_memory_regions.push(user_memory_region);
                }
            }
        }

        Ok(())
    }

    fn unmap_mmio_regions(&mut self) {
        for mmio_region in self.common.mmio_regions.iter_mut() {
            for user_memory_region in mmio_region.user_memory_regions.drain(..) {
                // Remove region
                // SAFETY: guaranteed by hypervisor::mmap::MmapRegion invariants
                if let Err(e) = unsafe {
                    self.vm.remove_user_memory_region(
                        user_memory_region.slot,
                        user_memory_region.start,
                        user_memory_region.mapping.len(),
                        user_memory_region.mapping.addr(),
                        false,
                    )
                } {
                    error!("Could not remove the userspace memory region: {e}");
                }

                self.memory_slot_allocator
                    .free_memory_slot(user_memory_region.slot);
                // memory will be unmapped on drop
            }
        }
    }

    fn remap_after_reconnect(&mut self) {
        if self.client.lock().unwrap().generation == self.mapped_generation {
            return;
        }

        self.unmap_mmio_regions();
        if let Err(e) = self.map_mmio_regions() {
            error!(
                "Failed mapping the BARs of {} from the reconnected vfio-user backend: {e}",
                self.id
            );
        }
    }

    pub fn dma_map(
        &mut self,
        region: &GuestRegionMmap<AtomicBitmap>,
    ) -> Result<(), VfioUserPciDeviceError> {
        let (fd, offset) = match region.file_offset() {
            Some(_file_offset) => (_file_offset.file().as_raw_fd(), _file_offset.start()),
            None => return Ok(()),
        };

        let result = self
            .client
            .lock()
            .unwrap()
            .dma_map(offset, region.start_addr().raw_value(), region.len(), fd)
            .map_err(VfioUserPciDeviceError::DmaMap);
        self.remap_after_reconnect();
        result
    }

    pub fn dma_unmap(
        &mut self,
        region: &GuestRegionMmap<AtomicBitmap>,
    ) -> Result<(), VfioUserPciDeviceError> {
        let result = self
            .client
            .lock()
            .unwrap()
            .dma_unmap(region.start_addr().raw_value(), region.len())
            .map_err(VfioUserPciDeviceError::DmaUnmap);
        self.remap_after_reconnect();
        result
    }
}

impl BusDevice for VfioUserPciDevice {
    fn read(&mut self, base: u64, offset: u64, data: &mut [u8]) {
        self.read_bar(base, offset, data);
    }

    fn write(&mut self, base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        self.write_bar(base, offset, data)
    }
}

struct VfioUserClientWrapper {
    client: Arc<Mutex<VfioUserClient>>,
}

impl Vfio for VfioUserClientWrapper {
    fn region_read(&self, index: u32, offset: u64, data: &mut [u8]) {
        self.client
            .lock()
            .unwrap()
            .region_read(index, offset, data)
            .ok();
    }

    fn region_write(&self, index: u32, offset: u64, data: &[u8]) {
        self.client
            .lock()
            .unwrap()
            .region_write(index, offset, data)
            .ok();
    }

    fn get_irq_info(&self, irq_index: u32) -> Option<VfioIrq> {
        self.client
            .lock()
            .unwrap()
            .get_irq_info(irq_index)
            .ok()
            .map(|i| VfioIrq {
                index: i.index,
                flags: i.flags,
                count: i.count,
            })
    }

    fn enable_irq(&self, irq_index: u32, event_fds: Vec<&EventFd>) -> Result<(), VfioError> {
        info!(
            "Enabling IRQ {:x} number of fds = {:?}",
            irq_index,
            event_fds.len()
        );
        self.client
            .lock()
            .unwrap()
            .enable_irq(irq_index, &event_fds)
            .map_err(VfioError::VfioUser)
    }

    fn disable_irq(&self, irq_index: u32) -> Result<(), VfioError> {
        info!("Disabling IRQ {irq_index:x}");
        self.client
            .lock()
            .unwrap()
            .disable_irq(irq_index)
            .map_err(VfioError::VfioUser)
    }

    fn unmask_irq(&self, irq_index: u32) -> Result<(), VfioError> {
        info!("Unmasking IRQ {irq_index:x}");
        self.client
            .lock()
            .unwrap()
            .unmask_irq(irq_index)
            .map_err(VfioError::VfioUser)
    }
}

impl PciDevice for VfioUserPciDevice {
    fn allocate_bars(
        &mut self,
        allocator: &mut SystemAllocator,
        mmio32_allocator: &mut AddressAllocator,
        mmio64_allocator: &mut AddressAllocator,
        resources: Option<Vec<Resource>>,
    ) -> Result<Vec<PciBarConfiguration>, PciDeviceError> {
        self.common.allocate_bars(
            allocator,
            mmio32_allocator,
            mmio64_allocator,
            resources.as_deref(),
        )
    }

    fn free_bars(
        &mut self,
        allocator: &mut SystemAllocator,
        mmio32_allocator: &mut AddressAllocator,
        mmio64_allocator: &mut AddressAllocator,
    ) -> Result<(), PciDeviceError> {
        self.common
            .free_bars(allocator, mmio32_allocator, mmio64_allocator)
    }

    fn restore_bar_addr(&mut self, params: &BarReprogrammingParams) {
        self.common.configuration.restore_bar_addr(params);
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn write_config_register(
        &mut self,
        reg_idx: usize,
        offset: u64,
        data: &[u8],
    ) -> (Vec<BarReprogrammingParams>, Option<Arc<Barrier>>) {
        let result = self.common.write_config_register(reg_idx, offset, data);
        self.remap_after_reconnect();
        result
    }

    fn read_config_register(&mut self, reg_idx: usize) -> u32 {
        let value = self.common.read_config_register(reg_idx);
        self.remap_after_reconnect();
        value
    }

    fn read_bar(&mut self, base: u64, offset: u64, data: &mut [u8]) {
        self.common.read_bar(base, offset, data);
        self.remap_after_reconnect();
    }

    fn write_bar(&mut self, base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        let barrier = self.common.write_bar(base, offset, data);
        self.remap_after_reconnect();
        barrier
    }

    fn move_bar(&mut self, old_base: u64, new_base: u64) -> Result<(), io::Error> {
        info!("Moving BAR 0x{old_base:x} -> 0x{new_base:x}");
        for mmio_region in self.common.mmio_regions.iter_mut() {
            if mmio_region.start.raw_value() == old_base {
                mmio_region.start = GuestAddress(new_base);

                for user_memory_region in mmio_region.user_memory_regions.iter_mut() {
                    // Remove old region
                    // SAFETY: only valid regions are in user_memory_regions
                    unsafe {
                        self.vm.remove_user_memory_region(
                            user_memory_region.slot,
                            user_memory_region.start,
                            user_memory_region.mapping.len(),
                            user_memory_region.mapping.addr(),
                            false,
                        )
                    }
                    .map_err(io::Error::other)?;

                    // Update the user memory region with the correct start address.
                    if new_base > old_base {
                        user_memory_region.start += new_base - old_base;
                    } else {
                        user_memory_region.start -= old_base - new_base;
                    }

                    // Insert new region
                    // SAFETY: only valid regions are in user_memory_regions
                    unsafe {
                        self.vm.create_user_memory_region(
                            user_memory_region.slot,
                            user_memory_region.start,
                            user_memory_region.mapping.len(),
                            user_memory_region.mapping.addr(),
                            false,
                            false,
                            hypervisor::MemoryVisibility::Shared,
                        )
                    }
                    .map_err(io::Error::other)?;
                }
                info!("Moved bar 0x{old_base:x} -> 0x{new_base:x}");
            }
        }

        Ok(())
    }

    fn id(&self) -> Option<String> {
        Some(self.id.clone())
    }
}

impl Drop for VfioUserPciDevice {
    fn drop(&mut self) {
        self.client
            .lock()
            .unwrap()
            .reconnect_disabled
            .store(true, Ordering::Relaxed);
        self.unmap_mmio_regions();

        if let Some(msix) = &self.common.interrupt.msix
            && msix.bar.enabled()
        {
            self.common.disable_msix();
        }

        if let Some(msi) = &self.common.interrupt.msi
            && msi.cfg.enabled()
        {
            self.common.disable_msi();
        }

        if self.common.interrupt.intx_in_use() {
            self.common.disable_intx();
        }

        if let Err(e) = self.client.lock().unwrap().shutdown() {
            error!("Failed shutting down vfio-user client: {e}");
        }
    }
}

impl Pausable for VfioUserPciDevice {}

impl Snapshottable for VfioUserPciDevice {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> result::Result<Snapshot, MigratableError> {
        let mut vfio_pci_dev_snapshot = Snapshot::default();

        // Snapshot VfioCommon
        vfio_pci_dev_snapshot.add_snapshot(self.common.id(), self.common.snapshot()?);

        Ok(vfio_pci_dev_snapshot)
    }
}
impl Transportable for VfioUserPciDevice {}
impl Migratable for VfioUserPciDevice {}

pub struct VfioUserDmaMapping<M: GuestAddressSpace> {
    client: Arc<Mutex<VfioUserClient>>,
    memory: Arc<M>,
}

impl<M: GuestAddressSpace> VfioUserDmaMapping<M> {
    pub fn new(client: Arc<Mutex<VfioUserClient>>, memory: Arc<M>) -> Self {
        Self { client, memory }
    }
}

impl<M: GuestAddressSpace + Sync + Send> ExternalDmaMapping for VfioUserDmaMapping<M>
where
    M::M: GuestMemoryBackend,
{
    fn map(&self, iova: u64, gpa: u64, size: u64) -> result::Result<(), io::Error> {
        let mem = self.memory.memory();
        let guest_addr = GuestAddress(gpa);
        let Some(region) = mem.find_region(guest_addr) else {
            return Err(io::Error::other(format!("Region not found for 0x{gpa:x}")));
        };

        // Check that the range fits in the region.
        let region_offset = guest_addr
            .checked_offset_from(region.start_addr())
            .ok_or_else(|| io::Error::other(format!("gpa 0x{gpa:x} below region start")))?;
        let region_remaining = (region.len())
            .checked_sub(region_offset)
            .ok_or_else(|| io::Error::other(format!("gpa 0x{gpa:x} past region end")))?;
        if size > region_remaining {
            return Err(io::Error::other(format!(
                "DMA map (gpa 0x{gpa:x}, size 0x{size:x}) extends past region end"
            )));
        }

        let file_offset = region.file_offset().ok_or_else(|| {
            io::Error::other(format!("region for gpa 0x{gpa:x} has no backing file"))
        })?;
        let offset = region_offset
            .checked_add(file_offset.start())
            .ok_or_else(|| io::Error::other("offset overflow in DMA map"))?;

        self.client
            .lock()
            .unwrap()
            .dma_map(offset, iova, size, file_offset.file().as_raw_fd())
            .map_err(|e| io::Error::other(format!("Error mapping region: {e}")))
    }

    fn unmap(&self, iova: u64, size: u64) -> result::Result<(), io::Error> {
        self.client
            .lock()
            .unwrap()
            .dma_unmap(iova, size)
            .map_err(|e| io::Error::other(format!("Error unmapping region: {e}")))
    }
}
