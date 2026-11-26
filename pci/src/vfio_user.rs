// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::any::Any;
use std::os::unix::prelude::AsRawFd;
use std::sync::{Arc, Barrier, Mutex};
use std::{io, process, result};

use log::{error, info};
use thiserror::Error;
use vfio_bindings::bindings::vfio::*;
use vfio_ioctls::VfioIrq;
use vfio_user::{Client, Error as VfioUserError};
use vm_allocator::{
    AddressAllocator, GuestMemoryNotification, GuestRegion, GuestRegionError, MemorySlotAllocator,
    SystemAllocator,
};
use vm_device::dma_mapping::{ExternalDmaMapping, ExternalDmaMappingError};
use vm_device::interrupt::{InterruptManager, InterruptSourceGroup, MsiIrqGroupConfig};
use vm_device::{BusDevice, Resource};
use vm_memory::{Address, GuestAddress, GuestAddressSpace, GuestMemoryBackend, GuestMemoryRegion};
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
use vmm_sys_util::eventfd::EventFd;

use crate::vfio::{
    VFIO_COMMON_ID, Vfio, VfioBarMemoryRegion, VfioCommon, VfioCommonConfig, VfioError,
    find_alignment,
};
use crate::{
    BarReprogrammingParams, PciBarConfiguration, PciBdf, PciDevice, PciDeviceError, PciSubclass,
    VfioPciError,
};

pub struct VfioUserPciDevice {
    id: String,
    vm: Arc<dyn hypervisor::Vm>,
    client: Arc<Mutex<Client>>,
    common: VfioCommon,
    memory_slot_allocator: Arc<MemorySlotAllocator>,
    bdf: PciBdf,
}

#[derive(Error, Debug)]
pub enum VfioUserPciDeviceError {
    #[error("Client error")]
    Client(#[source] VfioUserError),
    #[error("Failed to map VFIO PCI region into guest")]
    MapRegionGuest(#[source] GuestRegionError),
    #[error("Missing region {0}")]
    MissingRegion(u32),
    #[error("Missing file descriptor for mappable region {0}")]
    MissingRegionFd(u32),
    #[error(
        "Sparse mmap area [0x{offset:x}, +0x{size:x}) outside the 0x{region_size:x} byte region"
    )]
    SparseAreaOutsideRegion {
        offset: u64,
        size: u64,
        region_size: u64,
    },
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
        client: Arc<Mutex<Client>>,
        msi_interrupt_manager: Arc<dyn InterruptManager<GroupConfig = MsiIrqGroupConfig>>,
        legacy_interrupt_group: Option<Arc<dyn InterruptSourceGroup>>,
        bdf: PciBdf,
        memory_slot_allocator: Arc<MemorySlotAllocator>,
        snapshot: Option<&Snapshot>,
    ) -> Result<Self, VfioUserPciDeviceError> {
        {
            let mut client = client.lock().unwrap();
            if client.resettable() {
                client.reset().map_err(VfioUserPciDeviceError::Client)?;
            }
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
            bdf,
        })
    }

    /// Map all of the MMIO regions.
    pub fn map_mmio_regions(&mut self) -> Result<(), VfioUserPciDeviceError> {
        for mmio_region in &mut self.common.bars {
            let (region_flags, region_size, file_offset, sparse_areas) = {
                let client = self.client.lock().unwrap();
                let region = client
                    .region(mmio_region.index)
                    .ok_or(VfioUserPciDeviceError::MissingRegion(mmio_region.index))?;
                (
                    region.flags,
                    region.size,
                    region.file_offset.clone(),
                    region.sparse_areas.clone(),
                )
            };

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
                        size: region_size,
                    }]
                } else {
                    sparse_areas
                };

                let file_offset = file_offset
                    .as_ref()
                    .ok_or(VfioUserPciDeviceError::MissingRegionFd(mmio_region.index))?;

                // MSI-X relocation can enlarge the guest BAR beyond the
                // backend region. Both limits must constrain the mappings.
                let mmap_limit = region_size.min(mmio_region.length);
                for s in mmaps.iter() {
                    // The area layout comes from the untrusted backend. Never
                    // mmap or create a memory slot outside either region.
                    if s.offset
                        .checked_add(s.size)
                        .is_none_or(|end| end > mmap_limit)
                    {
                        return Err(VfioUserPciDeviceError::SparseAreaOutsideRegion {
                            offset: s.offset,
                            size: s.size,
                            region_size: mmap_limit,
                        });
                    }

                    let offset = file_offset.start().checked_add(s.offset).ok_or_else(|| {
                        VfioUserPciDeviceError::Other(io::Error::other("File offset overflows"))
                    })?;
                    let size = usize::try_from(s.size)
                        .map_err(|e| VfioUserPciDeviceError::Other(io::Error::other(e)))?;
                    let mapping = GuestRegion::from_file(
                        vm_memory::FileOffset::from_arc(Arc::clone(file_offset.arc()), offset),
                        size,
                        find_alignment(size),
                        GuestAddress(mmio_region.start.0 + s.offset),
                        prot,
                        Arc::clone(&self.vm),
                        Arc::clone(&self.memory_slot_allocator),
                    )
                    .map_err(|e| VfioUserPciDeviceError::Other(io::Error::other(e)))?;
                    mapping
                        .register()
                        .map_err(VfioUserPciDeviceError::MapRegionGuest)?;
                    let mapping = Arc::new(Mutex::new(mapping));

                    let bar_memory_region = VfioBarMemoryRegion {
                        offset: s.offset,
                        region: mapping,
                        p2p_mapping: None,
                    };

                    mmio_region.bar_memory_regions.push(bar_memory_region);
                }
            }
        }

        Ok(())
    }

    fn unmap_mmio_regions(&mut self) {
        for mmio_region in &mut self.common.bars {
            mmio_region.bar_memory_regions.clear();
        }
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
    client: Arc<Mutex<Client>>,
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

    fn enable_irq(
        &self,
        irq_index: u32,
        mut start: u32,
        event_fds: &[Option<&EventFd>],
    ) -> Result<(), VfioError> {
        info!(
            "Enabling IRQ {irq_index:x} start = {start} count = {}",
            event_fds.len()
        );
        let mut client = self.client.lock().unwrap();
        // A request without descriptors clears its whole range.
        for run in event_fds.chunk_by(|a, b| a.is_some() == b.is_some()) {
            // Only requests carrying descriptors need the sendmsg() limit.
            let batch_size = if run[0].is_some() { 16 } else { run.len() };
            for chunk in run.chunks(batch_size) {
                let fds: Vec<_> = chunk.iter().flatten().map(|fd| fd.as_raw_fd()).collect();
                client
                    .set_irqs(
                        irq_index,
                        VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER,
                        start,
                        chunk.len() as u32,
                        &fds,
                    )
                    .map_err(VfioError::VfioUser)?;
                start += chunk.len() as u32;
            }
        }

        Ok(())
    }

    fn disable_irq(&self, irq_index: u32) -> Result<(), VfioError> {
        info!("Disabling IRQ {irq_index:x}");
        self.client
            .lock()
            .unwrap()
            .set_irqs(
                irq_index,
                VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_TRIGGER,
                0,
                0,
                &[],
            )
            .map_err(VfioError::VfioUser)
    }

    fn unmask_irq(&self, irq_index: u32) -> Result<(), VfioError> {
        info!("Unmasking IRQ {irq_index:x}");
        self.client
            .lock()
            .unwrap()
            .set_irqs(
                irq_index,
                VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_UNMASK,
                0,
                1,
                &[],
            )
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
        self.common.write_config_register(reg_idx, offset, data)
    }

    fn read_config_register(&mut self, reg_idx: usize) -> u32 {
        self.common.read_config_register(reg_idx)
    }

    fn read_bar(&mut self, base: u64, offset: u64, data: &mut [u8]) {
        self.common.read_bar(base, offset, data);
    }

    fn write_bar(&mut self, base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        self.common.write_bar(base, offset, data)
    }

    fn move_bar(&mut self, bar_idx: usize, new_base: u64) -> Result<(), io::Error> {
        info!("Moving BAR {bar_idx} -> 0x{new_base:x}");
        self.common
            .move_bar(bar_idx, new_base)
            .map_err(io::Error::other)
    }

    fn id(&self) -> Option<String> {
        Some(self.id.clone())
    }

    fn bdf(&self) -> PciBdf {
        self.bdf
    }

    fn is_removable(&self) -> bool {
        true
    }
}

impl Drop for VfioUserPciDevice {
    fn drop(&mut self) {
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
    client: Arc<Mutex<Client>>,
    memory: Arc<M>,
}

impl<M: GuestAddressSpace> VfioUserDmaMapping<M> {
    pub fn new(client: Arc<Mutex<Client>>, memory: Arc<M>) -> Self {
        Self { client, memory }
    }
}

impl<M: GuestAddressSpace + Sync + Send> ExternalDmaMapping for VfioUserDmaMapping<M>
where
    M::M: GuestMemoryBackend,
{
    fn map(&self, iova: u64, gpa: u64, size: u64) -> result::Result<(), ExternalDmaMappingError> {
        let mem = self.memory.memory();
        let guest_addr = GuestAddress(gpa);
        let region = mem
            .find_region(guest_addr)
            .ok_or(ExternalDmaMappingError::RegionNotFound { gpa })?;

        // Check that the range fits in the region.
        let region_offset = guest_addr
            .checked_offset_from(region.start_addr())
            .ok_or(ExternalDmaMappingError::InvalidGuestRange { gpa, size })?;
        let region_remaining = (region.len())
            .checked_sub(region_offset)
            .ok_or(ExternalDmaMappingError::InvalidGuestRange { gpa, size })?;
        if size > region_remaining {
            return Err(ExternalDmaMappingError::InvalidGuestRange { gpa, size });
        }

        let file_offset = region
            .file_offset()
            .ok_or(ExternalDmaMappingError::MissingBackingFile { gpa })?;
        let offset = region_offset.checked_add(file_offset.start()).ok_or(
            ExternalDmaMappingError::FileOffsetOverflow {
                file_offset: file_offset.start(),
                region_offset,
            },
        )?;

        self.client
            .lock()
            .unwrap()
            .dma_map(offset, iova, size, file_offset.file().as_raw_fd())
            .map_err(|e| ExternalDmaMappingError::Map {
                iova,
                gpa,
                size,
                source: e.into(),
            })
    }

    fn unmap(&self, iova: u64, size: u64) -> result::Result<(), ExternalDmaMappingError> {
        self.client
            .lock()
            .unwrap()
            .dma_unmap(iova, size)
            .map_err(|e| ExternalDmaMappingError::Unmap {
                iova,
                size,
                source: e.into(),
            })
    }
}

impl<M: GuestAddressSpace + Send + Sync> GuestMemoryNotification for VfioUserDmaMapping<M>
where
    M::M: GuestMemoryBackend,
{
    fn region_added(&self, region: &GuestRegion) {
        if region.file_offset().is_some() {
            let gpa = region.start_addr().raw_value();
            if let Err(e) = self.map(gpa, gpa, region.len()) {
                error!("FATAL: vfio-user: {e:?}");
                process::exit(1);
            }
        }
    }

    fn region_removed(&self, region: &GuestRegion) {
        if region.file_offset().is_some()
            && let Err(e) = self.unmap(region.start_addr().raw_value(), region.len())
        {
            error!("FATAL: vfio-user: {e:?}");
            process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Write;
    use std::thread;

    use vfio_user::{DmaMapFlags, DmaUnmapFlags, IrqInfo, Server, ServerBackend};
    use vmm_sys_util::tempdir::TempDir;

    use super::*;

    #[derive(Default)]
    struct IrqBackend {
        requests: Vec<(u32, u32, usize)>,
    }

    impl ServerBackend for IrqBackend {
        fn region_read(&mut self, _: u32, _: u64, _: &mut [u8]) -> io::Result<()> {
            unreachable!()
        }

        fn region_write(&mut self, _: u32, _: u64, _: &[u8]) -> io::Result<()> {
            unreachable!()
        }

        fn dma_map(
            &mut self,
            _: DmaMapFlags,
            _: u64,
            _: u64,
            _: u64,
            _: Option<File>,
        ) -> io::Result<()> {
            unreachable!()
        }

        fn dma_unmap(&mut self, _: DmaUnmapFlags, _: u64, _: u64) -> io::Result<()> {
            unreachable!()
        }

        fn reset(&mut self) -> io::Result<()> {
            unreachable!()
        }

        fn set_irqs(
            &mut self,
            index: u32,
            flags: u32,
            start: u32,
            count: u32,
            fds: Vec<File>,
        ) -> io::Result<()> {
            assert_eq!(index, VFIO_PCI_MSIX_IRQ_INDEX);
            assert_eq!(
                flags,
                VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER
            );
            self.requests.push((start, count, fds.len()));
            for (offset, mut fd) in fds.into_iter().enumerate() {
                fd.write_all(&(u64::from(start) + offset as u64 + 1).to_ne_bytes())?;
            }
            Ok(())
        }
    }

    #[test]
    fn irq_ranges_preserve_indices_and_batch_descriptors() {
        let dir = TempDir::new().unwrap();
        let path = dir.as_path().join("vfio.sock");
        let irqs = (0..=VFIO_PCI_MSIX_IRQ_INDEX)
            .map(|index| IrqInfo {
                index,
                flags: VFIO_IRQ_INFO_EVENTFD,
                count: 2048,
            })
            .collect();
        let server = Server::new(&path, false, irqs, Vec::new()).unwrap();
        let server_thread = thread::spawn(move || {
            let mut backend = IrqBackend::default();
            server.run(&mut backend).unwrap();
            backend.requests
        });
        let wrapper = VfioUserClientWrapper {
            client: Arc::new(Mutex::new(Client::new(&path).unwrap())),
        };
        assert_eq!(
            wrapper.get_irq_info(VFIO_PCI_MSIX_IRQ_INDEX).unwrap().flags,
            VFIO_IRQ_INFO_EVENTFD
        );
        let fds: Vec<_> = (0..33)
            .map(|_| EventFd::new(libc::EFD_NONBLOCK).unwrap())
            .collect();
        let mut entries = vec![None, None];
        entries.extend(fds[..17].iter().map(Some));
        entries.push(None);
        entries.extend(fds[17..].iter().map(Some));
        entries.extend([None; 17]);
        wrapper
            .enable_irq(VFIO_PCI_MSIX_IRQ_INDEX, 1000, &entries)
            .unwrap();

        for (fd, index) in fds.iter().zip((1002..1019).chain(1020..1036)) {
            assert_eq!(fd.read().unwrap(), index + 1);
        }
        wrapper.client.lock().unwrap().shutdown().unwrap();
        assert_eq!(
            server_thread.join().unwrap(),
            vec![
                (1000, 2, 0),
                (1002, 16, 16),
                (1018, 1, 1),
                (1019, 1, 0),
                (1020, 16, 16),
                (1036, 17, 0),
            ]
        );
    }
}
