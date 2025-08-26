// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//

use std::any::Any;
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::ptr::null_mut;
use std::sync::{Arc, Barrier, Mutex};

use anyhow::anyhow;
use byteorder::{ByteOrder, LittleEndian};
use hypervisor::HypervisorVmError;
use libc::{_SC_PAGESIZE, sysconf};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use vfio_bindings::bindings::vfio::*;
use vfio_ioctls::{
    VfioContainer, VfioDevice, VfioIrq, VfioRegionInfoCap, VfioRegionSparseMmapArea,
};
use vm_allocator::page_size::{
    align_page_size_down, align_page_size_up, is_4k_aligned, is_4k_multiple, is_page_size_aligned,
};
use vm_allocator::{AddressAllocator, MemorySlotAllocator, SystemAllocator};
use vm_device::dma_mapping::ExternalDmaMapping;
use vm_device::interrupt::{
    InterruptIndex, InterruptManager, InterruptSourceGroup, MsiIrqGroupConfig,
};
use vm_device::{BusDevice, Resource};
use vm_memory::{Address, GuestAddress, GuestAddressSpace, GuestMemory, GuestUsize};
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
use vmm_sys_util::eventfd::EventFd;

use crate::msi::{MSI_CONFIG_ID, MsiConfigState};
use crate::msix::MsixConfigState;
use crate::{
    BarReprogrammingParams, MSIX_CONFIG_ID, MSIX_TABLE_ENTRY_SIZE, MsiCap, MsiConfig, MsixCap,
    MsixConfig, PCI_CONFIGURATION_ID, PciBarConfiguration, PciBarPrefetchable, PciBarRegionType,
    PciBdf, PciCapabilityId, PciClassCode, PciConfiguration, PciDevice, PciDeviceError,
    PciExpressCapabilityId, PciHeaderType, PciSubclass, msi_num_enabled_vectors,
};

pub(crate) const VFIO_COMMON_ID: &str = "vfio_common";

#[derive(Debug, Error)]
pub enum VfioPciError {
    #[error("Failed to create user memory region")]
    CreateUserMemoryRegion(#[source] HypervisorVmError),
    #[error("Failed to DMA map: {0} for device {1} (guest BDF: {2})")]
    DmaMap(#[source] vfio_ioctls::VfioError, PathBuf, PciBdf),
    #[error("Failed to DMA unmap: {0} for device {1} (guest BDF: {2})")]
    DmaUnmap(#[source] vfio_ioctls::VfioError, PathBuf, PciBdf),
    #[error("Failed to enable INTx")]
    EnableIntx(#[source] VfioError),
    #[error("Failed to enable MSI")]
    EnableMsi(#[source] VfioError),
    #[error("Failed to enable MSI-x")]
    EnableMsix(#[source] VfioError),
    #[error("Failed to mmap the area")]
    MmapArea,
    #[error("Failed to notifier's eventfd")]
    MissingNotifier,
    #[error("Invalid region alignment")]
    RegionAlignment,
    #[error("Invalid region size")]
    RegionSize,
    #[error("Failed to retrieve MsiConfigState")]
    RetrieveMsiConfigState(#[source] anyhow::Error),
    #[error("Failed to retrieve MsixConfigState")]
    RetrieveMsixConfigState(#[source] anyhow::Error),
    #[error("Failed to retrieve PciConfigurationState")]
    RetrievePciConfigurationState(#[source] anyhow::Error),
    #[error("Failed to retrieve VfioCommonState")]
    RetrieveVfioCommonState(#[source] anyhow::Error),
}

#[derive(Copy, Clone)]
enum PciVfioSubclass {
    VfioSubclass = 0xff,
}

impl PciSubclass for PciVfioSubclass {
    fn get_register_value(&self) -> u8 {
        *self as u8
    }
}

enum InterruptUpdateAction {
    EnableMsi,
    DisableMsi,
    EnableMsix,
    DisableMsix,
}

#[derive(Serialize, Deserialize)]
struct IntxState {
    enabled: bool,
}

pub(crate) struct VfioIntx {
    interrupt_source_group: Arc<dyn InterruptSourceGroup>,
    enabled: bool,
}

#[derive(Serialize, Deserialize)]
struct MsiState {
    cap: MsiCap,
    cap_offset: u32,
}

pub(crate) struct VfioMsi {
    pub(crate) cfg: MsiConfig,
    cap_offset: u32,
    interrupt_source_group: Arc<dyn InterruptSourceGroup>,
}

impl VfioMsi {
    fn update(&mut self, offset: u64, data: &[u8]) -> Option<InterruptUpdateAction> {
        let old_enabled = self.cfg.enabled();

        self.cfg.update(offset, data);

        let new_enabled = self.cfg.enabled();

        if !old_enabled && new_enabled {
            return Some(InterruptUpdateAction::EnableMsi);
        }

        if old_enabled && !new_enabled {
            return Some(InterruptUpdateAction::DisableMsi);
        }

        None
    }
}

#[derive(Serialize, Deserialize)]
struct MsixState {
    cap: MsixCap,
    cap_offset: u32,
    bdf: u32,
}

pub(crate) struct VfioMsix {
    pub(crate) bar: MsixConfig,
    cap: MsixCap,
    cap_offset: u32,
    interrupt_source_group: Arc<dyn InterruptSourceGroup>,
}

impl VfioMsix {
    fn update(&mut self, offset: u64, data: &[u8]) -> Option<InterruptUpdateAction> {
        let old_enabled = self.bar.enabled();

        // Update "Message Control" word
        if offset == 2 && data.len() == 2 {
            self.bar.set_msg_ctl(LittleEndian::read_u16(data));
        }

        let new_enabled = self.bar.enabled();

        if !old_enabled && new_enabled {
            return Some(InterruptUpdateAction::EnableMsix);
        }

        if old_enabled && !new_enabled {
            return Some(InterruptUpdateAction::DisableMsix);
        }

        None
    }

    fn table_accessed(&self, bar_index: u32, offset: u64) -> bool {
        let table_offset: u64 = u64::from(self.cap.table_offset());
        let table_size: u64 = u64::from(self.cap.table_size()) * (MSIX_TABLE_ENTRY_SIZE as u64);
        let table_bir: u32 = self.cap.table_bir();

        bar_index == table_bir && offset >= table_offset && offset < table_offset + table_size
    }
}

pub(crate) struct Interrupt {
    pub(crate) intx: Option<VfioIntx>,
    pub(crate) msi: Option<VfioMsi>,
    pub(crate) msix: Option<VfioMsix>,
}

impl Interrupt {
    fn update_msi(&mut self, offset: u64, data: &[u8]) -> Option<InterruptUpdateAction> {
        if let Some(msi) = &mut self.msi {
            let action = msi.update(offset, data);
            return action;
        }

        None
    }

    fn update_msix(&mut self, offset: u64, data: &[u8]) -> Option<InterruptUpdateAction> {
        if let Some(msix) = &mut self.msix {
            let action = msix.update(offset, data);
            return action;
        }

        None
    }

    fn accessed(&self, offset: u64) -> Option<(PciCapabilityId, u64)> {
        if let Some(msi) = &self.msi
            && offset >= u64::from(msi.cap_offset)
            && offset < u64::from(msi.cap_offset) + msi.cfg.size()
        {
            return Some((
                PciCapabilityId::MessageSignalledInterrupts,
                u64::from(msi.cap_offset),
            ));
        }

        if let Some(msix) = &self.msix
            && offset == u64::from(msix.cap_offset)
        {
            return Some((PciCapabilityId::MsiX, u64::from(msix.cap_offset)));
        }

        None
    }

    fn msix_table_accessed(&self, bar_index: u32, offset: u64) -> bool {
        if let Some(msix) = &self.msix {
            return msix.table_accessed(bar_index, offset);
        }

        false
    }

    fn msix_write_table(&mut self, offset: u64, data: &[u8]) {
        if let Some(msix) = &mut self.msix {
            let offset = offset - u64::from(msix.cap.table_offset());
            msix.bar.write_table(offset, data)
        }
    }

    fn msix_read_table(&self, offset: u64, data: &mut [u8]) {
        if let Some(msix) = &self.msix {
            let offset = offset - u64::from(msix.cap.table_offset());
            msix.bar.read_table(offset, data)
        }
    }

    pub(crate) fn intx_in_use(&self) -> bool {
        if let Some(intx) = &self.intx {
            return intx.enabled;
        }

        false
    }
}

#[derive(Copy, Clone)]
pub struct UserMemoryRegion {
    pub slot: u32,
    pub start: u64,
    pub size: u64,
    pub host_addr: u64,
}

#[derive(Clone)]
pub struct MmioRegion {
    pub start: GuestAddress,
    pub length: GuestUsize,
    pub(crate) type_: PciBarRegionType,
    pub(crate) index: u32,
    pub(crate) user_memory_regions: Vec<UserMemoryRegion>,
}

trait MmioRegionRange {
    fn check_range(&self, guest_addr: u64, size: u64) -> bool;
    fn find_user_address(&self, guest_addr: u64) -> Result<u64, io::Error>;
}

impl MmioRegionRange for Vec<MmioRegion> {
    // Check if a guest address is within the range of mmio regions
    fn check_range(&self, guest_addr: u64, size: u64) -> bool {
        for region in self.iter() {
            let Some(guest_addr_end) = guest_addr.checked_add(size) else {
                return false;
            };
            let Some(region_end) = region.start.raw_value().checked_add(region.length) else {
                return false;
            };
            if guest_addr >= region.start.raw_value() && guest_addr_end <= region_end {
                return true;
            }
        }
        false
    }

    // Locate the user region address for a guest address within all mmio regions
    fn find_user_address(&self, guest_addr: u64) -> Result<u64, io::Error> {
        for region in self.iter() {
            for user_region in region.user_memory_regions.iter() {
                if guest_addr >= user_region.start
                    && guest_addr < user_region.start + user_region.size
                {
                    return Ok(user_region.host_addr + (guest_addr - user_region.start));
                }
            }
        }

        Err(io::Error::other(format!(
            "unable to find user address: 0x{guest_addr:x}"
        )))
    }
}

#[derive(Debug, Error)]
pub enum VfioError {
    #[error("Kernel VFIO error")]
    KernelVfio(#[source] vfio_ioctls::VfioError),
    #[error("VFIO user error")]
    VfioUser(#[source] vfio_user::Error),
}

pub(crate) trait Vfio: Send + Sync {
    fn read_config_byte(&self, offset: u32) -> u8 {
        let mut data: [u8; 1] = [0];
        self.read_config(offset, &mut data);
        data[0]
    }

    fn read_config_word(&self, offset: u32) -> u16 {
        let mut data: [u8; 2] = [0, 0];
        self.read_config(offset, &mut data);
        u16::from_le_bytes(data)
    }

    fn read_config_dword(&self, offset: u32) -> u32 {
        let mut data: [u8; 4] = [0, 0, 0, 0];
        self.read_config(offset, &mut data);
        u32::from_le_bytes(data)
    }

    fn write_config_dword(&self, offset: u32, buf: u32) {
        let data: [u8; 4] = buf.to_le_bytes();
        self.write_config(offset, &data)
    }

    fn read_config(&self, offset: u32, data: &mut [u8]) {
        self.region_read(VFIO_PCI_CONFIG_REGION_INDEX, offset.into(), data.as_mut());
    }

    fn write_config(&self, offset: u32, data: &[u8]) {
        self.region_write(VFIO_PCI_CONFIG_REGION_INDEX, offset.into(), data)
    }

    fn enable_msi(&self, fds: Vec<&EventFd>) -> Result<(), VfioError> {
        self.enable_irq(VFIO_PCI_MSI_IRQ_INDEX, fds)
    }

    fn disable_msi(&self) -> Result<(), VfioError> {
        self.disable_irq(VFIO_PCI_MSI_IRQ_INDEX)
    }

    fn enable_msix(&self, fds: Vec<&EventFd>) -> Result<(), VfioError> {
        self.enable_irq(VFIO_PCI_MSIX_IRQ_INDEX, fds)
    }

    fn disable_msix(&self) -> Result<(), VfioError> {
        self.disable_irq(VFIO_PCI_MSIX_IRQ_INDEX)
    }

    fn region_read(&self, _index: u32, _offset: u64, _data: &mut [u8]) {
        unimplemented!()
    }

    fn region_write(&self, _index: u32, _offset: u64, _data: &[u8]) {
        unimplemented!()
    }

    fn get_irq_info(&self, _irq_index: u32) -> Option<VfioIrq> {
        unimplemented!()
    }

    fn enable_irq(&self, _irq_index: u32, _event_fds: Vec<&EventFd>) -> Result<(), VfioError> {
        unimplemented!()
    }

    fn disable_irq(&self, _irq_index: u32) -> Result<(), VfioError> {
        unimplemented!()
    }

    fn unmask_irq(&self, _irq_index: u32) -> Result<(), VfioError> {
        unimplemented!()
    }
}

struct VfioDeviceWrapper {
    device: Arc<VfioDevice>,
}

impl VfioDeviceWrapper {
    fn new(device: Arc<VfioDevice>) -> Self {
        Self { device }
    }
}

impl Vfio for VfioDeviceWrapper {
    fn region_read(&self, index: u32, offset: u64, data: &mut [u8]) {
        self.device.region_read(index, data, offset)
    }

    fn region_write(&self, index: u32, offset: u64, data: &[u8]) {
        self.device.region_write(index, data, offset)
    }

    fn get_irq_info(&self, irq_index: u32) -> Option<VfioIrq> {
        self.device.get_irq_info(irq_index).copied()
    }

    fn enable_irq(&self, irq_index: u32, event_fds: Vec<&EventFd>) -> Result<(), VfioError> {
        self.device
            .enable_irq(irq_index, event_fds)
            .map_err(VfioError::KernelVfio)
    }

    fn disable_irq(&self, irq_index: u32) -> Result<(), VfioError> {
        self.device
            .disable_irq(irq_index)
            .map_err(VfioError::KernelVfio)
    }

    fn unmask_irq(&self, irq_index: u32) -> Result<(), VfioError> {
        self.device
            .unmask_irq(irq_index)
            .map_err(VfioError::KernelVfio)
    }
}

#[derive(Serialize, Deserialize)]
struct VfioCommonState {
    intx_state: Option<IntxState>,
    msi_state: Option<MsiState>,
    msix_state: Option<MsixState>,
}

pub(crate) struct ConfigPatch {
    mask: u32,
    patch: u32,
}

pub(crate) struct VfioCommon {
    pub(crate) configuration: PciConfiguration,
    pub(crate) mmio_regions: Vec<MmioRegion>,
    pub(crate) interrupt: Interrupt,
    pub(crate) msi_interrupt_manager: Arc<dyn InterruptManager<GroupConfig = MsiIrqGroupConfig>>,
    pub(crate) legacy_interrupt_group: Option<Arc<dyn InterruptSourceGroup>>,
    pub(crate) vfio_wrapper: Arc<dyn Vfio>,
    pub(crate) patches: HashMap<usize, ConfigPatch>,
    x_nv_gpudirect_clique: Option<u8>,
}

impl VfioCommon {
    pub(crate) fn new(
        msi_interrupt_manager: Arc<dyn InterruptManager<GroupConfig = MsiIrqGroupConfig>>,
        legacy_interrupt_group: Option<Arc<dyn InterruptSourceGroup>>,
        vfio_wrapper: Arc<dyn Vfio>,
        subclass: &dyn PciSubclass,
        bdf: PciBdf,
        snapshot: Option<Snapshot>,
        x_nv_gpudirect_clique: Option<u8>,
    ) -> Result<Self, VfioPciError> {
        let pci_configuration_state =
            vm_migration::state_from_id(snapshot.as_ref(), PCI_CONFIGURATION_ID).map_err(|e| {
                VfioPciError::RetrievePciConfigurationState(anyhow!(
                    "Failed to get PciConfigurationState from Snapshot: {}",
                    e
                ))
            })?;

        let configuration = PciConfiguration::new(
            0,
            0,
            0,
            PciClassCode::Other,
            subclass,
            None,
            PciHeaderType::Device,
            0,
            0,
            None,
            pci_configuration_state,
        );

        let mut vfio_common = VfioCommon {
            mmio_regions: Vec::new(),
            configuration,
            interrupt: Interrupt {
                intx: None,
                msi: None,
                msix: None,
            },
            msi_interrupt_manager,
            legacy_interrupt_group,
            vfio_wrapper,
            patches: HashMap::new(),
            x_nv_gpudirect_clique,
        };

        let state: Option<VfioCommonState> = snapshot
            .as_ref()
            .map(|s| s.to_state())
            .transpose()
            .map_err(|e| {
                VfioPciError::RetrieveVfioCommonState(anyhow!(
                    "Failed to get VfioCommonState from Snapshot: {}",
                    e
                ))
            })?;
        let msi_state =
            vm_migration::state_from_id(snapshot.as_ref(), MSI_CONFIG_ID).map_err(|e| {
                VfioPciError::RetrieveMsiConfigState(anyhow!(
                    "Failed to get MsiConfigState from Snapshot: {}",
                    e
                ))
            })?;
        let msix_state =
            vm_migration::state_from_id(snapshot.as_ref(), MSIX_CONFIG_ID).map_err(|e| {
                VfioPciError::RetrieveMsixConfigState(anyhow!(
                    "Failed to get MsixConfigState from Snapshot: {}",
                    e
                ))
            })?;

        if let Some(state) = state.as_ref() {
            vfio_common.set_state(state, msi_state, msix_state)?;
        } else {
            vfio_common.parse_capabilities(bdf);
            vfio_common.initialize_legacy_interrupt()?;
        }

        Ok(vfio_common)
    }

    /// In case msix table offset is not page size aligned, we need do some fixup to achieve it.
    /// Because we don't want the MMIO RW region and trap region overlap each other.
    fn fixup_msix_region(&mut self, bar_id: u32, region_size: u64) -> u64 {
        if let Some(msix) = self.interrupt.msix.as_mut() {
            let msix_cap = &mut msix.cap;

            // Suppose table_bir equals to pba_bir here. Am I right?
            let (table_offset, table_size) = msix_cap.table_range();
            if is_page_size_aligned(table_offset) || msix_cap.table_bir() != bar_id {
                return region_size;
            }

            let (pba_offset, pba_size) = msix_cap.pba_range();
            let msix_sz = align_page_size_up(table_size + pba_size);
            // Expand region to hold RW and trap region which both page size aligned
            let size = std::cmp::max(region_size * 2, msix_sz * 2);
            // let table starts from the middle of the region
            msix_cap.table_set_offset((size / 2) as u32);
            msix_cap.pba_set_offset((size / 2 + pba_offset - table_offset) as u32);

            size
        } else {
            // MSI-X not supported for this device
            region_size
        }
    }

    // The `allocator` argument is unused on `aarch64`
    #[allow(unused_variables)]
    pub(crate) fn allocate_bars(
        &mut self,
        allocator: &Arc<Mutex<SystemAllocator>>,
        mmio32_allocator: &mut AddressAllocator,
        mmio64_allocator: &mut AddressAllocator,
        resources: Option<Vec<Resource>>,
    ) -> Result<Vec<PciBarConfiguration>, PciDeviceError> {
        let mut bars = Vec::new();
        let mut bar_id = VFIO_PCI_BAR0_REGION_INDEX;

        // Going through all regular regions to compute the BAR size.
        // We're not saving the BAR address to restore it, because we
        // are going to allocate a guest address for each BAR and write
        // that new address back.
        while bar_id < VFIO_PCI_CONFIG_REGION_INDEX {
            let mut region_size: u64 = 0;
            let mut region_type = PciBarRegionType::Memory32BitRegion;
            let mut prefetchable = PciBarPrefetchable::NotPrefetchable;
            let mut flags: u32 = 0;

            let mut restored_bar_addr = None;
            if let Some(resources) = &resources {
                for resource in resources {
                    if let Resource::PciBar {
                        index,
                        base,
                        size,
                        type_,
                        ..
                    } = resource
                        && *index == bar_id as usize
                    {
                        restored_bar_addr = Some(GuestAddress(*base));
                        region_size = *size;
                        region_type = PciBarRegionType::from(*type_);
                        break;
                    }
                }
                if restored_bar_addr.is_none() {
                    bar_id += 1;
                    continue;
                }
            } else {
                let bar_offset = if bar_id == VFIO_PCI_ROM_REGION_INDEX {
                    (PCI_ROM_EXP_BAR_INDEX * 4) as u32
                } else {
                    PCI_CONFIG_BAR_OFFSET + bar_id * 4
                };

                // First read flags
                flags = self.vfio_wrapper.read_config_dword(bar_offset);

                // Is this an IO BAR?
                let io_bar = if bar_id != VFIO_PCI_ROM_REGION_INDEX {
                    matches!(flags & PCI_CONFIG_IO_BAR, PCI_CONFIG_IO_BAR)
                } else {
                    false
                };

                // Is this a 64-bit BAR?
                let is_64bit_bar = if bar_id != VFIO_PCI_ROM_REGION_INDEX {
                    matches!(
                        flags & PCI_CONFIG_MEMORY_BAR_64BIT,
                        PCI_CONFIG_MEMORY_BAR_64BIT
                    )
                } else {
                    false
                };

                if matches!(
                    flags & PCI_CONFIG_BAR_PREFETCHABLE,
                    PCI_CONFIG_BAR_PREFETCHABLE
                ) {
                    prefetchable = PciBarPrefetchable::Prefetchable
                };

                // To get size write all 1s
                self.vfio_wrapper
                    .write_config_dword(bar_offset, 0xffff_ffff);

                // And read back BAR value. The device will write zeros for bits it doesn't care about
                let mut lower = self.vfio_wrapper.read_config_dword(bar_offset);

                if io_bar {
                    // Mask flag bits (lowest 2 for I/O bars)
                    lower &= !0b11;

                    // BAR is not enabled
                    if lower == 0 {
                        bar_id += 1;
                        continue;
                    }

                    // IO BAR
                    region_type = PciBarRegionType::IoRegion;

                    // Invert bits and add 1 to calculate size
                    region_size = (!lower + 1) as u64;
                } else if is_64bit_bar {
                    // 64 bits Memory BAR
                    region_type = PciBarRegionType::Memory64BitRegion;

                    // Query size of upper BAR of 64-bit BAR
                    let upper_offset: u32 = PCI_CONFIG_BAR_OFFSET + (bar_id + 1) * 4;
                    self.vfio_wrapper
                        .write_config_dword(upper_offset, 0xffff_ffff);
                    let upper = self.vfio_wrapper.read_config_dword(upper_offset);

                    let mut combined_size = (u64::from(upper) << 32) | u64::from(lower);

                    // Mask out flag bits (lowest 4 for memory bars)
                    combined_size &= !0b1111;

                    // BAR is not enabled
                    if combined_size == 0 {
                        bar_id += 1;
                        continue;
                    }

                    // Invert and add 1 to to find size
                    region_size = !combined_size + 1;
                } else {
                    region_type = PciBarRegionType::Memory32BitRegion;

                    // Mask out flag bits (lowest 4 for memory bars)
                    lower &= !0b1111;

                    if lower == 0 {
                        bar_id += 1;
                        continue;
                    }

                    // Invert and add 1 to to find size
                    region_size = (!lower + 1) as u64;
                }
            }

            let bar_addr = match region_type {
                PciBarRegionType::IoRegion => {
                    // The address needs to be 4 bytes aligned.
                    allocator
                        .lock()
                        .unwrap()
                        .allocate_io_addresses(restored_bar_addr, region_size, Some(0x4))
                        .ok_or(PciDeviceError::IoAllocationFailed(region_size))?
                }
                PciBarRegionType::Memory32BitRegion => {
                    // BAR allocation must be naturally aligned
                    mmio32_allocator
                        .allocate(restored_bar_addr, region_size, Some(region_size))
                        .ok_or(PciDeviceError::IoAllocationFailed(region_size))?
                }
                PciBarRegionType::Memory64BitRegion => {
                    // We need do some fixup to keep MMIO RW region and msix cap region page size
                    // aligned.
                    region_size = self.fixup_msix_region(bar_id, region_size);
                    mmio64_allocator
                        .allocate(
                            restored_bar_addr,
                            region_size,
                            Some(std::cmp::max(
                                // SAFETY: FFI call. Trivially safe.
                                unsafe { sysconf(_SC_PAGESIZE) as GuestUsize },
                                region_size,
                            )),
                        )
                        .ok_or(PciDeviceError::IoAllocationFailed(region_size))?
                }
            };

            // We can now build our BAR configuration block.
            let bar = PciBarConfiguration::default()
                .set_index(bar_id as usize)
                .set_address(bar_addr.raw_value())
                .set_size(region_size)
                .set_region_type(region_type)
                .set_prefetchable(prefetchable);

            if bar_id == VFIO_PCI_ROM_REGION_INDEX {
                self.configuration
                    .add_pci_rom_bar(&bar, flags & 0x1)
                    .map_err(|e| PciDeviceError::IoRegistrationFailed(bar_addr.raw_value(), e))?;
            } else {
                self.configuration
                    .add_pci_bar(&bar)
                    .map_err(|e| PciDeviceError::IoRegistrationFailed(bar_addr.raw_value(), e))?;
            }

            bars.push(bar);
            self.mmio_regions.push(MmioRegion {
                start: bar_addr,
                length: region_size,
                type_: region_type,
                index: bar_id,
                user_memory_regions: Vec::new(),
            });

            bar_id += 1;
            if region_type == PciBarRegionType::Memory64BitRegion {
                bar_id += 1;
            }
        }

        Ok(bars)
    }

    // The `allocator` argument is unused on `aarch64`
    #[allow(unused_variables)]
    pub(crate) fn free_bars(
        &mut self,
        allocator: &mut SystemAllocator,
        mmio32_allocator: &mut AddressAllocator,
        mmio64_allocator: &mut AddressAllocator,
    ) -> Result<(), PciDeviceError> {
        for region in self.mmio_regions.iter() {
            match region.type_ {
                PciBarRegionType::IoRegion => {
                    allocator.free_io_addresses(region.start, region.length);
                }
                PciBarRegionType::Memory32BitRegion => {
                    mmio32_allocator.free(region.start, region.length);
                }
                PciBarRegionType::Memory64BitRegion => {
                    mmio64_allocator.free(region.start, region.length);
                }
            }
        }
        Ok(())
    }

    fn parse_msix_capabilities(&mut self, cap: u8) -> MsixCap {
        let msg_ctl = self.vfio_wrapper.read_config_word((cap + 2).into());

        let table = self.vfio_wrapper.read_config_dword((cap + 4).into());

        let pba = self.vfio_wrapper.read_config_dword((cap + 8).into());

        MsixCap {
            msg_ctl,
            table,
            pba,
        }
    }

    fn initialize_msix(
        &mut self,
        msix_cap: MsixCap,
        cap_offset: u32,
        bdf: PciBdf,
        state: Option<MsixConfigState>,
    ) {
        let interrupt_source_group = self
            .msi_interrupt_manager
            .create_group(MsiIrqGroupConfig {
                base: 0,
                count: msix_cap.table_size() as InterruptIndex,
            })
            .unwrap();

        let msix_config = MsixConfig::new(
            msix_cap.table_size(),
            interrupt_source_group.clone(),
            bdf.into(),
            state,
        )
        .unwrap();

        self.interrupt.msix = Some(VfioMsix {
            bar: msix_config,
            cap: msix_cap,
            cap_offset,
            interrupt_source_group,
        });
    }

    fn parse_msi_capabilities(&mut self, cap: u8) -> u16 {
        self.vfio_wrapper.read_config_word((cap + 2).into())
    }

    fn initialize_msi(&mut self, msg_ctl: u16, cap_offset: u32, state: Option<MsiConfigState>) {
        let interrupt_source_group = self
            .msi_interrupt_manager
            .create_group(MsiIrqGroupConfig {
                base: 0,
                count: msi_num_enabled_vectors(msg_ctl) as InterruptIndex,
            })
            .unwrap();

        let msi_config = MsiConfig::new(msg_ctl, interrupt_source_group.clone(), state).unwrap();

        self.interrupt.msi = Some(VfioMsi {
            cfg: msi_config,
            cap_offset,
            interrupt_source_group,
        });
    }

    /// Returns true, if the device claims to have a PCI capability list.
    fn has_capabilities(&self) -> bool {
        let status = self.vfio_wrapper.read_config_word(PCI_CONFIG_STATUS_OFFSET);
        status & PCI_CONFIG_STATUS_CAPABILITIES_LIST != 0
    }

    fn get_msix_cap_idx(&self) -> Option<usize> {
        if !self.has_capabilities() {
            return None;
        }

        let mut cap_next = self
            .vfio_wrapper
            .read_config_byte(PCI_CONFIG_CAPABILITY_OFFSET)
            & PCI_CONFIG_CAPABILITY_PTR_MASK;

        while cap_next != 0 {
            let cap_id = self.vfio_wrapper.read_config_byte(cap_next.into());
            if PciCapabilityId::from(cap_id) == PciCapabilityId::MsiX {
                return Some(cap_next as usize);
            } else {
                let cap_ptr = self.vfio_wrapper.read_config_byte((cap_next + 1).into())
                    & PCI_CONFIG_CAPABILITY_PTR_MASK;

                // See parse_capabilities below for an explanation.
                if cap_ptr != cap_next {
                    cap_next = cap_ptr;
                } else {
                    break;
                }
            }
        }

        None
    }

    fn parse_capabilities(&mut self, bdf: PciBdf) {
        if !self.has_capabilities() {
            return;
        }

        let mut cap_iter = self
            .vfio_wrapper
            .read_config_byte(PCI_CONFIG_CAPABILITY_OFFSET)
            & PCI_CONFIG_CAPABILITY_PTR_MASK;

        let mut pci_express_cap_found = false;
        let mut power_management_cap_found = false;

        while cap_iter != 0 {
            let cap_id = self.vfio_wrapper.read_config_byte(cap_iter.into());

            match PciCapabilityId::from(cap_id) {
                PciCapabilityId::MessageSignalledInterrupts => {
                    if let Some(irq_info) = self.vfio_wrapper.get_irq_info(VFIO_PCI_MSI_IRQ_INDEX)
                        && irq_info.count > 0
                    {
                        // Parse capability only if the VFIO device
                        // supports MSI.
                        let msg_ctl = self.parse_msi_capabilities(cap_iter);
                        self.initialize_msi(msg_ctl, cap_iter as u32, None);
                    }
                }
                PciCapabilityId::MsiX => {
                    if let Some(irq_info) = self.vfio_wrapper.get_irq_info(VFIO_PCI_MSIX_IRQ_INDEX)
                        && irq_info.count > 0
                    {
                        // Parse capability only if the VFIO device
                        // supports MSI-X.
                        let msix_cap = self.parse_msix_capabilities(cap_iter);
                        self.initialize_msix(msix_cap, cap_iter as u32, bdf, None);
                    }
                }
                PciCapabilityId::PciExpress => pci_express_cap_found = true,
                PciCapabilityId::PowerManagement => power_management_cap_found = true,
                _ => {}
            };

            let cap_next = self.vfio_wrapper.read_config_byte((cap_iter + 1).into())
                & PCI_CONFIG_CAPABILITY_PTR_MASK;

            // Break out of the loop, if we either find the end or we have a broken device. This
            // doesn't handle all cases where a device might send us in a loop here, but it
            // handles case of a device returning 0xFF instead of implementing a real
            // capabilities list.
            if cap_next == 0 || cap_next == cap_iter {
                break;
            }

            cap_iter = cap_next;
        }

        if let Some(clique_id) = self.x_nv_gpudirect_clique {
            self.add_nv_gpudirect_clique_cap(cap_iter, clique_id);
        }

        if pci_express_cap_found && power_management_cap_found {
            self.parse_extended_capabilities();
        }
    }

    fn add_nv_gpudirect_clique_cap(&mut self, cap_iter: u8, clique_id: u8) {
        // Turing, Ampere, Hopper, and Lovelace GPUs have dedicated space
        // at 0xD4 for this capability.
        let cap_offset = 0xd4u32;

        let reg_idx = (cap_iter / 4) as usize;
        self.patches.insert(
            reg_idx,
            ConfigPatch {
                mask: 0x0000_ff00,
                patch: cap_offset << 8,
            },
        );

        let reg_idx = (cap_offset / 4) as usize;
        self.patches.insert(
            reg_idx,
            ConfigPatch {
                mask: 0xffff_ffff,
                patch: 0x50080009u32,
            },
        );
        self.patches.insert(
            reg_idx + 1,
            ConfigPatch {
                mask: 0xffff_ffff,
                patch: (u32::from(clique_id) << 19) | 0x5032,
            },
        );
    }

    fn parse_extended_capabilities(&mut self) {
        let mut current_offset = PCI_CONFIG_EXTENDED_CAPABILITY_OFFSET;

        loop {
            let ext_cap_hdr = self.vfio_wrapper.read_config_dword(current_offset);

            let cap_id: u16 = (ext_cap_hdr & 0xffff) as u16;
            let cap_next: u16 = ((ext_cap_hdr >> 20) & 0xfff) as u16;

            match PciExpressCapabilityId::from(cap_id) {
                PciExpressCapabilityId::AlternativeRoutingIdentificationInterpretation
                | PciExpressCapabilityId::ResizeableBar
                | PciExpressCapabilityId::SingleRootIoVirtualization => {
                    let reg_idx = (current_offset / 4) as usize;
                    self.patches.insert(
                        reg_idx,
                        ConfigPatch {
                            mask: 0x0000_ffff,
                            patch: PciExpressCapabilityId::NullCapability as u32,
                        },
                    );
                }
                _ => {}
            }

            if cap_next == 0 {
                break;
            }

            current_offset = cap_next.into();
        }
    }

    pub(crate) fn enable_intx(&mut self) -> Result<(), VfioPciError> {
        if let Some(intx) = &mut self.interrupt.intx
            && !intx.enabled
        {
            if let Some(eventfd) = intx.interrupt_source_group.notifier(0) {
                self.vfio_wrapper
                    .enable_irq(VFIO_PCI_INTX_IRQ_INDEX, vec![&eventfd])
                    .map_err(VfioPciError::EnableIntx)?;

                intx.enabled = true;
            } else {
                return Err(VfioPciError::MissingNotifier);
            }
        }

        Ok(())
    }

    pub(crate) fn disable_intx(&mut self) {
        if let Some(intx) = &mut self.interrupt.intx
            && intx.enabled
        {
            if let Err(e) = self.vfio_wrapper.disable_irq(VFIO_PCI_INTX_IRQ_INDEX) {
                error!("Could not disable INTx: {}", e);
            } else {
                intx.enabled = false;
            }
        }
    }

    pub(crate) fn enable_msi(&self) -> Result<(), VfioPciError> {
        if let Some(msi) = &self.interrupt.msi {
            let mut irq_fds: Vec<EventFd> = Vec::new();
            for i in 0..msi.cfg.num_enabled_vectors() {
                if let Some(eventfd) = msi.interrupt_source_group.notifier(i as InterruptIndex) {
                    irq_fds.push(eventfd);
                } else {
                    return Err(VfioPciError::MissingNotifier);
                }
            }

            self.vfio_wrapper
                .enable_msi(irq_fds.iter().collect())
                .map_err(VfioPciError::EnableMsi)?;
        }

        Ok(())
    }

    pub(crate) fn disable_msi(&self) {
        if let Err(e) = self.vfio_wrapper.disable_msi() {
            error!("Could not disable MSI: {}", e);
        }
    }

    pub(crate) fn enable_msix(&self) -> Result<(), VfioPciError> {
        if let Some(msix) = &self.interrupt.msix {
            let mut irq_fds: Vec<EventFd> = Vec::new();
            for i in 0..msix.bar.table_entries.len() {
                if let Some(eventfd) = msix.interrupt_source_group.notifier(i as InterruptIndex) {
                    irq_fds.push(eventfd);
                } else {
                    return Err(VfioPciError::MissingNotifier);
                }
            }

            self.vfio_wrapper
                .enable_msix(irq_fds.iter().collect())
                .map_err(VfioPciError::EnableMsix)?;
        }

        Ok(())
    }

    pub(crate) fn disable_msix(&self) {
        if let Err(e) = self.vfio_wrapper.disable_msix() {
            error!("Could not disable MSI-X: {}", e);
        }
    }

    fn initialize_legacy_interrupt(&mut self) -> Result<(), VfioPciError> {
        if let Some(irq_info) = self.vfio_wrapper.get_irq_info(VFIO_PCI_INTX_IRQ_INDEX)
            && irq_info.count == 0
        {
            // A count of 0 means the INTx IRQ is not supported, therefore
            // it shouldn't be initialized.
            return Ok(());
        }

        if let Some(interrupt_source_group) = self.legacy_interrupt_group.clone() {
            self.interrupt.intx = Some(VfioIntx {
                interrupt_source_group,
                enabled: false,
            });

            self.enable_intx()?;
        }

        Ok(())
    }

    fn update_msi_capabilities(&mut self, offset: u64, data: &[u8]) -> Result<(), VfioPciError> {
        match self.interrupt.update_msi(offset, data) {
            Some(InterruptUpdateAction::EnableMsi) => {
                // Disable INTx before we can enable MSI
                self.disable_intx();
                self.enable_msi()?;
            }
            Some(InterruptUpdateAction::DisableMsi) => {
                // Fallback onto INTx when disabling MSI
                self.disable_msi();
                self.enable_intx()?;
            }
            _ => {}
        }

        Ok(())
    }

    fn update_msix_capabilities(&mut self, offset: u64, data: &[u8]) -> Result<(), VfioPciError> {
        match self.interrupt.update_msix(offset, data) {
            Some(InterruptUpdateAction::EnableMsix) => {
                // Disable INTx before we can enable MSI-X
                self.disable_intx();
                self.enable_msix()?;
            }
            Some(InterruptUpdateAction::DisableMsix) => {
                // Fallback onto INTx when disabling MSI-X
                self.disable_msix();
                self.enable_intx()?;
            }
            _ => {}
        }

        Ok(())
    }

    fn find_region(&self, addr: u64) -> Option<MmioRegion> {
        for region in self.mmio_regions.iter() {
            if addr >= region.start.raw_value()
                && addr < region.start.unchecked_add(region.length).raw_value()
            {
                return Some(region.clone());
            }
        }
        None
    }

    pub(crate) fn read_bar(&mut self, base: u64, offset: u64, data: &mut [u8]) {
        let addr = base + offset;
        if let Some(region) = self.find_region(addr) {
            let offset = addr - region.start.raw_value();

            if self.interrupt.msix_table_accessed(region.index, offset) {
                self.interrupt.msix_read_table(offset, data);
            } else {
                self.vfio_wrapper.region_read(region.index, offset, data);
            }
        }

        // INTx EOI
        // The guest reading from the BAR potentially means the interrupt has
        // been received and can be acknowledged.
        if self.interrupt.intx_in_use()
            && let Err(e) = self.vfio_wrapper.unmask_irq(VFIO_PCI_INTX_IRQ_INDEX)
        {
            error!("Failed unmasking INTx IRQ: {}", e);
        }
    }

    pub(crate) fn write_bar(
        &mut self,
        base: u64,
        offset: u64,
        data: &[u8],
    ) -> Option<Arc<Barrier>> {
        let addr = base + offset;
        if let Some(region) = self.find_region(addr) {
            let offset = addr - region.start.raw_value();

            // If the MSI-X table is written to, we need to update our cache.
            if self.interrupt.msix_table_accessed(region.index, offset) {
                self.interrupt.msix_write_table(offset, data);
            } else {
                self.vfio_wrapper.region_write(region.index, offset, data);
            }
        }

        // INTx EOI
        // The guest writing to the BAR potentially means the interrupt has
        // been received and can be acknowledged.
        if self.interrupt.intx_in_use()
            && let Err(e) = self.vfio_wrapper.unmask_irq(VFIO_PCI_INTX_IRQ_INDEX)
        {
            error!("Failed unmasking INTx IRQ: {}", e);
        }

        None
    }

    pub(crate) fn write_config_register(
        &mut self,
        reg_idx: usize,
        offset: u64,
        data: &[u8],
    ) -> (Vec<BarReprogrammingParams>, Option<Arc<Barrier>>) {
        // When the guest wants to write to a BAR, we trap it into
        // our local configuration space. We're not reprogramming
        // VFIO device.
        if (PCI_CONFIG_BAR0_INDEX..PCI_CONFIG_BAR0_INDEX + BAR_NUMS).contains(&reg_idx)
            || reg_idx == PCI_ROM_EXP_BAR_INDEX
        {
            // We keep our local cache updated with the BARs.
            // We'll read it back from there when the guest is asking
            // for BARs (see read_config_register()).
            return (
                self.configuration
                    .write_config_register(reg_idx, offset, data),
                None,
            );
        }

        let reg = (reg_idx * PCI_CONFIG_REGISTER_SIZE) as u64;

        // If the MSI or MSI-X capabilities are accessed, we need to
        // update our local cache accordingly.
        // Depending on how the capabilities are modified, this could
        // trigger a VFIO MSI or MSI-X toggle.
        if let Some((cap_id, cap_base)) = self.interrupt.accessed(reg) {
            let cap_offset: u64 = reg - cap_base + offset;
            match cap_id {
                PciCapabilityId::MessageSignalledInterrupts => {
                    if let Err(e) = self.update_msi_capabilities(cap_offset, data) {
                        error!("Could not update MSI capabilities: {}", e);
                    }
                }
                PciCapabilityId::MsiX => {
                    if let Err(e) = self.update_msix_capabilities(cap_offset, data) {
                        error!("Could not update MSI-X capabilities: {}", e);
                    }
                }
                _ => {}
            }
        }

        // Make sure to write to the device's PCI config space after MSI/MSI-X
        // interrupts have been enabled/disabled. In case of MSI, when the
        // interrupts are enabled through VFIO (using VFIO_DEVICE_SET_IRQS),
        // the MSI Enable bit in the MSI capability structure found in the PCI
        // config space is disabled by default. That's why when the guest is
        // enabling this bit, we first need to enable the MSI interrupts with
        // VFIO through VFIO_DEVICE_SET_IRQS ioctl, and only after we can write
        // to the device region to update the MSI Enable bit.
        self.vfio_wrapper.write_config((reg + offset) as u32, data);

        // Return pending BAR repgrogramming if MSE bit is set
        let mut ret_param = self.configuration.pending_bar_reprogram();
        if !ret_param.is_empty() {
            if self.read_config_register(crate::configuration::COMMAND_REG)
                & crate::configuration::COMMAND_REG_MEMORY_SPACE_MASK
                == crate::configuration::COMMAND_REG_MEMORY_SPACE_MASK
            {
                info!("BAR reprogramming parameter is returned: {:x?}", ret_param);
                self.configuration.clear_pending_bar_reprogram();
            } else {
                info!(
                    "MSE bit is disabled. No BAR reprogramming parameter is returned: {:x?}",
                    ret_param
                );

                ret_param = Vec::new();
            }
        }

        (ret_param, None)
    }

    pub(crate) fn read_config_register(&mut self, reg_idx: usize) -> u32 {
        // When reading the BARs, we trap it and return what comes
        // from our local configuration space. We want the guest to
        // use that and not the VFIO device BARs as it does not map
        // with the guest address space.
        if (PCI_CONFIG_BAR0_INDEX..PCI_CONFIG_BAR0_INDEX + BAR_NUMS).contains(&reg_idx)
            || reg_idx == PCI_ROM_EXP_BAR_INDEX
        {
            return self.configuration.read_reg(reg_idx);
        }

        if let Some(id) = self.get_msix_cap_idx() {
            let msix = self.interrupt.msix.as_mut().unwrap();
            if reg_idx * 4 == id + 4 {
                return msix.cap.table;
            } else if reg_idx * 4 == id + 8 {
                return msix.cap.pba;
            }
        }

        // Since we don't support passing multi-functions devices, we should
        // mask the multi-function bit, bit 7 of the Header Type byte on the
        // register 3.
        let mask = if reg_idx == PCI_HEADER_TYPE_REG_INDEX {
            0xff7f_ffff
        } else {
            0xffff_ffff
        };

        // The config register read comes from the VFIO device itself.
        let mut value = self.vfio_wrapper.read_config_dword((reg_idx * 4) as u32) & mask;

        if let Some(config_patch) = self.patches.get(&reg_idx) {
            value = (value & !config_patch.mask) | config_patch.patch;
        }

        value
    }

    fn state(&self) -> VfioCommonState {
        let intx_state = self.interrupt.intx.as_ref().map(|intx| IntxState {
            enabled: intx.enabled,
        });

        let msi_state = self.interrupt.msi.as_ref().map(|msi| MsiState {
            cap: msi.cfg.cap,
            cap_offset: msi.cap_offset,
        });

        let msix_state = self.interrupt.msix.as_ref().map(|msix| MsixState {
            cap: msix.cap,
            cap_offset: msix.cap_offset,
            bdf: msix.bar.devid,
        });

        VfioCommonState {
            intx_state,
            msi_state,
            msix_state,
        }
    }

    fn set_state(
        &mut self,
        state: &VfioCommonState,
        msi_state: Option<MsiConfigState>,
        msix_state: Option<MsixConfigState>,
    ) -> Result<(), VfioPciError> {
        if let (Some(intx), Some(interrupt_source_group)) =
            (&state.intx_state, self.legacy_interrupt_group.clone())
        {
            self.interrupt.intx = Some(VfioIntx {
                interrupt_source_group,
                enabled: false,
            });

            if intx.enabled {
                self.enable_intx()?;
            }
        }

        if let Some(msi) = &state.msi_state {
            self.initialize_msi(msi.cap.msg_ctl, msi.cap_offset, msi_state);
        }

        if let Some(msix) = &state.msix_state {
            self.initialize_msix(msix.cap, msix.cap_offset, msix.bdf.into(), msix_state);
        }

        Ok(())
    }
}

impl Pausable for VfioCommon {}

impl Snapshottable for VfioCommon {
    fn id(&self) -> String {
        String::from(VFIO_COMMON_ID)
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        let mut vfio_common_snapshot = Snapshot::new_from_state(&self.state())?;

        // Snapshot PciConfiguration
        vfio_common_snapshot.add_snapshot(self.configuration.id(), self.configuration.snapshot()?);

        // Snapshot MSI
        if let Some(msi) = &mut self.interrupt.msi {
            vfio_common_snapshot.add_snapshot(msi.cfg.id(), msi.cfg.snapshot()?);
        }

        // Snapshot MSI-X
        if let Some(msix) = &mut self.interrupt.msix {
            vfio_common_snapshot.add_snapshot(msix.bar.id(), msix.bar.snapshot()?);
        }

        Ok(vfio_common_snapshot)
    }
}

/// VfioPciDevice represents a VFIO PCI device.
/// This structure implements the BusDevice and PciDevice traits.
///
/// A VfioPciDevice is bound to a VfioDevice and is also a PCI device.
/// The VMM creates a VfioDevice, then assigns it to a VfioPciDevice,
/// which then gets added to the PCI bus.
pub struct VfioPciDevice {
    id: String,
    vm: Arc<dyn hypervisor::Vm>,
    device: Arc<VfioDevice>,
    container: Arc<VfioContainer>,
    common: VfioCommon,
    iommu_attached: bool,
    memory_slot_allocator: MemorySlotAllocator,
    bdf: PciBdf,
    device_path: PathBuf,
}

impl VfioPciDevice {
    /// Constructs a new Vfio Pci device for the given Vfio device
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        vm: &Arc<dyn hypervisor::Vm>,
        device: VfioDevice,
        container: Arc<VfioContainer>,
        msi_interrupt_manager: Arc<dyn InterruptManager<GroupConfig = MsiIrqGroupConfig>>,
        legacy_interrupt_group: Option<Arc<dyn InterruptSourceGroup>>,
        iommu_attached: bool,
        bdf: PciBdf,
        memory_slot_allocator: MemorySlotAllocator,
        snapshot: Option<Snapshot>,
        x_nv_gpudirect_clique: Option<u8>,
        device_path: PathBuf,
    ) -> Result<Self, VfioPciError> {
        let device = Arc::new(device);
        device.reset();

        let vfio_wrapper = VfioDeviceWrapper::new(Arc::clone(&device));

        let common = VfioCommon::new(
            msi_interrupt_manager,
            legacy_interrupt_group,
            Arc::new(vfio_wrapper) as Arc<dyn Vfio>,
            &PciVfioSubclass::VfioSubclass,
            bdf,
            vm_migration::snapshot_from_id(snapshot.as_ref(), VFIO_COMMON_ID),
            x_nv_gpudirect_clique,
        )?;

        let vfio_pci_device = VfioPciDevice {
            id,
            vm: vm.clone(),
            device,
            container,
            common,
            iommu_attached,
            memory_slot_allocator,
            bdf,
            device_path: device_path.clone(),
        };

        Ok(vfio_pci_device)
    }

    pub fn iommu_attached(&self) -> bool {
        self.iommu_attached
    }

    fn generate_sparse_areas(
        caps: &[VfioRegionInfoCap],
        region_index: u32,
        region_start: u64,
        region_size: u64,
        vfio_msix: Option<&VfioMsix>,
    ) -> Result<Vec<VfioRegionSparseMmapArea>, VfioPciError> {
        for cap in caps {
            match cap {
                VfioRegionInfoCap::SparseMmap(sparse_mmap) => return Ok(sparse_mmap.areas.clone()),
                VfioRegionInfoCap::MsixMappable => {
                    if !is_4k_aligned(region_start) {
                        error!(
                            "Region start address 0x{:x} must be at least aligned on 4KiB",
                            region_start
                        );
                        return Err(VfioPciError::RegionAlignment);
                    }
                    if !is_4k_multiple(region_size) {
                        error!(
                            "Region size 0x{:x} must be at least a multiple of 4KiB",
                            region_size
                        );
                        return Err(VfioPciError::RegionSize);
                    }

                    // In case the region contains the MSI-X vectors table or
                    // the MSI-X PBA table, we must calculate the subregions
                    // around them, leading to a list of sparse areas.
                    // We want to make sure we will still trap MMIO accesses
                    // to these MSI-X specific ranges. If these region don't align
                    // with pagesize, we can achieve it by enlarging its range.
                    //
                    // Using a BtreeMap as the list provided through the iterator is sorted
                    // by key. This ensures proper split of the whole region.
                    let mut inter_ranges = BTreeMap::new();
                    if let Some(msix) = vfio_msix {
                        if region_index == msix.cap.table_bir() {
                            let (offset, size) = msix.cap.table_range();
                            let offset = align_page_size_down(offset);
                            let size = align_page_size_up(size);
                            inter_ranges.insert(offset, size);
                        }
                        if region_index == msix.cap.pba_bir() {
                            let (offset, size) = msix.cap.pba_range();
                            let offset = align_page_size_down(offset);
                            let size = align_page_size_up(size);
                            inter_ranges.insert(offset, size);
                        }
                    }

                    let mut sparse_areas = Vec::new();
                    let mut current_offset = 0;
                    for (range_offset, range_size) in inter_ranges {
                        if range_offset > current_offset {
                            sparse_areas.push(VfioRegionSparseMmapArea {
                                offset: current_offset,
                                size: range_offset - current_offset,
                            });
                        }
                        current_offset = align_page_size_down(range_offset + range_size);
                    }

                    if region_size > current_offset {
                        sparse_areas.push(VfioRegionSparseMmapArea {
                            offset: current_offset,
                            size: region_size - current_offset,
                        });
                    }

                    return Ok(sparse_areas);
                }
                _ => {}
            }
        }

        // In case no relevant capabilities have been found, create a single
        // sparse area corresponding to the entire MMIO region.
        Ok(vec![VfioRegionSparseMmapArea {
            offset: 0,
            size: region_size,
        }])
    }

    /// Map MMIO regions into the guest, and avoid VM exits when the guest tries
    /// to reach those regions.
    ///
    /// # Arguments
    ///
    /// * `vm` - The VM object. It is used to set the VFIO MMIO regions
    ///   as user memory regions.
    /// * `mem_slot` - The closure to return a memory slot.
    pub fn map_mmio_regions(&mut self) -> Result<(), VfioPciError> {
        let fd = self.device.as_raw_fd();

        for region in self.common.mmio_regions.iter_mut() {
            let region_flags = self.device.get_region_flags(region.index);
            if region_flags & VFIO_REGION_INFO_FLAG_MMAP != 0 {
                let mut prot = 0;
                if region_flags & VFIO_REGION_INFO_FLAG_READ != 0 {
                    prot |= libc::PROT_READ;
                }
                if region_flags & VFIO_REGION_INFO_FLAG_WRITE != 0 {
                    prot |= libc::PROT_WRITE;
                }

                // Retrieve the list of capabilities found on the region
                let caps = if region_flags & VFIO_REGION_INFO_FLAG_CAPS != 0 {
                    self.device.get_region_caps(region.index)
                } else {
                    Vec::new()
                };

                // Don't try to mmap the region if it contains MSI-X table or
                // MSI-X PBA subregion, and if we couldn't find MSIX_MAPPABLE
                // in the list of supported capabilities.
                if let Some(msix) = self.common.interrupt.msix.as_ref()
                    && (region.index == msix.cap.table_bir() || region.index == msix.cap.pba_bir())
                    && !caps.contains(&VfioRegionInfoCap::MsixMappable)
                {
                    continue;
                }

                let mmap_size = self.device.get_region_size(region.index);
                let mmap_offset = self.device.get_region_offset(region.index);

                let sparse_areas = Self::generate_sparse_areas(
                    &caps,
                    region.index,
                    region.start.0,
                    mmap_size,
                    self.common.interrupt.msix.as_ref(),
                )?;

                for area in sparse_areas.iter() {
                    // SAFETY: FFI call with correct arguments
                    let host_addr = unsafe {
                        libc::mmap(
                            null_mut(),
                            area.size as usize,
                            prot,
                            libc::MAP_SHARED,
                            fd,
                            mmap_offset as libc::off_t + area.offset as libc::off_t,
                        )
                    };

                    if std::ptr::eq(host_addr, libc::MAP_FAILED) {
                        error!(
                            "Could not mmap sparse area (offset = 0x{:x}, size = 0x{:x}): {}",
                            area.offset,
                            area.size,
                            std::io::Error::last_os_error()
                        );
                        return Err(VfioPciError::MmapArea);
                    }

                    if !is_page_size_aligned(area.size) || !is_page_size_aligned(area.offset) {
                        warn!(
                            "Could not mmap sparse area that is not page size aligned (offset = 0x{:x}, size = 0x{:x})",
                            area.offset, area.size,
                        );
                        return Ok(());
                    }

                    let user_memory_region = UserMemoryRegion {
                        slot: self.memory_slot_allocator.next_memory_slot(),
                        start: region.start.0 + area.offset,
                        size: area.size,
                        host_addr: host_addr as u64,
                    };

                    region.user_memory_regions.push(user_memory_region);

                    let mem_region = self.vm.make_user_memory_region(
                        user_memory_region.slot,
                        user_memory_region.start,
                        user_memory_region.size,
                        user_memory_region.host_addr,
                        false,
                        false,
                    );

                    self.vm
                        .create_user_memory_region(mem_region)
                        .map_err(VfioPciError::CreateUserMemoryRegion)?;

                    if !self.iommu_attached {
                        self.container
                            .vfio_dma_map(
                                user_memory_region.start,
                                user_memory_region.size,
                                user_memory_region.host_addr,
                            )
                            .map_err(|e| {
                                VfioPciError::DmaMap(e, self.device_path.clone(), self.bdf)
                            })?;
                    }
                }
            }
        }

        Ok(())
    }

    pub fn unmap_mmio_regions(&mut self) {
        for region in self.common.mmio_regions.iter() {
            for user_memory_region in region.user_memory_regions.iter() {
                // Unmap from vfio container
                if !self.iommu_attached
                    && let Err(e) = self
                        .container
                        .vfio_dma_unmap(user_memory_region.start, user_memory_region.size)
                        .map_err(|e| VfioPciError::DmaUnmap(e, self.device_path.clone(), self.bdf))
                {
                    error!(
                        "Could not unmap mmio region from vfio container: \
                            iova 0x{:x}, size 0x{:x}: {}, ",
                        user_memory_region.start, user_memory_region.size, e
                    );
                }

                // Remove region
                let r = self.vm.make_user_memory_region(
                    user_memory_region.slot,
                    user_memory_region.start,
                    user_memory_region.size,
                    user_memory_region.host_addr,
                    false,
                    false,
                );

                if let Err(e) = self.vm.remove_user_memory_region(r) {
                    error!("Could not remove the userspace memory region: {}", e);
                }

                self.memory_slot_allocator
                    .free_memory_slot(user_memory_region.slot);

                // SAFETY: FFI call with correct arguments
                let ret = unsafe {
                    libc::munmap(
                        user_memory_region.host_addr as *mut libc::c_void,
                        user_memory_region.size as usize,
                    )
                };
                if ret != 0 {
                    error!(
                        "Could not unmap region {}, error:{}",
                        region.index,
                        io::Error::last_os_error()
                    );
                }
            }
        }
    }

    pub fn dma_map(&self, iova: u64, size: u64, user_addr: u64) -> Result<(), VfioPciError> {
        if !self.iommu_attached {
            self.container
                .vfio_dma_map(iova, size, user_addr)
                .map_err(|e| VfioPciError::DmaMap(e, self.device_path.clone(), self.bdf))?;
        }

        Ok(())
    }

    pub fn dma_unmap(&self, iova: u64, size: u64) -> Result<(), VfioPciError> {
        if !self.iommu_attached {
            self.container
                .vfio_dma_unmap(iova, size)
                .map_err(|e| VfioPciError::DmaUnmap(e, self.device_path.clone(), self.bdf))?;
        }

        Ok(())
    }

    pub fn mmio_regions(&self) -> Vec<MmioRegion> {
        self.common.mmio_regions.clone()
    }
}

impl Drop for VfioPciDevice {
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
            self.common.disable_msi()
        }

        if self.common.interrupt.intx_in_use() {
            self.common.disable_intx();
        }
    }
}

impl BusDevice for VfioPciDevice {
    fn read(&mut self, base: u64, offset: u64, data: &mut [u8]) {
        self.read_bar(base, offset, data)
    }

    fn write(&mut self, base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        self.write_bar(base, offset, data)
    }
}

// Offset of the 16-bit status register in the PCI configuration space.
const PCI_CONFIG_STATUS_OFFSET: u32 = 0x06;
// Status bit indicating the presence of a capabilities list.
const PCI_CONFIG_STATUS_CAPABILITIES_LIST: u16 = 1 << 4;
// First BAR offset in the PCI config space.
const PCI_CONFIG_BAR_OFFSET: u32 = 0x10;
// Capability register offset in the PCI config space.
const PCI_CONFIG_CAPABILITY_OFFSET: u32 = 0x34;
// The valid bits for the capabilities pointer.
const PCI_CONFIG_CAPABILITY_PTR_MASK: u8 = !0b11;
// Extended capabilities register offset in the PCI config space.
const PCI_CONFIG_EXTENDED_CAPABILITY_OFFSET: u32 = 0x100;
// IO BAR when first BAR bit is 1.
const PCI_CONFIG_IO_BAR: u32 = 0x1;
// 64-bit memory bar flag.
const PCI_CONFIG_MEMORY_BAR_64BIT: u32 = 0x4;
// Prefetchable BAR bit
const PCI_CONFIG_BAR_PREFETCHABLE: u32 = 0x8;
// PCI config register size (4 bytes).
const PCI_CONFIG_REGISTER_SIZE: usize = 4;
// Number of BARs for a PCI device
const BAR_NUMS: usize = 6;
// PCI Header Type register index
const PCI_HEADER_TYPE_REG_INDEX: usize = 3;
// First BAR register index
const PCI_CONFIG_BAR0_INDEX: usize = 4;
// PCI ROM expansion BAR register index
const PCI_ROM_EXP_BAR_INDEX: usize = 12;

impl PciDevice for VfioPciDevice {
    fn allocate_bars(
        &mut self,
        allocator: &Arc<Mutex<SystemAllocator>>,
        mmio32_allocator: &mut AddressAllocator,
        mmio64_allocator: &mut AddressAllocator,
        resources: Option<Vec<Resource>>,
    ) -> Result<Vec<PciBarConfiguration>, PciDeviceError> {
        self.common
            .allocate_bars(allocator, mmio32_allocator, mmio64_allocator, resources)
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
        self.common.read_bar(base, offset, data)
    }

    fn write_bar(&mut self, base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        self.common.write_bar(base, offset, data)
    }

    fn move_bar(&mut self, old_base: u64, new_base: u64) -> Result<(), io::Error> {
        for region in self.common.mmio_regions.iter_mut() {
            if region.start.raw_value() == old_base {
                region.start = GuestAddress(new_base);

                for user_memory_region in region.user_memory_regions.iter_mut() {
                    // Unmap the old MMIO region from vfio container
                    if !self.iommu_attached
                        && let Err(e) = self
                            .container
                            .vfio_dma_unmap(user_memory_region.start, user_memory_region.size)
                            .map_err(|e| {
                                VfioPciError::DmaUnmap(e, self.device_path.clone(), self.bdf)
                            })
                    {
                        error!(
                            "Could not unmap mmio region from vfio container: \
                                iova 0x{:x}, size 0x{:x}: {}, ",
                            user_memory_region.start, user_memory_region.size, e
                        );
                    }

                    // Remove old region
                    let old_mem_region = self.vm.make_user_memory_region(
                        user_memory_region.slot,
                        user_memory_region.start,
                        user_memory_region.size,
                        user_memory_region.host_addr,
                        false,
                        false,
                    );

                    self.vm
                        .remove_user_memory_region(old_mem_region)
                        .map_err(io::Error::other)?;

                    // Update the user memory region with the correct start address.
                    if new_base > old_base {
                        user_memory_region.start += new_base - old_base;
                    } else {
                        user_memory_region.start -= old_base - new_base;
                    }

                    // Insert new region
                    let new_mem_region = self.vm.make_user_memory_region(
                        user_memory_region.slot,
                        user_memory_region.start,
                        user_memory_region.size,
                        user_memory_region.host_addr,
                        false,
                        false,
                    );

                    self.vm
                        .create_user_memory_region(new_mem_region)
                        .map_err(io::Error::other)?;

                    // Map the moved mmio region to vfio container
                    if !self.iommu_attached {
                        self.container
                            .vfio_dma_map(
                                user_memory_region.start,
                                user_memory_region.size,
                                user_memory_region.host_addr,
                            )
                            .map_err(|e| {
                                VfioPciError::DmaMap(e, self.device_path.clone(), self.bdf)
                            })
                            .map_err(|e| {
                                io::Error::other(format!(
                                    "Could not map mmio region to vfio container: \
                                    iova 0x{:x}, size 0x{:x}: {}, ",
                                    user_memory_region.start, user_memory_region.size, e
                                ))
                            })?;
                    }
                }
            }
        }

        Ok(())
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn id(&self) -> Option<String> {
        Some(self.id.clone())
    }
}

impl Pausable for VfioPciDevice {}

impl Snapshottable for VfioPciDevice {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        let mut vfio_pci_dev_snapshot = Snapshot::default();

        // Snapshot VfioCommon
        vfio_pci_dev_snapshot.add_snapshot(self.common.id(), self.common.snapshot()?);

        Ok(vfio_pci_dev_snapshot)
    }
}
impl Transportable for VfioPciDevice {}
impl Migratable for VfioPciDevice {}

/// This structure implements the ExternalDmaMapping trait. It is meant to
/// be used when the caller tries to provide a way to update the mappings
/// associated with a specific VFIO container.
pub struct VfioDmaMapping<M: GuestAddressSpace> {
    container: Arc<VfioContainer>,
    memory: Arc<M>,
    mmio_regions: Arc<Mutex<Vec<MmioRegion>>>,
}

impl<M: GuestAddressSpace> VfioDmaMapping<M> {
    /// Create a DmaMapping object.
    /// # Parameters
    /// * `container`: VFIO container object.
    /// * `memory`: guest memory to mmap.
    /// * `mmio_regions`: mmio_regions to mmap.
    pub fn new(
        container: Arc<VfioContainer>,
        memory: Arc<M>,
        mmio_regions: Arc<Mutex<Vec<MmioRegion>>>,
    ) -> Self {
        VfioDmaMapping {
            container,
            memory,
            mmio_regions,
        }
    }
}

impl<M: GuestAddressSpace + Sync + Send> ExternalDmaMapping for VfioDmaMapping<M> {
    fn map(&self, iova: u64, gpa: u64, size: u64) -> std::result::Result<(), io::Error> {
        let mem = self.memory.memory();
        let guest_addr = GuestAddress(gpa);
        let user_addr = if mem.check_range(guest_addr, size as usize) {
            match mem.get_host_address(guest_addr) {
                Ok(t) => t as u64,
                Err(e) => {
                    return Err(io::Error::other(format!(
                        "unable to retrieve user address for gpa 0x{gpa:x} from guest memory region: {e}"
                    )));
                }
            }
        } else if self.mmio_regions.lock().unwrap().check_range(gpa, size) {
            self.mmio_regions.lock().unwrap().find_user_address(gpa)?
        } else {
            return Err(io::Error::other(format!(
                "failed to locate guest address 0x{gpa:x} in guest memory"
            )));
        };

        self.container
            .vfio_dma_map(iova, size, user_addr)
            .map_err(|e| {
                io::Error::other(format!(
                    "failed to map memory for VFIO container, \
                         iova 0x{iova:x}, gpa 0x{gpa:x}, size 0x{size:x}: {e:?}"
                ))
            })
    }

    fn unmap(&self, iova: u64, size: u64) -> std::result::Result<(), io::Error> {
        self.container.vfio_dma_unmap(iova, size).map_err(|e| {
            io::Error::other(format!(
                "failed to unmap memory for VFIO container, \
                     iova 0x{iova:x}, size 0x{size:x}: {e:?}"
            ))
        })
    }
}
