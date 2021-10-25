// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//

use crate::{
    msi_num_enabled_vectors, BarReprogrammingParams, MsiConfig, MsixCap, MsixConfig,
    PciBarConfiguration, PciBarRegionType, PciCapabilityId, PciClassCode, PciConfiguration,
    PciDevice, PciDeviceError, PciHeaderType, PciSubclass, MSIX_TABLE_ENTRY_SIZE,
};
use byteorder::{ByteOrder, LittleEndian};
use hypervisor::HypervisorVmError;
use std::any::Any;
use std::collections::BTreeMap;
use std::io;
use std::os::unix::io::AsRawFd;
use std::ptr::null_mut;
use std::sync::{Arc, Barrier};
use thiserror::Error;
use vfio_bindings::bindings::vfio::*;
use vfio_ioctls::{VfioContainer, VfioDevice, VfioIrq};
use vm_allocator::SystemAllocator;
use vm_device::interrupt::{
    InterruptIndex, InterruptManager, InterruptSourceGroup, MsiIrqGroupConfig,
};
use vm_device::BusDevice;
use vm_memory::{Address, GuestAddress, GuestUsize};
use vmm_sys_util::eventfd::EventFd;

#[derive(Debug, Error)]
pub enum VfioPciError {
    #[error("Failed to DMA map: {0}")]
    DmaMap(#[source] vfio_ioctls::VfioError),
    #[error("Failed to DMA unmap: {0}")]
    DmaUnmap(#[source] vfio_ioctls::VfioError),
    #[error("Failed to enable INTx: {0}")]
    EnableIntx(#[source] VfioError),
    #[error("Failed to enable MSI: {0}")]
    EnableMsi(#[source] VfioError),
    #[error("Failed to enable MSI-x: {0}")]
    EnableMsix(#[source] VfioError),
    #[error("Failed to map VFIO PCI region into guest: {0}")]
    MapRegionGuest(#[source] HypervisorVmError),
    #[error("Failed to notifier's eventfd")]
    MissingNotifier,
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

pub(crate) struct VfioIntx {
    interrupt_source_group: Arc<dyn InterruptSourceGroup>,
    enabled: bool,
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
        if let Some(ref mut msi) = &mut self.msi {
            let action = msi.update(offset, data);
            return action;
        }

        None
    }

    fn update_msix(&mut self, offset: u64, data: &[u8]) -> Option<InterruptUpdateAction> {
        if let Some(ref mut msix) = &mut self.msix {
            let action = msix.update(offset, data);
            return action;
        }

        None
    }

    fn accessed(&self, offset: u64) -> Option<(PciCapabilityId, u64)> {
        if let Some(msi) = &self.msi {
            if offset >= u64::from(msi.cap_offset)
                && offset < u64::from(msi.cap_offset) + msi.cfg.size()
            {
                return Some((
                    PciCapabilityId::MessageSignalledInterrupts,
                    u64::from(msi.cap_offset),
                ));
            }
        }

        if let Some(msix) = &self.msix {
            if offset == u64::from(msix.cap_offset) {
                return Some((PciCapabilityId::MsiX, u64::from(msix.cap_offset)));
            }
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
        if let Some(ref mut msix) = &mut self.msix {
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
    slot: u32,
    start: u64,
    size: u64,
    host_addr: u64,
}

#[derive(Clone)]
pub struct MmioRegion {
    pub start: GuestAddress,
    pub length: GuestUsize,
    pub(crate) type_: PciBarRegionType,
    pub(crate) index: u32,
    pub(crate) mem_slot: Option<u32>,
    pub(crate) host_addr: Option<u64>,
    pub(crate) mmap_size: Option<usize>,
    pub(crate) user_memory_regions: Vec<UserMemoryRegion>,
}
#[derive(Debug, Error)]
pub enum VfioError {
    #[error("Kernel VFIO error: {0}")]
    KernelVfio(#[source] vfio_ioctls::VfioError),
    #[error("VFIO user error: {0}")]
    VfioUser(#[source] vfio_user::Error),
}

pub(crate) trait Vfio {
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

pub(crate) struct VfioCommon {
    pub(crate) configuration: PciConfiguration,
    pub(crate) mmio_regions: Vec<MmioRegion>,
    pub(crate) interrupt: Interrupt,
}

impl VfioCommon {
    pub(crate) fn allocate_bars(
        &mut self,
        allocator: &mut SystemAllocator,
        vfio_wrapper: &dyn Vfio,
    ) -> Result<Vec<(GuestAddress, GuestUsize, PciBarRegionType)>, PciDeviceError> {
        let mut ranges = Vec::new();
        let mut bar_id = VFIO_PCI_BAR0_REGION_INDEX as u32;

        // Going through all regular regions to compute the BAR size.
        // We're not saving the BAR address to restore it, because we
        // are going to allocate a guest address for each BAR and write
        // that new address back.
        while bar_id < VFIO_PCI_CONFIG_REGION_INDEX {
            let region_size: u64;
            let bar_addr: GuestAddress;

            let bar_offset = if bar_id == VFIO_PCI_ROM_REGION_INDEX {
                (PCI_ROM_EXP_BAR_INDEX * 4) as u32
            } else {
                PCI_CONFIG_BAR_OFFSET + bar_id * 4
            };

            // First read flags
            let flags = vfio_wrapper.read_config_dword(bar_offset);

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

            // By default, the region type is 32 bits memory BAR.
            let mut region_type = PciBarRegionType::Memory32BitRegion;

            // To get size write all 1s
            vfio_wrapper.write_config_dword(bar_offset, 0xffff_ffff);

            // And read back BAR value. The device will write zeros for bits it doesn't care about
            let mut lower = vfio_wrapper.read_config_dword(bar_offset);

            if io_bar {
                #[cfg(target_arch = "x86_64")]
                {
                    // IO BAR
                    region_type = PciBarRegionType::IoRegion;

                    // Mask flag bits (lowest 2 for I/O bars)
                    lower &= !0b11;

                    // BAR is not enabled
                    if lower == 0 {
                        bar_id += 1;
                        continue;
                    }

                    // Invert bits and add 1 to calculate size
                    region_size = (!lower + 1) as u64;

                    // The address needs to be 4 bytes aligned.
                    bar_addr = allocator
                        .allocate_io_addresses(None, region_size, Some(0x4))
                        .ok_or(PciDeviceError::IoAllocationFailed(region_size))?;
                }
                #[cfg(target_arch = "aarch64")]
                unimplemented!()
            } else if is_64bit_bar {
                // 64 bits Memory BAR
                region_type = PciBarRegionType::Memory64BitRegion;

                // Query size of upper BAR of 64-bit BAR
                let upper_offset: u32 = PCI_CONFIG_BAR_OFFSET + (bar_id + 1) * 4;
                vfio_wrapper.write_config_dword(upper_offset, 0xffff_ffff);
                let upper = vfio_wrapper.read_config_dword(upper_offset);

                let mut combined_size = u64::from(upper) << 32 | u64::from(lower);

                // Mask out flag bits (lowest 4 for memory bars)
                combined_size &= !0b1111;

                // BAR is not enabled
                if combined_size == 0 {
                    bar_id += 1;
                    continue;
                }

                // Invert and add 1 to to find size
                region_size = (!combined_size + 1) as u64;

                // BAR allocation must be naturally aligned
                bar_addr = allocator
                    .allocate_mmio_addresses(None, region_size, Some(region_size))
                    .ok_or(PciDeviceError::IoAllocationFailed(region_size))?;
            } else {
                // Mask out flag bits (lowest 4 for memory bars)
                lower &= !0b1111;

                if lower == 0 {
                    bar_id += 1;
                    continue;
                }

                // Invert and add 1 to to find size
                region_size = (!lower + 1) as u64;

                // BAR allocation must be naturally aligned
                bar_addr = allocator
                    .allocate_mmio_hole_addresses(None, region_size, Some(region_size))
                    .ok_or(PciDeviceError::IoAllocationFailed(region_size))?;
            }

            let reg_idx = if bar_id == VFIO_PCI_ROM_REGION_INDEX {
                PCI_ROM_EXP_BAR_INDEX
            } else {
                bar_id as usize
            };

            // We can now build our BAR configuration block.
            let config = PciBarConfiguration::default()
                .set_register_index(reg_idx)
                .set_address(bar_addr.raw_value())
                .set_size(region_size)
                .set_region_type(region_type);

            if bar_id == VFIO_PCI_ROM_REGION_INDEX {
                self.configuration
                    .add_pci_rom_bar(&config, flags & 0x1)
                    .map_err(|e| PciDeviceError::IoRegistrationFailed(bar_addr.raw_value(), e))?;
            } else {
                self.configuration
                    .add_pci_bar(&config)
                    .map_err(|e| PciDeviceError::IoRegistrationFailed(bar_addr.raw_value(), e))?;
            }

            ranges.push((bar_addr, region_size, region_type));
            self.mmio_regions.push(MmioRegion {
                start: bar_addr,
                length: region_size,
                type_: region_type,
                index: bar_id as u32,
                mem_slot: None,
                host_addr: None,
                mmap_size: None,
                user_memory_regions: Vec::new(),
            });

            bar_id += 1;
            if is_64bit_bar {
                bar_id += 1;
            }
        }

        Ok(ranges)
    }

    pub(crate) fn free_bars(
        &mut self,
        allocator: &mut SystemAllocator,
    ) -> Result<(), PciDeviceError> {
        for region in self.mmio_regions.iter() {
            match region.type_ {
                PciBarRegionType::IoRegion => {
                    #[cfg(target_arch = "x86_64")]
                    allocator.free_io_addresses(region.start, region.length);
                    #[cfg(target_arch = "aarch64")]
                    error!("I/O region is not supported");
                }
                PciBarRegionType::Memory32BitRegion => {
                    allocator.free_mmio_hole_addresses(region.start, region.length);
                }
                PciBarRegionType::Memory64BitRegion => {
                    allocator.free_mmio_addresses(region.start, region.length);
                }
            }
        }
        Ok(())
    }

    pub(crate) fn parse_msix_capabilities(
        &mut self,
        cap: u8,
        interrupt_manager: &Arc<dyn InterruptManager<GroupConfig = MsiIrqGroupConfig>>,
        vfio_wrapper: &dyn Vfio,
    ) {
        let msg_ctl = vfio_wrapper.read_config_word((cap + 2).into());

        let table = vfio_wrapper.read_config_dword((cap + 4).into());

        let pba = vfio_wrapper.read_config_dword((cap + 8).into());

        let msix_cap = MsixCap {
            msg_ctl,
            table,
            pba,
        };

        let interrupt_source_group = interrupt_manager
            .create_group(MsiIrqGroupConfig {
                base: 0,
                count: msix_cap.table_size() as InterruptIndex,
            })
            .unwrap();

        let msix_config = MsixConfig::new(msix_cap.table_size(), interrupt_source_group.clone(), 0);

        self.interrupt.msix = Some(VfioMsix {
            bar: msix_config,
            cap: msix_cap,
            cap_offset: cap.into(),
            interrupt_source_group,
        });
    }

    pub(crate) fn parse_msi_capabilities(
        &mut self,
        cap: u8,
        interrupt_manager: &Arc<dyn InterruptManager<GroupConfig = MsiIrqGroupConfig>>,
        vfio_wrapper: &dyn Vfio,
    ) {
        let msg_ctl = vfio_wrapper.read_config_word((cap + 2).into());

        let interrupt_source_group = interrupt_manager
            .create_group(MsiIrqGroupConfig {
                base: 0,
                count: msi_num_enabled_vectors(msg_ctl) as InterruptIndex,
            })
            .unwrap();

        let msi_config = MsiConfig::new(msg_ctl, interrupt_source_group.clone());

        self.interrupt.msi = Some(VfioMsi {
            cfg: msi_config,
            cap_offset: cap.into(),
            interrupt_source_group,
        });
    }

    pub(crate) fn parse_capabilities(
        &mut self,
        interrupt_manager: &Arc<dyn InterruptManager<GroupConfig = MsiIrqGroupConfig>>,
        vfio_wrapper: &dyn Vfio,
    ) {
        let mut cap_next = vfio_wrapper.read_config_byte(PCI_CONFIG_CAPABILITY_OFFSET);

        while cap_next != 0 {
            let cap_id = vfio_wrapper.read_config_byte(cap_next.into());

            match PciCapabilityId::from(cap_id) {
                PciCapabilityId::MessageSignalledInterrupts => {
                    if let Some(irq_info) = vfio_wrapper.get_irq_info(VFIO_PCI_MSI_IRQ_INDEX) {
                        if irq_info.count > 0 {
                            // Parse capability only if the VFIO device
                            // supports MSI.
                            self.parse_msi_capabilities(cap_next, interrupt_manager, vfio_wrapper);
                        }
                    }
                }
                PciCapabilityId::MsiX => {
                    if let Some(irq_info) = vfio_wrapper.get_irq_info(VFIO_PCI_MSIX_IRQ_INDEX) {
                        if irq_info.count > 0 {
                            // Parse capability only if the VFIO device
                            // supports MSI-X.
                            self.parse_msix_capabilities(cap_next, interrupt_manager, vfio_wrapper);
                        }
                    }
                }
                _ => {}
            };

            cap_next = vfio_wrapper.read_config_byte((cap_next + 1).into());
        }
    }

    pub(crate) fn enable_intx(&mut self, wrapper: &dyn Vfio) -> Result<(), VfioPciError> {
        if let Some(intx) = &mut self.interrupt.intx {
            if !intx.enabled {
                if let Some(eventfd) = intx.interrupt_source_group.notifier(0) {
                    wrapper
                        .enable_irq(VFIO_PCI_INTX_IRQ_INDEX, vec![&eventfd])
                        .map_err(VfioPciError::EnableIntx)?;

                    intx.enabled = true;
                } else {
                    return Err(VfioPciError::MissingNotifier);
                }
            }
        }

        Ok(())
    }

    pub(crate) fn disable_intx(&mut self, wrapper: &dyn Vfio) {
        if let Some(intx) = &mut self.interrupt.intx {
            if intx.enabled {
                if let Err(e) = wrapper.disable_irq(VFIO_PCI_INTX_IRQ_INDEX) {
                    error!("Could not disable INTx: {}", e);
                } else {
                    intx.enabled = false;
                }
            }
        }
    }

    pub(crate) fn enable_msi(&self, wrapper: &dyn Vfio) -> Result<(), VfioPciError> {
        if let Some(msi) = &self.interrupt.msi {
            let mut irq_fds: Vec<EventFd> = Vec::new();
            for i in 0..msi.cfg.num_enabled_vectors() {
                if let Some(eventfd) = msi.interrupt_source_group.notifier(i as InterruptIndex) {
                    irq_fds.push(eventfd);
                } else {
                    return Err(VfioPciError::MissingNotifier);
                }
            }

            wrapper
                .enable_msi(irq_fds.iter().collect())
                .map_err(VfioPciError::EnableMsi)?;
        }

        Ok(())
    }

    pub(crate) fn disable_msi(&self, wrapper: &dyn Vfio) {
        if let Err(e) = wrapper.disable_msi() {
            error!("Could not disable MSI: {}", e);
        }
    }

    pub(crate) fn enable_msix(&self, wrapper: &dyn Vfio) -> Result<(), VfioPciError> {
        if let Some(msix) = &self.interrupt.msix {
            let mut irq_fds: Vec<EventFd> = Vec::new();
            for i in 0..msix.bar.table_entries.len() {
                if let Some(eventfd) = msix.interrupt_source_group.notifier(i as InterruptIndex) {
                    irq_fds.push(eventfd);
                } else {
                    return Err(VfioPciError::MissingNotifier);
                }
            }

            wrapper
                .enable_msix(irq_fds.iter().collect())
                .map_err(VfioPciError::EnableMsix)?;
        }

        Ok(())
    }

    pub(crate) fn disable_msix(&self, wrapper: &dyn Vfio) {
        if let Err(e) = wrapper.disable_msix() {
            error!("Could not disable MSI-X: {}", e);
        }
    }

    pub(crate) fn initialize_legacy_interrupt(
        &mut self,
        legacy_interrupt_group: Option<Arc<dyn InterruptSourceGroup>>,
        wrapper: &dyn Vfio,
    ) -> Result<(), VfioPciError> {
        if let Some(irq_info) = wrapper.get_irq_info(VFIO_PCI_INTX_IRQ_INDEX) {
            if irq_info.count == 0 {
                // A count of 0 means the INTx IRQ is not supported, therefore
                // it shouldn't be initialized.
                return Ok(());
            }
        }

        if let Some(interrupt_source_group) = legacy_interrupt_group {
            self.interrupt.intx = Some(VfioIntx {
                interrupt_source_group,
                enabled: false,
            });

            self.enable_intx(wrapper)?;
        }

        Ok(())
    }

    pub(crate) fn update_msi_capabilities(
        &mut self,
        offset: u64,
        data: &[u8],
        wrapper: &dyn Vfio,
    ) -> Result<(), VfioPciError> {
        match self.interrupt.update_msi(offset, data) {
            Some(InterruptUpdateAction::EnableMsi) => {
                // Disable INTx before we can enable MSI
                self.disable_intx(wrapper);
                self.enable_msi(wrapper)?;
            }
            Some(InterruptUpdateAction::DisableMsi) => {
                // Fallback onto INTx when disabling MSI
                self.disable_msi(wrapper);
                self.enable_intx(wrapper)?;
            }
            _ => {}
        }

        Ok(())
    }

    pub(crate) fn update_msix_capabilities(
        &mut self,
        offset: u64,
        data: &[u8],
        wrapper: &dyn Vfio,
    ) -> Result<(), VfioPciError> {
        match self.interrupt.update_msix(offset, data) {
            Some(InterruptUpdateAction::EnableMsix) => {
                // Disable INTx before we can enable MSI-X
                self.disable_intx(wrapper);
                self.enable_msix(wrapper)?;
            }
            Some(InterruptUpdateAction::DisableMsix) => {
                // Fallback onto INTx when disabling MSI-X
                self.disable_msix(wrapper);
                self.enable_intx(wrapper)?;
            }
            _ => {}
        }

        Ok(())
    }

    pub(crate) fn find_region(&self, addr: u64) -> Option<MmioRegion> {
        for region in self.mmio_regions.iter() {
            if addr >= region.start.raw_value()
                && addr < region.start.unchecked_add(region.length).raw_value()
            {
                return Some(region.clone());
            }
        }
        None
    }

    pub(crate) fn read_bar(&mut self, base: u64, offset: u64, data: &mut [u8], wrapper: &dyn Vfio) {
        let addr = base + offset;
        if let Some(region) = self.find_region(addr) {
            let offset = addr - region.start.raw_value();

            if self.interrupt.msix_table_accessed(region.index, offset) {
                self.interrupt.msix_read_table(offset, data);
            } else {
                wrapper.region_read(region.index, offset, data);
            }
        }

        // INTx EOI
        // The guest reading from the BAR potentially means the interrupt has
        // been received and can be acknowledged.
        if self.interrupt.intx_in_use() {
            if let Err(e) = wrapper.unmask_irq(VFIO_PCI_INTX_IRQ_INDEX) {
                error!("Failed unmasking INTx IRQ: {}", e);
            }
        }
    }

    pub(crate) fn write_bar(
        &mut self,
        base: u64,
        offset: u64,
        data: &[u8],
        wrapper: &dyn Vfio,
    ) -> Option<Arc<Barrier>> {
        let addr = base + offset;
        if let Some(region) = self.find_region(addr) {
            let offset = addr - region.start.raw_value();

            // If the MSI-X table is written to, we need to update our cache.
            if self.interrupt.msix_table_accessed(region.index, offset) {
                self.interrupt.msix_write_table(offset, data);
            } else {
                wrapper.region_write(region.index, offset, data);
            }
        }

        // INTx EOI
        // The guest writing to the BAR potentially means the interrupt has
        // been received and can be acknowledged.
        if self.interrupt.intx_in_use() {
            if let Err(e) = wrapper.unmask_irq(VFIO_PCI_INTX_IRQ_INDEX) {
                error!("Failed unmasking INTx IRQ: {}", e);
            }
        }

        None
    }

    pub(crate) fn write_config_register(
        &mut self,
        reg_idx: usize,
        offset: u64,
        data: &[u8],
        wrapper: &dyn Vfio,
    ) -> Option<Arc<Barrier>> {
        // When the guest wants to write to a BAR, we trap it into
        // our local configuration space. We're not reprogramming
        // VFIO device.
        if (PCI_CONFIG_BAR0_INDEX..PCI_CONFIG_BAR0_INDEX + BAR_NUMS).contains(&reg_idx)
            || reg_idx == PCI_ROM_EXP_BAR_INDEX
        {
            // We keep our local cache updated with the BARs.
            // We'll read it back from there when the guest is asking
            // for BARs (see read_config_register()).
            self.configuration
                .write_config_register(reg_idx, offset, data);
            return None;
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
                    if let Err(e) = self.update_msi_capabilities(cap_offset, data, wrapper) {
                        error!("Could not update MSI capabilities: {}", e);
                    }
                }
                PciCapabilityId::MsiX => {
                    if let Err(e) = self.update_msix_capabilities(cap_offset, data, wrapper) {
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
        wrapper.write_config((reg + offset) as u32, data);

        None
    }

    pub(crate) fn read_config_register(&mut self, reg_idx: usize, wrapper: &dyn Vfio) -> u32 {
        // When reading the BARs, we trap it and return what comes
        // from our local configuration space. We want the guest to
        // use that and not the VFIO device BARs as it does not map
        // with the guest address space.
        if (PCI_CONFIG_BAR0_INDEX..PCI_CONFIG_BAR0_INDEX + BAR_NUMS).contains(&reg_idx)
            || reg_idx == PCI_ROM_EXP_BAR_INDEX
        {
            return self.configuration.read_reg(reg_idx);
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
        wrapper.read_config_dword((reg_idx * 4) as u32) & mask
    }
}

/// VfioPciDevice represents a VFIO PCI device.
/// This structure implements the BusDevice and PciDevice traits.
///
/// A VfioPciDevice is bound to a VfioDevice and is also a PCI device.
/// The VMM creates a VfioDevice, then assigns it to a VfioPciDevice,
/// which then gets added to the PCI bus.
pub struct VfioPciDevice {
    vm: Arc<dyn hypervisor::Vm>,
    device: Arc<VfioDevice>,
    container: Arc<VfioContainer>,
    vfio_wrapper: VfioDeviceWrapper,
    common: VfioCommon,
    iommu_attached: bool,
}

impl VfioPciDevice {
    /// Constructs a new Vfio Pci device for the given Vfio device
    pub fn new(
        vm: &Arc<dyn hypervisor::Vm>,
        device: VfioDevice,
        container: Arc<VfioContainer>,
        msi_interrupt_manager: &Arc<dyn InterruptManager<GroupConfig = MsiIrqGroupConfig>>,
        legacy_interrupt_group: Option<Arc<dyn InterruptSourceGroup>>,
        iommu_attached: bool,
    ) -> Result<Self, VfioPciError> {
        let device = Arc::new(device);
        device.reset();

        let configuration = PciConfiguration::new(
            0,
            0,
            0,
            PciClassCode::Other,
            &PciVfioSubclass::VfioSubclass,
            None,
            PciHeaderType::Device,
            0,
            0,
            None,
        );

        let vfio_wrapper = VfioDeviceWrapper::new(Arc::clone(&device));

        let mut common = VfioCommon {
            mmio_regions: Vec::new(),
            configuration,
            interrupt: Interrupt {
                intx: None,
                msi: None,
                msix: None,
            },
        };

        common.parse_capabilities(msi_interrupt_manager, &vfio_wrapper);
        common.initialize_legacy_interrupt(legacy_interrupt_group, &vfio_wrapper)?;

        let vfio_pci_device = VfioPciDevice {
            vm: vm.clone(),
            device,
            container,
            vfio_wrapper,
            common,
            iommu_attached,
        };

        Ok(vfio_pci_device)
    }

    pub fn iommu_attached(&self) -> bool {
        self.iommu_attached
    }

    fn align_4k(address: u64) -> u64 {
        (address + 0xfff) & 0xffff_ffff_ffff_f000
    }

    fn is_4k_aligned(address: u64) -> bool {
        (address & 0xfff) == 0
    }

    fn is_4k_multiple(size: u64) -> bool {
        (size & 0xfff) == 0
    }

    fn generate_user_memory_regions<F>(
        region_index: u32,
        region_start: u64,
        region_size: u64,
        host_addr: u64,
        mem_slot: F,
        vfio_msix: Option<&VfioMsix>,
    ) -> Vec<UserMemoryRegion>
    where
        F: Fn() -> u32,
    {
        if !Self::is_4k_aligned(region_start) {
            error!(
                "Region start address 0x{:x} must be at least aligned on 4KiB",
                region_start
            );
        }
        if !Self::is_4k_multiple(region_size) {
            error!(
                "Region size 0x{:x} must be at least a multiple of 4KiB",
                region_size
            );
        }

        // Using a BtreeMap as the list provided through the iterator is sorted
        // by key. This ensures proper split of the whole region.
        let mut inter_ranges = BTreeMap::new();
        if let Some(msix) = vfio_msix {
            if region_index == msix.cap.table_bir() {
                let (offset, size) = msix.cap.table_range();
                let base = region_start + offset;
                inter_ranges.insert(base, size);
            }
            if region_index == msix.cap.pba_bir() {
                let (offset, size) = msix.cap.pba_range();
                let base = region_start + offset;
                inter_ranges.insert(base, size);
            }
        }

        let mut user_memory_regions = Vec::new();
        let mut new_start = region_start;
        for (range_start, range_size) in inter_ranges {
            if range_start > new_start {
                user_memory_regions.push(UserMemoryRegion {
                    slot: mem_slot(),
                    start: new_start,
                    size: range_start - new_start,
                    host_addr: host_addr + new_start - region_start,
                });
            }

            new_start = Self::align_4k(range_start + range_size);
        }

        if region_start + region_size > new_start {
            user_memory_regions.push(UserMemoryRegion {
                slot: mem_slot(),
                start: new_start,
                size: region_start + region_size - new_start,
                host_addr: host_addr + new_start - region_start,
            });
        }

        user_memory_regions
    }

    /// Map MMIO regions into the guest, and avoid VM exits when the guest tries
    /// to reach those regions.
    ///
    /// # Arguments
    ///
    /// * `vm` - The VM object. It is used to set the VFIO MMIO regions
    ///          as user memory regions.
    /// * `mem_slot` - The closure to return a memory slot.
    pub fn map_mmio_regions<F>(
        &mut self,
        vm: &Arc<dyn hypervisor::Vm>,
        mem_slot: F,
    ) -> Result<(), VfioPciError>
    where
        F: Fn() -> u32,
    {
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

                // We ignore the mmap offset because we only support running on
                // host with VFIO newer than 4.16. That's because sparse mmap
                // has been deprecated and instead MSI-X regions can now be
                // entirely mapped.
                let (_, mmap_size) = self.device.get_region_mmap(region.index);
                let offset = self.device.get_region_offset(region.index);

                let host_addr = unsafe {
                    libc::mmap(
                        null_mut(),
                        mmap_size as usize,
                        prot,
                        libc::MAP_SHARED,
                        fd,
                        offset as libc::off_t,
                    )
                };

                if host_addr == libc::MAP_FAILED {
                    warn!(
                        "Could not mmap region index {}: {}",
                        region.index,
                        io::Error::last_os_error()
                    );
                    continue;
                }

                // In case the region that is being mapped contains the MSI-X
                // vectors table or the MSI-X PBA table, we must adjust what
                // is being declared through the hypervisor. We want to make
                // sure we will still trap MMIO accesses to these MSI-X
                // specific ranges.
                let user_memory_regions = Self::generate_user_memory_regions(
                    region.index,
                    region.start.raw_value(),
                    mmap_size,
                    host_addr as u64,
                    &mem_slot,
                    self.common.interrupt.msix.as_ref(),
                );
                for user_memory_region in user_memory_regions.iter() {
                    let mem_region = vm.make_user_memory_region(
                        user_memory_region.slot,
                        user_memory_region.start,
                        user_memory_region.size,
                        user_memory_region.host_addr,
                        false,
                        false,
                    );

                    vm.create_user_memory_region(mem_region)
                        .map_err(VfioPciError::MapRegionGuest)?;
                }

                // Update the region with memory mapped info.
                region.host_addr = Some(host_addr as u64);
                region.mmap_size = Some(mmap_size as usize);
                region.user_memory_regions = user_memory_regions;
            }
        }

        Ok(())
    }

    pub fn unmap_mmio_regions(&mut self) {
        for region in self.common.mmio_regions.iter() {
            for user_memory_region in region.user_memory_regions.iter() {
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
            }

            if let (Some(host_addr), Some(mmap_size)) = (region.host_addr, region.mmap_size) {
                let ret = unsafe { libc::munmap(host_addr as *mut libc::c_void, mmap_size) };
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
                .map_err(VfioPciError::DmaMap)?;
        }

        Ok(())
    }

    pub fn dma_unmap(&self, iova: u64, size: u64) -> Result<(), VfioPciError> {
        if !self.iommu_attached {
            self.container
                .vfio_dma_unmap(iova, size)
                .map_err(VfioPciError::DmaUnmap)?;
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

        if let Some(msix) = &self.common.interrupt.msix {
            if msix.bar.enabled() {
                self.common.disable_msix(&self.vfio_wrapper);
            }
        }

        if let Some(msi) = &self.common.interrupt.msi {
            if msi.cfg.enabled() {
                self.common.disable_msi(&self.vfio_wrapper)
            }
        }

        if self.common.interrupt.intx_in_use() {
            self.common.disable_intx(&self.vfio_wrapper);
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

// First BAR offset in the PCI config space.
const PCI_CONFIG_BAR_OFFSET: u32 = 0x10;
// Capability register offset in the PCI config space.
const PCI_CONFIG_CAPABILITY_OFFSET: u32 = 0x34;
// IO BAR when first BAR bit is 1.
const PCI_CONFIG_IO_BAR: u32 = 0x1;
// 64-bit memory bar flag.
const PCI_CONFIG_MEMORY_BAR_64BIT: u32 = 0x4;
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
        allocator: &mut SystemAllocator,
    ) -> Result<Vec<(GuestAddress, GuestUsize, PciBarRegionType)>, PciDeviceError> {
        self.common.allocate_bars(allocator, &self.vfio_wrapper)
    }

    fn free_bars(&mut self, allocator: &mut SystemAllocator) -> Result<(), PciDeviceError> {
        self.common.free_bars(allocator)
    }

    fn write_config_register(
        &mut self,
        reg_idx: usize,
        offset: u64,
        data: &[u8],
    ) -> Option<Arc<Barrier>> {
        self.common
            .write_config_register(reg_idx, offset, data, &self.vfio_wrapper)
    }

    fn read_config_register(&mut self, reg_idx: usize) -> u32 {
        self.common
            .read_config_register(reg_idx, &self.vfio_wrapper)
    }

    fn detect_bar_reprogramming(
        &mut self,
        reg_idx: usize,
        data: &[u8],
    ) -> Option<BarReprogrammingParams> {
        self.common
            .configuration
            .detect_bar_reprogramming(reg_idx, data)
    }

    fn read_bar(&mut self, base: u64, offset: u64, data: &mut [u8]) {
        self.common.read_bar(base, offset, data, &self.vfio_wrapper)
    }

    fn write_bar(&mut self, base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        self.common
            .write_bar(base, offset, data, &self.vfio_wrapper)
    }

    fn move_bar(&mut self, old_base: u64, new_base: u64) -> Result<(), io::Error> {
        for region in self.common.mmio_regions.iter_mut() {
            if region.start.raw_value() == old_base {
                region.start = GuestAddress(new_base);

                for user_memory_region in region.user_memory_regions.iter_mut() {
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
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

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
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                }
            }
        }

        Ok(())
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}
