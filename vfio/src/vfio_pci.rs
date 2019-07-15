// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//

extern crate devices;
extern crate pci;
extern crate vm_allocator;

use crate::vfio_device::VfioDevice;
use byteorder::{ByteOrder, LittleEndian};
use devices::BusDevice;
use kvm_ioctls::*;
use pci::{
    MsiCap, MsixCap, MsixConfig, PciBarConfiguration, PciBarRegionType, PciCapabilityID,
    PciClassCode, PciConfiguration, PciDevice, PciDeviceError, PciHeaderType, PciSubclass,
    MSIX_TABLE_ENTRY_SIZE,
};
use std::sync::Arc;
use vfio_bindings::bindings::vfio::*;
use vm_allocator::SystemAllocator;
use vm_memory::{Address, GuestAddress, GuestUsize};

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

#[derive(Copy, Clone)]
struct VfioMsi {
    cap: MsiCap,
    cap_offset: u32,
}

impl VfioMsi {
    fn update(&mut self, offset: u64, data: &[u8]) -> Option<InterruptUpdateAction> {
        let old_enabled = self.cap.enabled();

        self.cap.update(offset, data);

        let new_enabled = self.cap.enabled();

        if !old_enabled && new_enabled {
            return Some(InterruptUpdateAction::EnableMsi);
        }

        if old_enabled && !new_enabled {
            return Some(InterruptUpdateAction::DisableMsi);
        }

        None
    }
}

struct VfioMsix {
    bar: MsixConfig,
    cap: MsixCap,
    cap_offset: u32,
}

impl VfioMsix {
    fn update(&mut self, offset: u64, data: &[u8]) -> Option<InterruptUpdateAction> {
        let old_enabled = self.cap.enabled();

        // Update "Message Control" word
        if offset == 2 && data.len() == 2 {
            self.cap.set_msg_ctl(LittleEndian::read_u16(data));
        }

        let new_enabled = self.cap.enabled();

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

struct Interrupt {
    msi: Option<VfioMsi>,
    msix: Option<VfioMsix>,
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

    fn accessed(&self, offset: u64) -> Option<(PciCapabilityID, u64)> {
        if let Some(msi) = &self.msi {
            if offset >= u64::from(msi.cap_offset)
                && offset < u64::from(msi.cap_offset) + msi.cap.size()
            {
                return Some((
                    PciCapabilityID::MessageSignalledInterrupts,
                    u64::from(msi.cap_offset),
                ));
            }
        }

        if let Some(msix) = &self.msix {
            if offset == u64::from(msix.cap_offset) {
                return Some((PciCapabilityID::MSIX, u64::from(msix.cap_offset)));
            }
        }

        None
    }

    fn msix_enabled(&self) -> bool {
        if let Some(msix) = &self.msix {
            return msix.cap.enabled();
        }

        false
    }

    fn msix_function_masked(&self) -> bool {
        if let Some(msix) = &self.msix {
            return msix.cap.masked();
        }

        false
    }

    fn msix_table_accessed(&self, bar_index: u32, offset: u64) -> bool {
        if let Some(msix) = &self.msix {
            return msix.table_accessed(bar_index, offset);
        }

        false
    }

    fn msix_write_table(&mut self, offset: u64, data: &[u8]) {
        if let Some(ref mut msix) = &mut self.msix {
            msix.bar.write_table(offset, data)
        }
    }

    fn msix_read_table(&self, offset: u64, data: &mut [u8]) {
        if let Some(msix) = &self.msix {
            msix.bar.read_table(offset, data)
        }
    }
}

#[derive(Copy, Clone)]
struct MmioRegion {
    start: GuestAddress,
    length: GuestUsize,
    index: u32,
}

struct VfioPciConfig {
    device: Arc<VfioDevice>,
}

impl VfioPciConfig {
    fn new(device: Arc<VfioDevice>) -> Self {
        VfioPciConfig { device }
    }

    fn read_config_byte(&self, offset: u32) -> u8 {
        let mut data: [u8; 1] = [0];
        self.device
            .region_read(VFIO_PCI_CONFIG_REGION_INDEX, data.as_mut(), offset.into());

        data[0]
    }

    fn read_config_word(&self, offset: u32) -> u16 {
        let mut data: [u8; 2] = [0, 0];
        self.device
            .region_read(VFIO_PCI_CONFIG_REGION_INDEX, data.as_mut(), offset.into());

        u16::from_le_bytes(data)
    }

    fn read_config_dword(&self, offset: u32) -> u32 {
        let mut data: [u8; 4] = [0, 0, 0, 0];
        self.device
            .region_read(VFIO_PCI_CONFIG_REGION_INDEX, data.as_mut(), offset.into());

        u32::from_le_bytes(data)
    }

    fn write_config_dword(&self, buf: u32, offset: u32) {
        let data: [u8; 4] = buf.to_le_bytes();
        self.device
            .region_write(VFIO_PCI_CONFIG_REGION_INDEX, &data, offset.into())
    }
}

/// VfioPciDevice represents a VFIO PCI device.
/// This structure implements the BusDevice and PciDevice traits.
///
/// A VfioPciDevice is bound to a VfioDevice and is also a PCI device.
/// The VMM creates a VfioDevice, then assigns it to a VfioPciDevice,
/// which then gets added to the PCI bus.
pub struct VfioPciDevice {
    vm_fd: Arc<VmFd>,
    device: Arc<VfioDevice>,
    vfio_pci_configuration: VfioPciConfig,
    configuration: PciConfiguration,
    mmio_regions: Vec<MmioRegion>,
    interrupt: Interrupt,
}

impl VfioPciDevice {
    /// Constructs a new Vfio Pci device for the given Vfio device
    pub fn new(
        vm_fd: &Arc<VmFd>,
        allocator: &mut SystemAllocator,
        device: VfioDevice,
    ) -> Result<Self> {
        let device = Arc::new(device);
        device.reset();

        let configuration = PciConfiguration::new(
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

        let vfio_pci_configuration = VfioPciConfig::new(Arc::clone(&device));

        let mut vfio_pci_device = VfioPciDevice {
            vm_fd: vm_fd.clone(),
            device,
            configuration,
            vfio_pci_configuration,
            mmio_regions: Vec::new(),
            interrupt: Interrupt {
                msi: None,
                msix: None,
            },
        };

        vfio_pci_device.parse_capabilities();

        Ok(vfio_pci_device)
    }

    fn parse_msix_capabilities(&mut self, cap: u8) {
        let msg_ctl = self
            .vfio_pci_configuration
            .read_config_word((cap + 2).into());

        let table = self
            .vfio_pci_configuration
            .read_config_dword((cap + 4).into());

        let pba = self
            .vfio_pci_configuration
            .read_config_dword((cap + 8).into());

        let msix_cap = MsixCap {
            msg_ctl,
            table,
            pba,
        };
        let msix_config = MsixConfig::new(msix_cap.table_size());

        self.interrupt.msix = Some(VfioMsix {
            bar: msix_config,
            cap: msix_cap,
            cap_offset: cap.into(),
        });
    }

    fn parse_msi_capabilities(&mut self, cap: u8) {
        let msg_ctl = self
            .vfio_pci_configuration
            .read_config_word((cap + 2).into());

        self.interrupt.msi = Some(VfioMsi {
            cap: MsiCap {
                msg_ctl,
                ..Default::default()
            },
            cap_offset: cap.into(),
        });
    }

    fn parse_capabilities(&mut self) {
        let mut cap_next = self
            .vfio_pci_configuration
            .read_config_byte(PCI_CONFIG_CAPABILITY_OFFSET);

        while cap_next != 0 {
            let cap_id = self
                .vfio_pci_configuration
                .read_config_byte(cap_next.into());

            match PciCapabilityID::from(cap_id) {
                PciCapabilityID::MessageSignalledInterrupts => {
                    self.parse_msi_capabilities(cap_next);
                }
                PciCapabilityID::MSIX => {
                    self.parse_msix_capabilities(cap_next);
                }
                _ => {}
            };

            cap_next = self
                .vfio_pci_configuration
                .read_config_byte((cap_next + 1).into());
        }
    }

    fn update_msi_capabilities(&mut self, offset: u64, data: &[u8]) {
        self.interrupt.update_msix(offset, data);
    }

    fn update_msix_capabilities(&mut self, offset: u64, data: &[u8]) {
        self.interrupt.update_msix(offset, data);
    }

    fn find_region(&self, addr: u64) -> Option<MmioRegion> {
        for region in self.mmio_regions.iter() {
            if addr >= region.start.raw_value()
                && addr < region.start.unchecked_add(region.length).raw_value()
            {
                return Some(*region);
            }
        }
        None
    }
}

impl Drop for VfioPciDevice {
    fn drop(&mut self) {
        if self.interrupt.msi.is_some() && self.device.disable_msi().is_err() {
            error!("Could not disable MSI");
        }

        if self.interrupt.msix.is_some() && self.device.disable_msix().is_err() {
            error!("Could not disable MSI-X");
        }

        if self.device.unset_dma_map().is_err() {
            error!("failed to remove all guest memory regions from iommu table");
        }
    }
}

impl BusDevice for VfioPciDevice {
    fn read(&mut self, base: u64, offset: u64, data: &mut [u8]) {
        self.read_bar(base, offset, data)
    }

    fn write(&mut self, base: u64, offset: u64, data: &[u8]) {
        self.write_bar(base, offset, data)
    }
}

// First BAR offset in the PCI config space.
const PCI_CONFIG_BAR_OFFSET: u32 = 0x10;
// First BAR register index
const PCI_CONFIG_BAR0_INDEX: usize = 4;
// Capability register offset in the PCI config space.
const PCI_CONFIG_CAPABILITY_OFFSET: u32 = 0x34;
// IO BAR when first BAR bit is 1.
const PCI_CONFIG_IO_BAR: u32 = 0x1;
// Memory BAR flags (lower 4 bits).
const PCI_CONFIG_MEMORY_BAR_FLAG_MASK: u32 = 0xf;
// 64-bit memory bar flag.
const PCI_CONFIG_MEMORY_BAR_64BIT: u32 = 0x4;
// PCI config register size (4 bytes).
const PCI_CONFIG_REGISTER_SIZE: usize = 4;
// Number of BARs for a PCI device
const BAR_NUMS: usize = 6;

impl PciDevice for VfioPciDevice {
    fn allocate_bars(
        &mut self,
        allocator: &mut SystemAllocator,
    ) -> std::result::Result<Vec<(GuestAddress, GuestUsize, PciBarRegionType)>, PciDeviceError>
    {
        let mut ranges = Vec::new();
        let mut bar_id = VFIO_PCI_BAR0_REGION_INDEX as u32;

        // Going through all regular regions to compute the BAR size.
        // We're not saving the BAR address to restore it, because we
        // are going to allocate a guest address for each BAR and write
        // that new address back.
        while bar_id < VFIO_PCI_ROM_REGION_INDEX {
            let mut lsb_size: u32 = 0xffff_ffff;
            let mut msb_size = 0;
            let mut region_size: u64;
            let bar_addr: GuestAddress;

            // Read the BAR size (Starts by all 1s to the BAR)
            let bar_offset = PCI_CONFIG_BAR_OFFSET + bar_id * 4;

            self.vfio_pci_configuration
                .write_config_dword(lsb_size, bar_offset);
            lsb_size = self.vfio_pci_configuration.read_config_dword(bar_offset);

            // We've just read the BAR size back. Or at least its LSB.
            let lsb_flag = lsb_size & PCI_CONFIG_MEMORY_BAR_FLAG_MASK;

            if lsb_size == 0 {
                bar_id += 1;
                continue;
            }

            // Is this an IO BAR?
            let io_bar = match lsb_flag & PCI_CONFIG_IO_BAR {
                PCI_CONFIG_IO_BAR => true,
                _ => false,
            };

            // Is this a 64-bit BAR?
            let is_64bit_bar = match lsb_flag & PCI_CONFIG_MEMORY_BAR_64BIT {
                PCI_CONFIG_MEMORY_BAR_64BIT => true,
                _ => false,
            };

            // By default, the region type is 32 bits memory BAR.
            let mut region_type = PciBarRegionType::Memory32BitRegion;

            if io_bar {
                // IO BAR
                region_type = PciBarRegionType::IORegion;

                // Clear first bit.
                lsb_size &= 0xffff_fffc;

                // Find the first bit that's set to 1.
                let first_bit = lsb_size.trailing_zeros();
                region_size = 2u64.pow(first_bit);
                // We need to allocate a guest PIO address range for that BAR.
                bar_addr = allocator
                    .allocate_io_addresses(None, region_size, Some(0x4))
                    .ok_or_else(|| PciDeviceError::IoAllocationFailed(region_size))?;
            } else {
                if is_64bit_bar {
                    // 64 bits Memory BAR
                    region_type = PciBarRegionType::Memory64BitRegion;

                    msb_size = 0xffff_ffff;
                    let msb_bar_offset: u32 = PCI_CONFIG_BAR_OFFSET + (bar_id + 1) * 4;

                    self.vfio_pci_configuration
                        .write_config_dword(msb_bar_offset, msb_size);

                    msb_size = self
                        .vfio_pci_configuration
                        .read_config_dword(msb_bar_offset);
                }

                // Clear the first four bytes from our LSB.
                lsb_size &= 0xffff_fff0;

                region_size = u64::from(msb_size);
                region_size <<= 32;
                region_size |= u64::from(lsb_size);

                // Find the first that's set to 1.
                let first_bit = region_size.trailing_zeros();
                region_size = 2u64.pow(first_bit);

                // We need to allocate a guest MMIO address range for that BAR.
                if is_64bit_bar {
                    bar_addr = allocator
                        .allocate_mmio_addresses(None, region_size, Some(0x1000))
                        .ok_or_else(|| PciDeviceError::IoAllocationFailed(region_size))?;
                } else {
                    bar_addr = allocator
                        .allocate_mmio_hole_addresses(None, region_size, Some(0x1000))
                        .ok_or_else(|| PciDeviceError::IoAllocationFailed(region_size))?;
                }
            }

            // We can now build our BAR configuration block.
            let config = PciBarConfiguration::default()
                .set_register_index(bar_id as usize)
                .set_address(bar_addr.raw_value())
                .set_size(region_size)
                .set_region_type(region_type);

            self.configuration
                .add_pci_bar(&config)
                .map_err(|e| PciDeviceError::IoRegistrationFailed(bar_addr.raw_value(), e))?;

            ranges.push((bar_addr, region_size, region_type));
            self.mmio_regions.push(MmioRegion {
                start: bar_addr,
                length: region_size,
                index: bar_id as u32,
            });

            bar_id += 1;
            if is_64bit_bar {
                bar_id += 1;
            }
        }

        if self.device.setup_dma_map().is_err() {
            error!("failed to add all guest memory regions into iommu table");
        }

        Ok(ranges)
    }

    fn write_config_register(&mut self, reg_idx: usize, offset: u64, data: &[u8]) {
        // When the guest wants to write to a BAR, we trap it into
        // our local configuration space. We're not reprogramming
        // VFIO device.
        if reg_idx >= PCI_CONFIG_BAR0_INDEX && reg_idx < PCI_CONFIG_BAR0_INDEX + BAR_NUMS {
            // We keep our local cache updated with the BARs.
            // We'll read it back from there when the guest is asking
            // for BARs (see read_config_register()).
            return self
                .configuration
                .write_config_register(reg_idx, offset, data);
        }

        let reg = (reg_idx * PCI_CONFIG_REGISTER_SIZE) as u64;
        self.device
            .region_write(VFIO_PCI_CONFIG_REGION_INDEX, data, reg + offset);

        // If the MSI or MSI-X capabilities are accessed, we need to
        // update our local cache accordingly.
        // Depending on how the capabilities are modified, this could
        // trigger a VFIO MSI or MSI-X toggle.
        if let Some((cap_id, cap_base)) = self.interrupt.accessed(reg) {
            let cap_offset: u64 = reg - cap_base + offset;
            match cap_id {
                PciCapabilityID::MessageSignalledInterrupts => {
                    self.update_msi_capabilities(cap_offset, data);
                }
                PciCapabilityID::MSIX => {
                    self.update_msix_capabilities(cap_offset, data);
                }
                _ => {}
            }
        }
    }

    fn read_config_register(&self, reg_idx: usize) -> u32 {
        // When reading the BARs, we trap it and return what comes
        // from our local configuration space. We want the guest to
        // use that and not the VFIO device BARs as it does not map
        // with the guest address space.
        if reg_idx >= PCI_CONFIG_BAR0_INDEX && reg_idx < PCI_CONFIG_BAR0_INDEX + BAR_NUMS {
            return self.configuration.read_reg(reg_idx);
        }

        // The config register read comes from the VFIO device itself.
        self.vfio_pci_configuration
            .read_config_dword((reg_idx * 4) as u32)
    }

    fn read_bar(&mut self, base: u64, offset: u64, data: &mut [u8]) {
        let addr = base + offset;
        if let Some(region) = self.find_region(addr) {
            let offset = addr - region.start.raw_value();
            self.device.region_read(region.index, data, offset);
        }
    }

    fn write_bar(&mut self, base: u64, offset: u64, data: &[u8]) {
        let addr = base + offset;
        if let Some(region) = self.find_region(addr) {
            let offset = addr - region.start.raw_value();
            self.device.region_write(region.index, data, offset);
        }
    }
}
