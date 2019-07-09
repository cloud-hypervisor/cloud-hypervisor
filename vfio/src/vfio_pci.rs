// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//

extern crate devices;
extern crate pci;
extern crate vm_allocator;
extern crate vm_memory;

use devices::BusDevice;
use kvm_bindings::kvm_userspace_memory_region;
use kvm_ioctls::*;
use pci::{
    PciBarConfiguration, PciCapabilityID, PciClassCode, PciConfiguration, PciDevice,
    PciDeviceError, PciHeaderType, PciSubclass,
};
use std::fmt;
use std::io;
use std::os::unix::io::AsRawFd;
use std::ptr::null_mut;
use std::sync::Arc;
use std::u32;
use vfio_bindings::bindings::vfio::*;
use vm_allocator::SystemAllocator;
use vm_memory::{Address, GuestAddress, GuestUsize};
use vmm_sys_util::EventFd;

use crate::vfio_device::VfioDevice;

const PCI_CONFIG_BAR_OFFSET: u32 = 0x10;
const PCI_CONFIG_CAPABILITY_OFFSET: u32 = 0x34;
// IO BAR when first BAR bit is 1.
const PCI_CONFIG_IO_BAR: u32 = 0x1;

// Memory BAR flags (lower 4 bits)
const PCI_CONFIG_MEMORY_BAR_FLAG_MASK: u32 = 0xf;
const PCI_CONFIG_MEMORY_BAR_64BIT: u32 = 0x2 << 1;

// First BAR register index
const BAR0_REG: usize = 4;
// Number of BARs for a PCI device
const BAR_NUMS: usize = 6;

#[derive(Debug)]
pub enum VfioPciError {
    AllocateGsi,
    EventFd(io::Error),
    IrqFd(io::Error),
    NewVfioPciDevice,
    MapRegionHost(io::Error),
    MapRegionGuest(io::Error),
}
pub type Result<T> = std::result::Result<T, VfioPciError>;

impl fmt::Display for VfioPciError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VfioPciError::AllocateGsi => write!(f, "failed to allocate GSI"),
            VfioPciError::EventFd(e) => write!(f, "failed to create eventfd: {}", e),
            VfioPciError::IrqFd(e) => write!(f, "failed to register irqfd: {}", e),
            VfioPciError::NewVfioPciDevice => write!(f, "failed to create VFIO PCI device"),
            VfioPciError::MapRegionHost(e) => write!(
                f,
                "failed to mmap VFIO PCI device region on device file: {}",
                e
            ),
            VfioPciError::MapRegionGuest(e) => {
                write!(f, "failed to map VFIO PCI region into guest: {}", e)
            }
        }
    }
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

#[allow(dead_code)]
#[derive(Copy, Clone)]
struct MsiCap {
    offset: u32,
    length: u32,
    msg_ctl: u16,
    msg_address: u64,
    msg_data: u16,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Default)]
struct MsixCap {
    offset: u32,
    msg_ctl: u16,
    table: u32,
    pba: u32,
}

struct InterruptCap {
    msi: Option<MsiCap>,
    msix: Option<MsixCap>,
}

#[derive(Copy, Clone)]
struct MmioRegion {
    start: GuestAddress,
    length: GuestUsize,
    index: u32,
}

#[allow(dead_code)]
#[derive(Copy, Clone)]
struct MsiVector {
    msg_addr_lo: u32,
    msg_addr_hi: u32,
    msg_data: u32,
    dev_id: u32,
}

#[allow(dead_code)]
struct InterruptRoute {
    gsi: u32,
    irq_fd: EventFd,
    msi_vector: Option<MsiVector>,
}

impl InterruptRoute {
    fn new(
        vm: &Arc<VmFd>,
        allocator: &mut SystemAllocator,
        msi_vector: Option<MsiVector>,
    ) -> Result<Self> {
        let irq_fd = EventFd::new(libc::EFD_NONBLOCK).map_err(VfioPciError::EventFd)?;
        let gsi = allocator.allocate_irq().ok_or(VfioPciError::AllocateGsi)?;

        vm.register_irqfd(irq_fd.as_raw_fd(), gsi)
            .map_err(VfioPciError::IrqFd)?;

        Ok(InterruptRoute {
            gsi,
            irq_fd,
            msi_vector,
        })
    }
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

/// Implements the Vfio Pci device, then a pci device is added into vm
pub struct VfioPciDevice {
    device: Arc<VfioDevice>,
    vfio_pci_configuration: VfioPciConfig,
    configuration: PciConfiguration,
    mmio_regions: Vec<MmioRegion>,
    interrupt_capabilities: InterruptCap,
    interrupt_routes: Vec<InterruptRoute>,
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

        let interrupt_capabilities = InterruptCap {
            msi: None,
            msix: None,
        };

        let mut vfio_pci_device = VfioPciDevice {
            device,
            configuration,
            vfio_pci_configuration,
            mmio_regions: Vec::new(),
            interrupt_capabilities,
            interrupt_routes: Vec::new(),
        };

        vfio_pci_device.parse_capabilities();

        // Allocate temporary interrupt routes for now.
        // The MSI vectors will be filled when the guest driver programs the device.
        let max_interrupts = vfio_pci_device.device.max_interrupts();
        for _ in 0..max_interrupts {
            let mut route = InterruptRoute::new(vm_fd, allocator, None)?;
            vfio_pci_device.interrupt_routes.push(route);
        }

        Ok(vfio_pci_device)
    }

    fn write_msi_capabilities(&mut self, _offset: u64, _data: &[u8]) {}
    fn write_msix_capabilities(&mut self, offset: u64, data: &[u8]) {
        let len = data.len();
        let mut msix_cap = self.interrupt_capabilities.msix.unwrap();

        // Write MSI-X msg_ctl
        if len == 2 && offset == 2 {
            let ctl: [u8; 2] = [data[0], data[1]];
            msix_cap.msg_ctl = u16::from_le_bytes(ctl);
        }

        if len == 4 {
            let buf: [u8; 4] = [data[0], data[1], data[2], data[3]];

            // Write MSI-X table offset
            if offset == 4 {
                msix_cap.table = u32::from_le_bytes(buf);
            }

            // Write MSI-X PBA offset
            if offset == 8 {
                msix_cap.pba = u32::from_le_bytes(buf);
            }
        }

        self.interrupt_capabilities.msix = Some(msix_cap);
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
            .read_config_dword((cap + 4).into());

        println!(
            "MSIX cap @0x{:x} ctl 0x{:x} table 0x{:x} PBA 0x{:x}",
            cap, msg_ctl, table, pba
        );

        self.interrupt_capabilities.msix = Some(MsixCap {
            offset: cap.into(),
            msg_ctl,
            table,
            pba,
        });
    }

    fn parse_msi_capabilities(&mut self, cap: u8) {
        let mut msi_len: u8 = 0xa;
        let mut msg_address_msb: u32 = 0x0;

        let msg_ctl = self
            .vfio_pci_configuration
            .read_config_word((cap + 2).into());

        if msg_ctl & 0x80 != 0 {
            msi_len += 4;
            msg_address_msb = self
                .vfio_pci_configuration
                .read_config_dword((cap + 8).into());
        }
        if msg_ctl & 0x100 != 0 {
            msi_len += 0xa;
        }

        let msg_address_lsb = self
            .vfio_pci_configuration
            .read_config_dword((cap + 4).into());

        let mut msg_address = u64::from(msg_address_msb);
        msg_address <<= 32;
        msg_address |= u64::from(msg_address_lsb);

        println!(
            "MSI cap @0x{:x} ctl 0x{:x} address 0x{:x}",
            cap, msg_ctl, msg_address
        );

        self.interrupt_capabilities.msi = Some(MsiCap {
            offset: cap.into(),
            length: msi_len.into(),
            msg_ctl,
            msg_address,
            msg_data: 0,
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

            println!("Found cap ID 0x{:x}", cap_id);

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

    // Check if there is an MSI or MSIX capability structure at a given config
    // space offset.
    fn msi_capability(&self, offset: u64) -> Option<PciCapabilityID> {
        if let Some(msi_cap) = self.interrupt_capabilities.msi {
            if offset == u64::from(msi_cap.offset) {
                return Some(PciCapabilityID::MessageSignalledInterrupts);
            }
        }

        if let Some(msix_cap) = self.interrupt_capabilities.msix {
            if offset == u64::from(msix_cap.offset) {
                return Some(PciCapabilityID::MSIX);
            }
        }

        None
    }

    fn msi_enabled(&self) -> bool {
        if let Some(msi_cap) = self.interrupt_capabilities.msi {
            if msi_cap.msg_ctl & 0x1 == 0x1 {
                return true;
            }
        }

        false
    }

    fn msix_enabled(&self) -> bool {
        if let Some(msix_cap) = self.interrupt_capabilities.msix {
            if msix_cap.msg_ctl & 0x8000 == 0x8000 {
                return true;
            }
        }

        false
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

    pub fn map_mmio_regions(&mut self, vm: &Arc<VmFd>, mem_slots: u32) -> Result<()> {
        let mut slot = mem_slots;
        let fd = self.device.as_raw_fd();

        for region in self.mmio_regions.iter() {
            let region_flags = self.device.get_region_flags(region.index);
            if region_flags & VFIO_REGION_INFO_FLAG_MMAP != 0 {
                let mut prot = 0;
                if region_flags & VFIO_REGION_INFO_FLAG_READ != 0 {
                    prot |= libc::PROT_READ;
                }
                if region_flags & VFIO_REGION_INFO_FLAG_WRITE != 0 {
                    prot |= libc::PROT_WRITE;
                }
                let (mmap_offset, mmap_size) = self.device.get_region_mmap(region.index);
                let offset = self.device.get_region_offset(region.index) + mmap_offset;

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
                    error!(
                        "Could not mmap regions, error:{}",
                        io::Error::last_os_error()
                    );
                    continue;
                }

                let mem_region = kvm_userspace_memory_region {
                    slot,
                    guest_phys_addr: region.start.raw_value() + mmap_offset,
                    memory_size: mmap_size as u64,
                    userspace_addr: host_addr as u64,
                    flags: 0,
                };

                // Safe because the guest regions are guaranteed not to overlap.
                unsafe {
                    vm.set_user_memory_region(mem_region)
                        .map_err(VfioPciError::MapRegionGuest)?;
                }
                slot += 1;
            }
        }

        Ok(())
    }
}

impl Drop for VfioPciDevice {
    fn drop(&mut self) {
        if self.interrupt_capabilities.msi.is_some() && self.device.disable_msi().is_err() {
            error!("Could not disable MSI");
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

impl PciDevice for VfioPciDevice {
    fn allocate_bars(
        &mut self,
        allocator: &mut SystemAllocator,
    ) -> std::result::Result<Vec<(GuestAddress, GuestUsize)>, PciDeviceError> {
        let mut ranges = Vec::new();
        let mut bar_id = VFIO_PCI_BAR0_REGION_INDEX as u32;

        // Going through all regular regions to compute the BAR size.
        // We're not saving the BAR address to restore it, because we
        // are going to allocate a guest address for each BAR and write
        // that new address back.
        while bar_id < VFIO_PCI_ROM_REGION_INDEX {
            println!("Going through region #{}", bar_id);
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
            //            let mut lsb_size = u32::from_le_bytes(lsb_bytes);
            let lsb_flag = lsb_size & PCI_CONFIG_MEMORY_BAR_FLAG_MASK;

            println! {"\tLSB size 0x{:x} flags 0x{:x}", lsb_size, lsb_flag};

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

            println!("\tIO:{} 64-bit:{}", io_bar, is_64bit_bar);

            if io_bar {
                // Clear first bit.
                lsb_size &= 0xffff_fffc;

                // Find the first bit that's set to 1.
                let first_bit = lsb_size.trailing_zeros();
                region_size = 2u64.pow(first_bit);
                // We need to allocate a guest PIO address range for that BAR.
                bar_addr = allocator
                    .allocate_io_addresses(None, region_size, Some(region_size))
                    .ok_or_else(|| PciDeviceError::IoAllocationFailed(region_size))?;
            } else {
                if is_64bit_bar {
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
                bar_addr = allocator
                    .allocate_mmio_addresses(None, region_size, Some(region_size))
                    .ok_or_else(|| PciDeviceError::IoAllocationFailed(region_size))?;
            }

            println!("\tRegion size {}", region_size);
            println!("\tBAR address 0x{:x}", bar_addr.raw_value());

            // We can now build our BAR configuration block.
            let config = PciBarConfiguration::default()
                .set_register_index(bar_id as usize)
                .set_address(bar_addr.raw_value())
                .set_size(region_size);

            self.configuration
                .add_pci_bar(&config)
                .map_err(|e| PciDeviceError::IoRegistrationFailed(bar_addr.raw_value(), e))?;

            ranges.push((bar_addr, region_size));
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
        // Keep our configuration map updated.
        self.configuration
            .write_config_register(reg_idx, offset, data);

        // When the guest wants to write to a BAR, we trap it into
        // our local configuration space. We're not reprogramming
        // VFIO device.
        if reg_idx >= BAR0_REG && reg_idx < BAR0_REG + BAR_NUMS {
            return;
        }

        let base = (reg_idx * 4) as u8;
        let start = u64::from(base) + offset;

        match self.msi_capability(u64::from(base)) {
            Some(PciCapabilityID::MessageSignalledInterrupts) => {
                let old_enabled = self.msi_enabled();
                self.write_msi_capabilities(offset, data);
                let new_enabled = self.msi_enabled();

                if !old_enabled && new_enabled {
                    // Switching from disabled to enabled
                    println!("VFIO: Enabling MSI");
                    if let Err(e) = self.device.enable_msi(&self.interrupt_routes[0].irq_fd) {
                        warn!("Could not enable MSI: {}", e);
                    }
                } else if old_enabled && !new_enabled {
                    // Switching from enabled to disabled
                    println!("VFIO: Disabling MSI");
                    if let Err(e) = self.device.disable_msi() {
                        warn!("Could not disable MSI: {}", e);
                    }
                }
            }
            Some(PciCapabilityID::MSIX) => {
                let old_enabled = self.msix_enabled();
                self.write_msix_capabilities(offset, data);
                let new_enabled = self.msix_enabled();
                println!(
                    "MSI-X: Old enabled {} new enabled {}",
                    old_enabled, new_enabled
                );

                if !old_enabled && new_enabled {
                    // Switching from disabled to enabled
                    println!("VFIO: Enabling MSIX");
                    if let Err(e) = self.device.enable_msix(&self.interrupt_routes[0].irq_fd) {
                        warn!("Could not enable MSIX: {}", e);
                    }
                } else if old_enabled && !new_enabled {
                    println!("VFIO: Disabling MSIX");
                    if let Err(e) = self.device.disable_msix() {
                        warn!("Could not disable MSIX: {}", e);
                    }
                }
            }
            _ => {}
        }

        self.device
            .region_write(VFIO_PCI_CONFIG_REGION_INDEX, data, start);
    }

    fn read_config_register(&self, reg_idx: usize) -> u32 {
        // When reading the BARs, we trap it and return what comes
        // from our local configuration space. We want the guest to
        // use that and not the VFIO device BARs as it does not map
        // with the guest address space.
        if reg_idx >= BAR0_REG && reg_idx < BAR0_REG + BAR_NUMS {
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
