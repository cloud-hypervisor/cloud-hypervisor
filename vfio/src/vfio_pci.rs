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
    InterruptDelivery, PciBarConfiguration, PciCapabilityID, PciClassCode, PciConfiguration,
    PciDevice, PciDeviceError, PciHeaderType, PciInterruptPin, PciSubclass,
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

const PCI_CONFIG_BAR_OFFSET: u64 = 0x10;
const PCI_CONFIG_CAPABILITY_OFFSET: u64 = 0x34;
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
    NewVfioPciDevice,
    MapRegionHost(io::Error),
    MapRegionGuest(io::Error),
}
pub type Result<T> = std::result::Result<T, VfioPciError>;

impl fmt::Display for VfioPciError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
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

/// Implements the Vfio Pci device, then a pci device is added into vm
pub struct VfioPciDevice {
    device: Arc<VfioDevice>,
    configuration: PciConfiguration,
    interrupt_evt: Option<EventFd>,
    mmio_regions: Vec<MmioRegion>,
    interrupt_capabilities: InterruptCap,
    virq: u32,
}

impl VfioPciDevice {
    /// Constructs a new Vfio Pci device for the given Vfio device
    pub fn new(device: VfioDevice) -> Result<Self> {
        device.reset();

        let mut id = vec![0; 4];
        // Vendor and device IDs
        device.region_read(VFIO_PCI_CONFIG_REGION_INDEX, &mut id, 0x0);

        let device_id: u16 = u16::from(id[0]) | u16::from(id[1]) << 8;
        let vendor_id: u16 = u16::from(id[2]) | u16::from(id[3]) << 8;

        // Sub vendor and device IDs
        device.region_read(VFIO_PCI_CONFIG_REGION_INDEX, &mut id, 0x40);
        let sub_vendor_id: u16 = u16::from(id[0]) | u16::from(id[1]) << 8;
        let sub_device_id: u16 = u16::from(id[2]) | u16::from(id[3]) << 8;

        let configuration = PciConfiguration::new(
            vendor_id,
            device_id,
            PciClassCode::Other,
            &PciVfioSubclass::VfioSubclass,
            None,
            PciHeaderType::Device,
            sub_vendor_id,
            sub_device_id,
            None,
        );

        let interrupt_capabilities = InterruptCap {
            msi: None,
            msix: None,
        };

        let mut vfio_pci_device = VfioPciDevice {
            device: Arc::new(device),
            configuration,
            interrupt_evt: None,
            mmio_regions: Vec::new(),
            interrupt_capabilities,
            virq: 0,
        };

        vfio_pci_device.parse_capabilities();

        Ok(vfio_pci_device)
    }

    fn parse_msix_capabilities(&mut self, cap: u8) {
        let mut msg_ctl: u16 = 0;
        let mut table: u32 = 0;
        let mut pba: u32 = 0;

        // safe as convert u16 to &[u8;2]
        self.device.region_read(
            VFIO_PCI_CONFIG_REGION_INDEX,
            unsafe {
                ::std::slice::from_raw_parts_mut(&mut *(&mut msg_ctl as *mut u16 as *mut u8), 2)
            },
            (cap + 2).into(),
        );

        self.device.region_read(
            VFIO_PCI_CONFIG_REGION_INDEX,
            unsafe {
                ::std::slice::from_raw_parts_mut(&mut *(&mut table as *mut u32 as *mut u8), 4)
            },
            (cap + 4).into(),
        );

        self.device.region_read(
            VFIO_PCI_CONFIG_REGION_INDEX,
            unsafe { ::std::slice::from_raw_parts_mut(&mut *(&mut pba as *mut u32 as *mut u8), 4) },
            (cap + 8).into(),
        );

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
        let mut msg_ctl: u16 = 0;
        let mut msg_address_lsb: u32 = 0xff;
        let mut msg_address_msb: u32 = 0x0;

        // safe as convert u16 to &[u8;2]
        self.device.region_read(
            VFIO_PCI_CONFIG_REGION_INDEX,
            unsafe {
                ::std::slice::from_raw_parts_mut(&mut *(&mut msg_ctl as *mut u16 as *mut u8), 2)
            },
            (cap + 2).into(),
        );

        if msg_ctl & 0x80 != 0 {
            msi_len += 4;
            self.device.region_read(
                VFIO_PCI_CONFIG_REGION_INDEX,
                unsafe {
                    ::std::slice::from_raw_parts_mut(
                        &mut *(&mut msg_address_msb as *mut u32 as *mut u8),
                        4,
                    )
                },
                (cap + 8).into(),
            );
        }
        if msg_ctl & 0x100 != 0 {
            msi_len += 0xa;
        }

        self.device.region_read(
            VFIO_PCI_CONFIG_REGION_INDEX,
            unsafe {
                ::std::slice::from_raw_parts_mut(
                    &mut *(&mut msg_address_lsb as *mut u32 as *mut u8),
                    4,
                )
            },
            (cap + 4).into(),
        );

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
        let mut cap_next: u8 = 0;

        // safe as convert u8 to &[u8;1]
        self.device.region_read(
            VFIO_PCI_CONFIG_REGION_INDEX,
            unsafe { ::std::slice::from_raw_parts_mut(&mut cap_next, 1) },
            PCI_CONFIG_CAPABILITY_OFFSET,
        );

        while cap_next != 0 {
            let mut cap_id: u8 = 0;
            // safe as convert u8 to &[u8;1]
            self.device.region_read(
                VFIO_PCI_CONFIG_REGION_INDEX,
                unsafe { ::std::slice::from_raw_parts_mut(&mut cap_id, 1) },
                cap_next.into(),
            );

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

            // Read next capability.
            // safe as convert u8 to &[u8;1]
            self.device.region_read(
                VFIO_PCI_CONFIG_REGION_INDEX,
                unsafe { ::std::slice::from_raw_parts_mut(&mut cap_next, 1) },
                (cap_next + 1).into(),
            );
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
    fn assign_pin_irq(
        &mut self,
        irq_evt: Option<EventFd>,
        _irq_cb: Arc<InterruptDelivery>,
        irq_num: u32,
        irq_pin: PciInterruptPin,
    ) {
        self.configuration.set_irq(irq_num as u8, irq_pin);
        self.interrupt_evt = irq_evt;
        self.virq = irq_num;
    }

    fn allocate_bars(
        &mut self,
        allocator: &mut SystemAllocator,
    ) -> std::result::Result<Vec<(GuestAddress, GuestUsize)>, PciDeviceError> {
        let mut ranges = Vec::new();
        let mut bar_id = u64::from(VFIO_PCI_BAR0_REGION_INDEX);

        // Going through all regular regions to compute the BAR size.
        // We're not saving the BAR address to restore it, because we
        // are going to allocate a guest address for each BAR and write
        // that new address back.
        while bar_id < VFIO_PCI_ROM_REGION_INDEX.into() {
            println!("Going through region #{}", bar_id);
            let mut lsb_bytes: [u8; 4] = [0xff, 0xff, 0xff, 0xff];
            let mut msb_bytes: [u8; 4] = [0, 0, 0, 0];
            let mut region_size: u64;
            let bar_addr: GuestAddress;

            // Read the BAR size (Starts by all 1s to the BAR)
            self.device.region_write(
                VFIO_PCI_CONFIG_REGION_INDEX,
                lsb_bytes.as_mut(),
                (PCI_CONFIG_BAR_OFFSET + bar_id * 4) as u64,
            );
            self.device.region_read(
                VFIO_PCI_CONFIG_REGION_INDEX,
                lsb_bytes.as_mut(),
                (PCI_CONFIG_BAR_OFFSET + bar_id * 4) as u64,
            );

            // We've just read the BAR size back. Or at least its LSB.
            let mut lsb_size = u32::from_le_bytes(lsb_bytes);
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
                    let msb_bar_id = bar_id + 1;
                    msb_bytes = [0xff, 0xff, 0xff, 0xff];

                    self.device.region_write(
                        VFIO_PCI_CONFIG_REGION_INDEX,
                        msb_bytes.as_mut(),
                        (PCI_CONFIG_BAR_OFFSET + msb_bar_id * 4) as u64,
                    );
                    self.device.region_read(
                        VFIO_PCI_CONFIG_REGION_INDEX,
                        msb_bytes.as_mut(),
                        (PCI_CONFIG_BAR_OFFSET + msb_bar_id * 4) as u64,
                    );
                }

                let msb_size = u32::from_le_bytes(msb_bytes);

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
        self.device
            .region_write(VFIO_PCI_CONFIG_REGION_INDEX, data, start);

        match self.msi_capability(u64::from(base)) {
            Some(PciCapabilityID::MessageSignalledInterrupts) => {
                let old_enabled = self.msi_enabled();
                self.parse_msi_capabilities(base);
                let new_enabled = self.msi_enabled();

                if !old_enabled && new_enabled {
                    // Switching from disabled to enabled
                    if let Some(ref interrupt_evt) = self.interrupt_evt {
                        println!("VFIO: Enabling MSI");
                        if let Err(e) = self.device.enable_msi(interrupt_evt) {
                            warn!("Could not enable MSI: {}", e);
                        }
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
                self.parse_msix_capabilities(base);
                let new_enabled = self.msix_enabled();

                if !old_enabled && new_enabled {
                    // Switching from disabled to enabled
                    if let Some(ref interrupt_evt) = self.interrupt_evt {
                        println!("VFIO: Enabling MSIX");
                        if let Err(e) = self.device.enable_msix(interrupt_evt) {
                            warn!("Could not enable MSIX: {}", e);
                        }
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
        let mut config: [u8; 4] = [0, 0, 0, 0];
        self.device.region_read(
            VFIO_PCI_CONFIG_REGION_INDEX,
            config.as_mut(),
            (reg_idx * 4) as u64,
        );

        u32::from_le_bytes(config)
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
