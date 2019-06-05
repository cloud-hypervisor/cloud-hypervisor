// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

use crate::configuration::{PciBridgeSubclass, PciClassCode, PciConfiguration, PciHeaderType};
use crate::device::{Error as PciDeviceError, PciDevice};
use byteorder::{ByteOrder, LittleEndian};
use devices::BusDevice;
use std;
use std::sync::Arc;
use std::sync::Mutex;
use vm_memory::{Address, GuestAddress, GuestUsize};

const VENDOR_ID_INTEL: u16 = 0x8086;
const DEVICE_ID_INTEL_VIRT_PCIE_HOST: u16 = 0x0d57;

/// Errors for device manager.
#[derive(Debug)]
pub enum PciRootError {
    /// Could not allocate device address space for the device.
    AllocateDeviceAddrs(PciDeviceError),
    /// Could not allocate an IRQ number.
    AllocateIrq,
    /// Could not add a device to the mmio bus.
    MmioInsert(devices::BusError),
}
pub type Result<T> = std::result::Result<T, PciRootError>;

/// Emulates the PCI Root bridge.
pub struct PciRoot {
    /// Bus configuration for the root device.
    configuration: PciConfiguration,
    /// Devices attached to this bridge.
    devices: Vec<Arc<Mutex<dyn PciDevice>>>,
}

impl PciRoot {
    /// Create an empty PCI root bus.
    pub fn new(configuration: Option<PciConfiguration>) -> Self {
        if let Some(config) = configuration {
            PciRoot {
                configuration: config,
                devices: Vec::new(),
            }
        } else {
            PciRoot {
                configuration: PciConfiguration::new(
                    VENDOR_ID_INTEL,
                    DEVICE_ID_INTEL_VIRT_PCIE_HOST,
                    PciClassCode::BridgeDevice,
                    &PciBridgeSubclass::HostBridge,
                    None,
                    PciHeaderType::Bridge,
                    0,
                    0,
                    None,
                ),
                devices: Vec::new(),
            }
        }
    }

    /// Add a `device` to this root PCI bus.
    pub fn add_device(&mut self, pci_device: Arc<Mutex<dyn PciDevice>>) -> Result<()> {
        self.devices.push(pci_device);
        Ok(())
    }

    /// Register Guest Address mapping of a `device` to IO bus.
    pub fn register_mapping(
        &self,
        device: Arc<Mutex<dyn BusDevice>>,
        bus: &mut devices::Bus,
        bars: Vec<(GuestAddress, GuestUsize)>,
    ) -> Result<()> {
        for (address, size) in bars {
            bus.insert(device.clone(), address.raw_value(), size)
                .map_err(PciRootError::MmioInsert)?;
        }
        Ok(())
    }
    pub fn config_space_read(
        &self,
        bus: usize,
        device: usize,
        _function: usize,
        register: usize,
    ) -> u32 {
        // Only support one bus.
        if bus != 0 {
            return 0xffff_ffff;
        }

        match device {
            0 => {
                // If bus and device are both zero, then read from the root config.
                self.configuration.read_config_register(register)
            }
            dev_num => self.devices.get(dev_num - 1).map_or(0xffff_ffff, |d| {
                d.lock().unwrap().read_config_register(register)
            }),
        }
    }

    pub fn config_space_write(
        &mut self,
        bus: usize,
        device: usize,
        _function: usize,
        register: usize,
        offset: u64,
        data: &[u8],
    ) {
        if offset as usize + data.len() > 4 {
            return;
        }

        // Only support one bus.
        if bus != 0 {
            return;
        }

        match device {
            0 => {
                // If bus and device are both zero, then read from the root config.
                self.configuration
                    .write_config_register(register, offset, data);
            }
            dev_num => {
                if let Some(d) = self.devices.get(dev_num - 1) {
                    d.lock()
                        .unwrap()
                        .write_config_register(register, offset, data);
                }
            }
        }
    }
}

/// Emulates PCI configuration access mechanism #1 (I/O ports 0xcf8 and 0xcfc).
pub struct PciConfigIo {
    /// PCI root bridge.
    pci_root: PciRoot,
    /// Current address to read/write from (0xcf8 register, litte endian).
    config_address: u32,
}

impl PciConfigIo {
    pub fn new(pci_root: PciRoot) -> Self {
        PciConfigIo {
            pci_root,
            config_address: 0,
        }
    }

    fn config_space_read(&self) -> u32 {
        let enabled = (self.config_address & 0x8000_0000) != 0;
        if !enabled {
            return 0xffff_ffff;
        }

        let (bus, device, function, register) =
            parse_config_address(self.config_address & !0x8000_0000);
        self.pci_root
            .config_space_read(bus, device, function, register)
    }

    fn config_space_write(&mut self, offset: u64, data: &[u8]) {
        let enabled = (self.config_address & 0x8000_0000) != 0;
        if !enabled {
            return;
        }

        let (bus, device, function, register) =
            parse_config_address(self.config_address & !0x8000_0000);
        self.pci_root
            .config_space_write(bus, device, function, register, offset, data)
    }

    fn set_config_address(&mut self, offset: u64, data: &[u8]) {
        if offset as usize + data.len() > 4 {
            return;
        }
        let (mask, value): (u32, u32) = match data.len() {
            1 => (
                0x0000_00ff << (offset * 8),
                u32::from(data[0]) << (offset * 8),
            ),
            2 => (
                0x0000_ffff << (offset * 16),
                (u32::from(data[1]) << 8 | u32::from(data[0])) << (offset * 16),
            ),
            4 => (0xffff_ffff, LittleEndian::read_u32(data)),
            _ => return,
        };
        self.config_address = (self.config_address & !mask) | value;
    }
}

impl BusDevice for PciConfigIo {
    fn read(&mut self, offset: u64, data: &mut [u8]) {
        // `offset` is relative to 0xcf8
        let value = match offset {
            0...3 => self.config_address,
            4...7 => self.config_space_read(),
            _ => 0xffff_ffff,
        };

        // Only allow reads to the register boundary.
        let start = offset as usize % 4;
        let end = start + data.len();
        if end <= 4 {
            for i in start..end {
                data[i - start] = (value >> (i * 8)) as u8;
            }
        } else {
            for d in data {
                *d = 0xff;
            }
        }
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        // `offset` is relative to 0xcf8
        match offset {
            o @ 0...3 => self.set_config_address(o, data),
            o @ 4...7 => self.config_space_write(o - 4, data),
            _ => (),
        };
    }
}

/// Emulates PCI memory-mapped configuration access mechanism.
pub struct PciConfigMmio {
    /// PCI root bridge.
    pci_root: PciRoot,
}

impl PciConfigMmio {
    pub fn new(pci_root: PciRoot) -> Self {
        PciConfigMmio { pci_root }
    }

    fn config_space_read(&self, config_address: u32) -> u32 {
        let (bus, device, function, register) = parse_config_address(config_address);
        self.pci_root
            .config_space_read(bus, device, function, register)
    }

    fn config_space_write(&mut self, config_address: u32, offset: u64, data: &[u8]) {
        let (bus, device, function, register) = parse_config_address(config_address);
        self.pci_root
            .config_space_write(bus, device, function, register, offset, data)
    }
}

impl BusDevice for PciConfigMmio {
    fn read(&mut self, offset: u64, data: &mut [u8]) {
        // Only allow reads to the register boundary.
        let start = offset as usize % 4;
        let end = start + data.len();
        if end > 4 || offset > u64::from(u32::max_value()) {
            for d in data {
                *d = 0xff;
            }
            return;
        }

        let value = self.config_space_read(offset as u32);
        for i in start..end {
            data[i - start] = (value >> (i * 8)) as u8;
        }
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        if offset > u64::from(u32::max_value()) {
            return;
        }
        self.config_space_write(offset as u32, offset % 4, data)
    }
}

// Parse the CONFIG_ADDRESS register to a (bus, device, function, register) tuple.
fn parse_config_address(config_address: u32) -> (usize, usize, usize, usize) {
    const BUS_NUMBER_OFFSET: usize = 16;
    const BUS_NUMBER_MASK: u32 = 0x00ff;
    const DEVICE_NUMBER_OFFSET: usize = 11;
    const DEVICE_NUMBER_MASK: u32 = 0x1f;
    const FUNCTION_NUMBER_OFFSET: usize = 8;
    const FUNCTION_NUMBER_MASK: u32 = 0x07;
    const REGISTER_NUMBER_OFFSET: usize = 2;
    const REGISTER_NUMBER_MASK: u32 = 0x3f;

    let bus_number = ((config_address >> BUS_NUMBER_OFFSET) & BUS_NUMBER_MASK) as usize;
    let device_number = ((config_address >> DEVICE_NUMBER_OFFSET) & DEVICE_NUMBER_MASK) as usize;
    let function_number =
        ((config_address >> FUNCTION_NUMBER_OFFSET) & FUNCTION_NUMBER_MASK) as usize;
    let register_number =
        ((config_address >> REGISTER_NUMBER_OFFSET) & REGISTER_NUMBER_MASK) as usize;

    (bus_number, device_number, function_number, register_number)
}
