// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

use std::sync::{Arc, Mutex};

use crate::{MsixConfig, PciInterruptPin};
use byteorder::{ByteOrder, LittleEndian};
use std::fmt::{self, Display};

// The number of 32bit registers in the config space, 256 bytes.
const NUM_CONFIGURATION_REGISTERS: usize = 64;

const STATUS_REG: usize = 1;
const STATUS_REG_CAPABILITIES_USED_MASK: u32 = 0x0010_0000;
const BAR0_REG: usize = 4;
const BAR_IO_ADDR_MASK: u32 = 0xffff_fffc;
const BAR_MEM_ADDR_MASK: u32 = 0xffff_fff0;
const NUM_BAR_REGS: usize = 6;
const CAPABILITY_LIST_HEAD_OFFSET: usize = 0x34;
const FIRST_CAPABILITY_OFFSET: usize = 0x40;
const CAPABILITY_MAX_OFFSET: usize = 192;

const INTERRUPT_LINE_PIN_REG: usize = 15;

/// Represents the types of PCI headers allowed in the configuration registers.
#[derive(Copy, Clone)]
pub enum PciHeaderType {
    Device,
    Bridge,
}

/// Classes of PCI nodes.
#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum PciClassCode {
    TooOld,
    MassStorage,
    NetworkController,
    DisplayController,
    MultimediaController,
    MemoryController,
    BridgeDevice,
    SimpleCommunicationController,
    BaseSystemPeripheral,
    InputDevice,
    DockingStation,
    Processor,
    SerialBusController,
    WirelessController,
    IntelligentIoController,
    EncryptionController,
    DataAcquisitionSignalProcessing,
    Other = 0xff,
}

impl PciClassCode {
    pub fn get_register_value(self) -> u8 {
        self as u8
    }
}

/// A PCI sublcass. Each class in `PciClassCode` can specify a unique set of subclasses. This trait
/// is implemented by each subclass. It allows use of a trait object to generate configurations.
pub trait PciSubclass {
    /// Convert this subclass to the value used in the PCI specification.
    fn get_register_value(&self) -> u8;
}

/// Subclasses of the MultimediaController class.
#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum PciMultimediaSubclass {
    VideoController = 0x00,
    AudioController = 0x01,
    TelephonyDevice = 0x02,
    AudioDevice = 0x03,
    Other = 0x80,
}

impl PciSubclass for PciMultimediaSubclass {
    fn get_register_value(&self) -> u8 {
        *self as u8
    }
}

/// Subclasses of the BridgeDevice
#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum PciBridgeSubclass {
    HostBridge = 0x00,
    IsaBridge = 0x01,
    EisaBridge = 0x02,
    McaBridge = 0x03,
    PciToPciBridge = 0x04,
    PcmciaBridge = 0x05,
    NuBusBridge = 0x06,
    CardBusBridge = 0x07,
    RACEwayBridge = 0x08,
    PciToPciSemiTransparentBridge = 0x09,
    InfiniBrandToPciHostBridge = 0x0a,
    OtherBridgeDevice = 0x80,
}

impl PciSubclass for PciBridgeSubclass {
    fn get_register_value(&self) -> u8 {
        *self as u8
    }
}

/// Subclass of the SerialBus
#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum PciSerialBusSubClass {
    Firewire = 0x00,
    ACCESSbus = 0x01,
    SSA = 0x02,
    USB = 0x03,
}

impl PciSubclass for PciSerialBusSubClass {
    fn get_register_value(&self) -> u8 {
        *self as u8
    }
}

/// Mass Storage Sub Classes
#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum PciMassStorageSubclass {
    SCSIStorage = 0x00,
    IDEInterface = 0x01,
    FloppyController = 0x02,
    IPIController = 0x03,
    RAIDController = 0x04,
    ATAController = 0x05,
    SATAController = 0x06,
    SerialSCSIController = 0x07,
    NVMController = 0x08,
    MassStorage = 0x80,
}

impl PciSubclass for PciMassStorageSubclass {
    fn get_register_value(&self) -> u8 {
        *self as u8
    }
}

/// Network Controller Sub Classes
#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum PciNetworkControllerSubclass {
    EthernetController = 0x00,
    TokenRingController = 0x01,
    FDDIController = 0x02,
    ATMController = 0x03,
    ISDNController = 0x04,
    WorldFipController = 0x05,
    PICMGController = 0x06,
    InfinibandController = 0x07,
    FabricController = 0x08,
    NetworkController = 0x80,
}

impl PciSubclass for PciNetworkControllerSubclass {
    fn get_register_value(&self) -> u8 {
        *self as u8
    }
}

/// A PCI class programming interface. Each combination of `PciClassCode` and
/// `PciSubclass` can specify a set of register-level programming interfaces.
/// This trait is implemented by each programming interface.
/// It allows use of a trait object to generate configurations.
pub trait PciProgrammingInterface {
    /// Convert this programming interface to the value used in the PCI specification.
    fn get_register_value(&self) -> u8;
}

/// Types of PCI capabilities.
#[derive(PartialEq, Copy, Clone)]
#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[repr(C)]
pub enum PciCapabilityID {
    ListID = 0,
    PowerManagement = 0x01,
    AcceleratedGraphicsPort = 0x02,
    VitalProductData = 0x03,
    SlotIdentification = 0x04,
    MessageSignalledInterrupts = 0x05,
    CompactPCIHotSwap = 0x06,
    PCIX = 0x07,
    HyperTransport = 0x08,
    VendorSpecific = 0x09,
    Debugport = 0x0A,
    CompactPCICentralResourceControl = 0x0B,
    PCIStandardHotPlugController = 0x0C,
    BridgeSubsystemVendorDeviceID = 0x0D,
    AGPTargetPCIPCIbridge = 0x0E,
    SecureDevice = 0x0F,
    PCIExpress = 0x10,
    MSIX = 0x11,
    SATADataIndexConf = 0x12,
    PCIAdvancedFeatures = 0x13,
    PCIEnhancedAllocation = 0x14,
}

impl From<u8> for PciCapabilityID {
    fn from(c: u8) -> Self {
        match c {
            0 => PciCapabilityID::ListID,
            0x01 => PciCapabilityID::PowerManagement,
            0x02 => PciCapabilityID::AcceleratedGraphicsPort,
            0x03 => PciCapabilityID::VitalProductData,
            0x04 => PciCapabilityID::SlotIdentification,
            0x05 => PciCapabilityID::MessageSignalledInterrupts,
            0x06 => PciCapabilityID::CompactPCIHotSwap,
            0x07 => PciCapabilityID::PCIX,
            0x08 => PciCapabilityID::HyperTransport,
            0x09 => PciCapabilityID::VendorSpecific,
            0x0A => PciCapabilityID::Debugport,
            0x0B => PciCapabilityID::CompactPCICentralResourceControl,
            0x0C => PciCapabilityID::PCIStandardHotPlugController,
            0x0D => PciCapabilityID::BridgeSubsystemVendorDeviceID,
            0x0E => PciCapabilityID::AGPTargetPCIPCIbridge,
            0x0F => PciCapabilityID::SecureDevice,
            0x10 => PciCapabilityID::PCIExpress,
            0x11 => PciCapabilityID::MSIX,
            0x12 => PciCapabilityID::SATADataIndexConf,
            0x13 => PciCapabilityID::PCIAdvancedFeatures,
            0x14 => PciCapabilityID::PCIEnhancedAllocation,
            _ => PciCapabilityID::ListID,
        }
    }
}

/// A PCI capability list. Devices can optionally specify capabilities in their configuration space.
pub trait PciCapability {
    fn bytes(&self) -> &[u8];
    fn id(&self) -> PciCapabilityID;
}

/// Contains the configuration space of a PCI node.
/// See the [specification](https://en.wikipedia.org/wiki/PCI_configuration_space).
/// The configuration space is accessed with DWORD reads and writes from the guest.
pub struct PciConfiguration {
    registers: [u32; NUM_CONFIGURATION_REGISTERS],
    writable_bits: [u32; NUM_CONFIGURATION_REGISTERS], // writable bits for each register.
    bar_size: [u32; NUM_BAR_REGS],
    bar_used: [bool; NUM_BAR_REGS],
    // Contains the byte offset and size of the last capability.
    last_capability: Option<(usize, usize)>,
    msix_cap_reg_idx: Option<usize>,
    msix_config: Option<Arc<Mutex<MsixConfig>>>,
}

/// See pci_regs.h in kernel
#[derive(Copy, Clone)]
pub enum PciBarRegionType {
    Memory32BitRegion = 0,
    IORegion = 0x01,
    Memory64BitRegion = 0x04,
}

#[derive(Copy, Clone)]
pub enum PciBarPrefetchable {
    NotPrefetchable = 0,
    Prefetchable = 0x08,
}

#[derive(Copy, Clone)]
pub struct PciBarConfiguration {
    addr: u64,
    size: u64,
    reg_idx: usize,
    region_type: PciBarRegionType,
    prefetchable: PciBarPrefetchable,
}

#[derive(Debug)]
pub enum Error {
    BarAddressInvalid(u64, u64),
    BarInUse(usize),
    BarInUse64(usize),
    BarInvalid(usize),
    BarInvalid64(usize),
    BarSizeInvalid(u64),
    CapabilityEmpty,
    CapabilityLengthInvalid(usize),
    CapabilitySpaceFull(usize),
}
pub type Result<T> = std::result::Result<T, Error>;

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;
        match self {
            BarAddressInvalid(a, s) => write!(f, "address {} size {} too big", a, s),
            BarInUse(b) => write!(f, "bar {} already used", b),
            BarInUse64(b) => write!(f, "64bit bar {} already used(requires two regs)", b),
            BarInvalid(b) => write!(f, "bar {} invalid, max {}", b, NUM_BAR_REGS - 1),
            BarInvalid64(b) => write!(
                f,
                "64bitbar {} invalid, requires two regs, max {}",
                b,
                NUM_BAR_REGS - 1
            ),
            BarSizeInvalid(s) => write!(f, "bar address {} not a power of two", s),
            CapabilityEmpty => write!(f, "empty capabilities are invalid"),
            CapabilityLengthInvalid(l) => write!(f, "Invalid capability length {}", l),
            CapabilitySpaceFull(s) => write!(f, "capability of size {} doesn't fit", s),
        }
    }
}

impl PciConfiguration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vendor_id: u16,
        device_id: u16,
        class_code: PciClassCode,
        subclass: &dyn PciSubclass,
        programming_interface: Option<&dyn PciProgrammingInterface>,
        header_type: PciHeaderType,
        subsystem_vendor_id: u16,
        subsystem_id: u16,
        msix_config: Option<Arc<Mutex<MsixConfig>>>,
    ) -> Self {
        let mut registers = [0u32; NUM_CONFIGURATION_REGISTERS];
        let mut writable_bits = [0u32; NUM_CONFIGURATION_REGISTERS];
        let bar_size = [0u32; NUM_BAR_REGS];
        registers[0] = u32::from(device_id) << 16 | u32::from(vendor_id);
        // TODO(dverkamp): Status should be write-1-to-clear
        writable_bits[1] = 0x0000_ffff; // Status (r/o), command (r/w)
        let pi = if let Some(pi) = programming_interface {
            pi.get_register_value()
        } else {
            0
        };
        registers[2] = u32::from(class_code.get_register_value()) << 24
            | u32::from(subclass.get_register_value()) << 16
            | u32::from(pi) << 8;
        writable_bits[3] = 0x0000_00ff; // Cacheline size (r/w)
        match header_type {
            PciHeaderType::Device => {
                registers[3] = 0x0000_0000; // Header type 0 (device)
                writable_bits[15] = 0x0000_00ff; // Interrupt line (r/w)
            }
            PciHeaderType::Bridge => {
                registers[3] = 0x0001_0000; // Header type 1 (bridge)
                writable_bits[9] = 0xfff0_fff0; // Memory base and limit
                writable_bits[15] = 0xffff_00ff; // Bridge control (r/w), interrupt line (r/w)
            }
        };
        registers[11] = u32::from(subsystem_id) << 16 | u32::from(subsystem_vendor_id);

        PciConfiguration {
            registers,
            writable_bits,
            bar_size,
            bar_used: [false; NUM_BAR_REGS],
            last_capability: None,
            msix_cap_reg_idx: None,
            msix_config,
        }
    }

    /// Reads a 32bit register from `reg_idx` in the register map.
    pub fn read_reg(&self, reg_idx: usize) -> u32 {
        *(self.registers.get(reg_idx).unwrap_or(&0xffff_ffff))
    }

    /// Writes a 32bit register to `reg_idx` in the register map.
    pub fn write_reg(&mut self, reg_idx: usize, value: u32) {
        let mut mask = self.writable_bits[reg_idx];
        if reg_idx >= BAR0_REG && reg_idx < BAR0_REG + NUM_BAR_REGS {
            // Handle very specific case where the BAR is being written with
            // all 1's to retrieve the BAR size on next BAR reading.
            if value == 0xffff_ffff {
                mask = self.bar_size[reg_idx - 4];
            }
        }

        if let Some(r) = self.registers.get_mut(reg_idx) {
            *r = (*r & !self.writable_bits[reg_idx]) | (value & mask);
        } else {
            warn!("bad PCI register write {}", reg_idx);
        }
    }

    /// Writes a 16bit word to `offset`. `offset` must be 16bit aligned.
    pub fn write_word(&mut self, offset: usize, value: u16) {
        let shift = match offset % 4 {
            0 => 0,
            2 => 16,
            _ => {
                warn!("bad PCI config write offset {}", offset);
                return;
            }
        };
        let reg_idx = offset / 4;

        if let Some(r) = self.registers.get_mut(reg_idx) {
            let writable_mask = self.writable_bits[reg_idx];
            let mask = (0xffffu32 << shift) & writable_mask;
            let shifted_value = (u32::from(value) << shift) & writable_mask;
            *r = *r & !mask | shifted_value;
        } else {
            warn!("bad PCI config write offset {}", offset);
        }
    }

    /// Writes a byte to `offset`.
    pub fn write_byte(&mut self, offset: usize, value: u8) {
        self.write_byte_internal(offset, value, true);
    }

    /// Writes a byte to `offset`, optionally enforcing read-only bits.
    fn write_byte_internal(&mut self, offset: usize, value: u8, apply_writable_mask: bool) {
        let shift = (offset % 4) * 8;
        let reg_idx = offset / 4;

        if let Some(r) = self.registers.get_mut(reg_idx) {
            let writable_mask = if apply_writable_mask {
                self.writable_bits[reg_idx]
            } else {
                0xffff_ffff
            };
            let mask = (0xffu32 << shift) & writable_mask;
            let shifted_value = (u32::from(value) << shift) & writable_mask;
            *r = *r & !mask | shifted_value;
        } else {
            warn!("bad PCI config write offset {}", offset);
        }
    }

    /// Adds a region specified by `config`.  Configures the specified BAR(s) to
    /// report this region and size to the guest kernel.  Enforces a few constraints
    /// (i.e, region size must be power of two, register not already used). Returns 'None' on
    /// failure all, `Some(BarIndex)` on success.
    pub fn add_pci_bar(&mut self, config: &PciBarConfiguration) -> Result<usize> {
        if self.bar_used[config.reg_idx] {
            return Err(Error::BarInUse(config.reg_idx));
        }

        if config.size.count_ones() != 1 {
            return Err(Error::BarSizeInvalid(config.size));
        }

        if config.reg_idx >= NUM_BAR_REGS {
            return Err(Error::BarInvalid(config.reg_idx));
        }

        let bar_idx = BAR0_REG + config.reg_idx;
        let end_addr = config
            .addr
            .checked_add(config.size)
            .ok_or_else(|| Error::BarAddressInvalid(config.addr, config.size))?;
        match config.region_type {
            PciBarRegionType::Memory32BitRegion | PciBarRegionType::IORegion => {
                if end_addr > u64::from(u32::max_value()) {
                    return Err(Error::BarAddressInvalid(config.addr, config.size));
                }
            }
            PciBarRegionType::Memory64BitRegion => {
                if config.reg_idx + 1 >= NUM_BAR_REGS {
                    return Err(Error::BarInvalid64(config.reg_idx));
                }

                if end_addr > u64::max_value() {
                    return Err(Error::BarAddressInvalid(config.addr, config.size));
                }

                if self.bar_used[config.reg_idx + 1] {
                    return Err(Error::BarInUse64(config.reg_idx));
                }

                self.registers[bar_idx + 1] = (config.addr >> 32) as u32;
                self.writable_bits[bar_idx + 1] = 0xffff_ffff;
                self.bar_size[config.reg_idx + 1] = (config.size >> 32) as u32;
                self.bar_used[config.reg_idx + 1] = true;
            }
        }

        let (mask, lower_bits) = match config.region_type {
            PciBarRegionType::Memory32BitRegion | PciBarRegionType::Memory64BitRegion => (
                BAR_MEM_ADDR_MASK,
                config.prefetchable as u32 | config.region_type as u32,
            ),
            PciBarRegionType::IORegion => (BAR_IO_ADDR_MASK, config.region_type as u32),
        };

        self.registers[bar_idx] = ((config.addr as u32) & mask) | lower_bits;
        self.writable_bits[bar_idx] = mask;
        self.bar_size[config.reg_idx] = config.size as u32;
        self.bar_used[config.reg_idx] = true;
        Ok(config.reg_idx)
    }

    /// Returns the address of the given 32 bits BAR region.
    pub fn get_bar32_addr(&self, bar_num: usize) -> u32 {
        let bar_idx = BAR0_REG + bar_num;

        self.registers[bar_idx] & BAR_MEM_ADDR_MASK
    }

    /// Returns the address of the given 64 bits BAR region.
    pub fn get_bar64_addr(&self, bar_num: usize) -> u64 {
        let bar_idx = BAR0_REG + bar_num;

        u64::from(self.registers[bar_idx] & BAR_MEM_ADDR_MASK)
            | (u64::from(self.registers[bar_idx + 1]) << 32)
    }

    /// Configures the IRQ line and pin used by this device.
    pub fn set_irq(&mut self, line: u8, pin: PciInterruptPin) {
        // `pin` is 1-based in the pci config space.
        let pin_idx = (pin as u32) + 1;
        self.registers[INTERRUPT_LINE_PIN_REG] = (self.registers[INTERRUPT_LINE_PIN_REG]
            & 0xffff_0000)
            | (pin_idx << 8)
            | u32::from(line);
    }

    /// Adds the capability `cap_data` to the list of capabilities.
    /// `cap_data` should include the two-byte PCI capability header (type, next),
    /// but not populate it. Correct values will be generated automatically based
    /// on `cap_data.id()`.
    pub fn add_capability(&mut self, cap_data: &dyn PciCapability) -> Result<usize> {
        let total_len = cap_data.bytes().len();
        // Check that the length is valid.
        if cap_data.bytes().is_empty() {
            return Err(Error::CapabilityEmpty);
        }
        let (cap_offset, tail_offset) = match self.last_capability {
            Some((offset, len)) => (Self::next_dword(offset, len), offset + 1),
            None => (FIRST_CAPABILITY_OFFSET, CAPABILITY_LIST_HEAD_OFFSET),
        };
        let end_offset = cap_offset
            .checked_add(total_len)
            .ok_or_else(|| Error::CapabilitySpaceFull(total_len))?;
        if end_offset > CAPABILITY_MAX_OFFSET {
            return Err(Error::CapabilitySpaceFull(total_len));
        }
        self.registers[STATUS_REG] |= STATUS_REG_CAPABILITIES_USED_MASK;
        self.write_byte_internal(tail_offset, cap_offset as u8, false);
        self.write_byte_internal(cap_offset, cap_data.id() as u8, false);
        self.write_byte_internal(cap_offset + 1, 0, false); // Next pointer.
        for (i, byte) in cap_data.bytes().iter().enumerate() {
            self.write_byte_internal(cap_offset + i + 2, *byte, false);
        }
        self.last_capability = Some((cap_offset, total_len));

        if cap_data.id() == PciCapabilityID::MSIX {
            self.msix_cap_reg_idx = Some(cap_offset / 4);
        }

        Ok(cap_offset)
    }

    // Find the next aligned offset after the one given.
    fn next_dword(offset: usize, len: usize) -> usize {
        let next = offset + len;
        (next + 3) & !3
    }

    pub fn write_config_register(&mut self, reg_idx: usize, offset: u64, data: &[u8]) {
        if offset as usize + data.len() > 4 {
            return;
        }

        // Handle potential write to MSI-X message control register
        if let Some(msix_cap_reg_idx) = self.msix_cap_reg_idx {
            if let Some(msix_config) = &self.msix_config {
                if msix_cap_reg_idx == reg_idx && offset == 2 && data.len() == 2 {
                    msix_config
                        .lock()
                        .unwrap()
                        .set_msg_ctl(LittleEndian::read_u16(data));
                }
            }
        }

        match data.len() {
            1 => self.write_byte(reg_idx * 4 + offset as usize, data[0]),
            2 => self.write_word(
                reg_idx * 4 + offset as usize,
                u16::from(data[0]) | u16::from(data[1]) << 8,
            ),
            4 => self.write_reg(reg_idx, LittleEndian::read_u32(data)),
            _ => (),
        }
    }

    pub fn read_config_register(&self, reg_idx: usize) -> u32 {
        self.read_reg(reg_idx)
    }
}

impl Default for PciBarConfiguration {
    fn default() -> Self {
        PciBarConfiguration {
            reg_idx: 0,
            addr: 0,
            size: 0,
            region_type: PciBarRegionType::Memory64BitRegion,
            prefetchable: PciBarPrefetchable::NotPrefetchable,
        }
    }
}

impl PciBarConfiguration {
    pub fn new(
        reg_idx: usize,
        size: u64,
        region_type: PciBarRegionType,
        prefetchable: PciBarPrefetchable,
    ) -> Self {
        PciBarConfiguration {
            reg_idx,
            addr: 0,
            size,
            region_type,
            prefetchable,
        }
    }

    pub fn set_register_index(mut self, reg_idx: usize) -> Self {
        self.reg_idx = reg_idx;
        self
    }

    pub fn set_address(mut self, addr: u64) -> Self {
        self.addr = addr;
        self
    }

    pub fn set_size(mut self, size: u64) -> Self {
        self.size = size;
        self
    }

    pub fn get_size(&self) -> u64 {
        self.size
    }

    pub fn set_region_type(mut self, region_type: PciBarRegionType) -> Self {
        self.region_type = region_type;
        self
    }
}

#[cfg(test)]
mod tests {
    use vm_memory::ByteValued;

    use super::*;

    #[repr(packed)]
    #[derive(Clone, Copy, Default)]
    #[allow(dead_code)]
    struct TestCap {
        _vndr: u8,
        _next: u8,
        len: u8,
        foo: u8,
    }

    // It is safe to implement BytesValued; all members are simple numbers and any value is valid.
    unsafe impl ByteValued for TestCap {}

    impl PciCapability for TestCap {
        fn bytes(&self) -> &[u8] {
            self.as_slice()
        }

        fn id(&self) -> PciCapabilityID {
            PciCapabilityID::VendorSpecific
        }
    }

    #[test]
    #[ignore]
    fn add_capability() {
        let mut cfg = PciConfiguration::new(
            0x1234,
            0x5678,
            PciClassCode::MultimediaController,
            &PciMultimediaSubclass::AudioController,
            None,
            PciHeaderType::Device,
            0xABCD,
            0x2468,
            None,
        );

        // Add two capabilities with different contents.
        let cap1 = TestCap {
            _vndr: 0,
            _next: 0,
            len: 4,
            foo: 0xAA,
        };
        let cap1_offset = cfg.add_capability(&cap1).unwrap();
        assert_eq!(cap1_offset % 4, 0);

        let cap2 = TestCap {
            _vndr: 0,
            _next: 0,
            len: 0x04,
            foo: 0x55,
        };
        let cap2_offset = cfg.add_capability(&cap2).unwrap();
        assert_eq!(cap2_offset % 4, 0);

        // The capability list head should be pointing to cap1.
        let cap_ptr = cfg.read_reg(CAPABILITY_LIST_HEAD_OFFSET / 4) & 0xFF;
        assert_eq!(cap1_offset, cap_ptr as usize);

        // Verify the contents of the capabilities.
        let cap1_data = cfg.read_reg(cap1_offset / 4);
        assert_eq!(cap1_data & 0xFF, 0x09); // capability ID
        assert_eq!((cap1_data >> 8) & 0xFF, cap2_offset as u32); // next capability pointer
        assert_eq!((cap1_data >> 16) & 0xFF, 0x04); // cap1.len
        assert_eq!((cap1_data >> 24) & 0xFF, 0xAA); // cap1.foo

        let cap2_data = cfg.read_reg(cap2_offset / 4);
        assert_eq!(cap2_data & 0xFF, 0x09); // capability ID
        assert_eq!((cap2_data >> 8) & 0xFF, 0x00); // next capability pointer
        assert_eq!((cap2_data >> 16) & 0xFF, 0x04); // cap2.len
        assert_eq!((cap2_data >> 24) & 0xFF, 0x55); // cap2.foo
    }

    #[derive(Copy, Clone)]
    enum TestPI {
        Test = 0x5a,
    }

    impl PciProgrammingInterface for TestPI {
        fn get_register_value(&self) -> u8 {
            *self as u8
        }
    }

    #[test]
    fn class_code() {
        let cfg = PciConfiguration::new(
            0x1234,
            0x5678,
            PciClassCode::MultimediaController,
            &PciMultimediaSubclass::AudioController,
            Some(&TestPI::Test),
            PciHeaderType::Device,
            0xABCD,
            0x2468,
            None,
        );

        let class_reg = cfg.read_reg(2);
        let class_code = (class_reg >> 24) & 0xFF;
        let subclass = (class_reg >> 16) & 0xFF;
        let prog_if = (class_reg >> 8) & 0xFF;
        assert_eq!(class_code, 0x04);
        assert_eq!(subclass, 0x01);
        assert_eq!(prog_if, 0x5a);
    }
}
