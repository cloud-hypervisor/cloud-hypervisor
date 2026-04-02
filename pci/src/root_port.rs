// Copyright 2026 Prime Intellect, Inc. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::any::Any;
use std::sync::{Arc, Barrier};

use vm_device::{BusDevice, PciBarType, Resource};
use vm_memory::ByteValued;

use crate::configuration::{
    PciBridgeSubclass, PciCapability, PciCapabilityId, PciClassCode, PciConfiguration,
    PciHeaderType,
};
use crate::device::{BarReprogrammingParams, Error as PciDeviceError, PciDevice};

const VENDOR_ID_INTEL: u16 = 0x8086;
const DEVICE_ID_INTEL_VIRT_PCIE_ROOT_PORT: u16 = 0x0d58;
const BRIDGE_BUS_NUMBERS_REG: usize = 6;
const IO_BASE_LIMIT_REG: usize = 7;
const MEMORY_BASE_LIMIT_REG: usize = 8;
const PREFETCHABLE_MEMORY_BASE_LIMIT_REG: usize = 9;
const PREFETCHABLE_MEMORY_BASE_UPPER_REG: usize = 10;
const PREFETCHABLE_MEMORY_LIMIT_UPPER_REG: usize = 11;
const IO_BASE_LIMIT_UPPER_REG: usize = 12;

const IO_WINDOW_ALIGNMENT: u64 = 0x1_000;
const MEMORY_WINDOW_ALIGNMENT: u64 = 0x10_0000;
const PCIE_ROOT_PORT_TYPE: u16 = 0x4;
const PCIE_CAPABILITY_VERSION: u16 = 0x2;
const PCIE_LINK_SPEED_16_0_GT_PER_S: u16 = 0x4;
const PCIE_LINK_WIDTH_X16: u16 = 0x10;
const PCIE_SUPPORTED_LINK_SPEEDS: u32 = 0x1e;

#[derive(Copy, Clone)]
struct Window {
    base: u64,
    limit: u64,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct PcieRootPortCapability {
    pcie_capabilities: u16,
    device_capabilities: u32,
    device_control: u16,
    device_status: u16,
    link_capabilities: u32,
    link_control: u16,
    link_status: u16,
    slot_capabilities: u32,
    slot_control: u16,
    slot_status: u16,
    root_control: u16,
    root_capabilities: u16,
    root_status: u32,
    device_capabilities_2: u32,
    device_control_2: u16,
    link_capabilities_2: u32,
    link_control_2: u16,
    link_status_2: u16,
}

// SAFETY: All members are integer fields and any bit pattern is valid.
unsafe impl ByteValued for PcieRootPortCapability {}

impl PcieRootPortCapability {
    fn new() -> Self {
        let link_speed = u32::from(PCIE_LINK_SPEED_16_0_GT_PER_S);
        let link_width = u32::from(PCIE_LINK_WIDTH_X16) << 4;

        Self {
            pcie_capabilities: PCIE_CAPABILITY_VERSION | (PCIE_ROOT_PORT_TYPE << 4),
            device_capabilities: 0,
            device_control: 0,
            device_status: 0,
            link_capabilities: link_speed | link_width,
            link_control: 0,
            link_status: PCIE_LINK_SPEED_16_0_GT_PER_S | (PCIE_LINK_WIDTH_X16 << 4),
            slot_capabilities: 0,
            slot_control: 0,
            slot_status: 0,
            root_control: 0,
            root_capabilities: 0,
            root_status: 0,
            device_capabilities_2: 0,
            device_control_2: 0,
            link_capabilities_2: PCIE_SUPPORTED_LINK_SPEEDS,
            link_control_2: 0,
            link_status_2: 0,
        }
    }
}

impl PciCapability for PcieRootPortCapability {
    fn bytes(&self) -> &[u8] {
        self.as_slice()
    }

    fn id(&self) -> PciCapabilityId {
        PciCapabilityId::PciExpress
    }
}

pub struct PcieRootPort {
    id: String,
    config: PciConfiguration,
    secondary_bus_number: u8,
}

impl PcieRootPort {
    pub fn new(id: String, secondary_bus_number: u8) -> Result<Self, PciDeviceError> {
        let mut config = PciConfiguration::new(
            VENDOR_ID_INTEL,
            DEVICE_ID_INTEL_VIRT_PCIE_ROOT_PORT,
            0,
            PciClassCode::BridgeDevice,
            &PciBridgeSubclass::PciToPciBridge,
            None,
            PciHeaderType::Bridge,
            0,
            0,
            None,
            None,
        );

        config
            .add_capability(&PcieRootPortCapability::new())
            .map_err(PciDeviceError::CapabilitiesSetup)?;

        config.write_reg(
            BRIDGE_BUS_NUMBERS_REG,
            (u32::from(secondary_bus_number) << 8) | (u32::from(secondary_bus_number) << 16),
        );

        // Keep all downstream apertures closed until a child device is added.
        Self::set_io_window_registers(&mut config, None);
        Self::set_memory_window_registers(&mut config, None);
        Self::set_prefetchable_memory_window_registers(&mut config, None);

        Ok(Self {
            id,
            config,
            secondary_bus_number,
        })
    }

    pub fn secondary_bus_number(&self) -> u8 {
        self.secondary_bus_number
    }

    pub fn configure_windows(&mut self, resources: &[Resource]) {
        let mut io_window = None;
        let mut memory_window = None;
        let mut prefetchable_memory_window = None;

        for resource in resources {
            let Resource::PciBar {
                base,
                size,
                type_,
                prefetchable,
                ..
            } = resource
            else {
                continue;
            };

            let Some(limit) = base.checked_add(size.saturating_sub(1)) else {
                continue;
            };

            match type_ {
                PciBarType::Io => Self::extend_window(&mut io_window, *base, limit),
                PciBarType::Mmio32 | PciBarType::Mmio64 if *prefetchable => {
                    Self::extend_window(&mut prefetchable_memory_window, *base, limit);
                }
                PciBarType::Mmio32 | PciBarType::Mmio64 => {
                    Self::extend_window(&mut memory_window, *base, limit);
                }
            }
        }

        Self::set_io_window_registers(&mut self.config, io_window);
        Self::set_memory_window_registers(&mut self.config, memory_window);
        Self::set_prefetchable_memory_window_registers(
            &mut self.config,
            prefetchable_memory_window,
        );
    }

    fn extend_window(window: &mut Option<Window>, base: u64, limit: u64) {
        match window {
            Some(existing) => {
                existing.base = existing.base.min(base);
                existing.limit = existing.limit.max(limit);
            }
            None => {
                *window = Some(Window { base, limit });
            }
        }
    }

    fn align_down(value: u64, alignment: u64) -> u64 {
        value & !(alignment - 1)
    }

    fn align_up(value: u64, alignment: u64) -> u64 {
        value.saturating_add(alignment - 1) & !(alignment - 1)
    }

    fn set_io_window_registers(config: &mut PciConfiguration, window: Option<Window>) {
        let (low, upper) = if let Some(window) = window {
            let base = Self::align_down(window.base, IO_WINDOW_ALIGNMENT);
            let limit = Self::align_up(window.limit.saturating_add(1), IO_WINDOW_ALIGNMENT)
                .saturating_sub(1);

            (
                (((limit >> 8) as u32) & 0x0000_f000) | (((base >> 8) as u32) & 0x0000_00f0),
                (((limit >> 16) as u32) & 0xffff_0000) | (((base >> 16) as u32) & 0x0000_ffff),
            )
        } else {
            (0x0000_00f0, 0x0000_ffff)
        };

        config.write_reg(IO_BASE_LIMIT_REG, low);
        config.write_reg(IO_BASE_LIMIT_UPPER_REG, upper);
    }

    fn set_memory_window_registers(config: &mut PciConfiguration, window: Option<Window>) {
        let value = if let Some(window) = window {
            let base = Self::align_down(window.base, MEMORY_WINDOW_ALIGNMENT);
            let limit = Self::align_up(window.limit.saturating_add(1), MEMORY_WINDOW_ALIGNMENT)
                .saturating_sub(1);

            ((((limit >> 16) as u32) & 0x0000_fff0) << 16) | (((base >> 16) as u32) & 0x0000_fff0)
        } else {
            0x0000_fff0
        };

        config.write_reg(MEMORY_BASE_LIMIT_REG, value);
    }

    fn set_prefetchable_memory_window_registers(
        config: &mut PciConfiguration,
        window: Option<Window>,
    ) {
        let (low, upper_base, upper_limit) = if let Some(window) = window {
            let base = Self::align_down(window.base, MEMORY_WINDOW_ALIGNMENT);
            let limit = Self::align_up(window.limit.saturating_add(1), MEMORY_WINDOW_ALIGNMENT)
                .saturating_sub(1);

            (
                (((((limit >> 16) as u32) & 0x0000_fff0) | 0x1) << 16)
                    | ((((base >> 16) as u32) & 0x0000_fff0) | 0x1),
                (base >> 32) as u32,
                (limit >> 32) as u32,
            )
        } else {
            (0x0001_fff1, 0, 0)
        };

        config.write_reg(PREFETCHABLE_MEMORY_BASE_LIMIT_REG, low);
        config.write_reg(PREFETCHABLE_MEMORY_BASE_UPPER_REG, upper_base);
        config.write_reg(PREFETCHABLE_MEMORY_LIMIT_UPPER_REG, upper_limit);
    }
}

impl BusDevice for PcieRootPort {}

impl PciDevice for PcieRootPort {
    fn write_config_register(
        &mut self,
        reg_idx: usize,
        offset: u64,
        data: &[u8],
    ) -> (Vec<BarReprogrammingParams>, Option<Arc<Barrier>>) {
        (
            self.config.write_config_register(reg_idx, offset, data),
            None,
        )
    }

    fn read_config_register(&mut self, reg_idx: usize) -> u32 {
        self.config.read_reg(reg_idx)
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn id(&self) -> Option<String> {
        Some(self.id.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAPABILITY_LIST_HEAD_REG: usize = 0x34 / 4;

    #[test]
    fn root_port_exposes_pcie_capability() {
        let mut root_port = PcieRootPort::new("rp0".to_string(), 1).unwrap();

        let cap_offset = (root_port.read_config_register(CAPABILITY_LIST_HEAD_REG) & 0xff) as usize;
        assert_eq!(cap_offset, 0x40);

        let capability_header = root_port.read_config_register(cap_offset / 4);
        assert_eq!(capability_header & 0xff, PciCapabilityId::PciExpress as u32);
        assert_eq!(
            (capability_header >> 16) & 0xf,
            PCIE_CAPABILITY_VERSION as u32
        );
        assert_eq!((capability_header >> 20) & 0xf, PCIE_ROOT_PORT_TYPE as u32);

        let link_capabilities = root_port.read_config_register((cap_offset + 0x0c) / 4);
        let link_status = root_port.read_config_register((cap_offset + 0x10) / 4) >> 16;

        assert_eq!(
            link_capabilities & 0xf,
            u32::from(PCIE_LINK_SPEED_16_0_GT_PER_S)
        );
        assert_eq!(
            (link_capabilities >> 4) & 0x3f,
            u32::from(PCIE_LINK_WIDTH_X16)
        );
        assert_eq!(link_status & 0xf, u32::from(PCIE_LINK_SPEED_16_0_GT_PER_S));
        assert_eq!((link_status >> 4) & 0x3f, u32::from(PCIE_LINK_WIDTH_X16));
    }
}
