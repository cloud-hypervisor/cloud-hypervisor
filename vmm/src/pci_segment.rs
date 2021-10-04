// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2019 - 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
//

use crate::device_manager::{AddressManager, DeviceManagerError, DeviceManagerResult};
use pci::{DeviceRelocation, PciBus, PciConfigMmio, PciRoot};
#[cfg(target_arch = "x86_64")]
use pci::{PciConfigIo, PCI_CONFIG_IO_PORT, PCI_CONFIG_IO_PORT_SIZE};
use std::sync::{Arc, Mutex};
use vm_device::BusDevice;

pub(crate) struct PciSegment {
    id: u16,
    pub(crate) pci_bus: Arc<Mutex<PciBus>>,
    pub(crate) pci_config_mmio: Arc<Mutex<PciConfigMmio>>,
    mmio_config_address: u64,

    #[cfg(target_arch = "x86_64")]
    pub(crate) pci_config_io: Option<Arc<Mutex<PciConfigIo>>>,

    // Bitmap of PCI devices to hotplug.
    pub(crate) pci_devices_up: u32,
    // Bitmap of PCI devices to hotunplug.
    pub(crate) pci_devices_down: u32,
    // List of allocated IRQs for each PCI slot.
    pub(crate) pci_irq_slots: [u8; 32],
}

impl PciSegment {
    pub(crate) fn new_default_segment(
        address_manager: &Arc<AddressManager>,
    ) -> DeviceManagerResult<PciSegment> {
        let pci_root = PciRoot::new(None);
        let pci_bus = Arc::new(Mutex::new(PciBus::new(
            pci_root,
            Arc::clone(address_manager) as Arc<dyn DeviceRelocation>,
        )));

        let pci_config_mmio = Arc::new(Mutex::new(PciConfigMmio::new(Arc::clone(&pci_bus))));
        address_manager
            .mmio_bus
            .insert(
                Arc::clone(&pci_config_mmio) as Arc<Mutex<dyn BusDevice>>,
                arch::layout::PCI_MMCONFIG_START.0,
                arch::layout::PCI_MMCONFIG_SIZE,
            )
            .map_err(DeviceManagerError::BusError)?;

        #[cfg(target_arch = "x86_64")]
        let pci_config_io = Arc::new(Mutex::new(PciConfigIo::new(Arc::clone(&pci_bus))));

        #[cfg(target_arch = "x86_64")]
        address_manager
            .io_bus
            .insert(
                pci_config_io.clone(),
                PCI_CONFIG_IO_PORT,
                PCI_CONFIG_IO_PORT_SIZE,
            )
            .map_err(DeviceManagerError::BusError)?;

        let mut segment = PciSegment {
            id: 0,
            pci_bus,
            pci_config_mmio,
            mmio_config_address: arch::layout::PCI_MMCONFIG_START.0,
            pci_devices_up: 0,
            pci_devices_down: 0,
            pci_irq_slots: [0; 32],
            #[cfg(target_arch = "x86_64")]
            pci_config_io: Some(pci_config_io),
        };

        // Reserve some IRQs for PCI devices in case they need to support INTx.
        segment.reserve_legacy_interrupts_for_pci_devices(address_manager)?;

        info!(
            "Adding PCI segment: id={}, PCI MMIO config address: 0x{:x}",
            segment.id, segment.mmio_config_address
        );
        Ok(segment)
    }

    pub(crate) fn next_device_bdf(&self) -> DeviceManagerResult<u32> {
        // We need to shift the device id since the 3 first bits
        // are dedicated to the PCI function, and we know we don't
        // do multifunction. Also, because we only support one PCI
        // bus, the bus 0, we don't need to add anything to the
        // global device ID.
        Ok(self
            .pci_bus
            .lock()
            .unwrap()
            .next_device_id()
            .map_err(DeviceManagerError::NextPciDeviceId)?
            << 3)
    }

    fn reserve_legacy_interrupts_for_pci_devices(
        &mut self,
        address_manager: &Arc<AddressManager>,
    ) -> DeviceManagerResult<()> {
        // Reserve 8 IRQs which will be shared across all PCI devices.
        let num_irqs = 8;
        let mut irqs: Vec<u8> = Vec::new();
        for _ in 0..num_irqs {
            irqs.push(
                address_manager
                    .allocator
                    .lock()
                    .unwrap()
                    .allocate_irq()
                    .ok_or(DeviceManagerError::AllocateIrq)? as u8,
            );
        }

        // There are 32 devices on the PCI bus, let's assign them an IRQ.
        for i in 0..32 {
            self.pci_irq_slots[i] = irqs[(i % num_irqs) as usize];
        }

        Ok(())
    }
}
