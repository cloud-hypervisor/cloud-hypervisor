// Copyright © 2024 Tencent Corporation. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

use std::any::Any;
use std::path::PathBuf;
use std::result;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Barrier, Mutex};

use anyhow::anyhow;
use byteorder::{ByteOrder, LittleEndian};
use pci::{
    BarReprogrammingParams, PCI_CONFIGURATION_ID, PciBarConfiguration, PciBarPrefetchable,
    PciBarRegionType, PciClassCode, PciConfiguration, PciDevice, PciDeviceError, PciHeaderType,
    PciSubclass,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use vm_allocator::{AddressAllocator, SystemAllocator};
use vm_device::{BusDevice, Resource, UserspaceMapping};
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::{Address, GuestAddress};
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};

const IVSHMEM_BAR0_IDX: usize = 0;
const IVSHMEM_BAR1_IDX: usize = 1;
const IVSHMEM_BAR2_IDX: usize = 2;

const IVSHMEM_VENDOR_ID: u16 = 0x1af4;
const IVSHMEM_DEVICE_ID: u16 = 0x1110;

const IVSHMEM_REG_BAR_SIZE: u64 = 0x100;

type GuestRegionMmap = vm_memory::GuestRegionMmap<AtomicBitmap>;

#[derive(Debug, Error)]
pub enum IvshmemError {
    #[error("Failed to retrieve PciConfigurationState: {0}")]
    RetrievePciConfigurationState(#[source] anyhow::Error),
    #[error("Failed to retrieve IvshmemDeviceState: {0}")]
    RetrieveIvshmemDeviceStateState(#[source] anyhow::Error),
    #[error("Failed to remove user memory region")]
    RemoveUserMemoryRegion,
    #[error("Failed to create user memory region.")]
    CreateUserMemoryRegion,
    #[error("Failed to create userspace mapping.")]
    CreateUserspaceMapping,
    #[error("Failed to remove old userspace mapping.")]
    RemoveUserspaceMapping,
}

#[derive(Copy, Clone)]
pub enum IvshmemSubclass {
    Other = 0x00,
}

impl PciSubclass for IvshmemSubclass {
    fn get_register_value(&self) -> u8 {
        *self as u8
    }
}

pub trait IvshmemOps: Send + Sync {
    fn map_ram_region(
        &mut self,
        start_addr: u64,
        size: usize,
        backing_file: Option<PathBuf>,
    ) -> Result<(Arc<GuestRegionMmap>, UserspaceMapping), IvshmemError>;

    fn unmap_ram_region(&mut self, mapping: UserspaceMapping) -> Result<(), IvshmemError>;
}

/// Inner-Vm Shared Memory Device (Ivshmem device)
///
/// This device can share memory between host and guest(ivshmem-plain)
/// and share memory between guests(ivshmem-doorbell).
/// But only ivshmem-plain support now, ivshmem-doorbell doesn't support yet.
pub struct IvshmemDevice {
    id: String,

    // ivshmem device registers
    // (only used for ivshmem-doorbell, ivshmem-doorbell don't support yet)
    _interrupt_mask: u32,
    _interrupt_status: Arc<AtomicU32>,
    _iv_position: u32,
    _doorbell: u32,

    // PCI configuration registers.
    configuration: PciConfiguration,
    bar_regions: Vec<PciBarConfiguration>,

    region_size: u64,
    ivshmem_ops: Arc<Mutex<dyn IvshmemOps>>,
    backend_file: Option<PathBuf>,
    region: Option<Arc<GuestRegionMmap>>,
    userspace_mapping: Option<UserspaceMapping>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct IvshmemDeviceState {
    interrupt_mask: u32,
    interrupt_status: u32,
    iv_position: u32,
    doorbell: u32,
}

impl IvshmemDevice {
    pub fn new(
        id: String,
        region_size: u64,
        backend_file: Option<PathBuf>,
        ivshmem_ops: Arc<Mutex<dyn IvshmemOps>>,
        snapshot: Option<Snapshot>,
    ) -> Result<Self, IvshmemError> {
        let pci_configuration_state =
            vm_migration::state_from_id(snapshot.as_ref(), PCI_CONFIGURATION_ID).map_err(|e| {
                IvshmemError::RetrievePciConfigurationState(anyhow!(
                    "Failed to get PciConfigurationState from Snapshot: {e}",
                ))
            })?;

        let state: Option<IvshmemDeviceState> = snapshot
            .as_ref()
            .map(|s| s.to_state())
            .transpose()
            .map_err(|e| {
                IvshmemError::RetrieveIvshmemDeviceStateState(anyhow!(
                    "Failed to get IvshmemDeviceState from Snapshot: {e}",
                ))
            })?;

        let configuration = PciConfiguration::new(
            IVSHMEM_VENDOR_ID,
            IVSHMEM_DEVICE_ID,
            0x1,
            PciClassCode::MemoryController,
            &IvshmemSubclass::Other,
            None,
            PciHeaderType::Device,
            0,
            0,
            None,
            pci_configuration_state,
        );

        let device = if let Some(s) = state {
            IvshmemDevice {
                id,
                configuration,
                bar_regions: vec![],
                _interrupt_mask: s.interrupt_mask,
                _interrupt_status: Arc::new(AtomicU32::new(s.interrupt_status)),
                _iv_position: s.iv_position,
                _doorbell: s.doorbell,
                region_size,
                ivshmem_ops,
                region: None,
                userspace_mapping: None,
                backend_file,
            }
        } else {
            IvshmemDevice {
                id,
                configuration,
                bar_regions: vec![],
                _interrupt_mask: 0,
                _interrupt_status: Arc::new(AtomicU32::new(0)),
                _iv_position: 0,
                _doorbell: 0,
                region_size,
                ivshmem_ops,
                region: None,
                userspace_mapping: None,
                backend_file,
            }
        };
        Ok(device)
    }

    pub fn set_region(
        &mut self,
        region: Arc<GuestRegionMmap>,
        userspace_mapping: UserspaceMapping,
    ) {
        self.region = Some(region);
        self.userspace_mapping = Some(userspace_mapping);
    }

    pub fn config_bar_addr(&self) -> u64 {
        self.configuration.get_bar_addr(IVSHMEM_BAR0_IDX)
    }

    pub fn data_bar_addr(&self) -> u64 {
        self.configuration.get_bar_addr(IVSHMEM_BAR2_IDX)
    }

    fn state(&self) -> IvshmemDeviceState {
        IvshmemDeviceState {
            interrupt_mask: self._interrupt_mask,
            interrupt_status: self._interrupt_status.load(Ordering::SeqCst),
            iv_position: self._iv_position,
            doorbell: self._doorbell,
        }
    }
}

impl BusDevice for IvshmemDevice {
    fn read(&mut self, base: u64, offset: u64, data: &mut [u8]) {
        self.read_bar(base, offset, data)
    }

    fn write(&mut self, base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        self.write_bar(base, offset, data)
    }
}

impl PciDevice for IvshmemDevice {
    fn allocate_bars(
        &mut self,
        _allocator: &Arc<Mutex<SystemAllocator>>,
        mmio32_allocator: &mut AddressAllocator,
        mmio64_allocator: &mut AddressAllocator,
        resources: Option<Vec<Resource>>,
    ) -> std::result::Result<Vec<PciBarConfiguration>, PciDeviceError> {
        let mut bars = Vec::new();
        let mut bar0_addr = None;
        let mut bar2_addr = None;

        let restoring = resources.is_some();
        if let Some(resources) = resources {
            for resource in resources {
                match resource {
                    Resource::PciBar { index, base, .. } => {
                        match index {
                            IVSHMEM_BAR0_IDX => {
                                bar0_addr = Some(GuestAddress(base));
                            }
                            IVSHMEM_BAR1_IDX => {}
                            IVSHMEM_BAR2_IDX => {
                                bar2_addr = Some(GuestAddress(base));
                            }
                            _ => {
                                error!("Unexpected pci bar index {index}");
                            }
                        };
                    }
                    _ => {
                        error!("Unexpected resource {resource:?}");
                    }
                }
            }
            if bar0_addr.is_none() || bar2_addr.is_none() {
                return Err(PciDeviceError::MissingResource);
            }
        }

        // BAR0 holds device registers (256 Byte MMIO)
        let bar0_addr = mmio32_allocator
            .allocate(bar0_addr, IVSHMEM_REG_BAR_SIZE, None)
            .ok_or(PciDeviceError::IoAllocationFailed(IVSHMEM_REG_BAR_SIZE))?;
        debug!("ivshmem bar0 address 0x{:x}", bar0_addr.0);

        let bar0 = PciBarConfiguration::default()
            .set_index(IVSHMEM_BAR0_IDX)
            .set_address(bar0_addr.raw_value())
            .set_size(IVSHMEM_REG_BAR_SIZE)
            .set_region_type(PciBarRegionType::Memory32BitRegion)
            .set_prefetchable(PciBarPrefetchable::NotPrefetchable);

        // BAR1 holds MSI-X table and PBA (only ivshmem-doorbell).

        // BAR2 maps the shared memory object
        let bar2_size = self.region_size;
        let bar2_addr = mmio64_allocator
            .allocate(bar2_addr, bar2_size, None)
            .ok_or(PciDeviceError::IoAllocationFailed(bar2_size))?;
        debug!("ivshmem bar2 address 0x{:x}", bar2_addr.0);

        let bar2 = PciBarConfiguration::default()
            .set_index(IVSHMEM_BAR2_IDX)
            .set_address(bar2_addr.raw_value())
            .set_size(bar2_size)
            .set_region_type(PciBarRegionType::Memory64BitRegion)
            .set_prefetchable(PciBarPrefetchable::Prefetchable);

        if !restoring {
            self.configuration
                .add_pci_bar(&bar0)
                .map_err(|e| PciDeviceError::IoRegistrationFailed(bar0_addr.raw_value(), e))?;
            self.configuration
                .add_pci_bar(&bar2)
                .map_err(|e| PciDeviceError::IoRegistrationFailed(bar2_addr.raw_value(), e))?;
        }

        bars.push(bar0);
        bars.push(bar2);
        self.bar_regions = bars.clone();

        Ok(bars)
    }

    fn free_bars(
        &mut self,
        _allocator: &mut SystemAllocator,
        _mmio32_allocator: &mut AddressAllocator,
        _mmio64_allocator: &mut AddressAllocator,
    ) -> std::result::Result<(), PciDeviceError> {
        unimplemented!("Device hotplug  and remove are not supported for ivshmem");
    }

    fn write_config_register(
        &mut self,
        reg_idx: usize,
        offset: u64,
        data: &[u8],
    ) -> (Vec<BarReprogrammingParams>, Option<Arc<Barrier>>) {
        (
            self.configuration
                .write_config_register(reg_idx, offset, data),
            None,
        )
    }

    fn read_config_register(&mut self, reg_idx: usize) -> u32 {
        self.configuration.read_reg(reg_idx)
    }

    fn read_bar(&mut self, base: u64, offset: u64, data: &mut [u8]) {
        debug!("read base {base:x} offset {offset}");

        let mut bar_idx = 0;
        for (idx, bar) in self.bar_regions.iter().enumerate() {
            if bar.addr() == base {
                bar_idx = idx;
            }
        }
        match bar_idx {
            // bar 0
            0 => {
                // ivshmem don't use interrupt, we return zero now.
                LittleEndian::write_u32(data, 0);
            }
            // bar 2
            1 => warn!("Unexpected read ivshmem memory idx: {offset}"),
            _ => {
                warn!("Invalid bar_idx: {bar_idx}");
            }
        };
    }

    fn write_bar(&mut self, base: u64, offset: u64, _data: &[u8]) -> Option<Arc<Barrier>> {
        debug!("write base {base:x} offset {offset}");
        warn!("Unexpected write ivshmem memory idx: {offset}");
        None
    }

    fn move_bar(&mut self, old_base: u64, new_base: u64) -> result::Result<(), std::io::Error> {
        if new_base == self.data_bar_addr() {
            if let Some(old_mapping) = self.userspace_mapping.take() {
                self.ivshmem_ops
                    .lock()
                    .unwrap()
                    .unmap_ram_region(old_mapping)
                    .map_err(std::io::Error::other)?;
            }
            let (region, new_mapping) = self
                .ivshmem_ops
                .lock()
                .unwrap()
                .map_ram_region(
                    new_base,
                    self.region_size as usize,
                    self.backend_file.clone(),
                )
                .map_err(std::io::Error::other)?;
            self.set_region(region, new_mapping);
        }
        for bar in self.bar_regions.iter_mut() {
            if bar.addr() == old_base {
                *bar = bar.set_address(new_base);
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

impl Pausable for IvshmemDevice {}

impl Snapshottable for IvshmemDevice {
    fn id(&self) -> String {
        self.id.clone()
    }

    // The snapshot/restore (also live migration) support only work for ivshmem-plain mode.
    // Additional work is needed for supporting ivshmem-doorbell.
    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        let mut snapshot = Snapshot::new_from_state(&self.state())?;

        // Snapshot PciConfiguration
        snapshot.add_snapshot(self.configuration.id(), self.configuration.snapshot()?);

        Ok(snapshot)
    }
}

impl Transportable for IvshmemDevice {}

impl Migratable for IvshmemDevice {}
