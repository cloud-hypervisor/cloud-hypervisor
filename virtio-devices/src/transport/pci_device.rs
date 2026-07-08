// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::any::Any;
use std::io::Write;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::{cmp, io, result};

use anyhow::anyhow;
use libc::EFD_NONBLOCK;
use log::{error, info, warn};
use pci::{
    BarReprogrammingParams, MaybeMutInterruptSourceGroup, MsixCap, MsixConfig, PciBarConfiguration,
    PciBarRegionType, PciCapability, PciCapabilityId, PciClassCode, PciConfiguration, PciDevice,
    PciDeviceError, PciHeaderType, PciMassStorageSubclass, PciNetworkControllerSubclass,
    PciSubclass,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use virtio_queue::{Queue, QueueT};
use vm_allocator::{AddressAllocator, SystemAllocator};
use vm_device::dma_mapping::ExternalDmaMapping;
use vm_device::interrupt::{
    InterruptIndex, InterruptManager, InterruptSourceGroup, MsiIrqGroupConfig,
};
use vm_device::{BusDevice, PciBarType, Resource};
use vm_memory::{Address, ByteValued, GuestAddress, GuestAddressSpace, GuestMemoryAtomic, Le32};
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
use vm_virtio::AccessPlatform;
use vmm_sys_util::eventfd::EventFd;

use super::pci_common_config::VirtioPciCommonConfigState;
use crate::transport::{VIRTIO_PCI_COMMON_CONFIG_ID, VirtioPciCommonConfig, VirtioTransport};
use crate::{
    ActivateResult, ActivationContext, DEVICE_ACKNOWLEDGE, DEVICE_DRIVER, DEVICE_DRIVER_OK,
    DEVICE_FAILED, DEVICE_FEATURES_OK, DEVICE_INIT, GuestMemoryMmap, VirtioDevice,
    VirtioDeviceType, VirtioInterrupt, VirtioInterruptType, mark_device_needs_reset,
};

/// Vector value used to disable MSI for a queue.
pub(super) const VIRTQ_MSI_NO_VECTOR: u16 = 0xffff;

enum PciCapabilityType {
    Common = 1,
    Notify = 2,
    Isr = 3,
    Device = 4,
    Pci = 5,
    SharedMemory = 8,
}

// This offset represents the 2 bytes omitted from the VirtioPciCap structure
// as they are already handled through add_capability(). These 2 bytes are the
// fields cap_vndr (1 byte) and cap_next (1 byte) defined in the virtio spec.
const VIRTIO_PCI_CAP_OFFSET: usize = 2;

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct VirtioPciCap {
    cap_len: u8,      // Generic PCI field: capability length
    cfg_type: u8,     // Identifies the structure.
    pci_bar: u8,      // Where to find it.
    id: u8,           // Multiple capabilities of the same type
    padding: [u8; 2], // Pad to full dword.
    offset: Le32,     // Offset within bar.
    length: Le32,     // Length of the structure, in bytes.
}
// SAFETY: All members are simple numbers and any value is valid.
unsafe impl ByteValued for VirtioPciCap {}

impl PciCapability for VirtioPciCap {
    fn bytes(&self) -> &[u8] {
        self.as_slice()
    }

    fn id(&self) -> PciCapabilityId {
        PciCapabilityId::VendorSpecific
    }
}

const VIRTIO_PCI_CAP_LEN_OFFSET: u8 = 2;

impl VirtioPciCap {
    pub fn new(cfg_type: PciCapabilityType, pci_bar: u8, offset: u32, length: u32) -> Self {
        VirtioPciCap {
            cap_len: (size_of::<VirtioPciCap>() as u8) + VIRTIO_PCI_CAP_LEN_OFFSET,
            cfg_type: cfg_type as u8,
            pci_bar,
            id: 0,
            padding: [0; 2],
            offset: Le32::from(offset),
            length: Le32::from(length),
        }
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct VirtioPciNotifyCap {
    cap: VirtioPciCap,
    notify_off_multiplier: Le32,
}
// SAFETY: All members are simple numbers and any value is valid.
unsafe impl ByteValued for VirtioPciNotifyCap {}

impl PciCapability for VirtioPciNotifyCap {
    fn bytes(&self) -> &[u8] {
        self.as_slice()
    }

    fn id(&self) -> PciCapabilityId {
        PciCapabilityId::VendorSpecific
    }
}

impl VirtioPciNotifyCap {
    pub fn new(
        cfg_type: PciCapabilityType,
        pci_bar: u8,
        offset: u32,
        length: u32,
        multiplier: Le32,
    ) -> Self {
        VirtioPciNotifyCap {
            cap: VirtioPciCap {
                cap_len: (size_of::<VirtioPciNotifyCap>() as u8) + VIRTIO_PCI_CAP_LEN_OFFSET,
                cfg_type: cfg_type as u8,
                pci_bar,
                id: 0,
                padding: [0; 2],
                offset: Le32::from(offset),
                length: Le32::from(length),
            },
            notify_off_multiplier: multiplier,
        }
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct VirtioPciCap64 {
    cap: VirtioPciCap,
    offset_hi: Le32,
    length_hi: Le32,
}
// SAFETY: All members are simple numbers and any value is valid.
unsafe impl ByteValued for VirtioPciCap64 {}

impl PciCapability for VirtioPciCap64 {
    fn bytes(&self) -> &[u8] {
        self.as_slice()
    }

    fn id(&self) -> PciCapabilityId {
        PciCapabilityId::VendorSpecific
    }
}

impl VirtioPciCap64 {
    pub fn new(cfg_type: PciCapabilityType, pci_bar: u8, id: u8, offset: u64, length: u64) -> Self {
        VirtioPciCap64 {
            cap: VirtioPciCap {
                cap_len: (size_of::<VirtioPciCap64>() as u8) + VIRTIO_PCI_CAP_LEN_OFFSET,
                cfg_type: cfg_type as u8,
                pci_bar,
                id,
                padding: [0; 2],
                offset: Le32::from(offset as u32),
                length: Le32::from(length as u32),
            },
            offset_hi: Le32::from((offset >> 32) as u32),
            length_hi: Le32::from((length >> 32) as u32),
        }
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct VirtioPciCfgCap {
    cap: VirtioPciCap,
    pci_cfg_data: [u8; 4],
}
// SAFETY: All members are simple numbers and any value is valid.
unsafe impl ByteValued for VirtioPciCfgCap {}

impl PciCapability for VirtioPciCfgCap {
    fn bytes(&self) -> &[u8] {
        self.as_slice()
    }

    fn id(&self) -> PciCapabilityId {
        PciCapabilityId::VendorSpecific
    }
}

impl VirtioPciCfgCap {
    fn new() -> Self {
        VirtioPciCfgCap {
            cap: VirtioPciCap {
                cap_len: (size_of::<VirtioPciCfgCap>() as u8) + VIRTIO_PCI_CAP_LEN_OFFSET,
                cfg_type: PciCapabilityType::Pci as u8,
                pci_bar: 0,
                id: 0,
                padding: [0; 2],
                offset: Le32::from(0),
                length: Le32::from(0),
            },
            ..Default::default()
        }
    }

    /// Return the BAR offset and clamped access length for a PCI CFG cap
    /// indirect BAR access.
    fn bar_access_params(&self, data_len: usize) -> (u64, usize) {
        let bar_offset = self.cap.offset.to_native() as u64;
        let cap_length = self.cap.length.to_native() as usize;
        (bar_offset, cmp::min(cap_length, data_len))
    }
}

#[derive(Clone, Copy, Default)]
struct VirtioPciCfgCapInfo {
    offset: usize,
    cap: VirtioPciCfgCap,
}

#[derive(Copy, Clone)]
pub enum PciVirtioSubclass {
    NonTransitionalBase = 0xff,
}

impl PciSubclass for PciVirtioSubclass {
    fn get_register_value(&self) -> u8 {
        *self as u8
    }
}

/// Max number of virtio queues Cloud Hypervisor supports.
/// This is set by the current size of the notification BAR.
const MAX_QUEUES: u64 = 0x400;

// Automatically compute the position of the next entry in the BAR.
// This handles alignment properly and is much less error-prone than
// manual calculation.
const fn next_bar_addr_align(offset: u64, size: u64, align: u64) -> u64 {
    assert!(align >= 0x2000, "too small alignment for structure in BAR");
    assert!(align.is_power_of_two(), "alignment must be a power of 2");
    (offset + size).next_multiple_of(align)
}
// Same as next_bar_addr_align(), but with the default alignment (8K).
const fn next_bar_addr(offset: u64, size: u64) -> u64 {
    next_bar_addr_align(offset, size, 0x2000)
}

// Allocate one bar for the structs pointed to by the capability structures.
// As per the PCI specification, because the same BAR shares MSI-X and non
// MSI-X structures, it is recommended to use 8KiB alignment for all those
// structures.
const COMMON_CONFIG_BAR_OFFSET: u64 = 0x0000;
const COMMON_CONFIG_SIZE: u64 = 56;
const ISR_CONFIG_BAR_OFFSET: u64 = next_bar_addr(COMMON_CONFIG_BAR_OFFSET, COMMON_CONFIG_SIZE);
const ISR_CONFIG_SIZE: u64 = 1;
const DEVICE_CONFIG_BAR_OFFSET: u64 = next_bar_addr(ISR_CONFIG_BAR_OFFSET, ISR_CONFIG_SIZE);
const DEVICE_CONFIG_SIZE: u64 = 0x1000;
const NOTIFICATION_BAR_OFFSET: u64 = next_bar_addr(DEVICE_CONFIG_BAR_OFFSET, DEVICE_CONFIG_SIZE);
const NOTIFICATION_SIZE: u64 = MAX_QUEUES * NOTIFY_OFF_MULTIPLIER as u64;
const MSIX_TABLE_BAR_OFFSET: u64 = next_bar_addr(NOTIFICATION_BAR_OFFSET, NOTIFICATION_SIZE);

// The size is 256KiB because the table can hold up to 2048 entries, with each
// entry being 128 bits (4 DWORDS).
const MSIX_TABLE_SIZE: u64 = 0x40000;
const MSIX_PBA_BAR_OFFSET: u64 = next_bar_addr(MSIX_TABLE_BAR_OFFSET, MSIX_TABLE_SIZE);
// The size is 2KiB because the Pending Bit Array has one bit per vector and it
// can support up to 2048 vectors.
const MSIX_PBA_SIZE: u64 = 0x800;
// The BAR size must be a power of 2.
const CAPABILITY_BAR_SIZE: u64 = (MSIX_PBA_BAR_OFFSET + MSIX_PBA_SIZE).next_power_of_two();
// Align larger than natural alignment to work around Windows driver issues
const VIRTIO_PCI_BAR_ALIGN: u64 = 0x80_0000;
const VIRTIO_COMMON_BAR_INDEX: u8 = 0;
const VIRTIO_SHM_BAR_INDEX: usize = 2;

const NOTIFY_OFF_MULTIPLIER: u32 = 4; // A dword per notification address.

const VIRTIO_PCI_VENDOR_ID: u16 = 0x1af4;
const VIRTIO_PCI_DEVICE_ID_BASE: u16 = 0x1040; // Add to device type to get device ID.

#[derive(Serialize, Deserialize)]
struct QueueState {
    max_size: u16,
    size: u16,
    ready: bool,
    desc_table: u64,
    avail_ring: u64,
    used_ring: u64,
}

#[derive(Serialize, Deserialize)]
pub struct VirtioPciDeviceState {
    device_activated: bool,
    queues: Vec<QueueState>,
    interrupt_status: usize,
    cap_pci_cfg_offset: usize,
    cap_pci_cfg: Vec<u8>,
}

pub struct VirtioPciDeviceActivator {
    interrupt: Arc<dyn VirtioInterrupt>,
    memory: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    device: Arc<Mutex<dyn VirtioDevice>>,
    device_activated: Arc<AtomicBool>,
    queues: Option<Vec<(usize, Queue, EventFd)>>,
    barrier: Option<Arc<Barrier>>,
    id: String,
    status: Arc<AtomicU8>,
}

impl VirtioPciDeviceActivator {
    pub fn activate(mut self) -> ActivateResult {
        let result = self.device.lock().unwrap().activate(ActivationContext {
            mem: self.memory.take().unwrap(),
            interrupt_cb: self.interrupt.clone(),
            queues: self.queues.take().unwrap(),
            device_status: self.status.clone(),
        });

        if let Err(e) = &result {
            mark_device_needs_reset(
                &self.status,
                self.interrupt.as_ref(),
                format_args!("{}: virtio device activation failed: {e:?}", self.id),
            );
        } else {
            self.device_activated.store(true, Ordering::SeqCst);
        }

        // Release the barrier regardless of outcome. A failing activate()
        // would otherwise deadlock the vCPU that wrote DRIVER_OK.
        if let Some(barrier) = self.barrier.take() {
            info!("{}: Waiting for barrier", self.id);
            barrier.wait();
            info!("{}: Barrier released", self.id);
        }

        result
    }
}

#[derive(Error, Debug)]
pub enum VirtioPciDeviceError {
    #[error("Failed creating VirtioPciDevice")]
    CreateVirtioPciDevice(#[source] anyhow::Error),
}
pub type Result<T> = result::Result<T, VirtioPciDeviceError>;

pub struct VirtioPciDevice {
    id: String,

    // PCI configuration registers.
    configuration: PciConfiguration,

    // virtio PCI common configuration
    common_config: VirtioPciCommonConfig,

    // MSI-X config
    msix_config: Arc<Mutex<MsixConfig>>,

    // Number of MSI-X vectors
    msix_num: u16,

    // Virtio device reference and status
    device: Arc<Mutex<dyn VirtioDevice>>,
    device_activated: Arc<AtomicBool>,

    // PCI interrupts.
    interrupt_status: Arc<AtomicUsize>,
    virtio_interrupt: Arc<dyn VirtioInterrupt>,

    // virtio queues
    queues: Vec<Queue>,
    queue_evts: Vec<EventFd>,

    // Guest memory
    memory: GuestMemoryAtomic<GuestMemoryMmap>,

    // Whether to use 64-bit bar location or 32-bit
    use_64bit_bar: bool,

    // Add a dedicated structure to hold information about the very specific
    // virtio-pci capability VIRTIO_PCI_CAP_PCI_CFG. This is needed to support
    // the legacy/backward compatible mechanism of letting the guest access the
    // other virtio capabilities without mapping the PCI BARs. This can be
    // needed when the guest tries to early access the virtio configuration of
    // a device.
    cap_pci_cfg_info: VirtioPciCfgCapInfo,

    // Details of bar regions to free
    bar_regions: Vec<PciBarConfiguration>,

    // EventFd to signal on to request activation
    activate_evt: EventFd,

    // Optional DMA handler
    dma_handler: Option<Arc<dyn ExternalDmaMapping>>,

    // Pending activations
    pending_activations: Arc<Mutex<Vec<VirtioPciDeviceActivator>>>,
}

impl VirtioPciDevice {
    /// Constructs a new PCI transport for the given virtio device.
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        memory: GuestMemoryAtomic<GuestMemoryMmap>,
        device: Arc<Mutex<dyn VirtioDevice>>,
        access_platform: Option<&Arc<dyn AccessPlatform>>,
        interrupt_manager: &dyn InterruptManager<GroupConfig = MsiIrqGroupConfig>,
        pci_device_bdf: u32,
        activate_evt: EventFd,
        use_64bit_bar: bool,
        dma_handler: Option<Arc<dyn ExternalDmaMapping>>,
        pending_activations: Arc<Mutex<Vec<VirtioPciDeviceActivator>>>,
        snapshot: Option<&Snapshot>,
    ) -> Result<Self> {
        let mut locked_device = device.lock().unwrap();
        let mut queue_evts = Vec::new();
        for _ in locked_device.queue_max_sizes().iter() {
            queue_evts.push(EventFd::new(EFD_NONBLOCK).map_err(|e| {
                VirtioPciDeviceError::CreateVirtioPciDevice(anyhow!("Failed creating eventfd: {e}"))
            })?);
        }
        let num_queues = locked_device.queue_max_sizes().len();

        if let Some(access_platform) = access_platform {
            locked_device.set_access_platform(access_platform.clone());
        }

        let mut queues: Vec<Queue> = locked_device
            .queue_max_sizes()
            .iter()
            .map(|&s| Queue::new(s).unwrap())
            .collect();

        let pci_device_id = VIRTIO_PCI_DEVICE_ID_BASE + locked_device.device_type() as u16;

        // Allows support for one MSI-X vector per interrupt needed by the device.
        // It also adds 1 as we need to take into account the dedicated vector to notify
        // about a virtio config change.
        let msix_num = (locked_device.queue_max_sizes().len() + 1) as u16;

        let interrupt_source_group: MaybeMutInterruptSourceGroup = {
            let config = MsiIrqGroupConfig {
                base: 0,
                count: msix_num as InterruptIndex,
            };
            (if locked_device.interrupt_source_mutable() {
                interrupt_manager
                    .create_group_mut(config)
                    .map(MaybeMutInterruptSourceGroup::Mutable)
            } else {
                interrupt_manager
                    .create_group(config)
                    .map(MaybeMutInterruptSourceGroup::Immutable)
            })
            .map_err(|e| {
                VirtioPciDeviceError::CreateVirtioPciDevice(anyhow!(
                    "Failed creating MSI interrupt group: {e}"
                ))
            })?
        };
        let msix_state =
            vm_migration::state_from_id(snapshot, pci::MSIX_CONFIG_ID).map_err(|e| {
                VirtioPciDeviceError::CreateVirtioPciDevice(anyhow!(
                    "Failed to get MsixConfigState from Snapshot: {e}"
                ))
            })?;

        let (msix_config, msix_config_clone) = {
            let interrupt_source_group: MaybeMutInterruptSourceGroup =
                interrupt_source_group.clone();
            let msix_config = Arc::new(Mutex::new(
                MsixConfig::new(msix_num, interrupt_source_group, pci_device_bdf, msix_state)
                    .unwrap(),
            ));
            let msix_config_clone = msix_config.clone();
            (msix_config, msix_config_clone)
        };

        let (class, subclass) = match VirtioDeviceType::from(locked_device.device_type()) {
            VirtioDeviceType::Net => (
                PciClassCode::NetworkController,
                &PciNetworkControllerSubclass::EthernetController as &dyn PciSubclass,
            ),
            VirtioDeviceType::Block => (
                PciClassCode::MassStorage,
                &PciMassStorageSubclass::MassStorage as &dyn PciSubclass,
            ),
            _ => (
                PciClassCode::Other,
                &PciVirtioSubclass::NonTransitionalBase as &dyn PciSubclass,
            ),
        };

        let pci_configuration_state =
            vm_migration::state_from_id(snapshot, pci::PCI_CONFIGURATION_ID).map_err(|e| {
                VirtioPciDeviceError::CreateVirtioPciDevice(anyhow!(
                    "Failed to get PciConfigurationState from Snapshot: {e}"
                ))
            })?;

        let configuration = PciConfiguration::new(
            VIRTIO_PCI_VENDOR_ID,
            pci_device_id,
            0x1, // For modern virtio-PCI devices
            class,
            subclass,
            None,
            PciHeaderType::Device,
            VIRTIO_PCI_VENDOR_ID,
            pci_device_id,
            Some(msix_config_clone),
            pci_configuration_state,
        );

        let common_config_state =
            vm_migration::state_from_id(snapshot, VIRTIO_PCI_COMMON_CONFIG_ID).map_err(|e| {
                VirtioPciDeviceError::CreateVirtioPciDevice(anyhow!(
                    "Failed to get VirtioPciCommonConfigState from Snapshot: {e}"
                ))
            })?;

        let common_config = if let Some(common_config_state) = common_config_state {
            VirtioPciCommonConfig::new(common_config_state, device.clone())
        } else {
            VirtioPciCommonConfig::new(
                VirtioPciCommonConfigState {
                    driver_status: 0,
                    config_generation: 0,
                    device_feature_select: 0,
                    driver_feature_select: 0,
                    queue_select: 0,
                    msix_config: VIRTQ_MSI_NO_VECTOR,
                    msix_queues: vec![VIRTQ_MSI_NO_VECTOR; num_queues],
                },
                device.clone(),
            )
        };

        let state: Option<VirtioPciDeviceState> = snapshot
            .as_ref()
            .map(|s| s.to_state())
            .transpose()
            .map_err(|e| {
                VirtioPciDeviceError::CreateVirtioPciDevice(anyhow!(
                    "Failed to get VirtioPciDeviceState from Snapshot: {e}"
                ))
            })?;

        let (device_activated, interrupt_status, cap_pci_cfg_info) = if let Some(state) = state {
            // Update virtqueues indexes for both available and used rings.
            for (i, queue) in queues.iter_mut().enumerate() {
                queue.set_size(state.queues[i].size);
                queue.set_ready(state.queues[i].ready);
                queue
                    .try_set_desc_table_address(GuestAddress(state.queues[i].desc_table))
                    .unwrap();
                queue
                    .try_set_avail_ring_address(GuestAddress(state.queues[i].avail_ring))
                    .unwrap();
                queue
                    .try_set_used_ring_address(GuestAddress(state.queues[i].used_ring))
                    .unwrap();
                queue.set_next_avail(
                    queue
                        .used_idx(memory.memory().deref(), Ordering::Acquire)
                        .unwrap()
                        .0,
                );
                queue.set_next_used(
                    queue
                        .used_idx(memory.memory().deref(), Ordering::Acquire)
                        .unwrap()
                        .0,
                );
            }

            (
                state.device_activated,
                state.interrupt_status,
                VirtioPciCfgCapInfo {
                    offset: state.cap_pci_cfg_offset,
                    cap: *VirtioPciCfgCap::from_slice(&state.cap_pci_cfg).unwrap(),
                },
            )
        } else {
            (false, 0, VirtioPciCfgCapInfo::default())
        };

        // Dropping the MutexGuard to unlock the VirtioDevice. This is required
        // in the context of a restore given the device might require some
        // activation, meaning it will require locking. Dropping the lock
        // prevents from a subtle deadlock.
        drop(locked_device);

        let virtio_interrupt = Arc::new(VirtioInterruptMsix::new(
            msix_config.clone(),
            common_config.msix_config.clone(),
            common_config.config_changed.clone(),
            common_config.msix_queues.clone(),
            interrupt_source_group.clone(),
        ));

        let mut virtio_pci_device = VirtioPciDevice {
            id,
            configuration,
            common_config,
            msix_config,
            msix_num,
            device,
            device_activated: Arc::new(AtomicBool::new(device_activated)),
            interrupt_status: Arc::new(AtomicUsize::new(interrupt_status)),
            virtio_interrupt,
            queues,
            queue_evts,
            memory,
            use_64bit_bar,
            cap_pci_cfg_info,
            bar_regions: vec![],
            activate_evt,
            dma_handler,
            pending_activations,
        };

        // In case of a restore, we can activate the device, as we know at
        // this point the virtqueues are in the right state and the device is
        // ready to be activated, which will spawn each virtio worker thread.
        if virtio_pci_device.device_activated.load(Ordering::SeqCst)
            && virtio_pci_device.is_driver_ready()
        {
            virtio_pci_device.activate().map_err(|e| {
                VirtioPciDeviceError::CreateVirtioPciDevice(anyhow!(
                    "Failed activating the device: {e}"
                ))
            })?;
        }

        Ok(virtio_pci_device)
    }

    fn state(&self) -> VirtioPciDeviceState {
        VirtioPciDeviceState {
            device_activated: self.device_activated.load(Ordering::Acquire),
            interrupt_status: self.interrupt_status.load(Ordering::Acquire),
            queues: self
                .queues
                .iter()
                .map(|q| QueueState {
                    max_size: q.max_size(),
                    size: q.size(),
                    ready: q.ready(),
                    desc_table: q.desc_table(),
                    avail_ring: q.avail_ring(),
                    used_ring: q.used_ring(),
                })
                .collect(),
            cap_pci_cfg_offset: self.cap_pci_cfg_info.offset,
            cap_pci_cfg: self.cap_pci_cfg_info.cap.bytes().to_vec(),
        }
    }

    /// Gets the list of queue events that must be triggered whenever the VM writes to
    /// `virtio::NOTIFY_REG_OFFSET` past the MMIO base. Each event must be triggered when the
    /// value being written equals the index of the event in this list.
    fn queue_evts(&self) -> &[EventFd] {
        self.queue_evts.as_slice()
    }

    fn is_driver_ready(&self) -> bool {
        let ready_bits =
            (DEVICE_ACKNOWLEDGE | DEVICE_DRIVER | DEVICE_DRIVER_OK | DEVICE_FEATURES_OK) as u8;
        let driver_status = self.common_config.driver_status.load(Ordering::SeqCst);
        driver_status == ready_bits && (driver_status & DEVICE_FAILED as u8) == 0
    }

    /// Determines if the driver has requested the device (re)init / reset itself
    fn is_driver_init(&self) -> bool {
        self.common_config.driver_status.load(Ordering::SeqCst) == DEVICE_INIT as u8
    }

    pub fn config_bar_addr(&self) -> u64 {
        self.configuration
            .get_bar_addr(VIRTIO_COMMON_BAR_INDEX.into())
    }

    fn add_pci_capabilities(
        &mut self,
        device_config_size: u64,
    ) -> result::Result<(), PciDeviceError> {
        // Add pointers to the different configuration structures from the PCI capabilities.
        let common_cap = VirtioPciCap::new(
            PciCapabilityType::Common,
            VIRTIO_COMMON_BAR_INDEX,
            COMMON_CONFIG_BAR_OFFSET as u32,
            COMMON_CONFIG_SIZE as u32,
        );
        self.configuration
            .add_capability(&common_cap)
            .map_err(PciDeviceError::CapabilitiesSetup)?;

        let isr_cap = VirtioPciCap::new(
            PciCapabilityType::Isr,
            VIRTIO_COMMON_BAR_INDEX,
            ISR_CONFIG_BAR_OFFSET as u32,
            ISR_CONFIG_SIZE as u32,
        );
        self.configuration
            .add_capability(&isr_cap)
            .map_err(PciDeviceError::CapabilitiesSetup)?;

        if device_config_size > 0 {
            let device_cap = VirtioPciCap::new(
                PciCapabilityType::Device,
                VIRTIO_COMMON_BAR_INDEX,
                DEVICE_CONFIG_BAR_OFFSET as u32,
                device_config_size as u32,
            );
            self.configuration
                .add_capability(&device_cap)
                .map_err(PciDeviceError::CapabilitiesSetup)?;
        }

        let notify_cap = VirtioPciNotifyCap::new(
            PciCapabilityType::Notify,
            VIRTIO_COMMON_BAR_INDEX,
            NOTIFICATION_BAR_OFFSET as u32,
            NOTIFICATION_SIZE as u32,
            Le32::from(NOTIFY_OFF_MULTIPLIER),
        );
        self.configuration
            .add_capability(&notify_cap)
            .map_err(PciDeviceError::CapabilitiesSetup)?;

        let configuration_cap = VirtioPciCfgCap::new();
        self.cap_pci_cfg_info.offset = self
            .configuration
            .add_capability(&configuration_cap)
            .map_err(PciDeviceError::CapabilitiesSetup)?
            + VIRTIO_PCI_CAP_OFFSET;
        self.cap_pci_cfg_info.cap = configuration_cap;

        let msix_cap = MsixCap::new(
            VIRTIO_COMMON_BAR_INDEX,
            self.msix_num,
            MSIX_TABLE_BAR_OFFSET as u32,
            VIRTIO_COMMON_BAR_INDEX,
            MSIX_PBA_BAR_OFFSET as u32,
        );
        self.configuration
            .add_capability(&msix_cap)
            .map_err(PciDeviceError::CapabilitiesSetup)?;

        Ok(())
    }

    fn read_cap_pci_cfg(&mut self, offset: usize, mut data: &mut [u8]) {
        let cap_slice = self.cap_pci_cfg_info.cap.as_slice();
        let data_len = data.len();
        let cap_len = cap_slice.len();
        if offset + data_len > cap_len {
            error!("Failed to read cap_pci_cfg from config space");
            return;
        }

        if offset < size_of::<VirtioPciCap>() {
            if let Some(end) = offset.checked_add(data_len) {
                // This write can't fail, offset and end are checked against config_len.
                data.write_all(&cap_slice[offset..cmp::min(end, cap_len)])
                    .unwrap();
            }
        } else {
            let (bar_offset, access_len) = self.cap_pci_cfg_info.cap.bar_access_params(data_len);
            if access_len > 0 {
                self.read_bar(0, bar_offset, &mut data[..access_len]);
            }
        }
    }

    fn write_cap_pci_cfg(&mut self, offset: usize, data: &[u8]) -> Option<Arc<Barrier>> {
        let cap_slice = self.cap_pci_cfg_info.cap.as_mut_slice();
        let data_len = data.len();
        let cap_len = cap_slice.len();
        if offset + data_len > cap_len {
            error!("Failed to write cap_pci_cfg to config space");
            return None;
        }

        if offset < size_of::<VirtioPciCap>() {
            let (_, right) = cap_slice.split_at_mut(offset);
            right[..data_len].copy_from_slice(data);
            None
        } else {
            let (bar_offset, access_len) = self.cap_pci_cfg_info.cap.bar_access_params(data_len);
            if access_len > 0 {
                self.write_bar(0, bar_offset, &data[..access_len])
            } else {
                None
            }
        }
    }

    pub fn virtio_device(&self) -> Arc<Mutex<dyn VirtioDevice>> {
        self.device.clone()
    }

    fn prepare_activator(&mut self, barrier: Option<Arc<Barrier>>) -> VirtioPciDeviceActivator {
        let mut queues = Vec::new();

        for (queue_index, queue) in self.queues.iter().enumerate() {
            if !queue.ready() {
                continue;
            }

            if !queue.is_valid(self.memory.memory().deref()) {
                error!("Queue {queue_index} is not valid; skipping activation");
                continue;
            }

            queues.push((
                queue_index,
                vm_virtio::clone_queue(queue),
                self.queue_evts[queue_index].try_clone().unwrap(),
            ));
        }

        VirtioPciDeviceActivator {
            interrupt: self.virtio_interrupt.clone(),
            memory: Some(self.memory.clone()),
            device: self.device.clone(),
            queues: Some(queues),
            device_activated: self.device_activated.clone(),
            barrier,
            id: self.id.clone(),
            status: self.common_config.driver_status.clone(),
        }
    }

    fn activate(&mut self) -> ActivateResult {
        self.prepare_activator(None).activate()
    }

    fn needs_activation(&self) -> bool {
        !self.device_activated.load(Ordering::SeqCst)
            && self.is_driver_ready()
            && self.queues.iter().any(|q| q.ready())
    }

    pub fn dma_handler(&self) -> Option<&dyn ExternalDmaMapping> {
        self.dma_handler.as_deref()
    }
}

impl VirtioTransport for VirtioPciDevice {
    fn ioeventfds(&self, base_addr: u64) -> impl Iterator<Item = (&EventFd, u64)> {
        let notify_base = base_addr + NOTIFICATION_BAR_OFFSET;
        self.queue_evts().iter().enumerate().map(move |(i, event)| {
            (
                event,
                notify_base + i as u64 * u64::from(NOTIFY_OFF_MULTIPLIER),
            )
        })
    }
}

pub struct VirtioInterruptMsix {
    msix_config: Arc<Mutex<MsixConfig>>,
    config_vector: Arc<AtomicU16>,
    config_changed: Arc<AtomicBool>,
    queues_vectors: Arc<Mutex<Vec<u16>>>,
    interrupt_source_group: MaybeMutInterruptSourceGroup,
    msix_table_size: usize,
}

impl VirtioInterruptMsix {
    pub fn new(
        msix_config: Arc<Mutex<MsixConfig>>,
        config_vector: Arc<AtomicU16>,
        config_changed: Arc<AtomicBool>,
        queues_vectors: Arc<Mutex<Vec<u16>>>,
        interrupt_source_group: MaybeMutInterruptSourceGroup,
    ) -> Self {
        let msix_table_size = msix_config.lock().unwrap().table_entries.len();
        VirtioInterruptMsix {
            msix_config,
            config_vector,
            config_changed,
            queues_vectors,
            interrupt_source_group,
            msix_table_size,
        }
    }
}

impl VirtioInterrupt for VirtioInterruptMsix {
    fn trigger(&self, int_type: VirtioInterruptType) -> io::Result<()> {
        if matches!(int_type, VirtioInterruptType::Config) {
            self.config_changed.store(true, Ordering::Release);
        }

        let vector = match int_type {
            VirtioInterruptType::Config => self.config_vector.load(Ordering::Acquire),
            VirtioInterruptType::Queue(queue_index) => {
                self.queues_vectors.lock().unwrap()[queue_index as usize]
            }
        };

        if vector == VIRTQ_MSI_NO_VECTOR {
            return Ok(());
        }

        if vector as usize >= self.msix_table_size {
            warn!("MSI-X vector {vector} out of range, ignoring interrupt");
            return Ok(());
        }

        let config = &mut self.msix_config.lock().unwrap();
        let entry = &config.table_entries[vector as usize];
        // In case the vector control register associated with the entry
        // has its first bit set, this means the vector is masked and the
        // device should not inject the interrupt.
        // Instead, the Pending Bit Array table is updated to reflect there
        // is a pending interrupt for this specific vector.
        if config.masked() || entry.masked() {
            config.set_pba_bit(vector, false);
            return Ok(());
        }

        self.interrupt_source_group
            .trigger(vector as InterruptIndex)
    }

    fn notifier(&self, int_type: VirtioInterruptType) -> Option<EventFd> {
        let vector = match int_type {
            VirtioInterruptType::Config => self.config_vector.load(Ordering::Acquire),
            VirtioInterruptType::Queue(queue_index) => {
                self.queues_vectors.lock().unwrap()[queue_index as usize]
            }
        };

        if vector == VIRTQ_MSI_NO_VECTOR {
            return None;
        }

        if vector as usize >= self.msix_table_size {
            warn!("MSI-X vector {vector} out of range, notifier unavailable");
            return None;
        }

        self.interrupt_source_group
            .notifier(vector as InterruptIndex)
    }

    fn set_notifier(
        &self,
        interrupt: u32,
        eventfd: Option<EventFd>,
        vm: &dyn hypervisor::Vm,
    ) -> io::Result<()> {
        self.interrupt_source_group
            .set_notifier(interrupt, eventfd, vm)
    }
}

impl PciDevice for VirtioPciDevice {
    fn write_config_register(
        &mut self,
        reg_idx: usize,
        offset: u64,
        data: &[u8],
    ) -> (Vec<BarReprogrammingParams>, Option<Arc<Barrier>>) {
        // Handle the special case where the capability VIRTIO_PCI_CAP_PCI_CFG
        // is accessed. This capability has a special meaning as it allows the
        // guest to access other capabilities without mapping the PCI BAR.
        let base = reg_idx * 4;
        if base + offset as usize >= self.cap_pci_cfg_info.offset
            && base + offset as usize + data.len()
                <= self.cap_pci_cfg_info.offset + self.cap_pci_cfg_info.cap.bytes().len()
        {
            let offset = base + offset as usize - self.cap_pci_cfg_info.offset;
            (Vec::new(), self.write_cap_pci_cfg(offset, data))
        } else {
            (
                self.configuration
                    .write_config_register(reg_idx, offset, data),
                None,
            )
        }
    }

    fn read_config_register(&mut self, reg_idx: usize) -> u32 {
        // Handle the special case where the capability VIRTIO_PCI_CAP_PCI_CFG
        // is accessed. This capability has a special meaning as it allows the
        // guest to access other capabilities without mapping the PCI BAR.
        let base = reg_idx * 4;
        if base >= self.cap_pci_cfg_info.offset
            && base + 4 <= self.cap_pci_cfg_info.offset + self.cap_pci_cfg_info.cap.bytes().len()
        {
            let offset = base - self.cap_pci_cfg_info.offset;
            let mut data = [0u8; 4];
            self.read_cap_pci_cfg(offset, &mut data);
            u32::from_le_bytes(data)
        } else {
            self.configuration.read_reg(reg_idx)
        }
    }

    fn allocate_bars(
        &mut self,
        _allocator: &mut SystemAllocator,
        mmio32_allocator: &mut AddressAllocator,
        mmio64_allocator: &mut AddressAllocator,
        resources: Option<Vec<Resource>>,
    ) -> result::Result<Vec<PciBarConfiguration>, PciDeviceError> {
        let mut bars = Vec::new();
        let device_clone = self.device.clone();
        let device = device_clone.lock().unwrap();

        let mut settings_bar_addr = None;
        let mut use_64bit_bar = self.use_64bit_bar;
        let restoring = resources.is_some();
        if let Some(resources) = resources {
            for resource in resources {
                if let Resource::PciBar {
                    index, base, type_, ..
                } = resource
                    && index == usize::from(VIRTIO_COMMON_BAR_INDEX)
                {
                    settings_bar_addr = Some(GuestAddress(base));
                    use_64bit_bar = match type_ {
                        PciBarType::Io => {
                            return Err(PciDeviceError::InvalidResource(resource));
                        }
                        PciBarType::Mmio32 => false,
                        PciBarType::Mmio64 => true,
                    };
                    break;
                }
            }
            // Error out if no resource was matching the BAR id.
            if settings_bar_addr.is_none() {
                return Err(PciDeviceError::MissingResource);
            }
        }

        // Allocate the virtio-pci capability BAR.
        // See http://docs.oasis-open.org/virtio/virtio/v1.0/cs04/virtio-v1.0-cs04.html#x1-740004
        let (virtio_pci_bar_addr, region_type) = if use_64bit_bar {
            let region_type = PciBarRegionType::Memory64BitRegion;
            let alignment = if restoring {
                None
            } else {
                Some(VIRTIO_PCI_BAR_ALIGN)
            };
            let addr = mmio64_allocator
                .allocate(settings_bar_addr, CAPABILITY_BAR_SIZE, alignment)
                .ok_or(PciDeviceError::IoAllocationFailed(CAPABILITY_BAR_SIZE))?;
            (addr, region_type)
        } else {
            let region_type = PciBarRegionType::Memory32BitRegion;
            let addr = mmio32_allocator
                .allocate(
                    settings_bar_addr,
                    CAPABILITY_BAR_SIZE,
                    Some(CAPABILITY_BAR_SIZE),
                )
                .ok_or(PciDeviceError::IoAllocationFailed(CAPABILITY_BAR_SIZE))?;
            (addr, region_type)
        };

        let bar = PciBarConfiguration::default()
            .set_index(VIRTIO_COMMON_BAR_INDEX.into())
            .set_address(virtio_pci_bar_addr.raw_value())
            .set_size(CAPABILITY_BAR_SIZE)
            .set_region_type(region_type);

        // The creation of the PCI BAR and its associated capabilities must
        // happen only during the creation of a brand new VM. When a VM is
        // restored from a known state, the BARs are already created with the
        // right content, therefore we don't need to go through this codepath.
        if !restoring {
            self.configuration.add_pci_bar(&bar).map_err(|e| {
                PciDeviceError::IoRegistrationFailed(virtio_pci_bar_addr.raw_value(), e)
            })?;

            // Once the BARs are allocated, the capabilities can be added to the PCI configuration.
            let device_config_size = device.config_size().unwrap_or(DEVICE_CONFIG_SIZE);
            self.add_pci_capabilities(device_config_size)?;
        }

        bars.push(bar);

        // Allocate a dedicated BAR if there are some shared memory regions.
        if let Some(shm_list) = device.get_shm_regions() {
            let bar = PciBarConfiguration::default()
                .set_index(VIRTIO_SHM_BAR_INDEX)
                .set_address(shm_list.addr.raw_value())
                .set_size(shm_list.mapping.size() as _);

            // The creation of the PCI BAR and its associated capabilities must
            // happen only during the creation of a brand new VM. When a VM is
            // restored from a known state, the BARs are already created with the
            // right content, therefore we don't need to go through this codepath.
            if !restoring {
                self.configuration.add_pci_bar(&bar).map_err(|e| {
                    PciDeviceError::IoRegistrationFailed(shm_list.addr.raw_value(), e)
                })?;

                for (idx, shm) in shm_list.region_list.iter().enumerate() {
                    let shm_cap = VirtioPciCap64::new(
                        PciCapabilityType::SharedMemory,
                        VIRTIO_SHM_BAR_INDEX as u8,
                        idx as u8,
                        shm.offset,
                        shm.len,
                    );
                    self.configuration
                        .add_capability(&shm_cap)
                        .map_err(PciDeviceError::CapabilitiesSetup)?;
                }
            }

            bars.push(bar);
        }

        self.bar_regions.clone_from(&bars);

        Ok(bars)
    }

    fn free_bars(
        &mut self,
        _allocator: &mut SystemAllocator,
        mmio32_allocator: &mut AddressAllocator,
        mmio64_allocator: &mut AddressAllocator,
    ) -> result::Result<(), PciDeviceError> {
        for bar in self.bar_regions.drain(..) {
            match bar.region_type() {
                PciBarRegionType::Memory32BitRegion => {
                    mmio32_allocator.free(GuestAddress(bar.addr()), bar.size());
                }
                PciBarRegionType::Memory64BitRegion => {
                    mmio64_allocator.free(GuestAddress(bar.addr()), bar.size());
                }
                _ => error!("Unexpected PCI bar type"),
            }
        }
        Ok(())
    }

    fn move_bar(&mut self, old_base: u64, new_base: u64) -> io::Result<()> {
        // We only update our idea of the bar in order to support free_bars() above.
        // The majority of the reallocation is done inside DeviceManager.
        for bar in self.bar_regions.iter_mut() {
            if bar.addr() == old_base {
                *bar = bar.set_address(new_base);
            }
        }

        Ok(())
    }

    fn restore_bar_addr(&mut self, params: &BarReprogrammingParams) {
        self.configuration.restore_bar_addr(params);
    }

    fn read_bar(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        match offset {
            o if o < COMMON_CONFIG_BAR_OFFSET + COMMON_CONFIG_SIZE => {
                self.common_config
                    .read(o - COMMON_CONFIG_BAR_OFFSET, data, &self.queues);
            }
            o if (ISR_CONFIG_BAR_OFFSET..ISR_CONFIG_BAR_OFFSET + ISR_CONFIG_SIZE).contains(&o) => {
                if let Some(v) = data.get_mut(0) {
                    // Reading this register resets it to 0.
                    *v = self.interrupt_status.swap(0, Ordering::AcqRel) as u8;
                }
            }
            o if (DEVICE_CONFIG_BAR_OFFSET..DEVICE_CONFIG_BAR_OFFSET + DEVICE_CONFIG_SIZE)
                .contains(&o) =>
            {
                self.common_config.consume_config_change();
                let device = self.device.lock().unwrap();
                device.read_config(o - DEVICE_CONFIG_BAR_OFFSET, data);
            }
            o if (NOTIFICATION_BAR_OFFSET..NOTIFICATION_BAR_OFFSET + NOTIFICATION_SIZE)
                .contains(&o) =>
            {
                // Handled with ioeventfds.
            }
            o if (MSIX_TABLE_BAR_OFFSET..MSIX_TABLE_BAR_OFFSET + MSIX_TABLE_SIZE).contains(&o) => {
                self.msix_config
                    .lock()
                    .unwrap()
                    .read_table(o - MSIX_TABLE_BAR_OFFSET, data);
            }
            o if (MSIX_PBA_BAR_OFFSET..MSIX_PBA_BAR_OFFSET + MSIX_PBA_SIZE).contains(&o) => {
                self.msix_config
                    .lock()
                    .unwrap()
                    .read_pba(o - MSIX_PBA_BAR_OFFSET, data);
            }
            _ => (),
        }
    }

    fn write_bar(&mut self, base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        let initial_ready = self.is_driver_ready();
        match offset {
            o if o < COMMON_CONFIG_BAR_OFFSET + COMMON_CONFIG_SIZE => {
                self.common_config
                    .write(o - COMMON_CONFIG_BAR_OFFSET, data, &mut self.queues);
            }
            o if (ISR_CONFIG_BAR_OFFSET..ISR_CONFIG_BAR_OFFSET + ISR_CONFIG_SIZE).contains(&o) => {
                if let Some(v) = data.first() {
                    self.interrupt_status
                        .fetch_and(!(*v as usize), Ordering::AcqRel);
                }
            }
            o if (DEVICE_CONFIG_BAR_OFFSET..DEVICE_CONFIG_BAR_OFFSET + DEVICE_CONFIG_SIZE)
                .contains(&o) =>
            {
                let mut device = self.device.lock().unwrap();
                device.write_config(o - DEVICE_CONFIG_BAR_OFFSET, data);
            }
            o if (NOTIFICATION_BAR_OFFSET..NOTIFICATION_BAR_OFFSET + NOTIFICATION_SIZE)
                .contains(&o) =>
            {
                // A queue notification (doorbell) is normally delivered to the device through an
                // ioeventfd registered on the notify address, so a plain MMIO write to the notify
                // register never reaches this function.
                //
                // It *does* reach here when the driver rings the doorbell through the
                // VIRTIO_PCI_CAP_PCI_CFG window (write_cap_pci_cfg -> write_bar) instead of
                // through a mapped BAR, or on backends that deliver the write to the VMM (e.g.
                // SEV-SNP).
                //
                // In those cases we must signal the matching queue eventfd ourselves. The virtio
                // spec explicitly allows driving the device purely through the PCI_CFG window, so
                // honour a doorbell that arrives this way.
                let mut signalled = false;
                for (event, addr) in self.ioeventfds(base) {
                    if addr == base + offset {
                        event.write(1).ok();
                        signalled = true;
                    }
                }
                if !signalled {
                    warn!("Notification BAR write matched no queue: offset = 0x{o:x}");
                }
            }
            o if (MSIX_TABLE_BAR_OFFSET..MSIX_TABLE_BAR_OFFSET + MSIX_TABLE_SIZE).contains(&o) => {
                self.msix_config
                    .lock()
                    .unwrap()
                    .write_table(o - MSIX_TABLE_BAR_OFFSET, data);
            }
            o if (MSIX_PBA_BAR_OFFSET..MSIX_PBA_BAR_OFFSET + MSIX_PBA_SIZE).contains(&o) => {
                self.msix_config
                    .lock()
                    .unwrap()
                    .write_pba(o - MSIX_PBA_BAR_OFFSET, data);
            }
            _ => (),
        }

        // Try and activate the device if the driver status has changed (from unready to ready)
        if !initial_ready && self.needs_activation() {
            let barrier = Arc::new(Barrier::new(2));
            let activator = self.prepare_activator(Some(barrier.clone()));
            self.pending_activations.lock().unwrap().push(activator);
            info!(
                "{}: Needs activation; writing to activate event fd",
                self.id
            );
            self.activate_evt.write(1).ok();
            info!("{}: Needs activation; returning barrier", self.id);
            return Some(barrier);
        }

        // The driver requested a reset by writing 0 to device_status. Per the
        // virtio spec this is permitted at any point in initialisation.
        if self.is_driver_init() {
            if self.device_activated.swap(false, Ordering::SeqCst) {
                let mut device = self.device.lock().unwrap();
                device.reset();
            }

            // Reset queue readiness and the common configuration
            self.queues.iter_mut().for_each(Queue::reset);
            self.common_config.reset();
        }

        None
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn id(&self) -> Option<String> {
        Some(self.id.clone())
    }
}

impl BusDevice for VirtioPciDevice {
    fn read(&mut self, base: u64, offset: u64, data: &mut [u8]) {
        self.read_bar(base, offset, data);
    }

    fn write(&mut self, base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        self.write_bar(base, offset, data)
    }
}

impl Pausable for VirtioPciDevice {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        Ok(())
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        Ok(())
    }
}

impl Snapshottable for VirtioPciDevice {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> result::Result<Snapshot, MigratableError> {
        let mut virtio_pci_dev_snapshot = Snapshot::new_from_state(&self.state())?;

        // Snapshot PciConfiguration
        virtio_pci_dev_snapshot
            .add_snapshot(self.configuration.id(), self.configuration.snapshot()?);

        // Snapshot VirtioPciCommonConfig
        virtio_pci_dev_snapshot
            .add_snapshot(self.common_config.id(), self.common_config.snapshot()?);

        // Snapshot MSI-X
        {
            let mut msix_config = self.msix_config.lock().unwrap();
            virtio_pci_dev_snapshot.add_snapshot(msix_config.id(), msix_config.snapshot()?);
        }

        Ok(virtio_pci_dev_snapshot)
    }
}
impl Transportable for VirtioPciDevice {}
impl Migratable for VirtioPciDevice {}

#[cfg(test)]
mod unit_tests {
    use std::thread;

    use vm_device::interrupt::InterruptSourceConfig;

    use super::*;
    use crate::{ActivateError, DEVICE_NEEDS_RESET};

    struct TestInterruptSourceGroup {
        event_fd: EventFd,
    }

    impl InterruptSourceGroup for TestInterruptSourceGroup {
        fn trigger(&self, _index: InterruptIndex) -> io::Result<()> {
            self.event_fd.write(1)
        }
        fn notifier(&self, _index: InterruptIndex) -> Option<EventFd> {
            Some(self.event_fd.try_clone().unwrap())
        }
        fn update(
            &self,
            _index: InterruptIndex,
            _config: InterruptSourceConfig,
            _masked: bool,
            _set_gsi: bool,
        ) -> io::Result<()> {
            Ok(())
        }
        fn set_gsi(&self) -> io::Result<()> {
            Ok(())
        }
    }

    fn make_msix_interrupt(num_vectors: u16) -> VirtioInterruptMsix {
        let isg = Arc::new(TestInterruptSourceGroup {
            event_fd: EventFd::new(0).unwrap(),
        });
        let msix_config = Arc::new(Mutex::new(
            MsixConfig::new(
                num_vectors,
                MaybeMutInterruptSourceGroup::Immutable(isg.clone()),
                0,
                None,
            )
            .unwrap(),
        ));
        let config_vector = Arc::new(AtomicU16::new(VIRTQ_MSI_NO_VECTOR));
        let config_changed = Arc::new(AtomicBool::new(false));
        let queues_vectors = Arc::new(Mutex::new(vec![VIRTQ_MSI_NO_VECTOR; 1]));

        VirtioInterruptMsix::new(
            msix_config,
            config_vector,
            config_changed,
            queues_vectors,
            MaybeMutInterruptSourceGroup::Immutable(isg),
        )
    }

    #[test]
    fn trigger_with_oob_vector_does_not_panic() {
        let intr = make_msix_interrupt(2);
        intr.queues_vectors.lock().unwrap()[0] = 0xFFFE;
        intr.trigger(VirtioInterruptType::Queue(0)).unwrap();
    }

    #[test]
    fn trigger_with_no_vector_returns_ok() {
        let intr = make_msix_interrupt(2);
        intr.trigger(VirtioInterruptType::Queue(0)).unwrap();
    }

    #[test]
    fn notifier_with_oob_vector_returns_none() {
        let intr = make_msix_interrupt(2);
        intr.queues_vectors.lock().unwrap()[0] = 0xFFFE;
        assert!(intr.notifier(VirtioInterruptType::Queue(0)).is_none());
    }

    #[test]
    fn trigger_with_valid_vector_fires() {
        let intr = make_msix_interrupt(2);
        intr.queues_vectors.lock().unwrap()[0] = 0;
        intr.msix_config.lock().unwrap().set_msg_ctl(1u16 << 15);
        intr.trigger(VirtioInterruptType::Queue(0)).unwrap();
    }

    #[test]
    fn config_vector_oob_does_not_panic() {
        let intr = make_msix_interrupt(2);
        intr.config_vector.store(0xFFFE, Ordering::Release);
        intr.trigger(VirtioInterruptType::Config).unwrap();
    }

    #[test]
    fn trigger_config_sets_config_changed_flag() {
        let intr = make_msix_interrupt(2);
        assert!(!intr.config_changed.load(Ordering::Acquire));
        intr.trigger(VirtioInterruptType::Config).unwrap();
        assert!(intr.config_changed.load(Ordering::Acquire));
    }

    #[test]
    fn trigger_queue_does_not_set_config_changed_flag() {
        let intr = make_msix_interrupt(2);
        intr.trigger(VirtioInterruptType::Queue(0)).unwrap();
        assert!(!intr.config_changed.load(Ordering::Acquire));
    }

    #[test]
    fn pci_cfg_cap_len_includes_data_window() {
        let cap = VirtioPciCfgCap::new();
        let expected = (size_of::<VirtioPciCfgCap>() as u8) + VIRTIO_PCI_CAP_LEN_OFFSET;
        assert_eq!(cap.cap.cap_len, expected);
        assert_eq!(cap.cap.cap_len, 20);
    }

    #[test]
    fn pci_cfg_cap_cfg_type_is_pci() {
        let cap = VirtioPciCfgCap::new();
        assert_eq!(cap.cap.cfg_type, PciCapabilityType::Pci as u8);
        assert_eq!(cap.cap.cfg_type, 5);
    }

    #[test]
    fn compound_caps_size_cap_len_from_own_type() {
        let notify = VirtioPciNotifyCap::new(PciCapabilityType::Notify, 0, 0, 0, Le32::from(0));
        assert_eq!(
            notify.cap.cap_len,
            (size_of::<VirtioPciNotifyCap>() as u8) + VIRTIO_PCI_CAP_LEN_OFFSET
        );

        let cap64 = VirtioPciCap64::new(PciCapabilityType::SharedMemory, 0, 0, 0, 0);
        assert_eq!(
            cap64.cap.cap_len,
            (size_of::<VirtioPciCap64>() as u8) + VIRTIO_PCI_CAP_LEN_OFFSET
        );
    }

    #[test]
    fn bar_access_params_clamps_to_cap_length() {
        let mut cap = VirtioPciCfgCap::new();
        let slice = cap.as_mut_slice();

        // Program cap.offset = 0x14, cap.length = 1 (byte access)
        slice[6..10].copy_from_slice(&0x14u32.to_le_bytes());
        slice[10..14].copy_from_slice(&1u32.to_le_bytes());

        // PCI config reads always produce 4 bytes, but cap.length = 1
        let (bar_offset, access_len) = cap.bar_access_params(4);
        assert_eq!(bar_offset, 0x14);
        assert_eq!(access_len, 1);
    }

    #[test]
    fn bar_access_params_uses_data_len_when_smaller() {
        let mut cap = VirtioPciCfgCap::new();
        let slice = cap.as_mut_slice();

        // cap.length = 4, but caller provides only 2 bytes
        slice[6..10].copy_from_slice(&0x00u32.to_le_bytes());
        slice[10..14].copy_from_slice(&4u32.to_le_bytes());

        let (bar_offset, access_len) = cap.bar_access_params(2);
        assert_eq!(bar_offset, 0);
        assert_eq!(access_len, 2);
    }

    struct TestVirtioDevice {
        result: Mutex<Option<ActivateResult>>,
    }

    impl VirtioDevice for TestVirtioDevice {
        fn device_type(&self) -> u32 {
            0
        }
        fn queue_max_sizes(&self) -> &[u16] {
            &[]
        }
        fn activate(&mut self, _context: ActivationContext) -> ActivateResult {
            self.result.lock().unwrap().take().unwrap()
        }
    }

    struct TestVirtioInterrupt {
        triggers: Mutex<Vec<VirtioInterruptType>>,
    }

    impl VirtioInterrupt for TestVirtioInterrupt {
        fn trigger(&self, int_type: VirtioInterruptType) -> io::Result<()> {
            self.triggers.lock().unwrap().push(int_type);
            Ok(())
        }
        fn set_notifier(
            &self,
            _int_type: u32,
            _notifier: Option<EventFd>,
            _vm: &dyn hypervisor::Vm,
        ) -> io::Result<()> {
            Ok(())
        }
    }

    fn make_activator(
        result: ActivateResult,
    ) -> (
        VirtioPciDeviceActivator,
        Arc<AtomicU8>,
        Arc<AtomicBool>,
        Arc<TestVirtioInterrupt>,
        Arc<Barrier>,
    ) {
        let interrupt = Arc::new(TestVirtioInterrupt {
            triggers: Mutex::new(Vec::new()),
        });
        let status = Arc::new(AtomicU8::new(DEVICE_DRIVER_OK as u8));
        let device_activated = Arc::new(AtomicBool::new(false));
        let device = Arc::new(Mutex::new(TestVirtioDevice {
            result: Mutex::new(Some(result)),
        }));
        let memory = GuestMemoryAtomic::new(
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );
        let barrier = Arc::new(Barrier::new(2));
        let activator = VirtioPciDeviceActivator {
            interrupt: interrupt.clone(),
            memory: Some(memory),
            device,
            device_activated: device_activated.clone(),
            queues: Some(Vec::new()),
            barrier: Some(barrier.clone()),
            id: "test-dev".to_string(),
            status: status.clone(),
        };
        (activator, status, device_activated, interrupt, barrier)
    }

    #[test]
    fn activate_failure_marks_needs_reset_and_releases_barrier() {
        let (activator, status, device_activated, interrupt, barrier) =
            make_activator(Err(ActivateError::BadActivate));

        // Simulate the vCPU thread blocked on the activation
        // barrier after writing DRIVER_OK.
        let waiter = thread::spawn(move || barrier.wait());

        let result = activator.activate();

        assert!(matches!(result, Err(ActivateError::BadActivate)));
        assert!(!device_activated.load(Ordering::SeqCst));
        assert_ne!(
            status.load(Ordering::SeqCst) & (DEVICE_NEEDS_RESET as u8),
            0
        );
        let triggers = interrupt.triggers.lock().unwrap();
        assert_eq!(triggers.len(), 1);
        assert!(matches!(triggers[0], VirtioInterruptType::Config));

        // The barrier waiter must complete, showing the activator
        // did not deadlock the vCPU thread.
        waiter.join().expect("barrier waiter deadlocked");
    }

    #[test]
    fn activate_success_sets_activated_and_does_not_signal_reset() {
        let (activator, status, device_activated, interrupt, barrier) = make_activator(Ok(()));
        let initial_status = status.load(Ordering::SeqCst);

        let waiter = thread::spawn(move || barrier.wait());

        let result = activator.activate();

        result.unwrap();
        assert!(device_activated.load(Ordering::SeqCst));
        assert_eq!(
            status.load(Ordering::SeqCst) & (DEVICE_NEEDS_RESET as u8),
            0
        );
        assert_eq!(status.load(Ordering::SeqCst), initial_status);
        assert!(interrupt.triggers.lock().unwrap().is_empty());

        waiter.join().expect("barrier waiter deadlocked");
    }

    struct TestInterruptManager;

    impl InterruptManager for TestInterruptManager {
        type GroupConfig = MsiIrqGroupConfig;

        fn create_group(
            &self,
            _config: Self::GroupConfig,
        ) -> io::Result<Arc<dyn InterruptSourceGroup>> {
            Ok(Arc::new(TestInterruptSourceGroup {
                event_fd: EventFd::new(0).unwrap(),
            }))
        }

        fn destroy_group(&self, _group: Arc<dyn InterruptSourceGroup>) -> io::Result<()> {
            Ok(())
        }
    }

    fn make_virtio_pci_device() -> VirtioPciDevice {
        let memory = GuestMemoryAtomic::new(
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );
        let device = Arc::new(Mutex::new(TestVirtioDevice {
            result: Mutex::new(None),
        }));
        VirtioPciDevice::new(
            "test-dev".to_string(),
            memory,
            device,
            None,
            &TestInterruptManager,
            0,
            EventFd::new(EFD_NONBLOCK).unwrap(),
            false,
            None,
            Arc::new(Mutex::new(Vec::new())),
            None,
        )
        .unwrap()
    }

    fn has_device_config_cap(cfg: &PciConfiguration) -> bool {
        let mut ptr = (cfg.read_reg(0x34 / 4) & 0xFF) as usize;
        while ptr != 0 {
            let dword = cfg.read_reg(ptr / 4);
            if dword & 0xFF == 0x09 && (dword >> 24) & 0xFF == PciCapabilityType::Device as u32 {
                return true;
            }
            ptr = ((dword >> 8) & 0xFF) as usize;
        }
        false
    }

    #[test]
    fn add_pci_capabilities_includes_device_config_when_sized() {
        let mut dev = make_virtio_pci_device();
        dev.add_pci_capabilities(DEVICE_CONFIG_SIZE).unwrap();
        assert!(has_device_config_cap(&dev.configuration));
    }

    #[test]
    fn add_pci_capabilities_omits_device_config_when_zero() {
        let mut dev = make_virtio_pci_device();
        dev.add_pci_capabilities(0).unwrap();
        assert!(!has_device_config_cap(&dev.configuration));
    }

    struct QueuedTestDevice {
        queue_sizes: Vec<u16>,
    }

    impl VirtioDevice for QueuedTestDevice {
        fn device_type(&self) -> u32 {
            0
        }
        fn queue_max_sizes(&self) -> &[u16] {
            &self.queue_sizes
        }
        fn activate(&mut self, _context: ActivationContext) -> ActivateResult {
            Ok(())
        }
    }

    fn make_virtio_pci_device_with_queues(num_queues: usize) -> VirtioPciDevice {
        let memory = GuestMemoryAtomic::new(
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );
        let device = Arc::new(Mutex::new(QueuedTestDevice {
            queue_sizes: vec![256; num_queues],
        }));
        VirtioPciDevice::new(
            "test-dev".to_string(),
            memory,
            device,
            None,
            &TestInterruptManager,
            0,
            EventFd::new(EFD_NONBLOCK).unwrap(),
            false,
            None,
            Arc::new(Mutex::new(Vec::new())),
            None,
        )
        .unwrap()
    }

    // A doorbell that reaches write_bar (e.g. delivered through the
    // VIRTIO_PCI_CAP_PCI_CFG window rather than a mapped BAR) must signal the
    // matching queue eventfd, not be dropped.
    #[test]
    fn notification_write_bar_signals_matching_queue_eventfd() {
        let mut dev = make_virtio_pci_device_with_queues(2);

        // Ring queue 1's doorbell the way write_cap_pci_cfg() would:
        // write_bar(0, notify_offset, ..).
        let offset = NOTIFICATION_BAR_OFFSET + u64::from(NOTIFY_OFF_MULTIPLIER);
        dev.write_bar(0, offset, &[0u8, 0u8]);

        // Queue 1 got exactly one notification; queue 0 was untouched (its
        // non-blocking eventfd read returns an error).
        assert_eq!(dev.queue_evts()[1].read().unwrap(), 1);
        dev.queue_evts()[0].read().unwrap_err();
    }

    // Each notify offset must map to its own queue, so a doorbell for queue 0
    // never wakes queue 1 and vice versa.
    #[test]
    fn notification_write_bar_targets_only_the_addressed_queue() {
        let mut dev = make_virtio_pci_device_with_queues(2);

        dev.write_bar(0, NOTIFICATION_BAR_OFFSET, &[0u8, 0u8]);

        assert_eq!(dev.queue_evts()[0].read().unwrap(), 1);
        dev.queue_evts()[1].read().unwrap_err();
    }
}
