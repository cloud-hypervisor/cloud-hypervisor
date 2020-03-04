// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
//

extern crate vm_device;

use crate::config::ConsoleOutputMode;
#[cfg(feature = "pci_support")]
use crate::config::DeviceConfig;
use crate::config::{DiskConfig, NetConfig, VmConfig};
use crate::interrupt::{
    KvmLegacyUserspaceInterruptManager, KvmMsiInterruptManager, KvmRoutingEntry,
};
use crate::memory_manager::{Error as MemoryManagerError, MemoryManager};
#[cfg(feature = "acpi")]
use acpi_tables::{aml, aml::Aml};
#[cfg(feature = "acpi")]
use arch::layout;
use arch::layout::{APIC_START, IOAPIC_SIZE, IOAPIC_START};
use devices::{ioapic, BusDevice, HotPlugNotificationFlags};
use kvm_ioctls::*;
use libc::O_TMPFILE;
use libc::TIOCGWINSZ;
#[cfg(feature = "pci_support")]
use pci::{
    DeviceRelocation, PciBarRegionType, PciBus, PciConfigIo, PciConfigMmio, PciDevice, PciRoot,
};
use qcow::{self, ImageType, QcowFile};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, sink, stdout};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::result;
use std::sync::Weak;
use std::sync::{Arc, Mutex};
use tempfile::NamedTempFile;
#[cfg(feature = "pci_support")]
use vfio::{VfioDevice, VfioDmaMapping, VfioPciDevice, VfioPciError};
use vm_allocator::SystemAllocator;
use vm_device::interrupt::{
    InterruptIndex, InterruptManager, LegacyIrqGroupConfig, MsiIrqGroupConfig,
};
use vm_device::{Migratable, MigratableError, Pausable, Snapshotable};
use vm_memory::guest_memory::FileOffset;
#[cfg(feature = "cmos")]
use vm_memory::GuestAddressSpace;
use vm_memory::{Address, GuestAddress, GuestUsize, MmapRegion};
#[cfg(feature = "pci_support")]
use vm_virtio::transport::VirtioPciDevice;
use vm_virtio::transport::VirtioTransport;
use vm_virtio::vhost_user::VhostUserConfig;
#[cfg(feature = "pci_support")]
use vm_virtio::{DmaRemapping, IommuMapping, VirtioIommuRemapping};
use vm_virtio::{VirtioSharedMemory, VirtioSharedMemoryList};
use vmm_sys_util::eventfd::EventFd;

#[cfg(feature = "mmio_support")]
const MMIO_LEN: u64 = 0x1000;

/// Errors associated with device manager
#[derive(Debug)]
pub enum DeviceManagerError {
    /// Cannot create EventFd.
    EventFd(io::Error),

    /// Cannot open disk path
    Disk(io::Error),

    /// Cannot create vhost-user-net device
    CreateVhostUserNet(vm_virtio::vhost_user::Error),

    /// Cannot create virtio-blk device
    CreateVirtioBlock(io::Error),

    /// Cannot create virtio-net device
    CreateVirtioNet(vm_virtio::net::Error),

    /// Cannot create virtio-console device
    CreateVirtioConsole(io::Error),

    /// Cannot create virtio-rng device
    CreateVirtioRng(io::Error),

    /// Cannot create virtio-fs device
    CreateVirtioFs(vm_virtio::vhost_user::Error),

    /// Cannot create vhost-user-blk device
    CreateVhostUserBlk(vm_virtio::vhost_user::Error),

    /// Cannot create virtio-pmem device
    CreateVirtioPmem(io::Error),

    /// Cannot create virtio-vsock device
    CreateVirtioVsock(io::Error),

    /// Failed converting Path to &str for the virtio-vsock device.
    CreateVsockConvertPath,

    /// Cannot create virtio-vsock backend
    CreateVsockBackend(vm_virtio::vsock::VsockUnixError),

    /// Cannot create virtio-iommu device
    CreateVirtioIommu(io::Error),

    /// Failed parsing disk image format
    DetectImageType(qcow::Error),

    /// Cannot open qcow disk path
    QcowDeviceCreate(qcow::Error),

    /// Cannot open tap interface
    OpenTap(net_util::TapError),

    /// Cannot allocate IRQ.
    AllocateIrq,

    /// Cannot configure the IRQ.
    Irq(kvm_ioctls::Error),

    /// Cannot allocate PCI BARs
    #[cfg(feature = "pci_support")]
    AllocateBars(pci::PciDeviceError),

    /// Cannot register ioevent.
    RegisterIoevent(kvm_ioctls::Error),

    /// Cannot create virtio device
    VirtioDevice(vmm_sys_util::errno::Error),

    /// Cannot add PCI device
    #[cfg(feature = "pci_support")]
    AddPciDevice(pci::PciRootError),

    /// Cannot open persistent memory file
    PmemFileOpen(io::Error),

    /// Cannot set persistent memory file size
    PmemFileSetLen(io::Error),

    /// Cannot find a memory range for persistent memory
    PmemRangeAllocation,

    /// Cannot find a memory range for virtio-fs
    FsRangeAllocation,

    /// Error creating serial output file
    SerialOutputFileOpen(io::Error),

    /// Error creating console output file
    ConsoleOutputFileOpen(io::Error),

    /// Cannot create a VFIO device
    #[cfg(feature = "pci_support")]
    VfioCreate(vfio::VfioError),

    /// Cannot create a VFIO PCI device
    #[cfg(feature = "pci_support")]
    VfioPciCreate(vfio::VfioPciError),

    /// Failed to map VFIO MMIO region.
    #[cfg(feature = "pci_support")]
    VfioMapRegion(VfioPciError),

    /// Failed to create the KVM device.
    CreateKvmDevice(kvm_ioctls::Error),

    /// Failed to memory map.
    Mmap(io::Error),

    /// Cannot add legacy device to Bus.
    BusError(devices::BusError),

    /// Failed to allocate IO port
    AllocateIOPort,

    // Failed to make hotplug notification
    HotPlugNotification(io::Error),

    // Error from a memory manager operation
    MemoryManager(MemoryManagerError),

    /// Failed to create new interrupt source group.
    CreateInterruptGroup(io::Error),

    /// Failed to update interrupt source group.
    UpdateInterruptGroup(io::Error),

    /// Failed creating IOAPIC.
    CreateIoapic(ioapic::Error),

    /// Failed creating a new MmapRegion instance.
    NewMmapRegion(vm_memory::mmap::MmapRegionError),

    /// Failed cloning a File.
    CloneFile(io::Error),

    /// Failed to create socket file
    CreateSocketFile(io::Error),

    /// Failed to spawn the network backend
    SpawnNetBackend(io::Error),

    /// Failed to spawn the block backend
    SpawnBlockBackend(io::Error),

    /// Missing PCI bus.
    NoPciBus,
}
pub type DeviceManagerResult<T> = result::Result<T, DeviceManagerError>;

type VirtioDeviceArc = Arc<Mutex<dyn vm_virtio::VirtioDevice>>;

pub fn get_win_size() -> (u16, u16) {
    #[repr(C)]
    struct WS {
        rows: u16,
        cols: u16,
    };
    let ws: WS = WS {
        rows: 0u16,
        cols: 0u16,
    };
    unsafe {
        libc::ioctl(0, TIOCGWINSZ, &ws);
    }

    (ws.cols, ws.rows)
}

#[derive(Default)]
pub struct Console {
    // Serial port on 0x3f8
    serial: Option<Arc<Mutex<devices::legacy::Serial>>>,
    console_input: Option<Arc<vm_virtio::ConsoleInput>>,
    input_enabled: bool,
}

impl Console {
    pub fn queue_input_bytes(&self, out: &[u8]) -> vmm_sys_util::errno::Result<()> {
        if self.serial.is_some() {
            self.serial
                .as_ref()
                .unwrap()
                .lock()
                .expect("Failed to process stdin event due to poisoned lock")
                .queue_input_bytes(out)?;
        }

        if self.console_input.is_some() {
            self.console_input.as_ref().unwrap().queue_input_bytes(out);
        }

        Ok(())
    }

    pub fn update_console_size(&self, cols: u16, rows: u16) {
        if self.console_input.is_some() {
            self.console_input
                .as_ref()
                .unwrap()
                .update_console_size(cols, rows)
        }
    }

    pub fn input_enabled(&self) -> bool {
        self.input_enabled
    }
}

struct AddressManager {
    allocator: Arc<Mutex<SystemAllocator>>,
    io_bus: Weak<devices::Bus>,
    mmio_bus: Arc<devices::Bus>,
    vm_fd: Arc<VmFd>,
}

#[cfg(feature = "pci_support")]
impl DeviceRelocation for AddressManager {
    fn move_bar(
        &self,
        old_base: u64,
        new_base: u64,
        len: u64,
        pci_dev: &mut dyn PciDevice,
        region_type: PciBarRegionType,
    ) -> std::result::Result<(), std::io::Error> {
        match region_type {
            PciBarRegionType::IORegion => {
                // Update system allocator
                self.allocator
                    .lock()
                    .unwrap()
                    .free_io_addresses(GuestAddress(old_base), len as GuestUsize);

                self.allocator
                    .lock()
                    .unwrap()
                    .allocate_io_addresses(Some(GuestAddress(new_base)), len as GuestUsize, None)
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::Other, "failed allocating new IO range")
                    })?;

                // Update PIO bus
                self.io_bus
                    .upgrade()
                    .unwrap()
                    .update_range(old_base, len, new_base, len)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            }
            PciBarRegionType::Memory32BitRegion | PciBarRegionType::Memory64BitRegion => {
                // Update system allocator
                self.allocator
                    .lock()
                    .unwrap()
                    .free_mmio_addresses(GuestAddress(old_base), len as GuestUsize);

                if region_type == PciBarRegionType::Memory32BitRegion {
                    self.allocator
                        .lock()
                        .unwrap()
                        .allocate_mmio_hole_addresses(
                            Some(GuestAddress(new_base)),
                            len as GuestUsize,
                            None,
                        )
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::Other,
                                "failed allocating new 32 bits MMIO range",
                            )
                        })?;
                } else {
                    self.allocator
                        .lock()
                        .unwrap()
                        .allocate_mmio_addresses(
                            Some(GuestAddress(new_base)),
                            len as GuestUsize,
                            None,
                        )
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::Other,
                                "failed allocating new 64 bits MMIO range",
                            )
                        })?;
                }

                // Update MMIO bus
                self.mmio_bus
                    .update_range(old_base, len, new_base, len)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            }
        }

        let any_dev = pci_dev.as_any();
        if let Some(virtio_pci_dev) = any_dev.downcast_ref::<VirtioPciDevice>() {
            let bar_addr = virtio_pci_dev.config_bar_addr();
            if bar_addr == new_base {
                for (event, addr) in virtio_pci_dev.ioeventfds(old_base) {
                    let io_addr = IoEventAddress::Mmio(addr);
                    self.vm_fd
                        .unregister_ioevent(event, &io_addr)
                        .map_err(|e| io::Error::from_raw_os_error(e.errno()))?;
                }
                for (event, addr) in virtio_pci_dev.ioeventfds(new_base) {
                    let io_addr = IoEventAddress::Mmio(addr);
                    self.vm_fd
                        .register_ioevent(event, &io_addr, NoDatamatch)
                        .map_err(|e| io::Error::from_raw_os_error(e.errno()))?;
                }
            }
        }

        pci_dev.move_bar(old_base, new_base)
    }
}

struct ActivatedBackend {
    _socket_file: tempfile::NamedTempFile,
    child: std::process::Child,
}

impl Drop for ActivatedBackend {
    fn drop(&mut self) {
        self.child.wait().ok();
    }
}

pub struct DeviceManager {
    // Manage address space related to devices
    address_manager: Arc<AddressManager>,

    // Console abstraction
    console: Arc<Console>,

    // IOAPIC
    ioapic: Option<Arc<Mutex<ioapic::Ioapic>>>,

    // List of mmap()ed regions managed through MmapRegion instances.
    // Using MmapRegion will perform the unmapping automatically when
    // the instance is dropped, which happens when the DeviceManager
    // gets dropped.
    _mmap_regions: Vec<MmapRegion>,

    // Things to be added to the commandline (i.e. for virtio-mmio)
    cmdline_additions: Vec<String>,

    // ACPI GED notification device
    #[cfg(feature = "acpi")]
    ged_notification_device: Option<Arc<Mutex<devices::AcpiGEDDevice>>>,

    // VM configuration
    config: Arc<Mutex<VmConfig>>,

    // Migratable devices
    migratable_devices: Vec<Arc<Mutex<dyn Migratable>>>,

    // Memory Manager
    memory_manager: Arc<Mutex<MemoryManager>>,

    // The virtio devices on the system
    virtio_devices: Vec<(VirtioDeviceArc, bool)>,

    // The path to the VMM for self spawning
    vmm_path: PathBuf,

    // Backends that have been spawned
    vhost_user_backends: Vec<ActivatedBackend>,

    // Keep a reference to the PCI bus
    #[cfg(feature = "pci_support")]
    pci_bus: Option<Arc<Mutex<PciBus>>>,

    // MSI Interrupt Manager
    #[cfg(feature = "pci_support")]
    msi_interrupt_manager: Arc<dyn InterruptManager<GroupConfig = MsiIrqGroupConfig>>,

    // VFIO KVM device
    #[cfg(feature = "pci_support")]
    kvm_device_fd: Option<Arc<DeviceFd>>,

    // Paravirtualized IOMMU
    #[cfg(feature = "pci_support")]
    iommu_device: Option<Arc<Mutex<vm_virtio::Iommu>>>,

    // Bitmap of PCI devices to hotplug.
    #[cfg(feature = "pci_support")]
    pci_devices_up: u32,

    // Bitmap of PCI devices to hotunplug.
    #[cfg(feature = "pci_support")]
    pci_devices_down: u32,
}

impl DeviceManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vm_fd: Arc<VmFd>,
        config: Arc<Mutex<VmConfig>>,
        allocator: Arc<Mutex<SystemAllocator>>,
        memory_manager: Arc<Mutex<MemoryManager>>,
        _exit_evt: &EventFd,
        reset_evt: &EventFd,
        vmm_path: PathBuf,
        io_bus: &Arc<devices::Bus>,
    ) -> DeviceManagerResult<Arc<Mutex<Self>>> {
        let mut virtio_devices: Vec<(Arc<Mutex<dyn vm_virtio::VirtioDevice>>, bool)> = Vec::new();
        let migratable_devices: Vec<Arc<Mutex<dyn Migratable>>> = Vec::new();
        let mut _mmap_regions = Vec::new();

        #[allow(unused_mut)]
        let mut cmdline_additions = Vec::new();

        let address_manager = Arc::new(AddressManager {
            allocator,
            io_bus: Arc::downgrade(io_bus),
            mmio_bus: Arc::new(devices::Bus::new()),
            vm_fd: vm_fd.clone(),
        });

        // Create a shared list of GSI that can be shared through all PCI
        // devices. This way, we can maintain the full list of used GSI,
        // preventing one device from overriding interrupts setting from
        // another one.
        let kvm_gsi_msi_routes: Arc<Mutex<HashMap<u32, KvmRoutingEntry>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // First we create the MSI interrupt manager, the legacy one is created
        // later, after the IOAPIC device creation.
        // The reason we create the MSI one first is because the IOAPIC needs it,
        // and then the legacy interrupt manager needs an IOAPIC. So we're
        // handling a linear dependency chain:
        // msi_interrupt_manager <- IOAPIC <- legacy_interrupt_manager.
        let msi_interrupt_manager: Arc<dyn InterruptManager<GroupConfig = MsiIrqGroupConfig>> =
            Arc::new(KvmMsiInterruptManager::new(
                Arc::clone(&address_manager.allocator),
                vm_fd,
                Arc::clone(&kvm_gsi_msi_routes),
            ));

        let ioapic =
            DeviceManager::add_ioapic(&address_manager, Arc::clone(&msi_interrupt_manager))?;

        // Now we can create the legacy interrupt manager, which needs the freshly
        // formed IOAPIC device.
        let legacy_interrupt_manager: Arc<
            dyn InterruptManager<GroupConfig = LegacyIrqGroupConfig>,
        > = Arc::new(KvmLegacyUserspaceInterruptManager::new(ioapic.clone()));

        #[cfg(feature = "acpi")]
        address_manager
            .allocator
            .lock()
            .unwrap()
            .allocate_io_addresses(Some(GuestAddress(0x0a00)), 0x18, None)
            .ok_or(DeviceManagerError::AllocateIOPort)?;

        #[cfg(feature = "acpi")]
        address_manager
            .io_bus
            .upgrade()
            .unwrap()
            .insert(memory_manager.clone(), 0xa00, 0x18)
            .map_err(DeviceManagerError::BusError)?;

        let mut device_manager = DeviceManager {
            address_manager: Arc::clone(&address_manager),
            console: Arc::new(Console::default()),
            ioapic: Some(ioapic),
            _mmap_regions,
            cmdline_additions,
            #[cfg(feature = "acpi")]
            ged_notification_device: None,
            config,
            migratable_devices,
            memory_manager,
            virtio_devices: Vec::new(),
            vmm_path,
            vhost_user_backends: Vec::new(),
            #[cfg(feature = "pci_support")]
            pci_bus: None,
            #[cfg(feature = "pci_support")]
            msi_interrupt_manager: Arc::clone(&msi_interrupt_manager),
            #[cfg(feature = "pci_support")]
            kvm_device_fd: None,
            #[cfg(feature = "pci_support")]
            iommu_device: None,
            #[cfg(feature = "pci_support")]
            pci_devices_up: 0,
            #[cfg(feature = "pci_support")]
            pci_devices_down: 0,
        };

        device_manager
            .add_legacy_devices(reset_evt.try_clone().map_err(DeviceManagerError::EventFd)?)?;

        #[cfg(feature = "acpi")]
        {
            device_manager.ged_notification_device = device_manager.add_acpi_devices(
                &legacy_interrupt_manager,
                reset_evt.try_clone().map_err(DeviceManagerError::EventFd)?,
                _exit_evt.try_clone().map_err(DeviceManagerError::EventFd)?,
            )?;
        }

        device_manager.console =
            device_manager.add_console_device(&legacy_interrupt_manager, &mut virtio_devices)?;

        #[cfg(any(feature = "pci_support", feature = "mmio_support"))]
        virtio_devices.append(&mut device_manager.make_virtio_devices()?);

        if cfg!(feature = "pci_support") {
            device_manager.add_pci_devices(virtio_devices.clone())?;
        } else if cfg!(feature = "mmio_support") {
            device_manager.add_mmio_devices(virtio_devices.clone(), &legacy_interrupt_manager)?;
        }

        device_manager.virtio_devices = virtio_devices;

        let device_manager = Arc::new(Mutex::new(device_manager));

        #[cfg(feature = "acpi")]
        address_manager
            .allocator
            .lock()
            .unwrap()
            .allocate_io_addresses(Some(GuestAddress(0xae00)), 0x10, None)
            .ok_or(DeviceManagerError::AllocateIOPort)?;

        #[cfg(feature = "acpi")]
        address_manager
            .io_bus
            .upgrade()
            .unwrap()
            .insert(
                Arc::clone(&device_manager) as Arc<Mutex<dyn BusDevice>>,
                0xae00,
                0x10,
            )
            .map_err(DeviceManagerError::BusError)?;

        Ok(device_manager)
    }

    #[allow(unused_variables)]
    fn add_pci_devices(
        &mut self,
        virtio_devices: Vec<(Arc<Mutex<dyn vm_virtio::VirtioDevice>>, bool)>,
    ) -> DeviceManagerResult<()> {
        #[cfg(feature = "pci_support")]
        {
            let pci_root = PciRoot::new(None);
            let mut pci_bus = PciBus::new(
                pci_root,
                Arc::downgrade(&self.address_manager) as Weak<dyn DeviceRelocation>,
            );

            let (iommu_device, iommu_mapping) = if self.config.lock().unwrap().iommu {
                let (device, mapping) =
                    vm_virtio::Iommu::new().map_err(DeviceManagerError::CreateVirtioIommu)?;
                let device = Arc::new(Mutex::new(device));
                self.iommu_device = Some(Arc::clone(&device));
                (Some(device), Some(mapping))
            } else {
                (None, None)
            };

            let interrupt_manager = Arc::clone(&self.msi_interrupt_manager);

            let mut iommu_attached_devices = Vec::new();

            for (device, iommu_attached) in virtio_devices {
                let mapping: &Option<Arc<IommuMapping>> = if iommu_attached {
                    &iommu_mapping
                } else {
                    &None
                };

                let virtio_iommu_attach_dev =
                    self.add_virtio_pci_device(device, &mut pci_bus, mapping, &interrupt_manager)?;

                if let Some(dev_id) = virtio_iommu_attach_dev {
                    iommu_attached_devices.push(dev_id);
                }
            }

            let mut vfio_iommu_device_ids =
                self.add_vfio_devices(&mut pci_bus, &interrupt_manager)?;

            iommu_attached_devices.append(&mut vfio_iommu_device_ids);

            if let Some(iommu_device) = iommu_device {
                iommu_device
                    .lock()
                    .unwrap()
                    .attach_pci_devices(0, iommu_attached_devices);

                // Because we determined the virtio-iommu b/d/f, we have to
                // add the device to the PCI topology now. Otherwise, the
                // b/d/f won't match the virtio-iommu device as expected.
                self.add_virtio_pci_device(iommu_device, &mut pci_bus, &None, &interrupt_manager)?;
            }

            let pci_bus = Arc::new(Mutex::new(pci_bus));
            let pci_config_io = Arc::new(Mutex::new(PciConfigIo::new(Arc::clone(&pci_bus))));
            self.address_manager
                .io_bus
                .upgrade()
                .unwrap()
                .insert(pci_config_io, 0xcf8, 0x8)
                .map_err(DeviceManagerError::BusError)?;
            let pci_config_mmio = Arc::new(Mutex::new(PciConfigMmio::new(Arc::clone(&pci_bus))));
            self.address_manager
                .mmio_bus
                .insert(
                    pci_config_mmio,
                    arch::layout::PCI_MMCONFIG_START.0,
                    arch::layout::PCI_MMCONFIG_SIZE,
                )
                .map_err(DeviceManagerError::BusError)?;

            self.pci_bus = Some(pci_bus);
        }

        Ok(())
    }

    #[allow(unused_variables, unused_mut)]
    fn add_mmio_devices(
        &mut self,
        virtio_devices: Vec<(Arc<Mutex<dyn vm_virtio::VirtioDevice>>, bool)>,
        interrupt_manager: &Arc<dyn InterruptManager<GroupConfig = LegacyIrqGroupConfig>>,
    ) -> DeviceManagerResult<()> {
        #[cfg(feature = "mmio_support")]
        {
            for (device, _) in virtio_devices {
                let mmio_addr = self
                    .address_manager
                    .allocator
                    .lock()
                    .unwrap()
                    .allocate_mmio_addresses(None, MMIO_LEN, Some(MMIO_LEN));
                if let Some(addr) = mmio_addr {
                    self.add_virtio_mmio_device(device, interrupt_manager, addr)?;
                } else {
                    error!("Unable to allocate MMIO address!");
                }
            }
        }

        Ok(())
    }

    fn add_ioapic(
        address_manager: &Arc<AddressManager>,
        interrupt_manager: Arc<dyn InterruptManager<GroupConfig = MsiIrqGroupConfig>>,
    ) -> DeviceManagerResult<Arc<Mutex<ioapic::Ioapic>>> {
        // Create IOAPIC
        let ioapic = Arc::new(Mutex::new(
            ioapic::Ioapic::new(APIC_START, interrupt_manager)
                .map_err(DeviceManagerError::CreateIoapic)?,
        ));

        address_manager
            .mmio_bus
            .insert(ioapic.clone(), IOAPIC_START.0, IOAPIC_SIZE)
            .map_err(DeviceManagerError::BusError)?;

        Ok(ioapic)
    }

    #[cfg(feature = "acpi")]
    fn add_acpi_devices(
        &mut self,
        interrupt_manager: &Arc<dyn InterruptManager<GroupConfig = LegacyIrqGroupConfig>>,
        reset_evt: EventFd,
        exit_evt: EventFd,
    ) -> DeviceManagerResult<Option<Arc<Mutex<devices::AcpiGEDDevice>>>> {
        let acpi_device = Arc::new(Mutex::new(devices::AcpiShutdownDevice::new(
            exit_evt, reset_evt,
        )));

        self.address_manager
            .allocator
            .lock()
            .unwrap()
            .allocate_io_addresses(Some(GuestAddress(0x3c0)), 0x8, None)
            .ok_or(DeviceManagerError::AllocateIOPort)?;

        self.address_manager
            .io_bus
            .upgrade()
            .unwrap()
            .insert(acpi_device, 0x3c0, 0x4)
            .map_err(DeviceManagerError::BusError)?;

        let ged_irq = self
            .address_manager
            .allocator
            .lock()
            .unwrap()
            .allocate_irq()
            .unwrap();

        let interrupt_group = interrupt_manager
            .create_group(LegacyIrqGroupConfig {
                irq: ged_irq as InterruptIndex,
            })
            .map_err(DeviceManagerError::CreateInterruptGroup)?;

        let ged_device = Arc::new(Mutex::new(devices::AcpiGEDDevice::new(
            interrupt_group,
            ged_irq,
        )));

        self.address_manager
            .allocator
            .lock()
            .unwrap()
            .allocate_io_addresses(Some(GuestAddress(0xb000)), 0x1, None)
            .ok_or(DeviceManagerError::AllocateIOPort)?;

        self.address_manager
            .io_bus
            .upgrade()
            .unwrap()
            .insert(ged_device.clone(), 0xb000, 0x1)
            .map_err(DeviceManagerError::BusError)?;
        Ok(Some(ged_device))
    }

    fn add_legacy_devices(&mut self, reset_evt: EventFd) -> DeviceManagerResult<()> {
        // Add a shutdown device (i8042)
        let i8042 = Arc::new(Mutex::new(devices::legacy::I8042Device::new(reset_evt)));

        self.address_manager
            .io_bus
            .upgrade()
            .unwrap()
            .insert(i8042, 0x61, 0x4)
            .map_err(DeviceManagerError::BusError)?;
        #[cfg(feature = "cmos")]
        {
            // Add a CMOS emulated device
            use vm_memory::GuestMemory;
            let mem_size = self
                .memory_manager
                .lock()
                .unwrap()
                .guest_memory()
                .memory()
                .last_addr()
                .0
                + 1;
            let mem_below_4g = std::cmp::min(arch::layout::MEM_32BIT_RESERVED_START.0, mem_size);
            let mem_above_4g = mem_size.saturating_sub(arch::layout::RAM_64BIT_START.0);

            let cmos = Arc::new(Mutex::new(devices::legacy::Cmos::new(
                mem_below_4g,
                mem_above_4g,
            )));

            self.address_manager
                .io_bus
                .upgrade()
                .unwrap()
                .insert(cmos, 0x70, 0x2)
                .map_err(DeviceManagerError::BusError)?;
        }

        Ok(())
    }

    fn add_console_device(
        &mut self,
        interrupt_manager: &Arc<dyn InterruptManager<GroupConfig = LegacyIrqGroupConfig>>,
        virtio_devices: &mut Vec<(Arc<Mutex<dyn vm_virtio::VirtioDevice>>, bool)>,
    ) -> DeviceManagerResult<Arc<Console>> {
        let serial_config = self.config.lock().unwrap().serial.clone();
        let serial_writer: Option<Box<dyn io::Write + Send>> = match serial_config.mode {
            ConsoleOutputMode::File => Some(Box::new(
                File::create(serial_config.file.as_ref().unwrap())
                    .map_err(DeviceManagerError::SerialOutputFileOpen)?,
            )),
            ConsoleOutputMode::Tty => Some(Box::new(stdout())),
            ConsoleOutputMode::Off | ConsoleOutputMode::Null => None,
        };
        let serial = if serial_config.mode != ConsoleOutputMode::Off {
            // Serial is tied to IRQ #4
            let serial_irq = 4;

            let interrupt_group = interrupt_manager
                .create_group(LegacyIrqGroupConfig {
                    irq: serial_irq as InterruptIndex,
                })
                .map_err(DeviceManagerError::CreateInterruptGroup)?;

            let serial = Arc::new(Mutex::new(devices::legacy::Serial::new(
                interrupt_group,
                serial_writer,
            )));

            self.address_manager
                .allocator
                .lock()
                .unwrap()
                .allocate_io_addresses(Some(GuestAddress(0x3f8)), 0x8, None)
                .ok_or(DeviceManagerError::AllocateIOPort)?;

            self.address_manager
                .io_bus
                .upgrade()
                .unwrap()
                .insert(serial.clone(), 0x3f8, 0x8)
                .map_err(DeviceManagerError::BusError)?;

            Some(serial)
        } else {
            None
        };

        // Create serial and virtio-console
        let console_config = self.config.lock().unwrap().console.clone();
        let console_writer: Option<Box<dyn io::Write + Send + Sync>> = match console_config.mode {
            ConsoleOutputMode::File => Some(Box::new(
                File::create(console_config.file.as_ref().unwrap())
                    .map_err(DeviceManagerError::ConsoleOutputFileOpen)?,
            )),
            ConsoleOutputMode::Tty => Some(Box::new(stdout())),
            ConsoleOutputMode::Null => Some(Box::new(sink())),
            ConsoleOutputMode::Off => None,
        };
        let (col, row) = get_win_size();
        let console_input = if let Some(writer) = console_writer {
            let (virtio_console_device, console_input) =
                vm_virtio::Console::new(writer, col, row, console_config.iommu)
                    .map_err(DeviceManagerError::CreateVirtioConsole)?;
            virtio_devices.push((
                Arc::new(Mutex::new(virtio_console_device))
                    as Arc<Mutex<dyn vm_virtio::VirtioDevice>>,
                false,
            ));
            Some(console_input)
        } else {
            None
        };

        Ok(Arc::new(Console {
            serial,
            console_input,
            input_enabled: serial_config.mode.input_enabled()
                || console_config.mode.input_enabled(),
        }))
    }

    fn make_virtio_devices(&mut self) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool)>> {
        let mut devices: Vec<(Arc<Mutex<dyn vm_virtio::VirtioDevice>>, bool)> = Vec::new();

        // Create "standard" virtio devices (net/block/rng)
        devices.append(&mut self.make_virtio_block_devices()?);
        devices.append(&mut self.make_virtio_net_devices()?);
        devices.append(&mut self.make_virtio_rng_devices()?);

        // Add virtio-fs if required
        devices.append(&mut self.make_virtio_fs_devices()?);

        // Add virtio-pmem if required
        devices.append(&mut self.make_virtio_pmem_devices()?);

        // Add virtio-vsock if required
        devices.append(&mut self.make_virtio_vsock_devices()?);

        Ok(devices)
    }

    /// Launch block backend
    fn start_block_backend(&mut self, disk_cfg: &DiskConfig) -> DeviceManagerResult<String> {
        let _socket_file = NamedTempFile::new().map_err(DeviceManagerError::CreateSocketFile)?;
        let sock = _socket_file.path().to_str().unwrap().to_owned();

        let child = std::process::Command::new(&self.vmm_path)
            .args(&[
                "--block-backend",
                &format!(
                    "image={},sock={},num_queues={},queue_size={}",
                    disk_cfg.path.to_str().unwrap(),
                    &sock,
                    disk_cfg.num_queues,
                    disk_cfg.queue_size
                ),
            ])
            .spawn()
            .map_err(DeviceManagerError::SpawnBlockBackend)?;

        // The ActivatedBackend::drop() will automatically reap the child
        self.vhost_user_backends.push(ActivatedBackend {
            child,
            _socket_file,
        });

        Ok(sock)
    }

    fn make_virtio_block_devices(&mut self) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool)>> {
        let mut devices = Vec::new();

        let block_devices = self.config.lock().unwrap().disks.clone();
        if let Some(disk_list_cfg) = &block_devices {
            for disk_cfg in disk_list_cfg.iter() {
                if disk_cfg.vhost_user {
                    let sock = if let Some(sock) = disk_cfg.vhost_socket.clone() {
                        sock
                    } else {
                        self.start_block_backend(disk_cfg)?
                    };
                    let vu_cfg = VhostUserConfig {
                        sock,
                        num_queues: disk_cfg.num_queues,
                        queue_size: disk_cfg.queue_size,
                    };
                    let vhost_user_block_device = Arc::new(Mutex::new(
                        vm_virtio::vhost_user::Blk::new(disk_cfg.wce, vu_cfg)
                            .map_err(DeviceManagerError::CreateVhostUserBlk)?,
                    ));

                    devices.push((
                        Arc::clone(&vhost_user_block_device)
                            as Arc<Mutex<dyn vm_virtio::VirtioDevice>>,
                        false,
                    ));

                    self.migratable_devices
                        .push(Arc::clone(&vhost_user_block_device) as Arc<Mutex<dyn Migratable>>);
                } else {
                    let mut options = OpenOptions::new();
                    options.read(true);
                    options.write(!disk_cfg.readonly);
                    if disk_cfg.direct {
                        options.custom_flags(libc::O_DIRECT);
                    }
                    // Open block device path
                    let image: File = options
                        .open(&disk_cfg.path)
                        .map_err(DeviceManagerError::Disk)?;

                    let mut raw_img = vm_virtio::RawFile::new(image, disk_cfg.direct);

                    let image_type = qcow::detect_image_type(&mut raw_img)
                        .map_err(DeviceManagerError::DetectImageType)?;
                    match image_type {
                        ImageType::Raw => {
                            let dev = vm_virtio::Block::new(
                                raw_img,
                                disk_cfg.path.clone(),
                                disk_cfg.readonly,
                                disk_cfg.iommu,
                                disk_cfg.num_queues,
                                disk_cfg.queue_size,
                            )
                            .map_err(DeviceManagerError::CreateVirtioBlock)?;

                            let block = Arc::new(Mutex::new(dev));

                            devices.push((
                                Arc::clone(&block) as Arc<Mutex<dyn vm_virtio::VirtioDevice>>,
                                disk_cfg.iommu,
                            ));
                            self.migratable_devices
                                .push(Arc::clone(&block) as Arc<Mutex<dyn Migratable>>);
                        }
                        ImageType::Qcow2 => {
                            let qcow_img = QcowFile::from(raw_img)
                                .map_err(DeviceManagerError::QcowDeviceCreate)?;
                            let dev = vm_virtio::Block::new(
                                qcow_img,
                                disk_cfg.path.clone(),
                                disk_cfg.readonly,
                                disk_cfg.iommu,
                                disk_cfg.num_queues,
                                disk_cfg.queue_size,
                            )
                            .map_err(DeviceManagerError::CreateVirtioBlock)?;

                            let block = Arc::new(Mutex::new(dev));

                            devices.push((
                                Arc::clone(&block) as Arc<Mutex<dyn vm_virtio::VirtioDevice>>,
                                disk_cfg.iommu,
                            ));
                            self.migratable_devices
                                .push(Arc::clone(&block) as Arc<Mutex<dyn Migratable>>);
                        }
                    };
                }
            }
        }

        Ok(devices)
    }

    /// Launch network backend
    fn start_net_backend(&mut self, net_cfg: &NetConfig) -> DeviceManagerResult<String> {
        let _socket_file = NamedTempFile::new().map_err(DeviceManagerError::CreateSocketFile)?;
        let sock = _socket_file.path().to_str().unwrap().to_owned();

        let child = std::process::Command::new(&self.vmm_path)
            .args(&[
                "--net-backend",
                &format!(
                    "ip={},mask={},sock={},num_queues={},queue_size={}",
                    net_cfg.ip, net_cfg.mask, &sock, net_cfg.num_queues, net_cfg.queue_size
                ),
            ])
            .spawn()
            .map_err(DeviceManagerError::SpawnNetBackend)?;

        // The ActivatedBackend::drop() will automatically reap the child
        self.vhost_user_backends.push(ActivatedBackend {
            child,
            _socket_file,
        });

        Ok(sock)
    }

    /// Add virto-net and vhost-user-net devices
    fn make_virtio_net_devices(&mut self) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool)>> {
        let mut devices = Vec::new();
        let net_devices = self.config.lock().unwrap().net.clone();
        if let Some(net_list_cfg) = &net_devices {
            for net_cfg in net_list_cfg.iter() {
                if net_cfg.vhost_user {
                    let sock = if let Some(sock) = net_cfg.vhost_socket.clone() {
                        sock
                    } else {
                        self.start_net_backend(net_cfg)?
                    };
                    let vu_cfg = VhostUserConfig {
                        sock,
                        num_queues: net_cfg.num_queues,
                        queue_size: net_cfg.queue_size,
                    };
                    let vhost_user_net_device = Arc::new(Mutex::new(
                        vm_virtio::vhost_user::Net::new(net_cfg.mac, vu_cfg)
                            .map_err(DeviceManagerError::CreateVhostUserNet)?,
                    ));
                    devices.push((
                        Arc::clone(&vhost_user_net_device)
                            as Arc<Mutex<dyn vm_virtio::VirtioDevice>>,
                        net_cfg.iommu,
                    ));
                    self.migratable_devices
                        .push(Arc::clone(&vhost_user_net_device) as Arc<Mutex<dyn Migratable>>);
                } else {
                    let virtio_net_device = if let Some(ref tap_if_name) = net_cfg.tap {
                        Arc::new(Mutex::new(
                            vm_virtio::Net::new(
                                Some(tap_if_name),
                                None,
                                None,
                                Some(net_cfg.mac),
                                net_cfg.iommu,
                                net_cfg.num_queues,
                                net_cfg.queue_size,
                            )
                            .map_err(DeviceManagerError::CreateVirtioNet)?,
                        ))
                    } else {
                        Arc::new(Mutex::new(
                            vm_virtio::Net::new(
                                None,
                                Some(net_cfg.ip),
                                Some(net_cfg.mask),
                                Some(net_cfg.mac),
                                net_cfg.iommu,
                                net_cfg.num_queues,
                                net_cfg.queue_size,
                            )
                            .map_err(DeviceManagerError::CreateVirtioNet)?,
                        ))
                    };
                    devices.push((
                        Arc::clone(&virtio_net_device) as Arc<Mutex<dyn vm_virtio::VirtioDevice>>,
                        net_cfg.iommu,
                    ));
                    self.migratable_devices
                        .push(Arc::clone(&virtio_net_device) as Arc<Mutex<dyn Migratable>>);
                }
            }
        }

        Ok(devices)
    }

    fn make_virtio_rng_devices(&mut self) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool)>> {
        let mut devices = Vec::new();

        // Add virtio-rng if required
        let rng_config = self.config.lock().unwrap().rng.clone();
        if let Some(rng_path) = rng_config.src.to_str() {
            let virtio_rng_device = Arc::new(Mutex::new(
                vm_virtio::Rng::new(rng_path, rng_config.iommu)
                    .map_err(DeviceManagerError::CreateVirtioRng)?,
            ));
            devices.push((
                Arc::clone(&virtio_rng_device) as Arc<Mutex<dyn vm_virtio::VirtioDevice>>,
                false,
            ));

            self.migratable_devices
                .push(Arc::clone(&virtio_rng_device) as Arc<Mutex<dyn Migratable>>);
        }

        Ok(devices)
    }

    fn make_virtio_fs_devices(&mut self) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool)>> {
        let mut devices = Vec::new();
        // Add virtio-fs if required
        if let Some(fs_list_cfg) = &self.config.lock().unwrap().fs {
            for fs_cfg in fs_list_cfg.iter() {
                if let Some(fs_sock) = fs_cfg.sock.to_str() {
                    let cache: Option<(VirtioSharedMemoryList, u64)> = if fs_cfg.dax {
                        let fs_cache = fs_cfg.cache_size;
                        // The memory needs to be 2MiB aligned in order to support
                        // hugepages.
                        let fs_guest_addr = self
                            .address_manager
                            .allocator
                            .lock()
                            .unwrap()
                            .allocate_mmio_addresses(
                                None,
                                fs_cache as GuestUsize,
                                Some(0x0020_0000),
                            )
                            .ok_or(DeviceManagerError::FsRangeAllocation)?;

                        let mmap_region = MmapRegion::build(
                            None,
                            fs_cache as usize,
                            libc::PROT_NONE,
                            libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                        )
                        .map_err(DeviceManagerError::NewMmapRegion)?;
                        let addr: u64 = mmap_region.as_ptr() as u64;

                        self._mmap_regions.push(mmap_region);

                        self.memory_manager
                            .lock()
                            .unwrap()
                            .create_userspace_mapping(
                                fs_guest_addr.raw_value(),
                                fs_cache,
                                addr,
                                false,
                            )
                            .map_err(DeviceManagerError::MemoryManager)?;

                        let mut region_list = Vec::new();
                        region_list.push(VirtioSharedMemory {
                            offset: 0,
                            len: fs_cache,
                        });

                        Some((
                            VirtioSharedMemoryList {
                                addr: fs_guest_addr,
                                len: fs_cache as GuestUsize,
                                region_list,
                            },
                            addr,
                        ))
                    } else {
                        None
                    };

                    let virtio_fs_device = Arc::new(Mutex::new(
                        vm_virtio::vhost_user::Fs::new(
                            fs_sock,
                            &fs_cfg.tag,
                            fs_cfg.num_queues,
                            fs_cfg.queue_size,
                            cache,
                        )
                        .map_err(DeviceManagerError::CreateVirtioFs)?,
                    ));

                    devices.push((
                        Arc::clone(&virtio_fs_device) as Arc<Mutex<dyn vm_virtio::VirtioDevice>>,
                        false,
                    ));

                    self.migratable_devices
                        .push(Arc::clone(&virtio_fs_device) as Arc<Mutex<dyn Migratable>>);
                }
            }
        }

        Ok(devices)
    }

    fn make_virtio_pmem_devices(&mut self) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool)>> {
        let mut devices = Vec::new();
        // Add virtio-pmem if required
        if let Some(pmem_list_cfg) = &self.config.lock().unwrap().pmem {
            for pmem_cfg in pmem_list_cfg.iter() {
                let size = pmem_cfg.size;

                // The memory needs to be 2MiB aligned in order to support
                // hugepages.
                let pmem_guest_addr = self
                    .address_manager
                    .allocator
                    .lock()
                    .unwrap()
                    .allocate_mmio_addresses(None, size as GuestUsize, Some(0x0020_0000))
                    .ok_or(DeviceManagerError::PmemRangeAllocation)?;

                let (custom_flags, set_len) = if pmem_cfg.file.is_dir() {
                    (O_TMPFILE, true)
                } else {
                    (0, false)
                };

                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .custom_flags(custom_flags)
                    .open(&pmem_cfg.file)
                    .map_err(DeviceManagerError::PmemFileOpen)?;

                if set_len {
                    file.set_len(size)
                        .map_err(DeviceManagerError::PmemFileSetLen)?;
                }

                let cloned_file = file.try_clone().map_err(DeviceManagerError::CloneFile)?;
                let mmap_region =
                    MmapRegion::from_file(FileOffset::new(cloned_file, 0), size as usize)
                        .map_err(DeviceManagerError::NewMmapRegion)?;
                let addr: u64 = mmap_region.as_ptr() as u64;

                self._mmap_regions.push(mmap_region);

                self.memory_manager
                    .lock()
                    .unwrap()
                    .create_userspace_mapping(
                        pmem_guest_addr.raw_value(),
                        size,
                        addr,
                        pmem_cfg.mergeable,
                    )
                    .map_err(DeviceManagerError::MemoryManager)?;

                let virtio_pmem_device = Arc::new(Mutex::new(
                    vm_virtio::Pmem::new(file, pmem_guest_addr, size as GuestUsize, pmem_cfg.iommu)
                        .map_err(DeviceManagerError::CreateVirtioPmem)?,
                ));

                devices.push((
                    Arc::clone(&virtio_pmem_device) as Arc<Mutex<dyn vm_virtio::VirtioDevice>>,
                    false,
                ));

                self.migratable_devices
                    .push(Arc::clone(&virtio_pmem_device) as Arc<Mutex<dyn Migratable>>);
            }
        }

        Ok(devices)
    }

    fn make_virtio_vsock_devices(&mut self) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool)>> {
        let mut devices = Vec::new();
        // Add vsock if required
        if let Some(vsock_list_cfg) = &self.config.lock().unwrap().vsock {
            for vsock_cfg in vsock_list_cfg.iter() {
                let socket_path = vsock_cfg
                    .sock
                    .to_str()
                    .ok_or(DeviceManagerError::CreateVsockConvertPath)?;
                let backend =
                    vm_virtio::vsock::VsockUnixBackend::new(vsock_cfg.cid, socket_path.to_string())
                        .map_err(DeviceManagerError::CreateVsockBackend)?;

                let vsock_device = Arc::new(Mutex::new(
                    vm_virtio::Vsock::new(vsock_cfg.cid, backend, vsock_cfg.iommu)
                        .map_err(DeviceManagerError::CreateVirtioVsock)?,
                ));

                devices.push((
                    Arc::clone(&vsock_device) as Arc<Mutex<dyn vm_virtio::VirtioDevice>>,
                    false,
                ));

                self.migratable_devices
                    .push(Arc::clone(&vsock_device) as Arc<Mutex<dyn Migratable>>);
            }
        }

        Ok(devices)
    }

    #[cfg(feature = "pci_support")]
    fn create_kvm_device(vm: &Arc<VmFd>) -> DeviceManagerResult<DeviceFd> {
        let mut vfio_dev = kvm_bindings::kvm_create_device {
            type_: kvm_bindings::kvm_device_type_KVM_DEV_TYPE_VFIO,
            fd: 0,
            flags: 0,
        };

        vm.create_device(&mut vfio_dev)
            .map_err(DeviceManagerError::CreateKvmDevice)
    }

    #[cfg(feature = "pci_support")]
    fn add_vfio_device(
        &mut self,
        pci: &mut PciBus,
        interrupt_manager: &Arc<dyn InterruptManager<GroupConfig = MsiIrqGroupConfig>>,
        device_fd: &Arc<DeviceFd>,
        device_cfg: &DeviceConfig,
    ) -> DeviceManagerResult<u32> {
        // We need to shift the device id since the 3 first bits
        // are dedicated to the PCI function, and we know we don't
        // do multifunction. Also, because we only support one PCI
        // bus, the bus 0, we don't need to add anything to the
        // global device ID.
        let device_id = pci.next_device_id() << 3;

        let memory = self.memory_manager.lock().unwrap().guest_memory();
        let vfio_device = VfioDevice::new(
            &device_cfg.path,
            device_fd.clone(),
            memory.clone(),
            device_cfg.iommu,
        )
        .map_err(DeviceManagerError::VfioCreate)?;

        if device_cfg.iommu {
            if let Some(iommu) = &self.iommu_device {
                let vfio_mapping =
                    Arc::new(VfioDmaMapping::new(vfio_device.get_container(), memory));

                iommu
                    .lock()
                    .unwrap()
                    .add_external_mapping(device_id, vfio_mapping);
            }
        }

        let mut vfio_pci_device =
            VfioPciDevice::new(&self.address_manager.vm_fd, vfio_device, interrupt_manager)
                .map_err(DeviceManagerError::VfioPciCreate)?;

        let bars = vfio_pci_device
            .allocate_bars(&mut self.address_manager.allocator.lock().unwrap())
            .map_err(DeviceManagerError::AllocateBars)?;

        vfio_pci_device
            .map_mmio_regions(&self.address_manager.vm_fd, || {
                self.memory_manager
                    .lock()
                    .unwrap()
                    .allocate_kvm_memory_slot()
            })
            .map_err(DeviceManagerError::VfioMapRegion)?;

        let vfio_pci_device = Arc::new(Mutex::new(vfio_pci_device));

        pci.add_device(vfio_pci_device.clone())
            .map_err(DeviceManagerError::AddPciDevice)?;

        pci.register_mapping(
            vfio_pci_device,
            self.address_manager.io_bus.upgrade().unwrap().as_ref(),
            self.address_manager.mmio_bus.as_ref(),
            bars,
        )
        .map_err(DeviceManagerError::AddPciDevice)?;

        Ok(device_id)
    }

    #[cfg(feature = "pci_support")]
    fn add_vfio_devices(
        &mut self,
        pci: &mut PciBus,
        interrupt_manager: &Arc<dyn InterruptManager<GroupConfig = MsiIrqGroupConfig>>,
    ) -> DeviceManagerResult<Vec<u32>> {
        let mut iommu_attached_device_ids = Vec::new();
        let devices = self.config.lock().unwrap().devices.clone();

        if let Some(device_list_cfg) = &devices {
            // Create the KVM VFIO device
            let device_fd = DeviceManager::create_kvm_device(&self.address_manager.vm_fd)?;
            let device_fd = Arc::new(device_fd);
            self.kvm_device_fd = Some(Arc::clone(&device_fd));

            for device_cfg in device_list_cfg.iter() {
                let device_id =
                    self.add_vfio_device(pci, interrupt_manager, &device_fd, device_cfg)?;
                if self.iommu_device.is_some() {
                    iommu_attached_device_ids.push(device_id);
                }
            }
        }
        Ok(iommu_attached_device_ids)
    }

    #[cfg(feature = "pci_support")]
    fn add_virtio_pci_device(
        &mut self,
        virtio_device: Arc<Mutex<dyn vm_virtio::VirtioDevice>>,
        pci: &mut PciBus,
        iommu_mapping: &Option<Arc<IommuMapping>>,
        interrupt_manager: &Arc<dyn InterruptManager<GroupConfig = MsiIrqGroupConfig>>,
    ) -> DeviceManagerResult<Option<u32>> {
        // Allows support for one MSI-X vector per queue. It also adds 1
        // as we need to take into account the dedicated vector to notify
        // about a virtio config change.
        let msix_num = (virtio_device.lock().unwrap().queue_max_sizes().len() + 1) as u16;

        // We need to shift the device id since the 3 first bits are dedicated
        // to the PCI function, and we know we don't do multifunction.
        // Also, because we only support one PCI bus, the bus 0, we don't need
        // to add anything to the global device ID.
        let dev_id = pci.next_device_id() << 3;

        // Create the callback from the implementation of the DmaRemapping
        // trait. The point with the callback is to simplify the code as we
        // know about the device ID from this point.
        let iommu_mapping_cb: Option<Arc<VirtioIommuRemapping>> =
            if let Some(mapping) = iommu_mapping {
                let mapping_clone = mapping.clone();
                Some(Arc::new(Box::new(move |addr: u64| {
                    mapping_clone.translate(dev_id, addr).map_err(|e| {
                        std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!(
                                "failed to translate addr 0x{:x} for device 00:{:02x}.0 {}",
                                addr, dev_id, e
                            ),
                        )
                    })
                }) as VirtioIommuRemapping))
            } else {
                None
            };

        let memory = self.memory_manager.lock().unwrap().guest_memory();
        let mut virtio_pci_device = VirtioPciDevice::new(
            memory,
            virtio_device,
            msix_num,
            iommu_mapping_cb,
            interrupt_manager,
        )
        .map_err(DeviceManagerError::VirtioDevice)?;

        let mut allocator = self.address_manager.allocator.lock().unwrap();
        let bars = virtio_pci_device
            .allocate_bars(&mut allocator)
            .map_err(DeviceManagerError::AllocateBars)?;

        let bar_addr = virtio_pci_device.config_bar_addr();
        for (event, addr) in virtio_pci_device.ioeventfds(bar_addr) {
            let io_addr = IoEventAddress::Mmio(addr);
            self.address_manager
                .vm_fd
                .register_ioevent(event, &io_addr, NoDatamatch)
                .map_err(DeviceManagerError::RegisterIoevent)?;
        }

        let virtio_pci_device = Arc::new(Mutex::new(virtio_pci_device));

        pci.add_device(virtio_pci_device.clone())
            .map_err(DeviceManagerError::AddPciDevice)?;

        pci.register_mapping(
            virtio_pci_device.clone(),
            self.address_manager.io_bus.upgrade().unwrap().as_ref(),
            self.address_manager.mmio_bus.as_ref(),
            bars,
        )
        .map_err(DeviceManagerError::AddPciDevice)?;

        self.migratable_devices
            .push(Arc::clone(&virtio_pci_device) as Arc<Mutex<dyn Migratable>>);

        let ret = if iommu_mapping.is_some() {
            Some(dev_id)
        } else {
            None
        };

        Ok(ret)
    }

    #[cfg(feature = "mmio_support")]
    fn add_virtio_mmio_device(
        &mut self,
        virtio_device: Arc<Mutex<dyn vm_virtio::VirtioDevice>>,
        interrupt_manager: &Arc<dyn InterruptManager<GroupConfig = LegacyIrqGroupConfig>>,
        mmio_base: GuestAddress,
    ) -> DeviceManagerResult<()> {
        let memory = self.memory_manager.lock().unwrap().guest_memory();
        let mut mmio_device = vm_virtio::transport::MmioDevice::new(memory, virtio_device)
            .map_err(DeviceManagerError::VirtioDevice)?;

        for (i, (event, addr)) in mmio_device.ioeventfds(mmio_base.0).iter().enumerate() {
            let io_addr = IoEventAddress::Mmio(*addr);
            self.address_manager
                .vm_fd
                .register_ioevent(event, &io_addr, i as u32)
                .map_err(DeviceManagerError::RegisterIoevent)?;
        }

        let irq_num = self
            .address_manager
            .allocator
            .lock()
            .unwrap()
            .allocate_irq()
            .ok_or(DeviceManagerError::AllocateIrq)?;

        let interrupt_group = interrupt_manager
            .create_group(LegacyIrqGroupConfig {
                irq: irq_num as InterruptIndex,
            })
            .map_err(DeviceManagerError::CreateInterruptGroup)?;

        mmio_device.assign_interrupt(interrupt_group);

        let mmio_device_arc = Arc::new(Mutex::new(mmio_device));
        self.address_manager
            .mmio_bus
            .insert(mmio_device_arc.clone(), mmio_base.0, MMIO_LEN)
            .map_err(DeviceManagerError::BusError)?;

        self.cmdline_additions.push(format!(
            "virtio_mmio.device={}K@0x{:08x}:{}",
            MMIO_LEN / 1024,
            mmio_base.0,
            irq_num
        ));

        self.migratable_devices
            .push(Arc::clone(&mmio_device_arc) as Arc<Mutex<dyn Migratable>>);

        Ok(())
    }

    pub fn io_bus(&self) -> Arc<devices::Bus> {
        Arc::clone(&self.address_manager.io_bus.upgrade().unwrap())
    }

    pub fn mmio_bus(&self) -> &Arc<devices::Bus> {
        &self.address_manager.mmio_bus
    }

    pub fn allocator(&self) -> &Arc<Mutex<SystemAllocator>> {
        &self.address_manager.allocator
    }

    pub fn ioapic(&self) -> &Option<Arc<Mutex<ioapic::Ioapic>>> {
        &self.ioapic
    }

    pub fn console(&self) -> &Arc<Console> {
        &self.console
    }

    pub fn cmdline_additions(&self) -> &[String] {
        self.cmdline_additions.as_slice()
    }

    pub fn notify_hotplug(
        &self,
        _notification_type: HotPlugNotificationFlags,
    ) -> DeviceManagerResult<()> {
        #[cfg(feature = "acpi")]
        return self
            .ged_notification_device
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .notify(_notification_type)
            .map_err(DeviceManagerError::HotPlugNotification);
        #[cfg(not(feature = "acpi"))]
        return Ok(());
    }

    #[cfg(feature = "pci_support")]
    pub fn add_device(&mut self, path: String) -> DeviceManagerResult<DeviceConfig> {
        let device_cfg = DeviceConfig {
            path: PathBuf::from(path),
            iommu: false,
        };

        let pci = if let Some(pci_bus) = &self.pci_bus {
            Arc::clone(&pci_bus)
        } else {
            return Err(DeviceManagerError::NoPciBus);
        };

        let interrupt_manager = Arc::clone(&self.msi_interrupt_manager);

        let device_fd = if let Some(device_fd) = &self.kvm_device_fd {
            Arc::clone(&device_fd)
        } else {
            // If the VFIO KVM device file descriptor has not been created yet,
            // it is created here and stored in the DeviceManager structure for
            // future needs.
            let device_fd = DeviceManager::create_kvm_device(&self.address_manager.vm_fd)?;
            let device_fd = Arc::new(device_fd);
            self.kvm_device_fd = Some(Arc::clone(&device_fd));
            device_fd
        };

        let device_id = self.add_vfio_device(
            &mut pci.lock().unwrap(),
            &interrupt_manager,
            &device_fd,
            &device_cfg,
        )?;

        // Update the PCIU bitmap
        self.pci_devices_up |= 1 << (device_id >> 3);

        Ok(device_cfg)
    }
}

#[cfg(feature = "acpi")]
struct PciDevSlot {
    device_id: u8,
}

#[cfg(feature = "acpi")]
impl Aml for PciDevSlot {
    fn to_aml_bytes(&self) -> Vec<u8> {
        let sun = self.device_id;
        let adr: u32 = (self.device_id as u32) << 16;
        aml::Device::new(
            format!("S{:03}", self.device_id).as_str().into(),
            vec![
                &aml::Name::new("_SUN".into(), &sun),
                &aml::Name::new("_ADR".into(), &adr),
                &aml::Method::new(
                    "_EJ0".into(),
                    1,
                    true,
                    vec![&aml::MethodCall::new(
                        "\\_SB_.PHPR.PCEJ".into(),
                        vec![&aml::Path::new("_SUN")],
                    )],
                ),
            ],
        )
        .to_aml_bytes()
    }
}

#[cfg(feature = "acpi")]
struct PciDevSlotNotify {
    device_id: u8,
}

#[cfg(feature = "acpi")]
impl Aml for PciDevSlotNotify {
    fn to_aml_bytes(&self) -> Vec<u8> {
        let device_id_mask: u32 = 1 << self.device_id;
        let object = aml::Path::new(&format!("S{:03}", self.device_id));
        let mut bytes = aml::And::new(&aml::Local(0), &aml::Arg(0), &device_id_mask).to_aml_bytes();
        bytes.extend_from_slice(
            &aml::If::new(
                &aml::Equal::new(&aml::Local(0), &device_id_mask),
                vec![&aml::Notify::new(&object, &aml::Arg(1))],
            )
            .to_aml_bytes(),
        );
        bytes
    }
}

#[cfg(feature = "acpi")]
struct PciDevSlotMethods {}

#[cfg(feature = "acpi")]
impl Aml for PciDevSlotMethods {
    fn to_aml_bytes(&self) -> Vec<u8> {
        let mut device_notifies = Vec::new();
        for device_id in 0..32 {
            device_notifies.push(PciDevSlotNotify { device_id });
        }

        let mut device_notifies_refs: Vec<&dyn aml::Aml> = Vec::new();
        for device_notify in device_notifies.iter() {
            device_notifies_refs.push(device_notify);
        }

        let mut bytes =
            aml::Method::new("DVNT".into(), 2, true, device_notifies_refs).to_aml_bytes();

        bytes.extend_from_slice(
            &aml::Method::new(
                "PCNT".into(),
                0,
                true,
                vec![
                    &aml::MethodCall::new(
                        "DVNT".into(),
                        vec![&aml::Path::new("\\_SB_.PHPR.PCIU"), &aml::ONE],
                    ),
                    &aml::MethodCall::new(
                        "DVNT".into(),
                        vec![&aml::Path::new("\\_SB_.PHPR.PCID"), &3usize],
                    ),
                ],
            )
            .to_aml_bytes(),
        );
        bytes
    }
}

#[cfg(feature = "acpi")]
impl Aml for DeviceManager {
    fn to_aml_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        // PCI hotplug controller
        bytes.extend_from_slice(
            &aml::Device::new(
                "_SB_.PHPR".into(),
                vec![
                    &aml::Name::new("_HID".into(), &aml::EISAName::new("PNP0A06")),
                    &aml::Name::new("_STA".into(), &0x0bu8),
                    &aml::Mutex::new("BLCK".into(), 0),
                    // I/O port for PCI hotplug controller
                    &aml::Name::new(
                        "_CRS".into(),
                        &aml::ResourceTemplate::new(vec![&aml::IO::new(
                            0xae00, 0xae00, 0x01, 0x10,
                        )]),
                    ),
                    // OpRegion and Fields map I/O port into individual field values
                    &aml::OpRegion::new("PCST".into(), aml::OpRegionSpace::SystemIO, 0xae00, 0x10),
                    &aml::Field::new(
                        "PCST".into(),
                        aml::FieldAccessType::DWord,
                        aml::FieldUpdateRule::WriteAsZeroes,
                        vec![
                            aml::FieldEntry::Named(*b"PCIU", 32),
                            aml::FieldEntry::Named(*b"PCID", 32),
                            aml::FieldEntry::Named(*b"B0EJ", 32),
                        ],
                    ),
                    &aml::Method::new(
                        "PCEJ".into(),
                        1,
                        true,
                        vec![
                            // Take lock defined above
                            &aml::Acquire::new("BLCK".into(), 0xffff),
                            // Write PCI bus number (in first argument) to I/O port via field
                            &aml::ShiftLeft::new(&aml::Path::new("B0EJ"), &aml::ONE, &aml::Arg(0)),
                            // Release lock
                            &aml::Release::new("BLCK".into()),
                            // Return 0
                            &aml::Return::new(&aml::ZERO),
                        ],
                    ),
                ],
            )
            .to_aml_bytes(),
        );

        let start_of_device_area = self.memory_manager.lock().unwrap().start_of_device_area().0;
        let end_of_device_area = self.memory_manager.lock().unwrap().end_of_device_area().0;

        let mut pci_dsdt_inner_data: Vec<&dyn aml::Aml> = Vec::new();
        let hid = aml::Name::new("_HID".into(), &aml::EISAName::new("PNP0A08"));
        pci_dsdt_inner_data.push(&hid);
        let cid = aml::Name::new("_CID".into(), &aml::EISAName::new("PNP0A03"));
        pci_dsdt_inner_data.push(&cid);
        let adr = aml::Name::new("_ADR".into(), &aml::ZERO);
        pci_dsdt_inner_data.push(&adr);
        let seg = aml::Name::new("_SEG".into(), &aml::ZERO);
        pci_dsdt_inner_data.push(&seg);
        let uid = aml::Name::new("_UID".into(), &aml::ZERO);
        pci_dsdt_inner_data.push(&uid);
        let supp = aml::Name::new("SUPP".into(), &aml::ZERO);
        pci_dsdt_inner_data.push(&supp);
        let crs = aml::Name::new(
            "_CRS".into(),
            &aml::ResourceTemplate::new(vec![
                &aml::AddressSpace::new_bus_number(0x0u16, 0xffu16),
                &aml::IO::new(0xcf8, 0xcf8, 1, 0x8),
                &aml::AddressSpace::new_io(0x0u16, 0xcf7u16),
                &aml::AddressSpace::new_io(0xd00u16, 0xffffu16),
                &aml::AddressSpace::new_memory(
                    aml::AddressSpaceCachable::NotCacheable,
                    true,
                    layout::MEM_32BIT_DEVICES_START.0 as u32,
                    (layout::MEM_32BIT_DEVICES_START.0 + layout::MEM_32BIT_DEVICES_SIZE - 1) as u32,
                ),
                &aml::AddressSpace::new_memory(
                    aml::AddressSpaceCachable::NotCacheable,
                    true,
                    start_of_device_area,
                    end_of_device_area,
                ),
            ]),
        );
        pci_dsdt_inner_data.push(&crs);

        let mut pci_devices = Vec::new();
        for device_id in 0..32 {
            let pci_device = PciDevSlot { device_id };
            pci_devices.push(pci_device);
        }
        for pci_device in pci_devices.iter() {
            pci_dsdt_inner_data.push(pci_device);
        }

        let pci_device_methods = PciDevSlotMethods {};
        pci_dsdt_inner_data.push(&pci_device_methods);

        let pci_dsdt_data =
            aml::Device::new("_SB_.PCI0".into(), pci_dsdt_inner_data).to_aml_bytes();

        let mbrd_dsdt_data = aml::Device::new(
            "_SB_.MBRD".into(),
            vec![
                &aml::Name::new("_HID".into(), &aml::EISAName::new("PNP0C02")),
                &aml::Name::new("_UID".into(), &aml::ZERO),
                &aml::Name::new(
                    "_CRS".into(),
                    &aml::ResourceTemplate::new(vec![&aml::Memory32Fixed::new(
                        true,
                        layout::PCI_MMCONFIG_START.0 as u32,
                        layout::PCI_MMCONFIG_SIZE as u32,
                    )]),
                ),
            ],
        )
        .to_aml_bytes();

        let com1_dsdt_data = aml::Device::new(
            "_SB_.COM1".into(),
            vec![
                &aml::Name::new("_HID".into(), &aml::EISAName::new("PNP0501")),
                &aml::Name::new("_UID".into(), &aml::ZERO),
                &aml::Name::new(
                    "_CRS".into(),
                    &aml::ResourceTemplate::new(vec![
                        &aml::Interrupt::new(true, true, false, false, 4),
                        &aml::IO::new(0x3f8, 0x3f8, 0, 0x8),
                    ]),
                ),
            ],
        )
        .to_aml_bytes();

        let s5_sleep_data =
            aml::Name::new("_S5_".into(), &aml::Package::new(vec![&5u8])).to_aml_bytes();

        let ged_data = self
            .ged_notification_device
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .to_aml_bytes();

        bytes.extend_from_slice(pci_dsdt_data.as_slice());
        bytes.extend_from_slice(mbrd_dsdt_data.as_slice());
        if self.config.lock().unwrap().serial.mode != ConsoleOutputMode::Off {
            bytes.extend_from_slice(com1_dsdt_data.as_slice());
        }
        bytes.extend_from_slice(s5_sleep_data.as_slice());
        bytes.extend_from_slice(ged_data.as_slice());
        bytes
    }
}

impl Pausable for DeviceManager {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        for dev in &self.migratable_devices {
            dev.lock().unwrap().pause()?;
        }

        Ok(())
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        for dev in &self.migratable_devices {
            dev.lock().unwrap().resume()?;
        }

        Ok(())
    }
}

impl Snapshotable for DeviceManager {}
impl Migratable for DeviceManager {}

#[cfg(feature = "pci_support")]
const PCIU_FIELD_OFFSET: u64 = 0;
#[cfg(feature = "pci_support")]
const PCID_FIELD_OFFSET: u64 = 4;

#[cfg(feature = "pci_support")]
const PCIU_FIELD_SIZE: usize = 4;
#[cfg(feature = "pci_support")]
const PCID_FIELD_SIZE: usize = 4;

impl BusDevice for DeviceManager {
    fn read(&mut self, base: u64, offset: u64, data: &mut [u8]) {
        #[cfg(feature = "pci_support")]
        match offset {
            PCIU_FIELD_OFFSET => {
                assert!(data.len() == PCIU_FIELD_SIZE);
                data.copy_from_slice(&self.pci_devices_up.to_le_bytes());
                // Clear the PCIU bitmap
                self.pci_devices_up = 0;
            }
            PCID_FIELD_OFFSET => {
                assert!(data.len() == PCID_FIELD_SIZE);
                data.copy_from_slice(&self.pci_devices_down.to_le_bytes());
                // Clear the PCID bitmap
                self.pci_devices_down = 0;
            }
            _ => {}
        }

        debug!(
            "PCI_HP_REG_R: base 0x{:x}, offset 0x{:x}, data {:?}",
            base, offset, data
        )
    }

    fn write(&mut self, base: u64, offset: u64, data: &[u8]) {
        debug!(
            "PCI_HP_REG_W: base 0x{:x}, offset 0x{:x}, data {:?}",
            base, offset, data
        )
    }
}

impl Drop for DeviceManager {
    fn drop(&mut self) {
        for (device, _) in self.virtio_devices.drain(..) {
            device.lock().unwrap().shutdown();
        }
    }
}
