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
#[cfg(feature = "acpi")]
use crate::config::VmConfig;
use crate::interrupt::{KvmInterruptManager, KvmRoutingEntry};
use crate::memory_manager::{Error as MemoryManagerError, MemoryManager};
use crate::vm::VmInfo;
#[cfg(feature = "acpi")]
use acpi_tables::{aml, aml::Aml};
use arc_swap::ArcSwap;
#[cfg(feature = "acpi")]
use arch::layout;
use arch::layout::{APIC_START, IOAPIC_SIZE, IOAPIC_START};
use devices::{ioapic, HotPlugNotificationFlags};
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
use std::result;
#[cfg(feature = "pci_support")]
use std::sync::Weak;
use std::sync::{Arc, Mutex};
#[cfg(feature = "pci_support")]
use vfio::{VfioDevice, VfioDmaMapping, VfioPciDevice, VfioPciError};
use vm_allocator::SystemAllocator;
use vm_device::interrupt::InterruptManager;
use vm_device::interrupt::{InterruptIndex, PIN_IRQ};
use vm_device::{Migratable, MigratableError, Pausable, Snapshotable};
use vm_memory::guest_memory::FileOffset;
use vm_memory::{Address, GuestAddress, GuestMemoryMmap, GuestUsize, MmapRegion};
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
    io_bus: Arc<devices::Bus>,
    mmio_bus: Arc<devices::Bus>,
    #[cfg(feature = "pci_support")]
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

    // Virtual IOMMU ID along with the list of device IDs attached to the
    // virtual IOMMU. This is useful for filling the ACPI IORT table.
    virt_iommu: Option<(u32, Vec<u32>)>,

    // ACPI GED notification device
    #[cfg(feature = "acpi")]
    ged_notification_device: Option<Arc<Mutex<devices::AcpiGEDDevice>>>,

    // VM configuration
    #[cfg(feature = "acpi")]
    config: Arc<Mutex<VmConfig>>,

    // Migratable devices
    migratable_devices: Vec<Arc<Mutex<dyn Migratable>>>,

    // Memory Manager
    #[cfg(feature = "acpi")]
    memory_manager: Arc<Mutex<MemoryManager>>,
}

impl DeviceManager {
    pub fn new(
        vm_info: &VmInfo,
        allocator: Arc<Mutex<SystemAllocator>>,
        memory_manager: Arc<Mutex<MemoryManager>>,
        _exit_evt: &EventFd,
        reset_evt: &EventFd,
    ) -> DeviceManagerResult<Self> {
        let io_bus = devices::Bus::new();
        let mmio_bus = devices::Bus::new();

        let mut virtio_devices: Vec<(Arc<Mutex<dyn vm_virtio::VirtioDevice>>, bool)> = Vec::new();
        let mut migratable_devices: Vec<Arc<Mutex<dyn Migratable>>> = Vec::new();
        let mut _mmap_regions = Vec::new();

        #[allow(unused_mut)]
        let mut cmdline_additions = Vec::new();

        #[allow(unused_mut)]
        let mut virt_iommu: Option<(u32, Vec<u32>)> = None;

        let address_manager = Arc::new(AddressManager {
            allocator,
            io_bus: Arc::new(io_bus),
            mmio_bus: Arc::new(mmio_bus),
            #[cfg(feature = "pci_support")]
            vm_fd: vm_info.vm_fd.clone(),
        });

        // Create a shared list of GSI that can be shared through all PCI
        // devices. This way, we can maintain the full list of used GSI,
        // preventing one device from overriding interrupts setting from
        // another one.
        let kvm_gsi_msi_routes: Arc<Mutex<HashMap<u32, KvmRoutingEntry>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Here we create a first interrupt manager that will be directly
        // passed down to the Ioapic. The reason we need this extra interrupt
        // manager is because the more global one will need a handler onto the
        // Ioapic itself. We didn't want to solve this problem by adding some
        // setter to the KvmInterruptManager as this would have required the
        // interrupt manager to be mutable.
        //
        // One thing to note, it is safe to create two interrupt managers
        // without risking some concurrency between the two since the list
        // of GSI routes is shared and protected by a Mutex.
        let ioapic_interrupt_manager: Arc<dyn InterruptManager> =
            Arc::new(KvmInterruptManager::new(
                Arc::clone(&address_manager.allocator),
                Arc::clone(&vm_info.vm_fd),
                Arc::clone(&kvm_gsi_msi_routes),
                None,
            ));

        let ioapic = DeviceManager::add_ioapic(&address_manager, ioapic_interrupt_manager)?;

        // Creation of the global interrupt manager, which can take a hold onto
        // the brand new Ioapic.
        //
        // Note the list of GSI routes is Arc cloned, the same way it was Arc
        // cloned for the interrupt manager dedicated to the Ioapic. That's how
        // both interrupt managers are going to share the list correctly.
        let interrupt_manager: Arc<dyn InterruptManager> = Arc::new(KvmInterruptManager::new(
            Arc::clone(&address_manager.allocator),
            Arc::clone(&vm_info.vm_fd),
            Arc::clone(&kvm_gsi_msi_routes),
            Some(ioapic.clone()),
        ));

        let console = DeviceManager::add_console_device(
            vm_info,
            &address_manager,
            &interrupt_manager,
            &mut virtio_devices,
        )?;

        #[cfg(any(feature = "pci_support", feature = "mmio_support"))]
        virtio_devices.append(&mut DeviceManager::make_virtio_devices(
            vm_info,
            &address_manager,
            &memory_manager,
            &mut _mmap_regions,
            &mut migratable_devices,
        )?);

        DeviceManager::add_legacy_devices(
            vm_info,
            &address_manager,
            reset_evt.try_clone().map_err(DeviceManagerError::EventFd)?,
        )?;

        #[cfg(feature = "acpi")]
        let ged_notification_device = DeviceManager::add_acpi_devices(
            vm_info,
            &address_manager,
            &interrupt_manager,
            reset_evt.try_clone().map_err(DeviceManagerError::EventFd)?,
            _exit_evt.try_clone().map_err(DeviceManagerError::EventFd)?,
        )?;

        if cfg!(feature = "pci_support") {
            DeviceManager::add_pci_devices(
                vm_info,
                &address_manager,
                &memory_manager,
                &mut virt_iommu,
                virtio_devices,
                &interrupt_manager,
                &mut migratable_devices,
            )?;
        } else if cfg!(feature = "mmio_support") {
            DeviceManager::add_mmio_devices(
                vm_info,
                &address_manager,
                virtio_devices,
                &interrupt_manager,
                &mut cmdline_additions,
                &mut migratable_devices,
            )?;
        }

        #[cfg(feature = "acpi")]
        let config = vm_info.vm_cfg.clone();
        #[cfg(feature = "acpi")]
        let memory_manager_clone = memory_manager.clone();

        address_manager
            .allocator
            .lock()
            .unwrap()
            .allocate_io_addresses(Some(GuestAddress(0x0a00)), 0x18, None)
            .ok_or(DeviceManagerError::AllocateIOPort)?;

        address_manager
            .io_bus
            .insert(memory_manager, 0xa00, 0x18)
            .map_err(DeviceManagerError::BusError)?;

        Ok(DeviceManager {
            address_manager,
            console,
            ioapic: Some(ioapic),
            _mmap_regions,
            cmdline_additions,
            virt_iommu,
            #[cfg(feature = "acpi")]
            ged_notification_device,
            #[cfg(feature = "acpi")]
            config,
            migratable_devices,
            #[cfg(feature = "acpi")]
            memory_manager: memory_manager_clone,
        })
    }

    #[allow(unused_variables)]
    fn add_pci_devices(
        vm_info: &VmInfo,
        address_manager: &Arc<AddressManager>,
        memory_manager: &Arc<Mutex<MemoryManager>>,
        virt_iommu: &mut Option<(u32, Vec<u32>)>,
        virtio_devices: Vec<(Arc<Mutex<dyn vm_virtio::VirtioDevice>>, bool)>,
        interrupt_manager: &Arc<dyn InterruptManager>,
        migratable_devices: &mut Vec<Arc<Mutex<dyn Migratable>>>,
    ) -> DeviceManagerResult<()> {
        #[cfg(feature = "pci_support")]
        {
            let pci_root = PciRoot::new(None);
            let mut pci_bus = PciBus::new(
                pci_root,
                Arc::downgrade(&address_manager) as Weak<dyn DeviceRelocation>,
            );

            let (mut iommu_device, iommu_mapping) = if vm_info.vm_cfg.lock().unwrap().iommu {
                let (device, mapping) =
                    vm_virtio::Iommu::new().map_err(DeviceManagerError::CreateVirtioIommu)?;
                (Some(device), Some(mapping))
            } else {
                (None, None)
            };

            let mut iommu_attached_devices = Vec::new();

            for (device, iommu_attached) in virtio_devices {
                let mapping: &Option<Arc<IommuMapping>> = if iommu_attached {
                    &iommu_mapping
                } else {
                    &None
                };

                let virtio_iommu_attach_dev = DeviceManager::add_virtio_pci_device(
                    device,
                    vm_info.memory,
                    &address_manager,
                    vm_info.vm_fd,
                    &mut pci_bus,
                    mapping,
                    migratable_devices,
                    interrupt_manager,
                )?;

                if let Some(dev_id) = virtio_iommu_attach_dev {
                    iommu_attached_devices.push(dev_id);
                }
            }

            let mut vfio_iommu_device_ids = DeviceManager::add_vfio_devices(
                vm_info,
                &address_manager,
                &mut pci_bus,
                memory_manager,
                &mut iommu_device,
                interrupt_manager,
            )?;

            iommu_attached_devices.append(&mut vfio_iommu_device_ids);

            if let Some(mut iommu_device) = iommu_device {
                iommu_device.attach_pci_devices(0, iommu_attached_devices.clone());

                // We need to shift the device id since the 3 first bits
                // are dedicated to the PCI function, and we know we don't
                // do multifunction. Also, because we only support one PCI
                // bus, the bus 0, we don't need to add anything to the
                // global device ID.
                let iommu_id = pci_bus.next_device_id() << 3;

                // Because we determined the virtio-iommu b/d/f, we have to
                // add the device to the PCI topology now. Otherwise, the
                // b/d/f won't match the virtio-iommu device as expected.
                DeviceManager::add_virtio_pci_device(
                    Arc::new(Mutex::new(iommu_device)),
                    vm_info.memory,
                    &address_manager,
                    vm_info.vm_fd,
                    &mut pci_bus,
                    &None,
                    migratable_devices,
                    interrupt_manager,
                )?;

                *virt_iommu = Some((iommu_id, iommu_attached_devices));
            }

            let pci_bus = Arc::new(Mutex::new(pci_bus));
            let pci_config_io = Arc::new(Mutex::new(PciConfigIo::new(pci_bus.clone())));
            address_manager
                .io_bus
                .insert(pci_config_io, 0xcf8, 0x8)
                .map_err(DeviceManagerError::BusError)?;
            let pci_config_mmio = Arc::new(Mutex::new(PciConfigMmio::new(pci_bus)));
            address_manager
                .mmio_bus
                .insert(
                    pci_config_mmio,
                    arch::layout::PCI_MMCONFIG_START.0,
                    arch::layout::PCI_MMCONFIG_SIZE,
                )
                .map_err(DeviceManagerError::BusError)?;
        }

        Ok(())
    }

    #[allow(unused_variables, unused_mut)]
    fn add_mmio_devices(
        vm_info: &VmInfo,
        address_manager: &Arc<AddressManager>,
        virtio_devices: Vec<(Arc<Mutex<dyn vm_virtio::VirtioDevice>>, bool)>,
        interrupt_manager: &Arc<dyn InterruptManager>,
        mut cmdline_additions: &mut Vec<String>,
        migratable_devices: &mut Vec<Arc<Mutex<dyn Migratable>>>,
    ) -> DeviceManagerResult<()> {
        #[cfg(feature = "mmio_support")]
        {
            for (device, _) in virtio_devices {
                let mmio_addr = address_manager
                    .allocator
                    .lock()
                    .unwrap()
                    .allocate_mmio_addresses(None, MMIO_LEN, Some(MMIO_LEN));
                if let Some(addr) = mmio_addr {
                    DeviceManager::add_virtio_mmio_device(
                        device,
                        vm_info.memory,
                        &address_manager,
                        vm_info.vm_fd,
                        interrupt_manager,
                        addr,
                        &mut cmdline_additions,
                        migratable_devices,
                    )?;
                } else {
                    error!("Unable to allocate MMIO address!");
                }
            }
        }

        Ok(())
    }

    fn add_ioapic(
        address_manager: &Arc<AddressManager>,
        interrupt_manager: Arc<dyn InterruptManager>,
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

    #[allow(unused_variables)]
    #[cfg(feature = "acpi")]
    fn add_acpi_devices(
        vm_info: &VmInfo,
        address_manager: &Arc<AddressManager>,
        interrupt_manager: &Arc<dyn InterruptManager>,
        reset_evt: EventFd,
        exit_evt: EventFd,
    ) -> DeviceManagerResult<Option<Arc<Mutex<devices::AcpiGEDDevice>>>> {
        let acpi_device = Arc::new(Mutex::new(devices::AcpiShutdownDevice::new(
            exit_evt, reset_evt,
        )));

        address_manager
            .allocator
            .lock()
            .unwrap()
            .allocate_io_addresses(Some(GuestAddress(0x3c0)), 0x8, None)
            .ok_or(DeviceManagerError::AllocateIOPort)?;

        address_manager
            .io_bus
            .insert(acpi_device, 0x3c0, 0x4)
            .map_err(DeviceManagerError::BusError)?;

        let ged_irq = address_manager
            .allocator
            .lock()
            .unwrap()
            .allocate_irq()
            .unwrap();

        let interrupt_group = interrupt_manager
            .create_group(PIN_IRQ, ged_irq as InterruptIndex, 1 as InterruptIndex)
            .map_err(DeviceManagerError::CreateInterruptGroup)?;

        let ged_device = Arc::new(Mutex::new(devices::AcpiGEDDevice::new(
            interrupt_group,
            ged_irq,
        )));

        address_manager
            .allocator
            .lock()
            .unwrap()
            .allocate_io_addresses(Some(GuestAddress(0xb000)), 0x1, None)
            .ok_or(DeviceManagerError::AllocateIOPort)?;

        address_manager
            .io_bus
            .insert(ged_device.clone(), 0xb000, 0x1)
            .map_err(DeviceManagerError::BusError)?;
        Ok(Some(ged_device))
    }

    fn add_legacy_devices(
        _vm_info: &VmInfo,
        address_manager: &Arc<AddressManager>,
        reset_evt: EventFd,
    ) -> DeviceManagerResult<()> {
        // Add a shutdown device (i8042)
        let i8042 = Arc::new(Mutex::new(devices::legacy::I8042Device::new(reset_evt)));

        address_manager
            .io_bus
            .insert(i8042, 0x61, 0x4)
            .map_err(DeviceManagerError::BusError)?;
        #[cfg(feature = "cmos")]
        {
            // Add a CMOS emulated device
            use vm_memory::GuestMemory;
            let mem_size = _vm_info.memory.load().last_addr().0 + 1;
            let mem_below_4g = std::cmp::min(arch::layout::MEM_32BIT_RESERVED_START.0, mem_size);
            let mem_above_4g = mem_size.saturating_sub(arch::layout::RAM_64BIT_START.0);

            let cmos = Arc::new(Mutex::new(devices::legacy::Cmos::new(
                mem_below_4g,
                mem_above_4g,
            )));

            address_manager
                .io_bus
                .insert(cmos, 0x70, 0x2)
                .map_err(DeviceManagerError::BusError)?;
        }

        Ok(())
    }

    fn add_console_device(
        vm_info: &VmInfo,
        address_manager: &Arc<AddressManager>,
        interrupt_manager: &Arc<dyn InterruptManager>,
        virtio_devices: &mut Vec<(Arc<Mutex<dyn vm_virtio::VirtioDevice>>, bool)>,
    ) -> DeviceManagerResult<Arc<Console>> {
        let serial_config = vm_info.vm_cfg.lock().unwrap().serial.clone();
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
                .create_group(PIN_IRQ, serial_irq as InterruptIndex, 1 as InterruptIndex)
                .map_err(DeviceManagerError::CreateInterruptGroup)?;

            let serial = Arc::new(Mutex::new(devices::legacy::Serial::new(
                interrupt_group,
                serial_writer,
            )));

            address_manager
                .allocator
                .lock()
                .unwrap()
                .allocate_io_addresses(Some(GuestAddress(0x3f8)), 0x8, None)
                .ok_or(DeviceManagerError::AllocateIOPort)?;

            address_manager
                .io_bus
                .insert(serial.clone(), 0x3f8, 0x8)
                .map_err(DeviceManagerError::BusError)?;

            Some(serial)
        } else {
            None
        };

        // Create serial and virtio-console
        let console_config = vm_info.vm_cfg.lock().unwrap().console.clone();
        let console_writer: Option<Box<dyn io::Write + Send + Sync>> = match console_config.mode {
            ConsoleOutputMode::File => Some(Box::new(
                File::create(
                    vm_info
                        .vm_cfg
                        .lock()
                        .unwrap()
                        .console
                        .file
                        .as_ref()
                        .unwrap(),
                )
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

    fn make_virtio_devices(
        vm_info: &VmInfo,
        address_manager: &Arc<AddressManager>,
        memory_manager: &Arc<Mutex<MemoryManager>>,
        mmap_regions: &mut Vec<MmapRegion>,
        migratable_devices: &mut Vec<Arc<Mutex<dyn Migratable>>>,
    ) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool)>> {
        let mut allocator = address_manager.allocator.lock().unwrap();
        let mut devices: Vec<(Arc<Mutex<dyn vm_virtio::VirtioDevice>>, bool)> = Vec::new();

        // Create "standard" virtio devices (net/block/rng)
        devices.append(&mut DeviceManager::make_virtio_block_devices(
            vm_info,
            migratable_devices,
        )?);
        devices.append(&mut DeviceManager::make_virtio_net_devices(
            vm_info,
            migratable_devices,
        )?);
        devices.append(&mut DeviceManager::make_virtio_rng_devices(
            vm_info,
            migratable_devices,
        )?);

        // Add virtio-fs if required
        devices.append(&mut DeviceManager::make_virtio_fs_devices(
            vm_info,
            &mut allocator,
            memory_manager,
            mmap_regions,
            migratable_devices,
        )?);

        // Add virtio-pmem if required
        devices.append(&mut DeviceManager::make_virtio_pmem_devices(
            vm_info,
            &mut allocator,
            memory_manager,
            mmap_regions,
            migratable_devices,
        )?);

        // Add virtio-vhost-user-net if required
        devices.append(&mut DeviceManager::make_virtio_vhost_user_net_devices(
            vm_info,
            migratable_devices,
        )?);

        // Add virtio-vhost-user-blk if required
        devices.append(&mut DeviceManager::make_virtio_vhost_user_blk_devices(
            vm_info,
            migratable_devices,
        )?);

        // Add virtio-vsock if required
        devices.append(&mut DeviceManager::make_virtio_vsock_devices(
            vm_info,
            migratable_devices,
        )?);

        Ok(devices)
    }

    fn make_virtio_block_devices(
        vm_info: &VmInfo,
        migratable_devices: &mut Vec<Arc<Mutex<dyn Migratable>>>,
    ) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool)>> {
        let mut devices = Vec::new();

        if let Some(disk_list_cfg) = &vm_info.vm_cfg.lock().unwrap().disks {
            for disk_cfg in disk_list_cfg.iter() {
                if disk_cfg.vhost_user {
                    let vu_cfg = VhostUserConfig {
                        sock: disk_cfg.vhost_socket.clone().unwrap(),
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

                    migratable_devices
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
                            migratable_devices
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
                            migratable_devices
                                .push(Arc::clone(&block) as Arc<Mutex<dyn Migratable>>);
                        }
                    };
                }
            }
        }

        Ok(devices)
    }

    /// Add virto-net and vhost-user-net devices
    fn make_virtio_net_devices(
        vm_info: &VmInfo,
        migratable_devices: &mut Vec<Arc<Mutex<dyn Migratable>>>,
    ) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool)>> {
        let mut devices = Vec::new();

        if let Some(net_list_cfg) = &vm_info.vm_cfg.lock().unwrap().net {
            for net_cfg in net_list_cfg.iter() {
                if net_cfg.vhost_user {
                    let vu_cfg = VhostUserConfig {
                        sock: net_cfg.vhost_socket.clone().unwrap(),
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
                    migratable_devices
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
                    migratable_devices
                        .push(Arc::clone(&virtio_net_device) as Arc<Mutex<dyn Migratable>>);
                }
            }
        }

        Ok(devices)
    }

    fn make_virtio_rng_devices(
        vm_info: &VmInfo,
        migratable_devices: &mut Vec<Arc<Mutex<dyn Migratable>>>,
    ) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool)>> {
        let mut devices = Vec::new();

        // Add virtio-rng if required
        let rng_config = vm_info.vm_cfg.lock().unwrap().rng.clone();
        if let Some(rng_path) = rng_config.src.to_str() {
            let virtio_rng_device = Arc::new(Mutex::new(
                vm_virtio::Rng::new(rng_path, rng_config.iommu)
                    .map_err(DeviceManagerError::CreateVirtioRng)?,
            ));
            devices.push((
                Arc::clone(&virtio_rng_device) as Arc<Mutex<dyn vm_virtio::VirtioDevice>>,
                false,
            ));

            migratable_devices.push(Arc::clone(&virtio_rng_device) as Arc<Mutex<dyn Migratable>>);
        }

        Ok(devices)
    }

    fn make_virtio_fs_devices(
        vm_info: &VmInfo,
        allocator: &mut SystemAllocator,
        memory_manager: &Arc<Mutex<MemoryManager>>,
        mmap_regions: &mut Vec<MmapRegion>,
        migratable_devices: &mut Vec<Arc<Mutex<dyn Migratable>>>,
    ) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool)>> {
        let mut devices = Vec::new();
        // Add virtio-fs if required
        if let Some(fs_list_cfg) = &vm_info.vm_cfg.lock().unwrap().fs {
            for fs_cfg in fs_list_cfg.iter() {
                if let Some(fs_sock) = fs_cfg.sock.to_str() {
                    let cache: Option<(VirtioSharedMemoryList, u64)> = if fs_cfg.dax {
                        let fs_cache = fs_cfg.cache_size;
                        // The memory needs to be 2MiB aligned in order to support
                        // hugepages.
                        let fs_guest_addr = allocator
                            .allocate_mmio_addresses(
                                None,
                                fs_cache as GuestUsize,
                                Some(0x0020_0000),
                            )
                            .ok_or(DeviceManagerError::FsRangeAllocation)?;

                        let mmap_region = MmapRegion::new(fs_cache as usize)
                            .map_err(DeviceManagerError::NewMmapRegion)?;
                        let addr: u64 = mmap_region.as_ptr() as u64;

                        mmap_regions.push(mmap_region);

                        memory_manager
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

                    migratable_devices
                        .push(Arc::clone(&virtio_fs_device) as Arc<Mutex<dyn Migratable>>);
                }
            }
        }

        Ok(devices)
    }

    fn make_virtio_pmem_devices(
        vm_info: &VmInfo,
        allocator: &mut SystemAllocator,
        memory_manager: &Arc<Mutex<MemoryManager>>,
        mmap_regions: &mut Vec<MmapRegion>,
        migratable_devices: &mut Vec<Arc<Mutex<dyn Migratable>>>,
    ) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool)>> {
        let mut devices = Vec::new();
        // Add virtio-pmem if required
        if let Some(pmem_list_cfg) = &vm_info.vm_cfg.lock().unwrap().pmem {
            for pmem_cfg in pmem_list_cfg.iter() {
                let size = pmem_cfg.size;

                // The memory needs to be 2MiB aligned in order to support
                // hugepages.
                let pmem_guest_addr = allocator
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

                mmap_regions.push(mmap_region);

                memory_manager
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

                migratable_devices
                    .push(Arc::clone(&virtio_pmem_device) as Arc<Mutex<dyn Migratable>>);
            }
        }

        Ok(devices)
    }

    fn make_virtio_vhost_user_net_devices(
        vm_info: &VmInfo,
        migratable_devices: &mut Vec<Arc<Mutex<dyn Migratable>>>,
    ) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool)>> {
        let mut devices = Vec::new();
        // Add vhost-user-net if required
        if let Some(vhost_user_net_list_cfg) = &vm_info.vm_cfg.lock().unwrap().vhost_user_net {
            for vhost_user_net_cfg in vhost_user_net_list_cfg.iter() {
                let vu_cfg = VhostUserConfig {
                    sock: vhost_user_net_cfg.sock.clone(),
                    num_queues: vhost_user_net_cfg.num_queues,
                    queue_size: vhost_user_net_cfg.queue_size,
                };
                let vhost_user_net_device = Arc::new(Mutex::new(
                    vm_virtio::vhost_user::Net::new(vhost_user_net_cfg.mac, vu_cfg)
                        .map_err(DeviceManagerError::CreateVhostUserNet)?,
                ));

                devices.push((
                    Arc::clone(&vhost_user_net_device) as Arc<Mutex<dyn vm_virtio::VirtioDevice>>,
                    false,
                ));

                migratable_devices
                    .push(Arc::clone(&vhost_user_net_device) as Arc<Mutex<dyn Migratable>>);
            }
        }

        Ok(devices)
    }

    fn make_virtio_vhost_user_blk_devices(
        vm_info: &VmInfo,
        migratable_devices: &mut Vec<Arc<Mutex<dyn Migratable>>>,
    ) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool)>> {
        let mut devices = Vec::new();
        // Add vhost-user-blk if required
        if let Some(vhost_user_blk_list_cfg) = &vm_info.vm_cfg.lock().unwrap().vhost_user_blk {
            for vhost_user_blk_cfg in vhost_user_blk_list_cfg.iter() {
                let vu_cfg = VhostUserConfig {
                    sock: vhost_user_blk_cfg.sock.clone(),
                    num_queues: vhost_user_blk_cfg.num_queues,
                    queue_size: vhost_user_blk_cfg.queue_size,
                };
                let vhost_user_blk_device = Arc::new(Mutex::new(
                    vm_virtio::vhost_user::Blk::new(vhost_user_blk_cfg.wce, vu_cfg)
                        .map_err(DeviceManagerError::CreateVhostUserBlk)?,
                ));

                devices.push((
                    Arc::clone(&vhost_user_blk_device) as Arc<Mutex<dyn vm_virtio::VirtioDevice>>,
                    false,
                ));

                migratable_devices
                    .push(Arc::clone(&vhost_user_blk_device) as Arc<Mutex<dyn Migratable>>);
            }
        }

        Ok(devices)
    }

    fn make_virtio_vsock_devices(
        vm_info: &VmInfo,
        migratable_devices: &mut Vec<Arc<Mutex<dyn Migratable>>>,
    ) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool)>> {
        let mut devices = Vec::new();
        // Add vsock if required
        if let Some(vsock_list_cfg) = &vm_info.vm_cfg.lock().unwrap().vsock {
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

                migratable_devices.push(Arc::clone(&vsock_device) as Arc<Mutex<dyn Migratable>>);
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
    fn add_vfio_devices(
        vm_info: &VmInfo,
        address_manager: &Arc<AddressManager>,
        pci: &mut PciBus,
        memory_manager: &Arc<Mutex<MemoryManager>>,
        iommu_device: &mut Option<vm_virtio::Iommu>,
        interrupt_manager: &Arc<dyn InterruptManager>,
    ) -> DeviceManagerResult<Vec<u32>> {
        let mut mem_slot = memory_manager.lock().unwrap().allocate_kvm_memory_slot();
        let mut iommu_attached_device_ids = Vec::new();

        if let Some(device_list_cfg) = &vm_info.vm_cfg.lock().unwrap().devices {
            // Create the KVM VFIO device
            let device_fd = DeviceManager::create_kvm_device(vm_info.vm_fd)?;
            let device_fd = Arc::new(device_fd);

            for device_cfg in device_list_cfg.iter() {
                // We need to shift the device id since the 3 first bits
                // are dedicated to the PCI function, and we know we don't
                // do multifunction. Also, because we only support one PCI
                // bus, the bus 0, we don't need to add anything to the
                // global device ID.
                let device_id = pci.next_device_id() << 3;

                let vfio_device = VfioDevice::new(
                    &device_cfg.path,
                    device_fd.clone(),
                    vm_info.memory.clone(),
                    device_cfg.iommu,
                )
                .map_err(DeviceManagerError::VfioCreate)?;

                if device_cfg.iommu {
                    if let Some(iommu) = iommu_device {
                        let vfio_mapping = Arc::new(VfioDmaMapping::new(
                            vfio_device.get_container(),
                            Arc::clone(vm_info.memory),
                        ));

                        iommu_attached_device_ids.push(device_id);
                        iommu.add_external_mapping(device_id, vfio_mapping);
                    }
                }

                let mut vfio_pci_device =
                    VfioPciDevice::new(vm_info.vm_fd, vfio_device, interrupt_manager)
                        .map_err(DeviceManagerError::VfioPciCreate)?;

                let bars = vfio_pci_device
                    .allocate_bars(&mut address_manager.allocator.lock().unwrap())
                    .map_err(DeviceManagerError::AllocateBars)?;

                mem_slot = vfio_pci_device
                    .map_mmio_regions(vm_info.vm_fd, mem_slot)
                    .map_err(DeviceManagerError::VfioMapRegion)?;

                let vfio_pci_device = Arc::new(Mutex::new(vfio_pci_device));

                pci.add_device(vfio_pci_device.clone())
                    .map_err(DeviceManagerError::AddPciDevice)?;

                pci.register_mapping(
                    vfio_pci_device.clone(),
                    address_manager.io_bus.as_ref(),
                    address_manager.mmio_bus.as_ref(),
                    bars,
                )
                .map_err(DeviceManagerError::AddPciDevice)?;
            }
        }
        Ok(iommu_attached_device_ids)
    }

    #[cfg(feature = "pci_support")]
    #[allow(clippy::too_many_arguments)]
    fn add_virtio_pci_device(
        virtio_device: Arc<Mutex<dyn vm_virtio::VirtioDevice>>,
        memory: &Arc<ArcSwap<GuestMemoryMmap>>,
        address_manager: &Arc<AddressManager>,
        vm_fd: &Arc<VmFd>,
        pci: &mut PciBus,
        iommu_mapping: &Option<Arc<IommuMapping>>,
        migratable_devices: &mut Vec<Arc<Mutex<dyn Migratable>>>,
        interrupt_manager: &Arc<dyn InterruptManager>,
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

        let mut virtio_pci_device = VirtioPciDevice::new(
            memory.clone(),
            virtio_device,
            msix_num,
            iommu_mapping_cb,
            interrupt_manager,
        )
        .map_err(DeviceManagerError::VirtioDevice)?;

        let mut allocator = address_manager.allocator.lock().unwrap();
        let bars = virtio_pci_device
            .allocate_bars(&mut allocator)
            .map_err(DeviceManagerError::AllocateBars)?;

        let bar_addr = virtio_pci_device.config_bar_addr();
        for (event, addr) in virtio_pci_device.ioeventfds(bar_addr) {
            let io_addr = IoEventAddress::Mmio(addr);
            vm_fd
                .register_ioevent(event, &io_addr, NoDatamatch)
                .map_err(DeviceManagerError::RegisterIoevent)?;
        }

        let virtio_pci_device = Arc::new(Mutex::new(virtio_pci_device));

        pci.add_device(virtio_pci_device.clone())
            .map_err(DeviceManagerError::AddPciDevice)?;

        pci.register_mapping(
            virtio_pci_device.clone(),
            address_manager.io_bus.as_ref(),
            address_manager.mmio_bus.as_ref(),
            bars,
        )
        .map_err(DeviceManagerError::AddPciDevice)?;

        migratable_devices.push(Arc::clone(&virtio_pci_device) as Arc<Mutex<dyn Migratable>>);

        let ret = if iommu_mapping.is_some() {
            Some(dev_id)
        } else {
            None
        };

        Ok(ret)
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "mmio_support")]
    fn add_virtio_mmio_device(
        virtio_device: Arc<Mutex<dyn vm_virtio::VirtioDevice>>,
        memory: &Arc<ArcSwap<GuestMemoryMmap>>,
        address_manager: &Arc<AddressManager>,
        vm_fd: &Arc<VmFd>,
        interrupt_manager: &Arc<dyn InterruptManager>,
        mmio_base: GuestAddress,
        cmdline_additions: &mut Vec<String>,
        migratable_devices: &mut Vec<Arc<Mutex<dyn Migratable>>>,
    ) -> DeviceManagerResult<()> {
        let mut mmio_device = vm_virtio::transport::MmioDevice::new(memory.clone(), virtio_device)
            .map_err(DeviceManagerError::VirtioDevice)?;

        for (i, (event, addr)) in mmio_device.ioeventfds(mmio_base.0).iter().enumerate() {
            let io_addr = IoEventAddress::Mmio(*addr);
            vm_fd
                .register_ioevent(event, &io_addr, i as u32)
                .map_err(DeviceManagerError::RegisterIoevent)?;
        }

        let irq_num = address_manager
            .allocator
            .lock()
            .unwrap()
            .allocate_irq()
            .ok_or(DeviceManagerError::AllocateIrq)?;

        let interrupt_group = interrupt_manager
            .create_group(PIN_IRQ, irq_num as InterruptIndex, 1 as InterruptIndex)
            .map_err(DeviceManagerError::CreateInterruptGroup)?;

        mmio_device.assign_interrupt(interrupt_group);

        let mmio_device_arc = Arc::new(Mutex::new(mmio_device));
        address_manager
            .mmio_bus
            .insert(mmio_device_arc.clone(), mmio_base.0, MMIO_LEN)
            .map_err(DeviceManagerError::BusError)?;

        cmdline_additions.push(format!(
            "virtio_mmio.device={}K@0x{:08x}:{}",
            MMIO_LEN / 1024,
            mmio_base.0,
            irq_num
        ));

        migratable_devices.push(Arc::clone(&mmio_device_arc) as Arc<Mutex<dyn Migratable>>);

        Ok(())
    }

    pub fn io_bus(&self) -> &Arc<devices::Bus> {
        &self.address_manager.io_bus
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

    pub fn virt_iommu(&self) -> Option<(u32, &[u32])> {
        if let Some((iommu_id, dev_ids)) = self.virt_iommu.as_ref() {
            Some((*iommu_id, dev_ids.as_slice()))
        } else {
            None
        }
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
}

#[cfg(feature = "acpi")]
fn create_ged_device(ged_irq: u32) -> Vec<u8> {
    aml::Device::new(
        "_SB_.GED_".into(),
        vec![
            &aml::Name::new("_HID".into(), &"ACPI0013"),
            &aml::Name::new("_UID".into(), &aml::ZERO),
            &aml::Name::new(
                "_CRS".into(),
                &aml::ResourceTemplate::new(vec![&aml::Interrupt::new(
                    true, true, false, false, ged_irq,
                )]),
            ),
            &aml::OpRegion::new("GDST".into(), aml::OpRegionSpace::SystemIO, 0xb000, 0x1),
            &aml::Field::new(
                "GDST".into(),
                aml::FieldAccessType::Byte,
                aml::FieldUpdateRule::WriteAsZeroes,
                vec![aml::FieldEntry::Named(*b"GDAT", 8)],
            ),
            &aml::Method::new(
                "_EVT".into(),
                1,
                true,
                vec![
                    &aml::Store::new(&aml::Local(0), &aml::Path::new("GDAT")),
                    &aml::And::new(&aml::Local(1), &aml::Local(0), &aml::ONE),
                    &aml::If::new(
                        &aml::Equal::new(&aml::Local(1), &aml::ONE),
                        vec![&aml::MethodCall::new("\\_SB_.CPUS.CSCN".into(), vec![])],
                    ),
                    &aml::And::new(&aml::Local(1), &aml::Local(0), &2usize),
                    &aml::If::new(
                        &aml::Equal::new(&aml::Local(1), &2usize),
                        vec![&aml::MethodCall::new("\\_SB_.MHPC.MSCN".into(), vec![])],
                    ),
                ],
            ),
        ],
    )
    .to_aml_bytes()
}

#[cfg(feature = "acpi")]
impl Aml for DeviceManager {
    fn to_aml_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let start_of_device_area = self.memory_manager.lock().unwrap().start_of_device_area().0;
        let end_of_device_area = self.memory_manager.lock().unwrap().end_of_device_area().0;
        let pci_dsdt_data = aml::Device::new(
            "_SB_.PCI0".into(),
            vec![
                &aml::Name::new("_HID".into(), &aml::EISAName::new("PNP0A08")),
                &aml::Name::new("_CID".into(), &aml::EISAName::new("PNP0A03")),
                &aml::Name::new("_ADR".into(), &aml::ZERO),
                &aml::Name::new("_SEG".into(), &aml::ZERO),
                &aml::Name::new("_UID".into(), &aml::ZERO),
                &aml::Name::new("SUPP".into(), &aml::ZERO),
                &aml::Name::new(
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
                            (layout::MEM_32BIT_DEVICES_START.0 + layout::MEM_32BIT_DEVICES_SIZE - 1)
                                as u32,
                        ),
                        &aml::AddressSpace::new_memory(
                            aml::AddressSpaceCachable::NotCacheable,
                            true,
                            start_of_device_area,
                            end_of_device_area,
                        ),
                    ]),
                ),
            ],
        )
        .to_aml_bytes();

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

        let ged_data = create_ged_device(
            self.ged_notification_device
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .irq(),
        );

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
