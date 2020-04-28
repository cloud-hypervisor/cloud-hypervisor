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
use crate::config::{DiskConfig, FsConfig, NetConfig, PmemConfig, VmConfig};
use crate::interrupt::{
    KvmLegacyUserspaceInterruptManager, KvmMsiInterruptManager, KvmRoutingEntry,
};
use crate::memory_manager::{Error as MemoryManagerError, MemoryManager};
use crate::DEVICE_MANAGER_SNAPSHOT_ID;
#[cfg(feature = "acpi")]
use acpi_tables::{aml, aml::Aml};
use anyhow::anyhow;
#[cfg(feature = "acpi")]
use arch::layout;
use arch::layout::{APIC_START, IOAPIC_SIZE, IOAPIC_START};
use devices::{ioapic, BusDevice, HotPlugNotificationFlags};
use kvm_ioctls::*;
use libc::TIOCGWINSZ;
use libc::{MAP_NORESERVE, MAP_PRIVATE, MAP_SHARED, O_TMPFILE, PROT_READ, PROT_WRITE};
#[cfg(feature = "pci_support")]
use pci::{
    DeviceRelocation, PciBarRegionType, PciBus, PciConfigIo, PciConfigMmio, PciDevice, PciRoot,
};
use qcow::{self, ImageType, QcowFile};
#[cfg(feature = "pci_support")]
use std::any::Any;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, sink, stdout, Seek, SeekFrom};
#[cfg(feature = "pci_support")]
use std::num::Wrapping;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::result;
use std::sync::{Arc, Mutex};
use tempfile::NamedTempFile;
#[cfg(feature = "pci_support")]
use vfio::{VfioDevice, VfioDmaMapping, VfioPciDevice, VfioPciError};
use vm_allocator::SystemAllocator;
use vm_device::interrupt::{
    InterruptIndex, InterruptManager, LegacyIrqGroupConfig, MsiIrqGroupConfig,
};
use vm_memory::guest_memory::FileOffset;
use vm_memory::{
    Address, GuestAddress, GuestAddressSpace, GuestRegionMmap, GuestUsize, MmapRegion,
};
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
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

#[cfg(feature = "pci_support")]
const VFIO_DEVICE_NAME_PREFIX: &str = "vfio";

const DISK_DEVICE_NAME_PREFIX: &str = "disk";
const NET_DEVICE_NAME_PREFIX: &str = "net";
const PMEM_DEVICE_NAME_PREFIX: &str = "pmem";

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

    /// Virtio-fs device was created without a sock.
    NoVirtioFsSock,

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

    /// Could not free the BARs associated with a PCI device.
    #[cfg(feature = "pci_support")]
    FreePciBars(pci::PciDeviceError),

    /// Cannot register ioevent.
    RegisterIoevent(kvm_ioctls::Error),

    /// Cannot unregister ioevent.
    UnRegisterIoevent(kvm_ioctls::Error),

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

    /// Could not find an available device name.
    NoAvailableDeviceName,

    /// Missing PCI device.
    MissingPciDevice,

    /// Failed removing a PCI device from the PCI bus.
    #[cfg(feature = "pci_support")]
    RemoveDeviceFromPciBus(pci::PciRootError),

    /// Failed removing a bus device from the IO bus.
    RemoveDeviceFromIoBus(devices::BusError),

    /// Failed removing a bus device from the MMIO bus.
    RemoveDeviceFromMmioBus(devices::BusError),

    /// Failed to find VFIO device corresponding to the given identifier.
    #[cfg(feature = "pci_support")]
    UnknownVfioDeviceId(String),

    /// Failed to find an available PCI device ID.
    #[cfg(feature = "pci_support")]
    NextPciDeviceId(pci::PciRootError),

    /// Could not give the PCI device ID back.
    #[cfg(feature = "pci_support")]
    PutPciDeviceId(pci::PciRootError),

    /// Incorrect device ID as it is already used by another device.
    DeviceIdAlreadyInUse,

    /// No disk path was specified when one was expected
    NoDiskPath,

    /// Failed updating guest memory for virtio device.
    UpdateMemoryForVirtioDevice(vm_virtio::Error),

    /// Cannot create virtio-mem device
    CreateVirtioMem(io::Error),

    /// Cannot try Clone virtio-mem resize
    TryCloneVirtioMemResize(vm_virtio::mem::Error),

    /// Cannot find a memory range for virtio-mem memory
    VirtioMemRangeAllocation,

    /// Failed updating guest memory for VFIO PCI device.
    #[cfg(feature = "pci_support")]
    UpdateMemoryForVfioPciDevice(VfioPciError),

    /// Trying to use a directory for pmem but no size specified
    PmemWithDirectorySizeMissing,

    /// Trying to use a size that is not multiple of 2MiB
    PmemSizeNotAligned,
}
pub type DeviceManagerResult<T> = result::Result<T, DeviceManagerError>;

type VirtioDeviceArc = Arc<Mutex<dyn vm_virtio::VirtioDevice>>;

pub fn get_win_size() -> (u16, u16) {
    #[repr(C)]
    #[derive(Default)]
    struct WS {
        rows: u16,
        cols: u16,
        xpixel: u16,
        ypixel: u16,
    };
    let ws: WS = WS::default();

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
    io_bus: Arc<devices::Bus>,
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
                    .update_range(old_base, len, new_base, len)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            }
            PciBarRegionType::Memory32BitRegion | PciBarRegionType::Memory64BitRegion => {
                // Update system allocator
                if region_type == PciBarRegionType::Memory32BitRegion {
                    self.allocator
                        .lock()
                        .unwrap()
                        .free_mmio_hole_addresses(GuestAddress(old_base), len as GuestUsize);

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
                        .free_mmio_addresses(GuestAddress(old_base), len as GuestUsize);

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
            } else {
                let virtio_dev = virtio_pci_dev.virtio_device();
                let mut virtio_dev = virtio_dev.lock().unwrap();
                if let Some(mut shm_regions) = virtio_dev.get_shm_regions() {
                    if shm_regions.addr.raw_value() == old_base {
                        // Remove old region from KVM by passing a size of 0.
                        let mut mem_region = kvm_bindings::kvm_userspace_memory_region {
                            slot: shm_regions.mem_slot,
                            guest_phys_addr: old_base,
                            memory_size: 0,
                            userspace_addr: shm_regions.host_addr,
                            flags: 0,
                        };

                        // Safe because removing an existing guest region.
                        unsafe {
                            self.vm_fd
                                .set_user_memory_region(mem_region)
                                .map_err(|e| io::Error::from_raw_os_error(e.errno()))?;
                        }

                        // Create new mapping by inserting new region to KVM.
                        mem_region.guest_phys_addr = new_base;
                        mem_region.memory_size = shm_regions.len;

                        // Safe because the guest regions are guaranteed not to overlap.
                        unsafe {
                            self.vm_fd
                                .set_user_memory_region(mem_region)
                                .map_err(|e| io::Error::from_raw_os_error(e.errno()))?;
                        }

                        // Update shared memory regions to reflect the new mapping.
                        shm_regions.addr = GuestAddress(new_base);
                        virtio_dev.set_shm_regions(shm_regions).map_err(|e| {
                            io::Error::new(
                                io::ErrorKind::Other,
                                format!("failed to update shared memory regions: {:?}", e),
                            )
                        })?;
                    }
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

    // Things to be added to the commandline (i.e. for virtio-mmio)
    cmdline_additions: Vec<String>,

    // ACPI GED notification device
    #[cfg(feature = "acpi")]
    ged_notification_device: Option<Arc<Mutex<devices::AcpiGEDDevice>>>,

    // VM configuration
    config: Arc<Mutex<VmConfig>>,

    // Migratable devices
    // This is important to keep this as a Vec<> because the order the elements
    // are pushed into the list is important to restore them in the right order.
    // This is particularly important for VirtioPciDevice (or MmioDevice) and
    // their VirtioDevice counterpart.
    migratable_devices: Vec<(String, Arc<Mutex<dyn Migratable>>)>,

    // Memory Manager
    memory_manager: Arc<Mutex<MemoryManager>>,

    // The virtio devices on the system
    virtio_devices: Vec<(VirtioDeviceArc, bool, Option<String>)>,

    // List of bus devices
    // Let the DeviceManager keep strong references to the BusDevice devices.
    // This allows the IO and MMIO buses to be provided with Weak references,
    // which prevents cyclic dependencies.
    bus_devices: Vec<Arc<Mutex<dyn BusDevice>>>,

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

    // Hashmap of device's name to their corresponding PCI b/d/f.
    #[cfg(feature = "pci_support")]
    pci_id_list: HashMap<String, u32>,

    // Counter to keep track of the consumed device IDs.
    #[cfg(feature = "pci_support")]
    device_id_cnt: Wrapping<usize>,

    // Hashmap of PCI b/d/f to their corresponding Arc<Mutex<dyn PciDevice>>.
    #[cfg(feature = "pci_support")]
    pci_devices: HashMap<u32, Arc<dyn Any + Send + Sync>>,
}

impl DeviceManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vm_fd: Arc<VmFd>,
        config: Arc<Mutex<VmConfig>>,
        memory_manager: Arc<Mutex<MemoryManager>>,
        _exit_evt: &EventFd,
        reset_evt: &EventFd,
        vmm_path: PathBuf,
    ) -> DeviceManagerResult<Arc<Mutex<Self>>> {
        let mut virtio_devices: Vec<(VirtioDeviceArc, bool, Option<String>)> = Vec::new();
        let migratable_devices: Vec<(String, Arc<Mutex<dyn Migratable>>)> = Vec::new();
        let mut bus_devices: Vec<Arc<Mutex<dyn BusDevice>>> = Vec::new();

        #[allow(unused_mut)]
        let mut cmdline_additions = Vec::new();

        let address_manager = Arc::new(AddressManager {
            allocator: memory_manager.lock().unwrap().allocator(),
            io_bus: Arc::new(devices::Bus::new()),
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
        let ioapic_migratable = Arc::clone(&ioapic) as Arc<Mutex<dyn Migratable>>;
        bus_devices.push(Arc::clone(&ioapic) as Arc<Mutex<dyn BusDevice>>);

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
            .insert(memory_manager.clone(), 0xa00, 0x18)
            .map_err(DeviceManagerError::BusError)?;

        let mut device_manager = DeviceManager {
            address_manager: Arc::clone(&address_manager),
            console: Arc::new(Console::default()),
            ioapic: Some(ioapic),
            cmdline_additions,
            #[cfg(feature = "acpi")]
            ged_notification_device: None,
            config,
            migratable_devices,
            memory_manager,
            virtio_devices: Vec::new(),
            bus_devices,
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
            #[cfg(feature = "pci_support")]
            pci_id_list: HashMap::new(),
            #[cfg(feature = "pci_support")]
            device_id_cnt: Wrapping(0),
            #[cfg(feature = "pci_support")]
            pci_devices: HashMap::new(),
        };

        device_manager
            .add_legacy_devices(reset_evt.try_clone().map_err(DeviceManagerError::EventFd)?)?;

        device_manager.add_migratable_device(ioapic_migratable);

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
            .insert(
                Arc::clone(&device_manager) as Arc<Mutex<dyn BusDevice>>,
                0xae00,
                0x10,
            )
            .map_err(DeviceManagerError::BusError)?;

        Ok(device_manager)
    }

    fn add_migratable_device(&mut self, migratable_device: Arc<Mutex<dyn Migratable>>) {
        let id = migratable_device.lock().unwrap().id();
        self.migratable_devices.push((id, migratable_device));
    }

    #[allow(unused_variables)]
    fn add_pci_devices(
        &mut self,
        virtio_devices: Vec<(VirtioDeviceArc, bool, Option<String>)>,
    ) -> DeviceManagerResult<()> {
        #[cfg(feature = "pci_support")]
        {
            let pci_root = PciRoot::new(None);
            let mut pci_bus = PciBus::new(
                pci_root,
                Arc::clone(&self.address_manager) as Arc<dyn DeviceRelocation>,
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

            for (device, iommu_attached, id) in virtio_devices {
                let mapping: &Option<Arc<IommuMapping>> = if iommu_attached {
                    &iommu_mapping
                } else {
                    &None
                };

                let dev_id = self.add_virtio_pci_device(
                    device,
                    &mut pci_bus,
                    mapping,
                    &interrupt_manager,
                    id,
                )?;

                if iommu_attached {
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
                self.add_virtio_pci_device(
                    iommu_device,
                    &mut pci_bus,
                    &None,
                    &interrupt_manager,
                    None,
                )?;
            }

            let pci_bus = Arc::new(Mutex::new(pci_bus));
            let pci_config_io = Arc::new(Mutex::new(PciConfigIo::new(Arc::clone(&pci_bus))));
            self.bus_devices
                .push(Arc::clone(&pci_config_io) as Arc<Mutex<dyn BusDevice>>);
            self.address_manager
                .io_bus
                .insert(pci_config_io, 0xcf8, 0x8)
                .map_err(DeviceManagerError::BusError)?;
            let pci_config_mmio = Arc::new(Mutex::new(PciConfigMmio::new(Arc::clone(&pci_bus))));
            self.bus_devices
                .push(Arc::clone(&pci_config_mmio) as Arc<Mutex<dyn BusDevice>>);
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
        virtio_devices: Vec<(VirtioDeviceArc, bool, Option<String>)>,
        interrupt_manager: &Arc<dyn InterruptManager<GroupConfig = LegacyIrqGroupConfig>>,
    ) -> DeviceManagerResult<()> {
        #[cfg(feature = "mmio_support")]
        {
            for (device, _, _) in virtio_devices {
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

        self.bus_devices
            .push(Arc::clone(&acpi_device) as Arc<Mutex<dyn BusDevice>>);

        self.address_manager
            .allocator
            .lock()
            .unwrap()
            .allocate_io_addresses(Some(GuestAddress(0x3c0)), 0x8, None)
            .ok_or(DeviceManagerError::AllocateIOPort)?;

        self.address_manager
            .io_bus
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

        self.bus_devices
            .push(Arc::clone(&ged_device) as Arc<Mutex<dyn BusDevice>>);

        self.address_manager
            .allocator
            .lock()
            .unwrap()
            .allocate_io_addresses(Some(GuestAddress(0xb000)), 0x1, None)
            .ok_or(DeviceManagerError::AllocateIOPort)?;

        self.address_manager
            .io_bus
            .insert(ged_device.clone(), 0xb000, 0x1)
            .map_err(DeviceManagerError::BusError)?;
        Ok(Some(ged_device))
    }

    fn add_legacy_devices(&mut self, reset_evt: EventFd) -> DeviceManagerResult<()> {
        // Add a shutdown device (i8042)
        let i8042 = Arc::new(Mutex::new(devices::legacy::I8042Device::new(reset_evt)));

        self.bus_devices
            .push(Arc::clone(&i8042) as Arc<Mutex<dyn BusDevice>>);

        self.address_manager
            .io_bus
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

            self.bus_devices
                .push(Arc::clone(&cmos) as Arc<Mutex<dyn BusDevice>>);

            self.address_manager
                .io_bus
                .insert(cmos, 0x70, 0x2)
                .map_err(DeviceManagerError::BusError)?;
        }
        #[cfg(feature = "fwdebug")]
        {
            let fwdebug = Arc::new(Mutex::new(devices::legacy::FwDebugDevice::new()));

            self.bus_devices
                .push(Arc::clone(&fwdebug) as Arc<Mutex<dyn BusDevice>>);

            self.address_manager
                .io_bus
                .insert(fwdebug, 0x402, 0x1)
                .map_err(DeviceManagerError::BusError)?;
        }

        Ok(())
    }

    fn add_console_device(
        &mut self,
        interrupt_manager: &Arc<dyn InterruptManager<GroupConfig = LegacyIrqGroupConfig>>,
        virtio_devices: &mut Vec<(VirtioDeviceArc, bool, Option<String>)>,
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

            self.bus_devices
                .push(Arc::clone(&serial) as Arc<Mutex<dyn BusDevice>>);

            self.address_manager
                .allocator
                .lock()
                .unwrap()
                .allocate_io_addresses(Some(GuestAddress(0x3f8)), 0x8, None)
                .ok_or(DeviceManagerError::AllocateIOPort)?;

            self.address_manager
                .io_bus
                .insert(serial.clone(), 0x3f8, 0x8)
                .map_err(DeviceManagerError::BusError)?;

            self.add_migratable_device(Arc::clone(&serial) as Arc<Mutex<dyn Migratable>>);

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
                Arc::new(Mutex::new(virtio_console_device)) as VirtioDeviceArc,
                false,
                None,
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
        &mut self,
    ) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool, Option<String>)>> {
        let mut devices: Vec<(VirtioDeviceArc, bool, Option<String>)> = Vec::new();

        // Create "standard" virtio devices (net/block/rng)
        devices.append(&mut self.make_virtio_block_devices()?);
        devices.append(&mut self.make_virtio_net_devices()?);
        devices.append(&mut self.make_virtio_rng_devices()?);

        // Add virtio-fs if required
        devices.append(&mut self.make_virtio_fs_devices()?);

        // Add virtio-pmem if required
        devices.append(&mut self.make_virtio_pmem_devices()?);

        // Add virtio-vsock if required
        devices.append(&mut self.make_virtio_vsock_device()?);

        devices.append(&mut self.make_virtio_mem_devices()?);

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
                    disk_cfg
                        .path
                        .as_ref()
                        .ok_or(DeviceManagerError::NoDiskPath)?
                        .to_str()
                        .unwrap(),
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

    fn make_virtio_block_device(
        &mut self,
        disk_cfg: &mut DiskConfig,
    ) -> DeviceManagerResult<(VirtioDeviceArc, bool, Option<String>)> {
        if disk_cfg.id.is_none() {
            disk_cfg.id = self.next_device_name(DISK_DEVICE_NAME_PREFIX)?;
        }

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

            self.add_migratable_device(
                Arc::clone(&vhost_user_block_device) as Arc<Mutex<dyn Migratable>>
            );

            Ok((
                Arc::clone(&vhost_user_block_device) as VirtioDeviceArc,
                false,
                disk_cfg.id.clone(),
            ))
        } else {
            let mut options = OpenOptions::new();
            options.read(true);
            options.write(!disk_cfg.readonly);
            if disk_cfg.direct {
                options.custom_flags(libc::O_DIRECT);
            }
            // Open block device path
            let image: File = options
                .open(
                    disk_cfg
                        .path
                        .as_ref()
                        .ok_or(DeviceManagerError::NoDiskPath)?
                        .clone(),
                )
                .map_err(DeviceManagerError::Disk)?;

            let mut raw_img = vm_virtio::RawFile::new(image, disk_cfg.direct);

            let image_type = qcow::detect_image_type(&mut raw_img)
                .map_err(DeviceManagerError::DetectImageType)?;
            match image_type {
                ImageType::Raw => {
                    let dev = vm_virtio::Block::new(
                        raw_img,
                        disk_cfg
                            .path
                            .as_ref()
                            .ok_or(DeviceManagerError::NoDiskPath)?
                            .clone(),
                        disk_cfg.readonly,
                        disk_cfg.iommu,
                        disk_cfg.num_queues,
                        disk_cfg.queue_size,
                    )
                    .map_err(DeviceManagerError::CreateVirtioBlock)?;

                    let block = Arc::new(Mutex::new(dev));

                    self.add_migratable_device(Arc::clone(&block) as Arc<Mutex<dyn Migratable>>);

                    Ok((
                        Arc::clone(&block) as VirtioDeviceArc,
                        disk_cfg.iommu,
                        disk_cfg.id.clone(),
                    ))
                }
                ImageType::Qcow2 => {
                    let qcow_img =
                        QcowFile::from(raw_img).map_err(DeviceManagerError::QcowDeviceCreate)?;
                    let dev = vm_virtio::Block::new(
                        qcow_img,
                        disk_cfg
                            .path
                            .as_ref()
                            .ok_or(DeviceManagerError::NoDiskPath)?
                            .clone(),
                        disk_cfg.readonly,
                        disk_cfg.iommu,
                        disk_cfg.num_queues,
                        disk_cfg.queue_size,
                    )
                    .map_err(DeviceManagerError::CreateVirtioBlock)?;

                    let block = Arc::new(Mutex::new(dev));

                    self.add_migratable_device(Arc::clone(&block) as Arc<Mutex<dyn Migratable>>);

                    Ok((
                        Arc::clone(&block) as VirtioDeviceArc,
                        disk_cfg.iommu,
                        disk_cfg.id.clone(),
                    ))
                }
            }
        }
    }

    fn make_virtio_block_devices(
        &mut self,
    ) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool, Option<String>)>> {
        let mut devices = Vec::new();

        let mut block_devices = self.config.lock().unwrap().disks.clone();
        if let Some(disk_list_cfg) = &mut block_devices {
            for disk_cfg in disk_list_cfg.iter_mut() {
                devices.push(self.make_virtio_block_device(disk_cfg)?);
            }
        }
        self.config.lock().unwrap().disks = block_devices;

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

    fn make_virtio_net_device(
        &mut self,
        net_cfg: &mut NetConfig,
    ) -> DeviceManagerResult<(VirtioDeviceArc, bool, Option<String>)> {
        if net_cfg.id.is_none() {
            net_cfg.id = self.next_device_name(NET_DEVICE_NAME_PREFIX)?;
        }

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
            self.add_migratable_device(
                Arc::clone(&vhost_user_net_device) as Arc<Mutex<dyn Migratable>>
            );
            Ok((
                Arc::clone(&vhost_user_net_device) as VirtioDeviceArc,
                net_cfg.iommu,
                net_cfg.id.clone(),
            ))
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
            self.add_migratable_device(Arc::clone(&virtio_net_device) as Arc<Mutex<dyn Migratable>>);
            Ok((
                Arc::clone(&virtio_net_device) as VirtioDeviceArc,
                net_cfg.iommu,
                net_cfg.id.clone(),
            ))
        }
    }

    /// Add virto-net and vhost-user-net devices
    fn make_virtio_net_devices(
        &mut self,
    ) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool, Option<String>)>> {
        let mut devices = Vec::new();
        let mut net_devices = self.config.lock().unwrap().net.clone();
        if let Some(net_list_cfg) = &mut net_devices {
            for net_cfg in net_list_cfg.iter_mut() {
                devices.push(self.make_virtio_net_device(net_cfg)?);
            }
        }
        self.config.lock().unwrap().net = net_devices;

        Ok(devices)
    }

    fn make_virtio_rng_devices(
        &mut self,
    ) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool, Option<String>)>> {
        let mut devices = Vec::new();

        // Add virtio-rng if required
        let rng_config = self.config.lock().unwrap().rng.clone();
        if let Some(rng_path) = rng_config.src.to_str() {
            let virtio_rng_device = Arc::new(Mutex::new(
                vm_virtio::Rng::new(rng_path, rng_config.iommu)
                    .map_err(DeviceManagerError::CreateVirtioRng)?,
            ));
            devices.push((
                Arc::clone(&virtio_rng_device) as VirtioDeviceArc,
                false,
                None,
            ));

            self.add_migratable_device(
                Arc::clone(&virtio_rng_device) as Arc<Mutex<dyn Migratable>>
            );
        }

        Ok(devices)
    }

    fn make_virtio_fs_device(
        &mut self,
        fs_cfg: &FsConfig,
    ) -> DeviceManagerResult<(VirtioDeviceArc, bool, Option<String>)> {
        if let Some(fs_sock) = fs_cfg.sock.to_str() {
            let cache = if fs_cfg.dax {
                let fs_cache = fs_cfg.cache_size;
                // The memory needs to be 2MiB aligned in order to support
                // hugepages.
                let fs_guest_addr = self
                    .address_manager
                    .allocator
                    .lock()
                    .unwrap()
                    .allocate_mmio_addresses(None, fs_cache as GuestUsize, Some(0x0020_0000))
                    .ok_or(DeviceManagerError::FsRangeAllocation)?;

                let mmap_region = MmapRegion::build(
                    None,
                    fs_cache as usize,
                    libc::PROT_NONE,
                    libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                )
                .map_err(DeviceManagerError::NewMmapRegion)?;
                let host_addr: u64 = mmap_region.as_ptr() as u64;

                let mem_slot = self
                    .memory_manager
                    .lock()
                    .unwrap()
                    .create_userspace_mapping(
                        fs_guest_addr.raw_value(),
                        fs_cache,
                        host_addr,
                        false,
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
                        host_addr,
                        mem_slot,
                        addr: fs_guest_addr,
                        len: fs_cache as GuestUsize,
                        region_list,
                    },
                    mmap_region,
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

            self.add_migratable_device(Arc::clone(&virtio_fs_device) as Arc<Mutex<dyn Migratable>>);

            Ok((
                Arc::clone(&virtio_fs_device) as VirtioDeviceArc,
                false,
                None,
            ))
        } else {
            Err(DeviceManagerError::NoVirtioFsSock)
        }
    }

    fn make_virtio_fs_devices(
        &mut self,
    ) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool, Option<String>)>> {
        let mut devices = Vec::new();

        let fs_devices = self.config.lock().unwrap().fs.clone();
        if let Some(fs_list_cfg) = &fs_devices {
            for fs_cfg in fs_list_cfg.iter() {
                devices.push(self.make_virtio_fs_device(fs_cfg)?);
            }
        }

        Ok(devices)
    }

    fn make_virtio_pmem_device(
        &mut self,
        pmem_cfg: &mut PmemConfig,
    ) -> DeviceManagerResult<(VirtioDeviceArc, bool, Option<String>)> {
        if pmem_cfg.id.is_none() {
            pmem_cfg.id = self.next_device_name(PMEM_DEVICE_NAME_PREFIX)?;
        }

        let (custom_flags, set_len) = if pmem_cfg.file.is_dir() {
            if pmem_cfg.size.is_none() {
                return Err(DeviceManagerError::PmemWithDirectorySizeMissing);
            }
            (O_TMPFILE, true)
        } else {
            (0, false)
        };

        let mut file = OpenOptions::new()
            .read(true)
            .write(!pmem_cfg.discard_writes)
            .custom_flags(custom_flags)
            .open(&pmem_cfg.file)
            .map_err(DeviceManagerError::PmemFileOpen)?;

        let size = if let Some(size) = pmem_cfg.size {
            if set_len {
                file.set_len(size)
                    .map_err(DeviceManagerError::PmemFileSetLen)?;
            }
            size
        } else {
            file.seek(SeekFrom::End(0))
                .map_err(DeviceManagerError::PmemFileSetLen)?
        };

        if size % 0x20_0000 != 0 {
            return Err(DeviceManagerError::PmemSizeNotAligned);
        }

        // The memory needs to be 2MiB aligned in order to support
        // hugepages.
        let pmem_guest_addr = self
            .address_manager
            .allocator
            .lock()
            .unwrap()
            .allocate_mmio_addresses(None, size as GuestUsize, Some(0x0020_0000))
            .ok_or(DeviceManagerError::PmemRangeAllocation)?;

        let cloned_file = file.try_clone().map_err(DeviceManagerError::CloneFile)?;
        let mmap_region = MmapRegion::build(
            Some(FileOffset::new(cloned_file, 0)),
            size as usize,
            if pmem_cfg.discard_writes {
                PROT_READ
            } else {
                PROT_READ | PROT_WRITE
            },
            MAP_NORESERVE
                | if pmem_cfg.discard_writes {
                    MAP_PRIVATE
                } else {
                    MAP_SHARED
                },
        )
        .map_err(DeviceManagerError::NewMmapRegion)?;
        let host_addr: u64 = mmap_region.as_ptr() as u64;

        let mem_slot = self
            .memory_manager
            .lock()
            .unwrap()
            .create_userspace_mapping(
                pmem_guest_addr.raw_value(),
                size,
                host_addr,
                pmem_cfg.mergeable,
                pmem_cfg.discard_writes,
            )
            .map_err(DeviceManagerError::MemoryManager)?;

        let mapping = vm_virtio::UserspaceMapping {
            host_addr,
            mem_slot,
            addr: pmem_guest_addr,
            len: size,
            mergeable: pmem_cfg.mergeable,
        };

        let virtio_pmem_device = Arc::new(Mutex::new(
            vm_virtio::Pmem::new(file, pmem_guest_addr, mapping, mmap_region, pmem_cfg.iommu)
                .map_err(DeviceManagerError::CreateVirtioPmem)?,
        ));

        let migratable = Arc::clone(&virtio_pmem_device) as Arc<Mutex<dyn Migratable>>;
        let id = migratable.lock().unwrap().id();
        self.migratable_devices.push((id, migratable));

        Ok((
            Arc::clone(&virtio_pmem_device) as VirtioDeviceArc,
            false,
            pmem_cfg.id.clone(),
        ))
    }

    fn make_virtio_pmem_devices(
        &mut self,
    ) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool, Option<String>)>> {
        let mut devices = Vec::new();
        // Add virtio-pmem if required
        let mut pmem_devices = self.config.lock().unwrap().pmem.clone();
        if let Some(pmem_list_cfg) = &mut pmem_devices {
            for pmem_cfg in pmem_list_cfg.iter_mut() {
                devices.push(self.make_virtio_pmem_device(pmem_cfg)?);
            }
        }

        Ok(devices)
    }

    fn make_virtio_vsock_device(
        &mut self,
    ) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool, Option<String>)>> {
        let mut devices = Vec::new();
        // Add vsock if required
        if let Some(vsock_cfg) = &self.config.lock().unwrap().vsock {
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

            devices.push((Arc::clone(&vsock_device) as VirtioDeviceArc, false, None));

            let migratable = Arc::clone(&vsock_device) as Arc<Mutex<dyn Migratable>>;
            let id = migratable.lock().unwrap().id();
            self.migratable_devices.push((id, migratable));
        }

        Ok(devices)
    }

    fn make_virtio_mem_devices(
        &mut self,
    ) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool, Option<String>)>> {
        let mut devices = Vec::new();

        let mm = &self.memory_manager.lock().unwrap();
        if let (Some(region), Some(resize)) = (&mm.virtiomem_region, &mm.virtiomem_resize) {
            let virtio_mem_device = Arc::new(Mutex::new(
                vm_virtio::Mem::new(
                    &region,
                    resize
                        .try_clone()
                        .map_err(DeviceManagerError::TryCloneVirtioMemResize)?,
                )
                .map_err(DeviceManagerError::CreateVirtioMem)?,
            ));

            devices.push((
                Arc::clone(&virtio_mem_device) as VirtioDeviceArc,
                false,
                None,
            ));

            let migratable = Arc::clone(&virtio_mem_device) as Arc<Mutex<dyn Migratable>>;
            let id = migratable.lock().unwrap().id();
            self.migratable_devices.push((id, migratable));
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

    #[cfg(not(feature = "pci_support"))]
    fn next_device_name(&mut self, _prefix: &str) -> DeviceManagerResult<Option<String>> {
        Ok(None)
    }

    #[cfg(feature = "pci_support")]
    fn next_device_name(&mut self, prefix: &str) -> DeviceManagerResult<Option<String>> {
        let start_id = self.device_id_cnt;
        loop {
            // Generate the temporary name.
            let name = format!("{}{}", prefix, self.device_id_cnt);
            // Increment the counter.
            self.device_id_cnt += Wrapping(1);
            // Check if the name is already in use.
            if !self.pci_id_list.contains_key(&name) {
                return Ok(Some(name));
            }

            if self.device_id_cnt == start_id {
                // We went through a full loop and there's nothing else we can
                // do.
                break;
            }
        }
        Err(DeviceManagerError::NoAvailableDeviceName)
    }

    #[cfg(feature = "pci_support")]
    fn add_vfio_device(
        &mut self,
        pci: &mut PciBus,
        interrupt_manager: &Arc<dyn InterruptManager<GroupConfig = MsiIrqGroupConfig>>,
        device_fd: &Arc<DeviceFd>,
        device_cfg: &mut DeviceConfig,
    ) -> DeviceManagerResult<u32> {
        // We need to shift the device id since the 3 first bits
        // are dedicated to the PCI function, and we know we don't
        // do multifunction. Also, because we only support one PCI
        // bus, the bus 0, we don't need to add anything to the
        // global device ID.
        let pci_device_bdf = pci
            .next_device_id()
            .map_err(DeviceManagerError::NextPciDeviceId)?
            << 3;

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
                    .add_external_mapping(pci_device_bdf, vfio_mapping);
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

        pci.add_device(pci_device_bdf, vfio_pci_device.clone())
            .map_err(DeviceManagerError::AddPciDevice)?;

        self.pci_devices.insert(
            pci_device_bdf,
            Arc::clone(&vfio_pci_device) as Arc<dyn Any + Send + Sync>,
        );
        self.bus_devices
            .push(Arc::clone(&vfio_pci_device) as Arc<Mutex<dyn BusDevice>>);

        pci.register_mapping(
            vfio_pci_device,
            self.address_manager.io_bus.as_ref(),
            self.address_manager.mmio_bus.as_ref(),
            bars,
        )
        .map_err(DeviceManagerError::AddPciDevice)?;

        let vfio_name = if let Some(id) = &device_cfg.id {
            if self.pci_id_list.contains_key(id) {
                return Err(DeviceManagerError::DeviceIdAlreadyInUse);
            }

            id.clone()
        } else {
            let id = self.next_device_name(VFIO_DEVICE_NAME_PREFIX)?;
            device_cfg.id = id.clone();
            id.unwrap()
        };
        self.pci_id_list.insert(vfio_name, pci_device_bdf);

        Ok(pci_device_bdf)
    }

    #[cfg(feature = "pci_support")]
    fn add_vfio_devices(
        &mut self,
        pci: &mut PciBus,
        interrupt_manager: &Arc<dyn InterruptManager<GroupConfig = MsiIrqGroupConfig>>,
    ) -> DeviceManagerResult<Vec<u32>> {
        let mut iommu_attached_device_ids = Vec::new();
        let mut devices = self.config.lock().unwrap().devices.clone();

        if let Some(device_list_cfg) = &mut devices {
            // Create the KVM VFIO device
            let device_fd = DeviceManager::create_kvm_device(&self.address_manager.vm_fd)?;
            let device_fd = Arc::new(device_fd);
            self.kvm_device_fd = Some(Arc::clone(&device_fd));

            for device_cfg in device_list_cfg.iter_mut() {
                let device_id =
                    self.add_vfio_device(pci, interrupt_manager, &device_fd, device_cfg)?;
                if device_cfg.iommu && self.iommu_device.is_some() {
                    iommu_attached_device_ids.push(device_id);
                }
            }
        }

        // Update the list of devices
        self.config.lock().unwrap().devices = devices;

        Ok(iommu_attached_device_ids)
    }

    #[cfg(feature = "pci_support")]
    fn add_virtio_pci_device(
        &mut self,
        virtio_device: VirtioDeviceArc,
        pci: &mut PciBus,
        iommu_mapping: &Option<Arc<IommuMapping>>,
        interrupt_manager: &Arc<dyn InterruptManager<GroupConfig = MsiIrqGroupConfig>>,
        id: Option<String>,
    ) -> DeviceManagerResult<u32> {
        // Allows support for one MSI-X vector per queue. It also adds 1
        // as we need to take into account the dedicated vector to notify
        // about a virtio config change.
        let msix_num = (virtio_device.lock().unwrap().queue_max_sizes().len() + 1) as u16;

        // We need to shift the device id since the 3 first bits are dedicated
        // to the PCI function, and we know we don't do multifunction.
        // Also, because we only support one PCI bus, the bus 0, we don't need
        // to add anything to the global device ID.
        let pci_device_bdf = pci
            .next_device_id()
            .map_err(DeviceManagerError::NextPciDeviceId)?
            << 3;

        // Create the callback from the implementation of the DmaRemapping
        // trait. The point with the callback is to simplify the code as we
        // know about the device ID from this point.
        let iommu_mapping_cb: Option<Arc<VirtioIommuRemapping>> =
            if let Some(mapping) = iommu_mapping {
                let mapping_clone = mapping.clone();
                Some(Arc::new(Box::new(move |addr: u64| {
                    mapping_clone.translate(pci_device_bdf, addr).map_err(|e| {
                        std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!(
                                "failed to translate addr 0x{:x} for device 00:{:02x}.0 {}",
                                addr, pci_device_bdf, e
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

        pci.add_device(pci_device_bdf, virtio_pci_device.clone())
            .map_err(DeviceManagerError::AddPciDevice)?;
        self.pci_devices.insert(
            pci_device_bdf,
            Arc::clone(&virtio_pci_device) as Arc<dyn Any + Send + Sync>,
        );
        self.bus_devices
            .push(Arc::clone(&virtio_pci_device) as Arc<Mutex<dyn BusDevice>>);

        if let Some(id) = id {
            if self.pci_id_list.contains_key(&id) {
                return Err(DeviceManagerError::DeviceIdAlreadyInUse);
            }
            self.pci_id_list.insert(id, pci_device_bdf);
        }

        pci.register_mapping(
            virtio_pci_device.clone(),
            self.address_manager.io_bus.as_ref(),
            self.address_manager.mmio_bus.as_ref(),
            bars,
        )
        .map_err(DeviceManagerError::AddPciDevice)?;

        let migratable = Arc::clone(&virtio_pci_device) as Arc<Mutex<dyn Migratable>>;
        let id = migratable.lock().unwrap().id();
        self.migratable_devices.push((id, migratable));

        Ok(pci_device_bdf)
    }

    #[cfg(feature = "mmio_support")]
    fn add_virtio_mmio_device(
        &mut self,
        virtio_device: VirtioDeviceArc,
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
        self.bus_devices
            .push(Arc::clone(&mmio_device_arc) as Arc<Mutex<dyn BusDevice>>);
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

        self.add_migratable_device(Arc::clone(&mmio_device_arc) as Arc<Mutex<dyn Migratable>>);

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

    pub fn update_memory(&self, _new_region: &Arc<GuestRegionMmap>) -> DeviceManagerResult<()> {
        let memory = self.memory_manager.lock().unwrap().guest_memory();
        for (virtio_device, _, _) in self.virtio_devices.iter() {
            virtio_device
                .lock()
                .unwrap()
                .update_memory(&memory.memory())
                .map_err(DeviceManagerError::UpdateMemoryForVirtioDevice)?;
        }

        // Take care of updating the memory for VFIO PCI devices.
        #[cfg(feature = "pci_support")]
        {
            for (_, any_device) in self.pci_devices.iter() {
                if let Ok(vfio_pci_device) =
                    Arc::clone(any_device).downcast::<Mutex<VfioPciDevice>>()
                {
                    vfio_pci_device
                        .lock()
                        .unwrap()
                        .update_memory(_new_region)
                        .map_err(DeviceManagerError::UpdateMemoryForVfioPciDevice)?;
                }
            }
        }

        Ok(())
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
    pub fn add_device(&mut self, device_cfg: &mut DeviceConfig) -> DeviceManagerResult<()> {
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
            device_cfg,
        )?;

        // Update the PCIU bitmap
        self.pci_devices_up |= 1 << (device_id >> 3);

        Ok(())
    }

    #[cfg(feature = "pci_support")]
    pub fn remove_device(&mut self, id: String) -> DeviceManagerResult<()> {
        if let Some(pci_device_bdf) = self.pci_id_list.get(&id) {
            // Update the PCID bitmap
            self.pci_devices_down |= 1 << (*pci_device_bdf >> 3);

            Ok(())
        } else {
            Err(DeviceManagerError::UnknownVfioDeviceId(id))
        }
    }

    #[cfg(feature = "pci_support")]
    pub fn eject_device(&mut self, device_id: u8) -> DeviceManagerResult<()> {
        // Retrieve the PCI bus.
        let pci = if let Some(pci_bus) = &self.pci_bus {
            Arc::clone(&pci_bus)
        } else {
            return Err(DeviceManagerError::NoPciBus);
        };

        // Convert the device ID into the corresponding b/d/f.
        let pci_device_bdf = (device_id as u32) << 3;

        // Find the device name corresponding to the PCI b/d/f while removing
        // the device entry.
        self.pci_id_list.retain(|_, bdf| *bdf != pci_device_bdf);

        // Give the PCI device ID back to the PCI bus.
        pci.lock()
            .unwrap()
            .put_device_id(device_id as usize)
            .map_err(DeviceManagerError::PutPciDeviceId)?;

        if let Some(any_device) = self.pci_devices.remove(&pci_device_bdf) {
            let (pci_device, bus_device, migratable_device, virtio_device) = if let Ok(
                vfio_pci_device,
            ) =
                any_device.clone().downcast::<Mutex<VfioPciDevice>>()
            {
                (
                    Arc::clone(&vfio_pci_device) as Arc<Mutex<dyn PciDevice>>,
                    Arc::clone(&vfio_pci_device) as Arc<Mutex<dyn BusDevice>>,
                    None as Option<Arc<Mutex<dyn Migratable>>>,
                    None as Option<VirtioDeviceArc>,
                )
            } else if let Ok(virtio_pci_device) = any_device.downcast::<Mutex<VirtioPciDevice>>() {
                let bar_addr = virtio_pci_device.lock().unwrap().config_bar_addr();
                for (event, addr) in virtio_pci_device.lock().unwrap().ioeventfds(bar_addr) {
                    let io_addr = IoEventAddress::Mmio(addr);
                    self.address_manager
                        .vm_fd
                        .unregister_ioevent(event, &io_addr)
                        .map_err(DeviceManagerError::UnRegisterIoevent)?;
                }

                (
                    Arc::clone(&virtio_pci_device) as Arc<Mutex<dyn PciDevice>>,
                    Arc::clone(&virtio_pci_device) as Arc<Mutex<dyn BusDevice>>,
                    Some(Arc::clone(&virtio_pci_device) as Arc<Mutex<dyn Migratable>>),
                    Some(virtio_pci_device.lock().unwrap().virtio_device()),
                )
            } else {
                return Ok(());
            };

            // Free the allocated BARs
            pci_device
                .lock()
                .unwrap()
                .free_bars(&mut self.address_manager.allocator.lock().unwrap())
                .map_err(DeviceManagerError::FreePciBars)?;

            // Remove the device from the PCI bus
            pci.lock()
                .unwrap()
                .remove_by_device(&pci_device)
                .map_err(DeviceManagerError::RemoveDeviceFromPciBus)?;

            // Remove the device from the IO bus
            self.io_bus()
                .remove_by_device(&bus_device)
                .map_err(DeviceManagerError::RemoveDeviceFromIoBus)?;

            // Remove the device from the MMIO bus
            self.mmio_bus()
                .remove_by_device(&bus_device)
                .map_err(DeviceManagerError::RemoveDeviceFromMmioBus)?;

            // Remove the device from the list of BusDevice held by the
            // DeviceManager.
            self.bus_devices
                .retain(|dev| !Arc::ptr_eq(dev, &bus_device));

            // Remove the device from the list of Migratable devices.
            if let Some(migratable_device) = &migratable_device {
                let id = migratable_device.lock().unwrap().id();
                self.migratable_devices.retain(|(i, _)| *i != id);
            }

            // Shutdown and remove the underlying virtio-device if present
            if let Some(virtio_device) = virtio_device {
                for mapping in virtio_device.lock().unwrap().userspace_mappings() {
                    self.memory_manager
                        .lock()
                        .unwrap()
                        .remove_userspace_mapping(
                            mapping.addr.raw_value(),
                            mapping.len,
                            mapping.host_addr,
                            mapping.mergeable,
                            mapping.mem_slot,
                        )
                        .map_err(DeviceManagerError::MemoryManager)?;
                }

                virtio_device.lock().unwrap().shutdown();

                self.virtio_devices
                    .retain(|(d, _, _)| !Arc::ptr_eq(d, &virtio_device));
            }

            // At this point, the device has been removed from all the list and
            // buses where it was stored. At the end of this function, after
            // any_device, bus_device and pci_device are released, the actual
            // device will be dropped.

            Ok(())
        } else {
            Err(DeviceManagerError::MissingPciDevice)
        }
    }

    #[cfg(feature = "pci_support")]
    fn hotplug_virtio_pci_device(
        &mut self,
        device: VirtioDeviceArc,
        iommu_attached: bool,
        id: Option<String>,
    ) -> DeviceManagerResult<()> {
        if iommu_attached {
            warn!("Placing device behind vIOMMU is not available for hotplugged devices");
        }

        let pci = if let Some(pci_bus) = &self.pci_bus {
            Arc::clone(&pci_bus)
        } else {
            return Err(DeviceManagerError::NoPciBus);
        };

        let interrupt_manager = Arc::clone(&self.msi_interrupt_manager);

        // Add the virtio device to the device manager list. This is important
        // as the list is used to notify virtio devices about memory updates
        // for instance.
        self.virtio_devices
            .push((device.clone(), iommu_attached, id.clone()));

        let device_id = self.add_virtio_pci_device(
            device,
            &mut pci.lock().unwrap(),
            &None,
            &interrupt_manager,
            id,
        )?;

        // Update the PCIU bitmap
        self.pci_devices_up |= 1 << (device_id >> 3);

        Ok(())
    }

    #[cfg(feature = "pci_support")]
    pub fn add_disk(&mut self, disk_cfg: &mut DiskConfig) -> DeviceManagerResult<()> {
        let (device, iommu_attached, id) = self.make_virtio_block_device(disk_cfg)?;
        self.hotplug_virtio_pci_device(device, iommu_attached, id)
    }

    #[cfg(feature = "pci_support")]
    pub fn add_fs(&mut self, fs_cfg: &mut FsConfig) -> DeviceManagerResult<()> {
        let (device, iommu_attached, id) = self.make_virtio_fs_device(fs_cfg)?;
        self.hotplug_virtio_pci_device(device, iommu_attached, id)
    }

    #[cfg(feature = "pci_support")]
    pub fn add_pmem(&mut self, pmem_cfg: &mut PmemConfig) -> DeviceManagerResult<()> {
        let (device, iommu_attached, id) = self.make_virtio_pmem_device(pmem_cfg)?;
        self.hotplug_virtio_pci_device(device, iommu_attached, id)
    }

    #[cfg(feature = "pci_support")]
    pub fn add_net(&mut self, net_cfg: &mut NetConfig) -> DeviceManagerResult<()> {
        let (device, iommu_attached, id) = self.make_virtio_net_device(net_cfg)?;
        self.hotplug_virtio_pci_device(device, iommu_attached, id)
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
        for (_, dev) in self.migratable_devices.iter() {
            dev.lock().unwrap().pause()?;
        }

        Ok(())
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        for (_, dev) in self.migratable_devices.iter() {
            dev.lock().unwrap().resume()?;
        }

        Ok(())
    }
}

impl Snapshottable for DeviceManager {
    fn id(&self) -> String {
        DEVICE_MANAGER_SNAPSHOT_ID.to_string()
    }

    fn snapshot(&self) -> std::result::Result<Snapshot, MigratableError> {
        let mut snapshot = Snapshot::new(DEVICE_MANAGER_SNAPSHOT_ID);

        // We aggregate all devices snapshot.
        for (_, dev) in self.migratable_devices.iter() {
            let device_snapshot = dev.lock().unwrap().snapshot()?;
            snapshot.add_snapshot(device_snapshot);
        }

        Ok(snapshot)
    }

    fn restore(&mut self, snapshot: Snapshot) -> std::result::Result<(), MigratableError> {
        for (id, dev) in self.migratable_devices.iter() {
            debug!("Restoring {} from DeviceManager", id);
            if let Some(snapshot) = snapshot.snapshots.get(id) {
                dev.lock().unwrap().restore(*snapshot.clone())?;
            } else {
                return Err(MigratableError::Restore(anyhow!("Missing device {}", id)));
            }
        }

        Ok(())
    }
}

impl Transportable for DeviceManager {}
impl Migratable for DeviceManager {}

#[cfg(feature = "pci_support")]
const PCIU_FIELD_OFFSET: u64 = 0;
#[cfg(feature = "pci_support")]
const PCID_FIELD_OFFSET: u64 = 4;
#[cfg(feature = "pci_support")]
const B0EJ_FIELD_OFFSET: u64 = 8;

#[cfg(feature = "pci_support")]
const PCIU_FIELD_SIZE: usize = 4;
#[cfg(feature = "pci_support")]
const PCID_FIELD_SIZE: usize = 4;
#[cfg(feature = "pci_support")]
const B0EJ_FIELD_SIZE: usize = 4;

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
            _ => error!(
                "Accessing unknown location at base 0x{:x}, offset 0x{:x}",
                base, offset
            ),
        }

        debug!(
            "PCI_HP_REG_R: base 0x{:x}, offset 0x{:x}, data {:?}",
            base, offset, data
        )
    }

    fn write(&mut self, base: u64, offset: u64, data: &[u8]) {
        #[cfg(feature = "pci_support")]
        match offset {
            B0EJ_FIELD_OFFSET => {
                assert!(data.len() == B0EJ_FIELD_SIZE);
                let mut data_array: [u8; 4] = [0, 0, 0, 0];
                data_array.copy_from_slice(&data[..]);
                let device_bitmap = u32::from_le_bytes(data_array);

                for device_id in 0..32 {
                    let mask = 1u32 << device_id;
                    if (device_bitmap & mask) == mask {
                        if let Err(e) = self.eject_device(device_id as u8) {
                            error!("Failed ejecting device {}: {:?}", device_id, e);
                        }
                    }
                }
            }
            _ => error!(
                "Accessing unknown location at base 0x{:x}, offset 0x{:x}",
                base, offset
            ),
        }

        debug!(
            "PCI_HP_REG_W: base 0x{:x}, offset 0x{:x}, data {:?}",
            base, offset, data
        )
    }
}

impl Drop for DeviceManager {
    fn drop(&mut self) {
        for (device, _, _) in self.virtio_devices.drain(..) {
            device.lock().unwrap().shutdown();
        }
    }
}
