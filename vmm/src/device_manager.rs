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

use crate::config::ConsoleOutputMode;
use crate::vm::VmInfo;

use devices::ioapic;
use kvm_bindings::kvm_userspace_memory_region;
use kvm_ioctls::*;
use libc::O_TMPFILE;
use libc::{EFD_NONBLOCK, TIOCGWINSZ};

use net_util::Tap;
#[cfg(feature = "pci_support")]
use pci::{
    InterruptDelivery, InterruptParameters, PciBus, PciConfigIo, PciConfigMmio, PciDevice,
    PciInterruptPin, PciRoot,
};
use qcow::{self, ImageType, QcowFile};

use std::fs::{File, OpenOptions};
use std::io::{self, sink, stdout};

use arch::layout::{APIC_START, IOAPIC_SIZE, IOAPIC_START};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::ptr::null_mut;
use std::result;
use std::sync::{Arc, Mutex, RwLock};
#[cfg(feature = "pci_support")]
use vfio::{VfioDevice, VfioPciDevice, VfioPciError};
use vm_allocator::SystemAllocator;
#[cfg(feature = "mmio_support")]
use vm_memory::GuestAddress;
use vm_memory::{Address, GuestMemoryMmap, GuestUsize};
#[cfg(feature = "pci_support")]
use vm_virtio::transport::VirtioPciDevice;
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
    Irq(io::Error),

    /// Cannot allocate PCI BARs
    #[cfg(feature = "pci_support")]
    AllocateBars(pci::PciDeviceError),

    /// Cannot register ioevent.
    RegisterIoevent(io::Error),

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
    CreateKvmDevice(io::Error),

    /// Failed to memory map.
    Mmap(io::Error),

    /// Cannot add legacy device to Bus.
    BusError(devices::BusError),
}
pub type DeviceManagerResult<T> = result::Result<T, DeviceManagerError>;

struct BusInfo<'a> {
    io: &'a mut devices::Bus,
    mmio: &'a mut devices::Bus,
}

struct InterruptInfo<'a> {
    _msi_capable: bool,
    ioapic: &'a Option<Arc<Mutex<ioapic::Ioapic>>>,
}

struct KernelIoapicIrq {
    evt: EventFd,
}

impl KernelIoapicIrq {
    fn new(evt: EventFd) -> Self {
        KernelIoapicIrq { evt }
    }
}

impl devices::Interrupt for KernelIoapicIrq {
    fn deliver(&self) -> result::Result<(), io::Error> {
        self.evt.write(1)
    }
}

struct UserIoapicIrq {
    ioapic: Arc<Mutex<ioapic::Ioapic>>,
    irq: usize,
}

impl UserIoapicIrq {
    fn new(ioapic: Arc<Mutex<ioapic::Ioapic>>, irq: usize) -> Self {
        UserIoapicIrq { ioapic, irq }
    }
}

impl devices::Interrupt for UserIoapicIrq {
    fn deliver(&self) -> result::Result<(), io::Error> {
        self.ioapic
            .lock()
            .unwrap()
            .service_irq(self.irq)
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to inject IRQ #{}: {:?}", self.irq, e),
                )
            })
    }
}

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

pub struct DeviceManager {
    io_bus: devices::Bus,
    mmio_bus: devices::Bus,

    // Console abstraction
    console: Arc<Console>,

    // IOAPIC
    ioapic: Option<Arc<Mutex<ioapic::Ioapic>>>,

    // mmap()ed region to unmap on drop
    mmap_regions: Vec<(*mut libc::c_void, usize)>,

    // Things to be added to the commandline (i.e. for virtio-mmio)
    cmdline_additions: Vec<String>,

    // Virtual IOMMU ID along with the list of device IDs attached to the
    // virtual IOMMU. This is useful for filling the ACPI IORT table.
    virt_iommu: Option<(u32, Vec<u32>)>,
}

impl DeviceManager {
    pub fn new(
        vm_info: &VmInfo,
        allocator: &mut SystemAllocator,
        _msi_capable: bool,
        userspace_ioapic: bool,
        mut mem_slots: u32,
        _exit_evt: &EventFd,
        reset_evt: &EventFd,
    ) -> DeviceManagerResult<Self> {
        let mut io_bus = devices::Bus::new();
        let mut mmio_bus = devices::Bus::new();

        let mut buses = BusInfo {
            io: &mut io_bus,
            mmio: &mut mmio_bus,
        };

        let ioapic = if userspace_ioapic {
            // Create IOAPIC
            let ioapic = Arc::new(Mutex::new(ioapic::Ioapic::new(
                vm_info.vm_fd.clone(),
                APIC_START,
            )));
            buses
                .mmio
                .insert(ioapic.clone(), IOAPIC_START.0, IOAPIC_SIZE)
                .map_err(DeviceManagerError::BusError)?;
            Some(ioapic)
        } else {
            None
        };

        let interrupt_info = InterruptInfo {
            _msi_capable,
            ioapic: &ioapic,
        };

        let serial_writer: Option<Box<dyn io::Write + Send>> = match vm_info.vm_cfg.serial.mode {
            ConsoleOutputMode::File => Some(Box::new(
                File::create(vm_info.vm_cfg.serial.file.as_ref().unwrap())
                    .map_err(DeviceManagerError::SerialOutputFileOpen)?,
            )),
            ConsoleOutputMode::Tty => Some(Box::new(stdout())),
            ConsoleOutputMode::Off | ConsoleOutputMode::Null => None,
        };
        let serial = if vm_info.vm_cfg.serial.mode != ConsoleOutputMode::Off {
            // Serial is tied to IRQ #4
            let serial_irq = 4;
            let interrupt: Box<dyn devices::Interrupt> = if let Some(ioapic) = &ioapic {
                Box::new(UserIoapicIrq::new(ioapic.clone(), serial_irq))
            } else {
                let serial_evt = EventFd::new(EFD_NONBLOCK).map_err(DeviceManagerError::EventFd)?;
                vm_info
                    .vm_fd
                    .register_irqfd(serial_evt.as_raw_fd(), serial_irq as u32)
                    .map_err(DeviceManagerError::Irq)?;

                Box::new(KernelIoapicIrq::new(serial_evt))
            };

            let serial = Arc::new(Mutex::new(devices::legacy::Serial::new(
                interrupt,
                serial_writer,
            )));

            buses
                .io
                .insert(serial.clone(), 0x3f8, 0x8)
                .map_err(DeviceManagerError::BusError)?;

            Some(serial)
        } else {
            None
        };

        // Add a shutdown device (i8042)
        let i8042 = Arc::new(Mutex::new(devices::legacy::I8042Device::new(
            reset_evt.try_clone().map_err(DeviceManagerError::EventFd)?,
        )));
        buses
            .io
            .insert(i8042.clone(), 0x61, 0x4)
            .map_err(DeviceManagerError::BusError)?;
        #[cfg(feature = "cmos")]
        {
            use vm_memory::GuestMemory;
            let mem_size = vm_info.memory.as_ref().read().unwrap().end_addr().0 + 1;
            let mem_below_4g = std::cmp::min(arch::layout::MEM_32BIT_RESERVED_START.0, mem_size);
            let mem_above_4g = mem_size.saturating_sub(arch::layout::RAM_64BIT_START.0);

            let cmos = Arc::new(Mutex::new(devices::legacy::Cmos::new(
                mem_below_4g,
                mem_above_4g,
            )));
            buses
                .io
                .insert(cmos.clone(), 0x70, 0x2)
                .map_err(DeviceManagerError::BusError)?;
        }
        #[cfg(feature = "acpi")]
        {
            let acpi_device = Arc::new(Mutex::new(devices::AcpiShutdownDevice::new(
                _exit_evt.try_clone().map_err(DeviceManagerError::EventFd)?,
                reset_evt.try_clone().map_err(DeviceManagerError::EventFd)?,
            )));
            buses
                .io
                .insert(acpi_device.clone(), 0x3c0, 0x4)
                .map_err(DeviceManagerError::BusError)?;
        }

        let mut virtio_devices: Vec<(Box<dyn vm_virtio::VirtioDevice>, bool)> = Vec::new();

        // Create serial and virtio-console
        let console_writer: Option<Box<dyn io::Write + Send + Sync>> =
            match vm_info.vm_cfg.console.mode {
                ConsoleOutputMode::File => Some(Box::new(
                    File::create(vm_info.vm_cfg.console.file.as_ref().unwrap())
                        .map_err(DeviceManagerError::ConsoleOutputFileOpen)?,
                )),
                ConsoleOutputMode::Tty => Some(Box::new(stdout())),
                ConsoleOutputMode::Null => Some(Box::new(sink())),
                ConsoleOutputMode::Off => None,
            };
        let (col, row) = get_win_size();
        let console_input = if let Some(writer) = console_writer {
            let (virtio_console_device, console_input) =
                vm_virtio::Console::new(writer, col, row, vm_info.vm_cfg.console.iommu)
                    .map_err(DeviceManagerError::CreateVirtioConsole)?;
            virtio_devices.push((
                Box::new(virtio_console_device) as Box<dyn vm_virtio::VirtioDevice>,
                false,
            ));
            Some(console_input)
        } else {
            None
        };

        let console = Arc::new(Console {
            serial,
            console_input,
            input_enabled: vm_info.vm_cfg.serial.mode.input_enabled()
                || vm_info.vm_cfg.console.mode.input_enabled(),
        });

        let mut mmap_regions = Vec::new();

        virtio_devices.append(&mut DeviceManager::make_virtio_devices(
            vm_info,
            allocator,
            &mut mem_slots,
            &mut mmap_regions,
        )?);

        #[allow(unused_mut)]
        let mut cmdline_additions = Vec::new();

        #[allow(unused_mut)]
        let mut virt_iommu: Option<(u32, Vec<u32>)> = None;

        if cfg!(feature = "pci_support") {
            #[cfg(feature = "pci_support")]
            {
                let pci_root = PciRoot::new(None);
                let mut pci_bus = PciBus::new(pci_root);

                let (iommu_mapping, iommu_id) = if vm_info.vm_cfg.iommu {
                    let (iommu_device, mapping) =
                        vm_virtio::Iommu::new().map_err(DeviceManagerError::CreateVirtioIommu)?;

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
                        Box::new(iommu_device),
                        vm_info.memory,
                        allocator,
                        vm_info.vm_fd,
                        &mut pci_bus,
                        &mut buses,
                        &interrupt_info,
                        &None,
                    )?;

                    (Some(mapping), Some(iommu_id))
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
                        allocator,
                        vm_info.vm_fd,
                        &mut pci_bus,
                        &mut buses,
                        &interrupt_info,
                        mapping,
                    )?;

                    if let Some(dev_id) = virtio_iommu_attach_dev {
                        iommu_attached_devices.push(dev_id);
                    }
                }

                let mut iommu_attached_vfio_devices = DeviceManager::add_vfio_devices(
                    vm_info,
                    allocator,
                    &mut pci_bus,
                    &mut buses,
                    mem_slots,
                )?;

                iommu_attached_devices.append(&mut iommu_attached_vfio_devices);

                if let Some(iommu_id) = iommu_id {
                    virt_iommu = Some((iommu_id, iommu_attached_devices));
                }

                let pci_bus = Arc::new(Mutex::new(pci_bus));
                let pci_config_io = Arc::new(Mutex::new(PciConfigIo::new(pci_bus.clone())));
                io_bus
                    .insert(pci_config_io, 0xcf8, 0x8)
                    .map_err(DeviceManagerError::BusError)?;
                let pci_config_mmio = Arc::new(Mutex::new(PciConfigMmio::new(pci_bus)));
                mmio_bus
                    .insert(
                        pci_config_mmio,
                        arch::layout::PCI_MMCONFIG_START.0,
                        arch::layout::PCI_MMCONFIG_SIZE,
                    )
                    .map_err(DeviceManagerError::BusError)?;
            }
        } else if cfg!(feature = "mmio_support") {
            #[cfg(feature = "mmio_support")]
            {
                for (device, _) in virtio_devices {
                    if let Some(addr) =
                        allocator.allocate_mmio_addresses(None, MMIO_LEN, Some(MMIO_LEN))
                    {
                        DeviceManager::add_virtio_mmio_device(
                            device,
                            vm_info.memory,
                            allocator,
                            vm_info.vm_fd,
                            &mut buses,
                            &interrupt_info,
                            addr,
                            &mut cmdline_additions,
                        )?;
                    } else {
                        error!("Unable to allocate MMIO address!");
                    }
                }
            }
        }

        Ok(DeviceManager {
            io_bus,
            mmio_bus,
            console,
            ioapic,
            mmap_regions,
            cmdline_additions,
            virt_iommu,
        })
    }

    fn make_virtio_devices(
        vm_info: &VmInfo,
        allocator: &mut SystemAllocator,
        mut mem_slots: &mut u32,
        mmap_regions: &mut Vec<(*mut libc::c_void, usize)>,
    ) -> DeviceManagerResult<Vec<(Box<dyn vm_virtio::VirtioDevice>, bool)>> {
        let mut devices: Vec<(Box<dyn vm_virtio::VirtioDevice>, bool)> = Vec::new();

        // Create "standard" virtio devices (net/block/rng)
        devices.append(&mut DeviceManager::make_virtio_block_devices(vm_info)?);
        devices.append(&mut DeviceManager::make_virtio_net_devices(vm_info)?);
        devices.append(&mut DeviceManager::make_virtio_rng_devices(vm_info)?);

        // Add virtio-fs if required
        devices.append(&mut DeviceManager::make_virtio_fs_devices(
            vm_info,
            allocator,
            &mut mem_slots,
            mmap_regions,
        )?);

        // Add virtio-pmem if required
        devices.append(&mut DeviceManager::make_virtio_pmem_devices(
            vm_info,
            allocator,
            &mut mem_slots,
            mmap_regions,
        )?);

        // Add virtio-vhost-user-net if required
        devices.append(&mut DeviceManager::make_virtio_vhost_user_net_devices(
            vm_info,
        )?);

        // Add virtio-vhost-user-blk if required
        devices.append(&mut DeviceManager::make_virtio_vhost_user_blk_devices(
            vm_info,
        )?);

        // Add virtio-vsock if required
        devices.append(&mut DeviceManager::make_virtio_vsock_devices(vm_info)?);

        Ok(devices)
    }

    fn make_virtio_block_devices(
        vm_info: &VmInfo,
    ) -> DeviceManagerResult<Vec<(Box<dyn vm_virtio::VirtioDevice>, bool)>> {
        let mut devices = Vec::new();

        if let Some(disk_list_cfg) = &vm_info.vm_cfg.disks {
            for disk_cfg in disk_list_cfg.iter() {
                // Open block device path
                let raw_img: File = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&disk_cfg.path)
                    .map_err(DeviceManagerError::Disk)?;

                let image_type = qcow::detect_image_type(&raw_img)
                    .map_err(DeviceManagerError::DetectImageType)?;
                let block = match image_type {
                    ImageType::Raw => {
                        let raw_img = vm_virtio::RawFile::new(raw_img);
                        let dev = vm_virtio::Block::new(
                            raw_img,
                            disk_cfg.path.clone(),
                            false,
                            disk_cfg.iommu,
                        )
                        .map_err(DeviceManagerError::CreateVirtioBlock)?;
                        Box::new(dev) as Box<dyn vm_virtio::VirtioDevice>
                    }
                    ImageType::Qcow2 => {
                        let qcow_img = QcowFile::from(raw_img)
                            .map_err(DeviceManagerError::QcowDeviceCreate)?;
                        let dev = vm_virtio::Block::new(
                            qcow_img,
                            disk_cfg.path.clone(),
                            false,
                            disk_cfg.iommu,
                        )
                        .map_err(DeviceManagerError::CreateVirtioBlock)?;
                        Box::new(dev) as Box<dyn vm_virtio::VirtioDevice>
                    }
                };

                devices.push((block, disk_cfg.iommu));
            }
        }

        Ok(devices)
    }

    fn make_virtio_net_devices(
        vm_info: &VmInfo,
    ) -> DeviceManagerResult<Vec<(Box<dyn vm_virtio::VirtioDevice>, bool)>> {
        let mut devices = Vec::new();

        // Add virtio-net if required
        if let Some(net_list_cfg) = &vm_info.vm_cfg.net {
            for net_cfg in net_list_cfg.iter() {
                let virtio_net_device = if let Some(ref tap_if_name) = net_cfg.tap {
                    let tap = Tap::open_named(tap_if_name).map_err(DeviceManagerError::OpenTap)?;
                    vm_virtio::Net::new_with_tap(tap, Some(&net_cfg.mac), net_cfg.iommu)
                        .map_err(DeviceManagerError::CreateVirtioNet)?
                } else {
                    vm_virtio::Net::new(net_cfg.ip, net_cfg.mask, Some(&net_cfg.mac), net_cfg.iommu)
                        .map_err(DeviceManagerError::CreateVirtioNet)?
                };

                devices.push((
                    Box::new(virtio_net_device) as Box<dyn vm_virtio::VirtioDevice>,
                    net_cfg.iommu,
                ));
            }
        }

        Ok(devices)
    }

    fn make_virtio_rng_devices(
        vm_info: &VmInfo,
    ) -> DeviceManagerResult<Vec<(Box<dyn vm_virtio::VirtioDevice>, bool)>> {
        let mut devices = Vec::new();

        // Add virtio-rng if required
        if let Some(rng_path) = vm_info.vm_cfg.rng.src.to_str() {
            let virtio_rng_device = vm_virtio::Rng::new(rng_path, vm_info.vm_cfg.rng.iommu)
                .map_err(DeviceManagerError::CreateVirtioRng)?;
            devices.push((
                Box::new(virtio_rng_device) as Box<dyn vm_virtio::VirtioDevice>,
                false,
            ));
        }

        Ok(devices)
    }

    fn make_virtio_fs_devices(
        vm_info: &VmInfo,
        allocator: &mut SystemAllocator,
        mem_slots: &mut u32,
        mmap_regions: &mut Vec<(*mut libc::c_void, usize)>,
    ) -> DeviceManagerResult<Vec<(Box<dyn vm_virtio::VirtioDevice>, bool)>> {
        let mut devices = Vec::new();
        // Add virtio-fs if required
        if let Some(fs_list_cfg) = &vm_info.vm_cfg.fs {
            for fs_cfg in fs_list_cfg.iter() {
                if let Some(fs_sock) = fs_cfg.sock.to_str() {
                    let mut cache: Option<(VirtioSharedMemoryList, u64)> = None;
                    if let Some(fs_cache) = fs_cfg.cache_size {
                        // The memory needs to be 2MiB aligned in order to support
                        // hugepages.
                        let fs_guest_addr = allocator
                            .allocate_mmio_addresses(
                                None,
                                fs_cache as GuestUsize,
                                Some(0x0020_0000),
                            )
                            .ok_or(DeviceManagerError::FsRangeAllocation)?;

                        let addr = unsafe {
                            libc::mmap(
                                null_mut(),
                                fs_cache as usize,
                                libc::PROT_READ | libc::PROT_WRITE,
                                libc::MAP_NORESERVE | libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                                -1,
                                0 as libc::off_t,
                            )
                        };
                        if addr == libc::MAP_FAILED {
                            return Err(DeviceManagerError::Mmap(io::Error::last_os_error()));
                        }

                        mmap_regions.push((addr, fs_cache as usize));

                        let mem_region = kvm_userspace_memory_region {
                            slot: *mem_slots as u32,
                            guest_phys_addr: fs_guest_addr.raw_value(),
                            memory_size: fs_cache,
                            userspace_addr: addr as u64,
                            flags: 0,
                        };
                        // Safe because the guest regions are guaranteed not to overlap.
                        let _ = unsafe { vm_info.vm_fd.set_user_memory_region(mem_region) };

                        // Increment the KVM slot number
                        *mem_slots += 1;

                        let mut region_list = Vec::new();
                        region_list.push(VirtioSharedMemory {
                            offset: 0,
                            len: fs_cache,
                        });
                        cache = Some((
                            VirtioSharedMemoryList {
                                addr: fs_guest_addr,
                                len: fs_cache as GuestUsize,
                                region_list,
                            },
                            addr as u64,
                        ));
                    }

                    let virtio_fs_device = vm_virtio::vhost_user::Fs::new(
                        fs_sock,
                        &fs_cfg.tag,
                        fs_cfg.num_queues,
                        fs_cfg.queue_size,
                        cache,
                    )
                    .map_err(DeviceManagerError::CreateVirtioFs)?;

                    devices.push((
                        Box::new(virtio_fs_device) as Box<dyn vm_virtio::VirtioDevice>,
                        false,
                    ));
                }
            }
        }

        Ok(devices)
    }

    fn make_virtio_pmem_devices(
        vm_info: &VmInfo,
        allocator: &mut SystemAllocator,
        mem_slots: &mut u32,
        mmap_regions: &mut Vec<(*mut libc::c_void, usize)>,
    ) -> DeviceManagerResult<Vec<(Box<dyn vm_virtio::VirtioDevice>, bool)>> {
        let mut devices = Vec::new();
        // Add virtio-pmem if required
        if let Some(pmem_list_cfg) = &vm_info.vm_cfg.pmem {
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

                let addr = unsafe {
                    libc::mmap(
                        null_mut(),
                        size as usize,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_NORESERVE | libc::MAP_SHARED,
                        file.as_raw_fd(),
                        0 as libc::off_t,
                    )
                };

                mmap_regions.push((addr, size as usize));

                let mem_region = kvm_userspace_memory_region {
                    slot: *mem_slots as u32,
                    guest_phys_addr: pmem_guest_addr.raw_value(),
                    memory_size: size,
                    userspace_addr: addr as u64,
                    flags: 0,
                };
                // Safe because the guest regions are guaranteed not to overlap.
                let _ = unsafe { vm_info.vm_fd.set_user_memory_region(mem_region) };

                // Increment the KVM slot number
                *mem_slots += 1;

                let virtio_pmem_device =
                    vm_virtio::Pmem::new(file, pmem_guest_addr, size as GuestUsize, pmem_cfg.iommu)
                        .map_err(DeviceManagerError::CreateVirtioPmem)?;

                devices.push((
                    Box::new(virtio_pmem_device) as Box<dyn vm_virtio::VirtioDevice>,
                    false,
                ));
            }
        }

        Ok(devices)
    }

    fn make_virtio_vhost_user_net_devices(
        vm_info: &VmInfo,
    ) -> DeviceManagerResult<Vec<(Box<dyn vm_virtio::VirtioDevice>, bool)>> {
        let mut devices = Vec::new();
        // Add vhost-user-net if required
        if let Some(vhost_user_net_list_cfg) = &vm_info.vm_cfg.vhost_user_net {
            for vhost_user_net_cfg in vhost_user_net_list_cfg.iter() {
                let vu_cfg = VhostUserConfig {
                    sock: vhost_user_net_cfg.vu_cfg.sock.clone(),
                    num_queues: vhost_user_net_cfg.vu_cfg.num_queues,
                    queue_size: vhost_user_net_cfg.vu_cfg.queue_size,
                };
                let vhost_user_net_device =
                    vm_virtio::vhost_user::Net::new(vhost_user_net_cfg.mac, vu_cfg)
                        .map_err(DeviceManagerError::CreateVhostUserNet)?;

                devices.push((
                    Box::new(vhost_user_net_device) as Box<dyn vm_virtio::VirtioDevice>,
                    false,
                ));
            }
        }

        Ok(devices)
    }

    fn make_virtio_vhost_user_blk_devices(
        vm_info: &VmInfo,
    ) -> DeviceManagerResult<Vec<(Box<dyn vm_virtio::VirtioDevice>, bool)>> {
        let mut devices = Vec::new();
        // Add vhost-user-blk if required
        if let Some(vhost_user_blk_list_cfg) = &vm_info.vm_cfg.vhost_user_blk {
            for vhost_user_blk_cfg in vhost_user_blk_list_cfg.iter() {
                let vu_cfg = VhostUserConfig {
                    sock: vhost_user_blk_cfg.vu_cfg.sock.clone(),
                    num_queues: vhost_user_blk_cfg.vu_cfg.num_queues,
                    queue_size: vhost_user_blk_cfg.vu_cfg.queue_size,
                };
                let vhost_user_blk_device =
                    vm_virtio::vhost_user::Blk::new(vhost_user_blk_cfg.wce, vu_cfg)
                        .map_err(DeviceManagerError::CreateVhostUserBlk)?;

                devices.push((
                    Box::new(vhost_user_blk_device) as Box<dyn vm_virtio::VirtioDevice>,
                    false,
                ));
            }
        }

        Ok(devices)
    }

    fn make_virtio_vsock_devices(
        vm_info: &VmInfo,
    ) -> DeviceManagerResult<Vec<(Box<dyn vm_virtio::VirtioDevice>, bool)>> {
        let mut devices = Vec::new();
        // Add vsock if required
        if let Some(vsock_list_cfg) = &vm_info.vm_cfg.vsock {
            for vsock_cfg in vsock_list_cfg.iter() {
                let socket_path = vsock_cfg
                    .sock
                    .to_str()
                    .ok_or(DeviceManagerError::CreateVsockConvertPath)?;
                let backend =
                    vm_virtio::vsock::VsockUnixBackend::new(vsock_cfg.cid, socket_path.to_string())
                        .map_err(DeviceManagerError::CreateVsockBackend)?;

                let vsock_device = vm_virtio::Vsock::new(vsock_cfg.cid, backend, vsock_cfg.iommu)
                    .map_err(DeviceManagerError::CreateVirtioVsock)?;

                devices.push((
                    Box::new(vsock_device) as Box<dyn vm_virtio::VirtioDevice>,
                    false,
                ));
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
        allocator: &mut SystemAllocator,
        pci: &mut PciBus,
        buses: &mut BusInfo,
        mem_slots: u32,
    ) -> DeviceManagerResult<Vec<u32>> {
        let mut mem_slot = mem_slots;
        let mut iommu_attached_list = Vec::new();
        if let Some(device_list_cfg) = &vm_info.vm_cfg.devices {
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

                if device_cfg.iommu {
                    iommu_attached_list.push(device_id);
                }

                let vfio_device =
                    VfioDevice::new(&device_cfg.path, device_fd.clone(), vm_info.memory.clone())
                        .map_err(DeviceManagerError::VfioCreate)?;

                let mut vfio_pci_device = VfioPciDevice::new(vm_info.vm_fd, allocator, vfio_device)
                    .map_err(DeviceManagerError::VfioPciCreate)?;

                let bars = vfio_pci_device
                    .allocate_bars(allocator)
                    .map_err(DeviceManagerError::AllocateBars)?;

                mem_slot = vfio_pci_device
                    .map_mmio_regions(vm_info.vm_fd, mem_slot)
                    .map_err(DeviceManagerError::VfioMapRegion)?;

                let vfio_pci_device = Arc::new(Mutex::new(vfio_pci_device));

                pci.add_device(vfio_pci_device.clone())
                    .map_err(DeviceManagerError::AddPciDevice)?;

                pci.register_mapping(vfio_pci_device.clone(), buses.io, buses.mmio, bars)
                    .map_err(DeviceManagerError::AddPciDevice)?;
            }
        }
        Ok(iommu_attached_list)
    }

    #[cfg(feature = "pci_support")]
    #[allow(clippy::too_many_arguments)]
    fn add_virtio_pci_device(
        virtio_device: Box<dyn vm_virtio::VirtioDevice>,
        memory: &Arc<RwLock<GuestMemoryMmap>>,
        allocator: &mut SystemAllocator,
        vm_fd: &Arc<VmFd>,
        pci: &mut PciBus,
        buses: &mut BusInfo,
        interrupt_info: &InterruptInfo,
        iommu_mapping: &Option<Arc<IommuMapping>>,
    ) -> DeviceManagerResult<Option<u32>> {
        let msix_num = if interrupt_info._msi_capable {
            // Allows support for one MSI-X vector per queue. It also adds 1
            // as we need to take into account the dedicated vector to notify
            // about a virtio config change.
            (virtio_device.queue_max_sizes().len() + 1) as u16
        } else {
            0
        };

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

        let mut virtio_pci_device =
            VirtioPciDevice::new(memory.clone(), virtio_device, msix_num, iommu_mapping_cb)
                .map_err(DeviceManagerError::VirtioDevice)?;

        let bars = virtio_pci_device
            .allocate_bars(allocator)
            .map_err(DeviceManagerError::AllocateBars)?;

        for (event, addr, _) in virtio_pci_device.ioeventfds() {
            let io_addr = IoEventAddress::Mmio(addr);
            vm_fd
                .register_ioevent(event.as_raw_fd(), &io_addr, NoDatamatch)
                .map_err(DeviceManagerError::RegisterIoevent)?;
        }

        if interrupt_info._msi_capable {
            let vm_fd_clone = vm_fd.clone();

            let msi_cb = Arc::new(Box::new(move |p: InterruptParameters| {
                if let Some(entry) = p.msix {
                    use kvm_bindings::kvm_msi;
                    let msi_queue = kvm_msi {
                        address_lo: entry.msg_addr_lo,
                        address_hi: entry.msg_addr_hi,
                        data: entry.msg_data,
                        flags: 0u32,
                        devid: 0u32,
                        pad: [0u8; 12],
                    };

                    return vm_fd_clone.signal_msi(msi_queue).map(|ret| {
                        if ret > 0 {
                            debug!("MSI message successfully delivered");
                        } else if ret == 0 {
                            warn!("failed to deliver MSI message, blocked by guest");
                        }
                    });
                }

                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "missing MSI-X entry",
                ))
            }) as InterruptDelivery);

            virtio_pci_device.assign_msix(msi_cb);
        } else {
            let irq_num = allocator
                .allocate_irq()
                .ok_or(DeviceManagerError::AllocateIrq)?;

            let irq_cb = if let Some(ioapic) = interrupt_info.ioapic {
                let ioapic_clone = ioapic.clone();
                Box::new(move |_p: InterruptParameters| {
                    ioapic_clone
                        .lock()
                        .unwrap()
                        .service_irq(irq_num as usize)
                        .map_err(|e| {
                            std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!("failed to inject IRQ #{}: {:?}", irq_num, e),
                            )
                        })
                }) as InterruptDelivery
            } else {
                let irqfd = EventFd::new(EFD_NONBLOCK).map_err(DeviceManagerError::EventFd)?;
                vm_fd
                    .register_irqfd(irqfd.as_raw_fd(), irq_num)
                    .map_err(DeviceManagerError::Irq)?;

                Box::new(move |_p: InterruptParameters| irqfd.write(1)) as InterruptDelivery
            };

            virtio_pci_device.assign_pin_irq(
                Arc::new(irq_cb),
                irq_num as u32,
                PciInterruptPin::IntA,
            );
        }

        let virtio_pci_device = Arc::new(Mutex::new(virtio_pci_device));

        pci.add_device(virtio_pci_device.clone())
            .map_err(DeviceManagerError::AddPciDevice)?;

        pci.register_mapping(
            virtio_pci_device.clone(),
            &mut buses.io,
            &mut buses.mmio,
            bars,
        )
        .map_err(DeviceManagerError::AddPciDevice)?;

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
        virtio_device: Box<dyn vm_virtio::VirtioDevice>,
        memory: &Arc<RwLock<GuestMemoryMmap>>,
        allocator: &mut SystemAllocator,
        vm_fd: &Arc<VmFd>,
        buses: &mut BusInfo,
        interrupt_info: &InterruptInfo,
        mmio_base: GuestAddress,
        cmdline_additions: &mut Vec<String>,
    ) -> DeviceManagerResult<()> {
        let mut mmio_device = vm_virtio::transport::MmioDevice::new(memory.clone(), virtio_device)
            .map_err(DeviceManagerError::VirtioDevice)?;

        for (i, queue_evt) in mmio_device.queue_evts().iter().enumerate() {
            let io_addr = IoEventAddress::Mmio(
                mmio_base.0 + u64::from(vm_virtio::transport::NOTIFY_REG_OFFSET),
            );
            vm_fd
                .register_ioevent(queue_evt.as_raw_fd(), &io_addr, i as u32)
                .map_err(DeviceManagerError::RegisterIoevent)?;
        }

        let irq_num = allocator
            .allocate_irq()
            .ok_or(DeviceManagerError::AllocateIrq)?;

        let interrupt: Box<dyn devices::Interrupt> = if let Some(ioapic) = interrupt_info.ioapic {
            Box::new(UserIoapicIrq::new(ioapic.clone(), irq_num as usize))
        } else {
            let irqfd = EventFd::new(EFD_NONBLOCK).map_err(DeviceManagerError::EventFd)?;

            vm_fd
                .register_irqfd(irqfd.as_raw_fd(), irq_num as u32)
                .map_err(DeviceManagerError::Irq)?;

            Box::new(KernelIoapicIrq::new(irqfd))
        };

        mmio_device.assign_interrupt(interrupt);

        buses
            .mmio
            .insert(Arc::new(Mutex::new(mmio_device)), mmio_base.0, MMIO_LEN)
            .map_err(DeviceManagerError::BusError)?;

        cmdline_additions.push(format!(
            "virtio_mmio.device={}K@0x{:08x}:{}",
            MMIO_LEN / 1024,
            mmio_base.0,
            irq_num
        ));

        Ok(())
    }

    pub fn io_bus(&self) -> &devices::Bus {
        &self.io_bus
    }

    pub fn mmio_bus(&self) -> &devices::Bus {
        &self.mmio_bus
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
}

impl Drop for DeviceManager {
    fn drop(&mut self) {
        for (addr, size) in self.mmap_regions.drain(..) {
            unsafe {
                libc::munmap(addr, size);
            }
        }
    }
}
