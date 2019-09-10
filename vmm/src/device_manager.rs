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
use kvm_bindings::{kvm_msi, kvm_userspace_memory_region};
use kvm_ioctls::*;
use libc::O_TMPFILE;
use libc::{EFD_NONBLOCK, TIOCGWINSZ};

use net_util::Tap;
use pci::{
    InterruptDelivery, InterruptParameters, PciConfigIo, PciDevice, PciInterruptPin, PciRoot,
};
use qcow::{self, ImageType, QcowFile};

use std::fs::{File, OpenOptions};
use std::io::{self, sink, stdout};

use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::ptr::null_mut;
use std::result;
use std::sync::{Arc, Mutex, RwLock};
use vfio::{VfioDevice, VfioPciDevice, VfioPciError};
use vm_allocator::SystemAllocator;
use vm_memory::{Address, GuestMemoryMmap, GuestUsize};
use vm_virtio::transport::VirtioPciDevice;
use vm_virtio::{VirtioSharedMemory, VirtioSharedMemoryList};
use vmm_sys_util::eventfd::EventFd;

// IOAPIC address range
const IOAPIC_RANGE_ADDR: u64 = 0xfec0_0000;
const IOAPIC_RANGE_SIZE: u64 = 0x20;

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

    /// Cannot create virtio-pmem device
    CreateVirtioPmem(io::Error),

    /// Cannot create virtio-vsock device
    CreateVirtioVsock(io::Error),

    /// Failed converting Path to &str for the virtio-vsock device.
    CreateVsockConvertPath,

    /// Cannot create virtio-vsock backend
    CreateVsockBackend(vm_virtio::vsock::VsockUnixError),

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
    AllocateBars(pci::PciDeviceError),

    /// Cannot register ioevent.
    RegisterIoevent(io::Error),

    /// Cannot create virtio device
    VirtioDevice(vmm_sys_util::errno::Error),

    /// Cannot add PCI device
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
    VfioCreate(vfio::VfioError),

    /// Cannot create a VFIO PCI device
    VfioPciCreate(vfio::VfioPciError),

    /// Failed to map VFIO MMIO region.
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
    msi_capable: bool,
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

    // i8042 device for i8042 reset
    i8042: Arc<Mutex<devices::legacy::I8042Device>>,

    #[cfg(feature = "acpi")]
    // ACPI device for reboot/shutdwon
    acpi_device: Arc<Mutex<devices::AcpiShutdownDevice>>,

    // IOAPIC
    ioapic: Option<Arc<Mutex<ioapic::Ioapic>>>,

    // PCI root
    pci: Arc<Mutex<PciConfigIo>>,

    // mmap()ed region to unmap on drop
    mmap_regions: Vec<(*mut libc::c_void, usize)>,
}

impl DeviceManager {
    pub fn new(
        vm_info: &VmInfo,
        allocator: &mut SystemAllocator,
        msi_capable: bool,
        userspace_ioapic: bool,
        mut mem_slots: u32,
        exit_evt: &EventFd,
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
            Some(Arc::new(Mutex::new(ioapic::Ioapic::new(
                vm_info.vm_fd.clone(),
            ))))
        } else {
            None
        };

        let interrupt_info = InterruptInfo {
            msi_capable,
            ioapic: &ioapic,
        };

        let serial_writer: Option<Box<dyn io::Write + Send>> = match vm_info.vm_cfg.serial.mode {
            ConsoleOutputMode::File => Some(Box::new(
                File::create(vm_info.vm_cfg.serial.file.unwrap())
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

            Some(Arc::new(Mutex::new(devices::legacy::Serial::new(
                interrupt,
                serial_writer,
            ))))
        } else {
            None
        };

        // Add a shutdown device (i8042)
        let i8042 = Arc::new(Mutex::new(devices::legacy::I8042Device::new(
            reset_evt.try_clone().map_err(DeviceManagerError::EventFd)?,
        )));

        #[cfg(feature = "acpi")]
        let acpi_device = Arc::new(Mutex::new(devices::AcpiShutdownDevice::new(
            exit_evt.try_clone().map_err(DeviceManagerError::EventFd)?,
            reset_evt.try_clone().map_err(DeviceManagerError::EventFd)?,
        )));

        let mut virtio_devices: Vec<Box<dyn vm_virtio::VirtioDevice>> = Vec::new();

        let console_writer: Option<Box<dyn io::Write + Send>> = match vm_info.vm_cfg.console.mode {
            ConsoleOutputMode::File => Some(Box::new(
                File::create(vm_info.vm_cfg.console.file.unwrap())
                    .map_err(DeviceManagerError::ConsoleOutputFileOpen)?,
            )),
            ConsoleOutputMode::Tty => Some(Box::new(stdout())),
            ConsoleOutputMode::Null => Some(Box::new(sink())),
            ConsoleOutputMode::Off => None,
        };
        let (col, row) = get_win_size();
        let console_input = if console_writer.is_some() {
            let (virtio_console_device, console_input) =
                vm_virtio::Console::new(console_writer, col, row)
                    .map_err(DeviceManagerError::CreateVirtioConsole)?;
            virtio_devices
                .push(Box::new(virtio_console_device) as Box<dyn vm_virtio::VirtioDevice>);
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

        let pci_root = PciRoot::new(None);
        let mut pci = PciConfigIo::new(pci_root);

        for device in virtio_devices {
            DeviceManager::add_virtio_pci_device(
                device,
                vm_info.memory,
                allocator,
                vm_info.vm_fd,
                &mut pci,
                &mut buses,
                &interrupt_info,
            )?;
        }

        DeviceManager::add_vfio_devices(vm_info, allocator, &mut pci, &mut buses, mem_slots)?;

        let pci = Arc::new(Mutex::new(pci));

        Ok(DeviceManager {
            io_bus,
            mmio_bus,
            console,
            i8042,
            #[cfg(feature = "acpi")]
            acpi_device,
            ioapic,
            pci,
            mmap_regions,
        })
    }

    fn make_virtio_devices(
        vm_info: &VmInfo,
        allocator: &mut SystemAllocator,
        mut mem_slots: &mut u32,
        mmap_regions: &mut Vec<(*mut libc::c_void, usize)>,
    ) -> DeviceManagerResult<Vec<Box<dyn vm_virtio::VirtioDevice>>> {
        let mut devices: Vec<Box<dyn vm_virtio::VirtioDevice>> = Vec::new();

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

        // Add virtio-vsock if required
        devices.append(&mut DeviceManager::make_virtio_vsock_devices(vm_info)?);

        Ok(devices)
    }

    fn make_virtio_block_devices(
        vm_info: &VmInfo,
    ) -> DeviceManagerResult<Vec<Box<dyn vm_virtio::VirtioDevice>>> {
        let mut devices = Vec::new();

        if let Some(disk_list_cfg) = &vm_info.vm_cfg.disks {
            for disk_cfg in disk_list_cfg.iter() {
                // Open block device path
                let raw_img: File = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(disk_cfg.path)
                    .map_err(DeviceManagerError::Disk)?;

                let image_type = qcow::detect_image_type(&raw_img)
                    .map_err(DeviceManagerError::DetectImageType)?;
                let block = match image_type {
                    ImageType::Raw => {
                        let raw_img = vm_virtio::RawFile::new(raw_img);
                        let dev =
                            vm_virtio::Block::new(raw_img, disk_cfg.path.to_path_buf(), false)
                                .map_err(DeviceManagerError::CreateVirtioBlock)?;
                        Box::new(dev) as Box<dyn vm_virtio::VirtioDevice>
                    }
                    ImageType::Qcow2 => {
                        let qcow_img = QcowFile::from(raw_img)
                            .map_err(DeviceManagerError::QcowDeviceCreate)?;
                        let dev =
                            vm_virtio::Block::new(qcow_img, disk_cfg.path.to_path_buf(), false)
                                .map_err(DeviceManagerError::CreateVirtioBlock)?;
                        Box::new(dev) as Box<dyn vm_virtio::VirtioDevice>
                    }
                };

                devices.push(block);
            }
        }

        Ok(devices)
    }

    fn make_virtio_net_devices(
        vm_info: &VmInfo,
    ) -> DeviceManagerResult<Vec<Box<dyn vm_virtio::VirtioDevice>>> {
        let mut devices = Vec::new();

        // Add virtio-net if required
        if let Some(net_list_cfg) = &vm_info.vm_cfg.net {
            for net_cfg in net_list_cfg.iter() {
                let virtio_net_device = if let Some(tap_if_name) = net_cfg.tap {
                    let tap = Tap::open_named(tap_if_name).map_err(DeviceManagerError::OpenTap)?;
                    vm_virtio::Net::new_with_tap(tap, Some(&net_cfg.mac))
                        .map_err(DeviceManagerError::CreateVirtioNet)?
                } else {
                    vm_virtio::Net::new(net_cfg.ip, net_cfg.mask, Some(&net_cfg.mac))
                        .map_err(DeviceManagerError::CreateVirtioNet)?
                };

                devices.push(Box::new(virtio_net_device) as Box<dyn vm_virtio::VirtioDevice>);
            }
        }

        Ok(devices)
    }

    fn make_virtio_rng_devices(
        vm_info: &VmInfo,
    ) -> DeviceManagerResult<Vec<Box<dyn vm_virtio::VirtioDevice>>> {
        let mut devices = Vec::new();

        // Add virtio-rng if required
        if let Some(rng_path) = vm_info.vm_cfg.rng.src.to_str() {
            let virtio_rng_device =
                vm_virtio::Rng::new(rng_path).map_err(DeviceManagerError::CreateVirtioRng)?;
            devices.push(Box::new(virtio_rng_device) as Box<dyn vm_virtio::VirtioDevice>);
        }

        Ok(devices)
    }

    fn make_virtio_fs_devices(
        vm_info: &VmInfo,
        allocator: &mut SystemAllocator,
        mem_slots: &mut u32,
        mmap_regions: &mut Vec<(*mut libc::c_void, usize)>,
    ) -> DeviceManagerResult<Vec<Box<dyn vm_virtio::VirtioDevice>>> {
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
                        fs_cfg.tag,
                        fs_cfg.num_queues,
                        fs_cfg.queue_size,
                        cache,
                    )
                    .map_err(DeviceManagerError::CreateVirtioFs)?;

                    devices.push(Box::new(virtio_fs_device) as Box<dyn vm_virtio::VirtioDevice>);
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
    ) -> DeviceManagerResult<Vec<Box<dyn vm_virtio::VirtioDevice>>> {
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
                    .open(pmem_cfg.file)
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
                    vm_virtio::Pmem::new(file, pmem_guest_addr, size as GuestUsize)
                        .map_err(DeviceManagerError::CreateVirtioPmem)?;

                devices.push(Box::new(virtio_pmem_device) as Box<dyn vm_virtio::VirtioDevice>);
            }
        }

        Ok(devices)
    }

    fn make_virtio_vhost_user_net_devices(
        vm_info: &VmInfo,
    ) -> DeviceManagerResult<Vec<Box<dyn vm_virtio::VirtioDevice>>> {
        let mut devices = Vec::new();
        // Add vhost-user-net if required
        if let Some(vhost_user_net_list_cfg) = &vm_info.vm_cfg.vhost_user_net {
            for vhost_user_net_cfg in vhost_user_net_list_cfg.iter() {
                let vhost_user_net_device = vm_virtio::vhost_user::Net::new(
                    vhost_user_net_cfg.mac,
                    vhost_user_net_cfg.vu_cfg,
                )
                .map_err(DeviceManagerError::CreateVhostUserNet)?;

                devices.push(Box::new(vhost_user_net_device) as Box<dyn vm_virtio::VirtioDevice>);
            }
        }

        Ok(devices)
    }

    fn make_virtio_vsock_devices(
        vm_info: &VmInfo,
    ) -> DeviceManagerResult<Vec<Box<dyn vm_virtio::VirtioDevice>>> {
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

                let vsock_device = vm_virtio::Vsock::new(vsock_cfg.cid, backend)
                    .map_err(DeviceManagerError::CreateVirtioVsock)?;

                devices.push(Box::new(vsock_device) as Box<dyn vm_virtio::VirtioDevice>);
            }
        }

        Ok(devices)
    }

    fn create_kvm_device(vm: &Arc<VmFd>) -> DeviceManagerResult<DeviceFd> {
        let mut vfio_dev = kvm_bindings::kvm_create_device {
            type_: kvm_bindings::kvm_device_type_KVM_DEV_TYPE_VFIO,
            fd: 0,
            flags: 0,
        };

        vm.create_device(&mut vfio_dev)
            .map_err(DeviceManagerError::CreateKvmDevice)
    }

    fn add_vfio_devices(
        vm_info: &VmInfo,
        allocator: &mut SystemAllocator,
        pci: &mut PciConfigIo,
        buses: &mut BusInfo,
        mem_slots: u32,
    ) -> DeviceManagerResult<()> {
        let mut mem_slot = mem_slots;
        if let Some(device_list_cfg) = &vm_info.vm_cfg.devices {
            // Create the KVM VFIO device
            let device_fd = DeviceManager::create_kvm_device(vm_info.vm_fd)?;
            let device_fd = Arc::new(device_fd);

            for device_cfg in device_list_cfg.iter() {
                let vfio_device =
                    VfioDevice::new(device_cfg.path, device_fd.clone(), vm_info.memory.clone())
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
        Ok(())
    }

    fn add_virtio_pci_device(
        virtio_device: Box<dyn vm_virtio::VirtioDevice>,
        memory: &Arc<RwLock<GuestMemoryMmap>>,
        allocator: &mut SystemAllocator,
        vm_fd: &Arc<VmFd>,
        pci: &mut PciConfigIo,
        buses: &mut BusInfo,
        interrupt_info: &InterruptInfo,
    ) -> DeviceManagerResult<()> {
        let msix_num = if interrupt_info.msi_capable {
            // Allows support for one MSI-X vector per queue. It also adds 1
            // as we need to take into account the dedicated vector to notify
            // about a virtio config change.
            (virtio_device.queue_max_sizes().len() + 1) as u16
        } else {
            0
        };

        let mut virtio_pci_device = VirtioPciDevice::new(memory.clone(), virtio_device, msix_num)
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

        if interrupt_info.msi_capable {
            let vm_fd_clone = vm_fd.clone();

            let msi_cb = Arc::new(Box::new(move |p: InterruptParameters| {
                if let Some(entry) = p.msix {
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

        Ok(())
    }

    pub fn register_devices(&mut self) -> DeviceManagerResult<()> {
        if self.console.serial.is_some() {
            // Insert serial device
            self.io_bus
                .insert(self.console.serial.as_ref().unwrap().clone(), 0x3f8, 0x8)
                .map_err(DeviceManagerError::BusError)?;
        }

        // Insert i8042 device
        self.io_bus
            .insert(self.i8042.clone(), 0x61, 0x4)
            .map_err(DeviceManagerError::BusError)?;

        #[cfg(feature = "acpi")]
        self.io_bus
            .insert(self.acpi_device.clone(), 0x3c0, 0x4)
            .map_err(DeviceManagerError::BusError)?;

        // Insert the PCI root configuration space.
        self.io_bus
            .insert(self.pci.clone(), 0xcf8, 0x8)
            .map_err(DeviceManagerError::BusError)?;

        if let Some(ioapic) = &self.ioapic {
            // Insert IOAPIC
            self.mmio_bus
                .insert(ioapic.clone(), IOAPIC_RANGE_ADDR, IOAPIC_RANGE_SIZE)
                .map_err(DeviceManagerError::BusError)?;
        }

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
