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

use crate::config::{
    ConsoleOutputMode, DeviceConfig, DiskConfig, FsConfig, NetConfig, PmemConfig, VhostMode,
    VmConfig, VsockConfig,
};
use crate::device_tree::{DeviceNode, DeviceTree};
#[cfg(feature = "kvm")]
use crate::interrupt::kvm::KvmMsiInterruptManager as MsiInterruptManager;
#[cfg(feature = "mshv")]
use crate::interrupt::mshv::MshvMsiInterruptManager as MsiInterruptManager;
use crate::interrupt::LegacyUserspaceInterruptManager;
#[cfg(feature = "acpi")]
use crate::memory_manager::MEMORY_MANAGER_ACPI_SIZE;
use crate::memory_manager::{Error as MemoryManagerError, MemoryManager};
#[cfg(feature = "acpi")]
use crate::vm::NumaNodes;
use crate::PciDeviceInfo;
use crate::{device_node, DEVICE_MANAGER_SNAPSHOT_ID};
#[cfg(feature = "acpi")]
use acpi_tables::{aml, aml::Aml};
use anyhow::anyhow;
#[cfg(feature = "acpi")]
use arch::layout;
#[cfg(target_arch = "x86_64")]
use arch::layout::{APIC_START, IOAPIC_SIZE, IOAPIC_START};
#[cfg(target_arch = "aarch64")]
use arch::{DeviceType, MmioDeviceInfo};
use block_util::{
    async_io::DiskFile, block_io_uring_is_supported, detect_image_type,
    fixed_vhd_async::FixedVhdDiskAsync, fixed_vhd_sync::FixedVhdDiskSync, qcow_sync::QcowDiskSync,
    raw_async::RawFileDisk, raw_sync::RawFileDiskSync, ImageType,
};
#[cfg(target_arch = "aarch64")]
use devices::gic;
#[cfg(target_arch = "x86_64")]
use devices::ioapic;
#[cfg(target_arch = "aarch64")]
use devices::legacy::Pl011;
#[cfg(target_arch = "x86_64")]
use devices::legacy::Serial;
use devices::{
    interrupt_controller, interrupt_controller::InterruptController, AcpiNotificationFlags,
};
#[cfg(feature = "kvm")]
use hypervisor::kvm_ioctls::*;
#[cfg(feature = "mshv")]
use hypervisor::IoEventAddress;
use libc::{
    isatty, tcgetattr, tcsetattr, termios, ECHO, ICANON, ISIG, MAP_NORESERVE, MAP_PRIVATE,
    MAP_SHARED, O_TMPFILE, PROT_READ, PROT_WRITE, TCSANOW, TIOCGWINSZ,
};
#[cfg(feature = "kvm")]
use pci::VfioPciDevice;
use pci::{
    DeviceRelocation, PciBarRegionType, PciBus, PciConfigIo, PciConfigMmio, PciDevice, PciRoot,
};
use seccomp::SeccompAction;
use std::collections::HashMap;
use std::convert::TryInto;
use std::fs::{read_link, File, OpenOptions};
use std::io::{self, sink, stdout, Seek, SeekFrom};
use std::mem::zeroed;
use std::num::Wrapping;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::PathBuf;
use std::result;
use std::sync::{Arc, Barrier, Mutex};
#[cfg(feature = "kvm")]
use vfio_ioctls::{VfioContainer, VfioDevice};
use virtio_devices::transport::VirtioPciDevice;
use virtio_devices::transport::VirtioTransport;
use virtio_devices::vhost_user::VhostUserConfig;
use virtio_devices::{DmaRemapping, IommuMapping};
use virtio_devices::{VirtioSharedMemory, VirtioSharedMemoryList};
use vm_allocator::SystemAllocator;
#[cfg(feature = "kvm")]
use vm_device::dma_mapping::vfio::VfioDmaMapping;
use vm_device::interrupt::{
    InterruptIndex, InterruptManager, LegacyIrqGroupConfig, MsiIrqGroupConfig,
};
use vm_device::{Bus, BusDevice, Resource};
use vm_memory::guest_memory::FileOffset;
#[cfg(feature = "kvm")]
use vm_memory::GuestMemoryRegion;
use vm_memory::{Address, GuestAddress, GuestRegionMmap, GuestUsize, MmapRegion};
#[cfg(feature = "cmos")]
use vm_memory::{GuestAddressSpace, GuestMemory};
use vm_migration::{
    Migratable, MigratableError, Pausable, Snapshot, SnapshotDataSection, Snapshottable,
    Transportable,
};
use vm_virtio::{VirtioDeviceType, VirtioIommuRemapping};
use vmm_sys_util::eventfd::EventFd;

#[cfg(target_arch = "aarch64")]
const MMIO_LEN: u64 = 0x1000;

#[cfg(feature = "kvm")]
const VFIO_DEVICE_NAME_PREFIX: &str = "_vfio";

#[cfg(target_arch = "x86_64")]
const IOAPIC_DEVICE_NAME: &str = "_ioapic";

const SERIAL_DEVICE_NAME_PREFIX: &str = "_serial";
#[cfg(target_arch = "aarch64")]
const GPIO_DEVICE_NAME_PREFIX: &str = "_gpio";

const CONSOLE_DEVICE_NAME: &str = "_console";
const DISK_DEVICE_NAME_PREFIX: &str = "_disk";
const FS_DEVICE_NAME_PREFIX: &str = "_fs";
const MEM_DEVICE_NAME_PREFIX: &str = "_mem";
const BALLOON_DEVICE_NAME: &str = "_balloon";
const NET_DEVICE_NAME_PREFIX: &str = "_net";
const PMEM_DEVICE_NAME_PREFIX: &str = "_pmem";
const RNG_DEVICE_NAME: &str = "_rng";
const VSOCK_DEVICE_NAME_PREFIX: &str = "_vsock";
const WATCHDOG_DEVICE_NAME: &str = "_watchdog";

const IOMMU_DEVICE_NAME: &str = "_iommu";

const VIRTIO_PCI_DEVICE_NAME_PREFIX: &str = "_virtio-pci";

/// Errors associated with device manager
#[derive(Debug)]
pub enum DeviceManagerError {
    /// Cannot create EventFd.
    EventFd(io::Error),

    /// Cannot open disk path
    Disk(io::Error),

    /// Cannot create vhost-user-net device
    CreateVhostUserNet(virtio_devices::vhost_user::Error),

    /// Cannot create virtio-blk device
    CreateVirtioBlock(io::Error),

    /// Cannot create virtio-net device
    CreateVirtioNet(virtio_devices::net::Error),

    /// Cannot create virtio-console device
    CreateVirtioConsole(io::Error),

    /// Cannot create virtio-rng device
    CreateVirtioRng(io::Error),

    /// Cannot create virtio-fs device
    CreateVirtioFs(virtio_devices::vhost_user::Error),

    /// Virtio-fs device was created without a socket.
    NoVirtioFsSock,

    /// Cannot create vhost-user-blk device
    CreateVhostUserBlk(virtio_devices::vhost_user::Error),

    /// Cannot create virtio-pmem device
    CreateVirtioPmem(io::Error),

    /// Cannot create virtio-vsock device
    CreateVirtioVsock(io::Error),

    /// Failed converting Path to &str for the virtio-vsock device.
    CreateVsockConvertPath,

    /// Cannot create virtio-vsock backend
    CreateVsockBackend(virtio_devices::vsock::VsockUnixError),

    /// Cannot create virtio-iommu device
    CreateVirtioIommu(io::Error),

    /// Cannot create virtio-balloon device
    CreateVirtioBalloon(io::Error),

    /// Cannot create virtio-watchdog device
    CreateVirtioWatchdog(io::Error),

    /// Failed parsing disk image format
    DetectImageType(io::Error),

    /// Cannot open qcow disk path
    QcowDeviceCreate(qcow::Error),

    /// Cannot open tap interface
    OpenTap(net_util::TapError),

    /// Cannot allocate IRQ.
    AllocateIrq,

    /// Cannot configure the IRQ.
    Irq(vmm_sys_util::errno::Error),

    /// Cannot allocate PCI BARs
    AllocateBars(pci::PciDeviceError),

    /// Could not free the BARs associated with a PCI device.
    FreePciBars(pci::PciDeviceError),

    /// Cannot register ioevent.
    RegisterIoevent(anyhow::Error),

    /// Cannot unregister ioevent.
    UnRegisterIoevent(anyhow::Error),

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

    /// Error creating serial pty
    SerialPtyOpen(io::Error),

    /// Error creating console pty
    ConsolePtyOpen(io::Error),

    /// Error setting pty raw mode
    SetPtyRaw(vmm_sys_util::errno::Error),

    /// Error getting pty peer
    GetPtyPeer(vmm_sys_util::errno::Error),

    /// Cannot create a VFIO device
    VfioCreate(vfio_ioctls::VfioError),

    /// Cannot create a VFIO PCI device
    VfioPciCreate(pci::VfioPciError),

    /// Failed to map VFIO MMIO region.
    VfioMapRegion(pci::VfioPciError),

    /// Failed to DMA map VFIO device.
    VfioDmaMap(pci::VfioPciError),

    /// Failed to DMA unmap VFIO device.
    VfioDmaUnmap(pci::VfioPciError),

    /// Failed to create the passthrough device.
    CreatePassthroughDevice(anyhow::Error),

    /// Failed to memory map.
    Mmap(io::Error),

    /// Cannot add legacy device to Bus.
    BusError(vm_device::BusError),

    /// Failed to allocate IO port
    AllocateIoPort,

    /// Failed to allocate MMIO address
    AllocateMmioAddress,

    // Failed to make hotplug notification
    HotPlugNotification(io::Error),

    // Error from a memory manager operation
    MemoryManager(MemoryManagerError),

    /// Failed to create new interrupt source group.
    CreateInterruptGroup(io::Error),

    /// Failed to update interrupt source group.
    UpdateInterruptGroup(io::Error),

    /// Failed creating interrupt controller.
    CreateInterruptController(interrupt_controller::Error),

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
    RemoveDeviceFromPciBus(pci::PciRootError),

    /// Failed removing a bus device from the IO bus.
    RemoveDeviceFromIoBus(vm_device::BusError),

    /// Failed removing a bus device from the MMIO bus.
    RemoveDeviceFromMmioBus(vm_device::BusError),

    /// Failed to find the device corresponding to a specific PCI b/d/f.
    UnknownPciBdf(u32),

    /// Not allowed to remove this type of device from the VM.
    RemovalNotAllowed(vm_virtio::VirtioDeviceType),

    /// Failed to find device corresponding to the given identifier.
    UnknownDeviceId(String),

    /// Failed to find an available PCI device ID.
    NextPciDeviceId(pci::PciRootError),

    /// Could not reserve the PCI device ID.
    GetPciDeviceId(pci::PciRootError),

    /// Could not give the PCI device ID back.
    PutPciDeviceId(pci::PciRootError),

    /// Incorrect device ID as it is already used by another device.
    DeviceIdAlreadyInUse,

    /// No disk path was specified when one was expected
    NoDiskPath,

    /// Failed updating guest memory for virtio device.
    UpdateMemoryForVirtioDevice(virtio_devices::Error),

    /// Cannot create virtio-mem device
    CreateVirtioMem(io::Error),

    /// Cannot generate a ResizeSender from the Resize object.
    CreateResizeSender(virtio_devices::mem::Error),

    /// Cannot find a memory range for virtio-mem memory
    VirtioMemRangeAllocation,

    /// Failed updating guest memory for VFIO PCI device.
    UpdateMemoryForVfioPciDevice(pci::VfioPciError),

    /// Trying to use a directory for pmem but no size specified
    PmemWithDirectorySizeMissing,

    /// Trying to use a size that is not multiple of 2MiB
    PmemSizeNotAligned,

    /// Could not find the node in the device tree.
    MissingNode,

    /// Resource was already found.
    ResourceAlreadyExists,

    /// Expected resources for virtio-pci could not be found.
    MissingVirtioPciResources,

    /// Expected resources for virtio-fs could not be found.
    MissingVirtioFsResources,

    /// Missing PCI b/d/f from the DeviceNode.
    MissingDeviceNodePciBdf,

    /// No support for device passthrough
    NoDevicePassthroughSupport,

    /// Failed to resize virtio-balloon
    VirtioBalloonResize(virtio_devices::balloon::Error),

    /// Missing virtio-balloon, can't proceed as expected.
    MissingVirtioBalloon,

    /// Failed to do power button notification
    PowerButtonNotification(io::Error),

    /// Failed to do AArch64 GPIO power button notification
    #[cfg(target_arch = "aarch64")]
    AArch64PowerButtonNotification(devices::legacy::GpioDeviceError),

    /// Failed to set O_DIRECT flag to file descriptor
    SetDirectIo,

    /// Failed to create FixedVhdDiskAsync
    CreateFixedVhdDiskAsync(io::Error),

    /// Failed to create FixedVhdDiskSync
    CreateFixedVhdDiskSync(io::Error),

    /// Failed adding DMA mapping handler to virtio-mem device.
    AddDmaMappingHandlerVirtioMem(virtio_devices::mem::Error),

    /// Failed removing DMA mapping handler from virtio-mem device.
    RemoveDmaMappingHandlerVirtioMem(virtio_devices::mem::Error),
}
pub type DeviceManagerResult<T> = result::Result<T, DeviceManagerError>;

type VirtioDeviceArc = Arc<Mutex<dyn virtio_devices::VirtioDevice>>;

#[cfg(feature = "acpi")]
const DEVICE_MANAGER_ACPI_SIZE: usize = 0x10;

pub fn get_win_size() -> (u16, u16) {
    #[repr(C)]
    #[derive(Default)]
    struct WindowSize {
        rows: u16,
        cols: u16,
        xpixel: u16,
        ypixel: u16,
    }
    let ws: WindowSize = WindowSize::default();

    unsafe {
        libc::ioctl(0, TIOCGWINSZ, &ws);
    }

    (ws.cols, ws.rows)
}

const TIOCSPTLCK: libc::c_int = 0x4004_5431;
const TIOCGTPEER: libc::c_int = 0x5441;

pub fn create_pty() -> io::Result<(File, File, PathBuf)> {
    // Try to use /dev/pts/ptmx first then fall back to /dev/ptmx
    // This is done to try and use the devpts filesystem that
    // could be available for use in the process's namespace first.
    // Ideally these are all the same file though but different
    // kernels could have things setup differently.
    // See https://www.kernel.org/doc/Documentation/filesystems/devpts.txt
    // for further details.
    let main = match OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOCTTY)
        .open("/dev/pts/ptmx")
    {
        Ok(f) => f,
        _ => OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY)
            .open("/dev/ptmx")?,
    };
    let mut unlock: libc::c_ulong = 0;
    unsafe {
        libc::ioctl(
            main.as_raw_fd(),
            TIOCSPTLCK.try_into().unwrap(),
            &mut unlock,
        )
    };

    let sub_fd = unsafe {
        libc::ioctl(
            main.as_raw_fd(),
            TIOCGTPEER.try_into().unwrap(),
            libc::O_NOCTTY | libc::O_RDWR,
        )
    };
    if sub_fd == -1 {
        return vmm_sys_util::errno::errno_result().map_err(|e| e.into());
    }

    let proc_path = PathBuf::from(format!("/proc/self/fd/{}", sub_fd));
    let path = read_link(proc_path)?;

    Ok((main, unsafe { File::from_raw_fd(sub_fd) }, path))
}

enum ConsoleInput {
    Serial,
    VirtioConsole,
}
#[derive(Default)]
pub struct Console {
    #[cfg(target_arch = "x86_64")]
    // Serial port on 0x3f8
    serial: Option<Arc<Mutex<Serial>>>,
    #[cfg(target_arch = "aarch64")]
    serial: Option<Arc<Mutex<Pl011>>>,
    virtio_console_input: Option<Arc<virtio_devices::ConsoleInput>>,
    input: Option<ConsoleInput>,
}

impl Console {
    pub fn queue_input_bytes(&self, out: &[u8]) -> vmm_sys_util::errno::Result<()> {
        match self.input {
            Some(ConsoleInput::Serial) => {
                self.queue_input_bytes_serial(out)?;
            }

            Some(ConsoleInput::VirtioConsole) => {
                self.queue_input_bytes_console(out);
            }
            None => {}
        }

        Ok(())
    }

    pub fn queue_input_bytes_serial(&self, out: &[u8]) -> vmm_sys_util::errno::Result<()> {
        if self.serial.is_some() {
            self.serial
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .queue_input_bytes(out)?;
        }
        Ok(())
    }

    pub fn queue_input_bytes_console(&self, out: &[u8]) {
        if self.virtio_console_input.is_some() {
            self.virtio_console_input
                .as_ref()
                .unwrap()
                .queue_input_bytes(out);
        }
    }

    pub fn update_console_size(&self, cols: u16, rows: u16) {
        if self.virtio_console_input.is_some() {
            self.virtio_console_input
                .as_ref()
                .unwrap()
                .update_console_size(cols, rows)
        }
    }

    pub fn input_enabled(&self) -> bool {
        self.input.is_some()
    }
}

struct AddressManager {
    allocator: Arc<Mutex<SystemAllocator>>,
    #[cfg(target_arch = "x86_64")]
    io_bus: Arc<Bus>,
    mmio_bus: Arc<Bus>,
    vm: Arc<dyn hypervisor::Vm>,
    device_tree: Arc<Mutex<DeviceTree>>,
}

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
            PciBarRegionType::IoRegion => {
                #[cfg(target_arch = "x86_64")]
                {
                    // Update system allocator
                    self.allocator
                        .lock()
                        .unwrap()
                        .free_io_addresses(GuestAddress(old_base), len as GuestUsize);

                    self.allocator
                        .lock()
                        .unwrap()
                        .allocate_io_addresses(
                            Some(GuestAddress(new_base)),
                            len as GuestUsize,
                            None,
                        )
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::Other, "failed allocating new IO range")
                        })?;

                    // Update PIO bus
                    self.io_bus
                        .update_range(old_base, len, new_base, len)
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                }
                #[cfg(target_arch = "aarch64")]
                error!("I/O region is not supported");
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
            // Update the device_tree resources associated with the device
            if let Some(node) = self
                .device_tree
                .lock()
                .unwrap()
                .get_mut(&virtio_pci_dev.id())
            {
                let mut resource_updated = false;
                for resource in node.resources.iter_mut() {
                    if let Resource::MmioAddressRange { base, .. } = resource {
                        if *base == old_base {
                            *base = new_base;
                            resource_updated = true;
                            break;
                        }
                    }
                }

                if !resource_updated {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!(
                            "Couldn't find a resource with base 0x{:x} for device {}",
                            old_base,
                            virtio_pci_dev.id()
                        ),
                    ));
                }
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "Couldn't find device {} from device tree",
                        virtio_pci_dev.id()
                    ),
                ));
            }

            let bar_addr = virtio_pci_dev.config_bar_addr();
            if bar_addr == new_base {
                for (event, addr) in virtio_pci_dev.ioeventfds(old_base) {
                    let io_addr = IoEventAddress::Mmio(addr);
                    self.vm.unregister_ioevent(event, &io_addr).map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::Other,
                            format!("failed to unregister ioevent: {:?}", e),
                        )
                    })?;
                }
                for (event, addr) in virtio_pci_dev.ioeventfds(new_base) {
                    let io_addr = IoEventAddress::Mmio(addr);
                    self.vm
                        .register_ioevent(event, &io_addr, None)
                        .map_err(|e| {
                            io::Error::new(
                                io::ErrorKind::Other,
                                format!("failed to register ioevent: {:?}", e),
                            )
                        })?;
                }
            } else {
                let virtio_dev = virtio_pci_dev.virtio_device();
                let mut virtio_dev = virtio_dev.lock().unwrap();
                if let Some(mut shm_regions) = virtio_dev.get_shm_regions() {
                    if shm_regions.addr.raw_value() == old_base {
                        // Remove old region from KVM by passing a size of 0.
                        let mem_region = self.vm.make_user_memory_region(
                            shm_regions.mem_slot,
                            old_base,
                            0,
                            shm_regions.host_addr,
                            false,
                            false,
                        );

                        self.vm.set_user_memory_region(mem_region).map_err(|e| {
                            io::Error::new(
                                io::ErrorKind::Other,
                                format!("failed to set user memory region: {:?}", e),
                            )
                        })?;

                        // Create new mapping by inserting new region to KVM.
                        let mem_region = self.vm.make_user_memory_region(
                            shm_regions.mem_slot,
                            new_base,
                            shm_regions.len,
                            shm_regions.host_addr,
                            false,
                            false,
                        );

                        self.vm.set_user_memory_region(mem_region).map_err(|e| {
                            io::Error::new(
                                io::ErrorKind::Other,
                                format!("failed to set user memory regions: {:?}", e),
                            )
                        })?;

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

#[derive(Serialize, Deserialize)]
struct DeviceManagerState {
    device_tree: DeviceTree,
    device_id_cnt: Wrapping<usize>,
}

#[derive(Debug)]
pub struct PtyPair {
    pub main: File,
    pub sub: File,
    pub path: PathBuf,
}

impl PtyPair {
    fn clone(&self) -> Self {
        PtyPair {
            main: self.main.try_clone().unwrap(),
            sub: self.sub.try_clone().unwrap(),
            path: self.path.clone(),
        }
    }
}

#[derive(Clone)]
pub enum PciDeviceHandle {
    #[cfg(feature = "kvm")]
    Vfio(Arc<Mutex<VfioPciDevice>>),
    Virtio(Arc<Mutex<VirtioPciDevice>>),
}

pub struct DeviceManager {
    // Manage address space related to devices
    address_manager: Arc<AddressManager>,

    // Console abstraction
    console: Arc<Console>,

    // console PTY
    console_pty: Option<Arc<Mutex<PtyPair>>>,

    // serial PTY
    serial_pty: Option<Arc<Mutex<PtyPair>>>,

    // Interrupt controller
    #[cfg(target_arch = "x86_64")]
    interrupt_controller: Option<Arc<Mutex<ioapic::Ioapic>>>,
    #[cfg(target_arch = "aarch64")]
    interrupt_controller: Option<Arc<Mutex<gic::Gic>>>,

    // Things to be added to the commandline (i.e. for virtio-mmio)
    cmdline_additions: Vec<String>,

    // ACPI GED notification device
    #[cfg(feature = "acpi")]
    ged_notification_device: Option<Arc<Mutex<devices::AcpiGedDevice>>>,

    // VM configuration
    config: Arc<Mutex<VmConfig>>,

    // Memory Manager
    memory_manager: Arc<Mutex<MemoryManager>>,

    // The virtio devices on the system
    virtio_devices: Vec<(VirtioDeviceArc, bool, String)>,

    // List of bus devices
    // Let the DeviceManager keep strong references to the BusDevice devices.
    // This allows the IO and MMIO buses to be provided with Weak references,
    // which prevents cyclic dependencies.
    bus_devices: Vec<Arc<Mutex<dyn BusDevice>>>,

    // Counter to keep track of the consumed device IDs.
    device_id_cnt: Wrapping<usize>,

    // Keep a reference to the PCI bus
    pci_bus: Option<Arc<Mutex<PciBus>>>,

    #[cfg_attr(target_arch = "aarch64", allow(dead_code))]
    // MSI Interrupt Manager
    msi_interrupt_manager: Arc<dyn InterruptManager<GroupConfig = MsiIrqGroupConfig>>,

    #[cfg_attr(feature = "mshv", allow(dead_code))]
    // Legacy Interrupt Manager
    legacy_interrupt_manager: Option<Arc<dyn InterruptManager<GroupConfig = LegacyIrqGroupConfig>>>,

    // Passthrough device handle
    passthrough_device: Option<Arc<dyn hypervisor::Device>>,

    // Paravirtualized IOMMU
    iommu_device: Option<Arc<Mutex<virtio_devices::Iommu>>>,

    // Bitmap of PCI devices to hotplug.
    pci_devices_up: u32,

    // Bitmap of PCI devices to hotunplug.
    pci_devices_down: u32,

    // List of allocated IRQs for each PCI slot.
    pci_irq_slots: [u8; 32],

    // Tree of devices, representing the dependencies between devices.
    // Useful for introspection, snapshot and restore.
    device_tree: Arc<Mutex<DeviceTree>>,

    // Exit event
    #[cfg(feature = "acpi")]
    exit_evt: EventFd,

    reset_evt: EventFd,

    #[cfg(target_arch = "aarch64")]
    id_to_dev_info: HashMap<(DeviceType, String), MmioDeviceInfo>,

    // seccomp action
    seccomp_action: SeccompAction,

    // List of guest NUMA nodes.
    #[cfg(feature = "acpi")]
    numa_nodes: NumaNodes,

    // Possible handle to the virtio-balloon device
    balloon: Option<Arc<Mutex<virtio_devices::Balloon>>>,

    // Virtio Device activation EventFd to allow the VMM thread to trigger device
    // activation and thus start the threads from the VMM thread
    activate_evt: EventFd,

    #[cfg(feature = "acpi")]
    acpi_address: GuestAddress,

    // Possible handle to the virtio-balloon device
    virtio_mem_devices: Vec<Arc<Mutex<virtio_devices::Mem>>>,

    #[cfg(target_arch = "aarch64")]
    // GPIO device for AArch64
    gpio_device: Option<Arc<Mutex<devices::legacy::Gpio>>>,
}

impl DeviceManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vm: Arc<dyn hypervisor::Vm>,
        config: Arc<Mutex<VmConfig>>,
        memory_manager: Arc<Mutex<MemoryManager>>,
        _exit_evt: &EventFd,
        reset_evt: &EventFd,
        seccomp_action: SeccompAction,
        #[cfg(feature = "acpi")] numa_nodes: NumaNodes,
        activate_evt: &EventFd,
    ) -> DeviceManagerResult<Arc<Mutex<Self>>> {
        let device_tree = Arc::new(Mutex::new(DeviceTree::new()));

        let address_manager = Arc::new(AddressManager {
            allocator: memory_manager.lock().unwrap().allocator(),
            #[cfg(target_arch = "x86_64")]
            io_bus: Arc::new(Bus::new()),
            mmio_bus: Arc::new(Bus::new()),
            vm: vm.clone(),
            device_tree: Arc::clone(&device_tree),
        });

        // First we create the MSI interrupt manager, the legacy one is created
        // later, after the IOAPIC device creation.
        // The reason we create the MSI one first is because the IOAPIC needs it,
        // and then the legacy interrupt manager needs an IOAPIC. So we're
        // handling a linear dependency chain:
        // msi_interrupt_manager <- IOAPIC <- legacy_interrupt_manager.
        let msi_interrupt_manager: Arc<dyn InterruptManager<GroupConfig = MsiIrqGroupConfig>> =
            Arc::new(MsiInterruptManager::new(
                Arc::clone(&address_manager.allocator),
                vm,
            ));

        #[cfg(feature = "acpi")]
        let acpi_address = address_manager
            .allocator
            .lock()
            .unwrap()
            .allocate_mmio_addresses(None, DEVICE_MANAGER_ACPI_SIZE as u64, None)
            .ok_or(DeviceManagerError::AllocateIoPort)?;
        let device_manager = DeviceManager {
            address_manager: Arc::clone(&address_manager),
            console: Arc::new(Console::default()),
            interrupt_controller: None,
            cmdline_additions: Vec::new(),
            #[cfg(feature = "acpi")]
            ged_notification_device: None,
            config,
            memory_manager,
            virtio_devices: Vec::new(),
            bus_devices: Vec::new(),
            device_id_cnt: Wrapping(0),
            pci_bus: None,
            msi_interrupt_manager,
            legacy_interrupt_manager: None,
            passthrough_device: None,
            iommu_device: None,
            pci_devices_up: 0,
            pci_devices_down: 0,
            pci_irq_slots: [0; 32],
            device_tree,
            #[cfg(feature = "acpi")]
            exit_evt: _exit_evt.try_clone().map_err(DeviceManagerError::EventFd)?,
            reset_evt: reset_evt.try_clone().map_err(DeviceManagerError::EventFd)?,
            #[cfg(target_arch = "aarch64")]
            id_to_dev_info: HashMap::new(),
            seccomp_action,
            #[cfg(feature = "acpi")]
            numa_nodes,
            balloon: None,
            activate_evt: activate_evt
                .try_clone()
                .map_err(DeviceManagerError::EventFd)?,
            #[cfg(feature = "acpi")]
            acpi_address,
            serial_pty: None,
            console_pty: None,
            virtio_mem_devices: Vec::new(),
            #[cfg(target_arch = "aarch64")]
            gpio_device: None,
        };

        let device_manager = Arc::new(Mutex::new(device_manager));

        #[cfg(feature = "acpi")]
        address_manager
            .mmio_bus
            .insert(
                Arc::clone(&device_manager) as Arc<Mutex<dyn BusDevice>>,
                acpi_address.0,
                DEVICE_MANAGER_ACPI_SIZE as u64,
            )
            .map_err(DeviceManagerError::BusError)?;

        Ok(device_manager)
    }

    pub fn serial_pty(&self) -> Option<PtyPair> {
        self.serial_pty
            .as_ref()
            .map(|pty| pty.lock().unwrap().clone())
    }

    pub fn console_pty(&self) -> Option<PtyPair> {
        self.console_pty
            .as_ref()
            .map(|pty| pty.lock().unwrap().clone())
    }

    pub fn create_devices(
        &mut self,
        serial_pty: Option<PtyPair>,
        console_pty: Option<PtyPair>,
    ) -> DeviceManagerResult<()> {
        let mut virtio_devices: Vec<(VirtioDeviceArc, bool, String)> = Vec::new();

        let interrupt_controller = self.add_interrupt_controller()?;

        // Now we can create the legacy interrupt manager, which needs the freshly
        // formed IOAPIC device.
        let legacy_interrupt_manager: Arc<
            dyn InterruptManager<GroupConfig = LegacyIrqGroupConfig>,
        > = Arc::new(LegacyUserspaceInterruptManager::new(Arc::clone(
            &interrupt_controller,
        )));

        #[cfg(feature = "acpi")]
        {
            let memory_manager_acpi_address = self.memory_manager.lock().unwrap().acpi_address;
            self.address_manager
                .mmio_bus
                .insert(
                    Arc::clone(&self.memory_manager) as Arc<Mutex<dyn BusDevice>>,
                    memory_manager_acpi_address.0,
                    MEMORY_MANAGER_ACPI_SIZE as u64,
                )
                .map_err(DeviceManagerError::BusError)?;
        }

        #[cfg(target_arch = "x86_64")]
        self.add_legacy_devices(
            self.reset_evt
                .try_clone()
                .map_err(DeviceManagerError::EventFd)?,
        )?;

        #[cfg(target_arch = "aarch64")]
        self.add_legacy_devices(&legacy_interrupt_manager)?;

        #[cfg(feature = "acpi")]
        {
            self.ged_notification_device = self.add_acpi_devices(
                &legacy_interrupt_manager,
                self.reset_evt
                    .try_clone()
                    .map_err(DeviceManagerError::EventFd)?,
                self.exit_evt
                    .try_clone()
                    .map_err(DeviceManagerError::EventFd)?,
            )?;
        }

        self.console = self.add_console_device(
            &legacy_interrupt_manager,
            &mut virtio_devices,
            serial_pty,
            console_pty,
        )?;

        // Reserve some IRQs for PCI devices in case they need to support INTx.
        self.reserve_legacy_interrupts_for_pci_devices()?;

        self.legacy_interrupt_manager = Some(legacy_interrupt_manager);

        virtio_devices.append(&mut self.make_virtio_devices()?);

        self.add_pci_devices(virtio_devices.clone())?;

        self.virtio_devices = virtio_devices;

        Ok(())
    }

    fn reserve_legacy_interrupts_for_pci_devices(&mut self) -> DeviceManagerResult<()> {
        // Reserve 8 IRQs which will be shared across all PCI devices.
        let num_irqs = 8;
        let mut irqs: Vec<u8> = Vec::new();
        for _ in 0..num_irqs {
            irqs.push(
                self.address_manager
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

    fn state(&self) -> DeviceManagerState {
        DeviceManagerState {
            device_tree: self.device_tree.lock().unwrap().clone(),
            device_id_cnt: self.device_id_cnt,
        }
    }

    fn set_state(&mut self, state: &DeviceManagerState) {
        self.device_tree = Arc::new(Mutex::new(state.device_tree.clone()));
        self.device_id_cnt = state.device_id_cnt;
    }

    #[cfg(target_arch = "aarch64")]
    /// Gets the information of the devices registered up to some point in time.
    pub fn get_device_info(&self) -> &HashMap<(DeviceType, String), MmioDeviceInfo> {
        &self.id_to_dev_info
    }

    #[allow(unused_variables)]
    fn add_pci_devices(
        &mut self,
        virtio_devices: Vec<(VirtioDeviceArc, bool, String)>,
    ) -> DeviceManagerResult<()> {
        let pci_root = PciRoot::new(None);
        let mut pci_bus = PciBus::new(
            pci_root,
            Arc::clone(&self.address_manager) as Arc<dyn DeviceRelocation>,
        );

        let iommu_id = String::from(IOMMU_DEVICE_NAME);

        let (iommu_device, iommu_mapping) = if self.config.lock().unwrap().iommu {
            let (device, mapping) =
                virtio_devices::Iommu::new(iommu_id.clone(), self.seccomp_action.clone())
                    .map_err(DeviceManagerError::CreateVirtioIommu)?;
            let device = Arc::new(Mutex::new(device));
            self.iommu_device = Some(Arc::clone(&device));

            // Fill the device tree with a new node. In case of restore, we
            // know there is nothing to do, so we can simply override the
            // existing entry.
            self.device_tree
                .lock()
                .unwrap()
                .insert(iommu_id.clone(), device_node!(iommu_id, device));

            (Some(device), Some(mapping))
        } else {
            (None, None)
        };

        let mut iommu_attached_devices = Vec::new();

        for (device, iommu_attached, id) in virtio_devices {
            let mapping: &Option<Arc<IommuMapping>> = if iommu_attached {
                &iommu_mapping
            } else {
                &None
            };

            let dev_id = self.add_virtio_pci_device(device, &mut pci_bus, mapping, id)?;

            if iommu_attached {
                iommu_attached_devices.push(dev_id);
            }
        }

        let mut vfio_iommu_device_ids = self.add_vfio_devices(&mut pci_bus)?;

        iommu_attached_devices.append(&mut vfio_iommu_device_ids);

        if let Some(iommu_device) = iommu_device {
            iommu_device
                .lock()
                .unwrap()
                .attach_pci_devices(0, iommu_attached_devices);

            // Because we determined the virtio-iommu b/d/f, we have to
            // add the device to the PCI topology now. Otherwise, the
            // b/d/f won't match the virtio-iommu device as expected.
            self.add_virtio_pci_device(iommu_device, &mut pci_bus, &None, iommu_id)?;
        }

        let pci_bus = Arc::new(Mutex::new(pci_bus));
        let pci_config_io = Arc::new(Mutex::new(PciConfigIo::new(Arc::clone(&pci_bus))));
        self.bus_devices
            .push(Arc::clone(&pci_config_io) as Arc<Mutex<dyn BusDevice>>);
        #[cfg(target_arch = "x86_64")]
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

        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn add_interrupt_controller(
        &mut self,
    ) -> DeviceManagerResult<Arc<Mutex<dyn InterruptController>>> {
        let interrupt_controller: Arc<Mutex<gic::Gic>> = Arc::new(Mutex::new(
            gic::Gic::new(
                self.config.lock().unwrap().cpus.boot_vcpus,
                Arc::clone(&self.msi_interrupt_manager),
            )
            .map_err(DeviceManagerError::CreateInterruptController)?,
        ));

        self.interrupt_controller = Some(interrupt_controller.clone());

        // Unlike x86_64, the "interrupt_controller" here for AArch64 is only
        // a `Gic` object that implements the `InterruptController` to provide
        // interrupt delivery service. This is not the real GIC device so that
        // we do not need to insert it to the device tree.

        Ok(interrupt_controller)
    }

    #[cfg(target_arch = "aarch64")]
    pub fn get_interrupt_controller(&mut self) -> Option<&Arc<Mutex<gic::Gic>>> {
        self.interrupt_controller.as_ref()
    }

    #[cfg(target_arch = "x86_64")]
    fn add_interrupt_controller(
        &mut self,
    ) -> DeviceManagerResult<Arc<Mutex<dyn InterruptController>>> {
        let id = String::from(IOAPIC_DEVICE_NAME);

        // Create IOAPIC
        let interrupt_controller = Arc::new(Mutex::new(
            ioapic::Ioapic::new(
                id.clone(),
                APIC_START,
                Arc::clone(&self.msi_interrupt_manager),
            )
            .map_err(DeviceManagerError::CreateInterruptController)?,
        ));

        self.interrupt_controller = Some(interrupt_controller.clone());

        self.address_manager
            .mmio_bus
            .insert(interrupt_controller.clone(), IOAPIC_START.0, IOAPIC_SIZE)
            .map_err(DeviceManagerError::BusError)?;

        self.bus_devices
            .push(Arc::clone(&interrupt_controller) as Arc<Mutex<dyn BusDevice>>);

        // Fill the device tree with a new node. In case of restore, we
        // know there is nothing to do, so we can simply override the
        // existing entry.
        self.device_tree
            .lock()
            .unwrap()
            .insert(id.clone(), device_node!(id, interrupt_controller));

        Ok(interrupt_controller)
    }

    #[cfg(feature = "acpi")]
    fn add_acpi_devices(
        &mut self,
        interrupt_manager: &Arc<dyn InterruptManager<GroupConfig = LegacyIrqGroupConfig>>,
        reset_evt: EventFd,
        exit_evt: EventFd,
    ) -> DeviceManagerResult<Option<Arc<Mutex<devices::AcpiGedDevice>>>> {
        let shutdown_device = Arc::new(Mutex::new(devices::AcpiShutdownDevice::new(
            exit_evt, reset_evt,
        )));

        self.bus_devices
            .push(Arc::clone(&shutdown_device) as Arc<Mutex<dyn BusDevice>>);

        #[cfg(target_arch = "x86_64")]
        {
            self.address_manager
                .allocator
                .lock()
                .unwrap()
                .allocate_io_addresses(Some(GuestAddress(0x3c0)), 0x8, None)
                .ok_or(DeviceManagerError::AllocateIoPort)?;

            self.address_manager
                .io_bus
                .insert(shutdown_device, 0x3c0, 0x4)
                .map_err(DeviceManagerError::BusError)?;
        }

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
        let ged_address = self
            .address_manager
            .allocator
            .lock()
            .unwrap()
            .allocate_mmio_addresses(None, devices::acpi::GED_DEVICE_ACPI_SIZE as u64, None)
            .ok_or(DeviceManagerError::AllocateMmioAddress)?;
        let ged_device = Arc::new(Mutex::new(devices::AcpiGedDevice::new(
            interrupt_group,
            ged_irq,
            ged_address,
        )));
        self.address_manager
            .mmio_bus
            .insert(
                ged_device.clone(),
                ged_address.0,
                devices::acpi::GED_DEVICE_ACPI_SIZE as u64,
            )
            .map_err(DeviceManagerError::BusError)?;
        self.bus_devices
            .push(Arc::clone(&ged_device) as Arc<Mutex<dyn BusDevice>>);

        let pm_timer_device = Arc::new(Mutex::new(devices::AcpiPmTimerDevice::new()));

        self.bus_devices
            .push(Arc::clone(&pm_timer_device) as Arc<Mutex<dyn BusDevice>>);

        #[cfg(target_arch = "x86_64")]
        {
            self.address_manager
                .allocator
                .lock()
                .unwrap()
                .allocate_io_addresses(Some(GuestAddress(0xb008)), 0x4, None)
                .ok_or(DeviceManagerError::AllocateIoPort)?;

            self.address_manager
                .io_bus
                .insert(pm_timer_device, 0xb008, 0x4)
                .map_err(DeviceManagerError::BusError)?;
        }

        Ok(Some(ged_device))
    }

    #[cfg(target_arch = "x86_64")]
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

    #[cfg(target_arch = "aarch64")]
    fn add_legacy_devices(
        &mut self,
        interrupt_manager: &Arc<dyn InterruptManager<GroupConfig = LegacyIrqGroupConfig>>,
    ) -> DeviceManagerResult<()> {
        // Add a RTC device
        let rtc_irq = self
            .address_manager
            .allocator
            .lock()
            .unwrap()
            .allocate_irq()
            .unwrap();

        let interrupt_group = interrupt_manager
            .create_group(LegacyIrqGroupConfig {
                irq: rtc_irq as InterruptIndex,
            })
            .map_err(DeviceManagerError::CreateInterruptGroup)?;

        let rtc_device = Arc::new(Mutex::new(devices::legacy::Rtc::new(interrupt_group)));

        self.bus_devices
            .push(Arc::clone(&rtc_device) as Arc<Mutex<dyn BusDevice>>);

        let addr = GuestAddress(arch::layout::LEGACY_RTC_MAPPED_IO_START);

        self.address_manager
            .mmio_bus
            .insert(rtc_device, addr.0, MMIO_LEN)
            .map_err(DeviceManagerError::BusError)?;

        self.id_to_dev_info.insert(
            (DeviceType::Rtc, "rtc".to_string()),
            MmioDeviceInfo {
                addr: addr.0,
                irq: rtc_irq,
            },
        );

        // Add a GPIO device
        let id = String::from(GPIO_DEVICE_NAME_PREFIX);
        let gpio_irq = self
            .address_manager
            .allocator
            .lock()
            .unwrap()
            .allocate_irq()
            .unwrap();

        let interrupt_group = interrupt_manager
            .create_group(LegacyIrqGroupConfig {
                irq: gpio_irq as InterruptIndex,
            })
            .map_err(DeviceManagerError::CreateInterruptGroup)?;

        let gpio_device = Arc::new(Mutex::new(devices::legacy::Gpio::new(
            id.clone(),
            interrupt_group,
        )));

        self.bus_devices
            .push(Arc::clone(&gpio_device) as Arc<Mutex<dyn BusDevice>>);

        let addr = GuestAddress(arch::layout::LEGACY_GPIO_MAPPED_IO_START);

        self.address_manager
            .mmio_bus
            .insert(gpio_device.clone(), addr.0, MMIO_LEN)
            .map_err(DeviceManagerError::BusError)?;

        self.gpio_device = Some(gpio_device.clone());

        self.id_to_dev_info.insert(
            (DeviceType::Gpio, "gpio".to_string()),
            MmioDeviceInfo {
                addr: addr.0,
                irq: gpio_irq,
            },
        );

        self.device_tree
            .lock()
            .unwrap()
            .insert(id.clone(), device_node!(id, gpio_device));

        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn add_serial_device(
        &mut self,
        interrupt_manager: &Arc<dyn InterruptManager<GroupConfig = LegacyIrqGroupConfig>>,
        serial_writer: Option<Box<dyn io::Write + Send>>,
    ) -> DeviceManagerResult<Arc<Mutex<Serial>>> {
        // Serial is tied to IRQ #4
        let serial_irq = 4;

        let id = String::from(SERIAL_DEVICE_NAME_PREFIX);

        let interrupt_group = interrupt_manager
            .create_group(LegacyIrqGroupConfig {
                irq: serial_irq as InterruptIndex,
            })
            .map_err(DeviceManagerError::CreateInterruptGroup)?;

        let serial = Arc::new(Mutex::new(Serial::new(
            id.clone(),
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
            .ok_or(DeviceManagerError::AllocateIoPort)?;

        self.address_manager
            .io_bus
            .insert(serial.clone(), 0x3f8, 0x8)
            .map_err(DeviceManagerError::BusError)?;

        // Fill the device tree with a new node. In case of restore, we
        // know there is nothing to do, so we can simply override the
        // existing entry.
        self.device_tree
            .lock()
            .unwrap()
            .insert(id.clone(), device_node!(id, serial));

        Ok(serial)
    }

    #[cfg(target_arch = "aarch64")]
    fn add_serial_device(
        &mut self,
        interrupt_manager: &Arc<dyn InterruptManager<GroupConfig = LegacyIrqGroupConfig>>,
        serial_writer: Option<Box<dyn io::Write + Send>>,
    ) -> DeviceManagerResult<Arc<Mutex<Pl011>>> {
        let id = String::from(SERIAL_DEVICE_NAME_PREFIX);

        let serial_irq = self
            .address_manager
            .allocator
            .lock()
            .unwrap()
            .allocate_irq()
            .unwrap();

        let interrupt_group = interrupt_manager
            .create_group(LegacyIrqGroupConfig {
                irq: serial_irq as InterruptIndex,
            })
            .map_err(DeviceManagerError::CreateInterruptGroup)?;

        let serial = Arc::new(Mutex::new(devices::legacy::Pl011::new(
            id.clone(),
            interrupt_group,
            serial_writer,
        )));

        self.bus_devices
            .push(Arc::clone(&serial) as Arc<Mutex<dyn BusDevice>>);

        let addr = GuestAddress(arch::layout::LEGACY_SERIAL_MAPPED_IO_START);

        self.address_manager
            .mmio_bus
            .insert(serial.clone(), addr.0, MMIO_LEN)
            .map_err(DeviceManagerError::BusError)?;

        self.id_to_dev_info.insert(
            (DeviceType::Serial, DeviceType::Serial.to_string()),
            MmioDeviceInfo {
                addr: addr.0,
                irq: serial_irq,
            },
        );

        self.cmdline_additions
            .push(format!("earlycon=pl011,mmio,0x{:08x}", addr.0));

        // Fill the device tree with a new node. In case of restore, we
        // know there is nothing to do, so we can simply override the
        // existing entry.
        self.device_tree
            .lock()
            .unwrap()
            .insert(id.clone(), device_node!(id, serial));

        Ok(serial)
    }

    fn modify_mode<F: FnOnce(&mut termios)>(
        &self,
        fd: RawFd,
        f: F,
    ) -> vmm_sys_util::errno::Result<()> {
        // Safe because we check the return value of isatty.
        if unsafe { isatty(fd) } != 1 {
            return Ok(());
        }

        // The following pair are safe because termios gets totally overwritten by tcgetattr and we
        // check the return result.
        let mut termios: termios = unsafe { zeroed() };
        let ret = unsafe { tcgetattr(fd, &mut termios as *mut _) };
        if ret < 0 {
            return vmm_sys_util::errno::errno_result();
        }
        f(&mut termios);
        // Safe because the syscall will only read the extent of termios and we check the return result.
        let ret = unsafe { tcsetattr(fd, TCSANOW, &termios as *const _) };
        if ret < 0 {
            return vmm_sys_util::errno::errno_result();
        }

        Ok(())
    }

    fn set_raw_mode(&self, f: &mut File) -> vmm_sys_util::errno::Result<()> {
        self.modify_mode(f.as_raw_fd(), |t| t.c_lflag &= !(ICANON | ECHO | ISIG))
    }

    fn add_console_device(
        &mut self,
        interrupt_manager: &Arc<dyn InterruptManager<GroupConfig = LegacyIrqGroupConfig>>,
        virtio_devices: &mut Vec<(VirtioDeviceArc, bool, String)>,
        serial_pty: Option<PtyPair>,
        console_pty: Option<PtyPair>,
    ) -> DeviceManagerResult<Arc<Console>> {
        let serial_config = self.config.lock().unwrap().serial.clone();
        let serial_writer: Option<Box<dyn io::Write + Send>> = match serial_config.mode {
            ConsoleOutputMode::File => Some(Box::new(
                File::create(serial_config.file.as_ref().unwrap())
                    .map_err(DeviceManagerError::SerialOutputFileOpen)?,
            )),
            ConsoleOutputMode::Pty => {
                if let Some(pty) = serial_pty {
                    self.config.lock().unwrap().serial.file = Some(pty.path.clone());
                    let writer = pty.main.try_clone().unwrap();
                    self.serial_pty = Some(Arc::new(Mutex::new(pty)));
                    Some(Box::new(writer))
                } else {
                    let (main, mut sub, path) =
                        create_pty().map_err(DeviceManagerError::SerialPtyOpen)?;
                    self.set_raw_mode(&mut sub)
                        .map_err(DeviceManagerError::SetPtyRaw)?;
                    self.config.lock().unwrap().serial.file = Some(path.clone());
                    let writer = main.try_clone().unwrap();
                    self.serial_pty = Some(Arc::new(Mutex::new(PtyPair { main, sub, path })));
                    Some(Box::new(writer))
                }
            }
            ConsoleOutputMode::Tty => Some(Box::new(stdout())),
            ConsoleOutputMode::Off | ConsoleOutputMode::Null => None,
        };
        let serial = if serial_config.mode != ConsoleOutputMode::Off {
            Some(self.add_serial_device(interrupt_manager, serial_writer)?)
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
            ConsoleOutputMode::Pty => {
                if let Some(pty) = console_pty {
                    self.config.lock().unwrap().console.file = Some(pty.path.clone());
                    let writer = pty.main.try_clone().unwrap();
                    self.console_pty = Some(Arc::new(Mutex::new(pty)));
                    Some(Box::new(writer))
                } else {
                    let (main, mut sub, path) =
                        create_pty().map_err(DeviceManagerError::ConsolePtyOpen)?;
                    self.set_raw_mode(&mut sub)
                        .map_err(DeviceManagerError::SetPtyRaw)?;
                    self.config.lock().unwrap().console.file = Some(path.clone());
                    let writer = main.try_clone().unwrap();
                    self.console_pty = Some(Arc::new(Mutex::new(PtyPair { main, sub, path })));
                    Some(Box::new(writer))
                }
            }
            ConsoleOutputMode::Tty => Some(Box::new(stdout())),
            ConsoleOutputMode::Null => Some(Box::new(sink())),
            ConsoleOutputMode::Off => None,
        };
        let (col, row) = get_win_size();
        let virtio_console_input = if let Some(writer) = console_writer {
            let id = String::from(CONSOLE_DEVICE_NAME);

            let (virtio_console_device, virtio_console_input) = virtio_devices::Console::new(
                id.clone(),
                writer,
                col,
                row,
                console_config.iommu,
                self.seccomp_action.clone(),
            )
            .map_err(DeviceManagerError::CreateVirtioConsole)?;
            let virtio_console_device = Arc::new(Mutex::new(virtio_console_device));
            virtio_devices.push((
                Arc::clone(&virtio_console_device) as VirtioDeviceArc,
                console_config.iommu,
                id.clone(),
            ));

            // Fill the device tree with a new node. In case of restore, we
            // know there is nothing to do, so we can simply override the
            // existing entry.
            self.device_tree
                .lock()
                .unwrap()
                .insert(id.clone(), device_node!(id, virtio_console_device));

            Some(virtio_console_input)
        } else {
            None
        };

        let input = if serial_config.mode.input_enabled() {
            Some(ConsoleInput::Serial)
        } else if console_config.mode.input_enabled() {
            Some(ConsoleInput::VirtioConsole)
        } else {
            None
        };

        Ok(Arc::new(Console {
            serial,
            virtio_console_input,
            input,
        }))
    }

    fn make_virtio_devices(&mut self) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool, String)>> {
        let mut devices: Vec<(VirtioDeviceArc, bool, String)> = Vec::new();

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

        devices.append(&mut self.make_virtio_mem_devices()?);

        // Add virtio-balloon if required
        devices.append(&mut self.make_virtio_balloon_devices()?);

        // Add virtio-watchdog device
        devices.append(&mut self.make_virtio_watchdog_devices()?);

        Ok(devices)
    }

    fn make_virtio_block_device(
        &mut self,
        disk_cfg: &mut DiskConfig,
    ) -> DeviceManagerResult<(VirtioDeviceArc, bool, String)> {
        let id = if let Some(id) = &disk_cfg.id {
            id.clone()
        } else {
            let id = self.next_device_name(DISK_DEVICE_NAME_PREFIX)?;
            disk_cfg.id = Some(id.clone());
            id
        };

        info!("Creating virtio-block device: {:?}", disk_cfg);

        if disk_cfg.vhost_user {
            let socket = disk_cfg.vhost_socket.as_ref().unwrap().clone();
            let vu_cfg = VhostUserConfig {
                socket,
                num_queues: disk_cfg.num_queues,
                queue_size: disk_cfg.queue_size,
            };
            let vhost_user_block_device = Arc::new(Mutex::new(
                match virtio_devices::vhost_user::Blk::new(id.clone(), vu_cfg) {
                    Ok(vub_device) => vub_device,
                    Err(e) => {
                        return Err(DeviceManagerError::CreateVhostUserBlk(e));
                    }
                },
            ));

            // Fill the device tree with a new node. In case of restore, we
            // know there is nothing to do, so we can simply override the
            // existing entry.
            self.device_tree
                .lock()
                .unwrap()
                .insert(id.clone(), device_node!(id, vhost_user_block_device));

            Ok((
                Arc::clone(&vhost_user_block_device) as VirtioDeviceArc,
                false,
                id,
            ))
        } else {
            let mut options = OpenOptions::new();
            options.read(true);
            options.write(!disk_cfg.readonly);
            if disk_cfg.direct {
                options.custom_flags(libc::O_DIRECT);
            }
            // Open block device path
            let mut file: File = options
                .open(
                    disk_cfg
                        .path
                        .as_ref()
                        .ok_or(DeviceManagerError::NoDiskPath)?
                        .clone(),
                )
                .map_err(DeviceManagerError::Disk)?;
            let image_type =
                detect_image_type(&mut file).map_err(DeviceManagerError::DetectImageType)?;

            let image = match image_type {
                ImageType::FixedVhd => {
                    // Use asynchronous backend relying on io_uring if the
                    // syscalls are supported.
                    if block_io_uring_is_supported() && !disk_cfg.disable_io_uring {
                        info!("Using asynchronous fixed VHD disk file (io_uring)");
                        Box::new(
                            FixedVhdDiskAsync::new(file)
                                .map_err(DeviceManagerError::CreateFixedVhdDiskAsync)?,
                        ) as Box<dyn DiskFile>
                    } else {
                        info!("Using synchronous fixed VHD disk file");
                        Box::new(
                            FixedVhdDiskSync::new(file)
                                .map_err(DeviceManagerError::CreateFixedVhdDiskSync)?,
                        ) as Box<dyn DiskFile>
                    }
                }
                ImageType::Raw => {
                    // Use asynchronous backend relying on io_uring if the
                    // syscalls are supported.
                    if block_io_uring_is_supported() && !disk_cfg.disable_io_uring {
                        info!("Using asynchronous RAW disk file (io_uring)");
                        Box::new(RawFileDisk::new(file)) as Box<dyn DiskFile>
                    } else {
                        info!("Using synchronous RAW disk file");
                        Box::new(RawFileDiskSync::new(file)) as Box<dyn DiskFile>
                    }
                }
                ImageType::Qcow2 => {
                    info!("Using synchronous QCOW disk file");
                    Box::new(QcowDiskSync::new(file, disk_cfg.direct)) as Box<dyn DiskFile>
                }
            };

            let dev = Arc::new(Mutex::new(
                virtio_devices::Block::new(
                    id.clone(),
                    image,
                    disk_cfg
                        .path
                        .as_ref()
                        .ok_or(DeviceManagerError::NoDiskPath)?
                        .clone(),
                    disk_cfg.readonly,
                    disk_cfg.iommu,
                    disk_cfg.num_queues,
                    disk_cfg.queue_size,
                    self.seccomp_action.clone(),
                    disk_cfg.rate_limiter_config,
                )
                .map_err(DeviceManagerError::CreateVirtioBlock)?,
            ));

            let virtio_device = Arc::clone(&dev) as VirtioDeviceArc;
            let migratable_device = dev as Arc<Mutex<dyn Migratable>>;

            // Fill the device tree with a new node. In case of restore, we
            // know there is nothing to do, so we can simply override the
            // existing entry.
            self.device_tree
                .lock()
                .unwrap()
                .insert(id.clone(), device_node!(id, migratable_device));

            Ok((virtio_device, disk_cfg.iommu, id))
        }
    }

    fn make_virtio_block_devices(
        &mut self,
    ) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool, String)>> {
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

    fn make_virtio_net_device(
        &mut self,
        net_cfg: &mut NetConfig,
    ) -> DeviceManagerResult<(VirtioDeviceArc, bool, String)> {
        let id = if let Some(id) = &net_cfg.id {
            id.clone()
        } else {
            let id = self.next_device_name(NET_DEVICE_NAME_PREFIX)?;
            net_cfg.id = Some(id.clone());
            id
        };
        info!("Creating virtio-net device: {:?}", net_cfg);

        if net_cfg.vhost_user {
            let socket = net_cfg.vhost_socket.as_ref().unwrap().clone();
            let vu_cfg = VhostUserConfig {
                socket,
                num_queues: net_cfg.num_queues,
                queue_size: net_cfg.queue_size,
            };
            let server = match net_cfg.vhost_mode {
                VhostMode::Client => false,
                VhostMode::Server => true,
            };
            let vhost_user_net_device = Arc::new(Mutex::new(
                match virtio_devices::vhost_user::Net::new(
                    id.clone(),
                    net_cfg.mac,
                    vu_cfg,
                    server,
                    self.seccomp_action.clone(),
                ) {
                    Ok(vun_device) => vun_device,
                    Err(e) => {
                        return Err(DeviceManagerError::CreateVhostUserNet(e));
                    }
                },
            ));

            // Fill the device tree with a new node. In case of restore, we
            // know there is nothing to do, so we can simply override the
            // existing entry.
            self.device_tree
                .lock()
                .unwrap()
                .insert(id.clone(), device_node!(id, vhost_user_net_device));

            Ok((
                Arc::clone(&vhost_user_net_device) as VirtioDeviceArc,
                net_cfg.iommu,
                id,
            ))
        } else {
            let virtio_net_device = if let Some(ref tap_if_name) = net_cfg.tap {
                Arc::new(Mutex::new(
                    virtio_devices::Net::new(
                        id.clone(),
                        Some(tap_if_name),
                        None,
                        None,
                        Some(net_cfg.mac),
                        &mut net_cfg.host_mac,
                        net_cfg.iommu,
                        net_cfg.num_queues,
                        net_cfg.queue_size,
                        self.seccomp_action.clone(),
                        net_cfg.rate_limiter_config,
                    )
                    .map_err(DeviceManagerError::CreateVirtioNet)?,
                ))
            } else if let Some(fds) = &net_cfg.fds {
                Arc::new(Mutex::new(
                    virtio_devices::Net::from_tap_fds(
                        id.clone(),
                        fds,
                        Some(net_cfg.mac),
                        net_cfg.iommu,
                        net_cfg.queue_size,
                        self.seccomp_action.clone(),
                        net_cfg.rate_limiter_config,
                    )
                    .map_err(DeviceManagerError::CreateVirtioNet)?,
                ))
            } else {
                Arc::new(Mutex::new(
                    virtio_devices::Net::new(
                        id.clone(),
                        None,
                        Some(net_cfg.ip),
                        Some(net_cfg.mask),
                        Some(net_cfg.mac),
                        &mut net_cfg.host_mac,
                        net_cfg.iommu,
                        net_cfg.num_queues,
                        net_cfg.queue_size,
                        self.seccomp_action.clone(),
                        net_cfg.rate_limiter_config,
                    )
                    .map_err(DeviceManagerError::CreateVirtioNet)?,
                ))
            };

            // Fill the device tree with a new node. In case of restore, we
            // know there is nothing to do, so we can simply override the
            // existing entry.
            self.device_tree
                .lock()
                .unwrap()
                .insert(id.clone(), device_node!(id, virtio_net_device));

            Ok((
                Arc::clone(&virtio_net_device) as VirtioDeviceArc,
                net_cfg.iommu,
                id,
            ))
        }
    }

    /// Add virto-net and vhost-user-net devices
    fn make_virtio_net_devices(
        &mut self,
    ) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool, String)>> {
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
    ) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool, String)>> {
        let mut devices = Vec::new();

        // Add virtio-rng if required
        let rng_config = self.config.lock().unwrap().rng.clone();
        if let Some(rng_path) = rng_config.src.to_str() {
            info!("Creating virtio-rng device: {:?}", rng_config);
            let id = String::from(RNG_DEVICE_NAME);

            let virtio_rng_device = Arc::new(Mutex::new(
                virtio_devices::Rng::new(
                    id.clone(),
                    rng_path,
                    rng_config.iommu,
                    self.seccomp_action.clone(),
                )
                .map_err(DeviceManagerError::CreateVirtioRng)?,
            ));
            devices.push((
                Arc::clone(&virtio_rng_device) as VirtioDeviceArc,
                rng_config.iommu,
                id.clone(),
            ));

            // Fill the device tree with a new node. In case of restore, we
            // know there is nothing to do, so we can simply override the
            // existing entry.
            self.device_tree
                .lock()
                .unwrap()
                .insert(id.clone(), device_node!(id, virtio_rng_device));
        }

        Ok(devices)
    }

    fn make_virtio_fs_device(
        &mut self,
        fs_cfg: &mut FsConfig,
    ) -> DeviceManagerResult<(VirtioDeviceArc, bool, String)> {
        let id = if let Some(id) = &fs_cfg.id {
            id.clone()
        } else {
            let id = self.next_device_name(FS_DEVICE_NAME_PREFIX)?;
            fs_cfg.id = Some(id.clone());
            id
        };

        info!("Creating virtio-fs device: {:?}", fs_cfg);

        let mut node = device_node!(id);

        // Look for the id in the device tree. If it can be found, that means
        // the device is being restored, otherwise it's created from scratch.
        let cache_range = if let Some(node) = self.device_tree.lock().unwrap().get(&id) {
            debug!("Restoring virtio-fs {} resources", id);

            let mut cache_range: Option<(u64, u64)> = None;
            for resource in node.resources.iter() {
                match resource {
                    Resource::MmioAddressRange { base, size } => {
                        if cache_range.is_some() {
                            return Err(DeviceManagerError::ResourceAlreadyExists);
                        }

                        cache_range = Some((*base, *size));
                    }
                    _ => {
                        error!("Unexpected resource {:?} for {}", resource, id);
                    }
                }
            }

            if cache_range.is_none() {
                return Err(DeviceManagerError::MissingVirtioFsResources);
            }

            cache_range
        } else {
            None
        };

        if let Some(fs_socket) = fs_cfg.socket.to_str() {
            let cache = if fs_cfg.dax {
                let (cache_base, cache_size) = if let Some((base, size)) = cache_range {
                    // The memory needs to be 2MiB aligned in order to support
                    // hugepages.
                    self.address_manager
                        .allocator
                        .lock()
                        .unwrap()
                        .allocate_mmio_addresses(
                            Some(GuestAddress(base)),
                            size as GuestUsize,
                            Some(0x0020_0000),
                        )
                        .ok_or(DeviceManagerError::FsRangeAllocation)?;

                    (base, size)
                } else {
                    let size = fs_cfg.cache_size;
                    // The memory needs to be 2MiB aligned in order to support
                    // hugepages.
                    let base = self
                        .address_manager
                        .allocator
                        .lock()
                        .unwrap()
                        .allocate_mmio_addresses(None, size as GuestUsize, Some(0x0020_0000))
                        .ok_or(DeviceManagerError::FsRangeAllocation)?;

                    (base.raw_value(), size)
                };

                // Update the node with correct resource information.
                node.resources.push(Resource::MmioAddressRange {
                    base: cache_base,
                    size: cache_size,
                });

                let mmap_region = MmapRegion::build(
                    None,
                    cache_size as usize,
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
                        cache_base, cache_size, host_addr, false, false, false,
                    )
                    .map_err(DeviceManagerError::MemoryManager)?;

                let region_list = vec![VirtioSharedMemory {
                    offset: 0,
                    len: cache_size,
                }];

                Some((
                    VirtioSharedMemoryList {
                        host_addr,
                        mem_slot,
                        addr: GuestAddress(cache_base),
                        len: cache_size as GuestUsize,
                        region_list,
                    },
                    mmap_region,
                ))
            } else {
                None
            };

            let virtio_fs_device = Arc::new(Mutex::new(
                virtio_devices::vhost_user::Fs::new(
                    id.clone(),
                    fs_socket,
                    &fs_cfg.tag,
                    fs_cfg.num_queues,
                    fs_cfg.queue_size,
                    cache,
                    self.seccomp_action.clone(),
                )
                .map_err(DeviceManagerError::CreateVirtioFs)?,
            ));

            // Update the device tree with the migratable device.
            node.migratable = Some(Arc::clone(&virtio_fs_device) as Arc<Mutex<dyn Migratable>>);
            self.device_tree.lock().unwrap().insert(id.clone(), node);

            Ok((Arc::clone(&virtio_fs_device) as VirtioDeviceArc, false, id))
        } else {
            Err(DeviceManagerError::NoVirtioFsSock)
        }
    }

    fn make_virtio_fs_devices(
        &mut self,
    ) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool, String)>> {
        let mut devices = Vec::new();

        let mut fs_devices = self.config.lock().unwrap().fs.clone();
        if let Some(fs_list_cfg) = &mut fs_devices {
            for fs_cfg in fs_list_cfg.iter_mut() {
                devices.push(self.make_virtio_fs_device(fs_cfg)?);
            }
        }
        self.config.lock().unwrap().fs = fs_devices;

        Ok(devices)
    }

    fn make_virtio_pmem_device(
        &mut self,
        pmem_cfg: &mut PmemConfig,
    ) -> DeviceManagerResult<(VirtioDeviceArc, bool, String)> {
        let id = if let Some(id) = &pmem_cfg.id {
            id.clone()
        } else {
            let id = self.next_device_name(PMEM_DEVICE_NAME_PREFIX)?;
            pmem_cfg.id = Some(id.clone());
            id
        };

        info!("Creating virtio-pmem device: {:?}", pmem_cfg);

        let mut node = device_node!(id);

        // Look for the id in the device tree. If it can be found, that means
        // the device is being restored, otherwise it's created from scratch.
        let region_range = if let Some(node) = self.device_tree.lock().unwrap().get(&id) {
            debug!("Restoring virtio-pmem {} resources", id);

            let mut region_range: Option<(u64, u64)> = None;
            for resource in node.resources.iter() {
                match resource {
                    Resource::MmioAddressRange { base, size } => {
                        if region_range.is_some() {
                            return Err(DeviceManagerError::ResourceAlreadyExists);
                        }

                        region_range = Some((*base, *size));
                    }
                    _ => {
                        error!("Unexpected resource {:?} for {}", resource, id);
                    }
                }
            }

            if region_range.is_none() {
                return Err(DeviceManagerError::MissingVirtioFsResources);
            }

            region_range
        } else {
            None
        };

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

        let (region_base, region_size) = if let Some((base, size)) = region_range {
            // The memory needs to be 2MiB aligned in order to support
            // hugepages.
            self.address_manager
                .allocator
                .lock()
                .unwrap()
                .allocate_mmio_addresses(
                    Some(GuestAddress(base)),
                    size as GuestUsize,
                    Some(0x0020_0000),
                )
                .ok_or(DeviceManagerError::PmemRangeAllocation)?;

            (base, size)
        } else {
            // The memory needs to be 2MiB aligned in order to support
            // hugepages.
            let base = self
                .address_manager
                .allocator
                .lock()
                .unwrap()
                .allocate_mmio_addresses(None, size as GuestUsize, Some(0x0020_0000))
                .ok_or(DeviceManagerError::PmemRangeAllocation)?;

            (base.raw_value(), size)
        };

        let cloned_file = file.try_clone().map_err(DeviceManagerError::CloneFile)?;
        let mmap_region = MmapRegion::build(
            Some(FileOffset::new(cloned_file, 0)),
            region_size as usize,
            PROT_READ | PROT_WRITE,
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
                region_base,
                region_size,
                host_addr,
                pmem_cfg.mergeable,
                false,
                false,
            )
            .map_err(DeviceManagerError::MemoryManager)?;

        let mapping = virtio_devices::UserspaceMapping {
            host_addr,
            mem_slot,
            addr: GuestAddress(region_base),
            len: region_size,
            mergeable: pmem_cfg.mergeable,
        };

        let virtio_pmem_device = Arc::new(Mutex::new(
            virtio_devices::Pmem::new(
                id.clone(),
                file,
                GuestAddress(region_base),
                mapping,
                mmap_region,
                pmem_cfg.iommu,
                self.seccomp_action.clone(),
            )
            .map_err(DeviceManagerError::CreateVirtioPmem)?,
        ));

        // Update the device tree with correct resource information and with
        // the migratable device.
        node.resources.push(Resource::MmioAddressRange {
            base: region_base,
            size: region_size,
        });
        node.migratable = Some(Arc::clone(&virtio_pmem_device) as Arc<Mutex<dyn Migratable>>);
        self.device_tree.lock().unwrap().insert(id.clone(), node);

        Ok((
            Arc::clone(&virtio_pmem_device) as VirtioDeviceArc,
            pmem_cfg.iommu,
            id,
        ))
    }

    fn make_virtio_pmem_devices(
        &mut self,
    ) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool, String)>> {
        let mut devices = Vec::new();
        // Add virtio-pmem if required
        let mut pmem_devices = self.config.lock().unwrap().pmem.clone();
        if let Some(pmem_list_cfg) = &mut pmem_devices {
            for pmem_cfg in pmem_list_cfg.iter_mut() {
                devices.push(self.make_virtio_pmem_device(pmem_cfg)?);
            }
        }
        self.config.lock().unwrap().pmem = pmem_devices;

        Ok(devices)
    }

    fn make_virtio_vsock_device(
        &mut self,
        vsock_cfg: &mut VsockConfig,
    ) -> DeviceManagerResult<(VirtioDeviceArc, bool, String)> {
        let id = if let Some(id) = &vsock_cfg.id {
            id.clone()
        } else {
            let id = self.next_device_name(VSOCK_DEVICE_NAME_PREFIX)?;
            vsock_cfg.id = Some(id.clone());
            id
        };

        info!("Creating virtio-vsock device: {:?}", vsock_cfg);

        let socket_path = vsock_cfg
            .socket
            .to_str()
            .ok_or(DeviceManagerError::CreateVsockConvertPath)?;
        let backend =
            virtio_devices::vsock::VsockUnixBackend::new(vsock_cfg.cid, socket_path.to_string())
                .map_err(DeviceManagerError::CreateVsockBackend)?;

        let vsock_device = Arc::new(Mutex::new(
            virtio_devices::Vsock::new(
                id.clone(),
                vsock_cfg.cid,
                vsock_cfg.socket.clone(),
                backend,
                vsock_cfg.iommu,
                self.seccomp_action.clone(),
            )
            .map_err(DeviceManagerError::CreateVirtioVsock)?,
        ));

        // Fill the device tree with a new node. In case of restore, we
        // know there is nothing to do, so we can simply override the
        // existing entry.
        self.device_tree
            .lock()
            .unwrap()
            .insert(id.clone(), device_node!(id, vsock_device));

        Ok((
            Arc::clone(&vsock_device) as VirtioDeviceArc,
            vsock_cfg.iommu,
            id,
        ))
    }

    fn make_virtio_vsock_devices(
        &mut self,
    ) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool, String)>> {
        let mut devices = Vec::new();

        let mut vsock = self.config.lock().unwrap().vsock.clone();
        if let Some(ref mut vsock_cfg) = &mut vsock {
            devices.push(self.make_virtio_vsock_device(vsock_cfg)?);
        }
        self.config.lock().unwrap().vsock = vsock;

        Ok(devices)
    }

    fn make_virtio_mem_devices(
        &mut self,
    ) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool, String)>> {
        let mut devices = Vec::new();

        let mm = self.memory_manager.clone();
        let mm = mm.lock().unwrap();
        for (_memory_zone_id, memory_zone) in mm.memory_zones().iter() {
            if let Some(virtio_mem_zone) = memory_zone.virtio_mem_zone() {
                let id = self.next_device_name(MEM_DEVICE_NAME_PREFIX)?;
                info!("Creating virtio-mem device: id = {}", id);
                #[cfg(not(feature = "acpi"))]
                let node_id: Option<u16> = None;
                #[cfg(feature = "acpi")]
                let node_id = numa_node_id_from_memory_zone_id(&self.numa_nodes, _memory_zone_id)
                    .map(|i| i as u16);

                let virtio_mem_device = Arc::new(Mutex::new(
                    virtio_devices::Mem::new(
                        id.clone(),
                        virtio_mem_zone.region(),
                        virtio_mem_zone
                            .resize_handler()
                            .new_resize_sender()
                            .map_err(DeviceManagerError::CreateResizeSender)?,
                        self.seccomp_action.clone(),
                        node_id,
                        virtio_mem_zone.hotplugged_size(),
                        virtio_mem_zone.hugepages(),
                    )
                    .map_err(DeviceManagerError::CreateVirtioMem)?,
                ));

                self.virtio_mem_devices.push(Arc::clone(&virtio_mem_device));

                devices.push((
                    Arc::clone(&virtio_mem_device) as VirtioDeviceArc,
                    false,
                    id.clone(),
                ));

                // Fill the device tree with a new node. In case of restore, we
                // know there is nothing to do, so we can simply override the
                // existing entry.
                self.device_tree
                    .lock()
                    .unwrap()
                    .insert(id.clone(), device_node!(id, virtio_mem_device));
            }
        }

        Ok(devices)
    }

    fn make_virtio_balloon_devices(
        &mut self,
    ) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool, String)>> {
        let mut devices = Vec::new();

        if let Some(balloon_config) = &self.config.lock().unwrap().balloon {
            let id = String::from(BALLOON_DEVICE_NAME);
            info!("Creating virtio-balloon device: id = {}", id);

            let virtio_balloon_device = Arc::new(Mutex::new(
                virtio_devices::Balloon::new(
                    id.clone(),
                    balloon_config.size,
                    self.seccomp_action.clone(),
                )
                .map_err(DeviceManagerError::CreateVirtioBalloon)?,
            ));

            self.balloon = Some(virtio_balloon_device.clone());

            devices.push((
                Arc::clone(&virtio_balloon_device) as VirtioDeviceArc,
                false,
                id.clone(),
            ));

            self.device_tree
                .lock()
                .unwrap()
                .insert(id.clone(), device_node!(id, virtio_balloon_device));
        }

        Ok(devices)
    }

    fn make_virtio_watchdog_devices(
        &mut self,
    ) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool, String)>> {
        let mut devices = Vec::new();

        if !self.config.lock().unwrap().watchdog {
            return Ok(devices);
        }

        let id = String::from(WATCHDOG_DEVICE_NAME);
        info!("Creating virtio-watchdog device: id = {}", id);

        let virtio_watchdog_device = Arc::new(Mutex::new(
            virtio_devices::Watchdog::new(
                id.clone(),
                self.reset_evt.try_clone().unwrap(),
                self.seccomp_action.clone(),
            )
            .map_err(DeviceManagerError::CreateVirtioWatchdog)?,
        ));
        devices.push((
            Arc::clone(&virtio_watchdog_device) as VirtioDeviceArc,
            false,
            id.clone(),
        ));

        self.device_tree
            .lock()
            .unwrap()
            .insert(id.clone(), device_node!(id, virtio_watchdog_device));

        Ok(devices)
    }

    fn next_device_name(&mut self, prefix: &str) -> DeviceManagerResult<String> {
        let start_id = self.device_id_cnt;
        loop {
            // Generate the temporary name.
            let name = format!("{}{}", prefix, self.device_id_cnt);
            // Increment the counter.
            self.device_id_cnt += Wrapping(1);
            // Check if the name is already in use.
            if !self.device_tree.lock().unwrap().contains_key(&name) {
                return Ok(name);
            }

            if self.device_id_cnt == start_id {
                // We went through a full loop and there's nothing else we can
                // do.
                break;
            }
        }
        Err(DeviceManagerError::NoAvailableDeviceName)
    }

    #[cfg_attr(not(feature = "kvm"), allow(unused_variables))]
    fn add_passthrough_device(
        &mut self,
        pci: &mut PciBus,
        device_cfg: &mut DeviceConfig,
    ) -> DeviceManagerResult<(u32, String)> {
        // If the passthrough device has not been created yet, it is created
        // here and stored in the DeviceManager structure for future needs.
        if self.passthrough_device.is_none() {
            self.passthrough_device = Some(
                self.address_manager
                    .vm
                    .create_passthrough_device()
                    .map_err(|e| DeviceManagerError::CreatePassthroughDevice(e.into()))?,
            );
        }

        #[cfg(feature = "kvm")]
        return self.add_vfio_device(pci, device_cfg);

        #[cfg(not(feature = "kvm"))]
        Err(DeviceManagerError::NoDevicePassthroughSupport)
    }

    #[cfg(feature = "kvm")]
    fn add_vfio_device(
        &mut self,
        pci: &mut PciBus,
        device_cfg: &mut DeviceConfig,
    ) -> DeviceManagerResult<(u32, String)> {
        let passthrough_device = self
            .passthrough_device
            .as_ref()
            .ok_or(DeviceManagerError::NoDevicePassthroughSupport)?;

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

        // Safe because we know the RawFd is valid.
        //
        // This dup() is mandatory to be able to give full ownership of the
        // file descriptor to the DeviceFd::from_raw_fd() function later in
        // the code.
        //
        // This is particularly needed so that VfioContainer will still have
        // a valid file descriptor even if DeviceManager, and therefore the
        // passthrough_device are dropped. In case of Drop, the file descriptor
        // would be closed, but Linux would still have the duplicated file
        // descriptor opened from DeviceFd, preventing from unexpected behavior
        // where the VfioContainer would try to use a closed file descriptor.
        let dup_device_fd = unsafe { libc::dup(passthrough_device.as_raw_fd()) };

        // SAFETY the raw fd conversion here is safe because:
        //   1. This function is only called on KVM, see the feature guard above.
        //   2. When running on KVM, passthrough_device wraps around DeviceFd.
        //   3. The conversion here extracts the raw fd and then turns the raw fd into a DeviceFd
        //      of the same (correct) type.
        let vfio_container = Arc::new(
            VfioContainer::new(Arc::new(unsafe { DeviceFd::from_raw_fd(dup_device_fd) }))
                .map_err(DeviceManagerError::VfioCreate)?,
        );

        let vfio_device = VfioDevice::new(&device_cfg.path, Arc::clone(&vfio_container))
            .map_err(DeviceManagerError::VfioCreate)?;

        let vfio_mapping = Arc::new(VfioDmaMapping::new(
            Arc::clone(&vfio_container),
            Arc::new(memory),
        ));
        if device_cfg.iommu {
            if let Some(iommu) = &self.iommu_device {
                iommu
                    .lock()
                    .unwrap()
                    .add_external_mapping(pci_device_bdf, vfio_mapping);
            }
        } else {
            for virtio_mem_device in self.virtio_mem_devices.iter() {
                virtio_mem_device
                    .lock()
                    .unwrap()
                    .add_dma_mapping_handler(pci_device_bdf, vfio_mapping.clone())
                    .map_err(DeviceManagerError::AddDmaMappingHandlerVirtioMem)?;
            }
        }

        let legacy_interrupt_group = if let Some(legacy_interrupt_manager) =
            &self.legacy_interrupt_manager
        {
            Some(
                legacy_interrupt_manager
                    .create_group(LegacyIrqGroupConfig {
                        irq: self.pci_irq_slots[(pci_device_bdf >> 3) as usize] as InterruptIndex,
                    })
                    .map_err(DeviceManagerError::CreateInterruptGroup)?,
            )
        } else {
            None
        };

        let mut vfio_pci_device = VfioPciDevice::new(
            &self.address_manager.vm,
            vfio_device,
            vfio_container,
            &self.msi_interrupt_manager,
            legacy_interrupt_group,
            device_cfg.iommu,
        )
        .map_err(DeviceManagerError::VfioPciCreate)?;

        let vfio_name = if let Some(id) = &device_cfg.id {
            if self.device_tree.lock().unwrap().contains_key(id) {
                return Err(DeviceManagerError::DeviceIdAlreadyInUse);
            }

            id.clone()
        } else {
            let id = self.next_device_name(VFIO_DEVICE_NAME_PREFIX)?;
            device_cfg.id = Some(id.clone());
            id
        };

        vfio_pci_device
            .map_mmio_regions(&self.address_manager.vm, || {
                self.memory_manager.lock().unwrap().allocate_memory_slot()
            })
            .map_err(DeviceManagerError::VfioMapRegion)?;

        let mut node = device_node!(vfio_name);

        for region in vfio_pci_device.mmio_regions() {
            node.resources.push(Resource::MmioAddressRange {
                base: region.start.0,
                size: region.length as u64,
            });
        }

        // Register DMA mapping in IOMMU.
        // Do not register virtio-mem regions, as they are handled directly by
        // virtio-mem device itself.
        for (_, zone) in self.memory_manager.lock().unwrap().memory_zones().iter() {
            for region in zone.regions() {
                vfio_pci_device
                    .dma_map(
                        region.start_addr().raw_value(),
                        region.len() as u64,
                        region.as_ptr() as u64,
                    )
                    .map_err(DeviceManagerError::VfioDmaMap)?;
            }
        }

        let vfio_pci_device = Arc::new(Mutex::new(vfio_pci_device));

        self.add_pci_device(
            pci,
            vfio_pci_device.clone(),
            vfio_pci_device.clone(),
            pci_device_bdf,
        )?;

        node.pci_bdf = Some(pci_device_bdf);
        node.pci_device_handle = Some(PciDeviceHandle::Vfio(vfio_pci_device));

        self.device_tree
            .lock()
            .unwrap()
            .insert(vfio_name.clone(), node);

        Ok((pci_device_bdf, vfio_name))
    }

    fn add_pci_device(
        &mut self,
        pci_bus: &mut PciBus,
        bus_device: Arc<Mutex<dyn BusDevice>>,
        pci_device: Arc<Mutex<dyn PciDevice>>,
        bdf: u32,
    ) -> DeviceManagerResult<Vec<(GuestAddress, GuestUsize, PciBarRegionType)>> {
        let bars = pci_device
            .lock()
            .unwrap()
            .allocate_bars(&mut self.address_manager.allocator.lock().unwrap())
            .map_err(DeviceManagerError::AllocateBars)?;

        pci_bus
            .add_device(bdf, pci_device)
            .map_err(DeviceManagerError::AddPciDevice)?;

        self.bus_devices.push(Arc::clone(&bus_device));

        pci_bus
            .register_mapping(
                bus_device,
                #[cfg(target_arch = "x86_64")]
                self.address_manager.io_bus.as_ref(),
                self.address_manager.mmio_bus.as_ref(),
                bars.clone(),
            )
            .map_err(DeviceManagerError::AddPciDevice)?;

        Ok(bars)
    }

    fn add_vfio_devices(&mut self, pci: &mut PciBus) -> DeviceManagerResult<Vec<u32>> {
        let mut iommu_attached_device_ids = Vec::new();
        let mut devices = self.config.lock().unwrap().devices.clone();

        if let Some(device_list_cfg) = &mut devices {
            for device_cfg in device_list_cfg.iter_mut() {
                let (device_id, _) = self.add_passthrough_device(pci, device_cfg)?;
                if device_cfg.iommu && self.iommu_device.is_some() {
                    iommu_attached_device_ids.push(device_id);
                }
            }
        }

        // Update the list of devices
        self.config.lock().unwrap().devices = devices;

        Ok(iommu_attached_device_ids)
    }

    fn add_virtio_pci_device(
        &mut self,
        virtio_device: VirtioDeviceArc,
        pci: &mut PciBus,
        iommu_mapping: &Option<Arc<IommuMapping>>,
        virtio_device_id: String,
    ) -> DeviceManagerResult<u32> {
        let id = format!("{}-{}", VIRTIO_PCI_DEVICE_NAME_PREFIX, virtio_device_id);

        // Add the new virtio-pci node to the device tree.
        let mut node = device_node!(id);
        node.children = vec![virtio_device_id.clone()];

        // Look for the id in the device tree. If it can be found, that means
        // the device is being restored, otherwise it's created from scratch.
        let (pci_device_bdf, config_bar_addr) =
            if let Some(node) = self.device_tree.lock().unwrap().get(&id) {
                debug!("Restoring virtio-pci {} resources", id);
                let pci_device_bdf = node
                    .pci_bdf
                    .ok_or(DeviceManagerError::MissingDeviceNodePciBdf)?;

                pci.get_device_id((pci_device_bdf >> 3) as usize)
                    .map_err(DeviceManagerError::GetPciDeviceId)?;

                if node.resources.is_empty() {
                    return Err(DeviceManagerError::MissingVirtioPciResources);
                }

                // We know the configuration BAR address is stored on the first
                // resource in the list.
                let config_bar_addr = match node.resources[0] {
                    Resource::MmioAddressRange { base, .. } => Some(base),
                    _ => {
                        error!("Unexpected resource {:?} for {}", node.resources[0], id);
                        return Err(DeviceManagerError::MissingVirtioPciResources);
                    }
                };

                (pci_device_bdf, config_bar_addr)
            } else {
                // We need to shift the device id since the 3 first bits are dedicated
                // to the PCI function, and we know we don't do multifunction.
                // Also, because we only support one PCI bus, the bus 0, we don't need
                // to add anything to the global device ID.
                let pci_device_bdf = pci
                    .next_device_id()
                    .map_err(DeviceManagerError::NextPciDeviceId)?
                    << 3;

                (pci_device_bdf, None)
            };

        // Update the existing virtio node by setting the parent.
        if let Some(node) = self.device_tree.lock().unwrap().get_mut(&virtio_device_id) {
            node.parent = Some(id.clone());
        } else {
            return Err(DeviceManagerError::MissingNode);
        }

        // Allows support for one MSI-X vector per queue. It also adds 1
        // as we need to take into account the dedicated vector to notify
        // about a virtio config change.
        let msix_num = (virtio_device.lock().unwrap().queue_max_sizes().len() + 1) as u16;

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
            id.clone(),
            memory,
            virtio_device,
            msix_num,
            iommu_mapping_cb,
            &self.msi_interrupt_manager,
            pci_device_bdf,
            self.activate_evt
                .try_clone()
                .map_err(DeviceManagerError::EventFd)?,
        )
        .map_err(DeviceManagerError::VirtioDevice)?;

        // This is important as this will set the BAR address if it exists,
        // which is mandatory on the restore path.
        if let Some(addr) = config_bar_addr {
            virtio_pci_device.set_config_bar_addr(addr);
        }

        let virtio_pci_device = Arc::new(Mutex::new(virtio_pci_device));
        let bars = self.add_pci_device(
            pci,
            virtio_pci_device.clone(),
            virtio_pci_device.clone(),
            pci_device_bdf,
        )?;

        let bar_addr = virtio_pci_device.lock().unwrap().config_bar_addr();
        for (event, addr) in virtio_pci_device.lock().unwrap().ioeventfds(bar_addr) {
            let io_addr = IoEventAddress::Mmio(addr);
            self.address_manager
                .vm
                .register_ioevent(event, &io_addr, None)
                .map_err(|e| DeviceManagerError::RegisterIoevent(e.into()))?;
        }

        // Update the device tree with correct resource information.
        for pci_bar in bars.iter() {
            node.resources.push(Resource::MmioAddressRange {
                base: pci_bar.0.raw_value(),
                size: pci_bar.1 as u64,
            });
        }
        node.migratable = Some(Arc::clone(&virtio_pci_device) as Arc<Mutex<dyn Migratable>>);
        node.pci_bdf = Some(pci_device_bdf);
        node.pci_device_handle = Some(PciDeviceHandle::Virtio(virtio_pci_device));
        self.device_tree.lock().unwrap().insert(id, node);

        Ok(pci_device_bdf)
    }

    #[cfg(target_arch = "x86_64")]
    pub fn io_bus(&self) -> &Arc<Bus> {
        &self.address_manager.io_bus
    }

    pub fn mmio_bus(&self) -> &Arc<Bus> {
        &self.address_manager.mmio_bus
    }

    pub fn allocator(&self) -> &Arc<Mutex<SystemAllocator>> {
        &self.address_manager.allocator
    }

    pub fn interrupt_controller(&self) -> Option<Arc<Mutex<dyn InterruptController>>> {
        self.interrupt_controller
            .as_ref()
            .map(|ic| ic.clone() as Arc<Mutex<dyn InterruptController>>)
    }

    pub fn console(&self) -> &Arc<Console> {
        &self.console
    }

    pub fn cmdline_additions(&self) -> &[String] {
        self.cmdline_additions.as_slice()
    }

    pub fn update_memory(&self, new_region: &Arc<GuestRegionMmap>) -> DeviceManagerResult<()> {
        for (virtio_device, _, _) in self.virtio_devices.iter() {
            virtio_device
                .lock()
                .unwrap()
                .add_memory_region(new_region)
                .map_err(DeviceManagerError::UpdateMemoryForVirtioDevice)?;
        }

        // Take care of updating the memory for VFIO PCI devices.
        #[cfg(feature = "kvm")]
        {
            let device_tree = self.device_tree.lock().unwrap();
            for pci_device_node in device_tree.pci_devices() {
                if let PciDeviceHandle::Vfio(vfio_pci_device) = pci_device_node
                    .pci_device_handle
                    .as_ref()
                    .ok_or(DeviceManagerError::MissingPciDevice)?
                {
                    vfio_pci_device
                        .lock()
                        .unwrap()
                        .dma_map(
                            new_region.start_addr().raw_value(),
                            new_region.len() as u64,
                            new_region.as_ptr() as u64,
                        )
                        .map_err(DeviceManagerError::UpdateMemoryForVfioPciDevice)?;
                }
            }
        }

        Ok(())
    }

    pub fn activate_virtio_devices(&self) -> DeviceManagerResult<()> {
        // Find virtio pci devices and activate any pending ones
        let device_tree = self.device_tree.lock().unwrap();
        for pci_device_node in device_tree.pci_devices() {
            #[allow(irrefutable_let_patterns)]
            if let PciDeviceHandle::Virtio(virtio_pci_device) = &pci_device_node
                .pci_device_handle
                .as_ref()
                .ok_or(DeviceManagerError::MissingPciDevice)?
            {
                virtio_pci_device.lock().unwrap().maybe_activate();
            }
        }
        Ok(())
    }

    pub fn notify_hotplug(
        &self,
        _notification_type: AcpiNotificationFlags,
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

    pub fn add_device(
        &mut self,
        device_cfg: &mut DeviceConfig,
    ) -> DeviceManagerResult<PciDeviceInfo> {
        let pci = if let Some(pci_bus) = &self.pci_bus {
            Arc::clone(&pci_bus)
        } else {
            return Err(DeviceManagerError::NoPciBus);
        };

        let (device_id, device_name) =
            self.add_passthrough_device(&mut pci.lock().unwrap(), device_cfg)?;

        // Update the PCIU bitmap
        self.pci_devices_up |= 1 << (device_id >> 3);

        Ok(PciDeviceInfo {
            id: device_name,
            bdf: device_id,
        })
    }

    pub fn remove_device(&mut self, id: String) -> DeviceManagerResult<()> {
        // The node can be directly a PCI node in case the 'id' refers to a
        // VFIO device or a virtio-pci one.
        // In case the 'id' refers to a virtio device, we must find the PCI
        // node by looking at the parent.
        let device_tree = self.device_tree.lock().unwrap();
        let node = device_tree
            .get(&id)
            .ok_or(DeviceManagerError::UnknownDeviceId(id))?;

        let pci_device_node = if node.pci_bdf.is_some() && node.pci_device_handle.is_some() {
            node
        } else {
            let parent = node
                .parent
                .as_ref()
                .ok_or(DeviceManagerError::MissingNode)?;
            device_tree
                .get(parent)
                .ok_or(DeviceManagerError::MissingNode)?
        };

        let pci_device_bdf = pci_device_node
            .pci_bdf
            .ok_or(DeviceManagerError::MissingPciDevice)?;
        let pci_device_handle = pci_device_node
            .pci_device_handle
            .as_ref()
            .ok_or(DeviceManagerError::MissingPciDevice)?;
        #[allow(irrefutable_let_patterns)]
        if let PciDeviceHandle::Virtio(virtio_pci_device) = pci_device_handle {
            let device_type = VirtioDeviceType::from(
                virtio_pci_device
                    .lock()
                    .unwrap()
                    .virtio_device()
                    .lock()
                    .unwrap()
                    .device_type(),
            );
            match device_type {
                VirtioDeviceType::Net
                | VirtioDeviceType::Block
                | VirtioDeviceType::Pmem
                | VirtioDeviceType::Fs
                | VirtioDeviceType::Vsock => {}
                _ => return Err(DeviceManagerError::RemovalNotAllowed(device_type)),
            }
        }

        // Update the PCID bitmap
        self.pci_devices_down |= 1 << (pci_device_bdf >> 3);

        Ok(())
    }

    pub fn eject_device(&mut self, device_id: u8) -> DeviceManagerResult<()> {
        // Retrieve the PCI bus.
        let pci = if let Some(pci_bus) = &self.pci_bus {
            Arc::clone(&pci_bus)
        } else {
            return Err(DeviceManagerError::NoPciBus);
        };

        // Convert the device ID into the corresponding b/d/f.
        let pci_device_bdf = (device_id as u32) << 3;

        // Give the PCI device ID back to the PCI bus.
        pci.lock()
            .unwrap()
            .put_device_id(device_id as usize)
            .map_err(DeviceManagerError::PutPciDeviceId)?;

        // Remove the device from the device tree along with its children.
        let mut device_tree = self.device_tree.lock().unwrap();
        let pci_device_node = device_tree
            .remove_node_by_pci_bdf(pci_device_bdf)
            .ok_or(DeviceManagerError::MissingPciDevice)?;
        for child in pci_device_node.children.iter() {
            device_tree.remove(child);
        }

        let pci_device_handle = pci_device_node
            .pci_device_handle
            .ok_or(DeviceManagerError::MissingPciDevice)?;
        let (pci_device, bus_device, virtio_device) = match pci_device_handle {
            #[cfg(feature = "kvm")]
            PciDeviceHandle::Vfio(vfio_pci_device) => {
                {
                    // Unregister DMA mapping in IOMMU.
                    // Do not unregister the virtio-mem region, as it is
                    // directly handled by the virtio-mem device.
                    let dev = vfio_pci_device.lock().unwrap();
                    for (_, zone) in self.memory_manager.lock().unwrap().memory_zones().iter() {
                        for region in zone.regions() {
                            dev.dma_unmap(region.start_addr().raw_value(), region.len() as u64)
                                .map_err(DeviceManagerError::VfioDmaUnmap)?;
                        }
                    }

                    // Unregister the VFIO mapping handler from all virtio-mem
                    // devices.
                    if !dev.iommu_attached() {
                        for virtio_mem_device in self.virtio_mem_devices.iter() {
                            virtio_mem_device
                                .lock()
                                .unwrap()
                                .remove_dma_mapping_handler(pci_device_bdf)
                                .map_err(DeviceManagerError::RemoveDmaMappingHandlerVirtioMem)?;
                        }
                    }
                }

                (
                    Arc::clone(&vfio_pci_device) as Arc<Mutex<dyn PciDevice>>,
                    Arc::clone(&vfio_pci_device) as Arc<Mutex<dyn BusDevice>>,
                    None as Option<VirtioDeviceArc>,
                )
            }
            PciDeviceHandle::Virtio(virtio_pci_device) => {
                let bar_addr = virtio_pci_device.lock().unwrap().config_bar_addr();
                for (event, addr) in virtio_pci_device.lock().unwrap().ioeventfds(bar_addr) {
                    let io_addr = IoEventAddress::Mmio(addr);
                    self.address_manager
                        .vm
                        .unregister_ioevent(event, &io_addr)
                        .map_err(|e| DeviceManagerError::UnRegisterIoevent(e.into()))?;
                }

                (
                    Arc::clone(&virtio_pci_device) as Arc<Mutex<dyn PciDevice>>,
                    Arc::clone(&virtio_pci_device) as Arc<Mutex<dyn BusDevice>>,
                    Some(virtio_pci_device.lock().unwrap().virtio_device()),
                )
            }
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

        #[cfg(target_arch = "x86_64")]
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
    }

    fn hotplug_virtio_pci_device(
        &mut self,
        device: VirtioDeviceArc,
        iommu_attached: bool,
        id: String,
    ) -> DeviceManagerResult<PciDeviceInfo> {
        if iommu_attached {
            warn!("Placing device behind vIOMMU is not available for hotplugged devices");
        }

        let pci = if let Some(pci_bus) = &self.pci_bus {
            Arc::clone(&pci_bus)
        } else {
            return Err(DeviceManagerError::NoPciBus);
        };

        // Add the virtio device to the device manager list. This is important
        // as the list is used to notify virtio devices about memory updates
        // for instance.
        self.virtio_devices
            .push((device.clone(), iommu_attached, id.clone()));

        let device_id =
            self.add_virtio_pci_device(device, &mut pci.lock().unwrap(), &None, id.clone())?;

        // Update the PCIU bitmap
        self.pci_devices_up |= 1 << (device_id >> 3);

        Ok(PciDeviceInfo { id, bdf: device_id })
    }

    pub fn add_disk(&mut self, disk_cfg: &mut DiskConfig) -> DeviceManagerResult<PciDeviceInfo> {
        let (device, iommu_attached, id) = self.make_virtio_block_device(disk_cfg)?;
        self.hotplug_virtio_pci_device(device, iommu_attached, id)
    }

    pub fn add_fs(&mut self, fs_cfg: &mut FsConfig) -> DeviceManagerResult<PciDeviceInfo> {
        let (device, iommu_attached, id) = self.make_virtio_fs_device(fs_cfg)?;
        self.hotplug_virtio_pci_device(device, iommu_attached, id)
    }

    pub fn add_pmem(&mut self, pmem_cfg: &mut PmemConfig) -> DeviceManagerResult<PciDeviceInfo> {
        let (device, iommu_attached, id) = self.make_virtio_pmem_device(pmem_cfg)?;
        self.hotplug_virtio_pci_device(device, iommu_attached, id)
    }

    pub fn add_net(&mut self, net_cfg: &mut NetConfig) -> DeviceManagerResult<PciDeviceInfo> {
        let (device, iommu_attached, id) = self.make_virtio_net_device(net_cfg)?;
        self.hotplug_virtio_pci_device(device, iommu_attached, id)
    }

    pub fn add_vsock(&mut self, vsock_cfg: &mut VsockConfig) -> DeviceManagerResult<PciDeviceInfo> {
        let (device, iommu_attached, id) = self.make_virtio_vsock_device(vsock_cfg)?;
        self.hotplug_virtio_pci_device(device, iommu_attached, id)
    }

    pub fn counters(&self) -> HashMap<String, HashMap<&'static str, Wrapping<u64>>> {
        let mut counters = HashMap::new();

        for (virtio_device, _, id) in &self.virtio_devices {
            let virtio_device = virtio_device.lock().unwrap();
            if let Some(device_counters) = virtio_device.counters() {
                counters.insert(id.clone(), device_counters.clone());
            }
        }

        counters
    }

    pub fn resize_balloon(&mut self, size: u64) -> DeviceManagerResult<()> {
        if let Some(balloon) = &self.balloon {
            return balloon
                .lock()
                .unwrap()
                .resize(size)
                .map_err(DeviceManagerError::VirtioBalloonResize);
        }

        warn!("No balloon setup: Can't resize the balloon");
        Err(DeviceManagerError::MissingVirtioBalloon)
    }

    pub fn balloon_size(&self) -> u64 {
        if let Some(balloon) = &self.balloon {
            return balloon.lock().unwrap().get_actual();
        }

        0
    }

    pub fn device_tree(&self) -> Arc<Mutex<DeviceTree>> {
        self.device_tree.clone()
    }

    #[cfg(feature = "acpi")]
    #[cfg(target_arch = "x86_64")]
    pub fn notify_power_button(&self) -> DeviceManagerResult<()> {
        self.ged_notification_device
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .notify(AcpiNotificationFlags::POWER_BUTTON_CHANGED)
            .map_err(DeviceManagerError::PowerButtonNotification)
    }

    #[cfg(target_arch = "aarch64")]
    pub fn notify_power_button(&self) -> DeviceManagerResult<()> {
        self.gpio_device
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .trigger_key(3)
            .map_err(DeviceManagerError::AArch64PowerButtonNotification)
    }
}

#[cfg(feature = "acpi")]
fn numa_node_id_from_memory_zone_id(numa_nodes: &NumaNodes, memory_zone_id: &str) -> Option<u32> {
    for (numa_node_id, numa_node) in numa_nodes.iter() {
        if numa_node
            .memory_zones()
            .contains(&memory_zone_id.to_owned())
        {
            return Some(*numa_node_id);
        }
    }

    None
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
        #[cfg(target_arch = "aarch64")]
        use arch::aarch64::DeviceInfoForFdt;

        let mut bytes = Vec::new();
        // PCI hotplug controller
        bytes.extend_from_slice(
            &aml::Device::new(
                "_SB_.PHPR".into(),
                vec![
                    &aml::Name::new("_HID".into(), &aml::EisaName::new("PNP0A06")),
                    &aml::Name::new("_STA".into(), &0x0bu8),
                    &aml::Name::new("_UID".into(), &"PCI Hotplug Controller"),
                    &aml::Mutex::new("BLCK".into(), 0),
                    &aml::Name::new(
                        "_CRS".into(),
                        &aml::ResourceTemplate::new(vec![&aml::AddressSpace::new_memory(
                            aml::AddressSpaceCachable::NotCacheable,
                            true,
                            self.acpi_address.0 as u64,
                            self.acpi_address.0 + DEVICE_MANAGER_ACPI_SIZE as u64 - 1,
                        )]),
                    ),
                    // OpRegion and Fields map MMIO range into individual field values
                    &aml::OpRegion::new(
                        "PCST".into(),
                        aml::OpRegionSpace::SystemMemory,
                        self.acpi_address.0 as usize,
                        DEVICE_MANAGER_ACPI_SIZE,
                    ),
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
        let hid = aml::Name::new("_HID".into(), &aml::EisaName::new("PNP0A08"));
        pci_dsdt_inner_data.push(&hid);
        let cid = aml::Name::new("_CID".into(), &aml::EisaName::new("PNP0A03"));
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
                #[cfg(target_arch = "x86_64")]
                &aml::Io::new(0xcf8, 0xcf8, 1, 0x8),
                #[cfg(target_arch = "aarch64")]
                &aml::Memory32Fixed::new(
                    true,
                    layout::PCI_MMCONFIG_START.0 as u32,
                    layout::PCI_MMCONFIG_SIZE as u32,
                ),
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

        // Build PCI routing table, listing IRQs assigned to PCI devices.
        let prt_package_list: Vec<(u32, u32)> = self
            .pci_irq_slots
            .iter()
            .enumerate()
            .map(|(i, irq)| (((((i as u32) & 0x1fu32) << 16) | 0xffffu32), *irq as u32))
            .collect();
        let prt_package_list: Vec<aml::Package> = prt_package_list
            .iter()
            .map(|(bdf, irq)| aml::Package::new(vec![bdf, &0u8, &0u8, irq]))
            .collect();
        let prt_package_list: Vec<&dyn Aml> = prt_package_list
            .iter()
            .map(|item| item as &dyn Aml)
            .collect();
        let prt = aml::Name::new("_PRT".into(), &aml::Package::new(prt_package_list));
        pci_dsdt_inner_data.push(&prt);

        let pci_dsdt_data =
            aml::Device::new("_SB_.PCI0".into(), pci_dsdt_inner_data).to_aml_bytes();

        let mbrd_dsdt_data = aml::Device::new(
            "_SB_.MBRD".into(),
            vec![
                &aml::Name::new("_HID".into(), &aml::EisaName::new("PNP0C02")),
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

        // Serial device
        #[cfg(target_arch = "x86_64")]
        let serial_irq = 4;
        #[cfg(target_arch = "aarch64")]
        let serial_irq =
            if self.config.lock().unwrap().serial.clone().mode != ConsoleOutputMode::Off {
                self.get_device_info()
                    .clone()
                    .get(&(DeviceType::Serial, DeviceType::Serial.to_string()))
                    .unwrap()
                    .irq()
            } else {
                // If serial is turned off, add a fake device with invalid irq.
                31
            };
        let com1_dsdt_data = aml::Device::new(
            "_SB_.COM1".into(),
            vec![
                &aml::Name::new(
                    "_HID".into(),
                    #[cfg(target_arch = "x86_64")]
                    &aml::EisaName::new("PNP0501"),
                    #[cfg(target_arch = "aarch64")]
                    &"ARMH0011",
                ),
                &aml::Name::new("_UID".into(), &aml::ZERO),
                &aml::Name::new(
                    "_CRS".into(),
                    &aml::ResourceTemplate::new(vec![
                        &aml::Interrupt::new(true, true, false, false, serial_irq),
                        #[cfg(target_arch = "x86_64")]
                        &aml::Io::new(0x3f8, 0x3f8, 0, 0x8),
                        #[cfg(target_arch = "aarch64")]
                        &aml::Memory32Fixed::new(
                            true,
                            arch::layout::LEGACY_SERIAL_MAPPED_IO_START as u32,
                            MMIO_LEN as u32,
                        ),
                    ]),
                ),
            ],
        )
        .to_aml_bytes();

        let s5_sleep_data =
            aml::Name::new("_S5_".into(), &aml::Package::new(vec![&5u8])).to_aml_bytes();

        let power_button_dsdt_data = aml::Device::new(
            "_SB_.PWRB".into(),
            vec![
                &aml::Name::new("_HID".into(), &aml::EisaName::new("PNP0C0C")),
                &aml::Name::new("_UID".into(), &aml::ZERO),
            ],
        )
        .to_aml_bytes();

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
        bytes.extend_from_slice(power_button_dsdt_data.as_slice());
        bytes.extend_from_slice(ged_data.as_slice());
        bytes
    }
}

impl Pausable for DeviceManager {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        for (_, device_node) in self.device_tree.lock().unwrap().iter() {
            if let Some(migratable) = &device_node.migratable {
                migratable.lock().unwrap().pause()?;
            }
        }

        Ok(())
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        for (_, device_node) in self.device_tree.lock().unwrap().iter() {
            if let Some(migratable) = &device_node.migratable {
                migratable.lock().unwrap().resume()?;
            }
        }

        Ok(())
    }
}

impl Snapshottable for DeviceManager {
    fn id(&self) -> String {
        DEVICE_MANAGER_SNAPSHOT_ID.to_string()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        let mut snapshot = Snapshot::new(DEVICE_MANAGER_SNAPSHOT_ID);

        // We aggregate all devices snapshots.
        for (_, device_node) in self.device_tree.lock().unwrap().iter() {
            if let Some(migratable) = &device_node.migratable {
                let device_snapshot = migratable.lock().unwrap().snapshot()?;
                snapshot.add_snapshot(device_snapshot);
            }
        }

        // Then we store the DeviceManager state.
        snapshot.add_data_section(SnapshotDataSection::new_from_state(
            DEVICE_MANAGER_SNAPSHOT_ID,
            &self.state(),
        )?);

        Ok(snapshot)
    }

    fn restore(&mut self, snapshot: Snapshot) -> std::result::Result<(), MigratableError> {
        // Let's first restore the DeviceManager.

        self.set_state(&snapshot.to_state(DEVICE_MANAGER_SNAPSHOT_ID)?);

        // Now that DeviceManager is updated with the right states, it's time
        // to create the devices based on the configuration.
        self.create_devices(None, None)
            .map_err(|e| MigratableError::Restore(anyhow!("Could not create devices {:?}", e)))?;

        // Finally, restore all devices associated with the DeviceManager.
        // It's important to restore devices in the right order, that's why
        // the device tree is the right way to ensure we restore a child before
        // its parent node.
        for node in self
            .device_tree
            .lock()
            .unwrap()
            .breadth_first_traversal()
            .rev()
        {
            // Restore the node
            if let Some(migratable) = &node.migratable {
                debug!("Restoring {} from DeviceManager", node.id);
                if let Some(snapshot) = snapshot.snapshots.get(&node.id) {
                    migratable.lock().unwrap().pause()?;
                    migratable.lock().unwrap().restore(*snapshot.clone())?;
                } else {
                    return Err(MigratableError::Restore(anyhow!(
                        "Missing device {}",
                        node.id
                    )));
                }
            }
        }

        Ok(())
    }
}

impl Transportable for DeviceManager {}
impl Migratable for DeviceManager {}

const PCIU_FIELD_OFFSET: u64 = 0;
const PCID_FIELD_OFFSET: u64 = 4;
const B0EJ_FIELD_OFFSET: u64 = 8;

const PCIU_FIELD_SIZE: usize = 4;
const PCID_FIELD_SIZE: usize = 4;
const B0EJ_FIELD_SIZE: usize = 4;

impl BusDevice for DeviceManager {
    fn read(&mut self, base: u64, offset: u64, data: &mut [u8]) {
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
            B0EJ_FIELD_OFFSET => {
                assert!(data.len() == B0EJ_FIELD_SIZE);
                // Always return an empty bitmap since the eject is always
                // taken care of right away during a write access.
                data.copy_from_slice(&[0, 0, 0, 0]);
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

    fn write(&mut self, base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        match offset {
            B0EJ_FIELD_OFFSET => {
                assert!(data.len() == B0EJ_FIELD_SIZE);
                let mut data_array: [u8; 4] = [0, 0, 0, 0];
                data_array.copy_from_slice(&data);
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
        );

        None
    }
}

impl Drop for DeviceManager {
    fn drop(&mut self) {
        for (device, _, _) in self.virtio_devices.drain(..) {
            device.lock().unwrap().shutdown();
        }
    }
}
