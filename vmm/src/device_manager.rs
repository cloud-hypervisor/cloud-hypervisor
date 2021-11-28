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
    ConsoleOutputMode, DiskConfig, FsConfig, NetConfig, PmemConfig, VhostMode, VmConfig,
    VsockConfig,
};
#[cfg(feature = "pci_support")]
use crate::config::{DeviceConfig, UserDeviceConfig};
use crate::device_tree::{DeviceNode, DeviceTree};
#[cfg(feature = "kvm")]
use crate::interrupt::kvm::KvmMsiInterruptManager as MsiInterruptManager;
#[cfg(feature = "mshv")]
use crate::interrupt::mshv::MshvMsiInterruptManager as MsiInterruptManager;
use crate::interrupt::LegacyUserspaceInterruptManager;
#[cfg(feature = "acpi")]
use crate::memory_manager::MEMORY_MANAGER_ACPI_SIZE;
use crate::memory_manager::{Error as MemoryManagerError, MemoryManager};
#[cfg(feature = "pci_support")]
use crate::pci_segment::PciSegment;
use crate::seccomp_filters::{get_seccomp_filter, Thread};
use crate::serial_manager::{Error as SerialManagerError, SerialManager};
use crate::sigwinch_listener::start_sigwinch_listener;
use crate::GuestRegionMmap;
#[cfg(feature = "pci_support")]
use crate::PciDeviceInfo;
use crate::{device_node, DEVICE_MANAGER_SNAPSHOT_ID};
#[cfg(feature = "acpi")]
use acpi_tables::{aml, aml::Aml};
use anyhow::anyhow;
#[cfg(target_arch = "aarch64")]
use arch::aarch64::gic::gicv3_its::kvm::KvmGicV3Its;
#[cfg(feature = "acpi")]
use arch::layout;
#[cfg(target_arch = "x86_64")]
use arch::layout::{APIC_START, IOAPIC_SIZE, IOAPIC_START};
#[cfg(any(target_arch = "aarch64", feature = "acpi"))]
use arch::NumaNodes;
#[cfg(target_arch = "aarch64")]
use arch::{DeviceType, MmioDeviceInfo};
use block_util::{
    async_io::DiskFile, block_io_uring_is_supported, detect_image_type,
    fixed_vhd_async::FixedVhdDiskAsync, fixed_vhd_sync::FixedVhdDiskSync, qcow_sync::QcowDiskSync,
    raw_async::RawFileDisk, raw_sync::RawFileDiskSync, vhdx_sync::VhdxDiskSync, ImageType,
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
#[cfg(feature = "pci_support")]
use hypervisor::DeviceFd;
#[cfg(feature = "mshv")]
use hypervisor::IoEventAddress;
use libc::{
    cfmakeraw, isatty, tcgetattr, tcsetattr, termios, MAP_NORESERVE, MAP_PRIVATE, MAP_SHARED,
    O_TMPFILE, PROT_READ, PROT_WRITE, TCSANOW,
};
use pci::PciBdf;
#[cfg(all(target_arch = "x86_64", feature = "pci_support"))]
use pci::PciConfigIo;
#[cfg(feature = "pci_support")]
use pci::{
    DeviceRelocation, PciBarRegionType, PciDevice, VfioPciDevice, VfioUserDmaMapping,
    VfioUserPciDevice, VfioUserPciDeviceError,
};
use seccompiler::SeccompAction;
use std::collections::HashMap;
use std::convert::TryInto;
use std::fs::{read_link, File, OpenOptions};
use std::io::{self, stdout, Seek, SeekFrom};
use std::mem::zeroed;
use std::num::Wrapping;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::PathBuf;
use std::result;
use std::sync::{Arc, Mutex};
#[cfg(feature = "pci_support")]
use vfio_ioctls::{VfioContainer, VfioDevice};
#[cfg(feature = "pci_support")]
use virtio_devices::transport::VirtioPciDevice;
use virtio_devices::transport::VirtioTransport;
use virtio_devices::vhost_user::VhostUserConfig;
#[cfg(feature = "pci_support")]
use virtio_devices::AccessPlatformMapping;
use virtio_devices::Endpoint;
#[cfg(feature = "pci_support")]
use virtio_devices::IommuMapping;
#[cfg(feature = "pci_support")]
use virtio_devices::VirtioMemMappingSource;
use virtio_devices::{VirtioSharedMemory, VirtioSharedMemoryList};
#[cfg(feature = "pci_support")]
use virtio_queue::AccessPlatform;
#[cfg(feature = "pci_support")]
use vm_allocator::AddressAllocator;
use vm_allocator::SystemAllocator;
#[cfg(feature = "pci_support")]
use vm_device::dma_mapping::vfio::VfioDmaMapping;
use vm_device::interrupt::{
    InterruptIndex, InterruptManager, LegacyIrqGroupConfig, MsiIrqGroupConfig,
};
use vm_device::{Bus, BusDevice, Resource};
use vm_memory::guest_memory::FileOffset;
#[cfg(feature = "pci_support")]
use vm_memory::GuestMemoryRegion;
use vm_memory::{Address, GuestAddress, GuestUsize, MmapRegion};
#[cfg(all(target_arch = "x86_64", feature = "cmos"))]
use vm_memory::{GuestAddressSpace, GuestMemory};
use vm_migration::{
    protocol::MemoryRangeTable, Migratable, MigratableError, Pausable, Snapshot,
    SnapshotDataSection, Snapshottable, Transportable,
};
#[cfg(feature = "pci_support")]
use vm_virtio::VirtioDeviceType;
use vmm_sys_util::eventfd::EventFd;

#[cfg(any(feature = "mmio_support", target_arch = "aarch64"))]
const MMIO_LEN: u64 = 0x1000;

#[cfg(feature = "pci_support")]
const VFIO_DEVICE_NAME_PREFIX: &str = "_vfio";

#[cfg(feature = "pci_support")]
const VFIO_USER_DEVICE_NAME_PREFIX: &str = "_vfio_user";

#[cfg(target_arch = "x86_64")]
const IOAPIC_DEVICE_NAME: &str = "_ioapic";

const SERIAL_DEVICE_NAME_PREFIX: &str = "_serial";
#[cfg(target_arch = "aarch64")]
const GPIO_DEVICE_NAME_PREFIX: &str = "_gpio";

const CONSOLE_DEVICE_NAME: &str = "_console";
const DISK_DEVICE_NAME_PREFIX: &str = "_disk";
const FS_DEVICE_NAME_PREFIX: &str = "_fs";
const BALLOON_DEVICE_NAME: &str = "_balloon";
const NET_DEVICE_NAME_PREFIX: &str = "_net";
const PMEM_DEVICE_NAME_PREFIX: &str = "_pmem";
const RNG_DEVICE_NAME: &str = "_rng";
const VSOCK_DEVICE_NAME_PREFIX: &str = "_vsock";
const WATCHDOG_DEVICE_NAME: &str = "_watchdog";

#[cfg(feature = "pci_support")]
const IOMMU_DEVICE_NAME: &str = "_iommu";

#[cfg(feature = "pci_support")]
const VIRTIO_PCI_DEVICE_NAME_PREFIX: &str = "_virtio-pci";
#[cfg(feature = "mmio_support")]
const VIRTIO_MMIO_DEVICE_NAME_PREFIX: &str = "_virtio-mmio";

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

    /// Failed to convert Path to &str for the virtio-vsock device.
    CreateVsockConvertPath,

    /// Cannot create virtio-vsock backend
    CreateVsockBackend(virtio_devices::vsock::VsockUnixError),

    /// Cannot create virtio-iommu device
    CreateVirtioIommu(io::Error),

    /// Cannot create virtio-balloon device
    CreateVirtioBalloon(io::Error),

    /// Cannot create virtio-watchdog device
    CreateVirtioWatchdog(io::Error),

    /// Failed to parse disk image format
    DetectImageType(io::Error),

    /// Cannot open qcow disk path
    QcowDeviceCreate(qcow::Error),

    /// Cannot create serial manager
    CreateSerialManager(SerialManagerError),

    /// Cannot spawn the serial manager thread
    SpawnSerialManager(SerialManagerError),

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
    VfioDmaMap(vfio_ioctls::VfioError),

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

    /// Failed to make hotplug notification
    HotPlugNotification(io::Error),

    /// Error from a memory manager operation
    MemoryManager(MemoryManagerError),

    /// Failed to create new interrupt source group.
    CreateInterruptGroup(io::Error),

    /// Failed to update interrupt source group.
    UpdateInterruptGroup(io::Error),

    /// Failed to create interrupt controller.
    CreateInterruptController(interrupt_controller::Error),

    /// Failed to create a new MmapRegion instance.
    NewMmapRegion(vm_memory::mmap::MmapRegionError),

    /// Failed to clone a File.
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

    /// Failed to remove a PCI device from the PCI bus.
    RemoveDeviceFromPciBus(pci::PciRootError),

    /// Failed to remove a bus device from the IO bus.
    RemoveDeviceFromIoBus(vm_device::BusError),

    /// Failed to remove a bus device from the MMIO bus.
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

    /// Failed to update guest memory for virtio device.
    UpdateMemoryForVirtioDevice(virtio_devices::Error),

    /// Cannot create virtio-mem device
    CreateVirtioMem(io::Error),

    /// Cannot generate a ResizeSender from the Resize object.
    CreateResizeSender(virtio_devices::mem::Error),

    /// Cannot find a memory range for virtio-mem memory
    VirtioMemRangeAllocation,

    /// Failed to update guest memory for VFIO PCI device.
    UpdateMemoryForVfioPciDevice(vfio_ioctls::VfioError),

    /// Trying to use a directory for pmem but no size specified
    PmemWithDirectorySizeMissing,

    /// Trying to use a size that is not multiple of 2MiB
    PmemSizeNotAligned,

    /// Could not find the node in the device tree.
    MissingNode,

    /// Could not find a MMIO range.
    MmioRangeAllocation,

    /// Resource was already found.
    ResourceAlreadyExists,

    /// Expected resources for virtio-mmio could not be found.
    MissingVirtioMmioResources,

    /// Expected resources for virtio-pci could not be found.
    MissingVirtioPciResources,

    /// Expected resources for virtio-pmem could not be found.
    MissingVirtioPmemResources,

    /// Missing PCI b/d/f from the DeviceNode.
    MissingDeviceNodePciBdf,

    /// No support for device passthrough
    NoDevicePassthroughSupport,

    /// Failed to resize virtio-balloon
    VirtioBalloonResize(virtio_devices::balloon::Error),

    /// Missing virtio-balloon, can't proceed as expected.
    MissingVirtioBalloon,

    /// Missing virtual IOMMU device
    MissingVirtualIommu,

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

    /// Failed to create QcowDiskSync
    CreateQcowDiskSync(qcow::Error),

    /// Failed to create FixedVhdxDiskSync
    CreateFixedVhdxDiskSync(vhdx::vhdx::VhdxError),

    /// Failed to add DMA mapping handler to virtio-mem device.
    AddDmaMappingHandlerVirtioMem(virtio_devices::mem::Error),

    /// Failed to remove DMA mapping handler from virtio-mem device.
    RemoveDmaMappingHandlerVirtioMem(virtio_devices::mem::Error),

    /// Failed to create vfio-user client
    VfioUserCreateClient(vfio_user::Error),

    /// Failed to create VFIO user device
    #[cfg(feature = "pci_support")]
    VfioUserCreate(VfioUserPciDeviceError),

    /// Failed to map region from VFIO user device into guest
    #[cfg(feature = "pci_support")]
    VfioUserMapRegion(VfioUserPciDeviceError),

    /// Failed to DMA map VFIO user device.
    #[cfg(feature = "pci_support")]
    VfioUserDmaMap(VfioUserPciDeviceError),

    /// Failed to DMA unmap VFIO user device.
    #[cfg(feature = "pci_support")]
    VfioUserDmaUnmap(VfioUserPciDeviceError),

    /// Failed to update memory mappings for VFIO user device
    #[cfg(feature = "pci_support")]
    UpdateMemoryForVfioUserPciDevice(VfioUserPciDeviceError),

    /// Cannot duplicate file descriptor
    DupFd(vmm_sys_util::errno::Error),
}
pub type DeviceManagerResult<T> = result::Result<T, DeviceManagerError>;

type VirtioDeviceArc = Arc<Mutex<dyn virtio_devices::VirtioDevice>>;

#[cfg(feature = "acpi")]
const DEVICE_MANAGER_ACPI_SIZE: usize = 0x10;

const TIOCSPTLCK: libc::c_int = 0x4004_5431;
const TIOCGTPEER: libc::c_int = 0x5441;

pub fn create_pty(non_blocking: bool) -> io::Result<(File, File, PathBuf)> {
    // Try to use /dev/pts/ptmx first then fall back to /dev/ptmx
    // This is done to try and use the devpts filesystem that
    // could be available for use in the process's namespace first.
    // Ideally these are all the same file though but different
    // kernels could have things setup differently.
    // See https://www.kernel.org/doc/Documentation/filesystems/devpts.txt
    // for further details.

    let custom_flags = libc::O_NOCTTY | if non_blocking { libc::O_NONBLOCK } else { 0 };
    let main = match OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(custom_flags)
        .open("/dev/pts/ptmx")
    {
        Ok(f) => f,
        _ => OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(custom_flags)
            .open("/dev/ptmx")?,
    };
    let mut unlock: libc::c_ulong = 0;
    // SAFETY: FFI call into libc, trivially safe
    unsafe {
        libc::ioctl(
            main.as_raw_fd(),
            TIOCSPTLCK.try_into().unwrap(),
            &mut unlock,
        )
    };

    // SAFETY: FFI call into libc, trivally safe
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

    // SAFETY: sub_fd is checked to be valid before being wrapped in File
    Ok((main, unsafe { File::from_raw_fd(sub_fd) }, path))
}

#[derive(Default)]
pub struct Console {
    console_resizer: Option<Arc<virtio_devices::ConsoleResizer>>,
}

impl Console {
    pub fn update_console_size(&self) {
        if let Some(resizer) = self.console_resizer.as_ref() {
            resizer.update_console_size()
        }
    }
}

pub(crate) struct AddressManager {
    pub(crate) allocator: Arc<Mutex<SystemAllocator>>,
    #[cfg(target_arch = "x86_64")]
    pub(crate) io_bus: Arc<Bus>,
    pub(crate) mmio_bus: Arc<Bus>,
    vm: Arc<dyn hypervisor::Vm>,
    #[cfg(feature = "pci_support")]
    device_tree: Arc<Mutex<DeviceTree>>,
    #[cfg(feature = "pci_support")]
    pci_mmio_allocators: Vec<Arc<Mutex<AddressAllocator>>>,
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
                            Some(len),
                        )
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::Other,
                                "failed allocating new 32 bits MMIO range",
                            )
                        })?;
                } else {
                    // Find the specific allocator that this BAR was allocated from and use it for new one
                    for allocator in &self.pci_mmio_allocators {
                        let allocator_base = allocator.lock().unwrap().base();
                        let allocator_end = allocator.lock().unwrap().end();

                        if old_base >= allocator_base.0 && old_base <= allocator_end.0 {
                            allocator
                                .lock()
                                .unwrap()
                                .free(GuestAddress(old_base), len as GuestUsize);

                            allocator
                                .lock()
                                .unwrap()
                                .allocate(
                                    Some(GuestAddress(new_base)),
                                    len as GuestUsize,
                                    Some(len),
                                )
                                .ok_or_else(|| {
                                    io::Error::new(
                                        io::ErrorKind::Other,
                                        "failed allocating new 64 bits MMIO range",
                                    )
                                })?;

                            break;
                        }
                    }
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
                        let mem_region = self.vm.make_user_memory_region(
                            shm_regions.mem_slot,
                            old_base,
                            shm_regions.len,
                            shm_regions.host_addr,
                            false,
                            false,
                        );

                        self.vm.remove_user_memory_region(mem_region).map_err(|e| {
                            io::Error::new(
                                io::ErrorKind::Other,
                                format!("failed to remove user memory region: {:?}", e),
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

                        self.vm.create_user_memory_region(mem_region).map_err(|e| {
                            io::Error::new(
                                io::ErrorKind::Other,
                                format!("failed to create user memory regions: {:?}", e),
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

impl Clone for PtyPair {
    fn clone(&self) -> Self {
        PtyPair {
            main: self.main.try_clone().unwrap(),
            sub: self.sub.try_clone().unwrap(),
            path: self.path.clone(),
        }
    }
}

#[cfg(feature = "pci_support")]
#[derive(Clone)]
pub enum PciDeviceHandle {
    Vfio(Arc<Mutex<VfioPciDevice>>),
    Virtio(Arc<Mutex<VirtioPciDevice>>),
    VfioUser(Arc<Mutex<VfioUserPciDevice>>),
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

    // Serial Manager
    serial_manager: Option<Arc<SerialManager>>,

    // pty foreground status,
    console_resize_pipe: Option<Arc<File>>,

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
    virtio_devices: Vec<(VirtioDeviceArc, bool, String, u16)>,

    // List of bus devices
    // Let the DeviceManager keep strong references to the BusDevice devices.
    // This allows the IO and MMIO buses to be provided with Weak references,
    // which prevents cyclic dependencies.
    bus_devices: Vec<Arc<Mutex<dyn BusDevice>>>,

    // Counter to keep track of the consumed device IDs.
    device_id_cnt: Wrapping<usize>,

    #[cfg(feature = "pci_support")]
    pci_segments: Vec<PciSegment>,

    #[cfg_attr(target_arch = "aarch64", allow(dead_code))]
    // MSI Interrupt Manager
    msi_interrupt_manager: Arc<dyn InterruptManager<GroupConfig = MsiIrqGroupConfig>>,

    #[cfg_attr(feature = "mshv", allow(dead_code))]
    // Legacy Interrupt Manager
    legacy_interrupt_manager: Option<Arc<dyn InterruptManager<GroupConfig = LegacyIrqGroupConfig>>>,

    // Passthrough device handle
    #[cfg(feature = "pci_support")]
    passthrough_device: Option<Arc<dyn hypervisor::Device>>,

    // VFIO container
    // Only one container can be created, therefore it is stored as part of the
    // DeviceManager to be reused.
    #[cfg(feature = "pci_support")]
    vfio_container: Option<Arc<VfioContainer>>,

    // Paravirtualized IOMMU
    #[cfg(feature = "pci_support")]
    iommu_device: Option<Arc<Mutex<virtio_devices::Iommu>>>,

    // PCI information about devices attached to the paravirtualized IOMMU
    // It contains the virtual IOMMU PCI BDF along with the list of PCI BDF
    // representing the devices attached to the virtual IOMMU. This is useful
    // information for filling the ACPI VIOT table.
    #[cfg(feature = "pci_support")]
    iommu_attached_devices: Option<(PciBdf, Vec<PciBdf>)>,

    // Tree of devices, representing the dependencies between devices.
    // Useful for introspection, snapshot and restore.
    device_tree: Arc<Mutex<DeviceTree>>,

    // Exit event
    exit_evt: EventFd,
    reset_evt: EventFd,

    #[cfg(target_arch = "aarch64")]
    id_to_dev_info: HashMap<(DeviceType, String), MmioDeviceInfo>,

    // seccomp action
    seccomp_action: SeccompAction,

    // List of guest NUMA nodes.
    #[cfg(any(target_arch = "aarch64", feature = "acpi"))]
    numa_nodes: NumaNodes,

    // Possible handle to the virtio-balloon device
    balloon: Option<Arc<Mutex<virtio_devices::Balloon>>>,

    // Virtio Device activation EventFd to allow the VMM thread to trigger device
    // activation and thus start the threads from the VMM thread
    activate_evt: EventFd,

    #[cfg(feature = "acpi")]
    acpi_address: GuestAddress,
    #[cfg(feature = "acpi")]
    selected_segment: usize,

    // Possible handle to the virtio-mem device
    virtio_mem_devices: Vec<Arc<Mutex<virtio_devices::Mem>>>,

    #[cfg(target_arch = "aarch64")]
    // GPIO device for AArch64
    gpio_device: Option<Arc<Mutex<devices::legacy::Gpio>>>,

    // Flag to force setting the iommu on virtio devices
    force_iommu: bool,

    // Helps identify if the VM is currently being restored
    restoring: bool,

    // io_uring availability if detected
    io_uring_supported: Option<bool>,
}

impl DeviceManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vm: Arc<dyn hypervisor::Vm>,
        config: Arc<Mutex<VmConfig>>,
        memory_manager: Arc<Mutex<MemoryManager>>,
        exit_evt: &EventFd,
        reset_evt: &EventFd,
        seccomp_action: SeccompAction,
        #[cfg(any(target_arch = "aarch64", feature = "acpi"))] numa_nodes: NumaNodes,
        activate_evt: &EventFd,
        force_iommu: bool,
        restoring: bool,
    ) -> DeviceManagerResult<Arc<Mutex<Self>>> {
        let device_tree = Arc::new(Mutex::new(DeviceTree::new()));
        #[cfg(feature = "pci_support")]
        let mut pci_mmio_allocators;
        #[cfg(feature = "pci_support")]
        let mut pci_segments;
        #[cfg(feature = "pci_support")]
        let num_pci_segments;

        #[cfg(feature = "pci_support")]
        {
            num_pci_segments =
                if let Some(platform_config) = config.lock().unwrap().platform.as_ref() {
                    platform_config.num_pci_segments
                } else {
                    1
                };

            let start_of_device_area = memory_manager.lock().unwrap().start_of_device_area().0;
            let end_of_device_area = memory_manager.lock().unwrap().end_of_device_area().0;

            // Start each PCI segment range on a 4GiB boundary
            let pci_segment_size = (end_of_device_area - start_of_device_area + 1)
                / ((4 << 30) * num_pci_segments as u64)
                * (4 << 30);

            pci_mmio_allocators = vec![];
            for i in 0..num_pci_segments as u64 {
                let mmio_start = start_of_device_area + i * pci_segment_size;
                let allocator = Arc::new(Mutex::new(
                    AddressAllocator::new(GuestAddress(mmio_start), pci_segment_size).unwrap(),
                ));
                pci_mmio_allocators.push(allocator)
            }
        }

        let address_manager = Arc::new(AddressManager {
            allocator: memory_manager.lock().unwrap().allocator(),
            #[cfg(target_arch = "x86_64")]
            io_bus: Arc::new(Bus::new()),
            mmio_bus: Arc::new(Bus::new()),
            vm: vm.clone(),
            #[cfg(feature = "pci_support")]
            device_tree: Arc::clone(&device_tree),
            #[cfg(feature = "pci_support")]
            pci_mmio_allocators,
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
            .allocate_platform_mmio_addresses(None, DEVICE_MANAGER_ACPI_SIZE as u64, None)
            .ok_or(DeviceManagerError::AllocateIoPort)?;

        #[cfg(feature = "pci_support")]
        {
            let mut pci_irq_slots = [0; 32];
            PciSegment::reserve_legacy_interrupts_for_pci_devices(
                &address_manager,
                &mut pci_irq_slots,
            )?;

            pci_segments = vec![PciSegment::new_default_segment(
                &address_manager,
                Arc::clone(&address_manager.pci_mmio_allocators[0]),
                &pci_irq_slots,
            )?];

            for i in 1..num_pci_segments as usize {
                pci_segments.push(PciSegment::new(
                    i as u16,
                    &address_manager,
                    Arc::clone(&address_manager.pci_mmio_allocators[i]),
                    &pci_irq_slots,
                )?);
            }
        }

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
            msi_interrupt_manager,
            legacy_interrupt_manager: None,
            #[cfg(feature = "pci_support")]
            passthrough_device: None,
            #[cfg(feature = "pci_support")]
            vfio_container: None,
            #[cfg(feature = "pci_support")]
            iommu_device: None,
            #[cfg(feature = "pci_support")]
            iommu_attached_devices: None,
            #[cfg(feature = "pci_support")]
            pci_segments,
            device_tree,
            exit_evt: exit_evt.try_clone().map_err(DeviceManagerError::EventFd)?,
            reset_evt: reset_evt.try_clone().map_err(DeviceManagerError::EventFd)?,
            #[cfg(target_arch = "aarch64")]
            id_to_dev_info: HashMap::new(),
            seccomp_action,
            #[cfg(any(target_arch = "aarch64", feature = "acpi"))]
            numa_nodes,
            balloon: None,
            activate_evt: activate_evt
                .try_clone()
                .map_err(DeviceManagerError::EventFd)?,
            #[cfg(feature = "acpi")]
            acpi_address,
            #[cfg(feature = "acpi")]
            selected_segment: 0,
            serial_pty: None,
            serial_manager: None,
            console_pty: None,
            console_resize_pipe: None,
            virtio_mem_devices: Vec::new(),
            #[cfg(target_arch = "aarch64")]
            gpio_device: None,
            force_iommu,
            restoring,
            io_uring_supported: None,
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

    pub fn console_resize_pipe(&self) -> Option<Arc<File>> {
        self.console_resize_pipe.as_ref().map(Arc::clone)
    }

    pub fn create_devices(
        &mut self,
        serial_pty: Option<PtyPair>,
        console_pty: Option<PtyPair>,
        console_resize_pipe: Option<File>,
    ) -> DeviceManagerResult<()> {
        let mut virtio_devices: Vec<(VirtioDeviceArc, bool, String, u16)> = Vec::new();

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
            console_resize_pipe,
        )?;

        virtio_devices.append(&mut self.make_virtio_devices()?);

        if cfg!(feature = "pci_support") {
            self.add_pci_devices(virtio_devices.clone())?;
        } else if cfg!(feature = "mmio_support") {
            self.add_mmio_devices(virtio_devices.clone(), &legacy_interrupt_manager)?;
        }

        self.legacy_interrupt_manager = Some(legacy_interrupt_manager);

        self.virtio_devices = virtio_devices;

        Ok(())
    }

    fn state(&self) -> DeviceManagerState {
        DeviceManagerState {
            device_tree: self.device_tree.lock().unwrap().clone(),
            device_id_cnt: self.device_id_cnt,
        }
    }

    fn set_state(&mut self, state: &DeviceManagerState) {
        *self.device_tree.lock().unwrap() = state.device_tree.clone();
        self.device_id_cnt = state.device_id_cnt;
    }

    #[cfg(feature = "pci_support")]
    fn get_msi_iova_space(&mut self) -> (u64, u64) {
        #[cfg(target_arch = "aarch64")]
        {
            let vcpus = self.config.lock().unwrap().cpus.boot_vcpus;
            let msi_start = arch::layout::GIC_V3_DIST_START
                - arch::layout::GIC_V3_REDIST_SIZE * (vcpus as u64)
                - arch::layout::GIC_V3_ITS_SIZE;
            let msi_end = msi_start + arch::layout::GIC_V3_ITS_SIZE - 1;
            (msi_start, msi_end)
        }
        #[cfg(target_arch = "x86_64")]
        (0xfee0_0000, 0xfeef_ffff)
    }

    #[cfg(target_arch = "aarch64")]
    /// Gets the information of the devices registered up to some point in time.
    pub fn get_device_info(&self) -> &HashMap<(DeviceType, String), MmioDeviceInfo> {
        &self.id_to_dev_info
    }

    #[allow(unused_variables)]
    fn add_pci_devices(
        &mut self,
        virtio_devices: Vec<(VirtioDeviceArc, bool, String, u16)>,
    ) -> DeviceManagerResult<()> {
        #[cfg(feature = "pci_support")]
        {
            let iommu_id = String::from(IOMMU_DEVICE_NAME);

            let (iommu_device, iommu_mapping) = if self.config.lock().unwrap().iommu {
                let (device, mapping) = virtio_devices::Iommu::new(
                    iommu_id.clone(),
                    self.seccomp_action.clone(),
                    self.exit_evt
                        .try_clone()
                        .map_err(DeviceManagerError::EventFd)?,
                    self.get_msi_iova_space(),
                )
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
            {
                for (device, iommu_attached, id, pci_segment_id) in virtio_devices {
                    let mapping: &Option<Arc<IommuMapping>> = if iommu_attached {
                        &iommu_mapping
                    } else {
                        &None
                    };

                    let dev_id = self.add_virtio_pci_device(device, mapping, id, pci_segment_id)?;

                    if iommu_attached {
                        iommu_attached_devices.push(dev_id);
                    }
                }

                let mut vfio_iommu_device_ids = self.add_vfio_devices()?;
                iommu_attached_devices.append(&mut vfio_iommu_device_ids);

                let mut vfio_user_iommu_device_ids = self.add_user_devices()?;
                iommu_attached_devices.append(&mut vfio_user_iommu_device_ids);

                if let Some(iommu_device) = iommu_device {
                    let dev_id = self.add_virtio_pci_device(iommu_device, &None, iommu_id, 0)?;
                    self.iommu_attached_devices = Some((dev_id, iommu_attached_devices));
                }
            }

            for segment in &self.pci_segments {
                #[cfg(target_arch = "x86_64")]
                if let Some(pci_config_io) = segment.pci_config_io.as_ref() {
                    self.bus_devices
                        .push(Arc::clone(pci_config_io) as Arc<Mutex<dyn BusDevice>>);
                }

                self.bus_devices
                    .push(Arc::clone(&segment.pci_config_mmio) as Arc<Mutex<dyn BusDevice>>);
            }
        }

        Ok(())
    }

    #[allow(unused_variables)]
    fn add_mmio_devices(
        &mut self,
        virtio_devices: Vec<(VirtioDeviceArc, bool, String, u16)>,
        interrupt_manager: &Arc<dyn InterruptManager<GroupConfig = LegacyIrqGroupConfig>>,
    ) -> DeviceManagerResult<()> {
        #[cfg(feature = "mmio_support")]
        {
            for (device, _, id, _) in virtio_devices {
                self.add_virtio_mmio_device(id, device, interrupt_manager)?;
            }
        }

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
            .allocate_platform_mmio_addresses(
                None,
                devices::acpi::GED_DEVICE_ACPI_SIZE as u64,
                None,
            )
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
                len: MMIO_LEN,
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
                len: MMIO_LEN,
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
                len: MMIO_LEN,
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
        // SAFETY: safe because we check the return value of isatty.
        if unsafe { isatty(fd) } != 1 {
            return Ok(());
        }

        // SAFETY: The following pair are safe because termios gets totally overwritten by tcgetattr
        // and we check the return result.
        let mut termios: termios = unsafe { zeroed() };
        let ret = unsafe { tcgetattr(fd, &mut termios as *mut _) };
        if ret < 0 {
            return vmm_sys_util::errno::errno_result();
        }
        f(&mut termios);
        // SAFETY: Safe because the syscall will only read the extent of termios and we check
        // the return result.
        let ret = unsafe { tcsetattr(fd, TCSANOW, &termios as *const _) };
        if ret < 0 {
            return vmm_sys_util::errno::errno_result();
        }

        Ok(())
    }

    fn set_raw_mode(&self, f: &mut File) -> vmm_sys_util::errno::Result<()> {
        // SAFETY: FFI call. Variable t is guaranteed to be a valid termios from modify_mode.
        self.modify_mode(f.as_raw_fd(), |t| unsafe { cfmakeraw(t) })
    }

    fn listen_for_sigwinch_on_tty(&mut self, pty: &File) -> std::io::Result<()> {
        let seccomp_filter =
            get_seccomp_filter(&self.seccomp_action, Thread::PtyForeground).unwrap();

        match start_sigwinch_listener(seccomp_filter, pty) {
            Ok(pipe) => {
                self.console_resize_pipe = Some(Arc::new(pipe));
            }
            Err(e) => {
                warn!("Ignoring error from setting up SIGWINCH listener: {}", e)
            }
        }

        Ok(())
    }

    fn add_virtio_console_device(
        &mut self,
        virtio_devices: &mut Vec<(VirtioDeviceArc, bool, String, u16)>,
        console_pty: Option<PtyPair>,
        resize_pipe: Option<File>,
    ) -> DeviceManagerResult<Option<Arc<virtio_devices::ConsoleResizer>>> {
        let console_config = self.config.lock().unwrap().console.clone();
        let endpoint = match console_config.mode {
            ConsoleOutputMode::File => {
                let file = File::create(console_config.file.as_ref().unwrap())
                    .map_err(DeviceManagerError::ConsoleOutputFileOpen)?;
                Endpoint::File(file)
            }
            ConsoleOutputMode::Pty => {
                if let Some(pty) = console_pty {
                    self.config.lock().unwrap().console.file = Some(pty.path.clone());
                    let file = pty.main.try_clone().unwrap();
                    self.console_pty = Some(Arc::new(Mutex::new(pty)));
                    self.console_resize_pipe = resize_pipe.map(Arc::new);
                    Endpoint::FilePair(file.try_clone().unwrap(), file)
                } else {
                    let (main, mut sub, path) =
                        create_pty(false).map_err(DeviceManagerError::ConsolePtyOpen)?;
                    self.set_raw_mode(&mut sub)
                        .map_err(DeviceManagerError::SetPtyRaw)?;
                    self.config.lock().unwrap().console.file = Some(path.clone());
                    let file = main.try_clone().unwrap();
                    assert!(resize_pipe.is_none());
                    self.listen_for_sigwinch_on_tty(&sub).unwrap();
                    self.console_pty = Some(Arc::new(Mutex::new(PtyPair { main, sub, path })));
                    Endpoint::FilePair(file.try_clone().unwrap(), file)
                }
            }
            ConsoleOutputMode::Tty => {
                // Duplicating the file descriptors like this is needed as otherwise
                // they will be closed on a reboot and the numbers reused

                // SAFETY: FFI call to dup. Trivially safe.
                let stdout = unsafe { libc::dup(libc::STDOUT_FILENO) };
                if stdout == -1 {
                    return vmm_sys_util::errno::errno_result().map_err(DeviceManagerError::DupFd);
                }
                // SAFETY: stdout is valid and owned solely by us.
                let stdout = unsafe { File::from_raw_fd(stdout) };

                // If an interactive TTY then we can accept input
                // SAFETY: FFI call. Trivially safe.
                if unsafe { libc::isatty(libc::STDIN_FILENO) == 1 } {
                    // SAFETY: FFI call to dup. Trivially safe.
                    let stdin = unsafe { libc::dup(libc::STDIN_FILENO) };
                    if stdin == -1 {
                        return vmm_sys_util::errno::errno_result()
                            .map_err(DeviceManagerError::DupFd);
                    }
                    // SAFETY: stdin is valid and owned solely by us.
                    let stdin = unsafe { File::from_raw_fd(stdin) };

                    Endpoint::FilePair(stdout, stdin)
                } else {
                    Endpoint::File(stdout)
                }
            }
            ConsoleOutputMode::Null => Endpoint::Null,
            ConsoleOutputMode::Off => return Ok(None),
        };
        let id = String::from(CONSOLE_DEVICE_NAME);

        let (virtio_console_device, console_resizer) = virtio_devices::Console::new(
            id.clone(),
            endpoint,
            self.console_resize_pipe
                .as_ref()
                .map(|p| p.try_clone().unwrap()),
            self.force_iommu | console_config.iommu,
            self.seccomp_action.clone(),
            self.exit_evt
                .try_clone()
                .map_err(DeviceManagerError::EventFd)?,
        )
        .map_err(DeviceManagerError::CreateVirtioConsole)?;
        let virtio_console_device = Arc::new(Mutex::new(virtio_console_device));
        virtio_devices.push((
            Arc::clone(&virtio_console_device) as VirtioDeviceArc,
            console_config.iommu,
            id.clone(),
            0,
        ));

        // Fill the device tree with a new node. In case of restore, we
        // know there is nothing to do, so we can simply override the
        // existing entry.
        self.device_tree
            .lock()
            .unwrap()
            .insert(id.clone(), device_node!(id, virtio_console_device));

        // Only provide a resizer (for SIGWINCH handling) if the console is attached to the TTY
        Ok(if matches!(console_config.mode, ConsoleOutputMode::Tty) {
            Some(console_resizer)
        } else {
            None
        })
    }

    fn add_console_device(
        &mut self,
        interrupt_manager: &Arc<dyn InterruptManager<GroupConfig = LegacyIrqGroupConfig>>,
        virtio_devices: &mut Vec<(VirtioDeviceArc, bool, String, u16)>,
        serial_pty: Option<PtyPair>,
        console_pty: Option<PtyPair>,
        console_resize_pipe: Option<File>,
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
                    self.serial_pty = Some(Arc::new(Mutex::new(pty)));
                } else {
                    let (main, mut sub, path) =
                        create_pty(true).map_err(DeviceManagerError::SerialPtyOpen)?;
                    self.set_raw_mode(&mut sub)
                        .map_err(DeviceManagerError::SetPtyRaw)?;
                    self.config.lock().unwrap().serial.file = Some(path.clone());
                    self.serial_pty = Some(Arc::new(Mutex::new(PtyPair { main, sub, path })));
                }
                None
            }
            ConsoleOutputMode::Tty => Some(Box::new(stdout())),
            ConsoleOutputMode::Off | ConsoleOutputMode::Null => None,
        };
        if serial_config.mode != ConsoleOutputMode::Off {
            let serial = self.add_serial_device(interrupt_manager, serial_writer)?;
            self.serial_manager = match serial_config.mode {
                ConsoleOutputMode::Pty | ConsoleOutputMode::Tty => {
                    let serial_manager =
                        SerialManager::new(serial, self.serial_pty.clone(), serial_config.mode)
                            .map_err(DeviceManagerError::CreateSerialManager)?;
                    if let Some(mut serial_manager) = serial_manager {
                        serial_manager
                            .start_thread(
                                self.exit_evt
                                    .try_clone()
                                    .map_err(DeviceManagerError::EventFd)?,
                            )
                            .map_err(DeviceManagerError::SpawnSerialManager)?;
                        Some(Arc::new(serial_manager))
                    } else {
                        None
                    }
                }
                _ => None,
            };
        }

        let console_resizer =
            self.add_virtio_console_device(virtio_devices, console_pty, console_resize_pipe)?;

        Ok(Arc::new(Console { console_resizer }))
    }

    fn make_virtio_devices(
        &mut self,
    ) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool, String, u16)>> {
        let mut devices: Vec<(VirtioDeviceArc, bool, String, u16)> = Vec::new();

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

    // Cache whether io_uring is supported to avoid probing for very block device
    fn io_uring_is_supported(&mut self) -> bool {
        if let Some(supported) = self.io_uring_supported {
            return supported;
        }

        let supported = block_io_uring_is_supported();
        self.io_uring_supported = Some(supported);
        supported
    }

    fn make_virtio_block_device(
        &mut self,
        disk_cfg: &mut DiskConfig,
    ) -> DeviceManagerResult<(VirtioDeviceArc, bool, String, u16)> {
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
                match virtio_devices::vhost_user::Blk::new(
                    id.clone(),
                    vu_cfg,
                    self.restoring,
                    self.seccomp_action.clone(),
                    self.exit_evt
                        .try_clone()
                        .map_err(DeviceManagerError::EventFd)?,
                ) {
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
                disk_cfg.pci_segment,
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
                    if self.io_uring_is_supported() && !disk_cfg.disable_io_uring {
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
                    if self.io_uring_is_supported() && !disk_cfg.disable_io_uring {
                        info!("Using asynchronous RAW disk file (io_uring)");
                        Box::new(RawFileDisk::new(file)) as Box<dyn DiskFile>
                    } else {
                        info!("Using synchronous RAW disk file");
                        Box::new(RawFileDiskSync::new(file)) as Box<dyn DiskFile>
                    }
                }
                ImageType::Qcow2 => {
                    info!("Using synchronous QCOW disk file");
                    Box::new(
                        QcowDiskSync::new(file, disk_cfg.direct)
                            .map_err(DeviceManagerError::CreateQcowDiskSync)?,
                    ) as Box<dyn DiskFile>
                }
                ImageType::Vhdx => {
                    info!("Using synchronous VHDX disk file");
                    Box::new(
                        VhdxDiskSync::new(file)
                            .map_err(DeviceManagerError::CreateFixedVhdxDiskSync)?,
                    ) as Box<dyn DiskFile>
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
                    self.force_iommu | disk_cfg.iommu,
                    disk_cfg.num_queues,
                    disk_cfg.queue_size,
                    self.seccomp_action.clone(),
                    disk_cfg.rate_limiter_config,
                    self.exit_evt
                        .try_clone()
                        .map_err(DeviceManagerError::EventFd)?,
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

            Ok((virtio_device, disk_cfg.iommu, id, disk_cfg.pci_segment))
        }
    }

    fn make_virtio_block_devices(
        &mut self,
    ) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool, String, u16)>> {
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
    ) -> DeviceManagerResult<(VirtioDeviceArc, bool, String, u16)> {
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
                    self.restoring,
                    self.exit_evt
                        .try_clone()
                        .map_err(DeviceManagerError::EventFd)?,
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
                net_cfg.pci_segment,
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
                        self.force_iommu | net_cfg.iommu,
                        net_cfg.num_queues,
                        net_cfg.queue_size,
                        self.seccomp_action.clone(),
                        net_cfg.rate_limiter_config,
                        self.exit_evt
                            .try_clone()
                            .map_err(DeviceManagerError::EventFd)?,
                    )
                    .map_err(DeviceManagerError::CreateVirtioNet)?,
                ))
            } else if let Some(fds) = &net_cfg.fds {
                Arc::new(Mutex::new(
                    virtio_devices::Net::from_tap_fds(
                        id.clone(),
                        fds,
                        Some(net_cfg.mac),
                        self.force_iommu | net_cfg.iommu,
                        net_cfg.queue_size,
                        self.seccomp_action.clone(),
                        net_cfg.rate_limiter_config,
                        self.exit_evt
                            .try_clone()
                            .map_err(DeviceManagerError::EventFd)?,
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
                        self.force_iommu | net_cfg.iommu,
                        net_cfg.num_queues,
                        net_cfg.queue_size,
                        self.seccomp_action.clone(),
                        net_cfg.rate_limiter_config,
                        self.exit_evt
                            .try_clone()
                            .map_err(DeviceManagerError::EventFd)?,
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
                net_cfg.pci_segment,
            ))
        }
    }

    /// Add virto-net and vhost-user-net devices
    fn make_virtio_net_devices(
        &mut self,
    ) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool, String, u16)>> {
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
    ) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool, String, u16)>> {
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
                    self.force_iommu | rng_config.iommu,
                    self.seccomp_action.clone(),
                    self.exit_evt
                        .try_clone()
                        .map_err(DeviceManagerError::EventFd)?,
                )
                .map_err(DeviceManagerError::CreateVirtioRng)?,
            ));
            devices.push((
                Arc::clone(&virtio_rng_device) as VirtioDeviceArc,
                rng_config.iommu,
                id.clone(),
                0,
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
    ) -> DeviceManagerResult<(VirtioDeviceArc, bool, String, u16)> {
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
            info!("Restoring virtio-fs {} resources", id);

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

            cache_range
        } else {
            None
        };

        if let Some(fs_socket) = fs_cfg.socket.to_str() {
            let cache = if fs_cfg.dax {
                let (cache_base, cache_size) = if let Some((base, size)) = cache_range {
                    // The memory needs to be 2MiB aligned in order to support
                    // hugepages.
                    #[cfg(feature = "pci_support")]
                    self.pci_segments[fs_cfg.pci_segment as usize]
                        .allocator
                        .lock()
                        .unwrap()
                        .allocate(
                            Some(GuestAddress(base)),
                            size as GuestUsize,
                            Some(0x0020_0000),
                        )
                        .ok_or(DeviceManagerError::FsRangeAllocation)?;

                    #[cfg(not(feature = "pci_support"))]
                    self.address_manager
                        .allocator
                        .lock()
                        .unwrap()
                        .allocate_platform_mmio_addresses(
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
                    #[cfg(feature = "pci_support")]
                    let base = self.pci_segments[fs_cfg.pci_segment as usize]
                        .allocator
                        .lock()
                        .unwrap()
                        .allocate(None, size as GuestUsize, Some(0x0020_0000))
                        .ok_or(DeviceManagerError::FsRangeAllocation)?;

                    #[cfg(not(feature = "pci_support"))]
                    let base = self
                        .address_manager
                        .allocator
                        .lock()
                        .unwrap()
                        .allocate_platform_mmio_addresses(
                            None,
                            size as GuestUsize,
                            Some(0x0020_0000),
                        )
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
                    self.restoring,
                    self.exit_evt
                        .try_clone()
                        .map_err(DeviceManagerError::EventFd)?,
                )
                .map_err(DeviceManagerError::CreateVirtioFs)?,
            ));

            // Update the device tree with the migratable device.
            node.migratable = Some(Arc::clone(&virtio_fs_device) as Arc<Mutex<dyn Migratable>>);
            self.device_tree.lock().unwrap().insert(id.clone(), node);

            Ok((
                Arc::clone(&virtio_fs_device) as VirtioDeviceArc,
                false,
                id,
                fs_cfg.pci_segment,
            ))
        } else {
            Err(DeviceManagerError::NoVirtioFsSock)
        }
    }

    fn make_virtio_fs_devices(
        &mut self,
    ) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool, String, u16)>> {
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
    ) -> DeviceManagerResult<(VirtioDeviceArc, bool, String, u16)> {
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
            info!("Restoring virtio-pmem {} resources", id);

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
                return Err(DeviceManagerError::MissingVirtioPmemResources);
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
            #[cfg(feature = "pci_support")]
            self.pci_segments[pmem_cfg.pci_segment as usize]
                .allocator
                .lock()
                .unwrap()
                .allocate(
                    Some(GuestAddress(base)),
                    size as GuestUsize,
                    Some(0x0020_0000),
                )
                .ok_or(DeviceManagerError::PmemRangeAllocation)?;

            #[cfg(not(feature = "pci_support"))]
            self.address_manager
                .allocator
                .lock()
                .unwrap()
                .allocate_platform_mmio_addresses(
                    Some(GuestAddress(base)),
                    size as GuestUsize,
                    Some(0x0020_0000),
                )
                .ok_or(DeviceManagerError::PmemRangeAllocation)?;

            (base, size)
        } else {
            // The memory needs to be 2MiB aligned in order to support
            // hugepages.
            #[cfg(feature = "pci_support")]
            let base = self.pci_segments[pmem_cfg.pci_segment as usize]
                .allocator
                .lock()
                .unwrap()
                .allocate(None, size as GuestUsize, Some(0x0020_0000))
                .ok_or(DeviceManagerError::PmemRangeAllocation)?;

            #[cfg(not(feature = "pci_support"))]
            let base = self
                .address_manager
                .allocator
                .lock()
                .unwrap()
                .allocate_platform_mmio_addresses(None, size as GuestUsize, Some(0x0020_0000))
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
                self.force_iommu | pmem_cfg.iommu,
                self.seccomp_action.clone(),
                self.exit_evt
                    .try_clone()
                    .map_err(DeviceManagerError::EventFd)?,
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
            pmem_cfg.pci_segment,
        ))
    }

    fn make_virtio_pmem_devices(
        &mut self,
    ) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool, String, u16)>> {
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
    ) -> DeviceManagerResult<(VirtioDeviceArc, bool, String, u16)> {
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
                self.force_iommu | vsock_cfg.iommu,
                self.seccomp_action.clone(),
                self.exit_evt
                    .try_clone()
                    .map_err(DeviceManagerError::EventFd)?,
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
            vsock_cfg.pci_segment,
        ))
    }

    fn make_virtio_vsock_devices(
        &mut self,
    ) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool, String, u16)>> {
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
    ) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool, String, u16)>> {
        let mut devices = Vec::new();

        let mm = self.memory_manager.clone();
        let mm = mm.lock().unwrap();
        for (memory_zone_id, memory_zone) in mm.memory_zones().iter() {
            if let Some(virtio_mem_zone) = memory_zone.virtio_mem_zone() {
                info!("Creating virtio-mem device: id = {}", memory_zone_id);

                #[cfg(all(target_arch = "x86_64", not(feature = "acpi")))]
                let node_id: Option<u16> = None;
                #[cfg(any(target_arch = "aarch64", feature = "acpi"))]
                let node_id = numa_node_id_from_memory_zone_id(&self.numa_nodes, memory_zone_id)
                    .map(|i| i as u16);

                let virtio_mem_device = Arc::new(Mutex::new(
                    virtio_devices::Mem::new(
                        memory_zone_id.clone(),
                        virtio_mem_zone.region(),
                        virtio_mem_zone
                            .resize_handler()
                            .new_resize_sender()
                            .map_err(DeviceManagerError::CreateResizeSender)?,
                        self.seccomp_action.clone(),
                        node_id,
                        virtio_mem_zone.hotplugged_size(),
                        virtio_mem_zone.hugepages(),
                        self.exit_evt
                            .try_clone()
                            .map_err(DeviceManagerError::EventFd)?,
                        virtio_mem_zone.blocks_state().clone(),
                    )
                    .map_err(DeviceManagerError::CreateVirtioMem)?,
                ));

                self.virtio_mem_devices.push(Arc::clone(&virtio_mem_device));

                devices.push((
                    Arc::clone(&virtio_mem_device) as VirtioDeviceArc,
                    false,
                    memory_zone_id.clone(),
                    0,
                ));

                // Fill the device tree with a new node. In case of restore, we
                // know there is nothing to do, so we can simply override the
                // existing entry.
                self.device_tree.lock().unwrap().insert(
                    memory_zone_id.clone(),
                    device_node!(memory_zone_id, virtio_mem_device),
                );
            }
        }

        Ok(devices)
    }

    fn make_virtio_balloon_devices(
        &mut self,
    ) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool, String, u16)>> {
        let mut devices = Vec::new();

        if let Some(balloon_config) = &self.config.lock().unwrap().balloon {
            let id = String::from(BALLOON_DEVICE_NAME);
            info!("Creating virtio-balloon device: id = {}", id);

            let virtio_balloon_device = Arc::new(Mutex::new(
                virtio_devices::Balloon::new(
                    id.clone(),
                    balloon_config.size,
                    balloon_config.deflate_on_oom,
                    self.seccomp_action.clone(),
                    self.exit_evt
                        .try_clone()
                        .map_err(DeviceManagerError::EventFd)?,
                )
                .map_err(DeviceManagerError::CreateVirtioBalloon)?,
            ));

            self.balloon = Some(virtio_balloon_device.clone());

            devices.push((
                Arc::clone(&virtio_balloon_device) as VirtioDeviceArc,
                false,
                id.clone(),
                0,
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
    ) -> DeviceManagerResult<Vec<(VirtioDeviceArc, bool, String, u16)>> {
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
                self.exit_evt
                    .try_clone()
                    .map_err(DeviceManagerError::EventFd)?,
            )
            .map_err(DeviceManagerError::CreateVirtioWatchdog)?,
        ));
        devices.push((
            Arc::clone(&virtio_watchdog_device) as VirtioDeviceArc,
            false,
            id.clone(),
            0,
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

    #[cfg(feature = "pci_support")]
    fn add_passthrough_device(
        &mut self,
        device_cfg: &mut DeviceConfig,
    ) -> DeviceManagerResult<(PciBdf, String)> {
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

        self.add_vfio_device(device_cfg)
    }

    #[cfg(feature = "pci_support")]
    fn create_vfio_container(&self) -> DeviceManagerResult<Arc<VfioContainer>> {
        let passthrough_device = self
            .passthrough_device
            .as_ref()
            .ok_or(DeviceManagerError::NoDevicePassthroughSupport)?;

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
        if dup_device_fd == -1 {
            return vmm_sys_util::errno::errno_result().map_err(DeviceManagerError::DupFd);
        }

        // SAFETY the raw fd conversion here is safe because:
        //   1. When running on KVM or MSHV, passthrough_device wraps around DeviceFd.
        //   2. The conversion here extracts the raw fd and then turns the raw fd into a DeviceFd
        //      of the same (correct) type.
        Ok(Arc::new(
            VfioContainer::new(Arc::new(unsafe { DeviceFd::from_raw_fd(dup_device_fd) }))
                .map_err(DeviceManagerError::VfioCreate)?,
        ))
    }

    #[cfg(feature = "pci_support")]
    fn add_vfio_device(
        &mut self,
        device_cfg: &mut DeviceConfig,
    ) -> DeviceManagerResult<(PciBdf, String)> {
        let pci_segment_id = device_cfg.pci_segment;
        let pci_device_bdf = self.pci_segments[pci_segment_id as usize].next_device_bdf()?;

        let mut needs_dma_mapping = false;

        // Here we create a new VFIO container for two reasons. Either this is
        // the first VFIO device, meaning we need a new VFIO container, which
        // will be shared with other VFIO devices. Or the new VFIO device is
        // attached to a vIOMMU, meaning we must create a dedicated VFIO
        // container. In the vIOMMU use case, we can't let all devices under
        // the same VFIO container since we couldn't map/unmap memory for each
        // device. That's simply because the map/unmap operations happen at the
        // VFIO container level.
        let vfio_container = if device_cfg.iommu {
            let vfio_container = self.create_vfio_container()?;

            let vfio_mapping = Arc::new(VfioDmaMapping::new(
                Arc::clone(&vfio_container),
                Arc::new(self.memory_manager.lock().unwrap().guest_memory()),
            ));

            if let Some(iommu) = &self.iommu_device {
                iommu
                    .lock()
                    .unwrap()
                    .add_external_mapping(pci_device_bdf.into(), vfio_mapping);
            } else {
                return Err(DeviceManagerError::MissingVirtualIommu);
            }

            vfio_container
        } else if let Some(vfio_container) = &self.vfio_container {
            Arc::clone(vfio_container)
        } else {
            let vfio_container = self.create_vfio_container()?;
            needs_dma_mapping = true;
            self.vfio_container = Some(Arc::clone(&vfio_container));

            vfio_container
        };

        let vfio_device = VfioDevice::new(&device_cfg.path, Arc::clone(&vfio_container))
            .map_err(DeviceManagerError::VfioCreate)?;

        if needs_dma_mapping {
            // Register DMA mapping in IOMMU.
            // Do not register virtio-mem regions, as they are handled directly by
            // virtio-mem device itself.
            for (_, zone) in self.memory_manager.lock().unwrap().memory_zones().iter() {
                for region in zone.regions() {
                    vfio_container
                        .vfio_dma_map(
                            region.start_addr().raw_value(),
                            region.len() as u64,
                            region.as_ptr() as u64,
                        )
                        .map_err(DeviceManagerError::VfioDmaMap)?;
                }
            }

            let vfio_mapping = Arc::new(VfioDmaMapping::new(
                Arc::clone(&vfio_container),
                Arc::new(self.memory_manager.lock().unwrap().guest_memory()),
            ));

            for virtio_mem_device in self.virtio_mem_devices.iter() {
                virtio_mem_device
                    .lock()
                    .unwrap()
                    .add_dma_mapping_handler(
                        VirtioMemMappingSource::Container,
                        vfio_mapping.clone(),
                    )
                    .map_err(DeviceManagerError::AddDmaMappingHandlerVirtioMem)?;
            }
        }

        let legacy_interrupt_group =
            if let Some(legacy_interrupt_manager) = &self.legacy_interrupt_manager {
                Some(
                    legacy_interrupt_manager
                        .create_group(LegacyIrqGroupConfig {
                            irq: self.pci_segments[pci_segment_id as usize].pci_irq_slots
                                [pci_device_bdf.device() as usize]
                                as InterruptIndex,
                        })
                        .map_err(DeviceManagerError::CreateInterruptGroup)?,
                )
            } else {
                None
            };

        let vfio_pci_device = VfioPciDevice::new(
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

        let vfio_pci_device = Arc::new(Mutex::new(vfio_pci_device));

        self.add_pci_device(
            vfio_pci_device.clone(),
            vfio_pci_device.clone(),
            pci_segment_id,
            pci_device_bdf,
        )?;

        vfio_pci_device
            .lock()
            .unwrap()
            .map_mmio_regions(&self.address_manager.vm, || {
                self.memory_manager.lock().unwrap().allocate_memory_slot()
            })
            .map_err(DeviceManagerError::VfioMapRegion)?;

        let mut node = device_node!(vfio_name);

        for region in vfio_pci_device.lock().unwrap().mmio_regions() {
            node.resources.push(Resource::MmioAddressRange {
                base: region.start.0,
                size: region.length as u64,
            });
        }

        node.pci_bdf = Some(pci_device_bdf.into());
        node.pci_device_handle = Some(PciDeviceHandle::Vfio(vfio_pci_device));

        self.device_tree
            .lock()
            .unwrap()
            .insert(vfio_name.clone(), node);

        Ok((pci_device_bdf, vfio_name))
    }

    #[cfg(feature = "pci_support")]
    fn add_pci_device(
        &mut self,
        bus_device: Arc<Mutex<dyn BusDevice>>,
        pci_device: Arc<Mutex<dyn PciDevice>>,
        segment_id: u16,
        bdf: PciBdf,
    ) -> DeviceManagerResult<Vec<(GuestAddress, GuestUsize, PciBarRegionType)>> {
        let bars = pci_device
            .lock()
            .unwrap()
            .allocate_bars(
                &mut self.address_manager.allocator.lock().unwrap(),
                &mut self.pci_segments[segment_id as usize]
                    .allocator
                    .lock()
                    .unwrap(),
            )
            .map_err(DeviceManagerError::AllocateBars)?;

        let mut pci_bus = self.pci_segments[segment_id as usize]
            .pci_bus
            .lock()
            .unwrap();

        pci_bus
            .add_device(bdf.device() as u32, pci_device)
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

    #[cfg(feature = "pci_support")]
    fn add_vfio_devices(&mut self) -> DeviceManagerResult<Vec<PciBdf>> {
        let mut iommu_attached_device_ids = Vec::new();
        let mut devices = self.config.lock().unwrap().devices.clone();

        if let Some(device_list_cfg) = &mut devices {
            for device_cfg in device_list_cfg.iter_mut() {
                let (device_id, _) = self.add_passthrough_device(device_cfg)?;
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
    fn add_vfio_user_device(
        &mut self,
        device_cfg: &mut UserDeviceConfig,
    ) -> DeviceManagerResult<(PciBdf, String)> {
        let pci_segment_id = device_cfg.pci_segment;
        let pci_device_bdf = self.pci_segments[pci_segment_id as usize].next_device_bdf()?;

        let legacy_interrupt_group =
            if let Some(legacy_interrupt_manager) = &self.legacy_interrupt_manager {
                Some(
                    legacy_interrupt_manager
                        .create_group(LegacyIrqGroupConfig {
                            irq: self.pci_segments[pci_segment_id as usize].pci_irq_slots
                                [pci_device_bdf.device() as usize]
                                as InterruptIndex,
                        })
                        .map_err(DeviceManagerError::CreateInterruptGroup)?,
                )
            } else {
                None
            };

        let client = Arc::new(Mutex::new(
            vfio_user::Client::new(&device_cfg.socket)
                .map_err(DeviceManagerError::VfioUserCreateClient)?,
        ));

        let mut vfio_user_pci_device = VfioUserPciDevice::new(
            &self.address_manager.vm,
            client.clone(),
            &self.msi_interrupt_manager,
            legacy_interrupt_group,
        )
        .map_err(DeviceManagerError::VfioUserCreate)?;

        vfio_user_pci_device
            .map_mmio_regions(&self.address_manager.vm, || {
                self.memory_manager.lock().unwrap().allocate_memory_slot()
            })
            .map_err(DeviceManagerError::VfioUserMapRegion)?;

        let memory = self.memory_manager.lock().unwrap().guest_memory();
        let vfio_user_mapping = Arc::new(VfioUserDmaMapping::new(client, Arc::new(memory)));
        for virtio_mem_device in self.virtio_mem_devices.iter() {
            virtio_mem_device
                .lock()
                .unwrap()
                .add_dma_mapping_handler(
                    VirtioMemMappingSource::Device(pci_device_bdf.into()),
                    vfio_user_mapping.clone(),
                )
                .map_err(DeviceManagerError::AddDmaMappingHandlerVirtioMem)?;
        }

        for (_, zone) in self.memory_manager.lock().unwrap().memory_zones().iter() {
            for region in zone.regions() {
                vfio_user_pci_device
                    .dma_map(region)
                    .map_err(DeviceManagerError::VfioUserDmaMap)?;
            }
        }

        let vfio_user_pci_device = Arc::new(Mutex::new(vfio_user_pci_device));

        let vfio_user_name = if let Some(id) = &device_cfg.id {
            if self.device_tree.lock().unwrap().contains_key(id) {
                return Err(DeviceManagerError::DeviceIdAlreadyInUse);
            }

            id.clone()
        } else {
            let id = self.next_device_name(VFIO_USER_DEVICE_NAME_PREFIX)?;
            device_cfg.id = Some(id.clone());
            id
        };

        self.add_pci_device(
            vfio_user_pci_device.clone(),
            vfio_user_pci_device.clone(),
            pci_segment_id,
            pci_device_bdf,
        )?;

        let mut node = device_node!(vfio_user_name);

        node.pci_bdf = Some(pci_device_bdf.into());
        node.pci_device_handle = Some(PciDeviceHandle::VfioUser(vfio_user_pci_device));

        self.device_tree
            .lock()
            .unwrap()
            .insert(vfio_user_name.clone(), node);

        Ok((pci_device_bdf, vfio_user_name))
    }

    #[cfg(feature = "pci_support")]
    fn add_user_devices(&mut self) -> DeviceManagerResult<Vec<PciBdf>> {
        let mut user_devices = self.config.lock().unwrap().user_devices.clone();

        if let Some(device_list_cfg) = &mut user_devices {
            for device_cfg in device_list_cfg.iter_mut() {
                let (_device_id, _id) = self.add_vfio_user_device(device_cfg)?;
            }
        }

        // Update the list of devices
        self.config.lock().unwrap().user_devices = user_devices;

        Ok(vec![])
    }

    #[cfg(feature = "pci_support")]
    fn add_virtio_pci_device(
        &mut self,
        virtio_device: VirtioDeviceArc,
        iommu_mapping: &Option<Arc<IommuMapping>>,
        virtio_device_id: String,
        pci_segment_id: u16,
    ) -> DeviceManagerResult<PciBdf> {
        let id = format!("{}-{}", VIRTIO_PCI_DEVICE_NAME_PREFIX, virtio_device_id);

        // Add the new virtio-pci node to the device tree.
        let mut node = device_node!(id);
        node.children = vec![virtio_device_id.clone()];

        // Look for the id in the device tree. If it can be found, that means
        // the device is being restored, otherwise it's created from scratch.
        let (pci_segment_id, pci_device_bdf, config_bar_addr) = if let Some(node) =
            self.device_tree.lock().unwrap().get(&id)
        {
            info!("Restoring virtio-pci {} resources", id);
            let pci_device_bdf: PciBdf = node
                .pci_bdf
                .ok_or(DeviceManagerError::MissingDeviceNodePciBdf)?
                .into();
            let pci_segment_id = pci_device_bdf.segment();

            self.pci_segments[pci_segment_id as usize]
                .pci_bus
                .lock()
                .unwrap()
                .get_device_id(pci_device_bdf.device() as usize)
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

            (pci_segment_id, pci_device_bdf, config_bar_addr)
        } else {
            let pci_device_bdf = self.pci_segments[pci_segment_id as usize].next_device_bdf()?;

            (pci_segment_id, pci_device_bdf, None)
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

        // Create the AccessPlatform trait from the implementation IommuMapping.
        // This will provide address translation for any virtio device sitting
        // behind a vIOMMU.
        let access_platform: Option<Arc<dyn AccessPlatform>> = if let Some(mapping) = iommu_mapping
        {
            Some(Arc::new(AccessPlatformMapping::new(
                pci_device_bdf.into(),
                mapping.clone(),
            )))
        } else {
            None
        };

        let memory = self.memory_manager.lock().unwrap().guest_memory();
        let device_type = virtio_device.lock().unwrap().device_type();
        let mut virtio_pci_device = VirtioPciDevice::new(
            id.clone(),
            memory,
            virtio_device,
            msix_num,
            access_platform,
            &self.msi_interrupt_manager,
            pci_device_bdf.into(),
            self.activate_evt
                .try_clone()
                .map_err(DeviceManagerError::EventFd)?,
            // All device types *except* virtio block devices should be allocated a 64-bit bar
            // The block devices should be given a 32-bit BAR so that they are easily accessible
            // to firmware without requiring excessive identity mapping.
            // The exception being if not on the default PCI segment.
            pci_segment_id > 0 || device_type != VirtioDeviceType::Block as u32,
        )
        .map_err(DeviceManagerError::VirtioDevice)?;

        // This is important as this will set the BAR address if it exists,
        // which is mandatory on the restore path.
        if let Some(addr) = config_bar_addr {
            virtio_pci_device.set_config_bar_addr(addr);
        }

        let virtio_pci_device = Arc::new(Mutex::new(virtio_pci_device));
        let bars = self.add_pci_device(
            virtio_pci_device.clone(),
            virtio_pci_device.clone(),
            pci_segment_id,
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
        node.pci_bdf = Some(pci_device_bdf.into());
        node.pci_device_handle = Some(PciDeviceHandle::Virtio(virtio_pci_device));
        self.device_tree.lock().unwrap().insert(id, node);

        Ok(pci_device_bdf)
    }

    #[cfg(feature = "mmio_support")]
    fn add_virtio_mmio_device(
        &mut self,
        virtio_device_id: String,
        virtio_device: VirtioDeviceArc,
        interrupt_manager: &Arc<dyn InterruptManager<GroupConfig = LegacyIrqGroupConfig>>,
    ) -> DeviceManagerResult<()> {
        let id = format!("{}-{}", VIRTIO_MMIO_DEVICE_NAME_PREFIX, virtio_device_id);

        // Create the new virtio-mmio node that will be added later to the
        // device tree.
        let mut node = device_node!(id);
        node.children = vec![virtio_device_id.clone()];

        // Look for the id in the device tree. If it can be found, that means
        // the device is being restored, otherwise it's created from scratch.
        let (mmio_range, mmio_irq) = if let Some(node) = self.device_tree.lock().unwrap().get(&id) {
            debug!("Restoring virtio-mmio {} resources", id);

            let mut mmio_range: Option<(u64, u64)> = None;
            let mut mmio_irq: Option<u32> = None;
            for resource in node.resources.iter() {
                match resource {
                    Resource::MmioAddressRange { base, size } => {
                        if mmio_range.is_some() {
                            return Err(DeviceManagerError::ResourceAlreadyExists);
                        }

                        mmio_range = Some((*base, *size));
                    }
                    Resource::LegacyIrq(irq) => {
                        if mmio_irq.is_some() {
                            return Err(DeviceManagerError::ResourceAlreadyExists);
                        }

                        mmio_irq = Some(*irq);
                    }
                    _ => {
                        error!("Unexpected resource {:?} for {}", resource, id);
                    }
                }
            }

            if mmio_range.is_none() || mmio_irq.is_none() {
                return Err(DeviceManagerError::MissingVirtioMmioResources);
            }

            (mmio_range, mmio_irq)
        } else {
            (None, None)
        };

        // Update the existing virtio node by setting the parent.
        if let Some(node) = self.device_tree.lock().unwrap().get_mut(&virtio_device_id) {
            node.parent = Some(id.clone());
        } else {
            return Err(DeviceManagerError::MissingNode);
        }

        let (mmio_base, mmio_size) = if let Some((base, size)) = mmio_range {
            self.address_manager
                .allocator
                .lock()
                .unwrap()
                .allocate_platform_mmio_addresses(Some(GuestAddress(base)), size, Some(size))
                .ok_or(DeviceManagerError::MmioRangeAllocation)?;

            (base, size)
        } else {
            let size = MMIO_LEN;
            let base = self
                .address_manager
                .allocator
                .lock()
                .unwrap()
                .allocate_platform_mmio_addresses(None, size, Some(size))
                .ok_or(DeviceManagerError::MmioRangeAllocation)?;

            (base.raw_value(), size)
        };

        let irq_num = if let Some(irq) = mmio_irq {
            irq
        } else {
            self.address_manager
                .allocator
                .lock()
                .unwrap()
                .allocate_irq()
                .ok_or(DeviceManagerError::AllocateIrq)?
        };

        #[cfg(target_arch = "aarch64")]
        {
            let device_type = virtio_device.lock().unwrap().device_type();
            self.id_to_dev_info.insert(
                (DeviceType::Virtio(device_type), virtio_device_id),
                MmioDeviceInfo {
                    addr: mmio_base,
                    len: mmio_size,
                    irq: irq_num,
                },
            );
        }

        let memory = self.memory_manager.lock().unwrap().guest_memory();
        let interrupt_group = interrupt_manager
            .create_group(LegacyIrqGroupConfig {
                irq: irq_num as InterruptIndex,
            })
            .map_err(DeviceManagerError::CreateInterruptGroup)?;

        let mmio_device = virtio_devices::transport::VirtioMmioDevice::new(
            id.clone(),
            memory,
            virtio_device,
            None,
            interrupt_group,
            self.activate_evt
                .try_clone()
                .map_err(DeviceManagerError::EventFd)?,
        )
        .map_err(DeviceManagerError::VirtioDevice)?;

        for (i, (event, addr)) in mmio_device.ioeventfds(mmio_base).iter().enumerate() {
            let io_addr = IoEventAddress::Mmio(*addr);
            self.address_manager
                .vm
                .register_ioevent(
                    event,
                    &io_addr,
                    Some(hypervisor::vm::DataMatch::DataMatch32(i as u32)),
                )
                .map_err(|e| DeviceManagerError::RegisterIoevent(e.into()))?;
        }

        let mmio_device_arc = Arc::new(Mutex::new(mmio_device));
        self.bus_devices
            .push(Arc::clone(&mmio_device_arc) as Arc<Mutex<dyn BusDevice>>);
        self.address_manager
            .mmio_bus
            .insert(mmio_device_arc.clone(), mmio_base, MMIO_LEN)
            .map_err(DeviceManagerError::BusError)?;

        #[cfg(target_arch = "x86_64")]
        self.cmdline_additions.push(format!(
            "virtio_mmio.device={}K@0x{:08x}:{}",
            mmio_size / 1024,
            mmio_base,
            irq_num
        ));

        // Update the device tree with correct resource information.
        node.resources.push(Resource::MmioAddressRange {
            base: mmio_base,
            size: mmio_size,
        });
        node.resources.push(Resource::LegacyIrq(irq_num));
        node.migratable = Some(Arc::clone(&mmio_device_arc) as Arc<Mutex<dyn Migratable>>);
        self.device_tree.lock().unwrap().insert(id, node);

        Ok(())
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

    #[cfg(all(target_arch = "x86_64", feature = "pci_support"))]
    // Used to provide a fast path for handling PIO exits
    pub fn pci_config_io(&self) -> Arc<Mutex<PciConfigIo>> {
        Arc::clone(self.pci_segments[0].pci_config_io.as_ref().unwrap())
    }

    #[cfg(all(feature = "acpi", feature = "pci_support"))]
    pub(crate) fn pci_segments(&self) -> &Vec<PciSegment> {
        &self.pci_segments
    }

    pub fn console(&self) -> &Arc<Console> {
        &self.console
    }

    pub fn cmdline_additions(&self) -> &[String] {
        self.cmdline_additions.as_slice()
    }

    pub fn update_memory(&self, new_region: &Arc<GuestRegionMmap>) -> DeviceManagerResult<()> {
        for (virtio_device, _, _, _) in self.virtio_devices.iter() {
            virtio_device
                .lock()
                .unwrap()
                .add_memory_region(new_region)
                .map_err(DeviceManagerError::UpdateMemoryForVirtioDevice)?;
        }

        // Take care of updating the memory for VFIO PCI devices.
        #[cfg(feature = "pci_support")]
        {
            if let Some(vfio_container) = &self.vfio_container {
                vfio_container
                    .vfio_dma_map(
                        new_region.start_addr().raw_value(),
                        new_region.len() as u64,
                        new_region.as_ptr() as u64,
                    )
                    .map_err(DeviceManagerError::UpdateMemoryForVfioPciDevice)?;
            }
        }

        #[allow(clippy::single_match)]
        // Take care of updating the memory for vfio-user devices.
        #[cfg(feature = "pci_support")]
        {
            let device_tree = self.device_tree.lock().unwrap();
            for pci_device_node in device_tree.pci_devices() {
                match pci_device_node
                    .pci_device_handle
                    .as_ref()
                    .ok_or(DeviceManagerError::MissingPciDevice)?
                {
                    PciDeviceHandle::VfioUser(vfio_user_pci_device) => {
                        vfio_user_pci_device
                            .lock()
                            .unwrap()
                            .dma_map(new_region)
                            .map_err(DeviceManagerError::UpdateMemoryForVfioUserPciDevice)?;
                    }
                    _ => {}
                }
            }
        }

        Ok(())
    }

    pub fn activate_virtio_devices(&self) -> DeviceManagerResult<()> {
        #[cfg(feature = "pci_support")]
        {
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

    #[cfg(feature = "pci_support")]
    pub fn add_device(
        &mut self,
        device_cfg: &mut DeviceConfig,
    ) -> DeviceManagerResult<PciDeviceInfo> {
        let (bdf, device_name) = self.add_passthrough_device(device_cfg)?;

        // Update the PCIU bitmap
        self.pci_segments[device_cfg.pci_segment as usize].pci_devices_up |= 1 << bdf.device();

        Ok(PciDeviceInfo {
            id: device_name,
            bdf,
        })
    }

    #[cfg(feature = "pci_support")]
    pub fn add_user_device(
        &mut self,
        device_cfg: &mut UserDeviceConfig,
    ) -> DeviceManagerResult<PciDeviceInfo> {
        let (bdf, device_name) = self.add_vfio_user_device(device_cfg)?;

        // Update the PCIU bitmap
        self.pci_segments[device_cfg.pci_segment as usize].pci_devices_up |= 1 << bdf.device();

        Ok(PciDeviceInfo {
            id: device_name,
            bdf,
        })
    }

    #[cfg(feature = "pci_support")]
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

        let pci_device_bdf: PciBdf = pci_device_node
            .pci_bdf
            .ok_or(DeviceManagerError::MissingDeviceNodePciBdf)?
            .into();
        let pci_segment_id = pci_device_bdf.segment();

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
        self.pci_segments[pci_segment_id as usize].pci_devices_down |= 1 << pci_device_bdf.device();

        Ok(())
    }

    #[cfg(feature = "pci_support")]
    pub fn eject_device(&mut self, pci_segment_id: u16, device_id: u8) -> DeviceManagerResult<()> {
        info!(
            "Ejecting device_id = {} on segment_id={}",
            device_id, pci_segment_id
        );

        // Convert the device ID into the corresponding b/d/f.
        let pci_device_bdf = PciBdf::new(pci_segment_id, 0, device_id, 0);

        // Give the PCI device ID back to the PCI bus.
        self.pci_segments[pci_segment_id as usize]
            .pci_bus
            .lock()
            .unwrap()
            .put_device_id(device_id as usize)
            .map_err(DeviceManagerError::PutPciDeviceId)?;

        // Remove the device from the device tree along with its children.
        let mut device_tree = self.device_tree.lock().unwrap();
        let pci_device_node = device_tree
            .remove_node_by_pci_bdf(pci_device_bdf.into())
            .ok_or(DeviceManagerError::MissingPciDevice)?;
        for child in pci_device_node.children.iter() {
            device_tree.remove(child);
        }

        let pci_device_handle = pci_device_node
            .pci_device_handle
            .ok_or(DeviceManagerError::MissingPciDevice)?;
        let (pci_device, bus_device, virtio_device) = match pci_device_handle {
            // No need to remove any virtio-mem mapping here as the container outlives all devices
            PciDeviceHandle::Vfio(vfio_pci_device) => (
                Arc::clone(&vfio_pci_device) as Arc<Mutex<dyn PciDevice>>,
                Arc::clone(&vfio_pci_device) as Arc<Mutex<dyn BusDevice>>,
                None as Option<VirtioDeviceArc>,
            ),
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
            PciDeviceHandle::VfioUser(vfio_user_pci_device) => {
                let mut dev = vfio_user_pci_device.lock().unwrap();
                for (_, zone) in self.memory_manager.lock().unwrap().memory_zones().iter() {
                    for region in zone.regions() {
                        dev.dma_unmap(region)
                            .map_err(DeviceManagerError::VfioUserDmaUnmap)?;
                    }
                }

                for virtio_mem_device in self.virtio_mem_devices.iter() {
                    virtio_mem_device
                        .lock()
                        .unwrap()
                        .remove_dma_mapping_handler(VirtioMemMappingSource::Device(
                            pci_device_bdf.into(),
                        ))
                        .map_err(DeviceManagerError::RemoveDmaMappingHandlerVirtioMem)?;
                }

                (
                    Arc::clone(&vfio_user_pci_device) as Arc<Mutex<dyn PciDevice>>,
                    Arc::clone(&vfio_user_pci_device) as Arc<Mutex<dyn BusDevice>>,
                    None as Option<VirtioDeviceArc>,
                )
            }
        };

        // Free the allocated BARs
        pci_device
            .lock()
            .unwrap()
            .free_bars(
                &mut self.address_manager.allocator.lock().unwrap(),
                &mut self.pci_segments[pci_segment_id as usize]
                    .allocator
                    .lock()
                    .unwrap(),
            )
            .map_err(DeviceManagerError::FreePciBars)?;

        // Remove the device from the PCI bus
        self.pci_segments[pci_segment_id as usize]
            .pci_bus
            .lock()
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
                .retain(|(d, _, _, _)| !Arc::ptr_eq(d, &virtio_device));
        }

        // At this point, the device has been removed from all the list and
        // buses where it was stored. At the end of this function, after
        // any_device, bus_device and pci_device are released, the actual
        // device will be dropped.
        Ok(())
    }

    #[cfg(feature = "pci_support")]
    fn hotplug_virtio_pci_device(
        &mut self,
        device: VirtioDeviceArc,
        iommu_attached: bool,
        id: String,
        pci_segment_id: u16,
    ) -> DeviceManagerResult<PciDeviceInfo> {
        if iommu_attached {
            warn!("Placing device behind vIOMMU is not available for hotplugged devices");
        }

        // Add the virtio device to the device manager list. This is important
        // as the list is used to notify virtio devices about memory updates
        // for instance.
        self.virtio_devices
            .push((device.clone(), iommu_attached, id.clone(), pci_segment_id));

        let bdf = self.add_virtio_pci_device(device, &None, id.clone(), pci_segment_id)?;

        // Update the PCIU bitmap
        self.pci_segments[pci_segment_id as usize].pci_devices_up |= 1 << bdf.device();

        Ok(PciDeviceInfo { id, bdf })
    }

    #[cfg(feature = "pci_support")]
    pub fn add_disk(&mut self, disk_cfg: &mut DiskConfig) -> DeviceManagerResult<PciDeviceInfo> {
        let (device, iommu_attached, id, pci_segment_id) =
            self.make_virtio_block_device(disk_cfg)?;
        self.hotplug_virtio_pci_device(device, iommu_attached, id, pci_segment_id)
    }

    #[cfg(feature = "pci_support")]
    pub fn add_fs(&mut self, fs_cfg: &mut FsConfig) -> DeviceManagerResult<PciDeviceInfo> {
        let (device, iommu_attached, id, pci_segment_id) = self.make_virtio_fs_device(fs_cfg)?;
        self.hotplug_virtio_pci_device(device, iommu_attached, id, pci_segment_id)
    }

    #[cfg(feature = "pci_support")]
    pub fn add_pmem(&mut self, pmem_cfg: &mut PmemConfig) -> DeviceManagerResult<PciDeviceInfo> {
        let (device, iommu_attached, id, pci_segment_id) =
            self.make_virtio_pmem_device(pmem_cfg)?;
        self.hotplug_virtio_pci_device(device, iommu_attached, id, pci_segment_id)
    }

    #[cfg(feature = "pci_support")]
    pub fn add_net(&mut self, net_cfg: &mut NetConfig) -> DeviceManagerResult<PciDeviceInfo> {
        let (device, iommu_attached, id, pci_segment_id) = self.make_virtio_net_device(net_cfg)?;
        self.hotplug_virtio_pci_device(device, iommu_attached, id, pci_segment_id)
    }

    #[cfg(feature = "pci_support")]
    pub fn add_vsock(&mut self, vsock_cfg: &mut VsockConfig) -> DeviceManagerResult<PciDeviceInfo> {
        let (device, iommu_attached, id, pci_segment_id) =
            self.make_virtio_vsock_device(vsock_cfg)?;
        self.hotplug_virtio_pci_device(device, iommu_attached, id, pci_segment_id)
    }

    pub fn counters(&self) -> HashMap<String, HashMap<&'static str, Wrapping<u64>>> {
        let mut counters = HashMap::new();

        for (virtio_device, _, id, _) in &self.virtio_devices {
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

    pub fn restore_devices(
        &mut self,
        snapshot: Snapshot,
    ) -> std::result::Result<(), MigratableError> {
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
                info!("Restoring {} from DeviceManager", node.id);
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

        // The devices have been fully restored, we can now update the
        // restoring state of the DeviceManager.
        self.restoring = false;

        Ok(())
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
        // There are three use cases:
        // 1. The Cloud Hypervisor is built without feature acpi.
        // 2. The Cloud Hypervisor is built with feature acpi, but users will
        // use direct kernel boot with device tree.
        // 3. The Cloud Hypervisor is built with feature acpi, and users will
        // use ACPI+UEFI boot.
        #[cfg(not(feature = "acpi"))]
        // The `return` here will trigger a GPIO pin 3 event, which will trigger
        // a power button event for use case 1.
        return self
            .gpio_device
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .trigger_key(3)
            .map_err(DeviceManagerError::AArch64PowerButtonNotification);
        #[cfg(feature = "acpi")]
        {
            // Trigger a GPIO pin 3 event to satisify use case 2.
            self.gpio_device
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .trigger_key(3)
                .map_err(DeviceManagerError::AArch64PowerButtonNotification)?;
            // Trigger a GED power button event to satisify use case 3.
            return self
                .ged_notification_device
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .notify(AcpiNotificationFlags::POWER_BUTTON_CHANGED)
                .map_err(DeviceManagerError::PowerButtonNotification);
        }
    }

    #[cfg(not(feature = "pci_support"))]
    pub fn iommu_attached_devices(&self) -> &Option<(PciBdf, Vec<PciBdf>)> {
        &None
    }

    #[cfg(feature = "pci_support")]
    pub fn iommu_attached_devices(&self) -> &Option<(PciBdf, Vec<PciBdf>)> {
        &self.iommu_attached_devices
    }
}

#[cfg(any(target_arch = "aarch64", feature = "acpi"))]
fn numa_node_id_from_memory_zone_id(numa_nodes: &NumaNodes, memory_zone_id: &str) -> Option<u32> {
    for (numa_node_id, numa_node) in numa_nodes.iter() {
        if numa_node.memory_zones.contains(&memory_zone_id.to_owned()) {
            return Some(*numa_node_id);
        }
    }

    None
}

#[cfg(feature = "acpi")]
impl Aml for DeviceManager {
    fn append_aml_bytes(&self, bytes: &mut Vec<u8>) {
        #[cfg(target_arch = "aarch64")]
        use arch::aarch64::DeviceInfoForFdt;

        let mut pci_scan_methods = Vec::new();
        for i in 0..self.pci_segments.len() {
            pci_scan_methods.push(aml::MethodCall::new(
                format!("\\_SB_.PCI{:X}.PCNT", i).as_str().into(),
                vec![],
            ));
        }
        let mut pci_scan_inner: Vec<&dyn Aml> = Vec::new();
        for method in &pci_scan_methods {
            pci_scan_inner.push(method)
        }

        // PCI hotplug controller
        aml::Device::new(
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
                        aml::FieldEntry::Named(*b"PSEG", 32),
                    ],
                ),
                &aml::Method::new(
                    "PCEJ".into(),
                    2,
                    true,
                    vec![
                        // Take lock defined above
                        &aml::Acquire::new("BLCK".into(), 0xffff),
                        // Choose the current segment
                        &aml::Store::new(&aml::Path::new("PSEG"), &aml::Arg(1)),
                        // Write PCI bus number (in first argument) to I/O port via field
                        &aml::ShiftLeft::new(&aml::Path::new("B0EJ"), &aml::ONE, &aml::Arg(0)),
                        // Release lock
                        &aml::Release::new("BLCK".into()),
                        // Return 0
                        &aml::Return::new(&aml::ZERO),
                    ],
                ),
                &aml::Method::new("PSCN".into(), 0, true, pci_scan_inner),
            ],
        )
        .append_aml_bytes(bytes);

        for segment in &self.pci_segments {
            segment.append_aml_bytes(bytes);
        }

        let mut mbrd_memory = Vec::new();

        for segment in &self.pci_segments {
            mbrd_memory.push(aml::Memory32Fixed::new(
                true,
                segment.mmio_config_address as u32,
                layout::PCI_MMIO_CONFIG_SIZE_PER_SEGMENT as u32,
            ))
        }

        let mut mbrd_memory_refs = Vec::new();
        for mbrd_memory_ref in &mbrd_memory {
            mbrd_memory_refs.push(mbrd_memory_ref as &dyn Aml);
        }

        aml::Device::new(
            "_SB_.MBRD".into(),
            vec![
                &aml::Name::new("_HID".into(), &aml::EisaName::new("PNP0C02")),
                &aml::Name::new("_UID".into(), &aml::ZERO),
                &aml::Name::new("_CRS".into(), &aml::ResourceTemplate::new(mbrd_memory_refs)),
            ],
        )
        .append_aml_bytes(bytes);

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
        if self.config.lock().unwrap().serial.mode != ConsoleOutputMode::Off {
            aml::Device::new(
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
            .append_aml_bytes(bytes);
        }

        aml::Name::new("_S5_".into(), &aml::Package::new(vec![&5u8])).append_aml_bytes(bytes);

        aml::Device::new(
            "_SB_.PWRB".into(),
            vec![
                &aml::Name::new("_HID".into(), &aml::EisaName::new("PNP0C0C")),
                &aml::Name::new("_UID".into(), &aml::ZERO),
            ],
        )
        .append_aml_bytes(bytes);

        self.ged_notification_device
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .append_aml_bytes(bytes);
    }
}

impl Pausable for DeviceManager {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        for (_, device_node) in self.device_tree.lock().unwrap().iter() {
            if let Some(migratable) = &device_node.migratable {
                migratable.lock().unwrap().pause()?;
            }
        }
        // On AArch64, the pause of device manager needs to trigger
        // a "pause" of GIC, which will flush the GIC pending tables
        // and ITS tables to guest RAM.
        #[cfg(target_arch = "aarch64")]
        {
            let gic_device = Arc::clone(
                self.get_interrupt_controller()
                    .unwrap()
                    .lock()
                    .unwrap()
                    .get_gic_device()
                    .unwrap(),
            );
            if let Some(gicv3_its) = gic_device
                .lock()
                .unwrap()
                .as_any_concrete_mut()
                .downcast_mut::<KvmGicV3Its>()
            {
                gicv3_its.pause()?;
            } else {
                return Err(MigratableError::Pause(anyhow!(
                    "GicDevice downcast to KvmGicV3Its failed when pausing device manager!"
                )));
            };
        };

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
        self.create_devices(None, None, None)
            .map_err(|e| MigratableError::Restore(anyhow!("Could not create devices {:?}", e)))?;

        Ok(())
    }
}

impl Transportable for DeviceManager {}

impl Migratable for DeviceManager {
    fn start_dirty_log(&mut self) -> std::result::Result<(), MigratableError> {
        for (_, device_node) in self.device_tree.lock().unwrap().iter() {
            if let Some(migratable) = &device_node.migratable {
                migratable.lock().unwrap().start_dirty_log()?;
            }
        }
        Ok(())
    }

    fn stop_dirty_log(&mut self) -> std::result::Result<(), MigratableError> {
        for (_, device_node) in self.device_tree.lock().unwrap().iter() {
            if let Some(migratable) = &device_node.migratable {
                migratable.lock().unwrap().stop_dirty_log()?;
            }
        }
        Ok(())
    }

    fn dirty_log(&mut self) -> std::result::Result<MemoryRangeTable, MigratableError> {
        let mut tables = Vec::new();
        for (_, device_node) in self.device_tree.lock().unwrap().iter() {
            if let Some(migratable) = &device_node.migratable {
                tables.push(migratable.lock().unwrap().dirty_log()?);
            }
        }
        Ok(MemoryRangeTable::new_from_tables(tables))
    }

    fn complete_migration(&mut self) -> std::result::Result<(), MigratableError> {
        for (_, device_node) in self.device_tree.lock().unwrap().iter() {
            if let Some(migratable) = &device_node.migratable {
                migratable.lock().unwrap().complete_migration()?;
            }
        }
        Ok(())
    }
}

#[cfg(feature = "acpi")]
const PCIU_FIELD_OFFSET: u64 = 0;
#[cfg(feature = "acpi")]
const PCID_FIELD_OFFSET: u64 = 4;
#[cfg(feature = "acpi")]
const B0EJ_FIELD_OFFSET: u64 = 8;
#[cfg(feature = "acpi")]
const PSEG_FIELD_OFFSET: u64 = 12;
#[cfg(feature = "acpi")]
const PCIU_FIELD_SIZE: usize = 4;
#[cfg(feature = "acpi")]
const PCID_FIELD_SIZE: usize = 4;
#[cfg(feature = "acpi")]
const B0EJ_FIELD_SIZE: usize = 4;
#[cfg(feature = "acpi")]
const PSEG_FIELD_SIZE: usize = 4;

#[cfg(feature = "acpi")]
impl BusDevice for DeviceManager {
    fn read(&mut self, base: u64, offset: u64, data: &mut [u8]) {
        match offset {
            PCIU_FIELD_OFFSET => {
                assert!(data.len() == PCIU_FIELD_SIZE);
                data.copy_from_slice(
                    &self.pci_segments[self.selected_segment]
                        .pci_devices_up
                        .to_le_bytes(),
                );
                // Clear the PCIU bitmap
                self.pci_segments[self.selected_segment].pci_devices_up = 0;
            }
            PCID_FIELD_OFFSET => {
                assert!(data.len() == PCID_FIELD_SIZE);
                data.copy_from_slice(
                    &self.pci_segments[self.selected_segment]
                        .pci_devices_down
                        .to_le_bytes(),
                );
                // Clear the PCID bitmap
                self.pci_segments[self.selected_segment].pci_devices_down = 0;
            }
            B0EJ_FIELD_OFFSET => {
                assert!(data.len() == B0EJ_FIELD_SIZE);
                // Always return an empty bitmap since the eject is always
                // taken care of right away during a write access.
                data.fill(0);
            }
            PSEG_FIELD_OFFSET => {
                assert_eq!(data.len(), PSEG_FIELD_SIZE);
                data.copy_from_slice(&(self.selected_segment as u32).to_le_bytes());
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

    fn write(&mut self, base: u64, offset: u64, data: &[u8]) -> Option<Arc<std::sync::Barrier>> {
        match offset {
            B0EJ_FIELD_OFFSET => {
                assert!(data.len() == B0EJ_FIELD_SIZE);
                let mut data_array: [u8; 4] = [0, 0, 0, 0];
                data_array.copy_from_slice(data);
                let mut slot_bitmap = u32::from_le_bytes(data_array);

                while slot_bitmap > 0 {
                    let slot_id = slot_bitmap.trailing_zeros();
                    if let Err(e) = self.eject_device(self.selected_segment as u16, slot_id as u8) {
                        error!("Failed ejecting device {}: {:?}", slot_id, e);
                    }
                    slot_bitmap &= !(1 << slot_id);
                }
            }
            PSEG_FIELD_OFFSET => {
                assert_eq!(data.len(), PSEG_FIELD_SIZE);
                let mut data_array: [u8; 4] = [0, 0, 0, 0];
                data_array.copy_from_slice(data);
                let selected_segment = u32::from_le_bytes(data_array) as usize;
                if selected_segment >= self.pci_segments.len() {
                    error!(
                        "Segment selection out of range: {} >= {}",
                        selected_segment,
                        self.pci_segments.len()
                    );
                    return None;
                }
                self.selected_segment = selected_segment;
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
        for (device, _, _, _) in self.virtio_devices.drain(..) {
            device.lock().unwrap().shutdown();
        }
    }
}
