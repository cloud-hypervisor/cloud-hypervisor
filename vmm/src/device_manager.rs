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

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{File, OpenOptions};
use std::io::{self, IsTerminal, Seek, SeekFrom, stdout};
use std::num::Wrapping;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::PathBuf;
use std::result;
use std::sync::{Arc, Mutex};
#[cfg(not(target_arch = "riscv64"))]
use std::time::Instant;

use acpi_tables::sdt::GenericAddress;
use acpi_tables::{Aml, aml};
#[cfg(not(target_arch = "riscv64"))]
use anyhow::anyhow;
#[cfg(target_arch = "x86_64")]
use arch::layout::{APIC_START, IOAPIC_SIZE, IOAPIC_START};
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
use arch::{DeviceType, MmioDeviceInfo};
use arch::{NumaNodes, layout};
use block::async_io::DiskFile;
use block::fixed_vhd_sync::FixedVhdDiskSync;
use block::qcow_sync::QcowDiskSync;
use block::raw_async_aio::RawFileDiskAio;
use block::raw_sync::RawFileDiskSync;
use block::vhdx_sync::VhdxDiskSync;
use block::{
    ImageType, block_aio_is_supported, block_io_uring_is_supported, detect_image_type, qcow, vhdx,
};
#[cfg(feature = "io_uring")]
use block::{fixed_vhd_async::FixedVhdDiskAsync, raw_async::RawFileDisk};
#[cfg(target_arch = "riscv64")]
use devices::aia;
#[cfg(target_arch = "x86_64")]
use devices::debug_console;
#[cfg(target_arch = "x86_64")]
use devices::debug_console::DebugConsole;
#[cfg(target_arch = "aarch64")]
use devices::gic;
use devices::interrupt_controller::InterruptController;
#[cfg(target_arch = "x86_64")]
use devices::ioapic;
#[cfg(feature = "ivshmem")]
use devices::ivshmem::{IvshmemError, IvshmemOps};
#[cfg(target_arch = "aarch64")]
use devices::legacy::Pl011;
#[cfg(any(target_arch = "x86_64", target_arch = "riscv64"))]
use devices::legacy::Serial;
#[cfg(all(feature = "fw_cfg", target_arch = "x86_64"))]
use devices::legacy::fw_cfg::FW_CFG_ACPI_ID;
#[cfg(feature = "fw_cfg")]
use devices::legacy::{
    FwCfg,
    fw_cfg::{PORT_FW_CFG_BASE, PORT_FW_CFG_WIDTH},
};
#[cfg(feature = "pvmemcontrol")]
use devices::pvmemcontrol::{PvmemcontrolBusDevice, PvmemcontrolPciDevice};
use devices::{AcpiNotificationFlags, interrupt_controller};
use event_monitor::event;
use hypervisor::IoEventAddress;
#[cfg(target_arch = "aarch64")]
use hypervisor::arch::aarch64::regs::AARCH64_PMU_IRQ;
use libc::{
    MAP_NORESERVE, MAP_PRIVATE, MAP_SHARED, O_TMPFILE, PROT_READ, PROT_WRITE, TCSANOW, tcsetattr,
    termios,
};
use log::{debug, error, info, warn};
use pci::{
    DeviceRelocation, MmioRegion, PciBarRegionType, PciBdf, PciDevice, VfioDmaMapping,
    VfioPciDevice, VfioUserDmaMapping, VfioUserPciDevice, VfioUserPciDeviceError,
};
use rate_limiter::group::RateLimiterGroup;
use seccompiler::SeccompAction;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracer::trace_scoped;
use vfio_ioctls::{VfioContainer, VfioDevice, VfioDeviceFd};
use virtio_devices::transport::{VirtioPciDevice, VirtioPciDeviceActivator, VirtioTransport};
use virtio_devices::vhost_user::VhostUserConfig;
use virtio_devices::{
    AccessPlatformMapping, ActivateError, Block, Endpoint, IommuMapping, VdpaDmaMapping,
    VirtioMemMappingSource,
};
use vm_allocator::{AddressAllocator, SystemAllocator};
use vm_device::dma_mapping::ExternalDmaMapping;
use vm_device::interrupt::{
    InterruptIndex, InterruptManager, LegacyIrqGroupConfig, MsiIrqGroupConfig,
};
use vm_device::{Bus, BusDevice, BusDeviceSync, Resource, UserspaceMapping};
#[cfg(feature = "ivshmem")]
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::guest_memory::FileOffset;
use vm_memory::{Address, GuestAddress, GuestMemoryRegion, GuestUsize, MmapRegion, VolatileMemory};
#[cfg(target_arch = "x86_64")]
use vm_memory::{GuestAddressSpace, GuestMemory};
use vm_migration::protocol::MemoryRangeTable;
use vm_migration::{
    Migratable, MigratableError, Pausable, Snapshot, SnapshotData, Snapshottable, Transportable,
    snapshot_from_id, state_from_id,
};
use vm_virtio::{AccessPlatform, VirtioDeviceType};
use vmm_sys_util::eventfd::EventFd;

use crate::console_devices::{ConsoleDeviceError, ConsoleInfo, ConsoleOutput};
use crate::cpu::{CPU_MANAGER_ACPI_SIZE, CpuManager};
use crate::device_tree::{DeviceNode, DeviceTree};
use crate::interrupt::{LegacyUserspaceInterruptManager, MsiInterruptManager};
use crate::memory_manager::{Error as MemoryManagerError, MEMORY_MANAGER_ACPI_SIZE, MemoryManager};
use crate::pci_segment::PciSegment;
use crate::serial_manager::{Error as SerialManagerError, SerialManager};
#[cfg(feature = "ivshmem")]
use crate::vm_config::IvshmemConfig;
use crate::vm_config::{
    ConsoleOutputMode, DEFAULT_IOMMU_ADDRESS_WIDTH_BITS, DEFAULT_PCI_SEGMENT_APERTURE_WEIGHT,
    DeviceConfig, DiskConfig, FsConfig, NetConfig, PmemConfig, UserDeviceConfig, VdpaConfig,
    VhostMode, VmConfig, VsockConfig,
};
use crate::{DEVICE_MANAGER_SNAPSHOT_ID, GuestRegionMmap, PciDeviceInfo, device_node};

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const MMIO_LEN: u64 = 0x1000;

// Singleton devices / devices the user cannot name
#[cfg(target_arch = "x86_64")]
const IOAPIC_DEVICE_NAME: &str = "__ioapic";
const SERIAL_DEVICE_NAME: &str = "__serial";
#[cfg(target_arch = "x86_64")]
const DEBUGCON_DEVICE_NAME: &str = "__debug_console";
#[cfg(target_arch = "aarch64")]
const GPIO_DEVICE_NAME: &str = "__gpio";
const RNG_DEVICE_NAME: &str = "__rng";
const IOMMU_DEVICE_NAME: &str = "__iommu";
#[cfg(feature = "pvmemcontrol")]
const PVMEMCONTROL_DEVICE_NAME: &str = "__pvmemcontrol";
const BALLOON_DEVICE_NAME: &str = "__balloon";
const CONSOLE_DEVICE_NAME: &str = "__console";
const PVPANIC_DEVICE_NAME: &str = "__pvpanic";
#[cfg(feature = "ivshmem")]
const IVSHMEM_DEVICE_NAME: &str = "__ivshmem";

// Devices that the user may name and for which we generate
// identifiers if the user doesn't give one
const DISK_DEVICE_NAME_PREFIX: &str = "_disk";
const FS_DEVICE_NAME_PREFIX: &str = "_fs";
const NET_DEVICE_NAME_PREFIX: &str = "_net";
const PMEM_DEVICE_NAME_PREFIX: &str = "_pmem";
const VDPA_DEVICE_NAME_PREFIX: &str = "_vdpa";
const VSOCK_DEVICE_NAME_PREFIX: &str = "_vsock";
const WATCHDOG_DEVICE_NAME: &str = "__watchdog";
const VFIO_DEVICE_NAME_PREFIX: &str = "_vfio";
const VFIO_USER_DEVICE_NAME_PREFIX: &str = "_vfio_user";
const VIRTIO_PCI_DEVICE_NAME_PREFIX: &str = "_virtio-pci";

/// Errors associated with device manager
#[derive(Error, Debug)]
pub enum DeviceManagerError {
    /// Cannot create EventFd.
    #[error("Cannot create EventFd")]
    EventFd(#[source] io::Error),

    /// Cannot open disk path
    #[error("Cannot open disk path")]
    Disk(#[source] io::Error),

    /// Cannot create vhost-user-net device
    #[error("Cannot create vhost-user-net device")]
    CreateVhostUserNet(#[source] virtio_devices::vhost_user::Error),

    /// Cannot create virtio-blk device
    #[error("Cannot create virtio-blk device")]
    CreateVirtioBlock(#[source] io::Error),

    /// Cannot create virtio-net device
    #[error("Cannot create virtio-net device")]
    CreateVirtioNet(#[source] virtio_devices::net::Error),

    /// Cannot create virtio-console device
    #[error("Cannot create virtio-console device")]
    CreateVirtioConsole(#[source] io::Error),

    /// Cannot create virtio-rng device
    #[error("Cannot create virtio-rng device")]
    CreateVirtioRng(#[source] io::Error),

    /// Cannot create virtio-fs device
    #[error("Cannot create virtio-fs device")]
    CreateVirtioFs(#[source] virtio_devices::vhost_user::Error),

    /// Virtio-fs device was created without a socket.
    #[error("Virtio-fs device was created without a socket")]
    NoVirtioFsSock,

    /// Cannot create vhost-user-blk device
    #[error("Cannot create vhost-user-blk device")]
    CreateVhostUserBlk(#[source] virtio_devices::vhost_user::Error),

    /// Cannot create virtio-pmem device
    #[error("Cannot create virtio-pmem device")]
    CreateVirtioPmem(#[source] io::Error),

    /// Cannot create vDPA device
    #[error("Cannot create vdpa device")]
    CreateVdpa(#[source] virtio_devices::vdpa::Error),

    /// Cannot create virtio-vsock device
    #[error("Cannot create virtio-vsock device")]
    CreateVirtioVsock(#[source] io::Error),

    /// Cannot create tpm device
    #[error("Cannot create tmp device")]
    CreateTpmDevice(#[source] anyhow::Error),

    /// Failed to convert Path to &str for the vDPA device.
    #[error("Failed to convert Path to &str for the vDPA device")]
    CreateVdpaConvertPath,

    /// Failed to convert Path to &str for the virtio-vsock device.
    #[error("Failed to convert Path to &str for the virtio-vsock device")]
    CreateVsockConvertPath,

    /// Cannot create virtio-vsock backend
    #[error("Cannot create virtio-vsock backend")]
    CreateVsockBackend(#[source] virtio_devices::vsock::VsockUnixError),

    /// Cannot create virtio-iommu device
    #[error("Cannot create virtio-iommu device")]
    CreateVirtioIommu(#[source] io::Error),

    /// Cannot create virtio-balloon device
    #[error("Cannot create virtio-balloon device")]
    CreateVirtioBalloon(#[source] io::Error),

    /// Cannot create pvmemcontrol device
    #[cfg(feature = "pvmemcontrol")]
    #[error("Cannot create pvmemcontrol device")]
    CreatePvmemcontrol(#[source] io::Error),

    /// Cannot create virtio-watchdog device
    #[error("Cannot create virtio-watchdog device")]
    CreateVirtioWatchdog(#[source] io::Error),

    /// Failed to parse disk image format
    #[error("Failed to parse disk image format")]
    DetectImageType(#[source] io::Error),

    /// Cannot open qcow disk path
    #[error("Cannot open qcow disk path")]
    QcowDeviceCreate(#[source] qcow::Error),

    /// Cannot create serial manager
    #[error("Cannot create serial manager")]
    CreateSerialManager(#[source] SerialManagerError),

    /// Cannot spawn the serial manager thread
    #[error("Cannot spawn serial manager thread")]
    SpawnSerialManager(#[source] SerialManagerError),

    /// Cannot open tap interface
    #[error("Cannot open tap interface")]
    OpenTap(#[source] net_util::TapError),

    /// Cannot allocate IRQ.
    #[error("Cannot allocate IRQ")]
    AllocateIrq,

    /// Cannot configure the IRQ.
    #[error("Cannot configure the IRQ")]
    Irq(#[source] vmm_sys_util::errno::Error),

    /// Cannot allocate PCI BARs
    #[error("Cannot allocate PCI BARs")]
    AllocateBars(#[source] pci::PciDeviceError),

    /// Could not free the BARs associated with a PCI device.
    #[error("Could not free the BARs associated with a PCI device")]
    FreePciBars(#[source] pci::PciDeviceError),

    /// Cannot register ioevent.
    #[error("Cannot register ioevent")]
    RegisterIoevent(#[source] anyhow::Error),

    /// Cannot unregister ioevent.
    #[error("Cannot unregister ioevent")]
    UnRegisterIoevent(#[source] anyhow::Error),

    /// Cannot create virtio device
    #[error("Cannot create virtio device")]
    VirtioDevice(#[source] virtio_devices::transport::VirtioPciDeviceError),

    /// Cannot add PCI device
    #[error("Cannot add PCI device")]
    AddPciDevice(#[source] pci::PciRootError),

    /// Cannot open persistent memory file
    #[error("Cannot open persistent memory file")]
    PmemFileOpen(#[source] io::Error),

    /// Cannot set persistent memory file size
    #[error("Cannot set persistent memory file size")]
    PmemFileSetLen(#[source] io::Error),

    /// Cannot find a memory range for persistent memory
    #[error("Cannot find a memory range for persistent memory")]
    PmemRangeAllocation,

    /// Cannot find a memory range for virtio-fs
    #[error("Cannot find a memory range for virtio-fs")]
    FsRangeAllocation,

    /// Error creating serial output file
    #[error("Error creating serial output file")]
    SerialOutputFileOpen(#[source] io::Error),

    /// Error creating debug-console output file
    #[cfg(target_arch = "x86_64")]
    #[error("Error creating debug-console output file")]
    DebugconOutputFileOpen(#[source] io::Error),

    /// Error creating console output file
    #[error("Error creating console output file")]
    ConsoleOutputFileOpen(#[source] io::Error),

    /// Error creating serial pty
    #[error("Error creating serial pty")]
    SerialPtyOpen(#[source] io::Error),

    /// Error creating console pty
    #[error("Error creating console pty")]
    ConsolePtyOpen(#[source] io::Error),

    /// Error creating debugcon pty
    #[error("Error creating console pty")]
    DebugconPtyOpen(#[source] io::Error),

    /// Error setting pty raw mode
    #[error("Error setting pty raw mode")]
    SetPtyRaw(#[source] ConsoleDeviceError),

    /// Error getting pty peer
    #[error("Error getting pty peer")]
    GetPtyPeer(#[source] vmm_sys_util::errno::Error),

    /// Cannot create a VFIO device
    #[error("Cannot create a VFIO device")]
    VfioCreate(#[source] vfio_ioctls::VfioError),

    /// Cannot create a VFIO PCI device
    #[error("Cannot create a VFIO PCI device")]
    VfioPciCreate(#[source] pci::VfioPciError),

    /// Failed to map VFIO MMIO region.
    #[error("Failed to map VFIO MMIO region")]
    VfioMapRegion(#[source] pci::VfioPciError),

    /// Failed to DMA map VFIO device.
    #[error("Failed to DMA map VFIO device")]
    VfioDmaMap(#[source] vfio_ioctls::VfioError),

    /// Failed to DMA unmap VFIO device.
    #[error("Failed to DMA unmap VFIO device")]
    VfioDmaUnmap(#[source] pci::VfioPciError),

    /// Failed to create the passthrough device.
    #[error("Failed to create the passthrough device")]
    CreatePassthroughDevice(#[source] anyhow::Error),

    /// Failed to memory map.
    #[error("Failed to memory map")]
    Mmap(#[source] io::Error),

    /// Cannot add legacy device to Bus.
    #[error("Cannot add legacy device to Bus")]
    BusError(#[source] vm_device::BusError),

    /// Failed to allocate IO port
    #[error("Failed to allocate IO port")]
    AllocateIoPort,

    /// Failed to allocate MMIO address
    #[error("Failed to allocate MMIO address")]
    AllocateMmioAddress,

    /// Failed to make hotplug notification
    #[error("Failed to make hotplug notification")]
    HotPlugNotification(#[source] io::Error),

    /// Error from a memory manager operation
    #[error("Error from a memory manager operation")]
    MemoryManager(#[source] MemoryManagerError),

    /// Failed to create new interrupt source group.
    #[error("Failed to create new interrupt source group")]
    CreateInterruptGroup(#[source] io::Error),

    /// Failed to update interrupt source group.
    #[error("Failed to update interrupt source group")]
    UpdateInterruptGroup(#[source] io::Error),

    /// Failed to create interrupt controller.
    #[error("Failed to create interrupt controller")]
    CreateInterruptController(#[source] interrupt_controller::Error),

    /// Failed to create a new MmapRegion instance.
    #[error("Failed to create a new MmapRegion instance")]
    NewMmapRegion(#[source] vm_memory::mmap::MmapRegionError),

    /// Failed to clone a File.
    #[error("Failed to clone a File")]
    CloneFile(#[source] io::Error),

    /// Failed to create socket file
    #[error("Failed to create socket file")]
    CreateSocketFile(#[source] io::Error),

    /// Failed to spawn the network backend
    #[error("Failed to spawn the network backend")]
    SpawnNetBackend(#[source] io::Error),

    /// Failed to spawn the block backend
    #[error("Failed to spawn the block backend")]
    SpawnBlockBackend(#[source] io::Error),

    /// Missing PCI bus.
    #[error("Missing PCI bus")]
    NoPciBus,

    /// Could not find an available device name.
    #[error("Could not find an available device name")]
    NoAvailableDeviceName,

    /// Missing PCI device.
    #[error("Missing PCI device")]
    MissingPciDevice,

    /// Failed to remove a PCI device from the PCI bus.
    #[error("Failed to remove a PCI device from the PCI bus")]
    RemoveDeviceFromPciBus(#[source] pci::PciRootError),

    /// Failed to remove a bus device from the IO bus.
    #[error("Failed to remove a bus device from the IO bus")]
    RemoveDeviceFromIoBus(#[source] vm_device::BusError),

    /// Failed to remove a bus device from the MMIO bus.
    #[error("Failed to remove a bus device from the MMIO bus")]
    RemoveDeviceFromMmioBus(#[source] vm_device::BusError),

    /// Failed to find the device corresponding to a specific PCI b/d/f.
    #[error("Failed to find the device corresponding to a specific PCI b/d/f")]
    UnknownPciBdf(u32),

    /// Not allowed to remove this type of device from the VM.
    #[error("Not allowed to remove this type of device from the VM: {0}")]
    RemovalNotAllowed(vm_virtio::VirtioDeviceType),

    /// Failed to find device corresponding to the given identifier.
    #[error("Failed to find device corresponding to the given identifier")]
    UnknownDeviceId(String),

    /// Failed to find an available PCI device ID.
    #[error("Failed to find an available PCI device ID")]
    NextPciDeviceId(#[source] pci::PciRootError),

    /// Could not reserve the PCI device ID.
    #[error("Could not reserve the PCI device ID")]
    GetPciDeviceId(#[source] pci::PciRootError),

    /// Could not give the PCI device ID back.
    #[error("Could not give the PCI device ID back")]
    PutPciDeviceId(#[source] pci::PciRootError),

    /// No disk path was specified when one was expected
    #[error("No disk path was specified when one was expected")]
    NoDiskPath,

    /// Failed to update guest memory for virtio device.
    #[error("Failed to update guest memory for virtio device")]
    UpdateMemoryForVirtioDevice(#[source] virtio_devices::Error),

    /// Cannot create virtio-mem device
    #[error("Cannot create virtio-mem device")]
    CreateVirtioMem(#[source] io::Error),

    /// Cannot find a memory range for virtio-mem memory
    #[error("Cannot find a memory range for virtio-mem memory")]
    VirtioMemRangeAllocation,

    /// Failed to update guest memory for VFIO PCI device.
    #[error("Failed to update guest memory for VFIO PCI device")]
    UpdateMemoryForVfioPciDevice(#[source] vfio_ioctls::VfioError),

    /// Trying to use a directory for pmem but no size specified
    #[error("Trying to use a directory for pmem but no size specified")]
    PmemWithDirectorySizeMissing,

    /// Trying to use a size that is not multiple of 2MiB
    #[error("Trying to use a size that is not multiple of 2MiB")]
    PmemSizeNotAligned,

    /// Could not find the node in the device tree.
    #[error("Could not find the node in the device tree")]
    MissingNode,

    /// Resource was already found.
    #[error("Resource was already found")]
    ResourceAlreadyExists,

    /// Expected resources for virtio-pmem could not be found.
    #[error("Expected resources for virtio-pmem could not be found")]
    MissingVirtioPmemResources,

    /// Missing PCI b/d/f from the DeviceNode.
    #[error("Missing PCI b/d/f from the DeviceNode")]
    MissingDeviceNodePciBdf,

    /// No support for device passthrough
    #[error("No support for device passthrough")]
    NoDevicePassthroughSupport,

    /// No socket option support for console device
    #[error("No socket option support for console device")]
    NoSocketOptionSupportForConsoleDevice,

    /// Failed to resize virtio-balloon
    #[error("Failed to resize virtio-balloon")]
    VirtioBalloonResize(#[source] virtio_devices::balloon::Error),

    /// Missing virtio-balloon, can't proceed as expected.
    #[error("Missing virtio-balloon, can't proceed as expected")]
    MissingVirtioBalloon,

    /// Missing virtual IOMMU device
    #[error("Missing virtual IOMMU device")]
    MissingVirtualIommu,

    /// Failed to do power button notification
    #[error("Failed to do power button notification")]
    PowerButtonNotification(#[source] io::Error),

    /// Failed to do AArch64 GPIO power button notification
    #[cfg(target_arch = "aarch64")]
    #[error("Failed to do AArch64 GPIO power button notification")]
    AArch64PowerButtonNotification(#[source] devices::legacy::GpioDeviceError),

    /// Failed to set O_DIRECT flag to file descriptor
    #[error("Failed to set O_DIRECT flag to file descriptor")]
    SetDirectIo,

    /// Failed to create FixedVhdDiskAsync
    #[error("Failed to create FixedVhdDiskAsync")]
    CreateFixedVhdDiskAsync(#[source] io::Error),

    /// Failed to create FixedVhdDiskSync
    #[error("Failed to create FixedVhdDiskSync")]
    CreateFixedVhdDiskSync(#[source] io::Error),

    /// Failed to create QcowDiskSync
    #[error("Failed to create QcowDiskSync")]
    CreateQcowDiskSync(#[source] qcow::Error),

    /// Failed to create FixedVhdxDiskSync
    #[error("Failed to create FixedVhdxDiskSync")]
    CreateFixedVhdxDiskSync(#[source] vhdx::VhdxError),

    /// Failed to add DMA mapping handler to virtio-mem device.
    #[error("Failed to add DMA mapping handler to virtio-mem device")]
    AddDmaMappingHandlerVirtioMem(#[source] virtio_devices::mem::Error),

    /// Failed to remove DMA mapping handler from virtio-mem device.
    #[error("Failed to remove DMA mapping handler from virtio-mem device")]
    RemoveDmaMappingHandlerVirtioMem(#[source] virtio_devices::mem::Error),

    /// Failed to create vfio-user client
    #[error("Failed to create vfio-user client")]
    VfioUserCreateClient(#[source] vfio_user::Error),

    /// Failed to create VFIO user device
    #[error("Failed to create VFIO user device")]
    VfioUserCreate(#[source] VfioUserPciDeviceError),

    /// Failed to map region from VFIO user device into guest
    #[error("Failed to map region from VFIO user device into guest")]
    VfioUserMapRegion(#[source] VfioUserPciDeviceError),

    /// Failed to DMA map VFIO user device.
    #[error("Failed to DMA map VFIO user device")]
    VfioUserDmaMap(#[source] VfioUserPciDeviceError),

    /// Failed to DMA unmap VFIO user device.
    #[error("Failed to DMA unmap VFIO user device")]
    VfioUserDmaUnmap(#[source] VfioUserPciDeviceError),

    /// Failed to update memory mappings for VFIO user device
    #[error("Failed to update memory mappings for VFIO user device")]
    UpdateMemoryForVfioUserPciDevice(#[source] VfioUserPciDeviceError),

    /// Cannot duplicate file descriptor
    #[error("Cannot duplicate file descriptor")]
    DupFd(#[source] vmm_sys_util::errno::Error),

    /// Failed to DMA map virtio device.
    #[error("Failed to DMA map virtio device")]
    VirtioDmaMap(#[source] std::io::Error),

    /// Failed to DMA unmap virtio device.
    #[error("Failed to DMA unmap virtio device")]
    VirtioDmaUnmap(#[source] std::io::Error),

    /// Cannot hotplug device behind vIOMMU
    #[error("Cannot hotplug device behind vIOMMU")]
    InvalidIommuHotplug,

    /// Invalid identifier as it is not unique.
    #[error("Invalid identifier as it is not unique: {0}")]
    IdentifierNotUnique(String),

    /// Invalid identifier
    #[error("Invalid identifier: {0}")]
    InvalidIdentifier(String),

    /// Error activating virtio device
    #[error("Error activating virtio device")]
    VirtioActivate(#[source] ActivateError),

    /// Failed retrieving device state from snapshot
    #[error("Failed retrieving device state from snapshot")]
    RestoreGetState(#[source] MigratableError),

    /// Cannot create a PvPanic device
    #[error("Cannot create a PvPanic device")]
    PvPanicCreate(#[source] devices::pvpanic::PvPanicError),

    #[cfg(feature = "ivshmem")]
    /// Cannot create a ivshmem device
    #[error("Cannot create a ivshmem device: {0}")]
    IvshmemCreate(IvshmemError),

    /// Cannot create a RateLimiterGroup
    #[error("Cannot create a RateLimiterGroup")]
    RateLimiterGroupCreate(#[source] rate_limiter::group::Error),

    /// Cannot start sigwinch listener
    #[error("Cannot start sigwinch listener")]
    StartSigwinchListener(#[source] std::io::Error),

    // Invalid console info
    #[error("Invalid console info")]
    InvalidConsoleInfo,

    // Invalid console fd
    #[error("Invalid console fd")]
    InvalidConsoleFd,

    /// Cannot lock images of all block devices.
    #[error("Cannot lock images of all block devices")]
    DiskLockError(#[source] virtio_devices::block::Error),

    #[cfg(feature = "fw_cfg")]
    /// Error adding fw_cfg to bus.
    #[error("Error adding fw_cfg to bus")]
    ErrorAddingFwCfgToBus(#[source] vm_device::BusError),
}

pub type DeviceManagerResult<T> = result::Result<T, DeviceManagerError>;

const DEVICE_MANAGER_ACPI_SIZE: usize = 0x10;

#[derive(Default)]
pub struct Console {
    console_resizer: Option<Arc<virtio_devices::ConsoleResizer>>,
}

impl Console {
    pub fn need_resize(&self) -> bool {
        if let Some(_resizer) = self.console_resizer.as_ref() {
            return true;
        }

        false
    }

    pub fn update_console_size(&self) {
        if let Some(resizer) = self.console_resizer.as_ref() {
            resizer.update_console_size();
        }
    }
}

pub(crate) struct AddressManager {
    pub(crate) allocator: Arc<Mutex<SystemAllocator>>,
    pub(crate) io_bus: Arc<Bus>,
    pub(crate) mmio_bus: Arc<Bus>,
    pub(crate) vm: Arc<dyn hypervisor::Vm>,
    device_tree: Arc<Mutex<DeviceTree>>,
    pci_mmio32_allocators: Vec<Arc<Mutex<AddressAllocator>>>,
    pci_mmio64_allocators: Vec<Arc<Mutex<AddressAllocator>>>,
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
                // Update system allocator
                self.allocator
                    .lock()
                    .unwrap()
                    .free_io_addresses(GuestAddress(old_base), len as GuestUsize);

                self.allocator
                    .lock()
                    .unwrap()
                    .allocate_io_addresses(Some(GuestAddress(new_base)), len as GuestUsize, None)
                    .ok_or_else(|| io::Error::other("failed allocating new IO range"))?;

                // Update PIO bus
                self.io_bus
                    .update_range(old_base, len, new_base, len)
                    .map_err(io::Error::other)?;
            }
            PciBarRegionType::Memory32BitRegion | PciBarRegionType::Memory64BitRegion => {
                let allocators = if region_type == PciBarRegionType::Memory32BitRegion {
                    &self.pci_mmio32_allocators
                } else {
                    &self.pci_mmio64_allocators
                };

                // Find the specific allocator that this BAR was allocated from and use it for new one
                for allocator in allocators {
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
                            .allocate(Some(GuestAddress(new_base)), len as GuestUsize, Some(len))
                            .ok_or_else(|| io::Error::other("failed allocating new MMIO range"))?;

                        break;
                    }
                }

                // Update MMIO bus
                self.mmio_bus
                    .update_range(old_base, len, new_base, len)
                    .map_err(io::Error::other)?;
            }
        }

        // Update the device_tree resources associated with the device
        if let Some(id) = pci_dev.id() {
            if let Some(node) = self.device_tree.lock().unwrap().get_mut(&id) {
                let mut resource_updated = false;
                for resource in node.resources.iter_mut() {
                    if let Resource::PciBar { base, type_, .. } = resource
                        && PciBarRegionType::from(*type_) == region_type
                        && *base == old_base
                    {
                        *base = new_base;
                        resource_updated = true;
                        break;
                    }
                }

                if !resource_updated {
                    return Err(io::Error::other(format!(
                        "Couldn't find a resource with base 0x{old_base:x} for device {id}"
                    )));
                }
            } else {
                return Err(io::Error::other(format!(
                    "Couldn't find device {id} from device tree"
                )));
            }
        }

        let any_dev = pci_dev.as_any_mut();
        if let Some(virtio_pci_dev) = any_dev.downcast_ref::<VirtioPciDevice>() {
            let bar_addr = virtio_pci_dev.config_bar_addr();
            if bar_addr == new_base {
                for (event, addr) in virtio_pci_dev.ioeventfds(old_base) {
                    let io_addr = IoEventAddress::Mmio(addr);
                    self.vm.unregister_ioevent(event, &io_addr).map_err(|e| {
                        io::Error::other(format!("failed to unregister ioevent: {e:?}"))
                    })?;
                }
                for (event, addr) in virtio_pci_dev.ioeventfds(new_base) {
                    let io_addr = IoEventAddress::Mmio(addr);
                    self.vm
                        .register_ioevent(event, &io_addr, None)
                        .map_err(|e| {
                            io::Error::other(format!("failed to register ioevent: {e:?}"))
                        })?;
                }
            } else {
                let virtio_dev = virtio_pci_dev.virtio_device();
                let mut virtio_dev = virtio_dev.lock().unwrap();
                if let Some(mut shm_regions) = virtio_dev.get_shm_regions()
                    && shm_regions.addr.raw_value() == old_base
                {
                    // SAFETY: guaranteed by MmapRegion invariants
                    unsafe {
                        // Remove old mapping
                        self.vm
                            .remove_user_memory_region(
                                shm_regions.mem_slot,
                                old_base,
                                shm_regions.mapping.len(),
                                shm_regions.mapping.as_ptr(),
                                false,
                                false,
                            )
                            .map_err(|e| {
                                io::Error::other(format!(
                                    "failed to remove user memory region: {e:?}"
                                ))
                            })?;

                        // Create new mapping by inserting new region to KVM.
                        self.vm
                            .create_user_memory_region(
                                shm_regions.mem_slot,
                                new_base,
                                shm_regions.mapping.len(),
                                shm_regions.mapping.as_ptr(),
                                false,
                                false,
                            )
                            .map_err(|e| {
                                io::Error::other(format!(
                                    "failed to create user memory regions: {e:?}"
                                ))
                            })?;
                    }

                    // Update shared memory regions to reflect the new mapping.
                    shm_regions.addr = GuestAddress(new_base);
                    virtio_dev.set_shm_regions(shm_regions).map_err(|e| {
                        io::Error::other(format!("failed to update shared memory regions: {e:?}"))
                    })?;
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
    pub path: PathBuf,
}

impl Clone for PtyPair {
    fn clone(&self) -> Self {
        PtyPair {
            main: self.main.try_clone().unwrap(),
            path: self.path.clone(),
        }
    }
}

#[derive(Clone)]
pub enum PciDeviceHandle {
    Vfio(Arc<Mutex<VfioPciDevice>>),
    Virtio(Arc<Mutex<VirtioPciDevice>>),
    VfioUser(Arc<Mutex<VfioUserPciDevice>>),
}

#[derive(Clone)]
struct MetaVirtioDevice {
    virtio_device: Arc<Mutex<dyn virtio_devices::VirtioDevice>>,
    iommu: bool,
    id: String,
    pci_segment: u16,
    dma_handler: Option<Arc<dyn ExternalDmaMapping>>,
}

#[derive(Default)]
pub struct AcpiPlatformAddresses {
    pub pm_timer_address: Option<GenericAddress>,
    pub reset_reg_address: Option<GenericAddress>,
    pub sleep_control_reg_address: Option<GenericAddress>,
    pub sleep_status_reg_address: Option<GenericAddress>,
}

#[cfg(all(feature = "mshv", feature = "sev_snp"))]
struct SevSnpPageAccessProxy {
    vm: Arc<dyn hypervisor::Vm>,
}

#[cfg(all(feature = "mshv", feature = "sev_snp"))]
impl std::fmt::Debug for SevSnpPageAccessProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SNP Page access proxy")
    }
}

#[cfg(all(feature = "mshv", feature = "sev_snp"))]
impl SevSnpPageAccessProxy {
    fn new(vm: Arc<dyn hypervisor::Vm>) -> SevSnpPageAccessProxy {
        SevSnpPageAccessProxy { vm }
    }
}

#[cfg(all(feature = "mshv", feature = "sev_snp"))]
impl AccessPlatform for SevSnpPageAccessProxy {
    fn translate_gpa(&self, base: u64, _size: u64) -> std::result::Result<u64, std::io::Error> {
        Ok(base)
    }

    fn translate_gva(&self, base: u64, size: u64) -> std::result::Result<u64, std::io::Error> {
        self.vm
            .gain_page_access(base, size as u32)
            .map_err(io::Error::other)?;
        Ok(base)
    }
}

pub struct DeviceManager {
    // Manage address space related to devices
    address_manager: Arc<AddressManager>,

    // Console abstraction
    console: Arc<Console>,

    // Serial Manager
    serial_manager: Option<Arc<SerialManager>>,

    // pty foreground status,
    console_resize_pipe: Option<Arc<File>>,

    // To restore on exit.
    original_termios_opt: Arc<Mutex<Option<termios>>>,

    // Interrupt controller
    #[cfg(target_arch = "x86_64")]
    interrupt_controller: Option<Arc<Mutex<ioapic::Ioapic>>>,
    #[cfg(target_arch = "aarch64")]
    interrupt_controller: Option<Arc<Mutex<gic::Gic>>>,
    #[cfg(target_arch = "riscv64")]
    interrupt_controller: Option<Arc<Mutex<aia::Aia>>>,

    // Things to be added to the commandline (e.g. aarch64 or riscv64 early console)
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    cmdline_additions: Vec<String>,

    // ACPI GED notification device
    ged_notification_device: Option<Arc<Mutex<devices::AcpiGedDevice>>>,

    // VM configuration
    config: Arc<Mutex<VmConfig>>,

    // Memory Manager
    memory_manager: Arc<Mutex<MemoryManager>>,

    // CPU Manager
    cpu_manager: Arc<Mutex<CpuManager>>,

    // The virtio devices on the system
    virtio_devices: Vec<MetaVirtioDevice>,

    /// All disks. Needed for locking and unlocking the images.
    block_devices: Vec<Arc<Mutex<Block>>>,

    // List of bus devices
    // Let the DeviceManager keep strong references to the BusDevice devices.
    // This allows the IO and MMIO buses to be provided with Weak references,
    // which prevents cyclic dependencies.
    bus_devices: Vec<Arc<dyn BusDeviceSync>>,

    // Counter to keep track of the consumed device IDs.
    device_id_cnt: Wrapping<usize>,

    pci_segments: Vec<PciSegment>,

    #[cfg_attr(target_arch = "aarch64", allow(dead_code))]
    // MSI Interrupt Manager
    msi_interrupt_manager: Arc<dyn InterruptManager<GroupConfig = MsiIrqGroupConfig>>,

    #[cfg_attr(feature = "mshv", allow(dead_code))]
    // Legacy Interrupt Manager
    legacy_interrupt_manager: Option<Arc<dyn InterruptManager<GroupConfig = LegacyIrqGroupConfig>>>,

    // Passthrough device handle
    passthrough_device: Option<VfioDeviceFd>,

    // VFIO container
    // Only one container can be created, therefore it is stored as part of the
    // DeviceManager to be reused.
    vfio_container: Option<Arc<VfioContainer>>,

    // Paravirtualized IOMMU
    iommu_device: Option<Arc<Mutex<virtio_devices::Iommu>>>,
    iommu_mapping: Option<Arc<IommuMapping>>,

    // PCI information about devices attached to the paravirtualized IOMMU
    // It contains the virtual IOMMU PCI BDF along with the list of PCI BDF
    // representing the devices attached to the virtual IOMMU. This is useful
    // information for filling the ACPI VIOT table.
    iommu_attached_devices: Option<(PciBdf, Vec<PciBdf>)>,

    // Tree of devices, representing the dependencies between devices.
    // Useful for introspection, snapshot and restore.
    device_tree: Arc<Mutex<DeviceTree>>,

    // Exit event
    exit_evt: EventFd,
    reset_evt: EventFd,

    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    id_to_dev_info: HashMap<(DeviceType, String), MmioDeviceInfo>,

    // seccomp action
    seccomp_action: SeccompAction,

    // List of guest NUMA nodes.
    numa_nodes: NumaNodes,

    // Possible handle to the virtio-balloon device
    balloon: Option<Arc<Mutex<virtio_devices::Balloon>>>,

    // Virtio Device activation EventFd to allow the VMM thread to trigger device
    // activation and thus start the threads from the VMM thread
    activate_evt: EventFd,

    acpi_address: GuestAddress,

    selected_segment: usize,

    // Possible handle to the virtio-mem device
    virtio_mem_devices: Vec<Arc<Mutex<virtio_devices::Mem>>>,

    #[cfg(target_arch = "aarch64")]
    // GPIO device for AArch64
    gpio_device: Option<Arc<Mutex<devices::legacy::Gpio>>>,

    #[cfg(feature = "pvmemcontrol")]
    pvmemcontrol_devices: Option<(
        Arc<PvmemcontrolBusDevice>,
        Arc<Mutex<PvmemcontrolPciDevice>>,
    )>,

    // pvpanic device
    pvpanic_device: Option<Arc<Mutex<devices::PvPanicDevice>>>,

    // Flag to force setting the iommu on virtio devices
    force_iommu: bool,

    // io_uring availability if detected
    io_uring_supported: Option<bool>,

    // aio availability if detected
    aio_supported: Option<bool>,

    // List of unique identifiers provided at boot through the configuration.
    boot_id_list: BTreeSet<String>,

    #[cfg(not(target_arch = "riscv64"))]
    // Start time of the VM
    timestamp: Instant,

    // Pending activations
    pending_activations: Arc<Mutex<Vec<VirtioPciDeviceActivator>>>,

    // Addresses for ACPI platform devices e.g. ACPI PM timer, sleep/reset registers
    acpi_platform_addresses: AcpiPlatformAddresses,

    snapshot: Option<Snapshot>,

    rate_limit_groups: HashMap<String, Arc<RateLimiterGroup>>,

    mmio_regions: Arc<Mutex<Vec<MmioRegion>>>,

    #[cfg(feature = "fw_cfg")]
    fw_cfg: Option<Arc<Mutex<FwCfg>>>,

    #[cfg(feature = "ivshmem")]
    // ivshmem device
    ivshmem_device: Option<Arc<Mutex<devices::IvshmemDevice>>>,
}

fn create_mmio_allocators(
    start: u64,
    end: u64,
    num_pci_segments: u16,
    weights: Vec<u32>,
    alignment: u64,
) -> Vec<Arc<Mutex<AddressAllocator>>> {
    let total_weight: u32 = weights.iter().sum();

    // Start each PCI segment mmio range on an aligned boundary
    let pci_segment_mmio_size = (end - start + 1) / (alignment * total_weight as u64) * alignment;

    let mut mmio_allocators = vec![];
    let mut i = 0;
    for segment_id in 0..num_pci_segments as u64 {
        let weight = weights[segment_id as usize] as u64;
        let mmio_start = start + i * pci_segment_mmio_size;
        let mmio_size = pci_segment_mmio_size * weight;
        let allocator = Arc::new(Mutex::new(
            AddressAllocator::new(GuestAddress(mmio_start), mmio_size).unwrap(),
        ));
        mmio_allocators.push(allocator);
        i += weight;
    }

    mmio_allocators
}

impl DeviceManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        io_bus: Arc<Bus>,
        mmio_bus: Arc<Bus>,
        vm: Arc<dyn hypervisor::Vm>,
        config: Arc<Mutex<VmConfig>>,
        memory_manager: Arc<Mutex<MemoryManager>>,
        cpu_manager: Arc<Mutex<CpuManager>>,
        exit_evt: EventFd,
        reset_evt: EventFd,
        seccomp_action: SeccompAction,
        numa_nodes: NumaNodes,
        activate_evt: &EventFd,
        force_iommu: bool,
        boot_id_list: BTreeSet<String>,
        #[cfg(not(target_arch = "riscv64"))] timestamp: Instant,
        snapshot: Option<&Snapshot>,
        dynamic: bool,
    ) -> DeviceManagerResult<Arc<Mutex<Self>>> {
        trace_scoped!("DeviceManager::new");

        let (device_tree, device_id_cnt) = if let Some(snapshot) = snapshot.as_ref() {
            let state: DeviceManagerState = snapshot.to_state().unwrap();
            (
                Arc::new(Mutex::new(state.device_tree.clone())),
                state.device_id_cnt,
            )
        } else {
            (Arc::new(Mutex::new(DeviceTree::new())), Wrapping(0))
        };

        let num_pci_segments =
            if let Some(platform_config) = config.lock().unwrap().platform.as_ref() {
                platform_config.num_pci_segments
            } else {
                1
            };

        let mut mmio32_aperture_weights: Vec<u32> =
            std::iter::repeat_n(DEFAULT_PCI_SEGMENT_APERTURE_WEIGHT, num_pci_segments.into())
                .collect();
        if let Some(pci_segments) = &config.lock().unwrap().pci_segments {
            for pci_segment in pci_segments.iter() {
                mmio32_aperture_weights[pci_segment.pci_segment as usize] =
                    pci_segment.mmio32_aperture_weight;
            }
        }

        let start_of_mmio32_area = layout::MEM_32BIT_DEVICES_START.0;
        let end_of_mmio32_area = layout::MEM_32BIT_DEVICES_START.0 + layout::MEM_32BIT_DEVICES_SIZE;
        let pci_mmio32_allocators = create_mmio_allocators(
            start_of_mmio32_area,
            end_of_mmio32_area,
            num_pci_segments,
            mmio32_aperture_weights,
            4 << 10,
        );

        let mut mmio64_aperture_weights: Vec<u32> =
            std::iter::repeat_n(DEFAULT_PCI_SEGMENT_APERTURE_WEIGHT, num_pci_segments.into())
                .collect();
        if let Some(pci_segments) = &config.lock().unwrap().pci_segments {
            for pci_segment in pci_segments.iter() {
                mmio64_aperture_weights[pci_segment.pci_segment as usize] =
                    pci_segment.mmio64_aperture_weight;
            }
        }

        let start_of_mmio64_area = memory_manager.lock().unwrap().start_of_device_area().0;
        let end_of_mmio64_area = memory_manager.lock().unwrap().end_of_device_area().0;
        let pci_mmio64_allocators = create_mmio_allocators(
            start_of_mmio64_area,
            end_of_mmio64_area,
            num_pci_segments,
            mmio64_aperture_weights,
            4 << 30,
        );

        let address_manager = Arc::new(AddressManager {
            allocator: memory_manager.lock().unwrap().allocator(),
            io_bus,
            mmio_bus,
            vm: vm.clone(),
            device_tree: Arc::clone(&device_tree),
            pci_mmio32_allocators,
            pci_mmio64_allocators,
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

        let acpi_address = address_manager
            .allocator
            .lock()
            .unwrap()
            .allocate_platform_mmio_addresses(None, DEVICE_MANAGER_ACPI_SIZE as u64, None)
            .ok_or(DeviceManagerError::AllocateIoPort)?;

        let mut pci_irq_slots = [0; 32];
        PciSegment::reserve_legacy_interrupts_for_pci_devices(
            &address_manager,
            &mut pci_irq_slots,
        )?;

        let mut pci_segments = vec![PciSegment::new_default_segment(
            &address_manager,
            Arc::clone(&address_manager.pci_mmio32_allocators[0]),
            Arc::clone(&address_manager.pci_mmio64_allocators[0]),
            &pci_irq_slots,
        )?];

        for i in 1..num_pci_segments as usize {
            pci_segments.push(PciSegment::new(
                i as u16,
                numa_node_id_from_pci_segment_id(&numa_nodes, i as u16),
                &address_manager,
                Arc::clone(&address_manager.pci_mmio32_allocators[i]),
                Arc::clone(&address_manager.pci_mmio64_allocators[i]),
                &pci_irq_slots,
            )?);
        }

        if dynamic {
            let acpi_address = address_manager
                .allocator
                .lock()
                .unwrap()
                .allocate_platform_mmio_addresses(None, CPU_MANAGER_ACPI_SIZE as u64, None)
                .ok_or(DeviceManagerError::AllocateMmioAddress)?;

            address_manager
                .mmio_bus
                .insert(
                    cpu_manager.clone(),
                    acpi_address.0,
                    CPU_MANAGER_ACPI_SIZE as u64,
                )
                .map_err(DeviceManagerError::BusError)?;

            cpu_manager.lock().unwrap().set_acpi_address(acpi_address);
        }

        let mut rate_limit_groups = HashMap::<String, Arc<RateLimiterGroup>>::new();
        if let Some(rate_limit_groups_cfg) = config.lock().unwrap().rate_limit_groups.as_ref() {
            for rate_limit_group_cfg in rate_limit_groups_cfg {
                let rate_limit_cfg = rate_limit_group_cfg.rate_limiter_config;
                let bw = rate_limit_cfg.bandwidth.unwrap_or_default();
                let ops = rate_limit_cfg.ops.unwrap_or_default();
                let mut rate_limit_group = RateLimiterGroup::new(
                    &rate_limit_group_cfg.id,
                    bw.size,
                    bw.one_time_burst.unwrap_or(0),
                    bw.refill_time,
                    ops.size,
                    ops.one_time_burst.unwrap_or(0),
                    ops.refill_time,
                )
                .map_err(DeviceManagerError::RateLimiterGroupCreate)?;

                let exit_evt = exit_evt.try_clone().map_err(DeviceManagerError::EventFd)?;

                rate_limit_group.start_thread(exit_evt).unwrap();
                rate_limit_groups
                    .insert(rate_limit_group_cfg.id.clone(), Arc::new(rate_limit_group));
            }
        }

        let device_manager = DeviceManager {
            address_manager: Arc::clone(&address_manager),
            console: Arc::new(Console::default()),
            interrupt_controller: None,
            #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
            cmdline_additions: Vec::new(),
            ged_notification_device: None,
            config,
            memory_manager,
            cpu_manager,
            virtio_devices: Vec::new(),
            block_devices: vec![],
            bus_devices: Vec::new(),
            device_id_cnt,
            msi_interrupt_manager,
            legacy_interrupt_manager: None,
            passthrough_device: None,
            vfio_container: None,
            iommu_device: None,
            iommu_mapping: None,
            iommu_attached_devices: None,
            pci_segments,
            device_tree,
            exit_evt,
            reset_evt,
            #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
            id_to_dev_info: HashMap::new(),
            seccomp_action,
            numa_nodes,
            balloon: None,
            activate_evt: activate_evt
                .try_clone()
                .map_err(DeviceManagerError::EventFd)?,
            acpi_address,
            selected_segment: 0,
            serial_manager: None,
            console_resize_pipe: None,
            original_termios_opt: Arc::new(Mutex::new(None)),
            virtio_mem_devices: Vec::new(),
            #[cfg(target_arch = "aarch64")]
            gpio_device: None,
            #[cfg(feature = "pvmemcontrol")]
            pvmemcontrol_devices: None,
            pvpanic_device: None,
            force_iommu,
            io_uring_supported: None,
            aio_supported: None,
            boot_id_list,
            #[cfg(not(target_arch = "riscv64"))]
            timestamp,
            pending_activations: Arc::new(Mutex::new(Vec::default())),
            acpi_platform_addresses: AcpiPlatformAddresses::default(),
            snapshot: snapshot.cloned(),
            rate_limit_groups,
            mmio_regions: Arc::new(Mutex::new(Vec::new())),
            #[cfg(feature = "fw_cfg")]
            fw_cfg: None,
            #[cfg(feature = "ivshmem")]
            ivshmem_device: None,
        };

        let device_manager = Arc::new(Mutex::new(device_manager));

        address_manager
            .mmio_bus
            .insert(
                Arc::clone(&device_manager) as Arc<dyn BusDeviceSync>,
                acpi_address.0,
                DEVICE_MANAGER_ACPI_SIZE as u64,
            )
            .map_err(DeviceManagerError::BusError)?;

        Ok(device_manager)
    }

    pub fn console_resize_pipe(&self) -> Option<Arc<File>> {
        self.console_resize_pipe.clone()
    }

    pub fn create_interrupt_controller(
        &mut self,
    ) -> DeviceManagerResult<Arc<Mutex<dyn InterruptController>>> {
        self.add_interrupt_controller()
    }

    pub fn create_devices(
        &mut self,
        console_info: Option<ConsoleInfo>,
        console_resize_pipe: Option<Arc<File>>,
        original_termios_opt: Arc<Mutex<Option<termios>>>,
        interrupt_controller: Arc<Mutex<dyn InterruptController>>,
    ) -> DeviceManagerResult<()> {
        trace_scoped!("create_devices");

        let mut virtio_devices: Vec<MetaVirtioDevice> = Vec::new();

        self.cpu_manager
            .lock()
            .unwrap()
            .set_interrupt_controller(interrupt_controller.clone());

        // Now we can create the legacy interrupt manager, which needs the freshly
        // formed IOAPIC device.
        let legacy_interrupt_manager: Arc<
            dyn InterruptManager<GroupConfig = LegacyIrqGroupConfig>,
        > = Arc::new(LegacyUserspaceInterruptManager::new(Arc::clone(
            &interrupt_controller,
        )));

        {
            if let Some(acpi_address) = self.memory_manager.lock().unwrap().acpi_address() {
                self.address_manager
                    .mmio_bus
                    .insert(
                        Arc::clone(&self.memory_manager) as Arc<dyn BusDeviceSync>,
                        acpi_address.0,
                        MEMORY_MANAGER_ACPI_SIZE as u64,
                    )
                    .map_err(DeviceManagerError::BusError)?;
            }
        }

        #[cfg(target_arch = "x86_64")]
        self.add_legacy_devices(
            self.reset_evt
                .try_clone()
                .map_err(DeviceManagerError::EventFd)?,
        )?;

        #[cfg(target_arch = "aarch64")]
        self.add_legacy_devices(legacy_interrupt_manager.as_ref())?;

        {
            self.ged_notification_device = self.add_acpi_devices(
                legacy_interrupt_manager.as_ref(),
                self.reset_evt
                    .try_clone()
                    .map_err(DeviceManagerError::EventFd)?,
                self.exit_evt
                    .try_clone()
                    .map_err(DeviceManagerError::EventFd)?,
            )?;
        }

        self.original_termios_opt = original_termios_opt;

        self.console = self.add_console_devices(
            legacy_interrupt_manager.as_ref(),
            &mut virtio_devices,
            console_info,
            console_resize_pipe,
        )?;

        #[cfg(not(target_arch = "riscv64"))]
        if let Some(tpm) = self.config.clone().lock().unwrap().tpm.as_ref() {
            let tpm_dev = self.add_tpm_device(tpm.socket.clone())?;
            self.bus_devices
                .push(Arc::clone(&tpm_dev) as Arc<dyn BusDeviceSync>);
        }
        self.legacy_interrupt_manager = Some(legacy_interrupt_manager);

        virtio_devices.append(&mut self.make_virtio_devices()?);

        self.add_pci_devices(virtio_devices.clone())?;

        self.virtio_devices = virtio_devices;

        // Add pvmemcontrol if required
        #[cfg(feature = "pvmemcontrol")]
        {
            if self.config.lock().unwrap().pvmemcontrol.is_some() {
                let (pvmemcontrol_bus_device, pvmemcontrol_pci_device) =
                    self.make_pvmemcontrol_device()?;
                self.pvmemcontrol_devices =
                    Some((pvmemcontrol_bus_device, pvmemcontrol_pci_device));
            }
        }

        if self.config.clone().lock().unwrap().pvpanic {
            self.pvpanic_device = self.add_pvpanic_device()?;
        }

        #[cfg(feature = "ivshmem")]
        if let Some(ivshmem) = self.config.clone().lock().unwrap().ivshmem.as_ref() {
            self.ivshmem_device = self.add_ivshmem_device(ivshmem)?;
        }

        Ok(())
    }

    #[cfg(feature = "fw_cfg")]
    pub fn create_fw_cfg_device(&mut self) -> Result<(), DeviceManagerError> {
        let fw_cfg = Arc::new(Mutex::new(devices::legacy::FwCfg::new(
            self.memory_manager.lock().as_ref().unwrap().guest_memory(),
        )));

        self.fw_cfg = Some(fw_cfg.clone());

        self.bus_devices
            .push(Arc::clone(&fw_cfg) as Arc<dyn BusDeviceSync>);

        #[cfg(target_arch = "x86_64")]
        self.address_manager
            .io_bus
            .insert(fw_cfg, PORT_FW_CFG_BASE, PORT_FW_CFG_WIDTH)
            .map_err(DeviceManagerError::ErrorAddingFwCfgToBus)?;

        // default address for fw_cfg on arm via mmio
        // https://github.com/torvalds/linux/blob/master/drivers/firmware/qemu_fw_cfg.c#L27
        #[cfg(target_arch = "aarch64")]
        {
            self.address_manager
                .mmio_bus
                .insert(fw_cfg.clone(), PORT_FW_CFG_BASE, PORT_FW_CFG_WIDTH)
                .map_err(DeviceManagerError::ErrorAddingFwCfgToBus)?;

            let fw_cfg_irq = self
                .address_manager
                .allocator
                .lock()
                .unwrap()
                .allocate_irq()
                .unwrap();

            self.id_to_dev_info.insert(
                (DeviceType::FwCfg, "fw-cfg".to_string()),
                MmioDeviceInfo {
                    addr: PORT_FW_CFG_BASE,
                    len: PORT_FW_CFG_WIDTH,
                    irq: fw_cfg_irq,
                },
            );
        }
        Ok(())
    }

    fn state(&self) -> DeviceManagerState {
        DeviceManagerState {
            device_tree: self.device_tree.lock().unwrap().clone(),
            device_id_cnt: self.device_id_cnt,
        }
    }

    fn get_msi_iova_space(&mut self) -> (u64, u64) {
        #[cfg(target_arch = "aarch64")]
        {
            let vcpus = self.config.lock().unwrap().cpus.boot_vcpus;
            let vgic_config = gic::Gic::create_default_config(vcpus.into());
            (
                vgic_config.msi_addr,
                vgic_config.msi_addr + vgic_config.msi_size - 1,
            )
        }
        #[cfg(target_arch = "riscv64")]
        {
            let vcpus = self.config.lock().unwrap().cpus.boot_vcpus;
            let vaia_config = aia::Aia::create_default_config(vcpus.into());
            (
                vaia_config.imsic_addr,
                vaia_config.imsic_addr + vaia_config.vcpu_count as u64 * arch::layout::IMSIC_SIZE
                    - 1,
            )
        }
        #[cfg(target_arch = "x86_64")]
        (0xfee0_0000, 0xfeef_ffff)
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    /// Gets the information of the devices registered up to some point in time.
    pub fn get_device_info(&self) -> &HashMap<(DeviceType, String), MmioDeviceInfo> {
        &self.id_to_dev_info
    }

    #[allow(unused_variables)]
    fn add_pci_devices(
        &mut self,
        virtio_devices: Vec<MetaVirtioDevice>,
    ) -> DeviceManagerResult<()> {
        let iommu_id = String::from(IOMMU_DEVICE_NAME);

        let iommu_address_width_bits =
            if let Some(ref platform) = self.config.lock().unwrap().platform {
                platform.iommu_address_width_bits
            } else {
                DEFAULT_IOMMU_ADDRESS_WIDTH_BITS
            };

        let iommu_device = if self.config.lock().unwrap().iommu {
            let (device, mapping) = virtio_devices::Iommu::new(
                iommu_id.clone(),
                self.seccomp_action.clone(),
                self.exit_evt
                    .try_clone()
                    .map_err(DeviceManagerError::EventFd)?,
                self.get_msi_iova_space(),
                iommu_address_width_bits,
                state_from_id(self.snapshot.as_ref(), iommu_id.as_str())
                    .map_err(DeviceManagerError::RestoreGetState)?,
            )
            .map_err(DeviceManagerError::CreateVirtioIommu)?;
            let device = Arc::new(Mutex::new(device));
            self.iommu_device = Some(Arc::clone(&device));
            self.iommu_mapping = Some(mapping);

            // Fill the device tree with a new node. In case of restore, we
            // know there is nothing to do, so we can simply override the
            // existing entry.
            self.device_tree
                .lock()
                .unwrap()
                .insert(iommu_id.clone(), device_node!(iommu_id, device));

            Some(device)
        } else {
            None
        };

        let mut iommu_attached_devices = Vec::new();
        {
            for handle in virtio_devices {
                let mapping: Option<Arc<IommuMapping>> = if handle.iommu {
                    self.iommu_mapping.clone()
                } else {
                    None
                };

                let dev_id = self.add_virtio_pci_device(
                    handle.virtio_device,
                    &mapping,
                    handle.id,
                    handle.pci_segment,
                    handle.dma_handler,
                )?;

                if handle.iommu {
                    iommu_attached_devices.push(dev_id);
                }
            }

            let mut vfio_iommu_device_ids = self.add_vfio_devices()?;
            iommu_attached_devices.append(&mut vfio_iommu_device_ids);

            let mut vfio_user_iommu_device_ids = self.add_user_devices()?;
            iommu_attached_devices.append(&mut vfio_user_iommu_device_ids);

            // Add all devices from forced iommu segments
            if let Some(platform_config) = self.config.lock().unwrap().platform.as_ref()
                && let Some(iommu_segments) = platform_config.iommu_segments.as_ref()
            {
                for segment in iommu_segments {
                    for device in 0..32 {
                        let bdf = PciBdf::new(*segment, 0, device, 0);
                        if !iommu_attached_devices.contains(&bdf) {
                            iommu_attached_devices.push(bdf);
                        }
                    }
                }
            }

            if let Some(iommu_device) = iommu_device {
                let dev_id = self.add_virtio_pci_device(iommu_device, &None, iommu_id, 0, None)?;
                self.iommu_attached_devices = Some((dev_id, iommu_attached_devices));
            }
        }

        for segment in &self.pci_segments {
            #[cfg(target_arch = "x86_64")]
            if let Some(pci_config_io) = segment.pci_config_io.as_ref() {
                self.bus_devices
                    .push(Arc::clone(pci_config_io) as Arc<dyn BusDeviceSync>);
            }

            self.bus_devices
                .push(Arc::clone(&segment.pci_config_mmio) as Arc<dyn BusDeviceSync>);
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
                self.address_manager.vm.clone(),
            )
            .map_err(DeviceManagerError::CreateInterruptController)?,
        ));

        self.interrupt_controller = Some(interrupt_controller.clone());

        // Restore the vGic if this is in the process of restoration
        let id = String::from(gic::GIC_SNAPSHOT_ID);
        if let Some(vgic_snapshot) = snapshot_from_id(self.snapshot.as_ref(), &id) {
            // PMU support is optional. Nothing should be impacted if the PMU initialization failed.
            if self
                .cpu_manager
                .lock()
                .unwrap()
                .init_pmu(AARCH64_PMU_IRQ + 16)
                .is_err()
            {
                info!("Failed to initialize PMU");
            }

            let vgic_state = vgic_snapshot
                .to_state()
                .map_err(DeviceManagerError::RestoreGetState)?;
            let saved_vcpu_states = self.cpu_manager.lock().unwrap().get_saved_states();
            interrupt_controller
                .lock()
                .unwrap()
                .restore_vgic(vgic_state, &saved_vcpu_states)
                .unwrap();
        }

        self.device_tree
            .lock()
            .unwrap()
            .insert(id.clone(), device_node!(id, interrupt_controller));

        Ok(interrupt_controller)
    }

    #[cfg(target_arch = "aarch64")]
    pub fn get_interrupt_controller(&mut self) -> Option<&Arc<Mutex<gic::Gic>>> {
        self.interrupt_controller.as_ref()
    }

    #[cfg(target_arch = "riscv64")]
    fn add_interrupt_controller(
        &mut self,
    ) -> DeviceManagerResult<Arc<Mutex<dyn InterruptController>>> {
        let interrupt_controller: Arc<Mutex<aia::Aia>> = Arc::new(Mutex::new(
            aia::Aia::new(
                self.config.lock().unwrap().cpus.boot_vcpus,
                Arc::clone(&self.msi_interrupt_manager),
                self.address_manager.vm.clone(),
            )
            .map_err(DeviceManagerError::CreateInterruptController)?,
        ));

        self.interrupt_controller = Some(interrupt_controller.clone());

        // Restore the vAia if this is in the process of restoration
        let id = String::from(aia::_AIA_SNAPSHOT_ID);
        if let Some(_vaia_snapshot) = snapshot_from_id(self.snapshot.as_ref(), &id) {
            // TODO: vAia snapshotting and restoration is scheduled to next stage of riscv64 support.
            // TODO: PMU support is scheduled to next stage of riscv64 support.
            // PMU support is optional. Nothing should be impacted if the PMU initialization failed.
            unimplemented!()
        }

        self.device_tree
            .lock()
            .unwrap()
            .insert(id.clone(), device_node!(id, interrupt_controller));

        Ok(interrupt_controller)
    }

    #[cfg(target_arch = "riscv64")]
    pub fn get_interrupt_controller(&mut self) -> Option<&Arc<Mutex<aia::Aia>>> {
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
                self.msi_interrupt_manager.as_ref(),
                state_from_id(self.snapshot.as_ref(), id.as_str())
                    .map_err(DeviceManagerError::RestoreGetState)?,
            )
            .map_err(DeviceManagerError::CreateInterruptController)?,
        ));

        self.interrupt_controller = Some(interrupt_controller.clone());

        self.address_manager
            .mmio_bus
            .insert(interrupt_controller.clone(), IOAPIC_START.0, IOAPIC_SIZE)
            .map_err(DeviceManagerError::BusError)?;

        self.bus_devices
            .push(Arc::clone(&interrupt_controller) as Arc<dyn BusDeviceSync>);

        // Fill the device tree with a new node. In case of restore, we
        // know there is nothing to do, so we can simply override the
        // existing entry.
        self.device_tree
            .lock()
            .unwrap()
            .insert(id.clone(), device_node!(id, interrupt_controller));

        Ok(interrupt_controller)
    }

    fn add_acpi_devices(
        &mut self,
        interrupt_manager: &dyn InterruptManager<GroupConfig = LegacyIrqGroupConfig>,
        reset_evt: EventFd,
        exit_evt: EventFd,
    ) -> DeviceManagerResult<Option<Arc<Mutex<devices::AcpiGedDevice>>>> {
        let vcpus_kill_signalled = self
            .cpu_manager
            .lock()
            .unwrap()
            .vcpus_kill_signalled()
            .clone();
        let shutdown_device = Arc::new(Mutex::new(devices::AcpiShutdownDevice::new(
            exit_evt,
            reset_evt,
            vcpus_kill_signalled,
        )));

        self.bus_devices
            .push(Arc::clone(&shutdown_device) as Arc<dyn BusDeviceSync>);

        #[cfg(target_arch = "x86_64")]
        {
            let shutdown_pio_address: u16 = 0x600;

            self.address_manager
                .allocator
                .lock()
                .unwrap()
                .allocate_io_addresses(Some(GuestAddress(shutdown_pio_address.into())), 0x8, None)
                .ok_or(DeviceManagerError::AllocateIoPort)?;

            self.address_manager
                .io_bus
                .insert(shutdown_device, shutdown_pio_address.into(), 0x4)
                .map_err(DeviceManagerError::BusError)?;

            self.acpi_platform_addresses.sleep_control_reg_address =
                Some(GenericAddress::io_port_address::<u8>(shutdown_pio_address));
            self.acpi_platform_addresses.sleep_status_reg_address =
                Some(GenericAddress::io_port_address::<u8>(shutdown_pio_address));
            self.acpi_platform_addresses.reset_reg_address =
                Some(GenericAddress::io_port_address::<u8>(shutdown_pio_address));
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
            .push(Arc::clone(&ged_device) as Arc<dyn BusDeviceSync>);

        let pm_timer_device = Arc::new(Mutex::new(devices::AcpiPmTimerDevice::new()));

        self.bus_devices
            .push(Arc::clone(&pm_timer_device) as Arc<dyn BusDeviceSync>);

        #[cfg(target_arch = "x86_64")]
        {
            let pm_timer_pio_address: u16 = 0x608;

            self.address_manager
                .allocator
                .lock()
                .unwrap()
                .allocate_io_addresses(Some(GuestAddress(pm_timer_pio_address.into())), 0x4, None)
                .ok_or(DeviceManagerError::AllocateIoPort)?;

            self.address_manager
                .io_bus
                .insert(pm_timer_device, pm_timer_pio_address.into(), 0x4)
                .map_err(DeviceManagerError::BusError)?;

            self.acpi_platform_addresses.pm_timer_address =
                Some(GenericAddress::io_port_address::<u32>(pm_timer_pio_address));
        }

        Ok(Some(ged_device))
    }

    #[cfg(target_arch = "x86_64")]
    fn add_legacy_devices(&mut self, reset_evt: EventFd) -> DeviceManagerResult<()> {
        let vcpus_kill_signalled = self
            .cpu_manager
            .lock()
            .unwrap()
            .vcpus_kill_signalled()
            .clone();
        // Add a shutdown device (i8042)
        let i8042 = Arc::new(Mutex::new(devices::legacy::I8042Device::new(
            reset_evt.try_clone().unwrap(),
            vcpus_kill_signalled.clone(),
        )));

        self.bus_devices
            .push(Arc::clone(&i8042) as Arc<dyn BusDeviceSync>);

        self.address_manager
            .io_bus
            .insert(i8042, 0x61, 0x4)
            .map_err(DeviceManagerError::BusError)?;
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
                reset_evt,
                Some(vcpus_kill_signalled),
            )));

            self.bus_devices
                .push(Arc::clone(&cmos) as Arc<dyn BusDeviceSync>);

            self.address_manager
                .io_bus
                .insert(cmos, 0x70, 0x2)
                .map_err(DeviceManagerError::BusError)?;

            let fwdebug = Arc::new(Mutex::new(devices::legacy::FwDebugDevice::new()));

            self.bus_devices
                .push(Arc::clone(&fwdebug) as Arc<dyn BusDeviceSync>);

            self.address_manager
                .io_bus
                .insert(fwdebug, 0x402, 0x1)
                .map_err(DeviceManagerError::BusError)?;
        }

        // 0x80 debug port
        let debug_port = Arc::new(Mutex::new(devices::legacy::DebugPort::new(self.timestamp)));
        self.bus_devices
            .push(Arc::clone(&debug_port) as Arc<dyn BusDeviceSync>);
        self.address_manager
            .io_bus
            .insert(debug_port, 0x80, 0x1)
            .map_err(DeviceManagerError::BusError)?;

        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn add_legacy_devices(
        &mut self,
        interrupt_manager: &dyn InterruptManager<GroupConfig = LegacyIrqGroupConfig>,
    ) -> DeviceManagerResult<()> {
        // Add a RTC device
        let rtc_irq = self
            .address_manager
            .allocator
            .lock()
            .unwrap()
            .allocate_irq()
            .unwrap();

        let rtc_device = Arc::new(Mutex::new(devices::legacy::Rtc::new()));

        self.bus_devices
            .push(Arc::clone(&rtc_device) as Arc<dyn BusDeviceSync>);

        let addr = arch::layout::LEGACY_RTC_MAPPED_IO_START;

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
        let id = String::from(GPIO_DEVICE_NAME);
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
            state_from_id(self.snapshot.as_ref(), id.as_str())
                .map_err(DeviceManagerError::RestoreGetState)?,
        )));

        self.bus_devices
            .push(Arc::clone(&gpio_device) as Arc<dyn BusDeviceSync>);

        let addr = arch::layout::LEGACY_GPIO_MAPPED_IO_START;

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
    fn add_debug_console_device(
        &mut self,
        debug_console_writer: Box<dyn io::Write + Send>,
    ) -> DeviceManagerResult<Arc<Mutex<DebugConsole>>> {
        let id = String::from(DEBUGCON_DEVICE_NAME);
        let debug_console = Arc::new(Mutex::new(DebugConsole::new(
            id.clone(),
            debug_console_writer,
        )));

        let port = self
            .config
            .lock()
            .unwrap()
            .debug_console
            .clone()
            .iobase
            .map_or(debug_console::DEFAULT_PORT, |port| port as u64);

        self.bus_devices
            .push(Arc::clone(&debug_console) as Arc<dyn BusDeviceSync>);

        self.address_manager
            .allocator
            .lock()
            .unwrap()
            .allocate_io_addresses(Some(GuestAddress(port)), 0x1, None)
            .ok_or(DeviceManagerError::AllocateIoPort)?;

        self.address_manager
            .io_bus
            .insert(debug_console.clone(), port, 0x1)
            .map_err(DeviceManagerError::BusError)?;

        // Fill the device tree with a new node. In case of restore, we
        // know there is nothing to do, so we can simply override the
        // existing entry.
        self.device_tree
            .lock()
            .unwrap()
            .insert(id.clone(), device_node!(id, debug_console));

        Ok(debug_console)
    }

    #[cfg(target_arch = "x86_64")]
    fn add_serial_device(
        &mut self,
        interrupt_manager: &dyn InterruptManager<GroupConfig = LegacyIrqGroupConfig>,
        serial_writer: Option<Box<dyn io::Write + Send>>,
    ) -> DeviceManagerResult<Arc<Mutex<Serial>>> {
        // Serial is tied to IRQ #4
        let serial_irq = 4;

        let id = String::from(SERIAL_DEVICE_NAME);

        let interrupt_group = interrupt_manager
            .create_group(LegacyIrqGroupConfig {
                irq: serial_irq as InterruptIndex,
            })
            .map_err(DeviceManagerError::CreateInterruptGroup)?;

        let serial = Arc::new(Mutex::new(Serial::new(
            id.clone(),
            interrupt_group,
            serial_writer,
            state_from_id(self.snapshot.as_ref(), id.as_str())
                .map_err(DeviceManagerError::RestoreGetState)?,
        )));

        self.bus_devices
            .push(Arc::clone(&serial) as Arc<dyn BusDeviceSync>);

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
        interrupt_manager: &dyn InterruptManager<GroupConfig = LegacyIrqGroupConfig>,
        serial_writer: Option<Box<dyn io::Write + Send>>,
    ) -> DeviceManagerResult<Arc<Mutex<Pl011>>> {
        let id = String::from(SERIAL_DEVICE_NAME);

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
            self.timestamp,
            state_from_id(self.snapshot.as_ref(), id.as_str())
                .map_err(DeviceManagerError::RestoreGetState)?,
        )));

        self.bus_devices
            .push(Arc::clone(&serial) as Arc<dyn BusDeviceSync>);

        let addr = arch::layout::LEGACY_SERIAL_MAPPED_IO_START;

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

    #[cfg(target_arch = "riscv64")]
    fn add_serial_device(
        &mut self,
        interrupt_manager: &dyn InterruptManager<GroupConfig = LegacyIrqGroupConfig>,
        serial_writer: Option<Box<dyn io::Write + Send>>,
    ) -> DeviceManagerResult<Arc<Mutex<Serial>>> {
        let id = String::from(SERIAL_DEVICE_NAME);

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

        let serial = Arc::new(Mutex::new(Serial::new(
            id.clone(),
            interrupt_group,
            serial_writer,
            state_from_id(self.snapshot.as_ref(), id.as_str())
                .map_err(DeviceManagerError::RestoreGetState)?,
        )));

        self.bus_devices
            .push(Arc::clone(&serial) as Arc<dyn BusDeviceSync>);

        let addr = arch::layout::LEGACY_SERIAL_MAPPED_IO_START;

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
            .push(format!("earlycon=uart,mmio,0x{:08x}", addr.0));

        // Fill the device tree with a new node. In case of restore, we
        // know there is nothing to do, so we can simply override the
        // existing entry.
        self.device_tree
            .lock()
            .unwrap()
            .insert(id.clone(), device_node!(id, serial));

        Ok(serial)
    }

    fn add_virtio_console_device(
        &mut self,
        virtio_devices: &mut Vec<MetaVirtioDevice>,
        console_fd: ConsoleOutput,
        resize_pipe: Option<Arc<File>>,
    ) -> DeviceManagerResult<Option<Arc<virtio_devices::ConsoleResizer>>> {
        let console_config = self.config.lock().unwrap().console.clone();
        let endpoint = match console_fd {
            ConsoleOutput::File(file) => Endpoint::File(file),
            ConsoleOutput::Pty(file) => {
                self.console_resize_pipe = resize_pipe;
                Endpoint::PtyPair(Arc::new(file.try_clone().unwrap()), file)
            }
            ConsoleOutput::Tty(stdout) => {
                if stdout.is_terminal() {
                    self.console_resize_pipe = resize_pipe;
                }

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
                    Endpoint::FilePair(stdout, Arc::new(stdin))
                } else {
                    Endpoint::File(stdout)
                }
            }
            ConsoleOutput::Socket(_) => {
                return Err(DeviceManagerError::NoSocketOptionSupportForConsoleDevice);
            }
            ConsoleOutput::Null => Endpoint::Null,
            ConsoleOutput::Off => return Ok(None),
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
            state_from_id(self.snapshot.as_ref(), id.as_str())
                .map_err(DeviceManagerError::RestoreGetState)?,
        )
        .map_err(DeviceManagerError::CreateVirtioConsole)?;
        let virtio_console_device = Arc::new(Mutex::new(virtio_console_device));
        virtio_devices.push(MetaVirtioDevice {
            virtio_device: Arc::clone(&virtio_console_device)
                as Arc<Mutex<dyn virtio_devices::VirtioDevice>>,
            iommu: console_config.iommu,
            id: id.clone(),
            pci_segment: 0,
            dma_handler: None,
        });

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

    /// Adds all devices that behave like a console with respect to the VM
    /// configuration. This includes:
    /// - debug-console
    /// - serial-console
    /// - virtio-console
    fn add_console_devices(
        &mut self,
        interrupt_manager: &dyn InterruptManager<GroupConfig = LegacyIrqGroupConfig>,
        virtio_devices: &mut Vec<MetaVirtioDevice>,
        console_info: Option<ConsoleInfo>,
        console_resize_pipe: Option<Arc<File>>,
    ) -> DeviceManagerResult<Arc<Console>> {
        let serial_config = self.config.lock().unwrap().serial.clone();
        if console_info.is_none() {
            return Err(DeviceManagerError::InvalidConsoleInfo);
        }

        // SAFETY: console_info is Some, so it's safe to unwrap.
        let console_info = console_info.unwrap();

        let serial_writer: Option<Box<dyn io::Write + Send>> = match console_info.serial_main_fd {
            ConsoleOutput::File(ref file) | ConsoleOutput::Tty(ref file) => {
                Some(Box::new(Arc::clone(file)))
            }
            ConsoleOutput::Off
            | ConsoleOutput::Null
            | ConsoleOutput::Pty(_)
            | ConsoleOutput::Socket(_) => None,
        };

        if !matches!(console_info.serial_main_fd, ConsoleOutput::Off) {
            let serial = self.add_serial_device(interrupt_manager, serial_writer)?;
            self.serial_manager = match console_info.serial_main_fd {
                ConsoleOutput::Pty(_) | ConsoleOutput::Tty(_) | ConsoleOutput::Socket(_) => {
                    let serial_manager = SerialManager::new(
                        serial,
                        console_info.serial_main_fd,
                        serial_config.socket,
                    )
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

        #[cfg(target_arch = "x86_64")]
        {
            let debug_console_writer: Option<Box<dyn io::Write + Send>> =
                match console_info.debug_main_fd {
                    ConsoleOutput::File(file) | ConsoleOutput::Tty(file) => Some(Box::new(file)),
                    ConsoleOutput::Off
                    | ConsoleOutput::Null
                    | ConsoleOutput::Pty(_)
                    | ConsoleOutput::Socket(_) => None,
                };
            if let Some(writer) = debug_console_writer {
                let _ = self.add_debug_console_device(writer)?;
            }
        }

        let console_resizer = self.add_virtio_console_device(
            virtio_devices,
            console_info.console_main_fd,
            console_resize_pipe,
        )?;

        Ok(Arc::new(Console { console_resizer }))
    }

    #[cfg(not(target_arch = "riscv64"))]
    fn add_tpm_device(
        &mut self,
        tpm_path: PathBuf,
    ) -> DeviceManagerResult<Arc<Mutex<devices::tpm::Tpm>>> {
        // Create TPM Device
        let tpm = devices::tpm::Tpm::new(tpm_path.to_str().unwrap()).map_err(|e| {
            DeviceManagerError::CreateTpmDevice(anyhow!("Failed to create TPM Device : {e:?}"))
        })?;
        let tpm = Arc::new(Mutex::new(tpm));

        // Add TPM Device to mmio
        self.address_manager
            .mmio_bus
            .insert(
                tpm.clone(),
                arch::layout::TPM_START.0,
                arch::layout::TPM_SIZE,
            )
            .map_err(DeviceManagerError::BusError)?;

        Ok(tpm)
    }

    /// Tries to acquire advisory locks for all disk images.
    ///
    /// This should only be called when a VM boots or VM state is restored.
    /// For live-migration, the locks must be released on the destination side
    /// before they are acquired again by the receiving side.
    pub fn try_lock_disks(&self) -> DeviceManagerResult<()> {
        for dev in &self.block_devices {
            let mut dev = dev.lock().unwrap();
            dev.try_lock_image()
                .map_err(DeviceManagerError::DiskLockError)?;
        }
        Ok(())
    }

    /// Release all advisory locks held for the disk images.
    ///
    /// This should only be called when the VM is stopped and the VMM supposed
    /// to shut down. A new VMM, either after a live migration or a
    /// state save/resume cycle, should then acquire all locks before the VM
    /// starts to run.
    pub fn release_disk_locks(&self) -> DeviceManagerResult<()> {
        for dev in &self.block_devices {
            let mut dev = dev.lock().unwrap();
            dev.unlock_image()
                .map_err(DeviceManagerError::DiskLockError)?;
        }
        Ok(())
    }

    fn make_virtio_devices(&mut self) -> DeviceManagerResult<Vec<MetaVirtioDevice>> {
        let mut devices: Vec<MetaVirtioDevice> = Vec::new();

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

        // Add vDPA devices if required
        devices.append(&mut self.make_vdpa_devices()?);

        Ok(devices)
    }

    // Cache whether aio is supported to avoid checking for very block device
    fn aio_is_supported(&mut self) -> bool {
        if let Some(supported) = self.aio_supported {
            return supported;
        }

        let supported = block_aio_is_supported();
        self.aio_supported = Some(supported);
        supported
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

    /// Creates a [`MetaVirtioDevice`] from the provided [`DiskConfig`].
    ///
    /// Depending on the config, this is a [`vhost_user::Blk`] device or a [`virtio_devices::Block`]
    /// device.
    ///
    /// # Arguments
    /// - `disk_cfg`: The [`DiskConfig`] used to create the block device.
    /// - `is_hotplug`: Whether the device is being hotplugged and the lock for the disk image
    ///   should be acquired right away. Locking will only happen for normal block devices, and not
    ///   vhost-user devices.
    fn make_virtio_block_device(
        &mut self,
        disk_cfg: &mut DiskConfig,
        is_hotplug: bool,
    ) -> DeviceManagerResult<MetaVirtioDevice> {
        let id = if let Some(id) = &disk_cfg.id {
            id.clone()
        } else {
            let id = self.next_device_name(DISK_DEVICE_NAME_PREFIX)?;
            disk_cfg.id = Some(id.clone());
            id
        };

        info!("Creating virtio-block device: {disk_cfg:?}");

        let (virtio_device, migratable_device) = if disk_cfg.vhost_user {
            if is_hotplug {
                debug!("Acquiring image lock for vhost-user block device not supported");
            }
            let socket = disk_cfg.vhost_socket.as_ref().unwrap().clone();
            let vu_cfg = VhostUserConfig {
                socket,
                num_queues: disk_cfg.num_queues,
                queue_size: disk_cfg.queue_size,
            };
            let vhost_user_block = Arc::new(Mutex::new(
                match virtio_devices::vhost_user::Blk::new(
                    id.clone(),
                    vu_cfg,
                    self.seccomp_action.clone(),
                    self.exit_evt
                        .try_clone()
                        .map_err(DeviceManagerError::EventFd)?,
                    self.force_iommu,
                    state_from_id(self.snapshot.as_ref(), id.as_str())
                        .map_err(DeviceManagerError::RestoreGetState)?,
                ) {
                    Ok(vub_device) => vub_device,
                    Err(e) => {
                        return Err(DeviceManagerError::CreateVhostUserBlk(e));
                    }
                },
            ));

            (
                Arc::clone(&vhost_user_block) as Arc<Mutex<dyn virtio_devices::VirtioDevice>>,
                vhost_user_block as Arc<Mutex<dyn Migratable>>,
            )
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
                    if cfg!(feature = "io_uring")
                        && !disk_cfg.disable_io_uring
                        && self.io_uring_is_supported()
                    {
                        info!("Using asynchronous fixed VHD disk file (io_uring)");

                        #[cfg(not(feature = "io_uring"))]
                        unreachable!("Checked in if statement above");
                        #[cfg(feature = "io_uring")]
                        {
                            Box::new(
                                FixedVhdDiskAsync::new(file)
                                    .map_err(DeviceManagerError::CreateFixedVhdDiskAsync)?,
                            ) as Box<dyn DiskFile>
                        }
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
                    if cfg!(feature = "io_uring")
                        && !disk_cfg.disable_io_uring
                        && self.io_uring_is_supported()
                    {
                        info!("Using asynchronous RAW disk file (io_uring)");

                        #[cfg(not(feature = "io_uring"))]
                        unreachable!("Checked in if statement above");
                        #[cfg(feature = "io_uring")]
                        {
                            Box::new(RawFileDisk::new(file)) as Box<dyn DiskFile>
                        }
                    } else if !disk_cfg.disable_aio && self.aio_is_supported() {
                        info!("Using asynchronous RAW disk file (aio)");
                        Box::new(RawFileDiskAio::new(file)) as Box<dyn DiskFile>
                    } else {
                        info!("Using synchronous RAW disk file");
                        Box::new(RawFileDiskSync::new(file)) as Box<dyn DiskFile>
                    }
                }
                ImageType::Qcow2 => {
                    info!("Using synchronous QCOW2 disk file");
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

            let rate_limit_group =
                if let Some(rate_limiter_cfg) = disk_cfg.rate_limiter_config.as_ref() {
                    // Create an anonymous RateLimiterGroup that is dropped when the Disk
                    // is dropped.
                    let bw = rate_limiter_cfg.bandwidth.unwrap_or_default();
                    let ops = rate_limiter_cfg.ops.unwrap_or_default();
                    let mut rate_limit_group = RateLimiterGroup::new(
                        disk_cfg.id.as_ref().unwrap(),
                        bw.size,
                        bw.one_time_burst.unwrap_or(0),
                        bw.refill_time,
                        ops.size,
                        ops.one_time_burst.unwrap_or(0),
                        ops.refill_time,
                    )
                    .map_err(DeviceManagerError::RateLimiterGroupCreate)?;

                    rate_limit_group
                        .start_thread(
                            self.exit_evt
                                .try_clone()
                                .map_err(DeviceManagerError::EventFd)?,
                        )
                        .unwrap();

                    Some(Arc::new(rate_limit_group))
                } else if let Some(rate_limit_group) = disk_cfg.rate_limit_group.as_ref() {
                    self.rate_limit_groups.get(rate_limit_group).cloned()
                } else {
                    None
                };

            let queue_affinity = if let Some(queue_affinity) = disk_cfg.queue_affinity.as_ref() {
                queue_affinity
                    .iter()
                    .map(|a| (a.queue_index, a.host_cpus.clone()))
                    .collect()
            } else {
                BTreeMap::new()
            };

            let mut virtio_block = virtio_devices::Block::new(
                id.clone(),
                image,
                disk_cfg
                    .path
                    .as_ref()
                    .ok_or(DeviceManagerError::NoDiskPath)?
                    .clone(),
                disk_cfg.readonly,
                self.force_iommu | disk_cfg.iommu,
                disk_cfg.sparse,
                disk_cfg.num_queues,
                disk_cfg.queue_size,
                disk_cfg.serial.clone(),
                self.seccomp_action.clone(),
                rate_limit_group,
                self.exit_evt
                    .try_clone()
                    .map_err(DeviceManagerError::EventFd)?,
                state_from_id(self.snapshot.as_ref(), id.as_str())
                    .map_err(DeviceManagerError::RestoreGetState)?,
                queue_affinity,
            )
            .map_err(DeviceManagerError::CreateVirtioBlock)?;

            // We lock the file here only for hotplugging. In normal operation,
            // state save/resume, and live-migration, locking is part of the outer control flow
            // to ensure proper order of (un)locking.
            if is_hotplug {
                debug!("Acquiring lock for hotplugged image");
                virtio_block
                    .try_lock_image()
                    .map_err(DeviceManagerError::DiskLockError)?;
            }

            let virtio_block = Arc::new(Mutex::new(virtio_block));

            self.block_devices.push(virtio_block.clone());

            (
                Arc::clone(&virtio_block) as Arc<Mutex<dyn virtio_devices::VirtioDevice>>,
                virtio_block as Arc<Mutex<dyn Migratable>>,
            )
        };

        // Fill the device tree with a new node. In case of restore, we
        // know there is nothing to do, so we can simply override the
        // existing entry.
        self.device_tree
            .lock()
            .unwrap()
            .insert(id.clone(), device_node!(id, migratable_device));

        Ok(MetaVirtioDevice {
            virtio_device,
            iommu: disk_cfg.iommu,
            id,
            pci_segment: disk_cfg.pci_segment,
            dma_handler: None,
        })
    }

    fn make_virtio_block_devices(&mut self) -> DeviceManagerResult<Vec<MetaVirtioDevice>> {
        let mut devices = Vec::new();

        let mut block_devices = self.config.lock().unwrap().disks.clone();
        if let Some(disk_list_cfg) = &mut block_devices {
            for disk_cfg in disk_list_cfg.iter_mut() {
                devices.push(self.make_virtio_block_device(disk_cfg, false)?);
            }
        }
        self.config.lock().unwrap().disks = block_devices;

        Ok(devices)
    }

    fn make_virtio_net_device(
        &mut self,
        net_cfg: &mut NetConfig,
    ) -> DeviceManagerResult<MetaVirtioDevice> {
        let id = if let Some(id) = &net_cfg.id {
            id.clone()
        } else {
            let id = self.next_device_name(NET_DEVICE_NAME_PREFIX)?;
            net_cfg.id = Some(id.clone());
            id
        };
        info!("Creating virtio-net device: {net_cfg:?}");

        let (virtio_device, migratable_device) = if net_cfg.vhost_user {
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
            let vhost_user_net = Arc::new(Mutex::new(
                match virtio_devices::vhost_user::Net::new(
                    id.clone(),
                    net_cfg.mac,
                    net_cfg.mtu,
                    vu_cfg,
                    server,
                    self.seccomp_action.clone(),
                    self.exit_evt
                        .try_clone()
                        .map_err(DeviceManagerError::EventFd)?,
                    self.force_iommu,
                    state_from_id(self.snapshot.as_ref(), id.as_str())
                        .map_err(DeviceManagerError::RestoreGetState)?,
                    net_cfg.offload_tso,
                    net_cfg.offload_ufo,
                    net_cfg.offload_csum,
                ) {
                    Ok(vun_device) => vun_device,
                    Err(e) => {
                        return Err(DeviceManagerError::CreateVhostUserNet(e));
                    }
                },
            ));

            (
                Arc::clone(&vhost_user_net) as Arc<Mutex<dyn virtio_devices::VirtioDevice>>,
                vhost_user_net as Arc<Mutex<dyn Migratable>>,
            )
        } else {
            let state = state_from_id(self.snapshot.as_ref(), id.as_str())
                .map_err(DeviceManagerError::RestoreGetState)?;
            let virtio_net = if let Some(ref tap_if_name) = net_cfg.tap {
                Arc::new(Mutex::new(
                    virtio_devices::Net::new(
                        id.clone(),
                        Some(tap_if_name),
                        net_cfg.ip,
                        net_cfg.mask,
                        Some(net_cfg.mac),
                        &mut net_cfg.host_mac,
                        net_cfg.mtu,
                        self.force_iommu | net_cfg.iommu,
                        net_cfg.num_queues,
                        net_cfg.queue_size,
                        self.seccomp_action.clone(),
                        net_cfg.rate_limiter_config,
                        self.exit_evt
                            .try_clone()
                            .map_err(DeviceManagerError::EventFd)?,
                        state,
                        net_cfg.offload_tso,
                        net_cfg.offload_ufo,
                        net_cfg.offload_csum,
                    )
                    .map_err(DeviceManagerError::CreateVirtioNet)?,
                ))
            } else if let Some(fds) = &net_cfg.fds {
                let net = virtio_devices::Net::from_tap_fds(
                    id.clone(),
                    fds,
                    Some(net_cfg.mac),
                    net_cfg.mtu,
                    self.force_iommu | net_cfg.iommu,
                    net_cfg.queue_size,
                    self.seccomp_action.clone(),
                    net_cfg.rate_limiter_config,
                    self.exit_evt
                        .try_clone()
                        .map_err(DeviceManagerError::EventFd)?,
                    state,
                    net_cfg.offload_tso,
                    net_cfg.offload_ufo,
                    net_cfg.offload_csum,
                )
                .map_err(DeviceManagerError::CreateVirtioNet)?;

                // SAFETY: 'fds' are valid because TAP devices are created successfully
                unsafe {
                    self.config.lock().unwrap().add_preserved_fds(fds.clone());
                }

                Arc::new(Mutex::new(net))
            } else {
                Arc::new(Mutex::new(
                    virtio_devices::Net::new(
                        id.clone(),
                        None,
                        net_cfg.ip,
                        net_cfg.mask,
                        Some(net_cfg.mac),
                        &mut net_cfg.host_mac,
                        net_cfg.mtu,
                        self.force_iommu | net_cfg.iommu,
                        net_cfg.num_queues,
                        net_cfg.queue_size,
                        self.seccomp_action.clone(),
                        net_cfg.rate_limiter_config,
                        self.exit_evt
                            .try_clone()
                            .map_err(DeviceManagerError::EventFd)?,
                        state,
                        net_cfg.offload_tso,
                        net_cfg.offload_ufo,
                        net_cfg.offload_csum,
                    )
                    .map_err(DeviceManagerError::CreateVirtioNet)?,
                ))
            };

            (
                Arc::clone(&virtio_net) as Arc<Mutex<dyn virtio_devices::VirtioDevice>>,
                virtio_net as Arc<Mutex<dyn Migratable>>,
            )
        };

        // Fill the device tree with a new node. In case of restore, we
        // know there is nothing to do, so we can simply override the
        // existing entry.
        self.device_tree
            .lock()
            .unwrap()
            .insert(id.clone(), device_node!(id, migratable_device));

        Ok(MetaVirtioDevice {
            virtio_device,
            iommu: net_cfg.iommu,
            id,
            pci_segment: net_cfg.pci_segment,
            dma_handler: None,
        })
    }

    /// Add virto-net and vhost-user-net devices
    fn make_virtio_net_devices(&mut self) -> DeviceManagerResult<Vec<MetaVirtioDevice>> {
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

    fn make_virtio_rng_devices(&mut self) -> DeviceManagerResult<Vec<MetaVirtioDevice>> {
        let mut devices = Vec::new();

        // Add virtio-rng if required
        let rng_config = self.config.lock().unwrap().rng.clone();
        if let Some(rng_path) = rng_config.src.to_str() {
            info!("Creating virtio-rng device: {rng_config:?}");
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
                    state_from_id(self.snapshot.as_ref(), id.as_str())
                        .map_err(DeviceManagerError::RestoreGetState)?,
                )
                .map_err(DeviceManagerError::CreateVirtioRng)?,
            ));
            devices.push(MetaVirtioDevice {
                virtio_device: Arc::clone(&virtio_rng_device)
                    as Arc<Mutex<dyn virtio_devices::VirtioDevice>>,
                iommu: rng_config.iommu,
                id: id.clone(),
                pci_segment: 0,
                dma_handler: None,
            });

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
    ) -> DeviceManagerResult<MetaVirtioDevice> {
        let id = if let Some(id) = &fs_cfg.id {
            id.clone()
        } else {
            let id = self.next_device_name(FS_DEVICE_NAME_PREFIX)?;
            fs_cfg.id = Some(id.clone());
            id
        };

        info!("Creating virtio-fs device: {fs_cfg:?}");

        let mut node = device_node!(id);

        if let Some(fs_socket) = fs_cfg.socket.to_str() {
            let virtio_fs_device = Arc::new(Mutex::new(
                virtio_devices::vhost_user::Fs::new(
                    id.clone(),
                    fs_socket,
                    &fs_cfg.tag,
                    fs_cfg.num_queues,
                    fs_cfg.queue_size,
                    None,
                    self.seccomp_action.clone(),
                    self.exit_evt
                        .try_clone()
                        .map_err(DeviceManagerError::EventFd)?,
                    self.force_iommu,
                    state_from_id(self.snapshot.as_ref(), id.as_str())
                        .map_err(DeviceManagerError::RestoreGetState)?,
                )
                .map_err(DeviceManagerError::CreateVirtioFs)?,
            ));

            // Update the device tree with the migratable device.
            node.migratable = Some(Arc::clone(&virtio_fs_device) as Arc<Mutex<dyn Migratable>>);
            self.device_tree.lock().unwrap().insert(id.clone(), node);

            Ok(MetaVirtioDevice {
                virtio_device: Arc::clone(&virtio_fs_device)
                    as Arc<Mutex<dyn virtio_devices::VirtioDevice>>,
                iommu: false,
                id,
                pci_segment: fs_cfg.pci_segment,
                dma_handler: None,
            })
        } else {
            Err(DeviceManagerError::NoVirtioFsSock)
        }
    }

    fn make_virtio_fs_devices(&mut self) -> DeviceManagerResult<Vec<MetaVirtioDevice>> {
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
    ) -> DeviceManagerResult<MetaVirtioDevice> {
        let id = if let Some(id) = &pmem_cfg.id {
            id.clone()
        } else {
            let id = self.next_device_name(PMEM_DEVICE_NAME_PREFIX)?;
            pmem_cfg.id = Some(id.clone());
            id
        };

        info!("Creating virtio-pmem device: {pmem_cfg:?}");

        let mut node = device_node!(id);

        // Look for the id in the device tree. If it can be found, that means
        // the device is being restored, otherwise it's created from scratch.
        let region_range = if let Some(node) = self.device_tree.lock().unwrap().get(&id) {
            info!("Restoring virtio-pmem {id} resources");

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
                        error!("Unexpected resource {resource:?} for {id}");
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
            self.pci_segments[pmem_cfg.pci_segment as usize]
                .mem64_allocator
                .lock()
                .unwrap()
                .allocate(
                    Some(GuestAddress(base)),
                    size as GuestUsize,
                    Some(0x0020_0000),
                )
                .ok_or(DeviceManagerError::PmemRangeAllocation)?;

            (base, size)
        } else {
            // The memory needs to be 2MiB aligned in order to support
            // hugepages.
            let base = self.pci_segments[pmem_cfg.pci_segment as usize]
                .mem64_allocator
                .lock()
                .unwrap()
                .allocate(None, size as GuestUsize, Some(0x0020_0000))
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
        let host_addr = mmap_region.as_ptr();

        // SAFETY: host_addr points to region_size bytes of mmap-allocated memory.
        let mem_slot = unsafe {
            let region_size = region_size.try_into().unwrap();
            self.memory_manager
                .lock()
                .unwrap()
                .create_userspace_mapping(region_base, region_size, host_addr, false, false, false)
                .map_err(DeviceManagerError::MemoryManager)
        }?;

        let mapping = UserspaceMapping {
            mem_slot,
            addr: GuestAddress(region_base),
            mapping: Arc::new(mmap_region),
            mergeable: false,
        };

        let virtio_pmem_device = Arc::new(Mutex::new(
            virtio_devices::Pmem::new(
                id.clone(),
                file,
                GuestAddress(region_base),
                mapping,
                self.force_iommu | pmem_cfg.iommu,
                self.seccomp_action.clone(),
                self.exit_evt
                    .try_clone()
                    .map_err(DeviceManagerError::EventFd)?,
                state_from_id(self.snapshot.as_ref(), id.as_str())
                    .map_err(DeviceManagerError::RestoreGetState)?,
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

        Ok(MetaVirtioDevice {
            virtio_device: Arc::clone(&virtio_pmem_device)
                as Arc<Mutex<dyn virtio_devices::VirtioDevice>>,
            iommu: pmem_cfg.iommu,
            id,
            pci_segment: pmem_cfg.pci_segment,
            dma_handler: None,
        })
    }

    fn make_virtio_pmem_devices(&mut self) -> DeviceManagerResult<Vec<MetaVirtioDevice>> {
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
    ) -> DeviceManagerResult<MetaVirtioDevice> {
        let id = if let Some(id) = &vsock_cfg.id {
            id.clone()
        } else {
            let id = self.next_device_name(VSOCK_DEVICE_NAME_PREFIX)?;
            vsock_cfg.id = Some(id.clone());
            id
        };

        info!("Creating virtio-vsock device: {vsock_cfg:?}");

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
                state_from_id(self.snapshot.as_ref(), id.as_str())
                    .map_err(DeviceManagerError::RestoreGetState)?,
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

        Ok(MetaVirtioDevice {
            virtio_device: Arc::clone(&vsock_device)
                as Arc<Mutex<dyn virtio_devices::VirtioDevice>>,
            iommu: vsock_cfg.iommu,
            id,
            pci_segment: vsock_cfg.pci_segment,
            dma_handler: None,
        })
    }

    fn make_virtio_vsock_devices(&mut self) -> DeviceManagerResult<Vec<MetaVirtioDevice>> {
        let mut devices = Vec::new();

        let mut vsock = self.config.lock().unwrap().vsock.clone();
        if let Some(vsock_cfg) = &mut vsock {
            devices.push(self.make_virtio_vsock_device(vsock_cfg)?);
        }
        self.config.lock().unwrap().vsock = vsock;

        Ok(devices)
    }

    fn make_virtio_mem_devices(&mut self) -> DeviceManagerResult<Vec<MetaVirtioDevice>> {
        let mut devices = Vec::new();

        let mm = self.memory_manager.clone();
        let mut mm = mm.lock().unwrap();
        for (memory_zone_id, memory_zone) in mm.memory_zones_mut().iter_mut() {
            if let Some(virtio_mem_zone) = memory_zone.virtio_mem_zone_mut() {
                info!("Creating virtio-mem device: id = {memory_zone_id}");

                let node_id = numa_node_id_from_memory_zone_id(&self.numa_nodes, memory_zone_id)
                    .map(|i| i as u16);

                let virtio_mem_device = Arc::new(Mutex::new(
                    virtio_devices::Mem::new(
                        memory_zone_id.clone(),
                        virtio_mem_zone.region(),
                        self.seccomp_action.clone(),
                        node_id,
                        virtio_mem_zone.hotplugged_size(),
                        virtio_mem_zone.hugepages(),
                        self.exit_evt
                            .try_clone()
                            .map_err(DeviceManagerError::EventFd)?,
                        virtio_mem_zone.blocks_state().clone(),
                        state_from_id(self.snapshot.as_ref(), memory_zone_id.as_str())
                            .map_err(DeviceManagerError::RestoreGetState)?,
                    )
                    .map_err(DeviceManagerError::CreateVirtioMem)?,
                ));

                // Update the virtio-mem zone so that it has a handle onto the
                // virtio-mem device, which will be used for triggering a resize
                // if needed.
                virtio_mem_zone.set_virtio_device(Arc::clone(&virtio_mem_device));

                self.virtio_mem_devices.push(Arc::clone(&virtio_mem_device));

                devices.push(MetaVirtioDevice {
                    virtio_device: Arc::clone(&virtio_mem_device)
                        as Arc<Mutex<dyn virtio_devices::VirtioDevice>>,
                    iommu: false,
                    id: memory_zone_id.clone(),
                    pci_segment: 0,
                    dma_handler: None,
                });

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

    #[cfg(feature = "pvmemcontrol")]
    fn make_pvmemcontrol_device(
        &mut self,
    ) -> DeviceManagerResult<(
        Arc<PvmemcontrolBusDevice>,
        Arc<Mutex<PvmemcontrolPciDevice>>,
    )> {
        let id = String::from(PVMEMCONTROL_DEVICE_NAME);
        let pci_segment_id = 0x0_u16;

        let (pci_segment_id, pci_device_bdf, resources) =
            self.pci_resources(&id, pci_segment_id)?;

        info!("Creating pvmemcontrol device: id = {id}");
        let (pvmemcontrol_pci_device, pvmemcontrol_bus_device) =
            devices::pvmemcontrol::PvmemcontrolDevice::make_device(
                id.clone(),
                self.memory_manager.lock().unwrap().guest_memory(),
            );

        let pvmemcontrol_pci_device = Arc::new(Mutex::new(pvmemcontrol_pci_device));
        let pvmemcontrol_bus_device = Arc::new(pvmemcontrol_bus_device);

        let new_resources = self.add_pci_device(
            pvmemcontrol_bus_device.clone(),
            pvmemcontrol_pci_device.clone(),
            pci_segment_id,
            pci_device_bdf,
            resources,
        )?;

        let mut node = device_node!(id, pvmemcontrol_pci_device);

        node.resources = new_resources;
        node.pci_bdf = Some(pci_device_bdf);
        node.pci_device_handle = None;

        self.device_tree.lock().unwrap().insert(id, node);

        Ok((pvmemcontrol_bus_device, pvmemcontrol_pci_device))
    }

    fn make_virtio_balloon_devices(&mut self) -> DeviceManagerResult<Vec<MetaVirtioDevice>> {
        let mut devices = Vec::new();

        if let Some(balloon_config) = &self.config.lock().unwrap().balloon {
            let id = String::from(BALLOON_DEVICE_NAME);
            info!("Creating virtio-balloon device: id = {id}");

            let virtio_balloon_device = Arc::new(Mutex::new(
                virtio_devices::Balloon::new(
                    id.clone(),
                    balloon_config.size,
                    balloon_config.deflate_on_oom,
                    balloon_config.free_page_reporting,
                    self.seccomp_action.clone(),
                    self.exit_evt
                        .try_clone()
                        .map_err(DeviceManagerError::EventFd)?,
                    state_from_id(self.snapshot.as_ref(), id.as_str())
                        .map_err(DeviceManagerError::RestoreGetState)?,
                )
                .map_err(DeviceManagerError::CreateVirtioBalloon)?,
            ));

            self.balloon = Some(virtio_balloon_device.clone());

            devices.push(MetaVirtioDevice {
                virtio_device: Arc::clone(&virtio_balloon_device)
                    as Arc<Mutex<dyn virtio_devices::VirtioDevice>>,
                iommu: false,
                id: id.clone(),
                pci_segment: 0,
                dma_handler: None,
            });

            self.device_tree
                .lock()
                .unwrap()
                .insert(id.clone(), device_node!(id, virtio_balloon_device));
        }

        Ok(devices)
    }

    fn make_virtio_watchdog_devices(&mut self) -> DeviceManagerResult<Vec<MetaVirtioDevice>> {
        let mut devices = Vec::new();

        if !self.config.lock().unwrap().watchdog {
            return Ok(devices);
        }

        let id = String::from(WATCHDOG_DEVICE_NAME);
        info!("Creating virtio-watchdog device: id = {id}");

        let virtio_watchdog_device = Arc::new(Mutex::new(
            virtio_devices::Watchdog::new(
                id.clone(),
                self.reset_evt.try_clone().unwrap(),
                self.seccomp_action.clone(),
                self.exit_evt
                    .try_clone()
                    .map_err(DeviceManagerError::EventFd)?,
                state_from_id(self.snapshot.as_ref(), id.as_str())
                    .map_err(DeviceManagerError::RestoreGetState)?,
            )
            .map_err(DeviceManagerError::CreateVirtioWatchdog)?,
        ));
        devices.push(MetaVirtioDevice {
            virtio_device: Arc::clone(&virtio_watchdog_device)
                as Arc<Mutex<dyn virtio_devices::VirtioDevice>>,
            iommu: false,
            id: id.clone(),
            pci_segment: 0,
            dma_handler: None,
        });

        self.device_tree
            .lock()
            .unwrap()
            .insert(id.clone(), device_node!(id, virtio_watchdog_device));

        Ok(devices)
    }

    fn make_vdpa_device(
        &mut self,
        vdpa_cfg: &mut VdpaConfig,
    ) -> DeviceManagerResult<MetaVirtioDevice> {
        let id = if let Some(id) = &vdpa_cfg.id {
            id.clone()
        } else {
            let id = self.next_device_name(VDPA_DEVICE_NAME_PREFIX)?;
            vdpa_cfg.id = Some(id.clone());
            id
        };

        info!("Creating vDPA device: {vdpa_cfg:?}");

        let device_path = vdpa_cfg
            .path
            .to_str()
            .ok_or(DeviceManagerError::CreateVdpaConvertPath)?;

        let vdpa_device = Arc::new(Mutex::new(
            virtio_devices::Vdpa::new(
                id.clone(),
                device_path,
                self.memory_manager.lock().unwrap().guest_memory(),
                vdpa_cfg.num_queues as u16,
                state_from_id(self.snapshot.as_ref(), id.as_str())
                    .map_err(DeviceManagerError::RestoreGetState)?,
            )
            .map_err(DeviceManagerError::CreateVdpa)?,
        ));

        // Create the DMA handler that is required by the vDPA device
        let vdpa_mapping = Arc::new(VdpaDmaMapping::new(
            Arc::clone(&vdpa_device),
            Arc::new(self.memory_manager.lock().unwrap().guest_memory()),
        ));

        self.device_tree
            .lock()
            .unwrap()
            .insert(id.clone(), device_node!(id, vdpa_device));

        Ok(MetaVirtioDevice {
            virtio_device: vdpa_device as Arc<Mutex<dyn virtio_devices::VirtioDevice>>,
            iommu: vdpa_cfg.iommu,
            id,
            pci_segment: vdpa_cfg.pci_segment,
            dma_handler: Some(vdpa_mapping),
        })
    }

    fn make_vdpa_devices(&mut self) -> DeviceManagerResult<Vec<MetaVirtioDevice>> {
        let mut devices = Vec::new();
        // Add vdpa if required
        let mut vdpa_devices = self.config.lock().unwrap().vdpa.clone();
        if let Some(vdpa_list_cfg) = &mut vdpa_devices {
            for vdpa_cfg in vdpa_list_cfg.iter_mut() {
                devices.push(self.make_vdpa_device(vdpa_cfg)?);
            }
        }
        self.config.lock().unwrap().vdpa = vdpa_devices;

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
            if !self.boot_id_list.contains(&name)
                && !self.device_tree.lock().unwrap().contains_key(&name)
            {
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

    fn create_vfio_container(&self) -> DeviceManagerResult<Arc<VfioContainer>> {
        let passthrough_device = self
            .passthrough_device
            .as_ref()
            .ok_or(DeviceManagerError::NoDevicePassthroughSupport)?;

        let dup = passthrough_device
            .try_clone()
            .map_err(DeviceManagerError::VfioCreate)?;

        Ok(Arc::new(
            VfioContainer::new(Some(Arc::new(dup))).map_err(DeviceManagerError::VfioCreate)?,
        ))
    }

    fn add_vfio_device(
        &mut self,
        device_cfg: &mut DeviceConfig,
    ) -> DeviceManagerResult<(PciBdf, String)> {
        let vfio_name = if let Some(id) = &device_cfg.id {
            id.clone()
        } else {
            let id = self.next_device_name(VFIO_DEVICE_NAME_PREFIX)?;
            device_cfg.id = Some(id.clone());
            id
        };

        let (pci_segment_id, pci_device_bdf, resources) =
            self.pci_resources(&vfio_name, device_cfg.pci_segment)?;

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
                Arc::clone(&self.mmio_regions),
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
                    // vfio_dma_map is unsound and ought to be marked as unsafe
                    #[allow(unused_unsafe)]
                    // SAFETY: GuestMemoryMmap guarantees that region points
                    // to len bytes of valid memory starting at as_ptr()
                    // that will only be freed with munmap().
                    unsafe {
                        vfio_container.vfio_dma_map(
                            region.start_addr().raw_value(),
                            region.len(),
                            region.as_ptr() as u64,
                        )
                    }
                    .map_err(DeviceManagerError::VfioDmaMap)?;
                }
            }

            let vfio_mapping = Arc::new(VfioDmaMapping::new(
                Arc::clone(&vfio_container),
                Arc::new(self.memory_manager.lock().unwrap().guest_memory()),
                Arc::clone(&self.mmio_regions),
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

        let memory_manager = self.memory_manager.clone();

        let vfio_pci_device = VfioPciDevice::new(
            vfio_name.clone(),
            self.address_manager.vm.clone(),
            vfio_device,
            vfio_container,
            self.msi_interrupt_manager.clone(),
            legacy_interrupt_group,
            device_cfg.iommu,
            pci_device_bdf,
            memory_manager.lock().unwrap().memory_slot_allocator(),
            vm_migration::snapshot_from_id(self.snapshot.as_ref(), vfio_name.as_str()),
            device_cfg.x_nv_gpudirect_clique,
            device_cfg.path.clone(),
        )
        .map_err(DeviceManagerError::VfioPciCreate)?;

        let vfio_pci_device = Arc::new(Mutex::new(vfio_pci_device));

        let new_resources = self.add_pci_device(
            vfio_pci_device.clone(),
            vfio_pci_device.clone(),
            pci_segment_id,
            pci_device_bdf,
            resources,
        )?;

        vfio_pci_device
            .lock()
            .unwrap()
            .map_mmio_regions()
            .map_err(DeviceManagerError::VfioMapRegion)?;

        for mmio_region in vfio_pci_device.lock().unwrap().mmio_regions() {
            self.mmio_regions.lock().unwrap().push(mmio_region);
        }

        let mut node = device_node!(vfio_name, vfio_pci_device);

        // Update the device tree with correct resource information.
        node.resources = new_resources;
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
        bus_device: Arc<dyn BusDeviceSync>,
        pci_device: Arc<Mutex<dyn PciDevice>>,
        segment_id: u16,
        bdf: PciBdf,
        resources: Option<Vec<Resource>>,
    ) -> DeviceManagerResult<Vec<Resource>> {
        let bars = pci_device
            .lock()
            .unwrap()
            .allocate_bars(
                &self.address_manager.allocator,
                &mut self.pci_segments[segment_id as usize]
                    .mem32_allocator
                    .lock()
                    .unwrap(),
                &mut self.pci_segments[segment_id as usize]
                    .mem64_allocator
                    .lock()
                    .unwrap(),
                resources,
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
                self.address_manager.io_bus.as_ref(),
                self.address_manager.mmio_bus.as_ref(),
                bars.clone(),
            )
            .map_err(DeviceManagerError::AddPciDevice)?;

        let mut new_resources = Vec::new();
        for bar in bars {
            new_resources.push(Resource::PciBar {
                index: bar.idx(),
                base: bar.addr(),
                size: bar.size(),
                type_: bar.region_type().into(),
                prefetchable: bar.prefetchable().into(),
            });
        }

        Ok(new_resources)
    }

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

    fn add_vfio_user_device(
        &mut self,
        device_cfg: &mut UserDeviceConfig,
    ) -> DeviceManagerResult<(PciBdf, String)> {
        let vfio_user_name = if let Some(id) = &device_cfg.id {
            id.clone()
        } else {
            let id = self.next_device_name(VFIO_USER_DEVICE_NAME_PREFIX)?;
            device_cfg.id = Some(id.clone());
            id
        };

        let (pci_segment_id, pci_device_bdf, resources) =
            self.pci_resources(&vfio_user_name, device_cfg.pci_segment)?;

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

        let memory_manager = self.memory_manager.clone();

        let mut vfio_user_pci_device = VfioUserPciDevice::new(
            vfio_user_name.clone(),
            self.address_manager.vm.clone(),
            client.clone(),
            self.msi_interrupt_manager.clone(),
            legacy_interrupt_group,
            pci_device_bdf,
            memory_manager.lock().unwrap().memory_slot_allocator(),
            vm_migration::snapshot_from_id(self.snapshot.as_ref(), vfio_user_name.as_str()),
        )
        .map_err(DeviceManagerError::VfioUserCreate)?;

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

        let new_resources = self.add_pci_device(
            vfio_user_pci_device.clone(),
            vfio_user_pci_device.clone(),
            pci_segment_id,
            pci_device_bdf,
            resources,
        )?;

        // Note it is required to call 'add_pci_device()' in advance to have the list of
        // mmio regions provisioned correctly
        vfio_user_pci_device
            .lock()
            .unwrap()
            .map_mmio_regions()
            .map_err(DeviceManagerError::VfioUserMapRegion)?;

        let mut node = device_node!(vfio_user_name, vfio_user_pci_device);

        // Update the device tree with correct resource information.
        node.resources = new_resources;
        node.pci_bdf = Some(pci_device_bdf);
        node.pci_device_handle = Some(PciDeviceHandle::VfioUser(vfio_user_pci_device));

        self.device_tree
            .lock()
            .unwrap()
            .insert(vfio_user_name.clone(), node);

        Ok((pci_device_bdf, vfio_user_name))
    }

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

    fn add_virtio_pci_device(
        &mut self,
        virtio_device: Arc<Mutex<dyn virtio_devices::VirtioDevice>>,
        iommu_mapping: &Option<Arc<IommuMapping>>,
        virtio_device_id: String,
        pci_segment_id: u16,
        dma_handler: Option<Arc<dyn ExternalDmaMapping>>,
    ) -> DeviceManagerResult<PciBdf> {
        let id = format!("{VIRTIO_PCI_DEVICE_NAME_PREFIX}-{virtio_device_id}");

        // Add the new virtio-pci node to the device tree.
        let mut node = device_node!(id);
        node.children = vec![virtio_device_id.clone()];

        let (pci_segment_id, pci_device_bdf, resources) =
            self.pci_resources(&id, pci_segment_id)?;

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
        let mut access_platform: Option<Arc<dyn AccessPlatform>> = None;

        if let Some(mapping) = iommu_mapping {
            access_platform = Some(Arc::new(AccessPlatformMapping::new(
                pci_device_bdf.into(),
                mapping.clone(),
            )));
        }

        // If SEV-SNP is enabled create the AccessPlatform from SevSnpPageAccessProxy
        #[cfg(feature = "sev_snp")]
        if self.config.lock().unwrap().is_sev_snp_enabled() {
            access_platform = Some(Arc::new(SevSnpPageAccessProxy::new(
                self.address_manager.vm.clone(),
            )));
        }

        let memory = self.memory_manager.lock().unwrap().guest_memory();

        // Map DMA ranges if a DMA handler is available and if the device is
        // not attached to a virtual IOMMU.
        if let Some(dma_handler) = &dma_handler {
            if iommu_mapping.is_some() {
                if let Some(iommu) = &self.iommu_device {
                    iommu
                        .lock()
                        .unwrap()
                        .add_external_mapping(pci_device_bdf.into(), dma_handler.clone());
                } else {
                    return Err(DeviceManagerError::MissingVirtualIommu);
                }
            } else {
                // Let every virtio-mem device handle the DMA map/unmap through the
                // DMA handler provided.
                for virtio_mem_device in self.virtio_mem_devices.iter() {
                    virtio_mem_device
                        .lock()
                        .unwrap()
                        .add_dma_mapping_handler(
                            VirtioMemMappingSource::Device(pci_device_bdf.into()),
                            dma_handler.clone(),
                        )
                        .map_err(DeviceManagerError::AddDmaMappingHandlerVirtioMem)?;
                }

                // Do not register virtio-mem regions, as they are handled directly by
                // virtio-mem devices.
                for (_, zone) in self.memory_manager.lock().unwrap().memory_zones().iter() {
                    for region in zone.regions() {
                        let gpa = region.start_addr().0;
                        let size = region.len();
                        dma_handler
                            .map(gpa, gpa, size)
                            .map_err(DeviceManagerError::VirtioDmaMap)?;
                    }
                }
            }
        }

        let device_type = virtio_device.lock().unwrap().device_type();
        let virtio_pci_device = Arc::new(Mutex::new(
            VirtioPciDevice::new(
                id.clone(),
                memory,
                virtio_device,
                msix_num,
                access_platform,
                self.msi_interrupt_manager.as_ref(),
                pci_device_bdf.into(),
                self.activate_evt
                    .try_clone()
                    .map_err(DeviceManagerError::EventFd)?,
                // All device types *except* virtio block devices should be allocated a 64-bit bar
                // The block devices should be given a 32-bit BAR so that they are easily accessible
                // to firmware without requiring excessive identity mapping.
                // The exception being if not on the default PCI segment.
                pci_segment_id > 0 || device_type != VirtioDeviceType::Block as u32,
                dma_handler,
                self.pending_activations.clone(),
                vm_migration::snapshot_from_id(self.snapshot.as_ref(), id.as_str()),
            )
            .map_err(DeviceManagerError::VirtioDevice)?,
        ));

        let new_resources = self.add_pci_device(
            virtio_pci_device.clone(),
            virtio_pci_device.clone(),
            pci_segment_id,
            pci_device_bdf,
            resources,
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
        node.resources = new_resources;
        node.migratable = Some(Arc::clone(&virtio_pci_device) as Arc<Mutex<dyn Migratable>>);
        node.pci_bdf = Some(pci_device_bdf);
        node.pci_device_handle = Some(PciDeviceHandle::Virtio(virtio_pci_device));
        self.device_tree.lock().unwrap().insert(id, node);

        Ok(pci_device_bdf)
    }

    fn add_pvpanic_device(
        &mut self,
    ) -> DeviceManagerResult<Option<Arc<Mutex<devices::PvPanicDevice>>>> {
        let id = String::from(PVPANIC_DEVICE_NAME);
        let pci_segment_id = 0x0_u16;

        info!("Creating pvpanic device {id}");

        let (pci_segment_id, pci_device_bdf, resources) =
            self.pci_resources(&id, pci_segment_id)?;

        let snapshot = snapshot_from_id(self.snapshot.as_ref(), id.as_str());

        let pvpanic_device = devices::PvPanicDevice::new(id.clone(), snapshot)
            .map_err(DeviceManagerError::PvPanicCreate)?;

        let pvpanic_device = Arc::new(Mutex::new(pvpanic_device));

        let new_resources = self.add_pci_device(
            pvpanic_device.clone(),
            pvpanic_device.clone(),
            pci_segment_id,
            pci_device_bdf,
            resources,
        )?;

        let mut node = device_node!(id, pvpanic_device);

        node.resources = new_resources;
        node.pci_bdf = Some(pci_device_bdf);
        node.pci_device_handle = None;

        self.device_tree.lock().unwrap().insert(id, node);

        Ok(Some(pvpanic_device))
    }

    #[cfg(feature = "ivshmem")]
    fn add_ivshmem_device(
        &mut self,
        ivshmem_cfg: &IvshmemConfig,
    ) -> DeviceManagerResult<Option<Arc<Mutex<devices::IvshmemDevice>>>> {
        let id = String::from(IVSHMEM_DEVICE_NAME);
        let pci_segment_id = 0x0_u16;
        info!("Creating ivshmem device {id}");

        let (pci_segment_id, pci_device_bdf, resources) =
            self.pci_resources(&id, pci_segment_id)?;
        let snapshot = snapshot_from_id(self.snapshot.as_ref(), id.as_str());

        let ivshmem_ops = Arc::new(Mutex::new(IvshmemHandler {
            memory_manager: self.memory_manager.clone(),
        }));
        let ivshmem_device = Arc::new(Mutex::new(
            devices::IvshmemDevice::new(
                id.clone(),
                ivshmem_cfg.size as u64,
                Some(ivshmem_cfg.path.clone()),
                ivshmem_ops.clone(),
                snapshot,
            )
            .map_err(DeviceManagerError::IvshmemCreate)?,
        ));
        let new_resources = self.add_pci_device(
            ivshmem_device.clone(),
            ivshmem_device.clone(),
            pci_segment_id,
            pci_device_bdf,
            resources,
        )?;

        let start_addr = ivshmem_device.lock().unwrap().data_bar_addr();
        let (region, mapping) = ivshmem_ops
            .lock()
            .unwrap()
            .map_ram_region(start_addr, ivshmem_cfg.size, Some(ivshmem_cfg.path.clone()))
            .map_err(DeviceManagerError::IvshmemCreate)?;
        ivshmem_device.lock().unwrap().set_region(region, mapping);

        let mut node = device_node!(id, ivshmem_device);
        node.resources = new_resources;
        node.pci_bdf = Some(pci_device_bdf);
        node.pci_device_handle = None;
        self.device_tree.lock().unwrap().insert(id, node);

        Ok(Some(ivshmem_device))
    }

    fn pci_resources(
        &self,
        id: &str,
        pci_segment_id: u16,
    ) -> DeviceManagerResult<(u16, PciBdf, Option<Vec<Resource>>)> {
        // Look for the id in the device tree. If it can be found, that means
        // the device is being restored, otherwise it's created from scratch.
        let (pci_device_bdf, resources) =
            if let Some(node) = self.device_tree.lock().unwrap().get(id) {
                info!("Restoring virtio-pci {id} resources");
                let pci_device_bdf: PciBdf = node
                    .pci_bdf
                    .ok_or(DeviceManagerError::MissingDeviceNodePciBdf)?;
                (Some(pci_device_bdf), Some(node.resources.clone()))
            } else {
                (None, None)
            };

        Ok(if let Some(pci_device_bdf) = pci_device_bdf {
            let pci_segment_id = pci_device_bdf.segment();

            self.pci_segments[pci_segment_id as usize]
                .pci_bus
                .lock()
                .unwrap()
                .get_device_id(pci_device_bdf.device() as usize)
                .map_err(DeviceManagerError::GetPciDeviceId)?;

            (pci_segment_id, pci_device_bdf, resources)
        } else {
            let pci_device_bdf = self.pci_segments[pci_segment_id as usize].next_device_bdf()?;

            (pci_segment_id, pci_device_bdf, None)
        })
    }

    #[cfg(target_arch = "x86_64")]
    pub fn io_bus(&self) -> &Arc<Bus> {
        &self.address_manager.io_bus
    }

    pub fn mmio_bus(&self) -> &Arc<Bus> {
        &self.address_manager.mmio_bus
    }

    #[cfg(feature = "fw_cfg")]
    pub fn fw_cfg(&self) -> Option<&Arc<Mutex<FwCfg>>> {
        self.fw_cfg.as_ref()
    }

    pub fn allocator(&self) -> &Arc<Mutex<SystemAllocator>> {
        &self.address_manager.allocator
    }

    pub fn interrupt_controller(&self) -> Option<Arc<Mutex<dyn InterruptController>>> {
        self.interrupt_controller
            .as_ref()
            .map(|ic| ic.clone() as Arc<Mutex<dyn InterruptController>>)
    }

    pub(crate) fn pci_segments(&self) -> &Vec<PciSegment> {
        &self.pci_segments
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    pub fn cmdline_additions(&self) -> &[String] {
        self.cmdline_additions.as_slice()
    }

    pub fn update_memory(&self, new_region: &Arc<GuestRegionMmap>) -> DeviceManagerResult<()> {
        for handle in self.virtio_devices.iter() {
            handle
                .virtio_device
                .lock()
                .unwrap()
                .add_memory_region(new_region)
                .map_err(DeviceManagerError::UpdateMemoryForVirtioDevice)?;

            if let Some(dma_handler) = &handle.dma_handler
                && !handle.iommu
            {
                let gpa = new_region.start_addr().0;
                let size = new_region.len();
                dma_handler
                    .map(gpa, gpa, size)
                    .map_err(DeviceManagerError::VirtioDmaMap)?;
            }
        }

        // Take care of updating the memory for VFIO PCI devices.
        if let Some(vfio_container) = &self.vfio_container {
            // vfio_dma_map is unsound and ought to be marked as unsafe
            #[allow(unused_unsafe)]
            // SAFETY: GuestMemoryMmap guarantees that region points
            // to len bytes of valid memory starting at as_ptr()
            // that will only be freed with munmap().
            unsafe {
                vfio_container.vfio_dma_map(
                    new_region.start_addr().raw_value(),
                    new_region.len(),
                    new_region.as_ptr() as u64,
                )
            }
            .map_err(DeviceManagerError::UpdateMemoryForVfioPciDevice)?;
        }

        // Take care of updating the memory for vfio-user devices.
        {
            let device_tree = self.device_tree.lock().unwrap();
            for pci_device_node in device_tree.pci_devices() {
                if let PciDeviceHandle::VfioUser(vfio_user_pci_device) = pci_device_node
                    .pci_device_handle
                    .as_ref()
                    .ok_or(DeviceManagerError::MissingPciDevice)?
                {
                    vfio_user_pci_device
                        .lock()
                        .unwrap()
                        .dma_map(new_region)
                        .map_err(DeviceManagerError::UpdateMemoryForVfioUserPciDevice)?;
                }
            }
        }

        Ok(())
    }

    pub fn activate_virtio_devices(&self) -> DeviceManagerResult<()> {
        for mut activator in self.pending_activations.lock().unwrap().drain(..) {
            activator
                .activate()
                .map_err(DeviceManagerError::VirtioActivate)?;
        }
        Ok(())
    }

    pub fn notify_hotplug(
        &self,
        _notification_type: AcpiNotificationFlags,
    ) -> DeviceManagerResult<()> {
        return self
            .ged_notification_device
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .notify(_notification_type)
            .map_err(DeviceManagerError::HotPlugNotification);
    }

    pub fn add_device(
        &mut self,
        device_cfg: &mut DeviceConfig,
    ) -> DeviceManagerResult<PciDeviceInfo> {
        self.validate_identifier(&device_cfg.id)?;

        if device_cfg.iommu && !self.is_iommu_segment(device_cfg.pci_segment) {
            return Err(DeviceManagerError::InvalidIommuHotplug);
        }

        let (bdf, device_name) = self.add_passthrough_device(device_cfg)?;

        // Update the PCIU bitmap
        self.pci_segments[device_cfg.pci_segment as usize].pci_devices_up |= 1 << bdf.device();

        Ok(PciDeviceInfo {
            id: device_name,
            bdf,
        })
    }

    pub fn add_user_device(
        &mut self,
        device_cfg: &mut UserDeviceConfig,
    ) -> DeviceManagerResult<PciDeviceInfo> {
        self.validate_identifier(&device_cfg.id)?;

        let (bdf, device_name) = self.add_vfio_user_device(device_cfg)?;

        // Update the PCIU bitmap
        self.pci_segments[device_cfg.pci_segment as usize].pci_devices_up |= 1 << bdf.device();

        Ok(PciDeviceInfo {
            id: device_name,
            bdf,
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
            .ok_or(DeviceManagerError::UnknownDeviceId(id.clone()))?;

        // Release advisory locks by dropping all references.
        // Linux automatically releases all locks of that file if the last open FD is closed.
        {
            let maybe_block_device_index = self
                .block_devices
                .iter()
                .enumerate()
                .find(|(_, dev)| {
                    let dev = dev.lock().unwrap();
                    dev.id() == id
                })
                .map(|(i, _)| i);
            if let Some(index) = maybe_block_device_index {
                let _ = self.block_devices.swap_remove(index);
            }
        }

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
            .ok_or(DeviceManagerError::MissingDeviceNodePciBdf)?;
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
            // When the device is added, we close all file descriptors
            // opened externally for this device. This allows management
            // software to properly clean up resources, e.g., libvirt can clean
            // up tap devices.
            //
            // TODO: once we allow externally opened FDs for other devices as well,
            // we should create a descriptive abstraction/function for this
            // functionality.
            match device_type {
                VirtioDeviceType::Net => {
                    let mut config = self.config.lock().unwrap();
                    let nets = config.net.as_deref_mut().unwrap();
                    let net_dev_cfg = nets
                        .iter_mut()
                        .find(|net| net.id.as_ref() == Some(&id))
                        // unwrap: the device could not have been removed without an ID
                        .unwrap();
                    let fds = net_dev_cfg.fds.take().unwrap_or(Vec::new());

                    debug!("Closing preserved FDs from virtio-net device: id={id}, fds={fds:?}");
                    for fd in fds {
                        config.preserved_fds.as_mut().unwrap().retain(|x| *x != fd);
                        // SAFETY: We are closing the only remaining instance of this FD.
                        unsafe {
                            libc::close(fd);
                        }
                    }
                }
                VirtioDeviceType::Block
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

    pub fn eject_device(&mut self, pci_segment_id: u16, device_id: u8) -> DeviceManagerResult<()> {
        info!("Ejecting device_id = {device_id} on segment_id={pci_segment_id}");

        // Convert the device ID into the corresponding b/d/f.
        let pci_device_bdf = PciBdf::new(pci_segment_id, 0, device_id, 0);

        // Give the PCI device ID back to the PCI bus.
        self.pci_segments[pci_segment_id as usize]
            .pci_bus
            .lock()
            .unwrap()
            .put_device_id(device_id as usize)
            .map_err(DeviceManagerError::PutPciDeviceId)?;

        let (pci_device_handle, id) = {
            // Remove the device from the device tree along with its children.
            let mut device_tree = self.device_tree.lock().unwrap();
            let pci_device_node = device_tree
                .remove_node_by_pci_bdf(pci_device_bdf)
                .ok_or(DeviceManagerError::MissingPciDevice)?;

            // For VFIO and vfio-user the PCI device id is the id.
            // For virtio we overwrite it later as we want the id of the
            // underlying device.
            let mut id = pci_device_node.id;
            let pci_device_handle = pci_device_node
                .pci_device_handle
                .ok_or(DeviceManagerError::MissingPciDevice)?;
            if matches!(pci_device_handle, PciDeviceHandle::Virtio(_)) {
                // The virtio-pci device has a single child
                if !pci_device_node.children.is_empty() {
                    assert_eq!(pci_device_node.children.len(), 1);
                    let child_id = &pci_device_node.children[0];
                    id.clone_from(child_id);
                }
            }
            for child in pci_device_node.children.iter() {
                device_tree.remove(child);
            }

            (pci_device_handle, id)
        };

        let mut iommu_attached = false;
        if let Some((_, iommu_attached_devices)) = &self.iommu_attached_devices
            && iommu_attached_devices.contains(&pci_device_bdf)
        {
            iommu_attached = true;
        }

        let (pci_device, bus_device, virtio_device, remove_dma_handler) = match pci_device_handle {
            // No need to remove any virtio-mem mapping here as the container outlives all devices
            PciDeviceHandle::Vfio(vfio_pci_device) => {
                for mmio_region in vfio_pci_device.lock().unwrap().mmio_regions() {
                    self.mmio_regions
                        .lock()
                        .unwrap()
                        .retain(|x| x.start != mmio_region.start);
                }

                (
                    Arc::clone(&vfio_pci_device) as Arc<Mutex<dyn PciDevice>>,
                    Arc::clone(&vfio_pci_device) as Arc<dyn BusDeviceSync>,
                    None as Option<Arc<Mutex<dyn virtio_devices::VirtioDevice>>>,
                    false,
                )
            }
            PciDeviceHandle::Virtio(virtio_pci_device) => {
                let dev = virtio_pci_device.lock().unwrap();
                let bar_addr = dev.config_bar_addr();
                for (event, addr) in dev.ioeventfds(bar_addr) {
                    let io_addr = IoEventAddress::Mmio(addr);
                    self.address_manager
                        .vm
                        .unregister_ioevent(event, &io_addr)
                        .map_err(|e| DeviceManagerError::UnRegisterIoevent(e.into()))?;
                }

                if let Some(dma_handler) = dev.dma_handler()
                    && !iommu_attached
                {
                    for (_, zone) in self.memory_manager.lock().unwrap().memory_zones().iter() {
                        for region in zone.regions() {
                            let iova = region.start_addr().0;
                            let size = region.len();
                            dma_handler
                                .unmap(iova, size)
                                .map_err(DeviceManagerError::VirtioDmaUnmap)?;
                        }
                    }
                }

                (
                    Arc::clone(&virtio_pci_device) as Arc<Mutex<dyn PciDevice>>,
                    Arc::clone(&virtio_pci_device) as Arc<dyn BusDeviceSync>,
                    Some(dev.virtio_device()),
                    dev.dma_handler().is_some() && !iommu_attached,
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

                (
                    Arc::clone(&vfio_user_pci_device) as Arc<Mutex<dyn PciDevice>>,
                    Arc::clone(&vfio_user_pci_device) as Arc<dyn BusDeviceSync>,
                    None as Option<Arc<Mutex<dyn virtio_devices::VirtioDevice>>>,
                    true,
                )
            }
        };

        if remove_dma_handler {
            for virtio_mem_device in self.virtio_mem_devices.iter() {
                virtio_mem_device
                    .lock()
                    .unwrap()
                    .remove_dma_mapping_handler(VirtioMemMappingSource::Device(
                        pci_device_bdf.into(),
                    ))
                    .map_err(DeviceManagerError::RemoveDmaMappingHandlerVirtioMem)?;
            }
        }

        // Free the allocated BARs
        pci_device
            .lock()
            .unwrap()
            .free_bars(
                &mut self.address_manager.allocator.lock().unwrap(),
                &mut self.pci_segments[pci_segment_id as usize]
                    .mem32_allocator
                    .lock()
                    .unwrap(),
                &mut self.pci_segments[pci_segment_id as usize]
                    .mem64_allocator
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
            .remove_by_device(bus_device.as_ref())
            .map_err(DeviceManagerError::RemoveDeviceFromIoBus)?;

        // Remove the device from the MMIO bus
        self.mmio_bus()
            .remove_by_device(bus_device.as_ref())
            .map_err(DeviceManagerError::RemoveDeviceFromMmioBus)?;

        // Remove the device from the list of BusDevice held by the
        // DeviceManager.
        self.bus_devices
            .retain(|dev| !Arc::ptr_eq(dev, &bus_device));

        // Shutdown and remove the underlying virtio-device if present
        if let Some(virtio_device) = virtio_device {
            for mapping in virtio_device.lock().unwrap().userspace_mappings() {
                // SAFETY: userspace_mappings only has valid mappings.
                // TODO: do not rely on the correctness of all the code in this file
                // for this to hold.
                unsafe {
                    self.memory_manager
                        .lock()
                        .unwrap()
                        .remove_userspace_mapping(
                            mapping.addr.raw_value(),
                            mapping.mapping.size(),
                            mapping.mapping.as_ptr() as _,
                            mapping.mergeable,
                            mapping.mem_slot,
                        )
                        .map_err(DeviceManagerError::MemoryManager)
                }?;
            }

            virtio_device.lock().unwrap().shutdown();

            self.virtio_devices
                .retain(|handler| !Arc::ptr_eq(&handler.virtio_device, &virtio_device));
        }

        event!(
            "vm",
            "device-removed",
            "id",
            &id,
            "bdf",
            pci_device_bdf.to_string()
        );

        // At this point, the device has been removed from all the list and
        // buses where it was stored. At the end of this function, after
        // any_device, bus_device and pci_device are released, the actual
        // device will be dropped.
        Ok(())
    }

    fn hotplug_virtio_pci_device(
        &mut self,
        handle: MetaVirtioDevice,
    ) -> DeviceManagerResult<PciDeviceInfo> {
        // Add the virtio device to the device manager list. This is important
        // as the list is used to notify virtio devices about memory updates
        // for instance.
        self.virtio_devices.push(handle.clone());

        let mapping: Option<Arc<IommuMapping>> = if handle.iommu {
            self.iommu_mapping.clone()
        } else {
            None
        };

        let bdf = self.add_virtio_pci_device(
            handle.virtio_device,
            &mapping,
            handle.id.clone(),
            handle.pci_segment,
            handle.dma_handler,
        )?;

        // Update the PCIU bitmap
        self.pci_segments[handle.pci_segment as usize].pci_devices_up |= 1 << bdf.device();

        Ok(PciDeviceInfo { id: handle.id, bdf })
    }

    fn is_iommu_segment(&self, pci_segment_id: u16) -> bool {
        self.config
            .lock()
            .as_ref()
            .unwrap()
            .platform
            .as_ref()
            .map(|pc| {
                pc.iommu_segments
                    .as_ref()
                    .map(|v| v.contains(&pci_segment_id))
                    .unwrap_or_default()
            })
            .unwrap_or_default()
    }

    pub fn add_disk(&mut self, disk_cfg: &mut DiskConfig) -> DeviceManagerResult<PciDeviceInfo> {
        self.validate_identifier(&disk_cfg.id)?;

        if disk_cfg.iommu && !self.is_iommu_segment(disk_cfg.pci_segment) {
            return Err(DeviceManagerError::InvalidIommuHotplug);
        }

        let device = self.make_virtio_block_device(disk_cfg, true)?;
        self.hotplug_virtio_pci_device(device)
    }

    pub fn add_fs(&mut self, fs_cfg: &mut FsConfig) -> DeviceManagerResult<PciDeviceInfo> {
        self.validate_identifier(&fs_cfg.id)?;

        let device = self.make_virtio_fs_device(fs_cfg)?;
        self.hotplug_virtio_pci_device(device)
    }

    pub fn add_pmem(&mut self, pmem_cfg: &mut PmemConfig) -> DeviceManagerResult<PciDeviceInfo> {
        self.validate_identifier(&pmem_cfg.id)?;

        if pmem_cfg.iommu && !self.is_iommu_segment(pmem_cfg.pci_segment) {
            return Err(DeviceManagerError::InvalidIommuHotplug);
        }

        let device = self.make_virtio_pmem_device(pmem_cfg)?;
        self.hotplug_virtio_pci_device(device)
    }

    pub fn add_net(&mut self, net_cfg: &mut NetConfig) -> DeviceManagerResult<PciDeviceInfo> {
        self.validate_identifier(&net_cfg.id)?;

        if net_cfg.iommu && !self.is_iommu_segment(net_cfg.pci_segment) {
            return Err(DeviceManagerError::InvalidIommuHotplug);
        }

        let device = self.make_virtio_net_device(net_cfg)?;
        self.hotplug_virtio_pci_device(device)
    }

    pub fn add_vdpa(&mut self, vdpa_cfg: &mut VdpaConfig) -> DeviceManagerResult<PciDeviceInfo> {
        self.validate_identifier(&vdpa_cfg.id)?;

        if vdpa_cfg.iommu && !self.is_iommu_segment(vdpa_cfg.pci_segment) {
            return Err(DeviceManagerError::InvalidIommuHotplug);
        }

        let device = self.make_vdpa_device(vdpa_cfg)?;
        self.hotplug_virtio_pci_device(device)
    }

    pub fn add_vsock(&mut self, vsock_cfg: &mut VsockConfig) -> DeviceManagerResult<PciDeviceInfo> {
        self.validate_identifier(&vsock_cfg.id)?;

        if vsock_cfg.iommu && !self.is_iommu_segment(vsock_cfg.pci_segment) {
            return Err(DeviceManagerError::InvalidIommuHotplug);
        }

        let device = self.make_virtio_vsock_device(vsock_cfg)?;
        self.hotplug_virtio_pci_device(device)
    }

    pub fn counters(&self) -> HashMap<String, HashMap<&'static str, Wrapping<u64>>> {
        let mut counters = HashMap::new();

        for handle in &self.virtio_devices {
            let virtio_device = handle.virtio_device.lock().unwrap();
            if let Some(device_counters) = virtio_device.counters() {
                counters.insert(handle.id.clone(), device_counters.clone());
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
        // There are two use cases:
        // 1. Users will use direct kernel boot with device tree.
        // 2. Users will use ACPI+UEFI boot.

        // Trigger a GPIO pin 3 event to satisfy use case 1.
        self.gpio_device
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .trigger_key(3)
            .map_err(DeviceManagerError::AArch64PowerButtonNotification)?;
        // Trigger a GED power button event to satisfy use case 2.
        return self
            .ged_notification_device
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .notify(AcpiNotificationFlags::POWER_BUTTON_CHANGED)
            .map_err(DeviceManagerError::PowerButtonNotification);
    }

    pub fn iommu_attached_devices(&self) -> &Option<(PciBdf, Vec<PciBdf>)> {
        &self.iommu_attached_devices
    }

    fn validate_identifier(&self, id: &Option<String>) -> DeviceManagerResult<()> {
        if let Some(id) = id {
            if id.starts_with("__") {
                return Err(DeviceManagerError::InvalidIdentifier(id.clone()));
            }

            if self.device_tree.lock().unwrap().contains_key(id) {
                return Err(DeviceManagerError::IdentifierNotUnique(id.clone()));
            }
        }

        Ok(())
    }

    pub(crate) fn acpi_platform_addresses(&self) -> &AcpiPlatformAddresses {
        &self.acpi_platform_addresses
    }

    fn cleanup_vfio_container(&mut self) {
        // Drop the 'vfio container' instance when "Self" is the only reference
        if let Some(1) = self.vfio_container.as_ref().map(Arc::strong_count) {
            debug!("Drop 'vfio container' given no active 'vfio devices'.");
            self.vfio_container = None;
        }
    }
}

#[cfg(feature = "ivshmem")]
struct IvshmemHandler {
    memory_manager: Arc<Mutex<MemoryManager>>,
}

#[cfg(feature = "ivshmem")]
impl IvshmemOps for IvshmemHandler {
    fn map_ram_region(
        &mut self,
        start_addr: u64,
        size: usize,
        backing_file: Option<PathBuf>,
    ) -> Result<(Arc<MmapRegion<AtomicBitmap>>, UserspaceMapping), IvshmemError> {
        info!("Creating ivshmem mem region at 0x{start_addr:x}");

        let region = MemoryManager::create_ram_region_raw(
            &backing_file,
            0,
            size,
            false,
            true,
            false,
            None,
            None,
            None,
            false,
        )
        .map_err(|_| IvshmemError::CreateUserMemoryRegion)?;
        let mem_slot = {
            let mut manager = self.memory_manager.lock().unwrap();
            // SAFETY: guaranteed by MmapRegion invariants
            unsafe {
                manager.create_userspace_mapping(
                    start_addr,
                    region.len(),
                    region.as_ptr(),
                    false,
                    false,
                    false,
                )
            }
        }
        .map_err(|_| IvshmemError::CreateUserspaceMapping)?;
        let region = Arc::new(region);
        let mapping = UserspaceMapping {
            mapping: region.clone(),
            mem_slot,
            addr: GuestAddress(start_addr),
            mergeable: false,
        };
        Ok((region, mapping))
    }

    fn unmap_ram_region(&mut self, mapping: UserspaceMapping) -> Result<(), IvshmemError> {
        let mut manager = self.memory_manager.lock().unwrap();
        // SAFETY: UserspaceMapping is valid due to other code being correct
        unsafe {
            manager.remove_userspace_mapping(
                mapping.addr.raw_value(),
                mapping.mapping.len(),
                mapping.mapping.as_ptr(),
                mapping.mergeable,
                mapping.mem_slot,
            )
        }
        .map_err(|_| IvshmemError::RemoveUserspaceMapping)?;
        Ok(())
    }
}

fn numa_node_id_from_memory_zone_id(numa_nodes: &NumaNodes, memory_zone_id: &str) -> Option<u32> {
    for (numa_node_id, numa_node) in numa_nodes.iter() {
        if numa_node.memory_zones.contains(&memory_zone_id.to_owned()) {
            return Some(*numa_node_id);
        }
    }

    None
}

fn numa_node_id_from_pci_segment_id(numa_nodes: &NumaNodes, pci_segment_id: u16) -> u32 {
    for (numa_node_id, numa_node) in numa_nodes.iter() {
        if numa_node.pci_segments.contains(&pci_segment_id) {
            return *numa_node_id;
        }
    }

    0
}

#[cfg(not(target_arch = "riscv64"))]
struct TpmDevice {}

#[cfg(not(target_arch = "riscv64"))]
impl Aml for TpmDevice {
    fn to_aml_bytes(&self, sink: &mut dyn acpi_tables::AmlSink) {
        aml::Device::new(
            "TPM2".into(),
            vec![
                &aml::Name::new("_HID".into(), &"MSFT0101"),
                &aml::Name::new("_STA".into(), &(0xF_usize)),
                &aml::Name::new(
                    "_CRS".into(),
                    &aml::ResourceTemplate::new(vec![&aml::Memory32Fixed::new(
                        true,
                        layout::TPM_START.0 as u32,
                        layout::TPM_SIZE as u32,
                    )]),
                ),
            ],
        )
        .to_aml_bytes(sink);
    }
}

impl Aml for DeviceManager {
    fn to_aml_bytes(&self, sink: &mut dyn acpi_tables::AmlSink) {
        #[cfg(target_arch = "aarch64")]
        use arch::aarch64::DeviceInfoForFdt;
        #[cfg(target_arch = "riscv64")]
        use arch::riscv64::DeviceInfoForFdt;

        let mut pci_scan_methods = Vec::new();
        for i in 0..self.pci_segments.len() {
            pci_scan_methods.push(aml::MethodCall::new(
                format!("\\_SB_.PC{i:02X}.PCNT").as_str().into(),
                vec![],
            ));
        }
        let mut pci_scan_inner: Vec<&dyn Aml> = Vec::new();
        for method in &pci_scan_methods {
            pci_scan_inner.push(method);
        }

        // PCI hotplug controller
        aml::Device::new(
            "_SB_.PHPR".into(),
            vec![
                &aml::Name::new("_HID".into(), &aml::EISAName::new("PNP0A06")),
                &aml::Name::new("_STA".into(), &0x0bu8),
                &aml::Name::new("_UID".into(), &"PCI Hotplug Controller"),
                &aml::Mutex::new("BLCK".into(), 0),
                &aml::Name::new(
                    "_CRS".into(),
                    &aml::ResourceTemplate::new(vec![&aml::AddressSpace::new_memory(
                        aml::AddressSpaceCacheable::NotCacheable,
                        true,
                        self.acpi_address.0,
                        self.acpi_address.0 + DEVICE_MANAGER_ACPI_SIZE as u64 - 1,
                        None,
                    )]),
                ),
                // OpRegion and Fields map MMIO range into individual field values
                &aml::OpRegion::new(
                    "PCST".into(),
                    aml::OpRegionSpace::SystemMemory,
                    &(self.acpi_address.0 as usize),
                    &DEVICE_MANAGER_ACPI_SIZE,
                ),
                &aml::Field::new(
                    "PCST".into(),
                    aml::FieldAccessType::DWord,
                    aml::FieldLockRule::NoLock,
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
        .to_aml_bytes(sink);

        for segment in &self.pci_segments {
            segment.to_aml_bytes(sink);
        }

        let mut mbrd_memory = Vec::new();

        for segment in &self.pci_segments {
            mbrd_memory.push(aml::Memory32Fixed::new(
                true,
                segment.mmio_config_address as u32,
                layout::PCI_MMIO_CONFIG_SIZE_PER_SEGMENT as u32,
            ));
        }

        let mut mbrd_memory_refs = Vec::new();
        for mbrd_memory_ref in &mbrd_memory {
            mbrd_memory_refs.push(mbrd_memory_ref as &dyn Aml);
        }

        aml::Device::new(
            "_SB_.MBRD".into(),
            vec![
                &aml::Name::new("_HID".into(), &aml::EISAName::new("PNP0C02")),
                &aml::Name::new("_UID".into(), &aml::ZERO),
                &aml::Name::new("_CRS".into(), &aml::ResourceTemplate::new(mbrd_memory_refs)),
            ],
        )
        .to_aml_bytes(sink);

        #[cfg(all(feature = "fw_cfg", target_arch = "x86_64"))]
        if self.fw_cfg.is_some() {
            aml::Device::new(
                "_SB_.FWCF".into(),
                vec![
                    &aml::Name::new("_HID".into(), &FW_CFG_ACPI_ID.to_string()),
                    &aml::Name::new("_STA".into(), &0xB_usize),
                    &aml::Name::new(
                        "_CRS".into(),
                        &aml::ResourceTemplate::new(vec![&aml::IO::new(
                            PORT_FW_CFG_BASE as u16,
                            PORT_FW_CFG_BASE as u16,
                            0x01,
                            PORT_FW_CFG_WIDTH as u8,
                        )]),
                    ),
                ],
            )
            .to_aml_bytes(sink);
        }

        // Serial device
        #[cfg(target_arch = "x86_64")]
        let serial_irq = 4;
        #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
        let serial_irq =
            if self.config.lock().unwrap().serial.clone().mode == ConsoleOutputMode::Off {
                // If serial is turned off, add a fake device with invalid irq.
                31
            } else {
                self.get_device_info()
                    .clone()
                    .get(&(DeviceType::Serial, DeviceType::Serial.to_string()))
                    .unwrap()
                    .irq()
            };
        if self.config.lock().unwrap().serial.mode != ConsoleOutputMode::Off {
            aml::Device::new(
                "_SB_.COM1".into(),
                vec![
                    &aml::Name::new(
                        "_HID".into(),
                        #[cfg(target_arch = "x86_64")]
                        &aml::EISAName::new("PNP0501"),
                        #[cfg(target_arch = "aarch64")]
                        &"ARMH0011",
                        #[cfg(target_arch = "riscv64")]
                        &"RISCV011",
                    ),
                    &aml::Name::new("_UID".into(), &aml::ZERO),
                    &aml::Name::new("_DDN".into(), &"COM1"),
                    &aml::Name::new(
                        "_CRS".into(),
                        &aml::ResourceTemplate::new(vec![
                            &aml::Interrupt::new(true, true, false, false, serial_irq),
                            #[cfg(target_arch = "x86_64")]
                            &aml::IO::new(0x3f8, 0x3f8, 0, 0x8),
                            #[cfg(target_arch = "aarch64")]
                            &aml::Memory32Fixed::new(
                                true,
                                arch::layout::LEGACY_SERIAL_MAPPED_IO_START.raw_value() as u32,
                                MMIO_LEN as u32,
                            ),
                        ]),
                    ),
                ],
            )
            .to_aml_bytes(sink);
        }

        aml::Name::new("_S5_".into(), &aml::Package::new(vec![&5u8])).to_aml_bytes(sink);

        aml::Device::new(
            "_SB_.PWRB".into(),
            vec![
                &aml::Name::new("_HID".into(), &aml::EISAName::new("PNP0C0C")),
                &aml::Name::new("_UID".into(), &aml::ZERO),
            ],
        )
        .to_aml_bytes(sink);

        #[cfg(not(target_arch = "riscv64"))]
        if self.config.lock().unwrap().tpm.is_some() {
            // Add tpm device
            TpmDevice {}.to_aml_bytes(sink);
        }

        self.ged_notification_device
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .to_aml_bytes(sink);
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
            self.get_interrupt_controller()
                .unwrap()
                .lock()
                .unwrap()
                .pause()?;
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
        let mut snapshot = Snapshot::from_data(SnapshotData::new_from_state(&self.state())?);

        // We aggregate all devices snapshots.
        for (_, device_node) in self.device_tree.lock().unwrap().iter() {
            if let Some(migratable) = &device_node.migratable {
                let mut migratable = migratable.lock().unwrap();
                snapshot.add_snapshot(migratable.id(), migratable.snapshot()?);
            }
        }

        Ok(snapshot)
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

    fn start_migration(&mut self) -> std::result::Result<(), MigratableError> {
        for (_, device_node) in self.device_tree.lock().unwrap().iter() {
            if let Some(migratable) = &device_node.migratable {
                migratable.lock().unwrap().start_migration()?;
            }
        }
        Ok(())
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

const PCIU_FIELD_OFFSET: u64 = 0;
const PCID_FIELD_OFFSET: u64 = 4;
const B0EJ_FIELD_OFFSET: u64 = 8;
const PSEG_FIELD_OFFSET: u64 = 12;
const PCIU_FIELD_SIZE: usize = 4;
const PCID_FIELD_SIZE: usize = 4;
const B0EJ_FIELD_SIZE: usize = 4;
const PSEG_FIELD_SIZE: usize = 4;

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
            _ => error!("Accessing unknown location at base 0x{base:x}, offset 0x{offset:x}"),
        }

        debug!("PCI_HP_REG_R: base 0x{base:x}, offset 0x{offset:x}, data {data:?}");
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
                        error!("Failed ejecting device {slot_id}: {e:?}");
                    }
                    self.cleanup_vfio_container();
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
            _ => error!("Accessing unknown location at base 0x{base:x}, offset 0x{offset:x}"),
        }

        debug!("PCI_HP_REG_W: base 0x{base:x}, offset 0x{offset:x}, data {data:?}");

        None
    }
}

impl Drop for DeviceManager {
    fn drop(&mut self) {
        // Wake up the DeviceManager threads (mainly virtio device workers),
        // to avoid deadlock on waiting for paused/parked worker threads.
        if let Err(e) = self.resume() {
            error!("Error resuming DeviceManager: {e:?}");
        }

        for handle in self.virtio_devices.drain(..) {
            handle.virtio_device.lock().unwrap().shutdown();
        }

        if let Some(termios) = *self.original_termios_opt.lock().unwrap() {
            // SAFETY: FFI call
            let _ = unsafe { tcsetattr(stdout().lock().as_raw_fd(), TCSANOW, &termios) };
        }
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_create_mmio_allocators() {
        let res = create_mmio_allocators(0x100000, 0x400000, 1, vec![1], 4 << 10);
        assert_eq!(res.len(), 1);
        assert_eq!(
            res[0].lock().unwrap().base(),
            vm_memory::GuestAddress(0x100000)
        );
        assert_eq!(
            res[0].lock().unwrap().end(),
            vm_memory::GuestAddress(0x3fffff)
        );

        let res = create_mmio_allocators(0x100000, 0x400000, 2, vec![1, 1], 4 << 10);
        assert_eq!(res.len(), 2);
        assert_eq!(
            res[0].lock().unwrap().base(),
            vm_memory::GuestAddress(0x100000)
        );
        assert_eq!(
            res[0].lock().unwrap().end(),
            vm_memory::GuestAddress(0x27ffff)
        );
        assert_eq!(
            res[1].lock().unwrap().base(),
            vm_memory::GuestAddress(0x280000)
        );
        assert_eq!(
            res[1].lock().unwrap().end(),
            vm_memory::GuestAddress(0x3fffff)
        );

        let res = create_mmio_allocators(0x100000, 0x400000, 2, vec![2, 1], 4 << 10);
        assert_eq!(res.len(), 2);
        assert_eq!(
            res[0].lock().unwrap().base(),
            vm_memory::GuestAddress(0x100000)
        );
        assert_eq!(
            res[0].lock().unwrap().end(),
            vm_memory::GuestAddress(0x2fffff)
        );
        assert_eq!(
            res[1].lock().unwrap().base(),
            vm_memory::GuestAddress(0x300000)
        );
        assert_eq!(
            res[1].lock().unwrap().end(),
            vm_memory::GuestAddress(0x3fffff)
        );
    }
}
