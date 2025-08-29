// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self};
use std::ops::{BitAnd, Deref, Not, Sub};
#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
use std::os::fd::AsFd;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::{ffi, result, thread};

use acpi_tables::{aml, Aml};
use anyhow::anyhow;
use arch::RegionType;
#[cfg(target_arch = "x86_64")]
use devices::ioapic;
#[cfg(target_arch = "aarch64")]
use hypervisor::HypervisorVmError;
use libc::_SC_NPROCESSORS_ONLN;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracer::trace_scoped;
use virtio_devices::BlocksState;
#[cfg(target_arch = "x86_64")]
use vm_allocator::GsiApic;
use vm_allocator::{AddressAllocator, MemorySlotAllocator, SystemAllocator};
use vm_device::BusDevice;
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::guest_memory::FileOffset;
use vm_memory::mmap::MmapRegionError;
use vm_memory::{
    Address, Error as MmapError, GuestAddress, GuestAddressSpace, GuestMemory, GuestMemoryAtomic,
    GuestMemoryError, GuestMemoryRegion, GuestUsize, MmapRegion, ReadVolatile,
};
use vm_migration::protocol::{MemoryRange, MemoryRangeTable};
use vm_migration::{
    Migratable, MigratableError, Pausable, Snapshot, SnapshotData, Snapshottable, Transportable,
};

#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
use crate::coredump::{
    CoredumpMemoryRegion, CoredumpMemoryRegions, DumpState, GuestDebuggableError,
};
use crate::migration::url_to_path;
use crate::vm_config::{HotplugMethod, MemoryConfig, MemoryZoneConfig};
use crate::{GuestMemoryMmap, GuestRegionMmap, MEMORY_MANAGER_SNAPSHOT_ID};

pub const MEMORY_MANAGER_ACPI_SIZE: usize = 0x18;

const DEFAULT_MEMORY_ZONE: &str = "mem0";

const SNAPSHOT_FILENAME: &str = "memory-ranges";

#[cfg(target_arch = "x86_64")]
const X86_64_IRQ_BASE: u32 = 5;

const HOTPLUG_COUNT: usize = 8;

// Memory policy constants
const MPOL_BIND: u32 = 2;
const MPOL_MF_STRICT: u32 = 1;
const MPOL_MF_MOVE: u32 = 1 << 1;

// Reserve 1 MiB for platform MMIO devices (e.g. ACPI control devices)
const PLATFORM_DEVICE_AREA_SIZE: u64 = 1 << 20;

const MAX_PREFAULT_THREAD_COUNT: usize = 16;

#[derive(Clone, Default, Serialize, Deserialize)]
struct HotPlugState {
    base: u64,
    length: u64,
    active: bool,
    inserting: bool,
    removing: bool,
}

pub struct VirtioMemZone {
    region: Arc<GuestRegionMmap>,
    virtio_device: Option<Arc<Mutex<virtio_devices::Mem>>>,
    hotplugged_size: u64,
    hugepages: bool,
    blocks_state: Arc<Mutex<BlocksState>>,
}

impl VirtioMemZone {
    pub fn region(&self) -> &Arc<GuestRegionMmap> {
        &self.region
    }
    pub fn set_virtio_device(&mut self, virtio_device: Arc<Mutex<virtio_devices::Mem>>) {
        self.virtio_device = Some(virtio_device);
    }
    pub fn hotplugged_size(&self) -> u64 {
        self.hotplugged_size
    }
    pub fn hugepages(&self) -> bool {
        self.hugepages
    }
    pub fn blocks_state(&self) -> &Arc<Mutex<BlocksState>> {
        &self.blocks_state
    }
    pub fn plugged_ranges(&self) -> MemoryRangeTable {
        self.blocks_state
            .lock()
            .unwrap()
            .memory_ranges(self.region.start_addr().raw_value(), true)
    }
}

#[derive(Default)]
pub struct MemoryZone {
    regions: Vec<Arc<GuestRegionMmap>>,
    virtio_mem_zone: Option<VirtioMemZone>,
}

impl MemoryZone {
    pub fn regions(&self) -> &Vec<Arc<GuestRegionMmap>> {
        &self.regions
    }
    pub fn virtio_mem_zone(&self) -> &Option<VirtioMemZone> {
        &self.virtio_mem_zone
    }
    pub fn virtio_mem_zone_mut(&mut self) -> Option<&mut VirtioMemZone> {
        self.virtio_mem_zone.as_mut()
    }
}

pub type MemoryZones = HashMap<String, MemoryZone>;

#[derive(Clone, Serialize, Deserialize)]
struct GuestRamMapping {
    slot: u32,
    gpa: u64,
    size: u64,
    zone_id: String,
    virtio_mem: bool,
    file_offset: u64,
}

#[derive(Clone, Serialize, Deserialize)]
struct ArchMemRegion {
    base: u64,
    size: usize,
    r_type: RegionType,
}

pub struct MemoryManager {
    boot_guest_memory: GuestMemoryMmap,
    guest_memory: GuestMemoryAtomic<GuestMemoryMmap>,
    next_memory_slot: Arc<AtomicU32>,
    memory_slot_free_list: Arc<Mutex<Vec<u32>>>,
    start_of_device_area: GuestAddress,
    end_of_device_area: GuestAddress,
    end_of_ram_area: GuestAddress,
    pub vm: Arc<dyn hypervisor::Vm>,
    hotplug_slots: Vec<HotPlugState>,
    selected_slot: usize,
    mergeable: bool,
    allocator: Arc<Mutex<SystemAllocator>>,
    hotplug_method: HotplugMethod,
    boot_ram: u64,
    current_ram: u64,
    next_hotplug_slot: usize,
    shared: bool,
    hugepages: bool,
    hugepage_size: Option<u64>,
    prefault: bool,
    thp: bool,
    user_provided_zones: bool,
    snapshot_memory_ranges: MemoryRangeTable,
    memory_zones: MemoryZones,
    log_dirty: bool, // Enable dirty logging for created RAM regions
    arch_mem_regions: Vec<ArchMemRegion>,
    ram_allocator: AddressAllocator,
    dynamic: bool,

    // Keep track of calls to create_userspace_mapping() for guest RAM.
    // This is useful for getting the dirty pages as we need to know the
    // slots that the mapping is created in.
    guest_ram_mappings: Vec<GuestRamMapping>,

    pub acpi_address: Option<GuestAddress>,
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    uefi_flash: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
}

#[derive(Error, Debug)]
pub enum Error {
    /// Failed to create shared file.
    #[error("Failed to create shared file")]
    SharedFileCreate(#[source] io::Error),

    /// Failed to set shared file length.
    #[error("Failed to set shared file length")]
    SharedFileSetLen(#[source] io::Error),

    /// Mmap backed guest memory error
    #[error("Mmap backed guest memory error")]
    GuestMemory(#[source] MmapError),

    /// Failed to allocate a memory range.
    #[error("Failed to allocate a memory range")]
    MemoryRangeAllocation,

    /// Error from region creation
    #[error("Error from region creation")]
    GuestMemoryRegion(#[source] MmapRegionError),

    /// No ACPI slot available
    #[error("No ACPI slot available")]
    NoSlotAvailable,

    /// Not enough space in the hotplug RAM region
    #[error("Not enough space in the hotplug RAM region")]
    InsufficientHotplugRam,

    /// The requested hotplug memory addition is not a valid size
    #[error("The requested hotplug memory addition is not a valid size")]
    InvalidSize,

    /// Failed to create the user memory region.
    #[error("Failed to create the user memory region")]
    CreateUserMemoryRegion(#[source] hypervisor::HypervisorVmError),

    /// Failed to remove the user memory region.
    #[error("Failed to remove the user memory region")]
    RemoveUserMemoryRegion(#[source] hypervisor::HypervisorVmError),

    /// Failed to EventFd.
    #[error("Failed to EventFd")]
    EventFdFail(#[source] io::Error),

    /// Eventfd write error
    #[error("Eventfd write error")]
    EventfdError(#[source] io::Error),

    /// Failed to virtio-mem resize
    #[error("Failed to virtio-mem resize")]
    VirtioMemResizeFail(#[source] virtio_devices::mem::Error),

    /// Cannot restore VM
    #[error("Cannot restore VM")]
    Restore(#[source] MigratableError),

    /// Cannot restore VM because source URL is missing
    #[error("Cannot restore VM because source URL is missing")]
    RestoreMissingSourceUrl,

    /// Cannot create the system allocator
    #[error("Cannot create the system allocator")]
    CreateSystemAllocator,

    /// Failed creating a new MmapRegion instance.
    #[cfg(target_arch = "x86_64")]
    #[error("Failed creating a new MmapRegion instance")]
    NewMmapRegion(#[source] vm_memory::mmap::MmapRegionError),

    /// No memory zones found.
    #[error("No memory zones found")]
    MissingMemoryZones,

    /// Memory configuration is not valid.
    #[error("Memory configuration is not valid")]
    InvalidMemoryParameters,

    /// Forbidden operation. Impossible to resize guest memory if it is
    /// backed by user defined memory regions.
    #[error("Impossible to resize guest memory if it is backed by user defined memory regions")]
    InvalidResizeWithMemoryZones,

    /// It's invalid to try applying a NUMA policy to a memory zone that is
    /// memory mapped with MAP_SHARED.
    #[error("Invalid to try applying a NUMA policy to a memory zone that is memory mapped with MAP_SHARED")]
    InvalidSharedMemoryZoneWithHostNuma,

    /// Failed applying NUMA memory policy.
    #[error("Failed applying NUMA memory policy")]
    ApplyNumaPolicy(#[source] io::Error),

    /// Memory zone identifier is not unique.
    #[error("Memory zone identifier is not unique")]
    DuplicateZoneId,

    /// No virtio-mem resizing handler found.
    #[error("No virtio-mem resizing handler found")]
    MissingVirtioMemHandler,

    /// Unknown memory zone.
    #[error("Unknown memory zone")]
    UnknownMemoryZone,

    /// Invalid size for resizing. Can be anything except 0.
    #[error("Invalid size for resizing. Can be anything except 0")]
    InvalidHotplugSize,

    /// Invalid hotplug method associated with memory zones resizing capability.
    #[error("Invalid hotplug method associated with memory zones resizing capability")]
    InvalidHotplugMethodWithMemoryZones,

    /// Could not find specified memory zone identifier from hash map.
    #[error("Could not find specified memory zone identifier from hash map")]
    MissingZoneIdentifier,

    /// Resizing the memory zone failed.
    #[error("Resizing the memory zone failed")]
    ResizeZone,

    /// Guest address overflow
    #[error("Guest address overflow")]
    GuestAddressOverFlow,

    /// Error opening snapshot file
    #[error("Error opening snapshot file")]
    SnapshotOpen(#[source] io::Error),

    // Error copying snapshot into region
    #[error("Error copying snapshot into region")]
    SnapshotCopy(#[source] GuestMemoryError),

    /// Failed to allocate MMIO address
    #[error("Failed to allocate MMIO address")]
    AllocateMmioAddress,

    #[cfg(target_arch = "aarch64")]
    /// Failed to create UEFI flash
    #[error("Failed to create UEFI flash")]
    CreateUefiFlash(#[source] HypervisorVmError),

    /// Using a directory as a backing file for memory is not supported
    #[error("Using a directory as a backing file for memory is not supported")]
    DirectoryAsBackingFileForMemory,

    /// Failed to stat filesystem
    #[error("Failed to stat filesystem")]
    GetFileSystemBlockSize(#[source] io::Error),

    /// Memory size is misaligned with default page size or its hugepage size
    #[error("Memory size is misaligned with default page size or its hugepage size")]
    MisalignedMemorySize,
}

const ENABLE_FLAG: usize = 0;
const INSERTING_FLAG: usize = 1;
const REMOVING_FLAG: usize = 2;
const EJECT_FLAG: usize = 3;

const BASE_OFFSET_LOW: u64 = 0;
const BASE_OFFSET_HIGH: u64 = 0x4;
const LENGTH_OFFSET_LOW: u64 = 0x8;
const LENGTH_OFFSET_HIGH: u64 = 0xC;
const STATUS_OFFSET: u64 = 0x14;
const SELECTION_OFFSET: u64 = 0;

// The MMIO address space size is subtracted with 64k. This is done for the
// following reasons:
//  - Reduce the addressable space size by at least 4k to workaround a Linux
//    bug when the VMM allocates devices at the end of the addressable space
//  - Windows requires the addressable space size to be 64k aligned
fn mmio_address_space_size(phys_bits: u8) -> u64 {
    (1 << phys_bits) - (1 << 16)
}

// The `statfs` function can get information of hugetlbfs, and the hugepage size is in the
// `f_bsize` field.
//
// See: https://github.com/torvalds/linux/blob/v6.3/fs/hugetlbfs/inode.c#L1169
fn statfs_get_bsize(path: &str) -> Result<u64, Error> {
    let path = std::ffi::CString::new(path).map_err(|_| Error::InvalidMemoryParameters)?;
    let mut buf = std::mem::MaybeUninit::<libc::statfs>::uninit();

    // SAFETY: FFI call with a valid path and buffer
    let ret = unsafe { libc::statfs(path.as_ptr(), buf.as_mut_ptr()) };
    if ret != 0 {
        return Err(Error::GetFileSystemBlockSize(
            std::io::Error::last_os_error(),
        ));
    }

    // SAFETY: `buf` is valid at this point
    // Because this value is always positive, just convert it directly.
    // Note that the `f_bsize` is `i64` in glibc and `u64` in musl, using `as u64` will be warned
    // by `clippy` on musl target.  To avoid the warning, there should be `as _` instead of
    // `as u64`.
    let bsize = unsafe { (*buf.as_ptr()).f_bsize } as _;
    Ok(bsize)
}

fn memory_zone_get_align_size(zone: &MemoryZoneConfig) -> Result<u64, Error> {
    // SAFETY: FFI call. Trivially safe.
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 };

    // There is no backend file and the `hugepages` is disabled, just use system page size.
    if zone.file.is_none() && !zone.hugepages {
        return Ok(page_size);
    }

    // The `hugepages` is enabled and the `hugepage_size` is specified, just use it directly.
    if zone.hugepages && zone.hugepage_size.is_some() {
        return Ok(zone.hugepage_size.unwrap());
    }

    // There are two scenarios here:
    //  - `hugepages` is enabled but `hugepage_size` is not specified:
    //     Call `statfs` for `/dev/hugepages` for getting the default size of hugepage
    //  - The backing file is specified:
    //     Call `statfs` for the file and get its `f_bsize`.  If the value is larger than the page
    //     size of normal page, just use the `f_bsize` because the file is in a hugetlbfs.  If the
    //     value is less than or equal to the page size, just use the page size.
    let path = zone.file.as_ref().map_or(Ok("/dev/hugepages"), |pathbuf| {
        pathbuf.to_str().ok_or(Error::InvalidMemoryParameters)
    })?;

    let align_size = std::cmp::max(page_size, statfs_get_bsize(path)?);

    Ok(align_size)
}

#[inline]
fn align_down<T>(val: T, align: T) -> T
where
    T: BitAnd<Output = T> + Not<Output = T> + Sub<Output = T> + From<u8>,
{
    val & !(align - 1u8.into())
}

#[inline]
fn is_aligned<T>(val: T, align: T) -> bool
where
    T: BitAnd<Output = T> + Sub<Output = T> + From<u8> + PartialEq,
{
    (val & (align - 1u8.into())) == 0u8.into()
}

impl BusDevice for MemoryManager {
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        if self.selected_slot < self.hotplug_slots.len() {
            let state = &self.hotplug_slots[self.selected_slot];
            match offset {
                BASE_OFFSET_LOW => {
                    data.copy_from_slice(&state.base.to_le_bytes()[..4]);
                }
                BASE_OFFSET_HIGH => {
                    data.copy_from_slice(&state.base.to_le_bytes()[4..]);
                }
                LENGTH_OFFSET_LOW => {
                    data.copy_from_slice(&state.length.to_le_bytes()[..4]);
                }
                LENGTH_OFFSET_HIGH => {
                    data.copy_from_slice(&state.length.to_le_bytes()[4..]);
                }
                STATUS_OFFSET => {
                    // The Linux kernel, quite reasonably, doesn't zero the memory it gives us.
                    data.fill(0);
                    if state.active {
                        data[0] |= 1 << ENABLE_FLAG;
                    }
                    if state.inserting {
                        data[0] |= 1 << INSERTING_FLAG;
                    }
                    if state.removing {
                        data[0] |= 1 << REMOVING_FLAG;
                    }
                }
                _ => {
                    warn!(
                        "Unexpected offset for accessing memory manager device: {:#}",
                        offset
                    );
                }
            }
        } else {
            warn!("Out of range memory slot: {}", self.selected_slot);
        }
    }

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        match offset {
            SELECTION_OFFSET => {
                self.selected_slot = usize::from(data[0]);
            }
            STATUS_OFFSET => {
                if self.selected_slot < self.hotplug_slots.len() {
                    let state = &mut self.hotplug_slots[self.selected_slot];
                    // The ACPI code writes back a 1 to acknowledge the insertion
                    if (data[0] & (1 << INSERTING_FLAG) == 1 << INSERTING_FLAG) && state.inserting {
                        state.inserting = false;
                    }
                    // Ditto for removal
                    if (data[0] & (1 << REMOVING_FLAG) == 1 << REMOVING_FLAG) && state.removing {
                        state.removing = false;
                    }
                    // Trigger removal of "DIMM"
                    if data[0] & (1 << EJECT_FLAG) == 1 << EJECT_FLAG {
                        warn!("Ejection of memory not currently supported");
                    }
                } else {
                    warn!("Out of range memory slot: {}", self.selected_slot);
                }
            }
            _ => {
                warn!(
                    "Unexpected offset for accessing memory manager device: {:#}",
                    offset
                );
            }
        };
        None
    }
}

impl MemoryManager {
    /// Creates all memory regions based on the available RAM ranges defined
    /// by `ram_regions`, and based on the description of the memory zones.
    /// In practice, this function can perform multiple memory mappings of the
    /// same backing file if there's a hole in the address space between two
    /// RAM ranges.
    ///
    /// One example might be ram_regions containing 2 regions (0-3G and 4G-6G)
    /// and zones containing two zones (size 1G and size 4G).
    ///
    /// This function will create 3 resulting memory regions:
    /// - First one mapping entirely the first memory zone on 0-1G range
    /// - Second one mapping partially the second memory zone on 1G-3G range
    /// - Third one mapping partially the second memory zone on 4G-6G range
    ///
    /// Also, all memory regions are page-size aligned (e.g. their sizes must
    /// be multiple of page-size), which may leave an additional hole in the
    /// address space when hugepage is used.
    fn create_memory_regions_from_zones(
        ram_regions: &[(GuestAddress, usize)],
        zones: &[MemoryZoneConfig],
        prefault: Option<bool>,
        thp: bool,
    ) -> Result<(Vec<Arc<GuestRegionMmap>>, MemoryZones), Error> {
        let mut zone_iter = zones.iter();
        let mut mem_regions = Vec::new();
        let mut zone = zone_iter.next().ok_or(Error::MissingMemoryZones)?;
        let mut zone_align_size = memory_zone_get_align_size(zone)?;
        let mut zone_offset = 0u64;
        let mut memory_zones = HashMap::new();

        if !is_aligned(zone.size, zone_align_size) {
            return Err(Error::MisalignedMemorySize);
        }

        // Add zone id to the list of memory zones.
        memory_zones.insert(zone.id.clone(), MemoryZone::default());

        for ram_region in ram_regions.iter() {
            let mut ram_region_offset = 0;
            let mut exit = false;

            loop {
                let mut ram_region_consumed = false;
                let mut pull_next_zone = false;

                let ram_region_available_size =
                    align_down(ram_region.1 as u64 - ram_region_offset, zone_align_size);
                if ram_region_available_size == 0 {
                    break;
                }
                let zone_sub_size = zone.size - zone_offset;

                let file_offset = zone_offset;
                let region_start = ram_region
                    .0
                    .checked_add(ram_region_offset)
                    .ok_or(Error::GuestAddressOverFlow)?;
                let region_size = if zone_sub_size <= ram_region_available_size {
                    if zone_sub_size == ram_region_available_size {
                        ram_region_consumed = true;
                    }

                    ram_region_offset += zone_sub_size;
                    pull_next_zone = true;

                    zone_sub_size
                } else {
                    zone_offset += ram_region_available_size;
                    ram_region_consumed = true;

                    ram_region_available_size
                };

                info!(
                    "create ram region for zone {}, region_start: {:#x}, region_size: {:#x}",
                    zone.id,
                    region_start.raw_value(),
                    region_size
                );
                let region = MemoryManager::create_ram_region(
                    &zone.file,
                    file_offset,
                    region_start,
                    region_size as usize,
                    prefault.unwrap_or(zone.prefault),
                    zone.shared,
                    zone.hugepages,
                    zone.hugepage_size,
                    zone.host_numa_node,
                    None,
                    thp,
                )?;

                // Add region to the list of regions associated with the
                // current memory zone.
                if let Some(memory_zone) = memory_zones.get_mut(&zone.id) {
                    memory_zone.regions.push(region.clone());
                }

                mem_regions.push(region);

                if pull_next_zone {
                    // Get the next zone and reset the offset.
                    zone_offset = 0;
                    if let Some(z) = zone_iter.next() {
                        zone = z;
                    } else {
                        exit = true;
                        break;
                    }
                    zone_align_size = memory_zone_get_align_size(zone)?;
                    if !is_aligned(zone.size, zone_align_size) {
                        return Err(Error::MisalignedMemorySize);
                    }

                    // Check if zone id already exist. In case it does, throw
                    // an error as we need unique identifiers. Otherwise, add
                    // the new zone id to the list of memory zones.
                    if memory_zones.contains_key(&zone.id) {
                        error!(
                            "Memory zone identifier '{}' found more than once. \
                            It must be unique",
                            zone.id,
                        );
                        return Err(Error::DuplicateZoneId);
                    }
                    memory_zones.insert(zone.id.clone(), MemoryZone::default());
                }

                if ram_region_consumed {
                    break;
                }
            }

            if exit {
                break;
            }
        }

        Ok((mem_regions, memory_zones))
    }

    // Restore both GuestMemory regions along with MemoryZone zones.
    fn restore_memory_regions_and_zones(
        guest_ram_mappings: &[GuestRamMapping],
        zones_config: &[MemoryZoneConfig],
        prefault: Option<bool>,
        mut existing_memory_files: HashMap<u32, File>,
        thp: bool,
    ) -> Result<(Vec<Arc<GuestRegionMmap>>, MemoryZones), Error> {
        let mut memory_regions = Vec::new();
        let mut memory_zones = HashMap::new();

        for zone_config in zones_config {
            memory_zones.insert(zone_config.id.clone(), MemoryZone::default());
        }

        for guest_ram_mapping in guest_ram_mappings {
            for zone_config in zones_config {
                if guest_ram_mapping.zone_id == zone_config.id {
                    let region = MemoryManager::create_ram_region(
                        if guest_ram_mapping.virtio_mem {
                            &None
                        } else {
                            &zone_config.file
                        },
                        guest_ram_mapping.file_offset,
                        GuestAddress(guest_ram_mapping.gpa),
                        guest_ram_mapping.size as usize,
                        prefault.unwrap_or(zone_config.prefault),
                        zone_config.shared,
                        zone_config.hugepages,
                        zone_config.hugepage_size,
                        zone_config.host_numa_node,
                        existing_memory_files.remove(&guest_ram_mapping.slot),
                        thp,
                    )?;
                    memory_regions.push(Arc::clone(&region));
                    if let Some(memory_zone) = memory_zones.get_mut(&guest_ram_mapping.zone_id) {
                        if guest_ram_mapping.virtio_mem {
                            let hotplugged_size = zone_config.hotplugged_size.unwrap_or(0);
                            let region_size = region.len();
                            memory_zone.virtio_mem_zone = Some(VirtioMemZone {
                                region,
                                virtio_device: None,
                                hotplugged_size,
                                hugepages: zone_config.hugepages,
                                blocks_state: Arc::new(Mutex::new(BlocksState::new(region_size))),
                            });
                        } else {
                            memory_zone.regions.push(region);
                        }
                    }
                }
            }
        }

        memory_regions.sort_by_key(|x| x.start_addr());

        Ok((memory_regions, memory_zones))
    }

    fn fill_saved_regions(
        &mut self,
        file_path: PathBuf,
        saved_regions: MemoryRangeTable,
    ) -> Result<(), Error> {
        if saved_regions.is_empty() {
            return Ok(());
        }

        // Open (read only) the snapshot file.
        let mut memory_file = OpenOptions::new()
            .read(true)
            .open(file_path)
            .map_err(Error::SnapshotOpen)?;

        let guest_memory = self.guest_memory.memory();
        for range in saved_regions.regions() {
            let mut offset: u64 = 0;
            // Here we are manually handling the retry in case we can't write
            // the whole region at once because we can't use the implementation
            // from vm-memory::GuestMemory of read_exact_from() as it is not
            // following the correct behavior. For more info about this issue
            // see: https://github.com/rust-vmm/vm-memory/issues/174
            loop {
                let bytes_read = guest_memory
                    .read_volatile_from(
                        GuestAddress(range.gpa + offset),
                        &mut memory_file,
                        (range.length - offset) as usize,
                    )
                    .map_err(Error::SnapshotCopy)?;
                offset += bytes_read as u64;

                if offset == range.length {
                    break;
                }
            }
        }

        Ok(())
    }

    fn validate_memory_config(
        config: &MemoryConfig,
        user_provided_zones: bool,
    ) -> Result<(u64, Vec<MemoryZoneConfig>, bool), Error> {
        let mut allow_mem_hotplug = false;

        if !user_provided_zones {
            if config.zones.is_some() {
                error!(
                    "User defined memory regions can't be provided if the \
                    memory size is not 0"
                );
                return Err(Error::InvalidMemoryParameters);
            }

            if config.hotplug_size.is_some() {
                allow_mem_hotplug = true;
            }

            if let Some(hotplugged_size) = config.hotplugged_size {
                if let Some(hotplug_size) = config.hotplug_size {
                    if hotplugged_size > hotplug_size {
                        error!(
                            "'hotplugged_size' {} can't be bigger than \
                            'hotplug_size' {}",
                            hotplugged_size, hotplug_size,
                        );
                        return Err(Error::InvalidMemoryParameters);
                    }
                } else {
                    error!(
                        "Invalid to define 'hotplugged_size' when there is\
                        no 'hotplug_size'"
                    );
                    return Err(Error::InvalidMemoryParameters);
                }
                if config.hotplug_method == HotplugMethod::Acpi {
                    error!(
                        "Invalid to define 'hotplugged_size' with hotplug \
                        method 'acpi'"
                    );
                    return Err(Error::InvalidMemoryParameters);
                }
            }

            // Create a single zone from the global memory config. This lets
            // us reuse the codepath for user defined memory zones.
            let zones = vec![MemoryZoneConfig {
                id: String::from(DEFAULT_MEMORY_ZONE),
                size: config.size,
                file: None,
                shared: config.shared,
                hugepages: config.hugepages,
                hugepage_size: config.hugepage_size,
                host_numa_node: None,
                hotplug_size: config.hotplug_size,
                hotplugged_size: config.hotplugged_size,
                prefault: config.prefault,
            }];

            Ok((config.size, zones, allow_mem_hotplug))
        } else {
            if config.zones.is_none() {
                error!(
                    "User defined memory regions must be provided if the \
                    memory size is 0"
                );
                return Err(Error::MissingMemoryZones);
            }

            // Safe to unwrap as we checked right above there were some
            // regions.
            let zones = config.zones.clone().unwrap();
            if zones.is_empty() {
                return Err(Error::MissingMemoryZones);
            }

            let mut total_ram_size: u64 = 0;
            for zone in zones.iter() {
                total_ram_size += zone.size;

                if zone.shared && zone.file.is_some() && zone.host_numa_node.is_some() {
                    error!(
                        "Invalid to set host NUMA policy for a memory zone \
                        backed by a regular file and mapped as 'shared'"
                    );
                    return Err(Error::InvalidSharedMemoryZoneWithHostNuma);
                }

                if zone.hotplug_size.is_some() && config.hotplug_method == HotplugMethod::Acpi {
                    error!("Invalid to set ACPI hotplug method for memory zones");
                    return Err(Error::InvalidHotplugMethodWithMemoryZones);
                }

                if let Some(hotplugged_size) = zone.hotplugged_size {
                    if let Some(hotplug_size) = zone.hotplug_size {
                        if hotplugged_size > hotplug_size {
                            error!(
                                "'hotplugged_size' {} can't be bigger than \
                                'hotplug_size' {}",
                                hotplugged_size, hotplug_size,
                            );
                            return Err(Error::InvalidMemoryParameters);
                        }
                    } else {
                        error!(
                            "Invalid to define 'hotplugged_size' when there is\
                            no 'hotplug_size' for a memory zone"
                        );
                        return Err(Error::InvalidMemoryParameters);
                    }
                    if config.hotplug_method == HotplugMethod::Acpi {
                        error!(
                            "Invalid to define 'hotplugged_size' with hotplug \
                            method 'acpi'"
                        );
                        return Err(Error::InvalidMemoryParameters);
                    }
                }
            }

            Ok((total_ram_size, zones, allow_mem_hotplug))
        }
    }

    pub fn allocate_address_space(&mut self) -> Result<(), Error> {
        let mut list = Vec::new();

        for (zone_id, memory_zone) in self.memory_zones.iter() {
            let mut regions: Vec<(Arc<vm_memory::GuestRegionMmap<AtomicBitmap>>, bool)> =
                memory_zone
                    .regions()
                    .iter()
                    .map(|r| (r.clone(), false))
                    .collect();

            if let Some(virtio_mem_zone) = memory_zone.virtio_mem_zone() {
                regions.push((virtio_mem_zone.region().clone(), true));
            }

            list.push((zone_id.clone(), regions));
        }

        for (zone_id, regions) in list {
            for (region, virtio_mem) in regions {
                let slot = self.create_userspace_mapping(
                    region.start_addr().raw_value(),
                    region.len(),
                    region.as_ptr() as u64,
                    self.mergeable,
                    false,
                    self.log_dirty,
                )?;

                let file_offset = if let Some(file_offset) = region.file_offset() {
                    file_offset.start()
                } else {
                    0
                };

                self.guest_ram_mappings.push(GuestRamMapping {
                    gpa: region.start_addr().raw_value(),
                    size: region.len(),
                    slot,
                    zone_id: zone_id.clone(),
                    virtio_mem,
                    file_offset,
                });
                self.ram_allocator
                    .allocate(Some(region.start_addr()), region.len(), None)
                    .ok_or(Error::MemoryRangeAllocation)?;
            }
        }

        // Allocate SubRegion and Reserved address ranges.
        for region in self.arch_mem_regions.iter() {
            if region.r_type == RegionType::Ram {
                // Ignore the RAM type since ranges have already been allocated
                // based on the GuestMemory regions.
                continue;
            }
            self.ram_allocator
                .allocate(
                    Some(GuestAddress(region.base)),
                    region.size as GuestUsize,
                    None,
                )
                .ok_or(Error::MemoryRangeAllocation)?;
        }

        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    pub fn add_uefi_flash(&mut self) -> Result<(), Error> {
        // On AArch64, the UEFI binary requires a flash device at address 0.
        // 4 MiB memory is mapped to simulate the flash.
        let uefi_mem_slot = self.allocate_memory_slot();
        let uefi_region = GuestRegionMmap::new(
            MmapRegion::new(arch::layout::UEFI_SIZE as usize).unwrap(),
            arch::layout::UEFI_START,
        )
        .unwrap();
        let uefi_mem_region = self.vm.make_user_memory_region(
            uefi_mem_slot,
            uefi_region.start_addr().raw_value(),
            uefi_region.len(),
            uefi_region.as_ptr() as u64,
            false,
            false,
        );
        self.vm
            .create_user_memory_region(uefi_mem_region)
            .map_err(Error::CreateUefiFlash)?;

        let uefi_flash =
            GuestMemoryAtomic::new(GuestMemoryMmap::from_regions(vec![uefi_region]).unwrap());

        self.uefi_flash = Some(uefi_flash);

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vm: Arc<dyn hypervisor::Vm>,
        config: &MemoryConfig,
        prefault: Option<bool>,
        phys_bits: u8,
        #[cfg(feature = "tdx")] tdx_enabled: bool,
        restore_data: Option<&MemoryManagerSnapshotData>,
        existing_memory_files: Option<HashMap<u32, File>>,
    ) -> Result<Arc<Mutex<MemoryManager>>, Error> {
        trace_scoped!("MemoryManager::new");

        let user_provided_zones = config.size == 0;

        let mmio_address_space_size = mmio_address_space_size(phys_bits);
        debug_assert_eq!(
            (((mmio_address_space_size) >> 16) << 16),
            mmio_address_space_size
        );
        let start_of_platform_device_area =
            GuestAddress(mmio_address_space_size - PLATFORM_DEVICE_AREA_SIZE);
        let end_of_device_area = start_of_platform_device_area.unchecked_sub(1);

        let (ram_size, zones, allow_mem_hotplug) =
            Self::validate_memory_config(config, user_provided_zones)?;

        let (
            start_of_device_area,
            boot_ram,
            current_ram,
            arch_mem_regions,
            memory_zones,
            guest_memory,
            boot_guest_memory,
            hotplug_slots,
            next_memory_slot,
            selected_slot,
            next_hotplug_slot,
        ) = if let Some(data) = restore_data {
            let (regions, memory_zones) = Self::restore_memory_regions_and_zones(
                &data.guest_ram_mappings,
                &zones,
                prefault,
                existing_memory_files.unwrap_or_default(),
                config.thp,
            )?;
            let guest_memory =
                GuestMemoryMmap::from_arc_regions(regions).map_err(Error::GuestMemory)?;
            let boot_guest_memory = guest_memory.clone();
            (
                GuestAddress(data.start_of_device_area),
                data.boot_ram,
                data.current_ram,
                data.arch_mem_regions.clone(),
                memory_zones,
                guest_memory,
                boot_guest_memory,
                data.hotplug_slots.clone(),
                data.next_memory_slot,
                data.selected_slot,
                data.next_hotplug_slot,
            )
        } else {
            // Init guest memory
            let arch_mem_regions = arch::arch_memory_regions();

            let ram_regions: Vec<(GuestAddress, usize)> = arch_mem_regions
                .iter()
                .filter(|r| r.2 == RegionType::Ram)
                .map(|r| (r.0, r.1))
                .collect();

            let arch_mem_regions: Vec<ArchMemRegion> = arch_mem_regions
                .iter()
                .map(|(a, b, c)| ArchMemRegion {
                    base: a.0,
                    size: *b,
                    r_type: *c,
                })
                .collect();

            let (mem_regions, mut memory_zones) =
                Self::create_memory_regions_from_zones(&ram_regions, &zones, prefault, config.thp)?;

            let mut guest_memory =
                GuestMemoryMmap::from_arc_regions(mem_regions).map_err(Error::GuestMemory)?;

            let boot_guest_memory = guest_memory.clone();

            let mut start_of_device_area =
                MemoryManager::start_addr(guest_memory.last_addr(), allow_mem_hotplug)?;

            // Update list of memory zones for resize.
            for zone in zones.iter() {
                if let Some(memory_zone) = memory_zones.get_mut(&zone.id) {
                    if let Some(hotplug_size) = zone.hotplug_size {
                        if hotplug_size == 0 {
                            error!("'hotplug_size' can't be 0");
                            return Err(Error::InvalidHotplugSize);
                        }

                        if !user_provided_zones && config.hotplug_method == HotplugMethod::Acpi {
                            start_of_device_area = start_of_device_area
                                .checked_add(hotplug_size)
                                .ok_or(Error::GuestAddressOverFlow)?;
                        } else {
                            // Alignment must be "natural" i.e. same as size of block
                            let start_addr = GuestAddress(
                                start_of_device_area
                                    .0
                                    .div_ceil(virtio_devices::VIRTIO_MEM_ALIGN_SIZE)
                                    * virtio_devices::VIRTIO_MEM_ALIGN_SIZE,
                            );

                            // When `prefault` is set by vm_restore, memory manager
                            // will create ram region with `prefault` option in
                            // restore config rather than same option in zone
                            let region = MemoryManager::create_ram_region(
                                &None,
                                0,
                                start_addr,
                                hotplug_size as usize,
                                prefault.unwrap_or(zone.prefault),
                                zone.shared,
                                zone.hugepages,
                                zone.hugepage_size,
                                zone.host_numa_node,
                                None,
                                config.thp,
                            )?;

                            guest_memory = guest_memory
                                .insert_region(Arc::clone(&region))
                                .map_err(Error::GuestMemory)?;

                            let hotplugged_size = zone.hotplugged_size.unwrap_or(0);
                            let region_size = region.len();
                            memory_zone.virtio_mem_zone = Some(VirtioMemZone {
                                region,
                                virtio_device: None,
                                hotplugged_size,
                                hugepages: zone.hugepages,
                                blocks_state: Arc::new(Mutex::new(BlocksState::new(region_size))),
                            });

                            start_of_device_area = start_addr
                                .checked_add(hotplug_size)
                                .ok_or(Error::GuestAddressOverFlow)?;
                        }
                    }
                } else {
                    return Err(Error::MissingZoneIdentifier);
                }
            }

            let mut hotplug_slots = Vec::with_capacity(HOTPLUG_COUNT);
            hotplug_slots.resize_with(HOTPLUG_COUNT, HotPlugState::default);

            (
                start_of_device_area,
                ram_size,
                ram_size,
                arch_mem_regions,
                memory_zones,
                guest_memory,
                boot_guest_memory,
                hotplug_slots,
                0,
                0,
                0,
            )
        };

        let guest_memory = GuestMemoryAtomic::new(guest_memory);

        let allocator = Arc::new(Mutex::new(
            SystemAllocator::new(
                GuestAddress(0),
                1 << 16,
                start_of_platform_device_area,
                PLATFORM_DEVICE_AREA_SIZE,
                #[cfg(target_arch = "x86_64")]
                vec![GsiApic::new(
                    X86_64_IRQ_BASE,
                    ioapic::NUM_IOAPIC_PINS as u32 - X86_64_IRQ_BASE,
                )],
            )
            .ok_or(Error::CreateSystemAllocator)?,
        ));

        #[cfg(not(feature = "tdx"))]
        let dynamic = true;
        #[cfg(feature = "tdx")]
        let dynamic = !tdx_enabled;

        let acpi_address = if dynamic
            && config.hotplug_method == HotplugMethod::Acpi
            && (config.hotplug_size.unwrap_or_default() > 0)
        {
            Some(
                allocator
                    .lock()
                    .unwrap()
                    .allocate_platform_mmio_addresses(None, MEMORY_MANAGER_ACPI_SIZE as u64, None)
                    .ok_or(Error::AllocateMmioAddress)?,
            )
        } else {
            None
        };

        let end_of_ram_area = start_of_device_area.unchecked_sub(1);
        let ram_allocator = AddressAllocator::new(GuestAddress(0), start_of_device_area.0).unwrap();

        #[allow(unused_mut)]
        let mut memory_manager = MemoryManager {
            boot_guest_memory,
            guest_memory,
            next_memory_slot: Arc::new(AtomicU32::new(next_memory_slot)),
            memory_slot_free_list: Arc::new(Mutex::new(Vec::new())),
            start_of_device_area,
            end_of_device_area,
            end_of_ram_area,
            vm,
            hotplug_slots,
            selected_slot,
            mergeable: config.mergeable,
            allocator,
            hotplug_method: config.hotplug_method,
            boot_ram,
            current_ram,
            next_hotplug_slot,
            shared: config.shared,
            hugepages: config.hugepages,
            hugepage_size: config.hugepage_size,
            prefault: config.prefault,
            user_provided_zones,
            snapshot_memory_ranges: MemoryRangeTable::default(),
            memory_zones,
            guest_ram_mappings: Vec::new(),
            acpi_address,
            log_dirty: dynamic, // Cannot log dirty pages on a TD
            arch_mem_regions,
            ram_allocator,
            dynamic,
            #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
            uefi_flash: None,
            thp: config.thp,
        };

        Ok(Arc::new(Mutex::new(memory_manager)))
    }

    pub fn new_from_snapshot(
        snapshot: &Snapshot,
        vm: Arc<dyn hypervisor::Vm>,
        config: &MemoryConfig,
        source_url: Option<&str>,
        prefault: bool,
        phys_bits: u8,
    ) -> Result<Arc<Mutex<MemoryManager>>, Error> {
        if let Some(source_url) = source_url {
            let mut memory_file_path = url_to_path(source_url).map_err(Error::Restore)?;
            memory_file_path.push(String::from(SNAPSHOT_FILENAME));

            let mem_snapshot: MemoryManagerSnapshotData =
                snapshot.to_state().map_err(Error::Restore)?;

            let mm = MemoryManager::new(
                vm,
                config,
                Some(prefault),
                phys_bits,
                #[cfg(feature = "tdx")]
                false,
                Some(&mem_snapshot),
                None,
            )?;

            mm.lock()
                .unwrap()
                .fill_saved_regions(memory_file_path, mem_snapshot.memory_ranges)?;

            Ok(mm)
        } else {
            Err(Error::RestoreMissingSourceUrl)
        }
    }

    fn memfd_create(name: &ffi::CStr, flags: u32) -> Result<RawFd, io::Error> {
        // SAFETY: FFI call with correct arguments
        let res = unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), flags) };

        if res < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(res as RawFd)
        }
    }

    fn mbind(
        addr: *mut u8,
        len: u64,
        mode: u32,
        nodemask: Vec<u64>,
        maxnode: u64,
        flags: u32,
    ) -> Result<(), io::Error> {
        // SAFETY: FFI call with correct arguments
        let res = unsafe {
            libc::syscall(
                libc::SYS_mbind,
                addr as *mut libc::c_void,
                len,
                mode,
                nodemask.as_ptr(),
                maxnode,
                flags,
            )
        };

        if res < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn create_anonymous_file(
        size: usize,
        hugepages: bool,
        hugepage_size: Option<u64>,
    ) -> Result<FileOffset, Error> {
        let fd = Self::memfd_create(
            &ffi::CString::new("ch_ram").unwrap(),
            libc::MFD_CLOEXEC
                | if hugepages {
                    libc::MFD_HUGETLB
                        | if let Some(hugepage_size) = hugepage_size {
                            /*
                             * From the Linux kernel:
                             * Several system calls take a flag to request "hugetlb" huge pages.
                             * Without further specification, these system calls will use the
                             * system's default huge page size.  If a system supports multiple
                             * huge page sizes, the desired huge page size can be specified in
                             * bits [26:31] of the flag arguments.  The value in these 6 bits
                             * will encode the log2 of the huge page size.
                             */

                            hugepage_size.trailing_zeros() << 26
                        } else {
                            // Use the system default huge page size
                            0
                        }
                } else {
                    0
                },
        )
        .map_err(Error::SharedFileCreate)?;

        // SAFETY: fd is valid
        let f = unsafe { File::from_raw_fd(fd) };
        f.set_len(size as u64).map_err(Error::SharedFileSetLen)?;

        Ok(FileOffset::new(f, 0))
    }

    fn open_backing_file(backing_file: &PathBuf, file_offset: u64) -> Result<FileOffset, Error> {
        if backing_file.is_dir() {
            Err(Error::DirectoryAsBackingFileForMemory)
        } else {
            let f = OpenOptions::new()
                .read(true)
                .write(true)
                .open(backing_file)
                .map_err(Error::SharedFileCreate)?;

            Ok(FileOffset::new(f, file_offset))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_ram_region(
        backing_file: &Option<PathBuf>,
        file_offset: u64,
        start_addr: GuestAddress,
        size: usize,
        prefault: bool,
        shared: bool,
        hugepages: bool,
        hugepage_size: Option<u64>,
        host_numa_node: Option<u32>,
        existing_memory_file: Option<File>,
        thp: bool,
    ) -> Result<Arc<GuestRegionMmap>, Error> {
        let mut mmap_flags = libc::MAP_NORESERVE;

        // The duplication of mmap_flags ORing here is unfortunate but it also makes
        // the complexity of the handling clear.
        let fo = if let Some(f) = existing_memory_file {
            // It must be MAP_SHARED as we wouldn't already have an FD
            mmap_flags |= libc::MAP_SHARED;
            Some(FileOffset::new(f, file_offset))
        } else if let Some(backing_file) = backing_file {
            if shared {
                mmap_flags |= libc::MAP_SHARED;
            } else {
                mmap_flags |= libc::MAP_PRIVATE;
            }
            Some(Self::open_backing_file(backing_file, file_offset)?)
        } else if shared || hugepages {
            // For hugepages we must also MAP_SHARED otherwise we will trigger #4805
            // because the MAP_PRIVATE will trigger CoW against the backing file with
            // the VFIO pinning
            mmap_flags |= libc::MAP_SHARED;
            Some(Self::create_anonymous_file(size, hugepages, hugepage_size)?)
        } else {
            mmap_flags |= libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
            None
        };

        let region = GuestRegionMmap::new(
            MmapRegion::build(fo, size, libc::PROT_READ | libc::PROT_WRITE, mmap_flags)
                .map_err(Error::GuestMemoryRegion)?,
            start_addr,
        )
        .map_err(Error::GuestMemory)?;

        // Apply NUMA policy if needed.
        if let Some(node) = host_numa_node {
            let addr = region.deref().as_ptr();
            let len = region.deref().size() as u64;
            let mode = MPOL_BIND;
            let mut nodemask: Vec<u64> = Vec::new();
            let flags = MPOL_MF_STRICT | MPOL_MF_MOVE;

            // Linux is kind of buggy in the way it interprets maxnode as it
            // will cut off the last node. That's why we have to add 1 to what
            // we would consider as the proper maxnode value.
            let maxnode = node as u64 + 1 + 1;

            // Allocate the right size for the vector.
            nodemask.resize((node as usize / 64) + 1, 0);

            // Fill the global bitmask through the nodemask vector.
            let idx = (node / 64) as usize;
            let shift = node % 64;
            nodemask[idx] |= 1u64 << shift;

            // Policies are enforced by using MPOL_MF_MOVE flag as it will
            // force the kernel to move all pages that might have been already
            // allocated to the proper set of NUMA nodes. MPOL_MF_STRICT is
            // used to throw an error if MPOL_MF_MOVE didn't succeed.
            // MPOL_BIND is the selected mode as it specifies a strict policy
            // that restricts memory allocation to the nodes specified in the
            // nodemask.
            Self::mbind(addr, len, mode, nodemask, maxnode, flags)
                .map_err(Error::ApplyNumaPolicy)?;
        }

        // Prefault the region if needed, in parallel.
        if prefault {
            let page_size =
                Self::get_prefault_align_size(backing_file, hugepages, hugepage_size)? as usize;

            if !is_aligned(size, page_size) {
                warn!(
                    "Prefaulting memory size {} misaligned with page size {}",
                    size, page_size
                );
            }

            let num_pages = size / page_size;

            let num_threads = Self::get_prefault_num_threads(page_size, num_pages);

            let pages_per_thread = num_pages / num_threads;
            let remainder = num_pages % num_threads;

            let barrier = Arc::new(Barrier::new(num_threads));
            thread::scope(|s| {
                let r = &region;
                for i in 0..num_threads {
                    let barrier = Arc::clone(&barrier);
                    s.spawn(move || {
                        // Wait until all threads have been spawned to avoid contention
                        // over mmap_sem between thread stack allocation and page faulting.
                        barrier.wait();
                        let pages = pages_per_thread + if i < remainder { 1 } else { 0 };
                        let offset =
                            page_size * ((i * pages_per_thread) + std::cmp::min(i, remainder));
                        // SAFETY: FFI call with correct arguments
                        let ret = unsafe {
                            let addr = r.as_ptr().add(offset);
                            libc::madvise(addr as _, pages * page_size, libc::MADV_POPULATE_WRITE)
                        };
                        if ret != 0 {
                            let e = io::Error::last_os_error();
                            warn!("Failed to prefault pages: {}", e);
                        }
                    });
                }
            });
        }

        if region.file_offset().is_none() && thp {
            info!(
                "Anonymous mapping at 0x{:x} (size = 0x{:x})",
                region.as_ptr() as u64,
                size
            );
            // SAFETY: FFI call with correct arguments
            let ret = unsafe { libc::madvise(region.as_ptr() as _, size, libc::MADV_HUGEPAGE) };
            if ret != 0 {
                let e = io::Error::last_os_error();
                warn!("Failed to mark pages as THP eligible: {}", e);
            }
        }

        Ok(Arc::new(region))
    }

    // Duplicate of `memory_zone_get_align_size` that does not require a `zone`
    fn get_prefault_align_size(
        backing_file: &Option<PathBuf>,
        hugepages: bool,
        hugepage_size: Option<u64>,
    ) -> Result<u64, Error> {
        // SAFETY: FFI call. Trivially safe.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 };
        match (hugepages, hugepage_size, backing_file) {
            (false, _, _) => Ok(page_size),
            (true, Some(hugepage_size), _) => Ok(hugepage_size),
            (true, None, _) => {
                // There are two scenarios here:
                //  - `hugepages` is enabled but `hugepage_size` is not specified:
                //     Call `statfs` for `/dev/hugepages` for getting the default size of hugepage
                //  - The backing file is specified:
                //     Call `statfs` for the file and get its `f_bsize`.  If the value is larger than the page
                //     size of normal page, just use the `f_bsize` because the file is in a hugetlbfs.  If the
                //     value is less than or equal to the page size, just use the page size.
                let path = backing_file
                    .as_ref()
                    .map_or(Ok("/dev/hugepages"), |pathbuf| {
                        pathbuf.to_str().ok_or(Error::InvalidMemoryParameters)
                    })?;
                let align_size = std::cmp::max(page_size, statfs_get_bsize(path)?);
                Ok(align_size)
            }
        }
    }

    fn get_prefault_num_threads(page_size: usize, num_pages: usize) -> usize {
        let mut n: usize = 1;

        // Do not create more threads than processors available.
        // SAFETY: FFI call. Trivially safe.
        let procs = unsafe { libc::sysconf(_SC_NPROCESSORS_ONLN) };
        if procs > 0 {
            n = std::cmp::min(procs as usize, MAX_PREFAULT_THREAD_COUNT);
        }

        // Do not create more threads than pages being allocated.
        n = std::cmp::min(n, num_pages);

        // Do not create threads to allocate less than 64 MiB of memory.
        n = std::cmp::min(
            n,
            std::cmp::max(1, page_size * num_pages / (64 * (1 << 26))),
        );

        n
    }

    // Update the GuestMemoryMmap with the new range
    fn add_region(&mut self, region: Arc<GuestRegionMmap>) -> Result<(), Error> {
        let guest_memory = self
            .guest_memory
            .memory()
            .insert_region(region)
            .map_err(Error::GuestMemory)?;
        self.guest_memory.lock().unwrap().replace(guest_memory);

        Ok(())
    }

    //
    // Calculate the start address of an area next to RAM.
    //
    // If memory hotplug is allowed, the start address needs to be aligned
    // (rounded-up) to 128MiB boundary.
    // If memory hotplug is not allowed, there is no alignment required.
    // And it must also start at the 64bit start.
    fn start_addr(mem_end: GuestAddress, allow_mem_hotplug: bool) -> Result<GuestAddress, Error> {
        let mut start_addr = if allow_mem_hotplug {
            GuestAddress(mem_end.0 | ((128 << 20) - 1))
        } else {
            mem_end
        };

        start_addr = start_addr
            .checked_add(1)
            .ok_or(Error::GuestAddressOverFlow)?;

        #[cfg(not(target_arch = "riscv64"))]
        if mem_end < arch::layout::MEM_32BIT_RESERVED_START {
            return Ok(arch::layout::RAM_64BIT_START);
        }

        Ok(start_addr)
    }

    pub fn add_ram_region(
        &mut self,
        start_addr: GuestAddress,
        size: usize,
    ) -> Result<Arc<GuestRegionMmap>, Error> {
        // Allocate memory for the region
        let region = MemoryManager::create_ram_region(
            &None,
            0,
            start_addr,
            size,
            self.prefault,
            self.shared,
            self.hugepages,
            self.hugepage_size,
            None,
            None,
            self.thp,
        )?;

        // Map it into the guest
        let slot = self.create_userspace_mapping(
            region.start_addr().0,
            region.len(),
            region.as_ptr() as u64,
            self.mergeable,
            false,
            self.log_dirty,
        )?;
        self.guest_ram_mappings.push(GuestRamMapping {
            gpa: region.start_addr().raw_value(),
            size: region.len(),
            slot,
            zone_id: DEFAULT_MEMORY_ZONE.to_string(),
            virtio_mem: false,
            file_offset: 0,
        });

        self.add_region(Arc::clone(&region))?;

        Ok(region)
    }

    fn hotplug_ram_region(&mut self, size: usize) -> Result<Arc<GuestRegionMmap>, Error> {
        info!("Hotplugging new RAM: {}", size);

        // Check that there is a free slot
        if self.next_hotplug_slot >= HOTPLUG_COUNT {
            return Err(Error::NoSlotAvailable);
        }

        // "Inserted" DIMM must have a size that is a multiple of 128MiB
        if !size.is_multiple_of(128 << 20) {
            return Err(Error::InvalidSize);
        }

        let start_addr = MemoryManager::start_addr(self.guest_memory.memory().last_addr(), true)?;

        if start_addr
            .checked_add((size - 1).try_into().unwrap())
            .unwrap()
            > self.end_of_ram_area
        {
            return Err(Error::InsufficientHotplugRam);
        }

        let region = self.add_ram_region(start_addr, size)?;

        // Add region to the list of regions associated with the default
        // memory zone.
        if let Some(memory_zone) = self.memory_zones.get_mut(DEFAULT_MEMORY_ZONE) {
            memory_zone.regions.push(Arc::clone(&region));
        }

        // Tell the allocator
        self.ram_allocator
            .allocate(Some(start_addr), size as GuestUsize, None)
            .ok_or(Error::MemoryRangeAllocation)?;

        // Update the slot so that it can be queried via the I/O port
        let slot = &mut self.hotplug_slots[self.next_hotplug_slot];
        slot.active = true;
        slot.inserting = true;
        slot.base = region.start_addr().0;
        slot.length = region.len();

        self.next_hotplug_slot += 1;

        Ok(region)
    }

    pub fn guest_memory(&self) -> GuestMemoryAtomic<GuestMemoryMmap> {
        self.guest_memory.clone()
    }

    pub fn boot_guest_memory(&self) -> GuestMemoryMmap {
        self.boot_guest_memory.clone()
    }

    pub fn allocator(&self) -> Arc<Mutex<SystemAllocator>> {
        self.allocator.clone()
    }

    pub fn start_of_device_area(&self) -> GuestAddress {
        self.start_of_device_area
    }

    pub fn end_of_device_area(&self) -> GuestAddress {
        self.end_of_device_area
    }

    pub fn memory_slot_allocator(&mut self) -> MemorySlotAllocator {
        let memory_slot_free_list = Arc::clone(&self.memory_slot_free_list);
        let next_memory_slot = Arc::clone(&self.next_memory_slot);
        MemorySlotAllocator::new(next_memory_slot, memory_slot_free_list)
    }

    pub fn allocate_memory_slot(&mut self) -> u32 {
        self.memory_slot_allocator().next_memory_slot()
    }

    pub fn create_userspace_mapping(
        &mut self,
        guest_phys_addr: u64,
        memory_size: u64,
        userspace_addr: u64,
        mergeable: bool,
        readonly: bool,
        log_dirty: bool,
    ) -> Result<u32, Error> {
        let slot = self.allocate_memory_slot();
        let mem_region = self.vm.make_user_memory_region(
            slot,
            guest_phys_addr,
            memory_size,
            userspace_addr,
            readonly,
            log_dirty,
        );

        info!(
            "Creating userspace mapping: {:x} -> {:x} {:x}, slot {}",
            guest_phys_addr, userspace_addr, memory_size, slot
        );

        self.vm
            .create_user_memory_region(mem_region)
            .map_err(Error::CreateUserMemoryRegion)?;

        // SAFETY: the address and size are valid since the
        // mmap succeeded.
        let ret = unsafe {
            libc::madvise(
                userspace_addr as *mut libc::c_void,
                memory_size as libc::size_t,
                libc::MADV_DONTDUMP,
            )
        };
        if ret != 0 {
            let e = io::Error::last_os_error();
            warn!("Failed to mark mapping as MADV_DONTDUMP: {}", e);
        }

        // Mark the pages as mergeable if explicitly asked for.
        if mergeable {
            // SAFETY: the address and size are valid since the
            // mmap succeeded.
            let ret = unsafe {
                libc::madvise(
                    userspace_addr as *mut libc::c_void,
                    memory_size as libc::size_t,
                    libc::MADV_MERGEABLE,
                )
            };
            if ret != 0 {
                let err = io::Error::last_os_error();
                // Safe to unwrap because the error is constructed with
                // last_os_error(), which ensures the output will be Some().
                let errno = err.raw_os_error().unwrap();
                if errno == libc::EINVAL {
                    warn!("kernel not configured with CONFIG_KSM");
                } else {
                    warn!("madvise error: {}", err);
                }
                warn!("failed to mark pages as mergeable");
            }
        }

        info!(
            "Created userspace mapping: {:x} -> {:x} {:x}",
            guest_phys_addr, userspace_addr, memory_size
        );

        Ok(slot)
    }

    pub fn remove_userspace_mapping(
        &mut self,
        guest_phys_addr: u64,
        memory_size: u64,
        userspace_addr: u64,
        mergeable: bool,
        slot: u32,
    ) -> Result<(), Error> {
        let mem_region = self.vm.make_user_memory_region(
            slot,
            guest_phys_addr,
            memory_size,
            userspace_addr,
            false, /* readonly -- don't care */
            false, /* log dirty */
        );

        self.vm
            .remove_user_memory_region(mem_region)
            .map_err(Error::RemoveUserMemoryRegion)?;

        // Mark the pages as unmergeable if there were previously marked as
        // mergeable.
        if mergeable {
            // SAFETY: the address and size are valid as the region was
            // previously advised.
            let ret = unsafe {
                libc::madvise(
                    userspace_addr as *mut libc::c_void,
                    memory_size as libc::size_t,
                    libc::MADV_UNMERGEABLE,
                )
            };
            if ret != 0 {
                let err = io::Error::last_os_error();
                // Safe to unwrap because the error is constructed with
                // last_os_error(), which ensures the output will be Some().
                let errno = err.raw_os_error().unwrap();
                if errno == libc::EINVAL {
                    warn!("kernel not configured with CONFIG_KSM");
                } else {
                    warn!("madvise error: {}", err);
                }
                warn!("failed to mark pages as unmergeable");
            }
        }

        info!(
            "Removed userspace mapping: {:x} -> {:x} {:x}",
            guest_phys_addr, userspace_addr, memory_size
        );

        Ok(())
    }

    pub fn virtio_mem_resize(&mut self, id: &str, size: u64) -> Result<(), Error> {
        if let Some(memory_zone) = self.memory_zones.get_mut(id) {
            if let Some(virtio_mem_zone) = &mut memory_zone.virtio_mem_zone {
                if let Some(virtio_mem_device) = virtio_mem_zone.virtio_device.as_ref() {
                    virtio_mem_device
                        .lock()
                        .unwrap()
                        .resize(size)
                        .map_err(Error::VirtioMemResizeFail)?;
                }

                // Keep the hotplugged_size up to date.
                virtio_mem_zone.hotplugged_size = size;
            } else {
                error!("Failed resizing virtio-mem region: No virtio-mem handler");
                return Err(Error::MissingVirtioMemHandler);
            }

            return Ok(());
        }

        error!("Failed resizing virtio-mem region: Unknown memory zone");
        Err(Error::UnknownMemoryZone)
    }

    /// In case this function resulted in adding a new memory region to the
    /// guest memory, the new region is returned to the caller. The virtio-mem
    /// use case never adds a new region as the whole hotpluggable memory has
    /// already been allocated at boot time.
    pub fn resize(&mut self, desired_ram: u64) -> Result<Option<Arc<GuestRegionMmap>>, Error> {
        if self.user_provided_zones {
            error!(
                "Not allowed to resize guest memory when backed with user \
                defined memory zones."
            );
            return Err(Error::InvalidResizeWithMemoryZones);
        }

        let mut region: Option<Arc<GuestRegionMmap>> = None;
        match self.hotplug_method {
            HotplugMethod::VirtioMem => {
                if desired_ram >= self.boot_ram {
                    if !self.dynamic {
                        return Ok(region);
                    }

                    self.virtio_mem_resize(DEFAULT_MEMORY_ZONE, desired_ram - self.boot_ram)?;
                    self.current_ram = desired_ram;
                }
            }
            HotplugMethod::Acpi => {
                if desired_ram > self.current_ram {
                    if !self.dynamic {
                        return Ok(region);
                    }

                    region =
                        Some(self.hotplug_ram_region((desired_ram - self.current_ram) as usize)?);
                    self.current_ram = desired_ram;
                }
            }
        }
        Ok(region)
    }

    pub fn resize_zone(&mut self, id: &str, virtio_mem_size: u64) -> Result<(), Error> {
        if !self.user_provided_zones {
            error!(
                "Not allowed to resize guest memory zone when no zone is \
                defined."
            );
            return Err(Error::ResizeZone);
        }

        self.virtio_mem_resize(id, virtio_mem_size)
    }

    pub fn is_hardlink(f: &File) -> bool {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: FFI call with correct arguments
        let ret = unsafe { libc::fstat(f.as_raw_fd(), stat.as_mut_ptr()) };
        if ret != 0 {
            error!("Couldn't fstat the backing file");
            return false;
        }

        // SAFETY: stat is valid
        unsafe { (*stat.as_ptr()).st_nlink as usize > 0 }
    }

    pub fn memory_zones(&self) -> &MemoryZones {
        &self.memory_zones
    }

    pub fn memory_zones_mut(&mut self) -> &mut MemoryZones {
        &mut self.memory_zones
    }

    pub fn memory_range_table(
        &self,
        snapshot: bool,
    ) -> std::result::Result<MemoryRangeTable, MigratableError> {
        let mut table = MemoryRangeTable::default();

        for memory_zone in self.memory_zones.values() {
            if let Some(virtio_mem_zone) = memory_zone.virtio_mem_zone() {
                table.extend(virtio_mem_zone.plugged_ranges());
            }

            for region in memory_zone.regions() {
                if snapshot {
                    if let Some(file_offset) = region.file_offset() {
                        if (region.flags() & libc::MAP_SHARED == libc::MAP_SHARED)
                            && Self::is_hardlink(file_offset.file())
                        {
                            // In this very specific case, we know the memory
                            // region is backed by a file on the host filesystem
                            // that can be accessed by the user, and additionally
                            // the mapping is shared, which means that modifications
                            // to the content are written to the actual file.
                            // When meeting these conditions, we can skip the
                            // copy of the memory content for this specific region,
                            // as we can assume the user will have it saved through
                            // the backing file already.
                            continue;
                        }
                    }
                }

                table.push(MemoryRange {
                    gpa: region.start_addr().raw_value(),
                    length: region.len(),
                });
            }
        }

        Ok(table)
    }

    pub fn snapshot_data(&self) -> MemoryManagerSnapshotData {
        MemoryManagerSnapshotData {
            memory_ranges: self.snapshot_memory_ranges.clone(),
            guest_ram_mappings: self.guest_ram_mappings.clone(),
            start_of_device_area: self.start_of_device_area.0,
            boot_ram: self.boot_ram,
            current_ram: self.current_ram,
            arch_mem_regions: self.arch_mem_regions.clone(),
            hotplug_slots: self.hotplug_slots.clone(),
            next_memory_slot: self.next_memory_slot.load(Ordering::SeqCst),
            selected_slot: self.selected_slot,
            next_hotplug_slot: self.next_hotplug_slot,
        }
    }

    pub fn memory_slot_fds(&self) -> HashMap<u32, RawFd> {
        let mut memory_slot_fds = HashMap::new();
        for guest_ram_mapping in &self.guest_ram_mappings {
            let slot = guest_ram_mapping.slot;
            let guest_memory = self.guest_memory.memory();
            let file = guest_memory
                .find_region(GuestAddress(guest_ram_mapping.gpa))
                .unwrap()
                .file_offset()
                .unwrap()
                .file();
            memory_slot_fds.insert(slot, file.as_raw_fd());
        }
        memory_slot_fds
    }

    pub fn acpi_address(&self) -> Option<GuestAddress> {
        self.acpi_address
    }

    pub fn num_guest_ram_mappings(&self) -> u32 {
        self.guest_ram_mappings.len() as u32
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    pub fn uefi_flash(&self) -> GuestMemoryAtomic<GuestMemoryMmap> {
        self.uefi_flash.as_ref().unwrap().clone()
    }

    #[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
    pub fn coredump_memory_regions(&self, mem_offset: u64) -> CoredumpMemoryRegions {
        let mut mapping_sorted_by_gpa = self.guest_ram_mappings.clone();
        mapping_sorted_by_gpa.sort_by_key(|m| m.gpa);

        let mut mem_offset_in_elf = mem_offset;
        let mut ram_maps = BTreeMap::new();
        for mapping in mapping_sorted_by_gpa.iter() {
            ram_maps.insert(
                mapping.gpa,
                CoredumpMemoryRegion {
                    mem_offset_in_elf,
                    mem_size: mapping.size,
                },
            );
            mem_offset_in_elf += mapping.size;
        }

        CoredumpMemoryRegions { ram_maps }
    }

    #[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
    pub fn coredump_iterate_save_mem(
        &mut self,
        dump_state: &DumpState,
    ) -> std::result::Result<(), GuestDebuggableError> {
        let snapshot_memory_ranges = self
            .memory_range_table(false)
            .map_err(|e| GuestDebuggableError::Coredump(e.into()))?;

        if snapshot_memory_ranges.is_empty() {
            return Ok(());
        }

        let coredump_file = dump_state.file.as_ref().unwrap();

        let guest_memory = self.guest_memory.memory();
        let mut total_bytes: u64 = 0;

        for range in snapshot_memory_ranges.regions() {
            let mut offset: u64 = 0;
            loop {
                let bytes_written = guest_memory
                    .write_volatile_to(
                        GuestAddress(range.gpa + offset),
                        &mut coredump_file.as_fd(),
                        (range.length - offset) as usize,
                    )
                    .map_err(|e| GuestDebuggableError::Coredump(e.into()))?;
                offset += bytes_written as u64;
                total_bytes += bytes_written as u64;

                if offset == range.length {
                    break;
                }
            }
        }

        debug!("coredump total bytes {}", total_bytes);
        Ok(())
    }

    pub fn receive_memory_regions<F>(
        &mut self,
        ranges: &MemoryRangeTable,
        fd: &mut F,
    ) -> std::result::Result<(), MigratableError>
    where
        F: ReadVolatile,
    {
        let guest_memory = self.guest_memory();
        let mem = guest_memory.memory();

        for range in ranges.regions() {
            let mut offset: u64 = 0;
            // Here we are manually handling the retry in case we can't the
            // whole region at once because we can't use the implementation
            // from vm-memory::GuestMemory of read_exact_from() as it is not
            // following the correct behavior. For more info about this issue
            // see: https://github.com/rust-vmm/vm-memory/issues/174
            loop {
                let bytes_read = mem
                    .read_volatile_from(
                        GuestAddress(range.gpa + offset),
                        fd,
                        (range.length - offset) as usize,
                    )
                    .map_err(|e| {
                        MigratableError::MigrateReceive(anyhow!(
                            "Error receiving memory from socket: {}",
                            e
                        ))
                    })?;
                offset += bytes_read as u64;

                if offset == range.length {
                    break;
                }
            }
        }

        Ok(())
    }
}

struct MemoryNotify {
    slot_id: usize,
}

impl Aml for MemoryNotify {
    fn to_aml_bytes(&self, sink: &mut dyn acpi_tables::AmlSink) {
        let object = aml::Path::new(&format!("M{:03}", self.slot_id));
        aml::If::new(
            &aml::Equal::new(&aml::Arg(0), &self.slot_id),
            vec![&aml::Notify::new(&object, &aml::Arg(1))],
        )
        .to_aml_bytes(sink)
    }
}

struct MemorySlot {
    slot_id: usize,
}

impl Aml for MemorySlot {
    fn to_aml_bytes(&self, sink: &mut dyn acpi_tables::AmlSink) {
        aml::Device::new(
            format!("M{:03}", self.slot_id).as_str().into(),
            vec![
                &aml::Name::new("_HID".into(), &aml::EISAName::new("PNP0C80")),
                &aml::Name::new("_UID".into(), &self.slot_id),
                /*
                _STA return value:
                Bit [0] – Set if the device is present.
                Bit [1] – Set if the device is enabled and decoding its resources.
                Bit [2] – Set if the device should be shown in the UI.
                Bit [3] – Set if the device is functioning properly (cleared if device failed its diagnostics).
                Bit [4] – Set if the battery is present.
                Bits [31:5] – Reserved (must be cleared).
                */
                &aml::Method::new(
                    "_STA".into(),
                    0,
                    false,
                    // Call into MSTA method which will interrogate device
                    vec![&aml::Return::new(&aml::MethodCall::new(
                        "MSTA".into(),
                        vec![&self.slot_id],
                    ))],
                ),
                // Get details of memory
                &aml::Method::new(
                    "_CRS".into(),
                    0,
                    false,
                    // Call into MCRS which provides actual memory details
                    vec![&aml::Return::new(&aml::MethodCall::new(
                        "MCRS".into(),
                        vec![&self.slot_id],
                    ))],
                ),
            ],
        )
        .to_aml_bytes(sink)
    }
}

struct MemorySlots {
    slots: usize,
}

impl Aml for MemorySlots {
    fn to_aml_bytes(&self, sink: &mut dyn acpi_tables::AmlSink) {
        for slot_id in 0..self.slots {
            MemorySlot { slot_id }.to_aml_bytes(sink);
        }
    }
}

struct MemoryMethods {
    slots: usize,
}

impl Aml for MemoryMethods {
    fn to_aml_bytes(&self, sink: &mut dyn acpi_tables::AmlSink) {
        // Add "MTFY" notification method
        let mut memory_notifies = Vec::new();
        for slot_id in 0..self.slots {
            memory_notifies.push(MemoryNotify { slot_id });
        }

        let mut memory_notifies_refs: Vec<&dyn Aml> = Vec::new();
        for memory_notifier in memory_notifies.iter() {
            memory_notifies_refs.push(memory_notifier);
        }

        aml::Method::new("MTFY".into(), 2, true, memory_notifies_refs).to_aml_bytes(sink);

        // MSCN method
        aml::Method::new(
            "MSCN".into(),
            0,
            true,
            vec![
                // Take lock defined above
                &aml::Acquire::new("MLCK".into(), 0xffff),
                &aml::Store::new(&aml::Local(0), &aml::ZERO),
                &aml::While::new(
                    &aml::LessThan::new(&aml::Local(0), &self.slots),
                    vec![
                        // Write slot number (in first argument) to I/O port via field
                        &aml::Store::new(&aml::Path::new("\\_SB_.MHPC.MSEL"), &aml::Local(0)),
                        // Check if MINS bit is set (inserting)
                        &aml::If::new(
                            &aml::Equal::new(&aml::Path::new("\\_SB_.MHPC.MINS"), &aml::ONE),
                            // Notify device if it is
                            vec![
                                &aml::MethodCall::new(
                                    "MTFY".into(),
                                    vec![&aml::Local(0), &aml::ONE],
                                ),
                                // Reset MINS bit
                                &aml::Store::new(&aml::Path::new("\\_SB_.MHPC.MINS"), &aml::ONE),
                            ],
                        ),
                        // Check if MRMV bit is set
                        &aml::If::new(
                            &aml::Equal::new(&aml::Path::new("\\_SB_.MHPC.MRMV"), &aml::ONE),
                            // Notify device if it is (with the eject constant 0x3)
                            vec![
                                &aml::MethodCall::new("MTFY".into(), vec![&aml::Local(0), &3u8]),
                                // Reset MRMV bit
                                &aml::Store::new(&aml::Path::new("\\_SB_.MHPC.MRMV"), &aml::ONE),
                            ],
                        ),
                        &aml::Add::new(&aml::Local(0), &aml::Local(0), &aml::ONE),
                    ],
                ),
                // Release lock
                &aml::Release::new("MLCK".into()),
            ],
        )
        .to_aml_bytes(sink);

        // Memory status method
        aml::Method::new(
            "MSTA".into(),
            1,
            true,
            vec![
                // Take lock defined above
                &aml::Acquire::new("MLCK".into(), 0xffff),
                // Write slot number (in first argument) to I/O port via field
                &aml::Store::new(&aml::Path::new("\\_SB_.MHPC.MSEL"), &aml::Arg(0)),
                &aml::Store::new(&aml::Local(0), &aml::ZERO),
                // Check if MEN_ bit is set, if so make the local variable 0xf (see _STA for details of meaning)
                &aml::If::new(
                    &aml::Equal::new(&aml::Path::new("\\_SB_.MHPC.MEN_"), &aml::ONE),
                    vec![&aml::Store::new(&aml::Local(0), &0xfu8)],
                ),
                // Release lock
                &aml::Release::new("MLCK".into()),
                // Return 0 or 0xf
                &aml::Return::new(&aml::Local(0)),
            ],
        )
        .to_aml_bytes(sink);

        // Memory range method
        aml::Method::new(
            "MCRS".into(),
            1,
            true,
            vec![
                // Take lock defined above
                &aml::Acquire::new("MLCK".into(), 0xffff),
                // Write slot number (in first argument) to I/O port via field
                &aml::Store::new(&aml::Path::new("\\_SB_.MHPC.MSEL"), &aml::Arg(0)),
                &aml::Name::new(
                    "MR64".into(),
                    &aml::ResourceTemplate::new(vec![&aml::AddressSpace::new_memory(
                        aml::AddressSpaceCacheable::Cacheable,
                        true,
                        0x0000_0000_0000_0000u64,
                        0xFFFF_FFFF_FFFF_FFFEu64,
                        None,
                    )]),
                ),
                &aml::CreateQWordField::new(
                    &aml::Path::new("MINL"),
                    &aml::Path::new("MR64"),
                    &14usize,
                ),
                &aml::CreateDWordField::new(
                    &aml::Path::new("MINH"),
                    &aml::Path::new("MR64"),
                    &18usize,
                ),
                &aml::CreateQWordField::new(
                    &aml::Path::new("MAXL"),
                    &aml::Path::new("MR64"),
                    &22usize,
                ),
                &aml::CreateDWordField::new(
                    &aml::Path::new("MAXH"),
                    &aml::Path::new("MR64"),
                    &26usize,
                ),
                &aml::CreateQWordField::new(
                    &aml::Path::new("LENL"),
                    &aml::Path::new("MR64"),
                    &38usize,
                ),
                &aml::CreateDWordField::new(
                    &aml::Path::new("LENH"),
                    &aml::Path::new("MR64"),
                    &42usize,
                ),
                &aml::Store::new(&aml::Path::new("MINL"), &aml::Path::new("\\_SB_.MHPC.MHBL")),
                &aml::Store::new(&aml::Path::new("MINH"), &aml::Path::new("\\_SB_.MHPC.MHBH")),
                &aml::Store::new(&aml::Path::new("LENL"), &aml::Path::new("\\_SB_.MHPC.MHLL")),
                &aml::Store::new(&aml::Path::new("LENH"), &aml::Path::new("\\_SB_.MHPC.MHLH")),
                &aml::Add::new(
                    &aml::Path::new("MAXL"),
                    &aml::Path::new("MINL"),
                    &aml::Path::new("LENL"),
                ),
                &aml::Add::new(
                    &aml::Path::new("MAXH"),
                    &aml::Path::new("MINH"),
                    &aml::Path::new("LENH"),
                ),
                &aml::If::new(
                    &aml::LessThan::new(&aml::Path::new("MAXL"), &aml::Path::new("MINL")),
                    vec![&aml::Add::new(
                        &aml::Path::new("MAXH"),
                        &aml::ONE,
                        &aml::Path::new("MAXH"),
                    )],
                ),
                &aml::Subtract::new(&aml::Path::new("MAXL"), &aml::Path::new("MAXL"), &aml::ONE),
                // Release lock
                &aml::Release::new("MLCK".into()),
                &aml::Return::new(&aml::Path::new("MR64")),
            ],
        )
        .to_aml_bytes(sink)
    }
}

impl Aml for MemoryManager {
    fn to_aml_bytes(&self, sink: &mut dyn acpi_tables::AmlSink) {
        if let Some(acpi_address) = self.acpi_address {
            // Memory Hotplug Controller
            aml::Device::new(
                "_SB_.MHPC".into(),
                vec![
                    &aml::Name::new("_HID".into(), &aml::EISAName::new("PNP0A06")),
                    &aml::Name::new("_UID".into(), &"Memory Hotplug Controller"),
                    // Mutex to protect concurrent access as we write to choose slot and then read back status
                    &aml::Mutex::new("MLCK".into(), 0),
                    &aml::Name::new(
                        "_CRS".into(),
                        &aml::ResourceTemplate::new(vec![&aml::AddressSpace::new_memory(
                            aml::AddressSpaceCacheable::NotCacheable,
                            true,
                            acpi_address.0,
                            acpi_address.0 + MEMORY_MANAGER_ACPI_SIZE as u64 - 1,
                            None,
                        )]),
                    ),
                    // OpRegion and Fields map MMIO range into individual field values
                    &aml::OpRegion::new(
                        "MHPR".into(),
                        aml::OpRegionSpace::SystemMemory,
                        &(acpi_address.0 as usize),
                        &MEMORY_MANAGER_ACPI_SIZE,
                    ),
                    &aml::Field::new(
                        "MHPR".into(),
                        aml::FieldAccessType::DWord,
                        aml::FieldLockRule::NoLock,
                        aml::FieldUpdateRule::Preserve,
                        vec![
                            aml::FieldEntry::Named(*b"MHBL", 32), // Base (low 4 bytes)
                            aml::FieldEntry::Named(*b"MHBH", 32), // Base (high 4 bytes)
                            aml::FieldEntry::Named(*b"MHLL", 32), // Length (low 4 bytes)
                            aml::FieldEntry::Named(*b"MHLH", 32), // Length (high 4 bytes)
                        ],
                    ),
                    &aml::Field::new(
                        "MHPR".into(),
                        aml::FieldAccessType::DWord,
                        aml::FieldLockRule::NoLock,
                        aml::FieldUpdateRule::Preserve,
                        vec![
                            aml::FieldEntry::Reserved(128),
                            aml::FieldEntry::Named(*b"MHPX", 32), // PXM
                        ],
                    ),
                    &aml::Field::new(
                        "MHPR".into(),
                        aml::FieldAccessType::Byte,
                        aml::FieldLockRule::NoLock,
                        aml::FieldUpdateRule::WriteAsZeroes,
                        vec![
                            aml::FieldEntry::Reserved(160),
                            aml::FieldEntry::Named(*b"MEN_", 1), // Enabled
                            aml::FieldEntry::Named(*b"MINS", 1), // Inserting
                            aml::FieldEntry::Named(*b"MRMV", 1), // Removing
                            aml::FieldEntry::Named(*b"MEJ0", 1), // Ejecting
                        ],
                    ),
                    &aml::Field::new(
                        "MHPR".into(),
                        aml::FieldAccessType::DWord,
                        aml::FieldLockRule::NoLock,
                        aml::FieldUpdateRule::Preserve,
                        vec![
                            aml::FieldEntry::Named(*b"MSEL", 32), // Selector
                            aml::FieldEntry::Named(*b"MOEV", 32), // Event
                            aml::FieldEntry::Named(*b"MOSC", 32), // OSC
                        ],
                    ),
                    &MemoryMethods {
                        slots: self.hotplug_slots.len(),
                    },
                    &MemorySlots {
                        slots: self.hotplug_slots.len(),
                    },
                ],
            )
            .to_aml_bytes(sink);
        } else {
            aml::Device::new(
                "_SB_.MHPC".into(),
                vec![
                    &aml::Name::new("_HID".into(), &aml::EISAName::new("PNP0A06")),
                    &aml::Name::new("_UID".into(), &"Memory Hotplug Controller"),
                    // Empty MSCN for GED
                    &aml::Method::new("MSCN".into(), 0, true, vec![]),
                ],
            )
            .to_aml_bytes(sink);
        }
    }
}

impl Pausable for MemoryManager {}

#[derive(Clone, Serialize, Deserialize)]
pub struct MemoryManagerSnapshotData {
    memory_ranges: MemoryRangeTable,
    guest_ram_mappings: Vec<GuestRamMapping>,
    start_of_device_area: u64,
    boot_ram: u64,
    current_ram: u64,
    arch_mem_regions: Vec<ArchMemRegion>,
    hotplug_slots: Vec<HotPlugState>,
    next_memory_slot: u32,
    selected_slot: usize,
    next_hotplug_slot: usize,
}

impl Snapshottable for MemoryManager {
    fn id(&self) -> String {
        MEMORY_MANAGER_SNAPSHOT_ID.to_string()
    }

    fn snapshot(&mut self) -> result::Result<Snapshot, MigratableError> {
        let memory_ranges = self.memory_range_table(true)?;

        // Store locally this list of ranges as it will be used through the
        // Transportable::send() implementation. The point is to avoid the
        // duplication of code regarding the creation of the path for each
        // region. The 'snapshot' step creates the list of memory regions,
        // including information about the need to copy a memory region or
        // not. This saves the 'send' step having to go through the same
        // process, and instead it can directly proceed with storing the
        // memory range content for the ranges requiring it.
        self.snapshot_memory_ranges = memory_ranges;

        Ok(Snapshot::from_data(SnapshotData::new_from_state(
            &self.snapshot_data(),
        )?))
    }
}

impl Transportable for MemoryManager {
    fn send(
        &self,
        _snapshot: &Snapshot,
        destination_url: &str,
    ) -> result::Result<(), MigratableError> {
        if self.snapshot_memory_ranges.is_empty() {
            return Ok(());
        }

        let mut memory_file_path = url_to_path(destination_url)?;
        memory_file_path.push(String::from(SNAPSHOT_FILENAME));

        // Create the snapshot file for the entire memory
        let mut memory_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(memory_file_path)
            .map_err(|e| MigratableError::MigrateSend(e.into()))?;

        let guest_memory = self.guest_memory.memory();

        for range in self.snapshot_memory_ranges.regions() {
            let mut offset: u64 = 0;
            // Here we are manually handling the retry in case we can't read
            // the whole region at once because we can't use the implementation
            // from vm-memory::GuestMemory of write_all_to() as it is not
            // following the correct behavior. For more info about this issue
            // see: https://github.com/rust-vmm/vm-memory/issues/174
            loop {
                let bytes_written = guest_memory
                    .write_volatile_to(
                        GuestAddress(range.gpa + offset),
                        &mut memory_file,
                        (range.length - offset) as usize,
                    )
                    .map_err(|e| MigratableError::MigrateSend(e.into()))?;
                offset += bytes_written as u64;

                if offset == range.length {
                    break;
                }
            }
        }
        Ok(())
    }
}

impl Migratable for MemoryManager {
    // Start the dirty log in the hypervisor (kvm/mshv).
    // Also, reset the dirty bitmap logged by the vmm.
    // Just before we do a bulk copy we want to start/clear the dirty log so that
    // pages touched during our bulk copy are tracked.
    fn start_dirty_log(&mut self) -> std::result::Result<(), MigratableError> {
        self.vm.start_dirty_log().map_err(|e| {
            MigratableError::MigrateSend(anyhow!("Error starting VM dirty log {}", e))
        })?;

        for r in self.guest_memory.memory().iter() {
            (**r).bitmap().reset();
        }

        Ok(())
    }

    fn stop_dirty_log(&mut self) -> std::result::Result<(), MigratableError> {
        self.vm.stop_dirty_log().map_err(|e| {
            MigratableError::MigrateSend(anyhow!("Error stopping VM dirty log {}", e))
        })?;

        Ok(())
    }

    // Generate a table for the pages that are dirty. The dirty pages are collapsed
    // together in the table if they are contiguous.
    fn dirty_log(&mut self) -> std::result::Result<MemoryRangeTable, MigratableError> {
        let mut table = MemoryRangeTable::default();
        for r in &self.guest_ram_mappings {
            let vm_dirty_bitmap = self.vm.get_dirty_log(r.slot, r.gpa, r.size).map_err(|e| {
                MigratableError::MigrateSend(anyhow!("Error getting VM dirty log {}", e))
            })?;
            let vmm_dirty_bitmap = match self.guest_memory.memory().find_region(GuestAddress(r.gpa))
            {
                Some(region) => {
                    assert!(region.start_addr().raw_value() == r.gpa);
                    assert!(region.len() == r.size);
                    (**region).bitmap().get_and_reset()
                }
                None => {
                    return Err(MigratableError::MigrateSend(anyhow!(
                        "Error finding 'guest memory region' with address {:x}",
                        r.gpa
                    )))
                }
            };

            let dirty_bitmap: Vec<u64> = vm_dirty_bitmap
                .iter()
                .zip(vmm_dirty_bitmap.iter())
                .map(|(x, y)| x | y)
                .collect();

            let sub_table = MemoryRangeTable::from_bitmap(dirty_bitmap, r.gpa, 4096);

            if sub_table.regions().is_empty() {
                info!("Dirty Memory Range Table is empty");
            } else {
                info!("Dirty Memory Range Table:");
                for range in sub_table.regions() {
                    info!("GPA: {:x} size: {} (KiB)", range.gpa, range.length / 1024);
                }
            }

            table.extend(sub_table);
        }
        Ok(table)
    }
}
