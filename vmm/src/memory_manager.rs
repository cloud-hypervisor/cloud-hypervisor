// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
extern crate hypervisor;
#[cfg(target_arch = "x86_64")]
use crate::config::SgxEpcConfig;
use crate::config::{HotplugMethod, MemoryConfig, MemoryZoneConfig};
use crate::migration::url_to_path;
use crate::MEMORY_MANAGER_SNAPSHOT_ID;
#[cfg(feature = "acpi")]
use acpi_tables::{aml, aml::Aml};
use anyhow::anyhow;
#[cfg(target_arch = "x86_64")]
use arch::x86_64::{SgxEpcRegion, SgxEpcSection};
use arch::{layout, RegionType};
#[cfg(target_arch = "x86_64")]
use devices::ioapic;
#[cfg(target_arch = "x86_64")]
use libc::{MAP_NORESERVE, MAP_POPULATE, MAP_SHARED, PROT_READ, PROT_WRITE};
use std::collections::HashMap;
use std::convert::TryInto;
use std::ffi;
use std::fs::{File, OpenOptions};
use std::io;
use std::ops::Deref;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::PathBuf;
use std::result;
use std::sync::{Arc, Barrier, Mutex};
#[cfg(target_arch = "x86_64")]
use vm_allocator::GsiApic;
use vm_allocator::SystemAllocator;
use vm_device::BusDevice;
use vm_memory::guest_memory::FileOffset;
use vm_memory::{
    mmap::MmapRegionError, Address, Bytes, Error as MmapError, GuestAddress, GuestAddressSpace,
    GuestMemory, GuestMemoryAtomic, GuestMemoryError, GuestMemoryLoadGuard, GuestMemoryMmap,
    GuestMemoryRegion, GuestRegionMmap, GuestUsize, MmapRegion,
};
use vm_migration::{
    protocol::{MemoryRange, MemoryRangeTable},
    Migratable, MigratableError, Pausable, Snapshot, SnapshotDataSection, Snapshottable,
    Transportable,
};

#[cfg(feature = "acpi")]
pub const MEMORY_MANAGER_ACPI_SIZE: usize = 0x18;

const DEFAULT_MEMORY_ZONE: &str = "mem0";

#[cfg(target_arch = "x86_64")]
const X86_64_IRQ_BASE: u32 = 5;

const HOTPLUG_COUNT: usize = 8;

// Memory policy constants
const MPOL_BIND: u32 = 2;
const MPOL_MF_STRICT: u32 = 1;
const MPOL_MF_MOVE: u32 = 1 << 1;

#[derive(Default)]
struct HotPlugState {
    base: u64,
    length: u64,
    active: bool,
    inserting: bool,
    removing: bool,
}

pub struct VirtioMemZone {
    region: Arc<GuestRegionMmap>,
    resize_handler: virtio_devices::Resize,
    hotplugged_size: u64,
    hugepages: bool,
}

impl VirtioMemZone {
    pub fn region(&self) -> &Arc<GuestRegionMmap> {
        &self.region
    }
    pub fn resize_handler(&self) -> &virtio_devices::Resize {
        &self.resize_handler
    }
    pub fn hotplugged_size(&self) -> u64 {
        self.hotplugged_size
    }
    pub fn hugepages(&self) -> bool {
        self.hugepages
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
}

pub type MemoryZones = HashMap<String, MemoryZone>;

struct GuestRamMapping {
    slot: u32,
    gpa: u64,
    size: u64,
}

pub struct MemoryManager {
    boot_guest_memory: GuestMemoryMmap,
    guest_memory: GuestMemoryAtomic<GuestMemoryMmap>,
    next_memory_slot: u32,
    start_of_device_area: GuestAddress,
    end_of_device_area: GuestAddress,
    pub vm: Arc<dyn hypervisor::Vm>,
    hotplug_slots: Vec<HotPlugState>,
    selected_slot: usize,
    mergeable: bool,
    allocator: Arc<Mutex<SystemAllocator>>,
    hotplug_method: HotplugMethod,
    boot_ram: u64,
    current_ram: u64,
    next_hotplug_slot: usize,
    snapshot: Mutex<Option<GuestMemoryLoadGuard<GuestMemoryMmap>>>,
    shared: bool,
    hugepages: bool,
    hugepage_size: Option<u64>,
    #[cfg(target_arch = "x86_64")]
    sgx_epc_region: Option<SgxEpcRegion>,
    user_provided_zones: bool,
    snapshot_memory_regions: Vec<MemoryRegion>,
    memory_zones: MemoryZones,
    log_dirty: bool, // Enable dirty logging for created RAM regions

    // Keep track of calls to create_userspace_mapping() for guest RAM.
    // This is useful for getting the dirty pages as we need to know the
    // slots that the mapping is created in.
    guest_ram_mappings: Vec<GuestRamMapping>,

    #[cfg(feature = "acpi")]
    pub acpi_address: GuestAddress,
}

#[derive(Debug)]
pub enum Error {
    /// Failed to create shared file.
    SharedFileCreate(io::Error),

    /// Failed to set shared file length.
    SharedFileSetLen(io::Error),

    /// Mmap backed guest memory error
    GuestMemory(MmapError),

    /// Failed to allocate a memory range.
    MemoryRangeAllocation,

    /// Failed to create map region
    MmapRegion(),

    /// Error from region creation
    GuestMemoryRegion(MmapRegionError),

    /// No ACPI slot available
    NoSlotAvailable,

    /// Not enough space in the hotplug RAM region
    InsufficientHotplugRam,

    /// The requested hotplug memory addition is not a valid size
    InvalidSize,

    /// Failed to set the user memory region.
    SetUserMemoryRegion(hypervisor::HypervisorVmError),

    /// Failed to EventFd.
    EventFdFail(io::Error),

    /// Eventfd write error
    EventfdError(io::Error),

    /// Failed to virtio-mem resize
    VirtioMemResizeFail(virtio_devices::mem::Error),

    /// Cannot restore VM
    Restore(MigratableError),

    /// Cannot create the system allocator
    CreateSystemAllocator,

    /// The number of external backing files doesn't match the number of
    /// memory regions.
    InvalidAmountExternalBackingFiles,

    /// Invalid SGX EPC section size
    #[cfg(target_arch = "x86_64")]
    EpcSectionSizeInvalid,

    /// Failed allocating SGX EPC region
    #[cfg(target_arch = "x86_64")]
    SgxEpcRangeAllocation,

    /// Failed opening SGX virtual EPC device
    #[cfg(target_arch = "x86_64")]
    SgxVirtEpcOpen(io::Error),

    /// Failed setting the SGX virtual EPC section size
    #[cfg(target_arch = "x86_64")]
    SgxVirtEpcFileSetLen(io::Error),

    /// Failed creating a new MmapRegion instance.
    #[cfg(target_arch = "x86_64")]
    NewMmapRegion(vm_memory::mmap::MmapRegionError),

    /// No memory zones found.
    MissingMemoryZones,

    /// Memory configuration is not valid.
    InvalidMemoryParameters,

    /// Forbidden operation. Impossible to resize guest memory if it is
    /// backed by user defined memory regions.
    InvalidResizeWithMemoryZones,

    /// It's invalid to try applying a NUMA policy to a memory zone that is
    /// memory mapped with MAP_SHARED.
    InvalidSharedMemoryZoneWithHostNuma,

    /// Failed applying NUMA memory policy.
    ApplyNumaPolicy(io::Error),

    /// Memory zone identifier is not unique.
    DuplicateZoneId,

    /// No virtio-mem resizing handler found.
    MissingVirtioMemHandler,

    /// Unknown memory zone.
    UnknownMemoryZone,

    /// Invalid size for resizing. Can be anything except 0.
    InvalidHotplugSize,

    /// Invalid hotplug method associated with memory zones resizing capability.
    InvalidHotplugMethodWithMemoryZones,

    /// Could not find specified memory zone identifier from hash map.
    MissingZoneIdentifier,

    /// Resizing the memory zone failed.
    ResizeZone,

    /// Guest address overflow
    GuestAddressOverFlow,

    /// Error opening snapshot file
    SnapshotOpen(io::Error),

    // Error copying snapshot into region
    SnapshotCopy(GuestMemoryError),

    /// Failed to allocate MMIO address
    AllocateMmioAddress,
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
                    data.copy_from_slice(&[0; 8][0..data.len()]);
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
        }
    }

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        match offset {
            SELECTION_OFFSET => {
                self.selected_slot = usize::from(data[0]);
            }
            STATUS_OFFSET => {
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
    /// One example might be ram_regions containing 2 regions (0-3G and 4G-6G)
    /// and zones containing two zones (size 1G and size 4G).
    /// This function will create 3 resulting memory regions:
    /// - First one mapping entirely the first memory zone on 0-1G range
    /// - Second one mapping partially the second memory zone on 1G-3G range
    /// - Third one mapping partially the second memory zone on 4G-6G range
    fn create_memory_regions_from_zones(
        ram_regions: &[(GuestAddress, usize)],
        zones: &[MemoryZoneConfig],
        prefault: bool,
    ) -> Result<(Vec<Arc<GuestRegionMmap>>, MemoryZones), Error> {
        let mut zones = zones.to_owned();
        let mut mem_regions = Vec::new();
        let mut zone = zones.remove(0);
        let mut zone_offset = 0;
        let mut memory_zones = HashMap::new();

        // Add zone id to the list of memory zones.
        memory_zones.insert(zone.id.clone(), MemoryZone::default());

        for ram_region in ram_regions.iter() {
            let mut ram_region_offset = 0;
            let mut exit = false;

            loop {
                let mut ram_region_consumed = false;
                let mut pull_next_zone = false;

                let ram_region_sub_size = ram_region.1 - ram_region_offset;
                let zone_sub_size = zone.size as usize - zone_offset;

                let file_offset = zone_offset as u64;
                let region_start = ram_region
                    .0
                    .checked_add(ram_region_offset as u64)
                    .ok_or(Error::GuestAddressOverFlow)?;
                let region_size = if zone_sub_size <= ram_region_sub_size {
                    if zone_sub_size == ram_region_sub_size {
                        ram_region_consumed = true;
                    }

                    ram_region_offset += zone_sub_size;
                    pull_next_zone = true;

                    zone_sub_size
                } else {
                    zone_offset += ram_region_sub_size;
                    ram_region_consumed = true;

                    ram_region_sub_size
                };

                let region = MemoryManager::create_ram_region(
                    &zone.file,
                    file_offset,
                    region_start,
                    region_size,
                    prefault,
                    zone.shared,
                    zone.hugepages,
                    zone.hugepage_size,
                    zone.host_numa_node,
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
                    if zones.is_empty() {
                        exit = true;
                        break;
                    }
                    zone = zones.remove(0);

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

    fn fill_saved_regions(&mut self, saved_regions: Vec<MemoryRegion>) -> Result<(), Error> {
        for region in saved_regions {
            if let Some(content) = region.content {
                // Open (read only) the snapshot file for the given region.
                let mut memory_region_file = OpenOptions::new()
                    .read(true)
                    .open(content)
                    .map_err(Error::SnapshotOpen)?;

                self.guest_memory
                    .memory()
                    .read_exact_from(
                        region.start_addr,
                        &mut memory_region_file,
                        region.size as usize,
                    )
                    .map_err(Error::SnapshotCopy)?;
            }
        }

        Ok(())
    }

    pub fn new(
        vm: Arc<dyn hypervisor::Vm>,
        config: &MemoryConfig,
        prefault: bool,
        phys_bits: u8,
        #[cfg(feature = "tdx")] tdx_enabled: bool,
    ) -> Result<Arc<Mutex<MemoryManager>>, Error> {
        let user_provided_zones = config.size == 0;
        let mut allow_mem_hotplug: bool = false;

        let (ram_size, zones) = if !user_provided_zones {
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
            }];

            (config.size, zones)
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

            (total_ram_size, zones)
        };

        // Init guest memory
        let arch_mem_regions = arch::arch_memory_regions(ram_size);

        let ram_regions: Vec<(GuestAddress, usize)> = arch_mem_regions
            .iter()
            .filter(|r| r.2 == RegionType::Ram)
            .map(|r| (r.0, r.1))
            .collect();

        let (mem_regions, mut memory_zones) =
            Self::create_memory_regions_from_zones(&ram_regions, &zones, prefault)?;

        let guest_memory =
            GuestMemoryMmap::from_arc_regions(mem_regions).map_err(Error::GuestMemory)?;

        let boot_guest_memory = guest_memory.clone();

        let mmio_address_space_size = mmio_address_space_size(phys_bits);
        debug_assert_eq!(
            (((mmio_address_space_size) >> 16) << 16),
            mmio_address_space_size
        );
        let end_of_device_area = GuestAddress(mmio_address_space_size - 1);

        let mut start_of_device_area =
            MemoryManager::start_addr(guest_memory.last_addr(), allow_mem_hotplug)?;
        let mut virtio_mem_regions: Vec<Arc<GuestRegionMmap>> = Vec::new();

        // Update list of memory zones for resize.
        for zone in zones {
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
                            (start_of_device_area.0 + virtio_devices::VIRTIO_MEM_ALIGN_SIZE - 1)
                                / virtio_devices::VIRTIO_MEM_ALIGN_SIZE
                                * virtio_devices::VIRTIO_MEM_ALIGN_SIZE,
                        );

                        let region = MemoryManager::create_ram_region(
                            &None,
                            0,
                            start_addr,
                            hotplug_size as usize,
                            false,
                            zone.shared,
                            zone.hugepages,
                            zone.hugepage_size,
                            zone.host_numa_node,
                        )?;

                        virtio_mem_regions.push(region.clone());

                        memory_zone.virtio_mem_zone = Some(VirtioMemZone {
                            region,
                            resize_handler: virtio_devices::Resize::new()
                                .map_err(Error::EventFdFail)?,
                            hotplugged_size: zone.hotplugged_size.unwrap_or(0),
                            hugepages: zone.hugepages,
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

        let guest_memory = GuestMemoryAtomic::new(guest_memory);

        let mut hotplug_slots = Vec::with_capacity(HOTPLUG_COUNT);
        hotplug_slots.resize_with(HOTPLUG_COUNT, HotPlugState::default);

        // Both MMIO and PIO address spaces start at address 0.
        let allocator = Arc::new(Mutex::new(
            SystemAllocator::new(
                #[cfg(target_arch = "x86_64")]
                {
                    GuestAddress(0)
                },
                #[cfg(target_arch = "x86_64")]
                {
                    1 << 16
                },
                GuestAddress(0),
                mmio_address_space_size,
                layout::MEM_32BIT_DEVICES_START,
                layout::MEM_32BIT_DEVICES_SIZE,
                #[cfg(target_arch = "x86_64")]
                vec![GsiApic::new(
                    X86_64_IRQ_BASE,
                    ioapic::NUM_IOAPIC_PINS as u32 - X86_64_IRQ_BASE,
                )],
            )
            .ok_or(Error::CreateSystemAllocator)?,
        ));

        #[cfg(feature = "acpi")]
        let acpi_address = allocator
            .lock()
            .unwrap()
            .allocate_mmio_addresses(None, MEMORY_MANAGER_ACPI_SIZE as u64, None)
            .ok_or(Error::AllocateMmioAddress)?;

        #[cfg(not(feature = "tdx"))]
        let log_dirty = true;
        #[cfg(feature = "tdx")]
        let log_dirty = !tdx_enabled; // Cannot log dirty pages on a TD

        let memory_manager = Arc::new(Mutex::new(MemoryManager {
            boot_guest_memory,
            guest_memory: guest_memory.clone(),
            next_memory_slot: 0,
            start_of_device_area,
            end_of_device_area,
            vm,
            hotplug_slots,
            selected_slot: 0,
            mergeable: config.mergeable,
            allocator: allocator.clone(),
            hotplug_method: config.hotplug_method.clone(),
            boot_ram: ram_size,
            current_ram: ram_size,
            next_hotplug_slot: 0,
            snapshot: Mutex::new(None),
            shared: config.shared,
            hugepages: config.hugepages,
            hugepage_size: config.hugepage_size,
            #[cfg(target_arch = "x86_64")]
            sgx_epc_region: None,
            user_provided_zones,
            snapshot_memory_regions: Vec::new(),
            memory_zones,
            guest_ram_mappings: Vec::new(),
            #[cfg(feature = "acpi")]
            acpi_address,
            log_dirty,
        }));

        guest_memory.memory().with_regions(|_, region| {
            let mut mm = memory_manager.lock().unwrap();
            let slot = mm.create_userspace_mapping(
                region.start_addr().raw_value(),
                region.len() as u64,
                region.as_ptr() as u64,
                config.mergeable,
                false,
                log_dirty,
            )?;
            mm.guest_ram_mappings.push(GuestRamMapping {
                gpa: region.start_addr().raw_value(),
                size: region.len(),
                slot,
            });

            Ok(())
        })?;

        for region in virtio_mem_regions.drain(..) {
            let mut mm = memory_manager.lock().unwrap();
            let slot = mm.create_userspace_mapping(
                region.start_addr().raw_value(),
                region.len() as u64,
                region.as_ptr() as u64,
                config.mergeable,
                false,
                log_dirty,
            )?;

            mm.guest_ram_mappings.push(GuestRamMapping {
                gpa: region.start_addr().raw_value(),
                size: region.len(),
                slot,
            });
            allocator
                .lock()
                .unwrap()
                .allocate_mmio_addresses(Some(region.start_addr()), region.len(), None)
                .ok_or(Error::MemoryRangeAllocation)?;
            mm.add_region(region)?;
        }

        // Allocate RAM and Reserved address ranges.
        for region in arch_mem_regions.iter() {
            allocator
                .lock()
                .unwrap()
                .allocate_mmio_addresses(Some(region.0), region.1 as GuestUsize, None)
                .ok_or(Error::MemoryRangeAllocation)?;
        }

        Ok(memory_manager)
    }

    pub fn new_from_snapshot(
        snapshot: &Snapshot,
        vm: Arc<dyn hypervisor::Vm>,
        config: &MemoryConfig,
        source_url: Option<&str>,
        prefault: bool,
        phys_bits: u8,
    ) -> Result<Arc<Mutex<MemoryManager>>, Error> {
        let mm = MemoryManager::new(
            vm,
            config,
            prefault,
            phys_bits,
            #[cfg(feature = "tdx")]
            false,
        )?;

        if let Some(source_url) = source_url {
            let vm_snapshot_path = url_to_path(source_url).map_err(Error::Restore)?;

            let mem_snapshot: MemoryManagerSnapshotData = snapshot
                .to_state(MEMORY_MANAGER_SNAPSHOT_ID)
                .map_err(Error::Restore)?;

            // Here we turn the content file name into a content file path as
            // this will be needed to copy the content of the saved memory
            // region into the newly created memory region.
            // We simply ignore the content files that are None, as they
            // represent regions that have been directly saved by the user, with
            // no need for saving into a dedicated external file. For these
            // files, the VmConfig already contains the information on where to
            // find them.
            let mut saved_regions = mem_snapshot.memory_regions;
            for region in saved_regions.iter_mut() {
                if let Some(content) = &mut region.content {
                    let mut memory_region_path = vm_snapshot_path.clone();
                    memory_region_path.push(content.clone());
                    *content = memory_region_path;
                }
            }

            mm.lock().unwrap().fill_saved_regions(saved_regions)?;

            Ok(mm)
        } else {
            Ok(mm)
        }
    }

    fn memfd_create(name: &ffi::CStr, flags: u32) -> Result<RawFd, io::Error> {
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

    #[allow(clippy::too_many_arguments)]
    fn create_ram_region(
        backing_file: &Option<PathBuf>,
        file_offset: u64,
        start_addr: GuestAddress,
        size: usize,
        prefault: bool,
        shared: bool,
        hugepages: bool,
        hugepage_size: Option<u64>,
        host_numa_node: Option<u32>,
    ) -> Result<Arc<GuestRegionMmap>, Error> {
        let (f, f_off) = match backing_file {
            Some(ref file) => {
                if file.is_dir() {
                    // Override file offset as it does not apply in this case.
                    info!(
                        "Ignoring file offset since the backing file is a \
                        temporary file created from the specified directory."
                    );
                    let fs_str = format!("{}{}", file.display(), "/tmpfile_XXXXXX");
                    let fs = ffi::CString::new(fs_str).unwrap();
                    let mut path = fs.as_bytes_with_nul().to_owned();
                    let path_ptr = path.as_mut_ptr() as *mut _;
                    let fd = unsafe { libc::mkstemp(path_ptr) };
                    unsafe { libc::unlink(path_ptr) };
                    let f = unsafe { File::from_raw_fd(fd) };
                    f.set_len(size as u64).map_err(Error::SharedFileSetLen)?;

                    (f, 0)
                } else {
                    let f = OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(file)
                        .map_err(Error::SharedFileCreate)?;

                    (f, file_offset)
                }
            }
            None => {
                let fd = Self::memfd_create(
                    &ffi::CString::new("ch_ram").unwrap(),
                    if hugepages {
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

                let f = unsafe { File::from_raw_fd(fd) };
                f.set_len(size as u64).map_err(Error::SharedFileSetLen)?;

                (f, 0)
            }
        };

        let mut mmap_flags = libc::MAP_NORESERVE
            | if shared {
                libc::MAP_SHARED
            } else {
                libc::MAP_PRIVATE
            };
        if prefault {
            mmap_flags |= libc::MAP_POPULATE;
        }

        let region = GuestRegionMmap::new(
            MmapRegion::build(
                Some(FileOffset::new(f, f_off)),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                mmap_flags,
            )
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

        Ok(Arc::new(region))
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
    // On x86_64, it must also start at the 64bit start.
    #[allow(clippy::let_and_return)]
    fn start_addr(mem_end: GuestAddress, allow_mem_hotplug: bool) -> Result<GuestAddress, Error> {
        let mut start_addr = if allow_mem_hotplug {
            GuestAddress(mem_end.0 | ((128 << 20) - 1))
        } else {
            mem_end
        };

        start_addr = start_addr
            .checked_add(1)
            .ok_or(Error::GuestAddressOverFlow)?;

        #[cfg(target_arch = "x86_64")]
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
            false,
            self.shared,
            self.hugepages,
            self.hugepage_size,
            None,
        )?;

        // Map it into the guest
        let slot = self.create_userspace_mapping(
            region.start_addr().0,
            region.len() as u64,
            region.as_ptr() as u64,
            self.mergeable,
            false,
            self.log_dirty,
        )?;
        self.guest_ram_mappings.push(GuestRamMapping {
            gpa: region.start_addr().raw_value(),
            size: region.len(),
            slot,
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
        if size % (128 << 20) != 0 {
            return Err(Error::InvalidSize);
        }

        let start_addr = MemoryManager::start_addr(self.guest_memory.memory().last_addr(), true)?;

        if start_addr.checked_add(size.try_into().unwrap()).unwrap() > self.start_of_device_area() {
            return Err(Error::InsufficientHotplugRam);
        }

        let region = self.add_ram_region(start_addr, size)?;

        // Add region to the list of regions associated with the default
        // memory zone.
        if let Some(memory_zone) = self.memory_zones.get_mut(DEFAULT_MEMORY_ZONE) {
            memory_zone.regions.push(Arc::clone(&region));
        }

        // Tell the allocator
        self.allocator
            .lock()
            .unwrap()
            .allocate_mmio_addresses(Some(start_addr), size as GuestUsize, None)
            .ok_or(Error::MemoryRangeAllocation)?;

        // Update the slot so that it can be queried via the I/O port
        let mut slot = &mut self.hotplug_slots[self.next_hotplug_slot];
        slot.active = true;
        slot.inserting = true;
        slot.base = region.start_addr().0;
        slot.length = region.len() as u64;

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

    pub fn allocate_memory_slot(&mut self) -> u32 {
        let slot_id = self.next_memory_slot;
        self.next_memory_slot += 1;
        slot_id
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

        self.vm
            .set_user_memory_region(mem_region)
            .map_err(Error::SetUserMemoryRegion)?;

        // Mark the pages as mergeable if explicitly asked for.
        if mergeable {
            // Safe because the address and size are valid since the
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
            0, /* memory_size -- using 0 removes this slot */
            userspace_addr,
            false, /* readonly -- don't care */
            false, /* log dirty */
        );

        self.vm
            .set_user_memory_region(mem_region)
            .map_err(Error::SetUserMemoryRegion)?;

        // Mark the pages as unmergeable if there were previously marked as
        // mergeable.
        if mergeable {
            // Safe because the address and size are valid as the region was
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
            if let Some(virtio_mem_zone) = memory_zone.virtio_mem_zone() {
                virtio_mem_zone
                    .resize_handler()
                    .work(size)
                    .map_err(Error::VirtioMemResizeFail)?;
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
                    self.virtio_mem_resize(DEFAULT_MEMORY_ZONE, desired_ram - self.boot_ram)?;
                    self.current_ram = desired_ram;
                }
            }
            HotplugMethod::Acpi => {
                if desired_ram > self.current_ram {
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

    #[cfg(target_arch = "x86_64")]
    pub fn setup_sgx(&mut self, sgx_epc_config: Vec<SgxEpcConfig>) -> Result<(), Error> {
        // Go over each EPC section and verify its size is a 4k multiple. At
        // the same time, calculate the total size needed for the contiguous
        // EPC region.
        let mut epc_region_size = 0;
        for epc_section in sgx_epc_config.iter() {
            if epc_section.size == 0 {
                return Err(Error::EpcSectionSizeInvalid);
            }
            if epc_section.size & 0x0fff != 0 {
                return Err(Error::EpcSectionSizeInvalid);
            }

            epc_region_size += epc_section.size;
        }

        // Now that we know about the total size for the EPC region, we can
        // proceed with the allocation of the entire range. The EPC region
        // must be 4kiB aligned.
        let epc_region_start = self
            .allocator
            .lock()
            .unwrap()
            .allocate_mmio_addresses(None, epc_region_size as GuestUsize, Some(0x1000))
            .ok_or(Error::SgxEpcRangeAllocation)?;

        let mut sgx_epc_region = SgxEpcRegion::new(epc_region_start, epc_region_size as GuestUsize);

        // Each section can be memory mapped into the allocated region.
        let mut epc_section_start = epc_region_start.raw_value();
        for epc_section in sgx_epc_config.iter() {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/sgx_virt_epc")
                .map_err(Error::SgxVirtEpcOpen)?;

            let prot = PROT_READ | PROT_WRITE;
            let mut flags = MAP_NORESERVE | MAP_SHARED;
            if epc_section.prefault {
                flags |= MAP_POPULATE;
            }

            // We can't use the vm-memory crate to perform the memory mapping
            // here as it would try to ensure the size of the backing file is
            // matching the size of the expected mapping. The /dev/sgx_virt_epc
            // device does not work that way, it provides a file descriptor
            // which is not matching the mapping size, as it's a just a way to
            // let KVM know that an EPC section is being created for the guest.
            let host_addr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    epc_section.size as usize,
                    prot,
                    flags,
                    file.as_raw_fd(),
                    0,
                )
            } as u64;

            let _mem_slot = self.create_userspace_mapping(
                epc_section_start,
                epc_section.size,
                host_addr,
                false,
                false,
                false,
            )?;

            sgx_epc_region.push(SgxEpcSection::new(
                GuestAddress(epc_section_start),
                epc_section.size as GuestUsize,
            ));

            epc_section_start += epc_section.size;
        }

        self.sgx_epc_region = Some(sgx_epc_region);

        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    pub fn sgx_epc_region(&self) -> &Option<SgxEpcRegion> {
        &self.sgx_epc_region
    }

    pub fn is_hardlink(f: &File) -> bool {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        let ret = unsafe { libc::fstat(f.as_raw_fd(), stat.as_mut_ptr()) };
        if ret != 0 {
            error!("Couldn't fstat the backing file");
            return false;
        }

        unsafe { (*stat.as_ptr()).st_nlink as usize > 0 }
    }

    pub fn memory_zones(&self) -> &MemoryZones {
        &self.memory_zones
    }

    // Generate a table for the pages that are dirty. The dirty pages are collapsed
    // together in the table if they are contiguous.
    pub fn dirty_memory_range_table(
        &self,
    ) -> std::result::Result<MemoryRangeTable, MigratableError> {
        let page_size = 4096; // TODO: Does this need to vary?
        let mut table = MemoryRangeTable::default();
        for r in &self.guest_ram_mappings {
            let dirty_bitmap = self.vm.get_dirty_log(r.slot, r.size).map_err(|e| {
                MigratableError::MigrateSend(anyhow!("Error getting VM dirty log {}", e))
            })?;

            let mut entry: Option<MemoryRange> = None;
            for (i, block) in dirty_bitmap.iter().enumerate() {
                for j in 0..64 {
                    let is_page_dirty = ((block >> j) & 1u64) != 0u64;
                    let page_offset = ((i * 64) + j) as u64 * page_size;
                    if is_page_dirty {
                        if let Some(entry) = &mut entry {
                            entry.length += page_size;
                        } else {
                            entry = Some(MemoryRange {
                                gpa: r.gpa + page_offset,
                                length: page_size,
                            });
                        }
                    } else if let Some(entry) = entry.take() {
                        table.push(entry);
                    }
                }
            }
            if let Some(entry) = entry.take() {
                table.push(entry);
            }

            if table.regions().is_empty() {
                info!("Dirty Memory Range Table is empty");
            } else {
                info!("Dirty Memory Range Table:");
                for range in table.regions() {
                    info!("GPA: {:x} size: {} (KiB)", range.gpa, range.length / 1024);
                }
            }
        }
        Ok(table)
    }

    // The dirty log is cleared by the kernel by calling the KVM_GET_DIRTY_LOG ioctl.
    // Just before we do a bulk copy we want to clear the dirty log so that
    // pages touched during our bulk copy are tracked.
    pub fn start_memory_dirty_log(&self) -> std::result::Result<(), MigratableError> {
        for r in &self.guest_ram_mappings {
            self.vm.get_dirty_log(r.slot, r.size).map_err(|e| {
                MigratableError::MigrateSend(anyhow!("Error getting VM dirty log {}", e))
            })?;
        }
        Ok(())
    }
}

#[cfg(feature = "acpi")]
struct MemoryNotify {
    slot_id: usize,
}

#[cfg(feature = "acpi")]
impl Aml for MemoryNotify {
    fn to_aml_bytes(&self) -> Vec<u8> {
        let object = aml::Path::new(&format!("M{:03}", self.slot_id));
        aml::If::new(
            &aml::Equal::new(&aml::Arg(0), &self.slot_id),
            vec![&aml::Notify::new(&object, &aml::Arg(1))],
        )
        .to_aml_bytes()
    }
}

#[cfg(feature = "acpi")]
struct MemorySlot {
    slot_id: usize,
}

#[cfg(feature = "acpi")]
impl Aml for MemorySlot {
    fn to_aml_bytes(&self) -> Vec<u8> {
        aml::Device::new(
            format!("M{:03}", self.slot_id).as_str().into(),
            vec![
                &aml::Name::new("_HID".into(), &aml::EisaName::new("PNP0C80")),
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
                // We don't expose any NUMA characteristics so all memory is in the same "proximity domain"
                &aml::Method::new(
                    "_PXM".into(),
                    0,
                    false,
                    // We aren't NUMA so associate all RAM into the same proximity region (zero)
                    vec![&aml::Return::new(&0u32)],
                ),
            ],
        )
        .to_aml_bytes()
    }
}

#[cfg(feature = "acpi")]
struct MemorySlots {
    slots: usize,
}

#[cfg(feature = "acpi")]
impl Aml for MemorySlots {
    fn to_aml_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        for slot_id in 0..self.slots {
            bytes.extend_from_slice(&MemorySlot { slot_id }.to_aml_bytes());
        }

        bytes
    }
}

#[cfg(feature = "acpi")]
struct MemoryMethods {
    slots: usize,
}

#[cfg(feature = "acpi")]
impl Aml for MemoryMethods {
    fn to_aml_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        // Add "MTFY" notification method
        let mut memory_notifies = Vec::new();
        for slot_id in 0..self.slots {
            memory_notifies.push(MemoryNotify { slot_id });
        }

        let mut memory_notifies_refs: Vec<&dyn aml::Aml> = Vec::new();
        for memory_notifier in memory_notifies.iter() {
            memory_notifies_refs.push(memory_notifier);
        }

        bytes.extend_from_slice(
            &aml::Method::new("MTFY".into(), 2, true, memory_notifies_refs).to_aml_bytes(),
        );

        // MSCN method
        bytes.extend_from_slice(
            &aml::Method::new(
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
                                    &aml::Store::new(
                                        &aml::Path::new("\\_SB_.MHPC.MINS"),
                                        &aml::ONE,
                                    ),
                                ],
                            ),
                            // Check if MRMV bit is set
                            &aml::If::new(
                                &aml::Equal::new(&aml::Path::new("\\_SB_.MHPC.MRMV"), &aml::ONE),
                                // Notify device if it is (with the eject constant 0x3)
                                vec![
                                    &aml::MethodCall::new(
                                        "MTFY".into(),
                                        vec![&aml::Local(0), &3u8],
                                    ),
                                    // Reset MRMV bit
                                    &aml::Store::new(
                                        &aml::Path::new("\\_SB_.MHPC.MRMV"),
                                        &aml::ONE,
                                    ),
                                ],
                            ),
                            &aml::Add::new(&aml::Local(0), &aml::Local(0), &aml::ONE),
                        ],
                    ),
                    // Release lock
                    &aml::Release::new("MLCK".into()),
                ],
            )
            .to_aml_bytes(),
        );

        bytes.extend_from_slice(
            // Memory status method
            &aml::Method::new(
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
            .to_aml_bytes(),
        );

        bytes.extend_from_slice(
            // Memory range method
            &aml::Method::new(
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
                            aml::AddressSpaceCachable::Cacheable,
                            true,
                            0x0000_0000_0000_0000u64,
                            0xFFFF_FFFF_FFFF_FFFEu64,
                        )]),
                    ),
                    &aml::CreateField::<u64>::new(&aml::Path::new("MR64"), &14usize, "MINL".into()),
                    &aml::CreateField::<u32>::new(&aml::Path::new("MR64"), &18usize, "MINH".into()),
                    &aml::CreateField::<u64>::new(&aml::Path::new("MR64"), &22usize, "MAXL".into()),
                    &aml::CreateField::<u32>::new(&aml::Path::new("MR64"), &26usize, "MAXH".into()),
                    &aml::CreateField::<u64>::new(&aml::Path::new("MR64"), &38usize, "LENL".into()),
                    &aml::CreateField::<u32>::new(&aml::Path::new("MR64"), &42usize, "LENH".into()),
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
                    &aml::Subtract::new(
                        &aml::Path::new("MAXL"),
                        &aml::Path::new("MAXL"),
                        &aml::ONE,
                    ),
                    // Release lock
                    &aml::Release::new("MLCK".into()),
                    &aml::Return::new(&aml::Path::new("MR64")),
                ],
            )
            .to_aml_bytes(),
        );
        bytes
    }
}

#[cfg(feature = "acpi")]
impl Aml for MemoryManager {
    fn to_aml_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Memory Hotplug Controller
        bytes.extend_from_slice(
            &aml::Device::new(
                "_SB_.MHPC".into(),
                vec![
                    &aml::Name::new("_HID".into(), &aml::EisaName::new("PNP0A06")),
                    &aml::Name::new("_UID".into(), &"Memory Hotplug Controller"),
                    // Mutex to protect concurrent access as we write to choose slot and then read back status
                    &aml::Mutex::new("MLCK".into(), 0),
                    &aml::Name::new(
                        "_CRS".into(),
                        &aml::ResourceTemplate::new(vec![&aml::AddressSpace::new_memory(
                            aml::AddressSpaceCachable::NotCacheable,
                            true,
                            self.acpi_address.0 as u64,
                            self.acpi_address.0 + MEMORY_MANAGER_ACPI_SIZE as u64 - 1,
                        )]),
                    ),
                    // OpRegion and Fields map MMIO range into individual field values
                    &aml::OpRegion::new(
                        "MHPR".into(),
                        aml::OpRegionSpace::SystemMemory,
                        self.acpi_address.0 as usize,
                        MEMORY_MANAGER_ACPI_SIZE,
                    ),
                    &aml::Field::new(
                        "MHPR".into(),
                        aml::FieldAccessType::DWord,
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
                        aml::FieldUpdateRule::Preserve,
                        vec![
                            aml::FieldEntry::Reserved(128),
                            aml::FieldEntry::Named(*b"MHPX", 32), // PXM
                        ],
                    ),
                    &aml::Field::new(
                        "MHPR".into(),
                        aml::FieldAccessType::Byte,
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
            .to_aml_bytes(),
        );

        #[cfg(target_arch = "x86_64")]
        {
            if let Some(sgx_epc_region) = &self.sgx_epc_region {
                let min = sgx_epc_region.start().raw_value() as u64;
                let max = min + sgx_epc_region.size() as u64 - 1;
                // SGX EPC region
                bytes.extend_from_slice(
                    &aml::Device::new(
                        "_SB_.EPC_".into(),
                        vec![
                            &aml::Name::new("_HID".into(), &aml::EisaName::new("INT0E0C")),
                            // QWORD describing the EPC region start and size
                            &aml::Name::new(
                                "_CRS".into(),
                                &aml::ResourceTemplate::new(vec![&aml::AddressSpace::new_memory(
                                    aml::AddressSpaceCachable::NotCacheable,
                                    true,
                                    min,
                                    max,
                                )]),
                            ),
                            &aml::Method::new(
                                "_STA".into(),
                                0,
                                false,
                                vec![&aml::Return::new(&0xfu8)],
                            ),
                        ],
                    )
                    .to_aml_bytes(),
                );
            }
        }

        bytes
    }
}

impl Pausable for MemoryManager {}

#[derive(Serialize, Deserialize)]
#[serde(remote = "GuestAddress")]
pub struct GuestAddressDef(pub u64);

#[derive(Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    content: Option<PathBuf>,
    #[serde(with = "GuestAddressDef")]
    start_addr: GuestAddress,
    size: GuestUsize,
}

#[derive(Serialize, Deserialize)]
pub struct MemoryManagerSnapshotData {
    memory_regions: Vec<MemoryRegion>,
}

impl Snapshottable for MemoryManager {
    fn id(&self) -> String {
        MEMORY_MANAGER_SNAPSHOT_ID.to_string()
    }

    fn snapshot(&mut self) -> result::Result<Snapshot, MigratableError> {
        let mut memory_manager_snapshot = Snapshot::new(MEMORY_MANAGER_SNAPSHOT_ID);
        let guest_memory = self.guest_memory.memory();

        let mut memory_regions: Vec<MemoryRegion> = Vec::new();

        guest_memory.with_regions_mut(|index, region| {
            if region.len() == 0 {
                return Err(MigratableError::Snapshot(anyhow!("Zero length region")));
            }

            let mut content = Some(PathBuf::from(format!("memory-region-{}", index)));
            if let Some(file_offset) = region.file_offset() {
                if (region.flags() & libc::MAP_SHARED == libc::MAP_SHARED)
                    && Self::is_hardlink(file_offset.file())
                {
                    // In this very specific case, we know the memory region
                    // is backed by a file on the host filesystem that can be
                    // accessed by the user, and additionally the mapping is
                    // shared, which means that modifications to the content
                    // are written to the actual file.
                    // When meeting these conditions, we can skip the copy of
                    // the memory content for this specific region, as we can
                    // assume the user will have it saved through the backing
                    // file already.
                    content = None;
                }
            }

            memory_regions.push(MemoryRegion {
                content,
                start_addr: region.start_addr(),
                size: region.len(),
            });

            Ok(())
        })?;

        // Store locally this list of regions as it will be used through the
        // Transportable::send() implementation. The point is to avoid the
        // duplication of code regarding the creation of the path for each
        // region. The 'snapshot' step creates the list of memory regions,
        // including information about the need to copy a memory region or
        // not. This saves the 'send' step having to go through the same
        // process, and instead it can directly proceed with storing the
        // memory region content for the regions requiring it.
        self.snapshot_memory_regions = memory_regions.clone();

        memory_manager_snapshot.add_data_section(SnapshotDataSection::new_from_state(
            MEMORY_MANAGER_SNAPSHOT_ID,
            &MemoryManagerSnapshotData { memory_regions },
        )?);

        let mut memory_snapshot = self.snapshot.lock().unwrap();
        *memory_snapshot = Some(guest_memory);

        Ok(memory_manager_snapshot)
    }
}

impl Transportable for MemoryManager {
    fn send(
        &self,
        _snapshot: &Snapshot,
        destination_url: &str,
    ) -> result::Result<(), MigratableError> {
        let vm_memory_snapshot_path = url_to_path(destination_url)?;

        if let Some(guest_memory) = &*self.snapshot.lock().unwrap() {
            for region in self.snapshot_memory_regions.iter() {
                if let Some(content) = &region.content {
                    let mut memory_region_path = vm_memory_snapshot_path.clone();
                    memory_region_path.push(content);

                    // Create the snapshot file for the region
                    let mut memory_region_file = OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create_new(true)
                        .open(memory_region_path)
                        .map_err(|e| MigratableError::MigrateSend(e.into()))?;

                    guest_memory
                        .write_all_to(
                            region.start_addr,
                            &mut memory_region_file,
                            region.size as usize,
                        )
                        .map_err(|e| MigratableError::MigrateSend(e.into()))?;
                }
            }
        }
        Ok(())
    }
}
impl Migratable for MemoryManager {}
