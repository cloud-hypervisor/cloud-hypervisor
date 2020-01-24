// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

#[cfg(feature = "acpi")]
use acpi_tables::{aml, aml::Aml};
use arc_swap::ArcSwap;
use arch::RegionType;
use devices::BusDevice;
use kvm_bindings::kvm_userspace_memory_region;
use kvm_ioctls::*;
use std::convert::TryInto;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::io::FromRawFd;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use vm_allocator::SystemAllocator;
use vm_memory::guest_memory::FileOffset;
use vm_memory::{
    mmap::MmapRegionError, Address, Error as MmapError, GuestAddress, GuestMemory, GuestMemoryMmap,
    GuestMemoryRegion, GuestRegionMmap, GuestUsize, MmapRegion,
};

const HOTPLUG_COUNT: usize = 8;

#[derive(Default)]
struct HotPlugState {
    base: u64,
    length: u64,
    active: bool,
    inserting: bool,
    removing: bool,
}

pub struct MemoryManager {
    guest_memory: Arc<ArcSwap<GuestMemoryMmap>>,
    next_kvm_memory_slot: u32,
    start_of_device_area: GuestAddress,
    end_of_device_area: GuestAddress,
    fd: Arc<VmFd>,
    mem_regions: Vec<Arc<GuestRegionMmap>>,
    hotplug_slots: Vec<HotPlugState>,
    selected_slot: usize,
    backing_file: Option<PathBuf>,
    mergeable: bool,
    allocator: Arc<Mutex<SystemAllocator>>,
    current_ram: u64,
    next_hotplug_slot: usize,
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
    InsufficientHotplugRAM,

    /// The requested hotplug memory addition is not a valid size
    InvalidSize,

    /// Failed to set the user memory region.
    SetUserMemoryRegion(kvm_ioctls::Error),
}

pub fn get_host_cpu_phys_bits() -> u8 {
    use core::arch::x86_64;
    unsafe {
        let leaf = x86_64::__cpuid(0x8000_0000);

        // Detect and handle AMD SME (Secure Memory Encryption) properly.
        // Some physical address bits may become reserved when the feature is enabled.
        // See AMD64 Architecture Programmer's Manual Volume 2, Section 7.10.1
        let reduced = if leaf.eax >= 0x8000_001f
            && leaf.ebx == 0x6874_7541    // Vendor ID: AuthenticAMD
            && leaf.ecx == 0x444d_4163
            && leaf.edx == 0x6974_6e65
            && x86_64::__cpuid(0x8000_001f).eax & 0x1 != 0
        {
            (x86_64::__cpuid(0x8000_001f).ebx >> 6) & 0x3f
        } else {
            0
        };

        if leaf.eax >= 0x8000_0008 {
            let leaf = x86_64::__cpuid(0x8000_0008);
            ((leaf.eax & 0xff) - reduced) as u8
        } else {
            36
        }
    }
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

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) {
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
        }
    }
}

impl MemoryManager {
    pub fn new(
        allocator: Arc<Mutex<SystemAllocator>>,
        fd: Arc<VmFd>,
        boot_ram: u64,
        hotplug_size: Option<u64>,
        backing_file: &Option<PathBuf>,
        mergeable: bool,
    ) -> Result<Arc<Mutex<MemoryManager>>, Error> {
        // Init guest memory
        let arch_mem_regions = arch::arch_memory_regions(boot_ram);

        let ram_regions: Vec<(GuestAddress, usize)> = arch_mem_regions
            .iter()
            .filter(|r| r.2 == RegionType::Ram)
            .map(|r| (r.0, r.1))
            .collect();

        let mut mem_regions = Vec::new();
        for region in ram_regions.iter() {
            mem_regions.push(MemoryManager::create_ram_region(
                backing_file,
                region.0,
                region.1,
            )?);
        }

        let guest_memory =
            GuestMemoryMmap::from_arc_regions(mem_regions.clone()).map_err(Error::GuestMemory)?;

        let end_of_device_area = GuestAddress((1 << get_host_cpu_phys_bits()) - 1);
        let mem_end = guest_memory.last_addr();
        let mut start_of_device_area = if mem_end < arch::layout::MEM_32BIT_RESERVED_START {
            arch::layout::RAM_64BIT_START
        } else {
            mem_end.unchecked_add(1)
        };

        if let Some(size) = hotplug_size {
            start_of_device_area = start_of_device_area.unchecked_add(size);
        }

        let guest_memory = Arc::new(ArcSwap::new(Arc::new(guest_memory)));

        let mut hotplug_slots = Vec::with_capacity(HOTPLUG_COUNT);
        hotplug_slots.resize_with(HOTPLUG_COUNT, HotPlugState::default);

        let memory_manager = Arc::new(Mutex::new(MemoryManager {
            guest_memory: guest_memory.clone(),
            next_kvm_memory_slot: 0,
            start_of_device_area,
            end_of_device_area,
            fd,
            mem_regions,
            hotplug_slots,
            selected_slot: 0,
            backing_file: backing_file.clone(),
            mergeable,
            allocator: allocator.clone(),
            current_ram: boot_ram,
            next_hotplug_slot: 0,
        }));

        guest_memory.load().with_regions(|_, region| {
            let _ = memory_manager.lock().unwrap().create_userspace_mapping(
                region.start_addr().raw_value(),
                region.len() as u64,
                region.as_ptr() as u64,
                mergeable,
            )?;
            Ok(())
        })?;

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

    fn create_ram_region(
        backing_file: &Option<PathBuf>,
        start_addr: GuestAddress,
        size: usize,
    ) -> Result<Arc<GuestRegionMmap>, Error> {
        Ok(Arc::new(match backing_file {
            Some(ref file) => {
                let f = if file.is_dir() {
                    let fs_str = format!("{}{}", file.display(), "/tmpfile_XXXXXX");
                    let fs = std::ffi::CString::new(fs_str).unwrap();
                    let mut path = fs.as_bytes_with_nul().to_owned();
                    let path_ptr = path.as_mut_ptr() as *mut _;
                    let fd = unsafe { libc::mkstemp(path_ptr) };
                    unsafe { libc::unlink(path_ptr) };
                    unsafe { File::from_raw_fd(fd) }
                } else {
                    OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(file)
                        .map_err(Error::SharedFileCreate)?
                };

                f.set_len(size as u64).map_err(Error::SharedFileSetLen)?;

                GuestRegionMmap::new(
                    MmapRegion::from_file(FileOffset::new(f, 0), size)
                        .map_err(Error::GuestMemoryRegion)?,
                    start_addr,
                )
                .map_err(Error::GuestMemory)?
            }
            None => GuestRegionMmap::new(
                MmapRegion::new(size).map_err(Error::GuestMemoryRegion)?,
                start_addr,
            )
            .map_err(Error::GuestMemory)?,
        }))
    }

    fn hotplug_ram_region(&mut self, size: usize) -> Result<(), Error> {
        info!("Hotplugging new RAM: {}", size);

        // Check that there is a free slot
        if self.next_hotplug_slot >= HOTPLUG_COUNT {
            return Err(Error::NoSlotAvailable);
        }

        // "Inserted" DIMM must have a size that is a multiple of 128MiB
        if size % (128 << 20) != 0 {
            return Err(Error::InvalidSize);
        }

        // Start address needs to be non-contiguous with last memory added (leaving a gap of 256MiB)
        // and also aligned to 128MiB boundary. It must also start at the 64bit start.
        let mem_end = self.guest_memory.load().last_addr();
        let start_addr = if mem_end < arch::layout::MEM_32BIT_RESERVED_START {
            arch::layout::RAM_64BIT_START
        } else {
            GuestAddress((mem_end.0 + 1 + (256 << 20)) & !((128 << 20) - 1))
        };

        if start_addr.checked_add(size.try_into().unwrap()).unwrap() >= self.start_of_device_area()
        {
            return Err(Error::InsufficientHotplugRAM);
        }

        // Allocate memory for the region
        let region = MemoryManager::create_ram_region(&self.backing_file, start_addr, size)?;

        // Map it into the guest
        self.create_userspace_mapping(
            region.start_addr().0,
            region.len() as u64,
            region.as_ptr() as u64,
            self.mergeable,
        )?;

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

        // Update the GuestMemoryMmap with the new range
        self.mem_regions.push(region);
        let guest_memory = GuestMemoryMmap::from_arc_regions(self.mem_regions.clone())
            .map_err(Error::GuestMemory)?;
        self.guest_memory.store(Arc::new(guest_memory));

        Ok(())
    }

    pub fn guest_memory(&self) -> Arc<ArcSwap<GuestMemoryMmap>> {
        self.guest_memory.clone()
    }

    pub fn start_of_device_area(&self) -> GuestAddress {
        self.start_of_device_area
    }

    pub fn end_of_device_area(&self) -> GuestAddress {
        self.end_of_device_area
    }

    pub fn allocate_kvm_memory_slot(&mut self) -> u32 {
        let slot_id = self.next_kvm_memory_slot;
        self.next_kvm_memory_slot += 1;
        slot_id
    }

    pub fn create_userspace_mapping(
        &mut self,
        guest_phys_addr: u64,
        memory_size: u64,
        userspace_addr: u64,
        mergeable: bool,
    ) -> Result<u32, Error> {
        let slot = self.allocate_kvm_memory_slot();
        let mem_region = kvm_userspace_memory_region {
            slot,
            guest_phys_addr,
            memory_size,
            userspace_addr,
            flags: 0,
        };

        // Safe because the guest regions are guaranteed not to overlap.
        unsafe { self.fd.set_user_memory_region(mem_region) }
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

    pub fn resize(&mut self, desired_ram: u64) -> Result<bool, Error> {
        if desired_ram > self.current_ram {
            self.hotplug_ram_region((desired_ram - self.current_ram) as usize)?;
            self.current_ram = desired_ram;
            Ok(true)
        } else {
            Ok(false)
        }
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
                    &aml::Acquire::new("MLCK".into(), 0xfff),
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
                    &aml::Acquire::new("MLCK".into(), 0xfff),
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
                    &aml::Acquire::new("MLCK".into(), 0xfff),
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
                    &aml::CreateField::<u32>::new(&aml::Path::new("MR64"), &14usize, "MINL".into()),
                    &aml::CreateField::<u32>::new(&aml::Path::new("MR64"), &18usize, "MINH".into()),
                    &aml::CreateField::<u32>::new(&aml::Path::new("MR64"), &22usize, "MAXL".into()),
                    &aml::CreateField::<u32>::new(&aml::Path::new("MR64"), &26usize, "MAXH".into()),
                    &aml::CreateField::<u32>::new(&aml::Path::new("MR64"), &38usize, "LENL".into()),
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
                    &aml::Subtract::new(
                        &aml::Path::new("MAXH"),
                        &aml::Path::new("MAXH"),
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
                    &aml::Name::new("_HID".into(), &aml::EISAName::new("PNP0A06")),
                    // Mutex to protect concurrent access as we write to choose slot and then read back status
                    &aml::Mutex::new("MLCK".into(), 0),
                    // I/O port for memory controller
                    &aml::Name::new(
                        "_CRS".into(),
                        &aml::ResourceTemplate::new(vec![&aml::IO::new(
                            0x0a00, 0x0a00, 0x01, 0x18,
                        )]),
                    ),
                    // OpRegion and Fields map I/O port into individual field values
                    &aml::OpRegion::new("MHPR".into(), aml::OpRegionSpace::SystemIO, 0xa00, 0x18),
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

        bytes
    }
}
