// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use arc_swap::ArcSwap;
use arch::RegionType;
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
}

pub struct MemoryManager {
    guest_memory: Arc<ArcSwap<GuestMemoryMmap>>,
    next_kvm_memory_slot: u32,
    start_of_device_area: GuestAddress,
    end_of_device_area: GuestAddress,
    fd: Arc<VmFd>,
    mem_regions: Vec<Arc<GuestRegionMmap>>,
    hotplug_slots: Vec<HotPlugState>,
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
        let mem_end = guest_memory.end_addr();
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
            next_kvm_memory_slot: ram_regions.len() as u32,
            start_of_device_area,
            end_of_device_area,
            fd,
            mem_regions,
            hotplug_slots,
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
        let mem_end = self.guest_memory.load().end_addr();
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
        unsafe {
            self.fd
                .set_user_memory_region(mem_region)
                .map_err(|e| io::Error::from_raw_os_error(e.errno()))
        }
        .map_err(|_: io::Error| Error::GuestMemory(MmapError::NoMemoryRegion))?;

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

    pub fn resize(&mut self, desired_ram: u64) -> Result<(), Error> {
        if desired_ram >= self.current_ram {
            self.hotplug_ram_region((desired_ram - self.current_ram) as usize)?;
            self.current_ram = desired_ram;
        }
        Ok(())
    }
}
}
