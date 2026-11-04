// Copyright © 2026 Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0
//

use std::borrow::Borrow;
use std::ops::Deref;
use std::os::fd::AsFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{fmt, io, process};

use log::{error, info, warn};
use thiserror::Error;
use vm_memory::bitmap::{AtomicBitmap, BS, NewBitmap};
use vm_memory::mmap::{FromRangesError, MmapRegionBuilder, MmapRegionError};
use vm_memory::{
    Address, FileOffset, GuestAddress, GuestMemoryBackend, GuestMemoryError, GuestMemoryRegion,
    GuestMemoryRegionBytes, GuestRegionCollection, GuestRegionCollectionError, GuestRegionMmap,
    GuestUsize, MemoryRegionAddress, MmapRegion, VolatileSlice,
};

use crate::MemorySlotAllocator;
use crate::aligned_mapping::AlignedMapping;

/// Errors registering guest memory with the hypervisor.
#[derive(Error, Debug)]
pub enum Error {
    /// The region is already registered or registration is in progress.
    #[error("Guest region is already registered")]
    AlreadyRegistered,
    /// The region was constructed without a VM.
    #[error("Guest region has no VM")]
    MissingVm,
    /// The hypervisor rejected the memory region.
    #[error("Failed to create the user memory region")]
    CreateRegion(#[source] hypervisor::HypervisorVmError),
    /// The hypervisor could not remove the old registration.
    #[error("Failed to remove the user memory region")]
    RemoveRegion(#[source] hypervisor::HypervisorVmError),
    /// The guest address range overflows.
    #[error("Guest memory range overflows at {0:#x}")]
    InvalidGuestAddress(u64),
    /// Private memory cannot be recreated without preserving its guest_memfd.
    #[error("Cannot move a private memory region")]
    MovePrivateRegion,
    /// The aligned file mapping could not be allocated.
    #[error("Failed to map the backing file")]
    FileMapping(#[source] io::Error),
    /// The raw mapping could not be wrapped.
    #[error("Failed to create the mmap region")]
    MmapRegion(#[source] MmapRegionError),
}

/// A region of guest memory backed by an mmap allocation.
pub struct GuestRegion {
    region: GuestRegionMmap<AtomicBitmap>,
    // Owns the allocation because a MmapRegion built from a raw pointer does
    // not unmap it on drop. Must follow `region` so the backing is freed last.
    aligned_mapping: Option<AlignedMapping>,
    vm: Option<Arc<dyn hypervisor::Vm>>,
    slot_allocator: Option<Arc<MemorySlotAllocator>>,
    slot: Option<u32>,
    registered: AtomicBool,
    mergeable: bool,
    readonly: bool,
    log_dirty_pages: bool,
    visibility: hypervisor::MemoryVisibility,
}

impl fmt::Debug for GuestRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuestRegion")
            .field("region", &self.region)
            .field("slot", &self.slot)
            .field("mergeable", &self.mergeable)
            .finish_non_exhaustive()
    }
}

impl GuestRegion {
    /// Wrap a mapping and reserve a slot without registering it with the VM.
    #[expect(clippy::too_many_arguments)]
    pub fn from_mmap(
        mapping: MmapRegion<AtomicBitmap>,
        guest_addr: GuestAddress,
        vm: Arc<dyn hypervisor::Vm>,
        slot_allocator: Arc<MemorySlotAllocator>,
        mergeable: bool,
        readonly: bool,
        log_dirty_pages: bool,
        visibility: hypervisor::MemoryVisibility,
    ) -> Result<Self, Error> {
        let region = GuestRegionMmap::new(mapping, guest_addr)
            .ok_or(Error::InvalidGuestAddress(guest_addr.raw_value()))?;
        let slot = slot_allocator.next_memory_slot();
        Ok(Self {
            region,
            aligned_mapping: None,
            vm: Some(vm),
            slot_allocator: Some(slot_allocator),
            slot: Some(slot),
            registered: AtomicBool::new(false),
            mergeable,
            readonly,
            log_dirty_pages,
            visibility,
        })
    }

    /// Create a shared file mapping with the requested host address alignment.
    /// The returned region owns the allocation but is not registered yet.
    pub fn from_file(
        file_offset: FileOffset,
        size: usize,
        alignment: usize,
        guest_addr: GuestAddress,
        prot: i32,
        vm: Arc<dyn hypervisor::Vm>,
        slot_allocator: Arc<MemorySlotAllocator>,
    ) -> Result<Self, Error> {
        guest_addr
            .checked_add(size as u64)
            .ok_or(Error::InvalidGuestAddress(guest_addr.raw_value()))?;
        let backing = AlignedMapping::mmap(
            size as u64,
            alignment,
            prot,
            file_offset.file().as_fd(),
            file_offset.start(),
            0,
        )
        .map_err(Error::FileMapping)?;
        // SAFETY: backing owns the allocation and is retained until this region
        // is dropped. The non-owning mmap Arc cannot escape GuestRegion.
        let mapping = unsafe {
            MmapRegionBuilder::new_with_bitmap(size, AtomicBitmap::with_len(size))
                .with_raw_mmap_pointer(backing.addr())
                .with_file_offset(file_offset)
                .with_mmap_prot(prot)
                .with_mmap_flags(libc::MAP_SHARED)
                .build()
        }
        .map_err(Error::MmapRegion)?;
        let mut region = Self::from_mmap(
            mapping,
            guest_addr,
            vm,
            slot_allocator,
            false,
            false,
            false,
            hypervisor::MemoryVisibility::Shared,
        )?;
        region.aligned_mapping = Some(backing);
        Ok(region)
    }

    /// Register the region with the hypervisor.
    pub fn register(&self) -> Result<(), Error> {
        let vm = self.vm.as_ref().ok_or(Error::MissingVm)?;
        // Prevent concurrent calls from registering the same slot twice.
        self.registered
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::AlreadyRegistered)?;
        let slot = self.slot.unwrap();
        let guest_phys_addr = self.region.start_addr().raw_value();
        let memory_size = self.region.size();
        let userspace_addr = self.region.as_ptr();
        // SAFETY: the region keeps its mapping alive until after slot removal.
        if let Err(e) = unsafe {
            vm.create_user_memory_region(
                slot,
                guest_phys_addr,
                memory_size,
                userspace_addr,
                self.readonly,
                self.log_dirty_pages,
                self.visibility,
            )
        } {
            self.registered.store(false, Ordering::Release);
            return Err(Error::CreateRegion(e));
        }

        // SAFETY: the address and size are valid since the
        // mmap succeeded.
        let ret = unsafe {
            libc::madvise(
                userspace_addr.cast::<libc::c_void>(),
                memory_size as libc::size_t,
                libc::MADV_DONTDUMP,
            )
        };
        if ret != 0 {
            let e = io::Error::last_os_error();
            warn!("Failed to mark memory as MADV_DONTDUMP: {e}");
        }

        // Mark the pages as mergeable if explicitly asked for.
        if self.mergeable {
            // SAFETY: the address and size are valid since the
            // mmap succeeded.
            let ret = unsafe {
                libc::madvise(
                    userspace_addr.cast::<libc::c_void>(),
                    memory_size as libc::size_t,
                    libc::MADV_MERGEABLE,
                )
            };
            if ret != 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINVAL) {
                    warn!(
                        "Failed to mark memory as mergeable: Kernel not configured with CONFIG_KSM"
                    );
                } else {
                    warn!("Failed to mark memory as mergeable: {err}");
                }
            }
        }

        info!(
            "Created userspace mapping: {:#} -> {:#} {:#}",
            guest_phys_addr, userspace_addr as usize, memory_size
        );

        Ok(())
    }

    /// The reserved slot, including before registration.
    pub fn slot(&self) -> Option<u32> {
        self.slot
    }

    /// Whether the region is registered or registration is in progress.
    pub fn is_registered(&self) -> bool {
        self.registered.load(Ordering::Acquire)
    }

    /// Move a region to a new guest address without replacing its mapping.
    /// Unregistered regions remain unregistered. If removing a registered
    /// region fails, its old registration remains. If replacement fails,
    /// the slot stays reserved so the caller can restore the registration.
    pub fn move_guest_address(&mut self, guest_addr: GuestAddress) -> Result<(), Error> {
        let region = GuestRegionMmap::with_arc(self.region.get_mmap(), guest_addr)
            .ok_or(Error::InvalidGuestAddress(guest_addr.raw_value()))?;
        if !*self.registered.get_mut() {
            self.region = region;
            return Ok(());
        }
        if self.visibility != hypervisor::MemoryVisibility::Shared {
            return Err(Error::MovePrivateRegion);
        }
        if self.region.start_addr() == guest_addr {
            return Ok(());
        }
        let vm = self.vm.as_ref().unwrap();
        let slot = self.slot.unwrap();
        // SAFETY: exclusive access keeps the old region and its mapping alive.
        unsafe {
            vm.remove_user_memory_region(
                slot,
                self.region.start_addr().raw_value(),
                self.region.size(),
                self.region.as_ptr(),
                false,
            )
        }
        .map_err(Error::RemoveRegion)?;
        *self.registered.get_mut() = false;
        // SAFETY: both guest addresses refer to the same live mapping.
        unsafe {
            vm.create_user_memory_region(
                slot,
                guest_addr.raw_value(),
                region.size(),
                region.as_ptr(),
                self.readonly,
                self.log_dirty_pages,
                self.visibility,
            )
        }
        .map_err(Error::CreateRegion)?;
        self.region = region;
        *self.registered.get_mut() = true;
        Ok(())
    }
}

impl Deref for GuestRegion {
    type Target = MmapRegion<AtomicBitmap>;

    fn deref(&self) -> &Self::Target {
        &self.region
    }
}

impl GuestMemoryRegion for GuestRegion {
    type B = AtomicBitmap;

    fn len(&self) -> GuestUsize {
        self.region.len()
    }

    fn start_addr(&self) -> GuestAddress {
        self.region.start_addr()
    }

    fn bitmap(&self) -> BS<'_, Self::B> {
        self.region.bitmap()
    }

    fn get_host_address(&self, addr: MemoryRegionAddress) -> Result<*mut u8, GuestMemoryError> {
        self.region.get_host_address(addr)
    }

    fn file_offset(&self) -> Option<&FileOffset> {
        self.region.file_offset()
    }

    fn get_slice(
        &self,
        offset: MemoryRegionAddress,
        count: usize,
    ) -> Result<VolatileSlice<'_, BS<'_, Self::B>>, GuestMemoryError> {
        self.region.get_slice(offset, count)
    }

    #[cfg(target_os = "linux")]
    fn is_hugetlbfs(&self) -> Option<bool> {
        self.region.is_hugetlbfs()
    }
}

impl GuestMemoryRegionBytes for GuestRegion {}

impl From<GuestRegionMmap<AtomicBitmap>> for GuestRegion {
    fn from(region: GuestRegionMmap<AtomicBitmap>) -> Self {
        Self {
            region,
            aligned_mapping: None,
            vm: None,
            slot_allocator: None,
            slot: None,
            registered: AtomicBool::new(false),
            mergeable: false,
            readonly: false,
            log_dirty_pages: false,
            visibility: hypervisor::MemoryVisibility::Shared,
        }
    }
}

impl Drop for GuestRegion {
    fn drop(&mut self) {
        let guest_phys_addr = self.region.start_addr().raw_value();
        let memory_size = self.region.size();
        let userspace_addr = self.region.as_ptr();
        if *self.registered.get_mut() {
            let vm = self.vm.as_ref().unwrap();
            let slot = self.slot.unwrap();
            // SAFETY: the owned region remains mapped until after this destructor returns.
            if let Err(e) = unsafe {
                vm.remove_user_memory_region(
                    slot,
                    guest_phys_addr,
                    memory_size,
                    userspace_addr,
                    false, // Read-only flags are ignored when removing a region.
                )
            } {
                error!("Error releasing memory region: {e}");
                process::exit(1);
            }

            info!(
                "Removed userspace mapping: {:#} -> {:#} {:#}",
                guest_phys_addr, userspace_addr as usize, memory_size
            );
        }
        if self.mergeable {
            // SAFETY: the address and size are valid as the region was
            // previously advised.
            let ret = unsafe {
                libc::madvise(
                    userspace_addr.cast::<libc::c_void>(),
                    memory_size as libc::size_t,
                    libc::MADV_UNMERGEABLE,
                )
            };

            if ret != 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINVAL) {
                    warn!(
                        "Failed to mark memory as unmergeable: Kernel not configured with CONFIG_KSM"
                    );
                } else {
                    warn!("Failed to mark memory as unmergeable: {err}");
                }
            }
        }
        if let Some(slot) = self.slot {
            self.slot_allocator.as_ref().unwrap().free_memory_slot(slot);
        }
    }
}

/// A sorted collection of non-overlapping guest memory regions.
#[derive(Clone, Debug, Default)]
pub struct GuestMemory(GuestRegionCollection<GuestRegion>);

impl GuestMemory {
    /// The regions must be sorted by guest address and must not overlap.
    pub fn from_regions(regions: Vec<GuestRegion>) -> Result<Self, GuestRegionCollectionError> {
        GuestRegionCollection::from_regions(regions).map(Self)
    }

    /// The regions must be sorted by guest address and must not overlap.
    pub fn from_arc_regions(
        regions: Vec<Arc<GuestRegion>>,
    ) -> Result<Self, GuestRegionCollectionError> {
        GuestRegionCollection::from_arc_regions(regions).map(Self)
    }

    /// Returns a new collection containing the additional region.
    pub fn insert_region(
        &self,
        region: Arc<GuestRegion>,
    ) -> Result<Self, GuestRegionCollectionError> {
        self.0.insert_region(region).map(Self)
    }

    /// Allocates anonymous regions from non-overlapping ranges sorted by guest address.
    pub fn from_ranges(ranges: &[(GuestAddress, usize)]) -> Result<Self, FromRangesError> {
        Self::from_ranges_with_files(ranges.iter().map(|&(addr, size)| (addr, size, None)))
    }

    /// Allocates regions from non-overlapping ranges sorted by guest address.
    ///
    /// Each range specifies a guest address, size, and optional backing file offset.
    /// Ranges without a backing file use anonymous memory.
    pub fn from_ranges_with_files<A, T>(ranges: T) -> Result<Self, FromRangesError>
    where
        A: Borrow<(GuestAddress, usize, Option<FileOffset>)>,
        T: IntoIterator<Item = A>,
    {
        let regions = ranges
            .into_iter()
            .map(|range| {
                let (addr, size, file) = range.borrow();
                GuestRegionMmap::from_range(*addr, *size, file.clone()).map(GuestRegion::from)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::from_regions(regions).map_err(Into::into)
    }
}

impl GuestMemoryBackend for GuestMemory {
    type R = GuestRegion;

    fn num_regions(&self) -> usize {
        self.0.num_regions()
    }

    fn find_region(&self, addr: GuestAddress) -> Option<&Self::R> {
        self.0.find_region(addr)
    }

    fn iter(&self) -> impl Iterator<Item = &Self::R> {
        self.0.iter()
    }
}
