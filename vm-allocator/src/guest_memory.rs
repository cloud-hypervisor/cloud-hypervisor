// Copyright © 2026 Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0
//

use std::borrow::Borrow;
use std::ops::Deref;
use std::sync::Arc;

use vm_memory::bitmap::{AtomicBitmap, BS};
use vm_memory::mmap::FromRangesError;
use vm_memory::{
    FileOffset, GuestAddress, GuestMemoryBackend, GuestMemoryError, GuestMemoryRegion,
    GuestMemoryRegionBytes, GuestRegionCollection, GuestRegionCollectionError, GuestRegionMmap,
    GuestUsize, MemoryRegionAddress, MmapRegion, VolatileSlice,
};

/// A region of guest memory backed by an mmap allocation.
#[derive(Debug)]
pub struct GuestRegion {
    region: GuestRegionMmap<AtomicBitmap>,
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
        Self { region }
    }
}

/// A sorted collection of non-overlapping guest memory regions.
#[derive(Clone, Debug, Default)]
pub struct GuestMemory(GuestRegionCollection<GuestRegion>);

impl GuestMemory {
    /// Creates a collection from non-overlapping regions sorted by guest address.
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
