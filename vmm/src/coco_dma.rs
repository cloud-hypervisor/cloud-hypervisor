// Copyright © 2025 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! Synchronizes host IOMMU (VFIO) mappings with guest shared/private memory
//! conversions for confidential VMs (TDX, SEV-SNP).
//!
//! This mirrors the design of QEMU upstream commit 5d6483edaa9, where a
//! `RamDiscardManager` tracks the shared state of guest RAM at 4 KiB
//! granularity and notifies VFIO to map newly-shared pages and unmap pages
//! that become private. The host IOMMU must only ever hold mappings for
//! shared guest memory: the host cannot access private (encrypted) pages, so
//! a device DMA targeting such a page would fault or corrupt guest state.

use std::sync::{Arc, Mutex};

use hypervisor::MemoryConversionHandler;
use log::error;
use vm_device::dma_mapping::ExternalDmaMapping;

const PAGE_SIZE: u64 = 4096;
const PAGE_SHIFT: u64 = 12;

/// A contiguous guest RAM region tracked for conversion, with a per-4 KiB
/// bitmap recording whether each page is currently mapped into the host IOMMU
/// (i.e. shared). All pages start private (bit clear), matching the initial
/// state of confidential guest memory.
struct TrackedRegion {
    base: u64,
    size: u64,
    /// One bit per 4 KiB page; set means "shared and mapped in the IOMMU".
    shared: Vec<u64>,
}

impl TrackedRegion {
    fn new(base: u64, size: u64) -> Self {
        let pages = size.div_ceil(PAGE_SIZE) as usize;
        let words = pages.div_ceil(64);
        TrackedRegion {
            base,
            size,
            shared: vec![0u64; words],
        }
    }

    fn is_shared(&self, page_idx: usize) -> bool {
        (self.shared[page_idx / 64] >> (page_idx % 64)) & 1 != 0
    }

    fn set_shared(&mut self, page_idx: usize, shared: bool) {
        let word = page_idx / 64;
        let bit = 1u64 << (page_idx % 64);
        if shared {
            self.shared[word] |= bit;
        } else {
            self.shared[word] &= !bit;
        }
    }
}

/// Bridges guest memory conversion events to host IOMMU map/unmap operations.
///
/// The shared GPA is identity-mapped into the host IOMMU (`iova == gpa`),
/// matching how the static boot-time mapping is set up for non-confidential
/// VMs. Map and unmap are always issued at 4 KiB granularity so the request
/// granularity always matches the underlying VFIO mapping, which keeps partial
/// conversions safe.
pub struct SharedMemoryConverter {
    dma_mapping: Arc<dyn ExternalDmaMapping>,
    regions: Mutex<Vec<TrackedRegion>>,
}

impl SharedMemoryConverter {
    /// Build a converter wrapping `dma_mapping` and tracking the given guest
    /// RAM regions, each expressed as a `(base, size)` pair.
    pub fn new(
        dma_mapping: Arc<dyn ExternalDmaMapping>,
        regions: impl IntoIterator<Item = (u64, u64)>,
    ) -> Self {
        let regions = regions
            .into_iter()
            .map(|(base, size)| TrackedRegion::new(base, size))
            .collect();
        SharedMemoryConverter {
            dma_mapping,
            regions: Mutex::new(regions),
        }
    }
}

impl MemoryConversionHandler for SharedMemoryConverter {
    fn convert(&self, gpa: u64, size: u64, to_private: bool) {
        if size == 0 {
            return;
        }

        // Align the requested range to 4 KiB. Conversions are page-granular in
        // practice, but be defensive against unaligned inputs.
        let start = gpa & !(PAGE_SIZE - 1);
        let end = gpa.saturating_add(size).div_ceil(PAGE_SIZE) * PAGE_SIZE;

        let mut regions = self.regions.lock().unwrap();
        for region in regions.iter_mut() {
            let region_end = region.base.saturating_add(region.size);
            let overlap_start = start.max(region.base);
            let overlap_end = end.min(region_end);
            if overlap_start >= overlap_end {
                continue;
            }

            let mut page = overlap_start;
            while page < overlap_end {
                let idx = ((page - region.base) >> PAGE_SHIFT) as usize;
                let currently_shared = region.is_shared(idx);

                if to_private {
                    if currently_shared {
                        if let Err(e) = self.dma_mapping.unmap(page, PAGE_SIZE) {
                            // A failed unmap leaves a stale host IOMMU mapping
                            // pointing at memory that is about to become
                            // private. This is a security concern, so log it
                            // loudly; the bit is still cleared to avoid a later
                            // double unmap.
                            error!(
                                "Failed to unmap shared page {page:#x} from host IOMMU on private conversion: {e}"
                            );
                        }
                        region.set_shared(idx, false);
                    }
                } else if !currently_shared {
                    // Identity-map the newly shared GPA into the host IOMMU.
                    if let Err(e) = self.dma_mapping.map(page, page, PAGE_SIZE) {
                        error!(
                            "Failed to map shared page {page:#x} into host IOMMU on shared conversion: {e}"
                        );
                    } else {
                        region.set_shared(idx, true);
                    }
                }

                page = page.saturating_add(PAGE_SIZE);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct FakeMapping {
        events: Mutex<Vec<(bool, u64, u64)>>,
    }

    impl ExternalDmaMapping for FakeMapping {
        fn map(&self, iova: u64, _gpa: u64, size: u64) -> io::Result<()> {
            self.events.lock().unwrap().push((true, iova, size));
            Ok(())
        }

        fn unmap(&self, iova: u64, size: u64) -> io::Result<()> {
            self.events.lock().unwrap().push((false, iova, size));
            Ok(())
        }
    }

    #[test]
    fn test_shared_then_private_roundtrip() {
        let fake = Arc::new(FakeMapping::default());
        let converter = SharedMemoryConverter::new(fake.clone(), [(0x1000, 0x4000)]);

        // Convert two pages to shared.
        converter.convert(0x1000, 0x2000, false);
        // Convert the same range to private.
        converter.convert(0x1000, 0x2000, true);

        let events = fake.events.lock().unwrap();
        assert_eq!(
            *events,
            vec![
                (true, 0x1000, PAGE_SIZE),
                (true, 0x2000, PAGE_SIZE),
                (false, 0x1000, PAGE_SIZE),
                (false, 0x2000, PAGE_SIZE),
            ]
        );
    }

    #[test]
    fn test_redundant_conversions_are_skipped() {
        let fake = Arc::new(FakeMapping::default());
        let converter = SharedMemoryConverter::new(fake.clone(), [(0x0, 0x1000)]);

        converter.convert(0x0, 0x1000, false);
        // Repeating the shared conversion must not re-map.
        converter.convert(0x0, 0x1000, false);

        let events = fake.events.lock().unwrap();
        assert_eq!(*events, vec![(true, 0x0, PAGE_SIZE)]);
    }

    #[test]
    fn test_out_of_range_is_ignored() {
        let fake = Arc::new(FakeMapping::default());
        let converter = SharedMemoryConverter::new(fake.clone(), [(0x1000, 0x1000)]);

        // Entirely outside the tracked region.
        converter.convert(0x100000, 0x1000, false);

        assert!(fake.events.lock().unwrap().is_empty());
    }
}
