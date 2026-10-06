// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0
//

use std::io;
use std::sync::{Arc, Mutex};

use hypervisor::MemoryConversionHandler;
use log::error;
use vm_device::dma_mapping::ExternalDmaMapping;

/// SEV-SNP RMP/PSC minimum conversion granule.
pub(crate) const PAGE_SIZE_4K: u64 = 4096;

const BITS_PER_U64: usize = u64::BITS as usize;

struct TrackedRegion {
    base: u64,
    /// One bit per 4KiB page, bits past num_pages are just padding
    shared: Vec<u64>,
    /// Number of 4KiB tracked pages
    num_pages: usize,
}

impl TrackedRegion {
    fn new(base: u64, size: u64) -> Self {
        let num_pages = size.div_ceil(PAGE_SIZE_4K) as usize;
        Self {
            base,
            shared: vec![0; num_pages.div_ceil(BITS_PER_U64)],
            num_pages,
        }
    }

    fn end(&self) -> u64 {
        self.base + self.num_pages as u64 * PAGE_SIZE_4K
    }

    fn is_shared(&self, page: usize) -> bool {
        self.shared[page / BITS_PER_U64] & (1 << (page % BITS_PER_U64)) != 0
    }

    fn shared_gpas(&self) -> impl Iterator<Item = u64> + '_ {
        (0..self.num_pages)
            .filter(|&i| self.is_shared(i))
            .map(|i| self.base + i as u64 * PAGE_SIZE_4K)
    }
}

#[derive(Default)]
struct Inner {
    regions: Vec<TrackedRegion>,
    handler: Option<Arc<dyn ExternalDmaMapping>>,
}

/// Tracks which confidential guest pages are shared and keeps the device
/// IOMMU mapping exactly those pages.
#[derive(Default)]
pub(crate) struct SevSnpSharedPageTracker {
    inner: Mutex<Inner>,
}

impl SevSnpSharedPageTracker {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Register a confidential RAM region `[base, base + size)`.
    pub(crate) fn register_region(&self, base: u64, size: u64) {
        self.inner
            .lock()
            .unwrap()
            .regions
            .push(TrackedRegion::new(base, size));
    }

    /// Register a VFIO DMA handler, replaying the currently shared pages into it.
    /// A partial replay is rolled back, so a failed registration leaves nothing
    /// mapped in the IOMMU.
    pub(crate) fn add_dma_mapping_handler(
        &self,
        handler: Arc<dyn ExternalDmaMapping>,
    ) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        assert!(
            inner.handler.is_none(),
            "DMA mapping handler already registered"
        );

        let shared = inner.regions.iter().flat_map(TrackedRegion::shared_gpas);
        for (mapped, gpa) in shared.enumerate() {
            if let Err(e) = handler.map(gpa, gpa, PAGE_SIZE_4K) {
                // The handler stays unregistered, so no later conversion would
                // ever unmap what the replay already mapped.
                Self::undo_replay(handler.as_ref(), &inner.regions, mapped);
                return Err(anyhow::anyhow!("VFIO replay map failed gpa={gpa:#x}: {e}"));
            }
        }

        inner.handler = Some(handler);
        Ok(())
    }

    fn undo_replay(handler: &dyn ExternalDmaMapping, regions: &[TrackedRegion], count: usize) {
        let shared = regions.iter().flat_map(TrackedRegion::shared_gpas);
        for gpa in shared.take(count) {
            if let Err(e) = handler.unmap(gpa, PAGE_SIZE_4K) {
                error!("VFIO replay rollback failed gpa={gpa:#x}: {e}");
            }
        }
    }

    /// Drop the registered DMA handler.
    pub(crate) fn clear_dma_mapping_handler(&self) {
        self.inner.lock().unwrap().handler = None;
    }

    fn has_dma_handler(&self) -> bool {
        self.inner.lock().unwrap().handler.is_some()
    }

    /// Flip `[gpa, gpa + size)` shared/private in the tracker, driving the
    /// handler so the device IOMMU maps the shared pages only.
    fn set_shared(&self, gpa: u64, size: u64, shared: bool) -> io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        let Inner { regions, handler } = &mut *inner;
        let req_end = gpa.saturating_add(size);

        for region in regions.iter_mut() {
            let start = gpa.max(region.base);
            let end = req_end.min(region.end());
            if start >= end {
                continue;
            }
            let first_page = ((start - region.base) / PAGE_SIZE_4K) as usize;
            let end_page = (end - region.base).div_ceil(PAGE_SIZE_4K) as usize;

            if shared {
                Self::map_pages(handler.as_deref(), region, first_page, end_page)?;
            } else {
                Self::unmap_pages(handler.as_deref(), region, first_page, end_page)?;
            }
        }
        Ok(())
    }

    /// Map each newly shared page one at a time. We map one page per call,
    /// not one big mapping for the whole range. A  mapping can only be removed
    /// as a whole, never split, so the size we map here is the smallest unit we
    /// can later unmap. This lets `unmap_pages()` remove any single page.
    fn map_pages(
        handler: Option<&dyn ExternalDmaMapping>,
        region: &mut TrackedRegion,
        first_page: usize,
        end_page: usize,
    ) -> io::Result<()> {
        assert!(end_page <= region.num_pages);
        for i in first_page..end_page {
            if region.is_shared(i) {
                continue;
            }
            let gpa = region.base + i as u64 * PAGE_SIZE_4K;
            if let Some(handler) = handler {
                handler
                    .map(gpa, gpa, PAGE_SIZE_4K)
                    .map_err(|e| io::Error::other(format!("DMA map failed gpa={gpa:#x}: {e}")))?;
            }
            region.shared[i / BITS_PER_U64] |= 1 << (i % BITS_PER_U64);
        }
        Ok(())
    }

    /// Clear each shared page in `[first_page, end_page)`, coalescing contiguous runs
    /// into a single unmap.
    fn unmap_pages(
        handler: Option<&dyn ExternalDmaMapping>,
        region: &mut TrackedRegion,
        first_page: usize,
        end_page: usize,
    ) -> io::Result<()> {
        assert!(end_page <= region.num_pages);
        let mut i = first_page;
        while i < end_page {
            if !region.is_shared(i) {
                i += 1;
                continue;
            }
            let run = i;
            while i < end_page && region.is_shared(i) {
                i += 1;
            }
            let gpa = region.base + run as u64 * PAGE_SIZE_4K;
            let len = (i - run) as u64 * PAGE_SIZE_4K;
            if let Some(handler) = handler {
                handler.unmap(gpa, len).map_err(|e| {
                    io::Error::other(format!("DMA unmap failed gpa={gpa:#x} len={len:#x}: {e}"))
                })?;
            }
            for page in run..i {
                region.shared[page / BITS_PER_U64] &= !(1 << (page % BITS_PER_U64));
            }
        }
        Ok(())
    }
}

impl MemoryConversionHandler for SevSnpSharedPageTracker {
    fn handle_conversion(&self, gpa: u64, size: u64, to_shared: bool) -> anyhow::Result<()> {
        self.set_shared(gpa, size, to_shared)
            .map_err(|e| anyhow::anyhow!("confidential VFIO conversion failed: {e}"))
    }

    /// Only reclaim once a VFIO device is attached as `handle_conversion` would
    /// have unmapped the page, so freeing its stale mapping is safe.
    fn reclaims_shared_mapping(&self) -> bool {
        self.has_dma_handler()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Recorder {
        maps: Mutex<Vec<(u64, u64)>>,
        unmaps: Mutex<Vec<(u64, u64)>>,
        fail_map_gpa: Option<u64>,
    }

    impl ExternalDmaMapping for Recorder {
        fn map(&self, iova: u64, gpa: u64, size: u64) -> io::Result<()> {
            assert_eq!(iova, gpa, "tracker must identity-map (iova == gpa)");
            if self.fail_map_gpa == Some(gpa) {
                return Err(io::Error::other("injected map failure"));
            }
            self.maps.lock().unwrap().push((gpa, size));
            Ok(())
        }
        fn unmap(&self, iova: u64, size: u64) -> io::Result<()> {
            self.unmaps.lock().unwrap().push((iova, size));
            Ok(())
        }
    }

    fn page(n: u64) -> u64 {
        n * PAGE_SIZE_4K
    }

    fn tracker_with_region(base: u64, size: u64) -> (SevSnpSharedPageTracker, Arc<Recorder>) {
        let t = SevSnpSharedPageTracker::new();
        t.register_region(base, size);
        let rec = Arc::new(Recorder::default());
        t.add_dma_mapping_handler(Arc::clone(&rec) as Arc<dyn ExternalDmaMapping>)
            .unwrap();
        (t, rec)
    }

    #[test]
    fn shared_maps_each_page_individually() {
        let (t, rec) = tracker_with_region(page(0), 4 * PAGE_SIZE_4K);
        t.set_shared(page(0), 3 * PAGE_SIZE_4K, true).unwrap();
        assert_eq!(
            *rec.maps.lock().unwrap(),
            vec![
                (page(0), PAGE_SIZE_4K),
                (page(1), PAGE_SIZE_4K),
                (page(2), PAGE_SIZE_4K),
            ]
        );
    }

    #[test]
    fn shared_is_idempotent() {
        let (t, rec) = tracker_with_region(page(0), 4 * PAGE_SIZE_4K);
        t.set_shared(page(0), 2 * PAGE_SIZE_4K, true).unwrap();
        t.set_shared(page(0), 2 * PAGE_SIZE_4K, true).unwrap();
        assert_eq!(rec.maps.lock().unwrap().len(), 2);
    }

    #[test]
    fn private_coalesces_contiguous_runs() {
        let (t, rec) = tracker_with_region(page(0), 4 * PAGE_SIZE_4K);
        t.set_shared(page(0), 4 * PAGE_SIZE_4K, true).unwrap();
        rec.unmaps.lock().unwrap().clear();
        t.set_shared(page(0), 4 * PAGE_SIZE_4K, false).unwrap();
        assert_eq!(
            *rec.unmaps.lock().unwrap(),
            vec![(page(0), 4 * PAGE_SIZE_4K)]
        );
    }

    #[test]
    fn private_splits_runs_around_holes() {
        let (t, rec) = tracker_with_region(page(0), 4 * PAGE_SIZE_4K);
        t.set_shared(page(0), 2 * PAGE_SIZE_4K, true).unwrap();
        t.set_shared(page(3), PAGE_SIZE_4K, true).unwrap();
        rec.unmaps.lock().unwrap().clear();
        t.set_shared(page(0), 4 * PAGE_SIZE_4K, false).unwrap();
        assert_eq!(
            *rec.unmaps.lock().unwrap(),
            vec![(page(0), 2 * PAGE_SIZE_4K), (page(3), PAGE_SIZE_4K)]
        );
    }

    #[test]
    fn add_handler_replays_shared_set() {
        let (t, _first) = tracker_with_region(page(0), 4 * PAGE_SIZE_4K);
        t.set_shared(page(1), 2 * PAGE_SIZE_4K, true).unwrap();
        t.clear_dma_mapping_handler();
        let late = Arc::new(Recorder::default());
        t.add_dma_mapping_handler(Arc::clone(&late) as Arc<dyn ExternalDmaMapping>)
            .unwrap();
        assert_eq!(
            *late.maps.lock().unwrap(),
            vec![(page(1), PAGE_SIZE_4K), (page(2), PAGE_SIZE_4K)]
        );
    }

    #[test]
    fn replay_failure_rolls_back_partial_maps() {
        // Pages shared before any attach, as a guest converts them.
        let t = SevSnpSharedPageTracker::new();
        t.register_region(page(0), 2 * PAGE_SIZE_4K);
        t.register_region(page(8), 2 * PAGE_SIZE_4K);
        t.set_shared(page(0), 2 * PAGE_SIZE_4K, true).unwrap();
        t.set_shared(page(8), 2 * PAGE_SIZE_4K, true).unwrap();

        // The first page of the second region fails, so the rollback has to
        // reach back into the first one.
        let failed = Arc::new(Recorder {
            fail_map_gpa: Some(page(8)),
            ..Default::default()
        });
        assert!(
            t.add_dma_mapping_handler(Arc::clone(&failed) as Arc<dyn ExternalDmaMapping>)
                .is_err()
        );
        assert_eq!(
            *failed.unmaps.lock().unwrap(),
            vec![(page(0), PAGE_SIZE_4K), (page(1), PAGE_SIZE_4K)]
        );

        // The shared set is untouched, so a later attach replays all of it.
        let late = Arc::new(Recorder::default());
        t.add_dma_mapping_handler(Arc::clone(&late) as Arc<dyn ExternalDmaMapping>)
            .unwrap();
        assert_eq!(late.maps.lock().unwrap().len(), 4);
    }

    #[test]
    fn conversion_outside_any_region_is_ignored() {
        let (t, rec) = tracker_with_region(page(0), 2 * PAGE_SIZE_4K);
        t.set_shared(page(100), 4 * PAGE_SIZE_4K, true).unwrap();
        assert!(rec.maps.lock().unwrap().is_empty());
    }
}
