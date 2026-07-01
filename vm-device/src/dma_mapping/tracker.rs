// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0

//! Per-page bitmap of which pages are currently mapped into the device IOMMU.

use std::io;
use std::sync::{Arc, Mutex};

use super::ExternalDmaMapping;

struct TrackedRegion {
    base: u64,
    granularity: u64,
    /// `true` == mapped into every handler.
    populated: Vec<bool>,
}

impl TrackedRegion {
    fn new(base: u64, size: u64, granularity: u64) -> Self {
        Self {
            base,
            granularity,
            populated: vec![false; size.div_ceil(granularity) as usize],
        }
    }

    fn end(&self) -> u64 {
        self.base + self.populated.len() as u64 * self.granularity
    }
}

#[derive(Default)]
struct TrackerInner {
    regions: Vec<TrackedRegion>,
    handlers: Vec<Arc<dyn ExternalDmaMapping>>,
}

#[derive(Default)]
pub struct DmaMappingTracker {
    inner: Mutex<TrackerInner>,
}

impl DmaMappingTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a region `[base, base + size)` tracked at `granularity`.
    /// Initially all unpopulated.
    pub fn register_region(&self, base: u64, size: u64, granularity: u64) {
        self.inner
            .lock()
            .unwrap()
            .regions
            .push(TrackedRegion::new(base, size, granularity));
    }

    pub fn register_handler(&self, handler: Arc<dyn ExternalDmaMapping>) -> io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        // Before registering a new handler replay the currently-populated set into it.
        for region in inner.regions.iter() {
            for (i, &populated) in region.populated.iter().enumerate() {
                if populated {
                    let gpa = region.base + i as u64 * region.granularity; // iova == gpa
                    handler.map(gpa, gpa, region.granularity).map_err(|e| {
                        io::Error::other(format!("DMA replay map failed gpa={gpa:#x}: {e}"))
                    })?;
                }
            }
        }
        inner.handlers.push(handler);
        Ok(())
    }

    /// Number of registered DMA handlers.
    pub fn handler_count(&self) -> usize {
        self.inner.lock().unwrap().handlers.len()
    }

    /// Drop all registered DMA handlers.
    pub fn clear_handlers(&self) {
        self.inner.lock().unwrap().handlers.clear();
    }

    /// Flip `[gpa, gpa + size)` to populated/unpopulated, driving the registered
    /// DMA handlers so each device IOMMU maps exactly the currently-populated
    /// pages.
    pub fn set_populated(&self, gpa: u64, size: u64, populated: bool) -> io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        let TrackerInner { regions, handlers } = &mut *inner;
        let req_end = gpa.saturating_add(size);

        for region in regions.iter_mut() {
            let start = gpa.max(region.base);
            let end = req_end.min(region.end());
            if start >= end {
                continue; // conversion does not touch this region
            }
            let g = region.granularity;
            let first = ((start - region.base) / g) as usize;
            let last = ((end - region.base).div_ceil(g) as usize).min(region.populated.len());

            if populated {
                Self::map_pages(handlers, region, first, last)?;
            } else {
                Self::unmap_pages(handlers, region, first, last)?;
            }
        }
        Ok(())
    }

    /// Map each newly-populated page in `[first, last)`, one page at a
    /// time. Pages that are already populated are skipped.
    ///
    /// We map one page per call, not one big mapping for the whole range. A
    /// mapping can only be removed as a whole, never split, so the size we map
    /// here is the smallest unit we can later unmap. This lets `unmap_pages()`
    /// remove any single page.
    ///
    /// See linux/drivers/iommu/iommufd/io_pagetable.c (`iopt_unmap_iova_range`).
    fn map_pages(
        handlers: &[Arc<dyn ExternalDmaMapping>],
        region: &mut TrackedRegion,
        first: usize,
        last: usize,
    ) -> io::Result<()> {
        let g = region.granularity;
        for i in first..last {
            if region.populated[i] {
                continue; // already populated -> skip (no redundant ioctl)
            }
            region.populated[i] = true;
            let gpa = region.base + i as u64 * g;
            for handler in handlers.iter() {
                // iova == gpa (identity-mapped device IOMMU).
                handler
                    .map(gpa, gpa, g)
                    .map_err(|e| io::Error::other(format!("DMA map failed gpa={gpa:#x}: {e}")))?;
            }
        }
        Ok(())
    }

    /// Mark the pages in region range `[first, last)` as unpopulated and unmap
    /// them from all handlers, coalescing contiguous runs into a single unmap.
    fn unmap_pages(
        handlers: &[Arc<dyn ExternalDmaMapping>],
        region: &mut TrackedRegion,
        first: usize,
        last: usize,
    ) -> io::Result<()> {
        let g = region.granularity;
        let mut i = first;
        while i < last {
            if !region.populated[i] {
                i += 1;
                continue; // skip, already unpopulated
            }
            // Extend a maximal run of contiguous populated pages, clearing as we go.
            let run = i;
            while i < last && region.populated[i] {
                region.populated[i] = false;
                i += 1;
            }
            let gpa = region.base + run as u64 * g;
            let len = (i - run) as u64 * g;
            for handler in handlers.iter() {
                handler.unmap(gpa, len).map_err(|e| {
                    io::Error::other(format!("DMA unmap failed gpa={gpa:#x} len={len:#x}: {e}"))
                })?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// Records the map/unmap calls a handler receives, for assertions.
    #[derive(Default)]
    struct Recorder {
        maps: Mutex<Vec<(u64, u64)>>,
        unmaps: Mutex<Vec<(u64, u64)>>,
    }

    impl ExternalDmaMapping for Recorder {
        fn map(&self, iova: u64, gpa: u64, size: u64) -> io::Result<()> {
            assert_eq!(iova, gpa, "tracker must identity-map (iova == gpa)");
            self.maps.lock().unwrap().push((gpa, size));
            Ok(())
        }
        fn unmap(&self, iova: u64, size: u64) -> io::Result<()> {
            self.unmaps.lock().unwrap().push((iova, size));
            Ok(())
        }
    }

    const PAGE_SIZE_4KB: u64 = 4096;

    /// Base GPA of page `n` (regions in these tests are based at page 0).
    fn page_gpa(n: u64) -> u64 {
        n * PAGE_SIZE_4KB
    }

    fn tracker_with_region(base: u64, size: u64) -> (DmaMappingTracker, Arc<Recorder>) {
        let t = DmaMappingTracker::new();
        t.register_region(base, size, PAGE_SIZE_4KB);
        let rec = Arc::new(Recorder::default());
        t.register_handler(rec.clone()).unwrap();
        (t, rec)
    }

    #[test]
    fn populate_maps_each_page_individually() {
        let (t, rec) = tracker_with_region(page_gpa(0), 4 * PAGE_SIZE_4KB);
        t.set_populated(page_gpa(0), 3 * PAGE_SIZE_4KB, true)
            .unwrap();
        // One map per page, identity-mapped, page-sized.
        assert_eq!(
            *rec.maps.lock().unwrap(),
            vec![
                (page_gpa(0), PAGE_SIZE_4KB),
                (page_gpa(1), PAGE_SIZE_4KB),
                (page_gpa(2), PAGE_SIZE_4KB),
            ]
        );
    }

    #[test]
    fn populate_is_idempotent() {
        let (t, rec) = tracker_with_region(page_gpa(0), 4 * PAGE_SIZE_4KB);
        t.set_populated(page_gpa(0), 2 * PAGE_SIZE_4KB, true)
            .unwrap();
        t.set_populated(page_gpa(0), 2 * PAGE_SIZE_4KB, true)
            .unwrap();
        // Second call maps nothing (already populated).
        assert_eq!(rec.maps.lock().unwrap().len(), 2);
    }

    #[test]
    fn depopulate_coalesces_contiguous_runs() {
        let (t, rec) = tracker_with_region(page_gpa(0), 4 * PAGE_SIZE_4KB);
        t.set_populated(page_gpa(0), 4 * PAGE_SIZE_4KB, true)
            .unwrap();
        rec.unmaps.lock().unwrap().clear();
        t.set_populated(page_gpa(0), 4 * PAGE_SIZE_4KB, false)
            .unwrap();
        // The four contiguous pages unmap as one run.
        assert_eq!(
            *rec.unmaps.lock().unwrap(),
            vec![(page_gpa(0), 4 * PAGE_SIZE_4KB)]
        );
    }

    #[test]
    fn depopulate_splits_runs_around_holes() {
        let (t, rec) = tracker_with_region(page_gpa(0), 4 * PAGE_SIZE_4KB);
        // Populate pages 0, 1 and 3 (leave page 2 a hole).
        t.set_populated(page_gpa(0), 2 * PAGE_SIZE_4KB, true)
            .unwrap();
        t.set_populated(page_gpa(3), PAGE_SIZE_4KB, true).unwrap();
        rec.unmaps.lock().unwrap().clear();
        t.set_populated(page_gpa(0), 4 * PAGE_SIZE_4KB, false)
            .unwrap();
        // Two runs: pages 0-1 and page 3; the hole at page 2 is skipped.
        assert_eq!(
            *rec.unmaps.lock().unwrap(),
            vec![
                (page_gpa(0), 2 * PAGE_SIZE_4KB),
                (page_gpa(3), PAGE_SIZE_4KB)
            ]
        );
    }

    #[test]
    fn register_handler_replays_populated_set() {
        let (t, _first) = tracker_with_region(page_gpa(0), 4 * PAGE_SIZE_4KB);
        t.set_populated(page_gpa(1), 2 * PAGE_SIZE_4KB, true)
            .unwrap();
        // A handler attached later sees exactly the currently-populated pages.
        let late = Arc::new(Recorder::default());
        t.register_handler(late.clone()).unwrap();
        assert_eq!(
            *late.maps.lock().unwrap(),
            vec![(page_gpa(1), PAGE_SIZE_4KB), (page_gpa(2), PAGE_SIZE_4KB),]
        );
    }

    #[test]
    fn conversion_outside_any_region_is_ignored() {
        let (t, rec) = tracker_with_region(page_gpa(0), 2 * PAGE_SIZE_4KB);
        t.set_populated(page_gpa(100), 4 * PAGE_SIZE_4KB, true)
            .unwrap();
        assert!(rec.maps.lock().unwrap().is_empty());
    }
}
