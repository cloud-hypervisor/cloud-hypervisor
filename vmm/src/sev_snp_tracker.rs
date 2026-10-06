// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0
//

use std::sync::{Arc, Mutex, Weak};
use std::{io, ptr};

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

    /// Contiguous runs `[start, end)` of shared pages in `[first_page, end_page)`.
    fn shared_runs(&self, first_page: usize, end_page: usize) -> Vec<(usize, usize)> {
        let mut runs = Vec::new();
        let mut i = first_page;
        while i < end_page {
            if !self.is_shared(i) {
                i += 1;
                continue;
            }
            let run = i;
            while i < end_page && self.is_shared(i) {
                i += 1;
            }
            runs.push((run, i));
        }
        runs
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
    /// Held weakly: the device manager owns the handlers, and a handler may
    /// own its device, which can in turn reference the VM owning the tracker.
    handlers: Vec<Weak<dyn ExternalDmaMapping>>,
    /// Set once a handler may still map a page the tracker considers
    /// private. Every later conversion fails, so that no page is ever
    /// discarded while a device may still map it.
    poisoned: bool,
}

/// Tracks which confidential guest pages are shared and keeps every
/// registered DMA handler mapping exactly those pages.
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

    /// Register a DMA handler, replaying the currently shared pages into it.
    /// A partial replay is rolled back, and the tracker poisoned if that
    /// fails too. The caller keeps the handler alive until it removes it.
    pub(crate) fn add_dma_mapping_handler(
        &self,
        handler: &Arc<dyn ExternalDmaMapping>,
    ) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.poisoned {
            return Err(anyhow::anyhow!("shared page tracker is poisoned"));
        }
        assert!(
            !inner.handlers.iter().any(|h| Self::is_handler(h, handler)),
            "DMA mapping handler already registered"
        );

        let shared: Vec<u64> = inner
            .regions
            .iter()
            .flat_map(TrackedRegion::shared_gpas)
            .collect();
        for (mapped, &gpa) in shared.iter().enumerate() {
            if let Err(e) = handler.map(gpa, gpa, PAGE_SIZE_4K) {
                // The handler stays unregistered, so no later conversion would
                // ever unmap what the replay already mapped.
                if !Self::undo_replay(handler.as_ref(), &shared[..mapped]) {
                    inner.poisoned = true;
                }
                return Err(anyhow::anyhow!("DMA replay map failed gpa={gpa:#x}: {e}"));
            }
        }

        inner.handlers.push(Arc::downgrade(handler));
        Ok(())
    }

    /// Returns false if a page may have been left mapped.
    fn undo_replay(handler: &dyn ExternalDmaMapping, mapped: &[u64]) -> bool {
        let mut undone = true;
        for &gpa in mapped {
            if let Err(e) = handler.unmap(gpa, PAGE_SIZE_4K) {
                error!("DMA replay rollback failed gpa={gpa:#x}: {e}");
                undone = false;
            }
        }
        undone
    }

    /// Unregister a DMA handler, unmapping the currently shared pages from it.
    /// If that fails the handler may keep stale mappings, so the tracker is
    /// poisoned.
    pub(crate) fn remove_dma_mapping_handler(&self, handler: &Arc<dyn ExternalDmaMapping>) {
        let mut inner = self.inner.lock().unwrap();
        let Some(index) = inner
            .handlers
            .iter()
            .position(|h| Self::is_handler(h, handler))
        else {
            return;
        };
        inner.handlers.remove(index);

        let mut failed = false;
        for region in &inner.regions {
            for (start, end) in region.shared_runs(0, region.num_pages) {
                let gpa = region.base + start as u64 * PAGE_SIZE_4K;
                let len = (end - start) as u64 * PAGE_SIZE_4K;
                if let Err(e) = handler.unmap(gpa, len) {
                    error!("DMA unmap on handler removal failed gpa={gpa:#x} len={len:#x}: {e}");
                    failed = true;
                }
            }
        }
        inner.poisoned |= failed;
    }

    fn is_handler(
        registered: &Weak<dyn ExternalDmaMapping>,
        handler: &Arc<dyn ExternalDmaMapping>,
    ) -> bool {
        ptr::addr_eq(registered.as_ptr(), Arc::as_ptr(handler))
    }

    fn has_dma_handler(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        !inner.poisoned && inner.handlers.iter().any(|h| h.strong_count() > 0)
    }

    /// Flip `[gpa, gpa + size)` shared/private in the tracker, driving the
    /// handlers so the devices map the shared pages only.
    fn set_shared(&self, gpa: u64, size: u64, shared: bool) -> io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.poisoned {
            return Err(io::Error::other("shared page tracker is poisoned"));
        }
        inner.handlers.retain(|h| h.strong_count() > 0);
        let handlers: Vec<_> = inner.handlers.iter().filter_map(Weak::upgrade).collect();
        let req_end = gpa.saturating_add(size);

        let Inner {
            regions, poisoned, ..
        } = &mut *inner;
        for region in regions.iter_mut() {
            let start = gpa.max(region.base);
            let end = req_end.min(region.end());
            if start >= end {
                continue;
            }
            let first_page = ((start - region.base) / PAGE_SIZE_4K) as usize;
            let end_page = (end - region.base).div_ceil(PAGE_SIZE_4K) as usize;

            let result = if shared {
                Self::map_pages(&handlers, region, first_page, end_page)
            } else {
                Self::unmap_pages(&handlers, region, first_page, end_page)
            };
            if let Err((e, consistent)) = result {
                *poisoned |= !consistent;
                return Err(e);
            }
        }
        Ok(())
    }

    /// Map each newly shared page one at a time. We map one page per call,
    /// not one big mapping for the whole range. A  mapping can only be removed
    /// as a whole, never split, so the size we map here is the smallest unit we
    /// can later unmap. This lets `unmap_pages()` remove any single page.
    ///
    /// A page is only marked shared once every handler mapped it. If one
    /// fails, the handlers that already mapped the page unmap it again. The
    /// error says whether that rollback left the handlers consistent with
    /// the tracker.
    fn map_pages(
        handlers: &[Arc<dyn ExternalDmaMapping>],
        region: &mut TrackedRegion,
        first_page: usize,
        end_page: usize,
    ) -> Result<(), (io::Error, bool)> {
        assert!(end_page <= region.num_pages);
        for i in first_page..end_page {
            if region.is_shared(i) {
                continue;
            }
            let gpa = region.base + i as u64 * PAGE_SIZE_4K;
            for (mapped, handler) in handlers.iter().enumerate() {
                if let Err(e) = handler.map(gpa, gpa, PAGE_SIZE_4K) {
                    let mut consistent = true;
                    for handler in &handlers[..mapped] {
                        if let Err(e) = handler.unmap(gpa, PAGE_SIZE_4K) {
                            error!("DMA map rollback failed gpa={gpa:#x}: {e}");
                            consistent = false;
                        }
                    }
                    let e = io::Error::other(format!("DMA map failed gpa={gpa:#x}: {e}"));
                    return Err((e, consistent));
                }
            }
            region.shared[i / BITS_PER_U64] |= 1 << (i % BITS_PER_U64);
        }
        Ok(())
    }

    /// Clear each shared page in `[first_page, end_page)`, coalescing contiguous
    /// runs into a single unmap per handler. A failed unmap leaves the handlers
    /// inconsistent with the tracker.
    fn unmap_pages(
        handlers: &[Arc<dyn ExternalDmaMapping>],
        region: &mut TrackedRegion,
        first_page: usize,
        end_page: usize,
    ) -> Result<(), (io::Error, bool)> {
        assert!(end_page <= region.num_pages);
        for (start, end) in region.shared_runs(first_page, end_page) {
            let gpa = region.base + start as u64 * PAGE_SIZE_4K;
            let len = (end - start) as u64 * PAGE_SIZE_4K;
            for handler in handlers {
                handler.unmap(gpa, len).map_err(|e| {
                    let e = io::Error::other(format!(
                        "DMA unmap failed gpa={gpa:#x} len={len:#x}: {e}"
                    ));
                    (e, false)
                })?;
            }
            for page in start..end {
                region.shared[page / BITS_PER_U64] &= !(1 << (page % BITS_PER_U64));
            }
        }
        Ok(())
    }
}

/// Wraps a DMA handler whose unmaps must match a single earlier mapping,
/// such as a vfio-user client, splitting the tracker's coalesced unmaps
/// into the 4KiB mappings it made.
pub(crate) struct PerPageUnmap(pub(crate) Arc<dyn ExternalDmaMapping>);

impl ExternalDmaMapping for PerPageUnmap {
    fn map(&self, iova: u64, gpa: u64, size: u64) -> io::Result<()> {
        self.0.map(iova, gpa, size)
    }

    fn unmap(&self, iova: u64, size: u64) -> io::Result<()> {
        for offset in (0..size).step_by(PAGE_SIZE_4K as usize) {
            self.0.unmap(iova + offset, PAGE_SIZE_4K)?;
        }
        Ok(())
    }
}

impl MemoryConversionHandler for SevSnpSharedPageTracker {
    fn handle_conversion(&self, gpa: u64, size: u64, to_shared: bool) -> anyhow::Result<()> {
        self.set_shared(gpa, size, to_shared)
            .map_err(|e| anyhow::anyhow!("confidential DMA conversion failed: {e}"))
    }

    /// Only reclaim once a DMA handler is registered as `handle_conversion`
    /// would have unmapped the page, so freeing its stale mapping is safe.
    fn reclaims_shared_mapping(&self) -> bool {
        self.has_dma_handler()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    /// Records calls, and checks them against the mappings it holds the way
    /// an IOMMU would: no overlapping map, and an unmap must cover whole
    /// existing mappings.
    #[derive(Default)]
    struct Recorder {
        maps: Mutex<Vec<(u64, u64)>>,
        unmaps: Mutex<Vec<(u64, u64)>>,
        live: Mutex<BTreeMap<u64, u64>>,
        fail_map_gpa: Option<u64>,
        fail_unmap: AtomicBool,
    }

    impl Recorder {
        fn failing_map(gpa: u64) -> Self {
            Self {
                fail_map_gpa: Some(gpa),
                ..Default::default()
            }
        }

        fn live(&self) -> Vec<u64> {
            self.live.lock().unwrap().keys().copied().collect()
        }
    }

    impl ExternalDmaMapping for Recorder {
        fn map(&self, iova: u64, gpa: u64, size: u64) -> io::Result<()> {
            assert_eq!(iova, gpa, "tracker must identity-map (iova == gpa)");
            if self.fail_map_gpa == Some(gpa) {
                return Err(io::Error::other("injected map failure"));
            }
            let mut live = self.live.lock().unwrap();
            assert!(
                live.range(..gpa + size)
                    .next_back()
                    .is_none_or(|(&start, &len)| start + len <= gpa),
                "overlapping map gpa={gpa:#x}"
            );
            live.insert(gpa, size);
            self.maps.lock().unwrap().push((gpa, size));
            Ok(())
        }

        fn unmap(&self, iova: u64, size: u64) -> io::Result<()> {
            if self.fail_unmap.load(Ordering::Relaxed) {
                return Err(io::Error::other("injected unmap failure"));
            }
            let mut live = self.live.lock().unwrap();
            let covered: Vec<_> = live
                .range(iova..iova + size)
                .map(|(&s, &l)| (s, l))
                .collect();
            assert!(!covered.is_empty(), "unmap of nothing iova={iova:#x}");
            for (start, len) in covered {
                assert!(start + len <= iova + size, "unmap splits a mapping");
                live.remove(&start);
            }
            self.unmaps.lock().unwrap().push((iova, size));
            Ok(())
        }
    }

    fn page(n: u64) -> u64 {
        n * PAGE_SIZE_4K
    }

    fn add_recorder(t: &SevSnpSharedPageTracker, rec: Recorder) -> Arc<Recorder> {
        let rec = Arc::new(rec);
        t.add_dma_mapping_handler(&(Arc::clone(&rec) as Arc<dyn ExternalDmaMapping>))
            .unwrap();
        rec
    }

    fn tracker_with_region(base: u64, size: u64) -> (SevSnpSharedPageTracker, Arc<Recorder>) {
        let t = SevSnpSharedPageTracker::new();
        t.register_region(base, size);
        let rec = add_recorder(&t, Recorder::default());
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
        t.set_shared(page(0), 4 * PAGE_SIZE_4K, false).unwrap();
        assert_eq!(
            *rec.unmaps.lock().unwrap(),
            vec![(page(0), 4 * PAGE_SIZE_4K)]
        );
        assert!(rec.live().is_empty());
    }

    #[test]
    fn private_splits_runs_around_holes() {
        let (t, rec) = tracker_with_region(page(0), 4 * PAGE_SIZE_4K);
        t.set_shared(page(0), 2 * PAGE_SIZE_4K, true).unwrap();
        t.set_shared(page(3), PAGE_SIZE_4K, true).unwrap();
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
        let late = add_recorder(&t, Recorder::default());
        assert_eq!(late.live(), vec![page(1), page(2)]);
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
        let failed: Arc<dyn ExternalDmaMapping> = Arc::new(Recorder::failing_map(page(8)));
        assert!(t.add_dma_mapping_handler(&failed).is_err());

        // The shared set is untouched, so a later attach replays all of it.
        let late = add_recorder(&t, Recorder::default());
        assert_eq!(late.live(), vec![page(0), page(1), page(8), page(9)]);
    }

    #[test]
    fn replay_rollback_failure_poisons() {
        let t = SevSnpSharedPageTracker::new();
        t.register_region(page(0), 4 * PAGE_SIZE_4K);
        t.set_shared(page(0), 2 * PAGE_SIZE_4K, true).unwrap();

        let failed = Recorder::failing_map(page(1));
        failed.fail_unmap.store(true, Ordering::Relaxed);
        let failed: Arc<dyn ExternalDmaMapping> = Arc::new(failed);
        assert!(t.add_dma_mapping_handler(&failed).is_err());
        assert!(t.set_shared(page(0), PAGE_SIZE_4K, false).is_err());
    }

    #[test]
    fn conversion_outside_any_region_is_ignored() {
        let (t, rec) = tracker_with_region(page(0), 2 * PAGE_SIZE_4K);
        t.set_shared(page(100), 4 * PAGE_SIZE_4K, true).unwrap();
        assert!(rec.maps.lock().unwrap().is_empty());
    }

    #[test]
    fn every_handler_maps_and_unmaps() {
        let (t, first) = tracker_with_region(page(0), 4 * PAGE_SIZE_4K);
        let second = add_recorder(&t, Recorder::default());
        t.set_shared(page(0), 2 * PAGE_SIZE_4K, true).unwrap();
        for rec in [&first, &second] {
            assert_eq!(rec.live(), vec![page(0), page(1)]);
        }
        t.set_shared(page(0), 2 * PAGE_SIZE_4K, false).unwrap();
        for rec in [&first, &second] {
            assert!(rec.live().is_empty());
        }
    }

    #[test]
    fn map_failure_unmaps_page_from_earlier_handlers() {
        let (t, first) = tracker_with_region(page(0), 4 * PAGE_SIZE_4K);
        let failing = add_recorder(&t, Recorder::failing_map(page(1)));
        assert!(t.set_shared(page(0), 2 * PAGE_SIZE_4K, true).is_err());

        // Page 0 is shared in both, page 1 was rolled back from the first.
        assert_eq!(first.live(), vec![page(0)]);
        assert_eq!(failing.live(), vec![page(0)]);

        // The tracker is still usable: page 1 stayed private.
        t.set_shared(page(0), 2 * PAGE_SIZE_4K, false).unwrap();
        assert!(first.live().is_empty());
        assert!(failing.live().is_empty());
    }

    #[test]
    fn map_rollback_failure_poisons() {
        let (t, first) = tracker_with_region(page(0), 4 * PAGE_SIZE_4K);
        let _failing = add_recorder(&t, Recorder::failing_map(page(0)));
        first.fail_unmap.store(true, Ordering::Relaxed);
        assert!(t.set_shared(page(0), PAGE_SIZE_4K, true).is_err());

        // The first handler kept page 0 although the tracker thinks it is
        // private, so nothing converts anymore.
        assert_eq!(first.live(), vec![page(0)]);
        assert!(t.set_shared(page(0), PAGE_SIZE_4K, false).is_err());
        assert!(!t.has_dma_handler());
    }

    #[test]
    fn unmap_failure_poisons() {
        let (t, failing) = tracker_with_region(page(0), 4 * PAGE_SIZE_4K);
        t.set_shared(page(0), 2 * PAGE_SIZE_4K, true).unwrap();
        failing.fail_unmap.store(true, Ordering::Relaxed);
        assert!(t.set_shared(page(0), 2 * PAGE_SIZE_4K, false).is_err());

        // A retried conversion must not succeed, as the page is still mapped.
        failing.fail_unmap.store(false, Ordering::Relaxed);
        assert!(t.set_shared(page(0), 2 * PAGE_SIZE_4K, false).is_err());
        assert!(t.set_shared(page(2), PAGE_SIZE_4K, true).is_err());
    }

    #[test]
    fn remove_handler_unmaps_shared_set_and_stops_tracking() {
        let (t, kept) = tracker_with_region(page(0), 4 * PAGE_SIZE_4K);
        let removed = add_recorder(&t, Recorder::default());
        t.set_shared(page(0), 2 * PAGE_SIZE_4K, true).unwrap();
        t.set_shared(page(3), PAGE_SIZE_4K, true).unwrap();

        t.remove_dma_mapping_handler(&(Arc::clone(&removed) as Arc<dyn ExternalDmaMapping>));
        assert!(removed.live().is_empty());
        assert_eq!(kept.live(), vec![page(0), page(1), page(3)]);

        t.set_shared(page(2), PAGE_SIZE_4K, true).unwrap();
        assert!(removed.live().is_empty());
        assert_eq!(kept.live(), vec![page(0), page(1), page(2), page(3)]);
    }

    #[test]
    fn remove_failure_poisons() {
        let (t, rec) = tracker_with_region(page(0), 4 * PAGE_SIZE_4K);
        t.set_shared(page(0), PAGE_SIZE_4K, true).unwrap();
        rec.fail_unmap.store(true, Ordering::Relaxed);
        t.remove_dma_mapping_handler(&(Arc::clone(&rec) as Arc<dyn ExternalDmaMapping>));
        assert!(t.set_shared(page(1), PAGE_SIZE_4K, true).is_err());
    }

    #[test]
    fn per_page_unmap_splits_coalesced_unmaps() {
        let t = SevSnpSharedPageTracker::new();
        t.register_region(page(0), 4 * PAGE_SIZE_4K);
        let rec = Arc::new(Recorder::default());
        let handler: Arc<dyn ExternalDmaMapping> =
            Arc::new(PerPageUnmap(Arc::clone(&rec) as Arc<dyn ExternalDmaMapping>));
        t.add_dma_mapping_handler(&handler).unwrap();

        t.set_shared(page(0), 3 * PAGE_SIZE_4K, true).unwrap();
        t.set_shared(page(0), 2 * PAGE_SIZE_4K, false).unwrap();
        t.remove_dma_mapping_handler(&handler);
        assert_eq!(
            *rec.unmaps.lock().unwrap(),
            vec![
                (page(0), PAGE_SIZE_4K),
                (page(1), PAGE_SIZE_4K),
                (page(2), PAGE_SIZE_4K),
            ]
        );
    }

    #[test]
    fn dropped_handler_is_skipped() {
        let (t, kept) = tracker_with_region(page(0), 4 * PAGE_SIZE_4K);
        let dropped = add_recorder(&t, Recorder::default());
        let weak = Arc::downgrade(&dropped);
        drop(dropped);
        assert!(
            weak.upgrade().is_none(),
            "the tracker must not own handlers"
        );

        t.set_shared(page(0), PAGE_SIZE_4K, true).unwrap();
        assert_eq!(kept.live(), vec![page(0)]);
    }
}
