// Copyright © 2026 Crusoe. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, Barrier};
use std::{cmp, io, thread};

use log::warn;

use crate::memory_manager::{Error, is_aligned};

const MAX_PREFAULT_THREAD_COUNT: usize = 16;

// A guest memory region to prefault
pub(crate) struct PrefaultRegion {
    pub(crate) addr: usize,
    pub(crate) size: usize,
    pub(crate) page_size: usize,
}

pub(crate) fn prefault_regions(regions: &[PrefaultRegion]) -> Result<(), Error> {
    for region in regions {
        if !is_aligned(region.size, region.page_size) {
            warn!(
                "Prefaulting memory size {} misaligned with page size {}",
                region.size, region.page_size
            );
        }

        let num_pages = region.size / region.page_size;
        let num_threads = get_prefault_num_threads(region.page_size, num_pages);
        let pages_per_thread = num_pages / num_threads;
        let remainder = num_pages % num_threads;

        let barrier = Arc::new(Barrier::new(num_threads));
        thread::scope(|s| -> Result<(), Error> {
            let mut handles = Vec::new();
            for i in 0..num_threads {
                let barrier = Arc::clone(&barrier);
                let handle = s.spawn(move || {
                    // Wait until all threads have been spawned to avoid contention
                    // over mmap_sem between thread stack allocation and page faulting.
                    barrier.wait();
                    let pages = pages_per_thread + if i < remainder { 1 } else { 0 };
                    let offset =
                        region.page_size * ((i * pages_per_thread) + cmp::min(i, remainder));
                    // SAFETY: the caller keeps the region mappings alive for the
                    // duration of this call
                    let ret = unsafe {
                        libc::madvise(
                            (region.addr + offset) as *mut libc::c_void,
                            pages * region.page_size,
                            libc::MADV_POPULATE_WRITE,
                        )
                    };
                    if ret != 0 {
                        let e = io::Error::last_os_error();
                        return Err(e);
                    }
                    Ok(())
                });
                handles.push(handle);
            }

            for handle in handles {
                handle
                    .join()
                    .map_err(|e| {
                        Error::PrefaultMemory(io::Error::other(format!(
                            "Prefault thread panicked: {e:?}"
                        )))
                    })?
                    .map_err(Error::PrefaultMemory)?;
            }

            Ok(())
        })?;
    }

    Ok(())
}

fn get_prefault_num_threads(page_size: usize, num_pages: usize) -> usize {
    // Do not create more threads than processors available.
    let mut n = thread::available_parallelism()
        .map_or(1, |val| val.get())
        .min(MAX_PREFAULT_THREAD_COUNT);

    // Do not create more threads than pages being allocated.
    n = cmp::min(n, num_pages);

    // Do not create threads to allocate less than 64 MiB of memory.
    n = cmp::min(n, cmp::max(1, page_size * num_pages / (64 * (1 << 26))));

    n
}
