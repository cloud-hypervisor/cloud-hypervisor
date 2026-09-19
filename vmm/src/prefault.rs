// Copyright © 2026 Crusoe. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::read_to_string;
use std::mem::zeroed;
use std::sync::Barrier;
use std::{cmp, io, thread};

use log::{info, warn};

use crate::memory_manager::{Error, is_aligned};

// A guest memory region to prefault
pub(crate) struct PrefaultRegion {
    pub(crate) addr: usize,
    pub(crate) size: usize,
    pub(crate) page_size: usize,
    pub(crate) host_numa_node: Option<u32>,
}

// One worker's slice of a prefault region and the cpu set it pins to
struct CpuAffinityRange {
    addr: usize,
    len: usize,
    cpu_set: Option<libc::cpu_set_t>,
}

fn cpu_affinity_ranges(regions: &[PrefaultRegion]) -> Vec<CpuAffinityRange> {
    let mut ranges = Vec::new();
    for region in regions {
        if !is_aligned(region.size, region.page_size) {
            warn!(
                "Prefaulting memory size {} misaligned with page size {}",
                region.size, region.page_size
            );
        }

        let num_pages = region.size / region.page_size;
        if num_pages == 0 {
            continue;
        }

        let mut num_threads = get_prefault_num_threads(region.page_size, num_pages);
        let node_cpu_set = region.host_numa_node.and_then(node_cpu_set_within_current);
        if let Some((_, node_cpus)) = node_cpu_set {
            num_threads = cmp::min(num_threads, node_cpus);
        }

        let pages_per_thread = num_pages / num_threads;
        let remainder = num_pages % num_threads;
        for i in 0..num_threads {
            let pages = pages_per_thread + if i < remainder { 1 } else { 0 };
            let offset = region.page_size * ((i * pages_per_thread) + cmp::min(i, remainder));
            ranges.push(CpuAffinityRange {
                addr: region.addr + offset,
                len: pages * region.page_size,
                cpu_set: node_cpu_set.map(|(cpu_set, _)| cpu_set),
            });
        }
    }
    ranges
}

pub(crate) fn prefault_regions(regions: &[PrefaultRegion]) -> Result<(), Error> {
    if regions.is_empty() {
        return Ok(());
    }

    let ranges = cpu_affinity_ranges(regions);

    // Spans every region's workers, a pool still spawning would
    // otherwise stall the pools already populating
    let barrier = Barrier::new(ranges.len());

    thread::scope(|s| -> Result<(), Error> {
        let mut handles = Vec::new();
        for range in &ranges {
            let barrier = &barrier;
            let handle = s.spawn(move || {
                if let Some(cpu_set) = range.cpu_set {
                    // SAFETY: cpu_set is an initialized cpu_set_t of the size passed,
                    // and pid 0 means sched_setaffinity applies to the calling thread.
                    unsafe {
                        libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &cpu_set);
                    }
                }
                // Wait until all threads have been spawned to avoid contention
                // over mmap_sem between thread stack allocation and page faulting.
                barrier.wait();
                // SAFETY: the caller keeps the region mappings alive for the
                // duration of this call
                let ret = unsafe {
                    libc::madvise(
                        range.addr as *mut libc::c_void,
                        range.len,
                        libc::MADV_POPULATE_WRITE,
                    )
                };
                if ret != 0 {
                    return Err(io::Error::last_os_error());
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
    info!("Prefaulted {} memory regions", regions.len());

    Ok(())
}

// Intersect the node's cpu set with the calling thread's current
// affinity, so pinning a prefault worker never widens a task set the
// operator already restricted through a cpuset or sched_setaffinity.
// Falls back to no pinning if the intersection is empty or the affinity
// cannot be read.
fn node_cpu_set_within_current(node: u32) -> Option<(libc::cpu_set_t, usize)> {
    let (node_set, _) = numa_node_cpu_set(node)?;

    // SAFETY: an all zero cpu_set_t is a valid empty set
    let mut current = unsafe { zeroed::<libc::cpu_set_t>() };
    // SAFETY: current is an initialized cpu_set_t of the size passed,
    // and pid 0 means sched_getaffinity reads the calling thread
    if unsafe { libc::sched_getaffinity(0, size_of::<libc::cpu_set_t>(), &mut current) } != 0 {
        return None;
    }

    // SAFETY: an all zero cpu_set_t is a valid empty set
    let mut intersection = unsafe { zeroed::<libc::cpu_set_t>() };
    for cpu in 0..libc::CPU_SETSIZE as usize {
        // SAFETY: cpu is below CPU_SETSIZE, node_set and current are initialized
        if unsafe { libc::CPU_ISSET(cpu, &node_set) && libc::CPU_ISSET(cpu, &current) } {
            // SAFETY: cpu is below CPU_SETSIZE
            unsafe { libc::CPU_SET(cpu, &mut intersection) };
        }
    }

    // SAFETY: intersection is an initialized cpu_set_t
    let count = unsafe { libc::CPU_COUNT(&intersection) } as usize;
    (count > 0).then_some((intersection, count))
}

fn numa_node_cpu_set(node: u32) -> Option<(libc::cpu_set_t, usize)> {
    let cpulist = read_to_string(format!("/sys/devices/system/node/node{node}/cpulist")).ok()?;

    // SAFETY: an all zero cpu_set_t is a valid empty set
    let mut cpu_set = unsafe { zeroed::<libc::cpu_set_t>() };
    for part in cpulist.trim().split(',') {
        let mut bounds = part.splitn(2, '-');
        let start: usize = bounds.next()?.parse().ok()?;
        let end: usize = match bounds.next() {
            Some(e) => e.parse().ok()?,
            None => start,
        };
        for cpu in start..=end.min(libc::CPU_SETSIZE as usize - 1) {
            // SAFETY: cpu is below CPU_SETSIZE
            unsafe { libc::CPU_SET(cpu, &mut cpu_set) };
        }
    }

    // SAFETY: cpu_set is an initialized cpu_set_t
    let count = unsafe { libc::CPU_COUNT(&cpu_set) } as usize;
    (count > 0).then_some((cpu_set, count))
}

fn get_prefault_num_threads(page_size: usize, num_pages: usize) -> usize {
    // Do not create more threads than processors available.
    let mut n = thread::available_parallelism().map_or(1, |val| val.get());

    // Do not create more threads than pages being allocated.
    n = cmp::min(n, num_pages);

    // Do not create threads to allocate less than 4 GiB of memory.
    n = cmp::min(n, cmp::max(1, page_size * num_pages / (4 * (1 << 30))));

    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_numa_node_cpu_set() {
        // Node 0 exists with at least one CPU on any test host
        let (cpu_set, count) = numa_node_cpu_set(0).unwrap();
        assert!(count > 0);
        let set_bits = (0..libc::CPU_SETSIZE as usize)
            .filter(|&cpu| {
                // SAFETY: cpu is below CPU_SETSIZE
                unsafe { libc::CPU_ISSET(cpu, &cpu_set) }
            })
            .count();
        assert_eq!(count, set_bits);
    }

    #[test]
    fn test_numa_node_cpu_set_missing_node() {
        assert!(numa_node_cpu_set(u32::MAX).is_none());
    }
}
