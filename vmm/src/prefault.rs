// Copyright © 2026 Crusoe. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::read_to_string;
use std::mem::zeroed;
use std::sync::OnceLock;
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

// Minimum bytes of work per prefault thread, so a small region does not
// spawn threads it cannot keep busy.
const MIN_BYTES_PER_THREAD: usize = 4 * (1 << 30);

// A region's resolved prefault plan, filled in across the passes below.
struct RegionPlan {
    addr: usize,
    page_size: usize,
    num_pages: usize,
    // Most threads this region can use on its own, from its size.
    max_threads: usize,
    // The node this region pins to, or None when it runs unpinned. Regions
    // that share a node share its cpu budget, so this is also the pool key.
    node: Option<u32>,
    // Cores the pool may use, this region's node when pinned or the whole
    // machine when unpinned.
    pool_cores: usize,
    cpu_set: Option<libc::cpu_set_t>,
    threads: usize,
}

fn cpu_affinity_ranges(regions: &[PrefaultRegion]) -> Vec<CpuAffinityRange> {
    let machine_cores = thread::available_parallelism().map_or(1, |val| val.get());

    // Pass 1: resolve each region and the pool it draws threads from.
    let mut plans = Vec::with_capacity(regions.len());
    for region in regions {
        if !is_aligned(region.size, region.page_size) {
            warn!(
                "Prefaulting memory size {} misaligned with page size {}",
                region.size, region.page_size
            );
        }

        let num_pages = region.size / region.page_size;
        let max_threads = cmp::min(num_pages, cmp::max(1, region.size / MIN_BYTES_PER_THREAD));

        let (node, pool_cores, cpu_set) =
            match region.host_numa_node.and_then(node_cpu_set_within_current) {
                Some((cpu_set, node_cores)) => (region.host_numa_node, node_cores, Some(cpu_set)),
                None => (None, machine_cores, None),
            };

        plans.push(RegionPlan {
            addr: region.addr,
            page_size: region.page_size,
            num_pages,
            max_threads,
            node,
            pool_cores,
            cpu_set,
            threads: 0,
        });
    }

    // Pass 2: hand each region a share of its pool's cores.
    assign_threads(&mut plans, machine_cores);

    // Pass 3: split each region into one slice per assigned thread.
    let mut ranges = Vec::new();
    for plan in &plans {
        if plan.threads == 0 {
            continue;
        }
        let pages_per_thread = plan.num_pages / plan.threads;
        let remainder = plan.num_pages % plan.threads;
        for i in 0..plan.threads {
            let pages = pages_per_thread + if i < remainder { 1 } else { 0 };
            let offset = plan.page_size * ((i * pages_per_thread) + cmp::min(i, remainder));
            ranges.push(CpuAffinityRange {
                addr: plan.addr + offset,
                len: pages * plan.page_size,
                cpu_set: plan.cpu_set,
            });
        }
    }
    ranges
}

fn assign_threads(plans: &mut [RegionPlan], machine_cores: usize) {
    for i in 0..plans.len() {
        if plans[i].num_pages == 0 {
            continue;
        }
        let region_bytes = plans[i].num_pages * plans[i].page_size;
        let pool_bytes: usize = plans
            .iter()
            .filter(|p| p.node == plans[i].node && p.num_pages > 0)
            .map(|p| p.num_pages * p.page_size)
            .sum();
        let share = cmp::max(1, plans[i].pool_cores * region_bytes / pool_bytes.max(1));
        plans[i].threads = cmp::min(share, plans[i].max_threads);
    }

    let total: usize = plans.iter().map(|p| p.threads).sum();
    if total > machine_cores {
        for plan in plans.iter_mut().filter(|p| p.num_pages > 0) {
            plan.threads = cmp::max(1, plan.threads * machine_cores / total);
        }
    }
}

pub(crate) fn prefault_regions(regions: &[PrefaultRegion]) -> Result<(), Error> {
    if regions.is_empty() {
        return Ok(());
    }

    let ranges = cpu_affinity_ranges(regions);

    // Released once all workers spawn, so none populates while a sibling's
    // stack mmap is still queued. false means a spawn failed.
    let start: OnceLock<bool> = OnceLock::new();

    thread::scope(|s| -> Result<(), Error> {
        let mut handles = Vec::new();
        for range in &ranges {
            let start = &start;
            let worker = move || -> Result<(), io::Error> {
                if !*start.wait() {
                    return Ok(());
                }
                if let Some(cpu_set) = range.cpu_set {
                    // SAFETY: cpu_set is an initialized cpu_set_t of the size passed,
                    // and pid 0 means sched_setaffinity applies to the calling thread.
                    unsafe {
                        libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &cpu_set);
                    }
                }
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
            };
            match thread::Builder::new().spawn_scoped(s, worker) {
                Ok(handle) => handles.push(handle),
                Err(e) => {
                    let _ = start.set(false);
                    return Err(Error::PrefaultMemory(e));
                }
            }
        }

        let _ = start.set(true);

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

// Intersect with the current affinity so pinning never widens the launched cpu set.
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
