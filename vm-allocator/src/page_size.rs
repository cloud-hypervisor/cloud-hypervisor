// Copyright 2023 Arm Limited (or its affiliates). All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(fuzzing, allow(unexpected_cfgs))]

#[cfg(fuzzing)]
use std::sync::atomic::{AtomicU64, Ordering};

use libc::{_SC_PAGESIZE, sysconf};

#[cfg(fuzzing)]
static FUZZ_PAGE_SIZE: AtomicU64 = AtomicU64::new(0);

#[cfg(fuzzing)]
/// Set the page size used by fuzz-only callers.
pub fn set_fuzz_page_size(page_size: Option<u64>) {
    FUZZ_PAGE_SIZE.store(page_size.unwrap_or(0), Ordering::Relaxed);
}

/// get host page size
pub fn get_page_size() -> u64 {
    #[cfg(fuzzing)]
    if let page_size @ 1.. = FUZZ_PAGE_SIZE.load(Ordering::Relaxed) {
        return page_size;
    }

    // SAFETY: FFI call. Trivially safe.
    unsafe { sysconf(_SC_PAGESIZE) as u64 }
}

/// round up address to let it align page size
pub fn align_page_size_up(address: u64) -> u64 {
    let page_size = get_page_size();
    (address + page_size - 1) & !(page_size - 1)
}

/// round down address to let it align page size
pub fn align_page_size_down(address: u64) -> u64 {
    let page_size = get_page_size();
    address & !(page_size - 1)
}

/// Test if address is 4k aligned
pub fn is_4k_aligned(address: u64) -> bool {
    (address & 0xfff) == 0
}

/// Test if size is 4k aligned
pub fn is_4k_multiple(size: u64) -> bool {
    (size & 0xfff) == 0
}

/// Test if address is page size aligned
pub fn is_page_size_aligned(address: u64) -> bool {
    let page_size = get_page_size();
    address & (page_size - 1) == 0
}
