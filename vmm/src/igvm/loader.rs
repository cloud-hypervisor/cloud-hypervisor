// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2023, Microsoft Corporation
//
use crate::igvm::{BootPageAcceptance, StartupMemoryType, HV_PAGE_SIZE};
use range_map_vec::{Entry, RangeMap};
use thiserror::Error;
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::{
    Bytes, GuestAddress, GuestAddressSpace, GuestMemory, GuestMemoryAtomic, GuestMemoryMmap,
    GuestMemoryRegion,
};

/// Structure to hold the guest memory info/layout to check
/// the if the memory is accepted within the layout.
/// Adds up the total bytes written to the guest memory
pub struct Loader {
    memory: GuestMemoryAtomic<GuestMemoryMmap<AtomicBitmap>>,
    accepted_ranges: RangeMap<u64, BootPageAcceptance>,
    bytes_written: u64,
}

#[derive(Debug)]
pub struct ImportRegion {
    pub page_base: u64,
    pub page_count: u64,
    pub acceptance: BootPageAcceptance,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("overlaps with existing import region {0:?}")]
    OverlapsExistingRegion(ImportRegion),
    #[error("memory unavailable")]
    MemoryUnavailable,
    #[error("failed to import pages")]
    ImportPagesFailed,
    #[error("invalid vp context memory")]
    InvalidVpContextMemory(&'static str),
    #[error("data larger than imported region")]
    DataTooLarge,
}

impl Loader {
    pub fn new(memory: GuestMemoryAtomic<GuestMemoryMmap<AtomicBitmap>>) -> Loader {
        Loader {
            memory,
            accepted_ranges: RangeMap::new(),
            bytes_written: 0,
        }
    }

    /// Accept a new page range with a given acceptance into the map of accepted ranges.
    pub fn accept_new_range(
        &mut self,
        page_base: u64,
        page_count: u64,
        acceptance: BootPageAcceptance,
    ) -> Result<(), Error> {
        let page_end = page_base + page_count - 1;
        match self.accepted_ranges.entry(page_base..=page_end) {
            Entry::Overlapping(entry) => {
                let &(overlap_start, overlap_end, overlap_acceptance) = entry.get();

                Err(Error::OverlapsExistingRegion(ImportRegion {
                    page_base: overlap_start,
                    page_count: overlap_end - overlap_start + 1,
                    acceptance: overlap_acceptance,
                }))
            }
            Entry::Vacant(entry) => {
                entry.insert(acceptance);
                Ok(())
            }
        }
    }

    pub fn import_pages(
        &mut self,
        page_base: u64,
        page_count: u64,
        acceptance: BootPageAcceptance,
        data: &[u8],
    ) -> Result<(), Error> {
        // Page count must be larger or equal to data.
        if page_count * HV_PAGE_SIZE < data.len() as u64 {
            return Err(Error::DataTooLarge);
        }

        // Track accepted ranges for duplicate imports.
        self.accept_new_range(page_base, page_count, acceptance)?;

        let bytes_written = self
            .memory
            .memory()
            .write(data, GuestAddress(page_base * HV_PAGE_SIZE))
            .map_err(|_e| {
                debug!("Importing pages failed due to MemoryError");
                Error::MemoryUnavailable
            })?;
        if bytes_written != (page_count * HV_PAGE_SIZE) as usize {
            return Err(Error::ImportPagesFailed);
        }
        self.bytes_written += bytes_written as u64;
        Ok(())
    }

    pub fn verify_startup_memory_available(
        &mut self,
        page_base: u64,
        page_count: u64,
        memory_type: StartupMemoryType,
    ) -> Result<(), Error> {
        if memory_type != StartupMemoryType::Ram {
            return Err(Error::MemoryUnavailable);
        }

        let mut memory_found = false;

        for range in self.memory.memory().iter() {
            // Today, the memory layout only describes normal ram and mmio. Thus the memory
            // request must live completely within a single range, since any gaps are mmio.
            let base_address = page_base * HV_PAGE_SIZE;
            let end_address = base_address + (page_count * HV_PAGE_SIZE) - 1;

            if base_address >= range.start_addr().0 && base_address < range.last_addr().0 {
                if end_address > range.last_addr().0 {
                    debug!("startup memory end bigger than the current range");
                    return Err(Error::MemoryUnavailable);
                }

                memory_found = true;
            }
        }

        if memory_found {
            Ok(())
        } else {
            debug!("no valid memory range available for startup memory verify");
            Err(Error::MemoryUnavailable)
        }
    }
}
