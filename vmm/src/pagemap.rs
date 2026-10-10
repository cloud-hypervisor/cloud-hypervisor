// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

//! Reads `/proc/self/pagemap` to find the pages of a private file mapping
//! that are private copies and no longer read from the file.

use std::fs::File;
use std::io;
use std::ops::Range;
use std::os::unix::fs::FileExt;

use vm_allocator::page_size::get_page_size;

const PRESENT: u64 = 1 << 63;
const SWAPPED: u64 = 1 << 62;
const FILE_PAGE: u64 = 1 << 61;
const ENTRY_SIZE: u64 = 8;
const CHUNK_PAGES: u64 = 1 << 17;
// Private pages this close to each other come back as one range.
const MERGE_GAP_PAGES: u64 = 8;

pub(crate) struct PageMap {
    file: File,
}

impl PageMap {
    pub(crate) fn open() -> io::Result<Self> {
        Ok(Self {
            file: File::open("/proc/self/pagemap")?,
        })
    }

    /// Returns the private copies in `[addr, addr + len)` as byte ranges
    /// relative to `addr`.
    pub(crate) fn private_ranges(&self, addr: u64, len: u64) -> io::Result<Vec<Range<u64>>> {
        let page_size = get_page_size();
        let first_page = addr / page_size;
        let pages = len / page_size;
        let mut ranges: Vec<Range<u64>> = Vec::new();
        let mut buf = vec![0u8; (CHUNK_PAGES * ENTRY_SIZE) as usize];
        let mut page: u64 = 0;
        while page < pages {
            let count = (pages - page).min(CHUNK_PAGES);
            let entries = &mut buf[..(count * ENTRY_SIZE) as usize];
            self.file
                .read_exact_at(entries, (first_page + page) * ENTRY_SIZE)?;
            for (i, entry) in entries.as_chunks::<8>().0.iter().enumerate() {
                if !is_private(u64::from_ne_bytes(*entry)) {
                    continue;
                }
                let index = page + i as u64;
                match ranges.last_mut() {
                    Some(last) if index - last.end <= MERGE_GAP_PAGES => last.end = index + 1,
                    _ => ranges.push(index..index + 1),
                }
            }
            page += count;
        }
        for range in &mut ranges {
            range.start *= page_size;
            range.end *= page_size;
        }
        Ok(ranges)
    }
}

// A present or swapped page without the file bit no longer reads from the file.
fn is_private(entry: u64) -> bool {
    entry & (PRESENT | SWAPPED) != 0 && entry & FILE_PAGE == 0
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use vm_memory::guest_memory::FileOffset;
    use vm_memory::{Bytes, MmapRegion, VolatileMemory};

    use super::*;

    #[test]
    fn private_ranges_reports_written_pages_only() {
        let page = get_page_size() as usize;
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&vec![1u8; 32 * page]).unwrap();
        let region = MmapRegion::<()>::build(
            Some(FileOffset::new(file, 0)),
            32 * page,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE,
        )
        .unwrap();
        let memory = region.as_volatile_slice();
        for index in [1, 2, 6, 20, 31] {
            memory.write_obj(0xee_u8, index * page).unwrap();
        }
        assert_eq!(memory.read_obj::<u8>(3 * page).unwrap(), 1);
        // SAFETY: the page lies inside the mapping that `region` owns.
        let ret = unsafe {
            libc::madvise(
                region.as_ptr().add(31 * page).cast(),
                page,
                libc::MADV_DONTNEED,
            )
        };
        assert_eq!(ret, 0);
        assert_eq!(memory.read_obj::<u8>(31 * page).unwrap(), 1);

        let page = page as u64;
        assert_eq!(
            PageMap::open()
                .unwrap()
                .private_ranges(region.as_ptr() as u64, 32 * page)
                .unwrap(),
            vec![page..7 * page, 20 * page..21 * page]
        );
    }
}
