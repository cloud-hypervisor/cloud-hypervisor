// Copyright (c) 2020 Ant Financial
// Copyright (c) 2025 Demi Marie Obenour
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::HashMap;
use std::ffi::{c_ulong, c_void};
use std::os::fd::{AsRawFd as _, BorrowedFd};
use std::sync::Arc;

use vhost::vhost_user::Error;
use vhost::vhost_user::message::VhostUserMemoryRegion;
use vm_memory::{GuestAddress, GuestMemoryRegion as _};

#[derive(PartialEq, Eq, Hash, Copy, Clone)]
pub(super) struct MemRegionInfo {
    pub guest_phys_addr: u64,
    pub user_addr: u64,
    pub memory_size: u64,
}

pub(super) type Region = Arc<vm_memory::GuestRegionMmap<vm_memory::bitmap::AtomicBitmap>>;

pub(super) struct Mapping<T: Allocator> {
    region: Region,
    address_ranges: HashMap<MemRegionInfo, usize>,
    allocator: T,
    page_size_mask: u64,
}

const RESERVED_ADDRESS: u64 = i64::MAX as u64 + 1;

// Inner function with the unsafe code
fn unmap_region_internal(
    region: &Region,
    offset: usize,
    size: usize,
) -> Result<(), std::io::Error> {
    let region_size = region.size();
    if isize::try_from(region_size).is_err() || region_size < offset || region_size - offset < size
    {
        panic!("Internal size overflow")
    }

    let addr = region.as_ptr() as *mut c_void;

    // SAFETY: bounds checked above
    let addr_to_map = unsafe { addr.add(offset) };

    // SAFETY: the address is checked to fit within the GuestRegionMmap
    match unsafe { libc::munmap(addr_to_map, size) } {
        0 => Ok(()),
        -1 => Err(std::io::Error::last_os_error()),
        _ => panic!("bad munmap return value"),
    }
}

pub(super) trait Allocator {
    fn new(base: GuestAddress, size: u64) -> Self;
    fn allocate(&mut self, size: u64) -> Option<GuestAddress>;
    fn base(&self) -> GuestAddress;
}

impl<T: Allocator> Mapping<T> {
    pub(super) fn check_region(
        &self,
        &VhostUserMemoryRegion {
            guest_phys_addr,
            memory_size,
            mmap_offset,
            user_addr,
        }: &VhostUserMemoryRegion,
    ) -> Result<(), Error> {
        self.check_mmap_params(memory_size, mmap_offset)?;

        // This combination is reserved for internal use.
        if guest_phys_addr == RESERVED_ADDRESS && user_addr == u64::MAX {
            return Err(Error::InvalidParam);
        }

        // There must not be an overflow computing the end of the address
        // spaces.
        let (Some(_last_guest_phys_addr), Some(_last_user_addr)) = (
            memory_size.checked_add(guest_phys_addr),
            memory_size.checked_add(user_addr),
        ) else {
            return Err(Error::InvalidParam);
        };

        // The user address and guest physical address do not
        // technically need to be multiples of the page size,
        // but it would be very strange for them not to be.
        if guest_phys_addr & self.page_size_mask != 0 || user_addr & self.page_size_mask != 0 {
            return Err(Error::InvalidParam);
        }
        Ok(())
    }

    pub(super) fn check_mmap_params(
        &self,
        memory_size: u64,
        mmap_offset: u64,
    ) -> Result<(), Error> {
        let Some(last_byte_in_file) = memory_size.checked_add(mmap_offset) else {
            return Err(Error::InvalidParam);
        };

        let (Ok(_memory_size), Ok(_another_size), Ok(_offset)) = (
            libc::size_t::try_from(memory_size),
            isize::try_from(memory_size),
            libc::off64_t::try_from(last_byte_in_file),
        ) else {
            return Err(Error::InvalidParam);
        };
        // mmap64() takes the size as size_t and the offset
        // as off64_t.  Check that the size fits in size_t
        // and that the last byte of the file fits in off64_t.

        // The mmap offset and size must be multiples of the page size.
        if memory_size & self.page_size_mask != 0 || mmap_offset & self.page_size_mask != 0 {
            return Err(Error::InvalidParam);
        }
        Ok(())
    }
    pub(super) fn reset(&mut self) -> Result<(), Error> {
        let ranges = self.address_ranges.clone();
        for (region_info, mmap_offset) in ranges {
            let region = VhostUserMemoryRegion {
                guest_phys_addr: region_info.guest_phys_addr,
                memory_size: region_info.memory_size,
                user_addr: region_info.user_addr,
                mmap_offset: mmap_offset.try_into().unwrap(),
            };
            self.unmap_region(&region)?;
            self.address_ranges
                .remove(&region_info)
                .expect("was in table");
        }
        Ok(())
    }
    pub(super) fn map_region(
        &mut self,
        region: VhostUserMemoryRegion,
        file: BorrowedFd<'_>,
    ) -> Result<(), Error> {
        self.check_region(&region)?;

        let allocator: &mut T = &mut self.allocator;
        // inner function with the unsafe code
        fn map_region_not_method_raw(
            fd: BorrowedFd,
            region: &vm_memory::GuestRegionMmap<vm_memory::bitmap::AtomicBitmap>,
            offset: usize,
            size: usize,
            file_offset: libc::off64_t,
        ) -> std::io::Result<()> {
            let region_size: usize = region.size();
            if isize::try_from(region_size).is_err()
                || region_size < offset
                || region_size - offset < size
            {
                panic!("Internal size overflow")
            }

            // SAFETY: the address is checked to fit within the GuestRegionMmap
            let ptr = unsafe { region.as_ptr().cast::<c_void>().add(offset) };

            // SAFETY: MAP_FIXED_NOREPLACE passed and the address and FD are valid.
            // MAP_SHARED_VALIDATE is used, which means that any unknown flags
            // will cause an error.
            let addr = unsafe {
                libc::mmap64(
                    ptr,
                    size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_FIXED_NOREPLACE | libc::MAP_SHARED_VALIDATE,
                    fd.as_raw_fd(),
                    file_offset,
                )
            };
            if addr == libc::MAP_FAILED {
                return Err(std::io::Error::last_os_error());
            }
            if addr != ptr {
                // This means that there was a catastrophic failure that caused
                // the mapping to succeed, but map the memory somewhere other
                // than was assigned. This might mean memory corruption.
                std::process::abort()
            }
            Ok(())
        }
        let VhostUserMemoryRegion {
            guest_phys_addr,
            memory_size,
            mmap_offset,
            user_addr,
        } = region;
        let region_info = MemRegionInfo {
            guest_phys_addr,
            user_addr,
            memory_size,
        };
        if self.address_ranges.contains_key(&region_info) {
            return Err(Error::InvalidOperation("address already exists"));
        }
        // TODO: log message (out of memory)
        let GuestAddress(guest_address) = allocator
            .allocate(memory_size)
            .ok_or(Error::BackendInternalError)?;
        let GuestAddress(base) = allocator.base();
        let guest_offset = usize::try_from(guest_address - base).unwrap();
        map_region_not_method_raw(
            file,
            &self.region,
            guest_offset,
            memory_size.try_into().unwrap(),
            mmap_offset.try_into().unwrap(),
        )
        .map_err(Error::ReqHandlerError)?;
        assert!(
            self.address_ranges
                .insert(region_info, guest_offset)
                .is_none(),
            "duplicate address range"
        );
        Ok(())
    }

    pub(super) fn unmap_region(&mut self, region: &VhostUserMemoryRegion) -> Result<(), Error> {
        self.check_region(region)?;
        let region_lookup_key = MemRegionInfo {
            guest_phys_addr: region.guest_phys_addr,
            user_addr: region.user_addr,
            memory_size: region.memory_size,
        };
        let Some(&offset) = self.address_ranges.get(&region_lookup_key) else {
            return Err(Error::InvalidOperation("Key not found"));
        };
        unmap_region_internal(&self.region, offset, region.memory_size.try_into().unwrap())
            .map_err(Error::ReqHandlerError)?;
        self.address_ranges.remove(&region_lookup_key);
        Ok(())
    }

    pub(super) fn new(region: Region) -> Self {
        // SAFETY: FFI call with valid parameters
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) };
        assert!(page_size.count_ones() == 1);
        let allocator = T::new(region.start_addr(), region.size().try_into().unwrap());
        Self {
            region,
            address_ranges: Default::default(),
            allocator,
            page_size_mask: (page_size as c_ulong - 1) as _,
        }
    }
}
