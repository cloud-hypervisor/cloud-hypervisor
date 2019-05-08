// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Copyright © 2019 Intel Corporation
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::collections::btree_map::BTreeMap;
use std::result;
use vm_memory::{Address, GuestAddress, GuestUsize};

#[derive(Debug)]
pub enum Error {
    Overflow,
    Overlap,
    UnalignedAddress,
}

pub type Result<T> = result::Result<T, Error>;

/// Manages allocating address ranges.
/// Use `AddressAllocator` whenever an address range needs to be allocated to different users.
///
/// # Examples
///
/// ```
/// # use vm_allocator::AddressAllocator;
/// # use vm_memory::{Address, GuestAddress, GuestUsize};
///   AddressAllocator::new(GuestAddress(0x1000), 0x10000, Some(0x100)).map(|mut pool| {
///       assert_eq!(pool.allocate(None, 0x110), Some(GuestAddress(0x10e00)));
///       assert_eq!(pool.allocate(None, 0x100), Some(GuestAddress(0x10c00)));
///   });
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct AddressAllocator {
    base: GuestAddress,
    end: GuestAddress,
    alignment: GuestUsize,
    ranges: BTreeMap<GuestAddress, GuestUsize>,
}

impl AddressAllocator {
    /// Creates a new `AddressAllocator` for managing a range of addresses.
    /// Can return `None` if `pool_base` + `pool_size` overflows a u64 or if alignment isn't a power
    /// of two.
    ///
    /// * `pool_base` - The starting address of the range to manage.
    /// * `pool_size` - The size of the address range in bytes.
    /// * `align_size` - The minimum size of an address region to align to, defaults to four.
    pub fn new(
        base: GuestAddress,
        size: GuestUsize,
        align_size: Option<GuestUsize>,
    ) -> Option<Self> {
        if size == 0 {
            return None;
        }

        let end = base.checked_add(size - 1)?;
        let alignment = align_size.unwrap_or(4);
        if !alignment.is_power_of_two() || alignment == 0 {
            return None;
        }

        let mut allocator = AddressAllocator {
            base,
            end,
            alignment,
            ranges: BTreeMap::new(),
        };

        // Insert the last address as a zero size range.
        // This is our end of address space marker.
        allocator.ranges.insert(base.checked_add(size)?, 0);

        Some(allocator)
    }

    fn align_address(&self, address: GuestAddress) -> GuestAddress {
        let align_adjust = if address.raw_value() % self.alignment != 0 {
            self.alignment - (address.raw_value() % self.alignment)
        } else {
            0
        };

        address.unchecked_add(align_adjust)
    }

    fn available_range(
        &self,
        req_address: GuestAddress,
        req_size: GuestUsize,
    ) -> Result<GuestAddress> {
        let aligned_address = self.align_address(req_address);

        // The requested address should be aligned.
        if aligned_address != req_address {
            return Err(Error::UnalignedAddress);
        }

        // The aligned address should be within the address space range.
        if aligned_address >= self.end || aligned_address <= self.base {
            return Err(Error::Overflow);
        }

        let mut prev_end_address = self.base;
        for (address, size) in self.ranges.iter() {
            if aligned_address <= *address {
                // Do we overlap with the previous range?
                if prev_end_address > aligned_address {
                    return Err(Error::Overlap);
                }

                // Do we have enough space?
                if address
                    .unchecked_sub(aligned_address.raw_value())
                    .raw_value()
                    < req_size
                {
                    return Err(Error::Overlap);
                }

                return Ok(aligned_address);
            }

            prev_end_address = address.unchecked_add(*size);
        }

        // We have not found a range that starts after the requested address,
        // despite having a marker at the end of our range.
        Err(Error::Overflow)
    }

    fn first_available_range(&self, req_size: GuestUsize) -> Option<GuestAddress> {
        let mut prev_end_address = self.base;

        for (address, size) in self.ranges.iter() {
            // If we have enough space between this range and the previous one,
            // we return the start of this range minus the requested size.
            // As each new range is allocated at the end of the available address space,
            // we will tend to always allocate new ranges there as well. In other words,
            // ranges accumulate at the end of the address space.
            if address
                .unchecked_sub(self.align_address(prev_end_address).raw_value())
                .raw_value()
                >= req_size
            {
                return Some(self.align_address(address.unchecked_sub(req_size + self.alignment)));
            }

            prev_end_address = address.unchecked_add(*size);
        }

        None
    }

    /// Allocates a range of addresses from the managed region. Returns `Some(allocated_address)`
    /// when successful, or `None` if an area of `size` can't be allocated.
    pub fn allocate(
        &mut self,
        address: Option<GuestAddress>,
        size: GuestUsize,
    ) -> Option<GuestAddress> {
        if size == 0 {
            return None;
        }

        let new_addr = match address {
            Some(req_address) => match self.available_range(req_address, size) {
                Ok(addr) => addr,
                Err(_) => {
                    return None;
                }
            },
            None => self.first_available_range(size)?,
        };

        self.ranges.insert(new_addr, size);

        Some(new_addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_fails_overflow() {
        assert_eq!(
            AddressAllocator::new(GuestAddress(u64::max_value()), 0x100, None),
            None
        );
    }

    #[test]
    fn new_fails_size_zero() {
        assert_eq!(AddressAllocator::new(GuestAddress(0x1000), 0, None), None);
    }

    #[test]
    fn new_fails_alignment_zero() {
        assert_eq!(
            AddressAllocator::new(GuestAddress(0x1000), 0x10000, Some(0)),
            None
        );
    }

    #[test]
    fn new_fails_alignment_non_power_of_two() {
        assert_eq!(
            AddressAllocator::new(GuestAddress(0x1000), 0x10000, Some(200)),
            None
        );
    }

    #[test]
    fn allocate_fails_not_enough_space() {
        let mut pool = AddressAllocator::new(GuestAddress(0x1000), 0x1000, Some(0x100)).unwrap();
        assert_eq!(pool.allocate(None, 0x800), Some(GuestAddress(0x1700)));
        assert_eq!(pool.allocate(None, 0x900), None);
        assert_eq!(pool.allocate(None, 0x400), Some(GuestAddress(0x1200)));
    }

    #[test]
    fn allocate_alignment() {
        let mut pool = AddressAllocator::new(GuestAddress(0x1000), 0x10000, Some(0x100)).unwrap();
        assert_eq!(pool.allocate(None, 0x110), Some(GuestAddress(0x10e00)));
        assert_eq!(pool.allocate(None, 0x100), Some(GuestAddress(0x10c00)));
        assert_eq!(pool.allocate(None, 0x10), Some(GuestAddress(0x10b00)));
    }

    #[test]
    fn allocate_address() {
        let mut pool = AddressAllocator::new(GuestAddress(0x1000), 0x1000, None).unwrap();
        assert_eq!(
            pool.allocate(Some(GuestAddress(0x1200)), 0x800),
            Some(GuestAddress(0x1200))
        );

        assert_eq!(
            pool.allocate(Some(GuestAddress(0x1a00)), 0x100),
            Some(GuestAddress(0x1a00))
        );
    }

    #[test]
    fn allocate_address_alignment() {
        let mut pool = AddressAllocator::new(GuestAddress(0x1000), 0x1000, Some(0x100)).unwrap();
        assert_eq!(
            pool.allocate(Some(GuestAddress(0x1200)), 0x800),
            Some(GuestAddress(0x1200))
        );

        // Unaligned request
        assert_eq!(pool.allocate(Some(GuestAddress(0x1210)), 0x800), None);

        // Aligned request
        assert_eq!(
            pool.allocate(Some(GuestAddress(0x1b00)), 0x100),
            Some(GuestAddress(0x1b00))
        );
    }

    #[test]
    fn allocate_address_not_enough_space() {
        let mut pool = AddressAllocator::new(GuestAddress(0x1000), 0x1000, Some(0x100)).unwrap();

        // First range is [0x1200:0x1a00]
        assert_eq!(
            pool.allocate(Some(GuestAddress(0x1200)), 0x800),
            Some(GuestAddress(0x1200))
        );

        // Second range is [0x1c00:0x1e00]
        assert_eq!(
            pool.allocate(Some(GuestAddress(0x1c00)), 0x200),
            Some(GuestAddress(0x1c00))
        );

        // There is 0x200 between the first 2 ranges.
        // We ask for an available address but the range is too big
        assert_eq!(pool.allocate(Some(GuestAddress(0x1b00)), 0x800), None);

        // We ask for an available address, with a small enough range
        assert_eq!(
            pool.allocate(Some(GuestAddress(0x1b00)), 0x100),
            Some(GuestAddress(0x1b00))
        );
    }
}
