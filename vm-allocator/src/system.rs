// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Copyright © 2019 Intel Corporation
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use vm_memory::{GuestAddress, GuestUsize};

use crate::address::AddressAllocator;
use crate::id::IdAllocator;

use libc::{sysconf, _SC_PAGESIZE};
use std::fmt::{self, Display};
use std::result;
use std::sync::{Arc, Mutex};

/// Errors associated with system resources allocation.
#[derive(Debug)]
pub enum Error {
    /// Address is none.
    NoneAddress,
    /// Address allocation failed.
    AddressAllocate(crate::address::Error),
    /// Id allocation failed.
    IdAllocate(crate::id::Error),
}

impl Display for Error {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            NoneAddress => write!(f, "The address being allocated is null"),
            AddressAllocate(e) => write!(f, "Address being allocated failed, err={}", e),
            IdAllocate(e) => write!(f, "Address being allocated failed, err={}", e),
        }
    }
}

pub type Result<T> = result::Result<T, Error>;

/// Safe wrapper for `sysconf(_SC_PAGESIZE)`.
#[inline(always)]
fn pagesize() -> usize {
    // Trivially safe
    unsafe { sysconf(_SC_PAGESIZE) as usize }
}

/// Manages allocating system resources such as address space and interrupt numbers.
///
/// # Example - Use the `SystemAddress` builder.
///
/// ```
/// # use vm_allocator::SystemAllocator;
/// # use vm_memory::{Address, GuestAddress, GuestUsize};
///   let mut allocator = SystemAllocator::new(
///           Some(GuestAddress(0x1000)), Some(0x10000),
///           GuestAddress(0x10000000), 0x10000000,
///           5).unwrap();
///    assert_eq!(allocator.allocate_irq(), Some(5));
///    assert_eq!(allocator.allocate_irq(), Some(6));
///    assert_eq!(allocator.allocate_mmio_addresses(None, 0x1000), Some(GuestAddress(0x1fffe000)));
///
/// ```
#[derive(Clone)]
pub struct SystemAllocator {
    io_address_space: Arc<Mutex<Option<AddressAllocator>>>,
    mmio_address_space: Arc<Mutex<AddressAllocator>>,
    irq: Arc<Mutex<IdAllocator>>,
    instance_id: Arc<Mutex<IdAllocator>>,
}

impl SystemAllocator {
    /// Creates a new `SystemAllocator` for managing addresses and irq numvers.
    /// Can return `None` if `base` + `size` overflows a u64 or if alignment isn't a power
    /// of two.
    ///
    /// * `io_base` - The starting address of IO memory.
    /// * `io_size` - The size of IO memory.
    /// * `mmio_base` - The starting address of MMIO memory.
    /// * `mmio_size` - The size of MMIO memory.
    /// * `first_irq` - The first irq number to give out.
    /// * `last_irq` - The last irq number to give out.
    /// * `first_instance_id` - The first device instance id to give out.
    pub fn new(
        io_base: Option<GuestAddress>,
        io_size: Option<GuestUsize>,
        mmio_base: GuestAddress,
        mmio_size: GuestUsize,
        first_irq: u32,
        last_irq: u32,
        first_instance_id: u32,
    ) -> Option<Self> {
        let page_size = pagesize() as u64;
        Some(SystemAllocator {
            io_address_space: if let (Some(b), Some(s)) = (io_base, io_size) {
                Arc::new(Mutex::new(Some(AddressAllocator::new(b, s, Some(0x1))?)))
            } else {
                Arc::new(Mutex::new(None))
            },
            mmio_address_space: Arc::new(Mutex::new(AddressAllocator::new(
                mmio_base,
                mmio_size,
                Some(page_size),
            )?)),
            irq: Arc::new(Mutex::new(IdAllocator::new(first_irq, last_irq)?)),
            instance_id: Arc::new(Mutex::new(IdAllocator::new(
                first_instance_id,
                u32::max_value(),
            )?)),
        })
    }

    /// Reserves the next available system irq number.
    /// * `irq` - A specific value trying to allocate, or None means no specific value.
    pub fn allocate_irq(&mut self, irq: Option<u32>) -> Result<u32> {
        self.irq
            .lock()
            .expect("failed to acquire lock")
            .allocate(irq)
            .map_err(Error::IdAllocate)
    }

    /// Reserves the next available system device instance id number.
    pub fn allocate_instance_id(&mut self) -> Result<u32> {
        self.instance_id
            .lock()
            .expect("failed to acquire lock")
            .allocate(None)
            .map_err(Error::IdAllocate)
    }

    /// Free an interrupt number.
    /// Only free an `irq` if it matches exactly an already allocated one.
    pub fn free_irq(&mut self, irq: Option<u32>) {
        match irq {
            Some(i) => self.irq.lock().expect("failed to acquire lock").free(i),
            None => return,
        }
    }

    /// Free an instance id.
    /// Only free an `id` if it matches exactly an already allocated one.
    pub fn free_instance_id(&mut self, id: u32) {
        self.instance_id
            .lock()
            .expect("failed to acquire lock")
            .free(id);
    }

    /// Reserves a section of `size` bytes of IO address space.
    pub fn allocate_io_addresses(
        &mut self,
        address: GuestAddress,
        size: GuestUsize,
    ) -> Result<GuestAddress> {
        if let Some(io_address) = self
            .io_address_space
            .lock()
            .expect("failed to acquire lock")
            .as_mut()
        {
            io_address
                .allocate(Some(address), size)
                .map_err(Error::AddressAllocate)
        } else {
            Err(Error::NoneAddress)
        }
    }

    /// Reserves a section of `size` bytes of MMIO address space.
    pub fn allocate_mmio_addresses(
        &mut self,
        address: Option<GuestAddress>,
        size: GuestUsize,
    ) -> Result<GuestAddress> {
        self.mmio_address_space
            .lock()
            .expect("failed to acquire lock")
            .allocate(address, size)
            .map_err(Error::AddressAllocate)
    }

    /// Free an IO address range.
    /// We can only free a range if it matches exactly an already allocated range.
    pub fn free_io_addresses(&mut self, address: GuestAddress, size: GuestUsize) {
        if let Some(io_address) = self
            .io_address_space
            .lock()
            .expect("failed to acquire lock")
            .as_mut()
        {
            io_address.free(address, size)
        }
    }

    /// Free an MMIO address range.
    /// We can only free a range if it matches exactly an already allocated range.
    pub fn free_mmio_addresses(&mut self, address: GuestAddress, size: GuestUsize) {
        self.mmio_address_space
            .lock()
            .expect("failed to acquire lock")
            .free(address, size)
    }
}
