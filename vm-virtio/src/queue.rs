// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::cmp::min;
use std::convert::TryInto;
use std::fmt::{self, Display};
use std::num::Wrapping;
use std::sync::atomic::{fence, Ordering};
use std::sync::Arc;

use crate::device::VirtioIommuRemapping;
use vm_memory::{
    Address, ByteValued, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap, GuestUsize,
};

pub(super) const VIRTQ_DESC_F_NEXT: u16 = 0x1;
pub(super) const VIRTQ_DESC_F_WRITE: u16 = 0x2;
pub(super) const VIRTQ_DESC_F_INDIRECT: u16 = 0x4;

#[derive(Debug)]
pub enum Error {
    GuestMemoryError,
    InvalidIndirectDescriptor,
    InvalidChain,
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            GuestMemoryError => write!(f, "error accessing guest memory"),
            InvalidChain => write!(f, "invalid descriptor chain"),
            InvalidIndirectDescriptor => write!(f, "invalid indirect descriptor"),
        }
    }
}

// GuestMemoryMmap::read_obj() will be used to fetch the descriptor,
// which has an explicit constraint that the entire descriptor doesn't
// cross the page boundary. Otherwise the descriptor may be splitted into
// two mmap regions which causes failure of GuestMemoryMmap::read_obj().
//
// The Virtio Spec 1.0 defines the alignment of VirtIO descriptor is 16 bytes,
// which fulfills the explicit constraint of GuestMemoryMmap::read_obj().

/// An iterator over a single descriptor chain.  Not to be confused with AvailIter,
/// which iterates over the descriptor chain heads in a queue.
pub struct DescIter<'a> {
    next: Option<DescriptorChain<'a>>,
}

impl<'a> DescIter<'a> {
    /// Returns an iterator that only yields the readable descriptors in the chain.
    pub fn readable(self) -> impl Iterator<Item = DescriptorChain<'a>> {
        self.filter(|d| !d.is_write_only())
    }

    /// Returns an iterator that only yields the writable descriptors in the chain.
    pub fn writable(self) -> impl Iterator<Item = DescriptorChain<'a>> {
        self.filter(DescriptorChain::is_write_only)
    }
}

impl<'a> Iterator for DescIter<'a> {
    type Item = DescriptorChain<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(current) = self.next.take() {
            self.next = current.next_descriptor();
            Some(current)
        } else {
            None
        }
    }
}

/// A virtio descriptor constraints with C representive.
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct Descriptor {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

unsafe impl ByteValued for Descriptor {}

/// A virtio descriptor head, not tied to a GuestMemoryMmap.
pub struct DescriptorHead {
    desc_table: GuestAddress,
    table_size: u16,
    index: u16,
    iommu_mapping_cb: Option<Arc<VirtioIommuRemapping>>,
}

/// A virtio descriptor chain.
#[derive(Clone)]
pub struct DescriptorChain<'a> {
    desc_table: GuestAddress,
    table_size: u16,
    ttl: u16, // used to prevent infinite chain cycles
    iommu_mapping_cb: Option<Arc<VirtioIommuRemapping>>,

    /// Reference to guest memory
    pub mem: &'a GuestMemoryMmap,

    /// Index into the descriptor table
    pub index: u16,

    /// Guest physical address of device specific data
    pub addr: GuestAddress,

    /// Length of device specific data
    pub len: u32,

    /// Includes next, write, and indirect bits
    pub flags: u16,

    /// Index into the descriptor table of the next descriptor if flags has
    /// the next bit set
    pub next: u16,
}

impl<'a> DescriptorChain<'a> {
    pub fn checked_new(
        mem: &GuestMemoryMmap,
        desc_table: GuestAddress,
        table_size: u16,
        index: u16,
        iommu_mapping_cb: Option<Arc<VirtioIommuRemapping>>,
    ) -> Option<DescriptorChain> {
        if index >= table_size {
            return None;
        }

        let desc_head = match mem.checked_offset(desc_table, (index as usize) * 16) {
            Some(a) => a,
            None => return None,
        };
        mem.checked_offset(desc_head, 16)?;

        // These reads can't fail unless Guest memory is hopelessly broken.
        let desc = match mem.read_obj::<Descriptor>(desc_head) {
            Ok(ret) => ret,
            Err(_) => {
                // TODO log address
                error!("Failed to read from memory");
                return None;
            }
        };

        // Translate address if necessary
        let desc_addr = if let Some(iommu_mapping_cb) = &iommu_mapping_cb {
            (iommu_mapping_cb)(desc.addr).unwrap()
        } else {
            desc.addr
        };

        let chain = DescriptorChain {
            mem,
            desc_table,
            table_size,
            ttl: table_size,
            index,
            addr: GuestAddress(desc_addr),
            len: desc.len,
            flags: desc.flags,
            next: desc.next,
            iommu_mapping_cb,
        };

        if chain.is_valid() {
            Some(chain)
        } else {
            None
        }
    }

    pub fn new_from_indirect(&self) -> Result<DescriptorChain, Error> {
        if !self.is_indirect() {
            return Err(Error::InvalidIndirectDescriptor);
        }

        let desc_head = self.addr;
        self.mem
            .checked_offset(desc_head, 16)
            .ok_or(Error::GuestMemoryError)?;

        // These reads can't fail unless Guest memory is hopelessly broken.
        let desc = match self.mem.read_obj::<Descriptor>(desc_head) {
            Ok(ret) => ret,
            Err(_) => return Err(Error::GuestMemoryError),
        };

        // Translate address if necessary
        let (desc_addr, iommu_mapping_cb) =
            if let Some(iommu_mapping_cb) = self.iommu_mapping_cb.clone() {
                (
                    (iommu_mapping_cb)(desc.addr).unwrap(),
                    Some(iommu_mapping_cb),
                )
            } else {
                (desc.addr, None)
            };

        let chain = DescriptorChain {
            mem: self.mem,
            desc_table: self.addr,
            table_size: (self.len / 16).try_into().unwrap(),
            ttl: (self.len / 16).try_into().unwrap(),
            index: 0,
            addr: GuestAddress(desc_addr),
            len: desc.len,
            flags: desc.flags,
            next: desc.next,
            iommu_mapping_cb,
        };

        if !chain.is_valid() {
            return Err(Error::InvalidChain);
        }

        Ok(chain)
    }

    /// Returns a copy of a descriptor referencing a different GuestMemoryMmap object.
    pub fn new_from_head(
        mem: &'a GuestMemoryMmap,
        head: DescriptorHead,
    ) -> Result<DescriptorChain<'a>, Error> {
        match DescriptorChain::checked_new(
            mem,
            head.desc_table,
            head.table_size,
            head.index,
            head.iommu_mapping_cb,
        ) {
            Some(d) => Ok(d),
            None => Err(Error::InvalidChain),
        }
    }

    /// Returns a DescriptorHead that can be used to build a copy of a descriptor
    /// referencing a different GuestMemoryMmap.
    pub fn get_head(&self) -> DescriptorHead {
        DescriptorHead {
            desc_table: self.desc_table,
            table_size: self.table_size,
            index: self.index,
            iommu_mapping_cb: self.iommu_mapping_cb.clone(),
        }
    }

    fn is_valid(&self) -> bool {
        !(self
            .mem
            .checked_offset(self.addr, self.len as usize)
            .is_none()
            || (self.has_next() && self.next >= self.table_size))
    }

    /// Gets if this descriptor chain has another descriptor chain linked after it.
    pub fn has_next(&self) -> bool {
        self.flags & VIRTQ_DESC_F_NEXT != 0 && self.ttl > 1
    }

    /// If the driver designated this as a write only descriptor.
    ///
    /// If this is false, this descriptor is read only.
    /// Write only means the the emulated device can write and the driver can read.
    pub fn is_write_only(&self) -> bool {
        self.flags & VIRTQ_DESC_F_WRITE != 0
    }

    pub fn is_indirect(&self) -> bool {
        self.flags & VIRTQ_DESC_F_INDIRECT != 0
    }

    /// Gets the next descriptor in this descriptor chain, if there is one.
    ///
    /// Note that this is distinct from the next descriptor chain returned by `AvailIter`, which is
    /// the head of the next _available_ descriptor chain.
    pub fn next_descriptor(&self) -> Option<DescriptorChain<'a>> {
        if self.has_next() {
            DescriptorChain::checked_new(
                self.mem,
                self.desc_table,
                self.table_size,
                self.next,
                self.iommu_mapping_cb.clone(),
            )
            .map(|mut c| {
                c.ttl = self.ttl - 1;
                c
            })
        } else {
            None
        }
    }
}

impl<'a> IntoIterator for DescriptorChain<'a> {
    type Item = DescriptorChain<'a>;
    type IntoIter = DescIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        DescIter { next: Some(self) }
    }
}

/// Consuming iterator over all available descriptor chain heads in the queue.
pub struct AvailIter<'a, 'b> {
    mem: &'a GuestMemoryMmap,
    desc_table: GuestAddress,
    avail_ring: GuestAddress,
    next_index: Wrapping<u16>,
    last_index: Wrapping<u16>,
    queue_size: u16,
    next_avail: &'b mut Wrapping<u16>,
    iommu_mapping_cb: Option<Arc<VirtioIommuRemapping>>,
}

impl<'a, 'b> AvailIter<'a, 'b> {
    pub fn new(mem: &'a GuestMemoryMmap, q_next_avail: &'b mut Wrapping<u16>) -> AvailIter<'a, 'b> {
        AvailIter {
            mem,
            desc_table: GuestAddress(0),
            avail_ring: GuestAddress(0),
            next_index: Wrapping(0),
            last_index: Wrapping(0),
            queue_size: 0,
            next_avail: q_next_avail,
            iommu_mapping_cb: None,
        }
    }
}

impl<'a, 'b> Iterator for AvailIter<'a, 'b> {
    type Item = DescriptorChain<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_index == self.last_index {
            return None;
        }

        let offset = (4 + (self.next_index.0 % self.queue_size) * 2) as usize;
        let avail_addr = match self.mem.checked_offset(self.avail_ring, offset) {
            Some(a) => a,
            None => return None,
        };
        // This index is checked below in checked_new
        let desc_index: u16 = match self.mem.read_obj(avail_addr) {
            Ok(ret) => ret,
            Err(_) => {
                // TODO log address
                error!("Failed to read from memory");
                return None;
            }
        };

        self.next_index += Wrapping(1);

        let ret = DescriptorChain::checked_new(
            self.mem,
            self.desc_table,
            self.queue_size,
            desc_index,
            self.iommu_mapping_cb.clone(),
        );
        if ret.is_some() {
            *self.next_avail += Wrapping(1);
        }
        ret
    }
}

#[derive(Clone)]
/// A virtio queue's parameters.
pub struct Queue {
    /// The maximal size in elements offered by the device
    max_size: u16,

    /// The queue size in elements the driver selected
    pub size: u16,

    /// Inidcates if the queue is finished with configuration
    pub ready: bool,

    /// Interrupt vector index of the queue
    pub vector: u16,

    /// Guest physical address of the descriptor table
    pub desc_table: GuestAddress,

    /// Guest physical address of the available ring
    pub avail_ring: GuestAddress,

    /// Guest physical address of the used ring
    pub used_ring: GuestAddress,

    pub next_avail: Wrapping<u16>,
    pub next_used: Wrapping<u16>,

    pub iommu_mapping_cb: Option<Arc<VirtioIommuRemapping>>,
}

impl Queue {
    /// Constructs an empty virtio queue with the given `max_size`.
    pub fn new(max_size: u16) -> Queue {
        Queue {
            max_size,
            size: max_size,
            ready: false,
            vector: 0,
            desc_table: GuestAddress(0),
            avail_ring: GuestAddress(0),
            used_ring: GuestAddress(0),
            next_avail: Wrapping(0),
            next_used: Wrapping(0),
            iommu_mapping_cb: None,
        }
    }

    pub fn get_max_size(&self) -> u16 {
        self.max_size
    }

    pub fn enable(&mut self, set: bool) {
        self.ready = set;

        if set {
            // Translate address of descriptor table and vrings.
            if let Some(iommu_mapping_cb) = &self.iommu_mapping_cb {
                self.desc_table =
                    GuestAddress((iommu_mapping_cb)(self.desc_table.raw_value()).unwrap());
                self.avail_ring =
                    GuestAddress((iommu_mapping_cb)(self.avail_ring.raw_value()).unwrap());
                self.used_ring =
                    GuestAddress((iommu_mapping_cb)(self.used_ring.raw_value()).unwrap());
            }
        } else {
            self.desc_table = GuestAddress(0);
            self.avail_ring = GuestAddress(0);
            self.used_ring = GuestAddress(0);
        }
    }

    /// Return the actual size of the queue, as the driver may not set up a
    /// queue as big as the device allows.
    pub fn actual_size(&self) -> u16 {
        min(self.size, self.max_size)
    }

    /// Reset the queue to a state that is acceptable for a device reset
    pub fn reset(&mut self) {
        self.ready = false;
        self.size = self.max_size;
    }

    pub fn is_valid(&self, mem: &GuestMemoryMmap) -> bool {
        let queue_size = self.actual_size() as usize;
        let desc_table = self.desc_table;
        let desc_table_size = 16 * queue_size;
        let avail_ring = self.avail_ring;
        let avail_ring_size = 6 + 2 * queue_size;
        let used_ring = self.used_ring;
        let used_ring_size = 6 + 8 * queue_size;
        if !self.ready {
            error!("attempt to use virtio queue that is not marked ready");
            false
        } else if self.size > self.max_size || self.size == 0 || (self.size & (self.size - 1)) != 0
        {
            error!("virtio queue with invalid size: {}", self.size);
            false
        } else if desc_table
            .checked_add(desc_table_size as GuestUsize)
            .map_or(true, |v| !mem.address_in_range(v))
        {
            error!(
                "virtio queue descriptor table goes out of bounds: start:0x{:08x} size:0x{:08x}",
                desc_table.raw_value(),
                desc_table_size
            );
            false
        } else if avail_ring
            .checked_add(avail_ring_size as GuestUsize)
            .map_or(true, |v| !mem.address_in_range(v))
        {
            error!(
                "virtio queue available ring goes out of bounds: start:0x{:08x} size:0x{:08x}",
                avail_ring.raw_value(),
                avail_ring_size
            );
            false
        } else if used_ring
            .checked_add(used_ring_size as GuestUsize)
            .map_or(true, |v| !mem.address_in_range(v))
        {
            error!(
                "virtio queue used ring goes out of bounds: start:0x{:08x} size:0x{:08x}",
                used_ring.raw_value(),
                used_ring_size
            );
            false
        } else if desc_table.mask(0xf) != 0 {
            error!("virtio queue descriptor table breaks alignment contraints");
            false
        } else if avail_ring.mask(0x1) != 0 {
            error!("virtio queue available ring breaks alignment contraints");
            false
        } else if used_ring.mask(0x3) != 0 {
            error!("virtio queue used ring breaks alignment contraints");
            false
        } else {
            true
        }
    }

    /// A consuming iterator over all available descriptor chain heads offered by the driver.
    pub fn iter<'a, 'b>(&'b mut self, mem: &'a GuestMemoryMmap) -> AvailIter<'a, 'b> {
        let queue_size = self.actual_size();
        let avail_ring = self.avail_ring;

        let index_addr = match mem.checked_offset(avail_ring, 2) {
            Some(ret) => ret,
            None => {
                // TODO log address
                warn!("Invalid offset");
                return AvailIter::new(mem, &mut self.next_avail);
            }
        };
        // Note that last_index has no invalid values
        let last_index: u16 = match mem.read_obj::<u16>(index_addr) {
            Ok(ret) => ret,
            Err(_) => return AvailIter::new(mem, &mut self.next_avail),
        };

        AvailIter {
            mem,
            desc_table: self.desc_table,
            avail_ring,
            next_index: self.next_avail,
            last_index: Wrapping(last_index),
            queue_size,
            next_avail: &mut self.next_avail,
            iommu_mapping_cb: self.iommu_mapping_cb.clone(),
        }
    }

    /// Update avail_event on the used ring with the last index in the avail ring.
    pub fn update_avail_event(&mut self, mem: &GuestMemoryMmap) {
        let index_addr = match mem.checked_offset(self.avail_ring, 2) {
            Some(ret) => ret,
            None => {
                // TODO log address
                warn!("Invalid offset");
                return;
            }
        };
        // Note that last_index has no invalid values
        let last_index: u16 = match mem.read_obj::<u16>(index_addr) {
            Ok(ret) => ret,
            Err(_) => return,
        };

        match mem.checked_offset(self.used_ring, (4 + self.actual_size() * 8) as usize) {
            Some(a) => {
                mem.write_obj(last_index, a).unwrap();
            }
            None => warn!("Can't update avail_event"),
        }

        // This fence ensures the guest sees the value we've just written.
        fence(Ordering::Release);
    }

    /// Return the value present in the used_event field of the avail ring.
    #[inline(always)]
    pub fn get_used_event(&self, mem: &GuestMemoryMmap) -> Option<Wrapping<u16>> {
        let avail_ring = self.avail_ring;
        let used_event_addr =
            match mem.checked_offset(avail_ring, (4 + self.actual_size() * 2) as usize) {
                Some(a) => a,
                None => {
                    warn!("Invalid offset looking for used_event");
                    return None;
                }
            };

        // This fence ensures we're seeing the latest update from the guest.
        fence(Ordering::Acquire);
        match mem.read_obj::<u16>(used_event_addr) {
            Ok(ret) => Some(Wrapping(ret)),
            Err(_) => None,
        }
    }

    /// Puts an available descriptor head into the used ring for use by the guest.
    pub fn add_used(&mut self, mem: &GuestMemoryMmap, desc_index: u16, len: u32) -> Option<u16> {
        if desc_index >= self.actual_size() {
            error!(
                "attempted to add out of bounds descriptor to used ring: {}",
                desc_index
            );
            return None;
        }

        let used_ring = self.used_ring;
        let next_used = u64::from(self.next_used.0 % self.actual_size());
        let used_elem = used_ring.unchecked_add(4 + next_used * 8);

        // These writes can't fail as we are guaranteed to be within the descriptor ring.
        mem.write_obj(u32::from(desc_index), used_elem).unwrap();
        mem.write_obj(len as u32, used_elem.unchecked_add(4))
            .unwrap();

        self.next_used += Wrapping(1);

        // This fence ensures all descriptor writes are visible before the index update is.
        fence(Ordering::Release);

        mem.write_obj(self.next_used.0 as u16, used_ring.unchecked_add(2))
            .unwrap();

        Some(self.next_used.0)
    }

    /// Goes back one position in the available descriptor chain offered by the driver.
    /// Rust does not support bidirectional iterators. This is the only way to revert the effect
    /// of an iterator increment on the queue.
    pub fn go_to_previous_position(&mut self) {
        self.next_avail -= Wrapping(1);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    extern crate vm_memory;

    use std::marker::PhantomData;
    use std::mem;

    pub use super::*;
    use vm_memory::{GuestAddress, GuestMemoryMmap, GuestUsize};

    // Represents a location in GuestMemoryMmap which holds a given type.
    pub struct SomeplaceInMemory<'a, T> {
        pub location: GuestAddress,
        mem: &'a GuestMemoryMmap,
        phantom: PhantomData<*const T>,
    }

    // The ByteValued trait is required to use mem.read_obj and write_obj.
    impl<'a, T> SomeplaceInMemory<'a, T>
    where
        T: vm_memory::ByteValued,
    {
        fn new(location: GuestAddress, mem: &'a GuestMemoryMmap) -> Self {
            SomeplaceInMemory {
                location,
                mem,
                phantom: PhantomData,
            }
        }

        // Reads from the actual memory location.
        pub fn get(&self) -> T {
            self.mem.read_obj(self.location).unwrap()
        }

        // Writes to the actual memory location.
        pub fn set(&self, val: T) {
            self.mem.write_obj(val, self.location).unwrap()
        }

        // This function returns a place in memory which holds a value of type U, and starts
        // offset bytes after the current location.
        fn map_offset<U>(&self, offset: GuestUsize) -> SomeplaceInMemory<'a, U> {
            SomeplaceInMemory {
                location: self.location.checked_add(offset).unwrap(),
                mem: self.mem,
                phantom: PhantomData,
            }
        }

        // This function returns a place in memory which holds a value of type U, and starts
        // immediately after the end of self (which is location + sizeof(T)).
        fn next_place<U>(&self) -> SomeplaceInMemory<'a, U> {
            self.map_offset::<U>(mem::size_of::<T>() as u64)
        }

        fn end(&self) -> GuestAddress {
            self.location
                .checked_add(mem::size_of::<T>() as u64)
                .unwrap()
        }
    }

    // Represents a virtio descriptor in guest memory.
    pub struct VirtqDesc<'a> {
        pub addr: SomeplaceInMemory<'a, u64>,
        pub len: SomeplaceInMemory<'a, u32>,
        pub flags: SomeplaceInMemory<'a, u16>,
        pub next: SomeplaceInMemory<'a, u16>,
    }

    impl<'a> VirtqDesc<'a> {
        fn new(start: GuestAddress, mem: &'a GuestMemoryMmap) -> Self {
            assert_eq!(start.0 & 0xf, 0);

            let addr = SomeplaceInMemory::new(start, mem);
            let len = addr.next_place();
            let flags = len.next_place();
            let next = flags.next_place();

            VirtqDesc {
                addr,
                len,
                flags,
                next,
            }
        }

        fn start(&self) -> GuestAddress {
            self.addr.location
        }

        fn end(&self) -> GuestAddress {
            self.next.end()
        }

        pub fn set(&self, addr: u64, len: u32, flags: u16, next: u16) {
            self.addr.set(addr);
            self.len.set(len);
            self.flags.set(flags);
            self.next.set(next);
        }
    }

    // Represents a virtio queue ring. The only difference between the used and available rings,
    // is the ring element type.
    pub struct VirtqRing<'a, T> {
        pub flags: SomeplaceInMemory<'a, u16>,
        pub idx: SomeplaceInMemory<'a, u16>,
        pub ring: Vec<SomeplaceInMemory<'a, T>>,
        pub event: SomeplaceInMemory<'a, u16>,
    }

    impl<'a, T> VirtqRing<'a, T>
    where
        T: vm_memory::ByteValued,
    {
        fn new(
            start: GuestAddress,
            mem: &'a GuestMemoryMmap,
            qsize: u16,
            alignment: GuestUsize,
        ) -> Self {
            assert_eq!(start.0 & (alignment - 1), 0);

            let flags = SomeplaceInMemory::new(start, mem);
            let idx = flags.next_place();

            let mut ring = Vec::with_capacity(qsize as usize);

            ring.push(idx.next_place());

            for _ in 1..qsize as usize {
                let x = ring.last().unwrap().next_place();
                ring.push(x)
            }

            let event = ring.last().unwrap().next_place();

            flags.set(0);
            idx.set(0);
            event.set(0);

            VirtqRing {
                flags,
                idx,
                ring,
                event,
            }
        }

        pub fn end(&self) -> GuestAddress {
            self.event.end()
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct VirtqUsedElem {
        pub id: u32,
        pub len: u32,
    }

    unsafe impl vm_memory::ByteValued for VirtqUsedElem {}

    pub type VirtqAvail<'a> = VirtqRing<'a, u16>;
    pub type VirtqUsed<'a> = VirtqRing<'a, VirtqUsedElem>;

    pub struct VirtQueue<'a> {
        pub dtable: Vec<VirtqDesc<'a>>,
        pub avail: VirtqAvail<'a>,
        pub used: VirtqUsed<'a>,
    }

    impl<'a> VirtQueue<'a> {
        // We try to make sure things are aligned properly :-s
        pub fn new(start: GuestAddress, mem: &'a GuestMemoryMmap, qsize: u16) -> Self {
            // power of 2?
            assert!(qsize > 0 && qsize & (qsize - 1) == 0);

            let mut dtable = Vec::with_capacity(qsize as usize);

            let mut end = start;

            for _ in 0..qsize {
                let d = VirtqDesc::new(end, mem);
                end = d.end();
                dtable.push(d);
            }

            const AVAIL_ALIGN: u64 = 2;

            let avail = VirtqAvail::new(end, mem, qsize, AVAIL_ALIGN);

            const USED_ALIGN: u64 = 4;

            let mut x = avail.end().0;
            x = (x + USED_ALIGN - 1) & !(USED_ALIGN - 1);

            let used = VirtqUsed::new(GuestAddress(x), mem, qsize, USED_ALIGN);

            VirtQueue {
                dtable,
                avail,
                used,
            }
        }

        fn size(&self) -> u16 {
            self.dtable.len() as u16
        }

        fn dtable_start(&self) -> GuestAddress {
            self.dtable.first().unwrap().start()
        }

        fn avail_start(&self) -> GuestAddress {
            self.avail.flags.location
        }

        fn used_start(&self) -> GuestAddress {
            self.used.flags.location
        }

        // Creates a new Queue, using the underlying memory regions represented by the VirtQueue.
        pub fn create_queue(&self) -> Queue {
            let mut q = Queue::new(self.size());

            q.size = self.size();
            q.ready = true;
            q.desc_table = self.dtable_start();
            q.avail_ring = self.avail_start();
            q.used_ring = self.used_start();

            q
        }

        pub fn start(&self) -> GuestAddress {
            self.dtable_start()
        }

        pub fn end(&self) -> GuestAddress {
            self.used.end()
        }
    }

    #[test]
    fn test_checked_new_descriptor_chain() {
        let m = &GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let vq = VirtQueue::new(GuestAddress(0), m, 16);

        assert!(vq.end().0 < 0x1000);

        // index >= queue_size
        assert!(DescriptorChain::checked_new(m, vq.start(), 16, 16, None).is_none());

        // desc_table address is way off
        assert!(
            DescriptorChain::checked_new(m, GuestAddress(0x00ff_ffff_ffff), 16, 0, None).is_none()
        );

        // the addr field of the descriptor is way off
        vq.dtable[0].addr.set(0x0fff_ffff_ffff);
        assert!(DescriptorChain::checked_new(m, vq.start(), 16, 0, None).is_none());

        // let's create some invalid chains

        {
            // the addr field of the desc is ok now
            vq.dtable[0].addr.set(0x1000);
            // ...but the length is too large
            vq.dtable[0].len.set(0xffff_ffff);
            assert!(DescriptorChain::checked_new(m, vq.start(), 16, 0, None).is_none());
        }

        {
            // the first desc has a normal len now, and the next_descriptor flag is set
            vq.dtable[0].len.set(0x1000);
            vq.dtable[0].flags.set(VIRTQ_DESC_F_NEXT);
            //..but the the index of the next descriptor is too large
            vq.dtable[0].next.set(16);

            assert!(DescriptorChain::checked_new(m, vq.start(), 16, 0, None).is_none());
        }

        // finally, let's test an ok chain

        {
            vq.dtable[0].next.set(1);
            vq.dtable[1].set(0x2000, 0x1000, 0, 0);

            let c = DescriptorChain::checked_new(m, vq.start(), 16, 0, None).unwrap();

            assert_eq!(c.mem as *const GuestMemoryMmap, m as *const GuestMemoryMmap);
            assert_eq!(c.desc_table, vq.start());
            assert_eq!(c.table_size, 16);
            assert_eq!(c.ttl, c.table_size);
            assert_eq!(c.index, 0);
            assert_eq!(c.addr, GuestAddress(0x1000));
            assert_eq!(c.len, 0x1000);
            assert_eq!(c.flags, VIRTQ_DESC_F_NEXT);
            assert_eq!(c.next, 1);

            assert!(c.next_descriptor().unwrap().next_descriptor().is_none());
        }
    }

    #[test]
    fn test_new_from_descriptor_chain() {
        let m = &GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let vq = VirtQueue::new(GuestAddress(0), m, 16);

        // create a chain with a descriptor pointing to an indirect table
        vq.dtable[0].addr.set(0x1000);
        vq.dtable[0].len.set(0x1000);
        vq.dtable[0].next.set(0);
        vq.dtable[0].flags.set(VIRTQ_DESC_F_INDIRECT);

        let c = DescriptorChain::checked_new(m, vq.start(), 16, 0, None).unwrap();
        assert!(c.is_indirect());

        // create an indirect table with 4 chained descriptors
        let mut indirect_table = Vec::with_capacity(4 as usize);
        for j in 0..4 {
            let desc = VirtqDesc::new(GuestAddress(0x1000 + (j * 16)), m);
            desc.set(0x1000, 0x1000, VIRTQ_DESC_F_NEXT, (j + 1) as u16);
            indirect_table.push(desc);
        }

        // try to iterate through the indirect table descriptors
        let mut i = c.new_from_indirect().unwrap();
        for j in 0..4 {
            assert_eq!(i.flags, VIRTQ_DESC_F_NEXT);
            assert_eq!(i.next, j + 1);
            i = i.next_descriptor().unwrap();
        }
    }

    #[test]
    fn test_queue_and_iterator() {
        let m = &GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let vq = VirtQueue::new(GuestAddress(0), m, 16);

        let mut q = vq.create_queue();

        // q is currently valid
        assert!(q.is_valid(m));

        // shouldn't be valid when not marked as ready
        q.ready = false;
        assert!(!q.is_valid(m));
        q.ready = true;

        // or when size > max_size
        q.size = q.max_size << 1;
        assert!(!q.is_valid(m));
        q.size = q.max_size;

        // or when size is 0
        q.size = 0;
        assert!(!q.is_valid(m));
        q.size = q.max_size;

        // or when size is not a power of 2
        q.size = 11;
        assert!(!q.is_valid(m));
        q.size = q.max_size;

        // or if the various addresses are off

        q.desc_table = GuestAddress(0xffff_ffff);
        assert!(!q.is_valid(m));
        q.desc_table = GuestAddress(0x1001);
        assert!(!q.is_valid(m));
        q.desc_table = vq.dtable_start();

        q.avail_ring = GuestAddress(0xffff_ffff);
        assert!(!q.is_valid(m));
        q.avail_ring = GuestAddress(0x1001);
        assert!(!q.is_valid(m));
        q.avail_ring = vq.avail_start();

        q.used_ring = GuestAddress(0xffff_ffff);
        assert!(!q.is_valid(m));
        q.used_ring = GuestAddress(0x1001);
        assert!(!q.is_valid(m));
        q.used_ring = vq.used_start();

        {
            // an invalid queue should return an iterator with no next
            q.ready = false;
            let mut i = q.iter(m);
            assert!(i.next().is_none());
        }

        q.ready = true;

        // now let's create two simple descriptor chains

        {
            for j in 0..5 {
                vq.dtable[j].set(
                    0x1000 * (j + 1) as u64,
                    0x1000,
                    VIRTQ_DESC_F_NEXT,
                    (j + 1) as u16,
                );
            }

            // the chains are (0, 1) and (2, 3, 4)
            vq.dtable[1].flags.set(0);
            vq.dtable[4].flags.set(0);
            vq.avail.ring[0].set(0);
            vq.avail.ring[1].set(2);
            vq.avail.idx.set(2);

            let mut i = q.iter(m);

            {
                let mut c = i.next().unwrap();
                c = c.next_descriptor().unwrap();
                assert!(!c.has_next());
            }

            {
                let mut c = i.next().unwrap();
                c = c.next_descriptor().unwrap();
                c = c.next_descriptor().unwrap();
                assert!(!c.has_next());
            }
        }

        // also test go_to_previous_position() works as expected
        {
            assert!(q.iter(m).next().is_none());
            q.go_to_previous_position();
            let mut c = q.iter(m).next().unwrap();
            c = c.next_descriptor().unwrap();
            c = c.next_descriptor().unwrap();
            assert!(!c.has_next());
        }
    }

    #[test]
    fn test_add_used() {
        let m = &GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let vq = VirtQueue::new(GuestAddress(0), m, 16);

        let mut q = vq.create_queue();
        assert_eq!(vq.used.idx.get(), 0);

        //index too large
        q.add_used(m, 16, 0x1000);
        assert_eq!(vq.used.idx.get(), 0);

        //should be ok
        q.add_used(m, 1, 0x1000);
        assert_eq!(vq.used.idx.get(), 1);
        let x = vq.used.ring[0].get();
        assert_eq!(x.id, 1);
        assert_eq!(x.len, 0x1000);
    }
}
