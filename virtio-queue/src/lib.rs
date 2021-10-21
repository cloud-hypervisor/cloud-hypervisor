// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2019 Intel Corporation
//
// Copyright (C) 2020-2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

//! Virtio queue API for backend device drivers to access virtio queues.

#![deny(missing_docs)]

pub mod defs;

use std::cmp::min;
use std::convert::TryFrom;
use std::fmt::{self, Debug, Display};
use std::marker::PhantomData;
use std::mem::size_of;
use std::num::Wrapping;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{fence, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use log::error;
use vm_memory::{
    Address, ByteValued, Bytes, GuestAddress, GuestAddressSpace, GuestMemory, GuestMemoryError,
};

use self::defs::{
    VIRTQ_AVAIL_ELEMENT_SIZE, VIRTQ_AVAIL_RING_HEADER_SIZE, VIRTQ_AVAIL_RING_META_SIZE,
    VIRTQ_DESCRIPTOR_SIZE, VIRTQ_DESC_F_INDIRECT, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE,
    VIRTQ_MSI_NO_VECTOR, VIRTQ_USED_ELEMENT_SIZE, VIRTQ_USED_F_NO_NOTIFY,
    VIRTQ_USED_RING_HEADER_SIZE, VIRTQ_USED_RING_META_SIZE,
};

/// Trait for devices with access to data in memory being limited and/or
/// translated.
pub trait AccessPlatform: Send + Sync + Debug {
    /// Provide a way to translate address ranges.
    fn translate(&self, base: u64, size: u64) -> std::result::Result<u64, std::io::Error>;
}

/// Virtio Queue related errors.
#[derive(Debug)]
pub enum Error {
    /// Failed to access guest memory.
    GuestMemory(GuestMemoryError),
    /// Invalid indirect descriptor.
    InvalidIndirectDescriptor,
    /// Invalid indirect descriptor table.
    InvalidIndirectDescriptorTable,
    /// Invalid descriptor chain.
    InvalidChain,
    /// Invalid descriptor index.
    InvalidDescriptorIndex,
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            GuestMemory(_) => write!(f, "error accessing guest memory"),
            InvalidChain => write!(f, "invalid descriptor chain"),
            InvalidIndirectDescriptor => write!(f, "invalid indirect descriptor"),
            InvalidIndirectDescriptorTable => write!(f, "invalid indirect descriptor table"),
            InvalidDescriptorIndex => write!(f, "invalid descriptor index"),
        }
    }
}

impl std::error::Error for Error {}

/// A virtio descriptor constraints with C representation.
#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
pub struct Descriptor {
    /// Guest physical address of device specific data
    addr: u64,

    /// Length of device specific data
    len: u32,

    /// Includes next, write, and indirect bits
    flags: u16,

    /// Index into the descriptor table of the next descriptor if flags has
    /// the next bit set
    next: u16,
}

#[allow(clippy::len_without_is_empty)]
impl Descriptor {
    /// Creates a new descriptor
    #[cfg(any(test, feature = "test-utils"))]
    pub fn new(addr: u64, len: u32, flags: u16, next: u16) -> Self {
        Descriptor {
            addr,
            len,
            flags,
            next,
        }
    }

    /// Return the guest physical address of descriptor buffer
    pub fn addr(&self) -> GuestAddress {
        GuestAddress(self.addr)
    }

    /// Return the length of descriptor buffer
    pub fn len(&self) -> u32 {
        self.len
    }

    /// Return the flags for this descriptor, including next, write and indirect
    /// bits
    pub fn flags(&self) -> u16 {
        self.flags
    }

    /// Return the value stored in the `next` field of the descriptor.
    pub fn next(&self) -> u16 {
        self.next
    }

    /// Check whether this is an indirect descriptor.
    pub fn is_indirect(&self) -> bool {
        // TODO: The are a couple of restrictions in terms of which flags combinations are
        // actually valid for indirect descriptors. Implement those checks as well somewhere.
        self.flags() & VIRTQ_DESC_F_INDIRECT != 0
    }

    /// Check whether the `VIRTQ_DESC_F_NEXT` is set for the descriptor.
    pub fn has_next(&self) -> bool {
        self.flags() & VIRTQ_DESC_F_NEXT != 0
    }

    /// Checks if the driver designated this as a write only descriptor.
    ///
    /// If this is false, this descriptor is read only.
    /// Write only means the the emulated device can write and the driver can read.
    pub fn is_write_only(&self) -> bool {
        self.flags & VIRTQ_DESC_F_WRITE != 0
    }
}

unsafe impl ByteValued for Descriptor {}

/// A virtio descriptor chain.
#[derive(Clone, Debug)]
pub struct DescriptorChain<M: GuestAddressSpace> {
    mem: M::T,
    desc_table: GuestAddress,
    queue_size: u16,
    head_index: u16,
    next_index: u16,
    ttl: u16,
    is_indirect: bool,
    access_platform: Option<Arc<dyn AccessPlatform>>,
}

impl<M: GuestAddressSpace> DescriptorChain<M> {
    fn with_ttl(
        mem: M::T,
        desc_table: GuestAddress,
        queue_size: u16,
        ttl: u16,
        head_index: u16,
        access_platform: Option<Arc<dyn AccessPlatform>>,
    ) -> Self {
        DescriptorChain {
            mem,
            desc_table,
            queue_size,
            head_index,
            next_index: head_index,
            ttl,
            is_indirect: false,
            access_platform,
        }
    }

    /// Create a new `DescriptorChain` instance.
    fn new(
        mem: M::T,
        desc_table: GuestAddress,
        queue_size: u16,
        head_index: u16,
        access_platform: Option<Arc<dyn AccessPlatform>>,
    ) -> Self {
        Self::with_ttl(
            mem,
            desc_table,
            queue_size,
            queue_size,
            head_index,
            access_platform,
        )
    }

    /// Get the descriptor index of the chain header
    pub fn head_index(&self) -> u16 {
        self.head_index
    }

    /// Return a `GuestMemory` object that can be used to access the buffers
    /// pointed to by the descriptor chain.
    pub fn memory(&self) -> &M::M {
        &*self.mem
    }

    /// Returns an iterator that only yields the readable descriptors in the chain.
    pub fn readable(self) -> DescriptorChainRwIter<M> {
        DescriptorChainRwIter {
            chain: self,
            writable: false,
        }
    }

    /// Returns an iterator that only yields the writable descriptors in the chain.
    pub fn writable(self) -> DescriptorChainRwIter<M> {
        DescriptorChainRwIter {
            chain: self,
            writable: true,
        }
    }

    // Alters the internal state of the `DescriptorChain` to switch iterating over an
    // indirect descriptor table defined by `desc`.
    fn process_indirect_descriptor(&mut self, desc: Descriptor) -> Result<(), Error> {
        if self.is_indirect {
            return Err(Error::InvalidIndirectDescriptor);
        }

        let table_len = (desc.len as usize) / VIRTQ_DESCRIPTOR_SIZE;
        // Check the target indirect descriptor table is correctly aligned.
        if desc.addr().raw_value() & (VIRTQ_DESCRIPTOR_SIZE as u64 - 1) != 0
            || (desc.len as usize) & (VIRTQ_DESCRIPTOR_SIZE - 1) != 0
            || table_len > usize::from(u16::MAX)
        {
            return Err(Error::InvalidIndirectDescriptorTable);
        }

        self.desc_table = desc.addr();
        // try_from cannot fail as we've checked table_len above
        self.queue_size = u16::try_from(table_len).expect("invalid table_len");
        self.next_index = 0;
        self.ttl = self.queue_size;
        self.is_indirect = true;

        Ok(())
    }
}

impl<M: GuestAddressSpace> Iterator for DescriptorChain<M> {
    type Item = Descriptor;

    /// Returns the next descriptor in this descriptor chain, if there is one.
    ///
    /// Note that this is distinct from the next descriptor chain returned by
    /// [`AvailIter`](struct.AvailIter.html), which is the head of the next
    /// _available_ descriptor chain.
    fn next(&mut self) -> Option<Self::Item> {
        if self.ttl == 0 || self.next_index >= self.queue_size {
            return None;
        }

        // It's ok to use `unchecked_add` here because we previously verify the index does not
        // exceed the queue size, and the descriptor table location is expected to have been
        // validate before (for example, before activating a device). Moreover, this cannot
        // lead to unsafety because the actual memory accesses are always checked.
        let desc_addr = self
            .desc_table
            .unchecked_add(self.next_index as u64 * size_of::<Descriptor>() as u64);

        // The guest device driver should not touch the descriptor once submitted, so it's safe
        // to use read_obj() here.
        let mut desc = self.mem.read_obj::<Descriptor>(desc_addr).ok()?;
        // When needed, it's very important to translate the decriptor address
        // before returning the Descriptor to the consumer.
        if let Some(access_platform) = &self.access_platform {
            desc.addr = access_platform
                .translate(desc.addr, u64::from(desc.len))
                .ok()?;
        }

        if desc.is_indirect() {
            self.process_indirect_descriptor(desc).ok()?;
            return self.next();
        }

        if desc.has_next() {
            self.next_index = desc.next();
            // It's ok to decrement `self.ttl` here because we check at the start of the method
            // that it's greater than 0.
            self.ttl -= 1;
        } else {
            self.ttl = 0;
        }

        Some(desc)
    }
}

/// An iterator for readable or writable descriptors.
#[derive(Clone)]
pub struct DescriptorChainRwIter<M: GuestAddressSpace> {
    chain: DescriptorChain<M>,
    writable: bool,
}

impl<M: GuestAddressSpace> Iterator for DescriptorChainRwIter<M> {
    type Item = Descriptor;

    /// Returns the next descriptor in this descriptor chain, if there is one.
    ///
    /// Note that this is distinct from the next descriptor chain returned by
    /// [`AvailIter`](struct.AvailIter.html), which is the head of the next
    /// _available_ descriptor chain.
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.chain.next() {
                Some(v) => {
                    if v.is_write_only() == self.writable {
                        return Some(v);
                    }
                }
                None => return None,
            }
        }
    }
}

// We can't derive Debug, because rustc doesn't generate the M::T: Debug
// constraint
impl<M: Debug + GuestAddressSpace> Debug for DescriptorChainRwIter<M>
where
    M::T: Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DescriptorChainRwIter")
            .field("chain", &self.chain)
            .field("writable", &self.writable)
            .finish()
    }
}

/// Consuming iterator over all available descriptor chain heads in the queue.
#[derive(Debug)]
pub struct AvailIter<'b, M: GuestAddressSpace> {
    mem: M::T,
    desc_table: GuestAddress,
    avail_ring: GuestAddress,
    last_index: Wrapping<u16>,
    queue_size: u16,
    next_avail: &'b mut Wrapping<u16>,
    access_platform: &'b Option<Arc<dyn AccessPlatform>>,
}

impl<'b, M: GuestAddressSpace> AvailIter<'b, M> {
    /// Goes back one position in the available descriptor chain offered by the driver.
    ///
    /// Rust does not support bidirectional iterators. This is the only way to revert the effect
    /// of an iterator increment on the queue.
    ///
    /// Note: this method assumes there's only one thread manipulating the queue, so it should only
    /// be invoked in single-threaded context.
    pub fn go_to_previous_position(&mut self) {
        *self.next_avail -= Wrapping(1);
    }
}

impl<'b, M: GuestAddressSpace> Iterator for AvailIter<'b, M> {
    type Item = DescriptorChain<M>;

    fn next(&mut self) -> Option<Self::Item> {
        if *self.next_avail == self.last_index {
            return None;
        }

        // This computation cannot overflow because all the values involved are actually
        // `u16`s cast to `u64`.
        let elem_off = u64::from(self.next_avail.0 % self.queue_size) * VIRTQ_AVAIL_ELEMENT_SIZE;
        let offset = VIRTQ_AVAIL_RING_HEADER_SIZE + elem_off;

        // The logic in `Queue::is_valid` ensures it's ok to use `unchecked_add` as long
        // as the index is within bounds. We do not currently enforce that a queue is only used
        // after checking `is_valid`, but rather expect the device implementations to do so
        // before activation. The standard also forbids drivers to change queue parameters
        // while the device is "running". A warp-around cannot lead to unsafe memory accesses
        // because the memory model performs its own validations.
        let addr = self.avail_ring.unchecked_add(offset);
        let head_index: u16 = self
            .mem
            .load(addr, Ordering::Acquire)
            .map_err(|_| error!("Failed to read from memory {:x}", addr.raw_value()))
            .ok()?;

        *self.next_avail += Wrapping(1);

        Some(DescriptorChain::new(
            self.mem.clone(),
            self.desc_table,
            self.queue_size,
            head_index,
            self.access_platform.clone(),
        ))
    }
}

/// Represents the contents of an element from the used virtqueue ring.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct VirtqUsedElem {
    id: u32,
    len: u32,
}

impl VirtqUsedElem {
    /// Create a new `VirtqUsedElem` instance.
    pub fn new(id: u16, len: u32) -> Self {
        VirtqUsedElem {
            id: u32::from(id),
            len,
        }
    }
}

unsafe impl ByteValued for VirtqUsedElem {}

/// Struct to hold an exclusive reference to the underlying `QueueState` object.
pub enum QueueStateGuard<'a, M: GuestAddressSpace> {
    /// A reference to a `QueueState` object.
    StateObject(&'a mut QueueState<M>),
    /// A `MutexGuard` for a `QueueState` object.
    MutexGuard(MutexGuard<'a, QueueState<M>>),
}

impl<'a, M: GuestAddressSpace> Deref for QueueStateGuard<'a, M> {
    type Target = QueueState<M>;

    fn deref(&self) -> &Self::Target {
        match self {
            QueueStateGuard::StateObject(v) => v,
            QueueStateGuard::MutexGuard(v) => v.deref(),
        }
    }
}

impl<'a, M: GuestAddressSpace> DerefMut for QueueStateGuard<'a, M> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            QueueStateGuard::StateObject(v) => v,
            QueueStateGuard::MutexGuard(v) => v.deref_mut(),
        }
    }
}

/// Trait to access and manipulate a virtio queue.
///
/// To optimize for performance, different implementations of the `QueueStateT` trait may be
/// provided for single-threaded context and multi-threaded context.
pub trait QueueStateT<M: GuestAddressSpace> {
    /// Construct an empty virtio queue state object with the given `max_size`.
    fn new(max_size: u16) -> Self;

    /// Check whether the queue configuration is valid.
    fn is_valid(&self, mem: &M::T) -> bool;

    /// Reset the queue to the initial state.
    fn reset(&mut self);

    /// Get an exclusive reference to the underlying `QueueState` object.
    ///
    /// Logically this method will acquire the underlying lock protecting the `QueueState` Object.
    /// The lock will be released when the returned object gets dropped.
    fn lock(&mut self) -> QueueStateGuard<'_, M>;

    /// Get the maximum size of the virtio queue.
    fn max_size(&self) -> u16;

    /// Return the actual size of the queue.
    ///
    /// The virtio driver may configure queue size smaller than the value reported by `max_size()`.
    fn actual_size(&self) -> u16;

    /// Configure the queue size for the virtio queue.
    ///
    /// The `size` should power of two and less than or equal to value reported by `max_size()`,
    /// otherwise it will panic.
    fn set_size(&mut self, size: u16);

    /// Check whether the queue is ready to be processed.
    fn ready(&self) -> bool;

    /// Configure the queue to ready for processing.
    fn set_ready(&mut self, ready: bool);

    /// Set descriptor table address for the queue.
    ///
    /// The descriptor table address is 64-bit, the corresponding part will be updated if 'low'
    /// and/or `high` is valid.
    fn set_desc_table_address(&mut self, low: Option<u32>, high: Option<u32>);

    /// Set available ring address for the queue.
    ///
    /// The available ring address is 64-bit, the corresponding part will be updated if 'low'
    /// and/or `high` is valid.
    fn set_avail_ring_address(&mut self, low: Option<u32>, high: Option<u32>);

    /// Set used ring address for the queue.
    ///
    /// The used ring address is 64-bit, the corresponding part will be updated if 'low'
    /// and/or `high` is valid.
    fn set_used_ring_address(&mut self, low: Option<u32>, high: Option<u32>);

    /// Enable/disable the VIRTIO_F_RING_EVENT_IDX feature for interrupt coalescing.
    fn set_event_idx(&mut self, enabled: bool);

    /// Read the `idx` field from the available ring.
    fn avail_idx(&self, mem: &M::T, order: Ordering) -> Result<Wrapping<u16>, Error>;

    /// Read the `idx` field from the used ring.
    fn used_idx(&self, mem: &M::T, order: Ordering) -> Result<Wrapping<u16>, Error>;

    /// Put a used descriptor head into the used ring.
    fn add_used(&mut self, mem: &M::T, head_index: u16, len: u32) -> Result<(), Error>;

    /// Enable notification events from the guest driver.
    ///
    /// Return true if one or more descriptors can be consumed from the available ring after
    /// notifications were enabled (and thus it's possible there will be no corresponding
    /// notification).
    fn enable_notification(&mut self, mem: &M::T) -> Result<bool, Error>;

    /// Disable notification events from the guest driver.
    fn disable_notification(&mut self, mem: &M::T) -> Result<(), Error>;

    /// Check whether a notification to the guest is needed.
    ///
    /// Please note this method has side effects: once it returns `true`, it considers the
    /// driver will actually be notified, remember the associated index in the used ring, and
    /// won't return `true` again until the driver updates `used_event` and/or the notification
    /// conditions hold once more.
    fn needs_notification(&mut self, mem: &M::T) -> Result<bool, Error>;

    /// Return the index for the next descriptor in the available ring.
    fn next_avail(&self) -> u16;

    /// Return the index for the next descriptor in the used ring.
    fn next_used(&self) -> u16;

    /// Set the index for the next descriptor in the available ring.
    fn set_next_avail(&mut self, next_avail: u16);

    /// Set the index for the next descriptor in the used ring.
    fn set_next_used(&mut self, next_used: u16);
}

/// Struct to maintain information and manipulate state of a virtio queue.
#[derive(Clone, Debug)]
pub struct QueueState<M: GuestAddressSpace> {
    /// The maximal size in elements offered by the device
    pub max_size: u16,

    /// Tail position of the available ring.
    pub next_avail: Wrapping<u16>,

    /// Head position of the used ring.
    pub next_used: Wrapping<u16>,

    /// VIRTIO_F_RING_EVENT_IDX negotiated
    pub event_idx_enabled: bool,

    /// The last used value when using EVENT_IDX
    pub signalled_used: Option<Wrapping<u16>>,

    /// The queue size in elements the driver selected
    pub size: u16,

    /// Indicates if the queue is finished with configuration
    pub ready: bool,

    /// Guest physical address of the descriptor table
    pub desc_table: GuestAddress,

    /// Guest physical address of the available ring
    pub avail_ring: GuestAddress,

    /// Guest physical address of the used ring
    pub used_ring: GuestAddress,

    phantom: PhantomData<M>,

    /// Interrupt vector
    pub vector: u16,

    /// Access platform handler
    pub access_platform: Option<Arc<dyn AccessPlatform>>,
}

impl<M: GuestAddressSpace> QueueState<M> {
    /// Get a consuming iterator over all available descriptor chain heads offered by the driver.
    pub fn iter(&mut self, mem: M::T) -> Result<AvailIter<'_, M>, Error> {
        self.avail_idx(&mem, Ordering::Acquire)
            .map(move |idx| AvailIter {
                mem,
                desc_table: self.desc_table,
                avail_ring: self.avail_ring,
                last_index: idx,
                queue_size: self.actual_size(),
                next_avail: &mut self.next_avail,
                access_platform: &self.access_platform,
            })
    }

    // Helper method that writes `val` to the `avail_event` field of the used ring, using
    // the provided ordering.
    fn set_avail_event(&self, mem: &M::T, val: u16, order: Ordering) -> Result<(), Error> {
        let elem_sz = VIRTQ_USED_ELEMENT_SIZE * u64::from(self.actual_size());
        let offset = VIRTQ_USED_RING_HEADER_SIZE + elem_sz;
        let addr = self.used_ring.unchecked_add(offset);

        mem.store(val, addr, order).map_err(Error::GuestMemory)
    }

    // Set the value of the `flags` field of the used ring, applying the specified ordering.
    fn set_used_flags(&mut self, mem: &M::T, val: u16, order: Ordering) -> Result<(), Error> {
        mem.store(val, self.used_ring, order)
            .map_err(Error::GuestMemory)
    }

    // Write the appropriate values to enable or disable notifications from the driver.
    //
    // Every access in this method uses `Relaxed` ordering because a fence is added by the caller
    // when appropriate.
    fn set_notification(&mut self, mem: &M::T, enable: bool) -> Result<(), Error> {
        if enable {
            if self.event_idx_enabled {
                // We call `set_avail_event` using the `next_avail` value, instead of reading
                // and using the current `avail_idx` to avoid missing notifications. More
                // details in `enable_notification`.
                self.set_avail_event(mem, self.next_avail.0, Ordering::Relaxed)
            } else {
                self.set_used_flags(mem, 0, Ordering::Relaxed)
            }
        } else if !self.event_idx_enabled {
            self.set_used_flags(mem, VIRTQ_USED_F_NO_NOTIFY, Ordering::Relaxed)
        } else {
            // Notifications are effectively disabled by default after triggering once when
            // `VIRTIO_F_EVENT_IDX` is negotiated, so we don't do anything in that case.
            Ok(())
        }
    }

    /// Return the value present in the used_event field of the avail ring.
    ///
    /// If the VIRTIO_F_EVENT_IDX feature bit is not negotiated, the flags field in the available
    /// ring offers a crude mechanism for the driver to inform the device that it doesn’t want
    /// interrupts when buffers are used. Otherwise virtq_avail.used_event is a more performant
    /// alternative where the driver specifies how far the device can progress before interrupting.
    ///
    /// Neither of these interrupt suppression methods are reliable, as they are not synchronized
    /// with the device, but they serve as useful optimizations. So we only ensure access to the
    /// virtq_avail.used_event is atomic, but do not need to synchronize with other memory accesses.
    fn used_event(&self, mem: &M::T, order: Ordering) -> Result<Wrapping<u16>, Error> {
        // Safe because we have validated the queue and access guest
        // memory through GuestMemory interfaces.
        let elem_sz = u64::from(self.actual_size()) * VIRTQ_AVAIL_ELEMENT_SIZE;
        let offset = VIRTQ_AVAIL_RING_HEADER_SIZE + elem_sz;
        let used_event_addr = self.avail_ring.unchecked_add(offset);

        mem.load(used_event_addr, order)
            .map(Wrapping)
            .map_err(Error::GuestMemory)
    }

    /// Set the queue to "ready", and update desc_table, avail_ring and
    /// used_ring addresses based on the AccessPlatform handler.
    fn enable(&mut self, set: bool) {
        self.ready = set;

        if set {
            // Translate address of descriptor table and vrings.
            if let Some(access_platform) = &self.access_platform {
                self.desc_table =
                    GuestAddress(access_platform.translate(self.desc_table.0, 0).unwrap());
                self.avail_ring =
                    GuestAddress(access_platform.translate(self.avail_ring.0, 0).unwrap());
                self.used_ring =
                    GuestAddress(access_platform.translate(self.used_ring.0, 0).unwrap());
            }
        } else {
            self.desc_table = GuestAddress(0);
            self.avail_ring = GuestAddress(0);
            self.used_ring = GuestAddress(0);
        }
    }
}

impl<M: GuestAddressSpace> QueueStateT<M> for QueueState<M> {
    fn new(max_size: u16) -> Self {
        QueueState {
            max_size,
            size: max_size,
            ready: false,
            desc_table: GuestAddress(0),
            avail_ring: GuestAddress(0),
            used_ring: GuestAddress(0),
            next_avail: Wrapping(0),
            next_used: Wrapping(0),
            event_idx_enabled: false,
            signalled_used: None,
            phantom: PhantomData,
            vector: VIRTQ_MSI_NO_VECTOR,
            access_platform: None,
        }
    }

    fn is_valid(&self, mem: &M::T) -> bool {
        let queue_size = self.actual_size() as u64;
        let desc_table = self.desc_table;
        let desc_table_size = size_of::<Descriptor>() as u64 * queue_size;
        let avail_ring = self.avail_ring;
        let avail_ring_size = VIRTQ_AVAIL_RING_META_SIZE + VIRTQ_AVAIL_ELEMENT_SIZE * queue_size;
        let used_ring = self.used_ring;
        let used_ring_size = VIRTQ_USED_RING_META_SIZE + VIRTQ_USED_ELEMENT_SIZE * queue_size;
        if !self.ready {
            error!("attempt to use virtio queue that is not marked ready");
            false
        } else if self.size > self.max_size || self.size == 0 || (self.size & (self.size - 1)) != 0
        {
            error!("virtio queue with invalid size: {}", self.size);
            false
        } else if desc_table
            .checked_add(desc_table_size)
            .map_or(true, |v| !mem.address_in_range(v))
        {
            error!(
                "virtio queue descriptor table goes out of bounds: start:0x{:08x} size:0x{:08x}",
                desc_table.raw_value(),
                desc_table_size
            );
            false
        } else if avail_ring
            .checked_add(avail_ring_size)
            .map_or(true, |v| !mem.address_in_range(v))
        {
            error!(
                "virtio queue available ring goes out of bounds: start:0x{:08x} size:0x{:08x}",
                avail_ring.raw_value(),
                avail_ring_size
            );
            false
        } else if used_ring
            .checked_add(used_ring_size)
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

    fn reset(&mut self) {
        self.ready = false;
        self.size = self.max_size;
        self.desc_table = GuestAddress(0);
        self.avail_ring = GuestAddress(0);
        self.used_ring = GuestAddress(0);
        self.next_avail = Wrapping(0);
        self.next_used = Wrapping(0);
        self.signalled_used = None;
        self.event_idx_enabled = false;
        self.vector = VIRTQ_MSI_NO_VECTOR;
    }

    fn lock(&mut self) -> QueueStateGuard<'_, M> {
        QueueStateGuard::StateObject(self)
    }

    fn max_size(&self) -> u16 {
        self.max_size
    }

    fn actual_size(&self) -> u16 {
        min(self.size, self.max_size)
    }

    fn set_size(&mut self, size: u16) {
        self.size = size;
    }

    fn ready(&self) -> bool {
        self.ready
    }

    fn set_ready(&mut self, ready: bool) {
        self.ready = ready;
    }

    fn set_desc_table_address(&mut self, low: Option<u32>, high: Option<u32>) {
        let low = low.unwrap_or(self.desc_table.0 as u32) as u64;
        let high = high.unwrap_or((self.desc_table.0 >> 32) as u32) as u64;

        self.desc_table = GuestAddress((high << 32) | low);
    }

    fn set_avail_ring_address(&mut self, low: Option<u32>, high: Option<u32>) {
        let low = low.unwrap_or(self.avail_ring.0 as u32) as u64;
        let high = high.unwrap_or((self.avail_ring.0 >> 32) as u32) as u64;

        self.avail_ring = GuestAddress((high << 32) | low);
    }

    fn set_used_ring_address(&mut self, low: Option<u32>, high: Option<u32>) {
        let low = low.unwrap_or(self.used_ring.0 as u32) as u64;
        let high = high.unwrap_or((self.used_ring.0 >> 32) as u32) as u64;

        self.used_ring = GuestAddress((high << 32) | low);
    }

    fn set_event_idx(&mut self, enabled: bool) {
        self.signalled_used = None;
        self.event_idx_enabled = enabled;
    }

    fn avail_idx(&self, mem: &M::T, order: Ordering) -> Result<Wrapping<u16>, Error> {
        let addr = self.avail_ring.unchecked_add(2);

        mem.load(addr, order)
            .map(Wrapping)
            .map_err(Error::GuestMemory)
    }

    fn used_idx(&self, mem: &M::T, order: Ordering) -> Result<Wrapping<u16>, Error> {
        let addr = self.used_ring.unchecked_add(2);

        mem.load(addr, order)
            .map(Wrapping)
            .map_err(Error::GuestMemory)
    }

    fn add_used(&mut self, mem: &M::T, head_index: u16, len: u32) -> Result<(), Error> {
        if head_index >= self.actual_size() {
            error!(
                "attempted to add out of bounds descriptor to used ring: {}",
                head_index
            );
            return Err(Error::InvalidDescriptorIndex);
        }

        let next_used_index = u64::from(self.next_used.0 % self.actual_size());
        let elem_sz = next_used_index * VIRTQ_USED_ELEMENT_SIZE;
        let offset = VIRTQ_USED_RING_HEADER_SIZE + elem_sz;
        let addr = self.used_ring.unchecked_add(offset);
        mem.write_obj(VirtqUsedElem::new(head_index, len), addr)
            .map_err(Error::GuestMemory)?;

        self.next_used += Wrapping(1);

        mem.store(
            self.next_used.0,
            self.used_ring.unchecked_add(2),
            Ordering::Release,
        )
        .map_err(Error::GuestMemory)
    }

    // TODO: Turn this into a doc comment/example.
    // With the current implementation, a common way of consuming entries from the available ring
    // while also leveraging notification suppression is to use a loop, for example:
    //
    // loop {
    //     // We have to explicitly disable notifications if `VIRTIO_F_EVENT_IDX` has not been
    //     // negotiated.
    //     self.disable_notification()?;
    //
    //     for chain in self.iter()? {
    //         // Do something with each chain ...
    //         // Let's assume we process all available chains here.
    //     }
    //
    //     // If `enable_notification` returns `true`, the driver has added more entries to the
    //     // available ring.
    //     if !self.enable_notification()? {
    //         break;
    //     }
    // }
    fn enable_notification(&mut self, mem: &M::T) -> Result<bool, Error> {
        self.set_notification(mem, true)?;
        // Ensures the following read is not reordered before any previous write operation.
        fence(Ordering::SeqCst);

        // We double check here to avoid the situation where the available ring has been updated
        // just before we re-enabled notifications, and it's possible to miss one. We compare the
        // current `avail_idx` value to `self.next_avail` because it's where we stopped processing
        // entries. There are situations where we intentionally avoid processing everything in the
        // available ring (which will cause this method to return `true`), but in that case we'll
        // probably not re-enable notifications as we already know there are pending entries.
        self.avail_idx(mem, Ordering::Relaxed)
            .map(|idx| idx != self.next_avail)
    }

    fn disable_notification(&mut self, mem: &M::T) -> Result<(), Error> {
        self.set_notification(mem, false)
    }

    fn needs_notification(&mut self, mem: &M::T) -> Result<bool, Error> {
        let used_idx = self.next_used;

        // Complete all the writes in add_used() before reading the event.
        fence(Ordering::SeqCst);

        // The VRING_AVAIL_F_NO_INTERRUPT flag isn't supported yet.
        if self.event_idx_enabled {
            if let Some(old_idx) = self.signalled_used.replace(used_idx) {
                let used_event = self.used_event(mem, Ordering::Relaxed)?;
                // This check looks at `used_idx`, `used_event`, and `old_idx` as if they are on
                // an axis that wraps around. If `used_idx - used_used - Wrapping(1)` is greater
                // than or equal to the difference between `used_idx` and `old_idx`, then
                // `old_idx` is closer to `used_idx` than `used_event` (and thus more recent), so
                // we don't need to elicit another notification.
                if (used_idx - used_event - Wrapping(1u16)) >= (used_idx - old_idx) {
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }

    fn next_avail(&self) -> u16 {
        self.next_avail.0
    }

    fn next_used(&self) -> u16 {
        self.next_used.0
    }

    fn set_next_avail(&mut self, next_avail: u16) {
        self.next_avail = Wrapping(next_avail);
    }

    fn set_next_used(&mut self, next_used: u16) {
        self.next_used = Wrapping(next_used);
    }
}

/// Struct to maintain information and manipulate state of a virtio queue for multi-threaded
/// context.
#[derive(Clone, Debug)]
pub struct QueueStateSync<M: GuestAddressSpace> {
    state: Arc<Mutex<QueueState<M>>>,
}

impl<M: GuestAddressSpace> QueueStateT<M> for QueueStateSync<M> {
    fn new(max_size: u16) -> Self {
        QueueStateSync {
            state: Arc::new(Mutex::new(QueueState::new(max_size))),
        }
    }

    fn is_valid(&self, mem: &M::T) -> bool {
        self.state.lock().unwrap().is_valid(mem)
    }

    fn reset(&mut self) {
        self.state.lock().unwrap().reset();
    }

    fn lock(&mut self) -> QueueStateGuard<'_, M> {
        QueueStateGuard::MutexGuard(self.state.lock().unwrap())
    }

    fn max_size(&self) -> u16 {
        self.state.lock().unwrap().max_size()
    }

    fn actual_size(&self) -> u16 {
        self.state.lock().unwrap().actual_size()
    }

    fn set_size(&mut self, size: u16) {
        self.state.lock().unwrap().set_size(size)
    }

    fn ready(&self) -> bool {
        self.state.lock().unwrap().ready
    }

    fn set_ready(&mut self, ready: bool) {
        self.state.lock().unwrap().set_ready(ready)
    }

    fn set_desc_table_address(&mut self, low: Option<u32>, high: Option<u32>) {
        self.state.lock().unwrap().set_desc_table_address(low, high);
    }

    fn set_avail_ring_address(&mut self, low: Option<u32>, high: Option<u32>) {
        self.state.lock().unwrap().set_avail_ring_address(low, high);
    }

    fn set_used_ring_address(&mut self, low: Option<u32>, high: Option<u32>) {
        self.state.lock().unwrap().set_used_ring_address(low, high);
    }

    fn set_event_idx(&mut self, enabled: bool) {
        self.state.lock().unwrap().set_event_idx(enabled);
    }

    fn avail_idx(&self, mem: &M::T, order: Ordering) -> Result<Wrapping<u16>, Error> {
        self.state.lock().unwrap().avail_idx(mem, order)
    }

    fn used_idx(&self, mem: &M::T, order: Ordering) -> Result<Wrapping<u16>, Error> {
        self.state.lock().unwrap().used_idx(mem, order)
    }

    fn add_used(&mut self, mem: &M::T, head_index: u16, len: u32) -> Result<(), Error> {
        self.state.lock().unwrap().add_used(mem, head_index, len)
    }

    fn enable_notification(&mut self, mem: &M::T) -> Result<bool, Error> {
        self.state.lock().unwrap().enable_notification(mem)
    }

    fn disable_notification(&mut self, mem: &M::T) -> Result<(), Error> {
        self.state.lock().unwrap().disable_notification(mem)
    }

    fn needs_notification(&mut self, mem: &M::T) -> Result<bool, Error> {
        self.state.lock().unwrap().needs_notification(mem)
    }

    fn next_avail(&self) -> u16 {
        self.state.lock().unwrap().next_avail()
    }

    fn next_used(&self) -> u16 {
        self.state.lock().unwrap().next_used()
    }

    fn set_next_avail(&mut self, next_avail: u16) {
        self.state.lock().unwrap().set_next_avail(next_avail);
    }

    fn set_next_used(&mut self, next_used: u16) {
        self.state.lock().unwrap().set_next_used(next_used);
    }
}

/// A convenient wrapper struct for a virtio queue, with associated GuestMemory object.
#[derive(Clone, Debug)]
pub struct Queue<M: GuestAddressSpace, S: QueueStateT<M> = QueueState<M>> {
    /// Guest memory object associated with the queue.
    pub mem: M,
    /// Virtio queue state.
    pub state: S,
}

impl<M: GuestAddressSpace, S: QueueStateT<M>> Queue<M, S> {
    /// Construct an empty virtio queue with the given `max_size`.
    pub fn new(mem: M, max_size: u16) -> Self {
        Queue {
            mem,
            state: S::new(max_size),
        }
    }

    /// Check whether the queue configuration is valid.
    pub fn is_valid(&self) -> bool {
        self.state.is_valid(&self.mem.memory())
    }

    /// Reset the queue to the initial state.
    pub fn reset(&mut self) {
        self.state.reset()
    }

    /// Get an exclusive reference to the underlying `QueueState` object.
    ///
    /// Logically this method will acquire the underlying lock protecting the `QueueState` Object.
    /// The lock will be released when the returned object gets dropped.
    pub fn lock(&mut self) -> QueueStateGuard<'_, M> {
        self.state.lock()
    }

    /// Get the maximum size of the virtio queue.
    pub fn max_size(&self) -> u16 {
        self.state.max_size()
    }

    /// Return the actual size of the queue.
    ///
    /// The virtio driver may configure queue size smaller than the value reported by `max_size()`.
    pub fn actual_size(&self) -> u16 {
        self.state.actual_size()
    }

    /// Configure the queue size for the virtio queue.
    ///
    /// The `size` should power of two and less than or equal to value reported by `max_size()`,
    /// otherwise it will panic.
    pub fn set_size(&mut self, size: u16) {
        self.state.set_size(size)
    }

    /// Check whether the queue is ready to be processed.
    pub fn ready(&self) -> bool {
        self.state.ready()
    }

    /// Configure the queue to ready for processing.
    pub fn set_ready(&mut self, ready: bool) {
        self.state.set_ready(ready)
    }

    /// Set descriptor table address for the queue.
    ///
    /// The descriptor table address is 64-bit, the corresponding part will be updated if 'low'
    /// and/or `high` is valid.
    pub fn set_desc_table_address(&mut self, low: Option<u32>, high: Option<u32>) {
        self.state.set_desc_table_address(low, high);
    }

    /// Set available ring address for the queue.
    ///
    /// The available ring address is 64-bit, the corresponding part will be updated if 'low'
    /// and/or `high` is valid.
    pub fn set_avail_ring_address(&mut self, low: Option<u32>, high: Option<u32>) {
        self.state.set_avail_ring_address(low, high);
    }

    /// Set used ring address for the queue.
    ///
    /// The used ring address is 64-bit, the corresponding part will be updated if 'low'
    /// and/or `high` is valid.
    pub fn set_used_ring_address(&mut self, low: Option<u32>, high: Option<u32>) {
        self.state.set_used_ring_address(low, high)
    }

    /// Enable/disable the VIRTIO_F_RING_EVENT_IDX feature for interrupt coalescing.
    pub fn set_event_idx(&mut self, enabled: bool) {
        self.state.set_event_idx(enabled)
    }

    /// Read the `idx` field from the available ring.
    pub fn avail_idx(&self, order: Ordering) -> Result<Wrapping<u16>, Error> {
        self.state.avail_idx(&self.mem.memory(), order)
    }

    /// Reads the `idx` field from the used ring.
    pub fn used_idx(&self, order: Ordering) -> Result<Wrapping<u16>, Error> {
        self.state.used_idx(&self.mem.memory(), order)
    }

    /// Put a used descriptor head into the used ring.
    pub fn add_used(&mut self, head_index: u16, len: u32) -> Result<(), Error> {
        self.state.add_used(&self.mem.memory(), head_index, len)
    }

    /// Enable notification events from the guest driver.
    ///
    /// Return true if one or more descriptors can be consumed from the available ring after
    /// notifications were enabled (and thus it's possible there will be no corresponding
    /// notification).
    pub fn enable_notification(&mut self) -> Result<bool, Error> {
        self.state.enable_notification(&self.mem.memory())
    }

    /// Disable notification events from the guest driver.
    pub fn disable_notification(&mut self) -> Result<(), Error> {
        self.state.disable_notification(&self.mem.memory())
    }

    /// Check whether a notification to the guest is needed.
    ///
    /// Please note this method has side effects: once it returns `true`, it considers the
    /// driver will actually be notified, remember the associated index in the used ring, and
    /// won't return `true` again until the driver updates `used_event` and/or the notification
    /// conditions hold once more.
    pub fn needs_notification(&mut self) -> Result<bool, Error> {
        self.state.needs_notification(&self.mem.memory())
    }

    /// Return the index for the next descriptor in the available ring.
    pub fn next_avail(&self) -> u16 {
        self.state.next_avail()
    }

    /// Returns the index for the next descriptor in the used ring.
    pub fn next_used(&self) -> u16 {
        self.state.next_used()
    }

    /// Sets the index for the next descriptor in the available ring.
    pub fn set_next_avail(&mut self, next_avail: u16) {
        self.state.set_next_avail(next_avail);
    }

    /// Sets the index for the next descriptor in the used ring.
    pub fn set_next_used(&mut self, next_used: u16) {
        self.state.set_next_used(next_used);
    }
}

impl<M: GuestAddressSpace> Queue<M, QueueState<M>> {
    /// A consuming iterator over all available descriptor chain heads offered by the driver.
    pub fn iter(&mut self) -> Result<AvailIter<'_, M>, Error> {
        self.state.iter(self.mem.memory())
    }

    /// Set the queue to "ready", and update desc_table, avail_ring and
    /// used_ring addresses based on the AccessPlatform handler.
    pub fn enable(&mut self, set: bool) {
        self.state.enable(set)
    }
}
