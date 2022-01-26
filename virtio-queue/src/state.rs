// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright (C) 2020-2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::mem::size_of;
use std::num::Wrapping;
use std::ops::Deref;
use std::sync::atomic::{fence, Ordering};
use std::sync::Arc;

use vm_memory::{Address, Bytes, GuestAddress, GuestMemory};

use crate::defs::{
    DEFAULT_AVAIL_RING_ADDR, DEFAULT_DESC_TABLE_ADDR, DEFAULT_USED_RING_ADDR,
    VIRTQ_AVAIL_ELEMENT_SIZE, VIRTQ_AVAIL_RING_HEADER_SIZE, VIRTQ_AVAIL_RING_META_SIZE,
    VIRTQ_MSI_NO_VECTOR, VIRTQ_USED_ELEMENT_SIZE, VIRTQ_USED_F_NO_NOTIFY,
    VIRTQ_USED_RING_HEADER_SIZE, VIRTQ_USED_RING_META_SIZE,
};
use crate::{
    error, AccessPlatform, AvailIter, Descriptor, Error, QueueStateGuard, QueueStateT,
    VirtqUsedElem,
};

/// Struct to maintain information and manipulate state of a virtio queue.
#[derive(Clone, Debug)]
pub struct QueueState {
    /// The maximum size in elements offered by the device.
    pub max_size: u16,

    /// Tail position of the available ring.
    pub next_avail: Wrapping<u16>,

    /// Head position of the used ring.
    pub next_used: Wrapping<u16>,

    /// VIRTIO_F_RING_EVENT_IDX negotiated.
    pub event_idx_enabled: bool,

    /// The last used value when using VIRTIO_F_EVENT_IDX.
    pub signalled_used: Option<Wrapping<u16>>,

    /// The queue size in elements the driver selected.
    pub size: u16,

    /// Indicates if the queue is finished with configuration.
    pub ready: bool,

    /// Guest physical address of the descriptor table.
    pub desc_table: GuestAddress,

    /// Guest physical address of the available ring.
    pub avail_ring: GuestAddress,

    /// Guest physical address of the used ring.
    pub used_ring: GuestAddress,

    /// Interrupt vector
    pub vector: u16,

    /// Access platform handler
    pub access_platform: Option<Arc<dyn AccessPlatform>>,
}

impl QueueState {
    /// Get a consuming iterator over all available descriptor chain heads offered by the driver.
    ///
    /// # Arguments
    /// * `mem` - the `GuestMemory` object that can be used to access the queue buffers.
    pub fn iter<M>(&mut self, mem: M) -> Result<AvailIter<'_, M>, Error>
    where
        M: Deref,
        M::Target: GuestMemory + Sized,
    {
        self.avail_idx(mem.deref(), Ordering::Acquire)
            .map(move |idx| AvailIter::new(mem, idx, self))
    }

    // Helper method that writes `val` to the `avail_event` field of the used ring, using
    // the provided ordering.
    fn set_avail_event<M: GuestMemory>(
        &self,
        mem: &M,
        val: u16,
        order: Ordering,
    ) -> Result<(), Error> {
        // This can not overflow an u64 since it is working with relatively small numbers compared
        // to u64::MAX.
        let avail_event_offset =
            VIRTQ_USED_RING_HEADER_SIZE + VIRTQ_USED_ELEMENT_SIZE * u64::from(self.size);
        let addr = self
            .used_ring
            .checked_add(avail_event_offset)
            .ok_or(Error::AddressOverflow)?;

        mem.store(u16::to_le(val), addr, order)
            .map_err(Error::GuestMemory)
    }

    // Set the value of the `flags` field of the used ring, applying the specified ordering.
    fn set_used_flags<M: GuestMemory>(
        &mut self,
        mem: &M,
        val: u16,
        order: Ordering,
    ) -> Result<(), Error> {
        mem.store(u16::to_le(val), self.used_ring, order)
            .map_err(Error::GuestMemory)
    }

    // Write the appropriate values to enable or disable notifications from the driver.
    //
    // Every access in this method uses `Relaxed` ordering because a fence is added by the caller
    // when appropriate.
    fn set_notification<M: GuestMemory>(&mut self, mem: &M, enable: bool) -> Result<(), Error> {
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

    // Return the value present in the used_event field of the avail ring.
    //
    // If the VIRTIO_F_EVENT_IDX feature bit is not negotiated, the flags field in the available
    // ring offers a crude mechanism for the driver to inform the device that it doesn’t want
    // interrupts when buffers are used. Otherwise virtq_avail.used_event is a more performant
    // alternative where the driver specifies how far the device can progress before interrupting.
    //
    // Neither of these interrupt suppression methods are reliable, as they are not synchronized
    // with the device, but they serve as useful optimizations. So we only ensure access to the
    // virtq_avail.used_event is atomic, but do not need to synchronize with other memory accesses.
    fn used_event<M: GuestMemory>(&self, mem: &M, order: Ordering) -> Result<Wrapping<u16>, Error> {
        // This can not overflow an u64 since it is working with relatively small numbers compared
        // to u64::MAX.
        let used_event_offset =
            VIRTQ_AVAIL_RING_HEADER_SIZE + u64::from(self.size) * VIRTQ_AVAIL_ELEMENT_SIZE;
        let used_event_addr = self
            .avail_ring
            .checked_add(used_event_offset)
            .ok_or(Error::AddressOverflow)?;

        mem.load(used_event_addr, order)
            .map(u16::from_le)
            .map(Wrapping)
            .map_err(Error::GuestMemory)
    }

    /// Set the queue to "ready", and update desc_table, avail_ring and
    /// used_ring addresses based on the AccessPlatform handler.
    pub fn enable(&mut self, set: bool) {
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

impl<'a> QueueStateGuard<'a> for QueueState {
    type G = &'a mut Self;
}

impl QueueStateT for QueueState {
    fn new(max_size: u16) -> Self {
        QueueState {
            max_size,
            size: max_size,
            ready: false,
            desc_table: GuestAddress(DEFAULT_DESC_TABLE_ADDR),
            avail_ring: GuestAddress(DEFAULT_AVAIL_RING_ADDR),
            used_ring: GuestAddress(DEFAULT_USED_RING_ADDR),
            next_avail: Wrapping(0),
            next_used: Wrapping(0),
            event_idx_enabled: false,
            signalled_used: None,
            vector: VIRTQ_MSI_NO_VECTOR,
            access_platform: None,
        }
    }

    fn is_valid<M: GuestMemory>(&self, mem: &M) -> bool {
        let queue_size = self.size as u64;
        let desc_table = self.desc_table;
        // The multiplication can not overflow an u64 since we are multiplying an u16 with a
        // small number.
        let desc_table_size = size_of::<Descriptor>() as u64 * queue_size;
        let avail_ring = self.avail_ring;
        // The operations below can not overflow an u64 since they're working with relatively small
        // numbers compared to u64::MAX.
        let avail_ring_size = VIRTQ_AVAIL_RING_META_SIZE + VIRTQ_AVAIL_ELEMENT_SIZE * queue_size;
        let used_ring = self.used_ring;
        let used_ring_size = VIRTQ_USED_RING_META_SIZE + VIRTQ_USED_ELEMENT_SIZE * queue_size;

        if !self.ready {
            error!("attempt to use virtio queue that is not marked ready");
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
        } else {
            true
        }
    }

    fn reset(&mut self) {
        self.ready = false;
        self.size = self.max_size;
        self.desc_table = GuestAddress(DEFAULT_DESC_TABLE_ADDR);
        self.avail_ring = GuestAddress(DEFAULT_AVAIL_RING_ADDR);
        self.used_ring = GuestAddress(DEFAULT_USED_RING_ADDR);
        self.next_avail = Wrapping(0);
        self.next_used = Wrapping(0);
        self.signalled_used = None;
        self.event_idx_enabled = false;
        self.vector = VIRTQ_MSI_NO_VECTOR;
    }

    fn lock(&mut self) -> <Self as QueueStateGuard>::G {
        self
    }

    fn max_size(&self) -> u16 {
        self.max_size
    }

    fn set_size(&mut self, size: u16) {
        if size > self.max_size() || size == 0 || (size & (size - 1)) != 0 {
            error!("virtio queue with invalid size: {}", size);
            return;
        }
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

        let desc_table = GuestAddress((high << 32) | low);
        if desc_table.mask(0xf) != 0 {
            error!("virtio queue descriptor table breaks alignment constraints");
            return;
        }
        self.desc_table = desc_table;
    }

    fn set_avail_ring_address(&mut self, low: Option<u32>, high: Option<u32>) {
        let low = low.unwrap_or(self.avail_ring.0 as u32) as u64;
        let high = high.unwrap_or((self.avail_ring.0 >> 32) as u32) as u64;

        let avail_ring = GuestAddress((high << 32) | low);
        if avail_ring.mask(0x1) != 0 {
            error!("virtio queue available ring breaks alignment constraints");
            return;
        }
        self.avail_ring = avail_ring;
    }

    fn set_used_ring_address(&mut self, low: Option<u32>, high: Option<u32>) {
        let low = low.unwrap_or(self.used_ring.0 as u32) as u64;
        let high = high.unwrap_or((self.used_ring.0 >> 32) as u32) as u64;

        let used_ring = GuestAddress((high << 32) | low);
        if used_ring.mask(0x3) != 0 {
            error!("virtio queue used ring breaks alignment constraints");
            return;
        }
        self.used_ring = used_ring;
    }

    fn set_event_idx(&mut self, enabled: bool) {
        self.signalled_used = None;
        self.event_idx_enabled = enabled;
    }

    fn avail_idx<M: GuestMemory>(&self, mem: &M, order: Ordering) -> Result<Wrapping<u16>, Error> {
        let addr = self
            .avail_ring
            .checked_add(2)
            .ok_or(Error::AddressOverflow)?;

        mem.load(addr, order)
            .map(u16::from_le)
            .map(Wrapping)
            .map_err(Error::GuestMemory)
    }

    fn used_idx<M: GuestMemory>(&self, mem: &M, order: Ordering) -> Result<Wrapping<u16>, Error> {
        let addr = self.used_ring.unchecked_add(2);

        mem.load(addr, order)
            .map(Wrapping)
            .map_err(Error::GuestMemory)
    }

    fn add_used<M: GuestMemory>(
        &mut self,
        mem: &M,
        head_index: u16,
        len: u32,
    ) -> Result<(), Error> {
        if head_index >= self.size {
            error!(
                "attempted to add out of bounds descriptor to used ring: {}",
                head_index
            );
            return Err(Error::InvalidDescriptorIndex);
        }

        let next_used_index = u64::from(self.next_used.0 % self.size);
        // This can not overflow an u64 since it is working with relatively small numbers compared
        // to u64::MAX.
        let offset = VIRTQ_USED_RING_HEADER_SIZE + next_used_index * VIRTQ_USED_ELEMENT_SIZE;
        let addr = self
            .used_ring
            .checked_add(offset)
            .ok_or(Error::AddressOverflow)?;
        mem.write_obj(VirtqUsedElem::new(head_index.into(), len), addr)
            .map_err(Error::GuestMemory)?;

        self.next_used += Wrapping(1);

        mem.store(
            u16::to_le(self.next_used.0),
            self.used_ring
                .checked_add(2)
                .ok_or(Error::AddressOverflow)?,
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
    fn enable_notification<M: GuestMemory>(&mut self, mem: &M) -> Result<bool, Error> {
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

    fn disable_notification<M: GuestMemory>(&mut self, mem: &M) -> Result<(), Error> {
        self.set_notification(mem, false)
    }

    fn needs_notification<M: GuestMemory>(&mut self, mem: &M) -> Result<bool, Error> {
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
