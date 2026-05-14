// Copyright © 2026 Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0

//! Centralized descriptor buffer validation for virtio devices.
//!
//! This module provides [`CheckedDescriptorIter`], an iterator adapter over
//! [`DescriptorChain`] that validates each descriptor's buffer range against
//! guest memory before yielding it. Any descriptor whose translated
//! `(addr, len)` range is not fully backed by guest RAM is rejected, so the
//! device never performs I/O against memory the guest does not actually own.

use std::ops::Deref;

use log::warn;
use virtio_queue::DescriptorChain;
use virtio_queue::desc::split::Descriptor;
use vm_memory::{GuestAddress, GuestMemory};

use crate::{AccessPlatform, Translatable};

/// A descriptor whose buffer range has been validated against guest memory.
#[derive(Debug)]
pub struct CheckedDescriptor {
    inner: Descriptor,
    /// The translated guest physical address.
    addr: GuestAddress,
}

impl CheckedDescriptor {
    pub fn addr(&self) -> GuestAddress {
        self.addr
    }

    pub fn len(&self) -> u32 {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.len() == 0
    }

    pub fn is_write_only(&self) -> bool {
        self.inner.is_write_only()
    }

    pub fn has_next(&self) -> bool {
        self.inner.has_next()
    }
}

/// Iterator adapter that validates each descriptor's buffer against guest
/// memory before yielding it.
///
/// Each call to [`Iterator::next`] returns `Some(Ok(desc))` for a valid
/// descriptor, `Some(Err(addr))` when validation rejects a descriptor
/// (with the offending guest address), or `None` when the chain is
/// exhausted.
pub struct CheckedDescriptorIter<'a, M> {
    chain: &'a mut DescriptorChain<M>,
    access_platform: Option<&'a dyn AccessPlatform>,
    done: bool,
}

impl<'a, M> CheckedDescriptorIter<'a, M>
where
    M: Deref,
    M::Target: GuestMemory,
{
    pub fn new(
        chain: &'a mut DescriptorChain<M>,
        access_platform: Option<&'a dyn AccessPlatform>,
    ) -> Self {
        Self {
            chain,
            access_platform,
            done: false,
        }
    }
}

impl<M> Iterator for CheckedDescriptorIter<'_, M>
where
    M: Deref,
    M::Target: GuestMemory,
{
    type Item = Result<CheckedDescriptor, GuestAddress>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        let desc = self.chain.next()?;

        // A zero length descriptor describes no buffer, so skip
        // translation and range checks and let the device layer
        // decide. See CVE-2023-5158 for why hosts must tolerate them.
        if desc.len() == 0 {
            return Some(Ok(CheckedDescriptor {
                addr: desc.addr(),
                inner: desc,
            }));
        }

        let desc_addr = desc.addr();
        let desc_len = desc.len() as usize;

        let result = desc_addr
            .translate_gva(self.access_platform, desc_len)
            .map_err(|_| {
                warn!(
                    "Descriptor address translation failed: addr=0x{:x} len={}",
                    desc_addr.0, desc_len
                );
                desc_addr
            })
            .and_then(|addr| {
                if self.chain.memory().check_range(addr, desc_len) {
                    Ok(CheckedDescriptor { inner: desc, addr })
                } else {
                    warn!(
                        "Descriptor buffer extends past guest memory: addr=0x{:x} len={}",
                        addr.0, desc_len
                    );
                    Err(addr)
                }
            });

        if result.is_err() {
            self.done = true;
        }
        Some(result)
    }
}

/// Extension trait on [`DescriptorChain`] providing validated iteration.
pub trait DescriptorChainExt<M> {
    fn checked_iter<'a>(
        &'a mut self,
        access_platform: Option<&'a dyn AccessPlatform>,
    ) -> CheckedDescriptorIter<'a, M>;

    /// Fetch the next descriptor from the chain, validating its buffer range
    /// against guest memory.
    ///
    /// Returns `Ok(None)` when the chain is exhausted, and
    /// `Err(failing_addr)` when validation rejected a descriptor. Callers can
    /// map the failing address into a domain specific error.
    fn next_checked(
        &mut self,
        access_platform: Option<&dyn AccessPlatform>,
    ) -> Result<Option<CheckedDescriptor>, GuestAddress>;
}

impl<M> DescriptorChainExt<M> for DescriptorChain<M>
where
    M: Deref,
    M::Target: GuestMemory,
{
    fn checked_iter<'a>(
        &'a mut self,
        access_platform: Option<&'a dyn AccessPlatform>,
    ) -> CheckedDescriptorIter<'a, M> {
        CheckedDescriptorIter::new(self, access_platform)
    }

    fn next_checked(
        &mut self,
        access_platform: Option<&dyn AccessPlatform>,
    ) -> Result<Option<CheckedDescriptor>, GuestAddress> {
        match self.checked_iter(access_platform).next() {
            Some(Ok(desc)) => Ok(Some(desc)),
            Some(Err(addr)) => Err(addr),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod unit_tests {
    use virtio_bindings::virtio_ring::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};
    use virtio_queue::{Queue, QueueT};
    use vm_memory::bitmap::AtomicBitmap;
    use vm_memory::{GuestAddress, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};

    use super::*;
    use crate::queue::testing::VirtQueue as GuestQ;

    type TestMmap = GuestMemoryMmap<AtomicBitmap>;

    /// Set up a single descriptor in a virtqueue backed by `mem_size` bytes
    /// of guest RAM. Returns the guest memory, an atomic wrapper around it,
    /// and the ready queue.
    fn setup_vq(
        mem_size: usize,
        desc_addr: u64,
        desc_len: u32,
        desc_flags: u16,
    ) -> (TestMmap, GuestMemoryAtomic<TestMmap>, Queue) {
        const QSIZE: u16 = 2;

        let mem = TestMmap::from_ranges(&[(GuestAddress(0), mem_size)]).unwrap();
        let guest_vq = GuestQ::new(GuestAddress(0x1_0000), &mem, QSIZE);
        let queue = guest_vq.create_queue();

        guest_vq.dtable[0].set(desc_addr, desc_len, desc_flags, 0);
        guest_vq.avail.ring[0].set(0);
        guest_vq.avail.idx.set(1);

        let mem_atomic = GuestMemoryAtomic::new(mem.clone());
        (mem, mem_atomic, queue)
    }

    /// Set up a chain of descriptors linked via VRING_DESC_F_NEXT in a
    /// virtqueue backed by `mem_size` bytes of guest RAM. Each entry is
    /// `(addr, len, flags)`; the helper adds the NEXT flag on every
    /// descriptor except the last.
    fn setup_vq_chain(
        mem_size: usize,
        descs: &[(u64, u32, u16)],
    ) -> (TestMmap, GuestMemoryAtomic<TestMmap>, Queue) {
        let qsize = descs.len() as u16;
        assert!(qsize >= 1);

        let mem = TestMmap::from_ranges(&[(GuestAddress(0), mem_size)]).unwrap();
        let guest_vq = GuestQ::new(GuestAddress(0x1_0000), &mem, qsize);
        let queue = guest_vq.create_queue();

        let last = descs.len() - 1;
        for (i, &(addr, len, flags)) in descs.iter().enumerate() {
            let (flags, next) = if i < last {
                (
                    flags | u16::try_from(VRING_DESC_F_NEXT).unwrap(),
                    (i + 1) as u16,
                )
            } else {
                (flags, 0)
            };
            guest_vq.dtable[i].set(addr, len, flags, next);
        }
        guest_vq.avail.ring[0].set(0);
        guest_vq.avail.idx.set(1);

        let mem_atomic = GuestMemoryAtomic::new(mem.clone());
        (mem, mem_atomic, queue)
    }

    #[test]
    fn yields_valid_single_descriptor() {
        let (_mem, mem_atomic, mut queue) =
            setup_vq(128 * 1024, 0x4000, 256, VRING_DESC_F_WRITE as u16);
        let mem_guard = mem_atomic.memory();
        let mut chain = queue.pop_descriptor_chain(mem_guard).unwrap();
        let mut it = chain.checked_iter(None);
        let desc = it
            .next()
            .unwrap()
            .expect("valid descriptor must be yielded");
        assert_eq!(desc.addr().0, 0x4000);
        assert_eq!(desc.len(), 256);
        assert!(desc.is_write_only());
        assert!(it.next().is_none());
    }

    #[test]
    fn rejects_out_of_range_descriptor() {
        let (_mem, mem_atomic, mut queue) = setup_vq(128 * 1024, 0x4000, 1 << 30, 0);
        let mem_guard = mem_atomic.memory();
        let mut chain = queue.pop_descriptor_chain(mem_guard).unwrap();
        let mut it = chain.checked_iter(None);
        let result = it.next().expect("iterator must yield an item");
        result.unwrap_err();
    }

    #[test]
    fn passes_through_zero_length_descriptor() {
        let (_mem, mem_atomic, mut queue) = setup_vq(128 * 1024, 0x4000, 0, 0);
        let mem_guard = mem_atomic.memory();
        let mut chain = queue.pop_descriptor_chain(mem_guard).unwrap();
        let mut it = chain.checked_iter(None);
        let desc = it
            .next()
            .unwrap()
            .expect("zero length descriptor must pass through");
        assert_eq!(desc.len(), 0);
    }

    #[test]
    fn yields_valid_prefix_then_err_on_invalid() {
        let (_mem, mem_atomic, mut queue) =
            setup_vq_chain(128 * 1024, &[(0x4000, 256, 0), (0x8000, 1 << 30, 0)]);
        let mem_guard = mem_atomic.memory();
        let mut chain = queue.pop_descriptor_chain(mem_guard).unwrap();
        let mut it = chain.checked_iter(None);
        let first = it.next().unwrap().expect("first descriptor must be Ok");
        assert_eq!(first.addr().0, 0x4000);
        assert_eq!(first.len(), 256);
        let second = it.next().expect("second must yield an item");
        second.unwrap_err();
        assert!(it.next().is_none());
    }

    #[test]
    fn next_checked_returns_valid_descriptor() {
        let (_mem, mem_atomic, mut queue) = setup_vq(128 * 1024, 0x4000, 256, 0);
        let mem_guard = mem_atomic.memory();
        let mut chain = queue.pop_descriptor_chain(mem_guard).unwrap();
        let desc = chain
            .next_checked(None)
            .expect("validation must succeed")
            .expect("descriptor must be present");
        assert_eq!(desc.addr().0, 0x4000);
        assert_eq!(desc.len(), 256);
    }

    #[test]
    fn next_checked_returns_none_when_exhausted() {
        let (_mem, mem_atomic, mut queue) = setup_vq(128 * 1024, 0x4000, 256, 0);
        let mem_guard = mem_atomic.memory();
        let mut chain = queue.pop_descriptor_chain(mem_guard).unwrap();
        // Consume the single descriptor.
        let _ = chain.next_checked(None).unwrap().unwrap();
        // The chain is now exhausted; expect Ok(None).
        let res = chain.next_checked(None);
        assert!(matches!(res, Ok(None)));
    }
}
