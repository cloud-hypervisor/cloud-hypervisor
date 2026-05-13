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
