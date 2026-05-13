// Copyright © 2025 Cloud Hypervisor Authors
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
/// If any descriptor's `(addr, len)` range is not fully backed by guest RAM,
/// iteration terminates and [`Self::failed()`] returns `true`.
pub struct CheckedDescriptorIter<'a, M> {
    chain: &'a mut DescriptorChain<M>,
    access_platform: Option<&'a dyn AccessPlatform>,
    failed_addr: Option<GuestAddress>,
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
            failed_addr: None,
        }
    }

    /// Returns `true` if iteration was terminated due to an invalid descriptor.
    pub fn failed(&self) -> bool {
        self.failed_addr.is_some()
    }

    /// Returns the guest address of the descriptor that caused iteration to
    /// terminate, if any.
    pub fn failed_addr(&self) -> Option<GuestAddress> {
        self.failed_addr
    }
}

impl<M> Iterator for CheckedDescriptorIter<'_, M>
where
    M: Deref,
    M::Target: GuestMemory,
{
    type Item = CheckedDescriptor;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed_addr.is_some() {
            return None;
        }

        let desc = self.chain.next()?;

        if desc.len() == 0 {
            return Some(CheckedDescriptor {
                addr: desc.addr(),
                inner: desc,
            });
        }

        let addr = match desc
            .addr()
            .translate_gva(self.access_platform, desc.len() as usize)
        {
            Ok(a) => a,
            Err(_) => {
                warn!(
                    "Descriptor address translation failed: addr=0x{:x} len={}",
                    desc.addr().0,
                    desc.len()
                );
                self.failed_addr = Some(desc.addr());
                return None;
            }
        };

        if !self.chain.memory().check_range(addr, desc.len() as usize) {
            warn!(
                "Descriptor buffer extends past guest memory: addr=0x{:x} len={}",
                addr.0,
                desc.len()
            );
            self.failed_addr = Some(addr);
            return None;
        }

        Some(CheckedDescriptor { inner: desc, addr })
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
        let mut iter = self.checked_iter(access_platform);
        let desc = iter.next();
        if let Some(addr) = iter.failed_addr() {
            return Err(addr);
        }
        Ok(desc)
    }
}
