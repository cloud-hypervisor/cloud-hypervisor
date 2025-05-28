// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

#[cfg(target_arch = "x86_64")]
use std::collections::btree_map::BTreeMap;
use std::result;
use std::sync::{Arc, Mutex};

use bit_vec::BitVec;

/// According to the value set kernel
const KVM_MAX_IRQ_ROUTES: usize = 4096;
/// Invalid gsi num
pub const GSI_INVALID: u32 = u32::MAX;

#[derive(Debug)]
pub enum Error {
    Overflow,
}

pub type Result<T> = result::Result<T, Error>;

/// GsiApic
#[cfg(target_arch = "x86_64")]
#[derive(Copy, Clone)]
pub struct GsiApic {
    base: u32,
    irqs: u32,
}

#[cfg(target_arch = "x86_64")]
impl GsiApic {
    /// New GSI APIC
    pub fn new(base: u32, irqs: u32) -> Self {
        GsiApic { base, irqs }
    }
}

/// GsiAllocator
pub struct GsiAllocator {
    #[cfg(target_arch = "x86_64")]
    apics: BTreeMap<u32, u32>,
    next_irq: u32,
    gsi_base: u32,
    gsi_bitmap: Arc<Mutex<BitVec>>,
}

impl GsiAllocator {
    #[cfg(target_arch = "x86_64")]
    /// New GSI allocator
    pub fn new(apics: Vec<GsiApic>) -> Self {
        let mut allocator = GsiAllocator {
            apics: BTreeMap::new(),
            next_irq: 0xffff_ffff,
            gsi_base: 0,
            gsi_bitmap: Arc::new(Mutex::new(BitVec::from_elem(KVM_MAX_IRQ_ROUTES, false))),
        };

        for apic in &apics {
            if apic.base < allocator.next_irq {
                allocator.next_irq = apic.base;
            }

            allocator.apics.insert(apic.base, apic.irqs);
        }

        allocator
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    /// New GSI allocator
    pub fn new() -> Self {
        GsiAllocator {
            next_irq: arch::IRQ_BASE,
            gsi_base: arch::IRQ_BASE,
            gsi_bitmap: Arc::new(Mutex::new(BitVec::from_elem(KVM_MAX_IRQ_ROUTES, false))),
        }
    }

    /// Allocate a GSI
    pub fn allocate_gsi(&mut self) -> Result<u32> {
        let mut gsi_bitmap = self.gsi_bitmap.lock().unwrap();
        let mut gsi = GSI_INVALID;
        for i in self.gsi_base as usize..gsi_bitmap.len() {
            if !gsi_bitmap[i] {
                gsi = i as u32;
                break;
            }
        }
        gsi_bitmap.set(gsi as usize, true);

        Ok(gsi)
    }

    /// Free a GSI
    pub fn free_gsi(&mut self, gsi: u32) {
        self.gsi_bitmap.lock().unwrap().set(gsi as usize, false);
    }

    #[cfg(target_arch = "x86_64")]
    /// Allocate an IRQ
    pub fn allocate_irq(&mut self) -> Result<u32> {
        let mut irq: u32 = 0;
        for (base, irqs) in self.apics.iter() {
            // HACKHACK - This only works with 1 single IOAPIC...
            if self.next_irq >= *base && self.next_irq < *base + *irqs {
                irq = self.next_irq;
                self.next_irq += 1;
            }
        }

        if irq == 0 {
            return Err(Error::Overflow);
        }

        Ok(irq)
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    /// Allocate an IRQ
    pub fn allocate_irq(&mut self) -> Result<u32> {
        let irq = self.next_irq;
        self.next_irq = self.next_irq.checked_add(1).ok_or(Error::Overflow)?;
        Ok(irq)
    }
}

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
impl Default for GsiAllocator {
    fn default() -> Self {
        GsiAllocator::new()
    }
}
