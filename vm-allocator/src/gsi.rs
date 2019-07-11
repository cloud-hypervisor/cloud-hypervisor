// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

use std::collections::btree_map::BTreeMap;
use std::result;

#[derive(Debug)]
pub enum Error {
    Overflow,
}

pub type Result<T> = result::Result<T, Error>;

/// GsiApic
#[derive(Copy, Clone)]
pub struct GsiApic {
    base: u32,
    irqs: u32,
}

impl GsiApic {
    /// New GSI APIC
    pub fn new(base: u32, irqs: u32) -> Self {
        GsiApic { base, irqs }
    }
}

/// GsiAllocator
pub struct GsiAllocator {
    apics: BTreeMap<u32, u32>,
    next_irq: u32,
    next_gsi: u32,
}

impl GsiAllocator {
    /// New GSI allocator
    pub fn new(apics: Vec<GsiApic>) -> Self {
        let mut allocator = GsiAllocator {
            apics: BTreeMap::new(),
            next_irq: 0xffff_ffff,
            next_gsi: 0,
        };

        for apic in &apics {
            if apic.base < allocator.next_irq {
                allocator.next_irq = apic.base;
            }

            if apic.base + apic.irqs > allocator.next_gsi {
                allocator.next_gsi = apic.base + apic.irqs;
            }

            allocator.apics.insert(apic.base, apic.irqs);
        }

        allocator
    }

    /// Allocate a GSI
    pub fn allocate_gsi(&mut self) -> Result<u32> {
        self.next_gsi = self.next_gsi.checked_add(1).ok_or(Error::Overflow)?;

        Ok(self.next_gsi - 1)
    }

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
}
