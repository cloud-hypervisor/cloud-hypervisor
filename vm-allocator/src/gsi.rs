// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

// Only for this commit
#![expect(unused)]

#[cfg(target_arch = "x86_64")]
use std::collections::btree_map::BTreeMap;
use std::result;

use thiserror::Error;

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

/// Errors that may happen while allocating or freeing an interrupt.
#[derive(Error, Debug, PartialEq)]
pub enum InterruptAllocError {
    /// Interrupt allocator is exhausted, i.e. out of interrupt vectors.
    #[error("Interrupt allocator is exhausted (capacity: {0})")]
    ExhaustedError(u32 /* capacity/size */),

    /// Tried to free an interrupt that wasn't allocated.
    #[error("Interrupt was not allocated: {0}")]
    AlreadyFree(u32 /* vector */),

    /// Tried to free an interrupt that is not in range of the interrupt allocator.
    #[error("Interrupt vector is out of range: {0} (range: [{1},{2}))")]
    OutOfRange(
        u32, /* vector */
        u32, /* lower bound */
        u32, /* upper bound */
    ),
}

/// Simple bitmap-backed interrupt allocator.
///
/// The allocator can be configured with an offset. For example, to allocate
/// interrupt vectors in the range `[512, 1024)`, use an offset of 512 and a
/// size of 512.
#[derive(Debug)]
struct InterruptAllocator {
    /// Backing store for bitmap.
    words: Box<[usize]>,
    /// The offset to start allocating interrupts from.
    offset: u32,
    /// Number of allocatable interrupt vectors starting at `offset`.
    size: u32,
}

impl InterruptAllocator {
    /// Creates a new allocator.
    fn new(size: u32, offset: u32) -> Self {
        assert_ne!(size, 0);
        assert!(offset.checked_add(size).is_some());

        let num_words = size.div_ceil(usize::BITS);
        let num_words = usize::try_from(num_words).unwrap();
        let mut words = vec![0; num_words].into_boxed_slice();
        words[num_words - 1] = Self::last_word_mask(size);

        Self {
            words,
            size,
            offset,
        }
    }

    /// Returns the mask of the last word, ensuring that no more than requested
    /// interrupts can be allocated.
    fn last_word_mask(size: u32) -> usize {
        let rem = size % usize::BITS;

        if rem == 0 { 0 } else { !((1 << rem) - 1) }
    }

    /// Returns word and bit indices for a given vector index.
    fn word_and_bit(
        vector: u32,
    ) -> (
        usize, /* index into `words` */
        usize, /* index into `words[w]` */
    ) {
        let idx = usize::try_from(vector).unwrap();
        let bits = usize::try_from(usize::BITS).unwrap();
        (idx / bits, idx % bits)
    }

    /// Allocates a vector by setting its bit in the bitmap.
    ///
    /// Returns an error if the allocator is exhausted.
    fn alloc(&mut self) -> result::Result<u32, InterruptAllocError> {
        // Find the next word with capacity for allocating a vector.
        let Some(idx) = self.words.iter().position(|&w| w != usize::MAX) else {
            return Err(InterruptAllocError::ExhaustedError(self.size));
        };
        let word = &mut self.words[idx];

        // Find lowest free bit.
        let bit = (!*word).trailing_zeros() as usize;
        // Set the bit.
        *word |= 1 << bit;
        // Calculate index, add offset and return.

        let bits = usize::try_from(usize::BITS).unwrap();
        let vector = idx * bits + bit;
        let vector = u32::try_from(vector).unwrap();
        Ok(vector + self.offset)
    }

    /// Frees a vector by clearing its bit in the bitmap.
    ///
    /// This vector is assumed to include the internal `offset`.
    ///
    /// Returns an error if the vector is already free.
    fn free(&mut self, vector: u32) -> result::Result<(), InterruptAllocError> {
        // At first we make sure that the vector is not out of range.
        let begin = self.offset;
        let end = begin + self.size;
        if !(begin..end).contains(&vector) {
            return Err(InterruptAllocError::OutOfRange(
                vector,
                self.offset,
                self.offset + self.size,
            ));
        }

        let idx = vector.abs_diff(self.offset);
        let (w, b) = Self::word_and_bit(idx);
        let mask = 1 << b;

        // Let's first check whether the bit is set.
        if self.words[w] & mask == 0 {
            return Err(InterruptAllocError::AlreadyFree(vector));
        }
        // Clear the bit and we are done!
        self.words[w] &= !mask;
        Ok(())
    }

    /// Returns the capacity of vectors that can be allocated.
    #[cfg(target_arch = "x86_64")]
    fn size(&self) -> u32 {
        self.size
    }
}

/// GsiAllocator
pub struct GsiAllocator {
    #[cfg(target_arch = "x86_64")]
    apics: BTreeMap<u32, u32>,
    next_irq: u32,
    next_gsi: u32,
}

impl GsiAllocator {
    #[cfg(target_arch = "x86_64")]
    /// New GSI allocator
    pub fn new(apics: &[GsiApic]) -> Self {
        let mut allocator = GsiAllocator {
            apics: BTreeMap::new(),
            next_irq: 0xffff_ffff,
            next_gsi: 0,
        };

        for apic in apics {
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

    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    /// New GSI allocator
    pub fn new() -> Self {
        GsiAllocator {
            next_irq: arch::IRQ_BASE,
            next_gsi: arch::IRQ_BASE,
        }
    }

    /// Allocate a GSI
    pub fn allocate_gsi(&mut self) -> Result<u32> {
        let gsi = self.next_gsi;
        self.next_gsi = self.next_gsi.checked_add(1).ok_or(Error::Overflow)?;
        Ok(gsi)
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

#[cfg(test)]
mod unit_tests {
    use super::*;

    mod interrupt_allocator {
        use super::*;

        #[test]
        // Checks that the allocator can only allocate as many vectors as configured.
        fn test_allocator_respects_size() {
            for size in [1, 8, 16, 32, 63, 64, 65, 128] {
                let mut allocator = InterruptAllocator::new(size, 0);
                for _ in 0..size {
                    let _ = allocator.alloc().expect("should not be exhausted");
                }
                allocator.alloc().expect_err("should be exhausted");
            }
        }

        #[test]
        // Checks that the allocator starts allocating vectors at the given offset.
        fn test_allocator_respects_offset() {
            for offset in [0, 1, 2, 3, 8, 16, 32, 64, 77, 128] {
                let mut allocator = InterruptAllocator::new(8, offset);
                let vec = allocator.alloc().unwrap();
                assert_eq!(offset, vec);
                allocator.free(vec).unwrap();
            }
        }

        #[test]
        // Checks that the calculations in alloc and free are correct.
        fn test_allocator_alloc_and_free_all_vectors() {
            for size in [1, 3, 7, 8, 15, 16, 32, 63, 64, 65, 128, 4096] {
                let mut allocator = InterruptAllocator::new(size, 0);
                let mut num_vectors = 0;
                while allocator.alloc().is_ok() {
                    num_vectors += 1;
                }
                assert_eq!(size, num_vectors);
                num_vectors -= 1;
                loop {
                    if let Err(e) = allocator.free(num_vectors) {
                        println!("Could not free {num_vectors}: {e}");
                        break;
                    }
                    if let Some(v) = num_vectors.checked_sub(1) {
                        num_vectors = v;
                    } else {
                        break;
                    }
                }
            }
        }

        #[test]
        // Checks that freeing a vector that isn't allocated results in an error.
        fn test_can_only_free_allocated_vectors() {
            let mut allocator = InterruptAllocator::new(8, 0);
            // Never-allocated vector.
            assert_eq!(allocator.free(0), Err(InterruptAllocError::AlreadyFree(0)));
            // Allocated then freed vector.
            let vec = allocator.alloc().unwrap();
            allocator.free(vec).unwrap();
            assert_eq!(
                allocator.free(vec),
                Err(InterruptAllocError::AlreadyFree(vec))
            );
        }

        #[test]
        // Checks that freeing a vector that is not in range of the allocator results
        // in an error.
        fn test_can_only_free_vectors_in_range() {
            let size = 8;
            let offset = 16;
            let mut allocator = InterruptAllocator::new(size, offset);
            for _ in 0..size {
                let _ = allocator.alloc().expect("should not be exhausted");
            }
            // Out of range above.
            let vector_out_of_range = size + offset;
            assert_eq!(
                allocator.free(vector_out_of_range),
                Err(InterruptAllocError::OutOfRange(
                    vector_out_of_range,
                    offset,
                    offset + size
                ))
            );
            // Out of range below.
            assert_eq!(
                allocator.free(offset - 1),
                Err(InterruptAllocError::OutOfRange(
                    offset - 1,
                    offset,
                    offset + size
                ))
            );
            for i in 0..size {
                let vector = i + allocator.offset;
                allocator.free(vector).expect("should not be exhausted");
            }
        }
    }
}
