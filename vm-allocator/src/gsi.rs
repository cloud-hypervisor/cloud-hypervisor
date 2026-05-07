// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! Interrupt-number allocation for interrupts.
//!
//! See [`GsiAllocator`].

#[cfg(target_arch = "x86_64")]
use std::collections::btree_map::BTreeMap;
#[cfg(test)]
use std::ops::Range;
use std::result;

use thiserror::Error;

pub type Result<T> = result::Result<T, InterruptAllocError>;

/// Describes one APIC interrupt input range in the global system interrupt
/// namespace.
#[cfg(target_arch = "x86_64")]
#[derive(Copy, Clone)]
pub struct GsiApic {
    /// The offset from 0.
    base: u32,
    /// The number of interrupts in the range.
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

/// Maximum number of IRQ routes supported by KVM.
///
/// See <https://elixir.bootlin.com/linux/v7.0.1/source/include/linux/kvm_host.h#L2193>.
const KVM_MAX_IRQ_ROUTES: u32 = {
    #[cfg(feature = "kvm")]
    {
        4096
    }
    #[cfg(not(feature = "kvm"))]
    {
        0
    }
};

/// Maximum number of IRQ routes supported by MSHV.
///
/// See <https://elixir.bootlin.com/linux/v7.0.1/source/drivers/hv/mshv_root.h#L170>.
const MSHV_MAX_GUEST_IRQS: u32 = 4096;

/// The effective max number of IRQs.
///
/// This affects the number of interrupts that can be allocated. This number
/// alone doesn't mean that the backend necessarily accepts all the IRQs.
#[allow(clippy::absurd_extreme_comparisons)]
const MAX_GUEST_IRQS: u32 = {
    // cmp::max is not const compatible
    if KVM_MAX_IRQ_ROUTES > MSHV_MAX_GUEST_IRQS {
        KVM_MAX_IRQ_ROUTES
    } else {
        MSHV_MAX_GUEST_IRQS
    }
};

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
    fn alloc(&mut self) -> Result<u32> {
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
    fn free(&mut self, vector: u32) -> Result<()> {
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

    #[cfg(test)]
    fn range(&self) -> Range<u32> {
        self.offset..(self.offset + self.size)
    }
}

/// Coordinates graceful resource allocation of IRQs and GSIs from the interrupt
/// namespace.
///
/// Ensures that interrupt numbers either for IRQs or GSIs are not overlapping.
///
/// Check out the [module documentation](super::gsi) for more info.
pub struct GsiAllocator {
    #[cfg(target_arch = "x86_64")]
    apics: BTreeMap<u32 /* base */, u32 /* number of interrupts */>,
    irqs: InterruptAllocator,
    gsis: InterruptAllocator,
}

impl GsiAllocator {
    #[cfg(target_arch = "x86_64")]
    /// Creates a new GSI allocator with the proper interrupt number ranges
    /// for IRQs and GSIs.
    ///
    /// Respects the provided [`GsiApic`]s
    // On x86, the interrupt number space starts with IRQs and is followed by
    // GSI.
    pub fn new(apics: &[GsiApic]) -> Self {
        let next_irq = apics.iter().map(|apic| apic.base).min().unwrap_or(0);

        let next_gsi = apics
            .iter()
            .map(|apic| apic.base + apic.irqs)
            .max()
            .unwrap_or(0);

        let irqs = apics.iter().map(|apic| apic.irqs).sum();

        let allocator_apics = apics.iter().map(|apic| (apic.base, apic.irqs)).collect();

        let gsis = MAX_GUEST_IRQS - next_gsi;

        Self {
            apics: allocator_apics,
            irqs: InterruptAllocator::new(irqs, next_irq),
            gsis: InterruptAllocator::new(gsis, next_gsi),
        }
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    /// New GSI allocator.
    // On aarch 64 and riscv x86, the IRQs and GSIs use independent interrupt
    // number namespaces.
    pub fn new() -> Self {
        GsiAllocator {
            irqs: InterruptAllocator::new(MAX_GUEST_IRQS - arch::IRQ_BASE, arch::IRQ_BASE),
            gsis: InterruptAllocator::new(MAX_GUEST_IRQS - arch::IRQ_BASE, arch::IRQ_BASE),
        }
    }

    /// Allocate a GSI
    pub fn allocate_gsi(&mut self) -> Result<u32> {
        self.gsis.alloc()
    }

    /// Frees a GSI
    pub fn free_gsi(&mut self, vector: u32) -> Result<()> {
        self.gsis.free(vector)
    }

    #[cfg(target_arch = "x86_64")]
    /// Allocate an IRQ
    pub fn allocate_irq(&mut self) -> Result<u32> {
        let next_irq = self.irqs.alloc()?;
        for (base, irqs) in self.apics.iter() {
            // HACKHACK - This only works with 1 single IOAPIC...
            if next_irq >= *base && next_irq < *base + *irqs {
                return Ok(next_irq);
            }
        }

        self.irqs.free(next_irq)?;
        Err(InterruptAllocError::ExhaustedError(self.irqs.size()))
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    /// Allocate an IRQ
    pub fn allocate_irq(&mut self) -> Result<u32> {
        self.irqs.alloc()
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

    #[cfg(target_arch = "x86_64")]
    /// [`GsiAllocator`] tests for x86, where IRQs and GSIs are consecutive
    /// in a single interrupt number namespace.
    mod gsi_allocator {
        use super::*;

        fn single_apic_allocator() -> GsiAllocator {
            // One IOAPIC: GSI 0..24 are pin-based IRQs, GSIs start after that.
            GsiAllocator::new(&[GsiApic::new(5, 19)])
        }

        #[test]
        fn test_allocator_uses_apic_irq_and_gsi_ranges() {
            let mut allocator = single_apic_allocator();

            assert_eq!(allocator.irqs.range(), 5..24);
            assert_eq!(allocator.gsis.range(), 24..MAX_GUEST_IRQS);
            assert_eq!(allocator.allocate_irq(), Ok(5));
            assert_eq!(allocator.allocate_irq(), Ok(6));
            assert_eq!(allocator.allocate_gsi(), Ok(24));
            assert_eq!(allocator.allocate_gsi(), Ok(25));
        }

        #[test]
        fn test_allocator_exhausts_irqs_at_apic_boundary() {
            let mut allocator = single_apic_allocator();

            for expected_irq in 5..24 {
                assert_eq!(allocator.allocate_irq(), Ok(expected_irq));
            }

            assert_eq!(
                allocator.allocate_irq(),
                Err(InterruptAllocError::ExhaustedError(19))
            );
            assert_eq!(allocator.allocate_gsi(), Ok(24));
        }

        #[test]
        fn test_allocator_can_free_and_reuse_gsis() {
            let mut allocator = single_apic_allocator();

            assert_eq!(
                allocator.free_gsi(24),
                Err(InterruptAllocError::AlreadyFree(24))
            );

            let gsi = allocator.allocate_gsi().unwrap();
            assert_eq!(gsi, 24);

            allocator.free_gsi(gsi).unwrap();
            assert_eq!(allocator.allocate_gsi(), Ok(gsi));
        }
    }

    /// [`GsiAllocator`] tests for aarch64 and RISC-V, where IRQs and GSIs
    /// have independent interrupt number namespaces.
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    mod gsi_allocator {
        use super::*;

        fn single_apic_allocator() -> GsiAllocator {
            GsiAllocator::new()
        }

        #[test]
        fn test_allocator_uses_arch_irq_base() {
            let mut allocator = single_apic_allocator();

            assert_eq!(allocator.irqs.range(), ::arch::IRQ_BASE..MAX_GUEST_IRQS);
            assert_eq!(allocator.gsis.range(), ::arch::IRQ_BASE..MAX_GUEST_IRQS);
            assert_eq!(allocator.allocate_irq(), Ok(::arch::IRQ_BASE));
            assert_eq!(allocator.allocate_irq(), Ok(::arch::IRQ_BASE + 1));
            assert_eq!(allocator.allocate_gsi(), Ok(::arch::IRQ_BASE));
            assert_eq!(allocator.allocate_gsi(), Ok(::arch::IRQ_BASE + 1));
        }

        #[test]
        fn test_allocator_keeps_irq_and_gsi_namespaces_independent() {
            let mut allocator = single_apic_allocator();

            assert_eq!(allocator.allocate_irq(), Ok(::arch::IRQ_BASE));
            assert_eq!(allocator.allocate_gsi(), Ok(::arch::IRQ_BASE));
        }

        #[test]
        fn test_allocator_can_free_and_reuse_gsis() {
            let mut allocator = single_apic_allocator();

            assert_eq!(
                allocator.free_gsi(::arch::IRQ_BASE),
                Err(InterruptAllocError::AlreadyFree(::arch::IRQ_BASE))
            );

            let gsi = allocator.allocate_gsi().unwrap();
            assert_eq!(gsi, ::arch::IRQ_BASE);

            allocator.free_gsi(gsi).unwrap();
            assert_eq!(allocator.allocate_gsi(), Ok(gsi));
        }
    }
}
