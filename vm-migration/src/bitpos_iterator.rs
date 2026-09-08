// Copyright © 2026 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//
// Code imported from https://github.com/phip1611/bit_ops/blob/7befc3998fac6c7bc0d9238f89b040da3f8c1b02/src/bitpos_iter.rs
// but the generics were removed (only operates on u64).

use std::fmt::Debug;

/// Iterator over set bits of an unsigned integer.
///
/// The index / bit position starts at `0`, the last bit position is
/// `n_bits - 1`.
#[derive(Debug)]
pub(crate) struct BitsIter {
    value: u64,
}

impl BitsIter {
    pub(crate) const fn new(value: u64) -> Self {
        Self { value }
    }
}

impl Iterator for BitsIter {
    type Item = u64;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.value == 0 {
            return None;
        }
        let tz = self.value.trailing_zeros() as u64;
        self.value &= self.value - 1; // clear lowest set bit
        Some(tz)
    }
}

/// Iterator over set bits in (large) bitmaps, i.e., collection of unsigned
/// integers.
pub(crate) struct BitmapIter<I> {
    bitmap_iter: I,
    consumed_bits: u64,
    current_element_it: BitsIter,
}

impl<I: Iterator<Item = u64>> BitmapIter<I> {
    pub(crate) fn new<In: IntoIterator<IntoIter = I>>(bitmap_iter: In) -> Self {
        let mut bitmap_iter = bitmap_iter.into_iter();
        let current_element_it = BitsIter::new(bitmap_iter.next().unwrap_or(0));
        Self {
            bitmap_iter,
            consumed_bits: 0,
            current_element_it,
        }
    }
}

impl<I: Iterator<Item = u64>> Iterator for BitmapIter<I> {
    type Item = u64;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        // Performance: Avoid `checked_add` in the hot path.
        loop {
            // We return here, if we currently have an element.
            if let Some(bit) = self.current_element_it.next() {
                return Some(self.consumed_bits + bit);
            }

            // Current u64 exhausted: load next one or return `None` / exit.
            let next_u64 = self.bitmap_iter.next()?;
            // Unchecked add: see performance comment above
            self.consumed_bits += u64::BITS as u64;
            self.current_element_it = BitsIter::new(next_u64);
        }
    }
}

/// Extension for the Rust standard libraries [`Iterator`] for convenient
/// integration of [`BitmapIter`].
pub(crate) trait BitposIteratorExt: Iterator<Item = u64> + Sized {
    fn bit_positions(self) -> BitmapIter<Self> {
        BitmapIter::new(self)
    }
}

// Blanked implementation for all matching iterators.
impl<I: Iterator<Item = u64> + Sized> BitposIteratorExt for I {}

#[cfg(test)]
mod tests {
    use std::array;
    use std::vec::Vec;

    use super::*;

    #[test]
    fn bits_iter() {
        let iter = BitsIter::new(0_u64);
        assert_eq!(&iter.collect::<Vec<u64>>(), &[] as &[u64]);

        let iter = BitsIter::new(1_u64);
        assert_eq!(&iter.collect::<Vec<u64>>(), &[0]);

        let iter = BitsIter::new(0b1010_1010_u64);
        assert_eq!(&iter.collect::<Vec<u64>>(), &[1, 3, 5, 7]);

        let iter = BitsIter::new(0b1111_1111_u64);
        assert_eq!(&iter.collect::<Vec<u64>>(), &[0, 1, 2, 3, 4, 5, 6, 7]);

        let iter = BitsIter::new(u64::MAX);
        assert_eq!(
            &iter.collect::<Vec<u64>>(),
            // [0, 1, ..., 63]
            &array::from_fn::<u64, 64, _>(|i| i as u64)
        );
    }

    #[test]
    fn bitmap_iter() {
        let iter = BitmapIter::<_>::new([0_u64]);
        assert_eq!(&iter.collect::<Vec<u64>>(), &[] as &[u64]);

        let iter = BitmapIter::<_>::new([0b1111_0010, 0b1000, 1]);
        assert_eq!(&iter.collect::<Vec<u64>>(), &[1, 4, 5, 6, 7, 67, 128]);

        let iter = BitmapIter::<_>::new([0b10, 0b10, 0b11]);
        assert_eq!(&iter.collect::<Vec<u64>>(), &[1, 65, 128, 129]);
    }
}
