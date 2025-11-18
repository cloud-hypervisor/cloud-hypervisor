// Copyright © 2025 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0

use std::ops::Mul;

/// An iterator that turns a sequence of u64s into a sequence of bit positions
/// that are set.
///
/// This is useful to iterate over dirty memory bitmaps.
struct BitposIterator<I> {
    underlying_it: I,

    /// How many `u64`'s we've already consumed.
    ///
    /// `u32` is sufficient.
    word_pos: u32,

    /// If we already started working on a u64, it's here. Together with the bit
    /// position where we have to continue.
    current_word: Option<(u64 /* cur word */, u32 /* cur pos */)>,
}

impl<I> Iterator for BitposIterator<I>
where
    I: Iterator<Item = u64>,
{
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.current_word.is_none() {
                self.current_word = self.underlying_it.next().map(|w| (w, 0));
            }

            let (word, word_bit) = self.current_word?;

            // Continue early if there is no chance to find something.
            if word != 0 && word_bit < 64 {
                let shifted_word = word >> word_bit;
                if shifted_word != 0 {
                    let zeroes = shifted_word.trailing_zeros();

                    self.current_word = Some((word, zeroes + word_bit + 1));
                    let next_bitpos = (self.word_pos as u64)
                        .mul(64)
                        // the inner value can not overflow
                        .checked_add(word_bit as u64 + zeroes as u64)
                        .unwrap();

                    return Some(next_bitpos);
                }
            }

            self.current_word = None;
            self.word_pos += 1;
        }
    }
}

pub trait BitposIteratorExt: Iterator<Item = u64> + Sized {
    /// Turn an iterator over `u64` into an iterator over the bit positions of
    /// all 1s. We basically treat the incoming `u64` as one gigantic integer
    /// and just spit out which bits are set.
    fn bit_positions(self) -> impl Iterator<Item = u64> {
        BitposIterator {
            underlying_it: self,
            word_pos: 0,
            current_word: None,
        }
    }
}

impl<I: Iterator<Item = u64> + Sized> BitposIteratorExt for I {}

#[cfg(test)]
mod unit_tests {
    use super::*;

    fn bitpos_check(inp: &[u64], out: &[u64]) {
        assert_eq!(inp.iter().copied().bit_positions().collect::<Vec<_>>(), out);
    }

    #[test]
    fn bitpos_iterator_works() {
        bitpos_check(&[], &[]);
        bitpos_check(&[0], &[]);
        bitpos_check(&[1], &[0]);
        bitpos_check(&[5], &[0, 2]);
        bitpos_check(&[3 + 32], &[0, 1, 5]);
        bitpos_check(&[1 << 63], &[63]);

        bitpos_check(&[1, 1 + 32], &[0, 64, 69]);
    }
}
