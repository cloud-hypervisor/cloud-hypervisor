// Copyright © 2026 Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

use thiserror::Error;

/// Errors returned when validating or inserting a range in a [`RangeMap`].
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RangeMapError {
    /// Range length must be non-zero.
    #[error("Range length must be non-zero")]
    ZeroLength,
    /// Inclusive range end `base + (len - 1)` overflows `u64`.
    #[error("Range end overflows u64")]
    Overflow,
    /// Range overlaps an existing entry in the map.
    #[error("Range overlaps an existing entry")]
    Overlap,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RangeEntry<V> {
    len: u64,
    value: V,
}

/// Computes the inclusive end `base + (len - 1)` of a non-empty `u64` range.
fn inclusive_end(base: u64, len: u64) -> Result<u64, RangeMapError> {
    let last_offset = len.checked_sub(1).ok_or(RangeMapError::ZeroLength)?;
    base.checked_add(last_offset).ok_or(RangeMapError::Overflow)
}

/// A map from non-empty, pairwise disjoint `u64` ranges `[base, base + len)`
/// to values of type `V`.
///
/// Entries are ordered by ascending `base` address. Adjacent ranges such as
/// `[0, 10)` and `[10, 20)` are allowed and remain distinct entries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RangeMap<V> {
    entries: BTreeMap<u64, RangeEntry<V>>,
}

impl<V> Default for RangeMap<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V> RangeMap<V> {
    /// Creates an empty [`RangeMap`].
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Returns `true` if the map contains no ranges.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the number of mapped ranges.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    fn overlaps_inclusive(&self, base: u64, end: u64) -> bool {
        if let Some((&prev_base, prev)) = self.entries.range(..base).next_back() {
            // Every stored entry satisfies `prev.len >= 1` and
            // `prev_base + (prev.len - 1) <= u64::MAX`.
            let prev_end = prev_base + (prev.len - 1);
            if prev_end >= base {
                return true;
            }
        }
        self.entries.range(base..=end).next().is_some()
    }

    /// Returns `true` if any stored range overlaps `[base, base + len)`.
    ///
    /// A zero-length range overlaps nothing and returns `false`. If `base + (len - 1)`
    /// overflows `u64`, overlap is checked against the prefix `[base, u64::MAX]`.
    pub fn overlaps(&self, base: u64, len: u64) -> bool {
        let Some(last_offset) = len.checked_sub(1) else {
            return false;
        };
        let end = base.saturating_add(last_offset);
        self.overlaps_inclusive(base, end)
    }

    /// Checks whether a range `[base, base + len)` can be inserted without error.
    ///
    /// Returns [`RangeMapError::ZeroLength`] if `len == 0`,
    /// [`RangeMapError::Overflow`] if `base + (len - 1)` overflows `u64`, or
    /// [`RangeMapError::Overlap`] if it intersects an existing entry.
    pub fn check_insert(&self, base: u64, len: u64) -> Result<(), RangeMapError> {
        let end = inclusive_end(base, len)?;
        if self.overlaps_inclusive(base, end) {
            return Err(RangeMapError::Overlap);
        }
        Ok(())
    }

    /// Inserts `value` for the non-empty range `[base, base + len)`.
    ///
    /// Leaves the map unchanged and returns an error if `len == 0`,
    /// `base + (len - 1)` overflows `u64`, or the range overlaps an existing
    /// entry.
    pub fn insert(&mut self, base: u64, len: u64, value: V) -> Result<(), RangeMapError> {
        self.check_insert(base, len)?;
        self.entries.insert(base, RangeEntry { len, value });
        Ok(())
    }

    /// Returns a reference to the value stored for the exact range `(base, len)`.
    pub fn get_exact(&self, base: u64, len: u64) -> Option<&V> {
        self.entries
            .get(&base)
            .filter(|entry| entry.len == len)
            .map(|entry| &entry.value)
    }

    /// Removes and returns the value for the exact range `(base, len)`.
    ///
    /// Returns `None` without modifying the map if no entry starts at `base`
    /// with length `len`.
    pub fn remove_exact(&mut self, base: u64, len: u64) -> Option<V> {
        let Entry::Occupied(entry) = self.entries.entry(base) else {
            return None;
        };
        if entry.get().len != len {
            return None;
        }
        Some(entry.remove().value)
    }

    /// Removes all entries from the map.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Iterates over `(base, len, &value)` tuples in ascending `base` order.
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = (u64, u64, &V)> + ExactSizeIterator {
        self.entries
            .iter()
            .map(|(&base, entry)| (base, entry.len, &entry.value))
    }

    /// Iterates over `(base, len, &mut value)` tuples in ascending `base` order.
    pub fn iter_mut(
        &mut self,
    ) -> impl DoubleEndedIterator<Item = (u64, u64, &mut V)> + ExactSizeIterator {
        self.entries
            .iter_mut()
            .map(|(&base, entry)| (base, entry.len, &mut entry.value))
    }
}

#[cfg(test)]
mod tests {
    use super::{RangeMap, RangeMapError};

    #[test]
    fn empty_and_basic_queries() {
        let map: RangeMap<u32> = RangeMap::new();
        assert!(map.is_empty());
        assert_eq!(map.len(), 0);
        assert!(!map.overlaps(0, 0));
        assert!(!map.overlaps(0, 10));
        assert!(!map.overlaps(u64::MAX, 1));
        assert!(!map.overlaps(u64::MAX, 2));
        assert_eq!(map.get_exact(0, 10), None);
        assert_eq!(map.iter().count(), 0);
    }

    #[test]
    fn default_does_not_require_value_default() {
        struct NonDefault(u8);
        let map: RangeMap<NonDefault> = RangeMap::default();
        assert!(map.is_empty());
        let mut map = map;
        map.insert(0, 1, NonDefault(7)).unwrap();
        assert_eq!(map.get_exact(0, 1).map(|v| v.0), Some(7));
    }

    #[test]
    fn zero_length_rejected() {
        let mut map = RangeMap::new();
        assert_eq!(map.check_insert(0, 0), Err(RangeMapError::ZeroLength));
        assert_eq!(map.insert(0, 0, "a"), Err(RangeMapError::ZeroLength));
        assert_eq!(map.insert(0x1000, 0, "a"), Err(RangeMapError::ZeroLength));
        assert_eq!(map.insert(u64::MAX, 0, "a"), Err(RangeMapError::ZeroLength));
        assert!(map.is_empty());
        assert_eq!(map.remove_exact(0, 0), None);
    }

    #[test]
    fn adjacent_ranges_do_not_overlap() {
        let mut map = RangeMap::new();
        assert_eq!(map.insert(0, 10, "first"), Ok(()));
        assert_eq!(map.insert(20, 10, "third"), Ok(()));
        assert!(!map.overlaps(10, 10));
        assert_eq!(map.insert(10, 10, "second"), Ok(()));
        assert_eq!(map.len(), 3);
        assert!(!map.is_empty());

        let entries: Vec<_> = map.iter().collect();
        assert_eq!(
            entries,
            vec![(0, 10, &"first"), (10, 10, &"second"), (20, 10, &"third")]
        );

        let rev_entries: Vec<_> = map.iter().rev().collect();
        assert_eq!(
            rev_entries,
            vec![(20, 10, &"third"), (10, 10, &"second"), (0, 10, &"first")]
        );
    }

    #[test]
    fn overlap_cases() {
        let mut map = RangeMap::new();
        map.insert(100, 50, "mid").unwrap(); // [100, 149]

        // Touching neighbors do not overlap.
        assert!(!map.overlaps(50, 50)); // [50, 99]
        assert!(!map.overlaps(150, 50)); // [150, 199]
        assert!(!map.overlaps(100, 0));
        assert!(!map.overlaps(120, 0));

        // Every form of overlap must be rejected.
        for (base, len) in [
            (100, 50), // exact match
            (99, 2),   // overlaps first byte (prefix)
            (90, 20),  // partial prefix overlap
            (149, 1),  // last byte inside
            (140, 20), // partial suffix overlap
            (110, 10), // strictly contained inside
            (100, 10), // prefix inside
            (140, 10), // suffix inside
            (50, 200), // strictly enclosing
            (100, 60), // extending past end
            (90, 60),  // extending before start
        ] {
            assert!(
                map.overlaps(base, len),
                "expected overlap for [{base}, {base}+{len})"
            );
            assert_eq!(
                map.check_insert(base, len),
                Err(RangeMapError::Overlap),
                "expected check_insert Overlap for [{base}, {base}+{len})"
            );
            assert_eq!(
                map.insert(base, len, "dup"),
                Err(RangeMapError::Overlap),
                "expected insert Overlap for [{base}, {base}+{len})"
            );
        }

        // Insert another disjoint entry and verify bridging overlap across a gap.
        map.insert(200, 20, "high").unwrap(); // [200, 219]
        assert!(!map.overlaps(150, 50)); // exact gap [150, 199]
        assert!(map.overlaps(149, 52)); // spans both neighbors
        assert!(map.overlaps(150, 51)); // starts in gap, hits "high"
        assert!(map.overlaps(149, 51)); // starts in "mid", ends at 199
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn u64_max_boundary_and_overflow() {
        let mut map = RangeMap::new();

        // Overflow cases.
        assert_eq!(map.insert(u64::MAX, 2, 1), Err(RangeMapError::Overflow));
        assert_eq!(
            map.insert(u64::MAX - 9, 11, 1),
            Err(RangeMapError::Overflow)
        );
        assert_eq!(map.insert(2, u64::MAX, 1), Err(RangeMapError::Overflow));
        assert_eq!(
            map.check_insert(u64::MAX, u64::MAX),
            Err(RangeMapError::Overflow)
        );

        // Exact inclusive boundary `[0, u64::MAX - 1]` + `[u64::MAX, u64::MAX]`.
        map.insert(0, u64::MAX, 1).unwrap();
        assert!(!map.overlaps(u64::MAX, 1));
        assert!(!map.overlaps(u64::MAX, 2));
        map.insert(u64::MAX, 1, 2).unwrap();
        assert!(map.overlaps(u64::MAX, 1));
        assert!(map.overlaps(u64::MAX, 2));
        assert!(map.overlaps(0, 1));
        assert_eq!(map.insert(u64::MAX, 1, 3), Err(RangeMapError::Overlap));
        assert_eq!(map.len(), 2);
        assert_eq!(map.remove_exact(u64::MAX, 1), Some(2));
        assert_eq!(map.remove_exact(0, u64::MAX), Some(1));
        assert!(map.is_empty());

        // Exact inclusive boundary `[0, 0]` + `[1, u64::MAX]`.
        map.insert(1, u64::MAX, 10).unwrap();
        assert!(!map.overlaps(0, 1));
        assert!(map.overlaps(0, 2));
        map.insert(0, 1, 20).unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(map.remove_exact(1, u64::MAX), Some(10));
        assert_eq!(map.remove_exact(0, 1), Some(20));
        assert!(map.is_empty());

        // Non-overlapping checks ending at u64::MAX.
        map.insert(u64::MAX - 1, 2, 42).unwrap();
        assert!(!map.overlaps(u64::MAX - 10, 9));
        assert!(map.overlaps(u64::MAX - 10, 10));
        assert_eq!(map.insert(u64::MAX - 10, 9, 41), Ok(()));
        assert_eq!(map.insert(u64::MAX, 1, 43), Err(RangeMapError::Overlap));
    }

    #[test]
    fn remove_exact_and_reinsert() {
        let mut map = RangeMap::new();
        map.insert(10, 20, "x").unwrap();

        // Mismatched base or length leaves the map intact.
        assert_eq!(map.get_exact(10, 19), None);
        assert_eq!(map.get_exact(10, 21), None);
        assert_eq!(map.get_exact(11, 20), None);
        assert_eq!(map.remove_exact(10, 0), None);
        assert_eq!(map.remove_exact(10, 19), None);
        assert_eq!(map.remove_exact(10, 21), None);
        assert_eq!(map.remove_exact(11, 19), None);
        assert_eq!(map.remove_exact(0, 20), None);
        assert_eq!(map.len(), 1);
        assert_eq!(map.get_exact(10, 20), Some(&"x"));

        // Exact match removes and allows reinsertion with a different layout.
        assert_eq!(map.remove_exact(10, 20), Some("x"));
        assert!(map.is_empty());
        assert_eq!(map.remove_exact(10, 20), None);

        map.insert(10, 10, "a").unwrap();
        map.insert(20, 10, "b").unwrap();
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn iter_mut_and_clear() {
        let mut map = RangeMap::new();
        map.insert(0x2000, 0x1000, 2u32).unwrap();
        map.insert(0x0000, 0x1000, 1u32).unwrap();
        map.insert(0x4000, 0x2000, 3u32).unwrap();

        let mut seen = Vec::new();
        for (base, len, val) in map.iter_mut().rev() {
            *val *= 10;
            seen.push((base, len, *val));
        }
        assert_eq!(
            seen,
            vec![
                (0x4000, 0x2000, 30),
                (0x2000, 0x1000, 20),
                (0x0000, 0x1000, 10)
            ]
        );

        map.clear();
        assert!(map.is_empty());
        assert_eq!(map.len(), 0);
        assert!(!map.overlaps(0x0000, 0x1000));
        assert_eq!(map.insert(0x0000, 0x6000, 99), Ok(()));
    }
}
