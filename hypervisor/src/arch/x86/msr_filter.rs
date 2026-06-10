// Copyright © 2025 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

use std::cell::Cell;

/// Parameters for filtering read and/or write accesses to a range of MSRs.
#[derive(Debug, Clone, Copy, Default)]
pub struct MsrFilterRange<'a> {
    /// The type of operation(s) to filter: `1 << 0`, `1 << 1`, `(1 << 0) | (1 << 1)` refers to read, write, read and write respectively.
    // TODO: Consider using an enum here
    pub flags: u32,
    /// The number of MSRs in this filter range.
    pub nmsrs: u32,
    /// The first MSR index the bitmap starts at.
    pub base: u32,
    /// For bit position P ( 0 <= P <= nmsrs), the operations in `flags` are allowed for MSR:= base + P if the bit is set, otherwise they are denied.
    pub bitmap: &'a [u8],
}

impl<'a> MsrFilterRange<'a> {
    /// Modify the `flags` so that the ops in the bitmap refer to both reads and writes.
    pub fn with_read_write_flags(mut self) -> Self {
        self.flags = 1 | (1 << 1);
        self
    }

    /// Prepare up to [`MAX_FILTERS`] [`MsrFilterRanges`](MsrFilterRange)
    /// that collectively deny each of the MSRs specified in `denied`.
    ///
    /// The second component returned from this function is the number of
    /// valid entries in the returned array.
    ///
    /// # Errors
    ///
    /// This function can only error if more than [`MAX_BITMAP_SIZE`] bytes are required
    /// to construct any of the filters. In that case the number of bytes required for the
    /// largest filter range bitmap will be returned.
    pub(crate) fn denied_to_filter<'b, const MAX_FILTERS: usize, const MAX_BITMAP_SIZE: usize>(
        mut denied: Vec<u32>,
        bitmap_arena: &'a mut Vec<u8>,
        filter_range_buffer: &'b mut [MsrFilterRange<'a>; MAX_FILTERS],
    ) -> Result<&'b [MsrFilterRange<'a>], usize> {
        denied.sort_unstable();
        denied.dedup();

        let denied_sorted = &denied[..];
        let mut range_indices_buffer = [(0, 0); MAX_FILTERS];
        let range_indices =
            denied_to_range_indices::<MAX_FILTERS>(denied_sorted, &mut range_indices_buffer);

        range_indices_to_filter::<MAX_FILTERS, MAX_BITMAP_SIZE>(
            denied_sorted,
            range_indices,
            bitmap_arena,
            filter_range_buffer,
        )
    }
}

/// Convenience function that moves all elements apart from the first and last left by one.
///
/// The slice's first element will be removed from the slice, while the modified
/// slice's last element will be equal to the second last (prior to calling this method).
fn shift_left<T>(slice: &mut [T]) {
    for w in Cell::from_mut(slice).as_slice_of_cells().windows(2) {
        Cell::swap(&w[0], &w[1]);
    }
}

/// Essentially partitions `denied_sorted` into up to [`MAX_FILTERS`] ranges of
/// indices.
///
/// These ranges may then be used to place the MSRs into distinct [`MsrFilterRanges`](MsrFilterRange).
/// In other words; If (a,b) is an entry in the output of this function, then all MSRs in
/// `denied_sorted[a..=b]` are intended to be placed in the same filter range.
///
/// This partition minimizes the amount of memory necessary to construct the bitmaps for each
/// MSR filter range, that collectively cover all MSRs in `denied_sorted`, under the constraint
/// that none of the MSR filter ranges can intersect the x2APIC-related MSR range (0x801..=0x8ff).
///
/// ## Performance
///
/// This function has complexity` O(MAX_FILTERS * denied_sorted.len())` and does not allocate.
fn denied_to_range_indices<'a, const MAX_FILTERS: usize>(
    denied_sorted: &[u32],
    r_buff: &'a mut [(usize, usize); MAX_FILTERS],
) -> &'a [(usize, usize)] {
    let mut d_prevs = [u32::MAX; MAX_FILTERS];
    let mut r_cnt = 0;
    let mut min_dprev = u32::MAX;
    let mut min_pos = 0_usize;

    let compute_dprev = |p: u32, n: u32| {
        // Make dprev impractically large if it overlaps the x2apic MSR range
        if (p <= 0x8ff) && (n > 0x800) {
            u32::MAX
        } else {
            n - p
        }
    };

    // Called as soon as we discover a full contiguous range of MSRs to be denied
    // `r_s` is the index of the first MSR in this range and `r_e` the last.
    let mut eval_deny_range = |r_s: usize, r_e: usize| {
        let last_idx: usize = MAX_FILTERS - 1;
        let is_first = r_cnt == 0;

        let d_prev = if is_first {
            u32::MAX
        } else {
            let l_prev_idx = r_buff[r_cnt - 1].1;
            let l_prev = denied_sorted[l_prev_idx];
            compute_dprev(l_prev, denied_sorted[r_s])
        };

        if r_cnt < MAX_FILTERS {
            d_prevs[r_cnt] = d_prev;
            r_buff[r_cnt] = (r_s, r_e);
            if d_prev < min_dprev {
                min_dprev = d_prev;
                min_pos = r_cnt;
            }
            r_cnt += 1;
        } else {
            // Need to join ranges to find space
            // The idea is to merge the range groups closest to each other
            if d_prev <= min_dprev {
                // Make the final range group cover this range
                r_buff[last_idx].1 = r_e;
            } else {
                // Merge some previously gathered range groups to make space
                r_buff[min_pos - 1].1 = r_buff[min_pos].1;
                // shift every thing after min_pos left
                {
                    shift_left(&mut r_buff[min_pos..]);
                    shift_left(&mut d_prevs[min_pos..]);
                }
                // Now we have space for the new entry
                r_buff[last_idx] = (r_s, r_e);
                d_prevs[last_idx] = d_prev;
                // Recompute minimum meta data
                min_dprev = *d_prevs.iter().min().unwrap();
                min_pos = d_prevs.iter().position(|d| *d == min_dprev).unwrap();
            }
        }
    };
    // Produce all range groups
    let mut offset = 0_usize;
    let mut deny_slice = denied_sorted;
    while let Some(deny_slice_skip1) = deny_slice.get(1..) {
        let Some(pos) = deny_slice_skip1
            .iter()
            .zip(deny_slice)
            .position(|(n, p)| (n - p) > 1)
        else {
            break;
        };
        let r_s = offset;
        let r_e = offset + pos;
        eval_deny_range(r_s, r_e);
        offset = r_e + 1;
        deny_slice = &denied_sorted[offset..];
    }
    // Since there is no gap beyond the last element, we have one final deny range to
    // evaluate
    eval_deny_range(offset, denied_sorted.len() - 1);
    &r_buff[..r_cnt]
}

/// Construct `range_indices.len() (<= MAX_FILTERS)` [`MsrFilterRanges`](MsrFilterRange)
/// to deny all MSRs in `denied_sorted`.
///
/// For each pair `(r_s, r_e)` in `range_indices` there will be a corresponding
/// filter range denying the MSRs in [`denied_sorted[r_s..=r_e]`].
///
/// # Errors
///
/// This function can only error if more than [`MAX_BITMAP_SIZE`] bytes are required
/// to construct any of the filters.
///
/// # Performance
///
/// This function allocates once (but a possibly large allocation) and has otherwise
/// computational complexity `O(MAX_FILTERS * denied_sorted.len())`.
fn range_indices_to_filter<'a, 'b, const MAX_FILTERS: usize, const MAX_BITMAP_SIZE: usize>(
    denied_sorted: &[u32],
    range_indices: &[(usize, usize)],
    bitmap_arena: &'a mut Vec<u8>,
    filter_range_buffer: &'b mut [MsrFilterRange<'a>; MAX_FILTERS],
) -> Result<&'b [MsrFilterRange<'a>], usize> {
    let mut out = [MsrFilterRange::default().with_read_write_flags(); MAX_FILTERS];
    let num_filter_ranges = range_indices.len();
    let mut max_size = 0;
    let bytes_to_allocate: usize = range_indices
        .iter()
        .copied()
        .map(|(s, e)| {
            let size = (((denied_sorted[e] - denied_sorted[s]) + 1).div_ceil(8)) as usize;
            max_size = std::cmp::max(max_size, size);
            size
        })
        .sum();

    if max_size > MAX_BITMAP_SIZE {
        return Err(max_size);
    }

    bitmap_arena.extend(std::iter::repeat_n(u8::MAX, bytes_to_allocate));

    let mut arena_slice = &mut bitmap_arena[..];
    for (idx, (r_s, r_e)) in range_indices.iter().enumerate() {
        let base = denied_sorted[*r_s];
        let nmsrs = (denied_sorted[*r_e] - denied_sorted[*r_s]) + 1;
        let (bm, rest) = arena_slice.split_at_mut(nmsrs.div_ceil(8) as usize);
        arena_slice = rest;
        for msr in &denied_sorted[*r_s..=*r_e] {
            let d_base = *msr - base;
            let byte_idx = (d_base) / 8;
            let bit = 1 << (d_base % 8);
            bm[byte_idx as usize] ^= bit;
        }
        // Set the fields in the range filter
        {
            let filter_range = &mut out[idx];
            filter_range.base = base;
            filter_range.nmsrs = nmsrs;
            filter_range.bitmap = bm;
        }
    }

    *filter_range_buffer = out;
    Ok(&filter_range_buffer[..num_filter_ranges])
}

#[cfg(test)]
mod unit_tests {
    use super::MsrFilterRange;
    use proptest::prelude::*;

    const MAX_FILTERS: usize = 16;
    const MAX_BITMAP_SIZE: usize = 0x600;

    /// transforms entries out of the x2apic MSR range
    fn prepare(bases: Vec<u32>) -> Vec<u32> {
        // Remove bases in the x2apic MSR range
        let mut v: Vec<u32> = bases
            .into_iter()
            .map(|b| {
                if (0x800..=0x8ff).contains(&b) {
                    b % 0x800
                } else {
                    b
                }
            })
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    fn filter_to_msrs(filter: &[MsrFilterRange<'_>]) -> Vec<u32> {
        let mut out = Vec::new();
        for filter_range in filter {
            let base = filter_range.base;
            let mut num_msrs: u32 = 0;
            for byte in filter_range.bitmap {
                let mut inverse = !(*byte);
                while inverse != 0 {
                    let idx = inverse.trailing_zeros();
                    if num_msrs + idx > filter_range.nmsrs {
                        break;
                    }
                    out.push(base + num_msrs + idx);
                    let lsb = inverse & inverse.wrapping_neg();
                    inverse ^= lsb;
                }
                num_msrs += 8;
            }
        }
        out
    }

    proptest! {
        #[test]
        fn denied_to_filter_works_short(prepared_msrs in (prop::collection::vec(0..u32::MAX, 1..MAX_FILTERS)).prop_map(prepare)) {
            let mut bitmap_arena = Vec::new();
            let mut filter_ranges_buffer = Default::default();
            let filter = MsrFilterRange::denied_to_filter::<MAX_FILTERS, MAX_BITMAP_SIZE>(prepared_msrs.clone(), &mut bitmap_arena, &mut filter_ranges_buffer).unwrap();
            let mut recomputed_msrs = filter_to_msrs(filter);
            recomputed_msrs.sort_unstable();
            prop_assert_eq!(prepared_msrs, recomputed_msrs);
        }
    }

    proptest! {
        #[test]
        fn denied_to_filter_works(prepared_msrs in (prop::collection::vec(0..u32::MAX, 17..70)).prop_map(prepare)) {
            let mut bitmap_arena = Vec::new();
            let mut filter_ranges_buffer = Default::default();
            // Some of these may error due to the necessary bitmaps being too large. We focus on checking that the
            // successful cases satisfy our expectations.
            let Ok(filter) = MsrFilterRange::denied_to_filter::<MAX_FILTERS, MAX_BITMAP_SIZE>(prepared_msrs.clone(), &mut bitmap_arena, &mut filter_ranges_buffer) else {
                return Ok(());
            };
            let mut recomputed_msrs = filter_to_msrs(filter);
            recomputed_msrs.sort_unstable();
            prop_assert_eq!(prepared_msrs, recomputed_msrs);
        }
    }

    // Simple test that doesn't take too long to execute. We can
    // include a more thorough test later if desired.
    #[test]
    fn catches_attempt_to_allocate_too_much_memory() {
        let mut bitmap_arena = Vec::new();
        let denied_msrs: Vec<u32> = (0..MAX_FILTERS * 8 * 2)
            .map(|i| i * MAX_BITMAP_SIZE)
            .map(|v| u32::try_from(v).unwrap())
            .collect();
        let mut filter_ranges_buffer = Default::default();
        let _ = MsrFilterRange::denied_to_filter::<MAX_FILTERS, MAX_BITMAP_SIZE>(
            denied_msrs,
            &mut bitmap_arena,
            &mut filter_ranges_buffer,
        )
        .unwrap_err();
    }
}
