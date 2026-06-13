// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

pub mod rmw;
pub mod submit;

use crate::async_io::AsyncIoOperation;

/// `[offset, offset + len)` rounded outward to `alignment`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlignedRange {
    pub aligned_offset: u64,
    pub aligned_len: u64,
    pub head_pad: u64,
    pub tail_pad: u64,
}

/// Rounds `[offset, offset + len)` outward to `alignment`. Returns
/// `None` when `len` is zero or on overflow.
pub fn aligned_range(offset: u64, len: u64, alignment: u64) -> Option<AlignedRange> {
    debug_assert!(alignment.is_power_of_two() && alignment > 0);
    if len == 0 {
        return None;
    }
    let mask = alignment - 1;
    let aligned_offset = offset & !mask;
    let end = offset.checked_add(len)?;
    let aligned_end = end.checked_add(mask).map(|v| v & !mask)?;
    let aligned_len = aligned_end - aligned_offset;
    Some(AlignedRange {
        aligned_offset,
        aligned_len,
        head_pad: offset - aligned_offset,
        tail_pad: aligned_end - end,
    })
}

/// Returns true when `op` can be submitted directly at `alignment`.
/// Disk offset and every iovec base and length must be aligned.
pub fn op_is_aligned(op: &AsyncIoOperation, alignment: u64) -> bool {
    debug_assert!(alignment.is_power_of_two() && alignment > 0);
    if alignment <= 1 {
        return true;
    }
    let mask = (alignment - 1) as usize;
    if (op.offset() as u64) & (alignment - 1) != 0 {
        return false;
    }
    op.iovecs()
        .iter()
        .all(|iov| (iov.iov_base as usize) & mask == 0 && iov.iov_len & mask == 0)
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use crate::SECTOR_SIZE;

    #[test]
    fn aligned_range_zero_len() {
        assert_eq!(aligned_range(0, 0, 4096), None);
        assert_eq!(aligned_range(1234, 0, 4096), None);
    }

    #[test]
    fn aligned_range_already_aligned() {
        let r = aligned_range(4096, 8192, 4096).unwrap();
        assert_eq!(
            r,
            AlignedRange {
                aligned_offset: 4096,
                aligned_len: 8192,
                head_pad: 0,
                tail_pad: 0,
            }
        );
    }

    #[test]
    fn aligned_range_head_only() {
        let r = aligned_range(100, 3000, 4096).unwrap();
        assert_eq!(r.aligned_offset, 0);
        assert_eq!(r.aligned_len, 4096);
        assert_eq!(r.head_pad, 100);
        assert_eq!(r.tail_pad, 4096 - 3100);
    }

    #[test]
    fn aligned_range_tail_only() {
        let r = aligned_range(0, 100, 4096).unwrap();
        assert_eq!(r.aligned_offset, 0);
        assert_eq!(r.aligned_len, 4096);
        assert_eq!(r.head_pad, 0);
        assert_eq!(r.tail_pad, 4096 - 100);
    }

    #[test]
    fn aligned_range_head_and_tail() {
        let r = aligned_range(100, 100, 4096).unwrap();
        assert_eq!(r.aligned_offset, 0);
        assert_eq!(r.aligned_len, 4096);
        assert_eq!(r.head_pad, 100);
        assert_eq!(r.tail_pad, 4096 - 200);
    }

    #[test]
    fn aligned_range_spans_multiple_blocks() {
        let r = aligned_range(100, 8200, 4096).unwrap();
        assert_eq!(r.aligned_offset, 0);
        assert_eq!(r.aligned_len, 12288);
        assert_eq!(r.head_pad, 100);
        assert_eq!(r.tail_pad, 12288 - 8300);
    }

    #[test]
    fn aligned_range_single_byte_unaligned() {
        let r = aligned_range(1, 1, 4096).unwrap();
        assert_eq!(r.aligned_offset, 0);
        assert_eq!(r.aligned_len, 4096);
        assert_eq!(r.head_pad, 1);
        assert_eq!(r.tail_pad, 4094);
    }

    #[test]
    fn aligned_range_overflow_end() {
        assert!(aligned_range(u64::MAX, 1, 4096).is_none());
    }

    #[test]
    fn aligned_range_overflow_round_up_end() {
        let offset = u64::MAX - 100;
        assert!(aligned_range(offset, 100, 4096).is_none());
    }

    #[test]
    fn alignment_512_passthrough() {
        let r = aligned_range(SECTOR_SIZE, 2 * SECTOR_SIZE, SECTOR_SIZE).unwrap();
        assert_eq!(
            r,
            AlignedRange {
                aligned_offset: SECTOR_SIZE,
                aligned_len: 2 * SECTOR_SIZE,
                head_pad: 0,
                tail_pad: 0,
            }
        );
    }
}
