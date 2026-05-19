// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::cmp::min;
use std::fmt;
use std::sync::Arc;

use smallvec::SmallVec;
use vm_memory::bitmap::Bitmap;
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryError, GuestMemoryMmap};

trait GuestMemoryTargetOwner: Send + Sync {
    fn iovec_for_range(
        &self,
        addr: GuestAddress,
        len: usize,
    ) -> Result<libc::iovec, GuestMemoryError>;
    fn write_guest_slice(&self, buf: &[u8], addr: GuestAddress) -> Result<(), GuestMemoryError>;
    fn read_guest_slice(&self, buf: &mut [u8], addr: GuestAddress) -> Result<(), GuestMemoryError>;
}

impl<B> GuestMemoryTargetOwner for GuestMemoryMmap<B>
where
    B: Bitmap + Send + Sync + 'static,
{
    fn iovec_for_range(
        &self,
        addr: GuestAddress,
        len: usize,
    ) -> Result<libc::iovec, GuestMemoryError> {
        let slice = self.get_slice(addr, len)?;
        let guard = slice.ptr_guard_mut();

        Ok(libc::iovec {
            iov_base: guard.as_ptr().cast(),
            iov_len: len,
        })
    }

    fn write_guest_slice(&self, buf: &[u8], addr: GuestAddress) -> Result<(), GuestMemoryError> {
        <Self as Bytes<GuestAddress>>::write_slice(self, buf, addr)
    }

    fn read_guest_slice(&self, buf: &mut [u8], addr: GuestAddress) -> Result<(), GuestMemoryError> {
        <Self as Bytes<GuestAddress>>::read_slice(self, buf, addr)
    }
}

/// Retains a guest-memory Arc and the validated ranges used for I/O.
///
/// Keeping the guest memory arc with the ranges guarantees that the iovecs
/// remain valid for as long as Self is alive. The iovecs are also shared with
/// the kernel and must be stable.
pub struct GuestMemoryTarget {
    owner: Arc<dyn GuestMemoryTargetOwner>,
    ranges: SmallVec<[(GuestAddress, usize); 1]>,
    iovecs: Vec<libc::iovec>,
}

// SAFETY: GuestMemoryTarget owns an Arc to the guest memory backing and
// holds its iovecs in a heap allocation, so moving the target leaves the
// iovec addresses (and the host pointers they reference) stable.
unsafe impl Send for GuestMemoryTarget {}

impl GuestMemoryTarget {
    /// Creates a new `GuestMemoryTarget`.
    ///
    /// The memory Arc is retained for the life of `Self`, making this
    /// appropriate for asynchronous I/O operations on the specified ranges.
    pub fn new<B>(
        mem: Arc<GuestMemoryMmap<B>>,
        ranges: &[(GuestAddress, u32)],
    ) -> Result<Self, GuestMemoryError>
    where
        B: Bitmap + Send + Sync + 'static,
    {
        let retained_ranges: SmallVec<[(GuestAddress, usize); 1]> = ranges
            .iter()
            .copied()
            .filter(|&(_, len)| len != 0)
            .map(|(addr, len)| {
                let len = len as usize;
                mem.get_slice(addr, len)?;
                Ok((addr, len))
            })
            .collect::<Result<SmallVec<[_; 1]>, GuestMemoryError>>()?;

        // iovec_for_range cannot fail: each range was just validated by
        // get_slice above and the Arc keeps the mapping alive.
        let iovecs: Vec<libc::iovec> = retained_ranges
            .iter()
            .map(|&(addr, len)| {
                mem.iovec_for_range(addr, len)
                    .expect("range validated above and retained by owner Arc")
            })
            .collect();

        Ok(Self {
            owner: mem,
            ranges: retained_ranges,
            iovecs,
        })
    }

    /// Returns the raw iovecs to be passed to the kernel for asynchronous I/O.
    #[allow(dead_code)]
    pub(super) fn iovecs(&self) -> &[libc::iovec] {
        &self.iovecs
    }

    /// Returns the total length of the ranges specified at creation.
    pub fn total_len(&self) -> usize {
        self.ranges.iter().map(|(_, len)| len).sum()
    }

    pub(crate) fn write_bytes_at(&self, start: usize, data: &[u8]) -> Result<(), GuestMemoryError> {
        self.for_each_range(start, data.len(), |addr, offset, len| {
            self.owner
                .write_guest_slice(&data[offset..offset + len], addr)
        })
    }

    pub(crate) fn read_bytes_at(
        &self,
        start: usize,
        data: &mut [u8],
    ) -> Result<(), GuestMemoryError> {
        self.for_each_range(start, data.len(), |addr, offset, len| {
            self.owner
                .read_guest_slice(&mut data[offset..offset + len], addr)
        })
    }

    pub(crate) fn fill_zeroes_at(&self, start: usize, len: usize) -> Result<(), GuestMemoryError> {
        let zeroes = [0u8; 4096];
        self.for_each_range(start, len, |addr, _, mut len| {
            let mut offset = 0usize;
            while len > 0 {
                let count = min(len, zeroes.len());
                let addr = addr
                    .checked_add(offset as u64)
                    .ok_or(GuestMemoryError::InvalidGuestAddress(addr))?;
                self.owner.write_guest_slice(&zeroes[..count], addr)?;
                offset += count;
                len -= count;
            }
            Ok(())
        })
    }

    fn for_each_range<F>(&self, start: usize, len: usize, mut f: F) -> Result<(), GuestMemoryError>
    where
        F: FnMut(GuestAddress, usize, usize) -> Result<(), GuestMemoryError>,
    {
        self.validate_range(start, len)?;

        let mut copied = 0usize;
        let mut pos = 0usize;
        for &(addr, range_len) in self.ranges.iter() {
            let range_end = pos + range_len;
            if range_end <= start || copied == len {
                pos = range_end;
                continue;
            }

            let range_start = start.saturating_sub(pos);
            let count = min(range_len - range_start, len - copied);
            let addr = addr
                .checked_add(range_start as u64)
                .ok_or(GuestMemoryError::InvalidGuestAddress(addr))?;
            f(addr, copied, count)?;

            copied += count;
            if copied == len {
                break;
            }
            pos = range_end;
        }

        if copied != len {
            return Err(GuestMemoryError::PartialBuffer {
                expected: len,
                completed: copied,
            });
        }

        Ok(())
    }

    fn validate_range(&self, start: usize, len: usize) -> Result<(), GuestMemoryError> {
        let total_len = self.total_len();
        if start <= total_len
            && let Some(end) = start.checked_add(len)
            && end <= total_len
        {
            return Ok(());
        }

        Err(GuestMemoryError::PartialBuffer {
            expected: len,
            completed: total_len.saturating_sub(start).min(len),
        })
    }
}

impl fmt::Debug for GuestMemoryTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("GuestMemoryTarget");
        debug.field("ranges", &self.ranges.len());
        debug
            .field("iovecs", &self.iovecs.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use vm_memory::{GuestAddress, GuestMemoryMmap};

    use super::GuestMemoryTarget;

    #[test]
    fn iovecs_survive_move() {
        // The iovec array must live on the heap so its address stays valid
        // after the GuestMemoryTarget (and the AsyncIoOperation that owns it)
        // is moved into an in-flight map. Capture the addresses before the
        // move and confirm they still match afterwards.
        let mem = Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 4096)]).unwrap());
        let target = GuestMemoryTarget::new(mem, &[(GuestAddress(0), 512)]).unwrap();
        let iovec_ptr_before = target.iovecs().as_ptr() as usize;
        let iov_base_before = target.iovecs()[0].iov_base as usize;

        let moved = Box::new(target);

        assert_eq!(moved.iovecs().as_ptr() as usize, iovec_ptr_before);
        assert_eq!(moved.iovecs()[0].iov_base as usize, iov_base_before);
        assert_eq!(moved.iovecs().len(), 1);
    }
}
