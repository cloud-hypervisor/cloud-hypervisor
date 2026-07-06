// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::io;
use std::ops::Range;

use super::{AsyncIoError, AsyncIoResult, GuestMemoryTarget, OwnedIoBuffer};

/// A single async IO operation.
///
/// Each operation owns or retains the memory target for the duration of the
/// operation so backends can submit it to the kernel or copy through safe helper
/// methods.
#[derive(Debug)]
pub enum AsyncIoOperation {
    /// Read from disk into guest memory.
    ReadToMemory {
        /// Disk offset for the operation.
        offset: libc::off_t,
        /// Guest-memory destination.
        target: GuestMemoryTarget,
        /// Caller-provided completion identifier.
        user_data: u64,
    },
    /// Write from guest memory to disk.
    WriteFromMemory {
        /// Disk offset for the operation.
        offset: libc::off_t,
        /// Guest-memory source.
        target: GuestMemoryTarget,
        /// Caller-provided completion identifier.
        user_data: u64,
    },
    /// Read from disk into an owned host-memory buffer.
    ReadToVec {
        /// Disk offset for the operation.
        offset: libc::off_t,
        /// Owned destination buffer.
        buffer: OwnedIoBuffer,
        /// Caller-provided completion identifier.
        user_data: u64,
    },
    /// Write from an owned host-memory buffer to disk.
    WriteFromVec {
        /// Disk offset for the operation.
        offset: libc::off_t,
        /// Owned source buffer.
        buffer: OwnedIoBuffer,
        /// Caller-provided completion identifier.
        user_data: u64,
    },
}

impl AsyncIoOperation {
    /// Creates an operation that reads from disk into guest memory.
    pub fn read_to_memory(offset: libc::off_t, target: GuestMemoryTarget, user_data: u64) -> Self {
        Self::ReadToMemory {
            offset,
            target,
            user_data,
        }
    }

    /// Creates an operation that writes from guest memory to disk.
    pub fn write_from_memory(
        offset: libc::off_t,
        target: GuestMemoryTarget,
        user_data: u64,
    ) -> Self {
        Self::WriteFromMemory {
            offset,
            target,
            user_data,
        }
    }

    /// Creates an operation that reads from disk into an owned buffer.
    pub fn read_to_vec(offset: libc::off_t, buffer: OwnedIoBuffer, user_data: u64) -> Self {
        Self::ReadToVec {
            offset,
            buffer,
            user_data,
        }
    }

    /// Creates an operation that writes from an owned buffer to disk.
    pub fn write_from_vec(offset: libc::off_t, buffer: OwnedIoBuffer, user_data: u64) -> Self {
        Self::WriteFromVec {
            offset,
            buffer,
            user_data,
        }
    }

    /// Returns the value provided at construction.
    pub fn user_data(&self) -> u64 {
        match self {
            Self::ReadToMemory { user_data, .. }
            | Self::WriteFromMemory { user_data, .. }
            | Self::ReadToVec { user_data, .. }
            | Self::WriteFromVec { user_data, .. } => *user_data,
        }
    }

    /// Returns the disk offset for this operation.
    pub fn offset(&self) -> libc::off_t {
        match self {
            Self::ReadToMemory { offset, .. }
            | Self::WriteFromMemory { offset, .. }
            | Self::ReadToVec { offset, .. }
            | Self::WriteFromVec { offset, .. } => *offset,
        }
    }

    /// Updates the disk offset for this operation.
    pub fn set_offset(&mut self, new_offset: libc::off_t) {
        match self {
            Self::ReadToMemory { offset, .. }
            | Self::WriteFromMemory { offset, .. }
            | Self::ReadToVec { offset, .. }
            | Self::WriteFromVec { offset, .. } => *offset = new_offset,
        }
    }

    /// Returns whether this operation reads from disk.
    pub fn is_read(&self) -> bool {
        matches!(self, Self::ReadToMemory { .. } | Self::ReadToVec { .. })
    }

    /// Rejects an operation whose byte range falls outside a disk of `size` bytes.
    ///
    /// Returns the read/write-specific `AsyncIoError` variant, carrying an
    /// `InvalidData` error, when the offset overflows or `offset + len`
    /// exceeds `size`.
    pub(crate) fn validate_bounds(&self, size: u64) -> AsyncIoResult<()> {
        let bounds_error = || {
            let error = io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Invalid request offset {} and length {}, can't exceed file size {}",
                    self.offset(),
                    self.total_len(),
                    size
                ),
            );
            if self.is_read() {
                AsyncIoError::ReadVectored(error)
            } else {
                AsyncIoError::WriteVectored(error)
            }
        };

        let offset = u64::try_from(self.offset()).map_err(|_| bounds_error())?;
        let len = u64::try_from(self.total_len()).map_err(|_| bounds_error())?;
        let end = offset.checked_add(len).ok_or_else(bounds_error)?;

        if end > size {
            return Err(bounds_error());
        }

        Ok(())
    }

    /// Returns the retained iovec array for kernel submission.
    ///
    /// The iovec pointers are valid while this operation is alive.
    pub fn iovecs(&self) -> &[libc::iovec] {
        match self {
            Self::ReadToMemory { target, .. } | Self::WriteFromMemory { target, .. } => {
                target.iovecs()
            }
            Self::ReadToVec { buffer, .. } | Self::WriteFromVec { buffer, .. } => buffer.iovecs(),
        }
    }

    /// Returns the total number of bytes described by the operation iovecs.
    pub fn total_len(&self) -> usize {
        match self {
            Self::ReadToMemory { target, .. } | Self::WriteFromMemory { target, .. } => {
                target.total_len()
            }
            Self::ReadToVec { buffer, .. } | Self::WriteFromVec { buffer, .. } => {
                buffer.total_len()
            }
        }
    }

    fn checked_range(total_len: usize, start: usize, len: usize) -> io::Result<Range<usize>> {
        if start <= total_len
            && let Some(end) = start.checked_add(len)
            && end <= total_len
        {
            return Ok(start..end);
        }

        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "async I/O buffer range out of bounds",
        ))
    }

    /// Copies bytes into a read operation at `start`.
    pub(crate) fn write_bytes_at(&mut self, start: usize, data: &[u8]) -> io::Result<()> {
        match self {
            Self::ReadToMemory { target, .. } => {
                target.write_bytes_at(start, data).map_err(io::Error::other)
            }
            Self::ReadToVec { buffer, .. } => {
                let range = Self::checked_range(buffer.total_len(), start, data.len())?;
                buffer.as_mut_slice()[range].copy_from_slice(data);
                Ok(())
            }
            Self::WriteFromMemory { .. } | Self::WriteFromVec { .. } => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot write into a write operation",
            )),
        }
    }

    /// Fills a read operation with zeroes at `start`.
    pub(crate) fn fill_zeroes_at(&mut self, start: usize, len: usize) -> io::Result<()> {
        match self {
            Self::ReadToMemory { target, .. } => {
                target.fill_zeroes_at(start, len).map_err(io::Error::other)
            }
            Self::ReadToVec { buffer, .. } => {
                let range = Self::checked_range(buffer.total_len(), start, len)?;
                buffer.as_mut_slice()[range].fill(0);
                Ok(())
            }
            Self::WriteFromMemory { .. } | Self::WriteFromVec { .. } => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot write into a write operation",
            )),
        }
    }

    /// Copies bytes out of a write operation at `start`.
    pub(crate) fn read_bytes_at(&self, start: usize, data: &mut [u8]) -> io::Result<()> {
        match self {
            Self::WriteFromMemory { target, .. } => {
                target.read_bytes_at(start, data).map_err(io::Error::other)
            }
            Self::WriteFromVec { buffer, .. } => {
                let range = Self::checked_range(buffer.total_len(), start, data.len())?;
                data.copy_from_slice(&buffer.as_slice()[range]);
                Ok(())
            }
            Self::ReadToMemory { .. } | Self::ReadToVec { .. } => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot read from a read operation",
            )),
        }
    }

    /// Consumes the operation and returns the buffer needed by its completion.
    ///
    /// Only `ReadToVec` operations return a buffer because callers need the
    /// data they read.
    pub fn into_completion_buffer(self) -> Option<OwnedIoBuffer> {
        match self {
            Self::ReadToVec { buffer, .. } => Some(buffer),
            Self::ReadToMemory { .. }
            | Self::WriteFromMemory { .. }
            | Self::WriteFromVec { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_op(offset: libc::off_t, len: usize) -> AsyncIoOperation {
        AsyncIoOperation::read_to_vec(offset, OwnedIoBuffer::from_vec(vec![0u8; len]), 0)
    }

    fn write_op(offset: libc::off_t, len: usize) -> AsyncIoOperation {
        AsyncIoOperation::write_from_vec(offset, OwnedIoBuffer::from_vec(vec![0u8; len]), 0)
    }

    #[test]
    fn accepts_operation_exactly_filling_size() {
        read_op(0, 512).validate_bounds(512).unwrap();
    }

    #[test]
    fn rejects_read_straddling_size() {
        assert!(matches!(
            read_op(256, 512).validate_bounds(512),
            Err(AsyncIoError::ReadVectored(_))
        ));
    }

    #[test]
    fn rejects_write_straddling_size() {
        assert!(matches!(
            write_op(256, 512).validate_bounds(512),
            Err(AsyncIoError::WriteVectored(_))
        ));
    }

    #[test]
    fn rejects_offset_at_size() {
        assert!(read_op(512, 1).validate_bounds(512).is_err());
    }
}
