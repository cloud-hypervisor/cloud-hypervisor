// Copyright © 2026, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;
use std::os::unix::fs::FileExt;
use std::sync::Arc;
use std::{cmp, io};

use vmm_sys_util::eventfd::EventFd;

use crate::AlignedFile;
use crate::async_io::{AsyncIo, AsyncIoCompletion, AsyncIoError, AsyncIoOperation, AsyncIoResult};
use crate::formats::vmdk::flat::{ExtentAccess, VmdkExtent};

/// Synchronous, extent-aware I/O worker for flat VMDK images.
///
/// Maps each guest I/O request to one or more backing extents.
///
/// TO-DO: async backends (io_uring/AIO) are not supported.
pub(crate) struct FlatVmdkSync {
    extents: Arc<Vec<VmdkExtent>>,
    size: u64,
    eventfd: EventFd,
    completion_list: VecDeque<AsyncIoCompletion>,
}

impl FlatVmdkSync {
    pub fn new(extents: Arc<Vec<VmdkExtent>>, size: u64) -> io::Result<Self> {
        Ok(FlatVmdkSync {
            extents,
            size,
            eventfd: EventFd::new(libc::EFD_NONBLOCK)?,
            completion_list: VecDeque::new(),
        })
    }

    // Returns the extent containing virtual `offset`, or `None` if out of range.
    fn extent_at(&self, offset: u64) -> Option<&VmdkExtent> {
        self.extents
            .iter()
            .find(|e| offset >= e.virtual_start && offset < e.virtual_start + e.length)
    }

    fn check_access(&self, start: u64, total: u64, is_read: bool) -> io::Result<()> {
        let end = start + total;
        let mut cur = start;
        while cur < end {
            let extent = self.extent_at(cur).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "offset outside any VMDK extent")
            })?;
            match extent.access {
                ExtentAccess::NoAccess => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("VMDK extent at offset {cur} is NOACCESS; request rejected"),
                    ));
                }
                ExtentAccess::ReadOnly if !is_read => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("write to read-only VMDK extent at offset {cur} rejected"),
                    ));
                }
                _ => {}
            }
            cur = extent.virtual_start + extent.length;
        }
        Ok(())
    }

    // Reads or writes a single contiguous segment of one extent through the
    // extent's `AlignedFile`.
    fn segment_io(
        file: &AlignedFile,
        file_offset: u64,
        op: &mut AsyncIoOperation,
        buf_start: usize,
        seg_len: usize,
        is_read: bool,
    ) -> io::Result<usize> {
        // O_DIRECT unaligned
        if file.alignment() != 0 {
            return if is_read {
                file.read_unaligned(file_offset, seg_len, |data| {
                    op.write_bytes_at(buf_start, data)
                })
            } else {
                file.write_unaligned(file_offset, seg_len, |data| {
                    op.read_bytes_at(buf_start, data)
                })
            };
        }

        // Aligned & Buffered
        let mut buf = vec![0u8; seg_len];
        let mut done = 0usize;
        if is_read {
            while done < seg_len {
                match file.read_at(&mut buf[done..], file_offset + done as u64) {
                    Ok(0) => break, // EOF: nothing more to read
                    Ok(n) => done += n,
                    Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }
            op.write_bytes_at(buf_start, &buf[..done])?;
            Ok(done)
        } else {
            op.read_bytes_at(buf_start, &mut buf)?;
            while done < seg_len {
                match file.write_at(&buf[done..], file_offset + done as u64) {
                    Ok(0) => break, // no progress: avoid spinning forever
                    Ok(n) => done += n,
                    Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }
            Ok(done)
        }
    }

    // Single-extent path: the whole request lives in `extent`.
    //
    // The guest iovecs are handed to `AlignedFile::{read,write}_vectored_at`
    fn single_extent_io(
        &self,
        extent: &VmdkExtent,
        op: &mut AsyncIoOperation,
    ) -> io::Result<usize> {
        let file = extent.file.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "VMDK extent is not accessible",
            )
        })?;
        let file_offset = extent.file_base_offset + (op.offset() as u64 - extent.virtual_start);
        let iovecs = op.iovecs();

        // SAFETY: the iovec buffers are owned by `op` and remain valid for the
        // duration of this call.
        unsafe {
            if op.is_read() {
                file.read_vectored_at(iovecs, file_offset)
            } else {
                file.write_vectored_at(iovecs, file_offset)
            }
        }
    }

    // Slow path: the request straddles >= 2 extents.
    //
    // A single guest request here maps onto several *different* backing files,
    // Every segment goes through `segment_io` regardless of
    // alignment.
    fn spanning_io(&self, op: &mut AsyncIoOperation) -> io::Result<usize> {
        let start = op.offset() as u64;
        let total = op.total_len() as u64;
        let is_read = op.is_read();

        let mut done: u64 = 0;
        while done < total {
            let cur = start + done;
            let extent = self.extent_at(cur).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "offset outside any VMDK extent")
            })?;
            let extent_end = extent.virtual_start + extent.length;
            // Bytes handled in this extent before reaching its boundary.
            let seg_len = cmp::min(total - done, extent_end - cur) as usize;
            let file = extent.file.as_ref().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "VMDK extent is not accessible",
                )
            })?;
            let file_offset = extent.file_base_offset + (cur - extent.virtual_start);

            let n = Self::segment_io(file, file_offset, op, done as usize, seg_len, is_read)?;
            done += n as u64;
            if n < seg_len {
                break; // short read/write
            }
        }

        Ok(done as usize)
    }
}

impl AsyncIo for FlatVmdkSync {
    fn notifier(&self) -> &EventFd {
        &self.eventfd
    }

    fn submit_data_operation(&mut self, mut op: AsyncIoOperation) -> AsyncIoResult<()> {
        let start = op.offset() as u64;
        let total = op.total_len() as u64;
        let is_read = op.is_read();

        // Bounds check against the virtual disk size (overflow-safe: `start`
        // is checked before subtracting it from `size`).
        if start > self.size || total > self.size - start {
            let error = io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "VMDK request [{start}, {}) exceeds virtual size {}",
                    start + total,
                    self.size
                ),
            );
            return Err(if is_read {
                AsyncIoError::ReadVectored(error)
            } else {
                AsyncIoError::WriteVectored(error)
            });
        }

        // Reject the request up front if any extent it touches forbids it:
        // NOACCESS extents reject all I/O.
        if total != 0
            && let Err(error) = self.check_access(start, total, is_read)
        {
            return Err(if is_read {
                AsyncIoError::ReadVectored(error)
            } else {
                AsyncIoError::WriteVectored(error)
            });
        }

        let result = if total == 0 {
            Ok(0)
        } else if let Some(extent) = self.extent_at(start) {
            if start + total <= extent.virtual_start + extent.length {
                // Entire request fits in one extent
                self.single_extent_io(extent, &mut op)
            } else {
                // Request crosses an extent boundary
                self.spanning_io(&mut op)
            }
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "offset outside any VMDK extent",
            ))
        };

        let bytes = result.map_err(|e| {
            if is_read {
                AsyncIoError::ReadVectored(e)
            } else {
                AsyncIoError::WriteVectored(e)
            }
        })?;

        self.completion_list
            .push_back(AsyncIoCompletion::from_operation(op, bytes as i32));
        self.eventfd.write(1).unwrap();
        Ok(())
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        // Flush every extent: a single guest flush must durably persist data
        // that may have been written across multiple extent files.
        for extent in self.extents.iter() {
            // Skip NoAccess extents, which have no open file.
            if let Some(file) = extent.file.as_ref() {
                file.sync_all().map_err(AsyncIoError::Fsync)?;
            }
        }

        if let Some(user_data) = user_data {
            self.completion_list
                .push_back(AsyncIoCompletion::new(user_data, 0, None));
            self.eventfd.write(1).unwrap();
        }

        Ok(())
    }

    fn next_completed_request(&mut self) -> Option<AsyncIoCompletion> {
        self.completion_list.pop_front()
    }

    fn punch_hole(&mut self, _offset: u64, _length: u64, _user_data: u64) -> AsyncIoResult<()> {
        // Flat VMDK is not sparse-capable (see `SparseCapable` impl), so this
        // should never be negotiated by the guest.
        Err(AsyncIoError::PunchHole(io::Error::other(
            "punch_hole not supported for flat VMDK",
        )))
    }

    fn write_zeroes(&mut self, _offset: u64, _length: u64, _user_data: u64) -> AsyncIoResult<()> {
        Err(AsyncIoError::WriteZeroes(io::Error::other(
            "write_zeroes not supported for flat VMDK",
        )))
    }
}
