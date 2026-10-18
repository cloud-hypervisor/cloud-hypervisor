// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Splitting of block requests into NBD commands and aggregation of
//! their replies, shared by the NBD I/O engines.

use std::collections::HashMap;

use super::handshake::NbdExportInfo;
use super::proto::*;
use crate::async_io::{AsyncIoCompletion, AsyncIoOperation};

/// One NBD command that is part of a block request.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Chunk {
    /// Identifier of the request this command belongs to.
    pub(crate) id: u64,
    pub(crate) command: u16,
    pub(crate) offset: u64,
    pub(crate) length: u32,
    /// Byte offset of this command's payload within the operation iovecs.
    pub(crate) iov_start: usize,
}

struct Pending {
    /// `None` for requests issued internally that nobody waits on through
    /// the completion queue.
    user_data: Option<u64>,
    op: Option<AsyncIoOperation>,
    chunks_left: usize,
    errno: i32,
}

impl Pending {
    fn new(user_data: Option<u64>, op: Option<AsyncIoOperation>, chunks_left: usize) -> Self {
        Self {
            user_data,
            op,
            chunks_left,
            errno: 0,
        }
    }

    /// Converts a fully replied request into its outcome.
    fn finish(self, id: u64) -> Finished {
        let result = if self.errno != 0 {
            -self.errno
        } else {
            // Successful data operations report the transferred byte count.
            self.op.as_ref().map_or(0, |op| op.total_len() as i32)
        };
        match self.user_data {
            Some(user_data) => Finished::Completion(match self.op {
                Some(op) => AsyncIoCompletion::from_operation(op, result),
                None => AsyncIoCompletion::new(user_data, result, None),
            }),
            None => Finished::Internal {
                id,
                errno: self.errno,
            },
        }
    }
}

/// Outcome of a fully replied request.
#[derive(Debug)]
pub(crate) enum Finished {
    Completion(AsyncIoCompletion),
    /// Internal request finished with this positive errno (0 on success).
    ///
    /// `id` lets pipelining engines match the result to its waiter.
    Internal {
        #[cfg_attr(not(feature = "io_uring"), allow(dead_code))]
        id: u64,
        errno: i32,
    },
}

/// Result of adding a request.
pub(crate) enum Added {
    Chunks(Vec<Chunk>),
    /// The request needed no NBD command and is already complete.
    Done(Finished),
}

pub(crate) struct Tracker {
    next_id: u64,
    pending: HashMap<u64, Pending>,
    /// Largest READ or WRITE command, aligned to the minimum block size.
    max_data: u32,
    /// Largest TRIM or WRITE_ZEROES command, aligned to the minimum block
    /// size.
    max_command: u32,
}

/// Largest multiple of `align` that is not above `limit`.
fn align_down(limit: u32, align: u32) -> u32 {
    limit / align * align
}

impl Tracker {
    pub(crate) fn new(info: &NbdExportInfo) -> Self {
        Self {
            next_id: 0,
            pending: HashMap::new(),
            max_data: align_down(info.max_block, info.min_block),
            max_command: align_down(u32::MAX, info.min_block),
        }
    }

    fn next_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    /// Splits `[offset, offset + length)` into commands of at most
    /// `max_chunk` bytes.
    fn add(
        &mut self,
        user_data: u64,
        op: Option<AsyncIoOperation>,
        command: u16,
        offset: u64,
        length: u64,
        max_chunk: u32,
    ) -> Added {
        let id = self.next_id();
        let mut chunks = Vec::new();
        let mut done = 0u64;
        while done < length {
            let len = (length - done).min(max_chunk as u64) as u32;
            chunks.push(Chunk {
                id,
                command,
                offset: offset + done,
                length: len,
                iov_start: done as usize,
            });
            done += len as u64;
        }
        let pending = Pending::new(Some(user_data), op, chunks.len());
        if chunks.is_empty() {
            return Added::Done(pending.finish(id));
        }
        self.pending.insert(id, pending);
        Added::Chunks(chunks)
    }

    /// Adds a read or write operation.
    pub(crate) fn add_data(&mut self, op: AsyncIoOperation) -> Added {
        let command = if op.is_read() {
            NBD_CMD_READ
        } else {
            NBD_CMD_WRITE
        };
        let offset = op.offset() as u64;
        let length = op.total_len() as u64;
        let user_data = op.user_data();
        let max = self.max_data;
        self.add(user_data, Some(op), command, offset, length, max)
    }

    /// Adds a flush request.
    ///
    /// `user_data` is `None` for internal requests.
    pub(crate) fn add_flush(&mut self, user_data: Option<u64>) -> Added {
        let id = self.next_id();
        let chunk = Chunk {
            id,
            command: NBD_CMD_FLUSH,
            offset: 0,
            length: 0,
            iov_start: 0,
        };
        let pending = Pending::new(user_data, None, 1);
        self.pending.insert(id, pending);
        Added::Chunks(vec![chunk])
    }

    /// Adds a trim request.
    pub(crate) fn add_trim(&mut self, offset: u64, length: u64, user_data: u64) -> Added {
        let max = self.max_command;
        self.add(user_data, None, NBD_CMD_TRIM, offset, length, max)
    }

    /// Adds a write zeroes request.
    pub(crate) fn add_write_zeroes(&mut self, offset: u64, length: u64, user_data: u64) -> Added {
        let max = self.max_command;
        self.add(user_data, None, NBD_CMD_WRITE_ZEROES, offset, length, max)
    }

    /// Returns the iovecs of the operation owning request `id`.
    pub(crate) fn iovecs(&self, id: u64) -> &[libc::iovec] {
        self.pending
            .get(&id)
            .and_then(|p| p.op.as_ref())
            .map_or(&[], |op| op.iovecs())
    }

    /// Records the reply for one chunk of request `id`.
    ///
    /// Returns the request outcome once its last chunk has been replied.
    /// The first error of a request wins.
    pub(crate) fn chunk_done(&mut self, id: u64, errno: i32) -> Option<Finished> {
        let pending = self.pending.get_mut(&id)?;
        if pending.errno == 0 {
            pending.errno = errno;
        }
        pending.chunks_left -= 1;
        if pending.chunks_left > 0 {
            return None;
        }
        Some(self.pending.remove(&id).unwrap().finish(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::async_io::OwnedIoBuffer;

    fn info(min: u32, max: u32) -> NbdExportInfo {
        NbdExportInfo {
            size: 1 << 30,
            flags: NBD_FLAG_HAS_FLAGS,
            min_block: min,
            opt_block: 4096,
            max_block: max,
        }
    }

    #[test]
    fn data_split_and_aggregate() {
        let mut t = Tracker::new(&info(512, 4000));
        let op = AsyncIoOperation::write_from_vec(4096, OwnedIoBuffer::from_vec(vec![0; 10000]), 7);
        let Added::Chunks(chunks) = t.add_data(op) else {
            panic!("expected chunks");
        };
        // max payload is rounded down to 3584 (7 * 512).
        let lens: Vec<_> = chunks.iter().map(|c| c.length).collect();
        assert_eq!(lens, vec![3584, 3584, 2832]);
        assert_eq!(chunks[1].offset, 4096 + 3584);
        assert_eq!(chunks[2].iov_start, 7168);
        assert!(chunks.iter().all(|c| c.command == NBD_CMD_WRITE));

        let id = chunks[0].id;
        assert!(t.chunk_done(id, 0).is_none());
        assert!(t.chunk_done(id, libc::ENOSPC).is_none());
        match t.chunk_done(id, libc::EIO) {
            Some(Finished::Completion(c)) => {
                assert_eq!(c.user_data, 7);
                assert_eq!(c.result, -libc::ENOSPC);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn read_success_reports_length() {
        let mut t = Tracker::new(&info(1, 1 << 20));
        let op = AsyncIoOperation::read_to_vec(0, OwnedIoBuffer::from_vec(vec![0; 512]), 3);
        let Added::Chunks(chunks) = t.add_data(op) else {
            panic!("expected chunks");
        };
        assert_eq!(chunks.len(), 1);
        match t.chunk_done(chunks[0].id, 0) {
            Some(Finished::Completion(c)) => {
                assert_eq!(c.result, 512);
                assert!(c.buffer.is_some());
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn zero_length_completes_immediately() {
        let mut t = Tracker::new(&info(1, 1 << 20));
        let Added::Done(Finished::Completion(c)) = t.add_trim(0, 0, 9) else {
            panic!("expected immediate completion");
        };
        assert_eq!((c.user_data, c.result), (9, 0));
    }

    #[test]
    fn large_trim_split_and_internal_flush() {
        let mut t = Tracker::new(&info(4096, 1 << 20));
        let Added::Chunks(chunks) = t.add_trim(0, 5 << 30, 1) else {
            panic!("expected chunks");
        };
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].length, align_down(u32::MAX, 4096));

        let Added::Chunks(chunks) = t.add_flush(None) else {
            panic!("expected chunks");
        };
        assert_eq!(chunks.len(), 1);
        assert!(matches!(
            t.chunk_done(chunks[0].id, 0),
            Some(Finished::Internal { errno: 0, .. })
        ));
    }
}
