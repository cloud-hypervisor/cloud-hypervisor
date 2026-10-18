// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Blocking NBD I/O engine.
//!
//! Each request is sent and its reply consumed before `submit_*` returns,
//! so at most one NBD command is in flight on the connection.

use std::io;

use vmm_sys_util::eventfd::EventFd;

use super::conn::{NbdConn, sub_iovecs};
use super::proto::*;
use super::request::{Added, Chunk, Finished, Tracker};
use crate::async_io::{
    AsyncIo, AsyncIoCompletion, AsyncIoError, AsyncIoOperation, AsyncIoResult, CompletionCommon,
};

pub(crate) struct NbdSync {
    conn: NbdConn,
    completions: CompletionCommon,
    tracker: Tracker,
}

impl NbdSync {
    pub(crate) fn new(conn: NbdConn) -> Self {
        Self {
            tracker: Tracker::new(conn.info()),
            conn,
            completions: CompletionCommon::new(),
        }
    }

    /// Runs every chunk of a request and returns its outcome.
    fn run(&mut self, chunks: Vec<Chunk>) -> Finished {
        let mut finished = None;
        for chunk in chunks {
            let payload = sub_iovecs(
                self.tracker.iovecs(chunk.id),
                chunk.iov_start,
                if matches!(chunk.command, NBD_CMD_READ | NBD_CMD_WRITE) {
                    chunk.length as usize
                } else {
                    0
                },
            );
            // SAFETY: the payload iovecs come from the operation retained by
            // the tracker until the request finishes below.
            let errno = unsafe {
                self.conn
                    .command(chunk.command, chunk.offset, chunk.length, &payload)
            }
            .unwrap_or(libc::EIO);
            finished = self.tracker.chunk_done(chunk.id, errno);
        }
        finished.expect("request finishes with its last chunk")
    }

    /// Runs a request to completion and returns its result.
    fn execute(&mut self, added: Added) -> i32 {
        let finished = match added {
            Added::Chunks(chunks) => self.run(chunks),
            Added::Done(finished) => finished,
        };
        match finished {
            Finished::Completion(c) => {
                let result = c.result;
                self.completions.complete(c);
                result
            }
            Finished::Internal { errno, .. } => -errno,
        }
    }
}

impl AsyncIo for NbdSync {
    fn notifier(&self) -> &EventFd {
        self.completions.notifier()
    }

    fn submit_data_operation(&mut self, op: AsyncIoOperation) -> AsyncIoResult<()> {
        op.validate_bounds(self.conn.info().size)?;
        let added = self.tracker.add_data(op);
        self.execute(added);
        Ok(())
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        if !self.conn.info().has_flag(NBD_FLAG_SEND_FLUSH) {
            if let Some(user_data) = user_data {
                self.completions
                    .complete(AsyncIoCompletion::new(user_data, 0, None));
            }
            return Ok(());
        }
        let added = self.tracker.add_flush(user_data);
        let result = self.execute(added);
        if user_data.is_none() && result < 0 {
            return Err(AsyncIoError::Fsync(io::Error::from_raw_os_error(-result)));
        }
        Ok(())
    }

    fn punch_hole(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        let added = self.tracker.add_trim(offset, length, user_data);
        self.execute(added);
        Ok(())
    }

    fn write_zeroes(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        let added = self.tracker.add_write_zeroes(offset, length, user_data);
        self.execute(added);
        Ok(())
    }

    fn next_completed_request(&mut self) -> Option<AsyncIoCompletion> {
        self.completions.next_completed()
    }

    fn alignment(&self) -> Option<u64> {
        None
    }
}

impl Drop for NbdSync {
    fn drop(&mut self) {
        self.conn.disconnect();
    }
}
