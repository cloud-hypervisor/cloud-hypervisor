// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! io_uring based NBD I/O engine.
//!
//! Requests are pipelined on one socket. At most one `IORING_OP_SENDMSG`
//! and one `IORING_OP_RECVMSG` are outstanding at any time:
//!
//! - Sends are serialized: a request header (plus the payload for writes)
//!   is sent with one SENDMSG, and short sends resubmit the remainder
//!   before the next request goes out.
//! - Receives run a small state machine: first the 16 byte simple reply
//!   header, then, for successful reads, the payload straight into the
//!   operation's iovecs. A RECVMSG is only outstanding while requests are
//!   in flight, so an idle engine has no kernel operation on the socket.
//!
//! Replies are matched to requests by cookie and may arrive in any order.

use std::collections::{HashMap, VecDeque};
use std::os::fd::AsRawFd;
use std::{io, mem};

use io_uring::{IoUring, Probe, opcode, squeue, types};
use log::error;
use vmm_sys_util::eventfd::EventFd;

use super::conn::{NbdConn, advance_iovecs, iovecs_len, msghdr_for, sub_iovecs};
use super::proto::*;
use super::request::{Added, Chunk, Finished, Tracker};
use crate::async_io::{
    AsyncIo, AsyncIoCompletion, AsyncIoError, AsyncIoOperation, AsyncIoResult, CompletionCommon,
};

const SEND_TAG: u64 = 1;
const RECV_TAG: u64 = 2;
// One SENDMSG and one RECVMSG at most, with headroom.
const RING_ENTRIES: u32 = 4;

/// Returns true when the running kernel supports the io_uring socket
/// operations used by this engine.
pub(crate) fn supported() -> bool {
    let Ok(ring) = IoUring::new(1) else {
        return false;
    };
    let mut probe = Probe::new();
    ring.submitter().register_probe(&mut probe).is_ok()
        && probe.is_supported(opcode::SendMsg::CODE)
        && probe.is_supported(opcode::RecvMsg::CODE)
}

#[derive(Clone, Copy, Debug)]
enum Phase {
    Send { cookie: u64 },
    RecvHeader,
    RecvPayload { cookie: u64 },
}

/// State of one outstanding SENDMSG or RECVMSG.
///
/// Boxed so that `header`, `iovs` and `msg` keep stable addresses while
/// the kernel references them.
struct Transfer {
    header: [u8; NBD_REQUEST_SIZE],
    iovs: Vec<libc::iovec>,
    msg: libc::msghdr,
    phase: Phase,
}

// SAFETY: the raw pointers in `iovs` and `msg` refer either to the boxed
// transfer itself or to operation memory retained by the engine's tracker.
// Both move together with the engine, which is used by one thread at a time.
unsafe impl Send for Transfer {}

impl Transfer {
    fn new(header: &[u8], payload: Vec<libc::iovec>, phase: Phase) -> Box<Self> {
        let mut t = Box::new(Transfer {
            header: [0; NBD_REQUEST_SIZE],
            iovs: Vec::new(),
            // SAFETY: msghdr is a plain C struct for which all-zero is valid.
            msg: unsafe { mem::zeroed() },
            phase,
        });
        t.header[..header.len()].copy_from_slice(header);
        let mut iovs = Vec::with_capacity(1 + payload.len());
        iovs.push(libc::iovec {
            iov_base: t.header.as_mut_ptr().cast(),
            iov_len: header.len(),
        });
        iovs.extend(payload);
        t.set_iovs(iovs);
        t
    }

    fn set_iovs(&mut self, iovs: Vec<libc::iovec>) {
        self.iovs = iovs;
        self.msg = msghdr_for(&mut self.iovs);
    }

    /// Consumes `n` transferred bytes. Returns true if bytes remain.
    fn advance(&mut self, n: usize) -> bool {
        let mut iovs = mem::take(&mut self.iovs);
        advance_iovecs(&mut iovs, n);
        let more = iovecs_len(&iovs) > 0;
        self.set_iovs(iovs);
        more
    }
}

pub(crate) struct NbdUring {
    conn: NbdConn,
    ring: IoUring,
    completions: CompletionCommon,
    tracker: Tracker,
    /// Every command not yet replied, keyed by cookie.
    chunks: HashMap<u64, Chunk>,
    /// Cookies of commands waiting to be sent.
    queue: VecDeque<u64>,
    send: Option<Box<Transfer>>,
    recv: Option<Box<Transfer>>,
    /// Replies that arrived before their SENDMSG completion was reaped.
    deferred: Vec<(u64, i32)>,
    /// Results of internal requests (blocking flushes).
    internal: HashMap<u64, i32>,
}

impl NbdUring {
    pub(crate) fn new(conn: NbdConn) -> io::Result<Self> {
        let ring = IoUring::new(RING_ENTRIES)?;
        let completions = CompletionCommon::new();
        ring.submitter()
            .register_eventfd(completions.notifier().as_raw_fd())?;
        Ok(Self {
            tracker: Tracker::new(conn.info()),
            conn,
            ring,
            completions,
            chunks: HashMap::new(),
            queue: VecDeque::new(),
            send: None,
            recv: None,
            deferred: Vec::new(),
            internal: HashMap::new(),
        })
    }

    fn idle(&self) -> bool {
        self.send.is_none() && self.recv.is_none() && self.chunks.is_empty()
    }

    fn push(&mut self, entry: &squeue::Entry) -> io::Result<()> {
        // SAFETY: the entry references a boxed Transfer that stays alive
        // until its completion is reaped.
        unsafe { self.ring.submission().push(entry) }
            .map_err(|_| io::Error::other("io_uring submission queue is full"))
    }

    fn submit_send(&mut self) -> io::Result<()> {
        let t = self.send.as_ref().unwrap();
        let entry = opcode::SendMsg::new(types::Fd(self.conn.fd()), &t.msg)
            .flags(libc::MSG_NOSIGNAL as u32)
            .build()
            .user_data(SEND_TAG);
        self.push(&entry).inspect_err(|_| self.send = None)
    }

    fn submit_recv(&mut self) -> io::Result<()> {
        let t = self.recv.as_mut().unwrap();
        let entry = opcode::RecvMsg::new(types::Fd(self.conn.fd()), &mut t.msg)
            .flags(libc::MSG_WAITALL as u32)
            .build()
            .user_data(RECV_TAG);
        self.push(&entry).inspect_err(|_| self.recv = None)
    }

    fn deliver(&mut self, finished: Finished) {
        match finished {
            Finished::Completion(c) => self.completions.complete(c),
            Finished::Internal { id, errno } => {
                self.internal.insert(id, errno);
            }
        }
    }

    fn finish_chunk(&mut self, cookie: u64, errno: i32) {
        if let Some(t) = &self.send
            && matches!(t.phase, Phase::Send { cookie: c } if c == cookie)
        {
            // The kernel may still reference this request's payload.
            self.deferred.push((cookie, errno));
            return;
        }
        if let Some(chunk) = self.chunks.remove(&cookie)
            && let Some(finished) = self.tracker.chunk_done(chunk.id, errno)
        {
            self.deliver(finished);
        }
    }

    /// Submits the next queued request if no send is outstanding, and a
    /// reply header receive while replies are awaited.
    fn try_submit_pending(&mut self) -> io::Result<()> {
        if self.send.is_none() {
            while let Some(cookie) = self.queue.pop_front() {
                let Some(chunk) = self.chunks.get(&cookie).copied() else {
                    continue;
                };
                let header = NbdRequest {
                    flags: 0,
                    command: chunk.command,
                    cookie,
                    offset: chunk.offset,
                    length: chunk.length,
                }
                .encode();
                let payload = if chunk.command == NBD_CMD_WRITE {
                    sub_iovecs(
                        self.tracker.iovecs(chunk.id),
                        chunk.iov_start,
                        chunk.length as usize,
                    )
                } else {
                    Vec::new()
                };
                self.send = Some(Transfer::new(&header, payload, Phase::Send { cookie }));
                self.submit_send()?;
                break;
            }
        }
        if self.recv.is_none() && !self.chunks.is_empty() {
            self.recv = Some(Transfer::new(
                &[0; NBD_SIMPLE_REPLY_SIZE],
                Vec::new(),
                Phase::RecvHeader,
            ));
            self.submit_recv()?;
        }
        self.ring.submit()?;
        Ok(())
    }

    /// Like [`Self::try_submit_pending`], failing the connection on error.
    fn submit_pending(&mut self) {
        if let Err(e) = self.try_submit_pending() {
            self.fail(&e);
        }
    }

    fn on_send(&mut self, res: i32) -> io::Result<()> {
        if res == -libc::EINTR || res == -libc::EAGAIN {
            return self.submit_send();
        }
        if res <= 0 {
            return Err(if res == 0 {
                io::Error::new(io::ErrorKind::WriteZero, "NBD socket accepted no data")
            } else {
                io::Error::from_raw_os_error(-res)
            });
        }
        if self.send.as_mut().unwrap().advance(res as usize) {
            return self.submit_send();
        }
        self.send = None;
        for (cookie, errno) in mem::take(&mut self.deferred) {
            self.finish_chunk(cookie, errno);
        }
        Ok(())
    }

    fn on_recv(&mut self, res: i32) -> io::Result<()> {
        if res == -libc::EINTR || res == -libc::EAGAIN {
            return self.submit_recv();
        }
        if res < 0 {
            return Err(io::Error::from_raw_os_error(-res));
        }
        if res == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "NBD server closed the connection",
            ));
        }
        let t = self.recv.as_mut().unwrap();
        if t.advance(res as usize) {
            return self.submit_recv();
        }

        match t.phase {
            Phase::RecvHeader => {
                let header: [u8; NBD_SIMPLE_REPLY_SIZE] =
                    t.header[..NBD_SIMPLE_REPLY_SIZE].try_into().unwrap();
                let reply = NbdSimpleReply::decode(&header).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "bad NBD reply magic")
                })?;
                let chunk = self.chunks.get(&reply.cookie).copied().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unexpected NBD reply cookie {}", reply.cookie),
                    )
                })?;
                let errno = nbd_errno_to_errno(reply.error);
                if chunk.command == NBD_CMD_READ && errno == 0 && chunk.length > 0 {
                    let payload = sub_iovecs(
                        self.tracker.iovecs(chunk.id),
                        chunk.iov_start,
                        chunk.length as usize,
                    );
                    let t = self.recv.as_mut().unwrap();
                    t.phase = Phase::RecvPayload {
                        cookie: reply.cookie,
                    };
                    t.set_iovs(payload);
                    return self.submit_recv();
                }
                self.recv = None;
                self.finish_chunk(reply.cookie, errno);
            }
            Phase::RecvPayload { cookie } => {
                self.recv = None;
                self.finish_chunk(cookie, 0);
            }
            Phase::Send { .. } => unreachable!(),
        }
        Ok(())
    }

    /// Pops one completion as `(user_data, result)`.
    fn next_cqe(&mut self) -> Option<(u64, i32)> {
        self.ring
            .completion()
            .next()
            .map(|cqe| (cqe.user_data(), cqe.result()))
    }

    /// Processes every available completion. Returns true if any was found.
    fn process_cqes(&mut self) -> bool {
        let mut any = false;
        while let Some((tag, res)) = self.next_cqe() {
            any = true;
            let result = match tag {
                SEND_TAG => self.on_send(res),
                RECV_TAG => self.on_recv(res),
                tag => unreachable!("unknown NBD io_uring tag {tag}"),
            };
            if let Err(e) = result {
                // This completion was reaped and nothing was resubmitted.
                match tag {
                    SEND_TAG => self.send = None,
                    _ => self.recv = None,
                }
                self.fail(&e);
            }
        }
        if any && !self.conn.is_dead() {
            self.submit_pending();
        }
        any
    }

    /// Waits until the kernel no longer references any transfer.
    ///
    /// The socket must have been shut down so outstanding operations
    /// complete promptly.
    fn drain_kernel(&mut self) {
        while self.send.is_some() || self.recv.is_some() {
            if let Err(e) = self.ring.submit_and_wait(1) {
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                // Memory referenced by the kernel must not be freed.
                error!("Failed waiting for NBD io_uring completions, leaking buffers: {e}");
                mem::forget(self.send.take());
                mem::forget(self.recv.take());
                let tracker = Tracker::new(self.conn.info());
                mem::forget(mem::replace(&mut self.tracker, tracker));
                self.chunks.clear();
                return;
            }
            while let Some((tag, _)) = self.next_cqe() {
                match tag {
                    SEND_TAG => self.send = None,
                    RECV_TAG => self.recv = None,
                    _ => {}
                }
            }
        }
    }

    /// Tears the connection down and fails every pending request.
    fn fail(&mut self, e: &io::Error) {
        self.conn.mark_dead(e);
        self.drain_kernel();
        self.queue.clear();
        for (cookie, errno) in mem::take(&mut self.deferred) {
            self.finish_chunk(cookie, errno);
        }
        let cookies: Vec<u64> = self.chunks.keys().copied().collect();
        for cookie in cookies {
            self.finish_chunk(cookie, libc::EIO);
        }
    }

    /// Starts a request. Returns the internal id when it has chunks.
    fn start(&mut self, added: Added) -> Option<u64> {
        match added {
            Added::Done(finished) => {
                self.deliver(finished);
                None
            }
            Added::Chunks(chunks) => {
                let id = chunks[0].id;
                if self.conn.is_dead() {
                    for chunk in chunks {
                        if let Some(finished) = self.tracker.chunk_done(chunk.id, libc::EIO) {
                            self.deliver(finished);
                        }
                    }
                    return Some(id);
                }
                for chunk in chunks {
                    let cookie = self.conn.next_cookie();
                    self.chunks.insert(cookie, chunk);
                    self.queue.push_back(cookie);
                }
                self.submit_pending();
                Some(id)
            }
        }
    }

    /// Drives the ring until internal request `id` completes.
    fn wait_internal(&mut self, id: u64) -> i32 {
        loop {
            if let Some(errno) = self.internal.remove(&id) {
                return errno;
            }
            if self.conn.is_dead() && !self.chunks.values().any(|c| c.id == id) {
                return libc::EIO;
            }
            match self.ring.submit_and_wait(1) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    self.fail(&e);
                    continue;
                }
            }
            self.process_cqes();
        }
    }
}

impl AsyncIo for NbdUring {
    fn notifier(&self) -> &EventFd {
        self.completions.notifier()
    }

    fn submit_data_operation(&mut self, op: AsyncIoOperation) -> AsyncIoResult<()> {
        op.validate_bounds(self.conn.info().size)?;
        let added = self.tracker.add_data(op);
        self.start(added);
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
        match (user_data, self.start(added)) {
            (None, Some(id)) => match self.wait_internal(id) {
                0 => Ok(()),
                errno => Err(AsyncIoError::Fsync(io::Error::from_raw_os_error(errno))),
            },
            _ => Ok(()),
        }
    }

    fn punch_hole(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        let added = self.tracker.add_trim(offset, length, user_data);
        self.start(added);
        Ok(())
    }

    fn write_zeroes(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        let added = self.tracker.add_write_zeroes(offset, length, user_data);
        self.start(added);
        Ok(())
    }

    fn next_completed_request(&mut self) -> Option<AsyncIoCompletion> {
        loop {
            if let Some(completion) = self.completions.next_completed() {
                return Some(completion);
            }
            if !self.process_cqes() {
                return None;
            }
        }
    }

    fn alignment(&self) -> Option<u64> {
        None
    }
}

impl Drop for NbdUring {
    fn drop(&mut self) {
        if self.idle() {
            self.conn.disconnect();
        } else {
            self.conn.close();
            self.drain_kernel();
        }
    }
}
