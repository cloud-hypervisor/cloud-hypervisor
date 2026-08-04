// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Executes an op program against the disk image engine.
//!
//! The executor owns the engine handles and turns [`Op`]s into calls on
//! [`AsyncFullDiskFile`] and [`AsyncIo`]. Beyond crashes and panics from the
//! engine itself, it checks the invariants that the trait contract promises
//! to every caller:
//!
//! - an accepted op produces exactly one completion, carrying its own
//!   `user_data`, and a rejected op produces none;
//! - a completion never reports more bytes than were requested, and a
//!   successfully completed read transfers all of them, for a format that
//!   promises no short reads;
//! - a format with a fixed capacity never reports a different size unless a
//!   resize succeeded, and never transfers bytes beyond that size;
//! - a format whose data lives in the image file never advertises more
//!   capacity than the file can hold;
//! - read back data matches the shadow model, when one is available.

use std::marker::PhantomData;
use std::sync::Arc;

use block::async_io::{
    AsyncIo, AsyncIoCompletion, AsyncIoOperation, GuestMemoryTarget, OwnedIoBuffer,
};
use block::disk_file::{AsyncDiskFile, AsyncFullDiskFile};
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

use crate::disk_engine::format::DiskFormat;
use crate::disk_engine::model::Model;
use crate::disk_engine::program::{ring_depth, Op, MAX_OPS, MAX_OP_LEN};

/// Largest disk size the shadow model is kept for.
const MAX_MODEL_LEN: u64 = 8 << 20;

/// Largest size a `Resize` op may ask for.
const MAX_RESIZE_LEN: u64 = 64 << 20;

/// Drives an op program against one opened disk image.
pub struct Executor<F: DiskFormat> {
    disk: Box<dyn AsyncFullDiskFile>,
    clone: Option<Box<dyn AsyncDiskFile>>,
    io: Box<dyn AsyncIo>,
    mem: Arc<GuestMemoryMmap<()>>,
    size: u64,
    model: Option<Model>,
    user_data: u64,
    format: PhantomData<F>,
}

impl<F: DiskFormat> Executor<F> {
    /// Prepares an executor for `disk`.
    ///
    /// `with_model` enables the shadow model, which is only sound when the
    /// image started out valid and its contents are known. Returns `None`
    /// when the engine refuses to create the I/O resources, which is a normal
    /// outcome for a malformed image.
    pub fn new(
        disk: Box<dyn AsyncFullDiskFile>,
        ring_depth: u32,
        with_model: bool,
    ) -> Option<Self> {
        let io = disk.create_async_io(ring_depth).ok()?;
        let size = disk.logical_size().ok()?;
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), MAX_OP_LEN)]).ok()?;
        let model = (with_model && size <= MAX_MODEL_LEN).then(|| Model::new(size as usize));

        let executor = Self {
            disk,
            clone: None,
            io,
            mem: Arc::new(mem),
            size,
            model,
            user_data: 0,
            format: PhantomData,
        };
        executor.check_capacity_backing();

        Some(executor)
    }

    /// Runs up to [`MAX_OPS`] ops.
    pub fn run(&mut self, ops: &[Op]) {
        for op in ops.iter().take(MAX_OPS) {
            self.step(op);
        }
    }

    fn step(&mut self, op: &Op) {
        match *op {
            Op::ReadVec { offset, len } => self.read_vec(offset.resolve(self.size), len.get()),
            Op::WriteVec { offset, len, seed } => {
                self.write_vec(offset.resolve(self.size), len.get(), seed)
            }
            Op::ReadMem { offset, len } => self.read_mem(offset.resolve(self.size), len.get()),
            Op::WriteMem { offset, len, seed } => {
                self.write_mem(offset.resolve(self.size), len.get(), seed)
            }
            Op::PunchHole { offset, len } => self.punch_hole(offset.resolve(self.size), len.get()),
            Op::WriteZeroes { offset, len } => {
                self.write_zeroes(offset.resolve(self.size), len.get())
            }
            Op::Fsync { completion } => self.fsync(completion),
            Op::Resize { size_kib } => self.resize(u64::from(size_kib) * 1024),
            Op::RecreateIo { ring_depth: depth } => {
                if let Ok(io) = self.disk.create_async_io(ring_depth(depth)) {
                    self.io = io;
                }
            }
            Op::UseClone { ring_depth: depth } => self.use_clone(ring_depth(depth)),
            Op::QueryCaps => self.query_caps(),
        }
    }

    fn read_vec(&mut self, offset: u64, len: usize) {
        let user_data = self.next_user_data();
        let buffer = OwnedIoBuffer::from_vec(vec![0u8; len]);
        let op = AsyncIoOperation::read_to_vec(offset as libc::off_t, buffer, user_data);

        let Some(completion) = self.submit(op, user_data) else {
            return;
        };
        let Some(done) = self.read_transferred(&completion, offset, len) else {
            return;
        };
        let Some(buffer) = completion.buffer.as_ref() else {
            panic!("{}: read completion returned no buffer", F::NAME);
        };

        self.check_read(offset, &buffer.as_slice()[..done]);
    }

    fn write_vec(&mut self, offset: u64, len: usize, seed: u8) {
        let data = pattern(offset, len, seed);
        let user_data = self.next_user_data();
        let buffer = OwnedIoBuffer::from_vec(data.clone());
        let op = AsyncIoOperation::write_from_vec(offset as libc::off_t, buffer, user_data);

        let Some(completion) = self.submit(op, user_data) else {
            self.record_unknown(offset, len);
            return;
        };
        match self.transferred(&completion, offset, len) {
            Some(done) => self.record_write(offset, &data[..done], len - done),
            None => self.record_unknown(offset, len),
        }
    }

    fn read_mem(&mut self, offset: u64, len: usize) {
        let Some(target) = self.guest_target(len) else {
            return;
        };
        let user_data = self.next_user_data();
        let op = AsyncIoOperation::read_to_memory(offset as libc::off_t, target, user_data);

        let Some(completion) = self.submit(op, user_data) else {
            return;
        };
        let Some(done) = self.read_transferred(&completion, offset, len) else {
            return;
        };

        let mut data = vec![0u8; done];
        if self.mem.read_slice(&mut data, GuestAddress(0)).is_ok() {
            self.check_read(offset, &data);
        }
    }

    fn write_mem(&mut self, offset: u64, len: usize, seed: u8) {
        let data = pattern(offset, len, seed);
        if self.mem.write_slice(&data, GuestAddress(0)).is_err() {
            return;
        }
        let Some(target) = self.guest_target(len) else {
            return;
        };
        let user_data = self.next_user_data();
        let op = AsyncIoOperation::write_from_memory(offset as libc::off_t, target, user_data);

        let Some(completion) = self.submit(op, user_data) else {
            self.record_unknown(offset, len);
            return;
        };
        match self.transferred(&completion, offset, len) {
            Some(done) => self.record_write(offset, &data[..done], len - done),
            None => self.record_unknown(offset, len),
        }
    }

    fn punch_hole(&mut self, offset: u64, len: usize) {
        let user_data = self.next_user_data();
        let submitted = self.io.punch_hole(offset, len as u64, user_data).is_ok();
        let succeeded = submitted && self.completion_succeeded(user_data);

        if succeeded && F::PUNCH_HOLE_READS_ZEROES {
            self.record_zeroes(offset, len);
        } else {
            self.record_unknown(offset, len);
        }
    }

    fn write_zeroes(&mut self, offset: u64, len: usize) {
        let user_data = self.next_user_data();
        let submitted = self.io.write_zeroes(offset, len as u64, user_data).is_ok();

        if submitted && self.completion_succeeded(user_data) {
            self.record_zeroes(offset, len);
        } else {
            self.record_unknown(offset, len);
        }
    }

    fn fsync(&mut self, completion: bool) {
        let user_data = self.next_user_data();
        let requested = completion.then_some(user_data);

        if self.io.fsync(requested).is_err() {
            return;
        }
        if completion {
            self.expect_completion(user_data);
        } else {
            assert!(
                self.io.next_completed_request().is_none(),
                "{}: fsync without user data produced a completion",
                F::NAME
            );
        }
    }

    fn resize(&mut self, size: u64) {
        let size = size.min(MAX_RESIZE_LEN);
        let _ = self.disk.resize(size);

        // Trust the engine's own report rather than the requested size: a
        // format may round the capacity, and a failed resize may still have
        // changed it.
        let reported = self.disk.logical_size().unwrap_or(self.size);
        if reported == self.size {
            return;
        }

        self.size = reported;
        if reported > MAX_MODEL_LEN {
            self.model = None;
        } else if let Some(model) = self.model.as_mut() {
            model.resize(reported as usize);
        }
    }

    fn use_clone(&mut self, ring_depth: u32) {
        let Ok(clone) = self.disk.try_clone() else {
            return;
        };
        let Ok(io) = clone.create_async_io(ring_depth) else {
            return;
        };

        // The clone shares engine state with the original, so the model stays
        // valid. It is kept alive for as long as its I/O engine is in use.
        self.io = io;
        self.clone = Some(clone);
    }

    fn query_caps(&mut self) {
        let reported = self.disk.logical_size().unwrap_or(self.size);
        if F::FIXED_CAPACITY {
            assert_eq!(
                reported,
                self.size,
                "{}: reported size changed without a resize",
                F::NAME
            );
        } else {
            self.size = reported;
        }

        let _ = self.disk.physical_size();
        self.check_capacity_backing();
        let _ = self.disk.topology();
        let _ = self.disk.supports_sparse_operations();
        let _ = self.disk.supports_zero_flag();
        let _ = self.disk.fd();
        let _ = self.io.alignment();
        let _ = self.io.batch_requests_enabled();
        let _ = self.io.notifier();
    }

    /// Submits a data op and returns its completion, if it was accepted.
    fn submit(&mut self, op: AsyncIoOperation, user_data: u64) -> Option<AsyncIoCompletion> {
        if self.io.submit_data_operation(op).is_err() {
            assert!(
                self.io.next_completed_request().is_none(),
                "{}: rejected op {user_data} produced a completion",
                F::NAME
            );
            return None;
        }

        self.expect_completion(user_data)
    }

    /// Collects the single completion an accepted op owes the caller.
    fn expect_completion(&mut self, user_data: u64) -> Option<AsyncIoCompletion> {
        let Some(completion) = self.io.next_completed_request() else {
            assert!(
                !F::COMPLETES_INLINE,
                "{}: accepted op {user_data} produced no completion",
                F::NAME
            );
            return None;
        };

        assert_eq!(
            completion.user_data,
            user_data,
            "{}: completion carried the wrong user data",
            F::NAME
        );
        assert!(
            self.io.next_completed_request().is_none(),
            "{}: op {user_data} produced more than one completion",
            F::NAME
        );

        Some(completion)
    }

    /// Returns whether the op behind `user_data` completed successfully.
    fn completion_succeeded(&mut self, user_data: u64) -> bool {
        self.expect_completion(user_data)
            .is_some_and(|completion| completion.result >= 0)
    }

    /// Returns how many bytes a completed data op transferred.
    fn transferred(
        &self,
        completion: &AsyncIoCompletion,
        offset: u64,
        len: usize,
    ) -> Option<usize> {
        if completion.result < 0 {
            return None;
        }

        let done = completion.result as usize;
        assert!(
            done <= len,
            "{}: op reported {done} bytes for a {len} byte request",
            F::NAME
        );
        if F::FIXED_CAPACITY {
            assert!(
                done == 0 || offset < self.size,
                "{}: op at offset {offset} transferred {done} bytes past the {} byte capacity",
                F::NAME,
                self.size
            );
        }

        Some(done)
    }

    /// Returns how many bytes a completed read transferred.
    ///
    /// Only a read the engine both accepted and completed successfully
    /// reaches the short read check: a rejected op returns before this, and a
    /// failed one returns `None` from [`Executor::transferred`].
    fn read_transferred(
        &self,
        completion: &AsyncIoCompletion,
        offset: u64,
        len: usize,
    ) -> Option<usize> {
        let done = self.transferred(completion, offset, len)?;

        if F::NO_SHORT_READS {
            assert_eq!(
                done,
                len,
                "{}: read at offset {offset} transferred {done} of the {len} bytes requested",
                F::NAME
            );
        }

        Some(done)
    }

    /// Checks the advertised capacity against the file that holds it.
    ///
    /// Only a format that claims the layout is checked, and only when the
    /// engine answers both queries: an engine that fails a size query has
    /// made no claim to contradict.
    fn check_capacity_backing(&self) {
        let Some(tail) = F::CAPACITY_FILE_TAIL else {
            return;
        };
        let (Ok(logical), Ok(physical)) = (self.disk.logical_size(), self.disk.physical_size())
        else {
            return;
        };

        assert!(
            logical.saturating_add(tail) <= physical,
            "{}: capacity {logical} plus a {tail} byte tail exceeds the {physical} byte image file",
            F::NAME
        );
    }

    fn guest_target(&self, len: usize) -> Option<GuestMemoryTarget> {
        GuestMemoryTarget::new(Arc::clone(&self.mem), &[(GuestAddress(0), len as u32)]).ok()
    }

    fn check_read(&self, offset: u64, data: &[u8]) {
        let Some(model) = self.model.as_ref() else {
            return;
        };
        if let Err(mismatch) = model.check(offset, data) {
            panic!("{}: read back mismatch: {mismatch}", F::NAME);
        }
    }

    fn record_write(&mut self, offset: u64, written: &[u8], missing: usize) {
        let Some(model) = self.model.as_mut() else {
            return;
        };
        model.record_write(offset, written);
        if missing > 0 {
            model.record_unknown(offset + written.len() as u64, missing);
        }
    }

    fn record_zeroes(&mut self, offset: u64, len: usize) {
        if let Some(model) = self.model.as_mut() {
            model.record_zeroes(offset, len);
        }
    }

    fn record_unknown(&mut self, offset: u64, len: usize) {
        if let Some(model) = self.model.as_mut() {
            model.record_unknown(offset, len);
        }
    }

    fn next_user_data(&mut self) -> u64 {
        self.user_data += 1;
        self.user_data
    }
}

/// Builds an offset dependent byte pattern.
///
/// The value of every byte depends on its disk offset, so a read back that
/// returns the right bytes from the wrong place is still caught.
fn pattern(offset: u64, len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| {
            let at = offset.wrapping_add(i as u64);
            seed ^ (at as u8) ^ ((at >> 8) as u8).rotate_left(3) ^ ((at >> 16) as u8).rotate_left(5)
        })
        .collect()
}
