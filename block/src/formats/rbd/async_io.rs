// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Asynchronous I/O engine backed by librbd.
//!
//! Each virtqueue worker owns one [`RbdAsyncIo`] and therefore one
//! completion queue. All queues share the same [`RbdImageHandle`]; librbd
//! is responsible for multiplexing the requests. Completions are delivered
//! on librbd's internal threads and are forwarded to the worker through an
//! eventfd, matching the completion model used by the other block backends.

use std::collections::VecDeque;
use std::ffi::{c_int, c_void};
use std::sync::{Arc, Mutex};
use std::{io, ptr};

use log::warn;
use vmm_sys_util::eventfd::EventFd;

use super::image::{InFlight, RbdImageHandle};
use super::sys::*;
use crate::async_io::{
    AsyncIo, AsyncIoCompletion, AsyncIoError, AsyncIoOperation, AsyncIoResult, DiskFileError,
};
use crate::error::{BlockError, BlockErrorKind, BlockResult};

/// Completion queue shared with librbd completion callbacks.
struct CompletionQueue {
    done: Mutex<VecDeque<AsyncIoCompletion>>,
    eventfd: EventFd,
}

impl CompletionQueue {
    fn new() -> io::Result<Self> {
        Ok(Self {
            done: Mutex::new(VecDeque::new()),
            eventfd: EventFd::new(libc::EFD_NONBLOCK)?,
        })
    }

    fn notifier(&self) -> &EventFd {
        &self.eventfd
    }

    fn complete(&self, completion: AsyncIoCompletion) {
        self.done.lock().unwrap().push_back(completion);
        if let Err(error) = self.eventfd.write(1) {
            warn!("Failed to signal RBD completion eventfd: {error}");
        }
    }

    fn next_completed(&self) -> Option<AsyncIoCompletion> {
        self.done.lock().unwrap().pop_front()
    }
}

/// Context owned by one librbd completion.
struct AioCtx {
    queue: Arc<CompletionQueue>,
    in_flight: Arc<InFlight>,
    op: Option<AsyncIoOperation>,
    user_data: u64,
    total_len: usize,
    is_read: bool,
    iovecs: Vec<iovec>,
}

/// Simple (non-guest-memory) operation submitted through librbd.
#[derive(Clone, Copy, Debug)]
enum SimpleOp {
    Flush,
    Discard { offset: u64, length: u64 },
    WriteZeroes { offset: u64, length: u64 },
}

impl SimpleOp {
    fn error(&self, error: io::Error) -> AsyncIoError {
        match self {
            Self::Flush => AsyncIoError::Fsync(error),
            Self::Discard { .. } => AsyncIoError::PunchHole(error),
            Self::WriteZeroes { .. } => AsyncIoError::WriteZeroes(error),
        }
    }
}

fn data_error(is_read: bool, error: io::Error) -> AsyncIoError {
    if is_read {
        AsyncIoError::ReadVectored(error)
    } else {
        AsyncIoError::WriteVectored(error)
    }
}

/// librbd completion callback.
///
/// SAFETY: librbd calls this exactly once for every completion created with
/// `rbd_aio_create_completion`; `arg` is the `Box<AioCtx>` we passed in and
/// `c` is the matching completion handle.
unsafe extern "C" fn completion_cb(c: rbd_completion_t, arg: *mut c_void) {
    // SAFETY: `arg` is the Box<AioCtx> passed to rbd_aio_create_completion.
    let ctx = unsafe { Box::from_raw(arg.cast::<AioCtx>()) };
    // SAFETY: `c` is the completion handle associated with this callback.
    let ret = unsafe { rbd_aio_get_return_value(c) };
    // SAFETY: the callback owns the completion and releases it exactly once.
    unsafe { rbd_aio_release(c) };

    // Read/write completions report the number of transferred bytes; simple
    // operations report 0 on success. Negative values are -errno.
    let result = i32::try_from(ret).unwrap_or(-libc::EIO);
    let AioCtx {
        queue,
        in_flight,
        op,
        user_data,
        total_len,
        is_read,
        ..
    } = *ctx;

    if is_read && ret >= 0 && (ret as usize) < total_len {
        warn!("RBD short read: returned {ret} of {total_len} bytes");
    }

    let completion = match op {
        Some(op) => AsyncIoCompletion::from_operation(op, result),
        None => AsyncIoCompletion::new(user_data, result, None),
    };

    queue.complete(completion);
    in_flight.decrement();
}

/// Per-virtqueue librbd I/O engine.
pub(crate) struct RbdAsyncIo {
    image: Arc<RbdImageHandle>,
    queue: Arc<CompletionQueue>,
}

impl RbdAsyncIo {
    pub(crate) fn new(image: Arc<RbdImageHandle>) -> BlockResult<Self> {
        let queue = CompletionQueue::new()
            .map_err(|e| BlockError::new(BlockErrorKind::Io, DiskFileError::NewAsyncIo(e)))?;
        Ok(Self {
            image,
            queue: Arc::new(queue),
        })
    }

    fn submit_simple(&self, user_data: u64, simple: SimpleOp) -> AsyncIoResult<()> {
        let in_flight = self.image.in_flight();
        in_flight.increment();

        let ctx = Box::new(AioCtx {
            queue: Arc::clone(&self.queue),
            in_flight: Arc::clone(&in_flight),
            op: None,
            user_data,
            total_len: 0,
            is_read: false,
            iovecs: Vec::new(),
        });
        let ctx_ptr = Box::into_raw(ctx);

        let mut completion: rbd_completion_t = ptr::null_mut();
        // SAFETY: the callback and context are valid until the completion
        // fires; the box is reclaimed by the callback or on failure below.
        let ret = unsafe {
            rbd_aio_create_completion(ctx_ptr.cast(), Some(completion_cb), &mut completion)
        };
        if ret < 0 {
            // SAFETY: no completion was created, so the callback will not run.
            drop(unsafe { Box::from_raw(ctx_ptr) });
            in_flight.decrement();
            return Err(simple.error(errno_error(ret, "rbd_aio_create_completion")));
        }

        // SAFETY: `completion` was created above, the image handle is open,
        // and the context outlives the operation.
        let ret = unsafe {
            match simple {
                SimpleOp::Flush => rbd_aio_flush(self.image.raw_image(), completion),
                SimpleOp::Discard { offset, length } => {
                    rbd_aio_discard(self.image.raw_image(), offset, length, completion)
                }
                SimpleOp::WriteZeroes { offset, length } => rbd_aio_write_zeroes(
                    self.image.raw_image(),
                    offset,
                    length as usize,
                    completion,
                    RBD_WRITE_ZEROES_FLAG_THICK_PROVISION as c_int,
                    0,
                ),
            }
        };
        if ret < 0 {
            // SAFETY: submission failed, so the completion callback will not
            // run; release the unused completion and reclaim the context.
            unsafe { rbd_aio_release(completion) };
            // SAFETY: the callback will not fire after a failed submission.
            drop(unsafe { Box::from_raw(ctx_ptr) });
            in_flight.decrement();
            return Err(simple.error(errno_error(ret, "rbd_aio_*")));
        }

        Ok(())
    }
}

impl AsyncIo for RbdAsyncIo {
    fn notifier(&self) -> &EventFd {
        self.queue.notifier()
    }

    fn alignment(&self) -> Option<u64> {
        // librbd accepts arbitrary user buffer alignment.
        None
    }

    fn submit_data_operation(&mut self, op: AsyncIoOperation) -> AsyncIoResult<()> {
        let is_read = op.is_read();
        let offset = op.offset();
        let total_len = op.total_len();
        let user_data = op.user_data();

        if offset < 0 {
            return Err(data_error(
                is_read,
                io::Error::new(io::ErrorKind::InvalidInput, "negative RBD offset"),
            ));
        }
        if total_len == 0 {
            self.queue
                .complete(AsyncIoCompletion::from_operation(op, 0));
            return Ok(());
        }
        if total_len > i32::MAX as usize {
            return Err(data_error(
                is_read,
                io::Error::other("RBD request is larger than i32::MAX bytes"),
            ));
        }

        let iovecs: Vec<iovec> = op
            .iovecs()
            .iter()
            .map(|iov| iovec {
                iov_base: iov.iov_base,
                iov_len: iov.iov_len,
            })
            .collect();
        let iovcnt = i32::try_from(iovecs.len())
            .map_err(|_| data_error(is_read, io::Error::other("too many RBD iovecs")))?;

        let in_flight = self.image.in_flight();
        in_flight.increment();

        let ctx = Box::new(AioCtx {
            queue: Arc::clone(&self.queue),
            in_flight: Arc::clone(&in_flight),
            op: Some(op),
            user_data,
            total_len,
            is_read,
            iovecs,
        });
        let iovecs_ptr = ctx.iovecs.as_ptr();
        let ctx_ptr = Box::into_raw(ctx);

        let mut completion: rbd_completion_t = ptr::null_mut();
        // SAFETY: the callback and context are valid until the completion
        // fires; the box is reclaimed by the callback or on failure below.
        let ret = unsafe {
            rbd_aio_create_completion(ctx_ptr.cast(), Some(completion_cb), &mut completion)
        };
        if ret < 0 {
            // SAFETY: no completion was created, so the callback will not run.
            drop(unsafe { Box::from_raw(ctx_ptr) });
            in_flight.decrement();
            return Err(data_error(
                is_read,
                errno_error(ret, "rbd_aio_create_completion"),
            ));
        }

        // SAFETY: `iovecs_ptr` points into the boxed context, the image
        // handle is open, and the guest-memory buffers are kept alive by
        // the AsyncIoOperation stored in the same context.
        let ret = unsafe {
            if is_read {
                rbd_aio_readv(
                    self.image.raw_image(),
                    iovecs_ptr,
                    iovcnt,
                    offset as u64,
                    completion,
                )
            } else {
                rbd_aio_writev(
                    self.image.raw_image(),
                    iovecs_ptr,
                    iovcnt,
                    offset as u64,
                    completion,
                )
            }
        };
        if ret < 0 {
            // SAFETY: submission failed, so the completion callback will not
            // run; release the unused completion and reclaim the context.
            unsafe { rbd_aio_release(completion) };
            // SAFETY: the callback will not fire after a failed submission.
            drop(unsafe { Box::from_raw(ctx_ptr) });
            in_flight.decrement();
            return Err(data_error(
                is_read,
                errno_error(ret, "rbd_aio_readv/writev"),
            ));
        }

        Ok(())
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        match user_data {
            Some(user_data) => self.submit_simple(user_data, SimpleOp::Flush),
            None => {
                // SAFETY: the image handle is open.
                check(unsafe { rbd_flush(self.image.raw_image()) }, "rbd_flush")
                    .map_err(AsyncIoError::Fsync)
            }
        }
    }

    fn next_completed_request(&mut self) -> Option<AsyncIoCompletion> {
        self.queue.next_completed()
    }

    fn punch_hole(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        if length == 0 {
            self.queue
                .complete(AsyncIoCompletion::new(user_data, 0, None));
            return Ok(());
        }
        self.submit_simple(user_data, SimpleOp::Discard { offset, length })
    }

    fn write_zeroes(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        if length == 0 {
            self.queue
                .complete(AsyncIoCompletion::new(user_data, 0, None));
            return Ok(());
        }
        self.submit_simple(user_data, SimpleOp::WriteZeroes { offset, length })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_queue_roundtrip() {
        let queue = CompletionQueue::new().unwrap();
        assert!(queue.next_completed().is_none());

        queue.complete(AsyncIoCompletion::new(7, 42, None));

        let completion = queue.next_completed().unwrap();
        assert_eq!(completion.user_data, 7);
        assert_eq!(completion.result, 42);
        assert!(queue.next_completed().is_none());
        assert_eq!(queue.notifier().read().unwrap(), 1);
    }
}
