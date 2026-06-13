// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::os::fd::RawFd;

use super::op_is_aligned;
use super::rmw::submit_rmw;
use crate::async_io::{AsyncIoCompletion, AsyncIoError, AsyncIoOperation, AsyncIoResult};

/// Outcome of [`dispatch_op`].
pub enum Dispatch {
    /// RMW served `op` inline. Caller must deliver this completion.
    Done(AsyncIoCompletion),
    /// `op` was not eligible for RMW. Caller proceeds via its regular
    /// submission path.
    Pending(AsyncIoOperation),
}

/// Route `op` through RMW when `direct` is set and `op` is unaligned.
/// Returns the synthetic completion to deposit, or hands `op` back.
pub fn dispatch_op(
    fd: RawFd,
    direct: bool,
    alignment: u64,
    mut op: AsyncIoOperation,
) -> AsyncIoResult<Dispatch> {
    if !direct || op_is_aligned(&op, alignment) {
        return Ok(Dispatch::Pending(op));
    }
    let is_read = op.is_read();
    submit_rmw(fd, &mut op, alignment).map_err(|e| {
        if is_read {
            AsyncIoError::ReadVectored(e)
        } else {
            AsyncIoError::WriteVectored(e)
        }
    })?;
    let total = op.total_len() as i32;
    Ok(Dispatch::Done(AsyncIoCompletion::from_operation(op, total)))
}

#[cfg(test)]
mod unit_tests {
    use std::io::Write;
    use std::os::fd::AsRawFd;

    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::async_io::OwnedIoBuffer;

    fn temp_fd(size: usize) -> (TempFile, RawFd) {
        let tf = TempFile::new().unwrap();
        let pattern: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        tf.as_file().write_all(&pattern).unwrap();
        tf.as_file().sync_all().unwrap();
        let fd = tf.as_file().as_raw_fd();
        (tf, fd)
    }

    fn aligned_read_op(alignment: u64) -> AsyncIoOperation {
        let buf = OwnedIoBuffer::new(alignment as usize, alignment as usize).unwrap();
        AsyncIoOperation::read_to_vec(0, buf, 42)
    }

    fn unaligned_read_op() -> AsyncIoOperation {
        let buf = OwnedIoBuffer::from_vec(vec![0u8; 100]);
        AsyncIoOperation::read_to_vec(100, buf, 7)
    }

    fn unaligned_write_op() -> AsyncIoOperation {
        let buf = OwnedIoBuffer::from_vec(vec![1u8; 100]);
        AsyncIoOperation::write_from_vec(100, buf, 9)
    }

    #[test]
    fn dispatch_pending_when_dio_off() {
        let (_tf, fd) = temp_fd(8192);
        let op = unaligned_read_op();
        match dispatch_op(fd, false, 4096, op).unwrap() {
            Dispatch::Pending(op) => assert_eq!(op.user_data(), 7),
            Dispatch::Done(_) => panic!("expected Pending when direct is off"),
        }
    }

    #[test]
    fn dispatch_pending_when_aligned() {
        let (_tf, fd) = temp_fd(8192);
        let op = aligned_read_op(4096);
        match dispatch_op(fd, true, 4096, op).unwrap() {
            Dispatch::Pending(op) => assert_eq!(op.user_data(), 42),
            Dispatch::Done(_) => panic!("expected Pending for an aligned op"),
        }
    }

    #[test]
    fn dispatch_done_for_unaligned_read() {
        let (_tf, fd) = temp_fd(8192);
        let op = unaligned_read_op();
        match dispatch_op(fd, true, 4096, op).unwrap() {
            Dispatch::Done(c) => {
                assert_eq!(c.user_data, 7);
                assert_eq!(c.result, 100);
                assert!(c.buffer.is_some(), "read completion must return buffer");
            }
            Dispatch::Pending(_) => panic!("expected Done for an unaligned read"),
        }
    }

    #[test]
    fn dispatch_done_for_unaligned_write() {
        let (_tf, fd) = temp_fd(8192);
        let op = unaligned_write_op();
        match dispatch_op(fd, true, 4096, op).unwrap() {
            Dispatch::Done(c) => {
                assert_eq!(c.user_data, 9);
                assert_eq!(c.result, 100);
                assert!(c.buffer.is_none(), "write completion carries no buffer");
            }
            Dispatch::Pending(_) => panic!("expected Done for an unaligned write"),
        }
    }

    #[test]
    fn dispatch_maps_error_by_op_kind() {
        // A closed fd makes submit_rmw fail.
        let bad_fd: RawFd = -1;
        let Err(err) = dispatch_op(bad_fd, true, 4096, unaligned_read_op()) else {
            panic!("expected ReadVectored error for read op");
        };
        assert!(matches!(err, AsyncIoError::ReadVectored(_)));
        let Err(err) = dispatch_op(bad_fd, true, 4096, unaligned_write_op()) else {
            panic!("expected WriteVectored error for write op");
        };
        assert!(matches!(err, AsyncIoError::WriteVectored(_)));
    }
}
