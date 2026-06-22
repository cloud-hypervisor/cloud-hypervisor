// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//

use std::cmp;
use std::io::Write;
use std::num::Wrapping;

use super::{Error, Result, defs};

pub(super) trait TxBufSource {
    fn copy_to_tx_buf(&self, offset: usize, dst: &mut [u8]) -> Result<()>;
}

impl TxBufSource for [u8] {
    fn copy_to_tx_buf(&self, offset: usize, dst: &mut [u8]) -> Result<()> {
        let end = offset.checked_add(dst.len()).ok_or(Error::PktBufRead)?;
        let src = self.get(offset..end).ok_or(Error::PktBufRead)?;
        dst.copy_from_slice(src);
        Ok(())
    }
}

/// A simple ring-buffer implementation, used by vsock connections to buffer TX (guest -> host)
/// data.  Memory for this buffer is allocated lazily, since buffering will only be needed when
/// the host can't read fast enough.
///
pub struct TxBuf {
    /// The actual u8 buffer - only allocated after the first push.
    data: Option<Box<[u8]>>,
    /// Ring-buffer head offset - where new data is pushed to.
    head: Wrapping<u32>,
    /// Ring-buffer tail offset - where data is flushed from.
    tail: Wrapping<u32>,
}

impl TxBuf {
    /// Total buffer size, in bytes.
    ///
    const SIZE: usize = defs::CONN_TX_BUF_SIZE as usize;

    /// Ring-buffer constructor.
    ///
    pub fn new() -> Self {
        Self {
            data: None,
            head: Wrapping(0),
            tail: Wrapping(0),
        }
    }

    /// Get the used length of this buffer - number of bytes that have been pushed in, but not
    /// yet flushed out.
    ///
    pub fn len(&self) -> usize {
        (self.head - self.tail).0 as usize
    }

    /// Push data from a copy source into the ring-buffer.
    ///
    /// Either the entire length will be pushed to the ring-buffer, or none of it, if there
    /// isn't enough room, in which case `Err(Error::TxBufFull)` is returned.
    ///
    pub(super) fn push_from<S>(&mut self, src: &S, offset: usize, len: usize) -> Result<()>
    where
        S: TxBufSource + ?Sized,
    {
        // Error out if there's no room to push the entire length.
        if self.len() + len > Self::SIZE {
            return Err(Error::TxBufFull);
        }

        if len == 0 {
            return Ok(());
        }

        let data = self
            .data
            .get_or_insert_with(|| vec![0u8; Self::SIZE].into_boxed_slice());

        // Buffer head, as an offset into the data slice.
        let head_ofs = self.head.0 as usize % Self::SIZE;

        // Pushing to this buffer can take either one or two copies: - one copy, if the data
        // fits between `head_ofs` and `Self::SIZE`; or - two copies, if the
        // ring-buffer head wraps around.

        // First copy length: we can only go from the head offset up to the total buffer size.
        let first_len = cmp::min(Self::SIZE - head_ofs, len);
        src.copy_to_tx_buf(offset, &mut data[head_ofs..(head_ofs + first_len)])?;

        // If the data didn't fit, the buffer head will wrap around, and pushing continues
        // from the start of the buffer (`&self.data[0]`).
        if first_len < len {
            let offset = offset.checked_add(first_len).ok_or(Error::PktBufRead)?;
            src.copy_to_tx_buf(offset, &mut data[..(len - first_len)])?;
        }

        // Either way, we've just pushed exactly `len` bytes, so that's the amount by
        // which the (wrapping) buffer head needs to move forward.
        self.head += Wrapping(len as u32);

        Ok(())
    }

    /// Flush the contents of the ring-buffer to a writable stream.
    ///
    /// Return the number of bytes that have been transferred out of the ring-buffer and into
    /// the writable stream.
    ///
    pub fn flush_to<W>(&mut self, sink: &mut W) -> Result<usize>
    where
        W: Write,
    {
        // Nothing to do, if this buffer holds no data.
        if self.is_empty() {
            return Ok(0);
        }

        // Buffer tail, as an offset into the buffer data slice.
        let tail_ofs = self.tail.0 as usize % Self::SIZE;

        // Flushing the buffer can take either one or two writes:
        // - one write, if the tail doesn't need to wrap around to reach the head; or
        // - two writes, if the tail would wrap around: tail to slice end, then slice end to
        //   head.

        // First write length: the lesser of tail to slice end, or tail to head.
        let len_to_write = cmp::min(Self::SIZE - tail_ofs, self.len());

        // It's safe to unwrap here, since we've already checked if the buffer was empty.
        let data = self.data.as_ref().unwrap();

        // Issue the first write and absorb any `WouldBlock` error (we can just try again
        // later).
        let written = sink
            .write(&data[tail_ofs..(tail_ofs + len_to_write)])
            .map_err(Error::TxBufFlush)?;

        // Move the buffer tail ahead by the amount (of bytes) we were able to flush out.
        self.tail += Wrapping(written as u32);

        // If we weren't able to flush out as much as we tried, there's no point in attempting
        // our second write.
        if written < len_to_write {
            return Ok(written);
        }

        // Attempt our second write. This will return immediately if a second write isn't
        // needed, since checking for an empty buffer is the first thing we do in this
        // function.
        //
        // Interesting corner case: if we've already written some data in the first pass,
        // and then the second write fails, we will consider the flush action a success
        // and return the number of bytes written in the first pass.
        Ok(written + self.flush_to(sink).unwrap_or(0))
    }

    /// Check if the buffer holds any data that hasn't yet been flushed out.
    ///
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Push a byte slice onto the ring-buffer.
    ///
    /// A thin convenience wrapper around `push_from`, used only by the unit tests to push a
    /// plain slice without having to spell out the offset and length. Production code pushes
    /// directly from a packet buffer via `push_from`.
    ///
    #[cfg(test)]
    pub fn push(&mut self, src: &[u8]) -> Result<()> {
        self.push_from(src, 0, src.len())
    }
}

#[cfg(test)]
mod unit_tests {
    use std::io::{Error as IoError, ErrorKind, Result as IoResult};

    use super::*;

    struct TestSink {
        data: Vec<u8>,
        err: Option<IoError>,
        capacity: usize,
    }

    impl TestSink {
        const DEFAULT_CAPACITY: usize = 2 * TxBuf::SIZE;
        fn new() -> Self {
            Self {
                data: Vec::with_capacity(Self::DEFAULT_CAPACITY),
                err: None,
                capacity: Self::DEFAULT_CAPACITY,
            }
        }
    }

    impl Write for TestSink {
        fn write(&mut self, src: &[u8]) -> IoResult<usize> {
            if self.err.is_some() {
                return Err(self.err.take().unwrap());
            }
            let len_to_push = cmp::min(self.capacity - self.data.len(), src.len());
            self.data.extend_from_slice(&src[..len_to_push]);
            Ok(len_to_push)
        }
        fn flush(&mut self) -> IoResult<()> {
            Ok(())
        }
    }

    impl TestSink {
        fn clear(&mut self) {
            self.data = Vec::with_capacity(self.capacity);
            self.err = None;
        }
        fn set_err(&mut self, err: IoError) {
            self.err = Some(err);
        }
        fn set_capacity(&mut self, capacity: usize) {
            self.capacity = capacity;
            if self.data.len() > self.capacity {
                self.data.resize(self.capacity, 0);
            }
        }
    }

    #[test]
    fn test_push_nowrap() {
        let mut txbuf = TxBuf::new();
        let mut sink = TestSink::new();
        assert!(txbuf.is_empty());

        assert!(txbuf.data.is_none());
        txbuf.push(&[1, 2, 3, 4]).unwrap();
        txbuf.push(&[5, 6, 7, 8]).unwrap();
        txbuf.flush_to(&mut sink).unwrap();
        assert_eq!(sink.data, [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_push_wrap() {
        let mut txbuf = TxBuf::new();
        let mut sink = TestSink::new();
        let tmp: Vec<u8> = vec![0; TxBuf::SIZE - 2];
        txbuf.push(tmp.as_slice()).unwrap();
        txbuf.flush_to(&mut sink).unwrap();
        sink.clear();

        txbuf.push(&[1, 2, 3, 4]).unwrap();
        assert_eq!(txbuf.flush_to(&mut sink).unwrap(), 4);
        assert_eq!(sink.data, [1, 2, 3, 4]);
    }

    #[test]
    fn test_push_from_wrap() {
        let mut txbuf = TxBuf::new();
        let mut sink = TestSink::new();
        let tmp: Vec<u8> = vec![0; TxBuf::SIZE - 2];
        txbuf.push(tmp.as_slice()).unwrap();
        txbuf.flush_to(&mut sink).unwrap();
        sink.clear();

        let src = [1, 2, 3, 4];
        txbuf.push_from(&src[..], 0, src.len()).unwrap();

        assert_eq!(txbuf.flush_to(&mut sink).unwrap(), 4);
        assert_eq!(sink.data, src);
    }

    #[test]
    fn test_push_error() {
        let mut txbuf = TxBuf::new();
        let mut tmp = Vec::with_capacity(TxBuf::SIZE);

        tmp.resize(TxBuf::SIZE - 1, 0);
        txbuf.push(tmp.as_slice()).unwrap();
        match txbuf.push(&[1, 2]) {
            Err(Error::TxBufFull) => (),
            other => panic!("Unexpected result: {other:?}"),
        }
    }

    #[test]
    fn test_incomplete_flush() {
        let mut txbuf = TxBuf::new();
        let mut sink = TestSink::new();

        sink.set_capacity(2);
        txbuf.push(&[1, 2, 3, 4]).unwrap();
        assert_eq!(txbuf.flush_to(&mut sink).unwrap(), 2);
        assert_eq!(txbuf.len(), 2);
        assert_eq!(sink.data, [1, 2]);

        sink.set_capacity(4);
        assert_eq!(txbuf.flush_to(&mut sink).unwrap(), 2);
        assert!(txbuf.is_empty());
        assert_eq!(sink.data, [1, 2, 3, 4]);
    }

    #[test]
    fn test_flush_error() {
        const EACCESS: i32 = 13;

        let mut txbuf = TxBuf::new();
        let mut sink = TestSink::new();

        txbuf.push(&[1, 2, 3, 4]).unwrap();
        let io_err = IoError::from_raw_os_error(EACCESS);
        sink.set_err(io_err);
        match txbuf.flush_to(&mut sink) {
            Err(Error::TxBufFlush(ref err)) if err.kind() == ErrorKind::PermissionDenied => (),
            other => panic!("Unexpected result: {other:?}"),
        }
    }
}
