// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::VecDeque;
use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const MAX_BUFFER_SIZE: usize = 1 << 20;

// Circular buffer implementation for serial output.
// Read from head; push to tail
pub struct SerialBuffer {
    buffer: VecDeque<u8>,
    out: Box<dyn Write + Send>,
    write_out: Arc<AtomicBool>,
}

impl SerialBuffer {
    pub fn new(out: Box<dyn Write + Send>, write_out: Arc<AtomicBool>) -> Self {
        Self {
            buffer: VecDeque::new(),
            out,
            write_out,
        }
    }

    fn fill_buffer(&mut self, buf: &[u8]) {
        if buf.len() >= MAX_BUFFER_SIZE {
            let offset = buf.len() - MAX_BUFFER_SIZE;
            self.buffer = VecDeque::from(buf[offset..].to_vec());
            return;
        }

        let num_allowed_bytes = MAX_BUFFER_SIZE - buf.len();
        if self.buffer.len() > num_allowed_bytes {
            let num_bytes_to_remove = self.buffer.len() - num_allowed_bytes;
            self.buffer.drain(..num_bytes_to_remove);
        }

        self.buffer.extend(buf);
    }

    /// Replaces the downstream writer, leaving any buffered bytes intact.
    pub fn set_out(&mut self, out: Box<dyn Write + Send>) {
        self.out = out;
    }
}

impl Write for SerialBuffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Simply fill the buffer if we're not allowed to write to the out
        // device.
        if !self.write_out.load(Ordering::Acquire) {
            self.fill_buffer(buf);
            return Ok(buf.len());
        }

        // In case we're allowed to write to the out device, we flush the
        // content of the buffer.
        self.flush()?;

        // If after flushing the buffer, it's still not empty, that means
        // only a subset of the bytes was written and we should fill the buffer
        // with what's coming from the serial.
        if !self.buffer.is_empty() {
            self.fill_buffer(buf);
            return Ok(buf.len());
        }

        // We reach this point if we're allowed to write to the out device
        // and we know there's nothing left in the buffer.
        let mut offset = 0;
        loop {
            match self.out.write(&buf[offset..]) {
                Ok(written_bytes) => {
                    if written_bytes < buf.len() - offset {
                        offset += written_bytes;
                        continue;
                    }
                }
                Err(e) => {
                    if !matches!(e.kind(), io::ErrorKind::WouldBlock) {
                        return Err(e);
                    }
                    self.fill_buffer(&buf[offset..]);
                }
            }
            break;
        }

        // Make sure we flush anything that might have been written to the
        // out device.
        self.out.flush()?;

        Ok(buf.len())
    }

    // This function flushes the content of the buffer to the out device if
    // it is allowed to, otherwise this is a no-op.
    fn flush(&mut self) -> io::Result<()> {
        if !self.write_out.load(Ordering::Acquire) {
            return Ok(());
        }

        while let Some(byte) = self.buffer.pop_front() {
            if self.out.write_all(&[byte]).is_err() {
                self.buffer.push_front(byte);
                break;
            }
        }
        self.out.flush()
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use super::SerialBuffer;

    // A writer that appends into a shared Vec so tests can inspect what the
    // buffer wrote through to its downstream sink.
    #[derive(Clone)]
    struct TestSink(Arc<Mutex<Vec<u8>>>);

    impl TestSink {
        fn new() -> Self {
            TestSink(Arc::new(Mutex::new(Vec::new())))
        }
        fn taken(&self) -> Vec<u8> {
            self.0.lock().unwrap().clone()
        }
    }

    impl Write for TestSink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    // With no client attached (write_out == false) output is retained in the
    // ring and replayed in order once a client connects (set_out + write_out).
    #[test]
    fn accumulates_while_detached_then_replays_on_connect() {
        let write_out = Arc::new(AtomicBool::new(false));
        let mut buf = SerialBuffer::new(Box::new(io::sink()), write_out.clone());

        buf.write_all(b"boot: hello\n").unwrap();
        buf.write_all(b"login: ").unwrap();

        let sink = TestSink::new();
        buf.set_out(Box::new(sink.clone()));
        write_out.store(true, Ordering::Release);
        buf.flush().unwrap();

        assert_eq!(sink.taken(), b"boot: hello\nlogin: ");
    }

    // Once connected, live writes pass straight through.
    #[test]
    fn live_writes_pass_through_after_connect() {
        let write_out = Arc::new(AtomicBool::new(false));
        let mut buf = SerialBuffer::new(Box::new(io::sink()), write_out.clone());

        let sink = TestSink::new();
        buf.set_out(Box::new(sink.clone()));
        write_out.store(true, Ordering::Release);
        buf.write_all(b"live").unwrap();

        assert_eq!(sink.taken(), b"live");
    }

    // Output produced while no client is attached is buffered and delivered to
    // the next client to connect; bytes already drained by a previous client
    // are not resent.
    #[test]
    fn output_while_detached_goes_to_next_client() {
        let write_out = Arc::new(AtomicBool::new(false));
        let mut buf = SerialBuffer::new(Box::new(io::sink()), write_out.clone());

        // First client: connects, drains "early\n", then disconnects.
        let first = TestSink::new();
        buf.set_out(Box::new(first.clone()));
        write_out.store(true, Ordering::Release);
        buf.write_all(b"early\n").unwrap();
        assert_eq!(first.taken(), b"early\n");

        // Disconnect: detach to a discarding sink, keep accumulating.
        write_out.store(false, Ordering::Release);
        buf.set_out(Box::new(io::sink()));
        buf.write_all(b"while-away\n").unwrap();

        // Second client: receives what was produced while no one was attached.
        let second = TestSink::new();
        buf.set_out(Box::new(second.clone()));
        write_out.store(true, Ordering::Release);
        buf.flush().unwrap();
        assert_eq!(second.taken(), b"while-away\n");
    }

    // Bytes are delivered once: a second client connecting after the first
    // already drained the backlog, with no new output in between, gets nothing.
    #[test]
    fn drained_bytes_are_not_resent_to_a_second_client() {
        let write_out = Arc::new(AtomicBool::new(false));
        let mut buf = SerialBuffer::new(Box::new(io::sink()), write_out.clone());

        buf.write_all(b"boot log\n").unwrap();

        // First client drains the backlog.
        let first = TestSink::new();
        buf.set_out(Box::new(first.clone()));
        write_out.store(true, Ordering::Release);
        buf.flush().unwrap();
        assert_eq!(first.taken(), b"boot log\n");

        // First disconnects; no new output is produced while detached.
        write_out.store(false, Ordering::Release);
        buf.set_out(Box::new(io::sink()));

        // Second client connects: nothing left to deliver.
        let second = TestSink::new();
        buf.set_out(Box::new(second.clone()));
        write_out.store(true, Ordering::Release);
        buf.flush().unwrap();
        assert!(second.taken().is_empty());
    }
}
