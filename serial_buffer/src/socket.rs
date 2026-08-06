// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::SerialBuffer;

struct SharedSerialBuffer(Arc<Mutex<SerialBuffer>>);

impl Write for SharedSerialBuffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.lock().unwrap().flush()
    }
}

/// Serves a device byte stream over a socket to one client at a time, buffering
/// output until a client connects.
pub struct SocketConsole {
    buffer: Arc<Mutex<SerialBuffer>>,
    write_out: Arc<AtomicBool>,
    reader: Option<UnixStream>,
}

impl Default for SocketConsole {
    fn default() -> Self {
        Self::new()
    }
}

impl SocketConsole {
    pub fn new() -> Self {
        let write_out = Arc::new(AtomicBool::new(false));
        let buffer = Arc::new(Mutex::new(SerialBuffer::new(
            Box::new(io::sink()),
            write_out.clone(),
        )));
        Self {
            buffer,
            write_out,
            reader: None,
        }
    }

    pub fn out_sink(&self) -> Box<dyn Write + Send> {
        Box::new(SharedSerialBuffer(self.buffer.clone()))
    }

    /// Accept a client and return its fd for the caller to register with epoll.
    pub fn accept(&mut self, listener: &UnixListener) -> io::Result<RawFd> {
        if let Some(previous) = self.reader.take() {
            previous.shutdown(Shutdown::Both)?;
        }
        let (stream, _) = listener.accept()?;
        stream.set_nonblocking(true)?;
        let writer = stream.try_clone()?;
        let fd = stream.as_raw_fd();
        self.attach(writer)?;
        self.reader = Some(stream);
        Ok(fd)
    }

    /// Returns 0 with no client, on disconnect, or when nothing is pending.
    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Some(stream) = self.reader.take() else {
            return Ok(0);
        };
        let mut reader = &stream;
        match reader.read(buf) {
            Ok(0) => {
                stream.shutdown(Shutdown::Both)?;
                self.detach();
                Ok(0)
            }
            Ok(count) => {
                self.reader = Some(stream);
                Ok(count)
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.reader = Some(stream);
                Ok(0)
            }
            Err(e) => {
                self.reader = Some(stream);
                Err(e)
            }
        }
    }

    fn attach(&self, writer: UnixStream) -> io::Result<()> {
        let mut buffer = self.buffer.lock().unwrap();
        buffer.set_out(Box::new(writer));
        self.write_out.store(true, Ordering::Release);
        buffer.flush()
    }

    fn detach(&self) {
        self.write_out.store(false, Ordering::Release);
        self.buffer.lock().unwrap().set_out(Box::new(io::sink()));
    }
}
