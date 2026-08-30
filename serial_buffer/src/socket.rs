// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::io::{self, ErrorKind, Read, Write};
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

    /// Returns the connected client fd, or None when no client is attached.
    pub fn client_fd(&self) -> Option<RawFd> {
        self.reader.as_ref().map(|stream| stream.as_raw_fd())
    }

    pub fn shutdown(&mut self) -> io::Result<()> {
        if let Some(stream) = self.reader.take() {
            let res = stream.shutdown(Shutdown::Both);
            self.detach();
            res?;
        }
        Ok(())
    }

    pub fn accept(&mut self, listener: &UnixListener) -> io::Result<()> {
        let (stream, _) = listener.accept()?;
        stream.set_nonblocking(true)?;
        let writer = stream.try_clone()?;
        self.attach(Box::new(writer))?;
        self.reader = Some(stream);
        Ok(())
    }

    fn attach(&self, writer: Box<dyn Write + Send>) -> io::Result<()> {
        let mut buffer = self.buffer.lock().unwrap();
        buffer.set_out(writer);
        self.write_out.store(true, Ordering::Release);
        buffer.flush()
    }

    fn detach(&self) {
        self.write_out.store(false, Ordering::Release);
        self.buffer.lock().unwrap().set_out(Box::new(io::sink()));
    }
}

impl Read for SocketConsole {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Some(mut stream) = self.reader.as_ref() else {
            return Ok(0);
        };
        match stream.read(buf) {
            Ok(count) if count > 0 => Ok(count),
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(0),
            ended => {
                let _ = stream.shutdown(Shutdown::Both);
                self.reader = None;
                self.detach();
                ended
            }
        }
    }
}
