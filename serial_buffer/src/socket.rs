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

    pub fn connected(&self) -> bool {
        self.reader.is_some()
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
        self.attach(writer)?;
        self.reader = Some(stream);
        Ok(())
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

impl AsRawFd for SocketConsole {
    fn as_raw_fd(&self) -> RawFd {
        self.reader.as_ref().unwrap().as_raw_fd()
    }
}

#[cfg(test)]
mod unit_tests {
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::thread;
    use std::time::Duration;

    use vmm_sys_util::tempdir::TempDir;

    use super::SocketConsole;

    fn read_retry(console: &mut SocketConsole, buf: &mut [u8]) -> usize {
        for _ in 0..200 {
            let n = console.read(buf).unwrap();
            if n > 0 {
                return n;
            }
            thread::sleep(Duration::from_millis(1));
        }
        0
    }

    #[test]
    fn replays_buffered_output_to_client_on_connect() {
        let tmp_dir = TempDir::new().unwrap();
        let path = tmp_dir.as_path().join("socket");
        let listener = UnixListener::bind(&path).unwrap();
        let mut console = SocketConsole::new();

        let mut sink = console.out_sink();
        sink.write_all(b"boot\n").unwrap();

        let mut client = UnixStream::connect(&path).unwrap();
        console.accept(&listener).unwrap();

        let mut got = [0u8; 5];
        client.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"boot\n");
    }

    #[test]
    fn reads_input_from_connected_client() {
        let tmp_dir = TempDir::new().unwrap();
        let path = tmp_dir.as_path().join("socket");
        let listener = UnixListener::bind(&path).unwrap();
        let mut console = SocketConsole::new();

        let mut client = UnixStream::connect(&path).unwrap();
        console.accept(&listener).unwrap();

        client.write_all(b"hi").unwrap();
        client.flush().unwrap();

        let mut buf = [0u8; 8];
        let n = read_retry(&mut console, &mut buf);
        assert_eq!(&buf[..n], b"hi");
    }

    #[test]
    fn shutdown_then_accept_replaces_client() {
        let tmp_dir = TempDir::new().unwrap();
        let path = tmp_dir.as_path().join("socket");
        let listener = UnixListener::bind(&path).unwrap();
        let mut console = SocketConsole::new();

        let mut first = UnixStream::connect(&path).unwrap();
        console.accept(&listener).unwrap();

        let second = UnixStream::connect(&path).unwrap();
        console.shutdown().unwrap();
        console.accept(&listener).unwrap();

        // shutdown() closed the first connection.
        let mut discard = [0u8; 4];
        assert_eq!(first.read(&mut discard).unwrap(), 0);

        let mut sink = console.out_sink();
        sink.write_all(b"hey\n").unwrap();
        let mut got = [0u8; 4];
        (&second).read_exact(&mut got).unwrap();
        assert_eq!(&got, b"hey\n");
    }

    #[test]
    fn reports_connection_state() {
        let tmp_dir = TempDir::new().unwrap();
        let path = tmp_dir.as_path().join("socket");
        let listener = UnixListener::bind(&path).unwrap();
        let mut console = SocketConsole::new();
        assert!(!console.connected());

        let _client = UnixStream::connect(&path).unwrap();
        console.accept(&listener).unwrap();
        assert!(console.connected());
    }
}
