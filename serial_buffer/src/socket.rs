// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::io::{self, ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
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

enum ClientStream {
    Unix(UnixStream),
    Tcp(TcpStream),
}

impl ClientStream {
    fn try_clone(&self) -> io::Result<ClientStream> {
        Ok(match self {
            ClientStream::Unix(stream) => ClientStream::Unix(stream.try_clone()?),
            ClientStream::Tcp(stream) => ClientStream::Tcp(stream.try_clone()?),
        })
    }

    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        match self {
            ClientStream::Unix(stream) => stream.set_nonblocking(nonblocking),
            ClientStream::Tcp(stream) => stream.set_nonblocking(nonblocking),
        }
    }

    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        match self {
            ClientStream::Unix(stream) => stream.shutdown(how),
            ClientStream::Tcp(stream) => stream.shutdown(how),
        }
    }
}

impl AsRawFd for ClientStream {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            ClientStream::Unix(stream) => stream.as_raw_fd(),
            ClientStream::Tcp(stream) => stream.as_raw_fd(),
        }
    }
}

impl Read for ClientStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            ClientStream::Unix(stream) => stream.read(buf),
            ClientStream::Tcp(stream) => stream.read(buf),
        }
    }
}

impl Write for ClientStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            ClientStream::Unix(stream) => stream.write(buf),
            ClientStream::Tcp(stream) => stream.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            ClientStream::Unix(stream) => stream.flush(),
            ClientStream::Tcp(stream) => stream.flush(),
        }
    }
}

/// Serves a device byte stream over a socket to one client at a time, buffering
/// output until a client connects.
pub struct SocketConsole {
    buffer: Arc<Mutex<SerialBuffer>>,
    write_out: Arc<AtomicBool>,
    reader: Option<ClientStream>,
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
        self.install(ClientStream::Unix(stream))
    }

    pub fn accept_tcp(&mut self, listener: &TcpListener) -> io::Result<()> {
        let (stream, _) = listener.accept()?;
        stream.set_nodelay(true).ok();
        self.install(ClientStream::Tcp(stream))
    }

    pub fn connect(&mut self, addr: &SocketAddr) -> io::Result<()> {
        let stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true).ok();
        self.install(ClientStream::Tcp(stream))
    }

    fn install(&mut self, stream: ClientStream) -> io::Result<()> {
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
        let Some(stream) = self.reader.as_mut() else {
            return Ok(0);
        };
        let result = stream.read(buf);
        match result {
            Ok(count) if count > 0 => Ok(count),
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => Ok(0),
            _ => {
                if let Some(stream) = self.reader.take() {
                    let _ = stream.shutdown(Shutdown::Both);
                }
                self.detach();
                result
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
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
        assert!(console.client_fd().is_none());

        let _client = UnixStream::connect(&path).unwrap();
        console.accept(&listener).unwrap();
        assert!(console.client_fd().is_some());
    }

    #[test]
    fn replays_buffered_output_to_tcp_client_on_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut console = SocketConsole::new();

        let mut sink = console.out_sink();
        sink.write_all(b"boot\n").unwrap();

        let mut client = TcpStream::connect(addr).unwrap();
        console.accept_tcp(&listener).unwrap();

        let mut got = [0u8; 5];
        client.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"boot\n");
    }

    #[test]
    fn connects_to_remote_tcp_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let accepter = thread::spawn(move || listener.accept().unwrap().0);

        let mut console = SocketConsole::new();
        console.connect(&addr).unwrap();
        let mut remote = accepter.join().unwrap();

        let mut sink = console.out_sink();
        sink.write_all(b"hi\n").unwrap();
        let mut got = [0u8; 3];
        remote.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"hi\n");

        remote.write_all(b"in").unwrap();
        remote.flush().unwrap();
        let mut buf = [0u8; 8];
        let n = read_retry(&mut console, &mut buf);
        assert_eq!(&buf[..n], b"in");
    }
}
