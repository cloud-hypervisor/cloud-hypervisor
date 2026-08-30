// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::io::{self, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::SerialBuffer;

/// A `Write` handle so the serial device and the serial-manager thread can
/// share one `SerialBuffer` (the device holds it as its output sink).
pub struct SharedSerialBuffer(pub Arc<Mutex<SerialBuffer>>);

impl Write for SharedSerialBuffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.lock().unwrap().flush()
    }
}

#[derive(Clone)]
pub struct SocketConsole {
    /// Persistent ring buffer: captures serial output while no client is
    /// connected and replays it on connect. Shared with the serial device's
    /// `out` sink and retargeted by the epoll thread.
    pub buffer: Arc<Mutex<SerialBuffer>>,
    pub write_out: Arc<AtomicBool>,
}

impl SocketConsole {
    pub fn attach_client(&self, writer: UnixStream) -> io::Result<()> {
        let mut buffer = self.buffer.lock().unwrap();
        buffer.set_out(Box::new(writer));
        self.write_out.store(true, Ordering::Release);
        buffer.flush()
    }

    pub fn detach_client(&self) {
        self.write_out.store(false, Ordering::Release);
        self.buffer.lock().unwrap().set_out(Box::new(io::sink()));
    }
}
