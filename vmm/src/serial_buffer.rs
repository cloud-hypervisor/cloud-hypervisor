// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::io::Write;

// Circular buffer implementation for serial output.
// Read from head; push to tail
pub(crate) struct SerialBuffer {
    buffer: Vec<u8>,
    head: usize,
    tail: usize,
    out: Box<dyn Write + Send>,
}

const MAX_BUFFER_SIZE: usize = 16 << 10;

impl SerialBuffer {
    pub(crate) fn new(out: Box<dyn Write + Send>) -> Self {
        Self {
            buffer: vec![],
            head: 0,
            tail: 0,
            out,
        }
    }

    pub(crate) fn flush_buffer(&mut self) -> Result<(), std::io::Error> {
        if self.tail <= self.head {
            // The buffer to be written is in two parts
            let buf = &self.buffer[self.head..];
            match self.out.write(buf) {
                Ok(bytes_written) => {
                    if bytes_written == buf.len() {
                        self.head = 0;
                        // Can now proceed to write the other part of the buffer
                    } else {
                        self.head += bytes_written;
                        self.out.flush()?;
                        return Ok(());
                    }
                }
                Err(e) => {
                    if !matches!(e.kind(), std::io::ErrorKind::WouldBlock) {
                        return Err(e);
                    }
                    return Ok(());
                }
            }
        }

        let buf = &self.buffer[self.head..self.tail];
        match self.out.write(buf) {
            Ok(bytes_written) => {
                if bytes_written == buf.len() {
                    self.buffer.clear();
                    self.buffer.shrink_to_fit();
                    self.head = 0;
                    self.tail = 0;
                } else {
                    self.head += bytes_written;
                }
                self.out.flush()?;
            }
            Err(e) => {
                if !matches!(e.kind(), std::io::ErrorKind::WouldBlock) {
                    return Err(e);
                }
            }
        }

        Ok(())
    }
}
impl Write for SerialBuffer {
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        // The serial output only writes one byte at a time
        for v in buf {
            if self.buffer.is_empty() {
                // This case exists to avoid allocating the buffer if it's not needed
                if let Err(e) = self.out.write(&[*v]) {
                    if !matches!(e.kind(), std::io::ErrorKind::WouldBlock) {
                        return Err(e);
                    }
                    self.buffer.push(*v);
                    self.tail += 1;
                } else {
                    self.out.flush()?;
                }
            } else {
                // Buffer is completely full, lose the oldest byte by moving head forward
                if self.head == self.tail {
                    self.head = self.tail + 1;
                    if self.head == MAX_BUFFER_SIZE {
                        self.head = 0;
                    }
                }

                if self.buffer.len() < MAX_BUFFER_SIZE {
                    self.buffer.push(*v);
                } else {
                    self.buffer[self.tail] = *v;
                }

                self.tail += 1;
                if self.tail == MAX_BUFFER_SIZE {
                    self.tail = 0;
                }

                self.flush_buffer()?;
            }
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        Ok(())
    }
}
