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
}

const MAX_BUFFER_SIZE: usize = 16 << 10;

impl SerialBuffer {
    pub(crate) fn new() -> Self {
        Self {
            buffer: vec![],
            head: 0,
            tail: 0,
        }
    }

    pub(crate) fn flush_buffer(&mut self, writer: &mut dyn Write) -> Result<(), std::io::Error> {
        if self.tail <= self.head {
            // The buffer to be written is in two parts
            let buf = &self.buffer[self.head..];
            match writer.write(buf) {
                Ok(bytes_written) => {
                    if bytes_written == buf.len() {
                        self.head = 0;
                        // Can now proceed to write the other part of the buffer
                    } else {
                        self.head += bytes_written;
                        writer.flush()?;
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
        match writer.write(buf) {
            Ok(bytes_written) => {
                if bytes_written == buf.len() {
                    self.buffer.clear();
                    self.buffer.shrink_to_fit();
                    self.head = 0;
                    self.tail = 0;
                } else {
                    self.head += bytes_written;
                }
                writer.flush()?;
            }
            Err(e) => {
                if !matches!(e.kind(), std::io::ErrorKind::WouldBlock) {
                    return Err(e);
                }
            }
        }

        Ok(())
    }

    pub(crate) fn write_to(&mut self, v: u8, writer: &mut dyn Write) -> Result<(), std::io::Error> {
        if self.buffer.is_empty() {
            // This case exists to avoid allocating the buffer if it's not needed
            if let Err(e) = writer.write(&[v]) {
                if !matches!(e.kind(), std::io::ErrorKind::WouldBlock) {
                    return Err(e);
                }
                self.buffer.push(v);
                self.tail += 1;
            } else {
                writer.flush()?;
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
                self.buffer.push(v);
            } else {
                self.buffer[self.tail] = v;
            }

            self.tail += 1;
            if self.tail == MAX_BUFFER_SIZE {
                self.tail = 0;
            }

            self.flush_buffer(writer)?;
        }
        Ok(())
    }
}
