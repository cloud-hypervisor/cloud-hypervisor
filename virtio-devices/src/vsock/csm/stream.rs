// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: Apache-2.0
//

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};

use vm_memory::{ReadVolatile, WriteVolatile};

use super::super::defs::uapi::VSOCK_TYPE_STREAM;
use super::super::packet::VsockPacket;
use super::transport::{PayloadRead, RxState, SendResult, Transport, TxState};
use super::txbuf::TxBuf;
use super::{Error, Result};

pub(crate) struct StreamTransport<S> {
    pub(super) stream: S,
    pub(super) tx_buf: TxBuf,
}

impl<S> From<S> for StreamTransport<S> {
    fn from(stream: S) -> Self {
        Self {
            stream,
            tx_buf: TxBuf::new(),
        }
    }
}

impl<S: AsRawFd> AsRawFd for StreamTransport<S> {
    fn as_raw_fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }
}

impl<S: Read + ReadVolatile + Write + WriteVolatile + AsRawFd> Transport for StreamTransport<S> {
    fn socket_type(&self) -> u16 {
        VSOCK_TYPE_STREAM
    }

    fn receive(&mut self, pkt: &mut VsockPacket, credit: usize, _: u32) -> io::Result<PayloadRead> {
        let capacity = pkt.buf_capacity().ok_or(io::ErrorKind::InvalidInput)?;
        let len = pkt.read_volatile_from(&mut self.stream, capacity.min(credit))?;
        Ok(PayloadRead {
            len,
            eof: len == 0,
            more: len == capacity && credit > len,
            waiting_credit: false,
        })
    }

    fn send(&mut self, pkt: &VsockPacket) -> SendResult {
        let len = pkt.len() as usize;
        if !self.tx_buf.is_empty() {
            self.tx_buf
                .push_from(pkt, 0, len)
                .map_err(|error| (0, error))?;
            return Ok(0);
        }
        let written = match pkt.write_volatile_to(&mut self.stream, 0, len) {
            Ok(count) => count,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => 0,
            Err(e) => return Err((0, Error::StreamWrite(e))),
        };
        if written < len {
            self.tx_buf
                .push_from(pkt, written, len - written)
                .map_err(|error| (written, error))?;
        }
        Ok(written)
    }

    fn flush(&mut self) -> Result<usize> {
        self.tx_buf.flush_to(&mut self.stream)
    }

    fn rx_state(&self, credit: usize) -> RxState {
        if credit == 0 {
            RxState::WaitingForCredit
        } else {
            RxState::WaitingForData
        }
    }

    fn tx_state(&self) -> TxState {
        if self.tx_buf.is_empty() {
            TxState::Empty
        } else {
            TxState::Pending
        }
    }

    fn read_control(&mut self, data: &mut [u8]) -> io::Result<usize> {
        self.stream.read(data)
    }

    fn write_control(&mut self, data: &[u8]) -> io::Result<usize> {
        self.stream.write(data)
    }
}
