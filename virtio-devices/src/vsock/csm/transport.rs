// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: Apache-2.0
//

use std::os::fd::AsRawFd;
use std::{io, result};

use super::super::SocketType;
use super::super::packet::VsockPacket;
use super::{Error, Result};

pub(crate) type SendResult = result::Result<
    usize, /* bytes forwarded */
    (usize /* bytes forwarded before error */, Error),
>;

#[derive(Debug)]
pub(crate) struct PayloadRead {
    pub(crate) len: usize,
    pub(crate) eof: bool,
    pub(crate) more: bool,
    pub(crate) waiting_credit: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RxState {
    WaitingForData,
    WaitingForCredit,
    Buffered,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TxState {
    Empty,
    Partial,
    Pending,
}

/// Abstracts the host socket type through a dedicated Transport
/// interface. This allows VsockConnection to become agnostic
/// of the socket type.
pub(crate) trait Transport: AsRawFd {
    fn socket_type(&self) -> SocketType;
    fn receive(
        &mut self,
        pkt: &mut VsockPacket,
        credit: usize,
        capacity: u32,
    ) -> io::Result<PayloadRead>;
    fn send(&mut self, pkt: &VsockPacket) -> SendResult;
    fn flush(&mut self) -> Result<usize>;
    fn rx_state(&self, credit: usize) -> RxState;
    fn tx_state(&self) -> TxState;
    fn finish_send(&mut self) {}
    fn read_control(&mut self, data: &mut [u8]) -> io::Result<usize>;
    fn write_control(&mut self, data: &[u8]) -> io::Result<usize>;
}
