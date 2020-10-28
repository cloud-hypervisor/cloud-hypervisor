// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::MigratableError;

// Migration protocol
// 1: Source establishes communication with destination (file socket or TCP connection.)
// (The establishment is out of scope.)
// 2: Source -> Dest : send "start command"
// 3: Dest -> Source : sends "ok response" when read to accept state data
// 4: Source -> Dest : sends "state command" followed by state data, length
//                     in command is length of state data
// 5: Dest -> Source : sends "ok response" when ready to accept memory data
// 6: Source -> Dest : send "memory command" followed by table of u64 pairs (GPA, size)
//                     followed by the memory described in those pairs.
//                     !! length is size of table i.e. 16 * number of ranges !!
// 7: Dest -> Source : sends "ok response" when ready to accept more memory data
// 8..(n-2): Repeat steps 6 and 7 until source has no more memory to send
// (n-1): Source -> Dest : send "complete command"
// n: Dest -> Source: sends "ok response"

// The destination can at any time send an "error response" to cancel
// The source can at any time send an "abandon request" to cancel

use std::io::{Read, Write};

#[repr(u16)]
#[derive(Copy, Clone)]
pub enum Command {
    Invalid,
    Start,
    State,
    Memory,
    Complete,
    Abandon,
}

impl Default for Command {
    fn default() -> Self {
        Self::Invalid
    }
}

trait AsBytes {
    fn as_bytes<T: Sized>(p: &T) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts((p as *const T) as *const u8, std::mem::size_of::<T>())
        }
    }

    fn as_mut_bytes<T: Sized>(p: &mut T) -> &mut [u8] {
        unsafe {
            std::slice::from_raw_parts_mut((p as *mut T) as *mut u8, std::mem::size_of::<T>())
        }
    }
}

#[repr(C)]
#[derive(Default)]
pub struct Request {
    command: Command,
    padding: [u8; 6],
    length: u64, // Length of payload for command excluding the Request struct
}

impl Request {
    pub fn new(command: Command, length: u64) -> Self {
        Self {
            command,
            length,
            ..Default::default()
        }
    }

    pub fn start() -> Self {
        Self::new(Command::Start, 0)
    }

    pub fn state(length: u64) -> Self {
        Self::new(Command::State, length)
    }

    pub fn memory(length: u64) -> Self {
        Self::new(Command::Memory, length)
    }

    pub fn complete() -> Self {
        Self::new(Command::Complete, 0)
    }

    pub fn abandon() -> Self {
        Self::new(Command::Abandon, 0)
    }

    pub fn command(&self) -> Command {
        self.command
    }

    pub fn length(&self) -> u64 {
        self.length
    }

    pub fn read_from(fd: &mut dyn Read) -> Result<Request, MigratableError> {
        let mut request = Request::default();
        fd.read_exact(Self::as_mut_bytes(&mut request))
            .map_err(MigratableError::MigrateSocket)?;

        Ok(request)
    }

    pub fn write_to(&self, fd: &mut dyn Write) -> Result<(), MigratableError> {
        fd.write_all(Self::as_bytes(self))
            .map_err(MigratableError::MigrateSocket)
    }
}

impl AsBytes for Request {}

#[repr(u16)]
#[derive(Copy, Clone, PartialEq)]
pub enum Status {
    Invalid,
    Ok,
    Error,
}

impl Default for Status {
    fn default() -> Self {
        Self::Invalid
    }
}

#[repr(C)]
#[derive(Default)]
pub struct Response {
    status: Status,
    padding: [u8; 6],
    length: u64, // Length of payload for command excluding the Response struct
}

impl Response {
    pub fn new(status: Status, length: u64) -> Self {
        Self {
            status,
            length,
            ..Default::default()
        }
    }

    pub fn ok() -> Self {
        Self::new(Status::Ok, 0)
    }

    pub fn error() -> Self {
        Self::new(Status::Error, 0)
    }

    pub fn status(&self) -> Status {
        self.status
    }

    pub fn read_from(fd: &mut dyn Read) -> Result<Response, MigratableError> {
        let mut response = Response::default();
        fd.read_exact(Self::as_mut_bytes(&mut response))
            .map_err(MigratableError::MigrateSocket)?;

        Ok(response)
    }

    pub fn write_to(&self, fd: &mut dyn Write) -> Result<(), MigratableError> {
        fd.write_all(Self::as_bytes(self))
            .map_err(MigratableError::MigrateSocket)
    }
}

impl AsBytes for Response {}

#[repr(C)]
pub struct MemoryRange {
    pub gpa: u64,
    pub length: u64,
}

#[derive(Default)]
pub struct MemoryRangeTable {
    data: Vec<MemoryRange>,
}

impl MemoryRangeTable {
    pub fn regions(&self) -> &[MemoryRange] {
        &self.data
    }

    pub fn push(&mut self, range: MemoryRange) {
        self.data.push(range)
    }

    pub fn read_from(fd: &mut dyn Read, length: u64) -> Result<MemoryRangeTable, MigratableError> {
        assert!(length as usize % std::mem::size_of::<MemoryRange>() == 0);

        let mut data = Vec::with_capacity(length as usize / (std::mem::size_of::<MemoryRange>()));
        unsafe {
            data.set_len(length as usize / (std::mem::size_of::<MemoryRange>()));
        }
        fd.read_exact(unsafe {
            std::slice::from_raw_parts_mut(
                data.as_ptr() as *mut MemoryRange as *mut u8,
                length as usize,
            )
        })
        .map_err(MigratableError::MigrateSocket)?;

        Ok(Self { data })
    }

    pub fn length(&self) -> u64 {
        (std::mem::size_of::<MemoryRange>() * self.data.len()) as u64
    }

    pub fn write_to(&self, fd: &mut dyn Write) -> Result<(), MigratableError> {
        fd.write_all(unsafe {
            std::slice::from_raw_parts(
                self.data.as_ptr() as *const MemoryRange as *const u8,
                self.length() as usize,
            )
        })
        .map_err(MigratableError::MigrateSocket)
    }
}
