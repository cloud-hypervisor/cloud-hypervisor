// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! # Migration Protocol
//!
//! ## Cross-Host Migration
//!
//! A traditional network-based live migration where all resources are
//! transmitted over the wire. Externally-provided FDs must be opened and
//! managed by the management software on the destination side.
//!
//! **Supported migration modes**:
//! - TCP (currently one single connection)
//!
//! The following mermaid sequence diagram shows a brief overview:
//!
//! <!-- Best viewed and edited here: https://mermaid.live/edit -->
//! ```mermaid
//! sequenceDiagram
//!    Source<<->>Destination: Establish connection
//!    Source->>Destination: Start
//!    Destination-->>Source: OK
//!    Source->>Destination: Config
//!      Note right of Destination: Payload: VM Config
//!    Destination-->>Source: OK
//!      Note right of Source: Start Dirty Logging
//!    loop Dirty Memory Ranges (until handover decision was made)
//!      Source->>Destination: Memory
//!        Note right of Destination: Payload: Memory Range Table
//!        Note right of Destination: Payload: Memory Content
//!      Destination-->>Source: OK
//!      Note right of Source: VM is paused after last OK
//!    end
//!    Source->>Destination: Memory
//!      Note right of Destination: Payload: Final Memory Range Table
//!      Note right of Destination: Payload: Final Memory Content
//!    Destination-->>Source: OK
//!    Source->>Destination: State
//!      Note right of Destination: Final VM State (vCPU, devices)
//!    Destination-->>Source: OK
//!    Source->>Destination: Complete
//!    Destination-->>Source: OK
//! ```
//!
//! ## Local Migration
//!
//! A simplified migration taking a few shortcuts and only working on the
//! same host. The VM memory is not transferred over the wire but instead
//! passed as memory FD.
//!
//! The following mermaid sequence diagram shows a brief overview:
//!
//! <!-- Best viewed and edited here: https://mermaid.live/edit -->
//! ```mermaid
//! sequenceDiagram
//!    Source<<->>Destination: Establish connection
//!    Source->>Destination: Start
//!    Destination-->>Source: OK
//!    loop For each Memory FD
//!      Source->>Destination: Memory FD (1/n)
//!        Note right of Destination: Payload: (slot: u32, fd: u32)
//!      Destination-->>Source: OK
//!    end
//!    Source->>Destination: Config
//!      Note right of Destination: Payload: VM Config
//!    Destination-->>Source: OK
//!      Note right of Source: VM is paused
//!    Source->>Destination: State
//!      Note right of Destination: Payload: Final VM State (vCPU, devices)
//!    Destination-->>Source: OK
//!    Source->>Destination: Complete
//!    Destination-->>Source: OK
//! ```
//!
//! ## Protocol Versioning
//!
//! `Start` carries the sender's migration protocol version.
//! A zeroed version field is treated as legacy protocol `v0`.
//!
//! The destination validates that version and replies with a plain `OK` or
//! `Error`.
//!
//! Only the current and immediately previous protocol versions are
//! supported. Compatibility is one-way, from older protocol versions
//! to newer ones.

use std::io::{Read, Write};
use std::mem::size_of;
use std::ops::RangeInclusive;
use std::{mem, slice};

use anyhow::anyhow;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use vm_memory::ByteValued;

use crate::MigratableError;
use crate::bitpos_iterator::BitposIteratorExt;

/// The commands of the [live-migration protocol].
///
/// ### Sender State Machine
///
/// TODO refactor sender into state machine and add diagram
///
/// ### Receiver State Machine
///
/// <!-- Best viewed and edited here: https://mermaid.live/edit -->
/// ```mermaid
/// stateDiagram-v2
///     direction TB
///     [*] --> Started: Start
///     Started --> MemoryFdsReceived: MemoryFd
///     MemoryFdsReceived --> MemoryFdsReceived: MemoryFd
///     Started --> Configured: Config
///     MemoryFdsReceived --> Configured: Config
///     Configured --> Configured: Memory
///     Configured --> StateReceived: State
///     StateReceived --> Completed: Complete
///     StateReceived --> Completed: CompletePaused
///     Completed --> Completed: PageFault
/// ```
///
/// [live-migration protocol]: super::protocol
#[repr(u16)]
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub enum Command {
    #[default]
    Invalid = 0,
    Start = 1,
    Config = 2,
    State = 3,
    Memory = 4,
    /// Finalizes the migration and resumes the VM on the destination.
    /// Sent when the source VM was running at migration time.
    Complete = 5,
    Abandon = 6,
    MemoryFd = 7,
    /// Finalizes the migration without resuming the VM on the destination.
    /// Sent when the source VM was paused at migration time.
    CompletePaused = 8,
    /// Asking for a page to be faulted in. The page content can be sent
    /// through the response or simply written to the shared memory.
    PageFault = 9,
}

/// Role announced by the dialer as the first message on an *additional*
/// migration connection (the very first/control connection is implicit and
/// sends no header, preserving wire-compatibility with plain live migration).
///
/// Lets the receiver route each accepted connection to the right handler:
/// precopy memory workers vs. the dedicated post-copy/lazy fault channel.
#[repr(u16)]
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub enum ConnRole {
    #[default]
    Invalid = 0,
    /// Carries precopy memory pushes (`Command::Memory`).
    PrecopyMemory = 1,
    /// Dedicated channel carrying `Command::PageFault` request/response,
    /// served asynchronously for the whole post-copy/lazy lifetime.
    Fault = 2,
}

impl ConnRole {
    fn from_wire(value: u16) -> Self {
        match value {
            1 => ConnRole::PrecopyMemory,
            2 => ConnRole::Fault,
            _ => ConnRole::Invalid,
        }
    }
}

/// Fixed-size header sent by the dialer of an additional connection to declare
/// its [`ConnRole`] before any command traffic.
///
/// `role` is stored as a raw `u16` on the wire so the struct can be read with
/// `ByteValued` without risking an invalid enum discriminant; use
/// [`ConnHeader::role`] to decode it.
#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct ConnHeader {
    role: u16,
    version: u16,
    padding: [u8; 4],
}

// SAFETY: ConnHeader is a series of integers with no implicit padding.
unsafe impl ByteValued for ConnHeader {}

impl ConnHeader {
    /// Current header wire version.
    pub const VERSION: u16 = 1;

    pub fn new(role: ConnRole) -> Self {
        Self {
            role: role as u16,
            version: Self::VERSION,
            ..Default::default()
        }
    }

    pub fn role(&self) -> ConnRole {
        ConnRole::from_wire(self.role)
    }

    pub fn version(&self) -> u16 {
        self.version
    }

    pub fn read_from(fd: &mut dyn Read) -> Result<ConnHeader, MigratableError> {
        let mut header = ConnHeader::default();
        fd.read_exact(Self::as_mut_slice(&mut header))
            .map_err(MigratableError::MigrateSocket)?;
        Ok(header)
    }

    pub fn write_to(&self, fd: &mut dyn Write) -> Result<(), MigratableError> {
        fd.write_all(Self::as_slice(self))
            .map_err(MigratableError::MigrateSocket)
    }
}

/// Newest migration protocol version sent by this implementation.
pub const CURRENT_PROTOCOL_VERSION: u16 = 0;

/// Returns the current migration protocol version and the previous version, if any.
pub fn supported_protocol_versions() -> RangeInclusive<u16> {
    CURRENT_PROTOCOL_VERSION.saturating_sub(1)..=CURRENT_PROTOCOL_VERSION
}

#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct Request {
    command: Command,
    command_headers: [u8; 6],
    /// Length of payload for command excluding the Request struct
    length: u64,
}

// SAFETY: Request contains a series of integers with no implicit padding
unsafe impl ByteValued for Request {}

impl Request {
    fn encode_sender_version(version: u16) -> [u8; 6] {
        let mut command_headers = [0; 6];
        command_headers[..size_of::<u16>()].copy_from_slice(&version.to_le_bytes());
        command_headers
    }

    pub fn new(command: Command, length: u64) -> Self {
        Self {
            command,
            length,
            ..Default::default()
        }
    }

    pub fn start() -> Self {
        Self {
            command: Command::Start,
            command_headers: Self::encode_sender_version(CURRENT_PROTOCOL_VERSION),
            length: 0,
        }
    }

    pub fn state(length: u64) -> Self {
        Self::new(Command::State, length)
    }

    pub fn config(length: u64) -> Self {
        Self::new(Command::Config, length)
    }

    pub fn memory(length: u64) -> Self {
        Self::new(Command::Memory, length)
    }

    pub fn memory_fd(length: u64) -> Self {
        Self::new(Command::MemoryFd, length)
    }

    /// Finalizes the migration and resumes the VM on the destination.
    pub fn complete() -> Self {
        Self::new(Command::Complete, 0)
    }

    /// Finalizes the migration without resuming the VM on the destination.
    pub fn complete_paused() -> Self {
        Self::new(Command::CompletePaused, 0)
    }

    pub fn abandon() -> Self {
        Self::new(Command::Abandon, 0)
    }

    /// PageFault request always carries a single `MemoryRange`.
    pub fn page_fault() -> Self {
        Self::new(Command::PageFault, size_of::<MemoryRange>() as u64)
    }

    pub fn command(&self) -> Command {
        self.command
    }

    pub fn length(&self) -> u64 {
        self.length
    }

    pub fn command_headers(&self) -> &[u8; 6] {
        &self.command_headers
    }

    /// Returns the sender protocol version from a `Start` request if it is supported.
    pub fn sender_protocol_version(&self) -> Result<u16, MigratableError> {
        assert_eq!(
            self.command(),
            Command::Start,
            "sender_protocol_version() must only be called for Start requests",
        );

        // The protocol version is stored in the first two header bytes, the remaining bytes are ignored.
        let sender_version = u16::from_le_bytes([self.command_headers[0], self.command_headers[1]]);
        if !supported_protocol_versions().any(|version| version == sender_version) {
            let supported_versions = supported_protocol_versions().join(", ");
            return Err(MigratableError::MigrateReceive(anyhow!(
                "Migration protocol version {sender_version} doesn't match supported versions: {supported_versions}"
            )));
        }

        Ok(sender_version)
    }

    pub fn read_from(fd: &mut dyn Read) -> Result<Request, MigratableError> {
        let mut request = Request::default();
        fd.read_exact(Self::as_mut_slice(&mut request))
            .map_err(MigratableError::MigrateSocket)?;

        Ok(request)
    }

    pub fn write_to(&self, fd: &mut dyn Write) -> Result<(), MigratableError> {
        fd.write_all(Self::as_slice(self))
            .map_err(MigratableError::MigrateSocket)
    }
}

#[repr(u16)]
#[derive(Copy, Clone, PartialEq, Eq, Default)]
pub enum Status {
    #[default]
    Invalid,
    Ok,
    Error,
    Hole,
}

#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct Response {
    status: Status,
    padding: [u8; 6],
    length: u64, // Length of payload for command excluding the Response struct
}

// SAFETY: Response contains a series of integers with no implicit padding
unsafe impl ByteValued for Response {}

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

    pub fn length(&self) -> u64 {
        self.length
    }

    pub fn read_from(fd: &mut dyn Read) -> Result<Response, MigratableError> {
        let mut response = Response::default();
        fd.read_exact(Self::as_mut_slice(&mut response))
            .map_err(MigratableError::MigrateSocket)?;

        Ok(response)
    }

    pub fn ok_or_abandon<T>(
        self,
        fd: &mut T,
        error: MigratableError,
    ) -> Result<Response, MigratableError>
    where
        T: Read + Write,
    {
        if self.status != Status::Ok {
            Request::abandon().write_to(fd)?;
            Response::read_from(fd)?;
            return Err(error);
        }
        Ok(self)
    }

    pub fn write_to(&self, fd: &mut dyn Write) -> Result<(), MigratableError> {
        fd.write_all(Self::as_slice(self))
            .map_err(MigratableError::MigrateSocket)
    }
}

#[repr(C)]
#[derive(Copy, Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRange {
    pub gpa: u64,
    pub length: u64,
}

// SAFETY: MemoryRange is two u64 fields with no padding.
unsafe impl ByteValued for MemoryRange {}

// Useful helpers for reading/writing MemoryRange content through the socket.
impl MemoryRange {
    pub fn read_from(fd: &mut dyn Read) -> Result<MemoryRange, MigratableError> {
        let mut range = MemoryRange::default();
        fd.read_exact(Self::as_mut_slice(&mut range))
            .map_err(MigratableError::MigrateSocket)?;
        Ok(range)
    }

    pub fn write_to(&self, fd: &mut dyn Write) -> Result<(), MigratableError> {
        fd.write_all(Self::as_slice(self))
            .map_err(MigratableError::MigrateSocket)
    }
}

/// A set of guest-memory ranges to transfer as one migration payload.
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct MemoryRangeTable {
    data: Vec<MemoryRange>,
}

/// Iterator returned by [`MemoryRangeTable::partition`].
///
/// Each item contains at most `chunk_size` bytes. A range may be split across
/// multiple items.
///
/// The iterator may reorder ranges for efficiency, so callers must not rely on
/// the order in which chunks or ranges are yielded.
#[derive(Clone, Default, Debug)]
struct MemoryRangeTableIterator {
    chunk_size: u64,
    data: Vec<MemoryRange>,
}

impl MemoryRangeTableIterator {
    /// Create an iterator that partitions `table` into chunks of at most
    /// `chunk_size` bytes.
    pub fn new(table: MemoryRangeTable, chunk_size: u64) -> Self {
        MemoryRangeTableIterator {
            chunk_size,
            data: table.data,
        }
    }
}

impl Iterator for MemoryRangeTableIterator {
    type Item = MemoryRangeTable;

    /// Return the next memory range in the table, making sure that
    /// the returned range is not larger than `chunk_size`.
    ///
    /// **Note**: Do not rely on the order of the ranges returned by this
    /// iterator. This allows for a more efficient implementation.
    fn next(&mut self) -> Option<Self::Item> {
        let mut ranges: Vec<MemoryRange> = vec![];
        let mut ranges_size: u64 = 0;

        loop {
            assert!(ranges_size <= self.chunk_size);

            if ranges_size == self.chunk_size || self.data.is_empty() {
                break;
            }

            if let Some(range) = self.data.pop() {
                let next_range: MemoryRange = if ranges_size + range.length > self.chunk_size {
                    // How many bytes we need to put back into the table.
                    let leftover_bytes = ranges_size + range.length - self.chunk_size;
                    assert!(leftover_bytes <= range.length);
                    let returned_bytes = range.length - leftover_bytes;
                    assert!(returned_bytes <= range.length);
                    assert_eq!(leftover_bytes + returned_bytes, range.length);

                    self.data.push(MemoryRange {
                        gpa: range.gpa,
                        length: leftover_bytes,
                    });
                    MemoryRange {
                        gpa: range.gpa + leftover_bytes,
                        length: returned_bytes,
                    }
                } else {
                    range
                };

                ranges_size += next_range.length;
                ranges.push(next_range);
            }
        }

        if ranges.is_empty() {
            None
        } else {
            Some(MemoryRangeTable { data: ranges })
        }
    }
}

impl MemoryRangeTable {
    pub fn ranges(&self) -> &[MemoryRange] {
        &self.data
    }

    /// Partitions the table into chunks of at most `chunk_size` bytes.
    pub fn partition(self, chunk_size: u64) -> impl Iterator<Item = MemoryRangeTable> {
        MemoryRangeTableIterator::new(self, chunk_size)
    }

    /// Converts an iterator over a dirty bitmap into an iterator of dirty
    /// [`MemoryRange`]s, merging consecutive dirty pages into contiguous ranges.
    ///
    /// A memory page (i.e., a range) is marked dirty when its corresponding bit
    /// is set.
    fn dirty_ranges_iter(
        bitmap: impl IntoIterator<Item = u64>,
        start_addr: u64,
        page_size: u64,
    ) -> impl Iterator<Item = MemoryRange> {
        bitmap
            .into_iter()
            .bit_positions()
            // Turn them into single-element ranges for coalesce.
            .map(|b| b..(b + 1))
            // Merge adjacent ranges.
            .coalesce(|prev, curr| {
                if prev.end == curr.start {
                    Ok(prev.start..curr.end)
                } else {
                    Err((prev, curr))
                }
            })
            .map(move |r| MemoryRange {
                gpa: start_addr + r.start * page_size,
                length: (r.end - r.start) * page_size,
            })
    }

    /// Creates a new [`MemoryRangeTable`] from a bitmap (represented as
    /// multiple `u64`) where each bit corresponds to a dirty memory page.
    ///
    /// Only dirty ranges are represented in the resulting bitmap.
    pub fn from_dirty_bitmap(
        bitmap: impl IntoIterator<Item = u64>,
        start_addr: u64,
        page_size: u64,
    ) -> Self {
        Self {
            data: Self::dirty_ranges_iter(bitmap, start_addr, page_size).collect(),
        }
    }

    pub fn regions(&self) -> &[MemoryRange] {
        &self.data
    }

    pub fn push(&mut self, range: MemoryRange) {
        self.data.push(range);
    }

    pub fn read_from(fd: &mut dyn Read, length: u64) -> Result<MemoryRangeTable, MigratableError> {
        assert!((length as usize).is_multiple_of(size_of::<MemoryRange>()));

        let mut data: Vec<MemoryRange> =
            vec![MemoryRange::default(); length as usize / size_of::<MemoryRange>()];

        // SAFETY: The pointer points to the just created vector data.
        // `MemoryRange` can be read from and written to bytes since it's `[repr(C)]`.
        // The vector data was initialized with `length as usize / size_of::<MemoryRange>()` valid
        // `MemoryRange`s so the memory is valid for `length` bytes.
        // During the lifetime of the slice, neither the backing vector nor the pointed to memory are accessed.
        let data_slice_bytes =
            unsafe { slice::from_raw_parts_mut(data.as_mut_ptr().cast(), length as usize) };

        fd.read_exact(data_slice_bytes)
            .map_err(MigratableError::MigrateSocket)?;

        Ok(Self { data })
    }

    pub fn length(&self) -> u64 {
        (mem::size_of::<MemoryRange>() * self.data.len()) as u64
    }

    pub fn write_to(&self, fd: &mut dyn Write) -> Result<(), MigratableError> {
        // SAFETY: the slice is constructed with the correct arguments
        fd.write_all(unsafe {
            slice::from_raw_parts(self.data.as_ptr().cast(), self.length() as usize)
        })
        .map_err(MigratableError::MigrateSocket)
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn extend(&mut self, table: Self) {
        self.data.extend(table.data);
    }

    pub fn new_from_tables(tables: Vec<Self>) -> Self {
        let mut data = Vec::new();
        for table in tables {
            data.extend(table.data);
        }
        Self { data }
    }

    /// Returns the effective size in bytes.
    pub fn effective_size(&self) -> u64 {
        self.data.iter().map(|r| r.length).sum()
    }
}

#[cfg(test)]
mod unit_tests {
    use std::io::Cursor;

    use crate::protocol::{
        CURRENT_PROTOCOL_VERSION, Command, MemoryRange, MemoryRangeTable, Request,
    };

    #[test]
    fn test_start_request_ignores_residual_command_headers_bytes() {
        let request = Request {
            command: Command::Start,
            command_headers: [1, 0, 0xaa, 0xbb, 0xcc, 0xdd],
            length: 0,
        };

        assert_eq!(
            u16::from_le_bytes([request.command_headers()[0], request.command_headers()[1]]),
            1
        );
    }

    #[test]
    fn test_sender_protocol_version_rejects_unsupported_version() {
        let request = Request {
            command: Command::Start,
            command_headers: [255, 0, 0, 0, 0, 0],
            length: 0,
        };

        const { assert!(CURRENT_PROTOCOL_VERSION < 255) };
        request.sender_protocol_version().unwrap_err();
    }

    #[test]
    fn test_page_fault_request_roundtrip() {
        let req = Request::page_fault();
        assert_eq!(req.command(), Command::PageFault);
        assert_eq!(req.length(), size_of::<MemoryRange>() as u64);

        let range = MemoryRange {
            gpa: 0x4000,
            length: 0x1000,
        };

        let mut buf = Vec::new();
        req.write_to(&mut buf).unwrap();
        range.write_to(&mut buf).unwrap();

        let mut cursor = Cursor::new(buf);
        let parsed_req = Request::read_from(&mut cursor).unwrap();
        assert_eq!(parsed_req.command(), Command::PageFault);
        assert_eq!(parsed_req.length(), size_of::<MemoryRange>() as u64);
        let parsed_range = MemoryRange::read_from(&mut cursor).unwrap();
        assert_eq!(parsed_range, range);
    }

    #[test]
    fn test_memory_range_table_from_dirty_ranges_iter() {
        let input = [0b1111_1110_1110, 0b1_0000];

        let start_gpa = 0x1000;
        let page_size = 0x1000;

        let range = MemoryRangeTable::from_dirty_bitmap(input, start_gpa, page_size);
        assert_eq!(
            range.regions(),
            &[
                MemoryRange {
                    gpa: start_gpa + page_size,
                    length: page_size * 3,
                },
                MemoryRange {
                    gpa: start_gpa + 5 * page_size,
                    length: page_size * 7,
                },
                MemoryRange {
                    gpa: start_gpa + (64 + 4) * page_size,
                    length: page_size,
                }
            ]
        );
    }

    #[test]
    fn test_memory_range_table_partition() {
        // We start the test similar as the one above, but with a input that is simpler to parse for
        // developers.
        let input = [0b11_0011_0011_0011];

        let start_gpa = 0x1000;
        let page_size = 0x1000;

        let table = MemoryRangeTable::from_dirty_bitmap(input, start_gpa, page_size);
        let expected_regions = [
            MemoryRange {
                gpa: start_gpa,
                length: page_size * 2,
            },
            MemoryRange {
                gpa: start_gpa + 4 * page_size,
                length: page_size * 2,
            },
            MemoryRange {
                gpa: start_gpa + 8 * page_size,
                length: page_size * 2,
            },
            MemoryRange {
                gpa: start_gpa + 12 * page_size,
                length: page_size * 2,
            },
        ];
        assert_eq!(table.regions(), &expected_regions);

        // In the first test, we expect to see the exact same result as above, as we use the length
        // of every region (which is fixed!).
        {
            let chunks = table
                .clone()
                .partition(page_size * 2)
                .map(|table| table.data)
                .collect::<Vec<_>>();

            // The implementation currently returns the ranges in reverse order.
            // For better testability, we reverse it.
            let chunks = chunks
                .into_iter()
                .map(|vec| vec.into_iter().rev().collect::<Vec<_>>())
                .rev()
                .collect::<Vec<_>>();

            assert_eq!(
                chunks,
                &[
                    [expected_regions[0]].to_vec(),
                    [expected_regions[1]].to_vec(),
                    [expected_regions[2]].to_vec(),
                    [expected_regions[3]].to_vec(),
                ]
            );
        }

        // Next, we have a more sophisticated test with a chunk size of 5 pages.
        {
            let chunks = table
                .clone()
                .partition(page_size * 5)
                .map(|table| table.data)
                .collect::<Vec<_>>();

            // The implementation currently returns the ranges in reverse order.
            // For better testability, we reverse it.
            let chunks = chunks
                .into_iter()
                .map(|vec| vec.into_iter().rev().collect::<Vec<_>>())
                .rev()
                .collect::<Vec<_>>();

            assert_eq!(
                chunks,
                &[
                    vec![
                        MemoryRange {
                            gpa: start_gpa,
                            length: 2 * page_size
                        },
                        MemoryRange {
                            gpa: start_gpa + 4 * page_size,
                            length: page_size
                        }
                    ],
                    vec![
                        MemoryRange {
                            gpa: start_gpa + 5 * page_size,
                            length: page_size
                        },
                        MemoryRange {
                            gpa: start_gpa + 8 * page_size,
                            length: 2 * page_size
                        },
                        MemoryRange {
                            gpa: start_gpa + 12 * page_size,
                            length: 2 * page_size
                        }
                    ]
                ]
            );
        }
    }

    #[test]
    fn test_memory_range_table_partition_uneven_split() {
        // Three consecutive dirty pages produce one 3-page range, which lets
        // us test an uneven 1+2 page split while using the same helper as the
        // other partition tests above.
        let input = [0b111];
        let start_gpa = 0x1000;
        let page_size = 0x1000;

        let table = MemoryRangeTable::from_dirty_bitmap(input, start_gpa, page_size);

        let chunks = table
            .partition(page_size * 2)
            .map(|table| table.data)
            .collect::<Vec<_>>();

        // The implementation currently returns ranges in reverse order.
        let chunks = chunks.into_iter().rev().collect::<Vec<_>>();

        assert_eq!(
            chunks,
            &[
                vec![MemoryRange {
                    gpa: start_gpa,
                    length: page_size,
                }],
                vec![MemoryRange {
                    gpa: start_gpa + page_size,
                    length: page_size * 2,
                }],
            ]
        );
    }
}
