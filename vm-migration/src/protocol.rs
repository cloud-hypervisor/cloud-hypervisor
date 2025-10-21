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

use std::io::{Read, Write};

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
/// ```
///
/// [live-migration protocol]: super::protocol
#[repr(u16)]
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub enum Command {
    #[default]
    Invalid,
    Start,
    Config,
    State,
    Memory,
    Complete,
    Abandon,
    MemoryFd,
}

#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct Request {
    command: Command,
    padding: [u8; 6],
    length: u64, // Length of payload for command excluding the Request struct
}

// SAFETY: Request contains a series of integers with no implicit padding
unsafe impl ByteValued for Request {}

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

    pub fn config(length: u64) -> Self {
        Self::new(Command::Config, length)
    }

    pub fn memory(length: u64) -> Self {
        Self::new(Command::Memory, length)
    }

    pub fn memory_fd(length: u64) -> Self {
        Self::new(Command::MemoryFd, length)
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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRange {
    pub gpa: u64,
    pub length: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryRangeTable {
    data: Vec<MemoryRange>,
}

#[derive(Debug, Clone, Default)]
struct MemoryRangeTableIterator {
    chunk_size: u64,
    data: Vec<MemoryRange>,
}

impl MemoryRangeTableIterator {
    pub fn new(table: &MemoryRangeTable, chunk_size: u64) -> Self {
        MemoryRangeTableIterator {
            chunk_size,
            data: table.data.clone(),
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
                        gpa: range.gpa + returned_bytes,
                        length: leftover_bytes,
                    });
                    MemoryRange {
                        gpa: range.gpa,
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
    /// Partitions the table into chunks of at most `chunk_size` bytes.
    pub fn partition(&self, chunk_size: u64) -> impl Iterator<Item = MemoryRangeTable> {
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

        let mut data: Vec<MemoryRange> = Vec::new();
        data.resize_with(
            length as usize / (std::mem::size_of::<MemoryRange>()),
            Default::default,
        );
        // SAFETY: the slice is constructed with the correct arguments
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
        // SAFETY: the slice is constructed with the correct arguments
        fd.write_all(unsafe {
            std::slice::from_raw_parts(self.data.as_ptr() as *const u8, self.length() as usize)
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
}

#[cfg(test)]
mod unit_tests {
    use crate::protocol::{MemoryRange, MemoryRangeTable};

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
                    [expected_regions[0].clone()].to_vec(),
                    [expected_regions[1].clone()].to_vec(),
                    [expected_regions[2].clone()].to_vec(),
                    [expected_regions[3].clone()].to_vec(),
                ]
            );
        }

        // Next, we have a more sophisticated test with a chunk size of 5 pages.
        {
            let chunks = table
                .partition(page_size * 5)
                .map(|table| table.data)
                .collect::<Vec<_>>();

            // The implementation currently returns the ranges in reverse order.
            // For better testability, we reverse it.
            let chunks = chunks
                .into_iter()
                .map(|vec| vec.into_iter().rev().collect::<Vec<_>>())
                .collect::<Vec<_>>();

            assert_eq!(
                chunks,
                &[
                    vec![
                        MemoryRange {
                            gpa: start_gpa + 4 * page_size,
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
                    ],
                    vec![
                        MemoryRange {
                            gpa: start_gpa,
                            length: 2 * page_size
                        },
                        MemoryRange {
                            gpa: start_gpa + 5 * page_size,
                            length: page_size
                        }
                    ]
                ]
            );
        }
    }
}
